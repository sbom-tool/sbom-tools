//! KEV catalog client with caching support.

use super::catalog::{KevCatalog, KevCatalogResponse};
use crate::enrichment::stats::EnrichmentError;
use crate::model::{KevInfo, VulnerabilityRef};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Default CISA KEV catalog URL
pub const KEV_CATALOG_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// KEV client configuration
#[derive(Debug, Clone)]
pub struct KevClientConfig {
    /// Cache directory
    pub cache_dir: PathBuf,
    /// Cache time-to-live
    pub cache_ttl: Duration,
    /// KEV catalog URL
    pub kev_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Bypass cache and fetch fresh data
    pub bypass_cache: bool,
}

impl Default for KevClientConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            cache_ttl: Duration::from_secs(24 * 3600), // 24 hours
            kev_url: KEV_CATALOG_URL.to_string(),
            timeout: Duration::from_secs(30),
            bypass_cache: false,
        }
    }
}

/// Get the default cache directory
fn default_cache_dir() -> PathBuf {
    dirs_cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("sbom-tools")
        .join("kev")
}

/// Get cache directory (platform-aware)
fn dirs_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Caches"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CACHE_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".cache"))
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache"))
    }
}

/// KEV enrichment statistics
#[derive(Debug, Default)]
pub struct KevEnrichmentStats {
    /// Number of vulnerabilities checked
    pub vulns_checked: usize,
    /// Number of KEV matches found
    pub kev_matches: usize,
    /// Number of ransomware-related matches
    pub ransomware_related: usize,
    /// Number of overdue remediation deadlines
    pub overdue_count: usize,
    /// Whether catalog was loaded from cache
    pub cache_hit: bool,
    /// Catalog version
    pub catalog_version: Option<String>,
    /// Total entries in catalog
    pub catalog_size: usize,
}

/// KEV catalog client
pub struct KevClient {
    config: KevClientConfig,
    catalog: Option<KevCatalog>,
}

impl KevClient {
    /// Create a new KEV client
    #[must_use] 
    pub const fn new(config: KevClientConfig) -> Self {
        Self {
            config,
            catalog: None,
        }
    }

    /// Create with default configuration
    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(KevClientConfig::default())
    }

    /// Get the cache file path
    fn cache_file_path(&self) -> PathBuf {
        self.config.cache_dir.join("kev_catalog.json")
    }

    /// Check if cache is valid
    fn is_cache_valid(&self) -> bool {
        if self.config.bypass_cache {
            return false;
        }

        let cache_path = self.cache_file_path();
        if !cache_path.exists() {
            return false;
        }

        // Check cache age
        if let Ok(metadata) = fs::metadata(&cache_path)
            && let Ok(modified) = metadata.modified()
                && let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                    return elapsed < self.config.cache_ttl;
                }

        false
    }

    /// Load catalog from cache
    fn load_from_cache(&self) -> Option<KevCatalog> {
        let cache_path = self.cache_file_path();
        let content = fs::read_to_string(&cache_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Save catalog to cache
    fn save_to_cache(&self, catalog: &KevCatalog) -> Result<(), EnrichmentError> {
        let cache_path = self.cache_file_path();

        // Ensure cache directory exists
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;
        }

        let content = serde_json::to_string(catalog)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;

        fs::write(&cache_path, content)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;

        Ok(())
    }

    /// Fetch catalog from CISA API
    #[cfg(feature = "enrichment")]
    fn fetch_from_api(&self) -> Result<KevCatalog, EnrichmentError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let response = client
            .get(&self.config.kev_url)
            .send()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EnrichmentError::ApiError(format!(
                "KEV API returned status {}",
                response.status()
            )));
        }

        let catalog_response: KevCatalogResponse = response
            .json()
            .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

        Ok(KevCatalog::from_response(catalog_response))
    }

    /// Fetch catalog (stub for non-enrichment builds)
    #[cfg(not(feature = "enrichment"))]
    fn fetch_from_api(&self) -> Result<KevCatalog, EnrichmentError> {
        Err(EnrichmentError::ApiError(
            "Enrichment feature not enabled".to_string(),
        ))
    }

    /// Load the KEV catalog (from cache or API)
    pub fn load_catalog(&mut self) -> Result<(), EnrichmentError> {
        if self.catalog.is_some() {
            return Ok(());
        }

        // Try cache first
        if self.is_cache_valid()
            && let Some(catalog) = self.load_from_cache() {
                self.catalog = Some(catalog);
                return Ok(());
            }

        // Fetch from API
        let catalog = self.fetch_from_api()?;

        // Save to cache
        let _ = self.save_to_cache(&catalog);

        self.catalog = Some(catalog);
        Ok(())
    }

    /// Get the loaded catalog (if any)
    #[must_use] 
    pub const fn catalog(&self) -> Option<&KevCatalog> {
        self.catalog.as_ref()
    }

    /// Check if a CVE is in the KEV catalog
    #[must_use] 
    pub fn is_kev(&self, cve_id: &str) -> bool {
        self.catalog
            .as_ref()
            .is_some_and(|c| c.contains(cve_id))
    }

    /// Enrich vulnerabilities with KEV information
    pub fn enrich_vulnerabilities(
        &mut self,
        vulnerabilities: &mut [VulnerabilityRef],
    ) -> Result<KevEnrichmentStats, EnrichmentError> {
        let mut stats = KevEnrichmentStats::default();

        // Check cache validity before loading (avoids borrow conflict)
        let was_cache_hit = self.is_cache_valid();

        // Load catalog if not already loaded
        self.load_catalog()?;

        let catalog = self
            .catalog
            .as_ref()
            .expect("catalog populated by load_catalog above");
        stats.catalog_version = Some(catalog.version.clone());
        stats.catalog_size = catalog.len();
        stats.cache_hit = was_cache_hit;

        // Enrich each vulnerability
        for vuln in vulnerabilities.iter_mut() {
            stats.vulns_checked += 1;

            // Only check CVE IDs
            if !vuln.id.to_uppercase().starts_with("CVE-") {
                continue;
            }

            if let Some(kev_entry) = catalog.get(&vuln.id) {
                vuln.is_kev = true;
                vuln.kev_info = Some(KevInfo {
                    date_added: kev_entry.date_added,
                    due_date: kev_entry.due_date,
                    known_ransomware_use: kev_entry.known_ransomware_use,
                    required_action: kev_entry.required_action.clone(),
                    vendor_project: Some(kev_entry.vendor_project.clone()),
                    product: Some(kev_entry.product.clone()),
                });

                stats.kev_matches += 1;

                if kev_entry.known_ransomware_use {
                    stats.ransomware_related += 1;
                }

                if kev_entry.is_overdue() {
                    stats.overdue_count += 1;
                }
            }
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VulnerabilitySource;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir) -> KevClientConfig {
        KevClientConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            bypass_cache: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_kev_client_creation() {
        let client = KevClient::with_defaults();
        assert!(client.catalog.is_none());
    }

    #[test]
    fn test_cache_validity() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = test_config(&temp_dir);
        config.bypass_cache = false;

        let client = KevClient::new(config);
        assert!(!client.is_cache_valid());
    }

    #[test]
    fn test_enrich_non_cve() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        let mut client = KevClient::new(config);
        client.catalog = Some(KevCatalog::new());

        let mut vulns = vec![VulnerabilityRef::new(
            "GHSA-1234-abcd".to_string(),
            VulnerabilitySource::Ghsa,
        )];

        let stats = client.enrich_vulnerabilities(&mut vulns).unwrap();
        assert_eq!(stats.vulns_checked, 1);
        assert_eq!(stats.kev_matches, 0);
        assert!(!vulns[0].is_kev);
    }
}
