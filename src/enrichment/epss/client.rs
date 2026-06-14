//! EPSS scores client with caching support.

use super::scores::EpssScores;
use crate::enrichment::source::{JsonCache, namespaced_cache_dir};
use crate::enrichment::stats::EnrichmentError;
use crate::model::VulnerabilityRef;
use std::path::PathBuf;
use std::time::Duration;

/// Cache file name for the serialized EPSS dataset.
const EPSS_CACHE_FILE: &str = "epss_scores.json";

/// Default FIRST EPSS bulk-scores URL.
///
/// FIRST also serves a gzip-compressed `…/epss_scores-current.csv.gz`; the
/// uncompressed endpoint is used here so no gzip dependency is required.
pub const EPSS_SCORES_URL: &str = "https://epss.cybersecurity.fr/epss_scores-current.csv";

/// EPSS client configuration.
#[derive(Debug, Clone)]
pub struct EpssClientConfig {
    /// Cache directory.
    pub cache_dir: PathBuf,
    /// Cache time-to-live.
    pub cache_ttl: Duration,
    /// EPSS scores URL.
    pub epss_url: String,
    /// Request timeout.
    pub timeout: Duration,
    /// Bypass cache and fetch fresh data.
    pub bypass_cache: bool,
}

impl Default for EpssClientConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            cache_ttl: Duration::from_secs(24 * 3600), // 24 hours (daily dataset)
            epss_url: EPSS_SCORES_URL.to_string(),
            timeout: Duration::from_secs(30),
            bypass_cache: false,
        }
    }
}

/// Get the default cache directory.
fn default_cache_dir() -> PathBuf {
    namespaced_cache_dir("epss")
}

/// EPSS enrichment statistics.
#[derive(Debug, Default, Clone)]
pub struct EpssEnrichmentStats {
    /// Number of vulnerabilities checked.
    pub vulns_checked: usize,
    /// Number of EPSS matches found.
    pub epss_matches: usize,
    /// Number of high-probability matches (score >= 0.5).
    pub high_probability: usize,
    /// Whether the dataset was loaded from cache.
    pub cache_hit: bool,
    /// Score date of the dataset.
    pub score_date: Option<String>,
    /// Total entries in the dataset.
    pub dataset_size: usize,
}

/// EPSS scores client.
pub struct EpssClient {
    config: EpssClientConfig,
    scores: Option<EpssScores>,
}

impl EpssClient {
    /// Create a new EPSS client.
    #[must_use]
    pub const fn new(config: EpssClientConfig) -> Self {
        Self {
            config,
            scores: None,
        }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(EpssClientConfig::default())
    }

    /// Open the shared file cache for the serialized dataset.
    fn cache(&self) -> Result<JsonCache<EpssScores>, EnrichmentError> {
        JsonCache::new(self.config.cache_dir.clone(), self.config.cache_ttl)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))
    }

    /// Check if a valid (unexpired, current-schema) cached dataset exists.
    fn is_cache_valid(&self) -> bool {
        if self.config.bypass_cache {
            return false;
        }
        self.cache()
            .ok()
            .is_some_and(|c| c.get_named(EPSS_CACHE_FILE).is_some())
    }

    /// Load dataset from cache.
    fn load_from_cache(&self) -> Option<EpssScores> {
        self.cache().ok()?.get_named(EPSS_CACHE_FILE)
    }

    /// Save dataset to cache.
    fn save_to_cache(&self, scores: &EpssScores) -> Result<(), EnrichmentError> {
        self.cache()?
            .set_named(EPSS_CACHE_FILE, scores)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))
    }

    /// Fetch dataset from the FIRST EPSS endpoint.
    #[cfg(feature = "enrichment")]
    fn fetch_from_api(&self) -> Result<EpssScores, EnrichmentError> {
        let client = crate::enrichment::source::http_client(self.config.timeout)
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let response = crate::enrichment::source::get_with_retry(&client, &self.config.epss_url, 3)
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EnrichmentError::ApiError(format!(
                "EPSS API returned status {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

        Ok(EpssScores::from_csv(&body))
    }

    /// Fetch dataset (stub for non-enrichment builds).
    #[cfg(not(feature = "enrichment"))]
    fn fetch_from_api(&self) -> Result<EpssScores, EnrichmentError> {
        Err(EnrichmentError::ApiError(
            "Enrichment feature not enabled".to_string(),
        ))
    }

    /// Load the EPSS dataset (from cache or API).
    pub fn load_scores(&mut self) -> Result<(), EnrichmentError> {
        if self.scores.is_some() {
            return Ok(());
        }

        if self.is_cache_valid()
            && let Some(scores) = self.load_from_cache()
        {
            self.scores = Some(scores);
            return Ok(());
        }

        let scores = self.fetch_from_api()?;
        let _ = self.save_to_cache(&scores);
        self.scores = Some(scores);
        Ok(())
    }

    /// Get the loaded dataset (if any).
    #[must_use]
    pub const fn scores(&self) -> Option<&EpssScores> {
        self.scores.as_ref()
    }

    /// Enrich vulnerabilities with EPSS scores.
    ///
    /// Sets `epss_score` / `epss_percentile` on every CVE-identified
    /// [`VulnerabilityRef`] that matches the dataset.
    pub fn enrich_vulnerabilities(
        &mut self,
        vulnerabilities: &mut [VulnerabilityRef],
    ) -> Result<EpssEnrichmentStats, EnrichmentError> {
        let mut stats = EpssEnrichmentStats::default();

        let was_cache_hit = self.is_cache_valid();
        self.load_scores()?;

        let scores = self
            .scores
            .as_ref()
            .expect("scores populated by load_scores above");
        stats.score_date = scores.score_date.clone();
        stats.dataset_size = scores.len();
        stats.cache_hit = was_cache_hit;

        for vuln in vulnerabilities.iter_mut() {
            stats.vulns_checked += 1;

            // EPSS is keyed strictly by CVE id.
            if !vuln.id.to_uppercase().starts_with("CVE-") {
                continue;
            }

            if let Some(entry) = scores.get(&vuln.id) {
                vuln.epss_score = Some(entry.score);
                vuln.epss_percentile = Some(entry.percentile);
                stats.epss_matches += 1;
                if entry.score >= 0.5 {
                    stats.high_probability += 1;
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

    fn test_config(temp_dir: &TempDir) -> EpssClientConfig {
        EpssClientConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            bypass_cache: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_epss_client_creation() {
        let client = EpssClient::with_defaults();
        assert!(client.scores.is_none());
    }

    #[test]
    fn test_cache_validity() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = test_config(&temp_dir);
        config.bypass_cache = false;

        let client = EpssClient::new(config);
        assert!(!client.is_cache_valid());
    }

    #[test]
    fn test_enrich_sets_scores_on_cve() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        let mut client = EpssClient::new(config);
        client.scores = Some(EpssScores::from_csv(
            "#model_version:v1,score_date:2024-01-15\ncve,epss,percentile\nCVE-2024-1234,0.91234,0.99\n",
        ));

        let mut vulns = vec![
            VulnerabilityRef::new("CVE-2024-1234".to_string(), VulnerabilitySource::Cve),
            VulnerabilityRef::new("GHSA-aaaa-bbbb".to_string(), VulnerabilitySource::Ghsa),
        ];

        let stats = client.enrich_vulnerabilities(&mut vulns).unwrap();
        assert_eq!(stats.vulns_checked, 2);
        assert_eq!(stats.epss_matches, 1);
        assert_eq!(stats.high_probability, 1);
        assert_eq!(vulns[0].epss_score, Some(0.91234));
        assert_eq!(vulns[0].epss_percentile, Some(0.99));
        // Non-CVE id is skipped.
        assert!(vulns[1].epss_score.is_none());
    }
}
