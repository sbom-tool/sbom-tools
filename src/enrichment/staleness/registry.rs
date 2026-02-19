//! Package registry clients for staleness detection.

use crate::enrichment::stats::EnrichmentError;
use crate::model::{Component, Ecosystem, StalenessInfo, StalenessLevel};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Registry client configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Cache directory
    pub cache_dir: PathBuf,
    /// Cache time-to-live
    pub cache_ttl: Duration,
    /// Request timeout
    pub timeout: Duration,
    /// Bypass cache
    pub bypass_cache: bool,
    /// Threshold for "stale" classification (days)
    pub stale_threshold_days: u32,
    /// Threshold for "abandoned" classification (days)
    pub abandoned_threshold_days: u32,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            cache_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days (registry data is stable)
            timeout: Duration::from_secs(10),
            bypass_cache: false,
            stale_threshold_days: 365,
            abandoned_threshold_days: 730,
        }
    }
}

fn default_cache_dir() -> PathBuf {
    dirs_cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("sbom-tools")
        .join("staleness")
}

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

/// Package metadata from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package name
    pub name: String,
    /// Ecosystem
    pub ecosystem: String,
    /// Latest version available
    pub latest_version: Option<String>,
    /// Last publish date
    pub last_published: Option<DateTime<Utc>>,
    /// Whether deprecated
    pub is_deprecated: bool,
    /// Whether archived
    pub is_archived: bool,
    /// Deprecation message
    pub deprecation_message: Option<String>,
    /// Repository URL
    pub repository_url: Option<String>,
}

/// Staleness enrichment statistics
#[derive(Debug, Default)]
pub struct StalenessEnrichmentStats {
    /// Components checked
    pub components_checked: usize,
    /// Components enriched
    pub components_enriched: usize,
    /// Fresh count
    pub fresh_count: usize,
    /// Aging count
    pub aging_count: usize,
    /// Stale count
    pub stale_count: usize,
    /// Abandoned count
    pub abandoned_count: usize,
    /// Deprecated count
    pub deprecated_count: usize,
    /// API calls made
    pub api_calls: usize,
    /// Cache hits
    pub cache_hits: usize,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Skipped (unsupported ecosystem)
    pub skipped_count: usize,
}

/// Multi-registry client for staleness enrichment
pub struct RegistryClient {
    config: RegistryConfig,
    cache: HashMap<String, PackageMetadata>,
}

impl RegistryClient {
    /// Create a new registry client
    #[must_use]
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
        }
    }

    /// Get cache key for a package
    fn cache_key(&self, ecosystem: &str, name: &str) -> String {
        format!("{ecosystem}:{name}")
    }

    /// Get cache file path
    fn cache_file(&self, key: &str) -> PathBuf {
        let safe_key = key.replace(['/', ':'], "_");
        self.config.cache_dir.join(format!("{safe_key}.json"))
    }

    /// Check if cache is valid
    fn is_cache_valid(&self, key: &str) -> bool {
        if self.config.bypass_cache {
            return false;
        }

        let cache_path = self.cache_file(key);
        if !cache_path.exists() {
            return false;
        }

        if let Ok(metadata) = fs::metadata(&cache_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = SystemTime::now().duration_since(modified)
        {
            return elapsed < self.config.cache_ttl;
        }

        false
    }

    /// Load from cache
    fn load_from_cache(&self, key: &str) -> Option<PackageMetadata> {
        let cache_path = self.cache_file(key);
        let content = fs::read_to_string(&cache_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Save to cache
    fn save_to_cache(&self, key: &str, metadata: &PackageMetadata) -> Result<(), EnrichmentError> {
        let cache_path = self.cache_file(key);

        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).map_err(|e| EnrichmentError::CacheError(e.to_string()))?;
        }

        let content = serde_json::to_string(metadata)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;

        fs::write(&cache_path, content).map_err(|e| EnrichmentError::CacheError(e.to_string()))?;

        Ok(())
    }

    /// Query npm registry
    #[cfg(feature = "enrichment")]
    fn query_npm(&self, name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        let url = format!("https://registry.npmjs.org/{name}");

        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let response = client.get(&url).send();

        match response {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp
                    .json()
                    .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

                let time = json.get("time").and_then(|t| t.as_object());
                let latest_version = json
                    .get("dist-tags")
                    .and_then(|d| d.get("latest"))
                    .and_then(|l| l.as_str())
                    .map(std::string::ToString::to_string);

                let last_published = time
                    .and_then(|t| latest_version.as_ref().and_then(|v| t.get(v.as_str())))
                    .and_then(|v| v.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc));

                let is_deprecated = json.get("deprecated").is_some();
                let deprecation_message = json
                    .get("deprecated")
                    .and_then(|d| d.as_str())
                    .map(std::string::ToString::to_string);

                let repository_url = json
                    .get("repository")
                    .and_then(|r| r.get("url"))
                    .and_then(|u| u.as_str())
                    .map(std::string::ToString::to_string);

                Ok(Some(PackageMetadata {
                    name: name.to_string(),
                    ecosystem: "npm".to_string(),
                    latest_version,
                    last_published,
                    is_deprecated,
                    is_archived: false,
                    deprecation_message,
                    repository_url,
                }))
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => Ok(None),
            Ok(resp) => Err(EnrichmentError::ApiError(format!(
                "npm API returned {}",
                resp.status()
            ))),
            Err(e) => Err(EnrichmentError::ApiError(e.to_string())),
        }
    }

    /// Query `PyPI` registry
    #[cfg(feature = "enrichment")]
    fn query_pypi(&self, name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        let url = format!("https://pypi.org/pypi/{name}/json");

        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let response = client.get(&url).send();

        match response {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp
                    .json()
                    .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

                let info = json.get("info");
                let latest_version = info
                    .and_then(|i| i.get("version"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string);

                // Get release dates
                let releases = json.get("releases").and_then(|r| r.as_object());
                let last_published = releases
                    .and_then(|r| {
                        r.values()
                            .filter_map(|v| v.as_array())
                            .flat_map(|arr| arr.iter())
                            .filter_map(|item| {
                                item.get("upload_time_iso_8601")
                                    .and_then(|t| t.as_str())
                                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            })
                            .max()
                    })
                    .map(|d| d.with_timezone(&Utc));

                let is_deprecated = info
                    .and_then(|i| i.get("classifiers"))
                    .and_then(|c| c.as_array())
                    .is_some_and(|arr| {
                        arr.iter().any(|c| {
                            c.as_str()
                                .is_some_and(|s| s.contains("Inactive") || s.contains("Obsolete"))
                        })
                    });

                let repository_url = info
                    .and_then(|i| i.get("project_urls"))
                    .and_then(|u| {
                        u.get("Repository")
                            .or_else(|| u.get("Source"))
                            .or_else(|| u.get("Homepage"))
                    })
                    .and_then(|u| u.as_str())
                    .map(std::string::ToString::to_string);

                Ok(Some(PackageMetadata {
                    name: name.to_string(),
                    ecosystem: "pypi".to_string(),
                    latest_version,
                    last_published,
                    is_deprecated,
                    is_archived: false,
                    deprecation_message: None,
                    repository_url,
                }))
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => Ok(None),
            Ok(resp) => Err(EnrichmentError::ApiError(format!(
                "PyPI API returned {}",
                resp.status()
            ))),
            Err(e) => Err(EnrichmentError::ApiError(e.to_string())),
        }
    }

    /// Query crates.io registry
    #[cfg(feature = "enrichment")]
    fn query_crates_io(&self, name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        let url = format!("https://crates.io/api/v1/crates/{name}");

        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .user_agent("sbom-tools/1.0")
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let response = client.get(&url).send();

        match response {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp
                    .json()
                    .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

                let krate = json.get("crate");
                let latest_version = krate
                    .and_then(|c| c.get("newest_version"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string);

                let last_published = krate
                    .and_then(|c| c.get("updated_at"))
                    .and_then(|u| u.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc));

                let repository_url = krate
                    .and_then(|c| c.get("repository"))
                    .and_then(|r| r.as_str())
                    .map(std::string::ToString::to_string);

                Ok(Some(PackageMetadata {
                    name: name.to_string(),
                    ecosystem: "cargo".to_string(),
                    latest_version,
                    last_published,
                    is_deprecated: false,
                    is_archived: false,
                    deprecation_message: None,
                    repository_url,
                }))
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => Ok(None),
            Ok(resp) => Err(EnrichmentError::ApiError(format!(
                "crates.io API returned {}",
                resp.status()
            ))),
            Err(e) => Err(EnrichmentError::ApiError(e.to_string())),
        }
    }

    /// Stub implementations for non-enrichment builds
    #[cfg(not(feature = "enrichment"))]
    fn query_npm(&self, _name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        Ok(None)
    }

    #[cfg(not(feature = "enrichment"))]
    fn query_pypi(&self, _name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        Ok(None)
    }

    #[cfg(not(feature = "enrichment"))]
    fn query_crates_io(&self, _name: &str) -> Result<Option<PackageMetadata>, EnrichmentError> {
        Ok(None)
    }

    /// Query package metadata from appropriate registry
    pub fn query_package(
        &mut self,
        ecosystem: &Ecosystem,
        name: &str,
    ) -> Result<Option<PackageMetadata>, EnrichmentError> {
        let ecosystem_str = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Cargo => "cargo",
            _ => return Ok(None), // Unsupported ecosystem
        };

        let cache_key = self.cache_key(ecosystem_str, name);

        // Check memory cache first
        if let Some(metadata) = self.cache.get(&cache_key) {
            return Ok(Some(metadata.clone()));
        }

        // Check disk cache
        if self.is_cache_valid(&cache_key)
            && let Some(metadata) = self.load_from_cache(&cache_key)
        {
            self.cache.insert(cache_key.clone(), metadata.clone());
            return Ok(Some(metadata));
        }

        // Query registry
        let result = match ecosystem {
            Ecosystem::Npm => self.query_npm(name),
            Ecosystem::PyPi => self.query_pypi(name),
            Ecosystem::Cargo => self.query_crates_io(name),
            _ => Ok(None),
        };

        // Cache result
        if let Ok(Some(ref metadata)) = result {
            let _ = self.save_to_cache(&cache_key, metadata);
            self.cache.insert(cache_key, metadata.clone());
        }

        result
    }
}

/// Staleness enricher
pub struct StalenessEnricher {
    client: RegistryClient,
    config: RegistryConfig,
}

impl StalenessEnricher {
    /// Create a new staleness enricher
    #[must_use]
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            client: RegistryClient::new(config.clone()),
            config,
        }
    }

    /// Check if ecosystem is supported
    const fn is_supported(&self, ecosystem: Option<&Ecosystem>) -> bool {
        matches!(
            ecosystem,
            Some(Ecosystem::Npm | Ecosystem::PyPi | Ecosystem::Cargo)
        )
    }

    /// Calculate staleness level from metadata
    fn calculate_staleness(&self, metadata: &PackageMetadata) -> StalenessLevel {
        if metadata.is_archived {
            return StalenessLevel::Archived;
        }

        if metadata.is_deprecated {
            return StalenessLevel::Deprecated;
        }

        if let Some(last_published) = metadata.last_published {
            let days = (Utc::now() - last_published).num_days() as u32;

            if days >= self.config.abandoned_threshold_days {
                return StalenessLevel::Abandoned;
            } else if days >= self.config.stale_threshold_days {
                return StalenessLevel::Stale;
            } else if days >= 182 {
                return StalenessLevel::Aging;
            }
            return StalenessLevel::Fresh;
        }

        // Unknown age - assume fresh (no data)
        StalenessLevel::Fresh
    }

    /// Enrich components with staleness information
    pub fn enrich_components(
        &mut self,
        components: &mut [Component],
    ) -> Result<StalenessEnrichmentStats, EnrichmentError> {
        let mut stats = StalenessEnrichmentStats::default();

        for component in components.iter_mut() {
            stats.components_checked += 1;

            // Skip unsupported ecosystems
            if !self.is_supported(component.ecosystem.as_ref()) {
                stats.skipped_count += 1;
                continue;
            }

            let ecosystem = component
                .ecosystem
                .as_ref()
                .expect("ecosystem is Some after is_supported check");

            // Query registry
            match self.client.query_package(ecosystem, &component.name) {
                Ok(Some(metadata)) => {
                    stats.api_calls += 1;

                    let level = self.calculate_staleness(&metadata);
                    let days_since_update = metadata
                        .last_published
                        .map(|d| (Utc::now() - d).num_days() as u32);

                    component.staleness = Some(StalenessInfo {
                        level,
                        last_published: metadata.last_published,
                        is_deprecated: metadata.is_deprecated,
                        is_archived: metadata.is_archived,
                        deprecation_message: metadata.deprecation_message.clone(),
                        days_since_update,
                        latest_version: metadata.latest_version.clone(),
                    });

                    stats.components_enriched += 1;

                    match level {
                        StalenessLevel::Fresh => stats.fresh_count += 1,
                        StalenessLevel::Aging => stats.aging_count += 1,
                        StalenessLevel::Stale => stats.stale_count += 1,
                        StalenessLevel::Abandoned => stats.abandoned_count += 1,
                        StalenessLevel::Deprecated | StalenessLevel::Archived => {
                            stats.deprecated_count += 1;
                        }
                    }
                }
                Ok(None) => {
                    // Package not found in registry
                    stats.api_calls += 1;
                }
                Err(e) => {
                    stats.errors.push(format!("{}: {}", component.name, e));
                }
            }
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staleness_level_calculation() {
        let config = RegistryConfig::default();
        let enricher = StalenessEnricher::new(config);

        // Fresh - 1 month ago
        let metadata = PackageMetadata {
            name: "test".to_string(),
            ecosystem: "npm".to_string(),
            latest_version: Some("1.0.0".to_string()),
            last_published: Some(Utc::now() - chrono::Duration::days(30)),
            is_deprecated: false,
            is_archived: false,
            deprecation_message: None,
            repository_url: None,
        };
        assert_eq!(
            enricher.calculate_staleness(&metadata),
            StalenessLevel::Fresh
        );

        // Stale - 400 days ago
        let metadata = PackageMetadata {
            last_published: Some(Utc::now() - chrono::Duration::days(400)),
            ..metadata.clone()
        };
        assert_eq!(
            enricher.calculate_staleness(&metadata),
            StalenessLevel::Stale
        );

        // Deprecated
        let metadata = PackageMetadata {
            is_deprecated: true,
            ..metadata.clone()
        };
        assert_eq!(
            enricher.calculate_staleness(&metadata),
            StalenessLevel::Deprecated
        );
    }

    #[test]
    fn test_supported_ecosystems() {
        let config = RegistryConfig::default();
        let enricher = StalenessEnricher::new(config);

        assert!(enricher.is_supported(Some(&Ecosystem::Npm)));
        assert!(enricher.is_supported(Some(&Ecosystem::PyPi)));
        assert!(enricher.is_supported(Some(&Ecosystem::Cargo)));
        assert!(!enricher.is_supported(Some(&Ecosystem::Maven)));
        assert!(!enricher.is_supported(None));
    }
}
