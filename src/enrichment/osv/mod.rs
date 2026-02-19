//! OSV (Open Source Vulnerabilities) enrichment module.
//!
//! This module provides integration with the OSV database to enrich
//! SBOM components with known vulnerability information.
//!
//! See: <https://osv.dev>/

mod client;
mod mapper;
pub mod response;

pub use client::{OsvClient, OsvClientConfig};

use crate::enrichment::cache::{CacheKey, FileCache};
use crate::enrichment::stats::{EnrichmentError, EnrichmentStats};
use crate::enrichment::traits::VulnerabilityEnricher;
use crate::error::Result;
use crate::model::{Component, Ecosystem};
use response::OsvQuery;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Configuration for OSV enricher.
#[derive(Debug, Clone)]
pub struct OsvEnricherConfig {
    /// Cache directory
    pub cache_dir: PathBuf,
    /// Cache TTL
    pub cache_ttl: Duration,
    /// Bypass cache
    pub bypass_cache: bool,
    /// API timeout
    pub timeout: Duration,
    /// OSV API base URL
    pub api_base: String,
}

impl Default for OsvEnricherConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".cache/sbom-tools/osv"),
            cache_ttl: Duration::from_secs(24 * 3600),
            bypass_cache: false,
            timeout: Duration::from_secs(30),
            api_base: "https://api.osv.dev".to_string(),
        }
    }
}

/// OSV vulnerability enricher.
pub struct OsvEnricher {
    client: OsvClient,
    cache: FileCache,
    bypass_cache: bool,
}

impl OsvEnricher {
    /// Create a new OSV enricher with the given configuration.
    pub fn new(config: OsvEnricherConfig) -> Result<Self> {
        let client_config = OsvClientConfig {
            api_base: config.api_base,
            timeout: config.timeout,
            ..Default::default()
        };

        let client = OsvClient::new(client_config)?;
        let cache = FileCache::new(config.cache_dir, config.cache_ttl)?;

        Ok(Self {
            client,
            cache,
            bypass_cache: config.bypass_cache,
        })
    }

    /// Build a cache key and OSV query for a component.
    fn build_query(&self, component: &Component) -> Option<(CacheKey, OsvQuery)> {
        let cache_key = CacheKey::new(
            component.identifiers.purl.clone(),
            component.name.clone(),
            component.ecosystem.as_ref().map(ecosystem_to_osv_string),
            component.version.clone(),
        );

        // Prefer PURL if available
        if let Some(ref purl) = component.identifiers.purl {
            return Some((cache_key, OsvQuery::from_purl(purl.clone())));
        }

        // Fallback to name + ecosystem + version
        if let (Some(ecosystem), Some(version)) = (&component.ecosystem, &component.version) {
            let osv_ecosystem = ecosystem_to_osv_string(ecosystem);
            return Some((
                cache_key,
                OsvQuery::from_package(component.name.clone(), osv_ecosystem, version.clone()),
            ));
        }

        None
    }
}

impl VulnerabilityEnricher for OsvEnricher {
    fn enrich(&self, components: &mut [Component]) -> Result<EnrichmentStats> {
        let start = Instant::now();
        let mut stats = EnrichmentStats::new();

        // Build queries for all components
        let queries: Vec<(usize, CacheKey, OsvQuery)> = components
            .iter()
            .enumerate()
            .filter_map(|(idx, comp)| self.build_query(comp).map(|(key, query)| (idx, key, query)))
            .collect();

        stats.components_queried = queries.len();
        stats.components_skipped = components.len() - queries.len();

        // Separate cached vs needs-fetch
        let mut cached_results: Vec<(usize, Vec<crate::model::VulnerabilityRef>)> = Vec::new();
        let mut to_fetch: Vec<(usize, CacheKey, OsvQuery)> = Vec::new();

        for (idx, key, query) in queries {
            if !self.bypass_cache
                && let Some(cached_vulns) = self.cache.get(&key)
            {
                cached_results.push((idx, cached_vulns));
                stats.cache_hits += 1;
                continue;
            }
            to_fetch.push((idx, key, query));
        }

        // Apply cached results
        for (idx, vulns) in cached_results {
            if !vulns.is_empty() {
                stats.components_with_vulns += 1;
                stats.total_vulns_found += vulns.len();
                components[idx].vulnerabilities.extend(vulns);
            }
        }

        // Batch fetch remaining
        if !to_fetch.is_empty() {
            let queries_only: Vec<OsvQuery> = to_fetch.iter().map(|(_, _, q)| q.clone()).collect();

            // Calculate number of API calls (batches)
            let batch_size = 1000;
            stats.api_calls = queries_only.len().div_ceil(batch_size);

            match self.client.query_batch(&queries_only) {
                Ok(batch_responses) => {
                    // Match results back to components
                    for ((idx, key, _), result) in to_fetch.into_iter().zip(
                        batch_responses
                            .into_iter()
                            .flat_map(|r| r.results.into_iter()),
                    ) {
                        let vulns: Vec<_> = result
                            .vulns
                            .iter()
                            .map(mapper::map_osv_to_vulnerability_ref)
                            .collect();

                        // Cache the result (even if empty)
                        if let Err(e) = self.cache.set(&key, &vulns) {
                            stats
                                .errors
                                .push(EnrichmentError::CacheError(e.to_string()));
                        }

                        if !vulns.is_empty() {
                            stats.components_with_vulns += 1;
                            stats.total_vulns_found += vulns.len();
                            components[idx].vulnerabilities.extend(vulns);
                        }
                    }
                }
                Err(e) => {
                    stats.errors.push(EnrichmentError::ApiError(e.to_string()));
                }
            }
        }

        stats.duration = start.elapsed();
        Ok(stats)
    }

    fn name(&self) -> &'static str {
        "OSV"
    }

    fn is_available(&self) -> bool {
        self.client.health_check().unwrap_or(false)
    }
}

/// Convert our Ecosystem enum to OSV ecosystem string.
fn ecosystem_to_osv_string(ecosystem: &Ecosystem) -> String {
    match ecosystem {
        Ecosystem::Npm => "npm".to_string(),
        Ecosystem::PyPi => "PyPI".to_string(),
        Ecosystem::Cargo => "crates.io".to_string(),
        Ecosystem::Maven => "Maven".to_string(),
        Ecosystem::Golang => "Go".to_string(),
        Ecosystem::Nuget => "NuGet".to_string(),
        Ecosystem::RubyGems => "RubyGems".to_string(),
        Ecosystem::Composer => "Packagist".to_string(),
        Ecosystem::CocoaPods => "CocoaPods".to_string(),
        Ecosystem::Swift => "SwiftURL".to_string(),
        Ecosystem::Hex => "Hex".to_string(),
        Ecosystem::Pub => "Pub".to_string(),
        Ecosystem::Hackage => "Hackage".to_string(),
        Ecosystem::Cpan => "CPAN".to_string(),
        Ecosystem::Cran => "CRAN".to_string(),
        Ecosystem::Conda => "Conda".to_string(),
        Ecosystem::Conan => "Conan".to_string(),
        Ecosystem::Deb => "Debian".to_string(),
        Ecosystem::Rpm => "AlmaLinux".to_string(), // Or could be other RPM-based
        Ecosystem::Apk => "Alpine".to_string(),
        Ecosystem::Generic => "OSS-Fuzz".to_string(),
        Ecosystem::Unknown(s) => s.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_mapping() {
        assert_eq!(ecosystem_to_osv_string(&Ecosystem::Npm), "npm");
        assert_eq!(ecosystem_to_osv_string(&Ecosystem::PyPi), "PyPI");
        assert_eq!(ecosystem_to_osv_string(&Ecosystem::Cargo), "crates.io");
    }
}
