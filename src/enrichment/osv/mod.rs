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
use crate::model::{Component, Ecosystem, VulnerabilityRef};
use response::{OsvQuery, OsvVulnerability};
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
    /// Maximum retries for failed requests
    pub max_retries: u8,
}

impl Default for OsvEnricherConfig {
    fn default() -> Self {
        Self {
            cache_dir: crate::enrichment::source::namespaced_cache_dir("osv"),
            cache_ttl: Duration::from_secs(24 * 3600),
            bypass_cache: false,
            timeout: Duration::from_secs(30),
            api_base: "https://api.osv.dev".to_string(),
            max_retries: 3,
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
            max_retries: config.max_retries,
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
        // Skip cryptographic assets — they are not software packages and would
        // produce false positives when queried against vulnerability databases.
        if component.component_type == crate::model::ComponentType::Cryptographic {
            return None;
        }

        let cache_key = CacheKey::new(
            component.identifiers.purl.clone(),
            component.name.clone(),
            component.ecosystem.as_ref().map(ecosystem_to_osv_string),
            component.version.clone(),
        );

        // Prefer PURL if available. A `pkg:huggingface` PURL is forwarded as-is:
        // OSV does not index the HuggingFace ecosystem, so it simply returns no
        // vulns (harmless), but routing the query keeps the component in the
        // pipeline rather than counting it as skipped, and exploitability for
        // ML models is supplied downstream by KEV/advisory linkage on any
        // identifier-referenced CVEs (see `merge_vulnerabilities` consumers).
        if let Some(ref purl) = component.identifiers.purl {
            return Some((cache_key, OsvQuery::from_purl(purl.clone())));
        }

        // Fallback to name + ecosystem + version. Skip ecosystems OSV cannot
        // resolve (empty string) — e.g. HuggingFace — so we never send a query
        // that OSV would reject or, worse, silently mis-key.
        if let (Some(ecosystem), Some(version)) = (&component.ecosystem, &component.version) {
            let osv_ecosystem = ecosystem_to_osv_string(ecosystem);
            if osv_ecosystem.is_empty() {
                return None;
            }
            return Some((
                cache_key,
                OsvQuery::from_package(component.name.clone(), osv_ecosystem, version.clone()),
            ));
        }

        None
    }

    /// Cache key for an individual vulnerability record.
    fn vuln_cache_key(vuln_id: &str) -> CacheKey {
        CacheKey::new(None, format!("osv-vuln:{vuln_id}"), None, None)
    }

    /// Hydrate querybatch stubs into full vulnerability records.
    ///
    /// The `/v1/querybatch` endpoint returns only `{id, modified}` per
    /// vulnerability, so each record is fetched from `/v1/vulns/{id}` (or the
    /// per-vulnerability cache) before mapping. Returns the mapped
    /// vulnerabilities and whether every record was fully hydrated; records
    /// that could not be fetched fall back to the id-only stub.
    fn hydrate_vulns(
        &self,
        stubs: &[OsvVulnerability],
        stats: &mut EnrichmentStats,
    ) -> (Vec<VulnerabilityRef>, bool) {
        let mut vulns = Vec::with_capacity(stubs.len());
        let mut complete = true;

        for stub in stubs {
            let key = Self::vuln_cache_key(&stub.id);

            if !self.bypass_cache
                && let Some(cached) = self.cache.get(&key)
                && let Some(vuln) = cached.into_iter().next()
            {
                stats.cache_hits += 1;
                vulns.push(vuln);
                continue;
            }

            stats.api_calls += 1;
            match self.client.get_vulnerability(&stub.id) {
                Ok(Some(full)) => {
                    let vuln = mapper::map_osv_to_vulnerability_ref(&full);
                    if let Err(e) = self.cache.set(&key, std::slice::from_ref(&vuln)) {
                        stats
                            .errors
                            .push(EnrichmentError::CacheError(e.to_string()));
                    }
                    vulns.push(vuln);
                }
                Ok(None) => {
                    complete = false;
                    vulns.push(mapper::map_osv_to_vulnerability_ref(stub));
                }
                Err(e) => {
                    complete = false;
                    stats.errors.push(EnrichmentError::ApiError(e.to_string()));
                    vulns.push(mapper::map_osv_to_vulnerability_ref(stub));
                }
            }
        }

        (vulns, complete)
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
        let mut cached_results: Vec<(usize, Vec<VulnerabilityRef>)> = Vec::new();
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
                merge_vulnerabilities(&mut components[idx], vulns);
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
                        let (vulns, complete) = self.hydrate_vulns(&result.vulns, &mut stats);

                        // Cache the result (even if empty), but only when
                        // fully hydrated so failures are retried next run
                        if complete && let Err(e) = self.cache.set(&key, &vulns) {
                            stats
                                .errors
                                .push(EnrichmentError::CacheError(e.to_string()));
                        }

                        if !vulns.is_empty() {
                            stats.components_with_vulns += 1;
                            stats.total_vulns_found += vulns.len();
                            merge_vulnerabilities(&mut components[idx], vulns);
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

/// Append vulnerabilities to a component, skipping ids it already carries so
/// repeated enrichment runs are idempotent.
fn merge_vulnerabilities(component: &mut Component, vulns: Vec<VulnerabilityRef>) {
    let mut seen: std::collections::HashSet<String> = component
        .vulnerabilities
        .iter()
        .map(|v| v.id.clone())
        .collect();
    for vuln in vulns {
        if seen.insert(vuln.id.clone()) {
            component.vulnerabilities.push(vuln);
        }
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
        // OSV (osv.dev) has NO ecosystem for HuggingFace / ML models. Returning
        // an empty string is the honest signal "OSV cannot resolve this by
        // name+ecosystem". A `pkg:huggingface` PURL query is still forwarded
        // (OSV returns nothing for it), and real exploitability data for ML
        // components comes from KEV/advisory linkage on CVE identifiers the
        // model already carries — not from an OSV ecosystem lookup.
        Ecosystem::HuggingFace => String::new(),
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

    #[test]
    fn huggingface_has_no_osv_ecosystem_string() {
        // OSV does not index HuggingFace; the honest mapping is an empty string
        // so `build_query` never sends a name+ecosystem query OSV would reject.
        assert!(ecosystem_to_osv_string(&Ecosystem::HuggingFace).is_empty());
    }

    fn test_enricher() -> OsvEnricher {
        let dir = std::env::temp_dir().join(format!("osv-test-{}", std::process::id()));
        OsvEnricher::new(OsvEnricherConfig {
            cache_dir: dir,
            ..Default::default()
        })
        .expect("enricher")
    }

    #[test]
    fn build_query_forwards_huggingface_purl() {
        use crate::model::{Component, ComponentType};
        let enricher = test_enricher();

        let mut comp = Component::new("bert".to_string(), "ml-1".to_string())
            .with_purl("pkg:huggingface/google-bert/bert-base-uncased".to_string());
        comp.component_type = ComponentType::MachineLearningModel;

        // The HuggingFace PURL resolves to Ecosystem::HuggingFace...
        assert_eq!(comp.ecosystem, Some(Ecosystem::HuggingFace));
        // ...and OSV enrichment is still ATTEMPTED via the PURL query (not skipped),
        // so the model participates in the exploitability pipeline.
        let query = enricher.build_query(&comp);
        assert!(
            matches!(query, Some((_, OsvQuery::Purl { .. }))),
            "HuggingFace model with a PURL must be queried by PURL"
        );
    }

    #[test]
    fn build_query_skips_huggingface_name_fallback() {
        use crate::model::{Component, ComponentType, Ecosystem};
        let enricher = test_enricher();

        // No PURL — only ecosystem + version. OSV cannot resolve HuggingFace by
        // name+ecosystem, so we must NOT fabricate a garbage query.
        let mut comp = Component::new("bert".to_string(), "ml-2".to_string());
        comp.component_type = ComponentType::MachineLearningModel;
        comp.ecosystem = Some(Ecosystem::HuggingFace);
        comp.version = Some("v1".to_string());

        assert!(
            enricher.build_query(&comp).is_none(),
            "HuggingFace without a PURL must not emit a name+ecosystem OSV query"
        );
    }
}
