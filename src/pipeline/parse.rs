//! SBOM parsing and enrichment pipeline.
//!
//! Provides functions for parsing SBOMs with context and optional enrichment.

use crate::model::NormalizedSbom;
use crate::parsers::MAX_SBOM_FILE_SIZE;
use anyhow::{Context, Result, bail};
use std::io::Read;
use std::path::Path;

/// The path token that selects standard input instead of a file.
pub const STDIN_PATH: &str = "-";

/// Returns true when `path` refers to standard input (the `-` token).
#[must_use]
pub fn is_stdin_path(path: &Path) -> bool {
    path.as_os_str() == STDIN_PATH
}

/// Read an SBOM input to a string, applying the [`MAX_SBOM_FILE_SIZE`] guard.
///
/// `path` of `"-"` reads the full document from standard input (for CI pipelines
/// that pipe an SBOM in-flight, e.g. `syft -o cyclonedx-json | sbom-tools quality -`);
/// any other path reads the file. Either way the result is capped at 512 MB so a
/// runaway input cannot exhaust memory.
pub fn read_input(path: &Path) -> Result<String> {
    if is_stdin_path(path) {
        let mut buf = String::new();
        let limit = MAX_SBOM_FILE_SIZE + 1;
        let read = std::io::stdin()
            .lock()
            .take(limit)
            .read_to_string(&mut buf)
            .context("Failed to read SBOM from stdin")?;
        if read as u64 > MAX_SBOM_FILE_SIZE {
            bail!(
                "SBOM on stdin exceeds the {} MB limit. Split the document or filter it (e.g. `sbom-tools tailor`) before piping.",
                MAX_SBOM_FILE_SIZE / (1024 * 1024),
            );
        }
        return Ok(buf);
    }

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size > MAX_SBOM_FILE_SIZE {
        bail!(
            "SBOM file {} is {} MB, exceeding the {} MB limit. Split the document or filter it (e.g. `sbom-tools tailor`) before processing.",
            path.display(),
            size / (1024 * 1024),
            MAX_SBOM_FILE_SIZE / (1024 * 1024),
        );
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read SBOM file {}", path.display()))
}

/// A parsed SBOM with optional enrichment stats
pub struct ParsedSbom {
    /// The normalized SBOM
    pub sbom: NormalizedSbom,
    /// Original file content, preserved for Source tab rendering
    pub raw_content: String,
    /// Enrichment statistics (if enrichment was performed)
    #[cfg(feature = "enrichment")]
    pub enrichment_stats: Option<crate::enrichment::EnrichmentStats>,
}

impl ParsedSbom {
    /// Create a new `ParsedSbom` without enrichment
    #[must_use]
    pub const fn new(sbom: NormalizedSbom, raw_content: String) -> Self {
        Self {
            sbom,
            raw_content,
            #[cfg(feature = "enrichment")]
            enrichment_stats: None,
        }
    }

    /// Get a reference to the SBOM
    #[must_use]
    pub const fn sbom(&self) -> &NormalizedSbom {
        &self.sbom
    }

    /// Get a mutable reference to the SBOM
    pub const fn sbom_mut(&mut self) -> &mut NormalizedSbom {
        &mut self.sbom
    }

    /// Get a reference to the original file content
    #[must_use]
    pub fn raw_content(&self) -> &str {
        &self.raw_content
    }

    /// Consume and return the inner SBOM
    #[must_use]
    pub fn into_sbom(self) -> NormalizedSbom {
        self.sbom
    }

    /// Consume and return both the SBOM and the raw content
    #[must_use]
    pub fn into_parts(self) -> (NormalizedSbom, String) {
        (self.sbom, self.raw_content)
    }

    /// Drop the raw content to free memory. Only the TUI Source tab needs it.
    pub fn drop_raw_content(&mut self) {
        self.raw_content = String::new();
    }
}

/// Parse an SBOM with context for error messages.
///
/// Returns a [`PipelineError::ParseFailed`] with the file path on failure.
pub fn parse_sbom_with_context(path: &Path, quiet: bool) -> Result<ParsedSbom> {
    if !quiet {
        tracing::info!("Parsing SBOM: {:?}", path);
    }

    let path_display = if is_stdin_path(path) {
        "<stdin>".to_string()
    } else {
        path.display().to_string()
    };

    let raw_content = read_input(path).map_err(|e| super::PipelineError::ParseFailed {
        path: path_display.clone(),
        source: e,
    })?;
    let sbom = crate::parsers::parse_sbom_str(&raw_content).map_err(|e| {
        super::PipelineError::ParseFailed {
            path: path_display,
            source: e.into(),
        }
    })?;

    if !quiet {
        tracing::info!("Parsed {} components", sbom.component_count());
    }

    sbom.log_collision_summary();

    Ok(ParsedSbom::new(sbom, raw_content))
}

/// Build an `OsvEnricherConfig` from the user-facing `EnrichmentConfig`.
///
/// Centralizes the config construction that was previously duplicated in CLI handlers.
#[cfg(feature = "enrichment")]
#[must_use]
pub fn build_enrichment_config(
    config: &crate::config::EnrichmentConfig,
) -> crate::enrichment::OsvEnricherConfig {
    let mut osv_config = crate::enrichment::OsvEnricherConfig {
        cache_dir: config
            .cache_dir
            .clone()
            .unwrap_or_else(super::dirs::osv_cache_dir),
        cache_ttl: std::time::Duration::from_secs(config.cache_ttl_hours * 3600),
        bypass_cache: config.bypass_cache,
        timeout: std::time::Duration::from_secs(config.timeout_secs),
        ..Default::default()
    };
    if let Some(ref api_base) = config.api_base {
        osv_config.api_base = api_base.clone();
    }
    osv_config
}

/// Run an enricher over an SBOM's components without deep-cloning the map.
///
/// `NormalizedSbom::components` is an `IndexMap<CanonicalId, Component>`; the
/// enricher APIs all want a contiguous `&mut [Component]` slice, which the map's
/// non-contiguous bucket storage cannot provide directly. Rather than the old
/// pattern of `values().cloned().collect()` (a full deep clone of every
/// component — doubling peak memory) followed by a reinsert, this moves the
/// entries out (`mem::take`, no clone), splits them into a key vec plus a
/// component slice the enricher mutates in place, then re-zips the original
/// keys back. Keys are never cloned and component values are moved, not cloned.
///
/// The enricher must not change any component's `canonical_id`; the OSV/EOL/
/// staleness enrichers only populate `vulnerabilities`/`eol`/`staleness`, so the
/// key↔value pairing is preserved by index.
#[cfg(feature = "enrichment")]
fn enrich_components_in_place<S, E, F>(sbom: &mut NormalizedSbom, enrich: F) -> Result<S, E>
where
    F: FnOnce(&mut [crate::model::Component]) -> Result<S, E>,
{
    let (keys, mut comps): (Vec<_>, Vec<crate::model::Component>) =
        std::mem::take(&mut sbom.components).into_iter().unzip();
    let result = enrich(&mut comps);
    sbom.components = keys.into_iter().zip(comps).collect();
    result
}

/// Enrich an SBOM with vulnerability data from OSV
#[cfg(feature = "enrichment")]
pub fn enrich_sbom(
    sbom: &mut NormalizedSbom,
    config: &crate::enrichment::OsvEnricherConfig,
    quiet: bool,
) -> Option<crate::enrichment::EnrichmentStats> {
    use crate::enrichment::{OsvEnricher, VulnerabilityEnricher};

    if !quiet {
        eprintln!(
            "Enriching SBOM with OSV vulnerability data ({} components)...",
            sbom.component_count()
        );
    }

    match OsvEnricher::new(config.clone()) {
        Ok(enricher) => {
            if !enricher.is_available() {
                eprintln!("Warning: OSV API unavailable, skipping vulnerability enrichment");
                return None;
            }

            match enrich_components_in_place(sbom, |comps| enricher.enrich(comps)) {
                Ok(stats) => {
                    if !quiet {
                        eprintln!(
                            "Enriched: {} components with vulns, {} total vulns found",
                            stats.components_with_vulns, stats.total_vulns_found
                        );
                    }
                    Some(stats)
                }
                Err(e) => {
                    eprintln!("Warning: vulnerability enrichment failed: {e}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: failed to initialize OSV enricher: {e}");
            None
        }
    }
}

/// Enrich an SBOM with end-of-life data from endoflife.date
#[cfg(feature = "enrichment")]
pub fn enrich_eol(
    sbom: &mut NormalizedSbom,
    config: &crate::enrichment::EolClientConfig,
    quiet: bool,
) -> Option<crate::enrichment::EolEnrichmentStats> {
    use crate::enrichment::EolEnricher;

    if !quiet {
        eprintln!("Enriching SBOM with end-of-life data from endoflife.date...");
    }

    match EolEnricher::new(config.clone()) {
        Ok(mut enricher) => {
            match enrich_components_in_place(sbom, |comps| enricher.enrich_components(comps)) {
                Ok(stats) => {
                    if !quiet {
                        eprintln!(
                            "EOL enrichment: {} enriched, {} EOL, {} approaching, {} supported, {} skipped",
                            stats.components_enriched,
                            stats.eol_count,
                            stats.approaching_eol_count,
                            stats.supported_count,
                            stats.skipped_count,
                        );
                    }
                    Some(stats)
                }
                Err(e) => {
                    eprintln!("Warning: EOL enrichment failed: {e}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: failed to initialize EOL enricher: {e}");
            None
        }
    }
}

/// Enrich an SBOM's vulnerabilities with CISA KEV (Known Exploited
/// Vulnerabilities) catalog data.
///
/// Sets `is_kev` / `kev_info` on every CVE-identified `VulnerabilityRef` that
/// matches the catalog. Returns enrichment stats, or `None` if the catalog
/// could not be loaded (non-fatal).
#[cfg(feature = "enrichment")]
pub fn enrich_kev(
    sbom: &mut NormalizedSbom,
    config: &crate::enrichment::KevClientConfig,
    quiet: bool,
) -> Option<crate::enrichment::KevEnrichmentStats> {
    use crate::enrichment::KevClient;

    if !quiet {
        eprintln!("Enriching SBOM with CISA KEV (actively exploited) catalog...");
    }

    let mut client = KevClient::new(config.clone());

    // Collect all vulnerability refs across components into one flat buffer so
    // the catalog is loaded once, then scatter the enriched refs back.
    let mut all_vulns: Vec<crate::model::VulnerabilityRef> = sbom
        .components
        .values()
        .flat_map(|c| c.vulnerabilities.iter().cloned())
        .collect();

    if all_vulns.is_empty() {
        return Some(crate::enrichment::KevEnrichmentStats::default());
    }

    match client.enrich_vulnerabilities(&mut all_vulns) {
        Ok(stats) => {
            if !quiet {
                eprintln!(
                    "KEV enrichment: {} matched ({} ransomware, {} overdue) from a {}-entry catalog",
                    stats.kev_matches,
                    stats.ransomware_related,
                    stats.overdue_count,
                    stats.catalog_size,
                );
            }
            // Index enriched refs by vulnerability id so we can re-apply the KEV
            // flags onto the per-component vulnerability lists.
            let mut by_id: std::collections::HashMap<String, &crate::model::VulnerabilityRef> =
                std::collections::HashMap::new();
            for v in &all_vulns {
                if v.is_kev {
                    by_id.insert(v.id.clone(), v);
                }
            }
            for comp in sbom.components.values_mut() {
                for vuln in &mut comp.vulnerabilities {
                    if let Some(enriched) = by_id.get(&vuln.id) {
                        vuln.is_kev = true;
                        vuln.kev_info = enriched.kev_info.clone();
                    }
                }
            }
            Some(stats)
        }
        Err(e) => {
            eprintln!("Warning: KEV enrichment failed: {e}");
            None
        }
    }
}

/// Enrich an SBOM's vulnerabilities with FIRST EPSS (Exploit Prediction Scoring
/// System) exploit-probability scores.
///
/// Sets `epss_score` / `epss_percentile` on every CVE-identified
/// `VulnerabilityRef` that matches the dataset. Returns enrichment stats, or
/// `None` if the dataset could not be loaded (non-fatal).
#[cfg(feature = "enrichment")]
pub fn enrich_epss(
    sbom: &mut NormalizedSbom,
    config: &crate::enrichment::EpssClientConfig,
    quiet: bool,
) -> Option<crate::enrichment::EpssEnrichmentStats> {
    use crate::enrichment::EpssClient;

    if !quiet {
        eprintln!("Enriching SBOM with FIRST EPSS (exploit-probability) scores...");
    }

    let mut client = EpssClient::new(config.clone());

    // Collect all vulnerability refs across components into one flat buffer so
    // the dataset is loaded once, then scatter the enriched scores back.
    let mut all_vulns: Vec<crate::model::VulnerabilityRef> = sbom
        .components
        .values()
        .flat_map(|c| c.vulnerabilities.iter().cloned())
        .collect();

    if all_vulns.is_empty() {
        return Some(crate::enrichment::EpssEnrichmentStats::default());
    }

    match client.enrich_vulnerabilities(&mut all_vulns) {
        Ok(stats) => {
            if !quiet {
                eprintln!(
                    "EPSS enrichment: {} matched ({} high-probability) from a {}-entry dataset",
                    stats.epss_matches, stats.high_probability, stats.dataset_size,
                );
            }
            // Index enriched refs by vulnerability id so we can re-apply the EPSS
            // scores onto the per-component vulnerability lists.
            let mut by_id: std::collections::HashMap<String, &crate::model::VulnerabilityRef> =
                std::collections::HashMap::new();
            for v in &all_vulns {
                if v.epss_score.is_some() {
                    by_id.insert(v.id.clone(), v);
                }
            }
            for comp in sbom.components.values_mut() {
                for vuln in &mut comp.vulnerabilities {
                    if let Some(enriched) = by_id.get(&vuln.id) {
                        vuln.epss_score = enriched.epss_score;
                        vuln.epss_percentile = enriched.epss_percentile;
                    }
                }
            }
            Some(stats)
        }
        Err(e) => {
            eprintln!("Warning: EPSS enrichment failed: {e}");
            None
        }
    }
}

/// Enrich an SBOM's components with dependency staleness data from package
/// registries (npm / `PyPI` / crates.io).
///
/// Populates `Component::staleness`, which feeds the Lifecycle quality metric.
/// Returns enrichment stats, or `None` on initialization failure (non-fatal).
#[cfg(feature = "enrichment")]
pub fn enrich_staleness(
    sbom: &mut NormalizedSbom,
    config: &crate::enrichment::RegistryConfig,
    quiet: bool,
) -> Option<crate::enrichment::StalenessEnrichmentStats> {
    use crate::enrichment::StalenessEnricher;

    if !quiet {
        eprintln!("Enriching SBOM with dependency staleness data from package registries...");
    }

    let mut enricher = StalenessEnricher::new(config.clone());

    match enrich_components_in_place(sbom, |comps| enricher.enrich_components(comps)) {
        Ok(stats) => {
            if !quiet {
                eprintln!(
                    "Staleness enrichment: {} enriched, {} stale, {} abandoned, {} deprecated, {} skipped",
                    stats.components_enriched,
                    stats.stale_count,
                    stats.abandoned_count,
                    stats.deprecated_count,
                    stats.skipped_count,
                );
            }
            Some(stats)
        }
        Err(e) => {
            eprintln!("Warning: staleness enrichment failed: {e}");
            None
        }
    }
}

/// Enrich an SBOM with VEX data from external OpenVEX documents.
///
/// Returns enrichment statistics if any VEX documents were successfully loaded.
#[cfg(feature = "enrichment")]
pub fn enrich_vex(
    sbom: &mut NormalizedSbom,
    vex_paths: &[std::path::PathBuf],
    quiet: bool,
) -> Option<crate::enrichment::VexEnrichmentStats> {
    if vex_paths.is_empty() {
        return None;
    }

    if !quiet {
        eprintln!(
            "Enriching SBOM with VEX data from {} document(s)...",
            vex_paths.len()
        );
    }

    match crate::enrichment::VexEnricher::from_files(vex_paths) {
        Ok(mut enricher) => {
            let stats = enricher.enrich_sbom(sbom);
            if !quiet {
                eprintln!(
                    "VEX enrichment: {} documents, {} statements, {} vulns matched, {} components",
                    stats.documents_loaded,
                    stats.statements_parsed,
                    stats.vulns_matched,
                    stats.components_with_vex,
                );
            }
            Some(stats)
        }
        Err(e) => {
            eprintln!("Warning: failed to load VEX documents: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "enrichment")]
    #[test]
    fn test_enrich_components_in_place_preserves_pairing() {
        use crate::model::{Component, VulnerabilityRef, VulnerabilitySource};

        // Three distinct components in a known insertion order.
        let mut sbom = NormalizedSbom::default();
        for name in ["alpha", "bravo", "charlie"] {
            sbom.add_component(Component::new(name.to_string(), format!("pkg:test/{name}")));
        }
        assert_eq!(sbom.component_count(), 3);

        // Enricher that only touches indices 0 and 2 — mirrors how the real
        // enrichers mutate a subset of the `&mut [Component]` slice in place.
        let result: Result<usize, std::convert::Infallible> =
            enrich_components_in_place(&mut sbom, |comps| {
                assert_eq!(comps.len(), 3);
                comps[0].vulnerabilities.push(VulnerabilityRef::new(
                    "CVE-A".into(),
                    VulnerabilitySource::Cve,
                ));
                comps[2].vulnerabilities.push(VulnerabilityRef::new(
                    "CVE-C".into(),
                    VulnerabilitySource::Cve,
                ));
                Ok(comps.len())
            });
        assert_eq!(result.unwrap(), 3);

        // Count, order, and key↔value pairing must survive the move-out/write-back.
        assert_eq!(sbom.component_count(), 3);
        let by_name: std::collections::HashMap<&str, &Component> = sbom
            .components
            .values()
            .map(|c| (c.name.as_str(), c))
            .collect();
        assert_eq!(by_name["alpha"].vulnerabilities.len(), 1);
        assert_eq!(by_name["alpha"].vulnerabilities[0].id, "CVE-A");
        assert!(by_name["bravo"].vulnerabilities.is_empty());
        assert_eq!(by_name["charlie"].vulnerabilities.len(), 1);
        assert_eq!(by_name["charlie"].vulnerabilities[0].id, "CVE-C");

        // Each component still maps to its own canonical id (no key/value swap).
        for (id, comp) in &sbom.components {
            assert_eq!(*id, comp.canonical_id);
        }
    }

    #[test]
    fn test_parsed_sbom_creation() {
        let sbom = NormalizedSbom::default();
        let parsed = ParsedSbom::new(sbom, String::new());
        assert_eq!(parsed.sbom().component_count(), 0);
    }

    #[test]
    fn test_parsed_sbom_into_sbom() {
        let sbom = NormalizedSbom::default();
        let parsed = ParsedSbom::new(sbom, String::new());
        let recovered = parsed.into_sbom();
        assert_eq!(recovered.component_count(), 0);
    }

    #[test]
    fn test_parsed_sbom_raw_content() {
        let sbom = NormalizedSbom::default();
        let parsed = ParsedSbom::new(sbom, "raw content".to_string());
        assert_eq!(parsed.raw_content(), "raw content");
    }

    #[test]
    fn test_parsed_sbom_into_parts() {
        let sbom = NormalizedSbom::default();
        let parsed = ParsedSbom::new(sbom, "test".to_string());
        let (recovered, raw) = parsed.into_parts();
        assert_eq!(recovered.component_count(), 0);
        assert_eq!(raw, "test");
    }

    #[test]
    fn test_is_stdin_path() {
        assert!(is_stdin_path(Path::new("-")));
        assert!(!is_stdin_path(Path::new("sbom.json")));
        assert!(!is_stdin_path(Path::new("./-")));
        assert!(!is_stdin_path(Path::new("-.json")));
    }

    #[test]
    fn test_read_input_reads_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("sbom_tools_read_input_test.json");
        std::fs::write(&path, "{\"hello\":\"world\"}").expect("write temp file");
        let content = read_input(&path).expect("read should succeed");
        assert_eq!(content, "{\"hello\":\"world\"}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_input_missing_file_errors() {
        let err = read_input(Path::new("/nonexistent/sbom_tools_missing.json"))
            .expect_err("missing file should error");
        assert!(err.to_string().contains("Failed to read SBOM file"));
    }
}
