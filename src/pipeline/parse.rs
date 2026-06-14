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

            // Get mutable references to components
            let components: Vec<_> = sbom.components.values().cloned().collect();
            let mut comp_vec: Vec<_> = components;

            match enricher.enrich(&mut comp_vec) {
                Ok(stats) => {
                    if !quiet {
                        eprintln!(
                            "Enriched: {} components with vulns, {} total vulns found",
                            stats.components_with_vulns, stats.total_vulns_found
                        );
                    }
                    // Update SBOM with enriched components
                    for comp in comp_vec {
                        sbom.components.insert(comp.canonical_id.clone(), comp);
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
            let components: Vec<_> = sbom.components.values().cloned().collect();
            let mut comp_vec = components;

            match enricher.enrich_components(&mut comp_vec) {
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
                    // Update SBOM with enriched components
                    for comp in comp_vec {
                        sbom.components.insert(comp.canonical_id.clone(), comp);
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
    let mut comp_vec: Vec<_> = sbom.components.values().cloned().collect();

    match enricher.enrich_components(&mut comp_vec) {
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
            for comp in comp_vec {
                sbom.components.insert(comp.canonical_id.clone(), comp);
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
