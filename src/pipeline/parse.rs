//! SBOM parsing and enrichment pipeline.
//!
//! Provides functions for parsing SBOMs with context and optional enrichment.

use crate::model::NormalizedSbom;
use anyhow::Result;
use std::path::Path;

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

    let path_display = path.display().to_string();

    let raw_content = std::fs::read_to_string(path).map_err(|e| {
        super::PipelineError::ParseFailed {
            path: path_display.clone(),
            source: e.into(),
        }
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
    crate::enrichment::OsvEnricherConfig {
        cache_dir: config
            .cache_dir
            .clone()
            .unwrap_or_else(super::dirs::osv_cache_dir),
        cache_ttl: std::time::Duration::from_secs(config.cache_ttl_hours * 3600),
        bypass_cache: config.bypass_cache,
        timeout: std::time::Duration::from_secs(config.timeout_secs),
        ..Default::default()
    }
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
        tracing::info!("Enriching SBOM with OSV vulnerability data...");
    }

    match OsvEnricher::new(config.clone()) {
        Ok(enricher) => {
            if !enricher.is_available() {
                tracing::warn!("OSV API unavailable, skipping vulnerability enrichment");
                return None;
            }

            // Get mutable references to components
            let components: Vec<_> = sbom.components.values().cloned().collect();
            let mut comp_vec: Vec<_> = components;

            match enricher.enrich(&mut comp_vec) {
                Ok(stats) => {
                    if !quiet {
                        tracing::info!(
                            "Enriched: {} components with vulns, {} total vulns found",
                            stats.components_with_vulns,
                            stats.total_vulns_found
                        );
                    }
                    // Update SBOM with enriched components
                    for comp in comp_vec {
                        sbom.components.insert(comp.canonical_id.clone(), comp);
                    }
                    Some(stats)
                }
                Err(e) => {
                    tracing::warn!("Failed to enrich SBOM: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to initialize OSV enricher: {}", e);
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
        tracing::info!("Enriching SBOM with end-of-life data from endoflife.date...");
    }

    match EolEnricher::new(config.clone()) {
        Ok(mut enricher) => {
            let components: Vec<_> = sbom.components.values().cloned().collect();
            let mut comp_vec = components;

            match enricher.enrich_components(&mut comp_vec) {
                Ok(stats) => {
                    if !quiet {
                        tracing::info!(
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
                    tracing::warn!("Failed to enrich SBOM with EOL data: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to initialize EOL enricher: {}", e);
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
}
