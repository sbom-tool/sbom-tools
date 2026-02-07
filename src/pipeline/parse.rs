//! SBOM parsing and enrichment pipeline.
//!
//! Provides functions for parsing SBOMs with context and optional enrichment.

use crate::model::NormalizedSbom;
use anyhow::{Context, Result};
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

/// Parse an SBOM with context for error messages
pub fn parse_sbom_with_context(path: &Path, quiet: bool) -> Result<ParsedSbom> {
    if !quiet {
        tracing::info!("Parsing SBOM: {:?}", path);
    }

    let raw_content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read SBOM file: {}", path.display()))?;
    let sbom = crate::parsers::parse_sbom_str(&raw_content)
        .with_context(|| format!("Failed to parse SBOM: {}", path.display()))?;

    if !quiet {
        tracing::info!("Parsed {} components", sbom.component_count());
    }

    sbom.log_collision_summary();

    Ok(ParsedSbom::new(sbom, raw_content))
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
