//! Enrichment traits for extensibility.
//!
//! This module provides the `VulnerabilityEnricher` trait for adding
//! vulnerability information to SBOM components, along with implementations.

use crate::enrichment::EnrichmentStats;
use crate::error::Result;
use crate::model::Component;

/// Trait for vulnerability enrichers.
///
/// Implement this trait to add new vulnerability data sources.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::enrichment::{VulnerabilityEnricher, NoOpEnricher, OsvEnricher};
///
/// // Use NoOpEnricher when enrichment is disabled
/// let enricher: Box<dyn VulnerabilityEnricher> = if config.enabled {
///     Box::new(OsvEnricher::new(osv_config)?)
/// } else {
///     Box::new(NoOpEnricher)
/// };
///
/// let stats = enricher.enrich(&mut components)?;
/// ```
pub trait VulnerabilityEnricher: Send + Sync {
    /// Enrich components with vulnerability information.
    ///
    /// This method modifies the components in place, adding vulnerability
    /// references to each component based on external data sources.
    fn enrich(&self, components: &mut [Component]) -> Result<EnrichmentStats>;

    /// Get the name of this enricher (e.g., "OSV", "NVD").
    fn name(&self) -> &'static str;

    /// Check if the enricher's data source is available.
    ///
    /// Returns true if the API/database is reachable.
    fn is_available(&self) -> bool;
}

/// A no-operation enricher that does nothing.
///
/// Use this when vulnerability enrichment is disabled or unavailable.
/// It implements the Null Object pattern, allowing code to use the
/// `VulnerabilityEnricher` trait without null checks.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::enrichment::{VulnerabilityEnricher, NoOpEnricher};
///
/// let enricher = NoOpEnricher;
/// assert!(!enricher.is_available());
///
/// let stats = enricher.enrich(&mut components)?;
/// assert_eq!(stats.components_checked, 0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpEnricher;

impl NoOpEnricher {
    /// Create a new no-op enricher.
    pub fn new() -> Self {
        Self
    }
}

impl VulnerabilityEnricher for NoOpEnricher {
    fn enrich(&self, _components: &mut [Component]) -> Result<EnrichmentStats> {
        Ok(EnrichmentStats::empty())
    }

    fn name(&self) -> &'static str {
        "NoOp"
    }

    fn is_available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_enricher_creation() {
        let enricher = NoOpEnricher::new();
        assert_eq!(enricher.name(), "NoOp");
        assert!(!enricher.is_available());
    }

    #[test]
    fn test_noop_enricher_does_nothing() {
        let enricher = NoOpEnricher;
        let mut components = vec![];
        let stats = enricher.enrich(&mut components).unwrap();
        assert_eq!(stats.components_checked(), 0);
    }

    #[test]
    fn test_noop_enricher_default() {
        let enricher = NoOpEnricher::default();
        assert!(!enricher.is_available());
    }
}
