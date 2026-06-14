//! Configuration types for the diff engine.

use crate::matching::CrossEcosystemConfig;

/// Configuration for large SBOM optimization.
#[derive(Debug, Clone)]
pub struct LargeSbomConfig {
    /// Minimum component count to enable LSH-based matching
    pub lsh_threshold: usize,
    /// Cross-ecosystem matching configuration
    pub cross_ecosystem: CrossEcosystemConfig,
    /// Maximum candidates per component
    pub max_candidates: usize,
}

impl Default for LargeSbomConfig {
    fn default() -> Self {
        Self {
            lsh_threshold: 500,
            cross_ecosystem: CrossEcosystemConfig::default(),
            max_candidates: 100,
        }
    }
}

impl LargeSbomConfig {
    /// Check if cross-ecosystem matching is enabled.
    #[must_use]
    pub const fn enable_cross_ecosystem(&self) -> bool {
        self.cross_ecosystem.enabled
    }

    /// Aggressive optimization for very large SBOMs (1000+)
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            lsh_threshold: 300,
            cross_ecosystem: CrossEcosystemConfig::default(),
            max_candidates: 50,
        }
    }

    /// Conservative settings (for accuracy over speed)
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            lsh_threshold: 1000,
            cross_ecosystem: CrossEcosystemConfig::disabled(),
            max_candidates: 150,
        }
    }
}
