//! Configuration types for the diff engine.

use crate::matching::CrossEcosystemConfig;

/// Method used for component assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum AssignmentMethod {
    /// Optimal assignment using Hungarian algorithm (Kuhn-Munkres)
    #[default]
    Hungarian,
    /// Greedy assignment with 2-opt swap optimization
    GreedyWithSwaps,
    /// Simple greedy assignment (fastest, may be suboptimal)
    Greedy,
}

/// Configuration for large SBOM optimization.
#[derive(Debug, Clone)]
pub struct LargeSbomConfig {
    /// Minimum component count to enable LSH-based matching
    pub lsh_threshold: usize,
    /// Cross-ecosystem matching configuration
    pub cross_ecosystem: CrossEcosystemConfig,
    /// Maximum candidates per component
    pub max_candidates: usize,
    /// Maximum problem size for Hungarian algorithm (falls back to greedy+swaps above this)
    pub hungarian_threshold: usize,
    /// Enable 2-opt swap optimization for greedy assignment
    pub enable_swap_optimization: bool,
    /// Maximum swap iterations for 2-opt optimization
    pub max_swap_iterations: usize,
}

impl Default for LargeSbomConfig {
    fn default() -> Self {
        Self {
            lsh_threshold: 500,
            cross_ecosystem: CrossEcosystemConfig::default(),
            max_candidates: 100,
            hungarian_threshold: 5000,
            enable_swap_optimization: true,
            max_swap_iterations: 100,
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
            hungarian_threshold: 3000,
            enable_swap_optimization: true,
            max_swap_iterations: 50,
        }
    }

    /// Conservative settings (for accuracy over speed)
    #[must_use] 
    pub fn conservative() -> Self {
        Self {
            lsh_threshold: 1000,
            cross_ecosystem: CrossEcosystemConfig::disabled(),
            max_candidates: 150,
            hungarian_threshold: 10000,
            enable_swap_optimization: true,
            max_swap_iterations: 200,
        }
    }
}
