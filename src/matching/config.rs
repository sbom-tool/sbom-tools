//! Fuzzy matching configuration.

use serde::{Deserialize, Serialize};

/// Configuration for fuzzy matching behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyMatchConfig {
    /// Minimum confidence threshold (0.0 - 1.0)
    pub threshold: f64,
    /// Weight for Levenshtein distance component
    pub levenshtein_weight: f64,
    /// Weight for Jaro-Winkler similarity component
    pub jaro_winkler_weight: f64,
    /// Whether to use alias table lookups
    pub use_aliases: bool,
    /// Whether to use ecosystem-specific rules
    pub use_ecosystem_rules: bool,
    /// Maximum candidates to consider for fuzzy matching
    pub max_candidates: usize,
    /// Multi-field scoring weights (optional, enables multi-field matching when set)
    #[serde(default)]
    pub field_weights: Option<MultiFieldWeights>,
}

/// Weights for multi-field scoring.
///
/// All weights should sum to 1.0 for normalized scoring.
/// Fields with weight 0.0 are ignored in matching.
///
/// Penalty fields (negative values) are applied on top of the weighted score
/// to penalize mismatches more strongly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiFieldWeights {
    /// Weight for name similarity (primary field)
    pub name: f64,
    /// Weight for version match (exact match gives full score)
    pub version: f64,
    /// Weight for ecosystem match (exact match gives full score)
    pub ecosystem: f64,
    /// Weight for license overlap (Jaccard similarity of license sets)
    pub licenses: f64,
    /// Weight for supplier/publisher match
    pub supplier: f64,
    /// Weight for group/namespace match
    pub group: f64,

    // Penalty fields (applied on top of weighted score)

    /// Penalty applied when ecosystems are different (negative value, e.g., -0.15)
    #[serde(default)]
    pub ecosystem_mismatch_penalty: f64,
    /// Enable graduated version scoring based on semver distance
    #[serde(default = "default_true")]
    pub version_divergence_enabled: bool,
    /// Penalty per major version difference (e.g., 0.10 = 10% per major)
    #[serde(default = "default_version_major_penalty")]
    pub version_major_penalty: f64,
    /// Penalty per minor version difference, capped (e.g., 0.02 = 2% per minor)
    #[serde(default = "default_version_minor_penalty")]
    pub version_minor_penalty: f64,
}

const fn default_true() -> bool {
    true
}

const fn default_version_major_penalty() -> f64 {
    0.10
}

const fn default_version_minor_penalty() -> f64 {
    0.02
}

impl MultiFieldWeights {
    /// Default weights emphasizing name matching.
    #[must_use] 
    pub const fn name_focused() -> Self {
        Self {
            name: 0.80,
            version: 0.05,
            ecosystem: 0.10,
            licenses: 0.03,
            supplier: 0.01,
            group: 0.01,
            ecosystem_mismatch_penalty: -0.15,
            version_divergence_enabled: true,
            version_major_penalty: 0.10,
            version_minor_penalty: 0.02,
        }
    }

    /// Balanced weights across all fields.
    #[must_use] 
    pub const fn balanced() -> Self {
        Self {
            name: 0.60,
            version: 0.10,
            ecosystem: 0.15,
            licenses: 0.08,
            supplier: 0.04,
            group: 0.03,
            ecosystem_mismatch_penalty: -0.15, // Applied on top of weighted score
            version_divergence_enabled: true,
            version_major_penalty: 0.10,
            version_minor_penalty: 0.02,
        }
    }

    /// Weights for security-focused matching (emphasizes ecosystem and version).
    #[must_use] 
    pub const fn security_focused() -> Self {
        Self {
            name: 0.50,
            version: 0.20,
            ecosystem: 0.20,
            licenses: 0.05,
            supplier: 0.03,
            group: 0.02,
            ecosystem_mismatch_penalty: -0.25, // Stricter penalty
            version_divergence_enabled: true,
            version_major_penalty: 0.15, // Higher penalty for major version diff
            version_minor_penalty: 0.03,
        }
    }

    /// Legacy weights with no penalties (for backward compatibility).
    ///
    /// Use this preset when you want the old binary scoring behavior
    /// without ecosystem mismatch penalties or version divergence scoring.
    #[must_use] 
    pub const fn legacy() -> Self {
        Self {
            name: 0.60,
            version: 0.10,
            ecosystem: 0.15,
            licenses: 0.08,
            supplier: 0.04,
            group: 0.03,
            ecosystem_mismatch_penalty: 0.0, // No penalty
            version_divergence_enabled: false, // Binary scoring
            version_major_penalty: 0.0,
            version_minor_penalty: 0.0,
        }
    }

    /// Check if weights are properly normalized (sum to ~1.0).
    /// Note: Penalty fields are not included in normalization check.
    #[must_use] 
    pub fn is_normalized(&self) -> bool {
        let sum =
            self.name + self.version + self.ecosystem + self.licenses + self.supplier + self.group;
        (sum - 1.0).abs() < 0.001
    }

    /// Normalize weights to sum to 1.0.
    /// Note: Penalty fields are not affected by normalization.
    pub fn normalize(&mut self) {
        let sum =
            self.name + self.version + self.ecosystem + self.licenses + self.supplier + self.group;
        if sum > 0.0 {
            self.name /= sum;
            self.version /= sum;
            self.ecosystem /= sum;
            self.licenses /= sum;
            self.supplier /= sum;
            self.group /= sum;
        }
    }
}

impl Default for MultiFieldWeights {
    fn default() -> Self {
        Self::balanced()
    }
}

impl FuzzyMatchConfig {
    /// Strict matching for security-critical scenarios
    #[must_use] 
    pub const fn strict() -> Self {
        Self {
            threshold: 0.95,
            levenshtein_weight: 0.5,
            jaro_winkler_weight: 0.5,
            use_aliases: true,
            use_ecosystem_rules: true,
            max_candidates: 100,
            field_weights: None, // Single-field (name) matching by default
        }
    }

    /// Balanced matching for general diff operations
    #[must_use] 
    pub const fn balanced() -> Self {
        Self {
            threshold: 0.85,
            levenshtein_weight: 0.4,
            jaro_winkler_weight: 0.6,
            use_aliases: true,
            use_ecosystem_rules: true,
            max_candidates: 500,
            field_weights: None, // Single-field (name) matching by default
        }
    }

    /// Permissive matching for discovery/exploration
    #[must_use] 
    pub const fn permissive() -> Self {
        Self {
            threshold: 0.70,
            levenshtein_weight: 0.3,
            jaro_winkler_weight: 0.7,
            use_aliases: true,
            use_ecosystem_rules: true,
            max_candidates: 1000,
            field_weights: None, // Single-field (name) matching by default
        }
    }

    /// Enable multi-field scoring with the given weights.
    #[must_use]
    pub const fn with_multi_field(mut self, weights: MultiFieldWeights) -> Self {
        self.field_weights = Some(weights);
        self
    }

    /// Set a custom threshold value.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Strict matching with multi-field scoring for security scenarios.
    #[must_use] 
    pub const fn strict_multi_field() -> Self {
        Self::strict().with_multi_field(MultiFieldWeights::security_focused())
    }

    /// Balanced matching with multi-field scoring.
    #[must_use] 
    pub const fn balanced_multi_field() -> Self {
        Self::balanced().with_multi_field(MultiFieldWeights::balanced())
    }

    /// Create config from a preset name.
    ///
    /// Supported presets:
    /// - "strict", "balanced", "permissive" - single-field (name only)
    /// - "strict-multi", "balanced-multi" - multi-field scoring enabled
    #[must_use] 
    pub fn from_preset(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "strict" => Some(Self::strict()),
            "balanced" => Some(Self::balanced()),
            "permissive" => Some(Self::permissive()),
            "strict-multi" | "strict_multi" => Some(Self::strict_multi_field()),
            "balanced-multi" | "balanced_multi" => Some(Self::balanced_multi_field()),
            _ => None,
        }
    }
}

impl Default for FuzzyMatchConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

/// Configuration for cross-ecosystem matching.
///
/// Cross-ecosystem matching allows components to be matched across different
/// package ecosystems (e.g., npm vs `PyPI`) when they represent the same
/// underlying library. This is enabled by default with conservative settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossEcosystemConfig {
    /// Whether cross-ecosystem matching is enabled
    pub enabled: bool,
    /// Minimum score required for cross-ecosystem matches
    pub min_score: f64,
    /// Score penalty applied to cross-ecosystem matches
    pub score_penalty: f64,
    /// Maximum number of cross-ecosystem candidates per component
    pub max_candidates: usize,
    /// Only use verified cross-ecosystem mappings (stricter)
    pub verified_only: bool,
}

impl Default for CrossEcosystemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_score: 0.80,
            score_penalty: 0.10,
            max_candidates: 10,
            verified_only: false,
        }
    }
}

impl CrossEcosystemConfig {
    /// Disabled cross-ecosystem matching.
    #[must_use] 
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Strict settings for high-confidence matches only.
    #[must_use] 
    pub const fn strict() -> Self {
        Self {
            enabled: true,
            min_score: 0.90,
            score_penalty: 0.15,
            max_candidates: 5,
            verified_only: true,
        }
    }

    /// Permissive settings for discovery/exploration.
    #[must_use] 
    pub const fn permissive() -> Self {
        Self {
            enabled: true,
            min_score: 0.70,
            score_penalty: 0.05,
            max_candidates: 20,
            verified_only: false,
        }
    }
}
