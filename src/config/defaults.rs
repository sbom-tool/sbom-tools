//! Default configurations and presets for sbom-tools.
//!
//! Provides named presets for common use cases and default values.

use super::types::{AppConfig, MatchingConfig, OutputConfig, FilterConfig, BehaviorConfig, GraphAwareDiffConfig, MatchingRulesPathConfig, EcosystemRulesConfig, TuiConfig, EnrichmentConfig};

// ============================================================================
// Configuration Presets
// ============================================================================

/// Named configuration presets for common use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPreset {
    /// Default balanced settings suitable for most cases
    Default,
    /// Security-focused: strict matching, fail on vulnerabilities
    Security,
    /// CI/CD: machine-readable output, fail on changes
    CiCd,
    /// Permissive: loose matching for messy SBOMs
    Permissive,
    /// Strict: exact matching for well-maintained SBOMs
    Strict,
}

impl ConfigPreset {
    /// Get the preset name as a string.
    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Security => "security",
            Self::CiCd => "ci-cd",
            Self::Permissive => "permissive",
            Self::Strict => "strict",
        }
    }

    /// Parse a preset from a string name.
    #[must_use] 
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "default" | "balanced" => Some(Self::Default),
            "security" | "security-focused" => Some(Self::Security),
            "ci-cd" | "ci" | "cd" | "pipeline" => Some(Self::CiCd),
            "permissive" | "loose" => Some(Self::Permissive),
            "strict" | "exact" => Some(Self::Strict),
            _ => None,
        }
    }

    /// Get a description of this preset.
    #[must_use] 
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Default => "Balanced settings suitable for most SBOM comparisons",
            Self::Security => {
                "Strict matching with vulnerability detection and CI failure modes"
            }
            Self::CiCd => "Machine-readable output optimized for CI/CD pipelines",
            Self::Permissive => "Loose matching for SBOMs with inconsistent naming",
            Self::Strict => "Exact matching for well-maintained, consistent SBOMs",
        }
    }

    /// Get all available presets.
    #[must_use] 
    pub const fn all() -> &'static [Self] {
        &[
            Self::Default,
            Self::Security,
            Self::CiCd,
            Self::Permissive,
            Self::Strict,
        ]
    }
}

impl std::fmt::Display for ConfigPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Preset Implementations
// ============================================================================

impl AppConfig {
    /// Create an `AppConfig` from a named preset.
    #[must_use] 
    pub fn from_preset(preset: ConfigPreset) -> Self {
        match preset {
            ConfigPreset::Default => Self::default(),
            ConfigPreset::Security => Self::security_preset(),
            ConfigPreset::CiCd => Self::ci_cd_preset(),
            ConfigPreset::Permissive => Self::permissive_preset(),
            ConfigPreset::Strict => Self::strict_preset(),
        }
    }

    /// Security-focused preset.
    ///
    /// - Strict matching to avoid false negatives
    /// - Fail on new vulnerabilities
    /// - Enable typosquat detection
    #[must_use] 
    pub fn security_preset() -> Self {
        Self {
            matching: MatchingConfig {
                fuzzy_preset: "strict".to_string(),
                threshold: Some(0.9),
                include_unchanged: false,
            },
            output: OutputConfig::default(),
            filtering: FilterConfig::default(),
            behavior: BehaviorConfig {
                fail_on_vuln: true,
                fail_on_change: false,
                quiet: false,
                explain_matches: false,
                recommend_threshold: false,
            },
            graph_diff: GraphAwareDiffConfig::enabled(),
            rules: MatchingRulesPathConfig::default(),
            ecosystem_rules: EcosystemRulesConfig {
                config_file: None,
                disabled: false,
                detect_typosquats: true,
            },
            tui: TuiConfig::default(),
            enrichment: Some(EnrichmentConfig::default()),
        }
    }

    /// CI/CD pipeline preset.
    ///
    /// - JSON output for machine parsing
    /// - Fail on any changes
    /// - Quiet mode to reduce noise
    #[must_use] 
    pub fn ci_cd_preset() -> Self {
        use crate::reports::ReportFormat;

        Self {
            matching: MatchingConfig {
                fuzzy_preset: "balanced".to_string(),
                threshold: None,
                include_unchanged: false,
            },
            output: OutputConfig {
                format: ReportFormat::Json,
                file: None,
                report_types: crate::reports::ReportType::All,
                no_color: true,
                streaming: super::types::StreamingConfig::default(),
            },
            filtering: FilterConfig {
                only_changes: true,
                min_severity: None,
                exclude_vex_resolved: false,
            },
            behavior: BehaviorConfig {
                fail_on_vuln: true,
                fail_on_change: true,
                quiet: true,
                explain_matches: false,
                recommend_threshold: false,
            },
            graph_diff: GraphAwareDiffConfig::enabled(),
            rules: MatchingRulesPathConfig::default(),
            ecosystem_rules: EcosystemRulesConfig::default(),
            tui: TuiConfig::default(),
            enrichment: Some(EnrichmentConfig::default()),
        }
    }

    /// Permissive preset for messy SBOMs.
    ///
    /// - Low matching threshold
    /// - Include unchanged for full picture
    /// - No fail modes
    #[must_use] 
    pub fn permissive_preset() -> Self {
        Self {
            matching: MatchingConfig {
                fuzzy_preset: "permissive".to_string(),
                threshold: Some(0.6),
                include_unchanged: true,
            },
            output: OutputConfig::default(),
            filtering: FilterConfig::default(),
            behavior: BehaviorConfig::default(),
            graph_diff: GraphAwareDiffConfig::default(),
            rules: MatchingRulesPathConfig::default(),
            ecosystem_rules: EcosystemRulesConfig::default(),
            tui: TuiConfig::default(),
            enrichment: None,
        }
    }

    /// Strict preset for well-maintained SBOMs.
    ///
    /// - High matching threshold
    /// - Graph-aware diffing
    /// - Detailed explanations available
    #[must_use] 
    pub fn strict_preset() -> Self {
        Self {
            matching: MatchingConfig {
                fuzzy_preset: "strict".to_string(),
                threshold: Some(0.95),
                include_unchanged: false,
            },
            output: OutputConfig::default(),
            filtering: FilterConfig::default(),
            behavior: BehaviorConfig {
                fail_on_vuln: false,
                fail_on_change: false,
                quiet: false,
                explain_matches: false,
                recommend_threshold: false,
            },
            graph_diff: GraphAwareDiffConfig::enabled(),
            rules: MatchingRulesPathConfig::default(),
            ecosystem_rules: EcosystemRulesConfig::default(),
            tui: TuiConfig::default(),
            enrichment: None,
        }
    }
}

// ============================================================================
// Default Value Constants
// ============================================================================

/// Default matching threshold.
pub const DEFAULT_MATCHING_THRESHOLD: f64 = 0.8;

/// Default cluster threshold for matrix comparisons.
pub const DEFAULT_CLUSTER_THRESHOLD: f64 = 0.7;

/// Default cache TTL for enrichment in seconds.
pub const DEFAULT_ENRICHMENT_CACHE_TTL: u64 = 3600;

/// Default max concurrent requests for enrichment.
pub const DEFAULT_ENRICHMENT_MAX_CONCURRENT: usize = 10;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_names() {
        assert_eq!(ConfigPreset::Default.name(), "default");
        assert_eq!(ConfigPreset::Security.name(), "security");
        assert_eq!(ConfigPreset::CiCd.name(), "ci-cd");
    }

    #[test]
    fn test_preset_from_name() {
        assert_eq!(
            ConfigPreset::from_name("default"),
            Some(ConfigPreset::Default)
        );
        assert_eq!(
            ConfigPreset::from_name("security"),
            Some(ConfigPreset::Security)
        );
        assert_eq!(
            ConfigPreset::from_name("security-focused"),
            Some(ConfigPreset::Security)
        );
        assert_eq!(ConfigPreset::from_name("ci-cd"), Some(ConfigPreset::CiCd));
        assert_eq!(
            ConfigPreset::from_name("pipeline"),
            Some(ConfigPreset::CiCd)
        );
        assert_eq!(ConfigPreset::from_name("invalid"), None);
    }

    #[test]
    fn test_security_preset() {
        let config = AppConfig::security_preset();
        assert_eq!(config.matching.fuzzy_preset, "strict");
        assert!(config.behavior.fail_on_vuln);
        assert!(config.ecosystem_rules.detect_typosquats);
        assert!(config.enrichment.is_some());
    }

    #[test]
    fn test_ci_cd_preset() {
        let config = AppConfig::ci_cd_preset();
        assert!(config.behavior.fail_on_vuln);
        assert!(config.behavior.fail_on_change);
        assert!(config.behavior.quiet);
        assert!(config.output.no_color);
    }

    #[test]
    fn test_permissive_preset() {
        let config = AppConfig::permissive_preset();
        assert_eq!(config.matching.fuzzy_preset, "permissive");
        assert_eq!(config.matching.threshold, Some(0.6));
        assert!(config.matching.include_unchanged);
    }

    #[test]
    fn test_strict_preset() {
        let config = AppConfig::strict_preset();
        assert_eq!(config.matching.fuzzy_preset, "strict");
        assert_eq!(config.matching.threshold, Some(0.95));
        assert!(config.graph_diff.enabled);
    }

    #[test]
    fn test_from_preset() {
        let default = AppConfig::from_preset(ConfigPreset::Default);
        let security = AppConfig::from_preset(ConfigPreset::Security);

        assert_eq!(default.matching.fuzzy_preset, "balanced");
        assert_eq!(security.matching.fuzzy_preset, "strict");
    }

    #[test]
    fn test_all_presets() {
        let all = ConfigPreset::all();
        assert_eq!(all.len(), 5);
    }
}
