//! Configuration validation for sbom-tools.
//!
//! Provides validation traits and implementations for all configuration types.

use super::types::*;

// ============================================================================
// Configuration Error
// ============================================================================

/// Error type for configuration validation.
#[derive(Debug, Clone)]
pub struct ConfigError {
    /// The field that failed validation
    pub field: String,
    /// Description of the validation error
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// Validation Trait
// ============================================================================

/// Trait for validatable configuration types.
pub trait Validatable {
    /// Validate the configuration, returning any errors found.
    fn validate(&self) -> Vec<ConfigError>;

    /// Check if the configuration is valid.
    fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

// ============================================================================
// Validation Implementations
// ============================================================================

impl Validatable for AppConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        errors.extend(self.matching.validate());
        errors.extend(self.filtering.validate());
        errors.extend(self.output.validate());
        errors.extend(self.behavior.validate());
        errors.extend(self.tui.validate());

        if let Some(ref enrichment) = self.enrichment {
            errors.extend(enrichment.validate());
        }

        errors
    }
}

impl Validatable for MatchingConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        let valid_presets = ["strict", "balanced", "permissive", "security-focused"];
        if !valid_presets.contains(&self.fuzzy_preset.as_str()) {
            errors.push(ConfigError {
                field: "matching.fuzzy_preset".to_string(),
                message: format!(
                    "Invalid preset '{}'. Valid options: {}",
                    self.fuzzy_preset,
                    valid_presets.join(", ")
                ),
            });
        }

        if let Some(threshold) = self.threshold {
            if !(0.0..=1.0).contains(&threshold) {
                errors.push(ConfigError {
                    field: "matching.threshold".to_string(),
                    message: format!("Threshold must be between 0.0 and 1.0, got {}", threshold),
                });
            }
        }

        errors
    }
}

impl Validatable for FilterConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        if let Some(ref severity) = self.min_severity {
            let valid_severities = ["critical", "high", "medium", "low", "info"];
            if !valid_severities.contains(&severity.to_lowercase().as_str()) {
                errors.push(ConfigError {
                    field: "filtering.min_severity".to_string(),
                    message: format!(
                        "Invalid severity '{}'. Valid options: {}",
                        severity,
                        valid_severities.join(", ")
                    ),
                });
            }
        }
        errors
    }
}

impl Validatable for OutputConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        // Validate output file path if specified
        if let Some(ref file_path) = self.file {
            if let Some(parent) = file_path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    errors.push(ConfigError {
                        field: "output.file".to_string(),
                        message: format!("Parent directory does not exist: {}", parent.display()),
                    });
                }
            }
        }

        // Warn about contradictory streaming configuration
        if self.streaming.disabled && self.streaming.force {
            errors.push(ConfigError {
                field: "output.streaming".to_string(),
                message: "Contradictory streaming config: both 'disabled' and 'force' are true. \
                          'disabled' takes precedence."
                    .to_string(),
            });
        }

        errors
    }
}

impl Validatable for BehaviorConfig {
    fn validate(&self) -> Vec<ConfigError> {
        // BehaviorConfig contains only boolean flags that don't need validation
        Vec::new()
    }
}

impl Validatable for TuiConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        let valid_themes = ["dark", "light", "high-contrast"];
        if !valid_themes.contains(&self.theme.as_str()) {
            errors.push(ConfigError {
                field: "tui.theme".to_string(),
                message: format!(
                    "Invalid theme '{}'. Valid options: {}",
                    self.theme,
                    valid_themes.join(", ")
                ),
            });
        }

        if !(0.0..=1.0).contains(&self.initial_threshold) {
            errors.push(ConfigError {
                field: "tui.initial_threshold".to_string(),
                message: format!(
                    "Initial threshold must be between 0.0 and 1.0, got {}",
                    self.initial_threshold
                ),
            });
        }

        errors
    }
}

impl Validatable for EnrichmentConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        let valid_providers = ["osv", "nvd"];
        if !valid_providers.contains(&self.provider.as_str()) {
            errors.push(ConfigError {
                field: "enrichment.provider".to_string(),
                message: format!(
                    "Invalid provider '{}'. Valid options: {}",
                    self.provider,
                    valid_providers.join(", ")
                ),
            });
        }

        if self.max_concurrent == 0 {
            errors.push(ConfigError {
                field: "enrichment.max_concurrent".to_string(),
                message: "Max concurrent requests must be at least 1".to_string(),
            });
        }

        errors
    }
}

impl Validatable for DiffConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        // Validate paths exist
        if !self.paths.old.exists() {
            errors.push(ConfigError {
                field: "paths.old".to_string(),
                message: format!("File not found: {}", self.paths.old.display()),
            });
        }
        if !self.paths.new.exists() {
            errors.push(ConfigError {
                field: "paths.new".to_string(),
                message: format!("File not found: {}", self.paths.new.display()),
            });
        }

        // Validate nested configs
        errors.extend(self.matching.validate());
        errors.extend(self.filtering.validate());

        // Validate rules file if specified
        if let Some(ref rules_file) = self.rules.rules_file {
            if !rules_file.exists() {
                errors.push(ConfigError {
                    field: "rules.rules_file".to_string(),
                    message: format!("Rules file not found: {}", rules_file.display()),
                });
            }
        }

        // Validate ecosystem rules file if specified
        if let Some(ref config_file) = self.ecosystem_rules.config_file {
            if !config_file.exists() {
                errors.push(ConfigError {
                    field: "ecosystem_rules.config_file".to_string(),
                    message: format!("Ecosystem rules file not found: {}", config_file.display()),
                });
            }
        }

        errors
    }
}

impl Validatable for ViewConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        if !self.sbom_path.exists() {
            errors.push(ConfigError {
                field: "sbom_path".to_string(),
                message: format!("File not found: {}", self.sbom_path.display()),
            });
        }
        errors
    }
}

impl Validatable for MultiDiffConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        if !self.baseline.exists() {
            errors.push(ConfigError {
                field: "baseline".to_string(),
                message: format!("Baseline file not found: {}", self.baseline.display()),
            });
        }

        for (i, target) in self.targets.iter().enumerate() {
            if !target.exists() {
                errors.push(ConfigError {
                    field: format!("targets[{}]", i),
                    message: format!("Target file not found: {}", target.display()),
                });
            }
        }

        if self.targets.is_empty() {
            errors.push(ConfigError {
                field: "targets".to_string(),
                message: "At least one target SBOM is required".to_string(),
            });
        }

        errors.extend(self.matching.validate());
        errors
    }
}

impl Validatable for TimelineConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        for (i, path) in self.sbom_paths.iter().enumerate() {
            if !path.exists() {
                errors.push(ConfigError {
                    field: format!("sbom_paths[{}]", i),
                    message: format!("SBOM file not found: {}", path.display()),
                });
            }
        }

        if self.sbom_paths.len() < 2 {
            errors.push(ConfigError {
                field: "sbom_paths".to_string(),
                message: "Timeline analysis requires at least 2 SBOMs".to_string(),
            });
        }

        errors.extend(self.matching.validate());
        errors
    }
}

impl Validatable for MatrixConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        for (i, path) in self.sbom_paths.iter().enumerate() {
            if !path.exists() {
                errors.push(ConfigError {
                    field: format!("sbom_paths[{}]", i),
                    message: format!("SBOM file not found: {}", path.display()),
                });
            }
        }

        if self.sbom_paths.len() < 2 {
            errors.push(ConfigError {
                field: "sbom_paths".to_string(),
                message: "Matrix comparison requires at least 2 SBOMs".to_string(),
            });
        }

        if !(0.0..=1.0).contains(&self.cluster_threshold) {
            errors.push(ConfigError {
                field: "cluster_threshold".to_string(),
                message: format!(
                    "Cluster threshold must be between 0.0 and 1.0, got {}",
                    self.cluster_threshold
                ),
            });
        }

        errors.extend(self.matching.validate());
        errors
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matching_config_validation() {
        let config = MatchingConfig {
            fuzzy_preset: "balanced".to_string(),
            threshold: None,
            include_unchanged: false,
        };
        assert!(config.is_valid());

        let invalid = MatchingConfig {
            fuzzy_preset: "invalid".to_string(),
            threshold: None,
            include_unchanged: false,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_matching_config_threshold_validation() {
        let valid = MatchingConfig {
            fuzzy_preset: "balanced".to_string(),
            threshold: Some(0.85),
            include_unchanged: false,
        };
        assert!(valid.is_valid());

        let invalid = MatchingConfig {
            fuzzy_preset: "balanced".to_string(),
            threshold: Some(1.5),
            include_unchanged: false,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_filter_config_validation() {
        let config = FilterConfig {
            only_changes: true,
            min_severity: Some("high".to_string()),
            exclude_vex_resolved: false,
        };
        assert!(config.is_valid());

        let invalid = FilterConfig {
            only_changes: true,
            min_severity: Some("invalid".to_string()),
            exclude_vex_resolved: false,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_tui_config_validation() {
        let valid = TuiConfig::default();
        assert!(valid.is_valid());

        let invalid = TuiConfig {
            theme: "neon".to_string(),
            ..TuiConfig::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_enrichment_config_validation() {
        let valid = EnrichmentConfig::default();
        assert!(valid.is_valid());

        let invalid = EnrichmentConfig {
            max_concurrent: 0,
            ..EnrichmentConfig::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_config_error_display() {
        let error = ConfigError {
            field: "test_field".to_string(),
            message: "test error message".to_string(),
        };
        assert_eq!(error.to_string(), "test_field: test error message");
    }

    #[test]
    fn test_app_config_validation() {
        let valid = AppConfig::default();
        assert!(valid.is_valid());

        let mut invalid = AppConfig::default();
        invalid.matching.fuzzy_preset = "invalid".to_string();
        assert!(!invalid.is_valid());
    }
}
