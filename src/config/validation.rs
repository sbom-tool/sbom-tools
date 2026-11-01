//! Configuration validation for sbom-tools.
//!
//! Provides validation traits and implementations for all configuration types.

use super::types::{
    AppConfig, BehaviorConfig, ComplianceConfig, DiffConfig, EnrichmentConfig, FilterConfig,
    MatchingConfig, MatrixConfig, MultiDiffConfig, OutputConfig, TimelineConfig, TuiConfig,
    ViewConfig,
};

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
        errors.extend(self.compliance.validate());

        if let Some(ref enrichment) = self.enrichment {
            errors.extend(enrichment.validate());
        }

        errors
    }
}

impl Validatable for MatchingConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        // fuzzy_preset: FuzzyPreset enum makes invalid values unrepresentable at parse time

        if let Some(threshold) = self.threshold
            && !(0.0..=1.0).contains(&threshold)
        {
            errors.push(ConfigError {
                field: "matching.threshold".to_string(),
                message: format!("Threshold must be between 0.0 and 1.0, got {threshold}"),
            });
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
        if let Some(ref file_path) = self.file
            && let Some(parent) = file_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            errors.push(ConfigError {
                field: "output.file".to_string(),
                message: format!("Parent directory does not exist: {}", parent.display()),
            });
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

impl Validatable for ComplianceConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        // Standards and profile parse through the same alias-aware parsers
        // the CLI flags use, so a config typo fails at load time with the
        // exact list of valid values.
        for (i, standard) in self.standards.iter().enumerate() {
            if let Err(e) = standard.parse::<crate::quality::StandardSelector>() {
                errors.push(ConfigError {
                    field: format!("compliance.standards[{i}]"),
                    message: e,
                });
            }
        }

        if let Some(ref profile) = self.profile
            && let Err(e) = profile.parse::<crate::quality::ScoringProfile>()
        {
            errors.push(ConfigError {
                field: "compliance.profile".to_string(),
                message: e,
            });
        }

        if let Some(min_score) = self.min_score
            && !(0.0..=100.0).contains(&min_score)
        {
            errors.push(ConfigError {
                field: "compliance.min_score".to_string(),
                message: format!("min_score must be between 0 and 100, got {min_score}"),
            });
        }

        if let Some(ref class) = self.cra_product_class
            && let Err(message) = crate::model::CraProductClass::parse_cli_strict(class)
        {
            errors.push(ConfigError {
                field: "compliance.cra_product_class".to_string(),
                message,
            });
        }

        // Rule settings and `fail_on` name rules as `--rule` and
        // `--fail-on` do: a typo'd id fails here, naming the closest one.
        for (rule_id, setting) in &self.rules {
            let result = setting
                .parse::<crate::quality::RuleSetting>()
                .and_then(|setting| {
                    crate::quality::RuleSettings::new()
                        .set(rule_id, setting, crate::quality::SettingSource::Config)
                        .map(|_| ())
                });
            if let Err(message) = result {
                errors.push(ConfigError {
                    field: format!("compliance.rules.{rule_id}"),
                    message,
                });
            }
        }
        for (i, rule_id) in self.fail_on.iter().enumerate() {
            let result = crate::quality::resolve_rule_id(rule_id).and_then(|id| {
                if crate::quality::rule_kind(id) == Some(crate::quality::RuleKind::Pass) {
                    Err(format!(
                        "{id} reports passed checks, never a finding, so it can never fail a run"
                    ))
                } else {
                    Ok(())
                }
            });
            if let Err(message) = result {
                errors.push(ConfigError {
                    field: format!("compliance.fail_on[{i}]"),
                    message,
                });
            }
        }

        // The PQC defaults take the `--pqc-*` value names. A profile or a
        // category is a deadline-mode default, as on the command line.
        let pqc_mode = check_value_enum::<crate::quality::PqcMode>(
            &mut errors,
            "compliance.pqc_mode",
            self.pqc_mode.as_deref(),
        );
        check_value_enum::<crate::quality::PqcProfile>(
            &mut errors,
            "compliance.pqc_profile",
            self.pqc_profile.as_deref(),
        );
        check_value_enum::<crate::quality::CnsaCategory>(
            &mut errors,
            "compliance.cnsa_category",
            self.cnsa_category.as_deref(),
        );
        if pqc_mode != Some(crate::quality::PqcMode::Deadline) {
            for (field, value) in [
                ("compliance.pqc_profile", &self.pqc_profile),
                ("compliance.cnsa_category", &self.cnsa_category),
            ] {
                if value.is_some() {
                    errors.push(ConfigError {
                        field: field.to_string(),
                        message: "applies only with `compliance.pqc_mode: deadline`".to_string(),
                    });
                }
            }
        }

        errors
    }
}

/// Parse `value` as a `ValueEnum` flag value (any case), recording an error
/// for `field` when it names none. Returns the parsed value.
fn check_value_enum<T: clap::ValueEnum>(
    errors: &mut Vec<ConfigError>,
    field: &str,
    value: Option<&str>,
) -> Option<T> {
    let value = value?;
    match T::from_str(value, true) {
        Ok(parsed) => Some(parsed),
        Err(_) => {
            let valid: Vec<String> = T::value_variants()
                .iter()
                .filter_map(|v| v.to_possible_value())
                .map(|v| v.get_name().to_string())
                .collect();
            errors.push(ConfigError {
                field: field.to_string(),
                message: format!(
                    "invalid value '{value}'; valid values: {}",
                    valid.join(", ")
                ),
            });
            None
        }
    }
}

impl Validatable for TuiConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();

        // theme: ThemeName enum makes invalid values unrepresentable at parse time

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

        // Keep the validator in lockstep with the published JSON Schema
        // (`schemars(range(min = 1))`): a TTL or timeout of 0 must fail
        // `config check`, not silently disable caching / hang requests.
        if self.cache_ttl_hours == 0 {
            errors.push(ConfigError {
                field: "enrichment.cache_ttl_hours".to_string(),
                message: "Cache TTL must be at least 1 hour".to_string(),
            });
        }

        if self.timeout_secs == 0 {
            errors.push(ConfigError {
                field: "enrichment.timeout_secs".to_string(),
                message: "API timeout must be at least 1 second".to_string(),
            });
        }

        // Every URL override must be a well-formed http(s) URL with a host.
        // These point the enricher at a network endpoint that supplies
        // SECURITY data (which CVEs affect you); an unvalidated override could
        // otherwise be a non-http scheme (file://, etc.) or a malformed URL.
        // Private/self-hosted hosts are intentionally allowed (legitimate
        // internal mirrors); only scheme + host well-formedness is enforced.
        for (field, url) in [
            ("enrichment.api_base", &self.api_base),
            ("enrichment.kev_url", &self.kev_url),
            ("enrichment.epss_url", &self.epss_url),
            ("enrichment.huggingface_url", &self.huggingface_url),
        ] {
            if let Some(url) = url
                && !is_valid_http_url(url)
            {
                errors.push(ConfigError {
                    field: field.to_string(),
                    message: format!(
                        "'{url}' is not a valid http(s) URL with a host; \
                         enrichment endpoints must use http:// or https://"
                    ),
                });
            }
        }

        errors
    }
}

/// Whether `url` is a syntactically valid `http`/`https` URL with a non-empty
/// host. Deliberately lightweight (no `url` crate — config validation runs
/// without the enrichment feature): rejects non-http schemes, empty hosts, and
/// whitespace/control characters, which is enough to stop scheme abuse and
/// malformed overrides.
fn is_valid_http_url(url: &str) -> bool {
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => match url.strip_prefix("http://") {
            Some(r) => r,
            None => return false,
        },
    };
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    // Authority = everything up to the first '/', '?' or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip optional userinfo and port; a non-empty host must remain.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    !host.is_empty()
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
        if let Some(ref rules_file) = self.rules.rules_file
            && !rules_file.exists()
        {
            errors.push(ConfigError {
                field: "rules.rules_file".to_string(),
                message: format!("Rules file not found: {}", rules_file.display()),
            });
        }

        // Validate ecosystem rules file if specified
        if let Some(ref config_file) = self.ecosystem_rules.config_file
            && !config_file.exists()
        {
            errors.push(ConfigError {
                field: "ecosystem_rules.config_file".to_string(),
                message: format!("Ecosystem rules file not found: {}", config_file.display()),
            });
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
                    field: format!("targets[{i}]"),
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
                    field: format!("sbom_paths[{i}]"),
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
                    field: format!("sbom_paths[{i}]"),
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
    fn is_valid_http_url_accepts_and_rejects() {
        // Valid http(s) URLs with a host.
        assert!(is_valid_http_url("https://api.osv.dev"));
        assert!(is_valid_http_url("http://localhost:8080/v1"));
        assert!(is_valid_http_url(
            "https://user@internal.mirror:443/path?q=1"
        ));
        // Rejected: non-http scheme, missing host, malformed, whitespace.
        assert!(!is_valid_http_url("file:///etc/passwd"));
        assert!(!is_valid_http_url("ftp://example.com"));
        assert!(!is_valid_http_url("https://"));
        assert!(!is_valid_http_url("https:///path-only"));
        assert!(!is_valid_http_url("api.osv.dev"));
        assert!(!is_valid_http_url("https://exa mple.com"));
        assert!(!is_valid_http_url(""));
    }

    #[test]
    fn enrichment_config_rejects_bad_url_override() {
        let mut config = EnrichmentConfig {
            api_base: Some("file:///etc/passwd".to_string()),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.field == "enrichment.api_base"),
            "a non-http api_base override must be a config error"
        );

        // A valid override passes (this field, at least).
        config.api_base = Some("https://osv.example.internal/v1".to_string());
        let errors = config.validate();
        assert!(!errors.iter().any(|e| e.field == "enrichment.api_base"));
    }

    #[test]
    fn test_matching_config_validation() {
        // FuzzyPreset enum makes invalid presets unrepresentable at compile time.
        // Valid config should pass.
        let config = MatchingConfig {
            fuzzy_preset: super::super::FuzzyPreset::Balanced,
            threshold: None,
            include_unchanged: false,
        };
        assert!(config.is_valid());
    }

    #[test]
    fn test_matching_config_threshold_validation() {
        let valid = MatchingConfig {
            fuzzy_preset: super::super::FuzzyPreset::Balanced,
            threshold: Some(0.85),
            include_unchanged: false,
        };
        assert!(valid.is_valid());

        let invalid = MatchingConfig {
            fuzzy_preset: super::super::FuzzyPreset::Balanced,
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
            fail_on_vex_gap: false,
            fail_on_ml_regression: false,
        };
        assert!(config.is_valid());

        let invalid = FilterConfig {
            only_changes: true,
            min_severity: Some("invalid".to_string()),
            exclude_vex_resolved: false,
            fail_on_vex_gap: false,
            fail_on_ml_regression: false,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_tui_config_validation() {
        let valid = TuiConfig::default();
        assert!(valid.is_valid());

        // Theme is now ThemeName enum — invalid values are unrepresentable.
        // Only threshold validation remains testable.
        let invalid = TuiConfig {
            initial_threshold: 2.0,
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
    fn enrichment_config_rejects_zero_ttl_and_timeout() {
        // The JSON Schema declares minimum 1 for both; the runtime validator
        // must agree so `config check` and the schema can't disagree.
        let zero_ttl = EnrichmentConfig {
            cache_ttl_hours: 0,
            ..EnrichmentConfig::default()
        };
        assert!(
            zero_ttl
                .validate()
                .iter()
                .any(|e| e.field == "enrichment.cache_ttl_hours"),
            "cache_ttl_hours: 0 must be a config error"
        );

        let zero_timeout = EnrichmentConfig {
            timeout_secs: 0,
            ..EnrichmentConfig::default()
        };
        assert!(
            zero_timeout
                .validate()
                .iter()
                .any(|e| e.field == "enrichment.timeout_secs"),
            "timeout_secs: 0 must be a config error"
        );
    }

    #[test]
    fn compliance_config_accepts_canonical_values_and_aliases() {
        let config = ComplianceConfig {
            standards: vec![
                "ntia".to_string(),
                "cra-phase1".to_string(),
                "nist-ssdf".to_string(), // alias
            ],
            profile: Some("cyber-resilience".to_string()), // alias
            min_score: Some(70.0),
            cra_product_class: Some("important-class-1".to_string()),
            ..Default::default()
        };
        assert!(config.is_valid(), "{:?}", config.validate());
    }

    #[test]
    fn compliance_config_rejects_bad_values() {
        let config = ComplianceConfig {
            standards: vec!["not-a-standard".to_string()],
            profile: Some("not-a-profile".to_string()),
            min_score: Some(250.0),
            cra_product_class: Some("mega-critical".to_string()),
            ..Default::default()
        };
        let errors = config.validate();
        for field in [
            "compliance.standards[0]",
            "compliance.profile",
            "compliance.min_score",
            "compliance.cra_product_class",
        ] {
            assert!(
                errors.iter().any(|e| e.field == field),
                "expected an error for {field}: {errors:?}"
            );
        }
    }

    /// Rule settings and `fail_on` name rules as `--rule` and `--fail-on`
    /// do (any case), and the PQC keys take the `--pqc-*` value names.
    #[test]
    fn compliance_config_accepts_rule_settings_and_pqc_defaults() {
        let config = ComplianceConfig {
            rules: [
                ("SBOM-NTIA-SUPPLIER", "warning"),
                ("sbom-ntia-version", "OFF"),
                ("SBOM-CRA-ART-24", "error"),
            ]
            .into_iter()
            .map(|(id, setting)| (id.to_string(), setting.to_string()))
            .collect(),
            fail_on: vec!["sbom-ntia-supplier".to_string()],
            include_excluded_scope: true,
            pqc_mode: Some("deadline".to_string()),
            pqc_profile: Some("federal".to_string()),
            cnsa_category: Some("web-cloud".to_string()),
            ..Default::default()
        };
        assert!(config.is_valid(), "{:?}", config.validate());
    }

    #[test]
    fn compliance_config_rejects_bad_rule_settings_and_pqc_values() {
        let config = ComplianceConfig {
            rules: [
                ("SBOM-NTIA-SUPLIER", "warning"),
                ("SBOM-NTIA-VERSION", "warn"),
                ("SBOM-PQC-009", "error"),
            ]
            .into_iter()
            .map(|(id, setting)| (id.to_string(), setting.to_string()))
            .collect(),
            fail_on: vec!["SBOM-PQC-009".to_string(), "SBOM-NOPE".to_string()],
            pqc_mode: Some("eventually".to_string()),
            pqc_profile: Some("federal".to_string()),
            cnsa_category: Some("toasters".to_string()),
            ..Default::default()
        };
        let errors = config.validate();
        let message = |field: &str| {
            errors
                .iter()
                .find(|e| e.field == field)
                .map(|e| e.message.clone())
                .unwrap_or_else(|| panic!("expected an error for {field}: {errors:?}"))
        };
        assert!(message("compliance.rules.SBOM-NTIA-SUPLIER").contains("SBOM-NTIA-SUPPLIER"));
        assert!(
            message("compliance.rules.SBOM-NTIA-VERSION").contains("off, info, warning, error")
        );
        assert!(message("compliance.rules.SBOM-PQC-009").contains("passed checks"));
        assert!(message("compliance.fail_on[0]").contains("never a finding"));
        assert!(message("compliance.fail_on[1]").contains("unknown rule id"));
        assert!(message("compliance.pqc_mode").contains("readiness, deadline"));
        assert!(message("compliance.cnsa_category").contains("software-signing"));
        // A profile is a deadline-mode default; the mode is invalid here.
        assert!(message("compliance.pqc_profile").contains("pqc_mode: deadline"));
    }

    /// As on the command line, a profile or a category without deadline
    /// mode is an error.
    #[test]
    fn compliance_config_rejects_pqc_profile_outside_deadline_mode() {
        for mode in [None, Some("readiness")] {
            let config = ComplianceConfig {
                pqc_mode: mode.map(str::to_string),
                pqc_profile: Some("nist".to_string()),
                cnsa_category: Some("niche".to_string()),
                ..Default::default()
            };
            let fields: Vec<String> = config.validate().into_iter().map(|e| e.field).collect();
            assert_eq!(
                fields,
                ["compliance.pqc_profile", "compliance.cnsa_category"],
                "mode {mode:?}"
            );
        }
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

        // Enum fields make invalid presets unrepresentable.
        // Test with invalid threshold instead.
        let mut invalid = AppConfig::default();
        invalid.matching.threshold = Some(5.0);
        assert!(!invalid.is_valid());
    }
}
