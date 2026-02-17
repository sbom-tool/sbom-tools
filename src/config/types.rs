//! Configuration types for sbom-tools operations.
//!
//! Provides structured configuration for diff, view, and multi-comparison operations.

use crate::matching::FuzzyMatchConfig;
use crate::reports::{ReportFormat, ReportType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// Unified Application Configuration
// ============================================================================

/// Unified application configuration that can be loaded from CLI args or config files.
///
/// This is the top-level configuration struct that aggregates all configuration
/// options. It can be constructed from CLI arguments, config files, or both
/// (with CLI overriding file settings).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AppConfig {
    /// Matching configuration (thresholds, presets)
    pub matching: MatchingConfig,
    /// Output configuration (format, file, colors)
    pub output: OutputConfig,
    /// Filtering options
    pub filtering: FilterConfig,
    /// Behavior flags
    pub behavior: BehaviorConfig,
    /// Graph-aware diffing configuration
    pub graph_diff: GraphAwareDiffConfig,
    /// Custom matching rules configuration
    pub rules: MatchingRulesPathConfig,
    /// Ecosystem-specific rules configuration
    pub ecosystem_rules: EcosystemRulesConfig,
    /// TUI-specific configuration
    pub tui: TuiConfig,
    /// Enrichment configuration (OSV, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<EnrichmentConfig>,
}

impl AppConfig {
    /// Create a new `AppConfig` with default values.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an `AppConfig` builder.
    pub fn builder() -> AppConfigBuilder {
        AppConfigBuilder::default()
    }
}

// ============================================================================
// Builder for AppConfig
// ============================================================================

/// Builder for constructing `AppConfig` with fluent API.
#[derive(Debug, Default)]
#[must_use]
pub struct AppConfigBuilder {
    config: AppConfig,
}

impl AppConfigBuilder {
    /// Set the fuzzy matching preset.
    pub fn fuzzy_preset(mut self, preset: impl Into<String>) -> Self {
        self.config.matching.fuzzy_preset = preset.into();
        self
    }

    /// Set the matching threshold.
    pub const fn matching_threshold(mut self, threshold: f64) -> Self {
        self.config.matching.threshold = Some(threshold);
        self
    }

    /// Set the output format.
    pub const fn output_format(mut self, format: ReportFormat) -> Self {
        self.config.output.format = format;
        self
    }

    /// Set the output file.
    pub fn output_file(mut self, file: Option<PathBuf>) -> Self {
        self.config.output.file = file;
        self
    }

    /// Disable colored output.
    pub const fn no_color(mut self, no_color: bool) -> Self {
        self.config.output.no_color = no_color;
        self
    }

    /// Include unchanged components.
    pub const fn include_unchanged(mut self, include: bool) -> Self {
        self.config.matching.include_unchanged = include;
        self
    }

    /// Enable fail-on-vulnerability mode.
    pub const fn fail_on_vuln(mut self, fail: bool) -> Self {
        self.config.behavior.fail_on_vuln = fail;
        self
    }

    /// Enable fail-on-change mode.
    pub const fn fail_on_change(mut self, fail: bool) -> Self {
        self.config.behavior.fail_on_change = fail;
        self
    }

    /// Enable quiet mode.
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.config.behavior.quiet = quiet;
        self
    }

    /// Enable graph-aware diffing.
    pub fn graph_diff(mut self, enabled: bool) -> Self {
        self.config.graph_diff = if enabled {
            GraphAwareDiffConfig::enabled()
        } else {
            GraphAwareDiffConfig::default()
        };
        self
    }

    /// Set matching rules file.
    pub fn matching_rules_file(mut self, file: Option<PathBuf>) -> Self {
        self.config.rules.rules_file = file;
        self
    }

    /// Set ecosystem rules file.
    pub fn ecosystem_rules_file(mut self, file: Option<PathBuf>) -> Self {
        self.config.ecosystem_rules.config_file = file;
        self
    }

    /// Enable enrichment.
    pub fn enrichment(mut self, config: EnrichmentConfig) -> Self {
        self.config.enrichment = Some(config);
        self
    }

    /// Build the `AppConfig`.
    #[must_use] 
    pub fn build(self) -> AppConfig {
        self.config
    }
}

// ============================================================================
// TUI Preferences (persisted)
// ============================================================================

/// TUI preferences that persist across sessions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TuiPreferences {
    /// Theme name: "dark", "light", or "high-contrast"
    pub theme: String,
}

impl Default for TuiPreferences {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
        }
    }
}

impl TuiPreferences {
    /// Get the path to the preferences file.
    #[must_use] 
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("sbom-tools").join("preferences.json"))
    }

    /// Load preferences from disk, or return defaults if not found.
    #[must_use] 
    pub fn load() -> Self {
        Self::config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Save preferences to disk.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(path) = Self::config_path() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string_pretty(self)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }
}

// ============================================================================
// TUI Configuration
// ============================================================================

/// TUI-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TuiConfig {
    /// Theme name: "dark", "light", or "high-contrast"
    pub theme: String,
    /// Show line numbers in code views
    pub show_line_numbers: bool,
    /// Enable mouse support
    pub mouse_enabled: bool,
    /// Initial matching threshold for TUI threshold tuning
    #[schemars(range(min = 0.0, max = 1.0))]
    pub initial_threshold: f64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            show_line_numbers: true,
            mouse_enabled: true,
            initial_threshold: 0.8,
        }
    }
}

// ============================================================================
// Command-specific Configuration Types
// ============================================================================

/// Configuration for diff operations
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Paths to compare
    pub paths: DiffPaths,
    /// Output configuration
    pub output: OutputConfig,
    /// Matching configuration
    pub matching: MatchingConfig,
    /// Filtering options
    pub filtering: FilterConfig,
    /// Behavior flags
    pub behavior: BehaviorConfig,
    /// Graph-aware diffing configuration
    pub graph_diff: GraphAwareDiffConfig,
    /// Custom matching rules configuration
    pub rules: MatchingRulesPathConfig,
    /// Ecosystem-specific rules configuration
    pub ecosystem_rules: EcosystemRulesConfig,
    /// Enrichment configuration (always defined, runtime feature check)
    pub enrichment: EnrichmentConfig,
}

/// Paths for diff operation
#[derive(Debug, Clone)]
pub struct DiffPaths {
    /// Path to old/baseline SBOM
    pub old: PathBuf,
    /// Path to new SBOM
    pub new: PathBuf,
}

/// Configuration for view operations
#[derive(Debug, Clone)]
pub struct ViewConfig {
    /// Path to SBOM file
    pub sbom_path: PathBuf,
    /// Output configuration
    pub output: OutputConfig,
    /// Whether to validate against NTIA
    pub validate_ntia: bool,
    /// Filter by minimum vulnerability severity (critical, high, medium, low)
    pub min_severity: Option<String>,
    /// Only show components with vulnerabilities
    pub vulnerable_only: bool,
    /// Filter by ecosystem
    pub ecosystem_filter: Option<String>,
    /// Enrichment configuration
    pub enrichment: EnrichmentConfig,
}

/// Configuration for multi-diff operations
#[derive(Debug, Clone)]
pub struct MultiDiffConfig {
    /// Path to baseline SBOM
    pub baseline: PathBuf,
    /// Paths to target SBOMs
    pub targets: Vec<PathBuf>,
    /// Output configuration
    pub output: OutputConfig,
    /// Matching configuration
    pub matching: MatchingConfig,
}

/// Configuration for timeline analysis
#[derive(Debug, Clone)]
pub struct TimelineConfig {
    /// Paths to SBOMs in chronological order
    pub sbom_paths: Vec<PathBuf>,
    /// Output configuration
    pub output: OutputConfig,
    /// Matching configuration
    pub matching: MatchingConfig,
}

/// Configuration for query operations (searching components across multiple SBOMs)
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Paths to SBOM files to search
    pub sbom_paths: Vec<PathBuf>,
    /// Output configuration
    pub output: OutputConfig,
    /// Enrichment configuration
    pub enrichment: EnrichmentConfig,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Group results by SBOM source
    pub group_by_sbom: bool,
}

/// Configuration for matrix comparison
#[derive(Debug, Clone)]
pub struct MatrixConfig {
    /// Paths to SBOMs
    pub sbom_paths: Vec<PathBuf>,
    /// Output configuration
    pub output: OutputConfig,
    /// Matching configuration
    pub matching: MatchingConfig,
    /// Similarity threshold for clustering (0.0-1.0)
    pub cluster_threshold: f64,
}

// ============================================================================
// Sub-configuration Types
// ============================================================================

/// Output-related configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct OutputConfig {
    /// Output format
    pub format: ReportFormat,
    /// Output file path (None for stdout)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Report types to include
    pub report_types: ReportType,
    /// Disable colored output
    pub no_color: bool,
    /// Streaming configuration for large SBOMs
    pub streaming: StreamingConfig,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Auto,
            file: None,
            report_types: ReportType::All,
            no_color: false,
            streaming: StreamingConfig::default(),
        }
    }
}

/// Streaming configuration for memory-efficient processing of large SBOMs.
///
/// When streaming is enabled, the tool uses streaming parsers and reporters
/// to avoid loading entire SBOMs into memory. This is essential for SBOMs
/// with thousands of components.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct StreamingConfig {
    /// Enable streaming mode automatically for files larger than this threshold (in bytes).
    /// Default: 10 MB (`10_485_760` bytes)
    #[schemars(range(min = 0))]
    pub threshold_bytes: u64,
    /// Force streaming mode regardless of file size.
    /// Useful for testing or when processing stdin.
    pub force: bool,
    /// Disable streaming mode entirely (always load full SBOMs into memory).
    pub disabled: bool,
    /// Enable streaming for stdin input (since size is unknown).
    /// Default: true
    pub stream_stdin: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            threshold_bytes: 10 * 1024 * 1024, // 10 MB
            force: false,
            disabled: false,
            stream_stdin: true,
        }
    }
}

impl StreamingConfig {
    /// Check if streaming should be used for a file of the given size.
    #[must_use] 
    pub fn should_stream(&self, file_size: Option<u64>, is_stdin: bool) -> bool {
        if self.disabled {
            return false;
        }
        if self.force {
            return true;
        }
        if is_stdin && self.stream_stdin {
            return true;
        }
        file_size.map_or(self.stream_stdin, |size| size >= self.threshold_bytes)
    }

    /// Create a streaming config that always streams.
    #[must_use] 
    pub fn always() -> Self {
        Self {
            force: true,
            ..Default::default()
        }
    }

    /// Create a streaming config that never streams.
    #[must_use] 
    pub fn never() -> Self {
        Self {
            disabled: true,
            ..Default::default()
        }
    }

    /// Set the threshold in megabytes.
    #[must_use]
    pub const fn with_threshold_mb(mut self, mb: u64) -> Self {
        self.threshold_bytes = mb * 1024 * 1024;
        self
    }
}

/// Matching and comparison configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MatchingConfig {
    /// Fuzzy matching preset name
    pub fuzzy_preset: String,
    /// Custom matching threshold (overrides preset)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0.0, max = 1.0))]
    pub threshold: Option<f64>,
    /// Include unchanged components in output
    pub include_unchanged: bool,
}

impl Default for MatchingConfig {
    fn default() -> Self {
        Self {
            fuzzy_preset: "balanced".to_string(),
            threshold: None,
            include_unchanged: false,
        }
    }
}

impl MatchingConfig {
    /// Convert preset name to `FuzzyMatchConfig`
    #[must_use] 
    pub fn to_fuzzy_config(&self) -> FuzzyMatchConfig {
        let mut config = FuzzyMatchConfig::from_preset(&self.fuzzy_preset).unwrap_or_else(|| {
            tracing::warn!(
                "Unknown fuzzy preset '{}', using 'balanced'. Valid: strict, balanced, permissive",
                self.fuzzy_preset
            );
            FuzzyMatchConfig::balanced()
        });

        // Apply custom threshold if specified
        if let Some(threshold) = self.threshold {
            config = config.with_threshold(threshold);
        }

        config
    }
}

/// Filtering options for diff results
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FilterConfig {
    /// Only show items with changes
    pub only_changes: bool,
    /// Minimum severity filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<String>,
    /// Exclude vulnerabilities with VEX status `not_affected` or fixed
    #[serde(alias = "exclude_vex_not_affected")]
    pub exclude_vex_resolved: bool,
}

/// Behavior flags for diff operations
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BehaviorConfig {
    /// Exit with code 2 if new vulnerabilities are introduced
    pub fail_on_vuln: bool,
    /// Exit with code 1 if any changes detected
    pub fail_on_change: bool,
    /// Suppress non-essential output
    pub quiet: bool,
    /// Show detailed match explanations for each matched component
    pub explain_matches: bool,
    /// Recommend optimal matching threshold based on the SBOMs
    pub recommend_threshold: bool,
}

/// Graph-aware diffing configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct GraphAwareDiffConfig {
    /// Enable graph-aware diffing
    pub enabled: bool,
    /// Detect component reparenting
    pub detect_reparenting: bool,
    /// Detect depth changes
    pub detect_depth_changes: bool,
}

impl GraphAwareDiffConfig {
    /// Create enabled graph diff options with defaults
    #[must_use] 
    pub const fn enabled() -> Self {
        Self {
            enabled: true,
            detect_reparenting: true,
            detect_depth_changes: true,
        }
    }
}

/// Custom matching rules configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MatchingRulesPathConfig {
    /// Path to matching rules YAML file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_file: Option<PathBuf>,
    /// Dry-run mode (show what would match without applying)
    pub dry_run: bool,
}

/// Ecosystem-specific rules configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EcosystemRulesConfig {
    /// Path to ecosystem rules configuration file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<PathBuf>,
    /// Disable ecosystem-specific normalization
    pub disabled: bool,
    /// Enable typosquat detection warnings
    pub detect_typosquats: bool,
}

/// Enrichment configuration for vulnerability data sources.
///
/// This configuration is always defined regardless of the `enrichment` feature flag.
/// When the feature is disabled, the configuration is silently ignored at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EnrichmentConfig {
    /// Enable enrichment (if false, no enrichment is performed)
    pub enabled: bool,
    /// Enrichment provider ("osv", "nvd", etc.)
    pub provider: String,
    /// Cache time-to-live in hours
    #[schemars(range(min = 1))]
    pub cache_ttl_hours: u64,
    /// Maximum concurrent requests
    #[schemars(range(min = 1))]
    pub max_concurrent: usize,
    /// Cache directory for vulnerability data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<std::path::PathBuf>,
    /// Bypass cache and fetch fresh vulnerability data
    pub bypass_cache: bool,
    /// API timeout in seconds
    #[schemars(range(min = 1))]
    pub timeout_secs: u64,
    /// Enable end-of-life detection via endoflife.date API
    pub enable_eol: bool,
    /// Paths to external VEX documents (OpenVEX format)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vex_paths: Vec<std::path::PathBuf>,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "osv".to_string(),
            cache_ttl_hours: 24,
            max_concurrent: 10,
            cache_dir: None,
            bypass_cache: false,
            timeout_secs: 30,
            enable_eol: false,
            vex_paths: Vec::new(),
        }
    }
}

impl EnrichmentConfig {
    /// Create an enabled enrichment config with OSV provider.
    #[must_use] 
    pub fn osv() -> Self {
        Self {
            enabled: true,
            provider: "osv".to_string(),
            ..Default::default()
        }
    }

    /// Create an enabled enrichment config with custom settings.
    #[must_use]
    pub fn with_cache_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.cache_dir = Some(dir);
        self
    }

    /// Set the cache TTL in hours.
    #[must_use]
    pub const fn with_cache_ttl_hours(mut self, hours: u64) -> Self {
        self.cache_ttl_hours = hours;
        self
    }

    /// Enable cache bypass (refresh).
    #[must_use]
    pub const fn with_bypass_cache(mut self) -> Self {
        self.bypass_cache = true;
        self
    }

    /// Set the API timeout in seconds.
    #[must_use]
    pub const fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set VEX document paths.
    #[must_use]
    pub fn with_vex_paths(mut self, paths: Vec<std::path::PathBuf>) -> Self {
        self.vex_paths = paths;
        self
    }
}

// ============================================================================
// Builder for DiffConfig
// ============================================================================

/// Builder for `DiffConfig`
#[derive(Debug, Default)]
pub struct DiffConfigBuilder {
    old: Option<PathBuf>,
    new: Option<PathBuf>,
    output: OutputConfig,
    matching: MatchingConfig,
    filtering: FilterConfig,
    behavior: BehaviorConfig,
    graph_diff: GraphAwareDiffConfig,
    rules: MatchingRulesPathConfig,
    ecosystem_rules: EcosystemRulesConfig,
    enrichment: EnrichmentConfig,
}

impl DiffConfigBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn old_path(mut self, path: PathBuf) -> Self {
        self.old = Some(path);
        self
    }

    #[must_use]
    pub fn new_path(mut self, path: PathBuf) -> Self {
        self.new = Some(path);
        self
    }

    #[must_use]
    pub const fn output_format(mut self, format: ReportFormat) -> Self {
        self.output.format = format;
        self
    }

    #[must_use]
    pub fn output_file(mut self, file: Option<PathBuf>) -> Self {
        self.output.file = file;
        self
    }

    #[must_use]
    pub const fn report_types(mut self, types: ReportType) -> Self {
        self.output.report_types = types;
        self
    }

    #[must_use]
    pub const fn no_color(mut self, no_color: bool) -> Self {
        self.output.no_color = no_color;
        self
    }

    #[must_use]
    pub fn fuzzy_preset(mut self, preset: String) -> Self {
        self.matching.fuzzy_preset = preset;
        self
    }

    #[must_use]
    pub const fn matching_threshold(mut self, threshold: Option<f64>) -> Self {
        self.matching.threshold = threshold;
        self
    }

    #[must_use]
    pub const fn include_unchanged(mut self, include: bool) -> Self {
        self.matching.include_unchanged = include;
        self
    }

    #[must_use]
    pub const fn only_changes(mut self, only: bool) -> Self {
        self.filtering.only_changes = only;
        self
    }

    #[must_use]
    pub fn min_severity(mut self, severity: Option<String>) -> Self {
        self.filtering.min_severity = severity;
        self
    }

    #[must_use]
    pub const fn fail_on_vuln(mut self, fail: bool) -> Self {
        self.behavior.fail_on_vuln = fail;
        self
    }

    #[must_use]
    pub const fn fail_on_change(mut self, fail: bool) -> Self {
        self.behavior.fail_on_change = fail;
        self
    }

    #[must_use]
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.behavior.quiet = quiet;
        self
    }

    #[must_use]
    pub const fn explain_matches(mut self, explain: bool) -> Self {
        self.behavior.explain_matches = explain;
        self
    }

    #[must_use]
    pub const fn recommend_threshold(mut self, recommend: bool) -> Self {
        self.behavior.recommend_threshold = recommend;
        self
    }

    #[must_use]
    pub fn graph_diff(mut self, enabled: bool) -> Self {
        self.graph_diff = if enabled {
            GraphAwareDiffConfig::enabled()
        } else {
            GraphAwareDiffConfig::default()
        };
        self
    }

    #[must_use]
    pub fn matching_rules_file(mut self, file: Option<PathBuf>) -> Self {
        self.rules.rules_file = file;
        self
    }

    #[must_use]
    pub const fn dry_run_rules(mut self, dry_run: bool) -> Self {
        self.rules.dry_run = dry_run;
        self
    }

    #[must_use]
    pub fn ecosystem_rules_file(mut self, file: Option<PathBuf>) -> Self {
        self.ecosystem_rules.config_file = file;
        self
    }

    #[must_use]
    pub const fn disable_ecosystem_rules(mut self, disabled: bool) -> Self {
        self.ecosystem_rules.disabled = disabled;
        self
    }

    #[must_use]
    pub const fn detect_typosquats(mut self, detect: bool) -> Self {
        self.ecosystem_rules.detect_typosquats = detect;
        self
    }

    #[must_use]
    pub fn enrichment(mut self, config: EnrichmentConfig) -> Self {
        self.enrichment = config;
        self
    }

    #[must_use]
    pub const fn enable_enrichment(mut self, enabled: bool) -> Self {
        self.enrichment.enabled = enabled;
        self
    }

    pub fn build(self) -> anyhow::Result<DiffConfig> {
        let old = self.old.ok_or_else(|| anyhow::anyhow!("old path is required"))?;
        let new = self.new.ok_or_else(|| anyhow::anyhow!("new path is required"))?;

        Ok(DiffConfig {
            paths: DiffPaths { old, new },
            output: self.output,
            matching: self.matching,
            filtering: self.filtering,
            behavior: self.behavior,
            graph_diff: self.graph_diff,
            rules: self.rules,
            ecosystem_rules: self.ecosystem_rules,
            enrichment: self.enrichment,
        })
    }
}
