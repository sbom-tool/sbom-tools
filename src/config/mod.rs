//! Configuration module for sbom-tools.
//!
//! This module provides a unified configuration system with:
//! - Type-safe configuration structures
//! - Validation for all configuration values
//! - Named presets for common use cases
//! - YAML config file loading and discovery
//! - CLI argument merging
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use sbom_tools::config::{AppConfig, ConfigPreset};
//!
//! // Use defaults
//! let config = AppConfig::default();
//!
//! // Use a preset
//! let config = AppConfig::from_preset(ConfigPreset::Security);
//!
//! // Use builder
//! let config = AppConfig::builder()
//!     .fuzzy_preset("strict")
//!     .matching_threshold(0.9)
//!     .fail_on_vuln(true)
//!     .build();
//!
//! // Load from file
//! use sbom_tools::config::file::load_or_default;
//! let (config, loaded_from) = load_or_default(None);
//! ```
//!
//! # Configuration File
//!
//! Place a `.sbom-tools.yaml` file in your project root or `~/.config/sbom-tools/`:
//!
//! ```yaml
//! matching:
//!   fuzzy_preset: strict
//!   threshold: 0.9
//! behavior:
//!   fail_on_vuln: true
//! ```

mod defaults;
pub mod file;
mod types;
mod validation;

// Re-export main types
pub use defaults::{
    ConfigPreset, DEFAULT_CLUSTER_THRESHOLD, DEFAULT_ENRICHMENT_CACHE_TTL,
    DEFAULT_ENRICHMENT_MAX_CONCURRENT, DEFAULT_MATCHING_THRESHOLD,
};
pub use types::{
    AppConfig, AppConfigBuilder, BehaviorConfig, DiffConfig, DiffConfigBuilder, DiffPaths,
    EcosystemRulesConfig, EnrichmentConfig, FilterConfig, GraphAwareDiffConfig, MatchingConfig,
    MatchingRulesPathConfig, MatrixConfig, MultiDiffConfig, OutputConfig, StreamingConfig,
    TimelineConfig, TuiConfig, TuiPreferences, ViewConfig,
};
pub use validation::{ConfigError, Validatable};

// Re-export file utilities
pub use file::{
    discover_config_file, generate_example_config, generate_full_example_config, load_config_file,
    load_or_default, ConfigFileError,
};

/// Generate a JSON Schema for the `AppConfig` configuration format.
///
/// This schema documents all configuration options that can be set in
/// `.sbom-tools.yaml` config files. It can be used by editors for
/// validation and autocompletion.
#[must_use] 
pub fn generate_json_schema() -> String {
    let schema = schemars::schema_for!(AppConfig);
    serde_json::to_string_pretty(&schema).expect("schema serialization should not fail")
}
