//! Configuration file loading and discovery.
//!
//! Supports loading configuration from YAML files with automatic discovery.

use super::types::AppConfig;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration File Discovery
// ============================================================================

/// Standard config file names to search for.
const CONFIG_FILE_NAMES: &[&str] = &[
    ".sbom-tools.yaml",
    ".sbom-tools.yml",
    "sbom-tools.yaml",
    "sbom-tools.yml",
    ".sbom-toolsrc",
];

/// Discover a config file by searching standard locations.
///
/// Search order:
/// 1. Explicit path if provided
/// 2. Current directory
/// 3. Git repository root (if in a repo)
/// 4. User config directory (~/.config/sbom-tools/)
/// 5. Home directory
#[must_use] 
pub fn discover_config_file(explicit_path: Option<&Path>) -> Option<PathBuf> {
    // 1. Use explicit path if provided
    if let Some(path) = explicit_path
        && path.exists() {
            return Some(path.to_path_buf());
        }

    // 2. Search current directory
    if let Ok(cwd) = std::env::current_dir()
        && let Some(path) = find_config_in_dir(&cwd) {
            return Some(path);
        }

    // 3. Search git root (if in a repo)
    if let Some(git_root) = find_git_root()
        && let Some(path) = find_config_in_dir(&git_root) {
            return Some(path);
        }

    // 4. Search user config directory
    if let Some(config_dir) = dirs::config_dir() {
        let sbom_config_dir = config_dir.join("sbom-tools");
        if let Some(path) = find_config_in_dir(&sbom_config_dir) {
            return Some(path);
        }
    }

    // 5. Search home directory
    if let Some(home) = dirs::home_dir()
        && let Some(path) = find_config_in_dir(&home) {
            return Some(path);
        }

    None
}

/// Find a config file in a specific directory.
fn find_config_in_dir(dir: &Path) -> Option<PathBuf> {
    for name in CONFIG_FILE_NAMES {
        let path = dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Find the git repository root by walking up the directory tree.
fn find_git_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut current = cwd.as_path();

    loop {
        let git_dir = current.join(".git");
        if git_dir.exists() {
            return Some(current.to_path_buf());
        }

        current = current.parent()?;
    }
}

// ============================================================================
// Configuration File Loading
// ============================================================================

/// Error type for config file operations.
#[derive(Debug)]
pub enum ConfigFileError {
    /// File not found
    NotFound(PathBuf),
    /// IO error reading file
    Io(std::io::Error),
    /// YAML parsing error
    Parse(serde_yaml_ng::Error),
}

impl std::fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => {
                write!(f, "Config file not found: {}", path.display())
            }
            Self::Io(e) => write!(f, "Failed to read config file: {e}"),
            Self::Parse(e) => write!(f, "Failed to parse config file: {e}"),
        }
    }
}

impl std::error::Error for ConfigFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotFound(_) => None,
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for ConfigFileError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_yaml_ng::Error> for ConfigFileError {
    fn from(err: serde_yaml_ng::Error) -> Self {
        Self::Parse(err)
    }
}

/// Load an `AppConfig` from a YAML file.
pub fn load_config_file(path: &Path) -> Result<AppConfig, ConfigFileError> {
    if !path.exists() {
        return Err(ConfigFileError::NotFound(path.to_path_buf()));
    }

    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = serde_yaml_ng::from_str(&content)?;
    Ok(config)
}

/// Load config from discovered file, or return default.
#[must_use] 
pub fn load_or_default(explicit_path: Option<&Path>) -> (AppConfig, Option<PathBuf>) {
    discover_config_file(explicit_path).map_or_else(
        || (AppConfig::default(), None),
        |path| match load_config_file(&path) {
            Ok(config) => (config, Some(path)),
            Err(e) => {
                tracing::warn!("Failed to load config from {}: {}", path.display(), e);
                (AppConfig::default(), None)
            }
        },
    )
}

// ============================================================================
// Configuration Merging
// ============================================================================

impl AppConfig {
    /// Merge another config into this one, with `other` taking precedence.
    ///
    /// This is useful for layering CLI args over file config.
    pub fn merge(&mut self, other: &Self) {
        // Matching config
        if other.matching.fuzzy_preset != "balanced" {
            self.matching.fuzzy_preset.clone_from(&other.matching.fuzzy_preset);
        }
        if other.matching.threshold.is_some() {
            self.matching.threshold = other.matching.threshold;
        }
        if other.matching.include_unchanged {
            self.matching.include_unchanged = true;
        }

        // Output config - only override if explicitly set
        if other.output.format != crate::reports::ReportFormat::Auto {
            self.output.format = other.output.format;
        }
        if other.output.file.is_some() {
            self.output.file.clone_from(&other.output.file);
        }
        if other.output.no_color {
            self.output.no_color = true;
        }
        if other.output.export_template.is_some() {
            self.output.export_template.clone_from(&other.output.export_template);
        }

        // Filtering config
        if other.filtering.only_changes {
            self.filtering.only_changes = true;
        }
        if other.filtering.min_severity.is_some() {
            self.filtering.min_severity.clone_from(&other.filtering.min_severity);
        }

        // Behavior config (booleans - if set to true, override)
        if other.behavior.fail_on_vuln {
            self.behavior.fail_on_vuln = true;
        }
        if other.behavior.fail_on_change {
            self.behavior.fail_on_change = true;
        }
        if other.behavior.quiet {
            self.behavior.quiet = true;
        }
        if other.behavior.explain_matches {
            self.behavior.explain_matches = true;
        }
        if other.behavior.recommend_threshold {
            self.behavior.recommend_threshold = true;
        }

        // Graph diff config
        if other.graph_diff.enabled {
            self.graph_diff = other.graph_diff.clone();
        }

        // Rules config
        if other.rules.rules_file.is_some() {
            self.rules.rules_file.clone_from(&other.rules.rules_file);
        }
        if other.rules.dry_run {
            self.rules.dry_run = true;
        }

        // Ecosystem rules config
        if other.ecosystem_rules.config_file.is_some() {
            self.ecosystem_rules.config_file.clone_from(&other.ecosystem_rules.config_file);
        }
        if other.ecosystem_rules.disabled {
            self.ecosystem_rules.disabled = true;
        }
        if other.ecosystem_rules.detect_typosquats {
            self.ecosystem_rules.detect_typosquats = true;
        }

        // TUI config
        if other.tui.theme != "dark" {
            self.tui.theme.clone_from(&other.tui.theme);
        }

        // Enrichment config
        if other.enrichment.is_some() {
            self.enrichment.clone_from(&other.enrichment);
        }
    }

    /// Load from file and merge with CLI overrides.
    #[must_use] 
    pub fn from_file_with_overrides(
        config_path: Option<&Path>,
        cli_overrides: &Self,
    ) -> (Self, Option<PathBuf>) {
        let (mut config, loaded_from) = load_or_default(config_path);
        config.merge(cli_overrides);
        (config, loaded_from)
    }
}

// ============================================================================
// Example Config Generation
// ============================================================================

/// Generate an example config file content.
#[must_use] 
pub fn generate_example_config() -> String {
    let example = AppConfig::default();
    format!(
        r"# SBOM Diff Configuration
# Place this file at .sbom-tools.yaml in your project root or ~/.config/sbom-tools/

{}
",
        serde_yaml_ng::to_string(&example).unwrap_or_default()
    )
}

/// Generate a commented example config with all options.
#[must_use] 
pub fn generate_full_example_config() -> String {
    r"# SBOM Diff Configuration File
# ==============================
#
# This file configures sbom-tools behavior. Place it at:
#   - .sbom-tools.yaml in your project root
#   - ~/.config/sbom-tools/sbom-tools.yaml for global config
#
# CLI arguments always override file settings.

# Matching configuration
matching:
  # Preset: strict, balanced, permissive, security-focused
  fuzzy_preset: balanced
  # Custom threshold (0.0-1.0), overrides preset
  # threshold: 0.85
  # Include unchanged components in output
  include_unchanged: false

# Output configuration
output:
  # Format: auto, json, text, sarif, markdown, html
  format: auto
  # Output file path (omit for stdout)
  # file: report.json
  # Disable colored output
  no_color: false

# Filtering options
filtering:
  # Only show items with changes
  only_changes: false
  # Minimum severity filter: critical, high, medium, low, info
  # min_severity: high

# Behavior flags
behavior:
  # Exit with code 2 if new vulnerabilities are introduced
  fail_on_vuln: false
  # Exit with code 1 if any changes detected
  fail_on_change: false
  # Suppress non-essential output
  quiet: false
  # Show detailed match explanations
  explain_matches: false
  # Recommend optimal matching threshold
  recommend_threshold: false

# Graph-aware diffing
graph_diff:
  enabled: false
  detect_reparenting: true
  detect_depth_changes: true

# Custom matching rules
rules:
  # Path to matching rules YAML file
  # rules_file: ./matching-rules.yaml
  dry_run: false

# Ecosystem-specific rules
ecosystem_rules:
  # Path to ecosystem rules config
  # config_file: ./ecosystem-rules.yaml
  disabled: false
  detect_typosquats: false

# TUI configuration
tui:
  # Theme: dark, light, high-contrast
  theme: dark
  show_line_numbers: true
  mouse_enabled: true
  initial_threshold: 0.8

# Enrichment configuration (optional)
# enrichment:
#   enabled: true
#   provider: osv
#   cache_ttl: 3600
#   max_concurrent: 10
"
    .to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_find_config_in_dir() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join(".sbom-tools.yaml");
        std::fs::write(&config_path, "matching:\n  fuzzy_preset: strict\n").unwrap();

        let found = find_config_in_dir(tmp.path());
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn test_find_config_in_dir_not_found() {
        let tmp = TempDir::new().unwrap();
        let found = find_config_in_dir(tmp.path());
        assert_eq!(found, None);
    }

    #[test]
    fn test_load_config_file() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.yaml");

        let yaml = r#"
matching:
  fuzzy_preset: strict
  threshold: 0.9
behavior:
  fail_on_vuln: true
"#;
        std::fs::write(&config_path, yaml).unwrap();

        let config = load_config_file(&config_path).unwrap();
        assert_eq!(config.matching.fuzzy_preset, "strict");
        assert_eq!(config.matching.threshold, Some(0.9));
        assert!(config.behavior.fail_on_vuln);
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config_file(Path::new("/nonexistent/config.yaml"));
        assert!(matches!(result, Err(ConfigFileError::NotFound(_))));
    }

    #[test]
    fn test_config_merge() {
        let mut base = AppConfig::default();
        let override_config = AppConfig {
            matching: super::super::types::MatchingConfig {
                fuzzy_preset: "strict".to_string(),
                threshold: Some(0.95),
                include_unchanged: false,
            },
            behavior: super::super::types::BehaviorConfig {
                fail_on_vuln: true,
                ..Default::default()
            },
            ..AppConfig::default()
        };

        base.merge(&override_config);

        assert_eq!(base.matching.fuzzy_preset, "strict");
        assert_eq!(base.matching.threshold, Some(0.95));
        assert!(base.behavior.fail_on_vuln);
    }

    #[test]
    fn test_generate_example_config() {
        let example = generate_example_config();
        assert!(example.contains("matching:"));
        assert!(example.contains("fuzzy_preset"));
    }

    #[test]
    fn test_discover_explicit_path() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("custom-config.yaml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        writeln!(file, "matching:\n  fuzzy_preset: strict").unwrap();

        let discovered = discover_config_file(Some(&config_path));
        assert_eq!(discovered, Some(config_path));
    }
}
