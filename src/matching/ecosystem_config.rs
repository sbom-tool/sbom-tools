//! Ecosystem-specific configuration for package matching rules.
//!
//! This module provides configurable rules for normalizing and matching
//! package names across different ecosystems (npm, PyPI, Cargo, Maven, etc.).
//!
//! Configuration can be loaded from YAML files or use built-in defaults.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Root configuration for ecosystem rules
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcosystemRulesConfig {
    /// Configuration format version
    #[serde(default = "default_version")]
    pub version: String,

    /// Global settings
    #[serde(default)]
    pub settings: GlobalSettings,

    /// Per-ecosystem configuration
    #[serde(default)]
    pub ecosystems: HashMap<String, EcosystemConfig>,

    /// Cross-ecosystem package mappings (concept -> ecosystem -> package)
    #[serde(default)]
    pub cross_ecosystem: HashMap<String, HashMap<String, Option<String>>>,

    /// Custom organization-specific rules
    #[serde(default)]
    pub custom_rules: CustomRules,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Global settings that apply across all ecosystems
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalSettings {
    /// Default case sensitivity for ecosystems without explicit setting
    #[serde(default)]
    pub case_sensitive_default: bool,

    /// Whether to normalize unicode characters
    #[serde(default = "default_true")]
    pub normalize_unicode: bool,

    /// Enable security checks (typosquat detection, suspicious patterns)
    #[serde(default = "default_true")]
    pub enable_security_checks: bool,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            case_sensitive_default: false,
            normalize_unicode: true,
            enable_security_checks: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Configuration for a specific ecosystem
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EcosystemConfig {
    /// Name normalization settings
    #[serde(default)]
    pub normalization: NormalizationConfig,

    /// Prefixes to strip for fuzzy matching
    #[serde(default)]
    pub strip_prefixes: Vec<String>,

    /// Suffixes to strip for fuzzy matching
    #[serde(default)]
    pub strip_suffixes: Vec<String>,

    /// Known package aliases (canonical -> aliases)
    #[serde(default)]
    pub aliases: HashMap<String, Vec<String>>,

    /// Package groups (for monorepos)
    #[serde(default)]
    pub package_groups: HashMap<String, PackageGroup>,

    /// Version handling configuration
    #[serde(default)]
    pub versioning: VersioningConfig,

    /// Security-related configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// Import path mappings (for Go, etc.)
    #[serde(default)]
    pub import_mappings: Vec<ImportMapping>,

    /// Group/namespace migrations (for Maven javax->jakarta, etc.)
    #[serde(default)]
    pub group_migrations: Vec<GroupMigration>,
}

/// Name normalization configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NormalizationConfig {
    /// Whether name matching is case-sensitive
    #[serde(default)]
    pub case_sensitive: bool,

    /// Characters that should be treated as equivalent
    /// e.g., ["-", "_", "."] means foo-bar == foo_bar == foo.bar
    #[serde(default)]
    pub equivalent_chars: Vec<Vec<String>>,

    /// Whether to collapse repeated separators
    #[serde(default)]
    pub collapse_separators: bool,

    /// Whether to use full coordinate (groupId:artifactId for Maven)
    #[serde(default)]
    pub use_full_coordinate: bool,

    /// Whether to strip version suffix from module path (Go /v2, /v3)
    #[serde(default)]
    pub strip_version_suffix: bool,

    /// How to handle scoped packages (npm @scope/name)
    #[serde(default)]
    pub scope_handling: ScopeHandling,
}

/// How to handle scoped package names
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeHandling {
    /// Lowercase everything
    #[default]
    Lowercase,
    /// Preserve case in scope, lowercase name
    PreserveScopeCase,
    /// Preserve all case
    PreserveCase,
}

/// Package group definition (for monorepos)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PackageGroup {
    /// Canonical package name
    pub canonical: String,

    /// Member packages (can use glob patterns like "@babel/*")
    #[serde(default)]
    pub members: Vec<String>,
}

/// Version handling configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersioningConfig {
    /// Version specification type
    #[serde(default = "default_semver")]
    pub spec: VersionSpec,

    /// Pre-release identifier tags
    #[serde(default)]
    pub prerelease_tags: Vec<String>,

    /// Qualifier ordering (for Maven)
    #[serde(default)]
    pub qualifier_order: Vec<String>,
}

fn default_semver() -> VersionSpec {
    VersionSpec::Semver
}

impl Default for VersioningConfig {
    fn default() -> Self {
        Self {
            spec: VersionSpec::Semver,
            prerelease_tags: vec![],
            qualifier_order: vec![],
        }
    }
}

/// Version specification type
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VersionSpec {
    /// Semantic Versioning (npm, cargo, nuget)
    #[default]
    Semver,
    /// PEP 440 (Python)
    Pep440,
    /// Maven versioning
    Maven,
    /// RubyGems versioning
    Rubygems,
    /// Go module versioning
    Gomod,
    /// Generic/unknown
    Generic,
}

/// Security-related configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Known typosquat packages
    #[serde(default)]
    pub known_typosquats: Vec<TyposquatEntry>,

    /// Regex patterns for suspicious package names
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,

    /// Known malicious packages to warn about
    #[serde(default)]
    pub known_malicious: Vec<String>,
}

/// Typosquat package mapping
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TyposquatEntry {
    /// The malicious/typosquat package name
    pub malicious: String,

    /// The legitimate package it mimics
    pub legitimate: String,

    /// Optional description of the typosquat
    #[serde(default)]
    pub description: Option<String>,
}

/// Import path mapping (for Go modules)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImportMapping {
    /// Pattern to match (glob-style)
    pub pattern: String,

    /// Type of import (github, stdlib_extension, etc.)
    #[serde(rename = "type")]
    pub mapping_type: String,
}

/// Group/namespace migration (e.g., javax -> jakarta)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupMigration {
    /// Pattern to match (can use wildcards)
    pub from: String,

    /// Replacement pattern
    pub to: String,

    /// Optional version threshold (migration applies after this version)
    #[serde(default)]
    pub after_version: Option<String>,
}

/// Custom organization-specific rules
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CustomRules {
    /// Internal package prefixes to recognize
    #[serde(default)]
    pub internal_prefixes: Vec<String>,

    /// Custom equivalence mappings
    #[serde(default)]
    pub equivalences: Vec<CustomEquivalence>,

    /// Packages to always ignore in diffs
    #[serde(default)]
    pub ignored_packages: Vec<String>,
}

/// Custom equivalence mapping
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomEquivalence {
    /// Canonical package identifier
    pub canonical: String,

    /// Aliases that should map to canonical
    pub aliases: Vec<String>,

    /// Whether version must match for equivalence
    #[serde(default)]
    pub version_sensitive: bool,
}

impl EcosystemRulesConfig {
    /// Create a new empty configuration
    pub fn new() -> Self {
        Self {
            version: default_version(),
            settings: GlobalSettings::default(),
            ecosystems: HashMap::new(),
            cross_ecosystem: HashMap::new(),
            custom_rules: CustomRules::default(),
        }
    }

    /// Create configuration with built-in defaults
    pub fn builtin() -> Self {
        let mut config = Self::new();
        config.load_builtin_rules();
        config
    }

    /// Load configuration from a YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    /// Load configuration from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Load configuration from a file (auto-detects format)
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::Io)?;

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match extension.to_lowercase().as_str() {
            "yaml" | "yml" => Self::from_yaml(&content).map_err(ConfigError::Yaml),
            "json" => Self::from_json(&content).map_err(ConfigError::Json),
            _ => {
                // Try YAML first, then JSON
                Self::from_yaml(&content)
                    .map_err(ConfigError::Yaml)
                    .or_else(|_| Self::from_json(&content).map_err(ConfigError::Json))
            }
        }
    }

    /// Load configuration with precedence from multiple locations
    pub fn load_with_precedence(paths: &[&str]) -> Result<Self, ConfigError> {
        for path_str in paths {
            let path = if path_str.starts_with('~') {
                if let Some(home) = dirs::home_dir() {
                    home.join(&path_str[2..])
                } else {
                    continue;
                }
            } else {
                Path::new(path_str).to_path_buf()
            };

            if path.exists() {
                return Self::from_file(&path);
            }
        }

        // No config file found, use built-in defaults
        Ok(Self::builtin())
    }

    /// Load built-in ecosystem rules
    fn load_builtin_rules(&mut self) {
        // PyPI rules
        self.ecosystems.insert(
            "pypi".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: false,
                    equivalent_chars: vec![vec!["-".to_string(), "_".to_string(), ".".to_string()]],
                    collapse_separators: true,
                    ..Default::default()
                },
                strip_prefixes: vec!["python-".to_string(), "py-".to_string(), "lib".to_string()],
                strip_suffixes: vec![
                    "-python".to_string(),
                    "-py".to_string(),
                    "-py3".to_string(),
                    "-lib".to_string(),
                ],
                aliases: Self::pypi_aliases(),
                versioning: VersioningConfig {
                    spec: VersionSpec::Pep440,
                    prerelease_tags: vec![
                        "a".to_string(),
                        "b".to_string(),
                        "rc".to_string(),
                        "alpha".to_string(),
                        "beta".to_string(),
                        "dev".to_string(),
                        "post".to_string(),
                    ],
                    ..Default::default()
                },
                security: SecurityConfig {
                    known_typosquats: vec![
                        TyposquatEntry {
                            malicious: "python-dateutils".to_string(),
                            legitimate: "python-dateutil".to_string(),
                            description: Some("Common typosquat".to_string()),
                        },
                        TyposquatEntry {
                            malicious: "request".to_string(),
                            legitimate: "requests".to_string(),
                            description: Some("Missing 's' typosquat".to_string()),
                        },
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // npm rules
        self.ecosystems.insert(
            "npm".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: false,
                    scope_handling: ScopeHandling::PreserveScopeCase,
                    ..Default::default()
                },
                strip_prefixes: vec!["node-".to_string(), "@types/".to_string()],
                strip_suffixes: vec!["-js".to_string(), ".js".to_string(), "-node".to_string()],
                package_groups: Self::npm_package_groups(),
                versioning: VersioningConfig {
                    spec: VersionSpec::Semver,
                    prerelease_tags: vec![
                        "alpha".to_string(),
                        "beta".to_string(),
                        "rc".to_string(),
                        "next".to_string(),
                        "canary".to_string(),
                    ],
                    ..Default::default()
                },
                security: SecurityConfig {
                    suspicious_patterns: vec![
                        r"^[a-z]{1,2}$".to_string(), // Very short names
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // Cargo rules
        self.ecosystems.insert(
            "cargo".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: false,
                    // Replace "-" with "_" (target is first, source is second)
                    equivalent_chars: vec![vec!["_".to_string(), "-".to_string()]],
                    ..Default::default()
                },
                strip_prefixes: vec!["rust-".to_string(), "lib".to_string()],
                strip_suffixes: vec!["-rs".to_string(), "-rust".to_string()],
                versioning: VersioningConfig {
                    spec: VersionSpec::Semver,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // Maven rules
        self.ecosystems.insert(
            "maven".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: true,
                    use_full_coordinate: true,
                    ..Default::default()
                },
                group_migrations: vec![GroupMigration {
                    from: "javax.*".to_string(),
                    to: "jakarta.*".to_string(),
                    after_version: Some("9".to_string()),
                }],
                versioning: VersioningConfig {
                    spec: VersionSpec::Maven,
                    qualifier_order: vec![
                        "alpha".to_string(),
                        "beta".to_string(),
                        "milestone".to_string(),
                        "rc".to_string(),
                        "snapshot".to_string(),
                        "final".to_string(),
                        "ga".to_string(),
                        "sp".to_string(),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // Go rules
        self.ecosystems.insert(
            "golang".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: true,
                    strip_version_suffix: true,
                    ..Default::default()
                },
                import_mappings: vec![
                    ImportMapping {
                        pattern: "github.com/*/*".to_string(),
                        mapping_type: "github".to_string(),
                    },
                    ImportMapping {
                        pattern: "golang.org/x/*".to_string(),
                        mapping_type: "stdlib_extension".to_string(),
                    },
                ],
                versioning: VersioningConfig {
                    spec: VersionSpec::Gomod,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // NuGet rules
        self.ecosystems.insert(
            "nuget".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: false,
                    ..Default::default()
                },
                versioning: VersioningConfig {
                    spec: VersionSpec::Semver,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // RubyGems rules
        self.ecosystems.insert(
            "rubygems".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: true,
                    ..Default::default()
                },
                strip_prefixes: vec!["ruby-".to_string()],
                strip_suffixes: vec!["-ruby".to_string(), "-rb".to_string()],
                versioning: VersioningConfig {
                    spec: VersionSpec::Rubygems,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // Composer (PHP) rules
        self.ecosystems.insert(
            "composer".to_string(),
            EcosystemConfig {
                normalization: NormalizationConfig {
                    case_sensitive: false,
                    use_full_coordinate: true,
                    ..Default::default()
                },
                versioning: VersioningConfig {
                    spec: VersionSpec::Semver,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // Cross-ecosystem mappings
        self.load_cross_ecosystem_mappings();
    }

    /// PyPI known aliases
    fn pypi_aliases() -> HashMap<String, Vec<String>> {
        let mut aliases = HashMap::new();
        aliases.insert(
            "pillow".to_string(),
            vec!["PIL".to_string(), "python-pillow".to_string()],
        );
        aliases.insert(
            "scikit-learn".to_string(),
            vec!["sklearn".to_string(), "scikit_learn".to_string()],
        );
        aliases.insert(
            "beautifulsoup4".to_string(),
            vec![
                "bs4".to_string(),
                "BeautifulSoup".to_string(),
                "beautifulsoup".to_string(),
            ],
        );
        aliases.insert(
            "pyyaml".to_string(),
            vec!["yaml".to_string(), "PyYAML".to_string()],
        );
        aliases.insert(
            "opencv-python".to_string(),
            vec![
                "cv2".to_string(),
                "opencv-python-headless".to_string(),
                "opencv".to_string(),
            ],
        );
        aliases.insert("python-dateutil".to_string(), vec!["dateutil".to_string()]);
        aliases.insert("attrs".to_string(), vec!["attr".to_string()]);
        aliases.insert(
            "importlib-metadata".to_string(),
            vec!["importlib_metadata".to_string()],
        );
        aliases.insert(
            "typing-extensions".to_string(),
            vec!["typing_extensions".to_string()],
        );
        aliases
    }

    /// npm package groups
    fn npm_package_groups() -> HashMap<String, PackageGroup> {
        let mut groups = HashMap::new();
        groups.insert(
            "lodash".to_string(),
            PackageGroup {
                canonical: "lodash".to_string(),
                members: vec![
                    "lodash-es".to_string(),
                    "lodash.merge".to_string(),
                    "lodash.get".to_string(),
                    "lodash.set".to_string(),
                    "lodash.clonedeep".to_string(),
                ],
            },
        );
        groups.insert(
            "babel".to_string(),
            PackageGroup {
                canonical: "@babel/core".to_string(),
                members: vec!["@babel/*".to_string()],
            },
        );
        groups.insert(
            "react".to_string(),
            PackageGroup {
                canonical: "react".to_string(),
                members: vec![
                    "react-dom".to_string(),
                    "react-router".to_string(),
                    "react-redux".to_string(),
                ],
            },
        );
        groups
    }

    /// Load cross-ecosystem package mappings
    fn load_cross_ecosystem_mappings(&mut self) {
        // YAML parsing libraries
        let mut yaml_mapping = HashMap::new();
        yaml_mapping.insert("pypi".to_string(), Some("pyyaml".to_string()));
        yaml_mapping.insert("npm".to_string(), Some("js-yaml".to_string()));
        yaml_mapping.insert("cargo".to_string(), Some("serde_yaml".to_string()));
        yaml_mapping.insert("golang".to_string(), Some("gopkg.in/yaml.v3".to_string()));
        yaml_mapping.insert("rubygems".to_string(), Some("psych".to_string()));
        self.cross_ecosystem
            .insert("yaml_parsing".to_string(), yaml_mapping);

        // JSON parsing libraries
        let mut json_mapping = HashMap::new();
        json_mapping.insert("pypi".to_string(), None); // stdlib
        json_mapping.insert("npm".to_string(), None); // native
        json_mapping.insert("cargo".to_string(), Some("serde_json".to_string()));
        json_mapping.insert("golang".to_string(), None); // encoding/json stdlib
        self.cross_ecosystem
            .insert("json_parsing".to_string(), json_mapping);

        // HTTP client libraries
        let mut http_mapping = HashMap::new();
        http_mapping.insert("pypi".to_string(), Some("requests".to_string()));
        http_mapping.insert("npm".to_string(), Some("axios".to_string()));
        http_mapping.insert("cargo".to_string(), Some("reqwest".to_string()));
        http_mapping.insert("golang".to_string(), None); // net/http stdlib
        http_mapping.insert("rubygems".to_string(), Some("faraday".to_string()));
        self.cross_ecosystem
            .insert("http_client".to_string(), http_mapping);

        // Testing frameworks
        let mut test_mapping = HashMap::new();
        test_mapping.insert("pypi".to_string(), Some("pytest".to_string()));
        test_mapping.insert("npm".to_string(), Some("jest".to_string()));
        test_mapping.insert("cargo".to_string(), None); // built-in
        test_mapping.insert("golang".to_string(), None); // testing stdlib
        test_mapping.insert("rubygems".to_string(), Some("rspec".to_string()));
        self.cross_ecosystem
            .insert("testing".to_string(), test_mapping);
    }

    /// Get configuration for a specific ecosystem
    pub fn get_ecosystem(&self, ecosystem: &str) -> Option<&EcosystemConfig> {
        self.ecosystems.get(&ecosystem.to_lowercase())
    }

    /// Check if configuration is empty
    pub fn is_empty(&self) -> bool {
        self.ecosystems.is_empty()
            && self.cross_ecosystem.is_empty()
            && self.custom_rules.equivalences.is_empty()
    }

    /// Merge another configuration into this one (other takes precedence)
    pub fn merge(&mut self, other: Self) {
        // Merge ecosystems
        for (key, value) in other.ecosystems {
            self.ecosystems.insert(key, value);
        }

        // Merge cross-ecosystem mappings
        for (key, value) in other.cross_ecosystem {
            self.cross_ecosystem.insert(key, value);
        }

        // Merge custom rules
        self.custom_rules
            .internal_prefixes
            .extend(other.custom_rules.internal_prefixes);
        self.custom_rules
            .equivalences
            .extend(other.custom_rules.equivalences);
        self.custom_rules
            .ignored_packages
            .extend(other.custom_rules.ignored_packages);

        // Update settings if explicitly set
        if other.settings.enable_security_checks != self.settings.enable_security_checks {
            self.settings.enable_security_checks = other.settings.enable_security_checks;
        }
    }

    /// Export configuration to YAML
    pub fn to_yaml(&self) -> Result<String, serde_yaml_ng::Error> {
        serde_yaml_ng::to_string(self)
    }

    /// Export configuration to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for EcosystemRulesConfig {
    fn default() -> Self {
        Self::builtin()
    }
}

/// Configuration loading error
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Yaml(serde_yaml_ng::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Yaml(e) => write!(f, "YAML parse error: {}", e),
            Self::Json(e) => write!(f, "JSON parse error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_config() {
        let config = EcosystemRulesConfig::builtin();

        assert!(config.ecosystems.contains_key("pypi"));
        assert!(config.ecosystems.contains_key("npm"));
        assert!(config.ecosystems.contains_key("cargo"));
        assert!(config.ecosystems.contains_key("maven"));
        assert!(config.ecosystems.contains_key("golang"));
    }

    #[test]
    fn test_pypi_config() {
        let config = EcosystemRulesConfig::builtin();
        let pypi = config.get_ecosystem("pypi").unwrap();

        assert!(!pypi.normalization.case_sensitive);
        assert!(!pypi.strip_prefixes.is_empty());
        assert!(pypi.aliases.contains_key("pillow"));
        assert_eq!(pypi.versioning.spec, VersionSpec::Pep440);
    }

    #[test]
    fn test_npm_config() {
        let config = EcosystemRulesConfig::builtin();
        let npm = config.get_ecosystem("npm").unwrap();

        assert_eq!(
            npm.normalization.scope_handling,
            ScopeHandling::PreserveScopeCase
        );
        assert!(npm.package_groups.contains_key("lodash"));
    }

    #[test]
    fn test_cross_ecosystem_mapping() {
        let config = EcosystemRulesConfig::builtin();

        let yaml_libs = config.cross_ecosystem.get("yaml_parsing").unwrap();
        assert_eq!(yaml_libs.get("pypi").unwrap(), &Some("pyyaml".to_string()));
        assert_eq!(yaml_libs.get("npm").unwrap(), &Some("js-yaml".to_string()));
    }

    #[test]
    fn test_yaml_parsing() {
        let yaml = r#"
version: "1.0"
settings:
  case_sensitive_default: false
ecosystems:
  custom:
    normalization:
      case_sensitive: true
    strip_prefixes:
      - "my-"
    strip_suffixes:
      - "-custom"
"#;

        let config = EcosystemRulesConfig::from_yaml(yaml).unwrap();
        assert!(config.ecosystems.contains_key("custom"));

        let custom = config.get_ecosystem("custom").unwrap();
        assert!(custom.normalization.case_sensitive);
        assert_eq!(custom.strip_prefixes, vec!["my-"]);
    }

    #[test]
    fn test_config_merge() {
        let mut base = EcosystemRulesConfig::builtin();
        let overlay = EcosystemRulesConfig::from_yaml(
            r#"
ecosystems:
  pypi:
    strip_prefixes:
      - "custom-"
custom_rules:
  internal_prefixes:
    - "@mycompany/"
"#,
        )
        .unwrap();

        base.merge(overlay);

        // Overlay should override pypi
        let pypi = base.get_ecosystem("pypi").unwrap();
        assert_eq!(pypi.strip_prefixes, vec!["custom-"]);

        // Custom rules should be merged
        assert!(base
            .custom_rules
            .internal_prefixes
            .contains(&"@mycompany/".to_string()));
    }

    #[test]
    fn test_security_config() {
        let config = EcosystemRulesConfig::builtin();
        let pypi = config.get_ecosystem("pypi").unwrap();

        assert!(!pypi.security.known_typosquats.is_empty());
        let typosquat = &pypi.security.known_typosquats[0];
        assert_eq!(typosquat.malicious, "python-dateutils");
        assert_eq!(typosquat.legitimate, "python-dateutil");
    }
}
