//! Ecosystem-specific matching rules.
//!
//! Provides configurable rules for normalizing and matching package names
//! according to each ecosystem's conventions.

use crate::model::Ecosystem;
use regex::Regex;
use std::collections::HashMap;

use super::ecosystem_config::{
    ConfigError, EcosystemConfig, EcosystemRulesConfig, NormalizationConfig, ScopeHandling,
    TyposquatEntry,
};

/// Ecosystem-specific normalization and matching rules.
pub struct EcosystemRules {
    /// Configuration
    config: EcosystemRulesConfig,
    /// Compiled regex patterns for suspicious package detection
    suspicious_patterns: HashMap<String, Vec<Regex>>,
    /// Compiled regex patterns for group migrations
    migration_patterns: HashMap<String, Vec<(Regex, String)>>,
    /// Compiled regex patterns for package group glob members
    /// Key: ecosystem -> group_name -> Vec<Regex>
    package_group_patterns: HashMap<String, HashMap<String, Vec<Regex>>>,
}

impl EcosystemRules {
    /// Create a new ecosystem rules instance with built-in defaults
    pub fn new() -> Self {
        Self::with_config(EcosystemRulesConfig::builtin())
    }

    /// Create ecosystem rules with custom configuration
    pub fn with_config(config: EcosystemRulesConfig) -> Self {
        let suspicious_patterns = Self::compile_suspicious_patterns(&config);
        let migration_patterns = Self::compile_migration_patterns(&config);
        let package_group_patterns = Self::compile_package_group_patterns(&config);

        Self {
            config,
            suspicious_patterns,
            migration_patterns,
            package_group_patterns,
        }
    }

    /// Load configuration from a file
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let config = EcosystemRulesConfig::from_file(path)?;
        Ok(Self::with_config(config))
    }

    /// Load configuration from default locations with precedence
    pub fn from_default_locations() -> Self {
        let config = EcosystemRulesConfig::load_with_precedence(&[
            ".sbom-tools/ecosystem-rules.yaml",
            ".sbom-tools/ecosystem-rules.json",
            "~/.config/sbom-tools/ecosystem-rules.yaml",
            "~/.config/sbom-tools/ecosystem-rules.json",
        ])
        .unwrap_or_else(|_| EcosystemRulesConfig::builtin());

        Self::with_config(config)
    }

    /// Compile suspicious package name patterns
    fn compile_suspicious_patterns(config: &EcosystemRulesConfig) -> HashMap<String, Vec<Regex>> {
        let mut patterns = HashMap::with_capacity(config.ecosystems.len());

        for (ecosystem, eco_config) in &config.ecosystems {
            let mut compiled = Vec::with_capacity(eco_config.security.suspicious_patterns.len());
            for pattern in &eco_config.security.suspicious_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    compiled.push(re);
                }
            }
            if !compiled.is_empty() {
                patterns.insert(ecosystem.clone(), compiled);
            }
        }

        patterns
    }

    /// Compile group migration patterns
    fn compile_migration_patterns(
        config: &EcosystemRulesConfig,
    ) -> HashMap<String, Vec<(Regex, String)>> {
        let mut patterns = HashMap::with_capacity(config.ecosystems.len());

        for (ecosystem, eco_config) in &config.ecosystems {
            let mut compiled = Vec::with_capacity(eco_config.group_migrations.len());
            for migration in &eco_config.group_migrations {
                // Convert glob pattern to regex
                let regex_pattern = migration.from.replace('.', r"\.").replace('*', ".*");
                if let Ok(re) = Regex::new(&format!("^{regex_pattern}$")) {
                    compiled.push((re, migration.to.clone()));
                }
            }
            if !compiled.is_empty() {
                patterns.insert(ecosystem.clone(), compiled);
            }
        }

        patterns
    }

    /// Compile package group glob patterns for efficient matching
    fn compile_package_group_patterns(
        config: &EcosystemRulesConfig,
    ) -> HashMap<String, HashMap<String, Vec<Regex>>> {
        let mut eco_patterns = HashMap::with_capacity(config.ecosystems.len());

        for (ecosystem, eco_config) in &config.ecosystems {
            let mut group_patterns = HashMap::with_capacity(eco_config.package_groups.len());

            for (group_name, group) in &eco_config.package_groups {
                // Count glob patterns to pre-allocate
                let glob_count = group.members.iter().filter(|m| m.contains('*')).count();
                let mut compiled = Vec::with_capacity(glob_count);
                for member in &group.members {
                    if member.contains('*') {
                        // Convert glob pattern to regex
                        let regex_pattern = member.replace('.', r"\.").replace('*', ".*");
                        if let Ok(re) = Regex::new(&format!("^{regex_pattern}$")) {
                            compiled.push(re);
                        }
                    }
                }
                if !compiled.is_empty() {
                    group_patterns.insert(group_name.clone(), compiled);
                }
            }

            if !group_patterns.is_empty() {
                eco_patterns.insert(ecosystem.clone(), group_patterns);
            }
        }

        eco_patterns
    }

    /// Get the underlying configuration
    pub fn config(&self) -> &EcosystemRulesConfig {
        &self.config
    }

    /// Normalize a package name according to ecosystem rules
    pub fn normalize_name(&self, name: &str, ecosystem: &Ecosystem) -> String {
        let eco_key = Self::ecosystem_key(ecosystem);

        self.config.ecosystems.get(&eco_key).map_or_else(
            || {
                // Fallback to basic normalization
                name.to_lowercase()
            },
            |eco_config| self.apply_normalization(name, eco_config),
        )
    }

    /// Apply normalization rules from config
    fn apply_normalization(&self, name: &str, config: &EcosystemConfig) -> String {
        let norm = &config.normalization;
        let mut result = name.to_string();

        // Handle scoped packages (npm @scope/name)
        if result.starts_with('@') {
            result = self.normalize_scoped_name(&result, norm);
        } else {
            // Apply case sensitivity
            if !norm.case_sensitive {
                result = result.to_lowercase();
            }
        }

        // Apply character equivalence
        for char_group in &norm.equivalent_chars {
            if char_group.len() >= 2 {
                let target = &char_group[0];
                for source in &char_group[1..] {
                    result = result.replace(source.as_str(), target);
                }
            }
        }

        // Collapse separators if enabled
        if norm.collapse_separators {
            result = self.collapse_separators(&result);
        }

        // Strip version suffix for Go modules
        if norm.strip_version_suffix {
            result = self.strip_go_version_suffix(&result);
        }

        result
    }

    /// Normalize scoped package name (npm @scope/name)
    fn normalize_scoped_name(&self, name: &str, norm: &NormalizationConfig) -> String {
        match norm.scope_handling {
            ScopeHandling::Lowercase => name.to_lowercase(),
            ScopeHandling::PreserveScopeCase => {
                name.find('/').map_or_else(
                    || name.to_lowercase(),
                    |slash_pos| {
                        let scope = &name[..slash_pos];
                        let pkg_name = &name[slash_pos + 1..];
                        format!("{}/{}", scope.to_lowercase(), pkg_name.to_lowercase())
                    },
                )
            }
            ScopeHandling::PreserveCase => name.to_string(),
        }
    }

    /// Collapse repeated separators (hyphens, underscores, dots)
    fn collapse_separators(&self, name: &str) -> String {
        let mut result = String::with_capacity(name.len());
        let mut last_was_sep = false;

        for c in name.chars() {
            let is_sep = c == '-' || c == '_' || c == '.';
            if is_sep {
                if !last_was_sep {
                    result.push(c);
                }
                last_was_sep = true;
            } else {
                result.push(c);
                last_was_sep = false;
            }
        }

        // Trim separators from ends
        result
            .trim_matches(|c| c == '-' || c == '_' || c == '.')
            .to_string()
    }

    /// Strip Go module version suffix (/v2, /v3, etc.)
    fn strip_go_version_suffix(&self, name: &str) -> String {
        use std::sync::LazyLock;
        static GO_VERSION_SUFFIX: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"/v\d+$").expect("static regex"));
        GO_VERSION_SUFFIX.replace(name, "").to_string()
    }

    /// Check if two names match according to ecosystem rules
    pub fn names_match(&self, name_a: &str, name_b: &str, ecosystem: &Ecosystem) -> bool {
        let norm_a = self.normalize_name(name_a, ecosystem);
        let norm_b = self.normalize_name(name_b, ecosystem);
        norm_a == norm_b
    }

    /// Get the canonical name for an alias
    pub fn get_canonical(&self, name: &str, ecosystem: &Ecosystem) -> Option<String> {
        let eco_key = Self::ecosystem_key(ecosystem);
        let name_lower = name.to_lowercase();

        if let Some(eco_config) = self.config.ecosystems.get(&eco_key) {
            for (canonical, aliases) in &eco_config.aliases {
                if canonical.to_lowercase() == name_lower {
                    return Some(canonical.clone());
                }
                for alias in aliases {
                    if alias.to_lowercase() == name_lower {
                        return Some(canonical.clone());
                    }
                }
            }
        }

        // Check custom equivalences
        for equiv in &self.config.custom_rules.equivalences {
            if equiv.canonical.to_lowercase() == name_lower {
                return Some(equiv.canonical.clone());
            }
            for alias in &equiv.aliases {
                if alias.to_lowercase() == name_lower {
                    return Some(equiv.canonical.clone());
                }
            }
        }

        None
    }

    /// Check if a name is an alias of a canonical name
    pub fn is_alias(&self, canonical: &str, name: &str, ecosystem: &Ecosystem) -> bool {
        let eco_key = Self::ecosystem_key(ecosystem);
        let name_lower = name.to_lowercase();
        let canonical_lower = canonical.to_lowercase();

        if let Some(eco_config) = self.config.ecosystems.get(&eco_key) {
            if let Some(aliases) = eco_config.aliases.get(&canonical_lower) {
                return aliases.iter().any(|a| a.to_lowercase() == name_lower);
            }
        }

        false
    }

    /// Get common suffixes to strip for a given ecosystem
    pub fn get_strip_suffixes(&self, ecosystem: &Ecosystem) -> Vec<&str> {
        let eco_key = Self::ecosystem_key(ecosystem);

        self.config
            .ecosystems
            .get(&eco_key)
            .map(|c| c.strip_suffixes.iter().map(std::string::String::as_str).collect())
            .unwrap_or_default()
    }

    /// Get common prefixes to strip for a given ecosystem
    pub fn get_strip_prefixes(&self, ecosystem: &Ecosystem) -> Vec<&str> {
        let eco_key = Self::ecosystem_key(ecosystem);

        self.config
            .ecosystems
            .get(&eco_key)
            .map(|c| c.strip_prefixes.iter().map(std::string::String::as_str).collect())
            .unwrap_or_default()
    }

    /// Normalize name by stripping common prefixes/suffixes
    pub fn strip_affixes(&self, name: &str, ecosystem: &Ecosystem) -> String {
        let mut result = name.to_lowercase();

        for prefix in self.get_strip_prefixes(ecosystem) {
            if result.starts_with(prefix) {
                result = result[prefix.len()..].to_string();
                break;
            }
        }

        for suffix in self.get_strip_suffixes(ecosystem) {
            if result.ends_with(suffix) {
                result = result[..result.len() - suffix.len()].to_string();
                break;
            }
        }

        result
    }

    /// Check if a package name is a known typosquat
    pub fn is_typosquat(&self, name: &str, ecosystem: &Ecosystem) -> Option<&TyposquatEntry> {
        if !self.config.settings.enable_security_checks {
            return None;
        }

        let eco_key = Self::ecosystem_key(ecosystem);
        let name_lower = name.to_lowercase();

        if let Some(eco_config) = self.config.ecosystems.get(&eco_key) {
            for entry in &eco_config.security.known_typosquats {
                if entry.malicious.to_lowercase() == name_lower {
                    return Some(entry);
                }
            }
        }

        None
    }

    /// Check if a package name matches suspicious patterns
    pub fn is_suspicious(&self, name: &str, ecosystem: &Ecosystem) -> bool {
        if !self.config.settings.enable_security_checks {
            return false;
        }

        let eco_key = Self::ecosystem_key(ecosystem);

        self.suspicious_patterns.get(&eco_key).is_some_and(|patterns| patterns.iter().any(|re| re.is_match(name)))
    }

    /// Check if a package is a known malicious package
    pub fn is_known_malicious(&self, name: &str, ecosystem: &Ecosystem) -> bool {
        if !self.config.settings.enable_security_checks {
            return false;
        }

        let eco_key = Self::ecosystem_key(ecosystem);
        let name_lower = name.to_lowercase();

        self.config.ecosystems.get(&eco_key).is_some_and(|eco_config| {
            eco_config
                .security
                .known_malicious
                .iter()
                .any(|m| m.to_lowercase() == name_lower)
        })
    }

    /// Get the migrated group ID (for Maven javax -> jakarta, etc.)
    pub fn get_migrated_group(&self, group: &str, ecosystem: &Ecosystem) -> Option<String> {
        let eco_key = Self::ecosystem_key(ecosystem);

        if let Some(patterns) = self.migration_patterns.get(&eco_key) {
            for (pattern, replacement) in patterns {
                if pattern.is_match(group) {
                    let migrated = pattern.replace(group, replacement.as_str());
                    return Some(migrated.to_string());
                }
            }
        }

        None
    }

    /// Check if a package is part of a package group
    pub fn get_package_group(&self, name: &str, ecosystem: &Ecosystem) -> Option<&str> {
        let eco_key = Self::ecosystem_key(ecosystem);
        let name_lower = name.to_lowercase();

        if let Some(eco_config) = self.config.ecosystems.get(&eco_key) {
            // Get pre-compiled patterns for this ecosystem (if any)
            let compiled_patterns = self.package_group_patterns.get(&eco_key);

            for (group_name, group) in &eco_config.package_groups {
                // Check canonical
                if group.canonical.to_lowercase() == name_lower {
                    return Some(group_name);
                }

                // Check members using pre-compiled patterns for globs
                for member in &group.members {
                    if member.contains('*') {
                        // Use pre-compiled pattern
                        if let Some(group_patterns) = compiled_patterns {
                            if let Some(patterns) = group_patterns.get(group_name) {
                                if patterns.iter().any(|re| re.is_match(&name_lower)) {
                                    return Some(group_name);
                                }
                            }
                        }
                    } else if member.to_lowercase() == name_lower {
                        return Some(group_name);
                    }
                }
            }
        }

        None
    }

    /// Get cross-ecosystem equivalent package
    pub fn get_cross_ecosystem_equivalent(
        &self,
        concept: &str,
        target_ecosystem: &Ecosystem,
    ) -> Option<&str> {
        let eco_key = Self::ecosystem_key(target_ecosystem);

        self.config
            .cross_ecosystem
            .get(concept)
            .and_then(|mapping| mapping.get(&eco_key))
            .and_then(|opt| opt.as_deref())
    }

    /// Check if a package is an internal/organization package
    pub fn is_internal_package(&self, name: &str) -> bool {
        self.config
            .custom_rules
            .internal_prefixes
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

    /// Check if a package should be ignored in diffs
    pub fn is_ignored(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.config
            .custom_rules
            .ignored_packages
            .iter()
            .any(|p| p.to_lowercase() == name_lower)
    }

    /// Convert Ecosystem enum to string key
    fn ecosystem_key(ecosystem: &Ecosystem) -> String {
        match ecosystem {
            Ecosystem::Npm => "npm".to_string(),
            Ecosystem::PyPi => "pypi".to_string(),
            Ecosystem::Cargo => "cargo".to_string(),
            Ecosystem::Maven => "maven".to_string(),
            Ecosystem::Golang => "golang".to_string(),
            Ecosystem::Nuget => "nuget".to_string(),
            Ecosystem::RubyGems => "rubygems".to_string(),
            Ecosystem::Composer => "composer".to_string(),
            Ecosystem::CocoaPods => "cocoapods".to_string(),
            Ecosystem::Swift => "swift".to_string(),
            Ecosystem::Hex => "hex".to_string(),
            Ecosystem::Pub => "pub".to_string(),
            Ecosystem::Hackage => "hackage".to_string(),
            Ecosystem::Cpan => "cpan".to_string(),
            Ecosystem::Cran => "cran".to_string(),
            Ecosystem::Conda => "conda".to_string(),
            Ecosystem::Conan => "conan".to_string(),
            Ecosystem::Deb => "deb".to_string(),
            Ecosystem::Rpm => "rpm".to_string(),
            Ecosystem::Apk => "apk".to_string(),
            Ecosystem::Generic => "generic".to_string(),
            Ecosystem::Unknown(s) => s.to_lowercase(),
        }
    }
}

impl Default for EcosystemRules {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pypi_normalization() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.normalize_name("python-dateutil", &Ecosystem::PyPi),
            "python-dateutil"
        );
        assert_eq!(
            rules.normalize_name("python_dateutil", &Ecosystem::PyPi),
            "python-dateutil"
        );
        assert_eq!(
            rules.normalize_name("Python.Dateutil", &Ecosystem::PyPi),
            "python-dateutil"
        );
    }

    #[test]
    fn test_cargo_normalization() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.normalize_name("serde-json", &Ecosystem::Cargo),
            "serde_json"
        );
        assert_eq!(
            rules.normalize_name("serde_json", &Ecosystem::Cargo),
            "serde_json"
        );
    }

    #[test]
    fn test_npm_scoped_normalization() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.normalize_name("@Angular/Core", &Ecosystem::Npm),
            "@angular/core"
        );
    }

    #[test]
    fn test_names_match() {
        let rules = EcosystemRules::new();

        assert!(rules.names_match("python-dateutil", "python_dateutil", &Ecosystem::PyPi));
        assert!(rules.names_match("serde-json", "serde_json", &Ecosystem::Cargo));
    }

    #[test]
    fn test_strip_affixes() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.strip_affixes("python-requests", &Ecosystem::PyPi),
            "requests"
        );
        assert_eq!(rules.strip_affixes("lodash-js", &Ecosystem::Npm), "lodash");
    }

    #[test]
    fn test_typosquat_detection() {
        let rules = EcosystemRules::new();

        let result = rules.is_typosquat("python-dateutils", &Ecosystem::PyPi);
        assert!(result.is_some());
        assert_eq!(result.unwrap().legitimate, "python-dateutil");

        assert!(rules.is_typosquat("requests", &Ecosystem::PyPi).is_none());
    }

    #[test]
    fn test_package_group() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.get_package_group("lodash-es", &Ecosystem::Npm),
            Some("lodash")
        );
        assert_eq!(
            rules.get_package_group("lodash", &Ecosystem::Npm),
            Some("lodash")
        );
    }

    #[test]
    fn test_cross_ecosystem() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.get_cross_ecosystem_equivalent("yaml_parsing", &Ecosystem::PyPi),
            Some("pyyaml")
        );
        assert_eq!(
            rules.get_cross_ecosystem_equivalent("yaml_parsing", &Ecosystem::Npm),
            Some("js-yaml")
        );
    }

    #[test]
    fn test_go_version_suffix() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.normalize_name("github.com/foo/bar/v2", &Ecosystem::Golang),
            "github.com/foo/bar"
        );
        assert_eq!(
            rules.normalize_name("github.com/foo/bar", &Ecosystem::Golang),
            "github.com/foo/bar"
        );
    }

    #[test]
    fn test_canonical_lookup() {
        let rules = EcosystemRules::new();

        assert_eq!(
            rules.get_canonical("PIL", &Ecosystem::PyPi),
            Some("pillow".to_string())
        );
        assert_eq!(
            rules.get_canonical("sklearn", &Ecosystem::PyPi),
            Some("scikit-learn".to_string())
        );
    }

    #[test]
    fn test_custom_config() {
        let yaml = r#"
version: "1.0"
custom_rules:
  internal_prefixes:
    - "@mycompany/"
  ignored_packages:
    - "internal-tool"
"#;
        let config = EcosystemRulesConfig::from_yaml(yaml).unwrap();
        let rules = EcosystemRules::with_config(config);

        assert!(rules.is_internal_package("@mycompany/logger"));
        assert!(!rules.is_internal_package("lodash"));
        assert!(rules.is_ignored("internal-tool"));
    }
}
