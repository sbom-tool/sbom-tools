//! Custom component matching rules configuration.
//!
//! This module provides data structures for user-defined matching rules
//! that can be loaded from YAML configuration files.

use serde::{Deserialize, Serialize};

/// Root configuration for custom matching rules
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchingRulesConfig {
    /// Rule precedence strategy
    #[serde(default)]
    pub precedence: RulePrecedence,

    /// Component equivalence groups
    #[serde(default)]
    pub equivalences: Vec<EquivalenceGroup>,

    /// Component exclusion rules
    #[serde(default)]
    pub exclusions: Vec<ExclusionRule>,
}

/// Rule precedence strategy when multiple rules match
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RulePrecedence {
    /// First matching rule wins
    #[default]
    FirstMatch,
    /// Most specific rule wins (longer patterns, exact matches)
    MostSpecific,
}

impl std::fmt::Display for RulePrecedence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstMatch => write!(f, "first-match"),
            Self::MostSpecific => write!(f, "most-specific"),
        }
    }
}

/// Defines a group of components that should be treated as equivalent
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EquivalenceGroup {
    /// Optional name for this rule (for logging/debugging)
    #[serde(default)]
    pub name: Option<String>,

    /// The canonical identifier (others will be mapped to this)
    pub canonical: String,

    /// Aliases that should map to the canonical
    #[serde(default)]
    pub aliases: Vec<AliasPattern>,

    /// Whether version must also match for equivalence
    #[serde(default)]
    pub version_sensitive: bool,
}

/// Pattern for matching component aliases
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AliasPattern {
    /// Exact PURL match
    Exact(String),

    /// Pattern-based match
    Pattern {
        /// Glob pattern (e.g., "pkg:maven/org.apache.logging.log4j/*")
        #[serde(default)]
        pattern: Option<String>,

        /// Regex pattern
        #[serde(default)]
        regex: Option<String>,

        /// Match by ecosystem
        #[serde(default)]
        ecosystem: Option<String>,

        /// Match by name (within ecosystem)
        #[serde(default)]
        name: Option<String>,
    },
}

impl AliasPattern {
    /// Create an exact match pattern
    pub fn exact(purl: impl Into<String>) -> Self {
        Self::Exact(purl.into())
    }

    /// Create a glob pattern match
    pub fn glob(pattern: impl Into<String>) -> Self {
        Self::Pattern {
            pattern: Some(pattern.into()),
            regex: None,
            ecosystem: None,
            name: None,
        }
    }

    /// Create a regex pattern match
    pub fn regex(pattern: impl Into<String>) -> Self {
        Self::Pattern {
            pattern: None,
            regex: Some(pattern.into()),
            ecosystem: None,
            name: None,
        }
    }

    /// Get a description of this pattern for display
    #[must_use] 
    pub fn description(&self) -> String {
        match self {
            Self::Exact(purl) => format!("exact:{purl}"),
            Self::Pattern {
                pattern,
                regex,
                ecosystem,
                name,
            } => {
                let mut parts = Vec::new();
                if let Some(p) = pattern {
                    parts.push(format!("pattern:{p}"));
                }
                if let Some(r) = regex {
                    parts.push(format!("regex:{r}"));
                }
                if let Some(e) = ecosystem {
                    parts.push(format!("ecosystem:{e}"));
                }
                if let Some(n) = name {
                    parts.push(format!("name:{n}"));
                }
                parts.join(", ")
            }
        }
    }
}

/// Rule for excluding components from diff analysis
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExclusionRule {
    /// Exact PURL match
    Exact(String),

    /// Conditional exclusion
    Conditional {
        /// Glob pattern
        #[serde(default)]
        pattern: Option<String>,

        /// Regex pattern
        #[serde(default)]
        regex: Option<String>,

        /// Match by ecosystem (npm, maven, pypi, etc.)
        #[serde(default)]
        ecosystem: Option<String>,

        /// Match by component name
        #[serde(default)]
        name: Option<String>,

        /// Match by dependency scope (dev, test, build, runtime)
        #[serde(default)]
        scope: Option<String>,

        /// Reason for exclusion (for reporting)
        #[serde(default)]
        reason: Option<String>,
    },
}

impl ExclusionRule {
    /// Create an exact match exclusion
    pub fn exact(purl: impl Into<String>) -> Self {
        Self::Exact(purl.into())
    }

    /// Create a pattern-based exclusion
    pub fn pattern(pattern: impl Into<String>) -> Self {
        Self::Conditional {
            pattern: Some(pattern.into()),
            regex: None,
            ecosystem: None,
            name: None,
            scope: None,
            reason: None,
        }
    }

    /// Create an ecosystem-based exclusion
    pub fn ecosystem(ecosystem: impl Into<String>) -> Self {
        Self::Conditional {
            pattern: None,
            regex: None,
            ecosystem: Some(ecosystem.into()),
            name: None,
            scope: None,
            reason: None,
        }
    }

    /// Get the reason for this exclusion, if any
    #[must_use] 
    pub fn get_reason(&self) -> Option<&str> {
        match self {
            Self::Exact(_) => None,
            Self::Conditional { reason, .. } => reason.as_deref(),
        }
    }

    /// Get a description of this rule for display
    #[must_use] 
    pub fn description(&self) -> String {
        match self {
            Self::Exact(purl) => format!("exact:{purl}"),
            Self::Conditional {
                pattern,
                regex,
                ecosystem,
                name,
                scope,
                reason,
            } => {
                let mut parts = Vec::new();
                if let Some(p) = pattern {
                    parts.push(format!("pattern:{p}"));
                }
                if let Some(r) = regex {
                    parts.push(format!("regex:{r}"));
                }
                if let Some(e) = ecosystem {
                    parts.push(format!("ecosystem:{e}"));
                }
                if let Some(n) = name {
                    parts.push(format!("name:{n}"));
                }
                if let Some(s) = scope {
                    parts.push(format!("scope:{s}"));
                }
                if let Some(r) = reason {
                    parts.push(format!("reason:{r}"));
                }
                parts.join(", ")
            }
        }
    }
}

impl MatchingRulesConfig {
    /// Load rules from a YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    /// Load rules from a YAML file
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config = Self::from_yaml(&content)?;
        Ok(config)
    }

    /// Get summary statistics about the rules
    #[must_use] 
    pub fn summary(&self) -> RulesSummary {
        RulesSummary {
            equivalence_groups: self.equivalences.len(),
            total_aliases: self.equivalences.iter().map(|e| e.aliases.len()).sum(),
            exclusion_rules: self.exclusions.len(),
            precedence: self.precedence,
        }
    }

    /// Check if the configuration is empty (no rules defined)
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.equivalences.is_empty() && self.exclusions.is_empty()
    }
}

/// Summary of matching rules configuration
#[derive(Debug, Clone)]
pub struct RulesSummary {
    pub equivalence_groups: usize,
    pub total_aliases: usize,
    pub exclusion_rules: usize,
    pub precedence: RulePrecedence,
}

impl std::fmt::Display for RulesSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} equivalence group(s) ({} aliases), {} exclusion rule(s), precedence: {}",
            self.equivalence_groups, self.total_aliases, self.exclusion_rules, self.precedence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_config() {
        let yaml = r#"
precedence: first-match
equivalences:
  - name: "Log4j family"
    canonical: "pkg:maven/org.apache.logging.log4j/log4j-core"
    aliases:
      - "pkg:maven/org.apache.logging.log4j/log4j-api"
      - pattern: "pkg:maven/org.apache.logging.log4j/log4j-*"
exclusions:
  - "pkg:maven/junit/junit"
  - ecosystem: "npm"
    scope: "dev"
    reason: "Excluding npm dev dependencies"
"#;

        let config = MatchingRulesConfig::from_yaml(yaml).expect("Failed to parse YAML");
        assert_eq!(config.precedence, RulePrecedence::FirstMatch);
        assert_eq!(config.equivalences.len(), 1);
        assert_eq!(config.equivalences[0].aliases.len(), 2);
        assert_eq!(config.exclusions.len(), 2);
    }

    #[test]
    fn test_empty_config() {
        let config = MatchingRulesConfig::default();
        assert!(config.is_empty());
        assert_eq!(config.precedence, RulePrecedence::FirstMatch);
    }

    #[test]
    fn test_alias_pattern_description() {
        let exact = AliasPattern::exact("pkg:npm/lodash");
        assert!(exact.description().contains("exact:"));

        let glob = AliasPattern::glob("pkg:maven/*");
        assert!(glob.description().contains("pattern:"));
    }

    #[test]
    fn test_exclusion_rule_description() {
        let exact = ExclusionRule::exact("pkg:npm/jest");
        assert!(exact.description().contains("exact:"));

        let ecosystem = ExclusionRule::ecosystem("npm");
        assert!(ecosystem.description().contains("ecosystem:"));
    }

    #[test]
    fn test_rules_summary() {
        let config = MatchingRulesConfig {
            precedence: RulePrecedence::MostSpecific,
            equivalences: vec![EquivalenceGroup {
                name: Some("Test".to_string()),
                canonical: "pkg:npm/test".to_string(),
                aliases: vec![
                    AliasPattern::exact("pkg:npm/test-alias"),
                    AliasPattern::exact("pkg:npm/test-other"),
                ],
                version_sensitive: false,
            }],
            exclusions: vec![ExclusionRule::exact("pkg:npm/jest")],
        };

        let summary = config.summary();
        assert_eq!(summary.equivalence_groups, 1);
        assert_eq!(summary.total_aliases, 2);
        assert_eq!(summary.exclusion_rules, 1);
        assert_eq!(summary.precedence, RulePrecedence::MostSpecific);
    }
}
