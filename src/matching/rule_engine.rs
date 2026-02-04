//! Rule engine for applying custom matching rules.
//!
//! This module provides the engine that applies custom matching rules
//! to components during the diff process.

use indexmap::IndexMap;
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::model::{CanonicalId, Component};

use super::custom_rules::{AliasPattern, EquivalenceGroup, ExclusionRule, MatchingRulesConfig};

/// Result of applying matching rules to components
#[derive(Debug, Clone, Default)]
pub struct RuleApplicationResult {
    /// Original ID -> Canonical ID mapping (for equivalences)
    pub canonical_map: HashMap<CanonicalId, CanonicalId>,
    /// IDs that should be excluded from diff
    pub excluded: HashSet<CanonicalId>,
    /// Log of which rules were applied
    pub applied_rules: Vec<AppliedRule>,
}

/// Record of a rule being applied to a component
#[derive(Debug, Clone)]
pub struct AppliedRule {
    /// The component that was affected
    pub component_id: CanonicalId,
    /// The component name
    pub component_name: String,
    /// The type of rule applied
    pub rule_type: AppliedRuleType,
    /// Index of the rule in the config
    pub rule_index: usize,
    /// Name of the rule (if any)
    pub rule_name: Option<String>,
}

/// Type of rule that was applied
#[derive(Debug, Clone)]
pub enum AppliedRuleType {
    /// Component was mapped to a canonical ID
    Equivalence { canonical: String },
    /// Component was excluded
    Exclusion { reason: Option<String> },
}

/// Engine for applying custom matching rules
pub struct RuleEngine {
    config: MatchingRulesConfig,
    /// Compiled regex patterns for exclusions
    compiled_exclusion_regexes: Vec<Option<Regex>>,
    /// Compiled glob patterns for exclusions (converted to regex)
    compiled_exclusion_globs: Vec<Option<Regex>>,
    /// Compiled regex patterns for equivalence aliases
    compiled_alias_regexes: Vec<Vec<Option<Regex>>>,
    /// Compiled glob patterns for equivalence aliases (converted to regex)
    compiled_alias_globs: Vec<Vec<Option<Regex>>>,
}

impl RuleEngine {
    /// Create a new rule engine from configuration
    pub fn new(config: MatchingRulesConfig) -> Result<Self, String> {
        // Pre-compile regex patterns for exclusions
        let compiled_exclusion_regexes = config
            .exclusions
            .iter()
            .map(|rule| match rule {
                ExclusionRule::Exact(_) => Ok(None),
                ExclusionRule::Conditional { regex, .. } => {
                    if let Some(re) = regex {
                        Regex::new(re)
                            .map(Some)
                            .map_err(|e| format!("Invalid exclusion regex '{}': {}", re, e))
                    } else {
                        Ok(None)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Pre-compile glob patterns for exclusions
        let compiled_exclusion_globs = config
            .exclusions
            .iter()
            .map(|rule| match rule {
                ExclusionRule::Exact(_) => Ok(None),
                ExclusionRule::Conditional { pattern, .. } => {
                    if let Some(pat) = pattern {
                        compile_glob(pat).map(Some)
                    } else {
                        Ok(None)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Pre-compile regex patterns for equivalence aliases
        let compiled_alias_regexes = config
            .equivalences
            .iter()
            .map(|eq| {
                eq.aliases
                    .iter()
                    .map(|alias| match alias {
                        AliasPattern::Exact(_) => Ok(None),
                        AliasPattern::Pattern { regex, .. } => {
                            if let Some(re) = regex {
                                Regex::new(re)
                                    .map(Some)
                                    .map_err(|e| format!("Invalid alias regex '{}': {}", re, e))
                            } else {
                                Ok(None)
                            }
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Pre-compile glob patterns for equivalence aliases
        let compiled_alias_globs = config
            .equivalences
            .iter()
            .map(|eq| {
                eq.aliases
                    .iter()
                    .map(|alias| match alias {
                        AliasPattern::Exact(_) => Ok(None),
                        AliasPattern::Pattern { pattern, .. } => {
                            if let Some(pat) = pattern {
                                compile_glob(pat).map(Some)
                            } else {
                                Ok(None)
                            }
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            config,
            compiled_exclusion_regexes,
            compiled_exclusion_globs,
            compiled_alias_regexes,
            compiled_alias_globs,
        })
    }

    /// Apply rules to a set of components
    pub fn apply(&self, components: &IndexMap<CanonicalId, Component>) -> RuleApplicationResult {
        let mut result = RuleApplicationResult::default();

        for (id, component) in components {
            // Check exclusions first
            if let Some(applied) = self.check_exclusions(id, component) {
                result.excluded.insert(id.clone());
                result.applied_rules.push(applied);
                continue;
            }

            // Check equivalences
            if let Some((canonical_id, applied)) = self.check_equivalences(id, component) {
                result.canonical_map.insert(id.clone(), canonical_id);
                result.applied_rules.push(applied);
            }
        }

        result
    }

    /// Check if a component should be excluded
    fn check_exclusions(&self, id: &CanonicalId, component: &Component) -> Option<AppliedRule> {
        for (idx, rule) in self.config.exclusions.iter().enumerate() {
            if self.exclusion_matches(rule, idx, component) {
                return Some(AppliedRule {
                    component_id: id.clone(),
                    component_name: component.name.clone(),
                    rule_type: AppliedRuleType::Exclusion {
                        reason: rule.get_reason().map(|s| s.to_string()),
                    },
                    rule_index: idx,
                    rule_name: None,
                });
            }
        }
        None
    }

    /// Check if an exclusion rule matches a component
    fn exclusion_matches(
        &self,
        rule: &ExclusionRule,
        rule_idx: usize,
        component: &Component,
    ) -> bool {
        match rule {
            ExclusionRule::Exact(purl) => component
                .identifiers
                .purl
                .as_ref()
                .map(|p| p == purl)
                .unwrap_or(false),
            ExclusionRule::Conditional {
                pattern,
                regex: _,
                ecosystem,
                name,
                scope: _,
                reason: _,
            } => {
                // Check ecosystem
                if let Some(eco) = ecosystem {
                    let comp_eco = component
                        .ecosystem
                        .as_ref()
                        .map(|e| e.to_string().to_lowercase());
                    if comp_eco.as_deref() != Some(&eco.to_lowercase()) {
                        return false;
                    }
                }

                // Check name
                if let Some(n) = name {
                    if !component.name.to_lowercase().contains(&n.to_lowercase()) {
                        return false;
                    }
                }

                // Check pre-compiled glob pattern
                if pattern.is_some() {
                    if let Some(purl) = &component.identifiers.purl {
                        if let Some(Some(re)) = self.compiled_exclusion_globs.get(rule_idx) {
                            if !re.is_match(purl) {
                                return false;
                            }
                        }
                    } else {
                        return false;
                    }
                }

                // Check compiled regex
                if let Some(Some(re)) = self.compiled_exclusion_regexes.get(rule_idx) {
                    if let Some(purl) = &component.identifiers.purl {
                        if !re.is_match(purl) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                // If we get here and at least one condition was specified, it matched
                ecosystem.is_some()
                    || name.is_some()
                    || pattern.is_some()
                    || self
                        .compiled_exclusion_regexes
                        .get(rule_idx)
                        .map(|r| r.is_some())
                        .unwrap_or(false)
            }
        }
    }

    /// Check if a component matches any equivalence group
    fn check_equivalences(
        &self,
        id: &CanonicalId,
        component: &Component,
    ) -> Option<(CanonicalId, AppliedRule)> {
        let purl = component.identifiers.purl.as_ref()?;

        for (eq_idx, eq) in self.config.equivalences.iter().enumerate() {
            // Check if the PURL matches the canonical or any alias
            let matches_canonical = purl == &eq.canonical;
            let matches_alias = self.alias_matches(eq_idx, eq, purl);

            if matches_canonical || matches_alias {
                let canonical_id = CanonicalId::from_purl(&eq.canonical);
                let applied = AppliedRule {
                    component_id: id.clone(),
                    component_name: component.name.clone(),
                    rule_type: AppliedRuleType::Equivalence {
                        canonical: eq.canonical.clone(),
                    },
                    rule_index: eq_idx,
                    rule_name: eq.name.clone(),
                };
                return Some((canonical_id, applied));
            }
        }

        None
    }

    /// Check if a PURL matches any alias in an equivalence group
    fn alias_matches(&self, eq_idx: usize, eq: &EquivalenceGroup, purl: &str) -> bool {
        let alias_regexes = self.compiled_alias_regexes.get(eq_idx);
        let alias_globs = self.compiled_alias_globs.get(eq_idx);

        for (alias_idx, alias) in eq.aliases.iter().enumerate() {
            let matches = match alias {
                AliasPattern::Exact(exact_purl) => purl == exact_purl,
                AliasPattern::Pattern {
                    pattern: _,
                    regex: _,
                    ecosystem,
                    name,
                } => {
                    let mut matched = false;

                    // Check pre-compiled glob pattern
                    if let Some(Some(re)) = alias_globs.and_then(|v| v.get(alias_idx)) {
                        if re.is_match(purl) {
                            matched = true;
                        }
                    }

                    // Check regex
                    if let Some(Some(re)) = alias_regexes.and_then(|v| v.get(alias_idx)) {
                        if re.is_match(purl) {
                            matched = true;
                        }
                    }

                    // Check ecosystem match in PURL
                    if let Some(eco) = ecosystem {
                        let purl_lower = purl.to_lowercase();
                        let eco_lower = eco.to_lowercase();
                        // Check if PURL starts with pkg:<ecosystem>/
                        if purl_lower.starts_with("pkg:") {
                            if let Some(rest) = purl_lower.strip_prefix("pkg:") {
                                if rest.starts_with(&eco_lower)
                                    && rest[eco_lower.len()..].starts_with('/')
                                {
                                    matched = true;
                                }
                            }
                        }
                    }

                    // Check name match in PURL
                    if let Some(n) = name {
                        if purl.to_lowercase().contains(&n.to_lowercase()) {
                            matched = true;
                        }
                    }

                    matched
                }
            };

            if matches {
                return true;
            }
        }

        false
    }

    /// Get the configuration
    pub fn config(&self) -> &MatchingRulesConfig {
        &self.config
    }

    /// Check if a PURL is excluded by any rule
    pub fn is_excluded(&self, purl: &str) -> bool {
        for (idx, rule) in self.config.exclusions.iter().enumerate() {
            match rule {
                ExclusionRule::Exact(exact) => {
                    if purl == exact {
                        return true;
                    }
                }
                ExclusionRule::Conditional { pattern, .. } => {
                    // Check pre-compiled glob pattern
                    if pattern.is_some() {
                        if let Some(Some(re)) = self.compiled_exclusion_globs.get(idx) {
                            if re.is_match(purl) {
                                return true;
                            }
                        }
                    }
                    // Check pre-compiled regex
                    if let Some(Some(re)) = self.compiled_exclusion_regexes.get(idx) {
                        if re.is_match(purl) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Get the canonical PURL for a given PURL, if any equivalence applies
    pub fn get_canonical(&self, purl: &str) -> Option<String> {
        for (eq_idx, eq) in self.config.equivalences.iter().enumerate() {
            if purl == eq.canonical {
                return Some(eq.canonical.clone());
            }
            if self.alias_matches(eq_idx, eq, purl) {
                return Some(eq.canonical.clone());
            }
        }
        None
    }
}

/// Compile a glob pattern to a regex at construction time.
fn compile_glob(pattern: &str) -> Result<Regex, String> {
    let regex_pattern = pattern
        .replace('.', "\\.")
        .replace('*', ".*")
        .replace('?', ".");

    Regex::new(&format!("^{}$", regex_pattern))
        .map_err(|e| format!("Invalid glob pattern '{}': {}", pattern, e))
}

/// Simple glob pattern matching (supports * and ?) - used only in tests
#[cfg(test)]
fn glob_matches(pattern: &str, text: &str) -> bool {
    compile_glob(pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_component(name: &str, purl: Option<&str>) -> Component {
        use crate::model::*;
        let mut comp = Component::new(name.to_string(), purl.unwrap_or(name).to_string());
        comp.version = Some("1.0.0".to_string());
        comp.identifiers.purl = purl.map(|s| s.to_string());
        comp.ecosystem = Some(Ecosystem::Npm);
        comp
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("pkg:npm/*", "pkg:npm/lodash"));
        assert!(glob_matches("pkg:npm/lodash*", "pkg:npm/lodash-es"));
        assert!(!glob_matches("pkg:npm/*", "pkg:maven/test"));
        assert!(glob_matches("*.json", "test.json"));
    }

    #[test]
    fn test_exact_exclusion() {
        let config = MatchingRulesConfig {
            exclusions: vec![ExclusionRule::exact("pkg:npm/jest")],
            ..Default::default()
        };
        let engine = RuleEngine::new(config).unwrap();

        assert!(engine.is_excluded("pkg:npm/jest"));
        assert!(!engine.is_excluded("pkg:npm/lodash"));
    }

    #[test]
    fn test_pattern_exclusion() {
        let config = MatchingRulesConfig {
            exclusions: vec![ExclusionRule::pattern("pkg:npm/test-*")],
            ..Default::default()
        };
        let engine = RuleEngine::new(config).unwrap();

        assert!(engine.is_excluded("pkg:npm/test-utils"));
        assert!(engine.is_excluded("pkg:npm/test-runner"));
        assert!(!engine.is_excluded("pkg:npm/lodash"));
    }

    #[test]
    fn test_equivalence_matching() {
        let config = MatchingRulesConfig {
            equivalences: vec![EquivalenceGroup {
                name: Some("Lodash".to_string()),
                canonical: "pkg:npm/lodash".to_string(),
                aliases: vec![
                    AliasPattern::exact("pkg:npm/lodash-es"),
                    AliasPattern::glob("pkg:npm/lodash.*"),
                ],
                version_sensitive: false,
            }],
            ..Default::default()
        };
        let engine = RuleEngine::new(config).unwrap();

        assert_eq!(
            engine.get_canonical("pkg:npm/lodash"),
            Some("pkg:npm/lodash".to_string())
        );
        assert_eq!(
            engine.get_canonical("pkg:npm/lodash-es"),
            Some("pkg:npm/lodash".to_string())
        );
        assert_eq!(
            engine.get_canonical("pkg:npm/lodash.min"),
            Some("pkg:npm/lodash".to_string())
        );
        assert_eq!(engine.get_canonical("pkg:npm/underscore"), None);
    }

    #[test]
    fn test_apply_rules() {
        let config = MatchingRulesConfig {
            equivalences: vec![EquivalenceGroup {
                name: Some("Lodash".to_string()),
                canonical: "pkg:npm/lodash".to_string(),
                aliases: vec![AliasPattern::exact("pkg:npm/lodash-es")],
                version_sensitive: false,
            }],
            exclusions: vec![ExclusionRule::exact("pkg:npm/jest")],
            ..Default::default()
        };
        let engine = RuleEngine::new(config).unwrap();

        let mut components = IndexMap::new();
        components.insert(
            CanonicalId::from_purl("pkg:npm/lodash-es"),
            create_test_component("lodash-es", Some("pkg:npm/lodash-es")),
        );
        components.insert(
            CanonicalId::from_purl("pkg:npm/jest"),
            create_test_component("jest", Some("pkg:npm/jest")),
        );
        components.insert(
            CanonicalId::from_purl("pkg:npm/react"),
            create_test_component("react", Some("pkg:npm/react")),
        );

        let result = engine.apply(&components);

        // lodash-es should be mapped to canonical lodash
        assert!(result
            .canonical_map
            .contains_key(&CanonicalId::from_purl("pkg:npm/lodash-es")));

        // jest should be excluded
        assert!(result
            .excluded
            .contains(&CanonicalId::from_purl("pkg:npm/jest")));

        // react should have no rules applied
        assert!(!result
            .canonical_map
            .contains_key(&CanonicalId::from_purl("pkg:npm/react")));
        assert!(!result
            .excluded
            .contains(&CanonicalId::from_purl("pkg:npm/react")));

        // Check applied rules
        assert_eq!(result.applied_rules.len(), 2);
    }
}
