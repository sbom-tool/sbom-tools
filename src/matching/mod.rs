//! Fuzzy matching engine for cross-ecosystem package correlation.
//!
//! This module provides multi-tier matching strategies for correlating
//! components across different ecosystems and naming conventions.
//!
//! # Architecture
//!
//! The matching system is built on the [`ComponentMatcher`] trait, which
//! provides a pluggable interface for different matching strategies:
//!
//! - [`FuzzyMatcher`]: Multi-tier fuzzy matching (default)
//! - [`CompositeMatcher`]: Combines multiple matchers
//! - [`CachedMatcher`]: Wraps any matcher with caching
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::matching::{ComponentMatcher, FuzzyMatcher, FuzzyMatchConfig};
//!
//! // Use the trait for dependency injection
//! fn diff_with_matcher(matcher: &dyn ComponentMatcher) {
//!     let score = matcher.match_score(&comp_a, &comp_b);
//! }
//!
//! let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
//! diff_with_matcher(&matcher);
//! ```

pub mod adaptive;
mod aliases;
mod config;
pub mod cross_ecosystem;
pub mod custom_rules;
pub mod ecosystem_config;
pub mod index;
pub mod lsh;
mod purl;
pub mod rule_engine;
mod rules;
pub mod scoring;
pub mod string_similarity;
mod traits;

pub use adaptive::{
    AdaptiveMatching, AdaptiveMethod, AdaptiveThreshold, AdaptiveThresholdConfig,
    AdaptiveThresholdResult, ScoreStats,
};
pub use aliases::AliasTable;
pub use config::{CrossEcosystemConfig, FuzzyMatchConfig, MultiFieldWeights};
pub use cross_ecosystem::{CrossEcosystemDb, CrossEcosystemMatch, PackageFamily};
pub use custom_rules::{
    AliasPattern, EquivalenceGroup, ExclusionRule, MatchingRulesConfig, RulePrecedence,
    RulesSummary,
};
pub use ecosystem_config::{
    ConfigError, CustomEquivalence, CustomRules, EcosystemConfig, EcosystemRulesConfig,
    GlobalSettings, GroupMigration, ImportMapping, NormalizationConfig, PackageGroup,
    ScopeHandling, SecurityConfig, TyposquatEntry, VersionSpec, VersioningConfig,
};
pub use index::{
    BatchCandidateConfig, BatchCandidateGenerator, BatchCandidateResult, BatchCandidateStats,
    ComponentIndex, IndexStats, LazyComponentIndex, NormalizedEntry,
};
pub use lsh::{LshConfig, LshIndex, LshIndexStats, MinHashSignature};
pub use purl::PurlNormalizer;
pub use rule_engine::{AppliedRule, AppliedRuleType, RuleApplicationResult, RuleEngine};
pub use rules::EcosystemRules;
pub use scoring::MultiFieldScoreResult;
pub use traits::{
    CacheConfig, CacheStats, CachedMatcher, ComponentMatcher, CompositeMatcher,
    CompositeMatcherBuilder, MatchExplanation, MatchMetadata, MatchResult, MatchTier,
    ScoreComponent,
};

use crate::model::Component;
use strsim::{jaro_winkler, levenshtein};

/// Fuzzy matcher for component correlation.
#[must_use]
pub struct FuzzyMatcher {
    config: FuzzyMatchConfig,
    alias_table: AliasTable,
    purl_normalizer: PurlNormalizer,
    ecosystem_rules: EcosystemRules,
}

impl FuzzyMatcher {
    /// Create a new fuzzy matcher with the given configuration
    pub fn new(config: FuzzyMatchConfig) -> Self {
        Self {
            config,
            alias_table: AliasTable::default(),
            purl_normalizer: PurlNormalizer::new(),
            ecosystem_rules: EcosystemRules::new(),
        }
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &FuzzyMatchConfig {
        &self.config
    }

    /// Create a matcher with a custom alias table
    pub fn with_alias_table(mut self, table: AliasTable) -> Self {
        self.alias_table = table;
        self
    }

    /// Match two components and return a confidence score (0.0 - 1.0)
    #[must_use]
    pub fn match_components(&self, a: &Component, b: &Component) -> f64 {
        // Layer 1: Exact PURL match
        if let (Some(purl_a), Some(purl_b)) = (&a.identifiers.purl, &b.identifiers.purl) {
            let norm_a = self.purl_normalizer.normalize(purl_a);
            let norm_b = self.purl_normalizer.normalize(purl_b);
            if norm_a == norm_b {
                return 1.0;
            }
        }

        // Layer 2: Alias table lookup
        if self.check_alias_match(a, b) {
            return 0.95;
        }

        // Layer 3: Rule-based ecosystem normalization
        if let Some(score) = self.check_ecosystem_rules(a, b)
            && score >= 0.90
        {
            return score;
        }

        // Layer 4: Multi-field weighted scoring (if configured) or fuzzy string similarity
        if let Some(ref weights) = self.config.field_weights {
            // Use multi-field scoring when configured
            let result = self.compute_multi_field_score(a, b, weights);
            if result.total >= self.config.threshold {
                return result.total;
            }
        } else {
            // Fall back to simple fuzzy string similarity
            let fuzzy_score = self.compute_fuzzy_score(a, b);
            if fuzzy_score >= self.config.threshold {
                return fuzzy_score;
            }
        }

        0.0
    }

    /// Check if components match via alias table
    fn check_alias_match(&self, a: &Component, b: &Component) -> bool {
        // Check if either component's name is an alias of the other
        let names_a = self.get_all_names(a);
        let names_b = self.get_all_names(b);

        for name_a in &names_a {
            if let Some(canonical) = self.alias_table.get_canonical(name_a) {
                for name_b in &names_b {
                    if self.alias_table.is_alias(&canonical, name_b) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Get all possible names for a component
    fn get_all_names(&self, comp: &Component) -> Vec<String> {
        let mut names = vec![comp.name.clone()];
        names.extend(comp.identifiers.aliases.clone());

        // Extract name from PURL if available
        if let Some(purl) = &comp.identifiers.purl
            && let Some(name) = self.extract_name_from_purl(purl)
        {
            names.push(name);
        }

        names
    }

    /// Extract the package name from a PURL
    fn extract_name_from_purl(&self, purl: &str) -> Option<String> {
        // pkg:type/namespace/name@version?qualifiers#subpath
        let without_pkg = purl.strip_prefix("pkg:")?;
        let parts: Vec<&str> = without_pkg.split('/').collect();

        if parts.len() >= 2 {
            let name_part = parts.last()?;
            // Remove version and qualifiers
            let name = name_part.split('@').next()?;
            Some(name.to_string())
        } else {
            None
        }
    }

    /// Check ecosystem-specific matching rules
    fn check_ecosystem_rules(&self, a: &Component, b: &Component) -> Option<f64> {
        let ecosystem_a = a.ecosystem.as_ref()?;
        let ecosystem_b = b.ecosystem.as_ref()?;

        // Must be same ecosystem for rule-based matching
        if ecosystem_a != ecosystem_b {
            return None;
        }

        let norm_a = self.ecosystem_rules.normalize_name(&a.name, ecosystem_a);
        let norm_b = self.ecosystem_rules.normalize_name(&b.name, ecosystem_b);

        if norm_a == norm_b {
            return Some(0.90);
        }

        None
    }

    /// Compute fuzzy string similarity score
    fn compute_fuzzy_score(&self, a: &Component, b: &Component) -> f64 {
        let name_a = a.name.to_lowercase();
        let name_b = b.name.to_lowercase();

        // Compute Jaro-Winkler similarity
        let jw_score = jaro_winkler(&name_a, &name_b);

        // Compute normalized Levenshtein distance
        let max_len = name_a.len().max(name_b.len());
        let lev_distance = levenshtein(&name_a, &name_b);
        let lev_score = if max_len > 0 {
            1.0 - (lev_distance as f64 / max_len as f64)
        } else {
            1.0
        };

        // Compute token-based similarity (catches reordered names like "react-dom" vs "dom-react")
        let token_score = Self::compute_token_similarity(&name_a, &name_b);

        // Compute phonetic similarity (catches typos like "color" vs "colour")
        let phonetic_score = Self::compute_phonetic_similarity(&name_a, &name_b);

        // Weighted combination of character-based scores
        let char_score = jw_score.mul_add(
            self.config.jaro_winkler_weight,
            lev_score * self.config.levenshtein_weight,
        );

        // Use the MAXIMUM of character, token, and phonetic scores
        // This allows each method to catch different types of variations
        let combined = char_score.max(token_score).max(phonetic_score * 0.85);

        // Version-aware boost (semantic version similarity)
        let version_boost =
            Self::compute_version_similarity(a.version.as_ref(), b.version.as_ref());

        (combined + version_boost).min(1.0)
    }

    /// Compute token-based similarity using Jaccard index on name tokens.
    fn compute_token_similarity(name_a: &str, name_b: &str) -> f64 {
        string_similarity::compute_token_similarity(name_a, name_b)
    }

    /// Compute version similarity with semantic awareness.
    fn compute_version_similarity(va: Option<&String>, vb: Option<&String>) -> f64 {
        string_similarity::compute_version_similarity(va, vb)
    }

    /// Compute phonetic similarity using Soundex.
    #[must_use]
    pub fn compute_phonetic_similarity(name_a: &str, name_b: &str) -> f64 {
        string_similarity::compute_phonetic_similarity(name_a, name_b)
    }

    /// Compute multi-field weighted score.
    ///
    /// Combines scores from multiple component fields based on configured weights.
    #[must_use]
    pub fn compute_multi_field_score(
        &self,
        a: &Component,
        b: &Component,
        weights: &config::MultiFieldWeights,
    ) -> scoring::MultiFieldScoreResult {
        use std::collections::HashSet;

        let mut result = scoring::MultiFieldScoreResult::default();

        // 1. Name similarity (using fuzzy scoring)
        let name_score = self.compute_fuzzy_score(a, b);
        result.name_score = name_score;
        result.total += name_score * weights.name;

        // 2. Version match (graduated or binary scoring)
        let version_score = if weights.version_divergence_enabled {
            scoring::compute_version_divergence_score(&a.version, &b.version, weights)
        } else {
            // Legacy binary scoring
            match (&a.version, &b.version) {
                (Some(va), Some(vb)) if va == vb => 1.0,
                (None, None) => 0.5, // Both missing = neutral
                _ => 0.0,
            }
        };
        result.version_score = version_score;
        result.total += version_score * weights.version;

        // 3. Ecosystem match (exact match = 1.0, mismatch applies penalty)
        let (ecosystem_score, ecosystem_penalty) = match (&a.ecosystem, &b.ecosystem) {
            (Some(ea), Some(eb)) if ea == eb => (1.0, 0.0),
            (None, None) => (0.5, 0.0), // Both missing = neutral, no penalty
            (Some(_), Some(_)) => (0.0, weights.ecosystem_mismatch_penalty), // Different ecosystems = penalty
            _ => (0.0, 0.0), // One missing = no match but no penalty
        };
        result.ecosystem_score = ecosystem_score;
        result.total += ecosystem_score.mul_add(weights.ecosystem, ecosystem_penalty);

        // 4. License overlap (Jaccard similarity on declared licenses)
        let licenses_a: HashSet<_> = a
            .licenses
            .declared
            .iter()
            .map(|l| l.expression.as_str())
            .collect();
        let licenses_b: HashSet<_> = b
            .licenses
            .declared
            .iter()
            .map(|l| l.expression.as_str())
            .collect();
        let license_score = if licenses_a.is_empty() && licenses_b.is_empty() {
            0.5 // Both empty = neutral
        } else if licenses_a.is_empty() || licenses_b.is_empty() {
            0.0 // One empty = no match
        } else {
            let intersection = licenses_a.intersection(&licenses_b).count();
            let union = licenses_a.union(&licenses_b).count();
            if union > 0 {
                intersection as f64 / union as f64
            } else {
                0.0
            }
        };
        result.license_score = license_score;
        result.total += license_score * weights.licenses;

        // 5. Supplier match (exact match on supplier organization name)
        let supplier_score = match (&a.supplier, &b.supplier) {
            (Some(sa), Some(sb)) if sa.name.to_lowercase() == sb.name.to_lowercase() => 1.0,
            (None, None) => 0.5, // Both missing = neutral
            _ => 0.0,
        };
        result.supplier_score = supplier_score;
        result.total += supplier_score * weights.supplier;

        // 6. Group/namespace match
        let group_score = match (&a.group, &b.group) {
            (Some(ga), Some(gb)) if ga.to_lowercase() == gb.to_lowercase() => 1.0,
            (None, None) => 0.5, // Both missing = neutral
            _ => 0.0,
        };
        result.group_score = group_score;
        result.total += group_score * weights.group;

        // Clamp total to [0.0, 1.0] after penalty application
        result.total = result.total.clamp(0.0, 1.0);

        result
    }
}

impl Default for FuzzyMatcher {
    fn default() -> Self {
        Self::new(FuzzyMatchConfig::balanced())
    }
}

impl ComponentMatcher for FuzzyMatcher {
    fn match_score(&self, a: &Component, b: &Component) -> f64 {
        self.match_components(a, b)
    }

    fn match_detailed(&self, a: &Component, b: &Component) -> MatchResult {
        // Layer 1: Exact PURL match
        if let (Some(purl_a), Some(purl_b)) = (&a.identifiers.purl, &b.identifiers.purl) {
            let norm_a = self.purl_normalizer.normalize(purl_a);
            let norm_b = self.purl_normalizer.normalize(purl_b);
            if norm_a == norm_b {
                return MatchResult::with_metadata(
                    1.0,
                    MatchTier::ExactIdentifier,
                    MatchMetadata {
                        matched_fields: vec!["purl".to_string()],
                        normalization: Some("purl_normalized".to_string()),
                        rule_id: None,
                    },
                );
            }
        }

        // Layer 2: Alias table lookup
        if self.check_alias_match(a, b) {
            return MatchResult::with_metadata(
                0.95,
                MatchTier::Alias,
                MatchMetadata {
                    matched_fields: vec!["name".to_string()],
                    normalization: Some("alias_table".to_string()),
                    rule_id: None,
                },
            );
        }

        // Layer 3: Rule-based ecosystem normalization
        if let Some(score) = self.check_ecosystem_rules(a, b)
            && score >= 0.90
        {
            return MatchResult::with_metadata(
                score,
                MatchTier::EcosystemRule,
                MatchMetadata {
                    matched_fields: vec!["name".to_string(), "ecosystem".to_string()],
                    normalization: Some("ecosystem_rules".to_string()),
                    rule_id: None,
                },
            );
        }

        // Layer 4: Fuzzy string similarity
        let fuzzy_score = self.compute_fuzzy_score(a, b);
        if fuzzy_score >= self.config.threshold {
            return MatchResult::with_metadata(
                fuzzy_score,
                MatchTier::Fuzzy,
                MatchMetadata {
                    matched_fields: vec!["name".to_string()],
                    normalization: Some("fuzzy_similarity".to_string()),
                    rule_id: None,
                },
            );
        }

        MatchResult::no_match()
    }

    fn name(&self) -> &'static str {
        "FuzzyMatcher"
    }

    fn threshold(&self) -> f64 {
        self.config.threshold
    }

    fn explain_match(&self, a: &Component, b: &Component) -> MatchExplanation {
        use strsim::{jaro_winkler, levenshtein};

        // Layer 1: Exact PURL match
        if let (Some(purl_a), Some(purl_b)) = (&a.identifiers.purl, &b.identifiers.purl) {
            let norm_a = self.purl_normalizer.normalize(purl_a);
            let norm_b = self.purl_normalizer.normalize(purl_b);
            if norm_a == norm_b {
                return MatchExplanation::matched(
                    MatchTier::ExactIdentifier,
                    1.0,
                    format!("Exact PURL match: '{purl_a}' equals '{purl_b}' after normalization"),
                )
                .with_normalization("purl_normalized");
            }
        }

        // Layer 2: Alias table lookup
        if self.check_alias_match(a, b) {
            return MatchExplanation::matched(
                MatchTier::Alias,
                0.95,
                format!(
                    "'{}' and '{}' are known aliases of the same package",
                    a.name, b.name
                ),
            )
            .with_normalization("alias_table");
        }

        // Layer 3: Rule-based ecosystem normalization
        if let Some(score) = self.check_ecosystem_rules(a, b)
            && score >= 0.90
        {
            let ecosystem = a
                .ecosystem
                .as_ref()
                .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);
            return MatchExplanation::matched(
                MatchTier::EcosystemRule,
                score,
                format!(
                    "Names match after {} ecosystem normalization: '{}' -> '{}'",
                    ecosystem, a.name, b.name
                ),
            )
            .with_normalization(format!("{ecosystem}_normalization"));
        }

        // Layer 4: Fuzzy string similarity - compute detailed breakdown
        let name_a = a.name.to_lowercase();
        let name_b = b.name.to_lowercase();

        let jw_score = jaro_winkler(&name_a, &name_b);
        let max_len = name_a.len().max(name_b.len());
        let lev_distance = levenshtein(&name_a, &name_b);
        let lev_score = if max_len > 0 {
            1.0 - (lev_distance as f64 / max_len as f64)
        } else {
            1.0
        };

        let jw_weighted = jw_score * self.config.jaro_winkler_weight;
        let lev_weighted = lev_score * self.config.levenshtein_weight;

        let version_boost = if a.version == b.version && a.version.is_some() {
            0.05
        } else {
            0.0
        };

        let combined = (jw_weighted + lev_weighted + version_boost).min(1.0);

        let mut explanation = if combined >= self.config.threshold {
            MatchExplanation::matched(
                MatchTier::Fuzzy,
                combined,
                format!(
                    "Fuzzy match: '{}' ~ '{}' with {:.0}% similarity",
                    a.name,
                    b.name,
                    combined * 100.0
                ),
            )
        } else {
            MatchExplanation::no_match(format!(
                "Fuzzy similarity {:.2} below threshold {:.2}",
                combined, self.config.threshold
            ))
        };

        // Add score breakdown
        explanation = explanation
            .with_score_component(ScoreComponent {
                name: "Jaro-Winkler".to_string(),
                weight: self.config.jaro_winkler_weight,
                raw_score: jw_score,
                weighted_score: jw_weighted,
                description: format!("'{name_a}' vs '{name_b}' = {jw_score:.2}"),
            })
            .with_score_component(ScoreComponent {
                name: "Levenshtein".to_string(),
                weight: self.config.levenshtein_weight,
                raw_score: lev_score,
                weighted_score: lev_weighted,
                description: format!(
                    "edit distance {lev_distance} / max_len {max_len} = {lev_score:.2}"
                ),
            });

        if version_boost > 0.0 {
            explanation = explanation.with_score_component(ScoreComponent {
                name: "Version boost".to_string(),
                weight: 1.0,
                raw_score: version_boost,
                weighted_score: version_boost,
                description: format!("versions match: {:?}", a.version),
            });
        }

        explanation.with_normalization("lowercase")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_purl_match() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.identifiers.purl = Some("pkg:npm/lodash@4.17.21".to_string());

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.identifiers.purl = Some("pkg:npm/lodash@4.17.21".to_string());

        assert_eq!(matcher.match_components(&a, &b), 1.0);
    }

    #[test]
    fn test_fuzzy_name_match() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        // Similar names should have some fuzzy match score
        let a = Component::new("lodash-es".to_string(), "comp-1".to_string());
        let b = Component::new("lodash".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        // With permissive threshold (0.70), similar names should match
        assert!(
            score >= 0.70,
            "lodash-es vs lodash should have score >= 0.70, got {}",
            score
        );
    }

    #[test]
    fn test_different_names_low_score() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::strict());

        let a = Component::new("react".to_string(), "comp-1".to_string());
        let b = Component::new("angular".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        assert!(
            score < 0.5,
            "react vs angular should have low score, got {}",
            score
        );
    }

    #[test]
    fn test_multi_field_weights_normalized() {
        let weights = config::MultiFieldWeights::balanced();
        assert!(
            weights.is_normalized(),
            "Balanced weights should be normalized"
        );

        let weights = config::MultiFieldWeights::name_focused();
        assert!(
            weights.is_normalized(),
            "Name-focused weights should be normalized"
        );

        let weights = config::MultiFieldWeights::security_focused();
        assert!(
            weights.is_normalized(),
            "Security-focused weights should be normalized"
        );
    }

    #[test]
    fn test_multi_field_scoring_same_component() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        // Identical component should score very high
        // Note: empty licenses/supplier/group get neutral 0.5 score, so total won't be 1.0
        let result = matcher.compute_multi_field_score(&a, &a, &weights);
        assert!(
            result.total > 0.90,
            "Same component should score > 0.90, got {}",
            result.total
        );
        assert_eq!(result.name_score, 1.0);
        assert_eq!(result.version_score, 1.0);
        assert_eq!(result.ecosystem_score, 1.0);
        // Empty fields get neutral 0.5 score
        assert_eq!(
            result.license_score, 0.5,
            "Empty licenses should be neutral"
        );
        assert_eq!(
            result.supplier_score, 0.5,
            "Empty supplier should be neutral"
        );
        assert_eq!(result.group_score, 0.5, "Empty group should be neutral");
    }

    #[test]
    fn test_multi_field_scoring_different_versions() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string()); // Different patch version
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Name matches perfectly
        assert!(result.name_score > 0.9, "Name score should be > 0.9");

        // Graduated version scoring: same major.minor gives high score
        // 4.17.21 vs 4.17.20 = same major.minor, patch diff of 1
        // Expected: 0.8 - 0.01 * 1 = 0.79
        assert!(
            result.version_score > 0.7,
            "Same major.minor with patch diff should score high, got {}",
            result.version_score
        );

        // Ecosystem matches
        assert_eq!(
            result.ecosystem_score, 1.0,
            "Same ecosystem should score 1.0"
        );

        // Total should be high due to name, ecosystem, and graduated version score
        assert!(
            result.total > 0.8,
            "Total should be > 0.8, got {}",
            result.total
        );
    }

    #[test]
    fn test_multi_field_scoring_different_major_versions() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("3.10.0".to_string()); // Different major version
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Graduated version scoring: different major gives low score
        // 4 vs 3 = major diff of 1
        // Expected: 0.3 - 0.10 * 1 = 0.20
        assert!(
            result.version_score < 0.3,
            "Different major versions should score low, got {}",
            result.version_score
        );
    }

    #[test]
    fn test_multi_field_scoring_legacy_weights() {
        // Test that legacy weights disable graduated scoring
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::legacy();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string());
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Legacy mode: binary version scoring (exact match or 0)
        assert_eq!(
            result.version_score, 0.0,
            "Legacy mode: different versions should score 0"
        );
    }

    #[test]
    fn test_multi_field_config_preset() {
        let config = FuzzyMatchConfig::from_preset("balanced-multi").unwrap();
        assert!(config.field_weights.is_some());

        let config = FuzzyMatchConfig::from_preset("strict_multi").unwrap();
        assert!(config.field_weights.is_some());
    }

    #[test]
    fn test_multi_field_score_result_summary() {
        let result = MultiFieldScoreResult {
            total: 0.85,
            name_score: 1.0,
            version_score: 0.0,
            ecosystem_score: 1.0,
            license_score: 0.5,
            supplier_score: 0.5,
            group_score: 0.5,
        };

        let summary = result.summary();
        assert!(summary.contains("0.85"));
        assert!(summary.contains("name: 1.00"));
    }

    #[test]
    fn test_token_similarity_exact() {
        let score = string_similarity::compute_token_similarity("react-dom", "react-dom");
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_token_similarity_reordered() {
        // Reordered tokens should have high similarity
        let score = string_similarity::compute_token_similarity("react-dom", "dom-react");
        assert_eq!(score, 1.0, "Reordered tokens should match perfectly");
    }

    #[test]
    fn test_token_similarity_partial() {
        // Partial token overlap
        let score = string_similarity::compute_token_similarity("react-dom-utils", "react-dom");
        // Jaccard: 2 common / 3 total = 0.667
        assert!(
            (score - 0.667).abs() < 0.01,
            "Partial overlap should be ~0.67, got {}",
            score
        );
    }

    #[test]
    fn test_token_similarity_different_delimiters() {
        // Different delimiters should still work
        let score =
            string_similarity::compute_token_similarity("my_package_name", "my-package-name");
        assert_eq!(score, 1.0, "Different delimiters should match");
    }

    #[test]
    fn test_token_similarity_no_overlap() {
        let score = string_similarity::compute_token_similarity("react", "angular");
        assert_eq!(score, 0.0, "No common tokens should score 0");
    }

    #[test]
    fn test_version_similarity_exact() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.3".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.10, "Exact version match should give max boost");
    }

    #[test]
    fn test_version_similarity_same_major_minor() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.4".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.07, "Same major.minor should give 0.07 boost");
    }

    #[test]
    fn test_version_similarity_same_major() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.5.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.04, "Same major should give 0.04 boost");
    }

    #[test]
    fn test_version_similarity_different_major() {
        let v1 = "1.2.3".to_string();
        let v2 = "2.0.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.0, "Different major versions should give no boost");
    }

    #[test]
    fn test_version_similarity_prerelease() {
        // Handle prerelease versions like "1.2.3-beta"
        let v1 = "1.2.3-beta".to_string();
        let v2 = "1.2.4".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.07, "Prerelease should still match major.minor");
    }

    #[test]
    fn test_version_similarity_missing() {
        let v = "1.0.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(None, Some(&v));
        assert_eq!(score, 0.0, "Missing version should give no boost");

        let score = FuzzyMatcher::compute_version_similarity(None, None);
        assert_eq!(score, 0.0, "Both missing should give no boost");
    }

    #[test]
    fn test_fuzzy_match_with_reordered_tokens() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        let a = Component::new("react-dom".to_string(), "comp-1".to_string());
        let b = Component::new("dom-react".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        // Token similarity is 1.0, blended with character similarity
        assert!(
            score > 0.5,
            "Reordered names should still match, got {}",
            score
        );
    }

    #[test]
    fn test_fuzzy_match_version_boost() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        // Use slightly different names so we rely on fuzzy matching, not exact match
        let mut a = Component::new("lodash-utils".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());

        let mut b = Component::new("lodash-util".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string()); // Same major.minor -> +0.07 boost

        let mut c = Component::new("lodash-util".to_string(), "comp-3".to_string());
        c.version = Some("5.0.0".to_string()); // Different major -> +0.0 boost

        let score_same_minor = matcher.match_components(&a, &b);
        let score_diff_major = matcher.match_components(&a, &c);

        // Both should match (fuzzy), but same_minor should have version boost
        assert!(score_same_minor > 0.0, "Same minor should match");
        assert!(score_diff_major > 0.0, "Different major should still match");
        assert!(
            score_same_minor > score_diff_major,
            "Same minor version should score higher: {} vs {}",
            score_same_minor,
            score_diff_major
        );
    }

    #[test]
    fn test_soundex_basic() {
        // Test basic Soundex encoding
        assert_eq!(string_similarity::soundex("Robert"), "R163");
        assert_eq!(string_similarity::soundex("Rupert"), "R163"); // Same as Robert
        assert_eq!(string_similarity::soundex("Smith"), "S530");
        assert_eq!(string_similarity::soundex("Smyth"), "S530"); // Same as Smith
    }

    #[test]
    fn test_soundex_empty() {
        assert_eq!(string_similarity::soundex(""), "");
        assert_eq!(string_similarity::soundex("123"), ""); // No letters
    }

    #[test]
    fn test_phonetic_similarity_exact() {
        let score = string_similarity::compute_phonetic_similarity("color", "colour");
        assert_eq!(score, 1.0, "color and colour should match phonetically");
    }

    #[test]
    fn test_phonetic_similarity_different() {
        let score = string_similarity::compute_phonetic_similarity("react", "angular");
        assert!(
            score < 0.5,
            "Different names should have low phonetic similarity"
        );
    }

    #[test]
    fn test_phonetic_similarity_compound() {
        // Test compound names where tokens match phonetically
        let score = string_similarity::compute_phonetic_similarity("json-parser", "jayson-parser");
        assert!(
            score > 0.5,
            "Similar sounding compound names should match: {}",
            score
        );
    }

    #[test]
    fn test_fuzzy_match_with_phonetic() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        let a = Component::new("color-utils".to_string(), "comp-1".to_string());
        let b = Component::new("colour-utils".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        assert!(
            score > 0.7,
            "Phonetically similar names should match: {}",
            score
        );
    }
}
