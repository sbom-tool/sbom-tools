//! Trait definitions for component matching strategies.
//!
//! This module provides abstractions for component matching, enabling
//! pluggable matching strategies and easier testing.

use crate::model::Component;

/// Result of matching two components.
#[derive(Debug, Clone)]
#[must_use]
pub struct MatchResult {
    /// The matching confidence score (0.0 - 1.0)
    pub score: f64,
    /// The matching tier that produced this result
    pub tier: MatchTier,
    /// Additional metadata about the match
    pub metadata: MatchMetadata,
}

impl MatchResult {
    /// Create a new match result
    pub fn new(score: f64, tier: MatchTier) -> Self {
        Self {
            score,
            tier,
            metadata: MatchMetadata::default(),
        }
    }

    /// Create a match result with metadata
    pub const fn with_metadata(score: f64, tier: MatchTier, metadata: MatchMetadata) -> Self {
        Self {
            score,
            tier,
            metadata,
        }
    }

    /// Create a no-match result
    pub fn no_match() -> Self {
        Self {
            score: 0.0,
            tier: MatchTier::None,
            metadata: MatchMetadata::default(),
        }
    }

    /// Check if this represents a successful match
    #[must_use] 
    pub fn is_match(&self) -> bool {
        self.score > 0.0 && self.tier != MatchTier::None
    }
}

/// The tier/level at which a match was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatchTier {
    /// No match found
    None,
    /// Exact identifier match (PURL, CPE, etc.)
    ExactIdentifier,
    /// Match via alias table
    Alias,
    /// Match via ecosystem-specific rules
    EcosystemRule,
    /// Match via fuzzy string similarity
    Fuzzy,
    /// Match via custom user rules
    CustomRule,
}

impl MatchTier {
    /// Get the default confidence score for this tier
    #[must_use] 
    pub const fn default_score(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::ExactIdentifier => 1.0,
            Self::Alias => 0.95,
            Self::EcosystemRule => 0.90,
            Self::CustomRule => 0.92,
            Self::Fuzzy => 0.80,
        }
    }
}

/// Additional metadata about a match.
#[derive(Debug, Clone, Default)]
pub struct MatchMetadata {
    /// The field(s) that matched
    pub matched_fields: Vec<String>,
    /// The normalization applied, if any
    pub normalization: Option<String>,
    /// The rule that produced the match, if applicable
    pub rule_id: Option<String>,
}

/// Human-readable explanation of why two components matched (or didn't).
///
/// Useful for debugging match decisions and auditing SBOM diff results.
#[derive(Debug, Clone)]
pub struct MatchExplanation {
    /// The matching tier that produced this result
    pub tier: MatchTier,
    /// The final confidence score
    pub score: f64,
    /// Human-readable reason for the match/non-match
    pub reason: String,
    /// Detailed breakdown of score components
    pub score_breakdown: Vec<ScoreComponent>,
    /// Normalizations that were applied
    pub normalizations_applied: Vec<String>,
    /// Whether this was a successful match
    pub is_match: bool,
}

/// A component of the overall match score.
#[derive(Debug, Clone)]
pub struct ScoreComponent {
    /// Name of this score component
    pub name: String,
    /// Weight applied to this component
    pub weight: f64,
    /// Raw score before weighting
    pub raw_score: f64,
    /// Weighted contribution to final score
    pub weighted_score: f64,
    /// Description of what was compared
    pub description: String,
}

impl MatchExplanation {
    /// Create an explanation for a successful match.
    pub fn matched(tier: MatchTier, score: f64, reason: impl Into<String>) -> Self {
        Self {
            tier,
            score,
            reason: reason.into(),
            score_breakdown: Vec::new(),
            normalizations_applied: Vec::new(),
            is_match: true,
        }
    }

    /// Create an explanation for a failed match.
    pub fn no_match(reason: impl Into<String>) -> Self {
        Self {
            tier: MatchTier::None,
            score: 0.0,
            reason: reason.into(),
            score_breakdown: Vec::new(),
            normalizations_applied: Vec::new(),
            is_match: false,
        }
    }

    /// Add a score component to the breakdown.
    #[must_use]
    pub fn with_score_component(mut self, component: ScoreComponent) -> Self {
        self.score_breakdown.push(component);
        self
    }

    /// Add a normalization that was applied.
    #[must_use]
    pub fn with_normalization(mut self, normalization: impl Into<String>) -> Self {
        self.normalizations_applied.push(normalization.into());
        self
    }

    /// Generate a human-readable summary of the match.
    #[must_use] 
    pub fn summary(&self) -> String {
        if self.is_match {
            format!(
                "MATCH ({:.0}% confidence via {:?}): {}",
                self.score * 100.0,
                self.tier,
                self.reason
            )
        } else {
            format!("NO MATCH: {}", self.reason)
        }
    }

    /// Generate a detailed multi-line explanation.
    #[must_use] 
    pub fn detailed(&self) -> String {
        let mut lines = vec![self.summary()];

        if !self.score_breakdown.is_empty() {
            lines.push("Score breakdown:".to_string());
            for component in &self.score_breakdown {
                lines.push(format!(
                    "  - {}: {:.2} × {:.2} = {:.2} ({})",
                    component.name,
                    component.raw_score,
                    component.weight,
                    component.weighted_score,
                    component.description
                ));
            }
        }

        if !self.normalizations_applied.is_empty() {
            lines.push(format!(
                "Normalizations: {}",
                self.normalizations_applied.join(", ")
            ));
        }

        lines.join("\n")
    }
}

impl std::fmt::Display for MatchExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Trait for component matching strategies.
///
/// Implementors provide different strategies for determining if two
/// components represent the same logical package across SBOMs.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::matching::{ComponentMatcher, FuzzyMatcher, FuzzyMatchConfig};
///
/// let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
/// let score = matcher.match_score(&component_a, &component_b);
/// ```
pub trait ComponentMatcher: Send + Sync {
    /// Compute a match score between two components.
    ///
    /// Returns a score between 0.0 (no match) and 1.0 (perfect match).
    fn match_score(&self, a: &Component, b: &Component) -> f64;

    /// Compute a detailed match result between two components.
    ///
    /// Returns a `MatchResult` with score, tier, and metadata.
    fn match_detailed(&self, a: &Component, b: &Component) -> MatchResult {
        let score = self.match_score(a, b);
        if score > 0.0 {
            MatchResult::new(score, MatchTier::Fuzzy)
        } else {
            MatchResult::no_match()
        }
    }

    /// Generate a human-readable explanation of why two components matched or didn't.
    ///
    /// Useful for debugging and auditing match decisions.
    fn explain_match(&self, a: &Component, b: &Component) -> MatchExplanation {
        let result = self.match_detailed(a, b);
        if result.is_match() {
            MatchExplanation::matched(
                result.tier,
                result.score,
                format!("'{}' matches '{}' via {:?}", a.name, b.name, result.tier),
            )
        } else {
            MatchExplanation::no_match(format!(
                "'{}' does not match '{}' (score {:.2} below threshold)",
                a.name, b.name, result.score
            ))
        }
    }

    /// Find the best matching component from a list of candidates.
    ///
    /// Returns the best match and its score, or None if no match meets the threshold.
    fn find_best_match<'a>(
        &self,
        target: &Component,
        candidates: &'a [&Component],
        threshold: f64,
    ) -> Option<(&'a Component, f64)> {
        candidates
            .iter()
            .map(|c| (*c, self.match_score(target, c)))
            .filter(|(_, score)| *score >= threshold)
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the name of this matcher for logging/debugging.
    fn name(&self) -> &'static str {
        "ComponentMatcher"
    }

    /// Get the minimum threshold this matcher uses for fuzzy matching.
    fn threshold(&self) -> f64 {
        0.0
    }
}

/// Configuration for the cached matcher.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,
    /// Whether to cache detailed results (more memory).
    pub cache_detailed: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            cache_detailed: false,
        }
    }
}

impl CacheConfig {
    /// Create a config optimized for small SBOMs.
    #[must_use] 
    pub const fn small() -> Self {
        Self {
            max_entries: 10_000,
            cache_detailed: true,
        }
    }

    /// Create a config optimized for large SBOMs.
    #[must_use] 
    pub const fn large() -> Self {
        Self {
            max_entries: 500_000,
            cache_detailed: false,
        }
    }
}

/// Cache key combining component IDs.
#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    hash: u64,
}

impl CacheKey {
    fn new(a_id: &str, b_id: &str) -> Self {
        use xxhash_rust::xxh3::xxh3_64;

        // Create a combined key - order-independent for symmetry
        let (first, second) = if a_id < b_id {
            (a_id, b_id)
        } else {
            (b_id, a_id)
        };

        let combined = format!("{first}|{second}");
        Self {
            hash: xxh3_64(combined.as_bytes()),
        }
    }
}

/// Cached match result entry.
#[derive(Clone)]
struct CacheEntry {
    score: f64,
    detailed: Option<MatchResult>,
}

/// A wrapper that caches match results for performance.
///
/// The cache uses component IDs to generate cache keys and stores
/// match scores for quick lookup. This is particularly effective when
/// the same component pairs are compared multiple times.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::matching::{CachedMatcher, FuzzyMatcher, FuzzyMatchConfig, CacheConfig};
///
/// let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
/// let cached = CachedMatcher::new(matcher);
/// // Or with custom config:
/// let cached = CachedMatcher::with_config(matcher, CacheConfig::large());
/// ```
pub struct CachedMatcher<M: ComponentMatcher> {
    inner: M,
    config: CacheConfig,
    cache: std::sync::RwLock<std::collections::HashMap<CacheKey, CacheEntry>>,
    stats: std::sync::atomic::AtomicUsize,
    hits: std::sync::atomic::AtomicUsize,
}

impl<M: ComponentMatcher> CachedMatcher<M> {
    /// Create a new cached matcher wrapping the given matcher.
    pub fn new(inner: M) -> Self {
        Self::with_config(inner, CacheConfig::default())
    }

    /// Create a cached matcher with custom configuration.
    pub fn with_config(inner: M, config: CacheConfig) -> Self {
        Self {
            inner,
            config,
            cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            stats: std::sync::atomic::AtomicUsize::new(0),
            hits: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get a reference to the inner matcher.
    pub const fn inner(&self) -> &M {
        &self.inner
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        let total = self.stats.load(std::sync::atomic::Ordering::Relaxed);
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let size = self.cache.read().map(|c| c.len()).unwrap_or(0);
        CacheStats {
            total_lookups: total,
            cache_hits: hits,
            cache_misses: total.saturating_sub(hits),
            hit_rate: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
            cache_size: size,
        }
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        self.stats.store(0, std::sync::atomic::Ordering::Relaxed);
        self.hits.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Try to get a cached score.
    fn get_cached(&self, key: &CacheKey) -> Option<CacheEntry> {
        self.stats
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(cache) = self.cache.read()
            && let Some(entry) = cache.get(key) {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Some(entry.clone());
            }
        None
    }

    /// Store a result in the cache.
    fn store_cached(&self, key: CacheKey, entry: CacheEntry) {
        if let Ok(mut cache) = self.cache.write() {
            // Simple eviction: clear half the cache when full
            if cache.len() >= self.config.max_entries {
                let to_remove: Vec<CacheKey> = cache
                    .keys()
                    .take(self.config.max_entries / 2)
                    .cloned()
                    .collect();
                for k in to_remove {
                    cache.remove(&k);
                }
            }
            cache.insert(key, entry);
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cache lookups.
    pub total_lookups: usize,
    /// Number of cache hits.
    pub cache_hits: usize,
    /// Number of cache misses.
    pub cache_misses: usize,
    /// Hit rate (0.0 - 1.0).
    pub hit_rate: f64,
    /// Current cache size.
    pub cache_size: usize,
}

impl<M: ComponentMatcher> ComponentMatcher for CachedMatcher<M> {
    fn match_score(&self, a: &Component, b: &Component) -> f64 {
        let key = CacheKey::new(a.canonical_id.value(), b.canonical_id.value());

        // Check cache first
        if let Some(entry) = self.get_cached(&key) {
            return entry.score;
        }

        // Compute and cache
        let score = self.inner.match_score(a, b);
        self.store_cached(
            key,
            CacheEntry {
                score,
                detailed: None,
            },
        );
        score
    }

    fn match_detailed(&self, a: &Component, b: &Component) -> MatchResult {
        if !self.config.cache_detailed {
            return self.inner.match_detailed(a, b);
        }

        let key = CacheKey::new(a.canonical_id.value(), b.canonical_id.value());

        // Check cache for detailed result
        if let Some(entry) = self.get_cached(&key)
            && let Some(detailed) = entry.detailed {
                return detailed;
            }

        // Compute and cache
        let result = self.inner.match_detailed(a, b);
        self.store_cached(
            key,
            CacheEntry {
                score: result.score,
                detailed: Some(result.clone()),
            },
        );
        result
    }

    fn explain_match(&self, a: &Component, b: &Component) -> MatchExplanation {
        // Don't cache explanations as they're typically for debugging
        self.inner.explain_match(a, b)
    }

    fn name(&self) -> &'static str {
        "CachedMatcher"
    }

    fn threshold(&self) -> f64 {
        self.inner.threshold()
    }
}

/// A composite matcher that tries multiple strategies in order.
#[must_use]
pub struct CompositeMatcherBuilder {
    matchers: Vec<Box<dyn ComponentMatcher>>,
}

impl CompositeMatcherBuilder {
    /// Create a new composite matcher builder.
    pub fn new() -> Self {
        Self {
            matchers: Vec::new(),
        }
    }

    /// Add a matcher to the composite.
    pub fn with_matcher(mut self, matcher: Box<dyn ComponentMatcher>) -> Self {
        self.matchers.push(matcher);
        self
    }

    /// Build the composite matcher.
    #[must_use] 
    pub fn build(self) -> CompositeMatcher {
        CompositeMatcher {
            matchers: self.matchers,
        }
    }
}

impl Default for CompositeMatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A matcher that combines multiple matching strategies.
pub struct CompositeMatcher {
    matchers: Vec<Box<dyn ComponentMatcher>>,
}

impl ComponentMatcher for CompositeMatcher {
    fn match_score(&self, a: &Component, b: &Component) -> f64 {
        // Return the highest score from any matcher
        self.matchers
            .iter()
            .map(|m| m.match_score(a, b))
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0)
    }

    fn match_detailed(&self, a: &Component, b: &Component) -> MatchResult {
        // Return the best result from any matcher
        self.matchers
            .iter()
            .map(|m| m.match_detailed(a, b))
            .max_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or_else(MatchResult::no_match)
    }

    fn name(&self) -> &'static str {
        "CompositeMatcher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple test matcher that always returns a fixed score
    struct FixedScoreMatcher(f64);

    impl ComponentMatcher for FixedScoreMatcher {
        fn match_score(&self, _a: &Component, _b: &Component) -> f64 {
            self.0
        }

        fn name(&self) -> &'static str {
            "FixedScoreMatcher"
        }
    }

    #[test]
    fn test_match_result_creation() {
        let result = MatchResult::new(0.95, MatchTier::Alias);
        assert_eq!(result.score, 0.95);
        assert_eq!(result.tier, MatchTier::Alias);
        assert!(result.is_match());
    }

    #[test]
    fn test_no_match_result() {
        let result = MatchResult::no_match();
        assert_eq!(result.score, 0.0);
        assert_eq!(result.tier, MatchTier::None);
        assert!(!result.is_match());
    }

    #[test]
    fn test_match_tier_default_scores() {
        assert_eq!(MatchTier::ExactIdentifier.default_score(), 1.0);
        assert_eq!(MatchTier::Alias.default_score(), 0.95);
        assert_eq!(MatchTier::EcosystemRule.default_score(), 0.90);
        assert_eq!(MatchTier::None.default_score(), 0.0);
    }

    #[test]
    fn test_composite_matcher() {
        let matcher = CompositeMatcherBuilder::new()
            .with_matcher(Box::new(FixedScoreMatcher(0.5)))
            .with_matcher(Box::new(FixedScoreMatcher(0.8)))
            .with_matcher(Box::new(FixedScoreMatcher(0.3)))
            .build();

        let comp_a = Component::new("test".to_string(), "id-1".to_string());
        let comp_b = Component::new("test".to_string(), "id-2".to_string());

        // Should return the highest score (0.8)
        assert_eq!(matcher.match_score(&comp_a, &comp_b), 0.8);
    }

    #[test]
    fn test_find_best_match() {
        let matcher = FixedScoreMatcher(0.85);
        let target = Component::new("target".to_string(), "id-0".to_string());
        let candidates: Vec<Component> = vec![
            Component::new("candidate1".to_string(), "id-1".to_string()),
            Component::new("candidate2".to_string(), "id-2".to_string()),
        ];
        let candidate_refs: Vec<&Component> = candidates.iter().collect();

        // With threshold 0.8, should find a match
        let result = matcher.find_best_match(&target, &candidate_refs, 0.8);
        assert!(result.is_some());

        // With threshold 0.9, should not find a match
        let result = matcher.find_best_match(&target, &candidate_refs, 0.9);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_explanation_matched() {
        let explanation =
            MatchExplanation::matched(MatchTier::ExactIdentifier, 1.0, "Test match reason");

        assert!(explanation.is_match);
        assert_eq!(explanation.score, 1.0);
        assert_eq!(explanation.tier, MatchTier::ExactIdentifier);
        assert!(explanation.summary().contains("MATCH"));
        assert!(explanation.summary().contains("100%"));
    }

    #[test]
    fn test_match_explanation_no_match() {
        let explanation = MatchExplanation::no_match("Components are too different");

        assert!(!explanation.is_match);
        assert_eq!(explanation.score, 0.0);
        assert_eq!(explanation.tier, MatchTier::None);
        assert!(explanation.summary().contains("NO MATCH"));
    }

    #[test]
    fn test_match_explanation_with_breakdown() {
        let explanation = MatchExplanation::matched(MatchTier::Fuzzy, 0.85, "Fuzzy match")
            .with_score_component(ScoreComponent {
                name: "Jaro-Winkler".to_string(),
                weight: 0.7,
                raw_score: 0.9,
                weighted_score: 0.63,
                description: "name similarity".to_string(),
            })
            .with_score_component(ScoreComponent {
                name: "Levenshtein".to_string(),
                weight: 0.3,
                raw_score: 0.73,
                weighted_score: 0.22,
                description: "edit distance".to_string(),
            })
            .with_normalization("lowercase");

        assert_eq!(explanation.score_breakdown.len(), 2);
        assert_eq!(explanation.normalizations_applied.len(), 1);

        let detailed = explanation.detailed();
        assert!(detailed.contains("Score breakdown:"));
        assert!(detailed.contains("Jaro-Winkler"));
        assert!(detailed.contains("Normalizations: lowercase"));
    }

    #[test]
    fn test_match_explanation_display() {
        let explanation = MatchExplanation::matched(MatchTier::Alias, 0.95, "Known alias");
        let display = format!("{}", explanation);
        assert!(display.contains("MATCH"));
        assert!(display.contains("95%"));
    }
}
