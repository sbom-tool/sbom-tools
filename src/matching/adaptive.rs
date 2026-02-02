//! Adaptive threshold adjustment for fuzzy matching.
//!
//! This module provides algorithms to automatically adjust matching thresholds
//! based on the actual distribution of match scores in the data.
//!
//! # Problem
//!
//! A fixed threshold (e.g., 0.85) may be:
//! - Too strict for SBOMs with many renamed packages (missing valid matches)
//! - Too permissive for SBOMs with many similar-named packages (false positives)
//!
//! # Solution
//!
//! Adaptive thresholding analyzes the score distribution and finds an optimal
//! threshold that maximizes true matches while minimizing false positives.
//!
//! # Algorithms
//!
//! - **Target Match Ratio**: Binary search for threshold yielding ~N% matches
//! - **Otsu's Method**: Find threshold that maximizes between-class variance
//! - **Knee/Elbow Detection**: Find threshold at score distribution inflection point

use crate::matching::{ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher};
use crate::model::{Component, NormalizedSbom};

/// Configuration for adaptive threshold adjustment.
#[derive(Debug, Clone)]
pub struct AdaptiveThresholdConfig {
    /// Minimum allowed threshold (don't go below this)
    pub min_threshold: f64,
    /// Maximum allowed threshold (don't go above this)
    pub max_threshold: f64,
    /// Number of iterations for binary search
    pub max_iterations: usize,
    /// Target match ratio (0.0 - 1.0, where 1.0 means all components match)
    pub target_match_ratio: Option<f64>,
    /// Minimum number of samples needed for reliable estimation
    pub min_samples: usize,
    /// Precision for binary search convergence
    pub precision: f64,
}

impl Default for AdaptiveThresholdConfig {
    fn default() -> Self {
        Self {
            min_threshold: 0.50,
            max_threshold: 0.99,
            max_iterations: 20,
            target_match_ratio: None, // Use Otsu by default
            min_samples: 10,
            precision: 0.01,
        }
    }
}

impl AdaptiveThresholdConfig {
    /// Configure for target match ratio search.
    pub fn for_target_ratio(ratio: f64) -> Self {
        Self {
            target_match_ratio: Some(ratio.clamp(0.0, 1.0)),
            ..Default::default()
        }
    }

    /// Configure for Otsu's method (automatic threshold).
    pub fn otsu() -> Self {
        Self {
            target_match_ratio: None,
            ..Default::default()
        }
    }
}

/// Result of adaptive threshold computation.
#[derive(Debug, Clone)]
pub struct AdaptiveThresholdResult {
    /// The computed optimal threshold
    pub threshold: f64,
    /// Method used to compute the threshold
    pub method: AdaptiveMethod,
    /// Number of component pairs sampled
    pub samples: usize,
    /// Score statistics
    pub score_stats: ScoreStats,
    /// Match ratio at the computed threshold
    pub match_ratio: f64,
    /// Confidence in the result (0.0 - 1.0)
    pub confidence: f64,
}

/// Method used for adaptive threshold computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMethod {
    /// Binary search for target match ratio
    TargetRatio,
    /// Otsu's method (maximizes between-class variance)
    Otsu,
    /// Fallback to default threshold
    Default,
}

/// Statistics about the score distribution.
#[derive(Debug, Clone)]
pub struct ScoreStats {
    /// Minimum score observed
    pub min: f64,
    /// Maximum score observed
    pub max: f64,
    /// Mean score
    pub mean: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Median score
    pub median: f64,
    /// Number of exact matches (score = 1.0)
    pub exact_matches: usize,
    /// Number of complete non-matches (score = 0.0)
    pub zero_scores: usize,
}

impl ScoreStats {
    /// Compute statistics from a set of scores.
    pub fn from_scores(scores: &[f64]) -> Self {
        if scores.is_empty() {
            return Self {
                min: 0.0,
                max: 0.0,
                mean: 0.0,
                std_dev: 0.0,
                median: 0.0,
                exact_matches: 0,
                zero_scores: 0,
            };
        }

        let mut sorted = scores.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let mean = scores.iter().sum::<f64>() / scores.len() as f64;
        let median = if sorted.len().is_multiple_of(2) {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        } else {
            sorted[sorted.len() / 2]
        };

        let variance =
            scores.iter().map(|&s| (s - mean).powi(2)).sum::<f64>() / scores.len() as f64;
        let std_dev = variance.sqrt();

        let exact_matches = scores.iter().filter(|&&s| s >= 0.9999).count();
        let zero_scores = scores.iter().filter(|&&s| s < 0.0001).count();

        Self {
            min,
            max,
            mean,
            std_dev,
            median,
            exact_matches,
            zero_scores,
        }
    }
}

/// Adaptive threshold adjuster.
pub struct AdaptiveThreshold {
    config: AdaptiveThresholdConfig,
}

impl AdaptiveThreshold {
    /// Create a new adaptive threshold adjuster with the given config.
    pub fn new(config: AdaptiveThresholdConfig) -> Self {
        Self { config }
    }

    /// Compute the optimal threshold for matching between two SBOMs.
    pub fn compute_threshold(
        &self,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        matcher: &FuzzyMatcher,
    ) -> AdaptiveThresholdResult {
        // Sample scores between components
        let scores = self.sample_scores(old_sbom, new_sbom, matcher);

        if scores.len() < self.config.min_samples {
            // Not enough data, fall back to default
            return AdaptiveThresholdResult {
                threshold: matcher.config().threshold,
                method: AdaptiveMethod::Default,
                samples: scores.len(),
                score_stats: ScoreStats::from_scores(&scores),
                match_ratio: 0.0,
                confidence: 0.0,
            };
        }

        let stats = ScoreStats::from_scores(&scores);

        // Choose method based on config
        let (threshold, method) = if let Some(target_ratio) = self.config.target_match_ratio {
            let t = self.binary_search_threshold(&scores, target_ratio);
            (t, AdaptiveMethod::TargetRatio)
        } else {
            let t = self.otsu_threshold(&scores);
            (t, AdaptiveMethod::Otsu)
        };

        // Clamp to configured bounds
        let threshold = threshold.clamp(self.config.min_threshold, self.config.max_threshold);

        // Compute match ratio at this threshold
        let match_count = scores.iter().filter(|&&s| s >= threshold).count();
        let match_ratio = match_count as f64 / scores.len() as f64;

        // Estimate confidence based on sample size and score distribution
        let confidence = self.estimate_confidence(&scores, &stats);

        AdaptiveThresholdResult {
            threshold,
            method,
            samples: scores.len(),
            score_stats: stats,
            match_ratio,
            confidence,
        }
    }

    /// Sample match scores between components of two SBOMs.
    fn sample_scores(
        &self,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        matcher: &FuzzyMatcher,
    ) -> Vec<f64> {
        let mut scores = Vec::new();
        let max_samples = 1000; // Limit for performance

        let old_components: Vec<&Component> = old_sbom.components.values().collect();
        let new_components: Vec<&Component> = new_sbom.components.values().collect();

        // For each old component, find best match score in new SBOM
        for old_comp in old_components.iter().take(max_samples) {
            let best_score = new_components
                .iter()
                .map(|new_comp| matcher.match_score(old_comp, new_comp))
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or(0.0);

            scores.push(best_score);
        }

        scores
    }

    /// Binary search for threshold that yields target match ratio.
    fn binary_search_threshold(&self, scores: &[f64], target_ratio: f64) -> f64 {
        let mut low = self.config.min_threshold;
        let mut high = self.config.max_threshold;

        for _ in 0..self.config.max_iterations {
            let mid = (low + high) / 2.0;
            let match_count = scores.iter().filter(|&&s| s >= mid).count();
            let ratio = match_count as f64 / scores.len() as f64;

            if (ratio - target_ratio).abs() < self.config.precision {
                return mid;
            }

            if ratio > target_ratio {
                // Too many matches, increase threshold
                low = mid;
            } else {
                // Too few matches, decrease threshold
                high = mid;
            }
        }

        (low + high) / 2.0
    }

    /// Otsu's method: find threshold that maximizes between-class variance.
    fn otsu_threshold(&self, scores: &[f64]) -> f64 {
        // Discretize scores into bins
        let num_bins = 100;
        let mut histogram = vec![0usize; num_bins];

        for &score in scores {
            let bin = ((score * (num_bins - 1) as f64) as usize).min(num_bins - 1);
            histogram[bin] += 1;
        }

        let total = scores.len() as f64;
        let mut sum_total = 0.0;
        for (i, &count) in histogram.iter().enumerate() {
            sum_total += i as f64 * count as f64;
        }

        let mut first_optimal_bin = 0;
        let mut last_optimal_bin = 0;
        let mut best_variance = 0.0;
        let mut sum_background = 0.0;
        let mut weight_background = 0.0;
        let variance_tolerance = 1e-6; // Allow for floating-point comparison

        for (i, &count) in histogram.iter().enumerate() {
            weight_background += count as f64;
            if weight_background == 0.0 {
                continue;
            }

            let weight_foreground = total - weight_background;
            if weight_foreground == 0.0 {
                break;
            }

            sum_background += i as f64 * count as f64;
            let mean_background = sum_background / weight_background;
            let mean_foreground = (sum_total - sum_background) / weight_foreground;

            let between_variance =
                weight_background * weight_foreground * (mean_background - mean_foreground).powi(2);

            if between_variance > best_variance + variance_tolerance {
                // Found a new best - reset the range
                best_variance = between_variance;
                first_optimal_bin = i;
                last_optimal_bin = i;
            } else if (between_variance - best_variance).abs() <= variance_tolerance {
                // Same variance (within tolerance) - extend the range
                last_optimal_bin = i;
            }
        }

        // Use the middle of the optimal range for better practical thresholds
        // This helps when there's a gap between clusters (bimodal distribution)
        let middle_bin = (first_optimal_bin + last_optimal_bin) / 2;
        (middle_bin as f64 + 0.5) / num_bins as f64
    }

    /// Estimate confidence in the computed threshold.
    fn estimate_confidence(&self, scores: &[f64], stats: &ScoreStats) -> f64 {
        // Factors that increase confidence:
        // 1. More samples
        // 2. Clear bimodal distribution (high std_dev)
        // 3. Some exact matches (indicates correct matches exist)
        // 4. Not all zero scores

        let sample_factor = (scores.len() as f64 / 100.0).min(1.0);
        let distribution_factor = (stats.std_dev * 3.0).min(1.0);
        let exact_match_factor = if stats.exact_matches > 0 { 0.9 } else { 0.5 };
        let zero_score_penalty = if stats.zero_scores == scores.len() {
            0.0
        } else {
            1.0
        };

        (sample_factor * 0.3
            + distribution_factor * 0.3
            + exact_match_factor * 0.2
            + zero_score_penalty * 0.2)
            .clamp(0.0, 1.0)
    }
}

impl Default for AdaptiveThreshold {
    fn default() -> Self {
        Self::new(AdaptiveThresholdConfig::default())
    }
}

/// Extension trait for FuzzyMatcher to support adaptive thresholding.
pub trait AdaptiveMatching {
    /// Create a matcher with an adaptively computed threshold for the given SBOMs.
    fn with_adaptive_threshold(
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        base_config: FuzzyMatchConfig,
    ) -> (FuzzyMatcher, AdaptiveThresholdResult);

    /// Compute and apply adaptive threshold to an existing matcher.
    fn adapt_threshold(
        &self,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> AdaptiveThresholdResult;
}

impl AdaptiveMatching for FuzzyMatcher {
    fn with_adaptive_threshold(
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        base_config: FuzzyMatchConfig,
    ) -> (FuzzyMatcher, AdaptiveThresholdResult) {
        let base_matcher = FuzzyMatcher::new(base_config.clone());
        let adjuster = AdaptiveThreshold::default();
        let result = adjuster.compute_threshold(old_sbom, new_sbom, &base_matcher);

        // Create new matcher with adapted threshold
        let mut adapted_config = base_config;
        adapted_config.threshold = result.threshold;
        let adapted_matcher = FuzzyMatcher::new(adapted_config);

        (adapted_matcher, result)
    }

    fn adapt_threshold(
        &self,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> AdaptiveThresholdResult {
        let adjuster = AdaptiveThreshold::default();
        adjuster.compute_threshold(old_sbom, new_sbom, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DocumentMetadata;

    fn make_component(name: &str) -> Component {
        Component::new(name.to_string(), format!("id-{}", name))
    }

    fn make_sbom_with_components(names: &[&str]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for name in names {
            sbom.add_component(make_component(name));
        }
        sbom
    }

    #[test]
    fn test_score_stats_computation() {
        let scores = vec![0.0, 0.3, 0.5, 0.7, 1.0];
        let stats = ScoreStats::from_scores(&scores);

        assert_eq!(stats.min, 0.0);
        assert_eq!(stats.max, 1.0);
        assert!((stats.mean - 0.5).abs() < 0.01);
        assert_eq!(stats.median, 0.5);
        assert_eq!(stats.exact_matches, 1);
        assert_eq!(stats.zero_scores, 1);
    }

    #[test]
    fn test_score_stats_empty() {
        let scores: Vec<f64> = vec![];
        let stats = ScoreStats::from_scores(&scores);

        assert_eq!(stats.min, 0.0);
        assert_eq!(stats.max, 0.0);
        assert_eq!(stats.mean, 0.0);
    }

    #[test]
    fn test_adaptive_threshold_config() {
        let config = AdaptiveThresholdConfig::for_target_ratio(0.7);
        assert_eq!(config.target_match_ratio, Some(0.7));

        let config = AdaptiveThresholdConfig::otsu();
        assert!(config.target_match_ratio.is_none());
    }

    #[test]
    fn test_adaptive_threshold_with_similar_sboms() {
        let old = make_sbom_with_components(&[
            "lodash", "react", "express", "axios", "moment", "webpack", "babel", "eslint",
            "prettier", "jest",
        ]);
        let new = make_sbom_with_components(&[
            "lodash", "react", "express", "axios", "dayjs", // moment -> dayjs
            "webpack", "babel", "eslint", "prettier", "vitest", // jest -> vitest
        ]);

        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        let adjuster = AdaptiveThreshold::new(AdaptiveThresholdConfig::otsu());
        let result = adjuster.compute_threshold(&old, &new, &matcher);

        assert!(result.threshold >= 0.5 && result.threshold <= 0.99);
        assert!(result.samples >= 10);
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_adaptive_threshold_target_ratio() {
        let old = make_sbom_with_components(&[
            "package-a",
            "package-b",
            "package-c",
            "package-d",
            "package-e",
            "package-f",
            "package-g",
            "package-h",
            "package-i",
            "package-j",
        ]);
        let new = make_sbom_with_components(&[
            "package-a",
            "package-b",
            "package-c",
            "different-1",
            "different-2",
            "different-3",
            "different-4",
            "different-5",
            "different-6",
            "different-7",
        ]);

        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        let config = AdaptiveThresholdConfig::for_target_ratio(0.3); // Target 30% matches
        let adjuster = AdaptiveThreshold::new(config);
        let result = adjuster.compute_threshold(&old, &new, &matcher);

        assert_eq!(result.method, AdaptiveMethod::TargetRatio);
    }

    #[test]
    fn test_adaptive_matching_trait() {
        let old = make_sbom_with_components(&["lodash", "express", "react", "vue", "angular"]);
        let new = make_sbom_with_components(&["lodash", "express", "react", "svelte", "solid"]);

        let base_config = FuzzyMatchConfig::balanced();
        let (adapted_matcher, result) =
            FuzzyMatcher::with_adaptive_threshold(&old, &new, base_config);

        // The adapted matcher should have the computed threshold
        assert!((adapted_matcher.config().threshold - result.threshold).abs() < 0.001);
    }

    #[test]
    fn test_binary_search_threshold() {
        let scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        let adjuster = AdaptiveThreshold::new(AdaptiveThresholdConfig::for_target_ratio(0.5));

        let threshold = adjuster.binary_search_threshold(&scores, 0.5);

        // Should find threshold around 0.5 where 50% of scores are >= threshold
        assert!((threshold - 0.5).abs() < 0.1);
    }

    #[test]
    fn test_otsu_threshold_bimodal() {
        // Create bimodal distribution (two peaks) with deterministic values
        // Using extreme separation to make Otsu clearly identify the gap
        let mut scores = Vec::new();

        // Low scores: all exactly 0.1
        for _ in 0..50 {
            scores.push(0.1);
        }
        // High scores: all exactly 0.9
        for _ in 0..50 {
            scores.push(0.9);
        }

        let adjuster = AdaptiveThreshold::default();
        let threshold = adjuster.otsu_threshold(&scores);

        // Otsu should find threshold between the two peaks (around 0.5)
        // With perfectly bimodal data at 0.1 and 0.9, the optimal split is 0.5
        assert!(
            threshold > 0.2 && threshold < 0.8,
            "Threshold {} should be between peaks (0.2-0.8)",
            threshold
        );
    }
}
