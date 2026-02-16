//! Multi-field scoring and version divergence calculations.
//!
//! This module provides graduated version comparison and the
//! `MultiFieldScoreResult` type used by multi-field weighted matching.

use super::config;

/// Compute version divergence score using semver distance.
///
/// Returns a graduated score based on how different the versions are:
/// - Exact match: 1.0
/// - Same major.minor: 0.8 - (`patch_diff` * 0.01), min 0.5
/// - Same major: 0.5 - (`minor_diff` * `minor_penalty`), min 0.2
/// - Different major: 0.3 - (`major_diff` * `major_penalty`), min 0.0
#[must_use] 
pub fn compute_version_divergence_score(
    version_a: &Option<String>,
    version_b: &Option<String>,
    weights: &config::MultiFieldWeights,
) -> f64 {
    match (version_a, version_b) {
        (Some(va), Some(vb)) if va == vb => 1.0,
        (None, None) => 0.5, // Both missing = neutral
        (Some(va), Some(vb)) => {
            // Parse semver components
            let parts_a = parse_semver_parts(va);
            let parts_b = parse_semver_parts(vb);

            if let (Some((maj_a, min_a, patch_a)), Some((maj_b, min_b, patch_b))) = (parts_a, parts_b) {
                if maj_a == maj_b && min_a == min_b {
                    // Same major.minor - small penalty for patch difference
                    let patch_diff = (i64::from(patch_a) - i64::from(patch_b)).unsigned_abs() as f64;
                    patch_diff.mul_add(-0.01, 0.8).max(0.5)
                } else if maj_a == maj_b {
                    // Same major - moderate penalty for minor difference
                    let minor_diff = (i64::from(min_a) - i64::from(min_b)).unsigned_abs() as f64;
                    minor_diff.mul_add(-weights.version_minor_penalty, 0.5).max(0.2)
                } else {
                    // Different major - larger penalty
                    let major_diff = (i64::from(maj_a) - i64::from(maj_b)).unsigned_abs() as f64;
                    major_diff.mul_add(-weights.version_major_penalty, 0.3).max(0.0)
                }
            } else {
                // Couldn't parse semver - fall back to string comparison
                // Give partial credit if versions share a common prefix
                let common_prefix_len = va
                    .chars()
                    .zip(vb.chars())
                    .take_while(|(a, b)| a == b)
                    .count();
                let max_len = va.len().max(vb.len());
                if max_len > 0 && common_prefix_len > 0 {
                    (common_prefix_len as f64 / max_len as f64 * 0.5).min(0.4)
                } else {
                    0.1 // Different versions with no common prefix
                }
            }
        }
        _ => 0.0, // One missing
    }
}

/// Parse a version string into semver components (major, minor, patch).
/// Returns None if the version cannot be parsed.
#[must_use] 
pub fn parse_semver_parts(version: &str) -> Option<(u32, u32, u32)> {
    // Strip common prefixes like 'v' or 'V'
    let version = version.trim_start_matches(['v', 'V']);

    // Split on '.' and try to parse first three components
    let mut parts = version.split(['.', '-', '+']);

    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

/// Result of multi-field scoring with per-field breakdown.
#[derive(Debug, Clone, Default)]
pub struct MultiFieldScoreResult {
    /// Total weighted score (0.0 - 1.0)
    pub total: f64,
    /// Name similarity score
    pub name_score: f64,
    /// Version match score
    pub version_score: f64,
    /// Ecosystem match score
    pub ecosystem_score: f64,
    /// License overlap score (Jaccard)
    pub license_score: f64,
    /// Supplier match score
    pub supplier_score: f64,
    /// Group/namespace match score
    pub group_score: f64,
}

impl MultiFieldScoreResult {
    /// Get a human-readable summary of the score breakdown.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Total: {:.2} (name: {:.2}, version: {:.2}, ecosystem: {:.2}, licenses: {:.2}, supplier: {:.2}, group: {:.2})",
            self.total,
            self.name_score,
            self.version_score,
            self.ecosystem_score,
            self.license_score,
            self.supplier_score,
            self.group_score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver_basic() {
        assert_eq!(parse_semver_parts("1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn test_parse_semver_with_prefix() {
        assert_eq!(parse_semver_parts("v1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn test_parse_semver_major_only() {
        assert_eq!(parse_semver_parts("3"), Some((3, 0, 0)));
    }

    #[test]
    fn test_parse_semver_invalid() {
        assert_eq!(parse_semver_parts("abc"), None);
    }

    #[test]
    fn test_version_divergence_exact() {
        let weights = config::MultiFieldWeights::default();
        let v1 = Some("1.2.3".to_string());
        let v2 = Some("1.2.3".to_string());
        assert_eq!(compute_version_divergence_score(&v1, &v2, &weights), 1.0);
    }

    #[test]
    fn test_version_divergence_same_major_minor() {
        let weights = config::MultiFieldWeights::default();
        let v1 = Some("1.2.3".to_string());
        let v2 = Some("1.2.5".to_string());
        let score = compute_version_divergence_score(&v1, &v2, &weights);
        assert!((0.5..=0.8).contains(&score));
    }

    #[test]
    fn test_version_divergence_none() {
        let weights = config::MultiFieldWeights::default();
        assert_eq!(
            compute_version_divergence_score(&None, &None, &weights),
            0.5
        );
    }

    #[test]
    fn test_multi_field_score_result_summary() {
        let result = MultiFieldScoreResult {
            total: 0.85,
            name_score: 0.9,
            version_score: 1.0,
            ecosystem_score: 1.0,
            license_score: 0.5,
            supplier_score: 0.0,
            group_score: 1.0,
        };
        let summary = result.summary();
        assert!(summary.contains("0.85"));
    }
}
