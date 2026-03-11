//! License policy evaluation.
//!
//! Checks component licenses against allow/deny/review lists,
//! with glob pattern matching for license families.

use crate::model::{LicenseExpression, LicenseFamily, NormalizedSbom};
use serde::{Deserialize, Serialize};

/// License policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicensePolicyConfig {
    /// Allowed license SPDX IDs (glob patterns supported: `BSD-*`)
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied license SPDX IDs (glob patterns supported: `AGPL-*`)
    #[serde(default)]
    pub deny: Vec<String>,
    /// Licenses that require manual review
    #[serde(default)]
    pub review: Vec<String>,
    /// Fail on copyleft + proprietary conflicts in dependency tree
    #[serde(default = "default_true")]
    pub fail_on_conflict: bool,
}

fn default_true() -> bool {
    true
}

impl LicensePolicyConfig {
    /// Create a permissive policy that allows everything
    #[must_use]
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Create a strict policy that only allows common permissive licenses
    #[must_use]
    pub fn strict_permissive() -> Self {
        Self {
            allow: vec![
                "MIT".to_string(),
                "Apache-2.0".to_string(),
                "BSD-2-Clause".to_string(),
                "BSD-3-Clause".to_string(),
                "ISC".to_string(),
                "0BSD".to_string(),
                "Unlicense".to_string(),
                "CC0-1.0".to_string(),
            ],
            deny: vec![
                "AGPL-*".to_string(),
                "SSPL-*".to_string(),
                "BSL-*".to_string(),
            ],
            review: vec![
                "GPL-*".to_string(),
                "LGPL-*".to_string(),
                "MPL-*".to_string(),
                "EPL-*".to_string(),
                "CDDL-*".to_string(),
            ],
            fail_on_conflict: true,
        }
    }
}

/// Policy decision for a license
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// License is explicitly allowed
    Allowed,
    /// License is explicitly denied
    Denied,
    /// License requires manual review
    NeedsReview,
    /// No policy rule matched — allowed by default
    Unspecified,
    /// No license declared
    Undeclared,
}

/// A license policy violation for a specific component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePolicyViolation {
    /// Component name
    pub component: String,
    /// Component version
    pub version: Option<String>,
    /// The license expression that triggered the violation
    pub license: String,
    /// Policy decision
    pub decision: PolicyDecision,
    /// License family classification
    pub family: LicenseFamily,
}

/// Overall license policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePolicyResult {
    /// Total components evaluated
    pub total_components: usize,
    /// Components that passed policy
    pub allowed_count: usize,
    /// Components with denied licenses
    pub denied_count: usize,
    /// Components requiring review
    pub review_count: usize,
    /// Components with no license declared
    pub undeclared_count: usize,
    /// Whether the policy passed (no denied licenses)
    pub passed: bool,
    /// All violations (denied + review + undeclared)
    pub violations: Vec<LicensePolicyViolation>,
}

/// Check if a license ID matches a pattern (supports `*` glob at end)
fn matches_pattern(license_id: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        license_id.starts_with(prefix)
    } else {
        license_id.eq_ignore_ascii_case(pattern)
    }
}

/// Evaluate a single license expression against the policy
fn evaluate_expression(expr: &LicenseExpression, config: &LicensePolicyConfig) -> PolicyDecision {
    let license_id = &expr.expression;

    // Check deny list first (highest priority)
    for pattern in &config.deny {
        if matches_pattern(license_id, pattern) {
            return PolicyDecision::Denied;
        }
    }

    // Check review list
    for pattern in &config.review {
        if matches_pattern(license_id, pattern) {
            return PolicyDecision::NeedsReview;
        }
    }

    // Check allow list
    if config.allow.is_empty() {
        // No allow list means everything not denied/review is allowed
        return PolicyDecision::Unspecified;
    }

    for pattern in &config.allow {
        if matches_pattern(license_id, pattern) {
            return PolicyDecision::Allowed;
        }
    }

    // If allow list exists but license didn't match, it needs review
    PolicyDecision::NeedsReview
}

/// Evaluate all component licenses against a policy.
#[must_use]
pub fn evaluate_license_policy(
    sbom: &NormalizedSbom,
    config: &LicensePolicyConfig,
) -> LicensePolicyResult {
    let mut allowed_count = 0;
    let mut denied_count = 0;
    let mut review_count = 0;
    let mut undeclared_count = 0;
    let mut violations = Vec::new();

    for comp in sbom.components.values() {
        if comp.licenses.declared.is_empty() && comp.licenses.concluded.is_none() {
            undeclared_count += 1;
            violations.push(LicensePolicyViolation {
                component: comp.name.clone(),
                version: comp.version.clone(),
                license: "(undeclared)".to_string(),
                decision: PolicyDecision::Undeclared,
                family: LicenseFamily::Other,
            });
            continue;
        }

        let mut component_denied = false;
        let mut component_review = false;

        for license in &comp.licenses.declared {
            let decision = evaluate_expression(license, config);
            match decision {
                PolicyDecision::Denied => {
                    component_denied = true;
                    violations.push(LicensePolicyViolation {
                        component: comp.name.clone(),
                        version: comp.version.clone(),
                        license: license.expression.clone(),
                        decision: PolicyDecision::Denied,
                        family: license.family(),
                    });
                }
                PolicyDecision::NeedsReview => {
                    component_review = true;
                    violations.push(LicensePolicyViolation {
                        component: comp.name.clone(),
                        version: comp.version.clone(),
                        license: license.expression.clone(),
                        decision: PolicyDecision::NeedsReview,
                        family: license.family(),
                    });
                }
                PolicyDecision::Allowed | PolicyDecision::Unspecified => {}
                PolicyDecision::Undeclared => {}
            }
        }

        if component_denied {
            denied_count += 1;
        } else if component_review {
            review_count += 1;
        } else {
            allowed_count += 1;
        }
    }

    // Check for copyleft/proprietary conflicts
    if config.fail_on_conflict {
        for comp in sbom.components.values() {
            if comp.licenses.has_conflicts() {
                let license_str = comp
                    .licenses
                    .declared
                    .iter()
                    .map(|l| l.expression.as_str())
                    .collect::<Vec<_>>()
                    .join(" + ");
                violations.push(LicensePolicyViolation {
                    component: comp.name.clone(),
                    version: comp.version.clone(),
                    license: format!("CONFLICT: {license_str}"),
                    decision: PolicyDecision::Denied,
                    family: LicenseFamily::Other,
                });
            }
        }
    }

    let passed = denied_count == 0;

    LicensePolicyResult {
        total_components: sbom.components.len(),
        allowed_count,
        denied_count,
        review_count,
        undeclared_count,
        passed,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    fn make_sbom_with_licenses(licenses: &[&str]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for (i, lic) in licenses.iter().enumerate() {
            let mut comp = Component::new(format!("comp-{i}"), format!("id-{i}"));
            if !lic.is_empty() {
                comp.licenses
                    .add_declared(LicenseExpression::new(lic.to_string()));
            }
            sbom.components.insert(comp.canonical_id.clone(), comp);
        }
        sbom
    }

    #[test]
    fn permissive_policy_allows_all() {
        let sbom = make_sbom_with_licenses(&["MIT", "Apache-2.0", "GPL-3.0-only"]);
        let config = LicensePolicyConfig::permissive();
        let result = evaluate_license_policy(&sbom, &config);
        assert!(result.passed);
        assert_eq!(result.denied_count, 0);
    }

    #[test]
    fn strict_policy_denies_agpl() {
        let sbom = make_sbom_with_licenses(&["MIT", "AGPL-3.0-only"]);
        let config = LicensePolicyConfig::strict_permissive();
        let result = evaluate_license_policy(&sbom, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
    }

    #[test]
    fn strict_policy_flags_gpl_for_review() {
        let sbom = make_sbom_with_licenses(&["MIT", "GPL-3.0-only"]);
        let config = LicensePolicyConfig::strict_permissive();
        let result = evaluate_license_policy(&sbom, &config);
        assert!(result.passed); // review doesn't fail
        assert_eq!(result.review_count, 1);
    }

    #[test]
    fn undeclared_licenses_flagged() {
        let sbom = make_sbom_with_licenses(&["MIT", ""]);
        let config = LicensePolicyConfig::strict_permissive();
        let result = evaluate_license_policy(&sbom, &config);
        assert_eq!(result.undeclared_count, 1);
    }

    #[test]
    fn glob_pattern_matching() {
        assert!(matches_pattern("BSD-2-Clause", "BSD-*"));
        assert!(matches_pattern("AGPL-3.0-only", "AGPL-*"));
        assert!(!matches_pattern("MIT", "BSD-*"));
        assert!(matches_pattern("MIT", "MIT"));
        assert!(matches_pattern("mit", "MIT")); // case insensitive
    }

    #[test]
    fn allow_list_requires_match() {
        let sbom = make_sbom_with_licenses(&["MIT", "Artistic-2.0"]);
        let config = LicensePolicyConfig {
            allow: vec!["MIT".to_string()],
            ..Default::default()
        };
        let result = evaluate_license_policy(&sbom, &config);
        assert_eq!(result.review_count, 1); // Artistic-2.0 not on allow list
        assert_eq!(result.allowed_count, 1);
    }
}
