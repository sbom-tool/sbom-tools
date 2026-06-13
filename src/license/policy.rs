//! License policy evaluation.
//!
//! Checks component licenses against allow/deny/review lists,
//! with glob pattern matching for license families.
//!
//! SPDX expressions are evaluated operand-by-operand:
//! - `OR` is the licensee's choice — an expression is only denied if *every*
//!   alternative hits the deny list ("MIT OR GPL-3.0-only" passes a `GPL-*`
//!   deny; "GPL-2.0-only OR GPL-3.0-only" does not).
//! - `AND` requires every operand to comply — one denied operand denies the
//!   whole expression.
//! - `WITH` exceptions match patterns against the base license ID
//!   ("Apache-2.0 WITH LLVM-exception" matches an `Apache-2.0` pattern).
//!
//! Non-parseable expressions fall back to whole-string pattern matching.

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
        license_id
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    } else {
        license_id.eq_ignore_ascii_case(pattern)
    }
}

/// Check if a license ID matches any pattern in the list
fn matches_any(license_id: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_pattern(license_id, pattern))
}

/// Extract the operand license ID (without any WITH exception)
fn req_license_id(req: &spdx::LicenseReq) -> String {
    req.license.to_string()
}

/// Evaluate a single license ID (or non-parseable expression) against the policy
fn evaluate_license_id(license_id: &str, config: &LicensePolicyConfig) -> PolicyDecision {
    if matches_any(license_id, &config.deny) {
        return PolicyDecision::Denied;
    }

    if matches_any(license_id, &config.review) {
        return PolicyDecision::NeedsReview;
    }

    if config.allow.is_empty() {
        // No allow list means everything not denied/review is allowed
        return PolicyDecision::Unspecified;
    }

    if matches_any(license_id, &config.allow) {
        return PolicyDecision::Allowed;
    }

    // If allow list exists but license didn't match, it needs review
    PolicyDecision::NeedsReview
}

/// Evaluate a single license expression against the policy
fn evaluate_expression(expr: &LicenseExpression, config: &LicensePolicyConfig) -> PolicyDecision {
    let Ok(parsed) = spdx::Expression::parse_mode(&expr.expression, spdx::ParseMode::LAX) else {
        return evaluate_license_id(&expr.expression, config);
    };

    // Denied iff the expression cannot be satisfied while avoiding denied
    // operands (OR alternatives are the licensee's choice)
    if !parsed.evaluate(|req| !matches_any(&req_license_id(req), &config.deny)) {
        return PolicyDecision::Denied;
    }

    if config.allow.is_empty() {
        let clean = parsed.evaluate(|req| {
            let id = req_license_id(req);
            !matches_any(&id, &config.deny) && !matches_any(&id, &config.review)
        });
        if clean {
            PolicyDecision::Unspecified
        } else {
            PolicyDecision::NeedsReview
        }
    } else {
        let allowed = parsed.evaluate(|req| {
            let id = req_license_id(req);
            !matches_any(&id, &config.deny) && matches_any(&id, &config.allow)
        });
        if allowed {
            PolicyDecision::Allowed
        } else {
            PolicyDecision::NeedsReview
        }
    }
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

        for license in comp.licenses.all_licenses() {
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

        // Copyleft/proprietary conflicts deny the component, counted at most once
        if config.fail_on_conflict && comp.licenses.has_conflicts() {
            component_denied = true;
            let license_str = comp
                .licenses
                .all_licenses()
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

        if component_denied {
            denied_count += 1;
        } else if component_review {
            review_count += 1;
        } else {
            allowed_count += 1;
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

    fn make_sbom_with_component(declared: &[&str], concluded: Option<&str>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        let mut comp = Component::new("comp-0".to_string(), "id-0".to_string());
        for lic in declared {
            comp.licenses
                .add_declared(LicenseExpression::new((*lic).to_string()));
        }
        comp.licenses.concluded = concluded.map(|c| LicenseExpression::new(c.to_string()));
        sbom.components.insert(comp.canonical_id.clone(), comp);
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
        assert!(matches_pattern("agpl-3.0-only", "AGPL-*")); // case insensitive prefix
        assert!(!matches_pattern("MIT", "BSD-*"));
        assert!(matches_pattern("MIT", "MIT"));
        assert!(matches_pattern("mit", "MIT")); // case insensitive
    }

    #[test]
    fn conflict_fails_policy() {
        let sbom = make_sbom_with_component(&["GPL-3.0-only", "Proprietary"], None);
        let config = LicensePolicyConfig {
            fail_on_conflict: true,
            ..Default::default()
        };
        let result = evaluate_license_policy(&sbom, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
        assert!(result.violations.iter().any(|v| {
            v.license.starts_with("CONFLICT:") && v.decision == PolicyDecision::Denied
        }));
    }

    #[test]
    fn fail_on_conflict_false_skips() {
        let sbom = make_sbom_with_component(&["GPL-3.0-only", "Proprietary"], None);
        let config = LicensePolicyConfig {
            fail_on_conflict: false,
            ..Default::default()
        };
        let result = evaluate_license_policy(&sbom, &config);
        assert!(result.passed);
        assert_eq!(result.denied_count, 0);
    }

    #[test]
    fn concluded_only_license_evaluated() {
        let sbom = make_sbom_with_component(&[], Some("AGPL-3.0-only"));
        let config = LicensePolicyConfig::strict_permissive();
        let result = evaluate_license_policy(&sbom, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
        assert_eq!(result.undeclared_count, 0);
    }

    #[test]
    fn or_expression_denied_only_if_all_alternatives_denied() {
        let config = LicensePolicyConfig {
            deny: vec!["GPL-*".to_string()],
            ..Default::default()
        };

        let choice = make_sbom_with_component(&["MIT OR GPL-3.0-only"], None);
        let result = evaluate_license_policy(&choice, &config);
        assert!(result.passed);
        assert_eq!(result.denied_count, 0);

        let no_choice = make_sbom_with_component(&["GPL-2.0-only OR GPL-3.0-only"], None);
        let result = evaluate_license_policy(&no_choice, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
    }

    #[test]
    fn and_expression_denied_if_any_operand_denied() {
        let config = LicensePolicyConfig {
            deny: vec!["GPL-*".to_string()],
            ..Default::default()
        };
        let sbom = make_sbom_with_component(&["MIT AND GPL-3.0-only"], None);
        let result = evaluate_license_policy(&sbom, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
    }

    #[test]
    fn or_with_allow_list_chooses_allowed_branch() {
        let config = LicensePolicyConfig {
            allow: vec!["MIT".to_string()],
            review: vec!["GPL-*".to_string()],
            ..Default::default()
        };
        let sbom = make_sbom_with_component(&["MIT OR GPL-3.0-only"], None);
        let result = evaluate_license_policy(&sbom, &config);
        assert!(result.passed);
        assert_eq!(result.allowed_count, 1);
        assert_eq!(result.review_count, 0);
    }

    #[test]
    fn with_exception_matches_base_id() {
        let sbom = make_sbom_with_component(&["Apache-2.0 WITH LLVM-exception"], None);

        let allow_config = LicensePolicyConfig {
            allow: vec!["Apache-2.0".to_string()],
            ..Default::default()
        };
        let result = evaluate_license_policy(&sbom, &allow_config);
        assert_eq!(result.allowed_count, 1);

        let deny_config = LicensePolicyConfig {
            deny: vec!["Apache-2.0".to_string()],
            ..Default::default()
        };
        let result = evaluate_license_policy(&sbom, &deny_config);
        assert_eq!(result.denied_count, 1);
    }

    #[test]
    fn non_spdx_falls_back_to_string_match() {
        let config = LicensePolicyConfig {
            deny: vec!["Commercial*".to_string()],
            ..Default::default()
        };
        let sbom = make_sbom_with_component(&["Commercial EULA v2"], None);
        let result = evaluate_license_policy(&sbom, &config);
        assert!(!result.passed);
        assert_eq!(result.denied_count, 1);
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
