//! CLI handler for the `license-check` command.
//!
//! Evaluates license policy compliance and dependency propagation risks.
//!
//! Exit codes: 0 = policy passed, 5 = policy violations (denied licenses,
//! review-needed licenses under `--strict`, or propagation conflicts under
//! `--check-propagation`). Operational errors (unreadable SBOM, invalid
//! policy file, …) surface as `Err` and are routed to exit code 3 in `main`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::license::{
    LicenseConflict, LicensePolicyConfig, LicensePolicyResult, PolicyDecision,
    check_license_propagation, evaluate_license_policy,
};
use crate::pipeline::exit_codes;
use crate::reports::escape::sanitize_line;

/// Run the license-check command.
pub fn run_license_check(
    file: &Path,
    policy_file: Option<&PathBuf>,
    check_propagation: bool,
    strict: bool,
    format: &str,
    quiet: bool,
) -> Result<i32> {
    // Same parse path as validate/quality: supports `-` for stdin and adds
    // file context to parse errors.
    let sbom = crate::pipeline::parse_sbom_with_context(file, quiet)?.into_sbom();

    let config = if let Some(pf) = policy_file {
        let content = std::fs::read_to_string(pf)
            .with_context(|| format!("failed to read license policy file {}", pf.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("invalid license policy file {}", pf.display()))?
    } else if strict {
        LicensePolicyConfig::strict_permissive()
    } else {
        LicensePolicyConfig::permissive()
    };

    let result = evaluate_license_policy(&sbom, &config, strict);

    // Compute propagation conflicts up front so both output formats and the
    // exit code see them.
    let conflicts = if check_propagation {
        Some(check_license_propagation(&sbom))
    } else {
        None
    };

    if format == "json" {
        let doc = build_json_report(&result, conflicts.as_deref())?;
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else if !quiet {
        println!("License Policy Check");
        println!("====================");
        println!(
            "Total: {}  Allowed: {}  Denied: {}  Review: {}  Undeclared: {}",
            result.total_components,
            result.allowed_count,
            result.denied_count,
            result.review_count,
            result.undeclared_count,
        );

        let has_issues =
            result.denied_count > 0 || result.review_count > 0 || result.undeclared_count > 0;

        if has_issues {
            println!("\nViolations:");
            for v in &result.violations {
                let label = match v.decision {
                    PolicyDecision::Denied => "DENIED",
                    PolicyDecision::NeedsReview => "REVIEW",
                    PolicyDecision::Undeclared => "UNDECLARED",
                    _ => "INFO",
                };
                // SBOM text is sanitized: a line break or a leading `:` must
                // not let a component name start an output line.
                println!(
                    "  {label:>10}  {} {} — {}",
                    sanitize_line(&v.component),
                    sanitize_line(v.version.as_deref().unwrap_or("")),
                    sanitize_line(&v.license),
                );
            }
        }

        if let Some(conflicts) = conflicts.as_deref()
            && !conflicts.is_empty()
        {
            println!("\nLicense Propagation Risks:");
            for c in conflicts {
                println!(
                    "  {} → {} : {}",
                    sanitize_line(&c.component),
                    sanitize_line(&c.dependency),
                    sanitize_line(&c.reason)
                );
                if !c.path.is_empty() {
                    let path: Vec<_> = c.path.iter().map(|p| sanitize_line(p)).collect();
                    println!("    path: {}", path.join(" → "));
                }
            }
        }
    }

    let propagation_violations = conflicts.as_deref().is_some_and(|c| !c.is_empty());

    if result.denied_count > 0 || propagation_violations {
        Ok(exit_codes::LICENSE_VIOLATIONS)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Build the JSON report document: the policy result, plus a
/// `propagation_conflicts` array when `--check-propagation` was requested.
/// Everything lives inside the single JSON document so stdout stays
/// machine-parseable.
fn build_json_report(
    result: &LicensePolicyResult,
    conflicts: Option<&[LicenseConflict]>,
) -> Result<serde_json::Value> {
    let mut doc = serde_json::to_value(result)?;
    if let Some(conflicts) = conflicts {
        doc.as_object_mut()
            .expect("LicensePolicyResult serializes to a JSON object")
            .insert(
                "propagation_conflicts".to_string(),
                serde_json::to_value(conflicts)?,
            );
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LicenseFamily;

    fn empty_result() -> LicensePolicyResult {
        LicensePolicyResult {
            total_components: 0,
            allowed_count: 0,
            denied_count: 0,
            review_count: 0,
            undeclared_count: 0,
            passed: true,
            violations: Vec::new(),
        }
    }

    #[test]
    fn json_report_without_propagation_has_no_conflicts_key() {
        let doc = build_json_report(&empty_result(), None).unwrap();
        assert!(doc.get("propagation_conflicts").is_none());
        assert!(doc.get("passed").is_some());
    }

    #[test]
    fn json_report_embeds_propagation_conflicts() {
        let conflicts = vec![LicenseConflict {
            component: "app".to_string(),
            component_family: LicenseFamily::Permissive,
            dependency: "copyleft-dep".to_string(),
            dependency_family: LicenseFamily::Copyleft,
            path: vec!["app".to_string(), "copyleft-dep".to_string()],
            reason: "strong copyleft under permissive".to_string(),
        }];
        let doc = build_json_report(&empty_result(), Some(&conflicts)).unwrap();
        let arr = doc
            .get("propagation_conflicts")
            .and_then(|v| v.as_array())
            .expect("propagation_conflicts must be an array inside the document");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["component"], "app");
    }

    #[test]
    fn json_report_empty_conflicts_is_empty_array() {
        let doc = build_json_report(&empty_result(), Some(&[])).unwrap();
        assert_eq!(
            doc.get("propagation_conflicts"),
            Some(&serde_json::json!([]))
        );
    }
}
