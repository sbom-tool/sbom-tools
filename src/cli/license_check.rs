//! CLI handler for the `license-check` command.
//!
//! Evaluates license policy compliance and dependency propagation risks.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::license::{
    LicensePolicyConfig, PolicyDecision, check_license_propagation, evaluate_license_policy,
};
use crate::parsers::parse_sbom;
use crate::pipeline::exit_codes;

/// Run the license-check command.
pub fn run_license_check(
    file: &Path,
    policy_file: Option<&PathBuf>,
    check_propagation: bool,
    strict: bool,
    format: &str,
    quiet: bool,
) -> Result<i32> {
    let sbom = parse_sbom(file)?;

    let config = if let Some(pf) = policy_file {
        let content = std::fs::read_to_string(pf)?;
        serde_json::from_str(&content)?
    } else if strict {
        LicensePolicyConfig::strict_permissive()
    } else {
        LicensePolicyConfig::permissive()
    };

    let result = evaluate_license_policy(&sbom, &config);

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
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
                println!(
                    "  {label:>10}  {} {} — {}",
                    v.component,
                    v.version.as_deref().unwrap_or(""),
                    v.license,
                );
            }
        }
    }

    // Check propagation risks if requested
    if check_propagation {
        let conflicts = check_license_propagation(&sbom);
        if !conflicts.is_empty() && !quiet {
            println!("\nLicense Propagation Risks:");
            for c in &conflicts {
                println!("  {} → {} : {}", c.component, c.dependency, c.reason);
                if !c.path.is_empty() {
                    println!("    path: {}", c.path.join(" → "));
                }
            }
        }
    }

    if result.denied_count > 0 {
        Ok(exit_codes::LICENSE_VIOLATIONS)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}
