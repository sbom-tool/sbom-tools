//! Integration tests for the EU AI Act Annex IV technical-documentation
//! readiness profile (`ComplianceLevel::EuAiAct`, SBOM-AIACT-* rules).
//!
//! Frames the profile as a documentation-READINESS assessment, not a
//! legal-conformity guarantee: a fully documented AI-BOM passes, a non-AI SBOM
//! is N/A (never fails), the high-risk sidecar flag escalates severity, and the
//! SARIF output carries SBOM-AIACT-* rules.

use std::path::Path;

use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ViolationSeverity};
use sbom_tools::reports::generate_compliance_sarif;

fn fixture(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

#[test]
fn fully_documented_aibom_passes_annex_iv_readiness() {
    let sbom = parse_sbom(&fixture("cyclonedx/aibom-complete.cdx.json"))
        .expect("parse aibom-complete fixture");
    let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        result.is_compliant,
        "fully documented AI-BOM should be Annex IV ready; violations: {:?}",
        result.violations
    );
    assert_eq!(
        result.warning_count, 0,
        "no §1/§2(d)/§2(g)/§3 readiness warnings expected; got {:?}",
        result.violations
    );
    // It is an AI SBOM, so it must NOT report the not-applicable finding.
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-NA"),
        "AI SBOM must not be marked not-applicable"
    );
}

#[test]
fn non_ai_sbom_is_not_applicable_and_does_not_fail() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal.cdx.json")).expect("parse minimal fixture");
    let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(result.is_compliant, "non-AI SBOM must not fail AI-Act");
    assert_eq!(result.error_count, 0);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-NA" && v.severity == ViolationSeverity::Info),
        "non-AI SBOM should report a single informational N/A finding"
    );
}

#[test]
fn high_risk_flag_escalates_to_errors() {
    // minimal-mlbom has model components but is missing several Annex IV items,
    // so it produces readiness gaps to escalate.
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");

    let baseline = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
    assert!(
        baseline.warning_count > 0,
        "minimal mlbom should have readiness gaps to escalate"
    );

    let sidecar = CraSidecarMetadata {
        is_high_risk_ai: true,
        ..Default::default()
    };
    let escalated = ComplianceChecker::new(ComplianceLevel::EuAiAct)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !escalated.is_compliant && escalated.error_count > 0,
        "high-risk AI SBOM with Annex IV gaps must fail with errors"
    );
}

#[test]
fn compliance_sarif_emits_aiact_rules() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");
    let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("generate SARIF");
    let value: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF JSON");

    // At least one result must carry an SBOM-AIACT-* rule id.
    let result_rule_ids: Vec<String> = value["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        result_rule_ids
            .iter()
            .any(|id| id.starts_with("SBOM-AIACT-")),
        "expected an SBOM-AIACT-* result; got {result_rule_ids:?}"
    );
}
