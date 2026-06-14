//! Integration tests for the BSI/G7 "SBOM for AI — Minimum Elements" (Feb 2026)
//! minimum-elements readiness profile (`ComplianceLevel::BsiSbomForAi`,
//! SBOM-BSIAI-* rules).
//!
//! Frames the profile as a minimum-elements READINESS assessment, not a
//! legal-conformity guarantee: a well-documented AI-BOM passes the Models /
//! Datasets element checks, a non-AI SBOM is N/A (never fails), a sparse
//! AI-BOM fails specific element checks with the right rule_ids / cluster refs,
//! the `validate --standard bsi-ai` CLI path works, and the SARIF output
//! carries SBOM-BSIAI-* rules.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, StandardKind, ViolationSeverity};
use sbom_tools::reports::generate_compliance_sarif;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(rel: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(rel)
}

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be utf-8")
}

#[test]
fn well_documented_aibom_passes_models_and_datasets_element_checks() {
    let sbom = parse_sbom(&fixture("cyclonedx/bsi-aibom-complete.cdx.json"))
        .expect("parse bsi-aibom-complete fixture");
    let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(
        result.is_compliant,
        "well-documented AI-BOM should pass all MUST element checks; errors: {:?}",
        result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .collect::<Vec<_>>()
    );

    // None of the Models / Datasets MUST element checks should fire.
    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    for must in [
        "SBOM-BSIAI-MODEL-NAME",
        "SBOM-BSIAI-MODEL-VERSION",
        "SBOM-BSIAI-MODEL-IDENTIFIER",
        "SBOM-BSIAI-MODEL-HASH",
        "SBOM-BSIAI-MODEL-HASH-ALGO",
        "SBOM-BSIAI-MODEL-CARD",
        "SBOM-BSIAI-MODEL-ARCHITECTURE",
        "SBOM-BSIAI-MODEL-DATASETS",
        "SBOM-BSIAI-MODEL-LIMITATIONS",
        "SBOM-BSIAI-MODEL-LICENSE",
        "SBOM-BSIAI-DATASET-NAME",
        "SBOM-BSIAI-DATASET-IDENTIFIER",
        "SBOM-BSIAI-DATASET-HASH",
        "SBOM-BSIAI-DATASET-LICENSE",
        "SBOM-BSIAI-DATASET-SENSITIVITY",
        "SBOM-BSIAI-DATASET-PROVENANCE",
    ] {
        assert!(
            !ids.contains(&must),
            "well-documented AI-BOM unexpectedly flagged {must}; violations: {:?}",
            result.violations
        );
    }

    // It is an AI SBOM, so it must NOT report the not-applicable finding.
    assert!(
        !ids.contains(&"SBOM-BSIAI-NA"),
        "AI SBOM must not be marked not-applicable"
    );
}

#[test]
fn non_ai_sbom_is_not_applicable_and_does_not_fail() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal.cdx.json")).expect("parse minimal fixture");
    let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(result.is_compliant, "non-AI SBOM must not fail BSI-AI");
    assert_eq!(result.error_count, 0);
    assert_eq!(
        result.violations.len(),
        1,
        "non-AI SBOM should produce exactly one informational N/A finding; got {:?}",
        result.violations
    );
    let v = &result.violations[0];
    assert_eq!(v.rule_id, "SBOM-BSIAI-NA");
    assert_eq!(v.severity, ViolationSeverity::Info);
}

#[test]
fn sparse_aibom_fails_specific_element_checks_with_cluster_refs() {
    // minimal-mlbom has model components with no PURL, hash, license, model
    // card, architecture, or limitations — so the corresponding MUST/SHOULD
    // element checks must fire.
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");
    let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);

    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    for expected in [
        "SBOM-BSIAI-MODEL-IDENTIFIER",
        "SBOM-BSIAI-MODEL-HASH",
        "SBOM-BSIAI-MODEL-CARD",
        "SBOM-BSIAI-MODEL-LICENSE",
    ] {
        assert!(
            ids.contains(&expected),
            "sparse AI-BOM should flag {expected}; got {ids:?}"
        );
    }

    // MUST gaps (e.g. missing identifier / weight hash) make it non-compliant.
    assert!(
        !result.is_compliant,
        "sparse AI-BOM with MUST gaps must fail"
    );

    // The Models-cluster findings must carry a BSI/G7 SBOM-for-AI standard
    // reference whose id names the cluster + element.
    let model_hash = result
        .violations
        .iter()
        .find(|v| v.rule_id == "SBOM-BSIAI-MODEL-HASH")
        .expect("model-hash finding present");
    assert!(
        model_hash
            .standard_refs
            .iter()
            .any(|r| r.standard == StandardKind::BsiSbomForAi
                && r.id.contains("Models")
                && r.id.contains("hash")),
        "model-hash finding should reference the Models / Model hash element; got {:?}",
        model_hash.standard_refs
    );
}

#[test]
fn compliance_sarif_emits_bsiai_rules() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");
    let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("generate SARIF");
    let value: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF JSON");

    // At least one result must carry an SBOM-BSIAI-* rule id.
    let result_rule_ids: Vec<String> = value["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        result_rule_ids
            .iter()
            .any(|id| id.starts_with("SBOM-BSIAI-")),
        "expected an SBOM-BSIAI-* result; got {result_rule_ids:?}"
    );

    // The rule catalogue must register the BSI-AI rules too.
    let catalogue_rule_ids: Vec<String> = value["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        catalogue_rule_ids
            .iter()
            .any(|id| id.starts_with("SBOM-BSIAI-")),
        "rule catalogue should list SBOM-BSIAI-* rules; got {catalogue_rule_ids:?}"
    );
}

#[test]
fn cli_validate_standard_bsi_ai_runs() {
    // A sparse AI-BOM has MUST gaps → exit code 1 (compliance errors).
    let output = base_command()
        .arg("validate")
        .arg(fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .args(["--standard", "bsi-ai", "--summary"])
        .output()
        .expect("validate --standard bsi-ai should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "sparse AI-BOM should fail bsi-ai with exit code 1; stderr: {}",
        stderr(&output)
    );
    // Summary JSON should name the BSI/G7 SBOM-for-AI readiness profile.
    let out = stdout(&output);
    assert!(
        out.contains("BSI/G7 SBOM-for-AI"),
        "summary should name the BSI/G7 SBOM-for-AI profile; got: {out}"
    );
}

#[test]
fn cli_validate_standard_bsi_ai_sarif_emits_rules() {
    let output = base_command()
        .arg("validate")
        .arg(fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .args(["--standard", "bsi-ai", "-o", "sarif"])
        .output()
        .expect("validate --standard bsi-ai -o sarif should run");

    let out = stdout(&output);
    let start = out.find('{').expect("sarif JSON object on stdout");
    let value: serde_json::Value =
        serde_json::from_str(&out[start..]).expect("stdout payload should be valid SARIF JSON");
    let result_rule_ids: Vec<String> = value["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        result_rule_ids
            .iter()
            .any(|id| id.starts_with("SBOM-BSIAI-")),
        "CLI SARIF output should carry SBOM-BSIAI-* results; got {result_rule_ids:?}"
    );
}
