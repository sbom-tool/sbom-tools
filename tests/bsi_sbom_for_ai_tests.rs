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

#[path = "common/clock.rs"]
mod clock;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use clock::checker;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceLevel, StandardKind, ViolationSeverity};
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
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

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

    // It is an AI SBOM, so it must NOT be marked not applicable.
    assert!(
        result.is_applicable(),
        "AI SBOM must not be marked not-applicable"
    );
}

#[test]
fn non_ai_sbom_is_not_applicable_and_does_not_fail() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal.cdx.json")).expect("parse minimal fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(result.is_compliant, "non-AI SBOM must not fail BSI-AI");
    assert!(!result.is_applicable(), "a non-AI SBOM is not applicable");
    assert!(
        result.violations.is_empty(),
        "N/A is the result's applicability, not a finding: {:?}",
        result.violations
    );
}

#[test]
fn web_app_with_config_data_component_is_not_applicable() {
    // Flagship over-match fix: a web-app SBOM with one library and one
    // `type: data` config bundle (no dataset evidence) previously failed
    // BSI-AI with a blocking SBOM-BSIAI-DATASET-IDENTIFIER Error. It must be
    // N/A and compliant.
    let sbom = parse_sbom(&fixture("cyclonedx/webapp-data-config.cdx.json"))
        .expect("parse webapp-data-config fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(
        result.is_compliant,
        "web-app SBOM must not fail BSI-AI; violations: {:?}",
        result.violations
    );
    assert!(!result.is_applicable(), "a config bundle is no AI content");
    assert!(
        result.violations.is_empty(),
        "no finding expected; got {:?}",
        result.violations
    );
}

#[test]
fn cli_validate_bsi_ai_passes_web_app_with_config_data() {
    // End-to-end guard for the same fix: `validate --standard bsi-ai` on the
    // web-app SBOM must exit 0 (previously exit 1, NON-COMPLIANT).
    let output = base_command()
        .arg("validate")
        .arg(fixture("cyclonedx/webapp-data-config.cdx.json"))
        .args(["--standard", "bsi-ai", "--summary"])
        .output()
        .expect("validate --standard bsi-ai should run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "web-app SBOM must pass bsi-ai; stdout: {} stderr: {}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn application_typed_component_with_model_card_is_applicable() {
    // The parser sets ml_model from the modelCard regardless of the declared
    // component type; the Models cluster must see it (previously N/A).
    let sbom = parse_sbom(&fixture("cyclonedx/mistyped-mlbom.cdx.json"))
        .expect("parse mistyped-mlbom fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    assert!(
        result.is_applicable(),
        "SBOM with modelCard metadata must not be N/A; got {ids:?}"
    );
    // The Models element checks ran (no PURL/hash on the mistyped model).
    assert!(
        ids.contains(&"SBOM-BSIAI-MODEL-IDENTIFIER"),
        "Models cluster should run on the mistyped model; got {ids:?}"
    );
}

#[test]
fn model_card_external_ref_satisfies_model_card_element() {
    // A machine-learning-model documented via a `model-card` external
    // reference alone (no modelCard object) must not be flagged as missing
    // its model card.
    let sbom = parse_sbom(&fixture("cyclonedx/mlbom-extref-card.cdx.json"))
        .expect("parse mlbom-extref-card fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSIAI-MODEL-CARD"),
        "model-card external reference must satisfy the model-card element; got {:?}",
        result.violations
    );
}

#[test]
fn untyped_huggingface_model_is_applicable_with_mistyped_ml_warning() {
    // Evasion guard: a pkg:huggingface component typed `library` (no
    // modelCard) keeps the profile applicable and is surfaced.
    let sbom = parse_sbom(&fixture("cyclonedx/untyped-hf-model.cdx.json"))
        .expect("parse untyped-hf-model fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(
        result.is_applicable(),
        "huggingface PURL must keep the profile applicable; got {:?}",
        result.violations
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSIAI-UNTYPED-ML"
                && v.severity == ViolationSeverity::Warning),
        "mistyped-ML warning should fire; got {:?}",
        result.violations
    );
}

#[test]
fn dataset_component_with_dataset_evidence_still_counts() {
    // Data components WITH dataset structs must keep enrolling (no
    // regression from requiring dataset evidence).
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-dataset.cdx.json"))
        .expect("parse minimal-dataset fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    assert!(
        result.is_applicable(),
        "dataset evidence keeps the profile applicable; got {:?}",
        result.violations
    );
}

#[test]
fn xml_dataset_evidence_reaches_the_datasets_cluster() {
    // Regression: the CycloneDX XML converter hardcoded `data_components:
    // Vec::new()`, so `dataset.is_some()` never held for XML AI-BOMs and the
    // entire Datasets cluster — including the MUST-level identifier check —
    // was silently skipped (format-dependent false pass). A spec-valid
    // `<data>` element must now enroll the component like its JSON twin.
    let sbom = parse_sbom(&fixture("cyclonedx/aibom-dataset-gap.cdx.xml"))
        .expect("parse aibom-dataset-gap XML fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    assert!(
        ids.contains(&"SBOM-BSIAI-DATASET-IDENTIFIER"),
        "identifier-less XML dataset must fail the MUST identifier element; got {ids:?}"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSIAI-DATASET-IDENTIFIER"
                && v.severity == ViolationSeverity::Error
                && v.message.contains("training-corpus")),
        "the dataset identifier Error should name the XML dataset; got {:?}",
        result.violations
    );
    assert!(
        !result.is_compliant,
        "an XML AI-BOM with a MUST dataset gap must be non-compliant, matching the JSON path"
    );
}

#[test]
fn xml_documented_dataset_passes_datasets_cluster() {
    // Silent counterpart: a fully documented XML dataset (identifier, hash,
    // license, sensitivity, governance) must satisfy every Datasets element,
    // and dataset evidence alone must keep the XML SBOM applicable.
    let sbom = parse_sbom(&fixture("cyclonedx/aibom-dataset-complete.cdx.xml"))
        .expect("parse aibom-dataset-complete XML fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    assert!(
        result.is_applicable(),
        "XML dataset evidence must keep the profile applicable; got {ids:?}"
    );
    for rule in [
        "SBOM-BSIAI-DATASET-NAME",
        "SBOM-BSIAI-DATASET-IDENTIFIER",
        "SBOM-BSIAI-DATASET-HASH",
        "SBOM-BSIAI-DATASET-LICENSE",
        "SBOM-BSIAI-DATASET-SENSITIVITY",
        "SBOM-BSIAI-DATASET-PROVENANCE",
    ] {
        assert!(
            !ids.contains(&rule),
            "documented XML dataset unexpectedly flagged {rule}; got {:?}",
            result.violations
        );
    }
}

#[test]
fn huggingface_dataset_with_evidence_is_not_flagged_as_untyped_ml() {
    // A HuggingFace-hosted DATASET — typed `data`, full componentData
    // evidence — is legitimate, fully classified AI-BOM content. The
    // untyped-ML evasion heuristic (which also matches pkg:huggingface) must
    // not warn on it: the warning would be false and prescribe retyping a
    // correct dataset as machine-learning-model.
    let sbom = parse_sbom(&fixture("cyclonedx/hf-dataset-aibom.cdx.json"))
        .expect("parse hf-dataset-aibom fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

    let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
    assert!(
        !ids.contains(&"SBOM-BSIAI-UNTYPED-ML"),
        "dataset evidence must exempt the HF dataset from the untyped-ML warning; got {:?}",
        result.violations
    );
    // It stays enrolled as a dataset (profile applicable, no N/A).
    assert!(
        result.is_applicable(),
        "the HF dataset must keep the profile applicable; got {ids:?}"
    );
}

#[test]
fn sparse_aibom_fails_specific_element_checks_with_cluster_refs() {
    // minimal-mlbom has model components with no PURL, hash, license, model
    // card, architecture, or limitations — so the corresponding MUST/SHOULD
    // element checks must fire.
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);

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
    let result = checker(ComplianceLevel::BsiSbomForAi).check(&sbom);
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
