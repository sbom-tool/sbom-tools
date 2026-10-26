//! Integration tests for the EU AI Act Annex IV technical-documentation
//! readiness profile (`ComplianceLevel::EuAiAct`, SBOM-AIACT-* rules).
//!
//! Frames the profile as a documentation-READINESS assessment, not a
//! legal-conformity guarantee: a fully documented AI-BOM passes, a non-AI SBOM
//! is N/A (never fails), the high-risk sidecar flag escalates severity, and the
//! SARIF output carries SBOM-AIACT-* rules.

#[path = "common/clock.rs"]
mod clock;

use std::path::Path;

use clock::checker;
use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{Applicability, ComplianceLevel, ViolationSeverity};
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
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

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
        result.is_applicable(),
        "AI SBOM must not be marked not-applicable"
    );
}

#[test]
fn non_ai_sbom_is_not_applicable_and_does_not_fail() {
    let sbom = parse_sbom(&fixture("cyclonedx/minimal.cdx.json")).expect("parse minimal fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(result.is_compliant, "non-AI SBOM must not fail AI-Act");
    assert!(
        matches!(result.applicability, Applicability::NotApplicable(_)),
        "a non-AI SBOM is not applicable"
    );
    assert!(
        result.violations.is_empty(),
        "N/A is the result's applicability, not a finding: {:?}",
        result.violations
    );
}

#[test]
fn web_app_with_config_data_component_is_not_applicable() {
    // A `type: data` config bundle carries no dataset evidence and must not
    // make the profile applicable (previously every Data component counted
    // as an AI training dataset).
    let sbom = parse_sbom(&fixture("cyclonedx/webapp-data-config.cdx.json"))
        .expect("parse webapp-data-config fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(result.is_compliant, "web-app SBOM must not fail AI-Act");
    assert!(!result.is_applicable(), "a config bundle is no AI content");
    assert!(
        result.violations.is_empty(),
        "no finding expected; got {:?}",
        result.violations
    );
}

#[test]
fn application_typed_component_with_model_card_is_applicable() {
    // The parser sets ml_model from the modelCard regardless of the declared
    // component type; the profile must see it (previously "Not applicable").
    let sbom = parse_sbom(&fixture("cyclonedx/mistyped-mlbom.cdx.json"))
        .expect("parse mistyped-mlbom fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        result.is_applicable(),
        "SBOM with modelCard metadata must not be N/A; got {:?}",
        result.violations
    );
    // The Annex IV model checks actually ran (no training datasets declared).
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-2D-DATASETS"),
        "Annex IV checks should run against the mistyped model; got {:?}",
        result.violations
    );
}

#[test]
fn model_card_external_ref_and_description_satisfy_general_description() {
    // A machine-learning-model documented via description + a `model-card`
    // external reference (no modelCard object) must not be flagged as
    // lacking a general description.
    let sbom = parse_sbom(&fixture("cyclonedx/mlbom-extref-card.cdx.json"))
        .expect("parse mlbom-extref-card fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION"),
        "description + model-card reference must satisfy Annex IV §1; got {:?}",
        result.violations
    );
}

#[test]
fn untyped_huggingface_model_is_applicable_with_mistyped_ml_warning() {
    // Evasion guard: a pkg:huggingface component typed `library` (no
    // modelCard) keeps the profile applicable and is surfaced.
    let sbom = parse_sbom(&fixture("cyclonedx/untyped-hf-model.cdx.json"))
        .expect("parse untyped-hf-model fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        result.is_applicable(),
        "huggingface PURL must keep the profile applicable; got {:?}",
        result.violations
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-UNTYPED-ML"
                && v.severity == ViolationSeverity::Warning),
        "mistyped-ML warning should fire; got {:?}",
        result.violations
    );
}

#[test]
fn dataset_only_sbom_is_applicable_without_model_energy_info() {
    // Data components WITH dataset evidence still count (no regression), and
    // the model-energy recommendation must not fire with zero ML models.
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-dataset.cdx.json"))
        .expect("parse minimal-dataset fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        result.is_applicable(),
        "dataset evidence keeps the profile applicable; got {:?}",
        result.violations
    );
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-2C-ENERGY"),
        "energy Info must not fire on an SBOM with no ML models; got {:?}",
        result.violations
    );
}

#[test]
fn xml_dataset_evidence_reaches_annex_iv_dataset_checks() {
    // Regression: the CycloneDX XML converter dropped `<data>` componentData,
    // so the Annex IV §2(d) dataset checks were silently skipped for XML
    // AI-BOMs. The XML dataset (no sensitivity classification declared) must
    // now be assessed like its JSON twin.
    let sbom = parse_sbom(&fixture("cyclonedx/aibom-dataset-gap.cdx.xml"))
        .expect("parse aibom-dataset-gap XML fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY"
                && v.message.contains("training-corpus")),
        "the XML dataset without sensitivity classification must be flagged; got {:?}",
        result.violations
    );
}

#[test]
fn huggingface_dataset_with_evidence_is_not_flagged_as_untyped_ml() {
    // A HuggingFace-hosted DATASET with full componentData evidence is
    // correctly classified; the untyped-ML heuristic (which also matches
    // pkg:huggingface) must stay silent instead of prescribing that a correct
    // dataset be retyped as machine-learning-model.
    let sbom = parse_sbom(&fixture("cyclonedx/hf-dataset-aibom.cdx.json"))
        .expect("parse hf-dataset-aibom fixture");
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);

    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-AIACT-UNTYPED-ML"),
        "dataset evidence must exempt the HF dataset from the untyped-ML warning; got {:?}",
        result.violations
    );
    assert!(
        result.is_applicable(),
        "the HF dataset must keep the profile applicable; got {:?}",
        result.violations
    );
}

#[test]
fn high_risk_flag_escalates_to_errors() {
    // minimal-mlbom has model components but is missing several Annex IV items,
    // so it produces readiness gaps to escalate.
    let sbom = parse_sbom(&fixture("cyclonedx/minimal-mlbom.cdx.json"))
        .expect("parse minimal-mlbom fixture");

    let baseline = checker(ComplianceLevel::EuAiAct).check(&sbom);
    assert!(
        baseline.warning_count > 0,
        "minimal mlbom should have readiness gaps to escalate"
    );

    let sidecar = CraSidecarMetadata {
        is_high_risk_ai: true,
        ..Default::default()
    };
    let escalated = checker(ComplianceLevel::EuAiAct)
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
    let result = checker(ComplianceLevel::EuAiAct).check(&sbom);
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
