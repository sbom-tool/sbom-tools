//! Integration tests for the SBOM-AIBOM-* SARIF rule family (#185).
//!
//! Builds ML BOM components via the public API, scores them with the
//! AI-readiness profile, and renders SARIF via `generate_ai_readiness_sarif`.
//!
//! Note: `MlModelInfo` is `#[non_exhaustive]`, so an external crate cannot use
//! struct-literal construction — these tests use `Default::default()` plus public
//! field assignment. `DatasetRef` is `#[non_exhaustive]` with no `Default`, so it
//! is not constructible here; AI-003 (training datasets) is therefore exercised as
//! the single documentation gap rather than populated.

use sbom_tools::model::{Component, ComponentType, DocumentMetadata, MlModelInfo, NormalizedSbom};
use sbom_tools::quality::{QualityScorer, ScoringProfile};
use sbom_tools::reports::generate_ai_readiness_sarif;

fn render_sarif(sbom: &NormalizedSbom) -> serde_json::Value {
    let report = QualityScorer::new(ScoringProfile::AiReadiness).score(sbom);
    let metrics = report
        .ai_readiness_metrics
        .as_ref()
        .expect("AI readiness metrics");
    let na = metrics.is_not_applicable();
    let out = generate_ai_readiness_sarif(
        metrics,
        "model.cdx.json",
        "ai-readiness",
        if na { None } else { Some(report.overall_score) },
        if na { "N/A" } else { report.grade.letter() },
    )
    .expect("SARIF generation");
    serde_json::from_str(&out).expect("valid SARIF JSON")
}

/// A `MachineLearningModel` component whose `MlModelInfo` is built via the given
/// closure (Default + field assignment, since the type is `#[non_exhaustive]`).
fn ml_component(configure: impl FnOnce(&mut MlModelInfo, &mut Component)) -> Component {
    let mut component = Component::new("bert-base".to_string(), "ml-1".to_string())
        .with_version("1.0.0".to_string());
    component.component_type = ComponentType::MachineLearningModel;
    let mut ml = MlModelInfo::default();
    configure(&mut ml, &mut component);
    component.ml_model = Some(ml);
    component
}

fn rule_ids(value: &serde_json::Value) -> Vec<String> {
    value["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn result_rule_ids(value: &serde_json::Value) -> Vec<String> {
    value["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn aibom_rule_table_is_complete_with_help_uris() {
    let value = render_sarif(&NormalizedSbom::new(DocumentMetadata::default()));
    let ids = rule_ids(&value);
    for n in 1..=11 {
        assert!(
            ids.contains(&format!("SBOM-AIBOM-{n:03}")),
            "missing SBOM-AIBOM-{n:03}"
        );
    }
    assert!(ids.contains(&"SBOM-AIBOM-GENERAL".to_string()));

    for rule in value["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            rule["helpUri"],
            serde_json::json!("https://cyclonedx.org/capabilities/mlbom/"),
            "rule {} missing helpUri",
            rule["id"]
        );
    }
}

#[test]
fn aibom_not_applicable_emits_table_no_results() {
    // No ML components → not applicable: rule table present, zero findings.
    let value = render_sarif(&NormalizedSbom::new(DocumentMetadata::default()));
    let run = &value["runs"][0];
    assert_eq!(run["properties"]["applicable"], serde_json::json!(false));
    assert!(run["properties"]["overall_score"].is_null());
    assert_eq!(run["properties"]["grade"], serde_json::json!("N/A"));
    assert!(run["results"].as_array().unwrap().is_empty());
    assert!(!rule_ids(&value).is_empty());
}

#[test]
fn aibom_emits_result_per_failing_check() {
    // A model documenting only the URL + architecture family: AI-001/002 pass,
    // the remaining nine checks (AI-003..AI-011) fail with matching rule IDs.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(ml_component(|ml, _comp| {
        ml.architecture_family = Some("transformer".to_string());
        ml.model_card_url = Some("https://example.test/card".to_string());
    }));

    let value = render_sarif(&sbom);
    assert_eq!(
        value["runs"][0]["properties"]["applicable"],
        serde_json::json!(true)
    );

    let ids = result_rule_ids(&value);
    // AI-001 (URL) and AI-002 (family) pass → no result for them.
    assert!(!ids.contains(&"SBOM-AIBOM-001".to_string()));
    assert!(!ids.contains(&"SBOM-AIBOM-002".to_string()));
    // The remaining nine checks fail (AI-003..AI-011): AI-010 is the weight-hash
    // integrity check (no hashes) and AI-011 the exploitability/advisory-reference
    // check (no vuln or advisory ref on this model).
    for n in 3..=11 {
        assert!(
            ids.contains(&format!("SBOM-AIBOM-{n:03}")),
            "expected a finding for SBOM-AIBOM-{n:03}"
        );
    }

    // A failing result carries level, message, and standard-id properties.
    let datasets = value["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == serde_json::json!("SBOM-AIBOM-003"))
        .expect("AI-003 finding");
    assert_eq!(datasets["level"], serde_json::json!("warning"));
    assert!(
        datasets["message"]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("AI-003")
    );
    assert_eq!(
        datasets["properties"]["standardIds"][0],
        serde_json::json!("AIBOM:AI-003")
    );
}

#[test]
fn aibom_passing_checks_produce_no_result() {
    // Document everything except training datasets (AI-003): the typed checks
    // AI-001/002/006/008, the raw-pointer checks AI-004/005/007/009, the
    // weight-hash integrity check AI-010, and the exploitability-reference check
    // AI-011 all pass, so the ONLY finding is SBOM-AIBOM-003. Confirms passing
    // checks are skipped.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(ml_component(|ml, comp| {
        ml.architecture_family = Some("transformer".to_string());
        ml.model_card_url = Some("https://example.test/card".to_string());
        ml.energy_kwh_training = Some(12.5);
        ml.limitations = Some("English only".to_string());
        // A weight hash satisfies the AI-010 integrity check.
        comp.hashes.push(sbom_tools::model::Hash::new(
            sbom_tools::model::HashAlgorithm::Sha256,
            "c".repeat(64),
        ));
        // A vulnerability reference satisfies the AI-011 exploitability check.
        comp.vulnerabilities
            .push(sbom_tools::model::VulnerabilityRef::new(
                "CVE-2024-9999".to_string(),
                sbom_tools::model::VulnerabilitySource::Cve,
            ));
        comp.extensions.raw = Some(serde_json::json!({
            "mlModel": { "modelCard": {
                "quantitativeAnalysis": { "performanceMetrics": [{ "type": "accuracy", "value": 0.97 }] },
                "considerations": {
                    "fairnessConsiderations": ["Reviewed"],
                    "useCases": ["Classification"],
                    "ethicalConsiderations": ["Human review required"]
                }
            }}
        }));
    }));

    let value = render_sarif(&sbom);
    let ids = result_rule_ids(&value);
    assert_eq!(
        ids,
        vec!["SBOM-AIBOM-003".to_string()],
        "only the training-datasets gap should be reported"
    );
}

#[test]
fn aibom_011_emitted_when_no_exploitability_reference() {
    // A model with no vuln/advisory reference must yield an SBOM-AIBOM-011
    // finding at `warning` level — the BSI exploitability-referencing gap.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(ml_component(|_ml, _comp| {}));

    let value = render_sarif(&sbom);
    let finding = value["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == serde_json::json!("SBOM-AIBOM-011"))
        .expect("SBOM-AIBOM-011 finding for a model lacking an exploitability reference");
    assert_eq!(finding["level"], serde_json::json!("warning"));
    assert!(
        finding["message"]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("AI-011")
    );
}

#[test]
fn aibom_011_satisfied_by_security_advisory_external_ref() {
    // A model carrying a security-advisory external reference satisfies AI-011
    // even without an enriched vulnerability list, so no SBOM-AIBOM-011 finding.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(ml_component(|_ml, comp| {
        comp.external_refs
            .push(sbom_tools::model::ExternalReference {
                ref_type: sbom_tools::model::ExternalRefType::Advisories,
                url: "https://example.test/advisory".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
    }));

    let value = render_sarif(&sbom);
    let ids = result_rule_ids(&value);
    assert!(
        !ids.contains(&"SBOM-AIBOM-011".to_string()),
        "an advisory external reference must satisfy AI-011"
    );
}
