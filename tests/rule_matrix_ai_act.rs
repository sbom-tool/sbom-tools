//! Registry-driven per-rule matrix for `ComplianceLevel::EuAiAct` (EU AI
//! Act Annex IV technical-documentation readiness).
//!
//! The AI Act shares the CRA-family `COMPLIANCE_SARIF_RULE_IDS` catalogue;
//! its universe is that slice's `SBOM-AIACT-*` ids, one per Annex IV
//! element the profile checks. A declared high-risk system (CRA sidecar
//! `isHighRiskAi`) escalates every documentation gap; those escalations are
//! the departing firing cases.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, check, render_violations,
    run_matrix,
};
use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::quality::{COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::EuAiAct;

/// The AI Act rules of the shared CRA-family SARIF catalogue.
fn ai_act_universe() -> Vec<&'static str> {
    COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-AIACT-"))
        .collect()
}

/// An AI-BOM documenting every Annex IV element the profile reads: a typed
/// model whose card declares architecture, intended use, a training-dataset
/// reference, metrics, limitations and training energy, plus the dataset it
/// references, carrying a (non-personal) sensitivity classification.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-assistant");
    primary.component_type = "application".to_string();
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        primary: Some(primary),
        components: vec![
            ComponentFixture::ml_model("sentiment-bert"),
            ComponentFixture::dataset("reviews"),
        ],
        dependencies: vec![
            (
                "ref-acme-assistant".to_string(),
                vec!["ref-sentiment-bert".to_string()],
            ),
            (
                "ref-sentiment-bert".to_string(),
                vec!["ref-reviews".to_string()],
            ),
        ],
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// A plain software SBOM: out of the profile's scope.
fn non_ai() -> SbomFixture {
    broken(|s| {
        s.components = vec![
            ComponentFixture::conforming("libalpha"),
            ComponentFixture::conforming("libbeta"),
        ];
        s.dependencies = vec![(
            "ref-acme-assistant".to_string(),
            vec!["ref-libalpha".to_string(), "ref-libbeta".to_string()],
        )];
    })
}

/// Declare the system high-risk (Annex IV becomes mandatory).
fn high_risk(s: &mut SbomFixture) {
    s.sidecar = Some(CraSidecarMetadata {
        is_high_risk_ai: true,
        ..CraSidecarMetadata::default()
    });
}

/// The model component of `base()`.
fn model(s: &mut SbomFixture) -> &mut ComponentFixture {
    s.component_mut("sentiment-bert")
}

/// A model with no general description at all: no description, no
/// architecture, no model-card reference.
fn strip_description(s: &mut SbomFixture) {
    let m = model(s);
    m.description = None;
    m.external_refs.clear();
    let card = m.model_card_mut();
    card.architecture_family = None;
    card.model_architecture = None;
}

/// Declare the training data the nested way instead of through
/// `modelParameters.datasets`: the dataset component moves under the model
/// (`components[]`, which the parser links with a `contains` edge), keeping
/// its `data[]` evidence when `with_evidence`.
fn nest_dataset_under_model(s: &mut SbomFixture, with_evidence: bool) {
    let at = s
        .components
        .iter()
        .position(|c| c.name == "reviews")
        .expect("base() lists the reviews dataset");
    let mut dataset = s.components.remove(at);
    if !with_evidence {
        dataset.dataset = None;
    }
    s.dependencies
        .retain(|(from, _)| from != "ref-sentiment-bert");
    let m = model(s);
    m.model_card_mut().datasets.clear();
    m.children.push(dataset);
}

/// A HuggingFace-hosted model typed `library` with no model card: ML content
/// the profile must not lose.
fn untyped_hf_model() -> ComponentFixture {
    let mut c = ComponentFixture::conforming("bert-base");
    c.purl = Some("pkg:huggingface/google/bert-base@1.0.0".to_string());
    c
}

/// The complete AI-BOM must pass with a clean verdict.
#[test]
fn ai_act_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

/// A plain software SBOM is out of scope: the result says N/A and reports
/// no finding, never a failure.
#[test]
fn ai_act_non_ai_sbom_is_not_applicable() {
    let result = check(LEVEL, &non_ai());
    assert!(
        !result.is_applicable() && result.is_compliant && result.violations.is_empty(),
        "[{LEVEL:?}] a non-AI SBOM must be N/A with no finding:\n{}",
        render_violations(&result)
    );
}

#[test]
fn ai_act_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── Typing ───────────────────────────────────────────────────────
        // Untyping a model cannot dodge the assessment: the ML content is
        // surfaced, and alone it keeps the profile applicable.
        RuleEntry::tested(
            "SBOM-AIACT-UNTYPED-ML",
            Sev::Warning,
            broken(|s| s.components.push(untyped_hf_model())),
            base(),
        )
        .with_firing(
            "untyped HuggingFace model is the only ML content",
            Sev::Warning,
            broken(|s| {
                s.components = vec![untyped_hf_model()];
                s.dependencies = vec![(
                    "ref-acme-assistant".to_string(),
                    vec!["ref-bert-base".to_string()],
                )];
            }),
        ),
        // ── The Annex IV elements ──────────────────────────────────────────
        // A model-card reference alone is a general description (silent).
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
            Sev::Warning,
            broken(strip_description),
            broken(|s| {
                strip_description(s);
                model(s).external_refs.push((
                    "model-card".to_string(),
                    "https://acme.example/cards/sentiment-bert".to_string(),
                ));
            }),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                strip_description(s);
                high_risk(s);
            }),
        ),
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
            Sev::Warning,
            broken(|s| model(s).model_card_mut().use_cases.clear()),
            base(),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                model(s).model_card_mut().use_cases.clear();
                high_risk(s);
            }),
        ),
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
            Sev::Warning,
            broken(|s| model(s).model_card_mut().datasets.clear()),
            base(),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                model(s).model_card_mut().datasets.clear();
                high_risk(s);
            }),
        )
        // The nested shape ai_shared::declares_training_datasets accepts (as
        // do SBOM-BSIAI-MODEL-DATASETS and quality check AI-003): a dataset
        // component with data[] evidence nested under the model. A bare
        // nested `type: data` component is no dataset evidence.
        .with_silent(
            "dataset component with data[] evidence nested under the model",
            broken(|s| nest_dataset_under_model(s, true)),
        )
        .with_firing(
            "nested type: data component without data[] evidence",
            Sev::Warning,
            broken(|s| nest_dataset_under_model(s, false)),
        ),
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
            Sev::Warning,
            broken(|s| {
                s.component_mut("reviews")
                    .dataset_mut()
                    .sensitive_data
                    .clear()
            }),
            base(),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                s.component_mut("reviews")
                    .dataset_mut()
                    .sensitive_data
                    .clear();
                high_risk(s);
            }),
        ),
        // Personal data is a disclosure note, not a gap: Info, or Warning
        // for a declared high-risk system.
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
            Sev::Info,
            broken(|s| {
                s.component_mut("reviews").dataset_mut().sensitive_data =
                    vec!["personal-data".to_string()];
            }),
            base(),
        )
        .with_firing(
            "CRA sidecar declares personal-data processing",
            Sev::Info,
            broken(|s| {
                s.sidecar = Some(CraSidecarMetadata {
                    processes_personal_data: true,
                    ..CraSidecarMetadata::default()
                });
            }),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Warning,
            broken(|s| {
                s.component_mut("reviews").dataset_mut().sensitive_data = vec!["PII".to_string()];
                high_risk(s);
            }),
        ),
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-2G-METRICS",
            Sev::Warning,
            broken(|s| model(s).model_card_mut().performance_metrics.clear()),
            base(),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                model(s).model_card_mut().performance_metrics.clear();
                high_risk(s);
            }),
        ),
        // A recommendation about models: silent on a dataset-only AI-BOM.
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
            Sev::Info,
            broken(|s| model(s).model_card_mut().training_energy_kwh = None),
            broken(|s| {
                s.components = vec![ComponentFixture::dataset("reviews")];
                s.dependencies = vec![(
                    "ref-acme-assistant".to_string(),
                    vec!["ref-reviews".to_string()],
                )];
            }),
        ),
        RuleEntry::tested(
            "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
            Sev::Info,
            broken(|s| model(s).model_card_mut().technical_limitations.clear()),
            base(),
        )
        .with_departing_firing(
            "declared high-risk system",
            Sev::Error,
            broken(|s| {
                model(s).model_card_mut().technical_limitations.clear();
                high_risk(s);
            }),
        ),
    ];

    run_matrix(LEVEL, &ai_act_universe(), &entries);
}
