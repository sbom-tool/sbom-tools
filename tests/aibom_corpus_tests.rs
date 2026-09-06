//! Regression pins for the third-party AI-BOM corpus in `tests/fixtures/aibom/`.
//!
//! These documents were produced by other vendors' generators (see the README
//! there for provenance) and are kept verbatim. The assertions below record
//! how sbom-tools reads them *today*, so a parser or scoring change that
//! shifts the result is a deliberate decision rather than silent drift.
//! `scripts/test-aibom.sh` runs the same corpus through the CLI.

use sbom_tools::model::{ComponentType, DependencyType, NormalizedSbom};
use sbom_tools::quality::{QualityScorer, ScoringProfile};

fn corpus(name: &str) -> NormalizedSbom {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/aibom")
        .join(name);
    sbom_tools::parse_sbom(&path).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn check_passed(sbom: &NormalizedSbom, id: &str) -> bool {
    let report = QualityScorer::new(ScoringProfile::AiReadiness).score(sbom);
    let metrics = report
        .ai_readiness_metrics
        .as_ref()
        .expect("AI readiness metrics");
    assert_eq!(
        metrics.ml_component_count, 1,
        "exactly one model per corpus document"
    );
    metrics
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("check {id} missing"))
        .passed
}

/// Manifest `aibom-gen` nests weight files and datasets under the model as
/// sub-components. The parser must flatten them into the inventory and keep
/// the containment edges.
#[test]
fn manifest_corpus_nested_components_are_flattened_with_containment() {
    for (name, total, nested_data) in [
        ("Llama-3.2-1B-Instruct.cdx.json", 36, 21),
        ("Qwen2.5-7B-Instruct.cdx.json", 59, 45),
    ] {
        let sbom = corpus(name);
        assert_eq!(
            sbom.component_count(),
            total,
            "{name}: flattened component count"
        );

        let models: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::MachineLearningModel)
            .collect();
        assert_eq!(models.len(), 1, "{name}: one machine-learning-model");
        let model = models[0];

        let contained: Vec<_> = sbom
            .get_dependencies(&model.canonical_id)
            .into_iter()
            .filter(|e| e.relationship == DependencyType::Contains)
            .filter_map(|e| sbom.components.get(&e.to))
            .collect();
        assert!(
            !contained.is_empty(),
            "{name}: nested sub-components must be parented to the model"
        );
        let data_children = contained
            .iter()
            .filter(|c| c.component_type == ComponentType::Data)
            .count();
        assert_eq!(
            data_children, nested_data,
            "{name}: nested `type: data` children"
        );
    }
}

/// The corpus datasets are bare `type: data` children with properties only
/// (no `data[]` block), which is not dataset evidence under the shared AI
/// scope. AI-003 therefore fails for both documents by policy, even though
/// Llama declares 21 datasets that way. Flip this assertion only with a
/// deliberate change to `ai_shared::declares_training_datasets`.
#[test]
fn manifest_corpus_bare_nested_datasets_do_not_satisfy_ai_003() {
    for name in [
        "Llama-3.2-1B-Instruct.cdx.json",
        "Qwen2.5-7B-Instruct.cdx.json",
    ] {
        let sbom = corpus(name);
        assert!(
            sbom.components.values().all(|c| c.dataset.is_none()),
            "{name}: corpus datasets carry no `data[]` evidence (fixture drift?)"
        );
        assert!(
            !check_passed(&sbom, "AI-003"),
            "{name}: AI-003 must not pass on bare nested data components"
        );
    }
}

/// What the corpus *does* satisfy today: the model-card external reference
/// (AI-001) and the declared architecture (AI-002) are read from both files.
#[test]
fn manifest_corpus_model_card_and_architecture_are_read() {
    for name in [
        "Llama-3.2-1B-Instruct.cdx.json",
        "Qwen2.5-7B-Instruct.cdx.json",
    ] {
        let sbom = corpus(name);
        assert!(
            check_passed(&sbom, "AI-001"),
            "{name}: model card reference"
        );
        assert!(
            check_passed(&sbom, "AI-002"),
            "{name}: architecture declared"
        );
    }
}
