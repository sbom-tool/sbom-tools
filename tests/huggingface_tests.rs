//! Integration tests for HuggingFace Hub enrichment wiring.
//!
//! Covers, against a mocked HuggingFace API (httpmock):
//! - `enrich_sbom_full` injecting weight hashes (`siblings[].lfs.sha256` →
//!   component hashes), task (`pipeline_tag` → `MlModelInfo.task`), and a
//!   declared license only when none is present,
//! - the injected weight hash satisfying the AI-010 integrity check in the
//!   AI-readiness scoring profile.

#![cfg(feature = "enrichment")]

use sbom_tools::config::EnrichmentConfig;
use sbom_tools::model::{Component, ComponentType, LicenseExpression, MlModelInfo, NormalizedSbom};
use sbom_tools::pipeline::enrich_sbom_full;
use sbom_tools::quality::{QualityScorer, ScoringProfile};

use httpmock::prelude::*;

/// A HuggingFace model-info response body with two LFS weight files and the
/// freeform `cardData` block that must be ignored.
fn hf_model_body() -> serde_json::Value {
    serde_json::json!({
        "id": "google-bert/bert-base-uncased",
        "pipeline_tag": "fill-mask",
        "lastModified": "2020-02-19T11:06:12.000Z",
        "license": "apache-2.0",
        "cardData": { "anything": "must be ignored" },
        "siblings": [
            { "rfilename": "config.json" },
            {
                "rfilename": "model.safetensors",
                "lfs": { "sha256": "AAAA1111", "size": 440473133 }
            },
            {
                "rfilename": "pytorch_model.bin",
                "lfs": { "sha256": "BBBB2222", "size": 440473133 }
            }
        ]
    })
}

fn hf_ml_component(purl: &str) -> Component {
    let mut c = Component::new("bert-base-uncased".to_string(), "ml-1".to_string())
        .with_purl(purl.to_string())
        .with_version("1.0.0".to_string());
    c.component_type = ComponentType::MachineLearningModel;
    c.ml_model = Some(MlModelInfo::default());
    c
}

#[test]
fn enrich_sbom_full_injects_weight_hashes_and_task() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let hf_mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/models/google-bert/bert-base-uncased")
            .query_param("blobs", "true");
        then.status(200).json_body(hf_model_body());
    });

    let mut sbom = NormalizedSbom::default();
    sbom.add_component(hf_ml_component(
        "pkg:huggingface/google-bert/bert-base-uncased@1.0.0",
    ));

    let config = EnrichmentConfig::default()
        .with_huggingface()
        .with_huggingface_url(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();

    let stats = enrich_sbom_full(&mut sbom, &config, true);

    hf_mock.assert();
    let hf_stats = stats.huggingface.expect("HuggingFace stats produced");
    assert_eq!(hf_stats.models_resolved, 1);
    assert_eq!(hf_stats.models_enriched, 1);
    assert_eq!(hf_stats.hashes_added, 2, "two LFS sha256 hashes injected");
    assert_eq!(hf_stats.tasks_added, 1);
    assert_eq!(hf_stats.licenses_added, 1);

    let model = sbom
        .components
        .values()
        .find(|c| c.name == "bert-base-uncased")
        .expect("model present");

    // sha256 → component hashes (lower-cased).
    let hash_values: Vec<&str> = model.hashes.iter().map(|h| h.value.as_str()).collect();
    assert!(hash_values.contains(&"aaaa1111"));
    assert!(hash_values.contains(&"bbbb2222"));

    // pipeline_tag → task.
    assert_eq!(
        model.ml_model.as_ref().and_then(|m| m.task.as_deref()),
        Some("fill-mask")
    );

    // license applied (none was declared).
    assert_eq!(model.licenses.declared.len(), 1);
    assert_eq!(model.licenses.declared[0].expression, "apache-2.0");

    // lastModified → staleness signal.
    assert!(model.staleness.is_some());
}

#[test]
fn huggingface_enrichment_never_overwrites_declared_license() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    server.mock(|when, then| {
        when.method(GET);
        then.status(200).json_body(hf_model_body());
    });

    let mut sbom = NormalizedSbom::default();
    let mut comp = hf_ml_component("pkg:huggingface/google-bert/bert-base-uncased");
    comp.licenses
        .declared
        .push(LicenseExpression::new("MIT".to_string()));
    sbom.add_component(comp);

    let config = EnrichmentConfig::default()
        .with_huggingface()
        .with_huggingface_url(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();

    let stats = enrich_sbom_full(&mut sbom, &config, true);
    let hf_stats = stats.huggingface.expect("HuggingFace stats produced");
    assert_eq!(
        hf_stats.licenses_added, 0,
        "a declared license must never be overwritten"
    );

    let model = sbom.components.values().next().unwrap();
    assert_eq!(model.licenses.declared.len(), 1);
    assert_eq!(model.licenses.declared[0].expression, "MIT");
}

#[test]
fn injected_weight_hash_satisfies_ai010_integrity_check() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    server.mock(|when, then| {
        when.method(GET);
        then.status(200).json_body(hf_model_body());
    });

    let mut sbom = NormalizedSbom::default();
    sbom.add_component(hf_ml_component(
        "pkg:huggingface/google-bert/bert-base-uncased",
    ));

    // Before enrichment: no hashes → AI-010 fails.
    let before = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
    let ai010_before = before
        .ai_readiness_metrics
        .as_ref()
        .unwrap()
        .checks
        .iter()
        .find(|c| c.id == "AI-010")
        .unwrap()
        .passed;
    assert!(!ai010_before, "AI-010 should fail before HF enrichment");

    let config = EnrichmentConfig::default()
        .with_huggingface()
        .with_huggingface_url(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();
    enrich_sbom_full(&mut sbom, &config, true);

    // After enrichment: HF injected weight hashes → AI-010 passes.
    let after = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
    let ai010_after = after
        .ai_readiness_metrics
        .as_ref()
        .unwrap()
        .checks
        .iter()
        .find(|c| c.id == "AI-010")
        .unwrap()
        .passed;
    assert!(
        ai010_after,
        "AI-010 should pass once HuggingFace injects weight hashes"
    );
}
