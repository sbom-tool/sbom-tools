//! Integration tests for scoping the exploitability enrichment stack to ML
//! (HuggingFace) components — PR-C.
//!
//! Realizes the BSI thesis that an AI SBOM is only useful when connected to
//! cybersecurity tooling:
//! - a `pkg:huggingface` model component is routed through OSV enrichment (the
//!   OSV PURL query is attempted, not skipped), and
//! - KEV/advisory linkage by CVE identifier flags an exploited vulnerability a
//!   model already carries — independent of OSV's (absent) HuggingFace coverage.
//!
//! Honesty note: OSV (osv.dev) has NO ecosystem for HuggingFace models, so OSV
//! returns no vulns for a `pkg:huggingface` PURL. These tests therefore assert
//! that (a) the query is still ATTEMPTED and (b) exploitability data arrives via
//! the KEV path on identifier-referenced CVEs.

#![cfg(feature = "enrichment")]

use httpmock::prelude::*;
use sbom_tools::config::EnrichmentConfig;
use sbom_tools::enrichment::{OsvEnricher, OsvEnricherConfig, VulnerabilityEnricher};
use sbom_tools::model::{
    Component, ComponentType, Ecosystem, NormalizedSbom, VulnerabilityRef, VulnerabilitySource,
};
use sbom_tools::pipeline::enrich_sbom_full;
use std::time::Duration;

/// A `MachineLearningModel` component identified by a `pkg:huggingface` PURL.
fn hf_model(model_id: &str, bom_ref: &str) -> Component {
    let mut comp = Component::new(model_id.to_string(), bom_ref.to_string())
        .with_purl(format!("pkg:huggingface/{model_id}"));
    comp.component_type = ComponentType::MachineLearningModel;
    comp
}

/// A CISA KEV catalog body containing a single entry for the given CVE.
fn kev_catalog_body(cve_id: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.06.01",
        "dateReleased": "2026-06-01T12:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": cve_id,
                "vendorProject": "HuggingFace",
                "product": "transformers",
                "vulnerabilityName": "Unsafe model deserialization",
                "dateAdded": "2026-01-10",
                "shortDescription": "Loading an untrusted model executes code.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2026-01-24",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": ""
            }
        ]
    })
}

#[test]
fn huggingface_model_resolves_to_huggingface_ecosystem() {
    let comp = hf_model("google-bert/bert-base-uncased", "ml-1");
    assert_eq!(
        comp.ecosystem,
        Some(Ecosystem::HuggingFace),
        "a pkg:huggingface PURL must resolve to Ecosystem::HuggingFace"
    );
}

#[test]
fn osv_enrichment_is_attempted_for_huggingface_model() {
    // OSV does not index HuggingFace, so it returns no vulns — but the query
    // MUST be attempted (the component is not skipped). We assert the OSV
    // querybatch endpoint is hit with the model in the pipeline.
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        // OSV's honest answer for a HuggingFace PURL: an empty result set.
        then.status(200)
            .json_body(serde_json::json!({ "results": [{ "vulns": [] }] }));
    });

    let enricher = OsvEnricher::new(OsvEnricherConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        cache_ttl: Duration::from_secs(3600),
        bypass_cache: false,
        timeout: Duration::from_secs(5),
        api_base: server.base_url(),
        max_retries: 0,
    })
    .unwrap();

    let mut components = vec![hf_model("google-bert/bert-base-uncased", "ml-1")];
    let stats = enricher.enrich(&mut components).unwrap();

    // The HuggingFace model was queried (by PURL), not skipped.
    batch_mock.assert();
    assert_eq!(
        stats.components_queried, 1,
        "the HuggingFace model must be queried by PURL"
    );
    assert_eq!(
        stats.components_skipped, 0,
        "the HuggingFace model must not be skipped"
    );
    // OSV genuinely has nothing for it — that is correct and honest.
    assert_eq!(stats.total_vulns_found, 0);
}

#[test]
fn kev_linkage_flags_exploited_cve_on_huggingface_model() {
    // The exploitability signal for ML models arrives via KEV linkage on a CVE
    // the model already carries (e.g. from a SECURITY external ref or a prior
    // enrichment), NOT from OSV's HuggingFace coverage (which does not exist).
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200)
            .json_body(kev_catalog_body("CVE-2026-12345"));
    });

    let mut sbom = NormalizedSbom::default();
    let mut model = hf_model("evil-org/backdoored-model", "ml-1");
    // The model carries a CVE reference an analyst can pivot on.
    model.vulnerabilities.push(VulnerabilityRef::new(
        "CVE-2026-12345".to_string(),
        VulnerabilitySource::Cve,
    ));
    sbom.add_component(model);

    let config = EnrichmentConfig::default()
        .with_kev()
        .with_kev_url(format!("{}/kev.json", server.base_url()))
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();

    let stats = enrich_sbom_full(&mut sbom, &config, true);

    kev_mock.assert();
    let kev_stats = stats.kev.expect("KEV stats should be produced");
    assert_eq!(
        kev_stats.kev_matches, 1,
        "the model's CVE must be flagged as actively exploited"
    );

    // The flag landed on the ML component's vulnerability.
    let model = sbom
        .components
        .values()
        .find(|c| c.component_type == ComponentType::MachineLearningModel)
        .expect("ML component present");
    assert!(
        model.vulnerabilities.iter().any(|v| v.is_kev),
        "the ML model's CVE must be marked is_kev after KEV linkage"
    );
}
