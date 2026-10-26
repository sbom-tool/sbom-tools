//! Registry-driven per-rule matrix for `ComplianceLevel::BsiSbomForAi`
//! (BSI/G7 "SBOM for AI — Minimum Elements" readiness).
//!
//! BSI-AI shares the CRA-family `COMPLIANCE_SARIF_RULE_IDS` catalogue; its
//! universe is that slice's `SBOM-BSIAI-*` ids, one per minimum element the
//! profile checks, grouped below by the document's clusters (Metadata,
//! System-Level, Models, Datasets, Infrastructure, Security).
//!
//! Three elements have no SBOM field today (system data flow, AI security
//! controls, exploitability references): they fire as Info on every
//! applicable AI-BOM, so their only silent state is an out-of-scope SBOM.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, MD5_FILLER, RuleEntry, SbomFixture, check, render_violations, run_matrix,
};
use sbom_tools::quality::{COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ViolationSeverity as Sev};
use std::collections::BTreeMap;

const LEVEL: ComplianceLevel = ComplianceLevel::BsiSbomForAi;

/// The BSI-AI rules of the shared CRA-family SARIF catalogue.
fn bsi_ai_universe() -> Vec<&'static str> {
    COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-BSIAI-"))
        .collect()
}

/// An AI-BOM declaring every minimum element that has an SBOM field: Person
/// author + tool, timestamp, format version and a document signature; a
/// primary application; a typed model with name, version, PURL, SHA-256
/// weight hash, model-card reference, architecture, training-dataset
/// reference, limitations and license, wired into the dependency graph; and
/// the referenced dataset with name, PURL, hash, license, sensitivity and a
/// governance owner.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-assistant");
    primary.component_type = "application".to_string();
    let mut model = ComponentFixture::ml_model("sentiment-bert");
    model.external_refs.push((
        "model-card".to_string(),
        "https://acme.example/cards/sentiment-bert".to_string(),
    ));
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: vec![(
            "Dana Author".to_string(),
            Some("dana@acme.example".to_string()),
        )],
        primary: Some(primary),
        components: vec![model, ComponentFixture::dataset("reviews")],
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
        signature: Some(("ES256".to_string(), "c2lnbmF0dXJlLXZhbHVl".to_string())),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// Add one firing case per value that declares nothing — the placeholders
/// `TBD` and `N/A` and the sentinel `NOASSERTION` — written by `set`;
/// `labels` names the three cases in that order. Like every other presence
/// check, the model and dataset name, version and licence elements need a
/// known value.
fn with_placeholders(
    mut entry: RuleEntry,
    severity: Sev,
    labels: [&'static str; 3],
    set: fn(&mut SbomFixture, &str),
) -> RuleEntry {
    for (label, value) in labels.into_iter().zip(["TBD", "N/A", "NOASSERTION"]) {
        entry = entry.with_firing(label, severity, broken(|s| set(s, value)));
    }
    entry
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

/// An AI-BOM listing only the dataset: no primary, no model.
fn dataset_only() -> SbomFixture {
    broken(|s| {
        s.primary = None;
        s.components = vec![ComponentFixture::dataset("reviews")];
        s.dependencies.clear();
    })
}

fn model(s: &mut SbomFixture) -> &mut ComponentFixture {
    s.component_mut("sentiment-bert")
}

fn dataset(s: &mut SbomFixture) -> &mut ComponentFixture {
    s.component_mut("reviews")
}

/// A HuggingFace-hosted model typed `library` with no model card.
fn untyped_hf_model() -> ComponentFixture {
    let mut c = ComponentFixture::conforming("bert-base");
    c.purl = Some("pkg:huggingface/google/bert-base@1.0.0".to_string());
    c
}

/// The complete AI-BOM is compliant, and fires exactly the three elements
/// no SBOM field can carry, as Infos.
#[test]
fn bsi_ai_complete_fixture_fires_only_the_unmodeled_elements() {
    let result = check(LEVEL, &base());
    let fired: BTreeMap<&str, Sev> = result
        .violations
        .iter()
        .map(|v| (v.rule_id, v.severity))
        .collect();
    let expected: BTreeMap<&str, Sev> = [
        ("SBOM-BSIAI-SYS-DATAFLOW", Sev::Info),
        ("SBOM-BSIAI-SEC-CONTROLS", Sev::Info),
        ("SBOM-BSIAI-SEC-EXPLOITABILITY", Sev::Info),
    ]
    .into_iter()
    .collect();
    assert!(
        fired == expected && result.violations.len() == 3 && result.is_compliant,
        "[{LEVEL:?}] the complete AI-BOM must fire exactly the three unmodeled \
         elements as Info; got is_compliant={}:\n{}",
        result.is_compliant,
        render_violations(&result)
    );
}

/// A non-AI SBOM is not applicable: one Info, and the result says N/A.
#[test]
fn bsi_ai_non_ai_sbom_is_not_applicable() {
    let result = check(LEVEL, &non_ai());
    assert!(
        !result.is_applicable()
            && result.violations.len() == 1
            && result.violations[0].rule_id == "SBOM-BSIAI-NA",
        "[{LEVEL:?}] a non-AI SBOM must be N/A with the single NA Info:\n{}",
        render_violations(&result)
    );
}

#[test]
fn bsi_ai_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── Applicability and typing ───────────────────────────────────────
        RuleEntry::tested("SBOM-BSIAI-NA", Sev::Info, non_ai(), base()),
        RuleEntry::tested(
            "SBOM-BSIAI-UNTYPED-ML",
            Sev::Warning,
            broken(|s| s.components.push(untyped_hf_model())),
            base(),
        ),
        // ── Metadata cluster ───────────────────────────────────────────────
        RuleEntry::tested(
            "SBOM-BSIAI-META-AUTHOR",
            Sev::Error,
            broken(|s| {
                s.authors.clear();
                s.tools.clear();
            }),
            base(),
        ),
        // The parser keeps an empty specVersion verbatim.
        RuleEntry::tested(
            "SBOM-BSIAI-META-FORMAT",
            Sev::Error,
            broken(|s| s.spec_version = String::new()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-META-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-META-TOOL",
            Sev::Warning,
            broken(|s| s.tools.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-META-SIGNATURE",
            Sev::Info,
            broken(|s| s.signature = None),
            base(),
        ),
        // ── System-Level cluster ───────────────────────────────────────────
        RuleEntry::tested(
            "SBOM-BSIAI-SYS-PRIMARY",
            Sev::Warning,
            dataset_only(),
            base(),
        ),
        // Silent: an organization creator stands in for the producer.
        RuleEntry::tested(
            "SBOM-BSIAI-SYS-PRODUCER",
            Sev::Warning,
            broken(|s| {
                s.primary_mut().supplier = None;
                model(s).supplier = None;
            }),
            broken(|s| {
                s.primary_mut().supplier = None;
                model(s).supplier = None;
                s.manufacturer = Some(("Acme AI GmbH".to_string(), None));
            }),
        ),
        RuleEntry::tested("SBOM-BSIAI-SYS-DATAFLOW", Sev::Info, base(), non_ai()),
        // ── Models cluster ─────────────────────────────────────────────────
        with_placeholders(
            RuleEntry::tested(
                "SBOM-BSIAI-MODEL-NAME",
                Sev::Error,
                broken(|s| model(s).name = String::new()),
                base(),
            ),
            Sev::Error,
            [
                "model named TBD",
                "model named N/A",
                "model named NOASSERTION",
            ],
            |s, v| model(s).name = v.to_string(),
        ),
        with_placeholders(
            RuleEntry::tested(
                "SBOM-BSIAI-MODEL-VERSION",
                Sev::Error,
                broken(|s| model(s).version = None),
                base(),
            ),
            Sev::Error,
            [
                "model version TBD",
                "model version N/A",
                "model version NOASSERTION",
            ],
            |s, v| model(s).version = Some(v.to_string()),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-IDENTIFIER",
            Sev::Error,
            broken(|s| model(s).purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-HASH",
            Sev::Error,
            broken(|s| model(s).hashes.clear()),
            base(),
        ),
        // A weight hash that no NIST-approved algorithm produced.
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-HASH-ALGO",
            Sev::Error,
            broken(|s| model(s).hashes = vec![("MD5".to_string(), MD5_FILLER.to_string())]),
            base(),
        ),
        // The model card object alone does not reference a card: the URL
        // comes from the model-card external reference.
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-CARD",
            Sev::Warning,
            broken(|s| model(s).external_refs.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-ARCHITECTURE",
            Sev::Warning,
            broken(|s| {
                let card = model(s).model_card_mut();
                card.architecture_family = None;
                card.model_architecture = None;
            }),
            base(),
        ),
        // Silent: a dataset component with data[] evidence nested under the
        // model is the second spec-legal shape (no modelParameters.datasets).
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-DATASETS",
            Sev::Warning,
            broken(|s| model(s).model_card_mut().datasets.clear()),
            broken(|s| {
                let ds = s.components.remove(1);
                s.dependencies = vec![(
                    "ref-acme-assistant".to_string(),
                    vec!["ref-sentiment-bert".to_string()],
                )];
                let m = model(s);
                m.model_card_mut().datasets.clear();
                m.children.push(ds);
            }),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-MODEL-LIMITATIONS",
            Sev::Warning,
            broken(|s| model(s).model_card_mut().technical_limitations.clear()),
            base(),
        ),
        with_placeholders(
            RuleEntry::tested(
                "SBOM-BSIAI-MODEL-LICENSE",
                Sev::Warning,
                broken(|s| model(s).licenses.clear()),
                base(),
            ),
            Sev::Warning,
            [
                "model licence TBD",
                "model licence N/A",
                "model licence NOASSERTION",
            ],
            |s, v| model(s).licenses = vec![v.to_string()],
        ),
        // ── Datasets cluster ───────────────────────────────────────────────
        with_placeholders(
            RuleEntry::tested(
                "SBOM-BSIAI-DATASET-NAME",
                Sev::Error,
                broken(|s| dataset(s).name = String::new()),
                base(),
            ),
            Sev::Error,
            [
                "dataset named TBD",
                "dataset named N/A",
                "dataset named NOASSERTION",
            ],
            |s, v| dataset(s).name = v.to_string(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-DATASET-IDENTIFIER",
            Sev::Error,
            broken(|s| dataset(s).purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-DATASET-HASH",
            Sev::Warning,
            broken(|s| dataset(s).hashes.clear()),
            base(),
        ),
        with_placeholders(
            RuleEntry::tested(
                "SBOM-BSIAI-DATASET-LICENSE",
                Sev::Warning,
                broken(|s| dataset(s).licenses.clear()),
                base(),
            ),
            Sev::Warning,
            [
                "dataset licence TBD",
                "dataset licence N/A",
                "dataset licence NOASSERTION",
            ],
            |s, v| dataset(s).licenses = vec![v.to_string()],
        ),
        RuleEntry::tested(
            "SBOM-BSIAI-DATASET-SENSITIVITY",
            Sev::Warning,
            broken(|s| dataset(s).dataset_mut().sensitive_data.clear()),
            base(),
        ),
        // CycloneDX carries provenance only as governance owners (intended
        // use / preprocessing / anonymization are SPDX 3.0 fields).
        RuleEntry::tested(
            "SBOM-BSIAI-DATASET-PROVENANCE",
            Sev::Warning,
            broken(|s| dataset(s).dataset_mut().governance_owners.clear()),
            base(),
        ),
        // ── Infrastructure and Security clusters ───────────────────────────
        // Silent: a BOM link on the model stands in for a dependency edge.
        RuleEntry::tested(
            "SBOM-BSIAI-INFRA-RUNTIME",
            Sev::Info,
            broken(|s| s.dependencies.clear()),
            broken(|s| {
                s.dependencies.clear();
                model(s).external_refs.push((
                    "bom".to_string(),
                    "https://acme.example/sboms/runtime.cdx.json".to_string(),
                ));
            }),
        ),
        RuleEntry::tested("SBOM-BSIAI-SEC-CONTROLS", Sev::Info, base(), non_ai()),
        RuleEntry::tested("SBOM-BSIAI-SEC-EXPLOITABILITY", Sev::Info, base(), non_ai()),
    ];

    run_matrix(LEVEL, &bsi_ai_universe(), &entries);
}
