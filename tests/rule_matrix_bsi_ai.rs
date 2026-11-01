//! Registry-driven per-rule matrix for `ComplianceLevel::BsiSbomForAi`
//! (BSI/G7 "SBOM for AI — Minimum Elements" readiness).
//!
//! The universe is every registered `SBOM-BSIAI-*` rule but the fallback,
//! which `run_matrix` requires to be the level's rule list
//! (`rules_for_level`): one per minimum element the profile checks,
//! grouped below by the document's clusters (Metadata,
//! System-Level, Models, Datasets, Infrastructure, Security).
//!
//! Three elements have no SBOM field today (system data flow, AI security
//! controls, exploitability references): they fire as Info on every
//! applicable AI-BOM, so their only silent state is an out-of-scope SBOM.
//!
//! Every row runs in CycloneDX JSON, CycloneDX XML and SPDX 3; SPDX 2.3 has
//! no AI or dataset profile.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, Encoding, IMPLAUSIBLE_SHA256_DIGESTS, MD5_FILLER, Outcome, RuleEntry,
    SPDX23_HAS_NO_AI_PROFILE, SbomFixture, check_in, render_violations, run_matrix,
};
use sbom_tools::quality::{
    ComplianceLevel, ViolationSeverity as Sev, all_rule_ids, generic_rule_id_for_level,
};
use std::collections::BTreeMap;

const LEVEL: ComplianceLevel = ComplianceLevel::BsiSbomForAi;

/// The registered BSI-AI rules but the fallback rule, which no check emits.
fn bsi_ai_universe() -> Vec<&'static str> {
    all_rule_ids()
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-BSIAI-") && *id != generic_rule_id_for_level(LEVEL))
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
/// no SBOM field can carry, as Infos, in every encoding with an AI profile.
#[test]
fn bsi_ai_complete_fixture_fires_only_the_unmodeled_elements() {
    for &encoding in Encoding::ALL_BUT_SPDX23 {
        let result = check_in(LEVEL, &base(), encoding);
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
             elements as Info in {}; got is_compliant={}:\n{}",
            encoding.name(),
            result.is_compliant,
            render_violations(&result)
        );
    }
}

/// A plain software SBOM is out of scope: the result says N/A and reports
/// no finding, never a failure, in every encoding.
#[test]
fn bsi_ai_non_ai_sbom_is_not_applicable() {
    for &encoding in Encoding::ALL {
        let result = check_in(LEVEL, &non_ai(), encoding);
        assert!(
            !result.is_applicable() && result.is_compliant && result.violations.is_empty(),
            "[{LEVEL:?}] a non-AI SBOM must be N/A with no finding in {}:\n{}",
            encoding.name(),
            render_violations(&result)
        );
    }
}

#[test]
fn bsi_ai_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── Typing ───────────────────────────────────────────────────────
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
        )
        .case_only(
            "firing",
            &[Encoding::CycloneDxJson],
            "an empty CycloneDX specVersion: XML carries the version in the bom namespace \
             (one without reads as 1.4), and the SPDX encodings write their own version",
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
        )
        // Only plausible digests count.
        .with_implausible_digests(Sev::Error, &IMPLAUSIBLE_SHA256_DIGESTS, |alg, value| {
            broken(|s| {
                model(s).hashes = vec![(alg.to_string(), value.to_string())];
            })
        }),
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
        )
        .with_implausible_digests(
            Sev::Warning,
            &IMPLAUSIBLE_SHA256_DIGESTS,
            |alg, value| {
                broken(|s| {
                    dataset(s).hashes = vec![(alg.to_string(), value.to_string())];
                })
            },
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
        )
        .with_firing(
            "no governance owner and no supplier",
            Sev::Warning,
            broken(|s| {
                let ds = dataset(s);
                ds.dataset_mut().governance_owners.clear();
                ds.supplier = None;
            }),
        )
        .case_differs(
            "firing",
            &[Encoding::Spdx3JsonLd],
            Outcome::Silent,
            "the SPDX 3 parser reads a dataset's suppliedBy and originatedBy agents as its \
             governance owners (SPDX 3 has no governance field), so the supplier declares \
             the dataset's provenance",
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
        )
        .case_only(
            "silent",
            Encoding::CYCLONEDX,
            "SPDX 3.0.1 has no external-reference type for a linked BOM",
        ),
        RuleEntry::tested("SBOM-BSIAI-SEC-CONTROLS", Sev::Info, base(), non_ai()),
        RuleEntry::tested("SBOM-BSIAI-SEC-EXPLOITABILITY", Sev::Info, base(), non_ai()),
    ];

    // SPDX 2.3 has no AI profile: every row runs in the other three
    // encodings.
    let entries: Vec<RuleEntry> = entries
        .into_iter()
        .map(|entry| entry.only(Encoding::ALL_BUT_SPDX23, SPDX23_HAS_NO_AI_PROFILE))
        .collect();
    run_matrix(LEVEL, &bsi_ai_universe(), &entries);
}
