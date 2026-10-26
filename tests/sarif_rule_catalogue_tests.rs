//! SARIF rule-catalogue integrity: every result ruleId must have a
//! reportingDescriptor in driver.rules, and descriptor ids must be unique
//! (SARIF 2.1.0 requirement; GitHub code scanning drops rule metadata for
//! undeclared ids and rejects duplicate descriptors).

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{Component, DocumentMetadata, NormalizedSbom};
use sbom_tools::quality::{CNSA2_SARIF_RULE_IDS, ComplianceLevel, PQC_SARIF_RULE_IDS};
use sbom_tools::reports::{generate_compliance_sarif, generate_multi_compliance_sarif};
use std::collections::HashSet;

/// SBOM engineered to fire many rules: no timestamp, no creators, missing
/// versions/suppliers/identifiers, no edges.
fn violating_sbom() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.created = chrono::DateTime::UNIX_EPOCH;
    sbom.document.creators.clear();
    for i in 0..3 {
        sbom.add_component(Component::new(format!("lib{i}"), format!("lib{i}@1")));
    }
    sbom
}

fn assert_catalogue_complete(sarif_json: &str, label: &str) {
    let sarif: serde_json::Value = serde_json::from_str(sarif_json).expect("valid JSON");
    let run = &sarif["runs"][0];
    let declared: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().expect("rule id"))
        .collect();
    let mut seen = HashSet::new();
    for id in &declared {
        assert!(
            seen.insert(*id),
            "[{label}] duplicate reportingDescriptor id {id}"
        );
    }
    for result in run["results"].as_array().expect("results array") {
        let rule_id = result["ruleId"].as_str().expect("result ruleId");
        assert!(
            seen.contains(rule_id),
            "[{label}] result references undeclared rule {rule_id}"
        );
    }
}

#[test]
fn single_standard_sarif_declares_every_emitted_rule() {
    let sbom = violating_sbom();
    for level in [
        ComplianceLevel::NtiaMinimum,
        ComplianceLevel::FdaMedicalDevice,
        ComplianceLevel::Eo14028,
        ComplianceLevel::NistSsdf,
        ComplianceLevel::Cnsa2,
        ComplianceLevel::NistPqc,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::CraOssSteward,
        ComplianceLevel::BsiTr03183_2,
        ComplianceLevel::EuccSubstantial,
    ] {
        let result = checker(level).check(&sbom);
        let sarif = generate_compliance_sarif(&result).expect("sarif generation");
        assert_catalogue_complete(&sarif, level.name());
    }
}

/// The EUCC checks carry their own per-check rule identity: a sidecar-less
/// run must emit — and declare — the five SBOM-EUCC-* ids (not the collapsed
/// SBOM-CRA-GENERAL bucket), each with the Reg. (EU) 2024/482 helpUri.
#[test]
fn eucc_sarif_declares_per_check_rule_ids() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("sarif generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
    let run = &json["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let declared: HashSet<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
    let emitted: HashSet<&str> = run["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|r| r["ruleId"].as_str())
        .collect();
    for id in [
        "SBOM-EUCC-PP",
        "SBOM-EUCC-TOE",
        "SBOM-EUCC-ITSEF",
        "SBOM-EUCC-VALIDITY",
        "SBOM-EUCC-CERTREF",
    ] {
        assert!(declared.contains(id), "rule {id} must be declared");
        assert!(emitted.contains(id), "rule {id} must be emitted");
    }
    assert!(
        !emitted.contains("SBOM-CRA-GENERAL"),
        "EUCC findings must no longer collapse into SBOM-CRA-GENERAL"
    );
    for rule in rules.iter().filter(|r| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("SBOM-EUCC"))
    }) {
        assert_eq!(
            rule["helpUri"].as_str(),
            Some("https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng"),
            "EUCC rule {} must cite Implementing Regulation (EU) 2024/482",
            rule["id"]
        );
    }
}

#[test]
fn multi_standard_sarif_has_unique_descriptors() {
    let sbom = violating_sbom();
    let results: Vec<_> = [
        ComplianceLevel::CraPhase2,
        ComplianceLevel::BsiTr03183_2,
        ComplianceLevel::NtiaMinimum,
    ]
    .into_iter()
    .map(|l| checker(l).check(&sbom))
    .collect();
    let sarif = generate_multi_compliance_sarif(&results).expect("sarif generation");
    assert_catalogue_complete(&sarif, "multi cra,bsi,ntia");
}

/// A CNSA 2.0 / NIST PQC run must declare its own rule family as the SARIF
/// catalogue — not the CRA/BSI/EUCC/AI-family table it used to inherit from
/// the `_` arm (which had zero overlap with the rules actually evaluated).
#[test]
fn cnsa2_and_pqc_sarif_declare_only_their_own_rule_family() {
    let sbom = violating_sbom();
    for (level, prefix, slice) in [
        (ComplianceLevel::Cnsa2, "SBOM-CNSA2-", CNSA2_SARIF_RULE_IDS),
        (ComplianceLevel::NistPqc, "SBOM-PQC-", PQC_SARIF_RULE_IDS),
    ] {
        let result = checker(level).check(&sbom);
        let sarif = generate_compliance_sarif(&result).expect("sarif generation");
        assert_catalogue_complete(&sarif, level.name());
        let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
        let declared: HashSet<&str> = json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .filter_map(|r| r["id"].as_str())
            .collect();
        for id in declared.iter() {
            assert!(
                id.starts_with(prefix),
                "[{}] declared rule {id} is outside the {prefix}* family",
                level.name()
            );
        }
        for id in slice {
            assert!(
                declared.contains(id),
                "[{}] curated rule {id} missing from the declared catalogue",
                level.name()
            );
        }
    }
}

/// Multi-standard SARIF must carry per-standard applicability/score/verdict
/// on `properties.standards` — otherwise a standard that never evaluated the
/// SBOM (EU AI Act on a non-ML SBOM) is machine-indistinguishable from a
/// clean pass in `validate --standard ai-act,ntia -o sarif`.
#[test]
fn multi_standard_sarif_carries_per_standard_run_summaries() {
    let sbom = violating_sbom();
    let results: Vec<_> = [ComplianceLevel::EuAiAct, ComplianceLevel::NtiaMinimum]
        .into_iter()
        .map(|l| checker(l).check(&sbom))
        .collect();
    assert!(
        !results[0].is_applicable() && results[1].is_applicable(),
        "fixture must yield one N/A and one applicable standard"
    );

    let sarif = generate_multi_compliance_sarif(&results).expect("sarif generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
    let props = &json["runs"][0]["properties"];
    assert_eq!(
        props["applicable"],
        serde_json::json!(true),
        "at least one standard evaluated the SBOM"
    );

    let standards = props["standards"].as_array().expect("standards array");
    assert_eq!(standards.len(), results.len(), "one entry per standard");
    for (entry, result) in standards.iter().zip(&results) {
        assert_eq!(
            entry["profile"].as_str(),
            Some(result.level.name()),
            "profile carries the standard display name"
        );
        assert_eq!(
            entry["applicable"].as_bool(),
            Some(result.is_applicable()),
            "[{}] applicability mismatch",
            result.level.name()
        );
        assert_eq!(
            entry["compliant"].as_bool(),
            Some(result.is_compliant),
            "[{}] verdict mismatch",
            result.level.name()
        );
        if result.is_applicable() {
            assert_eq!(
                entry["overallScore"].as_f64(),
                result.score().map(f64::from),
                "[{}] score mismatch",
                result.level.name()
            );
            assert!(
                entry.get("notApplicableReason").is_none(),
                "[{}] applicable standard must not carry an N/A reason",
                result.level.name()
            );
        } else {
            assert!(
                entry.get("overallScore").is_none(),
                "[{}] unevaluated standard must omit overallScore (not null/0)",
                result.level.name()
            );
            assert!(
                entry["notApplicableReason"]
                    .as_str()
                    .is_some_and(|r| !r.is_empty()),
                "[{}] N/A entry must carry its human-readable reason",
                result.level.name()
            );
        }
    }
}

/// Every declared rule carries what GitHub code scanning shows for it: a
/// short and a full description within its 1,024-character limit, and help
/// as plain text and Markdown. Each check is its own rule, so no two rules
/// share a name.
#[test]
fn every_declared_rule_carries_descriptions_and_help() {
    use sbom_tools::quality::{QualityScorer, ScoringProfile};
    use sbom_tools::reports::{
        ReportConfig, ReportGenerator, SarifReporter, generate_quality_sarif,
    };
    let sbom = violating_sbom();
    let mut documents: Vec<(String, String)> = ComplianceLevel::all()
        .iter()
        .map(|level| {
            let result = checker(*level).check(&sbom);
            (
                level.name().to_string(),
                generate_compliance_sarif(&result).expect("sarif generation"),
            )
        })
        .collect();
    let report = QualityScorer::new(ScoringProfile::Standard).score(&sbom);
    documents.push((
        "quality".to_string(),
        generate_quality_sarif(&report, "test.cdx.json", "standard").expect("sarif"),
    ));
    let config = ReportConfig::all();
    let reporter = SarifReporter::new();
    documents.push((
        "view".to_string(),
        reporter
            .generate_view_report(&sbom, &config)
            .expect("sarif"),
    ));
    let empty = NormalizedSbom::default();
    let diff = sbom_tools::DiffEngine::new()
        .diff(&sbom, &empty)
        .expect("diff");
    documents.push((
        "diff".to_string(),
        reporter
            .generate_diff_report(&diff, &sbom, &empty, &config)
            .expect("sarif"),
    ));
    for (label, sarif) in &documents {
        let json: serde_json::Value = serde_json::from_str(sarif).expect("valid JSON");
        let rules = json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        let mut names = HashSet::new();
        for rule in rules {
            let id = rule["id"].as_str().expect("rule id");
            for pointer in [
                "/shortDescription/text",
                "/fullDescription/text",
                "/help/text",
                "/help/markdown",
            ] {
                let text = rule
                    .pointer(pointer)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                assert!(!text.trim().is_empty(), "[{label}] {id} lacks {pointer}");
                if pointer.ends_with("Description/text") {
                    assert!(
                        text.chars().count() <= 1024,
                        "[{label}] {id}: {pointer} exceeds 1,024 characters"
                    );
                }
            }
            let name = rule["name"].as_str().expect("rule name");
            assert!(names.insert(name), "[{label}] two rules are named {name}");
        }
    }
}
