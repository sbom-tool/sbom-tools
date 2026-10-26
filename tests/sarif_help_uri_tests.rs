//! Integration tests for CRA-P5.1 SARIF helpUri linking.
//!
//! Asserts that:
//! - `StandardRef::new` auto-populates `help_uri` from `StandardKind`
//!   (canonical EUR-Lex / BSI / NIST / OASIS URLs).
//! - SARIF rule definitions include `helpUri` for CRA-, BSI-, NTIA-,
//!   SSDF-, EO-, FDA-, PQC-, CSAF-, CNSA2-prefixed rules (every registered rule, in fact).
//! - SARIF result `properties.standardHelpUris` parallels `standardIds`
//!   when violations carry `StandardRef::help_uri`.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{Component, NormalizedSbom};
use sbom_tools::quality::{ComplianceLevel, StandardKind, StandardRef};
use sbom_tools::reports::generate_compliance_sarif;

#[test]
fn standard_ref_new_auto_populates_help_uri_for_cra() {
    let r = StandardRef::new(StandardKind::CraArticle, "Art. 13(8)");
    assert_eq!(
        r.help_uri.as_deref(),
        Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
    );
}

#[test]
fn standard_ref_new_auto_populates_help_uri_for_bsi() {
    let r = StandardRef::new(StandardKind::BsiTr03183_2, "TR-03183-2 §5.4");
    assert!(
        r.help_uri
            .as_deref()
            .is_some_and(|u| u.contains("bsi.bund.de")),
        "BSI helpUri should point at bsi.bund.de, got: {:?}",
        r.help_uri
    );
}

#[test]
fn standard_ref_new_pren_remains_none_until_published() {
    let r = StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-07");
    assert!(r.help_uri.is_none(), "prEN 40000-1-3 has no public URL yet");
}

#[test]
fn standard_ref_new_other_remains_none() {
    let r = StandardRef::new(StandardKind::Other, "ad-hoc");
    assert!(r.help_uri.is_none());
}

#[test]
fn standard_kinds_have_canonical_help_uri() {
    let kinds_with_uri = [
        StandardKind::CraArticle,
        StandardKind::CraAnnex,
        StandardKind::BsiTr03183_2,
        StandardKind::NistSsdf,
        StandardKind::Eo14028,
        StandardKind::FdaPremarket,
        StandardKind::NtiaMinimum,
        StandardKind::Csaf2,
        StandardKind::Cnsa2,
        StandardKind::NistPqc,
    ];
    for kind in kinds_with_uri {
        let uri = kind.canonical_help_uri("any-id");
        assert!(
            uri.is_some(),
            "{kind:?} should expose a canonical helpUri for CRA-P5.1"
        );
        let uri = uri.unwrap();
        assert!(
            uri.starts_with("https://"),
            "{kind:?} helpUri must be HTTPS, got {uri}"
        );
    }
}

#[test]
fn sarif_output_includes_help_uri_for_cra_rules() {
    // Empty SBOM under CraPhase2 generates many violations and exercises
    // the entire SARIF rule table.
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("SARIF generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");

    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    let cra_rule_with_uri = rules.iter().any(|r| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("SBOM-CRA-"))
            && r["helpUri"]
                .as_str()
                .is_some_and(|u| u.contains("eur-lex.europa.eu"))
    });
    assert!(
        cra_rule_with_uri,
        "At least one CRA rule must carry a EUR-Lex helpUri"
    );
}

#[test]
fn sarif_output_results_include_standard_help_uris() {
    let mut sbom = NormalizedSbom::default();
    let c = Component::new("foo".to_string(), "foo".to_string());
    sbom.add_component(c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("SARIF generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");

    let results = json["runs"][0]["results"].as_array().expect("results");
    let with_uri = results.iter().any(|r| {
        r["properties"]["standardHelpUris"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    });
    assert!(
        with_uri,
        "At least one result should expose properties.standardHelpUris"
    );
}

#[test]
fn sarif_output_includes_help_uri_for_bsi_rules() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("SARIF generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");

    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    let bsi_rule_with_uri = rules.iter().any(|r| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("SBOM-BSI-"))
            && r["helpUri"]
                .as_str()
                .is_some_and(|u| u.contains("bsi.bund.de"))
    });
    assert!(
        bsi_rule_with_uri,
        "BSI rules must carry a bsi.bund.de helpUri"
    );
}

/// Every rule a SARIF catalogue declares links to its standard. The CNSA 2.0
/// family carried no helpUri at all: the prefix table tested `SBOM-CNSA-`
/// while every rule ID is `SBOM-CNSA2-…`.
#[test]
fn every_declared_sarif_rule_has_a_help_uri() {
    let mut missing = std::collections::BTreeSet::new();
    for level in ComplianceLevel::all() {
        let result = checker(*level).check(&NormalizedSbom::default());
        let sarif = generate_compliance_sarif(&result).expect("SARIF generation");
        let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
        for run in json["runs"].as_array().into_iter().flatten() {
            assert_eq!(
                run["tool"]["driver"]["informationUri"], "https://github.com/sbom-tool/sbom-tools",
                "informationUri must point at the current repository"
            );
            for rule in run["tool"]["driver"]["rules"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let has_uri = rule["helpUri"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("https://"));
                if !has_uri {
                    missing.insert(rule["id"].as_str().unwrap_or("?").to_string());
                }
            }
        }
    }
    assert!(missing.is_empty(), "rules without a helpUri: {missing:?}");
}
