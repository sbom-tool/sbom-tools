//! Tests for the JSON `view` reporter's structured vulnerability output
//! and direct/transitive dependency classification (issue #178).

use chrono::{TimeZone, Utc};
use sbom_tools::model::{
    CompletenessDeclaration, Component, Creator, CreatorType, DependencyEdge, DependencyType,
    DocumentMetadata, KevInfo, NormalizedSbom, Remediation, RemediationType, SbomFormat, Severity,
    VulnerabilityRef, VulnerabilitySource,
};
use sbom_tools::reports::{JsonReporter, ReportConfig, ReportGenerator};

fn base_document_metadata() -> DocumentMetadata {
    DocumentMetadata {
        format: SbomFormat::CycloneDx,
        format_version: "1.6".to_string(),
        spec_version: "1.6".to_string(),
        serial_number: Some("urn:uuid:00000000-0000-0000-0000-000000000000".to_string()),
        created: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        creators: vec![Creator {
            creator_type: CreatorType::Organization,
            name: "Acme Corp".to_string(),
            email: None,
        }],
        name: Some("Acme Product".to_string()),
        security_contact: None,
        vulnerability_disclosure_url: None,
        support_end_date: None,
        lifecycle_phase: None,
        completeness_declaration: CompletenessDeclaration::Unknown,
        signature: None,
        distribution_classification: None,
        citations_count: 0,
    }
}

fn vulnerable_component(name: &str, version: &str, vuln_id: &str) -> Component {
    let mut comp = Component::new(name.to_string(), format!("{name}-ref"))
        .with_version(version.to_string());

    let mut v = VulnerabilityRef::new(vuln_id.to_string(), VulnerabilitySource::Osv);
    v.severity = Some(Severity::High);
    v.cwes = vec!["CWE-79".to_string()];
    v.is_kev = true;
    v.kev_info = Some(KevInfo::new(
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap(),
        "Apply vendor patch".to_string(),
    ));
    v.remediation = Some(Remediation {
        remediation_type: RemediationType::Upgrade,
        description: Some("Upgrade to fixed release".to_string()),
        fixed_version: Some("2.0.0".to_string()),
    });
    v.description = Some("XSS in template renderer".to_string());

    comp.vulnerabilities.push(v);
    comp
}

#[test]
fn json_view_emits_structured_vulnerability_details() {
    let mut sbom = NormalizedSbom::new(base_document_metadata());
    sbom.add_component(vulnerable_component("acme-web", "1.0.0", "CVE-2025-0001"));

    let json = JsonReporter::new()
        .generate_view_report(&sbom, &ReportConfig::default())
        .expect("view report");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let comp = value["components"]
        .as_array()
        .and_then(|arr| arr.first())
        .expect("at least one component");
    assert_eq!(comp["vulnerability_count"], 1);

    let vuln = comp["vulnerabilities"]
        .as_array()
        .and_then(|arr| arr.first())
        .expect("vuln entry on component");
    assert_eq!(vuln["id"], "CVE-2025-0001");
    assert_eq!(vuln["source"], "OSV");
    assert_eq!(vuln["severity"], "High");
    assert_eq!(vuln["fixed_version"], "2.0.0");
    assert_eq!(vuln["kev"], true);
    assert_eq!(vuln["cwes"][0], "CWE-79");
    assert!(vuln["kev_info"]["due_date"].is_string());
    assert_eq!(vuln["description"], "XSS in template renderer");

    let flat = value["vulnerabilities"]
        .as_array()
        .expect("top-level vulnerabilities array");
    assert_eq!(flat.len(), 1);
    assert_eq!(flat[0]["id"], "CVE-2025-0001");
    assert_eq!(flat[0]["package"], "acme-web");
    assert_eq!(flat[0]["package_version"], "1.0.0");
}

#[test]
fn json_view_classifies_direct_vs_transitive() {
    let mut sbom = NormalizedSbom::new(base_document_metadata());

    let root = Component::new("root".to_string(), "root-ref".to_string());
    let direct = vulnerable_component("direct-dep", "1.0.0", "CVE-2025-DIRECT");
    let transitive = vulnerable_component("trans-dep", "0.9.0", "CVE-2025-TRANS");

    let root_id = root.canonical_id.clone();
    let direct_id = direct.canonical_id.clone();
    let trans_id = transitive.canonical_id.clone();

    sbom.add_component(root);
    sbom.add_component(direct);
    sbom.add_component(transitive);
    sbom.set_primary_component(root_id.clone());

    sbom.add_edge(DependencyEdge::new(
        root_id,
        direct_id.clone(),
        DependencyType::DependsOn,
    ));
    sbom.add_edge(DependencyEdge::new(
        direct_id,
        trans_id,
        DependencyType::DependsOn,
    ));

    let json = JsonReporter::new()
        .generate_view_report(&sbom, &ReportConfig::default())
        .expect("view report");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let kinds: std::collections::HashMap<String, String> = value["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_string(),
                c["dependency_kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    assert_eq!(kinds.get("root").map(String::as_str), Some("primary"));
    assert_eq!(kinds.get("direct-dep").map(String::as_str), Some("direct"));
    assert_eq!(
        kinds.get("trans-dep").map(String::as_str),
        Some("transitive")
    );

    let flat = value["vulnerabilities"].as_array().unwrap();
    let direct_vuln = flat
        .iter()
        .find(|v| v["id"] == "CVE-2025-DIRECT")
        .expect("direct vuln present");
    assert_eq!(direct_vuln["dependency_kind"], "direct");
    assert_eq!(direct_vuln["is_direct"], true);

    let trans_vuln = flat
        .iter()
        .find(|v| v["id"] == "CVE-2025-TRANS")
        .expect("transitive vuln present");
    assert_eq!(trans_vuln["dependency_kind"], "transitive");
    assert_eq!(trans_vuln["is_direct"], false);
}

#[test]
fn json_view_empty_vulnerabilities_when_none() {
    let mut sbom = NormalizedSbom::new(base_document_metadata());
    sbom.add_component(Component::new("clean".to_string(), "clean-ref".to_string()));

    let json = JsonReporter::new()
        .generate_view_report(&sbom, &ReportConfig::default())
        .expect("view report");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let comp = &value["components"][0];
    assert_eq!(comp["vulnerability_count"], 0);
    assert_eq!(comp["vulnerabilities"].as_array().unwrap().len(), 0);
    assert_eq!(value["vulnerabilities"].as_array().unwrap().len(), 0);
}
