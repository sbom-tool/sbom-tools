//! Integration tests for CRA-P4.3 ConformityAssessmentSummary surface.
//!
//! Asserts that:
//! - `ComplianceResult::conformity_summary` is populated only when a CRA
//!   product class is pinned.
//! - The evidence checklist matches the expected per-route shape.
//! - Markdown / HTML report rendering surfaces the summary.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    Component, ConformityRoute, CraProductClass, CraSidecarMetadata, ExternalRefType,
    ExternalReference, NormalizedSbom,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::ComplianceLevel;

#[test]
fn no_summary_when_class_not_pinned() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        result.conformity_summary.is_none(),
        "no summary when no product class pinned"
    );
}

#[test]
fn summary_present_at_default_class_lists_doc_and_module_a() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    let summary = result
        .conformity_summary
        .as_ref()
        .expect("summary present at Default");
    assert_eq!(summary.product_class, CraProductClass::Default);
    assert_eq!(summary.route, ConformityRoute::ModuleA);
    let labels: Vec<&str> = summary.evidence.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.contains(&"EU Declaration of Conformity"));
    assert!(labels.contains(&"Internal-control technical file"));
    assert!(labels.contains(&"PSIRT contact (Art. 14)"));
}

#[test]
fn summary_module_bc_includes_eu_type_examination() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass2),
        conformity_assessment_route: Some(ConformityRoute::ModuleBC),
        ..Default::default()
    };
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary");
    assert_eq!(summary.route, ConformityRoute::ModuleBC);
    let labels: Vec<&str> = summary.evidence.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.iter().any(|l| l.contains("EU-type examination")));
    assert!(labels.iter().any(|l| l.contains("Production conformity")));
}

#[test]
fn summary_module_h_includes_qms_certification() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass2),
        conformity_assessment_route: Some(ConformityRoute::ModuleH),
        ..Default::default()
    };
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary");
    assert_eq!(summary.route, ConformityRoute::ModuleH);
    let labels: Vec<&str> = summary.evidence.iter().map(|e| e.label.as_str()).collect();
    assert!(
        labels
            .iter()
            .any(|l| l.contains("Quality-management-system"))
    );
    assert!(labels.iter().any(|l| l.contains("surveillance")));
}

#[test]
fn summary_eucc_includes_target_of_evaluation() {
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&NormalizedSbom::default());
    let summary = result.conformity_summary.expect("summary");
    assert_eq!(summary.route, ConformityRoute::Eucc);
    let labels: Vec<&str> = summary.evidence.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.iter().any(|l| l.contains("EUCC")));
    assert!(labels.iter().any(|l| l.contains("Target of Evaluation")));
}

#[test]
fn doc_evidence_satisfied_by_attestation_external_ref() {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("app".to_string(), "app".to_string());
    c.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::Attestation,
        url: "https://example.com/doc".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(c);
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary");
    let doc_row = summary
        .evidence
        .iter()
        .find(|e| e.label == "EU Declaration of Conformity")
        .unwrap();
    assert!(
        doc_row.satisfied,
        "Attestation external ref should satisfy DoC evidence"
    );
}

#[test]
fn psirt_evidence_satisfied_by_sidecar() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass1),
        psirt_url: Some("https://example.com/psirt".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&NormalizedSbom::default());
    let summary = result.conformity_summary.expect("summary");
    let psirt = summary
        .evidence
        .iter()
        .find(|e| e.label.contains("PSIRT"))
        .unwrap();
    assert!(psirt.satisfied);
}

#[test]
fn eucc_evidence_satisfied_by_certification_with_eucc_url() {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("app".to_string(), "app".to_string());
    c.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::Certification,
        url: "https://eucc.eu/cert/abc".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(c);
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary");
    let eucc = summary
        .evidence
        .iter()
        .find(|e| e.label.contains("EUCC"))
        .unwrap();
    assert!(eucc.satisfied, "EUCC URL must satisfy EUCC evidence row");
}

/// A CycloneDX document whose product carries `externalReferences` of the
/// given `(type, url)` pairs.
fn cyclonedx_with_refs(refs: &[(&str, &str)]) -> NormalizedSbom {
    let refs: Vec<serde_json::Value> = refs
        .iter()
        .map(|(ref_type, url)| serde_json::json!({ "type": ref_type, "url": url }))
        .collect();
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "app",
                "name": "app",
                "externalReferences": refs,
            },
        },
        "components": [],
    });
    parse_sbom_str(&doc.to_string()).expect("CycloneDX parses")
}

/// The model-built tests above, through the CycloneDX parser: the
/// `attestation` and `certification-report` reference types reach the
/// summary (until v0.4.0 the parser mapped both to `Other`). Every format
/// and route is covered in tests/external_ref_evidence_tests.rs.
#[test]
fn parsed_cyclonedx_references_satisfy_the_summary_rows() {
    let row = |sbom: &NormalizedSbom, class: CraProductClass, label: &str| {
        checker(ComplianceLevel::CraPhase2)
            .with_product_class(class)
            .check(sbom)
            .conformity_summary
            .expect("summary")
            .evidence
            .into_iter()
            .find(|e| e.label == label)
            .unwrap_or_else(|| panic!("row {label:?}"))
            .satisfied
    };
    let doc = "EU Declaration of Conformity";
    let eucc = "EUCC / Common Criteria certificate";
    assert!(!row(
        &cyclonedx_with_refs(&[]),
        CraProductClass::Default,
        doc
    ));
    assert!(row(
        &cyclonedx_with_refs(&[("attestation", "https://example.com/doc")]),
        CraProductClass::Default,
        doc
    ));
    assert!(!row(
        &cyclonedx_with_refs(&[]),
        CraProductClass::Critical,
        eucc
    ));
    assert!(row(
        &cyclonedx_with_refs(&[("certification-report", "https://eucc.eu/cert/abc")]),
        CraProductClass::Critical,
        eucc
    ));
}

#[test]
fn json_serialization_roundtrips_conformity_summary() {
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&NormalizedSbom::default());
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("conformity_summary"));
    assert!(json.contains("Critical"));
    assert!(json.contains("Eucc") || json.contains("EUCC"));
}
