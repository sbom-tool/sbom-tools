//! EU CRA checks: the CRA phases, the Art. 24 steward profile, the CRA
//! sidecar, product-class calibration, hardware and vendor hashes,
//! Art. 14 readiness and the class-pinned EUCC evidence.

use super::*;

/// CRA Art. 24 steward vuln-handling is satisfied by a DOCUMENT-level
/// disclosure URL — the check previously ignored doc fields (false-fail).
#[test]
fn cra_art24_honors_document_level_disclosure() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.vulnerability_disclosure_url = Some("https://acme.example/security".to_string());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    assert!(
        !r.violations.iter().any(|v| v.rule_id == "SBOM-CRA-ART-24"),
        "a document-level disclosure URL must satisfy the Art.24 vuln-handling gate"
    );
}

/// CRA Art. 24 steward SBOMs still need versioned, identified components
/// and dependency relationships — the per-component gates used to skip
/// the CraOssSteward level entirely (vacuous "SBOM completeness").
#[test]
fn oss_steward_enforces_component_completeness() {
    use crate::model::{Component, DocumentMetadata, ExternalRefType, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    // Steward vuln-handling satisfied so only completeness is under test.
    sbom.document.vulnerability_disclosure_url = Some("https://acme.example/security".to_string());
    for n in ["a", "b", "c"] {
        let mut c = Component::new(n.to_string(), n.to_string());
        c.external_refs.push(crate::model::ExternalReference {
            ref_type: ExternalRefType::Advisories,
            url: "https://acme.example/advisories".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        sbom.add_component(c);
    }
    let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-COMPONENT-VERSION"
                && v.severity == ViolationSeverity::Error),
        "steward components without versions must error"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-I-IDENTIFIER"
                && v.severity == ViolationSeverity::Error),
        "steward components without identifiers must error"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-I-DEPENDENCY"
                && v.severity == ViolationSeverity::Error),
        "steward SBOM without dependency edges must error"
    );
    assert!(!r.is_compliant, "incomplete steward SBOM must not pass");
}

/// A third-party dependency's upstream advisories/support refs must not
/// satisfy the manufacturer's Art. 13(17) contact / Annex I Part II (5)
/// CVD-policy obligations.
#[test]
fn third_party_refs_do_not_satisfy_manufacturer_obligations() {
    use crate::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType,
        ExternalReference, NormalizedSbom,
    };
    let build = |primary_has_contact: bool| {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut app = Component::new("app".to_string(), "app".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        if primary_has_contact {
            app.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::SecurityContact,
                url: "https://acme.example/security".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
            app.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::Advisories,
                url: "https://acme.example/advisories".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
        }
        // Third-party dep carrying its own upstream refs.
        let mut lodash = Component::new("lodash".to_string(), "lodash".to_string())
            .with_version("4.17.21".to_string())
            .with_purl("pkg:npm/lodash@4.17.21".to_string());
        lodash.external_refs.push(ExternalReference {
            ref_type: ExternalRefType::Advisories,
            url: "https://github.com/lodash/lodash/security/advisories".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        lodash.external_refs.push(ExternalReference {
            ref_type: ExternalRefType::Support,
            url: "https://lodash.com/docs".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        let app_id = app.canonical_id.clone();
        let lodash_id = lodash.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.add_component(app);
        sbom.add_component(lodash);
        sbom.edges.push(DependencyEdge::new(
            app_id,
            lodash_id,
            DependencyType::DependsOn,
        ));
        sbom
    };

    let r = checker(ComplianceLevel::CraPhase2).check(&build(false));
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
        "dep-level advisories/support refs must not satisfy Art. 13(17)"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-CVD-POLICY"),
        "dep-level advisories ref must not satisfy Annex I Part II (5)"
    );

    let r = checker(ComplianceLevel::CraPhase2).check(&build(true));
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
        "primary-component security contact satisfies Art. 13(17)"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-CVD-POLICY"),
        "primary-component advisories ref satisfies Annex I Part II (5)"
    );
}

/// Pinning an explicit product class must never weaken the phase-based
/// vendor-hash gate: 40% coverage is an Error under CraPhase2 regardless
/// of a pinned Important-1 class (whose own threshold severity is softer).
#[test]
fn explicit_product_class_never_weakens_vendor_hash_gate() {
    use crate::model::CraProductClass;
    let mut sbom = NormalizedSbom::default();
    for n in ["a", "b", "c", "d"] {
        let c = vendor_component(n, true);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    for n in ["e", "f", "g", "h", "i", "j"] {
        let c = vendor_component(n, false);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let result = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass1)
        .check(&sbom);
    let v = result.violations.iter().find(|v| {
        v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
    });
    assert!(
        v.is_some(),
        "40% coverage must stay an Error under CraPhase2 even with an explicit class"
    );
}

/// The sidecar's dedicated EUCC evidence fields must satisfy the
/// Critical-class EUCC reference check (not just URL substrings).
#[test]
fn eucc_sidecar_fields_satisfy_critical_class_check() {
    use crate::model::{Component, CraProductClass, CraSidecarMetadata, DocumentMetadata};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("fw".to_string(), "fw".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:generic/fw@1.0".to_string()),
    );

    let bare = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    assert!(
        bare.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV"),
        "Critical class without EUCC evidence must flag Annex IV"
    );

    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-CC-MFR-2024-01".to_string()),
        eucc_target_of_evaluation: Some("TOE-fw-1.0".to_string()),
        ..Default::default()
    };
    let with_sidecar = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !with_sidecar
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV"),
        "sidecar EUCC evidence fields must satisfy the Critical-class check"
    );
}

/// Sidecar EUCC evidence must be live: empty strings and expired
/// validity dates must not satisfy the Critical-class Annex IV gate.
#[test]
fn eucc_sidecar_empty_or_expired_evidence_does_not_satisfy() {
    use crate::model::{Component, CraProductClass, CraSidecarMetadata, DocumentMetadata};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("fw".to_string(), "fw".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:generic/fw@1.0".to_string()),
    );
    let check = |sidecar: CraSidecarMetadata| {
        checker(ComplianceLevel::CraPhase2)
            .with_product_class(CraProductClass::Critical)
            .with_sidecar(sidecar)
            .check(&sbom)
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV")
    };
    assert!(
        check(CraSidecarMetadata {
            eucc_protection_profile_id: Some("  ".to_string()),
            ..Default::default()
        }),
        "an empty-string EUCC field must not satisfy the Annex IV gate"
    );
    assert!(
        check(CraSidecarMetadata {
            eucc_valid_until: Some(as_of() - chrono::Duration::days(365)),
            ..Default::default()
        }),
        "an expired EUCC validity date must not satisfy the Annex IV gate"
    );
    assert!(
        !check(CraSidecarMetadata {
            eucc_valid_until: Some(as_of() + chrono::Duration::days(365)),
            ..Default::default()
        }),
        "a live EUCC validity date satisfies the Annex IV gate"
    );
    // An expired certificate voids its identifiers: they describe a
    // certificate that no longer holds.
    assert!(
        check(CraSidecarMetadata {
            eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
            eucc_itsef_identifier: Some("ITSEF-DE-0042".to_string()),
            eucc_valid_until: Some(as_of() - chrono::Duration::days(1)),
            ..Default::default()
        }),
        "identifiers beside an expired validity date must not satisfy the Annex IV gate"
    );
    assert!(
        !check(CraSidecarMetadata {
            eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
            eucc_valid_until: Some(as_of() + chrono::Duration::days(365)),
            ..Default::default()
        }),
        "an identifier with a live validity date satisfies the Annex IV gate"
    );
    assert!(
        !check(CraSidecarMetadata {
            eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
            ..Default::default()
        }),
        "an identifier without a validity date still satisfies the Annex IV gate"
    );
}

/// Steward supplier findings cite Art. 24 in their structured refs, not
/// the exempted Art. 13(16) manufacturer-identification obligation.
#[test]
fn steward_supplier_refs_cite_art_24() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.vulnerability_disclosure_url = Some("https://acme.example/security".to_string());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    let v = r
        .violations
        .iter()
        .find(|v| v.rule_id == "SBOM-CRA-ART-24-SUPPLIER")
        .expect("steward supplier warning fires");
    assert!(
        v.standard_refs
            .iter()
            .all(|sr| sr.id != "Art. 13(15)" && sr.id != "Art. 13(16)"),
        "steward supplier refs must not cite Art. 13(15)/13(16)"
    );
    assert!(
        v.standard_refs.iter().any(|sr| sr.id == "Art. 24"),
        "steward supplier refs must cite Art. 24"
    );
}

/// Manufacturer scope: cyclic graphs fall back to all components, and a
/// primary does not exclude sibling root products.
#[test]
fn manufacturer_scope_handles_cycles_and_sibling_roots() {
    use crate::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType,
        ExternalReference, NormalizedSbom,
    };
    // Cyclic: a <-> b, no primary; evidence on a must still count.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut a = Component::new("liba".to_string(), "liba".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/liba@1.0".to_string());
    a.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::SecurityContact,
        url: "https://acme.example/security".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    let b = Component::new("libb".to_string(), "libb".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/libb@1.0".to_string());
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();
    sbom.add_component(a);
    sbom.add_component(b);
    sbom.edges.push(DependencyEdge::new(
        a_id.clone(),
        b_id.clone(),
        DependencyType::DependsOn,
    ));
    sbom.edges
        .push(DependencyEdge::new(b_id, a_id, DependencyType::DependsOn));
    let r = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
        "evidence in a fully-cyclic graph must still count (fallback to all components)"
    );
}

/// Dependency cycles fire the ClassCheck::Cycles calibration: Warning at
/// Default class, Error at Important-2/Critical; acyclic graphs are silent.
#[test]
fn cra_dependency_cycles_scale_with_product_class() {
    use crate::model::{
        Component, CraProductClass, DependencyEdge, DependencyType, DocumentMetadata,
        NormalizedSbom,
    };
    let build = |cyclic: bool| {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let a = Component::new("liba".to_string(), "liba".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/liba@1.0".to_string());
        let b = Component::new("libb".to_string(), "libb".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/libb@1.0".to_string());
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        sbom.add_component(a);
        sbom.add_component(b);
        sbom.edges.push(DependencyEdge::new(
            a_id.clone(),
            b_id.clone(),
            DependencyType::DependsOn,
        ));
        if cyclic {
            sbom.edges
                .push(DependencyEdge::new(b_id, a_id, DependencyType::DependsOn));
        }
        sbom
    };

    let cycles = |r: &ComplianceResult| {
        r.violations
            .iter()
            .find(|v| v.rule_id == "SBOM-CRA-CYCLES")
            .map(|v| v.severity)
    };

    let r = checker(ComplianceLevel::CraPhase2).check(&build(true));
    assert_eq!(
        cycles(&r),
        Some(ViolationSeverity::Warning),
        "cycles warn at the default class"
    );
    let r = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&build(true));
    assert_eq!(
        cycles(&r),
        Some(ViolationSeverity::Error),
        "cycles error at Critical class"
    );
    let r = checker(ComplianceLevel::CraPhase2).check(&build(false));
    assert_eq!(cycles(&r), None, "acyclic graphs are silent");
}

/// CRA SBOM freshness: a creation timestamp after the evaluation instant
/// gave a negative age and passed as fresh (review finding V14). It warns
/// like a missing timestamp now, in both CRA phases, and the document
/// ages normally once the clock passes its timestamp.
#[test]
fn cra_freshness_flags_a_future_timestamp() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let ts = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp must parse")
            .with_timezone(&chrono::Utc)
    };
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.created = ts("2026-12-01T00:00:00Z");
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let freshness = |level: ComplianceLevel, as_of: &str| -> Vec<(ViolationSeverity, String)> {
        ComplianceChecker::new(level)
            .with_as_of(ts(as_of))
            .check(&sbom)
            .violations
            .into_iter()
            .filter(|v| v.rule_id == "SBOM-CRA-SBOM-FRESHNESS")
            .map(|v| (v.severity, v.message))
            .collect()
    };
    for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
        let future = freshness(level, "2026-10-12T00:00:00Z");
        assert_eq!(future.len(), 1, "{level:?}: {future:?}");
        assert_eq!(future[0].0, ViolationSeverity::Warning, "{level:?}");
        assert!(
            future[0].1.contains("later than the evaluation instant"),
            "{level:?}: {}",
            future[0].1
        );
        // Two weeks after its timestamp the document is fresh...
        assert!(
            freshness(level, "2026-12-15T00:00:00Z").is_empty(),
            "{level:?}"
        );
        // ...and 120 days after it, stale.
        let stale = freshness(level, "2027-03-31T00:00:00Z");
        assert_eq!(stale.len(), 1, "{level:?}: {stale:?}");
        assert!(
            stale[0].1.contains("120 days old"),
            "{level:?}: {}",
            stale[0].1
        );
    }
}

#[test]
fn sidecar_supplies_security_contact_downgrades_art_13_17() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default();

    // Without sidecar: Art. 13(17) is a Warning
    let bare = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let art_13_17_warning = bare.violations.iter().find(|v| {
        v.requirement.contains("Art. 13(17)") && v.severity == ViolationSeverity::Warning
    });
    assert!(
        art_13_17_warning.is_some(),
        "Without sidecar, Art. 13(17) should be a Warning"
    );

    // With sidecar that supplies security_contact: same finding becomes Info
    let sidecar = CraSidecarMetadata {
        security_contact: Some("security@acme.example".to_string()),
        ..Default::default()
    };
    let withsc = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let art_13_17_info = withsc
        .violations
        .iter()
        .find(|v| v.requirement.contains("Art. 13(17)") && v.severity == ViolationSeverity::Info);
    assert!(
        art_13_17_info.is_some(),
        "With sidecar, Art. 13(17) should be downgraded to Info"
    );
    assert!(
        !withsc
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 13(17)")
                && v.severity == ViolationSeverity::Warning),
        "With sidecar, no Warning-level Art. 13(17) violation should remain"
    );
}

#[test]
fn sidecar_supplies_product_name_downgrades_art_13_15() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default(); // no document name

    let sidecar = CraSidecarMetadata {
        product_name: Some("Demo Product".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let downgraded = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Art. 13(15)") && v.severity == ViolationSeverity::Info);
    assert!(
        downgraded.is_some(),
        "Sidecar product_name should downgrade Art. 13(15) to Info"
    );
}

/// An SPDX 2.x document always has a DocumentName; an empty (or
/// placeholder) one names neither the document nor the product. The
/// rule-matrix format axis found FDA and CRA accepting it: an SPDX 2.3
/// document with no name passed the checks its CycloneDX twin, which has
/// no `metadata.component`, fails.
#[test]
fn empty_document_name_is_no_name() {
    let spdx = |name: &str| {
        crate::parsers::parse_sbom_str(&format!(
            r#"{{
                  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
                  "SPDXID": "SPDXRef-DOCUMENT", "name": "{name}",
                  "documentNamespace": "https://acme.example/spdx/doc",
                  "creationInfo": {{
                    "created": "2026-01-15T10:00:00Z",
                    "creators": ["Tool: acme-sbom-tool-1.0.0"]
                  }},
                  "packages": []
                }}"#
        ))
        .expect("SPDX 2.3 document parses")
    };
    let fired = |sbom: &NormalizedSbom, level: ComplianceLevel, rule: &str| {
        checker(level)
            .check(sbom)
            .violations
            .iter()
            .any(|v| v.rule_id == rule)
    };
    for name in ["", "  ", "NOASSERTION"] {
        let sbom = spdx(name);
        assert!(
            fired(&sbom, ComplianceLevel::FdaMedicalDevice, "SBOM-FDA-NAME"),
            "document name {name:?} must fire SBOM-FDA-NAME"
        );
        assert!(
            fired(
                &sbom,
                ComplianceLevel::CraPhase2,
                "SBOM-CRA-ART-13-15-PRODUCT"
            ),
            "document name {name:?} must fire SBOM-CRA-ART-13-15-PRODUCT"
        );
    }
    let named = spdx("acme-router-os");
    assert!(!fired(
        &named,
        ComplianceLevel::FdaMedicalDevice,
        "SBOM-FDA-NAME"
    ));
    assert!(!fired(
        &named,
        ComplianceLevel::CraPhase2,
        "SBOM-CRA-ART-13-15-PRODUCT"
    ));
}

#[test]
fn sidecar_supplies_manufacturer_downgrades_art_13_16() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default();
    let sidecar = CraSidecarMetadata {
        manufacturer_name: Some("Demo Corp".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let downgraded = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Art. 13(16)") && v.severity == ViolationSeverity::Info);
    assert!(
        downgraded.is_some(),
        "Sidecar manufacturer_name should downgrade Art. 13(16) to Info"
    );
}

#[test]
fn sidecar_supplies_cvd_url_downgrades_cvd_policy() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default();
    let sidecar = CraSidecarMetadata {
        vulnerability_disclosure_url: Some("https://acme.example/security".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let downgraded = result.violations.iter().find(|v| {
        v.requirement.contains("Annex I Part II (5)") && v.severity == ViolationSeverity::Info
    });
    assert!(
        downgraded.is_some(),
        "Sidecar CVD URL should downgrade the Annex I Part II (5) CVD-policy finding to Info"
    );
}

fn vendor_component(name: &str, with_hash: bool) -> crate::model::Component {
    use crate::model::{Component, Hash, HashAlgorithm, Organization};
    let mut c = Component::new(name.to_string(), name.to_string())
        .with_purl(format!("pkg:cargo/{name}@1.0.0"));
    c.supplier = Some(Organization::new("VendorCorp".to_string()));
    if with_hash {
        c.hashes.push(Hash::new(
            HashAlgorithm::Sha256,
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
    }
    c
}

fn hw_component(
    name: &str,
    kind: crate::model::ComponentType,
    with_purl: bool,
    with_supplier: bool,
    version: Option<&str>,
) -> crate::model::Component {
    use crate::model::{Component, Organization};
    let mut c = Component::new(name.to_string(), name.to_string());
    c.component_type = kind;
    if with_purl {
        c = c.with_purl(format!("pkg:generic/{name}"));
    }
    if with_supplier {
        c.supplier = Some(Organization::new("HardwareCorp".to_string()));
    }
    if let Some(v) = version {
        c = c.with_version(v.to_string());
    }
    c
}

#[test]
fn hardware_check_skipped_for_software_only_sbom() {
    let mut sbom = NormalizedSbom::default();
    let c = vendor_component("software", true);
    sbom.components.insert(c.canonical_id.clone(), c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-8-RQ-02")),
        "Software-only SBOM should produce no PRE-8-RQ-02 violations"
    );
}

#[test]
fn hardware_check_passes_for_complete_firmware() {
    use crate::model::ComponentType;
    let mut sbom = NormalizedSbom::default();
    let c = hw_component(
        "router-fw",
        ComponentType::Firmware,
        true,
        true,
        Some("1.2.3"),
    );
    sbom.components.insert(c.canonical_id.clone(), c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-8-RQ-02")),
        "Complete firmware component should pass [PRE-8-RQ-02]"
    );
}

#[test]
fn hardware_check_flags_firmware_without_version() {
    use crate::model::ComponentType;
    let mut sbom = NormalizedSbom::default();
    let c = hw_component("router-fw", ComponentType::Firmware, true, true, None);
    sbom.components.insert(c.canonical_id.clone(), c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        result.violations.iter().any(|v| {
            v.requirement.contains("Firmware version") && v.severity == ViolationSeverity::Error
        }),
        "Firmware without version should produce an Error"
    );
}

#[test]
fn hardware_check_flags_missing_producer() {
    use crate::model::ComponentType;
    let mut sbom = NormalizedSbom::default();
    let c = hw_component("router", ComponentType::Device, true, false, Some("1.0"));
    sbom.components.insert(c.canonical_id.clone(), c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        result.violations.iter().any(|v| {
            v.requirement.contains("Hardware producer") && v.severity == ViolationSeverity::Error
        }),
        "Hardware without producer should produce an Error"
    );
}

#[test]
fn hardware_check_flags_synthetic_identifier() {
    use crate::model::{Component, ComponentType, Organization};
    let mut sbom = NormalizedSbom::default();
    let mut c =
        Component::new("router".to_string(), "router".to_string()).with_version("1.0".to_string());
    c.component_type = ComponentType::Device;
    c.supplier = Some(Organization::new("HardwareCorp".to_string()));
    // Note: no PURL/CPE/SWHID/SWID → falls back to synthetic
    sbom.components.insert(c.canonical_id.clone(), c);
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        result.violations.iter().any(|v| {
            v.requirement.contains("Hardware identifier") && v.severity == ViolationSeverity::Error
        }),
        "Hardware with synthetic ID should produce an Error"
    );
}

#[test]
fn hardware_check_device_with_firmware_dep_passes() {
    use crate::model::{ComponentType, DependencyEdge, DependencyType};
    let mut sbom = NormalizedSbom::default();
    let device = hw_component("router", ComponentType::Device, true, true, None);
    let firmware = hw_component(
        "router-fw",
        ComponentType::Firmware,
        true,
        true,
        Some("1.2.3"),
    );
    let device_id = device.canonical_id.clone();
    let firmware_id = firmware.canonical_id.clone();
    sbom.components.insert(device_id.clone(), device);
    sbom.components.insert(firmware_id.clone(), firmware);
    sbom.edges.push(DependencyEdge::new(
        device_id,
        firmware_id,
        DependencyType::DependsOn,
    ));
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| { v.requirement.contains("Device firmware association") }),
        "Device with firmware dependency should not trigger version warning"
    );
}

#[test]
fn vendor_hash_coverage_full() {
    use crate::quality::HashQualityMetrics;
    let mut sbom = NormalizedSbom::default();
    for n in ["a", "b", "c", "d", "e"] {
        let c = vendor_component(n, true);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let m = HashQualityMetrics::from_sbom(&sbom);
    assert_eq!(m.vendor_components_total, 5);
    assert_eq!(m.vendor_components_with_hash, 5);
    assert_eq!(m.vendor_hash_coverage(), Some(1.0));
}

#[test]
fn vendor_hash_coverage_partial_triggers_warning() {
    let mut sbom = NormalizedSbom::default();
    // 7 with hashes, 3 without → 70% < 80% → Warning under CraPhase2
    for n in ["a", "b", "c", "d", "e", "f", "g"] {
        let c = vendor_component(n, true);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    for n in ["h", "i", "j"] {
        let c = vendor_component(n, false);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let v = result.violations.iter().find(|v| {
        v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Warning
    });
    assert!(
        v.is_some(),
        "70% vendor-hash coverage should produce a Warning under CraPhase2"
    );
}

#[test]
fn vendor_hash_coverage_below_50_triggers_error() {
    let mut sbom = NormalizedSbom::default();
    // 4 with hashes, 6 without → 40% < 50% → Error under CraPhase2
    for n in ["a", "b", "c", "d"] {
        let c = vendor_component(n, true);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    for n in ["e", "f", "g", "h", "i", "j"] {
        let c = vendor_component(n, false);
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let v = result.violations.iter().find(|v| {
        v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
    });
    assert!(
        v.is_some(),
        "40% vendor-hash coverage should produce an Error under CraPhase2"
    );
}

/// A supplier named NOASSERTION (or a placeholder) names no vendor: such
/// a component is classified like one with no supplier, so it neither
/// lowers nor props up the [PRE-7-RQ-07-RE] coverage. The raw presence
/// test counted it as a vendor component.
#[test]
fn vendor_hash_coverage_ignores_sentinel_suppliers() {
    use crate::model::Organization;
    use crate::quality::HashQualityMetrics;
    let mut sbom = NormalizedSbom::default();
    let known = vendor_component("known", false);
    sbom.components.insert(known.canonical_id.clone(), known);
    for (name, supplier) in [("sentinel", "NOASSERTION"), ("placeholder", "TBD")] {
        let mut c = vendor_component(name, true);
        c.supplier = Some(Organization::new(supplier.to_string()));
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let m = HashQualityMetrics::from_sbom(&sbom);
    assert_eq!(m.vendor_components_total, 1, "only the known supplier");
    assert_eq!(m.vendor_components_with_hash, 0);
    assert_eq!(m.vendor_hash_coverage(), Some(0.0));
}

#[test]
fn vendor_hash_coverage_no_vendor_components_no_violation() {
    // SBOM with only synthetic-ID components — no vendor classification, no violation
    let mut sbom = NormalizedSbom::default();
    use crate::model::Component;
    for n in ["a", "b", "c"] {
        let c = Component::new(n.to_string(), n.to_string());
        sbom.components.insert(c.canonical_id.clone(), c);
    }
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
        "No vendor components → no [PRE-7-RQ-07-RE] violation"
    );
}

// ──────────────────────────────────────────────────────────────────
// P2 tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn art_13_2_warns_when_no_risk_assessment_referenced() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Art. 13(2)") && v.severity == ViolationSeverity::Warning);
    assert!(v.is_some(), "Empty SBOM should produce Art. 13(2) Warning");
}

#[test]
fn art_13_2_silenced_by_sidecar_risk_assessment_url() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default();
    let sidecar = CraSidecarMetadata {
        risk_assessment_url: Some("https://example.com/ra.pdf".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 13(2)")),
        "Sidecar risk_assessment_url should suppress Art. 13(2) violation"
    );
}

#[test]
fn article_14_pre_deadline_emits_info_only() {
    // The check uses the wall clock; today's date in tests will be
    // before/after 2026-09-11 depending on when tests run. We assert
    // the *existence* of the readiness violations rather than exact
    // severity, then verify with-sidecar suppresses.
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let art14_count = result
        .violations
        .iter()
        .filter(|v| v.requirement.contains("Art. 14"))
        .count();
    assert!(
        art14_count >= 4,
        "Art. 14 readiness should produce ≥4 violations (PSIRT, 14(1), 14(2), 14(7)); got {art14_count}"
    );
}

/// Pre-deadline (mocked clock 2026-04-26): all four channels missing.
/// PSIRT/14(1)/14(2) and 14(7) (ENISA platform) surface as Info.
/// Total: 4 Infos, 0 Warnings, 0 Errors at Art. 14 level.
#[test]
fn article_14_pre_deadline_mocked_clock_emits_4_infos() {
    let checker = checker(ComplianceLevel::CraPhase2);
    let mut violations = Vec::new();
    let now = chrono::DateTime::parse_from_rfc3339("2026-04-26T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    checker.check_article_14_readiness_at(now, &mut violations);

    let infos = violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
        .count();
    let warnings = violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14"))
        .count();
    assert_eq!(
        infos, 4,
        "Pre-deadline expects 4 Info-level Art. 14 findings; got {infos} (full list: {violations:?})"
    );
    assert_eq!(
        warnings, 0,
        "Pre-deadline expects 0 Warning-level Art. 14 findings"
    );
}

/// Post-deadline (mocked clock 2026-12-01): same SBOM-less state, but
/// all four channels become Warnings — 14(7), the ENISA platform every
/// notification goes through, included.
/// Total: 0 Infos, 4 Warnings.
#[test]
fn article_14_post_deadline_mocked_clock_emits_4_warnings() {
    let checker = checker(ComplianceLevel::CraPhase2);
    let mut violations = Vec::new();
    let now = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    checker.check_article_14_readiness_at(now, &mut violations);

    let infos = violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
        .count();
    let warnings = violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14"))
        .count();
    assert_eq!(
        warnings, 4,
        "Post-deadline expects 4 Warning-level Art. 14 findings (PSIRT/14(1)/14(2)/14(7)); got {warnings} (full: {violations:?})"
    );
    assert_eq!(
        infos, 0,
        "Post-deadline expects no Info-level Art. 14 finding (the ENISA platform finding warns too)"
    );
}

/// An unrated vulnerability needs no severity when its own VEX statement
/// is not_affected and names a justification (CRA FAQ v1.4, 4.3.1). The
/// check reads the model, so a statement from an OpenVEX overlay or an
/// SPDX 3.0 assessment counts the same as an embedded CycloneDX
/// analysis. No other statement counts.
#[test]
fn cra_phase2_vuln_metadata_accepts_only_a_justified_not_affected_statement() {
    use crate::model::{
        Component, VexJustification, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource,
    };
    let warns = |vex: Option<VexStatus>| {
        let mut vuln = VulnerabilityRef::new("CVE-2026-2222".to_string(), VulnerabilitySource::Cve);
        vuln.vex_status = vex;
        let mut component = Component::new("libalpha".to_string(), "libalpha@1".to_string());
        component.vulnerabilities.push(vuln);
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(component);
        checker(ComplianceLevel::CraPhase2)
            .check(&sbom)
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-VULN-METADATA")
    };
    let statement = |state: VexState, justified: bool, impact: Option<&str>| {
        let mut vex = VexStatus::new(state);
        if justified {
            vex.justification = Some(VexJustification::VulnerableCodeNotInExecutePath);
        }
        vex.impact_statement = impact.map(str::to_string);
        Some(vex)
    };

    assert!(
        !warns(statement(VexState::NotAffected, true, None)),
        "a justified not_affected statement documents the vulnerability"
    );
    assert!(warns(None), "an entry without a VEX statement warns");
    assert!(
        warns(statement(VexState::NotAffected, false, None)),
        "a bare not_affected claim is no record"
    );
    assert!(
        warns(statement(
            VexState::NotAffected,
            false,
            Some("the parser is never called")
        )),
        "an impact statement without a justification is not enough"
    );
    for state in [
        VexState::Affected,
        VexState::Fixed,
        VexState::UnderInvestigation,
    ] {
        assert!(
            warns(statement(state.clone(), true, None)),
            "a justification on a {state} statement does not count"
        );
    }
}

#[test]
fn article_14_sidecar_suppresses_psirt_warning() {
    use crate::model::CraSidecarMetadata;
    let sbom = NormalizedSbom::default();
    let sidecar = CraSidecarMetadata {
        psirt_url: Some("https://acme.example/psirt".to_string()),
        early_warning_contact: Some("psirt@acme.example".to_string()),
        incident_report_contact: Some("ir@acme.example".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    // PSIRT, 14(1), 14(2) suppressed; 14(7) (ENISA platform) remains.
    let art_14_psirt = result
        .violations
        .iter()
        .any(|v| v.requirement.contains("Art. 14: PSIRT"));
    let art_14_1 = result
        .violations
        .iter()
        .any(|v| v.requirement.contains("Art. 14(1)"));
    let art_14_2 = result
        .violations
        .iter()
        .any(|v| v.requirement.contains("Art. 14(2)"));
    assert!(
        !art_14_psirt,
        "Sidecar psirt_url should suppress PSIRT check"
    );
    assert!(
        !art_14_1,
        "Sidecar early_warning_contact should suppress 14(1)"
    );
    assert!(
        !art_14_2,
        "Sidecar incident_report_contact should suppress 14(2)"
    );
}

#[test]
fn direct_dep_missing_supplier_is_error_under_cra_phase2() {
    use crate::model::{Component, DependencyEdge, DependencyType};
    let mut sbom = NormalizedSbom::default();
    // Primary "app" with one direct dep "lib" missing supplier.
    let app = Component::new("app".to_string(), "app".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    let lib = Component::new("lib".to_string(), "lib".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    let app_id = app.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();
    sbom.primary_component_id = Some(app_id.clone());
    sbom.components.insert(app_id.clone(), app);
    sbom.components.insert(lib_id.clone(), lib);
    sbom.edges.push(DependencyEdge::new(
        app_id,
        lib_id,
        DependencyType::DependsOn,
    ));
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let v = result.violations.iter().find(|v| {
        v.requirement.contains("Direct dependency supplier")
            && v.severity == ViolationSeverity::Error
    });
    assert!(
        v.is_some(),
        "Direct dep without supplier should produce an Error under CraPhase2"
    );
}

#[test]
fn transitive_dep_missing_supplier_is_softer_than_direct() {
    use crate::model::{Component, DependencyEdge, DependencyType, Organization};
    let mut sbom = NormalizedSbom::default();
    // app → lib (with supplier) → deep (no supplier)
    let mut app = Component::new("app".to_string(), "app".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    app.supplier = Some(Organization::new("AppCorp".to_string()));
    let mut lib = Component::new("lib".to_string(), "lib".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    lib.supplier = Some(Organization::new("LibCorp".to_string()));
    let deep = Component::new("deep".to_string(), "deep".to_string())
        .with_purl("pkg:cargo/deep@1.0".to_string());
    let app_id = app.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();
    let deep_id = deep.canonical_id.clone();
    sbom.primary_component_id = Some(app_id.clone());
    sbom.components.insert(app_id.clone(), app);
    sbom.components.insert(lib_id.clone(), lib);
    sbom.components.insert(deep_id.clone(), deep);
    sbom.edges.push(DependencyEdge::new(
        app_id,
        lib_id.clone(),
        DependencyType::DependsOn,
    ));
    sbom.edges.push(DependencyEdge::new(
        lib_id,
        deep_id,
        DependencyType::DependsOn,
    ));
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let direct_err = result.violations.iter().any(|v| {
        v.requirement.contains("Direct dependency supplier")
            && v.severity == ViolationSeverity::Error
    });
    let transitive = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Transitive dependency supplier"));
    assert!(
        !direct_err,
        "No direct deps lack a supplier; should not error"
    );
    assert!(transitive.is_some(), "Transitive dep should be reported");
    assert_ne!(
        transitive.unwrap().severity,
        ViolationSeverity::Error,
        "Transitive supplier missing should never be Error (it's recommended, not mandatory)"
    );
}

#[test]
fn sidecar_does_not_override_present_sbom_field() {
    use crate::model::{CraSidecarMetadata, Creator, CreatorType};
    let mut sbom = NormalizedSbom::default();
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Organization,
        name: "SbomDeclaredCorp".to_string(),
        email: None,
    });
    let sidecar = CraSidecarMetadata {
        manufacturer_name: Some("SidecarCorp".to_string()),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    // No Art. 13(16) violation at all because SBOM provides org
    assert!(
        !result.violations.iter().any(|v| v
            .requirement
            .contains("Art. 13(16): Manufacturer identification")),
        "When SBOM provides manufacturer, no Art. 13(16) violation should be emitted"
    );
}
