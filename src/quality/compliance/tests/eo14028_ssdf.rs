//! EO 14028 and NIST SSDF checks.

use super::*;

/// EO 14028 §4(e) requires Supplier Name (an NTIA element); a missing
/// supplier must be a gating Error, not a sub-threshold Warning.
#[test]
fn eo14028_gates_on_missing_supplier() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    // Component with version + id but NO supplier.
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::Eo14028).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-EO14028-SUPPLIER"
                && v.severity == ViolationSeverity::Error),
        "missing supplier must be a gating Error under EO 14028"
    );
}

/// The EO 14028 §4(e) practice incorporates the NTIA minimum elements, which include the
/// creation timestamp.
#[test]
fn eo14028_gates_on_missing_timestamp() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.created = chrono::DateTime::UNIX_EPOCH;
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::Eo14028).check(&sbom);
    assert!(
        r.violations.iter().any(
            |v| v.rule_id == "SBOM-EO14028-TIMESTAMP" && v.severity == ViolationSeverity::Error
        ),
        "missing timestamp must fail EO 14028"
    );

    let mut with_ts = NormalizedSbom::new(DocumentMetadata::default());
    with_ts.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::Eo14028).check(&with_ts);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-EO14028-TIMESTAMP")
    );
}

/// SPDX 2.2 is an NTIA-accepted format; the EO 14028 machine-readable
/// gate must not error on it (SPDX 2.1 and older still fail).
#[test]
fn eo14028_accepts_spdx_2_2() {
    use crate::model::{DocumentMetadata, NormalizedSbom, SbomFormat};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.format = SbomFormat::Spdx;
    sbom.document.spec_version = "2.2".to_string();
    let r = checker(ComplianceLevel::Eo14028).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-EO14028-FORMAT"),
        "SPDX 2.2 is machine-readable under EO 14028"
    );

    sbom.document.spec_version = "2.1".to_string();
    let r = checker(ComplianceLevel::Eo14028).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-EO14028-FORMAT"),
        "SPDX 2.1 still fails the machine-readable gate"
    );
}

/// SWHID-only components carry a valid unique identifier; EO 14028 and
/// SSDF identifier checks must not flag them.
#[test]
fn eo14028_and_ssdf_accept_swhid_identifiers() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, SwhidObject};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut c =
        Component::new("lib".to_string(), "lib@1".to_string()).with_version("1.0".to_string());
    c.identifiers
        .swhid
        .push(SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap());
    sbom.add_component(c);
    let r = checker(ComplianceLevel::Eo14028).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-EO14028-IDENTIFIER"),
        "SWHID satisfies the EO 14028 identifier element"
    );
    let r = checker(ComplianceLevel::NistSsdf).check(&sbom);
    assert!(
        !r.violations.iter().any(|v| v.rule_id == "SBOM-SSDF-RV1"),
        "SWHID satisfies the SSDF RV.1 identifier check"
    );
}

#[test]
fn test_nist_ssdf_empty_sbom() {
    let sbom = NormalizedSbom::default();
    let checker = checker(ComplianceLevel::NistSsdf);
    let result = checker.check(&sbom);
    // Empty SBOM should have at least a creator violation
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PS.1"))
    );
}

#[test]
fn test_eo14028_empty_sbom() {
    let sbom = NormalizedSbom::default();
    let checker = checker(ComplianceLevel::Eo14028);
    let result = checker.check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.requirement.contains("EO 14028"))
    );
}
