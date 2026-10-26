//! Integration tests for CRA-P3.3 Article 24 open-source steward profile.
//!
//! Article 24 stewards (Eclipse Foundation, Apache, Linux Foundation, etc.)
//! supply software under the CRA but with reduced obligations: SBOM,
//! vulnerability handling process, and CVD policy are still required;
//! manufacturer email, EU DoC, conformity-assessment module, and Article 14
//! reporting channels are NOT enforced.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    Component, CraSidecarMetadata, ExternalRefType, ExternalReference, NormalizedSbom,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity};

fn empty_sbom() -> NormalizedSbom {
    NormalizedSbom::default()
}

fn sbom_with_security_contact() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("foo".to_string(), "foo".to_string())
        .with_purl("pkg:cargo/foo@1.0".to_string());
    c.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::SecurityContact,
        url: "https://example.org/security".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(c);
    sbom
}

fn sbom_with_advisories() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("foo".to_string(), "foo".to_string())
        .with_purl("pkg:cargo/foo@1.0".to_string());
    c.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::Advisories,
        url: "https://example.org/advisories".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(c);
    sbom
}

#[test]
fn oss_steward_is_cra_aligned() {
    assert!(ComplianceLevel::CraOssSteward.is_cra());
    assert_eq!(ComplianceLevel::CraOssSteward.cra_phase(), None);
}

#[test]
fn oss_steward_listed_in_all() {
    assert!(ComplianceLevel::all().contains(&ComplianceLevel::CraOssSteward));
}

#[test]
fn oss_steward_short_name_fits_compact_label() {
    assert!(ComplianceLevel::CraOssSteward.short_name().len() <= 8);
}

#[test]
fn oss_steward_does_not_require_manufacturer_email() {
    // Eclipse-Foundation-style SBOM: no manufacturer email, no DoC reference,
    // no Article 14 channels — but DOES have a SecurityContact for the
    // vulnerability-handling process.
    let sbom = sbom_with_security_contact();

    let res_steward = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    let res_phase2 = checker(ComplianceLevel::CraPhase2).check(&sbom);

    // Steward profile: should not fire manufacturer-identification Art. 13(16)
    assert!(
        !res_steward.violations.iter().any(
            |v| v.requirement.contains("Art. 13(16)") || v.requirement.contains("Manufacturer")
        ),
        "OSS steward must not fire manufacturer-email checks"
    );

    // Steward profile: should not fire Article 14 reporting checks
    assert!(
        !res_steward
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14")),
        "OSS steward must not fire Article 14 reporting checks"
    );

    // Steward profile: should not fire EU DoC (Annex V) check
    assert!(
        !res_steward
            .violations
            .iter()
            .any(|v| v.requirement.contains("Annex V:")
                || v.requirement.contains("Declaration of Conformity")),
        "OSS steward must not fire EU DoC checks"
    );

    // Steward profile: should not fire vendor-hash carry-through ([PRE-7-RQ-07-RE])
    assert!(
        !res_steward
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
        "OSS steward must not fire vendor-hash carry-through"
    );

    // Same SBOM under CraPhase2: SHOULD fire at least one of the
    // manufacturer-only checks the steward profile relaxes.
    let phase2_has_manufacturer_only = res_phase2.violations.iter().any(|v| {
        v.requirement.contains("Art. 14")
            || v.requirement.contains("Annex V:")
            || v.requirement.contains("PRE-7-RQ-07-RE")
    });
    assert!(
        phase2_has_manufacturer_only,
        "Sanity: same SBOM under CraPhase2 should still surface manufacturer-only checks"
    );
}

#[test]
fn oss_steward_requires_vulnerability_handling_process() {
    // Bare SBOM with no SecurityContact / Advisories / sidecar PSIRT URL:
    // steward floor must fire an Error.
    let sbom = empty_sbom();
    let res = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("Vulnerability-handling process"))
        .expect("Steward must require vuln-handling process");
    assert_eq!(v.severity, ViolationSeverity::Error);
}

#[test]
fn oss_steward_vuln_handling_satisfied_by_security_contact() {
    let sbom = sbom_with_security_contact();
    let res = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("Vulnerability-handling process")),
        "SecurityContact external ref satisfies steward vuln-handling requirement"
    );
}

#[test]
fn oss_steward_vuln_handling_satisfied_by_sidecar_psirt() {
    let sbom = empty_sbom();
    let sidecar = CraSidecarMetadata {
        psirt_url: Some("https://example.org/psirt".to_string()),
        ..Default::default()
    };
    let res = checker(ComplianceLevel::CraOssSteward)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("Vulnerability-handling process")),
        "Sidecar psirt_url satisfies steward vuln-handling requirement"
    );
}

#[test]
fn oss_steward_recommends_cvd_policy_as_warning() {
    // No Advisories ref, no sidecar coordinated_disclosure_policy_url
    let sbom = sbom_with_security_contact();
    let res = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex I Part II (5)"))
        .expect("Steward should warn on missing CVD policy");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

#[test]
fn oss_steward_cvd_satisfied_by_advisories_ref() {
    let sbom = sbom_with_advisories();
    let res = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part II (5)")),
        "Advisories external ref satisfies CVD policy requirement"
    );
}

#[test]
fn oss_steward_cvd_satisfied_by_sidecar_policy_url() {
    let sbom = sbom_with_security_contact();
    let sidecar = CraSidecarMetadata {
        coordinated_disclosure_policy_url: Some(
            "https://example.org/security/cvd-policy".to_string(),
        ),
        ..Default::default()
    };
    let res = checker(ComplianceLevel::CraOssSteward)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part II (5)")),
        "Sidecar coordinated_disclosure_policy_url satisfies CVD requirement"
    );
}

#[test]
fn oss_steward_does_not_run_hardware_check() {
    // A "device" component with no producer/version: under CraPhase2 this
    // would fire the [PRE-8-RQ-02] hardware check. Under steward, it's
    // skipped entirely.
    let mut sbom = sbom_with_security_contact();
    let mut device = Component::new("hw".to_string(), "router-mcu".to_string());
    device.component_type = sbom_tools::model::ComponentType::Device;
    sbom.add_component(device);

    let res = checker(ComplianceLevel::CraOssSteward).check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("PRE-8-RQ-02")),
        "OSS steward must not run hardware [PRE-8-RQ-02] checks"
    );
}

#[test]
fn sidecar_is_oss_steward_field_roundtrips() {
    let original = CraSidecarMetadata {
        is_oss_steward: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("is_oss_steward") || json.contains("isOssSteward"));
    let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_oss_steward);

    // Default value (false) must NOT serialize (skip_serializing_if)
    let default_sidecar = CraSidecarMetadata::default();
    let default_json = serde_json::to_string(&default_sidecar).unwrap();
    assert!(
        !default_json.contains("is_oss_steward") && !default_json.contains("isOssSteward"),
        "is_oss_steward=false should be skipped during serialization"
    );
}
