//! Golden-fixture regression tests (CRA-P5.2).
//!
//! Each fixture pins an expected violation profile against
//! `ComplianceChecker` so future changes that flip a check into / out of
//! the active set fail loudly. The expectations are deliberately broad
//! (presence/absence of a CRA Article, severity classes) rather than
//! exact violation count, so that adding more fine-grained checks does
//! not require updating every fixture in lockstep.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cra")
}

#[test]
fn cra_compliant_cdx_with_sidecar_has_no_errors_at_phase2() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    assert!(
        sbom_path.exists(),
        "fixture missing: {}",
        sbom_path.display()
    );
    assert!(
        sidecar_path.exists(),
        "sidecar missing: {}",
        sidecar_path.display()
    );

    let parsed = parse_sbom(&sbom_path).expect("parse compliant fixture");
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).expect("load sidecar");

    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should produce no Errors at CraPhase2; got: {errors:?}"
    );
}

#[test]
fn cra_compliant_cdx_passes_bsi_with_no_errors() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let parsed = parse_sbom(&sbom_path).expect("parse compliant fixture");
    let result = checker(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should pass BSI TR-03183-2 §5 with no Errors; got: {errors:?}"
    );
}

#[test]
fn cra_compliant_passes_oss_steward_floor() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    let result = checker(ComplianceLevel::CraOssSteward)
        .with_sidecar(sidecar)
        .check(&parsed);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should pass OSS-steward floor with no Errors; got: {errors:?}"
    );
}

#[test]
fn noncompliant_no_manufacturer_fires_art_13_16_or_supplier_check() {
    let sbom_path = fixtures_dir().join("cra-noncompliant-no-manufacturer.cdx.json");
    assert!(sbom_path.exists());
    let parsed = parse_sbom(&sbom_path).expect("parse fixture");
    let result = checker(ComplianceLevel::CraPhase2).check(&parsed);

    let manufacturer_finding = result.violations.iter().any(|v| {
        v.requirement.contains("Art. 13(16)")
            || v.requirement.contains("Manufacturer")
            || v.requirement.contains("manufacturer")
            || v.requirement.contains("Supplier")
            || v.requirement.contains("supplier")
    });
    assert!(
        manufacturer_finding,
        "no-manufacturer fixture should fire either Art. 13(16) or supplier-tracking violation"
    );
}

#[test]
fn noncompliant_weak_hashes_fires_at_bsi_or_phase2() {
    // BSI TR-03183-2 v2.1.0 §5.2.2 requires the SHA-512 hash of the
    // deployable component; the weak-hashes fixture must fire the hash rule
    // itself (SBOM-BSI-TR-03183-2-5-4), not just any BSI violation.
    let sbom_path = fixtures_dir().join("cra-noncompliant-weak-hashes.cdx.json");
    let parsed = parse_sbom(&sbom_path).expect("parse fixture");

    let bsi = checker(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let bsi_hash_finding = bsi.violations.iter().any(|v| {
        v.rule_id == "SBOM-BSI-TR-03183-2-5-4" || v.rule_id == "SBOM-BSI-TR-03183-2-5-4-MISSING"
    });
    assert!(
        bsi_hash_finding,
        "weak-hashes fixture must fire the BSI SHA-512 hash rule; \
         got requirements: {:?}",
        bsi.violations
            .iter()
            .map(|v| &v.requirement)
            .collect::<Vec<_>>()
    );
}

#[test]
fn vendor_hash_carry_through_satisfied_by_compliant_fixture() {
    // The compliant fixture has SHA-256 on every vendor component. Under
    // CraPhase2 + ImportantClass2 (80% threshold, Error), no vendor-hash
    // violation should fire.
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let mut sc = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    sc.product_class = Some(sbom_tools::model::CraProductClass::ImportantClass2);
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sc)
        .check(&parsed);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
        "Compliant fixture must clear vendor-hash carry-through at Important-2"
    );
}

#[test]
fn conformity_summary_present_when_class_pinned_via_sidecar() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let sc = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sc)
        .check(&parsed);
    assert!(
        result.conformity_summary.is_some(),
        "Sidecar pins productClass=important-class-1 → summary expected"
    );
    let summary = result.conformity_summary.unwrap();
    assert_eq!(
        summary.product_class,
        sbom_tools::model::CraProductClass::ImportantClass1
    );
}

/// Canonical SPDX 3.0.1 (flat @graph with a shared CreationInfo node that
/// elements reference by string) is the ONLY SPDX shape the BSI §4 gate
/// accepts — it must parse and clear the gate end-to-end. It used to
/// hard-fail the parse ("invalid type: string, expected struct
/// Spdx3CreationInfo"), so no canonical SPDX document could obtain a BSI
/// verdict at all.
#[test]
fn spdx3_shared_creationinfo_fixture_passes_bsi_gate_with_no_errors() {
    let sbom_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/spdx3/shared-creationinfo.spdx3.json");
    let parsed = parse_sbom(&sbom_path).expect("canonical SPDX 3.0.1 must parse");
    assert_eq!(
        parsed.document.spec_version, "3.0.1",
        "specVersion must resolve through the shared CreationInfo node"
    );

    let result = checker(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "canonical SPDX 3.0.1 fixture must produce no BSI Errors; got: {errors:?}"
    );
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS"),
        "declared relationship completeness must satisfy the §5.2.2 completeness warning"
    );
}
