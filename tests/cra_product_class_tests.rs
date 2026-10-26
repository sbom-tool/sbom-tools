//! Integration tests for CRA-P3.2 product-class severity calibration.
//!
//! Covers:
//! - Vendor-hash threshold scaling (Default 50%, Important-1/2 80%, Critical 100%)
//! - Vendor-hash severity scaling (Default/Important-1 Warning, Important-2/Critical Error)
//! - EOL severity escalation (Warning → Error at Important-2/Critical)
//! - Article 14 PSIRT severity escalation (Warning → Error at Important-2/Critical)
//! - Annex V Declaration-of-Conformity severity scaling (Info → Warning → Error)
//! - EUCC reference check fires only at ImportantClass2/Critical
//! - Module-attestation check fires only on B+C / H / EUCC routes
//! - Sidecar productClass overrides explicit `with_product_class`
//! - CLI parse_cli aliases

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    Component, ConformityRoute, CraProductClass, CraSidecarMetadata, EolInfo, EolStatus,
    ExternalRefType, ExternalReference, Hash, HashAlgorithm, NormalizedSbom, Organization,
};
use sbom_tools::quality::{ClassCheck, ComplianceLevel, ViolationSeverity};

// --- helpers -----------------------------------------------------------------

/// Build an SBOM with `vendor_total` vendor-supplied components, of which
/// `with_hash` carry a SHA-256 hash. Vendor = supplier set + PURL identifier.
fn vendor_sbom(vendor_total: usize, with_hash: usize) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    for i in 0..vendor_total {
        let mut c = Component::new(format!("c{i}"), format!("c{i}"))
            .with_purl(format!("pkg:cargo/c{i}@1.0"));
        c.supplier = Some(Organization::new(format!("Vendor{i}")));
        if i < with_hash {
            c.hashes
                .push(Hash::new(HashAlgorithm::Sha256, format!("{:064x}", i + 1)));
        }
        sbom.add_component(c);
    }
    sbom
}

fn vendor_hash_violation(
    result: &sbom_tools::quality::ComplianceResult,
) -> Option<ViolationSeverity> {
    result
        .violations
        .iter()
        .find(|v| v.requirement.contains("PRE-7-RQ-07-RE"))
        .map(|v| v.severity)
}

// --- vendor-hash threshold + severity ---------------------------------------

#[test]
fn vendor_hash_default_class_errors_below_50pct() {
    // 4/10 = 40% coverage → below the 50% threshold. The Phase 2 gate
    // (Error below 50%) is the floor; pinning an explicit product class
    // must never weaken it, so this stays an Error (not the class table's
    // Warning) — same verdict as running Phase 2 with no class at all.
    let sbom = vendor_sbom(10, 4);
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    assert_eq!(vendor_hash_violation(&res), Some(ViolationSeverity::Error));
}

#[test]
fn vendor_hash_default_class_keeps_phase2_warning_above_50pct() {
    // 6/10 = 60% — clears Default's 50% class bar, but the Phase 2 gate
    // still warns below 80%; the class must not suppress the phase floor.
    let sbom = vendor_sbom(10, 6);
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    assert_eq!(
        vendor_hash_violation(&res),
        Some(ViolationSeverity::Warning)
    );
}

#[test]
fn vendor_hash_important_class_1_warns_below_80pct() {
    // 6/10 = 60% — fails Important-1's 80% bar; severity is Warning
    let sbom = vendor_sbom(10, 6);
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass1)
        .check(&sbom);
    assert_eq!(
        vendor_hash_violation(&res),
        Some(ViolationSeverity::Warning)
    );
}

#[test]
fn vendor_hash_important_class_2_errors_below_80pct() {
    // 6/10 = 60% — fails Important-2's 80% bar; severity is Error
    let sbom = vendor_sbom(10, 6);
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass2)
        .check(&sbom);
    assert_eq!(vendor_hash_violation(&res), Some(ViolationSeverity::Error));
}

#[test]
fn vendor_hash_critical_demands_100pct() {
    // 9/10 = 90% — fails Critical's 100% bar; severity is Error
    let sbom = vendor_sbom(10, 9);
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    assert_eq!(vendor_hash_violation(&res), Some(ViolationSeverity::Error));

    // 10/10 = 100% — clears
    let sbom2 = vendor_sbom(10, 10);
    let res2 = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom2);
    assert_eq!(vendor_hash_violation(&res2), None);
}

#[test]
fn vendor_hash_no_class_preserves_phase2_two_stage() {
    // No product class set: existing CraPhase2 logic — warn at <80%, error at <50%
    let sbom_warn = vendor_sbom(10, 6); // 60%
    let res_warn = checker(ComplianceLevel::CraPhase2).check(&sbom_warn);
    assert_eq!(
        vendor_hash_violation(&res_warn),
        Some(ViolationSeverity::Warning)
    );

    let sbom_err = vendor_sbom(10, 4); // 40%
    let res_err = checker(ComplianceLevel::CraPhase2).check(&sbom_err);
    assert_eq!(
        vendor_hash_violation(&res_err),
        Some(ViolationSeverity::Error)
    );
}

// --- EOL severity escalation -------------------------------------------------

fn sbom_with_eol_component() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("eol".to_string(), "eol-lib".to_string())
        .with_purl("pkg:cargo/eol-lib@1.0".to_string());
    c.supplier = Some(Organization::new("EolCorp".to_string()));
    c.eol = Some(EolInfo {
        status: EolStatus::EndOfLife,
        product: "eol-lib".to_string(),
        cycle: "1".to_string(),
        eol_date: None,
        support_end_date: None,
        is_lts: false,
        latest_in_cycle: None,
        latest_release_date: None,
        days_until_eol: None,
    });
    sbom.add_component(c);
    sbom
}

#[test]
fn eol_severity_escalates_to_error_at_important_class_2() {
    let sbom = sbom_with_eol_component();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass2)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("lifecycle management"))
        .expect("EOL component violation expected");
    assert_eq!(v.severity, ViolationSeverity::Error);
}

#[test]
fn eol_severity_remains_warning_at_default_class() {
    let sbom = sbom_with_eol_component();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("lifecycle management"))
        .expect("EOL component violation expected");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

// --- Annex V DoC severity scaling -------------------------------------------

#[test]
fn doc_reference_severity_scales_with_class() {
    let sbom = NormalizedSbom::default();

    let res_default = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    let v = res_default
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex V:"))
        .expect("Annex V DoC violation expected");
    assert_eq!(v.severity, ViolationSeverity::Info);

    let res_imp1 = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass1)
        .check(&sbom);
    let v = res_imp1
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex V:"))
        .expect("Annex V DoC violation expected");
    assert_eq!(v.severity, ViolationSeverity::Warning);

    let res_critical = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    let v = res_critical
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex V:"))
        .expect("Annex V DoC violation expected");
    assert_eq!(v.severity, ViolationSeverity::Error);
}

// --- EUCC reference check ----------------------------------------------------

#[test]
fn eucc_reference_check_skipped_at_default_and_important_1() {
    let sbom = NormalizedSbom::default();
    for class in [CraProductClass::Default, CraProductClass::ImportantClass1] {
        let res = checker(ComplianceLevel::CraPhase2)
            .with_product_class(class)
            .check(&sbom);
        assert!(
            !res.violations
                .iter()
                .any(|v| v.requirement.contains("EUCC")),
            "EUCC check should be skipped at {class:?}"
        );
    }
}

#[test]
fn eucc_reference_check_fires_info_at_important_class_2() {
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass2)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("EUCC"))
        .expect("EUCC violation expected at Important-2");
    assert_eq!(v.severity, ViolationSeverity::Info);
}

#[test]
fn eucc_reference_check_fires_error_at_critical() {
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.requirement.contains("EUCC"))
        .expect("EUCC violation expected at Critical");
    assert_eq!(v.severity, ViolationSeverity::Error);
}

#[test]
fn eucc_reference_satisfied_by_certification_with_eucc_url() {
    let mut sbom = NormalizedSbom::default();
    let mut c = Component::new("app".to_string(), "app".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    c.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::Certification,
        url: "https://eucc.example.eu/cert/123".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(c);

    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.requirement.contains("EUCC")),
        "EUCC reference satisfied by EUCC certification URL"
    );
}

// --- Module attestation check ------------------------------------------------

#[test]
fn module_attestation_skipped_at_default_class() {
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-VIII"),
        "Module attestation check should be skipped at Default"
    );
}

#[test]
fn module_attestation_skipped_for_module_a_route() {
    // Important-1 with explicit Module A → skip
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass1),
        conformity_assessment_route: Some(ConformityRoute::ModuleA),
        ..Default::default()
    };
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !res.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-ANNEX-VIII"),
        "Module attestation check should be skipped on Module A route"
    );
}

#[test]
fn module_attestation_fires_warning_at_important_1_module_bc() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass1),
        conformity_assessment_route: Some(ConformityRoute::ModuleBC),
        ..Default::default()
    };
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.rule_id == "SBOM-CRA-ANNEX-VIII")
        .expect("Module attestation violation expected");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

#[test]
fn module_attestation_fires_error_at_critical_with_default_route() {
    // Critical implies EUCC by default — non-Module-A → check fires
    let sbom = NormalizedSbom::default();
    let res = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .check(&sbom);
    let v = res
        .violations
        .iter()
        .find(|v| v.rule_id == "SBOM-CRA-ANNEX-VIII")
        .expect("Module attestation violation expected");
    assert_eq!(v.severity, ViolationSeverity::Error);
}

// --- sidecar-vs-explicit precedence -----------------------------------------

#[test]
fn sidecar_product_class_overrides_explicit_with_product_class() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::Critical),
        ..Default::default()
    };
    let checker = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Default)
        .with_sidecar(sidecar);
    assert_eq!(checker.effective_product_class(), CraProductClass::Critical);
}

#[test]
fn explicit_with_product_class_used_when_sidecar_lacks_class() {
    let sidecar = CraSidecarMetadata {
        manufacturer_name: Some("Mfr".to_string()),
        ..Default::default()
    };
    let checker = checker(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass1)
        .with_sidecar(sidecar);
    assert_eq!(
        checker.effective_product_class(),
        CraProductClass::ImportantClass1
    );
}

#[test]
fn no_class_falls_back_to_default_class() {
    let checker = checker(ComplianceLevel::CraPhase2);
    assert_eq!(checker.effective_product_class(), CraProductClass::Default);
    assert!(!checker.has_explicit_product_class());
}

#[test]
fn class_severity_table_matches_plan() {
    let mk = |c| checker(ComplianceLevel::CraPhase2).with_product_class(c);
    use ClassCheck as K;
    use CraProductClass as C;
    use ViolationSeverity as S;

    // Vendor hash
    assert_eq!(
        mk(C::Default).class_severity(K::VendorHashCoverage),
        Some(S::Warning)
    );
    assert_eq!(
        mk(C::ImportantClass1).class_severity(K::VendorHashCoverage),
        Some(S::Warning)
    );
    assert_eq!(
        mk(C::ImportantClass2).class_severity(K::VendorHashCoverage),
        Some(S::Error)
    );
    assert_eq!(
        mk(C::Critical).class_severity(K::VendorHashCoverage),
        Some(S::Error)
    );
    // EOL
    assert_eq!(
        mk(C::Default).class_severity(K::EolComponents),
        Some(S::Warning)
    );
    assert_eq!(
        mk(C::Critical).class_severity(K::EolComponents),
        Some(S::Error)
    );
    // DoC
    assert_eq!(
        mk(C::Default).class_severity(K::DocReference),
        Some(S::Info)
    );
    assert_eq!(
        mk(C::ImportantClass1).class_severity(K::DocReference),
        Some(S::Warning)
    );
    assert_eq!(
        mk(C::Critical).class_severity(K::DocReference),
        Some(S::Error)
    );
    // EUCC
    assert_eq!(mk(C::Default).class_severity(K::EuccReference), None);
    assert_eq!(
        mk(C::ImportantClass1).class_severity(K::EuccReference),
        None
    );
    assert_eq!(
        mk(C::ImportantClass2).class_severity(K::EuccReference),
        Some(S::Info)
    );
    assert_eq!(
        mk(C::Critical).class_severity(K::EuccReference),
        Some(S::Error)
    );
    // Module attestation
    assert_eq!(mk(C::Default).class_severity(K::ModuleAttestation), None);
    assert_eq!(
        mk(C::ImportantClass1).class_severity(K::ModuleAttestation),
        Some(S::Warning)
    );
    assert_eq!(
        mk(C::Critical).class_severity(K::ModuleAttestation),
        Some(S::Error)
    );
    // PSIRT
    assert_eq!(
        mk(C::ImportantClass2).class_severity(K::Psirt),
        Some(S::Error)
    );
}

#[test]
fn vendor_hash_threshold_table_matches_plan() {
    let mk = |c| checker(ComplianceLevel::CraPhase2).with_product_class(c);
    assert!((mk(CraProductClass::Default).vendor_hash_threshold() - 0.50).abs() < 1e-9);
    assert!((mk(CraProductClass::ImportantClass1).vendor_hash_threshold() - 0.80).abs() < 1e-9);
    assert!((mk(CraProductClass::ImportantClass2).vendor_hash_threshold() - 0.80).abs() < 1e-9);
    assert!((mk(CraProductClass::Critical).vendor_hash_threshold() - 1.00).abs() < 1e-9);
}

#[test]
fn effective_route_falls_back_to_class_default() {
    let mk = |c| checker(ComplianceLevel::CraPhase2).with_product_class(c);
    assert_eq!(
        mk(CraProductClass::Default).effective_route(),
        ConformityRoute::ModuleA
    );
    assert_eq!(
        mk(CraProductClass::ImportantClass1).effective_route(),
        ConformityRoute::ModuleA
    );
    assert_eq!(
        mk(CraProductClass::ImportantClass2).effective_route(),
        ConformityRoute::ModuleBC
    );
    assert_eq!(
        mk(CraProductClass::Critical).effective_route(),
        ConformityRoute::Eucc
    );
}

#[test]
fn effective_route_sidecar_wins() {
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::Critical),
        conformity_assessment_route: Some(ConformityRoute::ModuleH),
        ..Default::default()
    };
    let checker = checker(ComplianceLevel::CraPhase2).with_sidecar(sidecar);
    assert_eq!(checker.effective_route(), ConformityRoute::ModuleH);
}
