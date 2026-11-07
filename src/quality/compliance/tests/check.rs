//! Tests of `ComplianceChecker::check()` itself: applicability and the
//! score, the elements a standard checks, the remediation, field and
//! standard references it completes from the registry, and the clock.

use super::*;

/// A readiness standard that never evaluated the SBOM must expose
/// NotApplicable and no score — is_compliant stays true by contract.
#[test]
fn not_applicable_result_has_no_score() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::EuAiAct).check(&sbom);
    assert!(!r.is_applicable(), "non-AI SBOM must be NotApplicable");
    assert!(
        matches!(r.applicability, Applicability::NotApplicable(_)),
        "applicability must carry the reason"
    );
    assert_eq!(r.score(), None, "unevaluated SBOMs have no score");
    assert!(r.is_compliant, "the N/A is_compliant contract is preserved");

    // An applicable run keeps a real score.
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(r.is_applicable());
    assert!(r.score().is_some());
}

/// The elements a standard checks: the document, plus the components in
/// its scope.
#[test]
fn elements_checked_follow_the_standards_scope() {
    use crate::model::{
        Component, ComponentType, CryptoAssetType, CryptoProperties, DocumentMetadata, MlModelInfo,
        NormalizedSbom,
    };
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    for name in ["a", "b"] {
        sbom.add_component(
            Component::new(name.to_string(), format!("{name}-ref"))
                .with_version("1.0".to_string())
                .with_purl(format!("pkg:npm/{name}@1.0")),
        );
    }
    let mut file = Component::new("README".to_string(), "file-ref".to_string());
    file.component_type = ComponentType::File;
    sbom.add_component(file);
    let mut aes = Component::new("AES-256-GCM".to_string(), "aes-ref".to_string());
    aes.component_type = ComponentType::Cryptographic;
    aes.crypto_properties = Some(CryptoProperties::new(CryptoAssetType::Algorithm));
    sbom.add_component(aes);
    let mut model = Component::new("model".to_string(), "model-ref".to_string());
    model.component_type = ComponentType::MachineLearningModel;
    model.ml_model = Some(MlModelInfo::default());
    sbom.add_component(model);

    let checked = |level| checker(level).check(&sbom).elements_checked;
    // The document, the two libraries and the (package-scoped) model.
    assert_eq!(checked(ComplianceLevel::NtiaMinimum), 4);
    assert_eq!(checked(ComplianceLevel::CraPhase2), 4);
    assert_eq!(checked(ComplianceLevel::Fsct), 4);
    // The document and the algorithm.
    assert_eq!(checked(ComplianceLevel::Cnsa2), 2);
    assert_eq!(checked(ComplianceLevel::NistPqc), 2);
    // The document and the model.
    assert_eq!(checked(ComplianceLevel::EuAiAct), 2);
    assert_eq!(checked(ComplianceLevel::BsiSbomForAi), 2);
    // The document alone.
    assert_eq!(checked(ComplianceLevel::EuccSubstantial), 1);
    // A result built by hand checked the document.
    assert_eq!(
        ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new()).elements_checked,
        1
    );
    assert_eq!(
        ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new())
            .with_elements_checked(0)
            .elements_checked,
        1,
        "a standard always checks the document"
    );
}

/// A large SBOM with one gap: the old formula halved the score of a
/// 500,000-component SBOM for one finding.
#[test]
fn one_gap_in_a_large_sbom_barely_moves_the_score() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let violation = |severity| Violation {
        severity,
        category: ViolationCategory::SupplierInfo,
        message: "x".to_string(),
        element: Some("lib".to_string()),
        requirement: "x".to_string(),
        rule_id: "SBOM-NTIA-SUPPLIER",
        component_id: Some("pkg:npm/lib@1.0".to_string()),
        counts: None,
        standard_refs: Cow::Borrowed(&[]),
        remediation: None,
        finding_detail: None,
        severity_override: None,
        deadline: None,
        field: None,
        observed: None,
    };
    let large = |severity| {
        ComplianceResult::new(ComplianceLevel::NtiaMinimum, vec![violation(severity)])
            .with_elements_checked(500_001)
    };
    assert_eq!(large(ViolationSeverity::Warning).score(), Some(99));
    assert_eq!(large(ViolationSeverity::Error).score(), Some(49));

    // Through the checker: a clean SBOM scores 100, and the component
    // count normalises its findings.
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::Minimum).check(&sbom);
    assert_eq!(r.elements_checked, 2);
    assert_eq!(
        r.score(),
        Some(compliance_score(
            r.violations
                .iter()
                .filter(|v| v.severity == ViolationSeverity::Error)
                .map(Violation::failed_checks)
                .sum(),
            r.violations
                .iter()
                .filter(|v| v.severity == ViolationSeverity::Warning)
                .map(Violation::failed_checks)
                .sum(),
            2,
        ))
    );
}

/// The evaluation instant the remediation tests pin the checker to.
fn remediation_test_clock() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid RFC 3339 instant")
        .with_timezone(&chrono::Utc)
}

/// An NTIA run over a one-component SBOM of the given format whose
/// component names no supplier, returning the SBOM-NTIA-SUPPLIER finding.
fn ntia_supplier_finding(format: SbomFormat, spec_version: &str) -> Violation {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.format = format;
    sbom.document.spec_version = spec_version.to_string();
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    ComplianceChecker::new(ComplianceLevel::NtiaMinimum)
        .with_as_of(remediation_test_clock())
        .check(&sbom)
        .violations
        .into_iter()
        .find(|v| v.rule_id == "SBOM-NTIA-SUPPLIER")
        .expect("a supplier-less component fails the NTIA supplier element")
}

/// Each violation's remediation names the fields of the format the SBOM
/// was written in: SPDX inputs used to get CycloneDX field advice.
#[test]
fn remediation_follows_the_input_format() {
    for (format, spec_version, own, foreign) in [
        (
            SbomFormat::CycloneDx,
            "1.6",
            "CycloneDX: set components[].supplier.name",
            ["packages[].supplier", "suppliedBy"],
        ),
        (
            SbomFormat::Spdx,
            "2.3",
            "SPDX 2.x: set packages[].supplier",
            ["components[].supplier.name", "suppliedBy"],
        ),
        (
            SbomFormat::Spdx,
            "3.0.1",
            "SPDX 3.0: set suppliedBy",
            ["components[].supplier.name", "packages[].supplier"],
        ),
    ] {
        let v = ntia_supplier_finding(format.clone(), spec_version);
        let text = v
            .remediation
            .as_deref()
            .expect("check() stamps remediation");
        assert!(
            text.contains(own),
            "{format} {spec_version}: expected {own:?} in {text:?}"
        );
        for field in foreign {
            assert!(
                !text.contains(field),
                "{format} {spec_version}: {field:?} belongs to another format: {text:?}"
            );
        }
        assert_eq!(v.remediation_guidance(), text);
    }
}

/// JSON carries `remediation` on every violation and `help_uri` from the
/// first standard reference that has a URL; `help_uri` is omitted when
/// no reference has one.
#[test]
fn violation_json_carries_remediation_and_help_uri() {
    let v = ntia_supplier_finding(SbomFormat::CycloneDx, "1.6");
    let json = serde_json::to_value(&v).expect("violation serializes");
    assert_eq!(
        json["remediation"].as_str(),
        v.remediation.as_deref(),
        "remediation is serialized verbatim"
    );
    let first_uri = v.standard_refs.iter().find_map(|r| r.help_uri.as_deref());
    assert!(first_uri.is_some(), "NTIA references carry a URL");
    assert_eq!(json["help_uri"].as_str(), first_uri);

    // prEN 40000-1-3 has no public URL, so a prEN-only rule links the
    // page of its family, the CRA regulation, as `sbom-tools rules` and
    // the SARIF rule do — and still has a remediation.
    let hardware = Violation {
        severity: ViolationSeverity::Error,
        category: ViolationCategory::SupplierInfo,
        message: "m".to_string(),
        element: None,
        requirement: "r".to_string(),
        rule_id: "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
        component_id: None,
        counts: None,
        standard_refs: rule_meta("SBOM-CRA-PRE-8-RQ-02-PRODUCER")
            .expect("registered rule")
            .refs
            .iter()
            .map(|(kind, id)| StandardRef::new(*kind, *id))
            .collect(),
        remediation: None,
        finding_detail: None,
        severity_override: None,
        deadline: None,
        field: None,
        observed: None,
    };
    let json = serde_json::to_value(&hardware).expect("violation serializes");
    assert_eq!(
        json["help_uri"], "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng",
        "no reference URL, the family's page: {json}"
    );
    assert_eq!(
        json["help_uri"].as_str(),
        rule_catalog_entry("SBOM-CRA-PRE-8-RQ-02-PRODUCER")
            .and_then(|entry| entry.help_uri)
            .as_deref(),
        "the rule catalogue's help URI"
    );
    assert!(
        json["remediation"]
            .as_str()
            .is_some_and(|r| r.contains("hardware component")),
        "unstamped violations still serialize the registry remediation: {json}"
    );
}

/// Payloads written before `remediation` and `help_uri` existed still
/// deserialize; a payload that carries `remediation` keeps it.
#[test]
fn remediation_payloads_round_trip_and_old_payloads_deserialize() {
    let v = ntia_supplier_finding(SbomFormat::Spdx, "2.3");
    let mut json = serde_json::to_value(&v).expect("violation serializes");
    let back: Violation =
        serde_json::from_value(json.clone()).expect("current payload deserializes");
    assert_eq!(back.remediation, v.remediation);

    let object = json.as_object_mut().expect("violation is a JSON object");
    object.remove("remediation");
    object.remove("help_uri");
    let old: Violation = serde_json::from_value(json).expect("old payload deserializes");
    assert_eq!(old.remediation, None);
    assert_eq!(old.rule_id, "SBOM-NTIA-SUPPLIER");
    assert!(
        !old.remediation_guidance().is_empty(),
        "an old payload still renders registry remediation"
    );
}

/// `finding_detail` is written right after `component_id`, only when
/// set, and round-trips; payloads without it deserialize to `None`.
#[test]
fn finding_detail_is_written_only_when_set_and_round_trips() {
    let mut v = ntia_supplier_finding(SbomFormat::CycloneDx, "1.6");
    let json = serde_json::to_value(&v).expect("violation serializes");
    assert!(
        json.get("finding_detail").is_none(),
        "omitted when None: {json}"
    );
    let old: Violation =
        serde_json::from_value(json).expect("payload without the field deserializes");
    assert_eq!(old.finding_detail, None);

    v.finding_detail = Some("CVE-2026-0001".to_string());
    let text = serde_json::to_string(&v).expect("violation serializes");
    assert!(
        text.contains(r#""component_id":"pkg:cargo/lib@1.0","finding_detail":"CVE-2026-0001","#),
        "{text}"
    );
    let back: Violation = serde_json::from_str(&text).expect("payload deserializes");
    assert_eq!(back.finding_detail.as_deref(), Some("CVE-2026-0001"));
}

/// A pinned evaluation clock makes deadline-sensitive checks
/// deterministic: Art. 14 severity flips across 2026-09-11, and EUCC
/// certificate expiry evaluates against the pinned instant.
#[test]
fn as_of_clock_pins_deadline_checks() {
    use crate::model::{Component, CraSidecarMetadata, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let ts = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };

    // Art. 14: Info before the 2026-09-11 application date, stronger after.
    let art14_severity = |as_of: &str| {
        ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_as_of(ts(as_of))
            .check(&sbom)
            .violations
            .iter()
            .find(|v| v.requirement.contains("Art. 14(2)(a)"))
            .map(|v| v.severity)
    };
    assert_eq!(
        art14_severity("2026-01-01T00:00:00Z"),
        Some(ViolationSeverity::Info),
        "pre-deadline Art. 14 findings are informational"
    );
    assert_eq!(
        art14_severity("2027-01-01T00:00:00Z"),
        Some(ViolationSeverity::Warning),
        "post-deadline Art. 14 findings escalate"
    );

    // EUCC certificate expiry against the pinned clock.
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-1".to_string()),
        eucc_target_of_evaluation: Some("TOE-1".to_string()),
        eucc_itsef_identifier: Some("ITSEF-1".to_string()),
        eucc_valid_until: Some(ts("2027-06-01T00:00:00Z")),
        ..Default::default()
    };
    let eucc_expired = |as_of: &str| {
        ComplianceChecker::new(ComplianceLevel::EuccSubstantial)
            .with_sidecar(sidecar.clone())
            .with_as_of(ts(as_of))
            .check(&sbom)
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-EUCC-VALIDITY")
    };
    assert!(
        !eucc_expired("2027-01-01T00:00:00Z"),
        "certificate valid at the pinned instant"
    );
    assert!(
        eucc_expired("2028-01-01T00:00:00Z"),
        "certificate expired at the pinned instant"
    );
}

/// Exhaustive registry coverage: every rule key emitted by the checker
/// across all compliance levels and a representative fixture set must
/// resolve in [`rule_meta`] — no orphan rules.
#[test]
fn every_emitted_violation_has_a_registered_rule_id() {
    let sbom = NormalizedSbom::default();
    for level in ComplianceLevel::all() {
        let result = checker(*level).check(&sbom);
        for v in &result.violations {
            assert!(
                rule_meta(v.rule_id).is_some(),
                "level {level:?}: violation {:?} has unregistered rule_id {:?}",
                v.requirement,
                v.rule_id
            );
        }
    }
}

#[test]
fn check_populates_standard_refs_for_cra_violations() {
    let sbom = NormalizedSbom::default();
    let checker = checker(ComplianceLevel::CraPhase2);
    let result = checker.check(&sbom);
    let cra_violations: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.requirement.to_lowercase().contains("cra"))
        .collect();
    assert!(
        !cra_violations.is_empty(),
        "empty SBOM should produce some CRA violations"
    );
    for v in &cra_violations {
        assert!(
            !v.standard_refs.is_empty(),
            "CRA violation {:?} should have standard_refs populated",
            v.requirement
        );
    }
}
