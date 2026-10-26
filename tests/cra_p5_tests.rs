//! Combined integration tests for CRA-P5.4 (EuccSubstantial),
//! P5.5 (controls-assertion sidecar block), and P5.7 (TUI presets).

#[path = "common/clock.rs"]
mod clock;

use clock::{as_of, checker};
use sbom_tools::model::{ControlAssertion, CraSidecarMetadata};
use sbom_tools::quality::{ComplianceLevel, StandardKind, ViolationSeverity};
use std::collections::BTreeMap;

// ============================================================================
// P5.4 — EuccSubstantial
// ============================================================================

#[test]
fn eucc_substantial_in_compliance_level_all() {
    assert!(ComplianceLevel::all().contains(&ComplianceLevel::EuccSubstantial));
}

#[test]
fn eucc_substantial_short_name_fits_compact_label() {
    assert!(ComplianceLevel::EuccSubstantial.short_name().len() <= 8);
}

#[test]
fn eucc_substantial_without_sidecar_fires_all_four_must_haves() {
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial).check(&sbom);
    let requirements: Vec<&String> = result.violations.iter().map(|v| &v.requirement).collect();
    assert!(
        requirements
            .iter()
            .any(|r| r.contains("Protection Profile reference"))
    );
    assert!(
        requirements
            .iter()
            .any(|r| r.contains("Target of Evaluation reference"))
    );
    assert!(requirements.iter().any(|r| r.contains("ITSEF")));
    assert!(requirements.iter().any(|r| r.contains("valid-until date")));
}

#[test]
fn eucc_substantial_with_complete_sidecar_only_warns() {
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-CC-MFR-2024-01".to_string()),
        eucc_target_of_evaluation: Some("https://example.com/toe".to_string()),
        eucc_itsef_identifier: Some("ITSEF-DE-001".to_string()),
        eucc_valid_until: Some(
            chrono::DateTime::parse_from_rfc3339("2030-12-31T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Complete EUCC sidecar should produce no Errors; got {errors:?}"
    );
}

#[test]
fn eucc_substantial_expired_certificate_is_error() {
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(
            chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error && v.message.contains("expired"))
    );
}

#[test]
fn eucc_substantial_near_expiry_is_warning() {
    let near = as_of() + chrono::Duration::days(60);
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(near),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Warning
                && v.message.contains("expires within"))
    );
}

#[test]
fn eucc_substantial_checks_fire_under_their_own_rule_ids() {
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial).check(&sbom);
    for (requirement, rule_id) in [
        ("Protection Profile reference", "SBOM-EUCC-PP"),
        ("Target of Evaluation reference", "SBOM-EUCC-TOE"),
        ("ITSEF identifier", "SBOM-EUCC-ITSEF"),
        ("certificate valid-until date", "SBOM-EUCC-VALIDITY"),
        ("Certification external reference", "SBOM-EUCC-CERTREF"),
    ] {
        let v = result
            .violations
            .iter()
            .find(|v| v.requirement.contains(requirement))
            .unwrap_or_else(|| panic!("expected a violation for {requirement:?}"));
        assert_eq!(
            v.rule_id, rule_id,
            "the {requirement:?} check must fire under its own rule id"
        );
    }
}

#[test]
fn eucc_validity_variants_share_the_validity_rule_id() {
    let expired = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(
            chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial)
        .with_sidecar(expired)
        .check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.message.contains("expired"))
        .expect("expired-certificate violation expected");
    assert_eq!(v.rule_id, "SBOM-EUCC-VALIDITY");
    assert_eq!(v.severity, ViolationSeverity::Error);

    let near_expiry = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(as_of() + chrono::Duration::days(60)),
        ..Default::default()
    };
    let result = checker(ComplianceLevel::EuccSubstantial)
        .with_sidecar(near_expiry)
        .check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.message.contains("expires within"))
        .expect("near-expiry violation expected");
    assert_eq!(v.rule_id, "SBOM-EUCC-VALIDITY");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

#[test]
fn eucc_violations_carry_eucc_standard_refs_with_2024_482_url() {
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::EuccSubstantial).check(&sbom);
    let eucc_violations: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.rule_id.starts_with("SBOM-EUCC-"))
        .collect();
    assert!(
        !eucc_violations.is_empty(),
        "sidecar-less EuccSubstantial run must fire EUCC violations"
    );
    for v in &eucc_violations {
        assert!(
            v.standard_refs
                .iter()
                .any(|r| r.standard == StandardKind::Eucc
                    && r.help_uri.as_deref()
                        == Some("https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng")),
            "violation {:?} must carry a StandardKind::Eucc ref with the 2024/482 URL; got {:?}",
            v.rule_id,
            v.standard_refs
        );
    }
}

// ============================================================================
// P5.5 — controls-assertion sidecar block
// ============================================================================

#[test]
fn controls_assertion_satisfied_with_evidence_clears_check() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: Some("https://example.com/evidence/1.a.pdf".to_string()),
            methodology: Some("prEN 40000-1-2 §5.3".to_string()),
            note: None,
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part I 1.a")),
        "satisfied + evidence_url present must not fire"
    );
}

#[test]
fn controls_assertion_satisfied_without_evidence_fires_warning() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: None,
            methodology: Some("informal".to_string()),
            note: None,
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex I Part I 1.a"))
        .expect("warning expected");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

#[test]
fn controls_assertion_unsatisfied_does_not_fire() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.b".to_string(),
        ControlAssertion {
            satisfied: false,
            evidence_url: None,
            methodology: None,
            note: Some("Not yet implemented".to_string()),
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part I 1.b"))
    );
}

#[test]
fn controls_assertion_serde_roundtrip_preserves_btreemap() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: Some("u".to_string()),
            methodology: Some("m".to_string()),
            note: None,
        },
    );
    controls.insert(
        "2.m".to_string(),
        ControlAssertion {
            satisfied: false,
            ..Default::default()
        },
    );
    let original = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("annex_i_part_i_controls") || json.contains("annexIPartIControls"));
    let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.annex_i_part_i_controls.len(), 2);
    assert!(parsed.annex_i_part_i_controls["1.a"].satisfied);
    assert!(!parsed.annex_i_part_i_controls["2.m"].satisfied);

    // Default (empty) must skip serialization.
    let default_json = serde_json::to_string(&CraSidecarMetadata::default()).unwrap();
    assert!(!default_json.contains("annex_i_part_i_controls"));
    assert!(!default_json.contains("annexIPartIControls"));
}

// ============================================================================
// P5.7 — TUI presets
// ============================================================================

#[test]
fn tui_policy_preset_includes_eucc_and_oss_steward() {
    use sbom_tools::tui::PolicyPreset;
    let p = PolicyPreset::EuccSubstantial;
    assert_eq!(p.compliance_level(), Some(ComplianceLevel::EuccSubstantial));
    assert!(p.is_standards_based());

    let oss = PolicyPreset::CraOssSteward;
    assert_eq!(oss.compliance_level(), Some(ComplianceLevel::CraOssSteward));
    assert!(oss.is_standards_based());
}

#[test]
fn tui_policy_preset_cycle_visits_eucc_and_oss_steward() {
    use sbom_tools::tui::PolicyPreset;
    let mut seen = Vec::new();
    let mut p = PolicyPreset::Enterprise;
    for _ in 0..14 {
        seen.push(p);
        p = p.next();
    }
    assert!(seen.contains(&PolicyPreset::EuccSubstantial));
    assert!(seen.contains(&PolicyPreset::CraOssSteward));
}
