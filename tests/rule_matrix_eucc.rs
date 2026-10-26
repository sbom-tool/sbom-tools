//! Registry-driven per-rule matrix for `ComplianceLevel::EuccSubstantial`
//! (Reg. (EU) 2024/482, reference-only profile).
//!
//! EUCC shares the CRA-family `COMPLIANCE_SARIF_RULE_IDS` catalogue; its
//! universe is that slice's `SBOM-EUCC-*` ids. Every id gets a firing
//! fixture and a silent fixture (real CycloneDX JSON through the real parser, with the
//! evidence fields in an attached CRA sidecar), or an explicit
//! skip-with-reason.
//!
//! SBOM-EUCC-CERTREF reads the document: a `certification-report` or
//! `attestation` external reference whose URL names EUCC or Common
//! Criteria, or a CDXA attestation. The CDXA path is beyond the fixture
//! DSL, so it is covered by the raw-JSON tests at the bottom of this file.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::{as_of, checker};
use rule_matrix::{
    ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, check, render_violations,
    run_matrix,
};
use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ComplianceResult, ViolationSeverity as Sev,
};

const LEVEL: ComplianceLevel = ComplianceLevel::EuccSubstantial;

/// The EUCC rules of the shared CRA-family SARIF catalogue.
fn eucc_universe() -> Vec<&'static str> {
    COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-EUCC-"))
        .collect()
}

/// `days` after the pinned test clock.
fn days_from_now(days: i64) -> chrono::DateTime<chrono::Utc> {
    as_of() + chrono::Duration::days(days)
}

/// A sidecar carrying all four Common Criteria references, with a
/// certificate valid for two more years.
fn eucc_sidecar() -> CraSidecarMetadata {
    CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-CC-HSM-2024-01".to_string()),
        eucc_target_of_evaluation: Some("https://acme.example/eucc/toe/hsm-3".to_string()),
        eucc_itsef_identifier: Some("ITSEF-DE-0042".to_string()),
        eucc_valid_until: Some(days_from_now(730)),
        ..CraSidecarMetadata::default()
    }
}

/// The product's EUCC certificate, as a CycloneDX external reference.
fn eucc_certificate_ref() -> (String, String) {
    (
        "certification-report".to_string(),
        "https://certification.enisa.europa.eu/eucc/certificates/EUCC-DE-2026-0042.pdf".to_string(),
    )
}

/// A conforming CycloneDX 1.6 product SBOM: the EUCC evidence in its
/// sidecar, and the certificate referenced from the product component.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-hsm");
    primary.external_refs = vec![eucc_certificate_ref()];
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        primary: Some(primary),
        components: vec![ComponentFixture::conforming("libalpha")],
        dependencies: vec![("ref-acme-hsm".to_string(), vec!["ref-libalpha".to_string()])],
        sidecar: Some(eucc_sidecar()),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// `base()` without the certificate reference: the sidecar evidence alone.
fn without_certref() -> SbomFixture {
    broken(|s| s.primary_mut().external_refs.clear())
}

/// The sidecar evidence and the certificate reference make a clean verdict.
#[test]
fn eucc_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

/// Pinned scope decision: the EUCC profile is reference-only. It reads the
/// certificate evidence (sidecar fields, a certificate reference, CDXA) and
/// runs no inventory or other SBOM-content check, so a document listing no
/// components at all passes once the sidecar evidence is complete — only
/// the in-document certificate reference is missing. The SBOM content is
/// the CRA profiles' to judge: `--standard cra` reports SBOM-CRA-INVENTORY
/// for the same document. Gating EUCC on the inventory would take a new
/// rule id (an SBOM-EUCC-INVENTORY the SARIF slice does not have).
#[test]
fn eucc_runs_no_inventory_check() {
    let empty = broken(|s| {
        s.primary = None;
        s.components.clear();
        s.dependencies.clear();
    });
    let eucc = check(LEVEL, &empty);
    assert!(
        eucc.is_compliant
            && eucc
                .violations
                .iter()
                .all(|v| v.sarif_rule_id() == "SBOM-EUCC-CERTREF"),
        "an empty SBOM with complete EUCC evidence draws only the certificate-reference \
         warning under EUCC:\n{}",
        render_violations(&eucc)
    );
    let cra = check(ComplianceLevel::CraPhase2, &empty);
    assert!(
        cra.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CRA-INVENTORY"),
        "the CRA profile judges the inventory:\n{}",
        render_violations(&cra)
    );
}

#[test]
fn eucc_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // An empty identifier is no reference either.
        RuleEntry::tested(
            "SBOM-EUCC-PP",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_protection_profile_id = None),
            base(),
        )
        .with_firing(
            "empty Protection Profile id",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_protection_profile_id = Some(String::new())),
        ),
        RuleEntry::tested(
            "SBOM-EUCC-TOE",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_target_of_evaluation = None),
            base(),
        )
        .with_firing(
            "empty Target of Evaluation reference",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_target_of_evaluation = Some(String::new())),
        ),
        RuleEntry::tested(
            "SBOM-EUCC-ITSEF",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_itsef_identifier = None),
            base(),
        )
        .with_firing(
            "empty ITSEF identifier",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_itsef_identifier = Some(String::new())),
        ),
        // Missing and expired are Errors; expiring within 180 days of the
        // pinned clock relaxes to a Warning at the same rule id.
        RuleEntry::tested(
            "SBOM-EUCC-VALIDITY",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_valid_until = None),
            base(),
        )
        .with_firing(
            "certificate expired",
            Sev::Error,
            broken(|s| s.sidecar_mut().eucc_valid_until = Some(days_from_now(-1))),
        )
        .with_departing_firing(
            "certificate expires within 180 days",
            Sev::Warning,
            broken(|s| s.sidecar_mut().eucc_valid_until = Some(days_from_now(90))),
        ),
        // A certification or attestation reference counts only when its URL
        // names the EUCC scheme or Common Criteria; the CDXA path is covered
        // by the raw-JSON tests eucc_certref_* below.
        RuleEntry::tested("SBOM-EUCC-CERTREF", Sev::Warning, without_certref(), base())
            .with_firing(
                "attestation reference naming no EUCC scheme",
                Sev::Warning,
                broken(|s| {
                    s.primary_mut().external_refs = vec![(
                        "attestation".to_string(),
                        "https://acme.example/attestations/iso-27001.pdf".to_string(),
                    )];
                }),
            )
            .with_silent(
                "attestation reference to a Common Criteria certificate",
                broken(|s| {
                    s.primary_mut().external_refs = vec![(
                        "attestation".to_string(),
                        "https://common-criteria.example/certificates/CC-2026-0042.pdf".to_string(),
                    )];
                }),
            ),
    ];

    run_matrix(LEVEL, &eucc_universe(), &entries);
}

// ---------------------------------------------------------------------------
// SBOM-EUCC-CERTREF: raw-JSON cases (CDXA declarations are beyond the DSL)
// ---------------------------------------------------------------------------

/// `without_certref()` plus a CDXA attestation that fully supports an EUCC /
/// Common Criteria requirement of a CRA-classified standard: a claim on the
/// primary component, backed by evidence created before and expiring after
/// the pinned clock, mapped with full conformance.
fn conforming_json() -> String {
    let mut doc: serde_json::Value =
        serde_json::from_str(&without_certref().to_json_string()).expect("fixture JSON re-parses");
    doc["definitions"] = serde_json::json!({
        "standards": [{
            "bom-ref": "std-eucc",
            "name": "EUCC Common Criteria certification (EU Cyber Resilience Act)",
            "version": "1.0",
            "requirements": [{ "bom-ref": "req-eucc-cert", "identifier": "EUCC-CERT" }],
        }],
    });
    doc["declarations"] = serde_json::json!({
        "claims": [{
            "bom-ref": "claim-eucc-cert",
            "target": "ref-acme-hsm",
            "predicate": "The product holds an EUCC Substantial certificate",
            "evidence": ["ev-eucc-cert"],
        }],
        "evidence": [{
            "bom-ref": "ev-eucc-cert",
            "propertyName": "eucc:certificate",
            "created": "2026-01-10T00:00:00Z",
            "expires": "2028-01-10T00:00:00Z",
        }],
        "attestations": [{
            "summary": "EUCC certificate attestation",
            "map": [{
                "requirement": "req-eucc-cert",
                "claims": ["claim-eucc-cert"],
                "conformance": { "score": 1.0 },
            }],
        }],
    });
    serde_json::to_string(&doc).expect("augmented fixture serializes")
}

fn check_json(json: &str) -> ComplianceResult {
    let sbom = parse_sbom_str(json).expect("raw fixture must parse as CycloneDX");
    checker(LEVEL).with_sidecar(eucc_sidecar()).check(&sbom)
}

/// Every sidecar evidence field present and a fresh CDXA EUCC attestation
/// instead of a certificate reference: the profile passes with zero
/// violations.
#[test]
fn eucc_cdxa_conforming_document_is_compliant_with_zero_violations() {
    let result = check_json(&conforming_json());
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "[{LEVEL:?}] conforming document must pass with zero violations; got \
         is_compliant={}:\n{}",
        result.is_compliant,
        render_violations(&result)
    );
}

#[test]
fn eucc_certref_fires_without_attestation_evidence() {
    let result = check_json(&without_certref().to_json_string());
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == "SBOM-EUCC-CERTREF" && v.severity == Sev::Warning),
        "a document with no EUCC attestation must warn:\n{}",
        render_violations(&result)
    );
    // The other four rules read the sidecar and stay silent.
    assert!(
        result
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() == "SBOM-EUCC-CERTREF"),
        "only SBOM-EUCC-CERTREF may fire on the sidecar-complete baseline:\n{}",
        render_violations(&result)
    );
}

#[test]
fn eucc_certref_silenced_by_fresh_cdxa_attestation() {
    let result = check_json(&conforming_json());
    assert!(
        result
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() != "SBOM-EUCC-CERTREF"),
        "fresh CDXA evidence for an EUCC standard must satisfy the reference:\n{}",
        render_violations(&result)
    );
}

/// Expired attestation evidence does not count (fail closed at the pinned
/// clock).
#[test]
fn eucc_certref_stale_cdxa_evidence_still_fires() {
    let stale = conforming_json().replace("2028-01-10T00:00:00Z", "2026-02-01T00:00:00Z");
    let result = check_json(&stale);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == "SBOM-EUCC-CERTREF"),
        "expired CDXA evidence must not satisfy the reference:\n{}",
        render_violations(&result)
    );
}
