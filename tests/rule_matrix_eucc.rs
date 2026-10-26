//! Registry-driven per-rule matrix for `ComplianceLevel::EuccSubstantial`
//! (Reg. (EU) 2024/482, reference-only profile).
//!
//! EUCC shares the CRA-family `COMPLIANCE_SARIF_RULE_IDS` catalogue; its
//! universe is that slice's `SBOM-EUCC-*` ids plus the slice-less family
//! catch-all `SBOM-EUCC-GENERAL`. Every id gets a firing fixture and a
//! silent fixture (real CycloneDX JSON through the real parser, with the
//! evidence fields in an attached CRA sidecar), or an explicit
//! skip-with-reason.
//!
//! SBOM-EUCC-CERTREF cannot be silenced through the fixture DSL: the only
//! document evidence the parser lets through is a CDXA attestation (see the
//! skip reason), so its firing and silent states are covered by the raw-JSON
//! tests at the bottom of this file.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::{as_of, checker};
use rule_matrix::{ComponentFixture, RuleEntry, SbomFixture, render_violations, run_matrix};
use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ComplianceResult, ViolationSeverity as Sev,
};

const LEVEL: ComplianceLevel = ComplianceLevel::EuccSubstantial;

/// The EUCC rules of the shared CRA-family SARIF catalogue, plus the
/// slice-less family catch-all.
fn eucc_universe() -> Vec<&'static str> {
    COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-EUCC-"))
        .chain(std::iter::once("SBOM-EUCC-GENERAL"))
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

/// A CycloneDX 1.6 product SBOM (CDXA-capable) with the EUCC evidence in its
/// sidecar. Not fully conforming: SBOM-EUCC-CERTREF fires on every DSL
/// fixture (see the module docs); the zero-violation document is
/// `conforming_json()` below.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        primary: Some(ComponentFixture::conforming("acme-hsm")),
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
        RuleEntry::skipped(
            "SBOM-EUCC-CERTREF",
            "bug: the CycloneDX parser maps externalReferences types \
             'attestation' / 'certification-report' to ExternalRefType::Other \
             (map_cdx_external_ref_type), so no document reference can satisfy \
             this rule and every DSL fixture fires it; firing, and the one \
             silent path left (fresh CDXA attestation evidence for an EUCC \
             standard), are covered by the raw-JSON tests eucc_certref_* below",
        ),
        RuleEntry::skipped(
            "SBOM-EUCC-GENERAL",
            "registry catch-all for the EUCC family: no check site in \
             check_eucc_substantial emits it (it is the SARIF re-bucketing \
             target only); it cannot fire from document content",
        ),
    ];

    run_matrix(LEVEL, &eucc_universe(), &entries);
}

// ---------------------------------------------------------------------------
// SBOM-EUCC-CERTREF: raw-JSON cases (CDXA declarations are beyond the DSL)
// ---------------------------------------------------------------------------

/// `base()` plus a CDXA attestation that fully supports an EUCC / Common
/// Criteria requirement of a CRA-classified standard: a claim on the
/// primary component, backed by evidence created before and expiring after
/// the pinned clock, mapped with full conformance.
fn conforming_json() -> String {
    let mut doc: serde_json::Value =
        serde_json::from_str(&base().to_json_string()).expect("fixture JSON re-parses");
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

/// Every evidence field present and a fresh CDXA EUCC attestation: the
/// profile passes with zero violations.
#[test]
fn eucc_conforming_document_is_compliant_with_zero_violations() {
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
    let result = check_json(&base().to_json_string());
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
