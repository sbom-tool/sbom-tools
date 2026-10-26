//! CDXA (CycloneDX 1.6 Attestations) compliance-rule integration tests —
//! phase 1 consumption.
//!
//! Covers the integration contract for wiring `declarations` +
//! `definitions.standards` evidence into the existing rules:
//!
//! - Fresh, fully-resolved attestation evidence SATISFIES SSDF PS.1/PO.3,
//!   the EO 14028 autogeneration proxy, the CRA conformity checklist rows,
//!   and the CRA/EUCC certificate-reference checks even where the legacy
//!   (presence-bit / sidecar) path alone would fail.
//! - Fail-closed rejections (expired/anachronistic evidence, dangling refs,
//!   counter claims/evidence, partial conformance) never satisfy, and the
//!   still-failing violation message names the specific reason.
//! - Documents without declarations see zero behavior change: no message
//!   gains any CDXA text (the full pre-existing suite is the broader
//!   regression proof).
//!
//! Every satisfaction assertion pins the evaluation clock via
//! `ComplianceChecker::with_as_of` — the same injectable clock `--as-of`
//! drives — so evidence freshness is reproducible.

use chrono::{DateTime, Utc};
use sbom_tools::model::{ConformityRoute, CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use sbom_tools::{parse_sbom, parse_sbom_str};
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn parse_fixture(name: &str) -> NormalizedSbom {
    parse_sbom(&fixture_path(name)).expect("fixture must parse")
}

fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("test timestamp must parse")
        .with_timezone(&Utc)
}

/// Instant inside the fixtures' evidence validity window
/// (created 2026-01-10, expires 2027-01-10).
const FRESH: &str = "2026-06-01T00:00:00Z";
/// Instant after the evidence expiry.
const EXPIRED: &str = "2027-06-01T00:00:00Z";
/// Instant before the evidence was created (anachronistic).
const BEFORE_CREATION: &str = "2025-12-01T00:00:00Z";

fn check_at(level: ComplianceLevel, sbom: &NormalizedSbom, as_of: &str) -> ComplianceResult {
    ComplianceChecker::new(level)
        .with_as_of(ts(as_of))
        .check(sbom)
}

fn rule_messages<'a>(result: &'a ComplianceResult, rule_id: &str) -> Vec<&'a str> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule_id)
        .map(|v| v.message.as_str())
        .collect()
}

fn has_rule(result: &ComplianceResult, rule_id: &str) -> bool {
    !rule_messages(result, rule_id).is_empty()
}

/// Messages of every finding reported under the SARIF rule `sarif_id`: both
/// PS.1 checks (creator, SBOM-SSDF-PS1, and generation tool,
/// SBOM-SSDF-PS1-TOOL) report as SBOM-SSDF-PS1.
fn sarif_rule_messages<'a>(result: &'a ComplianceResult, sarif_id: &str) -> Vec<&'a str> {
    result
        .violations
        .iter()
        .filter(|v| v.sarif_rule_id() == sarif_id)
        .map(|v| v.message.as_str())
        .collect()
}

fn has_sarif_rule(result: &ComplianceResult, sarif_id: &str) -> bool {
    !sarif_rule_messages(result, sarif_id).is_empty()
}

/// Minimal CycloneDX 1.6 document (no tool creator, no build refs, no
/// attestation-relevant external refs) with one CDXA standard/requirement,
/// one evidence item (fresh 2026-01-10..2027-01-10, signature present), and
/// caller-supplied claim / attestation-map JSON.
fn cdxa_document(
    standard_name: &str,
    requirement_identifier: &str,
    claims: &str,
    map: &str,
) -> String {
    format!(
        r#"{{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {{
            "timestamp": "2026-02-01T00:00:00Z",
            "component": {{"type": "application", "bom-ref": "app", "name": "app", "version": "1.0.0"}}
        }},
        "components": [
            {{"type": "library", "bom-ref": "lib-a", "name": "lib-a", "version": "1.0.0", "purl": "pkg:npm/lib-a@1.0.0"}}
        ],
        "definitions": {{"standards": [{{
            "bom-ref": "std-1",
            "name": "{standard_name}",
            "requirements": [{{"bom-ref": "req-1", "identifier": "{requirement_identifier}"}}]
        }}]}},
        "declarations": {{
            "claims": [{claims}],
            "evidence": [{{
                "bom-ref": "ev-1",
                "description": "audit evidence",
                "created": "2026-01-10T00:00:00Z",
                "expires": "2027-01-10T00:00:00Z",
                "signature": {{"algorithm": "ES256", "value": "cHJlc2VuY2U"}}
            }}],
            "attestations": [{{"map": [{map}]}}]
        }}
    }}"#
    )
}

const RESOLVED_CLAIM: &str = r#"{"bom-ref": "claim-1", "target": "app", "predicate": "practice is implemented", "evidence": ["ev-1"]}"#;
const FULL_CONFORMANCE_MAP: &str =
    r#"{"requirement": "req-1", "claims": ["claim-1"], "conformance": {"score": 1.0}}"#;

// ════════════════════════════════════════════════════════════════════════
// (a) Attestation satisfies where the legacy path alone fails (delta case)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn ssdf_ps1_po3_satisfied_by_attestation_where_legacy_path_fails() {
    // The delta fixture has NO tool/author creators (PS.1 legacy fails both
    // its sites) and NO BuildMeta/BuildSystem refs (PO.3 legacy fails), but
    // fully attests PS.1 and PO.3 with fresh resolved evidence.
    let sbom = parse_fixture("cyclonedx/declarations-cdxa-ssdf-delta.cdx.json");
    assert!(
        sbom.document.creators.is_empty(),
        "delta premise: no creators"
    );

    let fresh = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);
    assert!(
        !has_sarif_rule(&fresh, "SBOM-SSDF-PS1"),
        "fresh PS.1 attestation must satisfy the rule: {:?}",
        sarif_rule_messages(&fresh, "SBOM-SSDF-PS1")
    );
    assert!(
        !has_rule(&fresh, "SBOM-SSDF-PO3"),
        "fresh PO.3 attestation must satisfy the rule: {:?}",
        rule_messages(&fresh, "SBOM-SSDF-PO3")
    );

    // Delta proof: once the evidence is stale the attestation path drops
    // away and the legacy path alone demonstrably fails — both rules fire.
    let expired = check_at(ComplianceLevel::NistSsdf, &sbom, EXPIRED);
    assert!(has_rule(&expired, "SBOM-SSDF-PS1"));
    assert!(has_rule(&expired, "SBOM-SSDF-PS1-TOOL"));
    assert!(has_rule(&expired, "SBOM-SSDF-PO3"));
}

// ════════════════════════════════════════════════════════════════════════
// (b) Fail-closed rejections do not satisfy, and messages name the reason
// ════════════════════════════════════════════════════════════════════════

#[test]
fn expired_and_anachronistic_evidence_is_rejected_with_reason() {
    let sbom = parse_fixture("cyclonedx/declarations-cdxa-ssdf-delta.cdx.json");

    let expired = check_at(ComplianceLevel::NistSsdf, &sbom, EXPIRED);
    for rule in ["SBOM-SSDF-PS1", "SBOM-SSDF-PO3"] {
        let messages = sarif_rule_messages(&expired, rule);
        assert!(
            !messages.is_empty(),
            "{rule} must fire once evidence expired"
        );
        assert!(
            messages.iter().all(|m| m.contains("expired")),
            "{rule} messages must name the expiry rejection: {messages:?}"
        );
    }

    // Evidence created AFTER the pinned evaluation instant is anachronistic
    // and equally rejected, with its own reason.
    let anachronistic = check_at(ComplianceLevel::NistSsdf, &sbom, BEFORE_CREATION);
    let messages = rule_messages(&anachronistic, "SBOM-SSDF-PO3");
    assert!(
        messages
            .iter()
            .all(|m| m.contains("dated after the evaluation instant")),
        "anachronistic evidence must be named: {messages:?}"
    );
}

#[test]
fn dangling_attestation_chain_is_rejected_with_reason() {
    // The original CDXA fixture attests PS.1 fully but maps PO.3 onto a
    // claim whose target and evidence refs both dangle.
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let result = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);

    // PS.1 satisfied (legacy tool creator also present in this fixture).
    assert!(!has_sarif_rule(&result, "SBOM-SSDF-PS1"));

    // PO.3 fails closed and the message names the dangling chain.
    let messages = rule_messages(&result, "SBOM-SSDF-PO3");
    assert!(!messages.is_empty(), "dangling PO.3 chain must not satisfy");
    assert!(
        messages.iter().all(|m| m.contains("dangling")),
        "PO.3 message must name the dangling rejection: {messages:?}"
    );
}

#[test]
fn unattested_practice_message_points_at_attestation_path() {
    // The fixture carries declarations but no PW.6 map entry: the failing
    // PW.6 violation should advertise machine-readable attestation as an
    // accepted evidence path (declarations present, nothing rejected).
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let result = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);
    let messages = rule_messages(&result, "SBOM-SSDF-PW6");
    assert!(
        !messages.is_empty(),
        "PW.6 legacy path fails in this fixture"
    );
    assert!(
        messages
            .iter()
            .all(|m| m.contains("accepted evidence path")),
        "PW.6 message must mention the attestation evidence path: {messages:?}"
    );
}

#[test]
fn counter_evidence_on_claim_is_rejected_with_reason() {
    let claim = r#"{"bom-ref": "claim-1", "target": "app", "predicate": "p", "evidence": ["ev-1"], "counterEvidence": ["ev-1"]}"#;
    let doc = cdxa_document(
        "NIST Secure Software Development Framework",
        "PS.1",
        claim,
        FULL_CONFORMANCE_MAP,
    );
    let sbom = parse_sbom_str(&doc).expect("document must parse");
    let result = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);
    let messages = sarif_rule_messages(&result, "SBOM-SSDF-PS1");
    assert!(
        !messages.is_empty(),
        "countered claim must not satisfy PS.1"
    );
    assert!(
        messages.iter().all(|m| m.contains("counter-evidence")),
        "message must name the counter-evidence contest: {messages:?}"
    );
}

#[test]
fn counter_claims_on_map_entry_are_rejected_with_reason() {
    let map = r#"{"requirement": "req-1", "claims": ["claim-1"], "counterClaims": ["claim-1"], "conformance": {"score": 1.0}}"#;
    let doc = cdxa_document(
        "NIST Secure Software Development Framework",
        "PS.1",
        RESOLVED_CLAIM,
        map,
    );
    let sbom = parse_sbom_str(&doc).expect("document must parse");
    let result = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);
    let messages = sarif_rule_messages(&result, "SBOM-SSDF-PS1");
    assert!(
        !messages.is_empty(),
        "counter-claimed mapping must not satisfy"
    );
    assert!(
        messages.iter().all(|m| m.contains("counter-claim")),
        "message must name the counter-claim contest: {messages:?}"
    );
}

#[test]
fn partial_conformance_is_rejected_with_reason() {
    let map = r#"{"requirement": "req-1", "claims": ["claim-1"], "conformance": {"score": 0.5}}"#;
    let doc = cdxa_document(
        "NIST Secure Software Development Framework",
        "PS.1",
        RESOLVED_CLAIM,
        map,
    );
    let sbom = parse_sbom_str(&doc).expect("document must parse");
    let result = check_at(ComplianceLevel::NistSsdf, &sbom, FRESH);
    let messages = sarif_rule_messages(&result, "SBOM-SSDF-PS1");
    assert!(!messages.is_empty(), "partial conformance must not satisfy");
    assert!(
        messages.iter().all(|m| m.contains("partial")),
        "message must name partial conformance: {messages:?}"
    );
}

// ════════════════════════════════════════════════════════════════════════
// EO 14028 — autogeneration/provenance site
// ════════════════════════════════════════════════════════════════════════

#[test]
fn eo14028_autogen_satisfied_by_eo_family_attestation() {
    // Standard-level EO 14028 text wins classification even though the
    // requirement reuses the SSDF PS.1 identifier; the document has no tool
    // creator, so the legacy autogen path fails on its own.
    let doc = cdxa_document(
        "Executive Order 14028 secure software attestation",
        "PS.1",
        RESOLVED_CLAIM,
        FULL_CONFORMANCE_MAP,
    );
    let sbom = parse_sbom_str(&doc).expect("document must parse");
    assert!(
        sbom.document.creators.is_empty(),
        "delta premise: no creators"
    );

    let fresh = check_at(ComplianceLevel::Eo14028, &sbom, FRESH);
    assert!(
        !has_rule(&fresh, "SBOM-EO14028-AUTOGEN"),
        "fresh EO 14028 attestation must satisfy autogen: {:?}",
        rule_messages(&fresh, "SBOM-EO14028-AUTOGEN")
    );

    let expired = check_at(ComplianceLevel::Eo14028, &sbom, EXPIRED);
    let messages = rule_messages(&expired, "SBOM-EO14028-AUTOGEN");
    assert!(
        !messages.is_empty(),
        "expired evidence must not satisfy autogen"
    );
    assert!(
        messages.iter().all(|m| m.contains("expired")),
        "autogen message must name the expiry rejection: {messages:?}"
    );
}

// ════════════════════════════════════════════════════════════════════════
// CRA — conformity checklist rows and EUCC references
// ════════════════════════════════════════════════════════════════════════

fn cra_attested_sbom() -> NormalizedSbom {
    let doc = cdxa_document(
        "EU Cyber Resilience Act Annex V conformity assessment",
        "ANNEX-V",
        RESOLVED_CLAIM,
        FULL_CONFORMANCE_MAP,
    );
    parse_sbom_str(&doc).expect("document must parse")
}

#[test]
fn cra_conformity_rows_strengthened_by_cdxa_attestation() {
    let sbom = cra_attested_sbom();
    let sidecar = CraSidecarMetadata {
        product_class: Some(CraProductClass::ImportantClass2),
        conformity_assessment_route: Some(ConformityRoute::ModuleBC),
        ..Default::default()
    };
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar.clone())
        .with_as_of(ts(FRESH))
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary at pinned class");
    for label in [
        "EU Declaration of Conformity",
        "EU-type examination certificate (Module B)",
        "Production conformity statement (Module C)",
    ] {
        let row = summary
            .evidence
            .iter()
            .find(|e| e.label == label)
            .unwrap_or_else(|| panic!("row '{label}' present"));
        assert!(row.satisfied, "'{label}' satisfied via CDXA attestation");
        // The evidence item carries a signature object: presence-only, so
        // the reported level is signature-present, never verified.
        assert!(
            row.detail.contains("CDXA") && row.detail.contains("signature-present"),
            "'{label}' detail must name the CDXA evidence level: {}",
            row.detail
        );
    }

    // Expired evidence: rows fall back to the (failing) legacy verdict with
    // the original detail text.
    let expired = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .with_as_of(ts(EXPIRED))
        .check(&sbom);
    let summary = expired.conformity_summary.expect("summary at pinned class");
    let row = summary
        .evidence
        .iter()
        .find(|e| e.label == "EU-type examination certificate (Module B)")
        .expect("Module B row present");
    assert!(!row.satisfied, "expired attestation must not satisfy");
    assert!(
        !row.detail.contains("CDXA"),
        "unsatisfied row keeps the legacy detail text: {}",
        row.detail
    );
}

fn eucc_attested_sbom() -> NormalizedSbom {
    let doc = cdxa_document(
        "EUCC Common Criteria certification (EU Cyber Resilience Act Annex IV)",
        "EUCC-CERT",
        RESOLVED_CLAIM,
        FULL_CONFORMANCE_MAP,
    );
    parse_sbom_str(&doc).expect("document must parse")
}

#[test]
fn cra_annex_iv_eucc_reference_satisfied_by_cdxa_attestation() {
    let sbom = eucc_attested_sbom();
    let fresh = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .with_as_of(ts(FRESH))
        .check(&sbom);
    assert!(
        !has_rule(&fresh, "SBOM-CRA-ANNEX-IV"),
        "fresh EUCC-naming CRA attestation must satisfy Annex IV: {:?}",
        rule_messages(&fresh, "SBOM-CRA-ANNEX-IV")
    );

    let expired = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::Critical)
        .with_as_of(ts(EXPIRED))
        .check(&sbom);
    let messages = rule_messages(&expired, "SBOM-CRA-ANNEX-IV");
    assert!(
        !messages.is_empty(),
        "expired evidence must not satisfy Annex IV"
    );
    assert!(
        messages.iter().all(|m| m.contains("expired")),
        "Annex IV message must name the expiry rejection: {messages:?}"
    );
}

#[test]
fn eucc_certref_satisfied_by_cdxa_attestation() {
    let sbom = eucc_attested_sbom();
    let fresh = check_at(ComplianceLevel::EuccSubstantial, &sbom, FRESH);
    assert!(
        !has_rule(&fresh, "SBOM-EUCC-CERTREF"),
        "fresh EUCC-naming attestation must satisfy CERTREF: {:?}",
        rule_messages(&fresh, "SBOM-EUCC-CERTREF")
    );
    // The sidecar-backed EUCC rules are untouched by attestation evidence
    // and still fire (no sidecar attached here).
    for rule in [
        "SBOM-EUCC-PP",
        "SBOM-EUCC-TOE",
        "SBOM-EUCC-ITSEF",
        "SBOM-EUCC-VALIDITY",
    ] {
        assert!(
            has_rule(&fresh, rule),
            "{rule} must still fire without sidecar"
        );
    }

    let expired = check_at(ComplianceLevel::EuccSubstantial, &sbom, EXPIRED);
    let messages = rule_messages(&expired, "SBOM-EUCC-CERTREF");
    assert!(
        !messages.is_empty(),
        "expired evidence must not satisfy CERTREF"
    );
    assert!(
        messages.iter().all(|m| m.contains("expired")),
        "CERTREF message must name the expiry rejection: {messages:?}"
    );

    // A CRA-classified attestation that does NOT name EUCC/Common Criteria
    // never satisfies the certificate-reference rule (relevance gate).
    let non_eucc = cra_attested_sbom();
    let result = check_at(ComplianceLevel::EuccSubstantial, &non_eucc, FRESH);
    assert!(
        has_rule(&result, "SBOM-EUCC-CERTREF"),
        "non-EUCC CRA attestation must not satisfy CERTREF"
    );
}

// ════════════════════════════════════════════════════════════════════════
// (c) Documents without declarations: zero behavior change
// ════════════════════════════════════════════════════════════════════════

#[test]
fn documents_without_declarations_gain_no_cdxa_text() {
    let sbom = parse_fixture("cyclonedx/minimal.cdx.json");
    assert!(sbom.declarations().is_none(), "premise: no declarations");
    for level in [
        ComplianceLevel::NistSsdf,
        ComplianceLevel::Eo14028,
        ComplianceLevel::EuccSubstantial,
        ComplianceLevel::CraPhase1,
        ComplianceLevel::CraPhase2,
    ] {
        let result = check_at(level, &sbom, FRESH);
        for violation in &result.violations {
            assert!(
                !violation.message.contains("CDXA")
                    && !violation.message.contains("accepted evidence path"),
                "{level:?}: message must stay byte-identical without declarations: {}",
                violation.message
            );
        }
    }

    // Conformity summary rows are equally untouched.
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_product_class(CraProductClass::ImportantClass2)
        .with_as_of(ts(FRESH))
        .check(&sbom);
    let summary = result.conformity_summary.expect("summary at pinned class");
    for row in &summary.evidence {
        assert!(
            !row.detail.contains("CDXA"),
            "conformity detail must stay unchanged without declarations: {}",
            row.detail
        );
    }
}
