//! `--pqc-mode deadline`: the post-quantum migration calendar of `cnsa2`
//! and `pqc`.
//!
//! `tests/fixtures/cyclonedx/cbom-pqc-calendar.cdx.json` exercises every
//! schedule: NIST IR 8547 (final) Tables 2, 4 and 8 and §4.1.3, the federal
//! deadlines of EO 14412 / OMB M-26-15 / EO 14306, and NSA's CNSA 2.0
//! timeline, beside algorithms no schedule dates. Readiness mode, the
//! default, is pinned by the verdict snapshots and deadline mode by the
//! deadline snapshots (tests/compliance_snapshots.rs) and the PQC and
//! CNSA 2.0 rule matrices; this file holds the properties those pin case by
//! case.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::path::Path;
use std::process::{Command, Output};

use sbom_tools::model::NormalizedSbom;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    CnsaCategory, ComplianceChecker, ComplianceLevel, ComplianceResult, PqcMode, PqcProfile,
    Violation, ViolationSeverity as Sev,
};
use sbom_tools::reports::{SarifOptions, generate_compliance_json, generate_compliance_sarif_with};
use serde_json::Value;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const CALENDAR: &str = "cyclonedx/cbom-pqc-calendar.cdx.json";
const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/compliance/v2.schema.json"
);

/// The review date, before IR 8547's 2030 deprecation.
const D2026: &str = "2026-10-12T00:00:00Z";
/// In IR 8547's deprecation window.
const D2031: &str = "2031-06-01T00:00:00Z";
/// After IR 8547's 2035 disallowance.
const D2036: &str = "2036-06-01T00:00:00Z";

fn sbom(rel: &str) -> NormalizedSbom {
    let raw = std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel)).expect("fixture");
    parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"))
}

fn instant(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

fn date(ymd: &str) -> chrono::NaiveDate {
    chrono::NaiveDate::parse_from_str(ymd, "%Y-%m-%d").expect("valid date")
}

/// Readiness mode, the default, at `as_of`.
fn readiness(level: ComplianceLevel, as_of: &str, sbom: &NormalizedSbom) -> ComplianceResult {
    ComplianceChecker::new(level)
        .with_as_of(instant(as_of))
        .check(sbom)
}

/// Deadline mode at `as_of`.
fn deadline(
    level: ComplianceLevel,
    as_of: &str,
    profile: PqcProfile,
    category: Option<CnsaCategory>,
    sbom: &NormalizedSbom,
) -> ComplianceResult {
    let mut checker = ComplianceChecker::new(level)
        .with_as_of(instant(as_of))
        .with_pqc_mode(PqcMode::Deadline)
        .with_pqc_profile(profile);
    if let Some(category) = category {
        checker = checker.with_cnsa_category(category);
    }
    checker.check(sbom)
}

fn nist(level: ComplianceLevel, as_of: &str, sbom: &NormalizedSbom) -> ComplianceResult {
    deadline(level, as_of, PqcProfile::Nist, None, sbom)
}

fn subject(v: &Violation) -> &str {
    v.component_id.as_deref().unwrap_or("-")
}

/// A result's findings, as what a reader compares across dates: severity,
/// rule, subject and deadline, sorted.
fn findings(result: &ComplianceResult) -> Vec<String> {
    let mut lines: Vec<String> = result
        .violations
        .iter()
        .map(|v| {
            format!(
                "{:?} {} {} {:?}",
                v.severity,
                v.rule_id,
                subject(v),
                v.deadline.as_ref().map(|d| (d.date, d.source.as_str()))
            )
        })
        .collect();
    lines.sort();
    lines
}

/// The one finding of `rule_id` about `component`.
fn finding<'a>(result: &'a ComplianceResult, rule_id: &str, component: &str) -> &'a Violation {
    let matching: Vec<&Violation> = result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule_id && subject(v) == component)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected one {rule_id} finding about {component}, got {matching:#?}"
    );
    matching[0]
}

/// Severity, deadline date and source of a finding.
fn dated(v: &Violation) -> (Sev, Option<chrono::NaiveDate>, Option<&str>) {
    (
        v.severity,
        v.deadline.as_ref().map(|d| d.date),
        v.deadline.as_ref().map(|d| d.source.as_str()),
    )
}

// ============================================================================
// One SBOM at three dates
// ============================================================================

/// The crypto violation set used to be identical for every `--as-of`. In
/// deadline mode the same SBOM reads differently in 2026, 2031 and 2036; in
/// readiness mode it reads the same at every date, and nothing is dated.
#[test]
fn one_sbom_differs_across_2026_2031_and_2036_only_in_deadline_mode() {
    let sbom = sbom(CALENDAR);
    let dates = [D2026, D2031, D2036];
    for level in [ComplianceLevel::NistPqc, ComplianceLevel::Cnsa2] {
        let strict: Vec<ComplianceResult> =
            dates.iter().map(|d| readiness(level, d, &sbom)).collect();
        for result in &strict {
            assert!(
                result.violations.iter().all(|v| v.deadline.is_none()),
                "[{level:?}] readiness mode dates nothing"
            );
            assert!(
                result.violations.iter().all(|v| v.severity != Sev::Info),
                "[{level:?}] readiness mode reports every algorithm as an error"
            );
        }
        let messages = |r: &ComplianceResult| {
            r.violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(findings(&strict[0]), findings(&strict[1]), "[{level:?}]");
        assert_eq!(findings(&strict[1]), findings(&strict[2]), "[{level:?}]");
        assert_eq!(messages(&strict[0]), messages(&strict[2]), "[{level:?}]");
    }

    // Deadline mode: NIST IR 8547 (Info, Warning, Error), the federal
    // deadlines, and a CNSA 2.0 category whose milestones fall in 2030 and
    // 2033.
    let configs = [
        (ComplianceLevel::NistPqc, PqcProfile::Nist, None),
        (ComplianceLevel::NistPqc, PqcProfile::Federal, None),
        (
            ComplianceLevel::Cnsa2,
            PqcProfile::Nist,
            Some(CnsaCategory::Niche),
        ),
    ];
    for (level, profile, category) in configs {
        let [a, b, c] = dates.map(|d| findings(&deadline(level, d, profile, category, &sbom)));
        assert_ne!(a, b, "[{level:?} {profile:?}] 2026 vs 2031");
        assert_ne!(b, c, "[{level:?} {profile:?}] 2031 vs 2036");
        assert_ne!(a, c, "[{level:?} {profile:?}] 2026 vs 2036");
    }

    // The errors only grow as the milestones pass.
    let errors = |as_of| nist(ComplianceLevel::NistPqc, as_of, &sbom).error_count;
    assert!(errors(D2026) < errors(D2031) && errors(D2031) < errors(D2036));
    // Under the strictest CNSA 2.0 timeline 2031 and 2036 agree: both are
    // past its last milestone, exclusive use by 2030.
    let strictest = |as_of| findings(&nist(ComplianceLevel::Cnsa2, as_of, &sbom));
    assert_ne!(strictest(D2026), strictest(D2031));
    assert_eq!(strictest(D2031), strictest(D2036));
}

/// The IR 8547 ladder for a quantum-vulnerable scheme of Tables 2 and 4:
/// Info naming the 2030 deprecation, Warning while deprecated, Error once
/// disallowed.
#[test]
fn ir_8547_ladder_names_the_next_milestone() {
    let sbom = sbom(CALENDAR);
    let at = |as_of| nist(ComplianceLevel::NistPqc, as_of, &sbom);
    let ecdh = |as_of| {
        dated(finding(
            &at(as_of),
            "SBOM-PQC-001",
            "crypto/algorithm/ecdh-p256",
        ))
        .0
    };
    assert_eq!(ecdh(D2026), Sev::Info);
    assert_eq!(ecdh(D2031), Sev::Warning);
    assert_eq!(ecdh(D2036), Sev::Error);

    let r2026 = at(D2026);
    let info = finding(&r2026, "SBOM-PQC-001", "crypto/algorithm/ecdh-p256");
    assert_eq!(
        dated(info),
        (
            Sev::Info,
            Some(date("2030-12-31")),
            Some("NIST IR 8547 Table 4")
        )
    );
    assert!(
        info.message
            .ends_with("deprecated after 2030 and disallowed after 2035 (NIST IR 8547 Table 4)"),
        "{}",
        info.message
    );
    let r2031 = at(D2031);
    let warning = finding(&r2031, "SBOM-PQC-001", "crypto/algorithm/ecdsa-p384");
    assert_eq!(
        dated(warning),
        (
            Sev::Warning,
            Some(date("2035-12-31")),
            Some("NIST IR 8547 Table 2")
        )
    );
    // RSA without a primitive could sign or establish keys: both tables.
    let rsa = finding(&r2031, "SBOM-PQC-001", "crypto/algorithm/rsa-3072");
    assert_eq!(
        rsa.deadline.as_ref().map(|d| d.source.as_str()),
        Some("NIST IR 8547 Tables 2 and 4")
    );

    // IR 8547's symmetric rows: SHA-1 (Table 8) and the 112-bit level
    // (§4.1.3), disallowed after 2030.
    let owned = |as_of, rule, component| {
        let result = at(as_of);
        let (severity, deadline, source) = dated(finding(&result, rule, component));
        (severity, deadline, source.map(str::to_string))
    };
    let table8 = Some("NIST IR 8547 Table 8".to_string());
    assert_eq!(
        owned(D2026, "SBOM-PQC-005", "crypto/algorithm/sha-1"),
        (Sev::Warning, Some(date("2030-12-31")), table8.clone())
    );
    assert_eq!(
        owned(D2031, "SBOM-PQC-005", "crypto/algorithm/sha-1"),
        (Sev::Error, Some(date("2030-12-31")), table8)
    );
    let section = Some("NIST IR 8547 §4.1.3".to_string());
    assert_eq!(
        owned(D2026, "SBOM-PQC-KEY-001", "crypto/key/hmac-key-112"),
        (Sev::Info, Some(date("2030-12-31")), section.clone())
    );
    assert_eq!(
        owned(D2031, "SBOM-PQC-KEY-001", "crypto/key/hmac-key-112"),
        (Sev::Error, Some(date("2030-12-31")), section)
    );
}

// ============================================================================
// Every finding names its deadline and source
// ============================================================================

/// The findings of the calendar fixture no schedule dates, per standard:
/// algorithms disallowed with no transition or outside every list, and the
/// evidence gap of a missing quantum level.
const UNDATED_PQC: &[(&str, &str)] = &[
    ("SBOM-PQC-001", "crypto/algorithm/dsa-2048"),
    ("SBOM-PQC-001", "crypto/algorithm/rsa-1024"),
    ("SBOM-PQC-005", "crypto/algorithm/md5"),
    ("SBOM-PQC-012", "crypto/algorithm/md5"),
    ("SBOM-PQC-KEY-001", "crypto/key/legacy-key-64"),
];
const UNDATED_CNSA2: &[(&str, &str)] = &[
    ("SBOM-CNSA2-ALG-005", "crypto/algorithm/md5"),
    ("SBOM-CNSA2-ALG-005", "crypto/algorithm/sha-1"),
    ("SBOM-CNSA2-ALG-006", "crypto/algorithm/dsa-2048"),
    ("SBOM-CNSA2-ALG-006", "crypto/algorithm/ecdh-p256"),
    ("SBOM-CNSA2-ALG-006", "crypto/algorithm/ed25519"),
    ("SBOM-CNSA2-ALG-006", "crypto/algorithm/rsa-1024"),
    ("SBOM-CNSA2-ALG-006", "crypto/algorithm/rsa-2048"),
    // The suite name's ECDHE and ECDSA name no curve, so they cannot be
    // shown to be CNSA 1.0; its groups and signature schemes can.
    ("SBOM-CNSA2-PROTO-002", "crypto/protocol/tls12"),
    // X25519MLKEM768 and mldsa65 are not CNSA 1.0 either.
    ("SBOM-CNSA2-PROTO-002", "crypto/protocol/tls13"),
    ("SBOM-CNSA2-PROTO-002", "crypto/protocol/tls13"),
];

/// In deadline mode every crypto finding names its deadline and the
/// schedule that sets it, also in its message; a finding no schedule dates
/// is one of a pinned few, keeps its readiness severity, and says why.
#[test]
fn every_deadline_mode_finding_names_its_deadline_and_source() {
    let sbom = sbom(CALENDAR);
    let configs = [
        (
            ComplianceLevel::NistPqc,
            PqcProfile::Nist,
            None,
            UNDATED_PQC,
        ),
        (
            ComplianceLevel::NistPqc,
            PqcProfile::Federal,
            None,
            UNDATED_PQC,
        ),
        (
            ComplianceLevel::Cnsa2,
            PqcProfile::Nist,
            None,
            UNDATED_CNSA2,
        ),
        (
            ComplianceLevel::Cnsa2,
            PqcProfile::Nist,
            Some(CnsaCategory::OperatingSystems),
            UNDATED_CNSA2,
        ),
    ];
    for (level, profile, category, expected_undated) in configs {
        for as_of in [D2026, D2031, D2036] {
            let result = deadline(level, as_of, profile, category, &sbom);
            let label = format!("[{level:?} {profile:?} {category:?} @ {as_of}]");
            let mut undated: Vec<(&str, &str)> = Vec::new();
            for v in &result.violations {
                match &v.deadline {
                    Some(d) => {
                        assert!(!d.source.trim().is_empty(), "{label} {}", v.rule_id);
                        assert!(
                            v.message.contains(&d.source),
                            "{label} {} names its source in the message: {}",
                            v.rule_id,
                            v.message
                        );
                    }
                    None => {
                        undated.push((v.rule_id, subject(v)));
                        assert_eq!(v.severity, readiness_severity(v), "{label} {}", v.rule_id);
                        if v.rule_id != "SBOM-PQC-012" {
                            assert!(
                                v.message.contains("no transition applies"),
                                "{label} {} says why it is undated: {}",
                                v.rule_id,
                                v.message
                            );
                        }
                    }
                }
            }
            undated.sort_unstable();
            let mut expected = expected_undated.to_vec();
            expected.sort_unstable();
            assert_eq!(undated, expected, "{label}");
        }
    }
}

/// The severity readiness mode gives a finding no schedule dates: an Error,
/// but for the missing-quantum-level Warning.
fn readiness_severity(v: &Violation) -> Sev {
    if v.rule_id == "SBOM-PQC-012" {
        Sev::Warning
    } else {
        Sev::Error
    }
}

// ============================================================================
// CNSA 2.0 categories
// ============================================================================

/// `--cnsa-category` picks the year CNSA 2.0 is to be preferred and the
/// year it is to be used exclusively; unset, the strictest applies.
#[test]
fn cnsa_category_picks_its_milestones() {
    let sbom = sbom(CALENDAR);
    // (category, at 2026-10-12, at 2031-06-01) for the CNSA 1.0 ECDSA-P384.
    let cases: [(Option<CnsaCategory>, (Sev, &str), (Sev, &str)); 7] = [
        (
            None,
            (Sev::Warning, "2030-12-31"),
            (Sev::Error, "2030-12-31"),
        ),
        (
            Some(CnsaCategory::SoftwareSigning),
            (Sev::Warning, "2030-12-31"),
            (Sev::Error, "2030-12-31"),
        ),
        (
            Some(CnsaCategory::WebCloud),
            (Sev::Warning, "2033-12-31"),
            (Sev::Warning, "2033-12-31"),
        ),
        (
            Some(CnsaCategory::Networking),
            (Sev::Info, "2026-12-31"),
            (Sev::Error, "2030-12-31"),
        ),
        (
            Some(CnsaCategory::OperatingSystems),
            (Sev::Info, "2027-12-31"),
            (Sev::Warning, "2033-12-31"),
        ),
        (
            Some(CnsaCategory::Niche),
            (Sev::Info, "2030-12-31"),
            (Sev::Warning, "2033-12-31"),
        ),
        (
            Some(CnsaCategory::CustomLegacy),
            (Sev::Warning, "2033-12-31"),
            (Sev::Warning, "2033-12-31"),
        ),
    ];
    for (category, in_2026, in_2031) in cases {
        for (as_of, (severity, deadline_date)) in [(D2026, in_2026), (D2031, in_2031)] {
            let result = deadline(
                ComplianceLevel::Cnsa2,
                as_of,
                PqcProfile::Nist,
                category,
                &sbom,
            );
            let v = finding(&result, "SBOM-CNSA2-ALG-006", "crypto/algorithm/ecdsa-p384");
            let source = category.map_or("strictest category", CnsaCategory::label);
            assert_eq!(
                dated(v),
                (
                    severity,
                    Some(date(deadline_date)),
                    Some(format!("CNSA 2.0 timeline: {source}").as_str())
                ),
                "{category:?} @ {as_of}"
            );
        }
        // After 2033 every category uses CNSA 2.0 exclusively.
        let late = deadline(
            ComplianceLevel::Cnsa2,
            "2034-01-01T00:00:00Z",
            PqcProfile::Nist,
            category,
            &sbom,
        );
        assert_eq!(
            finding(&late, "SBOM-CNSA2-ALG-006", "crypto/algorithm/ecdsa-p384").severity,
            Sev::Error,
            "{category:?}"
        );
    }
    // What CNSA 1.0 never allowed is an error in every category.
    for category in CnsaCategory::ALL {
        let result = deadline(
            ComplianceLevel::Cnsa2,
            D2026,
            PqcProfile::Nist,
            Some(category),
            &sbom,
        );
        let v = finding(&result, "SBOM-CNSA2-ALG-006", "crypto/algorithm/rsa-2048");
        assert_eq!(dated(v), (Sev::Error, None, None), "{category:?}");
    }
}

// ============================================================================
// Certificates
// ============================================================================

/// A certificate keeps its signature until it expires, so it is judged on
/// the later of the evaluation date and its notValidAfter.
#[test]
fn certificates_are_judged_on_the_later_of_as_of_and_not_valid_after() {
    let sbom = sbom(CALENDAR);
    let ecdsa_cert = "crypto/certificate/gateway-ecdsa"; // notValidAfter 2033-06-30
    let rsa_cert = "crypto/certificate/gateway-rsa"; // notValidAfter 2027-06-01

    // NIST IR 8547 in 2026: the ECDSA certificate signs into the 2031–2035
    // deprecation window, the RSA one expires before it.
    let r2026 = nist(ComplianceLevel::NistPqc, D2026, &sbom);
    let ecdsa = finding(&r2026, "SBOM-PQC-CERT-001", ecdsa_cert);
    assert_eq!(
        dated(ecdsa),
        (
            Sev::Warning,
            Some(date("2035-12-31")),
            Some("NIST IR 8547 Table 2")
        )
    );
    assert!(
        ecdsa.message.contains("valid until 2033-06-30"),
        "{}",
        ecdsa.message
    );
    let rsa = finding(&r2026, "SBOM-PQC-CERT-001", rsa_cert);
    assert_eq!(dated(rsa).0, Sev::Info);
    assert!(
        rsa.message.contains("valid until 2027-06-01"),
        "{}",
        rsa.message
    );
    // The algorithm asset itself is judged on the evaluation date.
    assert_eq!(
        finding(&r2026, "SBOM-PQC-001", "crypto/algorithm/ecdsa-p384").severity,
        Sev::Info
    );

    // Once a certificate has expired, the evaluation date is the later one.
    let r2028 = nist(ComplianceLevel::NistPqc, "2028-01-01T00:00:00Z", &sbom);
    let expired = finding(&r2028, "SBOM-PQC-CERT-001", rsa_cert);
    assert_eq!(dated(expired).0, Sev::Info);
    assert!(
        !expired.message.contains("valid until"),
        "{}",
        expired.message
    );

    // The federal signature deadline, 2031-12-31, falls before the ECDSA
    // certificate's expiry.
    let federal = deadline(
        ComplianceLevel::NistPqc,
        D2026,
        PqcProfile::Federal,
        None,
        &sbom,
    );
    assert_eq!(
        dated(finding(&federal, "SBOM-PQC-CERT-001", ecdsa_cert)),
        (
            Sev::Error,
            Some(date("2031-12-31")),
            Some("EO 14412 §4(b)(iii), OMB M-26-15")
        )
    );

    // CNSA 2.0, strictest timeline: exclusive use by 2030 comes before 2033.
    let cnsa = nist(ComplianceLevel::Cnsa2, D2026, &sbom);
    assert_eq!(
        finding(&cnsa, "SBOM-CNSA2-CERT-001", ecdsa_cert).severity,
        Sev::Error
    );
    assert_eq!(
        finding(&cnsa, "SBOM-CNSA2-CERT-001", rsa_cert).severity,
        Sev::Warning
    );
}

// ============================================================================
// The federal profile
// ============================================================================

#[test]
fn federal_profile_applies_the_eo_14412_and_m_26_15_deadlines() {
    let sbom = sbom(CALENDAR);
    let at = |as_of| {
        deadline(
            ComplianceLevel::NistPqc,
            as_of,
            PqcProfile::Federal,
            None,
            &sbom,
        )
    };
    let ke = "EO 14412 §4(b)(ii), OMB M-26-15";
    let sig = "EO 14412 §4(b)(iii), OMB M-26-15";

    let r2026 = at(D2026);
    assert_eq!(
        dated(finding(
            &r2026,
            "SBOM-PQC-001",
            "crypto/algorithm/ecdh-p256"
        )),
        (Sev::Warning, Some(date("2030-12-31")), Some(ke))
    );
    assert_eq!(
        dated(finding(
            &r2026,
            "SBOM-PQC-001",
            "crypto/algorithm/ecdsa-p384"
        )),
        (Sev::Warning, Some(date("2031-12-31")), Some(sig))
    );
    // Use not stated: the earlier, key-establishment deadline, and why.
    let rsa = finding(&r2026, "SBOM-PQC-001", "crypto/algorithm/rsa-3072");
    assert_eq!(
        dated(rsa),
        (Sev::Warning, Some(date("2030-12-31")), Some(ke))
    );
    assert!(
        rsa.message
            .contains("does not say whether it signs or establishes keys"),
        "{}",
        rsa.message
    );
    // TLS 1.2 against the TLS 1.3 deadline; TLS 1.3 passes.
    assert_eq!(
        dated(finding(
            &r2026,
            "SBOM-PQC-PROTO-003",
            "crypto/protocol/tls12"
        )),
        (
            Sev::Warning,
            Some(date("2030-01-02")),
            Some("EO 14306, OMB M-26-15")
        )
    );
    assert!(
        !r2026
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-003" && subject(v) == "crypto/protocol/tls13")
    );

    // After the TLS deadline, before the key-establishment one.
    let r2030 = at("2030-06-01T00:00:00Z");
    assert_eq!(
        finding(&r2030, "SBOM-PQC-PROTO-003", "crypto/protocol/tls12").severity,
        Sev::Error
    );
    assert_eq!(
        finding(&r2030, "SBOM-PQC-001", "crypto/algorithm/ecdh-p256").severity,
        Sev::Warning
    );
    // After the key-establishment deadline, before the signature one.
    let r2031 = at(D2031);
    assert_eq!(
        finding(&r2031, "SBOM-PQC-001", "crypto/algorithm/ecdh-p256").severity,
        Sev::Error
    );
    assert_eq!(
        finding(&r2031, "SBOM-PQC-001", "crypto/algorithm/ecdsa-p384").severity,
        Sev::Warning
    );
    let r2032 = at("2032-01-01T00:00:00Z");
    assert_eq!(
        finding(&r2032, "SBOM-PQC-001", "crypto/algorithm/ecdsa-p384").severity,
        Sev::Error
    );

    // The NIST profile sets no TLS deadline.
    let plain = nist(ComplianceLevel::NistPqc, "2030-06-01T00:00:00Z", &sbom);
    assert!(
        !plain
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-003")
    );
}

// ============================================================================
// Output surfaces
// ============================================================================

/// The deadline reaches the JSON envelope (two fields, both or neither,
/// valid against the published schema), the SARIF result properties, and a
/// serde round trip.
#[test]
fn deadline_reaches_json_sarif_and_a_round_trip() {
    let sbom = sbom(CALENDAR);
    let result = nist(ComplianceLevel::NistPqc, D2026, &sbom);

    let json: Value =
        serde_json::from_str(&generate_compliance_json(std::slice::from_ref(&result)).unwrap())
            .unwrap();
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_PATH).unwrap()).unwrap();
    if let Err(errors) = json_schema::validate(&json_schema::strict_copy(&schema), &json) {
        panic!(
            "{} schema violation(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
    let violations = json["results"][0]["violations"].as_array().unwrap();
    for v in violations {
        assert_eq!(
            v.get("deadline").is_some(),
            v.get("deadline_source").is_some(),
            "{v}"
        );
    }
    let ecdh = violations
        .iter()
        .find(|v| {
            v["rule_id"] == "SBOM-PQC-001" && v["component_id"] == "crypto/algorithm/ecdh-p256"
        })
        .unwrap();
    assert_eq!(ecdh["deadline"], "2030-12-31");
    assert_eq!(ecdh["deadline_source"], "NIST IR 8547 Table 4");
    let dsa = violations
        .iter()
        .find(|v| {
            v["rule_id"] == "SBOM-PQC-001" && v["component_id"] == "crypto/algorithm/dsa-2048"
        })
        .unwrap();
    assert!(dsa.get("deadline").is_none(), "{dsa}");

    let sarif: Value = serde_json::from_str(
        &generate_compliance_sarif_with(&result, &SarifOptions::new()).unwrap(),
    )
    .unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let dated_results: Vec<&Value> = results
        .iter()
        .filter(|r| r["properties"].get("deadline").is_some())
        .collect();
    assert_eq!(
        dated_results.len(),
        result
            .violations
            .iter()
            .filter(|v| v.deadline.is_some())
            .count()
    );
    for r in &dated_results {
        assert!(r["properties"]["deadlineSource"].is_string(), "{r}");
        assert!(r["properties"].get("deadline_source").is_none(), "{r}");
    }
    let ecdh = results
        .iter()
        .find(|r| {
            r["ruleId"] == "SBOM-PQC-001"
                && r["properties"]["componentId"] == "crypto/algorithm/ecdh-p256"
        })
        .unwrap();
    assert_eq!(ecdh["properties"]["deadline"], "2030-12-31");
    assert_eq!(ecdh["properties"]["deadlineSource"], "NIST IR 8547 Table 4");
    assert_eq!(ecdh["level"], "note");

    // A dated result survives a serde round trip; an old payload without
    // the fields reads as undated.
    let text = serde_json::to_string(&result).unwrap();
    let back: ComplianceResult = serde_json::from_str(&text).unwrap();
    let deadlines = |r: &ComplianceResult| {
        r.violations
            .iter()
            .map(|v| v.deadline.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(deadlines(&back), deadlines(&result));
    let mut old: Value = serde_json::from_str(&text).unwrap();
    for v in old["violations"].as_array_mut().unwrap() {
        let obj = v.as_object_mut().unwrap();
        obj.remove("deadline");
        obj.remove("deadline_source");
    }
    let old: ComplianceResult = serde_json::from_value(old).unwrap();
    assert!(old.violations.iter().all(|v| v.deadline.is_none()));
}

/// Readiness output carries no deadline field anywhere.
#[test]
fn readiness_output_has_no_deadline_fields() {
    let sbom = sbom(CALENDAR);
    let results = [
        readiness(ComplianceLevel::NistPqc, D2026, &sbom),
        readiness(ComplianceLevel::Cnsa2, D2026, &sbom),
    ];
    let json = generate_compliance_json(&results).unwrap();
    assert!(!json.contains("\"deadline"), "{json}");
    for result in &results {
        let sarif = generate_compliance_sarif_with(result, &SarifOptions::new()).unwrap();
        assert!(
            !sarif.contains("\"deadline"),
            "readiness SARIF has no deadline"
        );
    }
}

// ============================================================================
// CLI
// ============================================================================

fn validate(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .arg("--no-color")
        .arg("validate")
        .args(args)
        .env("RUST_LOG", "error")
        .env("RUST_LOG_STYLE", "never")
        .output()
        .expect("validate runs")
}

fn fixture(rel: &str) -> String {
    Path::new(FIXTURES_DIR)
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

/// A CBOM migrating on schedule fails readiness mode but passes deadline
/// mode in 2026; its deprecated algorithms warn in 2031.
#[test]
fn cli_deadline_mode_gates_by_the_calendar() {
    let transition = fixture("cyclonedx/cbom-pqc-transition.cdx.json");
    let code = |extra: &[&str]| {
        let mut args = vec![transition.as_str(), "--standard", "pqc", "--summary"];
        args.extend_from_slice(extra);
        validate(&args).status.code()
    };
    assert_eq!(code(&["--as-of", "2026-10-12"]), Some(1));
    assert_eq!(
        code(&["--as-of", "2026-10-12", "--pqc-mode", "deadline"]),
        Some(0)
    );
    assert_eq!(
        code(&[
            "--as-of",
            "2031-06-01",
            "--pqc-mode",
            "deadline",
            "--fail-on-warning"
        ]),
        Some(2)
    );
    assert_eq!(
        code(&["--as-of", "2036-06-01", "--pqc-mode", "deadline"]),
        Some(1)
    );
}

/// The text report gives each dated finding a `deadline:` line.
#[test]
fn cli_text_output_has_a_deadline_line() {
    let out = validate(&[
        &fixture(CALENDAR),
        "--standard",
        "pqc",
        "--as-of",
        "2026-10-12",
        "--pqc-mode",
        "deadline",
    ]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("  deadline: 2030-12-31 (NIST IR 8547 Table 4)\n"),
        "{text}"
    );
    let readiness = validate(&[
        &fixture(CALENDAR),
        "--standard",
        "pqc",
        "--as-of",
        "2026-10-12",
    ]);
    assert!(
        !String::from_utf8(readiness.stdout)
            .unwrap()
            .contains("deadline:")
    );
}

/// `-o json` in deadline mode carries the fields, as the schema describes.
#[test]
fn cli_json_output_carries_deadline_fields() {
    let out = validate(&[
        &fixture(CALENDAR),
        "--standard",
        "cnsa2,pqc",
        "--as-of",
        "2031-06-01",
        "--pqc-mode",
        "deadline",
        "--pqc-profile",
        "federal",
        "--cnsa-category",
        "niche",
        "-o",
        "json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_PATH).unwrap()).unwrap();
    if let Err(errors) = json_schema::validate(&json_schema::strict_copy(&schema), &json) {
        panic!(
            "{} schema violation(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
    let sources: Vec<&str> = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["violations"].as_array().unwrap())
        .filter_map(|v| v["deadline_source"].as_str())
        .collect();
    assert!(sources.contains(&"CNSA 2.0 timeline: niche equipment"));
    assert!(sources.contains(&"EO 14306, OMB M-26-15"));
}

/// `--pqc-profile` and `--cnsa-category` only change deadline mode, so
/// without it they are a usage error (exit 3), not silently ignored.
#[test]
fn cli_profile_and_category_need_deadline_mode() {
    let calendar = fixture(CALENDAR);
    for extra in [
        &["--pqc-profile", "federal"][..],
        &["--cnsa-category", "niche"][..],
        &["--pqc-mode", "readiness", "--pqc-profile", "nist"][..],
    ] {
        let mut args = vec![calendar.as_str(), "--standard", "pqc", "--summary"];
        args.extend_from_slice(extra);
        let out = validate(&args);
        assert_eq!(out.status.code(), Some(3), "{extra:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--pqc-mode deadline"),
            "{extra:?}: {stderr}"
        );
    }
    // A mistyped value is clap's usage error, listing the valid ones.
    let out = validate(&[&calendar, "--pqc-mode", "deadlines"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("readiness") && stderr.contains("deadline"),
        "{stderr}"
    );
}

/// `quality --profile cbom` embeds NIST PQC, so it takes the same mode: the
/// on-schedule CBOM is non-compliant in readiness mode and compliant in
/// deadline mode in 2026.
#[test]
fn cli_quality_cbom_profile_takes_the_pqc_mode() {
    let transition = fixture("cyclonedx/cbom-pqc-transition.cdx.json");
    let quality = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
            .arg("--no-color")
            .arg("quality")
            .arg(&transition)
            .args([
                "--profile",
                "cbom",
                "--fail-on-noncompliant",
                "--as-of",
                "2026-10-12",
                "-o",
                "json",
            ])
            .args(extra)
            .env("RUST_LOG", "error")
            .output()
            .expect("quality runs")
    };
    assert_eq!(quality(&[]).status.code(), Some(1));
    let dated = quality(&["--pqc-mode", "deadline"]);
    assert_eq!(
        dated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&dated.stderr)
    );
    let json: Value = serde_json::from_slice(&dated.stdout).unwrap();
    let violations = json["report"]["compliance"]["violations"]
        .as_array()
        .unwrap();
    assert!(!violations.is_empty());
    assert!(
        violations
            .iter()
            .all(|v| v["severity"] == "Info" && v["deadline"] == "2030-12-31"),
        "{violations:#?}"
    );
    // The profile without deadline mode is a usage error here too.
    assert_eq!(
        quality(&["--pqc-profile", "federal"]).status.code(),
        Some(3)
    );
}

/// Every command that checks compliance takes the PQC flags from the one
/// shared definition and holds them to one rule: deadline mode with a
/// profile and a category is accepted, and `--pqc-profile` or
/// `--cnsa-category` without it is a usage error (exit 3), not silently
/// ignored. (`cra-docs` reads none of them, but takes them like the rest.)
#[test]
fn cli_every_compliance_command_takes_the_pqc_flags() {
    let calendar = fixture(CALENDAR);
    let dir = tempfile::tempdir().expect("temp dir");
    let dossier = dir.path().join("dossier");
    let dossier = dossier.to_str().expect("UTF-8 temp path");
    let commands: [&[&str]; 5] = [
        &[
            "validate",
            &calendar,
            "--standard",
            "cnsa2,pqc",
            "--summary",
        ],
        &["quality", &calendar, "--profile", "cbom", "-o", "json"],
        &["view", &calendar, "-o", "json"],
        &["diff", &calendar, &calendar, "-o", "json"],
        &["cra-docs", &calendar, "--output", dossier, "--force"],
    ];
    let run = |command: &[&str], extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
            .arg("--no-color")
            .args(command)
            .args(["--as-of", "2031-06-01"])
            .args(extra)
            .env("RUST_LOG", "error")
            .env("RUST_LOG_STYLE", "never")
            .output()
            .expect("command runs")
    };
    for command in commands {
        let accepted = run(
            command,
            &[
                "--pqc-mode",
                "deadline",
                "--pqc-profile",
                "federal",
                "--cnsa-category",
                "niche",
            ],
        );
        assert_ne!(
            accepted.status.code(),
            Some(3),
            "{}: {}",
            command[0],
            String::from_utf8_lossy(&accepted.stderr)
        );
        for extra in [
            &["--pqc-profile", "federal"][..],
            &["--cnsa-category", "niche"][..],
        ] {
            let refused = run(command, extra);
            assert_eq!(refused.status.code(), Some(3), "{} {extra:?}", command[0]);
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(
                stderr.contains("--pqc-mode deadline"),
                "{} {extra:?}: {stderr}",
                command[0]
            );
        }
    }
}
