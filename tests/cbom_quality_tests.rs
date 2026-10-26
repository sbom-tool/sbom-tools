//! CBOM evaluation must judge cryptographic assets on their cryptography,
//! not on package fields they cannot have (issue #370): a crypto asset has
//! no package version, supplier, license or hash, so the package-only
//! elements are scoped away from it (as for File entries), and the CBOM
//! quality profile embeds NIST PQC rather than the generic package checks.
//! Real findings — broken algorithms, unclassifiable assets — must stay.

#[path = "common/clock.rs"]
mod clock;

use clock::{as_of, checker};
use sbom_tools::{
    model::NormalizedSbom,
    parsers::{parse_sbom, parse_sbom_str},
    quality::{ComplianceLevel, QualityScorer, ScoringProfile, Violation, ViolationSeverity},
};
use std::path::Path;

fn sparse_cbom() -> NormalizedSbom {
    parse_sbom(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cyclonedx/cbom-1.7-sparse-ike.cdx.json"),
    )
    .expect("fixture parses")
}

const CRYPTO_ASSETS: [&str; 6] = [
    "IKEv1",
    "SSH",
    "HMAC_SHA1",
    "modp1024",
    "AES-128-CBC",
    "3DES",
];

/// Package-only findings: NTIA/CRA component elements and the quality
/// profiles' license/hash recommendations (all reported under the
/// SBOM-QUALITY-GENERAL SARIF rule).
fn is_package_finding(v: &Violation) -> bool {
    v.rule_id.starts_with("SBOM-NTIA-")
        || v.rule_id.starts_with("SBOM-CRA-COMPONENT-")
        || v.sarif_rule_id() == "SBOM-QUALITY-GENERAL"
}

fn names_crypto_asset(v: &Violation) -> bool {
    CRYPTO_ASSETS
        .iter()
        .any(|n| v.element.as_deref() == Some(*n) || v.message.contains(&format!("'{n}'")))
}

#[test]
fn cbom_profile_embeds_nist_pqc_not_package_checks() {
    let report = QualityScorer::new(ScoringProfile::Cbom).score(&sparse_cbom());
    assert_eq!(report.compliance.level, ComplianceLevel::NistPqc);

    let package: Vec<_> = report
        .compliance
        .violations
        .iter()
        .filter(|v| is_package_finding(v))
        .collect();
    assert!(
        package.is_empty(),
        "no package-only findings on a CBOM: {package:?}"
    );

    // Real cryptographic findings stay.
    for broken in ["HMAC_SHA1", "3DES"] {
        assert!(
            report
                .compliance
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-005"
                    && v.severity == ViolationSeverity::Error
                    && v.element.as_deref() == Some(broken)),
            "{broken} must still be reported broken: {:?}",
            report.compliance.violations
        );
    }
}

#[test]
fn package_standards_do_not_require_package_fields_of_crypto_assets() {
    let sbom = sparse_cbom();
    for level in [
        ComplianceLevel::NtiaMinimum,
        ComplianceLevel::Standard,
        ComplianceLevel::Comprehensive,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::Cisa2026,
    ] {
        let offending: Vec<_> = checker(level)
            .check(&sbom)
            .violations
            .into_iter()
            .filter(|v| {
                names_crypto_asset(v)
                    && v.category != sbom_tools::quality::ViolationCategory::CryptographyInfo
            })
            .collect();
        assert!(
            offending.is_empty(),
            "{level:?}: crypto assets must not be held to package elements: {offending:?}"
        );
    }
}

/// In a mixed document the carve-out is per component: a package without a
/// version is still flagged, the crypto asset next to it is not.
#[test]
fn mixed_sbom_still_holds_packages_to_ntia() {
    let sbom = parse_sbom_str(
        r#"{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,
            "metadata":{"timestamp":"2026-10-04T00:00:00Z"},
            "components":[
              {"type":"library","bom-ref":"openssl","name":"openssl"},
              {"type":"cryptographic-asset","bom-ref":"aes","name":"AES-256-GCM",
               "cryptoProperties":{"assetType":"algorithm",
                 "algorithmProperties":{"primitive":"ae","algorithmFamily":"AES","parameterSetIdentifier":"256"}}}]}"#,
    )
    .expect("parses");
    let violations = checker(ComplianceLevel::NtiaMinimum)
        .check(&sbom)
        .violations;
    for rule in ["SBOM-NTIA-VERSION", "SBOM-NTIA-SUPPLIER"] {
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == rule && v.element.as_deref() == Some("openssl")),
            "the openssl package must still get {rule}: {violations:?}"
        );
        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == rule && v.element.as_deref() == Some("AES-256-GCM")),
            "the crypto asset must not get {rule}: {violations:?}"
        );
    }
}

/// `modp1024` is the IKE name for 1024-bit finite-field DH: it must be
/// classified (quantum-vulnerable), not reported as unclassifiable.
#[test]
fn ike_group_names_are_classified() {
    let result = checker(ComplianceLevel::Cnsa2).check(&sparse_cbom());
    let modp: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.element.as_deref() == Some("modp1024"))
        .collect();
    assert!(
        modp.iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006" && v.message.contains("DH-1024")),
        "modp1024 must be judged as DH-1024: {modp:?}"
    );
    assert!(
        !modp.iter().any(|v| v.rule_id == "SBOM-CNSA2-ALG-UNKNOWN"),
        "modp1024 is not unclassifiable: {modp:?}"
    );
}

/// The quality metrics must count exactly the algorithms the compliance
/// engine calls broken — `HMAC_SHA1` used to escape a `starts_with` check,
/// so the score was softer than `validate` on the same file.
#[test]
fn quality_weak_count_matches_compliance_verdict() {
    let sbom = sparse_cbom();
    let report = QualityScorer::new(ScoringProfile::Cbom)
        .with_as_of(as_of())
        .score(&sbom);
    let cm = &report.cryptography_metrics;
    let mut weak = cm.weak_algorithm_names.clone();
    weak.sort();
    assert_eq!(weak, ["3DES", "HMAC_SHA1"]);

    let broken_by_compliance = checker(ComplianceLevel::NistPqc)
        .check(&sbom)
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-PQC-005")
        .count();
    assert_eq!(cm.weak_algorithm_count, broken_by_compliance);

    // modp1024 (DH) is quantum-vulnerable via the shared classifier.
    assert!(cm.quantum_vulnerable_count >= 1, "{cm:?}");
}

/// A protocol linked to its algorithms through `relatedCryptographicAssets`
/// (or `cryptoRefArray` / IKEv2 transforms) counts as linked in the CBOM
/// refs slot — only cipher suites used to count.
#[test]
fn refs_slot_counts_protocol_algorithm_references() {
    let sbom = parse_sbom(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cyclonedx/cbom-1.7-related-assets.cdx.json"),
    )
    .expect("fixture parses");
    let cm = QualityScorer::new(ScoringProfile::Cbom)
        .score(&sbom)
        .cryptography_metrics;
    assert_eq!(cm.protocols_count, 1);
    assert_eq!(cm.protocols_with_cipher_suites, 0);
    assert_eq!(cm.protocols_with_algorithm_refs, 1);
}
