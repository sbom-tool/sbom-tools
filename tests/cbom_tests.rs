//! CBOM (Cryptographic Bill of Materials) integration tests.
//!
//! Tests end-to-end parsing of CBOM fixtures, crypto property extraction,
//! PQC compliance checking (CNSA 2.0, NIST PQC), and diff engine crypto changes.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::{
    diff::DiffEngine,
    model::{ComponentType, CryptoAssetType},
    parsers::parse_sbom,
    quality::{ComplianceLevel, CryptographyMetrics, ViolationSeverity},
};
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Pinned evaluation instant for certificate-expiry assertions, so no test
/// changes verdict as real time passes (cbom-quantum-ready's certificate
/// expires on 2029-01-01).
fn as_of(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid timestamp")
        .with_timezone(&chrono::Utc)
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ============================================================================
// Parsing Tests
// ============================================================================

#[test]
fn parse_cbom_1_6_all_asset_types() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6.cdx.json")).unwrap();
    let sbom = &parsed;

    // Count crypto components
    let crypto: Vec<_> = sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::Cryptographic)
        .collect();
    assert!(
        crypto.len() >= 10,
        "expected >=10 crypto components, got {}",
        crypto.len()
    );

    // Verify algorithms have crypto_properties
    let aes = crypto
        .iter()
        .find(|c| c.name == "AES-256-GCM")
        .expect("AES-256-GCM not found");
    let cp = aes
        .crypto_properties
        .as_ref()
        .expect("missing crypto_properties");
    assert_eq!(cp.asset_type, CryptoAssetType::Algorithm);
    assert_eq!(cp.oid.as_deref(), Some("2.16.840.1.101.3.4.1.46"));
    let algo = cp
        .algorithm_properties
        .as_ref()
        .expect("missing algorithm_properties");
    assert_eq!(algo.classical_security_level, Some(256));
    assert_eq!(algo.nist_quantum_security_level, Some(1));
    assert!(algo.is_quantum_safe());
    assert!(!algo.is_weak());

    // Verify certificate
    let cert_comp = crypto
        .iter()
        .find(|c| c.name.contains("acme-webapp.example.com"))
        .expect("TLS cert not found");
    let cert_cp = cert_comp.crypto_properties.as_ref().unwrap();
    assert_eq!(cert_cp.asset_type, CryptoAssetType::Certificate);
    let cert = cert_cp
        .certificate_properties
        .as_ref()
        .expect("missing cert_properties");
    assert!(cert.subject_name.as_ref().unwrap().contains("acme-webapp"));
    assert!(cert.not_valid_after.is_some());

    // Verify key material
    let key = crypto
        .iter()
        .find(|c| c.name.contains("webapp-tls-public-key"))
        .expect("TLS public key not found");
    let key_cp = key.crypto_properties.as_ref().unwrap();
    assert_eq!(key_cp.asset_type, CryptoAssetType::RelatedCryptoMaterial);
    let mat = key_cp.related_crypto_material_properties.as_ref().unwrap();
    assert_eq!(mat.size, Some(2048));

    // Verify protocol
    let proto = crypto
        .iter()
        .find(|c| c.name == "TLS 1.2")
        .expect("TLS 1.2 not found");
    let proto_cp = proto.crypto_properties.as_ref().unwrap();
    assert_eq!(proto_cp.asset_type, CryptoAssetType::Protocol);
    let proto_props = proto_cp.protocol_properties.as_ref().unwrap();
    assert_eq!(proto_props.version.as_deref(), Some("1.2"));
    assert!(!proto_props.cipher_suites.is_empty());
}

#[test]
fn parse_cbom_1_7_provides_and_pqc() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.7.cdx.json")).unwrap();
    let sbom = &parsed;

    // Verify ML-KEM-1024 (post-quantum)
    let ml_kem = sbom
        .components
        .values()
        .find(|c| c.name == "ML-KEM-1024")
        .expect("ML-KEM-1024 not found");
    let algo = ml_kem
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert_eq!(algo.nist_quantum_security_level, Some(5));
    assert!(algo.is_quantum_safe());
    assert_eq!(algo.algorithm_family.as_deref(), Some("ML-KEM"));

    // Verify hybrid combiner
    let hybrid = sbom
        .components
        .values()
        .find(|c| c.name == "X25519-ML-KEM-768")
        .expect("Hybrid combiner not found");
    let hybrid_algo = hybrid
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert!(hybrid_algo.is_hybrid_pqc());
    assert_eq!(hybrid_algo.nist_quantum_security_level, Some(3));

    // Verify 'provides' edges exist
    let provides_edges: Vec<_> = sbom
        .edges
        .iter()
        .filter(|e| e.relationship == sbom_tools::model::DependencyType::Provides)
        .collect();
    assert!(
        !provides_edges.is_empty(),
        "expected Provides dependency edges from crypto-lib"
    );

    // Verify IKEv2 with transform types
    let ipsec = sbom
        .components
        .values()
        .find(|c| c.name.contains("IPsec"))
        .expect("IPsec protocol not found");
    let proto = ipsec
        .crypto_properties
        .as_ref()
        .unwrap()
        .protocol_properties
        .as_ref()
        .unwrap();
    assert!(proto.ikev2_transform_types.is_some());
    let ike = proto.ikev2_transform_types.as_ref().unwrap();
    assert!(!ike.encr.is_empty());
    assert!(!ike.ke.is_empty());
}

#[test]
fn parse_cbom_weak_crypto() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let sbom = &parsed;

    // Verify weak algorithms are detected
    let md5 = sbom
        .components
        .values()
        .find(|c| c.name == "MD5")
        .expect("MD5 not found");
    let algo = md5
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert!(algo.is_weak_by_name("MD5"));
    assert!(!algo.is_quantum_safe());

    // Verify expired certificate
    let expired = sbom
        .components
        .values()
        .find(|c| c.name.contains("expired"))
        .expect("expired cert not found");
    let cert = expired
        .crypto_properties
        .as_ref()
        .unwrap()
        .certificate_properties
        .as_ref()
        .unwrap();
    assert!(cert.is_expired());

    // Verify compromised key
    let compromised = sbom
        .components
        .values()
        .find(|c| c.name.contains("compromised"))
        .expect("compromised key not found");
    let mat = compromised
        .crypto_properties
        .as_ref()
        .unwrap()
        .related_crypto_material_properties
        .as_ref()
        .unwrap();
    assert_eq!(
        mat.state,
        Some(sbom_tools::model::CryptoMaterialState::Compromised)
    );
}

// ============================================================================
// Quality Metrics Tests
// ============================================================================

#[test]
fn crypto_metrics_quantum_ready() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-quantum-ready.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom_at(&parsed, as_of("2026-10-12T00:00:00Z"));

    assert!(metrics.has_data());
    assert!(metrics.algorithms_count >= 10);
    assert_eq!(metrics.weak_algorithm_count, 0);
    assert_eq!(metrics.expired_certificates, 0);
    assert_eq!(metrics.compromised_keys, 0);
    assert!(
        metrics.quantum_readiness_score().expect("has algorithms") > 90.0,
        "expected >90% quantum readiness"
    );
    assert!(metrics.quality_score().unwrap() > 80.0);
}

/// `--as-of` reaches certificate expiry in the quality metrics: the same
/// certificate is valid before 2029-01-01 and expired after it (review
/// finding T1 — the metrics read the wall clock regardless).
#[test]
fn crypto_metrics_judge_certificate_expiry_at_the_pinned_instant() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-quantum-ready.cdx.json")).unwrap();
    let before = CryptographyMetrics::from_sbom_at(&parsed, as_of("2026-10-12T00:00:00Z"));
    let after = CryptographyMetrics::from_sbom_at(&parsed, as_of("2030-06-01T00:00:00Z"));
    assert_eq!(before.expired_certificates, 0);
    assert_eq!(
        after.expired_certificates, 1,
        "the 2029 certificate has expired by 2030"
    );

    let report = sbom_tools::quality::QualityScorer::new(sbom_tools::quality::ScoringProfile::Cbom)
        .with_as_of(as_of("2030-06-01T00:00:00Z"))
        .score(&parsed);
    assert_eq!(
        report.cryptography_metrics.expired_certificates, 1,
        "QualityScorer::with_as_of must reach the cryptography metrics"
    );
}

#[test]
fn crypto_metrics_weak_crypto() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom_at(&parsed, as_of("2026-10-12T00:00:00Z"));

    assert!(metrics.has_data());
    assert!(metrics.weak_algorithm_count >= 5, "expected >=5 weak algos");
    // A broken algorithm counts as weak, not also as quantum-vulnerable
    // (review finding T1: broken primitives were counted twice).
    assert!(
        metrics.quantum_vulnerable_count + metrics.weak_algorithm_count <= metrics.algorithms_count,
        "an algorithm must land in at most one of the weak / quantum-vulnerable buckets: \
         {} + {} > {}",
        metrics.quantum_vulnerable_count,
        metrics.weak_algorithm_count,
        metrics.algorithms_count
    );
    assert!(metrics.expired_certificates >= 1);
    assert!(metrics.compromised_keys >= 1);
    assert!(
        metrics.quantum_readiness_score().expect("has algorithms") < 20.0,
        "expected <20% quantum readiness"
    );
    assert!(metrics.quality_score().unwrap() < 30.0);
}

#[test]
fn crypto_metrics_no_crypto_returns_none() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/minimal.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom(&parsed);

    assert!(!metrics.has_data());
    assert!(metrics.quality_score().is_none());
}

// ============================================================================
// Compliance Tests
// ============================================================================

#[test]
fn cnsa2_compliant_passes() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-cnsa2-compliant.cdx.json")).unwrap();
    let result = checker(ComplianceLevel::Cnsa2).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "CNSA 2.0 compliant fixture should have 0 errors, got {}:\n{}",
        errors.len(),
        errors
            .iter()
            .map(|v| format!("  - {}", v.message))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn cnsa2_violations_detected() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-cnsa2-violations.cdx.json")).unwrap();
    let result = checker(ComplianceLevel::Cnsa2).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.len() >= 5,
        "expected >=5 CNSA 2.0 errors, got {}:\n{}",
        errors.len(),
        errors
            .iter()
            .map(|v| format!("  - {}", v.message))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Verify specific violations
    let messages: Vec<_> = errors.iter().map(|v| v.message.as_str()).collect();
    assert!(
        messages.iter().any(|m| m.contains("AES-128")),
        "should flag AES-128"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("ML-KEM-768") || m.contains("ML-KEM-512")),
        "should flag ML-KEM sub-1024"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("RSA") || m.contains("ECDSA") || m.contains("ECDH")),
        "should flag quantum-vulnerable families"
    );
}

#[test]
fn nist_pqc_weak_crypto_violations() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let result = checker(ComplianceLevel::NistPqc).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.len() >= 5,
        "expected >=5 PQC errors for weak crypto, got {}",
        errors.len()
    );

    // Should detect broken algorithms
    let messages: Vec<_> = errors.iter().map(|v| v.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("MD5") || m.contains("SHA-1")),
        "should flag broken hashes"
    );
    assert!(
        messages.iter().any(|m| m.contains("quantum-vulnerable")),
        "should flag quantum-vulnerable algorithms"
    );
}

/// A realistic CycloneDX 1.6 CBOM (no `algorithmFamily` anywhere — a 1.7-only
/// field — and no `nistQuantumSecurityLevel`) must fail BOTH standards:
/// RSA-2048 is identified via its OID, AES-128-CBC via its name, and SHA-1
/// via its OID. Previously such CBOMs passed with zero violations.
#[test]
fn cyclonedx_16_cbom_without_family_fails_both_standards() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6-no-family.cdx.json")).unwrap();

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&parsed);
    assert!(!cnsa.is_compliant, "1.6 CBOM must not pass CNSA 2.0");
    let messages: Vec<_> = cnsa
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .map(|v| v.message.as_str())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("RSA")),
        "RSA-2048 (via OID) must be flagged: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("AES-128")),
        "AES-128-CBC (via name) must be flagged: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("SHA-1")),
        "SHA-1 (via OID) must be flagged: {messages:?}"
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&parsed);
    assert!(!pqc.is_compliant, "1.6 CBOM must not pass PQC readiness");
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error
                && v.message.contains("quantum-vulnerable")
                && v.message.contains("RSA")),
        "RSA-2048 must be flagged quantum-vulnerable without a declared level"
    );
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error && v.message.contains("SHA-1")),
        "SHA-1 must be flagged broken via OID"
    );
}

/// CycloneDX 1.6 names the curve `algorithmProperties.curve` (1.7 renamed it
/// `ellipticCurve`). An asset whose only identity signal is that curve must
/// be classified as quantum-vulnerable EC, not downgraded to an
/// unclassifiable Warning (issue #374).
#[test]
fn cyclonedx_16_curve_classifies_as_quantum_vulnerable_ec() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6-curve.cdx.json")).unwrap();

    let curve_of = |name: &str| {
        parsed
            .components
            .values()
            .find(|c| c.name == name)
            .and_then(|c| c.crypto_properties.as_ref())
            .and_then(|cp| cp.algorithm_properties.as_ref())
            .and_then(|a| a.elliptic_curve.clone())
    };
    assert_eq!(curve_of("key-exchange").as_deref(), Some("secp256r1"));
    assert_eq!(curve_of("token-signer").as_deref(), Some("secp384r1"));

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&parsed);
    for name in ["key-exchange", "token-signer"] {
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006"
                    && v.severity == ViolationSeverity::Error
                    && v.element.as_deref() == Some(name)),
            "{name} must be a CNSA 2.0 quantum-vulnerable Error: {:?}",
            cnsa.violations
        );
    }
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-UNKNOWN"),
        "a declared 1.6 curve must not leave the asset unclassifiable: {:?}",
        cnsa.violations
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&parsed);
    assert!(
        !pqc.is_compliant,
        "curve-only EC assets must fail PQC readiness"
    );
}

/// CycloneDX 1.7 replaces `signatureAlgorithmRef`, `subjectPublicKeyRef`,
/// `algorithmRef` and `cryptoRefArray` with typed
/// `relatedCryptographicAssets`. A 1.7-only CBOM must be parsed and judged
/// as fully as a 1.6 one: certificates and protocols that relate a
/// quantum-vulnerable algorithm fail, and a certificate relating several
/// algorithms is judged on all of them (fail closed), not the first.
#[test]
fn cyclonedx_17_related_crypto_assets_are_parsed_and_judged() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.7-related-assets.cdx.json")).unwrap();
    let props = |name: &str| {
        parsed
            .components
            .values()
            .find(|c| c.name == name)
            .and_then(|c| c.crypto_properties.clone())
            .unwrap_or_else(|| panic!("{name} must carry crypto properties"))
    };

    let mixed = props("mixed-cert").certificate_properties.unwrap();
    assert_eq!(mixed.related_crypto_assets.len(), 3);
    assert_eq!(
        mixed.signature_algorithm_refs(),
        ["crypto/algorithm/ml-dsa-87", "crypto/algorithm/rsa-2048"]
    );
    assert_eq!(
        mixed.subject_public_key_ref.as_deref(),
        Some("crypto/key/server-public-key")
    );
    assert_eq!(mixed.certificate_extension.as_deref(), Some("pem"));

    let key = props("server-public-key")
        .related_crypto_material_properties
        .unwrap();
    assert_eq!(
        key.algorithm_ref.as_deref(),
        Some("crypto/algorithm/rsa-2048")
    );

    let ssh = props("ssh-endpoint").protocol_properties.unwrap();
    assert_eq!(ssh.crypto_ref_array, ["crypto/algorithm/rsa-2048"]);

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&parsed);
    let has = |violations: &[sbom_tools::quality::Violation], rule: &str, name: &str| {
        violations.iter().any(|v| {
            v.rule_id == rule
                && v.severity == ViolationSeverity::Error
                && v.element.as_deref() == Some(name)
        })
    };
    assert!(
        has(&cnsa.violations, "SBOM-CNSA2-CERT-001", "mixed-cert"),
        "a certificate relating RSA must fail CNSA 2.0 even when ML-DSA is listed first: {:?}",
        cnsa.violations
    );
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.element.as_deref() == Some("pqc-cert")),
        "an ML-DSA-only certificate must pass CNSA 2.0: {:?}",
        cnsa.violations
    );
    assert!(
        has(&cnsa.violations, "SBOM-CNSA2-PROTO-002", "ssh-endpoint"),
        "a protocol relating RSA must fail CNSA 2.0: {:?}",
        cnsa.violations
    );
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.rule_id.ends_with("-UNKNOWN")),
        "1.7 typed references must resolve, not degrade to UNKNOWN: {:?}",
        cnsa.violations
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&parsed);
    assert!(
        has(&pqc.violations, "SBOM-PQC-CERT-001", "mixed-cert"),
        "a certificate relating RSA must fail PQC readiness: {:?}",
        pqc.violations
    );
    assert!(
        has(&pqc.violations, "SBOM-PQC-PROTO-002", "ssh-endpoint"),
        "a protocol relating RSA must fail PQC readiness: {:?}",
        pqc.violations
    );
}

/// CycloneDX 1.7 declares IKEv2 transforms as objects (`{name, keyLength,
/// algorithm}` / `{group, algorithm}`) where 1.6 used bom-ref strings. Such a
/// CBOM used to fail to parse at all (exit 3). Each transform must now be
/// judged by its reference, else its IANA name (with `keyLength` as the
/// size), else its key-exchange group, and the new `auth` list must count.
#[test]
fn cyclonedx_17_ikev2_transform_objects_are_parsed_and_judged() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.7-ikev2-objects.cdx.json"))
        .expect("a 1.7 CBOM with IKEv2 transform objects must parse");

    let ike = |name: &str| {
        parsed
            .components
            .values()
            .find(|c| c.name == name)
            .and_then(|c| c.crypto_properties.as_ref())
            .and_then(|cp| cp.protocol_properties.as_ref())
            .and_then(|p| p.ikev2_transform_types.clone())
            .unwrap_or_else(|| panic!("{name} must carry IKEv2 transform types"))
    };
    let legacy = ike("ipsec-legacy");
    assert_eq!(legacy.encr, ["ENCR_AES_CBC"]);
    assert_eq!(legacy.ke, ["DH-2048"]);
    assert_eq!(legacy.auth, ["RSA Digital Signature"]);
    assert_eq!(legacy.transforms.len(), 5);
    assert_eq!(legacy.transforms[0].key_length, Some(128));
    assert_eq!(ike("ipsec-cnsa").integ, ["crypto/algorithm/sha-384"]);

    let messages = |level| {
        checker(level)
            .check(&parsed)
            .violations
            .into_iter()
            .map(|v| (v.rule_id, v.severity, v.element, v.message))
            .collect::<Vec<_>>()
    };

    let cnsa = messages(ComplianceLevel::Cnsa2);
    let legacy_finding = cnsa
        .iter()
        .find(|(rule, sev, el, _)| {
            *rule == "SBOM-CNSA2-PROTO-002"
                && *sev == ViolationSeverity::Error
                && el.as_deref() == Some("ipsec-legacy")
        })
        .unwrap_or_else(|| panic!("ipsec-legacy must fail CNSA 2.0: {cnsa:?}"));
    for offender in ["AES-128", "SHA-1", "DH-2048", "RSA"] {
        assert!(
            legacy_finding.3.contains(offender),
            "{offender} must be named: {}",
            legacy_finding.3
        );
    }
    assert!(
        !legacy_finding.3.contains("SHA-384"),
        "the approved SHA-384 integrity transform must not be an offender: {}",
        legacy_finding.3
    );
    assert!(
        !cnsa
            .iter()
            .any(|(_, _, el, _)| el.as_deref() == Some("ipsec-cnsa")),
        "AES-256 + SHA-384 + ML-KEM-1024 (group 37) must pass CNSA 2.0: {cnsa:?}"
    );
    assert!(
        cnsa.iter().any(|(rule, sev, el, msg)| {
            *rule == "SBOM-CNSA2-PROTO-UNKNOWN"
                && *sev == ViolationSeverity::Error
                && el.as_deref() == Some("ipsec-opaque")
                && msg.contains("IKEv2 group 1000")
        }),
        "an unassigned key-exchange group must fail CNSA 2.0 closed, not pass: {cnsa:?}"
    );

    let pqc = messages(ComplianceLevel::NistPqc);
    assert!(
        pqc.iter().any(|(rule, sev, el, _)| {
            *rule == "SBOM-PQC-PROTO-002"
                && *sev == ViolationSeverity::Error
                && el.as_deref() == Some("ipsec-legacy")
        }),
        "ipsec-legacy must fail PQC readiness: {pqc:?}"
    );
    assert!(
        !pqc.iter()
            .any(|(_, sev, el, _)| *sev == ViolationSeverity::Error
                && el.as_deref() == Some("ipsec-cnsa")),
        "ipsec-cnsa must not fail PQC readiness: {pqc:?}"
    );
}

/// A protocol that declares only its type and version still cannot be
/// judged (no algorithms), so the UNKNOWN warning stays — but it must
/// acknowledge the declared version and name exactly what is missing,
/// never claim "no version" (issue #370). The 1.7 `ike` / `quic` protocol
/// types are recognized, not passed through as opaque strings.
#[test]
fn protocol_unknown_warning_acknowledges_declared_version() {
    use sbom_tools::model::ProtocolType;

    let parsed = parse_sbom(&fixture_path(
        "cyclonedx/cbom-1.7-protocol-versions.cdx.json",
    ))
    .unwrap();
    let proto_type = |name: &str| {
        parsed
            .components
            .values()
            .find(|c| c.name == name)
            .and_then(|c| c.crypto_properties.as_ref())
            .and_then(|cp| cp.protocol_properties.as_ref())
            .map(|p| p.protocol_type.clone())
    };
    assert_eq!(proto_type("IKEv1"), Some(ProtocolType::Ike));
    assert_eq!(proto_type("QUIC"), Some(ProtocolType::Quic));

    for (level, rule) in [
        (ComplianceLevel::Cnsa2, "SBOM-CNSA2-PROTO-UNKNOWN"),
        (ComplianceLevel::NistPqc, "SBOM-PQC-PROTO-UNKNOWN"),
    ] {
        let result = checker(level).check(&parsed);
        let message = |name: &str| {
            result
                .violations
                .iter()
                .find(|v| v.rule_id == rule && v.element.as_deref() == Some(name))
                .map(|v| v.message.clone())
                .unwrap_or_else(|| panic!("{rule} for {name}: {:?}", result.violations))
        };
        let ike = message("IKEv1");
        assert!(ike.contains("(ike 1.0)"), "{ike}");
        assert!(ike.contains("IKEv2 transform types"), "{ike}");
        assert!(!ike.contains("no version"), "{ike}");

        let ssh = message("SSH");
        assert!(ssh.contains("(ssh 2.0)"), "{ssh}");
        assert!(
            ssh.contains("cipher suites or algorithm references"),
            "{ssh}"
        );
        assert!(!ssh.contains("IKEv2"), "{ssh}");

        let quic = message("QUIC");
        assert!(quic.contains("(quic, no version)"), "{quic}");
    }
}

/// Protocol assets are now evaluated: the weak-crypto fixture's TLS 1.0
/// endpoint with RC4/3DES/DES suites must produce protocol violations under
/// both standards (previously protocols satisfied the inventory gate but got
/// zero checks) — and the weak fixture as a whole must fail CNSA 2.0, which
/// used to report it fully compliant.
#[test]
fn weak_crypto_protocols_and_cnsa2_verdict() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&parsed);
    assert!(
        !cnsa.is_compliant,
        "an MD5/SHA-1/DES/RC4 inventory must not be CNSA 2.0 compliant"
    );
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001" && v.message.contains("1.0")),
        "TLS 1.0 must fail the CNSA 2.0 TLS-1.3 gate"
    );
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-002" && v.message.contains("RC4")),
        "the RC4 cipher suite must be flagged under CNSA 2.0"
    );
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-005" && v.message.contains("MD5")),
        "MD5 (broken) must be flagged under the CNSA 2.0 allowlist"
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&parsed);
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
        "TLS 1.0 must fail the PQC minimum-version gate"
    );
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-002" && v.message.contains("broken")),
        "legacy cipher suites must be flagged under PQC"
    );
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-CERT-001"),
        "certificates signed with rsa-1024/sha1 must fire the PQC cert rule"
    );
}

/// A CBOM whose only assets carry unclassifiable crypto refs (a certificate
/// with a dangling opaque signatureAlgorithmRef, an IKEv2 protocol with
/// opaque transform refs) must NOT report a clean 100% pass: every
/// unverifiable asset is flagged (an Error under the CNSA 2.0 allowlist, a
/// Warning under PQC), and since nothing could be identified the inventory
/// gate fails too. Previously such CBOMs satisfied the gate while receiving
/// zero effective checks — a vacuous compliance claim.
#[test]
fn unclassifiable_refs_fail_instead_of_vacuous_pass() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-unclassifiable-refs.cdx.json")).unwrap();

    for (level, cert_rule, proto_rule, severity) in [
        (
            ComplianceLevel::Cnsa2,
            "SBOM-CNSA2-CERT-UNKNOWN",
            "SBOM-CNSA2-PROTO-UNKNOWN",
            ViolationSeverity::Error,
        ),
        (
            ComplianceLevel::NistPqc,
            "SBOM-PQC-CERT-UNKNOWN",
            "SBOM-PQC-PROTO-UNKNOWN",
            ViolationSeverity::Warning,
        ),
    ] {
        let result = checker(level).check(&parsed);
        assert!(
            result.violations.iter().any(|v| {
                v.severity == severity
                    && v.rule_id == cert_rule
                    && v.message.contains("sig-algo-42")
            }),
            "{level:?}: opaque cert sig ref must produce {cert_rule}; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        assert!(
            result.violations.iter().any(|v| {
                v.severity == severity
                    && v.rule_id == proto_rule
                    && v.message.contains("transform-encr-7")
            }),
            "{level:?}: opaque IKEv2 transform refs must produce {proto_rule}"
        );
        assert!(
            !result.is_compliant,
            "{level:?}: an inventory nothing could be identified in must not pass"
        );
    }
}

#[test]
fn nist_pqc_hybrid_transition_passes() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-pqc-transition.cdx.json")).unwrap();
    let result = checker(ComplianceLevel::NistPqc).check(&parsed);

    // Approved hybrid combiners are passed checks, not Info violations.
    assert!(
        result
            .passed
            .iter()
            .any(|p| p.rule_id == "SBOM-PQC-010" && p.message.contains("hybrid")),
        "should recognize hybrid PQC combiners as good practice: {:?}",
        result.passed
    );

    // So are approved PQC algorithms.
    assert!(
        result
            .passed
            .iter()
            .any(|p| p.rule_id == "SBOM-PQC-009" && p.message.contains("NIST-approved PQC")),
        "should recognize approved PQC algorithms: {:?}",
        result.passed
    );
    assert!(
        !result
            .violations
            .iter()
            .any(|v| matches!(v.rule_id, "SBOM-PQC-009" | "SBOM-PQC-010")),
        "an approval is never a violation: {:?}",
        result.violations
    );
}

// ============================================================================
// Diff Tests
// ============================================================================

#[test]
fn diff_weak_to_quantum_ready() {
    let old = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let new = parse_sbom(&fixture_path("cyclonedx/cbom-quantum-ready.cdx.json")).unwrap();

    let engine = DiffEngine::default();
    let result = engine.diff(&old, &new).unwrap();

    // Should detect many changes (different algorithms entirely)
    assert!(
        result.summary.total_changes > 0,
        "diff between weak and quantum-ready should detect changes"
    );
}

#[test]
fn parse_all_cbom_fixtures_successfully() {
    let fixtures = [
        "cyclonedx/cbom-1.6.cdx.json",
        "cyclonedx/cbom-1.6-no-family.cdx.json",
        "cyclonedx/cbom-1.6-curve.cdx.json",
        "cyclonedx/cbom-1.7.cdx.json",
        "cyclonedx/cbom-1.7-related-assets.cdx.json",
        "cyclonedx/cbom-1.7-ikev2-objects.cdx.json",
        "cyclonedx/cbom-1.7-protocol-versions.cdx.json",
        "cyclonedx/cbom-weak-crypto.cdx.json",
        "cyclonedx/cbom-quantum-ready.cdx.json",
        "cyclonedx/cbom-cnsa2-compliant.cdx.json",
        "cyclonedx/cbom-cnsa2-violations.cdx.json",
        "cyclonedx/cbom-pqc-transition.cdx.json",
        "cyclonedx/cbom-unclassifiable-refs.cdx.json",
    ];

    for fixture in &fixtures {
        let result = parse_sbom(&fixture_path(fixture));
        assert!(
            result.is_ok(),
            "Failed to parse {fixture}: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        let crypto_count = parsed
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::Cryptographic)
            .count();
        assert!(crypto_count > 0, "{fixture} should have crypto components");
    }
}

// ============================================================================
// Bom-ref Index Tests
// ============================================================================

#[test]
fn bom_ref_index_resolves_crypto_refs() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6.cdx.json")).unwrap();
    let sbom = &parsed;
    let index = sbom.build_index();

    // The cert references an algorithm via signatureAlgorithmRef
    let cert = sbom
        .components
        .values()
        .find(|c| c.name.contains("acme-webapp.example.com"))
        .expect("cert not found");
    let sig_ref = cert
        .crypto_properties
        .as_ref()
        .unwrap()
        .certificate_properties
        .as_ref()
        .unwrap()
        .signature_algorithm_ref
        .as_deref()
        .expect("missing sig ref");

    // Resolve the bom-ref through the index
    let resolved = index.resolve_bom_ref(sig_ref);
    assert!(resolved.is_some(), "should resolve bom-ref '{sig_ref}'");
}

/// A certificate's signature reference earns metric credit only when it
/// resolves inside the SBOM; a dangling opaque ref used to count.
#[test]
fn crypto_metrics_do_not_credit_dangling_refs() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-unclassifiable-refs.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom_at(&parsed, as_of("2026-10-12T00:00:00Z"));
    assert!(metrics.certificates_count >= 1);
    assert_eq!(
        metrics.certs_with_signature_algo_ref, 0,
        "the dangling 'sig-algo-42' reference must not count"
    );
}
