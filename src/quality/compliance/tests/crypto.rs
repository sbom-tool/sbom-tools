//! CNSA 2.0 and NIST PQC checks of cryptographic assets.

use super::*;

fn make_crypto_sbom(algos: &[(&str, &str, Option<&str>, Option<u8>)]) -> NormalizedSbom {
    use crate::model::{
        AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
    };
    let mut sbom = NormalizedSbom::default();
    for (name, family, param, ql) in algos {
        let mut c = crate::model::Component::new(name.to_string(), format!("{name}@1.0"));
        c.component_type = ComponentType::Cryptographic;
        let mut algo =
            AlgorithmProperties::new(CryptoPrimitive::Ae).with_algorithm_family(family.to_string());
        if let Some(p) = param {
            algo = algo.with_parameter_set_identifier(p.to_string());
        }
        if let Some(level) = ql {
            algo = algo.with_nist_quantum_security_level(*level);
        }
        c.crypto_properties =
            Some(CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(algo));
        sbom.add_component(c);
    }
    sbom
}

#[test]
fn test_cnsa2_aes128_violation() {
    let sbom = make_crypto_sbom(&[("AES-128-GCM", "AES", Some("128"), Some(1))]);
    let checker = checker(ComplianceLevel::Cnsa2);
    let result = checker.check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error && v.message.contains("AES-128")),
        "CNSA 2.0 should flag AES-128"
    );
}

#[test]
fn test_cnsa2_mlkem1024_passes() {
    let sbom = make_crypto_sbom(&[("ML-KEM-1024", "ML-KEM", Some("1024"), Some(5))]);
    let checker = checker(ComplianceLevel::Cnsa2);
    let result = checker.check(&sbom);
    let algo_errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| {
            v.severity == ViolationSeverity::Error && v.element.as_deref() == Some("ML-KEM-1024")
        })
        .collect();
    assert!(algo_errors.is_empty(), "ML-KEM-1024 should pass CNSA 2.0");
}

#[test]
fn test_pqc_quantum_vulnerable() {
    let sbom = make_crypto_sbom(&[("RSA-2048", "RSA", None, Some(0))]);
    let checker = checker(ComplianceLevel::NistPqc);
    let result = checker.check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error
                && v.message.contains("quantum-vulnerable")),
        "PQC should flag RSA-2048 as quantum-vulnerable"
    );
}

/// A plain SBOM with NO cryptographic inventory must NOT pass PQC/CNSA2 —
/// that was a vacuous false-pass. It now fails with an "inventory absent"
/// Error.
#[test]
fn crypto_standards_fail_on_empty_inventory() {
    let mut sbom = NormalizedSbom::default();
    sbom.add_component(crate::model::Component::new(
        "lodash".to_string(),
        "lodash@4.17.21".to_string(),
    ));
    for level in [ComplianceLevel::NistPqc, ComplianceLevel::Cnsa2] {
        let result = checker(level).check(&sbom);
        assert!(
            !result.is_compliant,
            "{level:?} must not report compliant with no crypto inventory"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.rule_id.ends_with("-000")),
            "{level:?} must emit an inventory-absent error"
        );
    }
}

/// A classical quantum-vulnerable algorithm (RSA/ECDSA/DH) must fail NIST
/// PQC even when nistQuantumSecurityLevel is UNSET (real CBOMs rarely set
/// it to an explicit 0).
#[test]
fn pqc_flags_classical_crypto_with_unset_quantum_level() {
    for family in ["RSA", "ECDSA", "ECDH", "DH", "DSA"] {
        let sbom = make_crypto_sbom(&[("classical", family, None, None)]);
        let result = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            !result.is_compliant,
            "{family} with unset quantum level must fail PQC"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-001"),
            "{family} must raise the quantum-vulnerable error"
        );
    }
}

/// SHA-224 and SHA-256 must fail CNSA 2.0 whether the size is in the family
/// string or the parameter (previously only family "SHA-2"/param "256"
/// was caught).
#[test]
fn cnsa2_flags_weak_sha2_in_either_encoding() {
    for (family, param) in [
        ("SHA-256", None),
        ("SHA-224", None),
        ("SHA-2", Some("256")),
        ("SHA-2", Some("224")),
    ] {
        let sbom = make_crypto_sbom(&[("hash", family, param, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
            "{family}/{param:?} must fail CNSA 2.0 hash gate"
        );
    }
    // SHA-384 passes the hash gate.
    let ok = make_crypto_sbom(&[("hash", "SHA-384", None, None)]);
    let result = checker(ComplianceLevel::Cnsa2).check(&ok);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
        "SHA-384 must not trip the hash gate"
    );
}

#[test]
fn test_pqc_approved_algorithm_is_a_passed_check() {
    let sbom = make_crypto_sbom(&[("ML-DSA-65", "ML-DSA", Some("65"), Some(3))]);
    let checker = checker(ComplianceLevel::NistPqc);
    let result = checker.check(&sbom);
    assert!(
        result
            .passed
            .iter()
            .any(|p| p.rule_id == "SBOM-PQC-009" && p.message.contains("approved")),
        "PQC should report ML-DSA-65 as approved: {:?}",
        result.passed
    );
    assert_eq!(result.info_count, 0, "an approval is no Info violation");
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-009"),
        "{:?}",
        result.violations
    );
    let pass = &result.passed[0];
    assert!(
        !pass.standard_refs.is_empty(),
        "check() back-fills the registry references of a pass"
    );
}

/// CNSA 2.0 is an exclusive allowlist: everything recognized but not on
/// it must Error — broken hashes, classical PK (including the families the
/// old blocklist missed: Ed25519/ECIES), non-CNSA symmetric ciphers,
/// sub-1024 or parameterless ML-KEM, and round-3 PQC names.
#[test]
fn cnsa2_allowlist_rejects_non_cnsa_algorithms() {
    for (family, param, expected_rule) in [
        ("SHA-1", None, "SBOM-CNSA2-ALG-005"),
        ("DES", None, "SBOM-CNSA2-ALG-005"),
        ("ChaCha20", None, "SBOM-CNSA2-ALG-008"),
        ("Ed25519", None, "SBOM-CNSA2-ALG-006"),
        ("ECIES", None, "SBOM-CNSA2-ALG-006"),
        ("EC", None, "SBOM-CNSA2-ALG-006"),
        ("Kyber", Some("768"), "SBOM-CNSA2-ALG-003"),
        ("ML-KEM-768", None, "SBOM-CNSA2-ALG-003"),
        ("ML-KEM", None, "SBOM-CNSA2-ALG-003"), // absent parameter set
        ("ML-DSA", Some("65"), "SBOM-CNSA2-ALG-004"),
        ("SLH-DSA", None, "SBOM-CNSA2-ALG-008"),
        ("SHA-3", Some("256"), "SBOM-CNSA2-ALG-008"),
        ("AES-128", None, "SBOM-CNSA2-ALG-001"), // size in family string
    ] {
        let sbom = make_crypto_sbom(&[("asset", family, param, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| { v.severity == ViolationSeverity::Error && v.rule_id == expected_rule }),
            "{family}/{param:?} must fail CNSA 2.0 with {expected_rule}; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        assert!(!result.is_compliant, "{family} must not be CNSA compliant");
    }
}

/// The full CNSA 2.0 suite passes the allowlist with zero errors:
/// AES-256, SHA-384, ML-KEM-1024, ML-DSA-87, and SP 800-208 LMS.
#[test]
fn cnsa2_allowlist_accepts_full_cnsa_suite() {
    let sbom = make_crypto_sbom(&[
        ("AES-256-GCM", "AES", Some("256"), Some(1)),
        ("SHA-384", "SHA-2", Some("384"), Some(2)),
        ("ML-KEM-1024", "ML-KEM", Some("1024"), Some(5)),
        ("ML-DSA-87", "ML-DSA", Some("87"), Some(5)),
        ("LMS", "LMS", None, Some(5)),
    ]);
    let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "full CNSA 2.0 suite must have zero errors, got {:?}",
        errors
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );
    assert!(result.is_compliant);
}

/// Unrecognizable algorithms fail CNSA 2.0 closed: it is an allowlist,
/// so an algorithm that cannot be identified cannot be shown to comply.
/// They also do not count as inventory, so a CBOM of unknowns fails the
/// CNSA2-000 gate.
#[test]
fn cnsa2_unknown_algorithm_fails_closed() {
    let sbom = make_crypto_sbom(&[("mystery", "proprietary-frobnicator", None, None)]);
    let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        result.violations.iter().any(|v| {
            v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-CNSA2-ALG-UNKNOWN"
        }),
        "unknown algorithm must fail closed with SBOM-CNSA2-ALG-UNKNOWN"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-000"),
        "an unidentifiable asset must not satisfy the inventory gate"
    );
    assert!(!result.is_compliant);
}

/// Under NIST PQC an unrecognizable algorithm warns (it cannot be
/// verified) instead of passing silently, and does not count as
/// inventory.
#[test]
fn pqc_unknown_algorithm_warns_and_is_not_inventory() {
    let sbom = make_crypto_sbom(&[("mystery", "proprietary-frobnicator", None, Some(5))]);
    let result = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        result.violations.iter().any(|v| {
            v.severity == ViolationSeverity::Warning && v.rule_id == "SBOM-PQC-ALG-UNKNOWN"
        }),
        "unknown algorithm must warn with SBOM-PQC-ALG-UNKNOWN even when it declares a level"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-000"),
        "an unidentifiable asset must not satisfy the inventory gate"
    );
}

/// A CycloneDX 1.6-style asset (no algorithmFamily) must still be
/// classified — via OID, or via the component name when both family and
/// OID are absent.
#[test]
fn cnsa2_classifies_without_algorithm_family() {
    use crate::model::{
        AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
    };
    let mut sbom = NormalizedSbom::default();
    // RSA via OID only.
    let mut rsa = crate::model::Component::new("RSA-2048".into(), "algo-1".into());
    rsa.component_type = ComponentType::Cryptographic;
    rsa.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Algorithm)
            .with_oid("1.2.840.113549.1.1.1".into())
            .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::Pke)),
    );
    sbom.add_component(rsa);
    // AES-128 via name only.
    let mut aes = crate::model::Component::new("AES-128-CBC".into(), "algo-2".into());
    aes.component_type = ComponentType::Cryptographic;
    aes.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Algorithm)
            .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::BlockCipher)),
    );
    sbom.add_component(aes);

    let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006" && v.message.contains("RSA")),
        "RSA must be flagged via OID without algorithmFamily"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-001" && v.message.contains("AES-128")),
        "AES-128 must be flagged via name without algorithmFamily/OID"
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-001" && v.message.contains("RSA")),
        "PQC must flag OID-only RSA as quantum-vulnerable"
    );
}

/// Spelling variants of broken algorithms must not escape SP 800-131A
/// detection under PQC.
#[test]
fn pqc_flags_broken_spelling_variants() {
    for family in ["SHA1", "TDES", "ARC4"] {
        let sbom = make_crypto_sbom(&[("legacy", family, None, None)]);
        let result = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-005"),
            "{family} must fail SP 800-131A broken-algorithm detection"
        );
    }
    // Silent case: a healthy modern hash raises no broken-algorithm error.
    let ok = make_crypto_sbom(&[("hash", "SHA-384", None, None)]);
    let result = checker(ComplianceLevel::NistPqc).check(&ok);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-005"),
        "SHA-384 must not be reported broken"
    );
}

fn make_protocol_sbom(version: &str, suite_name: &str, suite_algos: &[&str]) -> NormalizedSbom {
    use crate::model::{
        CipherSuite, ComponentType, CryptoAssetType, CryptoProperties, ProtocolProperties,
        ProtocolType,
    };
    let mut sbom = NormalizedSbom::default();
    let mut c = crate::model::Component::new("tls-endpoint".into(), "proto-1".into());
    c.component_type = ComponentType::Cryptographic;
    c.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
            ProtocolProperties::new(ProtocolType::Tls)
                .with_version(version.to_string())
                .with_cipher_suites(vec![CipherSuite {
                    name: Some(suite_name.to_string()),
                    algorithms: suite_algos.iter().map(ToString::to_string).collect(),
                    ..CipherSuite::default()
                }]),
        ),
    );
    sbom.add_component(c);
    sbom
}

/// A TLS 1.0 protocol asset with a legacy cipher suite must fail BOTH
/// standards — previously protocols satisfied the inventory gate but
/// received zero evaluation.
#[test]
fn protocol_tls10_rc4_fails_both_standards() {
    let sbom = make_protocol_sbom("1.0", "TLS_RSA_WITH_RC4_128_SHA", &[]);

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(!cnsa.is_compliant, "TLS 1.0 must fail CNSA 2.0");
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
        "TLS 1.0 must trip the CNSA TLS-1.3 version gate"
    );
    assert!(
        cnsa.violations.iter().any(|v| {
            v.rule_id == "SBOM-CNSA2-PROTO-002"
                && v.message.contains("RC4")
                && v.message.contains("RSA")
        }),
        "cipher-suite scan must flag RC4 and RSA; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| v.message.clone())
            .collect::<Vec<_>>()
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(!pqc.is_compliant, "TLS 1.0 must fail PQC readiness");
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
        "TLS 1.0 must trip the PQC minimum-version gate"
    );
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-002" && v.message.contains("broken")),
        "cipher-suite scan must flag broken algorithms under PQC"
    );
}

/// Silent case: TLS 1.3 with a CNSA 2.0 cipher suite passes both
/// standards' protocol checks.
#[test]
fn protocol_tls13_cnsa_suite_passes() {
    let sbom = make_protocol_sbom("1.3", "TLS_AES_256_GCM_SHA384", &[]);

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-CNSA2-PROTO")),
        "TLS 1.3 + CNSA suite must raise no CNSA protocol violations; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| v.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(cnsa.is_compliant);

    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        !pqc.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-PQC-PROTO")),
        "TLS 1.3 + CNSA suite must raise no PQC protocol violations"
    );
}

/// TLS 1.2 fails the CNSA 2.0 TLS-1.3 gate but passes the PQC
/// minimum-version gate (>= 1.2).
#[test]
fn protocol_tls12_fails_cnsa_only() {
    let sbom = make_protocol_sbom("1.2", "TLS_AES_256_GCM_SHA384", &[]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
        "TLS 1.2 must fail the CNSA 2.0 version gate"
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        !pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
        "TLS 1.2 must pass the PQC minimum-version gate"
    );
}

/// Cipher-suite algorithm bom-refs are resolved through the SBOM index
/// and classified — even when the ref string itself is opaque.
#[test]
fn protocol_resolves_cipher_suite_algorithm_refs() {
    use crate::model::{
        AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
    };
    let mut sbom = make_protocol_sbom("1.3", "OPAQUE_SUITE_1", &["suite-algo-7"]);
    let mut rsa = crate::model::Component::new("legacy-kx".into(), "suite-algo-7".into());
    rsa.component_type = ComponentType::Cryptographic;
    rsa.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
            AlgorithmProperties::new(CryptoPrimitive::Pke).with_algorithm_family("RSA".into()),
        ),
    );
    sbom.add_component(rsa);

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| { v.rule_id == "SBOM-CNSA2-PROTO-002" && v.message.contains("RSA") }),
        "resolved suite algorithm ref must be classified; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| v.message.clone())
            .collect::<Vec<_>>()
    );
}

fn make_cert_sbom(sig_ref: &str, algo_family: Option<&str>) -> NormalizedSbom {
    use crate::model::{
        AlgorithmProperties, CertificateProperties, ComponentType, CryptoAssetType,
        CryptoPrimitive, CryptoProperties,
    };
    let mut sbom = NormalizedSbom::default();
    if let Some(family) = algo_family {
        let mut algo = crate::model::Component::new("sig-algorithm".into(), sig_ref.into());
        algo.component_type = ComponentType::Cryptographic;
        algo.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Signature)
                    .with_algorithm_family(family.to_string()),
            ),
        );
        sbom.add_component(algo);
    }
    let mut cert = crate::model::Component::new("server-cert".into(), "cert-1".into());
    cert.component_type = ComponentType::Cryptographic;
    cert.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Certificate).with_certificate_properties(
            CertificateProperties::new().with_signature_algorithm_ref(sig_ref.to_string()),
        ),
    );
    sbom.add_component(cert);
    sbom
}

/// CERT-001 must resolve an OPAQUE signature-algorithm bom-ref through
/// the index to the referenced algorithm — the old substring heuristic
/// ("rsa" in the ref string) gave opaque refs zero checks.
#[test]
fn cnsa2_cert_resolves_opaque_signature_ref() {
    let sbom = make_cert_sbom("sig-algo-42", Some("RSA"));
    let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
        "opaque ref resolving to RSA must fire CERT-001; got {:?}",
        result
            .violations
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-CERT-001"),
        "opaque ref resolving to RSA must fire the PQC certificate rule"
    );
}

/// Silent case: a certificate signed with ML-DSA-87 passes CERT-001, and
/// an unresolvable ref still gets the word-boundary fallback on the raw
/// ref string.
#[test]
fn cnsa2_cert_approved_and_fallback_cases() {
    let ok = make_cert_sbom("sig-algo-42", Some("ML-DSA-87"));
    let result = checker(ComplianceLevel::Cnsa2).check(&ok);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
        "ML-DSA-87-signed certificate must pass CERT-001"
    );

    // Unresolvable ref: fall back to token-matching the ref string.
    let dangling = make_cert_sbom("crypto/algorithm/ecdsa-p256", None);
    let result = checker(ComplianceLevel::Cnsa2).check(&dangling);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
        "unresolvable ECDSA-named ref must still fire CERT-001 via token fallback"
    );
}

/// Key material alone must not satisfy the crypto-inventory gate — it
/// receives no CNSA 2.0 evaluation.
#[test]
fn cnsa2_key_material_alone_does_not_satisfy_inventory_gate() {
    use crate::model::{
        ComponentType, CryptoAssetType, CryptoMaterialType, CryptoProperties,
        RelatedCryptoMaterialProperties,
    };
    let mut sbom = NormalizedSbom::default();
    let mut key = crate::model::Component::new("some-key".into(), "key-1".into());
    key.component_type = ComponentType::Cryptographic;
    key.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
            .with_related_crypto_material_properties(
                RelatedCryptoMaterialProperties::new(CryptoMaterialType::PublicKey).with_size(2048),
            ),
    );
    sbom.add_component(key);

    let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-000"),
        "unevaluable key material must not satisfy the CNSA2-000 inventory gate"
    );
    assert!(!result.is_compliant);
}

/// Compound algorithmFamily spellings ("DES-CBC", "AES-128-CBC") must
/// fail both standards by their base algorithm — previously they
/// classified Unknown and produced only a Warning (false pass).
#[test]
fn compound_family_spellings_fail_both_standards() {
    let sbom = make_crypto_sbom(&[("legacy-cipher", "DES-CBC", None, None)]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(!cnsa.is_compliant, "DES-CBC must not be CNSA 2.0 compliant");
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-005" && v.message.contains("DES")),
        "DES-CBC must fire the broken-algorithm rule; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations.iter().any(|v| v.rule_id == "SBOM-PQC-005"),
        "DES-CBC must fire SP 800-131A under PQC"
    );

    let sbom = make_crypto_sbom(&[("aes-cbc", "AES-128-CBC", None, None)]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-001" && v.message.contains("AES-128")),
        "AES-128-CBC must fire the AES-256-only rule"
    );

    // Silent case: a compound spelling of an approved algorithm passes.
    let ok = make_crypto_sbom(&[("aead", "AES-256-GCM", None, None)]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&ok);
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error),
        "AES-256-GCM must pass the CNSA 2.0 allowlist; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );
}

/// Truncated SHA-2 (SHA-512/256, SHA-512/224) must fail the CNSA 2.0
/// hash gate by its truncated output size — previously it classified
/// as full SHA-512 and was falsely Approved.
#[test]
fn cnsa2_flags_truncated_sha2_variants() {
    for family in ["SHA-512/256", "SHA-512/224"] {
        let sbom = make_crypto_sbom(&[("hash", family, None, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
            "{family} must fail the CNSA 2.0 hash gate; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
    }
    // Silent case: full SHA-512 stays approved.
    let ok = make_crypto_sbom(&[("hash", "SHA-512", None, None)]);
    let result = checker(ComplianceLevel::Cnsa2).check(&ok);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
        "SHA-512 must not trip the hash gate"
    );
}

/// The name-only fallback must report the most severe token: a
/// hash-first name like "sha384-rsa-signature" is quantum-vulnerable
/// RSA, not CNSA-approved SHA-384 (previously the first token won and
/// both standards passed).
#[test]
fn name_fallback_reports_most_severe_token() {
    use crate::model::{
        AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
    };
    for name in ["sha384-rsa-signature", "rsa-sha384-signature"] {
        let mut sbom = NormalizedSbom::default();
        let mut c = crate::model::Component::new(name.into(), "algo-1".into());
        c.component_type = ComponentType::Cryptographic;
        c.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm)
                .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::Signature)),
        );
        sbom.add_component(c);

        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006" && v.message.contains("RSA")),
            "'{name}' must be flagged quantum-vulnerable under CNSA 2.0; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-001" && v.message.contains("RSA")),
            "'{name}' must be flagged quantum-vulnerable under PQC"
        );
    }
}

/// A certificate whose signature-algorithm ref cannot be resolved or
/// classified fails CNSA 2.0 closed and warns under PQC — previously it
/// counted as evaluated and passed silently (certificate-only CBOMs
/// reported 100% compliant).
#[test]
fn cert_unknown_signature_ref_is_flagged_by_both_standards() {
    let sbom = make_cert_sbom("sig-algo-42", None);

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations.iter().any(|v| {
            v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-CNSA2-CERT-UNKNOWN"
        }),
        "opaque dangling sig ref must fail CNSA 2.0 closed; got {:?}",
        cnsa.violations
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        !cnsa
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
        "an unverifiable ref is CERT-UNKNOWN, not CERT-001"
    );

    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations.iter().any(|v| {
            v.severity == ViolationSeverity::Warning && v.rule_id == "SBOM-PQC-CERT-UNKNOWN"
        }),
        "opaque dangling sig ref must warn under PQC"
    );

    // Silent case: a resolvable ML-DSA-87 signature produces neither
    // the Warning nor an Error.
    let ok = make_cert_sbom("sig-algo-42", Some("ML-DSA-87"));
    for level in [ComplianceLevel::Cnsa2, ComplianceLevel::NistPqc] {
        let result = checker(level).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id.ends_with("CERT-UNKNOWN")),
            "{level:?}: resolvable approved sig ref must not warn"
        );
    }
}

/// A protocol asset with nothing evaluable (SSH, no version, no cipher
/// suites, no refs) is flagged — an Error under CNSA 2.0, a Warning under
/// PQC — instead of silently counting as evaluated and suppressing the
/// no-inventory gate.
#[test]
fn protocol_without_evidence_is_flagged_by_both_standards() {
    use crate::model::{
        ComponentType, CryptoAssetType, CryptoProperties, ProtocolProperties, ProtocolType,
    };
    let mut sbom = NormalizedSbom::default();
    let mut c = crate::model::Component::new("ssh-endpoint".into(), "proto-1".into());
    c.component_type = ComponentType::Cryptographic;
    c.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Protocol)
            .with_protocol_properties(ProtocolProperties::new(ProtocolType::Ssh)),
    );
    sbom.add_component(c);

    for (level, rule, severity) in [
        (
            ComplianceLevel::Cnsa2,
            "SBOM-CNSA2-PROTO-UNKNOWN",
            ViolationSeverity::Error,
        ),
        (
            ComplianceLevel::NistPqc,
            "SBOM-PQC-PROTO-UNKNOWN",
            ViolationSeverity::Warning,
        ),
    ] {
        let result = checker(level).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == severity && v.rule_id == rule),
            "{level:?}: evidence-free protocol must be flagged with {rule}; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
    }

    // Silent case: a TLS 1.3 protocol with a classifiable suite raises
    // no PROTO-UNKNOWN warning.
    let ok = make_protocol_sbom("1.3", "TLS_AES_256_GCM_SHA384", &[]);
    for level in [ComplianceLevel::Cnsa2, ComplianceLevel::NistPqc] {
        let result = checker(level).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id.ends_with("PROTO-UNKNOWN")),
            "{level:?}: evaluable protocol must not warn"
        );
    }
}

/// An IKEv2 protocol whose transform refs are all opaque and
/// unresolvable is flagged by both standards (Error under CNSA 2.0,
/// Warning under PQC) — previously it counted as evaluated while
/// receiving zero effective checks (vacuous 100% compliant CBOMs).
#[test]
fn ikev2_opaque_transform_refs_are_flagged_by_both_standards() {
    use crate::model::{
        ComponentType, CryptoAssetType, CryptoProperties, Ikev2TransformTypes, ProtocolProperties,
        ProtocolType,
    };
    let mut sbom = NormalizedSbom::default();
    let mut c = crate::model::Component::new("ipsec-tunnel".into(), "proto-1".into());
    c.component_type = ComponentType::Cryptographic;
    c.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
            ProtocolProperties::new(ProtocolType::Ikev2).with_ikev2_transform_types(
                Ikev2TransformTypes {
                    encr: vec!["transform-encr-7".into()],
                    prf: vec!["transform-prf-3".into()],
                    integ: vec!["transform-integ-2".into()],
                    ke: vec!["transform-ke-9".into()],
                    auth: vec![],
                    transforms: vec![],
                },
            ),
        ),
    );
    sbom.add_component(c);

    for (level, rule, severity) in [
        (
            ComplianceLevel::Cnsa2,
            "SBOM-CNSA2-PROTO-UNKNOWN",
            ViolationSeverity::Error,
        ),
        (
            ComplianceLevel::NistPqc,
            "SBOM-PQC-PROTO-UNKNOWN",
            ViolationSeverity::Warning,
        ),
    ] {
        let result = checker(level).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.severity == severity
                    && v.rule_id == rule
                    && v.message.contains("transform-encr-7")
            }),
            "{level:?}: opaque IKEv2 transforms must be flagged with {rule}; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
    }
}

/// The CNSA 2.0 TLS gate must accept legitimate spellings of TLS 1.3
/// and share version parsing with the PQC gate, so the two standards
/// agree on the same input (previously "TLSv1.3" was a false Error and
/// "TLSv1.0" silently passed the PQC gate).
#[test]
fn tls_version_spellings_parse_tolerantly() {
    for version in ["TLSv1.3", "tls1.3", "1.3.0", " 1.3", "v1.3"] {
        let sbom = make_protocol_sbom(version, "TLS_AES_256_GCM_SHA384", &[]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            !cnsa
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
            "'{version}' must count as TLS 1.3; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
        );
    }
    // Spelled-out old versions now fail BOTH gates.
    let sbom = make_protocol_sbom("TLSv1.0", "TLS_AES_256_GCM_SHA384", &[]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
        "TLSv1.0 must fail the CNSA 2.0 version gate"
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
        "TLSv1.0 must fail the PQC minimum-version gate (previously silent)"
    );
    // Unparseable versions: strict Error under the CNSA 2.0 allowlist,
    // cannot-verify Warning under PQC.
    let sbom = make_protocol_sbom("quantum-safe", "TLS_AES_256_GCM_SHA384", &[]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
        "an unparseable version cannot affirm TLS 1.3"
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        pqc.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Warning
                && v.rule_id == "SBOM-PQC-PROTO-UNKNOWN"
                && v.message.contains("quantum-safe")),
        "an unparseable version must be a cannot-verify Warning under PQC"
    );
}

/// Reference resolution must carry the referenced asset's declared
/// classicalSecurityLevel: an AES asset whose key size is declared only
/// via classicalSecurityLevel=256 is Approved when evaluated directly,
/// so it must also be Approved when reached through a protocol's
/// cryptoRefArray (previously a false PROTO-002).
#[test]
fn protocol_ref_resolution_keeps_declared_security_level() {
    use crate::model::{
        AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        ProtocolProperties, ProtocolType,
    };
    let make = |classical_level: u32| {
        let mut sbom = NormalizedSbom::default();
        let mut aes = crate::model::Component::new("aes-gcm-cipher".into(), "algo-aes".into());
        aes.component_type = ComponentType::Cryptographic;
        aes.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Ae)
                    .with_algorithm_family("AES".into())
                    .with_classical_security_level(classical_level)
                    .with_nist_quantum_security_level(5),
            ),
        );
        sbom.add_component(aes);
        let mut proto = crate::model::Component::new("tls-endpoint".into(), "proto-1".into());
        proto.component_type = ComponentType::Cryptographic;
        proto.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
                ProtocolProperties::new(ProtocolType::Tls)
                    .with_version("1.3".into())
                    .with_crypto_ref_array(vec!["algo-aes".into()]),
            ),
        );
        sbom.add_component(proto);
        sbom
    };

    // AES-256 via classicalSecurityLevel only: both the direct and the
    // referenced evaluation must agree (zero errors).
    let result = checker(ComplianceLevel::Cnsa2).check(&make(256));
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error),
        "AES with classicalSecurityLevel=256 must pass via ref too; got {:?}",
        result
            .violations
            .iter()
            .map(|v| (v.rule_id, v.message.clone()))
            .collect::<Vec<_>>()
    );

    // Firing counterpart: a declared 128-bit level fails through the
    // ref path exactly as it does directly.
    let result = checker(ComplianceLevel::Cnsa2).check(&make(128));
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-002" && v.message.contains("AES")),
        "AES-128 referenced from a protocol must still fire PROTO-002"
    );
}

/// National quantum-vulnerable algorithms (SM2 / GOST R 34.10 /
/// brainpool) must fail PQC and CNSA 2.0 as classical crypto instead of
/// producing only an unclassifiable Warning.
#[test]
fn national_algorithms_fail_both_standards() {
    for family in ["SM2", "GOST R 34.10", "brainpoolP256r1"] {
        let sbom = make_crypto_sbom(&[("national-sig", family, None, None)]);
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-001"),
            "{family} must fire the quantum-vulnerable rule; got {:?}",
            pqc.violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006"),
            "{family} must fail the CNSA 2.0 allowlist as quantum-vulnerable"
        );
    }
    // SM4 (symmetric) and GOST hashes are recognized-but-not-approved
    // under CNSA 2.0, and not quantum-vulnerable under PQC.
    for family in ["SM4", "Streebog"] {
        let sbom = make_crypto_sbom(&[("national-prim", family, None, None)]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-008"),
            "{family} must be recognized as not CNSA 2.0-approved"
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            !pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-001" || v.rule_id == "SBOM-PQC-005"),
            "{family} must not be reported broken or quantum-vulnerable"
        );
    }
}
