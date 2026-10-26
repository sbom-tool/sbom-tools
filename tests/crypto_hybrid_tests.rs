//! PQ/T hybrids: hybrid key exchanges (TLS 1.3 groups, SSH methods, RFC 9370
//! IKEv2 additional key exchanges) and composite signatures classify as one
//! hybrid holding both parts, and the crypto profiles judge them by those
//! parts — NIST PQC by the post-quantum part, CNSA 2.0 by both — instead of
//! by the weaker one or as unknown.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    AlgorithmClass, AlgorithmClassification, NormalizedSbom, classify_algorithm,
    classify_algorithm_names,
};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, CryptographyMetrics, ViolationSeverity,
};

fn named(name: &str) -> AlgorithmClassification {
    classify_algorithm(None, Some(name), None, None, None)
}

fn by_oid(oid: &str) -> AlgorithmClassification {
    classify_algorithm(None, None, Some(oid), None, None)
}

/// The (classical, post-quantum) labels of a hybrid; panics on anything else.
fn parts(cls: &AlgorithmClassification, what: &str) -> (String, String) {
    assert_eq!(cls.class, AlgorithmClass::Hybrid, "{what}: {cls:?}");
    let parts = cls.hybrid_parts().expect("a hybrid has parts");
    (parts.classical.label(), parts.post_quantum.label())
}

// ── Classification ──────────────────────────────────────────────────────

/// The registered names: TLS 1.3 hybrid groups (RFC 10024 and the
/// provisional IANA entries), SSH methods (RFC 10042, RFC 9941) and the
/// composite names and labels.
#[test]
fn registered_hybrid_names_classify_with_both_parts() {
    for (name, classical, post_quantum) in [
        ("X25519MLKEM768", "X25519", "ML-KEM-768"),
        ("SecP256r1MLKEM768", "ECDH-P-256", "ML-KEM-768"),
        ("SecP384r1MLKEM1024", "ECDH-P-384", "ML-KEM-1024"),
        ("SecP256r1MLKEM512", "ECDH-P-256", "ML-KEM-512"),
        ("MLKEM512X25519", "X25519", "ML-KEM-512"),
        ("curveSM2MLKEM768", "SM2", "ML-KEM-768"),
        ("mlkem768x25519-sha256", "X25519", "ML-KEM-768"),
        ("mlkem768nistp256-sha256", "ECDH-P-256", "ML-KEM-768"),
        ("mlkem1024nistp384-sha384", "ECDH-P-384", "ML-KEM-1024"),
        ("sntrup761x25519-sha512", "X25519", "SNTRUP761"),
        ("sntrup761x25519-sha512@openssh.com", "X25519", "SNTRUP761"),
        ("id-MLDSA87-ECDSA-P384-SHA512", "ECDSA-P-384", "ML-DSA-87"),
        ("MLDSA87-ECDSA-P384-SHA512", "ECDSA-P-384", "ML-DSA-87"),
        (
            "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
            "ECDSA-P-384",
            "ML-DSA-87",
        ),
        (
            "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
            "ECDSA-brainpoolP256r1",
            "ML-DSA-65",
        ),
        ("id-MLDSA87-Ed448-SHAKE256", "ED448", "ML-DSA-87"),
        ("id-MLDSA44-RSA2048-PSS-SHA256", "RSA-2048", "ML-DSA-44"),
        (
            "id-MLKEM1024-ECDH-P384-SHA3-256",
            "ECDH-P-384",
            "ML-KEM-1024",
        ),
        ("id-MLKEM768-X25519-SHA3-256", "X25519", "ML-KEM-768"),
    ] {
        let expected = (classical.to_string(), post_quantum.to_string());
        assert_eq!(parts(&named(name), name), expected, "name {name}");
        match classify_algorithm_names(name).as_slice() {
            [one] => assert_eq!(parts(one, name), expected, "scan of {name}"),
            other => panic!("{name}: expected one mention, got {other:?}"),
        }
    }
    // Streamlined NTRU Prime is no NIST algorithm: the post-quantum part
    // stays unclassified under its own name.
    let sntrup = named("sntrup761x25519-sha512");
    let pq = &sntrup.hybrid_parts().expect("parts").post_quantum;
    assert_eq!(pq.class, AlgorithmClass::Unknown);
}

/// Every composite OID IANA allocated early under id-alg: composite ML-DSA
/// (draft-ietf-lamps-pq-composite-sigs-19 §6) and composite ML-KEM
/// (draft-ietf-lamps-pq-composite-kem-23 §6).
#[test]
fn composite_oids_classify_with_both_parts() {
    for (arc, classical, post_quantum) in [
        (37, "RSA-2048", "ML-DSA-44"),
        (38, "RSA-2048", "ML-DSA-44"),
        (39, "ED25519", "ML-DSA-44"),
        (40, "ECDSA-P-256", "ML-DSA-44"),
        (41, "RSA-3072", "ML-DSA-65"),
        (42, "RSA-3072", "ML-DSA-65"),
        (43, "RSA-4096", "ML-DSA-65"),
        (44, "RSA-4096", "ML-DSA-65"),
        (45, "ECDSA-P-256", "ML-DSA-65"),
        (46, "ECDSA-P-384", "ML-DSA-65"),
        (47, "ECDSA-brainpoolP256r1", "ML-DSA-65"),
        (48, "ED25519", "ML-DSA-65"),
        (49, "ECDSA-P-384", "ML-DSA-87"),
        (50, "ECDSA-brainpoolP384r1", "ML-DSA-87"),
        (51, "ED448", "ML-DSA-87"),
        (52, "RSA-3072", "ML-DSA-87"),
        (53, "RSA-4096", "ML-DSA-87"),
        (54, "ECDSA-P-521", "ML-DSA-87"),
        (55, "RSA-2048", "ML-KEM-768"),
        (56, "RSA-3072", "ML-KEM-768"),
        (57, "RSA-4096", "ML-KEM-768"),
        (58, "X25519", "ML-KEM-768"),
        (59, "ECDH-P-256", "ML-KEM-768"),
        (60, "ECDH-P-384", "ML-KEM-768"),
        (61, "ECDH-brainpoolP256r1", "ML-KEM-768"),
        (62, "RSA-3072", "ML-KEM-1024"),
        (63, "ECDH-P-384", "ML-KEM-1024"),
        (64, "ECDH-brainpoolP384r1", "ML-KEM-1024"),
        (65, "X448", "ML-KEM-1024"),
        (66, "ECDH-P-521", "ML-KEM-1024"),
    ] {
        let oid = format!("1.3.6.1.5.5.7.6.{arc}");
        assert_eq!(
            parts(&by_oid(&oid), &oid),
            (classical.to_string(), post_quantum.to_string()),
            "OID {oid}"
        );
    }
    // The neighbouring id-alg arcs keep their meaning: RFC 8692 below,
    // nothing assigned above.
    assert_eq!(
        by_oid("1.3.6.1.5.5.7.6.33").family.as_deref(),
        Some("ECDSA")
    );
    assert_eq!(by_oid("1.3.6.1.5.5.7.6.67").class, AlgorithmClass::Unknown);
}

/// A classical and a post-quantum algorithm glued together, joined with
/// `+`, side by side in either order, the curve of an ECDH or ECDSA read
/// from the token after it, OQS-style names, and a JCA-style pair.
#[test]
fn generic_hybrid_spellings_classify_with_both_parts() {
    for (name, classical, post_quantum) in [
        ("X25519+ML-KEM-768", "X25519", "ML-KEM-768"),
        ("X25519-ML-KEM-768", "X25519", "ML-KEM-768"),
        ("ML-KEM-768-X25519", "X25519", "ML-KEM-768"),
        ("ECDH-P384-ML-KEM-1024", "ECDH-P-384", "ML-KEM-1024"),
        ("ECDSA-P384-ML-DSA-65", "ECDSA-P-384", "ML-DSA-65"),
        ("p384_mlkem1024", "EC-P-384", "ML-KEM-1024"),
        ("p256_mldsa44", "EC-P-256", "ML-DSA-44"),
        ("rsa3072_mldsa44", "RSA-3072", "ML-DSA-44"),
        ("x25519_kyber768", "X25519", "ML-KEM-768"),
        ("X448MLKEM1024", "X448", "ML-KEM-1024"),
        ("X25519withML-KEM-768", "X25519", "ML-KEM-768"),
    ] {
        assert_eq!(
            parts(&named(name), name),
            (classical.to_string(), post_quantum.to_string()),
            "{name}"
        );
    }
    // A declared family that is itself a hybrid name.
    let family = classify_algorithm(Some("X25519MLKEM768"), None, None, None, None);
    assert_eq!(
        parts(&family, "family X25519MLKEM768"),
        ("X25519".to_string(), "ML-KEM-768".to_string())
    );
    // Inside a cipher-suite name the hybrid is one mention beside the rest.
    let suite = classify_algorithm_names("TLS_AES_256_GCM_SHA384_ECDH_P384_ML_KEM_1024");
    let labels: Vec<String> = suite.iter().map(AlgorithmClassification::label).collect();
    assert_eq!(labels, ["AES-256", "SHA-384", "ECDH-P-384 + ML-KEM-1024"]);
}

/// Pairs that make no hybrid stay apart: a KEM beside a signature, two
/// post-quantum algorithms, names not side by side. The pre-standard Kyber
/// draft groups and a post-quantum signature behind its digest stay
/// unclassified.
#[test]
fn pairs_that_make_no_hybrid_stay_apart() {
    for name in [
        "X25519-ML-DSA-65",
        "ML-KEM-768-ML-DSA-65",
        "x25519 and ml-kem-768",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ] {
        assert!(
            !classify_algorithm_names(name)
                .iter()
                .any(|m| m.class == AlgorithmClass::Hybrid),
            "{name} is no hybrid"
        );
    }
    // A classical algorithm named outside a hybrid still reports as the
    // worst mention.
    assert_eq!(
        named("X25519-ML-DSA-65").class,
        AlgorithmClass::ClassicalQuantumVulnerable
    );
    for name in [
        "X25519Kyber768Draft00",
        "SecP256r1Kyber768Draft00",
        "SHA512withML-DSA",
    ] {
        assert_eq!(named(name).class, AlgorithmClass::Unknown, "{name}");
    }
}

// ── Profile verdicts ────────────────────────────────────────────────────

/// A CycloneDX 1.7 CBOM of the given component JSON values.
fn cbom(components: Vec<serde_json::Value>) -> NormalizedSbom {
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:aea9ad3b-09d6-48d3-8090-7e01d8c456fd",
        "version": 1,
        "metadata": { "timestamp": "2026-10-01T00:00:00Z" },
        "components": components,
    });
    parse_sbom_str(&doc.to_string()).expect("CBOM parses")
}

/// One algorithm asset named `name`, with an optional OID and the declared
/// NIST quantum security level.
fn algorithm(name: &str, oid: Option<&str>, level: u8) -> serde_json::Value {
    let mut crypto = serde_json::json!({
        "assetType": "algorithm",
        "algorithmProperties": { "primitive": "kem", "nistQuantumSecurityLevel": level },
    });
    if let Some(oid) = oid {
        crypto["oid"] = oid.into();
    }
    serde_json::json!({
        "type": "cryptographic-asset",
        "bom-ref": format!("crypto/alg/{name}"),
        "name": name,
        "cryptoProperties": crypto,
    })
}

fn rules(result: &ComplianceResult) -> Vec<(&'static str, ViolationSeverity)> {
    result
        .violations
        .iter()
        .map(|v| (v.rule_id, v.severity))
        .collect()
}

/// The rules of the checks `result` passed.
fn passes(result: &ComplianceResult) -> Vec<&'static str> {
    result.passed.iter().map(|p| p.rule_id).collect()
}

fn findings(result: &ComplianceResult) -> Vec<String> {
    let violations = result
        .violations
        .iter()
        .map(|v| format!("{:?} {}: {}", v.severity, v.rule_id, v.message));
    let passes = result
        .passed
        .iter()
        .map(|p| format!("Pass {}: {}", p.rule_id, p.message));
    violations.chain(passes).collect()
}

/// The CNSA 2.0 outcome for one hybrid: approved, or the rule it fails and
/// the parts its message must name.
enum Cnsa {
    Approved,
    Fails(&'static str, &'static [&'static str]),
}

/// CNSA 2.0 approves a hybrid when its post-quantum part is ML-KEM-1024 or
/// ML-DSA-87 and its classical part is a CNSA 1.0 algorithm (ECDH/ECDSA
/// P-384, RSA/DH of 3072 bits or more), and otherwise names the failing
/// parts. NIST PQC accepts every hybrid whose post-quantum part it
/// approves, as a passed check, and warns on one whose post-quantum part it does
/// not recognize instead of failing the classical part.
#[test]
fn hybrid_algorithm_verdicts_under_both_profiles() {
    use Cnsa::{Approved, Fails};
    let cases: &[(&str, Option<&str>, Cnsa)] = &[
        ("SecP384r1MLKEM1024", None, Approved),
        ("mlkem1024nistp384-sha384", None, Approved),
        (
            "id-MLDSA87-ECDSA-P384-SHA512",
            Some("1.3.6.1.5.5.7.6.49"),
            Approved,
        ),
        (
            "id-MLDSA87-RSA3072-PSS-SHA512",
            Some("1.3.6.1.5.5.7.6.52"),
            Approved,
        ),
        (
            "id-MLKEM1024-ECDH-P384-SHA3-256",
            Some("1.3.6.1.5.5.7.6.63"),
            Approved,
        ),
        (
            "X25519MLKEM768",
            None,
            Fails(
                "SBOM-CNSA2-ALG-003",
                &["ML-KEM-768 is not ML-KEM-1024", "X25519"],
            ),
        ),
        (
            "mlkem768x25519-sha256",
            None,
            Fails("SBOM-CNSA2-ALG-003", &["ML-KEM-768", "X25519"]),
        ),
        (
            "SecP256r1MLKEM768",
            None,
            Fails("SBOM-CNSA2-ALG-003", &["ML-KEM-768", "ECDH-P-256"]),
        ),
        (
            "X448MLKEM1024",
            None,
            Fails("SBOM-CNSA2-ALG-003", &["X448 is not a CNSA 1.0 algorithm"]),
        ),
        (
            "id-MLDSA65-ECDSA-P384-SHA512",
            Some("1.3.6.1.5.5.7.6.46"),
            Fails("SBOM-CNSA2-ALG-004", &["ML-DSA-65 is not ML-DSA-87"]),
        ),
        (
            "id-MLDSA87-ECDSA-P521-SHA512",
            Some("1.3.6.1.5.5.7.6.54"),
            Fails("SBOM-CNSA2-ALG-004", &["ECDSA-P-521 is not a CNSA 1.0"]),
        ),
        (
            "id-MLDSA87-Ed448-SHAKE256",
            Some("1.3.6.1.5.5.7.6.51"),
            Fails("SBOM-CNSA2-ALG-004", &["ED448"]),
        ),
        (
            "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
            Some("1.3.6.1.5.5.7.6.50"),
            Fails("SBOM-CNSA2-ALG-004", &["ECDSA-brainpoolP384r1"]),
        ),
        (
            "id-MLDSA44-RSA2048-PSS-SHA256",
            Some("1.3.6.1.5.5.7.6.37"),
            Fails("SBOM-CNSA2-ALG-004", &["ML-DSA-44", "RSA-2048"]),
        ),
        (
            "sntrup761x25519-sha512",
            None,
            Fails(
                "SBOM-CNSA2-ALG-003",
                &[
                    "SNTRUP761 is not a recognized post-quantum algorithm",
                    "X25519",
                ],
            ),
        ),
    ];
    for (name, oid, cnsa) in cases {
        let sbom = cbom(vec![algorithm(name, *oid, 5)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        match cnsa {
            Approved => {
                assert!(result.is_compliant, "{name}: {:#?}", findings(&result));
                assert_eq!(result.error_count, 0, "{name}: {:#?}", findings(&result));
            }
            Fails(rule, named_parts) => {
                let finding = result
                    .violations
                    .iter()
                    .find(|v| v.rule_id == *rule)
                    .unwrap_or_else(|| panic!("{name}: no {rule} in {:#?}", findings(&result)));
                assert_eq!(finding.severity, ViolationSeverity::Error);
                for part in *named_parts {
                    assert!(
                        finding.message.contains(part),
                        "{name}: {}",
                        finding.message
                    );
                }
                assert!(
                    !result
                        .violations
                        .iter()
                        .any(|v| v.rule_id.ends_with("UNKNOWN")),
                    "{name}: {:#?}",
                    findings(&result)
                );
            }
        }

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        // An unverifiable hybrid is no evaluable inventory, so a CBOM of it
        // alone also fails the inventory gate; nothing else is an error, and
        // the classical part never fails on its own.
        let pq_unrecognized = *name == "sntrup761x25519-sha512";
        let errors: Vec<&str> = pqc
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .map(|v| v.rule_id)
            .collect();
        let inventory_gate: &[&str] = if pq_unrecognized {
            &["SBOM-PQC-000"]
        } else {
            &[]
        };
        assert_eq!(errors, inventory_gate, "{name}: {:#?}", findings(&pqc));
        // An unverifiable hybrid warns; an approved one is a passed check.
        if pq_unrecognized {
            assert!(
                rules(&pqc).contains(&("SBOM-PQC-ALG-UNKNOWN", ViolationSeverity::Warning)),
                "{name}: expected SBOM-PQC-ALG-UNKNOWN in {:#?}",
                findings(&pqc)
            );
        } else {
            assert!(
                passes(&pqc).contains(&"SBOM-PQC-010"),
                "{name}: expected the SBOM-PQC-010 pass in {:#?}",
                findings(&pqc)
            );
        }
    }
}

/// A declared hybrid combiner whose family names no hybrid (or one of its
/// parts) takes the hybrid its name names; one whose parts cannot be
/// identified warns under NIST PQC instead of passing the check.
#[test]
fn declared_combiners_take_the_hybrid_their_name_names() {
    let combiner = |name: &str, family: Option<&str>, parameter: Option<&str>| {
        let mut properties = serde_json::json!({
            "primitive": "combiner",
            "nistQuantumSecurityLevel": 5,
        });
        if let Some(f) = family {
            properties["algorithmFamily"] = f.into();
        }
        if let Some(p) = parameter {
            properties["parameterSetIdentifier"] = p.into();
        }
        serde_json::json!({
            "type": "cryptographic-asset",
            "bom-ref": format!("crypto/alg/{name}"),
            "name": name,
            "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": properties },
        })
    };
    // Family "ML-KEM" (a CycloneDX 1.7 family) + parameter 1024 would read
    // as ML-KEM-1024 alone; the name shows the X25519 beside it, which
    // CNSA 2.0 does not approve. The declared parameter set stands over
    // the name's.
    let sbom = cbom(vec![combiner(
        "X25519-ML-KEM-768",
        Some("ML-KEM"),
        Some("1024"),
    )]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-CNSA2-ALG-003"
                && v.message.contains("uses the hybrid X25519 + ML-KEM-1024")
                && !v.message.contains("ML-KEM-768 is not")),
        "{:#?}",
        findings(&cnsa)
    );
    // Family "Hybrid-KEM" is no CycloneDX family: the name decides.
    let sbom = cbom(vec![combiner(
        "ECDH-P384-ML-KEM-1024",
        Some("Hybrid-KEM"),
        None,
    )]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(cnsa.is_compliant, "{:#?}", findings(&cnsa));
    // A combiner nothing identifies cannot be verified under NIST PQC.
    let sbom = cbom(vec![combiner("vendor-kem-7", Some("Hybrid-KEM"), None)]);
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert!(
        rules(&pqc).contains(&("SBOM-PQC-ALG-UNKNOWN", ViolationSeverity::Warning)),
        "{:#?}",
        findings(&pqc)
    );
    assert!(
        !passes(&pqc).contains(&"SBOM-PQC-010"),
        "{:#?}",
        findings(&pqc)
    );
}

/// An IKEv2 protocol with the given key exchange groups (Transform Type 4)
/// and additional key exchange rounds (`addke1`… with their groups; group 0
/// is NONE), AES-256-GCM and an HMAC-SHA-384 PRF.
fn ikev2(ke: &[u32], additional: &[(&str, &[u32])]) -> NormalizedSbom {
    let groups = |gs: &[u32]| -> Vec<serde_json::Value> {
        gs.iter()
            .map(|g| serde_json::json!({ "group": g }))
            .collect()
    };
    let mut transforms = serde_json::json!({
        "encr": [{ "name": "ENCR_AES_GCM_16", "keyLength": 256 }],
        "prf": [{ "name": "PRF_HMAC_SHA2_384" }],
        "ke": groups(ke),
    });
    for (round, gs) in additional {
        transforms[*round] = groups(gs).into();
    }
    cbom(vec![serde_json::json!({
        "type": "cryptographic-asset",
        "bom-ref": "crypto/protocol/ipsec",
        "name": "ipsec",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": { "type": "ikev2", "version": "2", "ikev2TransformTypes": transforms },
        },
    })])
}

/// The protocol rule each profile reports (error or warning), if any.
fn protocol_rules(result: &ComplianceResult) -> Vec<&'static str> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id.contains("PROTO"))
        .map(|v| v.rule_id)
        .collect()
}

/// RFC 9370: the key exchange method and the additional key exchanges are
/// judged together. NSA's CNSA 2.0 IPsec profile — P-384 or a 3072/4096-bit
/// MODP group, then ML-KEM-1024 — passes both profiles; an optional (NONE)
/// additional exchange leaves the classical one alone; a classical part
/// that is not CNSA 1.0 or a post-quantum part that is not ML-KEM-1024
/// fails CNSA 2.0 but not NIST PQC; an unidentified additional exchange
/// cannot be verified.
#[test]
fn ikev2_additional_key_exchanges_are_judged_as_hybrids() {
    const NONE: u32 = 0;
    /// KE groups, ADDKE rounds, CNSA 2.0 protocol rules, NIST PQC protocol
    /// rules.
    type Case<'a> = (&'a [u32], &'a [Round<'a>], &'a [&'a str], &'a [&'a str]);
    type Round<'a> = (&'a str, &'a [u32]);
    let cases: &[Case] = &[
        (&[20], &[("addke1", &[37])], &[], &[]),
        (&[15], &[("addke1", &[37])], &[], &[]),
        (&[16], &[("addke1", &[37])], &[], &[]),
        (&[20], &[("addke3", &[37])], &[], &[]),
        (&[37], &[], &[], &[]),
        (
            &[20],
            &[("addke1", &[37, NONE])],
            &["SBOM-CNSA2-PROTO-002"],
            &["SBOM-PQC-PROTO-002"],
        ),
        (
            &[20],
            &[("addke1", &[NONE])],
            &["SBOM-CNSA2-PROTO-002"],
            &["SBOM-PQC-PROTO-002"],
        ),
        (&[20], &[("addke1", &[37]), ("addke2", &[NONE])], &[], &[]),
        (&[19], &[("addke1", &[37])], &["SBOM-CNSA2-PROTO-002"], &[]),
        (&[14], &[("addke1", &[37])], &["SBOM-CNSA2-PROTO-002"], &[]),
        (&[31], &[("addke1", &[36])], &["SBOM-CNSA2-PROTO-002"], &[]),
        (
            &[20, 19],
            &[("addke1", &[37])],
            &["SBOM-CNSA2-PROTO-002"],
            &[],
        ),
        (&[20], &[("addke1", &[36])], &["SBOM-CNSA2-PROTO-002"], &[]),
        (
            &[20],
            &[("addke1", &[1035])],
            &["SBOM-CNSA2-PROTO-UNKNOWN"],
            &["SBOM-PQC-PROTO-UNKNOWN"],
        ),
        (
            &[19],
            &[("addke1", &[1035])],
            &["SBOM-CNSA2-PROTO-002"],
            &["SBOM-PQC-PROTO-UNKNOWN"],
        ),
    ];
    for (ke, additional, cnsa_rules, pqc_rules) in cases {
        let sbom = ikev2(ke, additional);
        let label = format!("KE {ke:?} + {additional:?}");
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert_eq!(
            protocol_rules(&cnsa),
            *cnsa_rules,
            "{label} under CNSA 2.0: {:#?}",
            findings(&cnsa)
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert_eq!(
            protocol_rules(&pqc),
            *pqc_rules,
            "{label} under NIST PQC: {:#?}",
            findings(&pqc)
        );
    }
    // The failing hybrid is named by both of its parts.
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&ikev2(&[19], &[("addke1", &[37])]));
    assert!(
        cnsa.violations
            .iter()
            .any(|v| v.message.contains("ECDH-P-256 + ML-KEM-1024")),
        "{:#?}",
        findings(&cnsa)
    );
}

/// A key exchange given by reference to an unsized ECDH asset takes its
/// curve from the IANA group, so the classical part can be shown to be
/// P-384.
#[test]
fn ikev2_group_sizes_a_referenced_key_exchange() {
    let sbom = cbom(vec![
        serde_json::json!({
            "type": "cryptographic-asset",
            "bom-ref": "crypto/alg/ecdh",
            "name": "ECDH",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": { "primitive": "key-agree", "algorithmFamily": "ECDH" },
            },
        }),
        serde_json::json!({
            "type": "cryptographic-asset",
            "bom-ref": "crypto/protocol/ipsec",
            "name": "ipsec",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "ikev2",
                    "version": "2",
                    "ikev2TransformTypes": {
                        "encr": [{ "name": "ENCR_AES_GCM_16", "keyLength": 256 }],
                        "prf": [{ "name": "PRF_HMAC_SHA2_384" }],
                        "ke": [{ "group": 20, "algorithm": "crypto/alg/ecdh" }],
                        "addke1": [{ "group": 37 }],
                    },
                },
            },
        }),
    ]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    assert!(protocol_rules(&cnsa).is_empty(), "{:#?}", findings(&cnsa));
}

/// The CBOM quality metrics count a hybrid by its post-quantum part, as
/// NIST PQC judges it: X25519MLKEM768 is quantum-safe, not vulnerable.
#[test]
fn quality_metrics_count_a_hybrid_by_its_post_quantum_part() {
    let mut asset = algorithm("X25519-ML-KEM-768", None, 3);
    // No declared level: the classification alone decides.
    asset["cryptoProperties"]["algorithmProperties"]
        .as_object_mut()
        .expect("algorithm properties")
        .remove("nistQuantumSecurityLevel");
    let sbom = cbom(vec![asset]);
    let metrics = CryptographyMetrics::from_sbom_at(&sbom, clock::as_of());
    assert_eq!(metrics.quantum_safe_count, 1, "{metrics:?}");
    assert_eq!(metrics.quantum_vulnerable_count, 0, "{metrics:?}");
}
