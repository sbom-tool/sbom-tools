//! Crypto vocabulary: every CycloneDX 1.7 algorithm family, JCA
//! `<digest>with<signature>` names, curve aliases, PAKEs and the MAC/KDF
//! constructions classify to a real algorithm class, and the CNSA 2.0 and
//! NIST PQC profiles judge them by that class instead of failing them as
//! unknown.

use sbom_tools::model::{
    AlgorithmClass, AlgorithmClassification, NormalizedSbom, PqcKind, classify_algorithm,
};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity,
};

const SPEC_SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/cyclonedx-spec/1.7/cryptography-defs.schema.json"
);

/// Every verdict here is evaluated at this instant.
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// One enum from the vendored CycloneDX 1.7 `cryptography-defs.schema.json`.
fn spec_enum(definition: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(SPEC_SCHEMA).expect("vendored schema readable");
    let schema: serde_json::Value = serde_json::from_str(&raw).expect("vendored schema is JSON");
    schema["definitions"][definition]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("schema has no {definition} enum"))
        .iter()
        .map(|v| v.as_str().expect("enum values are strings").to_string())
        .collect()
}

fn family(f: &str) -> AlgorithmClassification {
    classify_algorithm(Some(f), None, None, None, None)
}

fn named(name: &str) -> AlgorithmClassification {
    classify_algorithm(None, Some(name), None, None, None)
}

fn by_oid(oid: &str) -> AlgorithmClassification {
    classify_algorithm(None, None, Some(oid), None, None)
}

const QV: AlgorithmClass = AlgorithmClass::ClassicalQuantumVulnerable;

/// The class each CycloneDX 1.7 `algorithmFamily` value receives. The keyed
/// constructions (CMAC, HKDF, HMAC, IKE-PRF, PBES2, PBKDF2, PBMAC1,
/// SP800-108) name no primitive on their own and classify as symmetric.
const FAMILY_CLASSES: &[(&str, AlgorithmClass)] = &[
    ("3DES", AlgorithmClass::Broken),
    ("3GPP-XOR", AlgorithmClass::Broken),
    ("A5/1", AlgorithmClass::Broken),
    ("A5/2", AlgorithmClass::Broken),
    ("AES", AlgorithmClass::Symmetric),
    ("ARIA", AlgorithmClass::Symmetric),
    ("Ascon", AlgorithmClass::Symmetric),
    ("BLAKE2", AlgorithmClass::OtherHash),
    ("BLAKE3", AlgorithmClass::OtherHash),
    ("BLS", QV),
    ("Blowfish", AlgorithmClass::Broken),
    ("CAMELLIA", AlgorithmClass::Symmetric),
    ("CAST5", AlgorithmClass::Broken),
    ("CAST6", AlgorithmClass::Symmetric),
    ("CMAC", AlgorithmClass::Symmetric),
    ("CMEA", AlgorithmClass::Broken),
    ("ChaCha", AlgorithmClass::Symmetric),
    ("ChaCha20", AlgorithmClass::Symmetric),
    ("DES", AlgorithmClass::Broken),
    ("DSA", QV),
    ("ECDH", QV),
    ("ECDSA", QV),
    ("ECIES", QV),
    ("EdDSA", QV),
    ("ElGamal", QV),
    ("FFDH", QV),
    ("Fortuna", AlgorithmClass::Symmetric),
    ("GOST", QV),
    ("HC", AlgorithmClass::Symmetric),
    ("HKDF", AlgorithmClass::Symmetric),
    ("HMAC", AlgorithmClass::Symmetric),
    ("IDEA", AlgorithmClass::Broken),
    ("IKE-PRF", AlgorithmClass::Symmetric),
    ("KMAC", AlgorithmClass::Sha3),
    ("LMS", AlgorithmClass::PostQuantum(PqcKind::Lms)),
    ("MD2", AlgorithmClass::Broken),
    ("MD4", AlgorithmClass::Broken),
    ("MD5", AlgorithmClass::Broken),
    ("MILENAGE", AlgorithmClass::Symmetric),
    ("ML-DSA", AlgorithmClass::PostQuantum(PqcKind::MlDsa)),
    ("ML-KEM", AlgorithmClass::PostQuantum(PqcKind::MlKem)),
    ("MQV", QV),
    ("PBES1", AlgorithmClass::Broken),
    ("PBES2", AlgorithmClass::Symmetric),
    ("PBKDF1", AlgorithmClass::Broken),
    ("PBKDF2", AlgorithmClass::Symmetric),
    ("PBMAC1", AlgorithmClass::Symmetric),
    ("Poly1305", AlgorithmClass::Symmetric),
    ("RABBIT", AlgorithmClass::Symmetric),
    ("RC2", AlgorithmClass::Broken),
    ("RC4", AlgorithmClass::Broken),
    ("RC5", AlgorithmClass::Broken),
    ("RC6", AlgorithmClass::Symmetric),
    ("RIPEMD", AlgorithmClass::OtherHash),
    ("RSAES-OAEP", QV),
    ("RSAES-PKCS1", QV),
    ("RSASSA-PKCS1", QV),
    ("RSASSA-PSS", QV),
    ("SEED", AlgorithmClass::Symmetric),
    ("SHA-1", AlgorithmClass::Broken),
    ("SHA-2", AlgorithmClass::Sha2),
    ("SHA-3", AlgorithmClass::Sha3),
    ("SLH-DSA", AlgorithmClass::PostQuantum(PqcKind::SlhDsa)),
    ("SNOW3G", AlgorithmClass::Symmetric),
    ("SP800-108", AlgorithmClass::Symmetric),
    ("Salsa20", AlgorithmClass::Symmetric),
    ("Serpent", AlgorithmClass::Symmetric),
    ("SipHash", AlgorithmClass::OtherHash),
    ("Skipjack", AlgorithmClass::Broken),
    ("TUAK", AlgorithmClass::Sha3),
    ("Twofish", AlgorithmClass::Symmetric),
    ("Whirlpool", AlgorithmClass::OtherHash),
    ("X3DH", QV),
    ("XMSS", AlgorithmClass::PostQuantum(PqcKind::Xmss)),
    ("Yarrow", AlgorithmClass::Symmetric),
    ("ZUC", AlgorithmClass::Symmetric),
    ("bcrypt", AlgorithmClass::OtherHash),
];

/// The enum sweep: no CycloneDX 1.7 `algorithmFamily` value is Unknown,
/// and each gets the class above. The table must list exactly the spec's
/// values, so a refreshed schema with new families fails here first.
#[test]
fn every_cyclonedx_1_7_algorithm_family_is_classified() {
    let families = spec_enum("algorithmFamiliesEnum");
    let mut problems = Vec::new();
    for value in &families {
        let cls = family(value);
        if cls.class == AlgorithmClass::Unknown {
            problems.push(format!("{value}: Unknown"));
            continue;
        }
        match FAMILY_CLASSES.iter().find(|(f, _)| f == value) {
            Some((_, expected)) if *expected != cls.class => problems.push(format!(
                "{value}: expected {expected:?}, got {:?} ({})",
                cls.class,
                cls.label()
            )),
            Some(_) => {}
            None => problems.push(format!("{value}: missing from FAMILY_CLASSES")),
        }
    }
    for (f, _) in FAMILY_CLASSES {
        if !families.iter().any(|v| v == f) {
            problems.push(format!("{f}: not a CycloneDX 1.7 family"));
        }
    }
    assert!(
        problems.is_empty(),
        "CycloneDX 1.7 algorithm families out of step with the classifier:\n  {}",
        problems.join("\n  ")
    );
}

/// The keyed constructions among the 1.7 families name no primitive by
/// themselves: they classify as the construction alone, never as Unknown.
#[test]
fn bare_construction_families_name_no_primitive() {
    for f in [
        "CMAC",
        "HKDF",
        "HMAC",
        "IKE-PRF",
        "PBES2",
        "PBKDF2",
        "PBMAC1",
        "SP800-108",
    ] {
        let cls = family(f);
        assert_eq!(cls.family, None, "{f} names no primitive");
        assert_eq!(cls.construction.as_deref(), Some(f), "construction for {f}");
        assert_eq!(cls.label(), f);
    }
}

/// Every 1.7 `ellipticCurve` value is classical elliptic-curve crypto.
#[test]
fn every_cyclonedx_1_7_elliptic_curve_is_quantum_vulnerable() {
    for curve in spec_enum("ellipticCurvesEnum") {
        let cls = classify_algorithm(None, None, None, None, Some(&curve));
        assert_eq!(cls.class, QV, "curve {curve}");
    }
}

/// Families CycloneDX added after 1.7 (in the 1.7.1/1.7.2 schema) that
/// this vocabulary covers too.
#[test]
fn later_cyclonedx_families_are_classified() {
    for (value, expected) in [
        ("Argon2", AlgorithmClass::OtherHash),
        ("J-PAKE", QV),
        ("OPAQUE", QV),
        ("SM2", QV),
        ("SM3", AlgorithmClass::OtherHash),
        ("SM4", AlgorithmClass::Symmetric),
        ("SM9", QV),
        ("SPAKE2", QV),
        ("SPAKE2PLUS", QV),
        ("SRP", QV),
        ("UMAC", AlgorithmClass::Symmetric),
        ("scrypt", AlgorithmClass::OtherHash),
        ("yescrypt", AlgorithmClass::OtherHash),
    ] {
        assert_eq!(family(value).class, expected, "class for {value}");
    }
}

/// JCA `<digest>with<signature>` names are judged by their weaker part:
/// the classical signature, or a broken digest.
#[test]
fn jca_signature_names_classify_by_their_weaker_part() {
    for (name, canonical, class) in [
        ("SHA256withRSA", "RSA", QV),
        ("SHA384withECDSA", "ECDSA", QV),
        ("SHA512withRSA", "RSA", QV),
        ("SHA224withDSA", "DSA", QV),
        ("SHA256withRSA/PSS", "RSA", QV),
        ("SHA256withRSAandMGF1", "RSA", QV),
        ("SHA3-256withECDSA", "ECDSA", QV),
        ("SHA3-512withRSA", "RSA", QV),
        ("SHA512/256withRSA", "RSA", QV),
        ("SHAKE128withRSAPSS", "RSA", QV),
        ("SHAKE256withECDSA", "ECDSA", QV),
        ("SHA256withECDSAinP1363Format", "ECDSA", QV),
        ("SHA256withDSAinP1363Format", "DSA", QV),
        ("SHA256withPLAIN-ECDSA", "ECDSA", QV),
        ("SHA256withECDDSA", "ECDSA", QV),
        ("SHA256withDDSA", "DSA", QV),
        ("sha256WithRSAEncryption", "RSA", QV),
        ("ecdsaWithSHA256", "ECDSA", QV),
        ("RIPEMD160withRSA", "RSA", QV),
        ("SM3withSM2", "SM2", QV),
        ("GOST3411withECGOST3410", "GOST-R-34.10", QV),
        ("NONEwithRSA", "RSA", QV),
        ("NONEwithECDSA", "ECDSA", QV),
        ("SHA1withRSA", "SHA-1", AlgorithmClass::Broken),
        ("SHA1withDSA", "SHA-1", AlgorithmClass::Broken),
        ("SHA1withECDSA", "SHA-1", AlgorithmClass::Broken),
        ("dsaWithSHA1", "SHA-1", AlgorithmClass::Broken),
        ("MD5withRSA", "MD5", AlgorithmClass::Broken),
        ("MD2withRSA", "MD2", AlgorithmClass::Broken),
    ] {
        for cls in [named(name), family(name)] {
            assert_eq!(cls.family.as_deref(), Some(canonical), "family for {name}");
            assert_eq!(cls.class, class, "class for {name}");
        }
    }
}

/// A key agreement named with its KDF ("ECDHwithSHA256KDF") is judged by
/// the classical agreement, whatever the KDF.
#[test]
fn jca_key_agreement_names_with_their_kdf_are_classical() {
    for (name, canonical) in [
        ("ECDHwithSHA256KDF", "ECDH"),
        ("ECCDHwithSHA256CKDF", "ECDH"),
        ("ECMQVwithSHA256CKDF", "ECMQV"),
        ("X25519withSHA256KDF", "X25519"),
        ("DHwithRFC2631KDF", "DH"),
    ] {
        for cls in [named(name), family(name)] {
            assert_eq!(cls.family.as_deref(), Some(canonical), "family for {name}");
            assert_eq!(cls.class, QV, "class for {name}");
        }
    }
}

/// A post-quantum signature with a pre-hash digest ("SHA512withML-DSA")
/// would hide behind the digest under a single classification, so such a
/// JCA name stays unclassified and fails closed. So does a digest beside a
/// signature the classifier does not know. (A classical part beside a
/// post-quantum one is the hybrid they make: tests/crypto_hybrid_tests.rs.)
#[test]
fn jca_names_with_post_quantum_signatures_stay_unclassified() {
    for name in [
        "SHA512withSPHINCS256",
        "SHA256withXMSS",
        "SHA512withML-DSA",
        "NONEwithML-DSA-87",
        "SHA256withUnknownSig",
    ] {
        assert_eq!(named(name).class, AlgorithmClass::Unknown, "{name}");
    }
}

/// A `with` that does not follow a digest is not a JCA separator: inside an
/// ordinary word, or after the OAEP padding of a JCA cipher transformation
/// ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding" is RSA, not SHA-1).
#[test]
fn with_after_anything_but_a_digest_is_not_a_jca_separator() {
    for (name, label, class) in [
        (
            "notwithstanding-aes-256",
            "AES-256",
            AlgorithmClass::Symmetric,
        ),
        ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA", QV),
        ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA", QV),
    ] {
        let cls = named(name);
        assert_eq!(cls.label(), label, "label for {name}");
        assert_eq!(cls.class, class, "class for {name}");
    }
}

/// A JCA password-based encryption name pairs a PRF with a cipher that must
/// both be approved ("PBEWithHmacSHA512AndAES_128" has an approved PRF but
/// AES-128), which one classification cannot carry, so it stays
/// unclassified and fails closed.
#[test]
fn jca_pbe_names_stay_unclassified() {
    for name in [
        "PBEWithMD5AndDES",
        "PBEWithSHA1AndDESede",
        "PBEWithHmacSHA512AndAES_128",
    ] {
        assert_eq!(named(name).class, AlgorithmClass::Unknown, "{name}");
    }
}

/// Other JCA standard names: the key-agreement, KEM and key-wrap cipher
/// names.
#[test]
fn jca_standard_names_classify() {
    for (name, label, class) in [
        ("DiffieHellman", "DH", QV),
        ("DHKEM", "ECDH", QV),
        ("AESWrap", "AES", AlgorithmClass::Symmetric),
        ("AESWrap_256", "AES-256", AlgorithmClass::Symmetric),
        ("AESWrapPad", "AES", AlgorithmClass::Symmetric),
        ("DESedeWrap", "3DES", AlgorithmClass::Broken),
    ] {
        for cls in [named(name), family(name)] {
            assert_eq!(cls.label(), label, "label for {name}");
            assert_eq!(cls.class, class, "class for {name}");
        }
    }
}

/// JCA names for MACs and password-based KDFs name their construction.
#[test]
fn jca_mac_and_kdf_names_name_their_construction() {
    for (name, label, class) in [
        ("HmacSHA256", "HMAC-SHA-256", AlgorithmClass::Sha2),
        ("HmacSHA512/256", "HMAC-SHA-256", AlgorithmClass::Sha2),
        ("HmacSHA3-384", "HMAC-SHA3-384", AlgorithmClass::Sha3),
        ("HmacMD5", "HMAC-MD5", AlgorithmClass::Broken),
        (
            "PBKDF2WithHmacSHA256",
            "PBKDF2-HMAC-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (
            "PBKDF2WithHmacSHA512",
            "PBKDF2-HMAC-SHA-512",
            AlgorithmClass::Sha2,
        ),
    ] {
        let cls = named(name);
        assert_eq!(cls.label(), label, "label for {name}");
        assert_eq!(cls.class, class, "class for {name}");
    }
}

/// Bare curve names and their aliases are elliptic-curve crypto; the NIST
/// prime curves share one canonical name.
#[test]
fn curve_aliases_classify_as_elliptic_curve_crypto() {
    for (name, label) in [
        ("P-256", "EC-P-256"),
        ("secp256r1", "EC-P-256"),
        ("prime256v1", "EC-P-256"),
        ("nistp256", "EC-P-256"),
        ("P-384", "EC-P-384"),
        ("secp384r1", "EC-P-384"),
        ("P-521", "EC-P-521"),
        ("secp521r1", "EC-P-521"),
        ("secp256k1", "EC-secp256k1"),
        ("sect571k1", "EC-sect571k1"),
        ("prime239v1", "EC-prime239v1"),
        ("ristretto255", "EC-ristretto255"),
        ("x25519", "X25519"),
        ("curve25519", "X25519"),
        ("x448", "X448"),
        ("curve448", "X448"),
        ("brainpoolP384r1", "EC"),
    ] {
        for cls in [named(name), family(name)] {
            assert_eq!(cls.class, QV, "class for {name}");
            assert_eq!(cls.label(), label, "label for {name}");
        }
    }
}

/// MQV, PAKEs and X3DH are classical key agreement; A5/1, A5/2, CMEA and
/// Dual_EC_DRBG are broken.
#[test]
fn key_agreement_and_broken_legacy_names() {
    for (identity, canonical, class) in [
        ("FFDH", "DH", QV),
        ("FFMQV", "MQV", QV),
        ("ECMQV", "ECMQV", QV),
        ("SPAKE2", "SPAKE2", QV),
        ("SPAKE2+", "SPAKE2+", QV),
        ("SRP-6a", "SRP", QV),
        ("CPace", "CPACE", QV),
        ("EC-JPAKE", "J-PAKE", QV),
        ("X3DH", "X3DH", QV),
        ("A5/1", "A5/1", AlgorithmClass::Broken),
        ("A5/2", "A5/2", AlgorithmClass::Broken),
        ("CMEA", "CMEA", AlgorithmClass::Broken),
        ("Dual_EC_DRBG", "DUAL-EC-DRBG", AlgorithmClass::Broken),
        ("DualECDRBG", "DUAL-EC-DRBG", AlgorithmClass::Broken),
    ] {
        for cls in [named(identity), family(identity)] {
            assert_eq!(
                cls.family.as_deref(),
                Some(canonical),
                "family for {identity}"
            );
            assert_eq!(cls.class, class, "class for {identity}");
        }
    }
}

/// Bare words that are also algorithm names do not classify from
/// unstructured names, while the declared family still does.
#[test]
fn everyday_words_do_not_classify_from_names() {
    for name in [
        "opaque-signed",
        "pace-maker",
        "sae-module",
        "rabbit-mq",
        "hc-vault",
    ] {
        assert_eq!(named(name).class, AlgorithmClass::Unknown, "{name}");
    }
    for f in ["OPAQUE", "PACE", "SAE", "RABBIT", "HC"] {
        assert_ne!(family(f).class, AlgorithmClass::Unknown, "{f}");
    }
}

/// MACs and KDFs take their primitive from the family, the parameter set,
/// the name or the OID, and are classified as that primitive; an everyday
/// word in the name ("seed-expander") names none.
#[test]
fn macs_and_kdfs_classify_by_their_primitive() {
    let cases = [
        (
            classify_algorithm(Some("HMAC"), None, None, Some("SHA-384"), None),
            "HMAC-SHA-384",
            AlgorithmClass::Sha2,
        ),
        (
            classify_algorithm(Some("HMAC"), Some("HMAC-SHA256"), None, None, None),
            "HMAC-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (
            classify_algorithm(Some("CMAC"), None, None, Some("SEED"), None),
            "CMAC-SEED",
            AlgorithmClass::Symmetric,
        ),
        (
            classify_algorithm(Some("SP800-108"), Some("seed-expander"), None, None, None),
            "SP800-108",
            AlgorithmClass::Symmetric,
        ),
        (
            classify_algorithm(Some("HMAC"), Some("HMAC-SHA512"), None, Some("512"), None),
            "HMAC-SHA-512",
            AlgorithmClass::Sha2,
        ),
        (
            classify_algorithm(Some("HKDF"), None, None, Some("SHA-256"), None),
            "HKDF-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (
            classify_algorithm(Some("CMAC"), None, None, Some("AES-256"), None),
            "CMAC-AES-256",
            AlgorithmClass::Symmetric,
        ),
        (
            classify_algorithm(Some("PBKDF2"), None, None, Some("HMAC-SHA512"), None),
            "PBKDF2-HMAC-SHA-512",
            AlgorithmClass::Sha2,
        ),
        (
            classify_algorithm(Some("KMAC"), None, None, Some("256"), None),
            "KMAC-256",
            AlgorithmClass::Sha3,
        ),
        (family("GMAC"), "GMAC-AES", AlgorithmClass::Symmetric),
        (
            named("AES-128-CMAC"),
            "CMAC-AES-128",
            AlgorithmClass::Symmetric,
        ),
        (
            named("AES-256-GMAC"),
            "GMAC-AES-256",
            AlgorithmClass::Symmetric,
        ),
        (named("hmac-sha2-256"), "HMAC-SHA-256", AlgorithmClass::Sha2),
        (
            named("pbkdf2_sha256"),
            "PBKDF2-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (named("HMAC_SHA1"), "HMAC-SHA-1", AlgorithmClass::Broken),
        (family("Argon2id"), "ARGON2", AlgorithmClass::OtherHash),
        (
            by_oid("1.2.840.113549.2.9"),
            "HMAC-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (
            by_oid("1.2.840.113549.2.10"),
            "HMAC-SHA-384",
            AlgorithmClass::Sha2,
        ),
        (
            by_oid("1.2.840.113549.2.13"),
            "HMAC-SHA-256",
            AlgorithmClass::Sha2,
        ),
        (
            by_oid("1.2.840.113549.2.7"),
            "HMAC-SHA-1",
            AlgorithmClass::Broken,
        ),
        (
            by_oid("1.3.6.1.5.5.8.1.2"),
            "HMAC-SHA-1",
            AlgorithmClass::Broken,
        ),
        (
            by_oid("2.16.840.1.101.3.4.2.14"),
            "HMAC-SHA3-256",
            AlgorithmClass::Sha3,
        ),
        (
            by_oid("1.2.840.113549.1.9.16.3.29"),
            "HKDF-SHA-384",
            AlgorithmClass::Sha2,
        ),
        (
            by_oid("1.2.840.113549.1.9.16.3.35"),
            "HKDF-SHA3-512",
            AlgorithmClass::Sha3,
        ),
        (
            by_oid("2.16.840.1.101.3.4.1.49"),
            "GMAC-AES-256",
            AlgorithmClass::Symmetric,
        ),
        (
            by_oid("2.16.840.1.101.3.4.2.20"),
            "KMAC-256",
            AlgorithmClass::Sha3,
        ),
        (
            by_oid("2.16.840.1.101.3.4.2.21"),
            "KMAC-128",
            AlgorithmClass::Sha3,
        ),
        (
            by_oid("1.2.840.113549.1.5.12"),
            "PBKDF2",
            AlgorithmClass::Symmetric,
        ),
        (
            by_oid("1.3.6.1.4.1.11591.4.11"),
            "SCRYPT",
            AlgorithmClass::OtherHash,
        ),
    ];
    for (cls, label, class) in cases {
        assert_eq!(cls.label(), label);
        assert_eq!(cls.class, class, "class for {label}");
    }
}

/// OIDs for signatures over a broken digest are judged by the digest, like
/// the matching JCA names; the other newly mapped OIDs get their family.
#[test]
fn newly_mapped_oids() {
    for (oid, canonical, class) in [
        ("1.2.840.113549.1.1.2", "MD2", AlgorithmClass::Broken),
        ("1.2.840.113549.1.1.3", "MD4", AlgorithmClass::Broken),
        ("1.2.840.113549.1.1.4", "MD5", AlgorithmClass::Broken),
        ("1.2.840.113549.1.1.5", "SHA-1", AlgorithmClass::Broken),
        ("1.2.840.10040.4.3", "SHA-1", AlgorithmClass::Broken),
        ("1.2.840.10045.4.1", "SHA-1", AlgorithmClass::Broken),
        ("1.2.840.113549.1.1.11", "RSA", QV),
        ("1.2.840.10040.4.1", "DSA", QV),
        ("1.3.6.1.5.5.7.6.31", "RSA", QV),
        ("1.3.6.1.5.5.7.6.33", "ECDSA", QV),
        ("1.2.840.113549.1.5.3", "PBES1", AlgorithmClass::Broken),
        ("1.2.840.113549.3.9", "RC5", AlgorithmClass::Broken),
        (
            "1.2.840.113549.1.9.16.3.18",
            "CHACHA20",
            AlgorithmClass::Symmetric,
        ),
        ("1.2.643.2.2.35.1", "GOST-R-34.10", QV),
        ("1.2.643.7.1.2.1.2.1", "GOST-R-34.10", QV),
    ] {
        let cls = by_oid(oid);
        assert_eq!(cls.family.as_deref(), Some(canonical), "family for {oid}");
        assert_eq!(cls.class, class, "class for {oid}");
    }
}

// ── Profile verdicts ────────────────────────────────────────────────────

/// One algorithm asset: name, primitive, and the optional family,
/// parameter set, OID and declared NIST quantum security level.
struct Asset {
    name: &'static str,
    primitive: &'static str,
    family: Option<&'static str>,
    parameter: Option<&'static str>,
    oid: Option<&'static str>,
    level: Option<u8>,
}

const fn asset(name: &'static str, primitive: &'static str) -> Asset {
    Asset {
        name,
        primitive,
        family: None,
        parameter: None,
        oid: None,
        level: None,
    }
}

/// A CycloneDX 1.7 CBOM listing `assets` as algorithm assets.
fn cbom(assets: &[Asset]) -> NormalizedSbom {
    let components: Vec<serde_json::Value> = assets
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let mut algorithm = serde_json::json!({ "primitive": a.primitive });
            if let Some(f) = a.family {
                algorithm["algorithmFamily"] = f.into();
            }
            if let Some(p) = a.parameter {
                algorithm["parameterSetIdentifier"] = p.into();
            }
            if let Some(l) = a.level {
                algorithm["nistQuantumSecurityLevel"] = l.into();
            }
            let mut crypto =
                serde_json::json!({ "assetType": "algorithm", "algorithmProperties": algorithm });
            if let Some(o) = a.oid {
                crypto["oid"] = o.into();
            }
            serde_json::json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto/alg/{i}"),
                "name": a.name,
                "cryptoProperties": crypto,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a",
        "version": 1,
        "metadata": { "timestamp": "2026-10-01T00:00:00Z" },
        "components": components,
    });
    parse_sbom_str(&doc.to_string()).expect("CBOM parses")
}

fn check(sbom: &NormalizedSbom, level: ComplianceLevel) -> ComplianceResult {
    let as_of = chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc);
    ComplianceChecker::new(level).with_as_of(as_of).check(sbom)
}

/// Every finding as "SEVERITY RULE: message", for assertion messages.
fn findings(result: &ComplianceResult) -> Vec<String> {
    result
        .violations
        .iter()
        .map(|v| format!("{:?} {}: {}", v.severity, v.rule_id, v.message))
        .collect()
}

/// HMAC and HKDF over SHA-384/SHA-512, and CMAC/GMAC over AES-256, pass
/// CNSA 2.0, whichever field names their primitive.
#[test]
fn cnsa2_approves_macs_and_kdfs_over_approved_primitives() {
    let sbom = cbom(&[
        Asset {
            family: Some("HMAC"),
            parameter: Some("SHA-384"),
            ..asset("HMAC-SHA-384", "mac")
        },
        Asset {
            oid: Some("1.2.840.113549.2.11"),
            ..asset("HMAC-SHA-512", "mac")
        },
        Asset {
            oid: Some("1.2.840.113549.1.9.16.3.29"),
            ..asset("HKDF-SHA-384", "kdf")
        },
        Asset {
            family: Some("HKDF"),
            ..asset("HKDF-SHA-512", "kdf")
        },
        Asset {
            family: Some("CMAC"),
            parameter: Some("AES-256"),
            ..asset("CMAC-AES-256", "mac")
        },
        Asset {
            oid: Some("2.16.840.1.101.3.4.1.49"),
            ..asset("GMAC", "mac")
        },
    ]);
    let result = check(&sbom, ComplianceLevel::Cnsa2);
    assert!(result.is_compliant, "{:#?}", findings(&result));
    assert_eq!(result.error_count, 0, "{:#?}", findings(&result));
}

/// HMAC-SHA256 and HKDF-SHA256 fail CNSA 2.0 on their hash, with a reason
/// that names SHA-256, not as unknown algorithms.
#[test]
fn cnsa2_rejects_macs_and_kdfs_over_sha256_naming_sha256() {
    let sbom = cbom(&[
        Asset {
            family: Some("HMAC"),
            parameter: Some("256"),
            ..asset("HMAC-SHA256", "mac")
        },
        Asset {
            oid: Some("1.2.840.113549.1.9.16.3.28"),
            ..asset("HKDF-SHA256", "kdf")
        },
    ]);
    let result = check(&sbom, ComplianceLevel::Cnsa2);
    let hash_findings: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-CNSA2-ALG-002")
        .collect();
    assert_eq!(hash_findings.len(), 2, "{:#?}", findings(&result));
    for v in hash_findings {
        assert_eq!(v.severity, ViolationSeverity::Error);
        assert!(v.message.contains("SHA-256"), "{}", v.message);
    }
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.rule_id.ends_with("UNKNOWN")),
        "{:#?}",
        findings(&result)
    );
    assert!(!result.is_compliant);
}

/// A construction that names no primitive fails CNSA 2.0 on the primitive
/// it is missing, and is not an unknown algorithm.
#[test]
fn cnsa2_rejects_constructions_without_a_primitive() {
    for (f, rule, missing) in [
        ("HMAC", "SBOM-CNSA2-ALG-002", "unspecified hash function"),
        ("PBKDF2", "SBOM-CNSA2-ALG-002", "unspecified hash function"),
        ("CMAC", "SBOM-CNSA2-ALG-001", "unspecified block cipher"),
        (
            "SP800-108",
            "SBOM-CNSA2-ALG-008",
            "unspecified hash function or block cipher",
        ),
    ] {
        let sbom = cbom(&[Asset {
            family: Some(f),
            ..asset("keyed", "mac")
        }]);
        let result = check(&sbom, ComplianceLevel::Cnsa2);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == rule && v.message.contains(missing)),
            "{f}: {:#?}",
            findings(&result)
        );
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id.ends_with("UNKNOWN")),
            "{f}: {:#?}",
            findings(&result)
        );
    }
}

/// NIST PQC (IR 8547 §4.1.3): symmetric MACs and KDFs at 128 bits of
/// security or more are not quantum-vulnerable, so they neither warn nor
/// fail.
#[test]
fn pqc_accepts_macs_and_kdfs_without_warnings() {
    let sbom = cbom(&[
        Asset {
            family: Some("HMAC"),
            parameter: Some("SHA-256"),
            level: Some(1),
            ..asset("HMAC-SHA-256", "mac")
        },
        Asset {
            oid: Some("1.2.840.113549.1.9.16.3.28"),
            level: Some(1),
            ..asset("HKDF-SHA-256", "kdf")
        },
        Asset {
            family: Some("KMAC"),
            parameter: Some("256"),
            level: Some(5),
            ..asset("KMAC256", "mac")
        },
        Asset {
            family: Some("CMAC"),
            parameter: Some("AES-128"),
            level: Some(1),
            ..asset("CMAC-AES-128", "mac")
        },
        Asset {
            family: Some("PBKDF2"),
            level: Some(1),
            ..asset("pbkdf2", "kdf")
        },
        Asset {
            family: Some("scrypt"),
            level: Some(1),
            ..asset("scrypt", "kdf")
        },
    ]);
    let result = check(&sbom, ComplianceLevel::NistPqc);
    assert!(result.is_compliant, "{:#?}", findings(&result));
    assert_eq!(result.error_count, 0, "{:#?}", findings(&result));
    assert_eq!(result.warning_count, 0, "{:#?}", findings(&result));
}

/// JCA signature names, curve names, MQV and PAKEs get their real
/// verdict under both profiles instead of the unknown-algorithm one.
#[test]
fn previously_unknown_names_get_their_real_verdict() {
    let sbom = cbom(&[
        asset("SHA256withRSA", "signature"),
        asset("SHA1withRSA", "signature"),
        asset("prime256v1", "key-agree"),
        Asset {
            family: Some("FFDH"),
            ..asset("FFDH", "key-agree")
        },
        Asset {
            family: Some("MQV"),
            ..asset("MQV", "key-agree")
        },
        asset("SPAKE2", "key-agree"),
        asset("Dual_EC_DRBG", "drbg"),
    ]);
    let rule_for = |result: &ComplianceResult, name: &str| {
        result
            .violations
            .iter()
            .filter(|v| v.element.as_deref() == Some(name))
            .map(|v| v.rule_id)
            .collect::<Vec<_>>()
    };
    let cnsa = check(&sbom, ComplianceLevel::Cnsa2);
    let pqc = check(&sbom, ComplianceLevel::NistPqc);
    for (name, cnsa_rule, pqc_rule) in [
        ("SHA256withRSA", "SBOM-CNSA2-ALG-006", "SBOM-PQC-001"),
        ("SHA1withRSA", "SBOM-CNSA2-ALG-005", "SBOM-PQC-005"),
        ("prime256v1", "SBOM-CNSA2-ALG-006", "SBOM-PQC-001"),
        ("FFDH", "SBOM-CNSA2-ALG-006", "SBOM-PQC-001"),
        ("MQV", "SBOM-CNSA2-ALG-006", "SBOM-PQC-001"),
        ("SPAKE2", "SBOM-CNSA2-ALG-006", "SBOM-PQC-001"),
        ("Dual_EC_DRBG", "SBOM-CNSA2-ALG-005", "SBOM-PQC-005"),
    ] {
        assert!(
            rule_for(&cnsa, name).contains(&cnsa_rule),
            "{name} under CNSA 2.0: {:?}",
            rule_for(&cnsa, name)
        );
        assert!(
            rule_for(&pqc, name).contains(&pqc_rule),
            "{name} under NIST PQC: {:?}",
            rule_for(&pqc, name)
        );
    }
    for result in [&cnsa, &pqc] {
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id.ends_with("UNKNOWN")),
            "{:#?}",
            findings(result)
        );
    }
}
