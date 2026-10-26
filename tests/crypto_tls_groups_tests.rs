//! TLS 1.3 named groups and signature schemes (CycloneDX 1.7 `tlsGroups` and
//! `tlsSignatureSchemes`): every assigned entry of the IANA "TLS Supported
//! Groups" and "TLS SignatureScheme" registries is recognized by name and by
//! codepoint and classified as the algorithm it stands for, and the crypto
//! profiles judge each offered entry under PROTO-002 (review finding V7: a
//! TLS 1.3 asset offering only x25519 and secp256r1 passed CNSA 2.0 and NIST
//! PQC with zero findings).

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    AlgorithmClass, NormalizedSbom, PqcKind, TlsRegistryEntry, is_tls_grease, tls_named_group,
    tls_signature_scheme,
};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceLevel, ComplianceResult, ViolationSeverity};

// ── The IANA registries ─────────────────────────────────────────────────

/// Every assigned entry of the IANA "TLS Supported Groups" registry as
/// (codepoint, name, marked obsolete), extracted from the registry's CSV
/// export <https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv>
/// (registry last updated 2026-10-21, fetched 2026-10-26). Unassigned,
/// reserved (GREASE, RFC 8701) and private-use codepoints are left out.
const SUPPORTED_GROUPS: &[(u16, &str, bool)] = &[
    (1, "sect163k1", false),
    (2, "sect163r1", false),
    (3, "sect163r2", false),
    (4, "sect193r1", false),
    (5, "sect193r2", false),
    (6, "sect233k1", false),
    (7, "sect233r1", false),
    (8, "sect239k1", false),
    (9, "sect283k1", false),
    (10, "sect283r1", false),
    (11, "sect409k1", false),
    (12, "sect409r1", false),
    (13, "sect571k1", false),
    (14, "sect571r1", false),
    (15, "secp160k1", false),
    (16, "secp160r1", false),
    (17, "secp160r2", false),
    (18, "secp192k1", false),
    (19, "secp192r1", false),
    (20, "secp224k1", false),
    (21, "secp224r1", false),
    (22, "secp256k1", false),
    (23, "secp256r1", false),
    (24, "secp384r1", false),
    (25, "secp521r1", false),
    (26, "brainpoolP256r1", false),
    (27, "brainpoolP384r1", false),
    (28, "brainpoolP512r1", false),
    (29, "x25519", false),
    (30, "x448", false),
    (31, "brainpoolP256r1tls13", false),
    (32, "brainpoolP384r1tls13", false),
    (33, "brainpoolP512r1tls13", false),
    (34, "GC256A", false),
    (35, "GC256B", false),
    (36, "GC256C", false),
    (37, "GC256D", false),
    (38, "GC512A", false),
    (39, "GC512B", false),
    (40, "GC512C", false),
    (41, "curveSM2", false),
    (256, "ffdhe2048", false),
    (257, "ffdhe3072", false),
    (258, "ffdhe4096", false),
    (259, "ffdhe6144", false),
    (260, "ffdhe8192", false),
    (512, "MLKEM512", false),
    (513, "MLKEM768", false),
    (514, "MLKEM1024", false),
    (4585, "SecP256r1MLKEM512", false),
    (4586, "MLKEM512X25519", false),
    (4587, "SecP256r1MLKEM768", false),
    (4588, "X25519MLKEM768", false),
    (4589, "SecP384r1MLKEM1024", false),
    (4590, "curveSM2MLKEM768", false),
    (25497, "X25519Kyber768Draft00", true),
    (25498, "SecP256r1Kyber768Draft00", true),
    (65281, "arbitrary_explicit_prime_curves", false),
    (65282, "arbitrary_explicit_char2_curves", false),
];

/// Every assigned entry of the IANA "TLS SignatureScheme" registry as
/// (codepoint, name, marked obsolete), extracted from the registry's CSV
/// export <https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv>
/// (registry last updated 2026-10-21, fetched 2026-10-26). The ranges
/// reserved for backward compatibility (the TLS 1.2 hash/signature pairs)
/// and for private use are left out.
const SIGNATURE_SCHEMES: &[(u16, &str, bool)] = &[
    (0x0201, "rsa_pkcs1_sha1", false),
    (0x0203, "ecdsa_sha1", false),
    (0x0401, "rsa_pkcs1_sha256", false),
    (0x0403, "ecdsa_secp256r1_sha256", false),
    (0x0420, "rsa_pkcs1_sha256_legacy", false),
    (0x0501, "rsa_pkcs1_sha384", false),
    (0x0503, "ecdsa_secp384r1_sha384", false),
    (0x0520, "rsa_pkcs1_sha384_legacy", false),
    (0x0601, "rsa_pkcs1_sha512", false),
    (0x0603, "ecdsa_secp521r1_sha512", false),
    (0x0620, "rsa_pkcs1_sha512_legacy", false),
    (0x0704, "eccsi_sha256", false),
    (0x0705, "iso_ibs1", false),
    (0x0706, "iso_ibs2", false),
    (0x0707, "iso_chinese_ibs", false),
    (0x0708, "sm2sig_sm3", false),
    (0x0709, "gostr34102012_256a", false),
    (0x070A, "gostr34102012_256b", false),
    (0x070B, "gostr34102012_256c", false),
    (0x070C, "gostr34102012_256d", false),
    (0x070D, "gostr34102012_512a", false),
    (0x070E, "gostr34102012_512b", false),
    (0x070F, "gostr34102012_512c", false),
    (0x0804, "rsa_pss_rsae_sha256", false),
    (0x0805, "rsa_pss_rsae_sha384", false),
    (0x0806, "rsa_pss_rsae_sha512", false),
    (0x0807, "ed25519", false),
    (0x0808, "ed448", false),
    (0x0809, "rsa_pss_pss_sha256", false),
    (0x080A, "rsa_pss_pss_sha384", false),
    (0x080B, "rsa_pss_pss_sha512", false),
    (0x081A, "ecdsa_brainpoolP256r1tls13_sha256", false),
    (0x081B, "ecdsa_brainpoolP384r1tls13_sha384", false),
    (0x081C, "ecdsa_brainpoolP512r1tls13_sha512", false),
    (0x0904, "mldsa44", false),
    (0x0905, "mldsa65", false),
    (0x0906, "mldsa87", false),
    (0x0911, "slhdsa_sha2_128s", false),
    (0x0912, "slhdsa_sha2_128f", false),
    (0x0913, "slhdsa_sha2_192s", false),
    (0x0914, "slhdsa_sha2_192f", false),
    (0x0915, "slhdsa_sha2_256s", false),
    (0x0916, "slhdsa_sha2_256f", false),
    (0x0917, "slhdsa_shake_128s", false),
    (0x0918, "slhdsa_shake_128f", false),
    (0x0919, "slhdsa_shake_192s", false),
    (0x091A, "slhdsa_shake_192f", false),
    (0x091B, "slhdsa_shake_256s", false),
    (0x091C, "slhdsa_shake_256f", false),
];

type Lookup = fn(&str) -> Option<TlsRegistryEntry>;

/// The lookup finds exactly the registry's entries: each by its name in any
/// ASCII case and by its codepoint in decimal and in hexadecimal, and no
/// codepoint the registry leaves unassigned, reserved or private.
fn assert_matches_registry(what: &str, lookup: Lookup, registry: &[(u16, &str, bool)]) {
    for &(codepoint, name, obsolete) in registry {
        let mut spellings = vec![
            name.to_string(),
            name.to_ascii_uppercase(),
            name.to_ascii_lowercase(),
            format!("  {name}\t"),
            codepoint.to_string(),
            format!("0x{codepoint:04X}"),
            format!("0x{codepoint:x}"),
            format!("0X{codepoint:04x}"),
        ];
        if obsolete {
            spellings.push(format!("{name} (OBSOLETE)"));
            spellings.push(format!("{name} (obsolete)"));
        }
        for spelling in spellings {
            let entry = lookup(&spelling)
                .unwrap_or_else(|| panic!("{what} {spelling:?} ({codepoint}) is not recognized"));
            assert_eq!(
                (entry.codepoint, entry.name, entry.obsolete),
                (codepoint, name, obsolete),
                "{what} {spelling:?}"
            );
            assert_eq!(
                entry.classification.is_some(),
                !obsolete,
                "{what} {name}: every entry but an obsolete draft names an algorithm"
            );
        }
    }
    for codepoint in 0..=u16::MAX {
        if registry.iter().any(|&(c, ..)| c == codepoint) {
            continue;
        }
        for spelling in [codepoint.to_string(), format!("0x{codepoint:04X}")] {
            assert!(
                lookup(&spelling).is_none(),
                "{what} {spelling} is not assigned in the IANA registry"
            );
        }
    }
}

/// The acceptance criterion of plan work package 2.3: the codepoint tables
/// match the IANA registries.
#[test]
fn tls_tables_match_the_iana_registries() {
    assert_matches_registry("TLS group", tls_named_group, SUPPORTED_GROUPS);
    assert_matches_registry(
        "TLS signature scheme",
        tls_signature_scheme,
        SIGNATURE_SCHEMES,
    );
    assert_aliases_resolve("TLS group", tls_named_group, GROUP_ALIASES);
    assert_aliases_resolve("TLS signature scheme", tls_signature_scheme, SCHEME_ALIASES);
}

/// Unambiguous spellings outside the registries, each with the IANA entry
/// it names: NIST, SSH, ANSI X9.62 and Go names of the prime curves, FIPS
/// 203 ML-KEM names, and hybrid group names with separators.
const GROUP_ALIASES: &[(&str, &str)] = &[
    ("P-192", "secp192r1"),
    ("P-224", "secp224r1"),
    ("P-256", "secp256r1"),
    ("P-384", "secp384r1"),
    ("P-521", "secp521r1"),
    ("P192", "secp192r1"),
    ("P224", "secp224r1"),
    ("P256", "secp256r1"),
    ("P384", "secp384r1"),
    ("P521", "secp521r1"),
    ("nistp192", "secp192r1"),
    ("nistp224", "secp224r1"),
    ("nistp256", "secp256r1"),
    ("nistp384", "secp384r1"),
    ("nistp521", "secp521r1"),
    ("prime192v1", "secp192r1"),
    ("prime256v1", "secp256r1"),
    ("CurveP256", "secp256r1"),
    ("CurveP384", "secp384r1"),
    ("CurveP521", "secp521r1"),
    ("ML-KEM-512", "MLKEM512"),
    ("ML-KEM-768", "MLKEM768"),
    ("ML-KEM-1024", "MLKEM1024"),
    ("SecP256r1-MLKEM512", "SecP256r1MLKEM512"),
    ("SecP256r1-ML-KEM-512", "SecP256r1MLKEM512"),
    ("MLKEM512-X25519", "MLKEM512X25519"),
    ("ML-KEM-512-X25519", "MLKEM512X25519"),
    ("SecP256r1-MLKEM768", "SecP256r1MLKEM768"),
    ("SecP256r1-ML-KEM-768", "SecP256r1MLKEM768"),
    ("X25519-MLKEM768", "X25519MLKEM768"),
    ("X25519-ML-KEM-768", "X25519MLKEM768"),
    ("SecP384r1-MLKEM1024", "SecP384r1MLKEM1024"),
    ("SecP384r1-ML-KEM-1024", "SecP384r1MLKEM1024"),
    ("curveSM2-MLKEM768", "curveSM2MLKEM768"),
    ("curveSM2-ML-KEM-768", "curveSM2MLKEM768"),
];

/// The FIPS 204 ML-DSA and FIPS 205 SLH-DSA parameter-set names, each with
/// the IANA signature scheme it names.
const SCHEME_ALIASES: &[(&str, &str)] = &[
    ("ML-DSA-44", "mldsa44"),
    ("ML-DSA-65", "mldsa65"),
    ("ML-DSA-87", "mldsa87"),
    ("SLH-DSA-SHA2-128s", "slhdsa_sha2_128s"),
    ("SLH-DSA-SHA2-128f", "slhdsa_sha2_128f"),
    ("SLH-DSA-SHA2-192s", "slhdsa_sha2_192s"),
    ("SLH-DSA-SHA2-192f", "slhdsa_sha2_192f"),
    ("SLH-DSA-SHA2-256s", "slhdsa_sha2_256s"),
    ("SLH-DSA-SHA2-256f", "slhdsa_sha2_256f"),
    ("SLH-DSA-SHAKE-128s", "slhdsa_shake_128s"),
    ("SLH-DSA-SHAKE-128f", "slhdsa_shake_128f"),
    ("SLH-DSA-SHAKE-192s", "slhdsa_shake_192s"),
    ("SLH-DSA-SHAKE-192f", "slhdsa_shake_192f"),
    ("SLH-DSA-SHAKE-256s", "slhdsa_shake_256s"),
    ("SLH-DSA-SHAKE-256f", "slhdsa_shake_256f"),
];

/// Each alias, in any ASCII case and with `_` or ` ` for `-`, resolves to
/// exactly the entry its IANA name resolves to.
fn assert_aliases_resolve(what: &str, lookup: Lookup, aliases: &[(&str, &str)]) {
    for &(alias, iana) in aliases {
        let expected = lookup(iana).unwrap_or_else(|| panic!("{what} {iana} is registered"));
        assert_eq!(expected.name, iana, "{what} {iana}");
        for spelling in [
            alias.to_string(),
            alias.to_ascii_lowercase(),
            alias.to_ascii_uppercase(),
            alias.replace('-', "_"),
            alias.replace('-', " "),
            format!(" {alias}\t"),
        ] {
            assert_eq!(
                lookup(&spelling).as_ref(),
                Some(&expected),
                "{what} alias {spelling:?} names {iana}"
            );
        }
    }
}

/// Kyber spellings are no aliases: round-3 Kyber is not ML-KEM, so they
/// stay unverifiable, and the registered Kyber drafts name no algorithm.
#[test]
fn kyber_spellings_stay_unverifiable() {
    for spelling in [
        "Kyber768",
        "kyber-768",
        "Kyber_768",
        "KYBER1024",
        "Kyber-512",
        "X25519Kyber768",
        "x25519_kyber768",
        "X25519-Kyber768",
        "X25519-Kyber-768",
        "p256_kyber768",
        "SecP256r1Kyber768",
        "x25519_kyber512",
        "X25519Kyber768Draft01",
        "X25519_Kyber768Draft00",
    ] {
        assert!(
            tls_named_group(spelling).is_none() && tls_signature_scheme(spelling).is_none(),
            "{spelling:?} names no entry"
        );
    }
    for draft in ["X25519Kyber768Draft00", "SecP256r1Kyber768Draft00", "25497"] {
        let entry = tls_named_group(draft).expect("a registered draft");
        assert!(entry.obsolete && entry.classification.is_none(), "{draft}");
    }
}

/// Codepoints are decimal or `0x` hexadecimal; nothing else is read as one,
/// and an unknown name is no entry.
#[test]
fn tls_codepoints_are_decimal_or_0x_hexadecimal() {
    for spelling in ["29", "029", "0x1D", "0x001d", "0X001D", " 0x1d "] {
        assert_eq!(
            tls_named_group(spelling).map(|e| e.name),
            Some("x25519"),
            "{spelling:?}"
        );
    }
    for spelling in [
        "",
        "0x",
        "1D",
        "x1D",
        "0x1G",
        "+29",
        "-29",
        "29.0",
        "65536",
        "0x10000",
        "0x 1D",
        "x 25519",
        "X25519+MLKEM768",
        "ML-KEM768",
        "MLKEM-1024",
        "P-255",
        "nistp255",
        "prime384v1",
        "kyber768",
        "ML-DSA-88",
        "MLDSA-87",
        "x25519 (OBSOLETE)",
        "X25519Kyber768Draft00 (OBSOLETE",
        "(OBSOLETE)",
        ")",
        "x25519\u{e9}",
        "\u{fc}\u{fc}\u{fc}\u{fc}\u{fc})",
        "\u{1F512}(OBSOLETE)",
        "\u{0661}\u{0662}",
    ] {
        assert!(
            tls_named_group(spelling).is_none() && tls_signature_scheme(spelling).is_none(),
            "{spelling:?} names no registry entry"
        );
    }
    assert_eq!(
        tls_signature_scheme("1027").map(|e| e.name),
        Some("ecdsa_secp256r1_sha256")
    );
    // GREASE (RFC 8701) and the TLS 1.2 DSA pairs reserved for backward
    // compatibility name nothing.
    assert!(tls_named_group("0x0A0A").is_none());
    assert!(tls_signature_scheme("0x0402").is_none());
}

/// The GREASE values RFC 8701 §2 reserves for named groups and signature
/// algorithms, as the RFC lists them.
const GREASE: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// GREASE values are recognized by codepoint, in decimal or hexadecimal,
/// and by nothing else; none is a registry entry.
#[test]
fn grease_values_are_recognized_by_codepoint() {
    for codepoint in 0..=u16::MAX {
        let grease = GREASE.contains(&codepoint);
        for spelling in [
            codepoint.to_string(),
            format!("0x{codepoint:04X}"),
            format!("0x{codepoint:x}"),
            format!(" 0X{codepoint:04x} "),
        ] {
            assert_eq!(is_tls_grease(&spelling), grease, "{spelling:?}");
            if grease {
                assert!(
                    tls_named_group(&spelling).is_none()
                        && tls_signature_scheme(&spelling).is_none(),
                    "GREASE {spelling} is no registry entry"
                );
            }
        }
    }
    for spelling in [
        "", "GREASE", "grease", "0x", "0x0A0A0", "0x0A0A,", "x0A0A", "2570.0", "+2570",
    ] {
        assert!(!is_tls_grease(spelling), "{spelling:?}");
    }
}

/// What a registry entry is classified as: its label and class.
fn classified(entry: Option<TlsRegistryEntry>) -> (String, AlgorithmClass) {
    let cls = entry
        .and_then(|e| e.classification)
        .expect("a classified registry entry");
    (cls.label(), cls.class)
}

/// Each group is the key exchange it stands for: ECDH(E) over its curve,
/// finite-field DH, X25519/X448, SM2, GOST, ML-KEM, or a PQ/T hybrid of
/// two of them; each signature scheme is its signature algorithm, the hash
/// being part of the scheme — but for the SHA-1 schemes, which SHA-1
/// breaks.
#[test]
fn tls_entries_classify_as_the_algorithm_they_stand_for() {
    use AlgorithmClass::{Broken, ClassicalQuantumVulnerable as Classical, Hybrid, PostQuantum};
    let groups: &[(&str, &str, AlgorithmClass)] = &[
        ("sect163k1", "ECDH-sect163k1", Classical),
        ("secp192r1", "ECDH-P-192", Classical),
        ("secp256r1", "ECDH-P-256", Classical),
        ("secp384r1", "ECDH-P-384", Classical),
        ("secp521r1", "ECDH-P-521", Classical),
        ("brainpoolP384r1tls13", "ECDH-brainpoolP384r1", Classical),
        ("x25519", "X25519", Classical),
        ("x448", "X448", Classical),
        ("GC256A", "GOST-R-34.10-256", Classical),
        ("GC512C", "GOST-R-34.10-512", Classical),
        ("curveSM2", "SM2", Classical),
        ("ffdhe2048", "DH-2048", Classical),
        ("ffdhe8192", "DH-8192", Classical),
        ("arbitrary_explicit_prime_curves", "ECDH", Classical),
        ("MLKEM512", "ML-KEM-512", PostQuantum(PqcKind::MlKem)),
        ("MLKEM768", "ML-KEM-768", PostQuantum(PqcKind::MlKem)),
        ("MLKEM1024", "ML-KEM-1024", PostQuantum(PqcKind::MlKem)),
        ("SecP256r1MLKEM512", "ECDH-P-256 + ML-KEM-512", Hybrid),
        ("MLKEM512X25519", "X25519 + ML-KEM-512", Hybrid),
        ("SecP256r1MLKEM768", "ECDH-P-256 + ML-KEM-768", Hybrid),
        ("X25519MLKEM768", "X25519 + ML-KEM-768", Hybrid),
        ("SecP384r1MLKEM1024", "ECDH-P-384 + ML-KEM-1024", Hybrid),
        ("curveSM2MLKEM768", "SM2 + ML-KEM-768", Hybrid),
    ];
    for (name, label, class) in groups {
        assert_eq!(
            classified(tls_named_group(name)),
            (label.to_string(), *class),
            "TLS group {name}"
        );
    }
    let schemes: &[(&str, &str, AlgorithmClass)] = &[
        ("rsa_pkcs1_sha1", "SHA-1", Broken),
        ("ecdsa_sha1", "SHA-1", Broken),
        ("rsa_pkcs1_sha256", "RSA", Classical),
        ("rsa_pkcs1_sha384_legacy", "RSA", Classical),
        ("rsa_pss_rsae_sha256", "RSA", Classical),
        ("rsa_pss_pss_sha512", "RSA", Classical),
        ("ecdsa_secp256r1_sha256", "ECDSA-P-256", Classical),
        ("ecdsa_secp384r1_sha384", "ECDSA-P-384", Classical),
        ("ecdsa_secp521r1_sha512", "ECDSA-P-521", Classical),
        (
            "ecdsa_brainpoolP256r1tls13_sha256",
            "ECDSA-brainpoolP256r1",
            Classical,
        ),
        ("ed25519", "ED25519", Classical),
        ("ed448", "ED448", Classical),
        ("eccsi_sha256", "EC", Classical),
        ("iso_ibs2", "EC", Classical),
        ("iso_chinese_ibs", "SM9", Classical),
        ("sm2sig_sm3", "SM2", Classical),
        ("gostr34102012_256a", "GOST-R-34.10-256", Classical),
        ("gostr34102012_512c", "GOST-R-34.10-512", Classical),
        ("mldsa44", "ML-DSA-44", PostQuantum(PqcKind::MlDsa)),
        ("mldsa65", "ML-DSA-65", PostQuantum(PqcKind::MlDsa)),
        ("mldsa87", "ML-DSA-87", PostQuantum(PqcKind::MlDsa)),
        (
            "slhdsa_sha2_128s",
            "SLH-DSA-SHA2-128s",
            PostQuantum(PqcKind::SlhDsa),
        ),
        (
            "slhdsa_shake_256f",
            "SLH-DSA-SHAKE-256f",
            PostQuantum(PqcKind::SlhDsa),
        ),
    ];
    for (name, label, class) in schemes {
        assert_eq!(
            classified(tls_signature_scheme(name)),
            (label.to_string(), *class),
            "TLS signature scheme {name}"
        );
    }
    // Every entry falls in one of the classes above.
    for &(codepoint, name, obsolete) in SUPPORTED_GROUPS {
        if obsolete {
            continue;
        }
        let (_, class) = classified(tls_named_group(name));
        let expected = match codepoint {
            512..=514 => PostQuantum(PqcKind::MlKem),
            4585..=4590 => Hybrid,
            _ => Classical,
        };
        assert_eq!(class, expected, "TLS group {name}");
    }
    for &(codepoint, name, _) in SIGNATURE_SCHEMES {
        let (_, class) = classified(tls_signature_scheme(name));
        let expected = match codepoint {
            0x0201 | 0x0203 => Broken,
            0x0904..=0x0906 => PostQuantum(PqcKind::MlDsa),
            0x0911..=0x091C => PostQuantum(PqcKind::SlhDsa),
            _ => Classical,
        };
        assert_eq!(class, expected, "TLS signature scheme {name}");
    }
}

// ── Profile verdicts ────────────────────────────────────────────────────

/// A CycloneDX 1.7 CBOM of one TLS 1.3 protocol whose cipher suite
/// (`TLS_AES_256_GCM_SHA384` unless `name` is `None`) offers the given
/// groups and signature schemes.
fn tls13(name: Option<&str>, groups: &[&str], schemes: &[&str]) -> NormalizedSbom {
    let mut suite = serde_json::json!({
        "identifiers": ["0x13", "0x02"],
        "tlsGroups": groups,
        "tlsSignatureSchemes": schemes,
    });
    if let Some(name) = name {
        suite["name"] = name.into();
    }
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:3e1f4a1c-58f2-4c39-9d0b-7a1e6c2d9b40",
        "version": 1,
        "metadata": { "timestamp": "2026-10-01T00:00:00Z" },
        "components": [{
            "type": "cryptographic-asset",
            "bom-ref": "crypto/protocol/tls13",
            "name": "TLS 1.3",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": { "type": "tls", "version": "1.3", "cipherSuites": [suite] },
            },
        }],
    });
    parse_sbom_str(&doc.to_string()).expect("CBOM parses")
}

fn suite(groups: &[&str], schemes: &[&str]) -> NormalizedSbom {
    tls13(Some("TLS_AES_256_GCM_SHA384"), groups, schemes)
}

/// Every finding, for a readable failure.
fn findings(result: &ComplianceResult) -> Vec<String> {
    result
        .violations
        .iter()
        .map(|v| format!("{:?} {}: {}", v.severity, v.rule_id, v.message))
        .collect()
}

/// The protocol rules a profile reports, with their severity.
fn protocol_rules(result: &ComplianceResult) -> Vec<(&'static str, ViolationSeverity)> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id.contains("PROTO"))
        .map(|v| (v.rule_id, v.severity))
        .collect()
}

/// The messages of the findings with rule `rule`, in order.
fn messages<'a>(result: &'a ComplianceResult, rule: &str) -> Vec<&'a str> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule)
        .map(|v| v.message.as_str())
        .collect()
}

/// The message of the one finding with rule `rule`.
fn message(result: &ComplianceResult, rule: &str) -> String {
    match messages(result, rule).as_slice() {
        [one] => (*one).to_string(),
        other => panic!(
            "expected one {rule}, got {}: {:#?}",
            other.len(),
            findings(result)
        ),
    }
}

const CNSA_PROTO_002: (&str, ViolationSeverity) =
    ("SBOM-CNSA2-PROTO-002", ViolationSeverity::Error);
const CNSA_UNKNOWN: (&str, ViolationSeverity) =
    ("SBOM-CNSA2-PROTO-UNKNOWN", ViolationSeverity::Error);
const PQC_PROTO_002: (&str, ViolationSeverity) = ("SBOM-PQC-PROTO-002", ViolationSeverity::Error);
const PQC_UNKNOWN: (&str, ViolationSeverity) =
    ("SBOM-PQC-PROTO-UNKNOWN", ViolationSeverity::Warning);

/// Every offered group and signature scheme is judged on its own, under
/// PROTO-002: classical ones fail both profiles; CNSA 2.0 approves only
/// MLKEM1024, SecP384r1MLKEM1024 (WP 2.4's hybrid verdict) and mldsa87,
/// while NIST PQC accepts every ML-KEM and ML-DSA parameter set, SLH-DSA
/// and the hybrids by their ML-KEM part. One classical alternative among
/// approved ones fails. An entry the registry does not identify, and an
/// obsolete Kyber draft group, cannot be verified. A GREASE value is
/// skipped: no peer negotiates it. An alias ("P-256", "ML-KEM-1024") is
/// judged as the entry it names.
#[test]
fn offered_tls_groups_and_signature_schemes_are_judged_one_by_one() {
    type Case<'a> = (
        &'a [&'a str],
        &'a [&'a str],
        &'a [(&'a str, ViolationSeverity)],
        &'a [(&'a str, ViolationSeverity)],
    );
    let cases: &[Case] = &[
        (&[], &[], &[], &[]),
        (
            &["x25519", "secp256r1"],
            &[],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (&["secp384r1"], &[], &[CNSA_PROTO_002], &[PQC_PROTO_002]),
        (&["ffdhe4096"], &[], &[CNSA_PROTO_002], &[PQC_PROTO_002]),
        (&["X25519"], &[], &[CNSA_PROTO_002], &[PQC_PROTO_002]),
        (&["MLKEM1024"], &[], &[], &[]),
        (&["MLKEM768"], &[], &[CNSA_PROTO_002], &[]),
        (&["MLKEM512"], &[], &[CNSA_PROTO_002], &[]),
        (&["SecP384r1MLKEM1024"], &[], &[], &[]),
        (&["X25519MLKEM768"], &[], &[CNSA_PROTO_002], &[]),
        (&["SecP256r1MLKEM768"], &[], &[CNSA_PROTO_002], &[]),
        (&["curveSM2MLKEM768"], &[], &[CNSA_PROTO_002], &[]),
        (
            &["MLKEM1024", "x25519"],
            &[],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (&[], &["mldsa87"], &[], &[]),
        (&[], &["mldsa65"], &[CNSA_PROTO_002], &[]),
        (&[], &["mldsa44"], &[CNSA_PROTO_002], &[]),
        (&[], &["slhdsa_sha2_128s"], &[CNSA_PROTO_002], &[]),
        (
            &[],
            &["ecdsa_secp384r1_sha384"],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (
            &[],
            &["rsa_pss_rsae_sha256"],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (&[], &["ed25519"], &[CNSA_PROTO_002], &[PQC_PROTO_002]),
        (
            &[],
            &["rsa_pkcs1_sha1"],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (
            &[],
            &["mldsa87", "ed25519"],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (
            &["x25519"],
            &["ecdsa_secp256r1_sha256"],
            &[CNSA_PROTO_002, CNSA_PROTO_002],
            &[PQC_PROTO_002, PQC_PROTO_002],
        ),
        (&["MLKEM1024", "SecP384r1MLKEM1024"], &["mldsa87"], &[], &[]),
        (&["514", "0x11ED"], &["0x0906", "2310"], &[], &[]),
        (
            &["29", "0x0017"],
            &["0x0403"],
            &[CNSA_PROTO_002, CNSA_PROTO_002],
            &[PQC_PROTO_002, PQC_PROTO_002],
        ),
        (
            &["X25519Kyber768Draft00"],
            &[],
            &[CNSA_UNKNOWN],
            &[PQC_UNKNOWN],
        ),
        (&["25498"], &[], &[CNSA_UNKNOWN], &[PQC_UNKNOWN]),
        (&["acme-group"], &[], &[CNSA_UNKNOWN], &[PQC_UNKNOWN]),
        // GREASE values are skipped, never judged nor unverifiable.
        (&["0x0A0A"], &["0x1A1A"], &[], &[]),
        (
            &["0x0A0A", "MLKEM1024", "64250"],
            &["2570", "mldsa87", "0xFAFA"],
            &[],
            &[],
        ),
        (
            &["0xCACA", "x25519"],
            &[],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        // An alias is judged as the entry it names; a Kyber spelling stays
        // unverifiable.
        (
            &["P-256", "nistp384"],
            &[],
            &[CNSA_PROTO_002],
            &[PQC_PROTO_002],
        ),
        (
            &["ML-KEM-1024", "SecP384r1_MLKEM1024"],
            &["ML-DSA-87", "SLH-DSA-SHAKE-256s"],
            &[CNSA_PROTO_002],
            &[],
        ),
        (
            &["X25519-MLKEM768"],
            &["ML-DSA-65"],
            &[CNSA_PROTO_002, CNSA_PROTO_002],
            &[],
        ),
        (&["x25519_kyber768"], &[], &[CNSA_UNKNOWN], &[PQC_UNKNOWN]),
        (&[], &["0x0402"], &[CNSA_UNKNOWN], &[PQC_UNKNOWN]),
        (
            &[],
            &["mldsa87_ecdsa_secp384r1_sha384"],
            &[CNSA_UNKNOWN],
            &[PQC_UNKNOWN],
        ),
        (
            &["MLKEM1024", "acme-group"],
            &["mldsa87"],
            &[CNSA_UNKNOWN],
            &[PQC_UNKNOWN],
        ),
        (
            &["x25519", "acme-group"],
            &[],
            &[CNSA_PROTO_002, CNSA_UNKNOWN],
            &[PQC_PROTO_002, PQC_UNKNOWN],
        ),
    ];
    for (groups, schemes, cnsa_rules, pqc_rules) in cases {
        let sbom = suite(groups, schemes);
        let label = format!("groups {groups:?}, schemes {schemes:?}");
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert_eq!(
            protocol_rules(&cnsa),
            *cnsa_rules,
            "{label} under CNSA 2.0: {:#?}",
            findings(&cnsa)
        );
        assert_eq!(
            cnsa.is_compliant,
            cnsa_rules.is_empty(),
            "{label} under CNSA 2.0"
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert_eq!(
            protocol_rules(&pqc),
            *pqc_rules,
            "{label} under NIST PQC: {:#?}",
            findings(&pqc)
        );
        let pqc_fails = pqc_rules
            .iter()
            .any(|(_, s)| *s == ViolationSeverity::Error);
        assert_eq!(pqc.is_compliant, !pqc_fails, "{label} under NIST PQC");
    }
}

/// The findings name the field and the offending algorithms; a scheme's
/// hash is not judged on its own.
#[test]
fn tls_findings_name_the_field_and_the_algorithms() {
    let classical = suite(
        &["x25519", "secp256r1"],
        &[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
        ],
    );
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&classical);
    assert_eq!(
        messages(&cnsa, "SBOM-CNSA2-PROTO-002"),
        [
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS groups with \
             non-CNSA 2.0 algorithms: X25519, ECDH-P-256",
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS signature \
             schemes with non-CNSA 2.0 algorithms: ECDSA-P-256, RSA",
        ]
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&classical);
    assert_eq!(
        messages(&pqc, "SBOM-PQC-PROTO-002"),
        [
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS groups with \
             broken or quantum-vulnerable algorithms: X25519 (quantum-vulnerable), ECDH-P-256 \
             (quantum-vulnerable)",
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS signature \
             schemes with broken or quantum-vulnerable algorithms: ECDSA-P-256 \
             (quantum-vulnerable), RSA (quantum-vulnerable)",
        ]
    );

    // A hybrid is named by its parts, and SLH-DSA by its parameter set
    // alone: its SHA-256 is no algorithm of its own.
    let cnsa =
        checker(ComplianceLevel::Cnsa2).check(&suite(&["X25519MLKEM768"], &["slhdsa_sha2_128s"]));
    assert_eq!(
        messages(&cnsa, "SBOM-CNSA2-PROTO-002"),
        [
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS groups with \
             non-CNSA 2.0 algorithms: X25519 + ML-KEM-768",
            "Protocol 'TLS 1.3' cipher suite 'TLS_AES_256_GCM_SHA384' offers TLS signature \
             schemes with non-CNSA 2.0 algorithms: SLH-DSA-SHA2-128s",
        ]
    );

    // An unverifiable entry is named as written, with the obsolete draft a
    // codepoint stands for; the GREASE values are not listed.
    let drafts = suite(
        &["X25519Kyber768Draft00", "25497", "0xFAFA", "acme-group"],
        &["0x0402", "6682"],
    );
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&drafts);
    assert_eq!(
        message(&cnsa, "SBOM-CNSA2-PROTO-UNKNOWN"),
        "Protocol 'TLS 1.3' has crypto references that cannot be resolved or classified: TLS \
         group 'X25519Kyber768Draft00' (an obsolete pre-standard draft), TLS group '25497' \
         (X25519Kyber768Draft00, an obsolete pre-standard draft), TLS group 'acme-group', TLS \
         signature scheme '0x0402'; they cannot be shown to be on the CNSA 2.0 allowlist"
    );
    let pqc = checker(ComplianceLevel::NistPqc).check(&drafts);
    assert!(
        message(&pqc, "SBOM-PQC-PROTO-UNKNOWN").contains("TLS group 'acme-group'"),
        "{:#?}",
        findings(&pqc)
    );
}

/// Offered groups and signature schemes are evidence on their own: a suite
/// with no name that offers only approved ones passes both profiles, and
/// one that offers classical ones fails them, instead of the protocol
/// being unverifiable.
#[test]
fn offered_entries_alone_judge_an_unnamed_suite() {
    let approved = tls13(None, &["MLKEM1024"], &["mldsa87"]);
    for level in [ComplianceLevel::Cnsa2, ComplianceLevel::NistPqc] {
        let result = checker(level).check(&approved);
        assert!(
            result.is_compliant && result.warning_count == 0,
            "{level:?}: {:#?}",
            findings(&result)
        );
    }
    let classical = tls13(None, &["x25519"], &[]);
    let cnsa = checker(ComplianceLevel::Cnsa2).check(&classical);
    assert_eq!(
        message(&cnsa, "SBOM-CNSA2-PROTO-002"),
        "Protocol 'TLS 1.3' cipher suite '(unnamed)' offers TLS groups with non-CNSA 2.0 \
         algorithms: X25519"
    );
    assert_eq!(protocol_rules(&cnsa), [CNSA_PROTO_002]);
    let pqc = checker(ComplianceLevel::NistPqc).check(&classical);
    assert_eq!(protocol_rules(&pqc), [PQC_PROTO_002]);
}
