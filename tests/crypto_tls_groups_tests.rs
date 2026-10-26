//! TLS 1.3 named groups and signature schemes (CycloneDX 1.7 `tlsGroups` and
//! `tlsSignatureSchemes`): every assigned entry of the IANA "TLS Supported
//! Groups" and "TLS SignatureScheme" registries is recognized by name and by
//! codepoint and classified as the algorithm it stands for.

use sbom_tools::model::{
    AlgorithmClass, PqcKind, TlsRegistryEntry, tls_named_group, tls_signature_scheme,
};

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
        "X25519-MLKEM768",
        "P-256",
        "prime256v1",
        "kyber768",
        "ML-DSA-87",
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
