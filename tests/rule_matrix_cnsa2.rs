//! Registry-driven per-rule matrix for `ComplianceLevel::Cnsa2` (NSA CNSA
//! 2.0 allowlist). The Error-level SBOM-CNSA2-ALG-007 (declared quantum
//! level below 5) was previously never asserted.
//!
//! Every rule id in `CNSA2_SARIF_RULE_IDS` gets a firing fixture and a
//! silent fixture (a CycloneDX 1.6 CBOM through the real parser), or an
//! explicit skip-with-reason; exhaustiveness is enforced against the
//! registry slice. Each row breaks one asset of the approved baseline, so a
//! crypto-vocabulary change that moves a verdict touches exactly the row
//! that pins it.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{CryptoAssetFixture, RuleEntry, SbomFixture, assert_no_violations, run_matrix};
use sbom_tools::quality::{CNSA2_SARIF_RULE_IDS, ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Cnsa2;

/// A CBOM of CNSA 2.0 allowlisted assets only: AES-256, SHA-384,
/// ML-KEM-1024 and ML-DSA-87 (both declaring quantum level 5), a
/// certificate signed with the ML-DSA-87 asset, and a TLS 1.3 protocol
/// whose cipher suite resolves to the AES-256 and SHA-384 assets.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        tools: vec![("acme-cbom-tool".to_string(), "1.0.0".to_string())],
        crypto_assets: vec![
            CryptoAssetFixture::algorithm("algo-aes256", "AES")
                .primitive("block-cipher")
                .parameter_set("256")
                .mode("gcm"),
            CryptoAssetFixture::algorithm("algo-sha384", "SHA-2")
                .primitive("hash")
                .parameter_set("384"),
            CryptoAssetFixture::algorithm("algo-mlkem1024", "ML-KEM")
                .primitive("kem")
                .parameter_set("1024")
                .quantum_level(5),
            CryptoAssetFixture::algorithm("algo-mldsa87", "ML-DSA")
                .primitive("signature")
                .parameter_set("87")
                .quantum_level(5),
            CryptoAssetFixture::certificate("leaf-cert", "algo-mldsa87"),
            CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"]),
        ],
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// Replace the baseline asset `bom_ref` with `asset` (keeping its position).
fn replace(s: &mut SbomFixture, bom_ref: &str, asset: CryptoAssetFixture) {
    *s.crypto_mut(bom_ref) = asset;
}

/// The all-approved CBOM must pass with a clean verdict.
#[test]
fn cnsa2_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

#[test]
fn cnsa2_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No asset the check can identify: an empty CBOM, one of key
        // material only (never evaluated), or one of unidentifiable
        // algorithms cannot claim CNSA 2.0.
        RuleEntry::tested(
            "SBOM-CNSA2-000",
            Sev::Error,
            broken(|s| s.crypto_assets.clear()),
            base(),
        )
        .with_firing(
            "key material only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets = vec![CryptoAssetFixture::material(
                    "session-key",
                    "symmetric-key",
                    Some(256),
                )];
            }),
        )
        .with_firing(
            "unidentifiable algorithms only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets = vec![CryptoAssetFixture::algorithm("algo-x", "acme-cipher")];
            }),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-001",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("algo-aes256").algorithm_mut().parameter_set = Some("128".to_string())
            }),
            base(),
        )
        .with_firing(
            "AES-128 identified by OID only",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-aes256",
                    CryptoAssetFixture::unidentified_algorithm("algo-aes256")
                        .primitive("block-cipher")
                        .oid("2.16.840.1.101.3.4.1.2"),
                );
            }),
        )
        .with_firing(
            "AES key size from classicalSecurityLevel only",
            Sev::Error,
            broken(|s| {
                // A neutral name: the classifier mines a component name for
                // a key size ("algo-aes256" would read as AES-256).
                replace(
                    s,
                    "algo-aes256",
                    CryptoAssetFixture::algorithm("algo-aes256", "AES")
                        .named("bulk-cipher")
                        .primitive("block-cipher")
                        .classical_level(128),
                );
            }),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-002",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("algo-sha384").algorithm_mut().parameter_set = Some("256".to_string())
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-003",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("algo-mlkem1024").algorithm_mut().parameter_set =
                    Some("768".to_string())
            }),
            base(),
        )
        .with_firing(
            "ML-KEM-768 identified by OID only",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-mlkem1024",
                    CryptoAssetFixture::unidentified_algorithm("algo-mlkem1024")
                        .primitive("kem")
                        .oid("2.16.840.1.101.3.4.4.2")
                        .quantum_level(5),
                );
            }),
        )
        // A PQ/T hybrid is judged by both parts: X25519MLKEM768 fails on
        // ML-KEM-768 and on X25519, which is not a CNSA 1.0 algorithm.
        .with_firing(
            "hybrid of X25519 and ML-KEM-768",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-hybrid", "X25519MLKEM768")
                        .primitive("combiner")
                        .quantum_level(3),
                );
            }),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-004",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("algo-mldsa87").algorithm_mut().parameter_set = Some("65".to_string())
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-005",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-sha384",
                    CryptoAssetFixture::algorithm("algo-sha384", "MD5").primitive("hash"),
                );
            }),
            base(),
        )
        .with_firing(
            "3DES block cipher",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-aes256",
                    CryptoAssetFixture::algorithm("algo-aes256", "3DES").primitive("block-cipher"),
                );
            }),
        ),
        // The family alone is authoritative for classical public-key
        // algorithms; a declared level 0 judges an unclassified asset.
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-006",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-mldsa87",
                    CryptoAssetFixture::algorithm("algo-mldsa87", "RSA")
                        .primitive("signature")
                        .parameter_set("3072"),
                );
            }),
            base(),
        )
        .with_firing(
            "declared quantum level 0 on an unclassified algorithm",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-mldsa87",
                    CryptoAssetFixture::algorithm("algo-mldsa87", "acme-legacy-pk")
                        .primitive("signature")
                        .quantum_level(0),
                );
            }),
        )
        .with_firing(
            "named elliptic curve only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-ec")
                        .primitive("signature")
                        .curve("P-256"),
                );
            }),
        )
        .with_firing(
            "identified by component name only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-legacy")
                        .named("RSA-2048")
                        .primitive("signature"),
                );
            }),
        ),
        // An allowlisted family declared below Level 5 (symmetric and hash
        // primitives are exempt: Grover, not Shor).
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-007",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("algo-mlkem1024").algorithm_mut().quantum_level = Some(3);
            }),
            broken(|s| {
                // Silent: a block cipher declared at level 1 is exempt.
                s.crypto_mut("algo-aes256").algorithm_mut().quantum_level = Some(1);
            }),
        ),
        // Recognized but not on the allowlist.
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-008",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-aes256",
                    CryptoAssetFixture::algorithm("algo-aes256", "ChaCha20").primitive("ae"),
                );
            }),
            base(),
        )
        .with_firing(
            "SHA3-384 hash",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-sha384",
                    CryptoAssetFixture::algorithm("algo-sha384", "SHA3-384").primitive("hash"),
                );
            }),
        )
        .with_firing(
            "SLH-DSA signature (FIPS 205, not CNSA 2.0)",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-mldsa87",
                    CryptoAssetFixture::algorithm("algo-mldsa87", "SLH-DSA")
                        .primitive("signature")
                        .quantum_level(5),
                );
            }),
        ),
        // CNSA 2.0 is an allowlist: an algorithm it cannot identify fails
        // closed, including a hybrid combiner of unidentifiable parts.
        RuleEntry::tested(
            "SBOM-CNSA2-ALG-UNKNOWN",
            Sev::Error,
            broken(|s| {
                s.crypto_assets
                    .push(CryptoAssetFixture::algorithm("algo-x", "acme-cipher"));
            }),
            base(),
        )
        .with_firing(
            "hybrid combiner of unidentifiable algorithms",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-hybrid", "acme-hybrid-kem")
                        .primitive("combiner")
                        .quantum_level(5),
                );
            }),
        ),
        // The signature algorithm ref is not a CNSA asset: an unresolvable
        // ref is token-classified ("ecdsa-p384" → ECDSA).
        RuleEntry::tested(
            "SBOM-CNSA2-CERT-001",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("ecdsa-p384".to_string());
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-CERT-UNKNOWN",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("sig-algo-42".to_string());
            }),
            base(),
        ),
        // TLS 1.3 only: an older TLS, SSL, or an unstated version fails.
        RuleEntry::tested(
            "SBOM-CNSA2-PROTO-001",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("tls13").protocol_mut().version = Some("1.2".to_string());
            }),
            base(),
        )
        .with_firing(
            "SSL",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "ssl", Some("3.0")),
                );
            }),
        )
        .with_firing(
            "TLS without a version",
            Sev::Error,
            broken(|s| s.crypto_mut("tls13").protocol_mut().version = None),
        ),
        RuleEntry::tested(
            "SBOM-CNSA2-PROTO-002",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_128_GCM_SHA256", &[]),
                );
            }),
            base(),
        )
        .with_firing(
            "cryptoRefArray reference to a non-allowlisted algorithm asset",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-aes128", "AES")
                        .primitive("block-cipher")
                        .parameter_set("128"),
                );
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .crypto_ref("algo-aes128"),
                );
            }),
        )
        // Each TLS group and signature scheme a suite offers is an
        // alternative a peer may negotiate (CycloneDX 1.7): one that is not
        // allowlisted fails beside approved ones.
        .with_firing(
            "TLS 1.3 suite offering x25519 beside MLKEM1024",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_groups(&["MLKEM1024", "x25519"]),
                );
            }),
        )
        .with_firing(
            "TLS 1.3 suite offering the hybrid group X25519MLKEM768",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_groups(&["X25519MLKEM768"]),
                );
            }),
        )
        .with_firing(
            "TLS 1.3 suite offering the mldsa65 signature scheme beside mldsa87",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_signature_schemes(&["mldsa87", "0x0905"]),
                );
            }),
        ),
        // Opaque references, or a protocol declaring nothing evaluable,
        // cannot be shown to be on the allowlist.
        RuleEntry::tested(
            "SBOM-CNSA2-PROTO-UNKNOWN",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("ACME_PROPRIETARY_SUITE", &["opaque-ref-1"]),
                );
            }),
            base(),
        )
        .with_firing(
            "SSH protocol declaring nothing evaluable",
            Sev::Error,
            broken(|s| {
                s.crypto_assets
                    .push(CryptoAssetFixture::protocol("ssh2", "ssh", Some("2.0")));
            }),
        )
        .with_firing(
            "TLS group the IANA registry obsoletes (pre-standard Kyber)",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_groups(&["X25519Kyber768Draft00"]),
                );
            }),
        ),
        RuleEntry::skipped(
            "SBOM-CNSA2-GENERAL",
            "registry catch-all for the CNSA 2.0 family: no check site in \
             check_cnsa2 emits it (it is the SARIF re-bucketing target only); \
             it cannot fire from document content",
        ),
    ];

    run_matrix(LEVEL, CNSA2_SARIF_RULE_IDS, &entries);
}
