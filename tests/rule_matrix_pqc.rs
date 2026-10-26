//! Registry-driven per-rule matrix for `ComplianceLevel::NistPqc` (NIST PQC
//! readiness: IR 8547, FIPS 203/204/205, SP 800-131A, SP 800-52). The
//! Error-level SBOM-PQC-008 (ECB mode) and SBOM-PQC-KEY-001 (symmetric key
//! below 128 bits) were previously never asserted.
//!
//! Every rule id in `PQC_SARIF_RULE_IDS` gets a firing fixture and a silent
//! fixture (a CycloneDX 1.6 CBOM through the real parser), or an explicit
//! skip-with-reason; exhaustiveness is enforced against the registry slice.
//! Each row breaks one asset of the ready baseline, so a crypto-vocabulary
//! change that moves a verdict touches exactly the row that pins it. The
//! two pass-only rules, SBOM-PQC-009 and SBOM-PQC-010, get passing fixtures
//! instead: each adds an approved asset, which the result reports as a
//! passed check.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{CryptoAssetFixture, RuleEntry, SbomFixture, assert_no_violations, run_matrix};
use sbom_tools::quality::{ComplianceLevel, PQC_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::NistPqc;

/// A PQC-ready CBOM that triggers no finding at all: AES-256-GCM and SHA-384
/// with declared quantum levels, a 256-bit symmetric key, a certificate
/// whose (unresolved) signature reference names ML-DSA-87, and a TLS 1.3
/// protocol whose cipher suite resolves to the AES and SHA assets. No
/// approved-PQC *algorithm asset* is listed, so the baseline passes no
/// check either: SBOM-PQC-009 and -010 report one pass per approved asset,
/// and their rows add one.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        tools: vec![("acme-cbom-tool".to_string(), "1.0.0".to_string())],
        crypto_assets: vec![
            CryptoAssetFixture::algorithm("algo-aes256", "AES")
                .primitive("block-cipher")
                .parameter_set("256")
                .mode("gcm")
                .quantum_level(1),
            CryptoAssetFixture::algorithm("algo-sha384", "SHA-2")
                .primitive("hash")
                .parameter_set("384")
                .quantum_level(2),
            CryptoAssetFixture::material("session-key", "symmetric-key", Some(256)),
            CryptoAssetFixture::certificate("leaf-cert", "ml-dsa-87"),
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

/// The PQC-ready CBOM must pass with a clean verdict.
#[test]
fn pqc_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

#[test]
fn pqc_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No asset the check can identify: nothing to assert readiness of.
        RuleEntry::tested(
            "SBOM-PQC-000",
            Sev::Error,
            broken(|s| s.crypto_assets.clear()),
            base(),
        )
        .with_firing(
            "unidentifiable algorithms only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets =
                    vec![CryptoAssetFixture::algorithm("algo-x", "acme-cipher").quantum_level(3)];
            }),
        ),
        // Classical public-key families are quantum-vulnerable regardless
        // of key size; a declared level 0 judges an unclassified asset.
        RuleEntry::tested(
            "SBOM-PQC-001",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-rsa", "RSA")
                        .primitive("signature")
                        .parameter_set("3072")
                        .quantum_level(0),
                );
            }),
            base(),
        )
        .with_firing(
            "declared quantum level 0 on an unclassified algorithm",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-legacy", "acme-legacy-pk")
                        .primitive("signature")
                        .quantum_level(0),
                );
            }),
        )
        .with_firing(
            "RSA identified by OID only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-rsa")
                        .primitive("pke")
                        .oid("1.2.840.113549.1.1.1")
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
                        .primitive("key-agree")
                        .curve("secp256r1")
                        .quantum_level(0),
                );
            }),
        ),
        RuleEntry::tested(
            "SBOM-PQC-012",
            Sev::Warning,
            broken(|s| s.crypto_mut("algo-aes256").algorithm_mut().quantum_level = None),
            base(),
        ),
        // Unclassifiable with a declared (non-zero) level: cannot verify. So
        // is a hybrid combiner whose parts cannot be identified.
        RuleEntry::tested(
            "SBOM-PQC-ALG-UNKNOWN",
            Sev::Warning,
            broken(|s| {
                s.crypto_assets
                    .push(CryptoAssetFixture::algorithm("algo-x", "acme-cipher").quantum_level(3));
            }),
            base(),
        )
        .with_firing(
            "hybrid combiner of unidentifiable algorithms",
            Sev::Warning,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-hybrid", "acme-hybrid-kem")
                        .primitive("combiner")
                        .quantum_level(3),
                );
            }),
        ),
        // A PQ/T hybrid whose post-quantum part NIST approves is an approved
        // combination, a passed check: SP 800-227 §4.6.2 for key
        // establishment.
        RuleEntry::passing(
            "SBOM-PQC-010",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-hybrid", "X25519MLKEM768")
                        .primitive("combiner")
                        .quantum_level(3),
                );
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-PQC-005",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "algo-sha384",
                    CryptoAssetFixture::algorithm("algo-sha384", "MD5")
                        .primitive("hash")
                        .quantum_level(1),
                );
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-PQC-008",
            Sev::Error,
            broken(|s| s.crypto_mut("algo-aes256").algorithm_mut().mode = Some("ecb".to_string())),
            base(),
        ),
        // An approved PQC algorithm asset is a passed check.
        RuleEntry::passing(
            "SBOM-PQC-009",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-mlkem768", "ML-KEM")
                        .primitive("kem")
                        .parameter_set("768")
                        .quantum_level(3),
                );
            }),
            base(),
        )
        .with_passing(
            "ML-DSA-87 identified by OID only",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-mldsa")
                        .primitive("signature")
                        .oid("2.16.840.1.101.3.4.3.19")
                        .quantum_level(5),
                );
            }),
        ),
        RuleEntry::tested(
            "SBOM-PQC-KEY-001",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "session-key",
                    CryptoAssetFixture::material("session-key", "symmetric-key", Some(64)),
                );
            }),
            base(),
        ),
        // Unresolved signature refs are token-classified ("ecdsa-p384").
        RuleEntry::tested(
            "SBOM-PQC-CERT-001",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("ecdsa-p384".to_string());
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-PQC-CERT-UNKNOWN",
            Sev::Warning,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("sig-algo-42".to_string());
            }),
            base(),
        ),
        // SSL, or TLS below 1.2 (SP 800-52 Rev. 2); TLS 1.2 is allowed.
        RuleEntry::tested(
            "SBOM-PQC-PROTO-001",
            Sev::Error,
            broken(|s| s.crypto_mut("tls13").protocol_mut().version = Some("1.1".to_string())),
            broken(|s| s.crypto_mut("tls13").protocol_mut().version = Some("1.2".to_string())),
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
        ),
        RuleEntry::tested(
            "SBOM-PQC-PROTO-002",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.2"))
                        .cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", &[]),
                );
            }),
            base(),
        )
        .with_firing(
            "cryptoRefArray reference to a quantum-vulnerable algorithm asset",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-ecdh", "ECDH")
                        .primitive("key-agree")
                        .quantum_level(0),
                );
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .crypto_ref("algo-ecdh"),
                );
            }),
        )
        // Each TLS group and signature scheme a suite offers is an
        // alternative a peer may negotiate (CycloneDX 1.7): a classical one
        // fails beside post-quantum ones.
        .with_firing(
            "TLS 1.3 suite offering secp384r1 beside X25519MLKEM768",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_groups(&["X25519MLKEM768", "secp384r1"]),
                );
            }),
        )
        .with_firing(
            "TLS 1.3 suite offering rsa_pss_rsae_sha256 beside mldsa44",
            Sev::Error,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_signature_schemes(&["mldsa44", "rsa_pss_rsae_sha256"]),
                );
            }),
        ),
        // Opaque references, an unparseable version, or a protocol that
        // declares nothing evaluable cannot be verified.
        RuleEntry::tested(
            "SBOM-PQC-PROTO-UNKNOWN",
            Sev::Warning,
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
            "unparseable TLS version",
            Sev::Warning,
            broken(|s| {
                s.crypto_mut("tls13").protocol_mut().version = Some("draft-acme".to_string());
            }),
        )
        .with_firing(
            "SSH protocol declaring nothing evaluable",
            Sev::Warning,
            broken(|s| {
                s.crypto_assets
                    .push(CryptoAssetFixture::protocol("ssh2", "ssh", Some("2.0")));
            }),
        )
        .with_firing(
            "TLS group codepoint the IANA registry does not assign",
            Sev::Warning,
            broken(|s| {
                s.spec_version = "1.7".to_string();
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"])
                        .tls_groups(&["MLKEM1024", "0x1234"]),
                );
            }),
        ),
    ];

    run_matrix(LEVEL, PQC_SARIF_RULE_IDS, &entries);
}
