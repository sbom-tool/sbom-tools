//! Registry-driven per-rule matrix for `ComplianceLevel::NistPqc` (NIST PQC
//! readiness: IR 8547, FIPS 203/204/205, SP 800-131A, SP 800-52). The
//! Error-level SBOM-PQC-008 (ECB mode) and SBOM-PQC-KEY-001 (symmetric key
//! below 128 bits) were previously never asserted.
//!
//! Every rule id in `PQC_SARIF_RULE_IDS` gets a firing fixture and a silent
//! fixture (a CycloneDX 1.6 CBOM, in JSON and in XML, through the real
//! parser; SPDX has no cryptographic-asset model), or an explicit
//! skip-with-reason; exhaustiveness is enforced against the registry slice.
//! Each row breaks one asset of the ready baseline, so a crypto-vocabulary
//! change that moves a verdict touches exactly the row that pins it. The
//! two pass-only rules, SBOM-PQC-009 and SBOM-PQC-010, get passing fixtures
//! instead: each adds an approved asset, which the result reports as a
//! passed check.
//!
//! Rows whose findings `--pqc-mode deadline` dates add cases in that mode
//! ([`DeadlineFixture`]): NIST IR 8547 makes a quantum-vulnerable scheme an
//! Info before its 2030 deprecation, a Warning until its 2035 disallowance
//! and an Error after; the federal profile has its own deadlines and its
//! own rule, SBOM-PQC-PROTO-003 (TLS 1.3 by 2030-01-02).

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CBOM_IS_CYCLONEDX, CryptoAssetFixture, DeadlineFixture, Encoding, RuleEntry, SbomFixture,
    assert_no_violations_in, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, PQC_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::NistPqc;

/// Deadline-mode instants: the shared test clock (before IR 8547's 2030
/// deprecation), a date in its deprecation window, one after its 2035
/// disallowance, and one past the federal TLS 1.3 deadline.
const BEFORE_2031: &str = rule_matrix::clock::AS_OF;
const IN_2031: &str = "2031-06-01T00:00:00Z";
const AFTER_2035: &str = "2036-06-01T00:00:00Z";
const AFTER_TLS13_DEADLINE: &str = "2030-06-01T00:00:00Z";
/// The last instant IR 8547 §4.1.3 allows the 112-bit security level, and
/// the first one it disallows it.
const END_OF_2030: &str = "2030-12-31T23:59:59Z";
const START_OF_2031: &str = "2031-01-01T00:00:00Z";

/// An RSA-3072 signature asset declaring quantum level 0.
fn rsa_signature() -> CryptoAssetFixture {
    CryptoAssetFixture::algorithm("algo-rsa", "RSA")
        .primitive("signature")
        .parameter_set("3072")
        .quantum_level(0)
}

/// A hash asset of the CycloneDX 1.7 `family` and the digest size
/// `parameter_set`, declaring quantum level 1.
fn hash(bom_ref: &str, family: &str, parameter_set: &str) -> CryptoAssetFixture {
    CryptoAssetFixture::algorithm(bom_ref, family)
        .primitive("hash")
        .parameter_set(parameter_set)
        .quantum_level(1)
}

/// SHA-224 by its CycloneDX 1.7 family and digest size.
fn sha224() -> CryptoAssetFixture {
    hash("algo-sha224", "SHA-2", "224")
}

/// An RSA-3072 signature over a SHA-224 digest, by its JCA name.
fn rsa_sha224_signature() -> CryptoAssetFixture {
    rsa_signature().named("SHA224withRSA")
}

/// A SHA-2 hash asset that states no digest size.
fn sha2_unsized() -> CryptoAssetFixture {
    CryptoAssetFixture::algorithm("algo-sha2", "SHA-2")
        .primitive("hash")
        .quantum_level(1)
}

/// The ready baseline plus `asset`, judged in deadline mode by `deadline`.
fn dated(asset: CryptoAssetFixture, deadline: DeadlineFixture) -> SbomFixture {
    broken(|s| {
        s.crypto_assets.push(asset);
        s.deadline = Some(deadline);
    })
}

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

/// The PQC-ready CBOM must pass with a clean verdict, in JSON and XML.
#[test]
fn pqc_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::CYCLONEDX);
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
        )
        // An SPDX document lists no cryptographic asset at all: it is an
        // empty CBOM, so only the empty-CBOM case runs in every encoding.
        .case_only(
            "unidentifiable algorithms only",
            Encoding::CYCLONEDX,
            CBOM_IS_CYCLONEDX,
        )
        .case_only("silent", Encoding::CYCLONEDX, CBOM_IS_CYCLONEDX),
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
        )
        // Deadline mode: IR 8547 Table 2 deprecates RSA signatures after
        // 2030 and disallows them after 2035.
        .with_departing_firing(
            "deadline mode before 2031: deprecated after 2030",
            Sev::Info,
            dated(rsa_signature(), DeadlineFixture::nist(BEFORE_2031)),
        )
        .with_departing_firing(
            "deadline mode in 2031: deprecated, disallowed after 2035",
            Sev::Warning,
            dated(rsa_signature(), DeadlineFixture::nist(IN_2031)),
        )
        .with_firing(
            "deadline mode after 2035: disallowed",
            Sev::Error,
            dated(rsa_signature(), DeadlineFixture::nist(AFTER_2035)),
        )
        // The federal profile: post-quantum key establishment by 2030-12-31.
        .with_departing_firing(
            "federal deadline mode before 2031: key establishment due by 2030-12-31",
            Sev::Warning,
            dated(
                CryptoAssetFixture::algorithm("algo-ecdh", "ECDH")
                    .primitive("key-agree")
                    .curve("secp256r1")
                    .quantum_level(0),
                DeadlineFixture::federal(BEFORE_2031),
            ),
        )
        .with_firing(
            "federal deadline mode in 2031: key establishment overdue",
            Sev::Error,
            dated(
                CryptoAssetFixture::algorithm("algo-ecdh", "ECDH")
                    .primitive("key-agree")
                    .curve("secp256r1")
                    .quantum_level(0),
                DeadlineFixture::federal(IN_2031),
            ),
        )
        // No transition dates what is disallowed already or not listed.
        .with_firing(
            "deadline mode keeps RSA-1024, below 112 bits, an error",
            Sev::Error,
            dated(
                CryptoAssetFixture::algorithm("algo-rsa", "RSA")
                    .primitive("signature")
                    .parameter_set("1024")
                    .quantum_level(0),
                DeadlineFixture::nist(BEFORE_2031),
            ),
        )
        .with_firing(
            "deadline mode keeps DSA, which FIPS 186-5 dropped, an error",
            Sev::Error,
            dated(
                CryptoAssetFixture::algorithm("algo-dsa", "DSA")
                    .primitive("signature")
                    .parameter_set("2048")
                    .quantum_level(0),
                DeadlineFixture::nist(BEFORE_2031),
            ),
        )
        // A signature over a 112-bit digest takes the digest's earlier
        // deadline (IR 8547 §4.1.3, Table 8): an Error from 2031, not a
        // Warning until 2035. Key establishment does not rest on the
        // collision resistance of the hash it names.
        .with_departing_firing(
            "deadline mode on 2030-12-31: a signature over SHA-224",
            Sev::Info,
            dated(rsa_sha224_signature(), DeadlineFixture::nist(END_OF_2030)),
        )
        .with_firing(
            "deadline mode on 2031-01-01: a signature over SHA-224, disallowed with its digest",
            Sev::Error,
            dated(rsa_sha224_signature(), DeadlineFixture::nist(START_OF_2031)),
        )
        .with_firing(
            "deadline mode on 2031-01-01: ecdsa-with-SHA224 identified by OID only",
            Sev::Error,
            dated(
                CryptoAssetFixture::unidentified_algorithm("algo-ecdsa-sha224")
                    .primitive("signature")
                    .oid("1.2.840.10045.4.3.1")
                    .quantum_level(0),
                DeadlineFixture::nist(START_OF_2031),
            ),
        )
        .with_departing_firing(
            "federal deadline mode on 2030-12-31: a signature over SHA-224",
            Sev::Warning,
            dated(
                rsa_sha224_signature(),
                DeadlineFixture::federal(END_OF_2030),
            ),
        )
        .with_firing(
            "federal deadline mode on 2031-01-01: a signature over SHA-224, before 2031-12-31",
            Sev::Error,
            dated(
                rsa_sha224_signature(),
                DeadlineFixture::federal(START_OF_2031),
            ),
        )
        .with_departing_firing(
            "deadline mode on 2031-01-01: key agreement with a SHA-224 KDF keeps Table 4",
            Sev::Warning,
            dated(
                CryptoAssetFixture::algorithm("algo-ecdh", "ECDH")
                    .named("ECDH-P256-SHA224-KDF")
                    .primitive("key-agree")
                    .curve("secp256r1")
                    .quantum_level(0),
                DeadlineFixture::nist(START_OF_2031),
            ),
        )
        // A 112-bit hash's declared level 0 is its collision strength,
        // which SBOM-PQC-HASH-001 judges.
        .with_silent(
            "SHA-224 declaring quantum level 0",
            broken(|s| s.crypto_assets.push(sha224().quantum_level(0))),
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
        )
        // Deadline mode: IR 8547 Table 8 deprecates SHA-1 now and disallows
        // it after 2030; MD5 has no transition.
        .with_departing_firing(
            "deadline mode before 2031: SHA-1 deprecated",
            Sev::Warning,
            dated(
                CryptoAssetFixture::algorithm("algo-sha1", "SHA-1")
                    .primitive("hash")
                    .quantum_level(1),
                DeadlineFixture::nist(BEFORE_2031),
            ),
        )
        .with_firing(
            "deadline mode in 2031: SHA-1 disallowed",
            Sev::Error,
            dated(
                CryptoAssetFixture::algorithm("algo-sha1", "SHA-1")
                    .primitive("hash")
                    .quantum_level(1),
                DeadlineFixture::nist(IN_2031),
            ),
        )
        .with_firing(
            "deadline mode keeps MD5 an error",
            Sev::Error,
            dated(
                CryptoAssetFixture::algorithm("algo-md5", "MD5")
                    .primitive("hash")
                    .quantum_level(1),
                DeadlineFixture::nist(BEFORE_2031),
            ),
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
        )
        // Deadline mode: IR 8547 §4.1.3 disallows the 112-bit security
        // level after 2030.
        .with_departing_firing(
            "deadline mode before 2031: a 112-bit key",
            Sev::Info,
            broken(|s| {
                replace(
                    s,
                    "session-key",
                    CryptoAssetFixture::material("session-key", "symmetric-key", Some(112)),
                );
                s.deadline = Some(DeadlineFixture::nist(BEFORE_2031));
            }),
        )
        .with_firing(
            "deadline mode in 2031: a 112-bit key",
            Sev::Error,
            broken(|s| {
                replace(
                    s,
                    "session-key",
                    CryptoAssetFixture::material("session-key", "symmetric-key", Some(112)),
                );
                s.deadline = Some(DeadlineFixture::nist(IN_2031));
            }),
        ),
        // NIST IR 8547 Table 8 gives SHA-224, SHA-512/224 and SHA3-224 112
        // bits of collision strength, however the CBOM names them, and
        // §4.1.3 disallows that level after 2030. A keyed use does not rest
        // on collision resistance, and a 256-bit digest has 128 bits.
        RuleEntry::tested(
            "SBOM-PQC-HASH-001",
            Sev::Error,
            broken(|s| s.crypto_assets.push(sha224())),
            base(),
        )
        .with_firing(
            "SHA3-224",
            Sev::Error,
            broken(|s| s.crypto_assets.push(hash("algo-sha3-224", "SHA-3", "224"))),
        )
        .with_firing(
            "SHA-2 with the SHA-512/224 parameter set",
            Sev::Error,
            broken(|s| {
                s.crypto_assets
                    .push(hash("algo-sha512-224", "SHA-2", "512/224"))
            }),
        )
        .with_firing(
            "SHA-512/224 identified by OID only",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-sha512-224")
                        .primitive("hash")
                        .oid("2.16.840.1.101.3.4.2.5")
                        .quantum_level(1),
                );
            }),
        )
        .with_firing(
            "named SHA224, without a family",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-sha224")
                        .named("SHA224")
                        .primitive("hash")
                        .quantum_level(1),
                );
            }),
        )
        .with_firing(
            "named sha3_224, the SPDX 3 algorithm name",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::unidentified_algorithm("algo-sha3-224")
                        .named("sha3_224")
                        .primitive("hash")
                        .quantum_level(1),
                );
            }),
        )
        .with_firing(
            "declared quantum level 0",
            Sev::Error,
            broken(|s| s.crypto_assets.push(sha224().quantum_level(0))),
        )
        // Deadline mode: Info through 2030-12-31, Error from 2031-01-01.
        .with_departing_firing(
            "deadline mode in 2026: disallowed after 2030",
            Sev::Info,
            dated(sha224(), DeadlineFixture::nist(BEFORE_2031)),
        )
        .with_departing_firing(
            "deadline mode on 2030-12-31: disallowed after 2030",
            Sev::Info,
            dated(sha224(), DeadlineFixture::nist(END_OF_2030)),
        )
        .with_firing(
            "deadline mode on 2031-01-01: disallowed",
            Sev::Error,
            dated(sha224(), DeadlineFixture::nist(START_OF_2031)),
        )
        // A SHA-2 hash that states no digest size could be SHA-224: a
        // Warning in either mode, at any date.
        .with_departing_firing(
            "SHA-2 that states no digest size",
            Sev::Warning,
            broken(|s| s.crypto_assets.push(sha2_unsized())),
        )
        .with_departing_firing(
            "deadline mode in 2026: SHA-2 that states no digest size",
            Sev::Warning,
            dated(sha2_unsized(), DeadlineFixture::nist(BEFORE_2031)),
        )
        .with_departing_firing(
            "deadline mode on 2031-01-01: SHA-2 that states no digest size",
            Sev::Warning,
            dated(sha2_unsized(), DeadlineFixture::nist(START_OF_2031)),
        )
        .with_silent(
            "SHA-256",
            broken(|s| s.crypto_assets.push(hash("algo-sha256", "SHA-2", "256"))),
        )
        .with_silent(
            "SHA-2 of no stated size declared a MAC",
            broken(|s| s.crypto_assets.push(sha2_unsized().primitive("mac"))),
        )
        .with_silent(
            "SHAKE128, a SHA-3 function of no stated size",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-shake128", "SHA-3")
                        .named("SHAKE128")
                        .primitive("xof")
                        .quantum_level(2),
                );
            }),
        )
        .with_silent(
            "SHA-512/256",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-sha512-256", "SHA-512/256")
                        .primitive("hash")
                        .quantum_level(2),
                );
            }),
        )
        .with_silent(
            "HMAC-SHA-224, a keyed construction",
            broken(|s| {
                s.crypto_assets.push(
                    CryptoAssetFixture::algorithm("algo-hmac", "HMAC")
                        .named("HMAC-SHA224")
                        .primitive("mac")
                        .quantum_level(1),
                );
            }),
        )
        .with_silent(
            "SHA-224 declared a MAC",
            broken(|s| s.crypto_assets.push(sha224().primitive("mac"))),
        ),
        // Unresolved signature refs are token-classified ("ecdsa-p384").
        RuleEntry::tested(
            "SBOM-PQC-CERT-001",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("ecdsa-p384".to_string());
            }),
            base(),
        )
        // Deadline mode judges a certificate on the later of the evaluation
        // date and its notValidAfter: one valid into 2033 signs while ECDSA
        // is deprecated.
        .with_departing_firing(
            "deadline mode before 2031: an ECDSA signature",
            Sev::Info,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref = Some("ecdsa-p384".to_string());
                s.deadline = Some(DeadlineFixture::nist(BEFORE_2031));
            }),
        )
        .with_departing_firing(
            "deadline mode: valid until 2033, judged on that date",
            Sev::Warning,
            broken(|s| {
                *s.crypto_mut("leaf-cert") =
                    CryptoAssetFixture::certificate("leaf-cert", "ecdsa-p384")
                        .valid_until("2033-06-30T00:00:00Z");
                s.deadline = Some(DeadlineFixture::nist(BEFORE_2031));
            }),
        )
        .with_firing(
            "federal deadline mode: valid until 2032, after the 2031 signature deadline",
            Sev::Error,
            broken(|s| {
                *s.crypto_mut("leaf-cert") =
                    CryptoAssetFixture::certificate("leaf-cert", "ecdsa-p384")
                        .valid_until("2032-06-30T00:00:00Z");
                s.deadline = Some(DeadlineFixture::federal(BEFORE_2031));
            }),
        )
        // Signed over a SHA-224 digest: the digest's earlier deadline.
        .with_departing_firing(
            "deadline mode on 2030-12-31: signed with sha224WithRSAEncryption",
            Sev::Info,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref =
                    Some("sha224WithRSAEncryption".to_string());
                s.deadline = Some(DeadlineFixture::nist(END_OF_2030));
            }),
        )
        .with_firing(
            "deadline mode on 2031-01-01: signed with sha224WithRSAEncryption",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("leaf-cert").signature_algorithm_ref =
                    Some("sha224WithRSAEncryption".to_string());
                s.deadline = Some(DeadlineFixture::nist(START_OF_2031));
            }),
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
        )
        // Deadline mode: the suite's ECDHE and RSA are on IR 8547's
        // calendar; its SHA-1 record MAC is deprecated now (Table 8).
        .with_departing_firing(
            "deadline mode before 2031: an ECDHE-RSA suite",
            Sev::Info,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.2"))
                        .cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", &[]),
                );
                s.deadline = Some(DeadlineFixture::nist(BEFORE_2031));
            }),
        )
        .with_departing_firing(
            "deadline mode before 2031: an ECDHE-RSA suite with a SHA-1 MAC",
            Sev::Warning,
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.2"))
                        .cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", &[]),
                );
                s.deadline = Some(DeadlineFixture::nist(BEFORE_2031));
            }),
        )
        // A reference to a signature over SHA-224 takes its digest's
        // deadline, as the asset does.
        .with_firing(
            "deadline mode on 2031-01-01: a reference to a signature over SHA-224",
            Sev::Error,
            broken(|s| {
                s.crypto_assets.push(rsa_sha224_signature());
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "tls", Some("1.3"))
                        .crypto_ref("algo-rsa"),
                );
                s.deadline = Some(DeadlineFixture::nist(START_OF_2031));
            }),
        ),
        // TLS 1.2 against the federal TLS 1.3 deadline (EO 14306, OMB
        // M-26-15), under the federal profile only.
        RuleEntry::tested(
            "SBOM-PQC-PROTO-003",
            Sev::Warning,
            broken(|s| {
                s.crypto_mut("tls13").protocol_mut().version = Some("1.2".to_string());
                s.deadline = Some(DeadlineFixture::federal(BEFORE_2031));
            }),
            broken(|s| s.deadline = Some(DeadlineFixture::federal(BEFORE_2031))),
        )
        .with_departing_firing(
            "after 2030-01-02",
            Sev::Error,
            broken(|s| {
                s.crypto_mut("tls13").protocol_mut().version = Some("TLSv1.2".to_string());
                s.deadline = Some(DeadlineFixture::federal(AFTER_TLS13_DEADLINE));
            }),
        )
        .with_silent(
            "TLS 1.2 in readiness mode",
            broken(|s| s.crypto_mut("tls13").protocol_mut().version = Some("1.2".to_string())),
        )
        .with_silent(
            "TLS 1.2 under the NIST profile",
            broken(|s| {
                s.crypto_mut("tls13").protocol_mut().version = Some("1.2".to_string());
                s.deadline = Some(DeadlineFixture::nist(AFTER_TLS13_DEADLINE));
            }),
        )
        .with_silent(
            "DTLS 1.2, which the deadline does not name",
            broken(|s| {
                replace(
                    s,
                    "tls13",
                    CryptoAssetFixture::protocol("tls13", "dtls", Some("1.2"))
                        .cipher_suite("TLS_AES_256_GCM_SHA384", &["algo-aes256", "algo-sha384"]),
                );
                s.deadline = Some(DeadlineFixture::federal(AFTER_TLS13_DEADLINE));
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

    // A CBOM is CycloneDX only: every row runs in CycloneDX JSON and XML,
    // but for the empty-CBOM case of SBOM-PQC-000 (its own row says so).
    let entries: Vec<RuleEntry> = entries
        .into_iter()
        .map(|entry| match entry.id {
            "SBOM-PQC-000" => entry,
            _ => entry.only(Encoding::CYCLONEDX, CBOM_IS_CYCLONEDX),
        })
        .collect();
    run_matrix(LEVEL, PQC_SARIF_RULE_IDS, &entries);
}
