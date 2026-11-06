//! The rules of the cryptography profiles: CNSA 2.0 and NIST PQC.

use super::*;

/// NIST PQC readiness remediation, shared by the SBOM-PQC-* rules.
///
/// NIST IR 8547 is cited as its final edition (October 2026, published
/// 2026-10-27); SP 800-131A is at Rev. 2 (Rev. 3 is draft-only).
const REMEDIATION_PQC: &str = "Migrate quantum-vulnerable algorithms per NIST IR 8547 (Transition to Post-Quantum Cryptography Standards): adopt ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) or SP 800-208 stateful hash-based signatures, and retire algorithms disallowed by SP 800-131A Rev. 2.";

/// CNSA 2.0 allowlist remediation, shared by the CNSA rules.
const REMEDIATION_CNSA2: &str = "Migrate to the CNSA 2.0 suite: AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87, or SP 800-208 stateful hash-based signatures (LMS/XMSS/HSS); use TLS 1.3 for network protocols. Unclassifiable algorithms cannot be verified — declare an algorithmFamily, OID, or recognizable name.";

/// NIST PQC protocol remediation.
const REMEDIATION_PQC_PROTO: &str = "Disable SSL and TLS versions below 1.2 (SP 800-52 Rev. 2) and remove broken (SP 800-131A) or quantum-vulnerable (IR 8547) algorithms from negotiated cipher suites and IKEv2 transforms.";

/// Remediation for a hash function at the 112-bit security level
/// (SBOM-PQC-HASH-001).
const REMEDIATION_PQC_HASH: &str = "NIST IR 8547 gives SHA-224, SHA-512/224 and SHA3-224 112 bits of collision strength (Table 8), a security level it disallows after 2030 (§4.1.3): replace them with a hash function of at least 128 bits, such as SHA-256, SHA-384, SHA-512 or SHA3-256. State the digest size of every SHA-2 asset, so that it can be judged. The rule reads the algorithm assets of a CBOM, not the hash values that identify components.";

/// NIST PQC certificate remediation.
const REMEDIATION_PQC_CERT: &str = "Re-issue the certificate with a NIST-approved post-quantum signature algorithm (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, or SP 800-208 LMS/XMSS/HSS).";

/// Remediation for the federal TLS 1.3 deadline (SBOM-PQC-PROTO-003).
const REMEDIATION_PQC_TLS13: &str = "Support TLS 1.3 or a successor version by January 2, 2030, as EO 14306 and OMB M-26-15 require of federal agencies: enable TLS 1.3, which carries the hybrid and post-quantum key exchanges, and record the version the protocol asset negotiates.";

/// Remediation for unverifiable crypto evidence under the PQC standard.
const REMEDIATION_PQC_UNKNOWN: &str = "Declare the asset's algorithm identity (algorithmFamily, OID, or a recognizable name), make bom-refs resolvable within the SBOM, and use parseable protocol versions so signature algorithms, cipher suites, and protocol references can be verified for PQC readiness.";

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
        // ---- CNSA 2.0 ----------------------------------------------------
        "SBOM-CNSA2-000" => RuleMeta {
            sarif_id: "SBOM-CNSA2-000",
            name: "Cnsa2CryptoInventory",
            short_description: "CNSA 2.0: cryptographic inventory (CBOM) with evaluable assets required — compliance cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-001",
            name: "Cnsa2SymmetricAlgorithm",
            short_description: "CNSA 2.0: symmetric encryption must be AES-256",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-002",
            name: "Cnsa2HashAlgorithm",
            short_description: "CNSA 2.0: hashing must be SHA-384 or SHA-512",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-003" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-003",
            name: "Cnsa2KeyEstablishment",
            short_description: "CNSA 2.0: key establishment must be ML-KEM-1024",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-004" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-004",
            name: "Cnsa2SignatureAlgorithm",
            short_description: "CNSA 2.0: digital signatures must be ML-DSA-87 or SP 800-208 stateful hash-based signatures",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-006" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-006",
            name: "Cnsa2QuantumVulnerable",
            short_description: "CNSA 2.0: quantum-vulnerable classical algorithm must migrate to the CNSA 2.0 suite",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-007" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-007",
            name: "Cnsa2QuantumSecurityLevel",
            short_description: "CNSA 2.0: declared quantum security level below Level 5",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Broken/legacy algorithm (SHA-1, MD5, DES, RC4, ...) under the CNSA
        // 2.0 allowlist.
        "SBOM-CNSA2-ALG-005" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-005",
            name: "Cnsa2BrokenAlgorithm",
            short_description: "CNSA 2.0: broken legacy algorithm (SHA-1, MD5, DES, RC4, …) in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Recognized algorithm that is simply not on the CNSA 2.0 allowlist
        // (ChaCha20, Camellia, SHA-3, SLH-DSA, Falcon, ...).
        "SBOM-CNSA2-ALG-008" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-008",
            name: "Cnsa2UnapprovedAlgorithm",
            short_description: "CNSA 2.0: recognized algorithm that is not on the CNSA 2.0 allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Unclassifiable algorithm asset — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-UNKNOWN",
            name: "Cnsa2UnclassifiableAlgorithm",
            short_description: "CNSA 2.0: algorithm cannot be classified, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-CERT-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-001",
            name: "Cnsa2CertificateSignature",
            short_description: "CNSA 2.0: certificate signature algorithm must be CNSA 2.0 approved",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // CNSA 2.0 compliance cannot be verified (Warning, never a silent
        // pass).
        "SBOM-CNSA2-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-UNKNOWN",
            name: "Cnsa2CertificateUnverifiable",
            short_description: "CNSA 2.0: certificate signature algorithm cannot be resolved, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol version gate: CNSA 2.0 network protocols require TLS 1.3.
        "SBOM-CNSA2-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-001",
            name: "Cnsa2ProtocolVersion",
            short_description: "CNSA 2.0: network protocols must use TLS 1.3",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs must use
        // CNSA 2.0 algorithms.
        "SBOM-CNSA2-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-002",
            name: "Cnsa2ProtocolAlgorithms",
            short_description: "CNSA 2.0: protocol cipher suites / IKEv2 transforms must use CNSA 2.0 algorithms",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // or with nothing evaluable at all — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-UNKNOWN",
            name: "Cnsa2ProtocolUnverifiable",
            short_description: "CNSA 2.0: protocol names no algorithm the classifier can identify, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Generic bucket for CNSA-2.0-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-CNSA2-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CNSA2-GENERAL",
            name: "Cnsa2GeneralRequirement",
            short_description: "CNSA 2.0: general algorithm-suite requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Cnsa2, CNSA2_CNSSP15)],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // ---- NIST PQC ----------------------------------------------------
        "SBOM-PQC-000" => RuleMeta {
            sarif_id: "SBOM-PQC-000",
            name: "PqcCryptoInventory",
            short_description: "NIST PQC: cryptographic inventory (CBOM) with evaluable assets required — readiness cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-001" => RuleMeta {
            sarif_id: "SBOM-PQC-001",
            name: "PqcQuantumVulnerable",
            short_description: "NIST IR 8547: quantum-vulnerable algorithm must migrate to a NIST PQC standard",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547"), (K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-012" => RuleMeta {
            sarif_id: "SBOM-PQC-012",
            name: "PqcQuantumAssessmentMissing",
            short_description: "NIST IR 8547: missing quantum security level assessment (nistQuantumSecurityLevel)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // A PQ/T hybrid (hybrid key exchange or composite signature) whose
        // post-quantum part NIST approves: an approved combination (SP
        // 800-227 §4.6.2 key combiners, IR 8547 §3.2.2 composite
        // signatures). A pass-only rule (`PASS_RULE_IDS`): its Info default
        // is the SARIF catalogue's `note`; the check site reports a pass.
        "SBOM-PQC-010" => RuleMeta {
            sarif_id: "SBOM-PQC-010",
            name: "PqcHybridCombiner",
            short_description: "NIST PQC: PQ/T hybrid with a NIST-approved post-quantum part — approved combination (SP 800-227, IR 8547)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "SP 800-227"), (K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-005" => RuleMeta {
            sarif_id: "SBOM-PQC-005",
            name: "PqcDisallowedAlgorithm",
            short_description: "NIST SP 800-131A: disallowed (broken) algorithm in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-008" => RuleMeta {
            sarif_id: "SBOM-PQC-008",
            name: "PqcEcbModeDisallowed",
            short_description: "NIST SP 800-131A: ECB mode of operation disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // An algorithm NIST approves for post-quantum use. A pass-only rule
        // (`PASS_RULE_IDS`), like SBOM-PQC-010.
        "SBOM-PQC-009" => RuleMeta {
            sarif_id: "SBOM-PQC-009",
            name: "PqcApprovedAlgorithm",
            short_description: "NIST PQC: NIST-approved post-quantum algorithm in use (FIPS 203/204/205, SP 800-208)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "FIPS 203/204/205"), (K::NistPqc, "SP 800-208")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-KEY-001" => RuleMeta {
            sarif_id: "SBOM-PQC-KEY-001",
            name: "PqcMinimumKeySize",
            short_description: "NIST SP 800-131A: key size below the approved minimum",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // A hash function asset at the 112-bit security level: IR 8547
        // Table 8 gives SHA-224, SHA-512/224 and SHA3-224 112 bits of
        // collision strength, and §4.1.3 disallows that level "in 2030".
        // An Error in readiness mode, as a 112-bit key is (SBOM-PQC-KEY-001);
        // `--pqc-mode deadline` makes it Info through 2030 and an Error
        // after. A SHA-2 asset that states no digest size could be SHA-224:
        // a Warning in either mode. Keyed uses (HMAC, HKDF, a MAC, KDF or
        // DRBG) are not judged. A signature over a 112-bit digest keeps its
        // scheme's rule, with the digest's earlier deadline.
        "SBOM-PQC-HASH-001" => RuleMeta {
            sarif_id: "SBOM-PQC-HASH-001",
            name: "PqcHashCollisionStrength",
            short_description: "NIST IR 8547: hash function at the 112-bit security level (SHA-224, SHA-512/224, SHA3-224), disallowed after 2030",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547 §4.1.3, Table 8")],
            remediation: REMEDIATION_PQC_HASH,
            advice: Some(&ADVICE_DIGEST_SIZE),
        },
        // Certificate signed with a broken or quantum-vulnerable algorithm.
        "SBOM-PQC-CERT-001" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-001",
            name: "PqcCertificateSignature",
            short_description: "NIST IR 8547: certificate signed with a broken or quantum-vulnerable algorithm",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC_CERT,
            advice: None,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // PQC readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-ALG-UNKNOWN",
            name: "PqcUnclassifiableAlgorithm",
            short_description: "NIST PQC: algorithm cannot be classified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        "SBOM-PQC-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-UNKNOWN",
            name: "PqcCertificateUnverifiable",
            short_description: "NIST PQC: certificate signature algorithm cannot be resolved — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        // Protocol version gate: SSL / TLS below 1.2 disallowed.
        "SBOM-PQC-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-001",
            name: "PqcProtocolVersion",
            short_description: "NIST SP 800-52 Rev. 2: SSL and TLS below 1.2 are disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-52 Rev. 2")],
            remediation: REMEDIATION_PQC_PROTO,
            advice: None,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs contain
        // broken or quantum-vulnerable algorithms.
        "SBOM-PQC-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-002",
            name: "PqcProtocolAlgorithms",
            short_description: "NIST PQC: protocol negotiates broken or quantum-vulnerable algorithms (SP 800-131A / IR 8547)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A / IR 8547")],
            remediation: REMEDIATION_PQC_PROTO,
            advice: None,
        },
        // TLS 1.2 against the federal TLS 1.3 deadline, reported only under
        // `--pqc-mode deadline --pqc-profile federal`: EO 14306 and OMB
        // M-26-15 have agencies support TLS 1.3 by 2030-01-02, so the
        // Warning becomes an Error after it. The reference is the NIST text
        // that relays the deadline (IR 8547 §4.2: "agencies are required to
        // support TLS version 1.3 no later than January 2, 2030"); the order
        // and the memo, which no standard kind describes, are named in the
        // description and in each finding's `deadline_source`.
        "SBOM-PQC-PROTO-003" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-003",
            name: "PqcFederalTls13",
            short_description: "Federal PQC deadline: TLS 1.3 must be supported by 2030-01-02 (EO 14306, OMB M-26-15)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 §4.2")],
            remediation: REMEDIATION_PQC_TLS13,
            advice: None,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // an unparseable TLS version, or nothing evaluable at all — PQC
        // readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-UNKNOWN",
            name: "PqcProtocolUnverifiable",
            short_description: "NIST PQC: protocol crypto references cannot be verified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        // Generic bucket for NIST-PQC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PQC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PQC-GENERAL",
            name: "PqcGeneralRequirement",
            short_description: "NIST PQC: general post-quantum readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        _ => return None,
    };
    Some(meta)
}
