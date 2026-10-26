//! Cryptographic-suite compliance: NSA CNSA 2.0 and NIST PQC readiness.
//!
//! Both checkers classify algorithms through the shared, input-robust
//! [`crate::model::classify_algorithm`] (family + OID + parameter +
//! elliptic-curve + guarded name fallback), so CycloneDX 1.6 CBOMs — which
//! have no `algorithmFamily` field — are evaluated instead of silently
//! passing. CNSA 2.0 is enforced as the exclusive **allowlist** it is
//! (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87, SP 800-208 LMS/XMSS/HSS);
//! anything recognized-but-not-approved is an Error and anything
//! unrecognizable is a Warning, never an implicit pass. Protocol assets
//! (TLS version, cipher suites, IKEv2 transforms, crypto references) are
//! evaluated under both standards by resolving bom-refs through the SBOM
//! index and word-boundary-scanning cipher-suite names.

use super::*;
use crate::model::{
    AlgorithmClass, AlgorithmClassification, CertificateProperties, Component, CryptoAssetType,
    Ikev2Transform, NormalizedSbomIndex, PqcKind, ProtocolProperties, ProtocolType,
    classify_algorithm, classify_algorithm_names, classify_algorithm_names_guarded,
    ikev2_key_exchange_group, worst_classification,
};

/// Outcome of checking one classified algorithm against the CNSA 2.0
/// allowlist.
enum CnsaVerdict {
    /// On the CNSA 2.0 allowlist.
    Approved,
    /// Recognized and definitively not CNSA 2.0; `detail` completes the
    /// sentence "'<component>' <detail>".
    NotApproved {
        rule_id: &'static str,
        detail: String,
    },
    /// Not recognizable — cannot verify (Warning, never a silent pass).
    Unknown,
}

/// Classify the algorithm identity of a crypto-asset component.
fn classify_crypto_component(comp: &Component) -> AlgorithmClassification {
    let cp = comp.crypto_properties.as_ref();
    let algo = cp.and_then(|c| c.algorithm_properties.as_ref());
    classify_algorithm(
        algo.and_then(|a| a.algorithm_family.as_deref()),
        Some(&comp.name),
        cp.and_then(|c| c.oid.as_deref()),
        algo.and_then(|a| a.parameter_set_identifier.as_deref()),
        algo.and_then(|a| a.elliptic_curve.as_deref()),
    )
}

/// The declared `classicalSecurityLevel` of a component's algorithm
/// properties — evidence of the key size (e.g., AES-256) that must survive
/// bom-ref resolution so referenced assets are judged with the same
/// evidence as directly evaluated ones.
fn classical_bits_of(comp: &Component) -> Option<u32> {
    comp.crypto_properties
        .as_ref()
        .and_then(|c| c.algorithm_properties.as_ref())
        .and_then(|a| a.classical_security_level)
}

/// Classify whatever a crypto bom-ref (signatureAlgorithmRef, cipher-suite
/// algorithm ref, IKEv2 transform ref, …) points at: resolve it through the
/// SBOM index to the referenced component when possible — carrying along its
/// declared `classicalSecurityLevel` — otherwise fall back to guarded
/// word-boundary token matching on the raw ref string, reporting the most
/// severe mention (opaque refs like "sig-algo-42" classify as Unknown rather
/// than silently passing checks).
fn classify_bom_ref(
    bom_ref: &str,
    sbom: &NormalizedSbom,
    index: &NormalizedSbomIndex,
) -> (AlgorithmClassification, Option<u32>) {
    match resolve_component(bom_ref, sbom, index) {
        Some(target) => (classify_crypto_component(target), classical_bits_of(target)),
        None => (
            worst_classification(classify_algorithm_names_guarded(bom_ref))
                .unwrap_or_else(AlgorithmClassification::unknown),
            None,
        ),
    }
}

/// Classify one IKEv2 transform: its algorithm bom-ref when that resolves or
/// token-matches, else its IANA transform name (with the declared key length
/// as size evidence, so `ENCR_AES_CBC` + 128 is judged as AES-128), else its
/// key-exchange group through the IANA registry. `Err` carries the label to
/// report as unverifiable.
fn classify_ike_transform(
    t: &Ikev2Transform,
    sbom: &NormalizedSbom,
    index: &NormalizedSbomIndex,
) -> Result<(AlgorithmClassification, Option<u32>), String> {
    // The declared key length sizes an otherwise unsized family, so it is
    // both judged and reported ("AES-128", not "AES").
    let sized = |mut cls: AlgorithmClassification| {
        if cls.parameter.is_none() {
            cls.parameter = t.key_length.map(|k| k.to_string());
        }
        cls
    };
    if let Some(r) = &t.algorithm_ref {
        let (cls, bits) = classify_bom_ref(r, sbom, index);
        if cls.class != AlgorithmClass::Unknown {
            return Ok((sized(cls), bits.or(t.key_length)));
        }
    }
    if let Some(name) = &t.name
        && let Some(cls) = worst_classification(classify_algorithm_names_guarded(name))
        && cls.class != AlgorithmClass::Unknown
    {
        return Ok((sized(cls), t.key_length));
    }
    if let Some((family, param)) = t.group.and_then(ikev2_key_exchange_group) {
        return Ok((
            classify_algorithm(Some(family), None, None, param, None),
            None,
        ));
    }
    Err(t
        .algorithm_ref
        .clone()
        .or_else(|| t.name.clone())
        .or_else(|| t.group.map(|g| format!("IKEv2 group {g}")))
        .unwrap_or_else(|| "(unidentified IKEv2 transform)".to_string()))
}

/// Resolve a bom-ref to the referenced component, if it exists.
fn resolve_component<'a>(
    bom_ref: &str,
    sbom: &'a NormalizedSbom,
    index: &NormalizedSbomIndex,
) -> Option<&'a Component> {
    index
        .resolve_bom_ref(bom_ref)
        .and_then(|id| sbom.components.get(id))
}

/// Judge a classified algorithm against the CNSA 2.0 exclusive allowlist:
/// AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87, and the SP 800-208
/// stateful hash-based signatures (LMS/XMSS/HSS). `classical_bits` is the
/// declared `classicalSecurityLevel`, accepted as evidence of the AES key
/// size when no parameter set is present.
fn cnsa2_verdict(cls: &AlgorithmClassification, classical_bits: Option<u32>) -> CnsaVerdict {
    use AlgorithmClass as C;
    match cls.class {
        C::Broken => CnsaVerdict::NotApproved {
            rule_id: "SBOM-CNSA2-ALG-005",
            detail: format!(
                "uses {}, a broken legacy algorithm not permitted by CNSA 2.0",
                cls.label()
            ),
        },
        C::ClassicalQuantumVulnerable => CnsaVerdict::NotApproved {
            rule_id: "SBOM-CNSA2-ALG-006",
            detail: format!(
                "({}) is quantum-vulnerable, must migrate to CNSA 2.0 approved algorithm",
                cls.label()
            ),
        },
        C::Symmetric => {
            if cls.family.as_deref() == Some("AES") {
                let bits = cls.parameter_bits().or(classical_bits);
                if bits == Some(256) {
                    CnsaVerdict::Approved
                } else {
                    let shown = bits.map_or_else(|| "unspecified".to_string(), |b| b.to_string());
                    CnsaVerdict::NotApproved {
                        rule_id: "SBOM-CNSA2-ALG-001",
                        detail: format!("uses AES-{shown}, CNSA 2.0 requires AES-256 only"),
                    }
                }
            } else {
                CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-008",
                    detail: format!(
                        "uses {}, which is not a CNSA 2.0 approved algorithm",
                        cls.label()
                    ),
                }
            }
        }
        C::Sha2 => match cls.parameter_bits() {
            Some(384 | 512) => CnsaVerdict::Approved,
            Some(_) => CnsaVerdict::NotApproved {
                rule_id: "SBOM-CNSA2-ALG-002",
                detail: "uses a SHA-2 digest < 384 bits, CNSA 2.0 requires SHA-384 or SHA-512"
                    .to_string(),
            },
            None => CnsaVerdict::NotApproved {
                rule_id: "SBOM-CNSA2-ALG-002",
                detail: "uses SHA-2 with an unspecified digest size, CNSA 2.0 requires \
                         SHA-384 or SHA-512"
                    .to_string(),
            },
        },
        C::Sha3 | C::OtherHash => CnsaVerdict::NotApproved {
            rule_id: "SBOM-CNSA2-ALG-008",
            detail: format!(
                "uses {}, which is not a CNSA 2.0 approved algorithm (CNSA 2.0 hashes \
                 are SHA-384 and SHA-512)",
                cls.label()
            ),
        },
        C::PostQuantum(kind) => match kind {
            PqcKind::MlKem => match cls.parameter.as_deref() {
                Some("1024") => CnsaVerdict::Approved,
                Some(p) => CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-003",
                    detail: format!("uses ML-KEM-{p}, CNSA 2.0 requires ML-KEM-1024 only"),
                },
                None => CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-003",
                    detail: "uses ML-KEM with an unspecified parameter set, CNSA 2.0 \
                             requires ML-KEM-1024 only"
                        .to_string(),
                },
            },
            PqcKind::MlDsa => match cls.parameter.as_deref() {
                Some("87") => CnsaVerdict::Approved,
                Some(p) => CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-004",
                    detail: format!("uses ML-DSA-{p}, CNSA 2.0 requires ML-DSA-87 only"),
                },
                None => CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-004",
                    detail: "uses ML-DSA with an unspecified parameter set, CNSA 2.0 \
                             requires ML-DSA-87 only"
                        .to_string(),
                },
            },
            // SP 800-208 stateful hash-based signatures are CNSA 2.0 approved
            // (the mandated firmware/software-signing algorithms).
            PqcKind::Lms | PqcKind::Xmss | PqcKind::Hss => CnsaVerdict::Approved,
            PqcKind::SlhDsa => CnsaVerdict::NotApproved {
                rule_id: "SBOM-CNSA2-ALG-008",
                detail: "uses SLH-DSA, which is NIST-approved (FIPS 205) but not part of \
                         CNSA 2.0"
                    .to_string(),
            },
            PqcKind::FnDsa => CnsaVerdict::NotApproved {
                rule_id: "SBOM-CNSA2-ALG-008",
                detail: "uses FN-DSA/Falcon, which is not a CNSA 2.0 approved algorithm"
                    .to_string(),
            },
        },
        C::Unknown => CnsaVerdict::Unknown,
    }
}

/// The requirement string displayed for each CNSA 2.0 rule.
fn cnsa2_requirement(rule_id: &str) -> &'static str {
    match rule_id {
        "SBOM-CNSA2-ALG-001" => "CNSA 2.0 Symmetric",
        "SBOM-CNSA2-ALG-002" => "CNSA 2.0 Hash",
        "SBOM-CNSA2-ALG-003" => "CNSA 2.0 KEM",
        "SBOM-CNSA2-ALG-004" => "CNSA 2.0 Signature",
        "SBOM-CNSA2-ALG-005" => "CNSA 2.0: broken algorithm",
        "SBOM-CNSA2-ALG-006" => "CNSA 2.0 PQC Migration",
        _ => "CNSA 2.0 Approved Algorithms",
    }
}

/// Parse a TLS/DTLS version string tolerantly, shared by the CNSA 2.0 and
/// PQC version gates so the two standards cannot disagree on the same
/// input: "1.3", "TLSv1.3", "tls1.3", "TLS 1.3", "v1.3", "1.3.0", and
/// "DTLSv1.3" all yield `(1, 3)`; "TLSv1" yields `(1, 0)`. Returns `None`
/// when no leading major version can be parsed.
fn parse_tls_version(v: &str) -> Option<(u32, u32)> {
    let s = v.trim().to_ascii_lowercase();
    let s = s
        .strip_prefix("dtls")
        .or_else(|| s.strip_prefix("tls"))
        .unwrap_or(&s)
        .trim_start();
    let s = s.strip_prefix('v').unwrap_or(s).trim_start();
    let mut parts = s.split('.');
    let major: u32 = parts.next()?.trim().parse().ok()?;
    let minor: u32 = parts.next().map_or(Some(0), |p| p.trim().parse().ok())?;
    Some((major, minor))
}

/// Whether the TLS/DTLS `version` string is below `min`. Unparseable
/// versions return `false` (the callers report them as "cannot verify").
fn tls_version_below(version: &str, min: (u32, u32)) -> bool {
    parse_tls_version(version).is_some_and(|v| v < min)
}

/// Whether a protocol asset is SSL (obsolete under every profile here).
/// Why a protocol offers nothing to evaluate: what it does declare (type
/// and version) and exactly which evaluable fields are absent. A declared
/// version alone names no algorithm, so the asset still cannot be judged —
/// but the message must not claim the version is missing.
fn unevaluable_protocol_detail(comp_name: &str, proto: &ProtocolProperties) -> String {
    let declared = match proto.version.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => format!("{} {v}", proto.protocol_type),
        _ => format!("{}, no version", proto.protocol_type),
    };
    let missing = if proto.protocol_type.is_ike_family() {
        "cipher suites, algorithm references (cryptoRefArray / \
         relatedCryptographicAssets) or IKEv2 transform types"
    } else {
        "cipher suites or algorithm references (cryptoRefArray / \
         relatedCryptographicAssets)"
    };
    format!("Protocol '{comp_name}' ({declared}) declares no {missing}")
}

fn is_ssl_protocol(proto: &ProtocolProperties) -> bool {
    matches!(&proto.protocol_type, ProtocolType::Other(s) if s.to_lowercase().contains("ssl"))
}

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CNSA 2.0 compliance checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_cnsa2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ComponentType;

        let index = sbom.build_index();

        // Count only assets the classifier could actually judge against the
        // CNSA 2.0 allowlist, so an inventory of unidentifiable assets
        // cannot satisfy the CNSA2-000 gate.
        let mut crypto_assets_evaluated = 0usize;

        // All components: the loop selects cryptographic assets by type.
        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            match cp.asset_type {
                CryptoAssetType::Algorithm => {
                    if Self::check_cnsa2_algorithm(comp, cp, violations) {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::Certificate => {
                    // CNSA2-CERT-001: cert must use a CNSA 2.0 signature
                    // algorithm. Only certificates carrying a signature
                    // algorithm reference are verifiable (and counted). A
                    // CycloneDX 1.7 certificate may relate several
                    // algorithms without naming the signing one: judge all.
                    let sig_refs = cp
                        .certificate_properties
                        .as_ref()
                        .map(CertificateProperties::signature_algorithm_refs)
                        .unwrap_or_default();
                    // Counted only when at least one signing candidate
                    // could be classified.
                    let mut judged = false;
                    for sig_ref in sig_refs {
                        let (cls, bits) = classify_bom_ref(sig_ref, sbom, &index);
                        let verdict = cnsa2_verdict(&cls, bits);
                        judged |= !matches!(verdict, CnsaVerdict::Unknown);
                        match verdict {
                            CnsaVerdict::Approved => {}
                            CnsaVerdict::NotApproved { detail, .. } => {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "Certificate '{}' signed with non-CNSA 2.0 algorithm: \
                                         {detail} (ref: {sig_ref})",
                                        comp.name
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Certificate".to_string(),
                                    rule_id: "SBOM-CNSA2-CERT-001",
                                    component_id: Some(comp.canonical_id.value().to_string()),
                                    counts: None,
                                    standard_refs: Vec::new(),
                                    remediation: None,
                                });
                            }
                            // An unclassifiable signature ref fails closed —
                            // CNSA 2.0 is an allowlist, so a signature that
                            // cannot be identified cannot be shown to comply.
                            CnsaVerdict::Unknown => {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "Certificate '{}' signature algorithm ref '{sig_ref}' \
                                         cannot be resolved or classified, so it cannot be \
                                         shown to be on the CNSA 2.0 allowlist",
                                        comp.name
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0: certificate signature identification"
                                        .to_string(),
                                    rule_id: "SBOM-CNSA2-CERT-UNKNOWN",
                                    component_id: Some(comp.canonical_id.value().to_string()),
                                    counts: None,
                                    standard_refs: Vec::new(),
                                    remediation: None,
                                });
                            }
                        }
                    }
                    if judged {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::Protocol => {
                    if let Some(proto) = &cp.protocol_properties
                        && Self::check_cnsa2_protocol(comp, proto, sbom, &index, violations)
                    {
                        crypto_assets_evaluated += 1;
                    }
                }
                // Key material and unrecognized asset kinds get no CNSA 2.0
                // evaluation, so they intentionally do NOT count toward the
                // inventory gate: an SBOM documenting only keys would
                // otherwise "pass" a standard that never looked at anything.
                _ => {}
            }
        }

        // CNSA2-000: no cryptographic inventory to evaluate — a "compliant"
        // verdict here would be a false CNSA 2.0 claim, so fail.
        if crypto_assets_evaluated == 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: "No cryptographic asset the CNSA 2.0 check could identify; \
                          compliance cannot be asserted. Provide algorithm, certificate, or \
                          protocol assets with a recognizable algorithm family, OID, or name."
                    .to_string(),
                element: None,
                requirement: "CNSA 2.0: cryptographic inventory required".to_string(),
                rule_id: "SBOM-CNSA2-000",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
    }

    /// Evaluate a single algorithm asset against the CNSA 2.0 allowlist plus
    /// the declared-quantum-level rules (ALG-006/ALG-007). Returns whether
    /// the asset was judged — classified, or declared quantum-vulnerable —
    /// which is what the CNSA2-000 inventory gate counts.
    fn check_cnsa2_algorithm(
        comp: &Component,
        cp: &crate::model::CryptoProperties,
        violations: &mut Vec<Violation>,
    ) -> bool {
        let cls = classify_crypto_component(comp);

        // Declared-quantum-level rules. Symmetric/hash primitives are allowed
        // at lower declared levels (Grover, not Shor).
        if let Some(algo) = &cp.algorithm_properties
            && let Some(ql) = algo.nist_quantum_security_level
            && ql < 5
        {
            let is_symmetric_or_hash = matches!(
                algo.primitive,
                crate::model::CryptoPrimitive::Ae
                    | crate::model::CryptoPrimitive::BlockCipher
                    | crate::model::CryptoPrimitive::Hash
                    | crate::model::CryptoPrimitive::Mac
                    | crate::model::CryptoPrimitive::Kdf
            );
            if !is_symmetric_or_hash {
                if ql == 0 {
                    // Classified classical families already get the
                    // family-based ALG-006 below — don't double-report.
                    if cls.class != AlgorithmClass::ClassicalQuantumVulnerable {
                        violations.push(Violation {
                            severity: ViolationSeverity::Error,
                            category: ViolationCategory::CryptographyInfo,
                            message: format!(
                                "'{}' is quantum-vulnerable (level {}), must migrate to PQC",
                                comp.name, ql
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "CNSA 2.0 PQC Migration".to_string(),
                            rule_id: "SBOM-CNSA2-ALG-006",
                            component_id: Some(comp.canonical_id.value().to_string()),
                            counts: None,
                            standard_refs: Vec::new(),
                            remediation: None,
                        });
                    }
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' quantum level {} < 5, CNSA 2.0 requires Level 5",
                            comp.name, ql
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CNSA 2.0 Level 5".to_string(),
                        rule_id: "SBOM-CNSA2-ALG-007",
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                    });
                }
            }
        }

        let classical_bits = cp
            .algorithm_properties
            .as_ref()
            .and_then(|a| a.classical_security_level);
        let declared_vulnerable = cp
            .algorithm_properties
            .as_ref()
            .and_then(|a| a.nist_quantum_security_level)
            == Some(0);
        match cnsa2_verdict(&cls, classical_bits) {
            CnsaVerdict::Approved => true,
            CnsaVerdict::NotApproved { rule_id, detail } => {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::CryptographyInfo,
                    message: format!("'{}' {detail}", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: cnsa2_requirement(rule_id).to_string(),
                    rule_id,
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                });
                true
            }
            CnsaVerdict::Unknown => {
                // A declared level-0 asset already produced the ALG-006 Error
                // above, which judges it; a second finding would be noise.
                // Otherwise fail closed: CNSA 2.0 is an allowlist, so an
                // algorithm that cannot be identified cannot be shown to
                // comply.
                if !declared_vulnerable {
                    let hybrid = cp
                        .algorithm_properties
                        .as_ref()
                        .is_some_and(crate::model::AlgorithmProperties::is_hybrid_pqc);
                    let what = if hybrid {
                        "is a hybrid combiner whose component algorithms cannot be identified"
                    } else {
                        "cannot be classified (no recognizable algorithm family, OID, or name)"
                    };
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' {what}, so it cannot be shown to be on the CNSA 2.0 allowlist",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CNSA 2.0: algorithm identification".to_string(),
                        rule_id: "SBOM-CNSA2-ALG-UNKNOWN",
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                    });
                }
                declared_vulnerable
            }
        }
    }

    /// Evaluate a protocol asset under CNSA 2.0: TLS 1.3 required, and every
    /// resolvable cipher-suite algorithm / IKEv2 transform / crypto reference
    /// must be on the allowlist. Returns whether the protocol was judged —
    /// failed on its version, or had at least one algorithm classified —
    /// which is what the CNSA2-000 inventory gate counts.
    fn check_cnsa2_protocol(
        comp: &Component,
        proto: &ProtocolProperties,
        sbom: &NormalizedSbom,
        index: &NormalizedSbomIndex,
        violations: &mut Vec<Violation>,
    ) -> bool {
        // PROTO-001: version gate — CNSA 2.0 network guidance requires TLS 1.3.
        let violations_before = violations.len();
        if is_ssl_protocol(proto) {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses SSL, which is obsolete; CNSA 2.0 requires TLS 1.3",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0 Protocol".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        } else if matches!(proto.protocol_type, ProtocolType::Tls | ProtocolType::Dtls)
            && proto.version.as_deref().and_then(parse_tls_version) != Some((1, 3))
        {
            // Tolerant version parsing: "TLSv1.3", "tls1.3", "1.3.0", … all
            // count as TLS 1.3 (previously exact string equality with "1.3"
            // failed spec-compliant spellings). Missing or unparseable
            // versions remain an Error: an allowlist standard cannot
            // affirm TLS 1.3 from a version it cannot read.
            let shown = proto.version.as_deref().map_or_else(
                || "an unspecified version".to_string(),
                |v| format!("version {v}"),
            );
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses {} {shown}, CNSA 2.0 requires TLS 1.3",
                    comp.name,
                    proto.protocol_type.to_string().to_uppercase()
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0 Protocol".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
        let version_rejected = violations.len() > violations_before;

        // Collect non-allowlisted algorithms per source, deduplicated by label.
        let mut push_proto_violation = |context: String, offenders: Vec<String>| {
            if offenders.is_empty() {
                return;
            }
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' {context} non-CNSA 2.0 algorithms: {}",
                    comp.name,
                    offenders.join(", ")
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0 Protocol".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-002",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        };
        // References that resolve nowhere and carry no recognizable token
        // receive no effective check — collect them so the protocol warns
        // instead of silently satisfying the CNSA2-000 inventory gate.
        let mut unverifiable: Vec<String> = Vec::new();
        // How many algorithms the classifier could identify, approved or not.
        let judged = std::cell::Cell::new(0usize);
        let record =
            |cls: &AlgorithmClassification, bits: Option<u32>, offenders: &mut Vec<String>| {
                if cls.class != AlgorithmClass::Unknown {
                    judged.set(judged.get() + 1);
                }
                if let CnsaVerdict::NotApproved { .. } = cnsa2_verdict(cls, bits) {
                    let label = cls.label();
                    if !offenders.contains(&label) {
                        offenders.push(label);
                    }
                }
            };

        // PROTO-002: cipher suites — both the algorithm refs (resolved
        // through the index, with the referenced asset's declared
        // classicalSecurityLevel as key-size evidence, or token-scanned when
        // unresolvable) and a word-boundary scan of the suite name.
        for suite in &proto.cipher_suites {
            let mut offenders = Vec::new();
            for algo_ref in &suite.algorithms {
                let (cls, bits) = classify_bom_ref(algo_ref, sbom, index);
                if cls.class == AlgorithmClass::Unknown {
                    unverifiable.push(algo_ref.clone());
                } else {
                    record(&cls, bits, &mut offenders);
                }
            }
            if let Some(name) = &suite.name {
                for cls in classify_algorithm_names(name) {
                    record(&cls, None, &mut offenders);
                }
            }
            push_proto_violation(
                format!(
                    "cipher suite '{}' includes",
                    suite.name.as_deref().unwrap_or("(unnamed)")
                ),
                offenders,
            );
        }

        // PROTO-002: IKEv2 transform types.
        if let Some(ike) = &proto.ikev2_transform_types {
            let mut offenders = Vec::new();
            for t in ike.judged_transforms() {
                match classify_ike_transform(&t, sbom, index) {
                    Ok((cls, bits)) => record(&cls, bits, &mut offenders),
                    Err(label) => unverifiable.push(label),
                }
            }
            push_proto_violation("IKEv2 transforms include".to_string(), offenders);
        }

        // PROTO-002: crypto reference array. Only algorithm assets are judged
        // here — referenced certificates/keys are evaluated as their own
        // assets. Unresolvable refs get the token-scan fallback.
        let mut offenders = Vec::new();
        for r in &proto.crypto_ref_array {
            match resolve_component(r, sbom, index) {
                Some(target) => {
                    if target
                        .crypto_properties
                        .as_ref()
                        .is_some_and(|c| c.asset_type == CryptoAssetType::Algorithm)
                    {
                        record(
                            &classify_crypto_component(target),
                            classical_bits_of(target),
                            &mut offenders,
                        );
                    }
                }
                None => {
                    if let Some(cls) = worst_classification(classify_algorithm_names_guarded(r)) {
                        record(&cls, None, &mut offenders);
                    } else {
                        unverifiable.push(r.clone());
                    }
                }
            }
        }
        push_proto_violation("references".to_string(), offenders);

        // Fail closed when the protocol's algorithms cannot be verified:
        // opaque references, or nothing the classifier can name at all (a
        // TLS 1.3 asset whose suites carry no recognizable algorithm passed
        // silently). A protocol already rejected on its version is judged.
        let judged = judged.get();
        let substantive = is_ssl_protocol(proto)
            || matches!(proto.protocol_type, ProtocolType::Tls | ProtocolType::Dtls)
            || !proto.cipher_suites.is_empty()
            || proto.ikev2_transform_types.is_some()
            || !proto.crypto_ref_array.is_empty();
        if !unverifiable.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' has crypto references that cannot be resolved or \
                     classified: {}; they cannot be shown to be on the CNSA 2.0 allowlist",
                    comp.name,
                    unverifiable.join(", ")
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0: protocol algorithm identification".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        } else if judged == 0 && !version_rejected {
            let detail = if substantive {
                format!(
                    "Protocol '{}' declares no cipher suite, transform or algorithm the \
                     classifier can name",
                    comp.name
                )
            } else {
                unevaluable_protocol_detail(&comp.name, proto)
            };
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "{detail}; its algorithms cannot be shown to be on the CNSA 2.0 allowlist"
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0: protocol algorithm identification".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
        version_rejected || judged > 0
    }

    // ════════════════════════════════════════════════════════════════════
    // NIST PQC Readiness checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_nist_pqc(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ComponentType;

        let index = sbom.build_index();

        // Track whether we actually evaluated any cryptographic asset. A tool
        // asserting PQC compliance must not report "compliant" when it found
        // no cryptographic inventory to evaluate. Only assets that receive a
        // substantive check are counted.
        let mut crypto_assets_evaluated = 0usize;

        // All components: the loop selects cryptographic assets by type.
        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            match cp.asset_type {
                CryptoAssetType::Algorithm => {
                    if Self::check_pqc_algorithm(comp, cp, violations) {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::Certificate => {
                    // PQC-CERT-001: certificate signature algorithm must not be
                    // broken or quantum-vulnerable. Resolved through the
                    // bom-ref index, with a token-match fallback on the raw
                    // ref string. Every related signing candidate is judged,
                    // as for CNSA2-CERT-001.
                    let sig_refs = cp
                        .certificate_properties
                        .as_ref()
                        .map(CertificateProperties::signature_algorithm_refs)
                        .unwrap_or_default();
                    // Counted only when at least one signing candidate
                    // could be classified.
                    let mut judged = false;
                    for sig_ref in sig_refs {
                        let (cls, _) = classify_bom_ref(sig_ref, sbom, &index);
                        judged |= cls.class != AlgorithmClass::Unknown;
                        let problem = match cls.class {
                            AlgorithmClass::Broken => Some("broken algorithm (SP 800-131A)"),
                            AlgorithmClass::ClassicalQuantumVulnerable => {
                                Some("quantum-vulnerable algorithm, must migrate to PQC (IR 8547)")
                            }
                            _ => None,
                        };
                        if let Some(problem) = problem {
                            violations.push(Violation {
                                severity: ViolationSeverity::Error,
                                category: ViolationCategory::CryptographyInfo,
                                message: format!(
                                    "Certificate '{}' signed with {} — {problem} (ref: {sig_ref})",
                                    comp.name,
                                    cls.label()
                                ),
                                element: Some(comp.name.clone()),
                                requirement: "IR 8547: certificate signature".to_string(),
                                rule_id: "SBOM-PQC-CERT-001",
                                component_id: Some(comp.canonical_id.value().to_string()),
                                counts: None,
                                standard_refs: Vec::new(),
                                remediation: None,
                            });
                        } else if cls.class == AlgorithmClass::Unknown {
                            // An unclassifiable signature ref must warn, never
                            // silently pass — mirrors SBOM-CNSA2-ALG-UNKNOWN
                            // (previously a certificate-only CBOM whose sig
                            // ref was opaque reported 100% PQC-ready).
                            violations.push(Violation {
                                severity: ViolationSeverity::Warning,
                                category: ViolationCategory::CryptographyInfo,
                                message: format!(
                                    "Certificate '{}' signature algorithm ref '{sig_ref}' \
                                     cannot be resolved or classified; unable to verify \
                                     PQC readiness",
                                    comp.name
                                ),
                                element: Some(comp.name.clone()),
                                requirement: "IR 8547: certificate signature identification"
                                    .to_string(),
                                rule_id: "SBOM-PQC-CERT-UNKNOWN",
                                component_id: Some(comp.canonical_id.value().to_string()),
                                counts: None,
                                standard_refs: Vec::new(),
                                remediation: None,
                            });
                        }
                    }
                    if judged {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::Protocol => {
                    if let Some(proto) = &cp.protocol_properties
                        && Self::check_pqc_protocol(comp, proto, sbom, &index, violations)
                    {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::RelatedCryptoMaterial => {
                    // PQC-KEY-001: symmetric key < 128 bits. Only material we
                    // actually evaluate (symmetric keys with a declared size)
                    // counts toward the inventory gate.
                    if let Some(mat) = &cp.related_crypto_material_properties
                        && let Some(size) = mat.size
                    {
                        let is_symmetric = matches!(
                            mat.material_type,
                            crate::model::CryptoMaterialType::SymmetricKey
                                | crate::model::CryptoMaterialType::SecretKey
                        );
                        if is_symmetric {
                            crypto_assets_evaluated += 1;
                            if size < 128 {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' symmetric key size {} bits < 128 minimum",
                                        comp.name, size
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "NIST: minimum key size".to_string(),
                                    rule_id: "SBOM-PQC-KEY-001",
                                    component_id: Some(comp.canonical_id.value().to_string()),
                                    counts: None,
                                    standard_refs: Vec::new(),
                                    remediation: None,
                                });
                            }
                        }
                    }
                }
                // Unrecognized asset kinds receive no evaluation and do not
                // count toward the inventory gate.
                _ => {}
            }
        }

        // PQC-000: no cryptographic inventory. Reporting "compliant" when there
        // was nothing to evaluate is a false PQC-readiness claim, so fail.
        if crypto_assets_evaluated == 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: "No cryptographic asset the PQC check could identify; NIST PQC \
                          readiness cannot be asserted. Provide algorithm, certificate, or \
                          protocol assets with a recognizable algorithm family, OID, or name."
                    .to_string(),
                element: None,
                requirement: "IR 8547: cryptographic inventory required".to_string(),
                rule_id: "SBOM-PQC-000",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
    }

    /// Evaluate a single algorithm asset for NIST PQC readiness. Returns
    /// whether the asset was judged — classified, or declared
    /// quantum-vulnerable — which is what the PQC-000 inventory gate counts.
    fn check_pqc_algorithm(
        comp: &Component,
        cp: &crate::model::CryptoProperties,
        violations: &mut Vec<Violation>,
    ) -> bool {
        let algo = cp.algorithm_properties.as_ref();
        let cls = classify_crypto_component(comp);
        let ql = algo.and_then(|a| a.nist_quantum_security_level);

        // PQC-ALG-UNKNOWN: an algorithm the classifier cannot name used to
        // pass silently whenever it declared a quantum level. It cannot be
        // verified, so it warns and does not count as inventory. A declared
        // level 0 is judged by PQC-001 below instead, and a declared hybrid
        // combiner by PQC-010.
        let hybrid = algo.is_some_and(crate::model::AlgorithmProperties::is_hybrid_pqc);
        if cls.class == AlgorithmClass::Unknown && ql != Some(0) && !hybrid {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' cannot be classified (no recognizable algorithm family, OID, or \
                     name); unable to verify PQC readiness",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: algorithm identification".to_string(),
                rule_id: "SBOM-PQC-ALG-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // PQC-001: quantum-vulnerable algorithm. A classical public-key
        // algorithm (RSA/ECDSA/ECDH/DH/DSA/EdDSA/…) is broken by Shor's
        // algorithm regardless of key size, so the classification alone is
        // authoritative — including via OID, elliptic-curve field, or name
        // when algorithmFamily is absent (CycloneDX 1.6). A declared level 0
        // also fires, unless the asset is already reported as Broken.
        let classical = cls.class == AlgorithmClass::ClassicalQuantumVulnerable;
        if classical || (ql == Some(0) && cls.class != AlgorithmClass::Broken) {
            let shown = if cls.family.is_some() {
                cls.label()
            } else {
                "classical".to_string()
            };
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' ({shown}) is quantum-vulnerable and must migrate to PQC (IR 8547)",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: quantum-vulnerable".to_string(),
                rule_id: "SBOM-PQC-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // PQC-012: missing quantum security level
        if ql.is_none() {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::CryptographyInfo,
                message: format!("'{}' missing nistQuantumSecurityLevel field", comp.name),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: quantum assessment required".to_string(),
                rule_id: "SBOM-PQC-012",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // PQC-005: broken/disallowed algorithms per SP 800-131A, via the
        // shared classifier (catches spelling variants like "SHA1"/"TDES"/
        // "ARC4" and OID/name-only CycloneDX 1.6 assets).
        if cls.class == AlgorithmClass::Broken {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' ({}) is broken/disallowed per SP 800-131A",
                    comp.name,
                    cls.label()
                ),
                element: Some(comp.name.clone()),
                requirement: "SP 800-131A: disallowed".to_string(),
                rule_id: "SBOM-PQC-005",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // PQC-008: ECB mode
        if algo.and_then(|a| a.mode.as_ref()) == Some(&crate::model::CryptoMode::Ecb) {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' uses ECB mode, disallowed per SP 800-131A Rev 3",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "SP 800-131A Rev 3: ECB disallowed".to_string(),
                rule_id: "SBOM-PQC-008",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // PQC-009: approved PQC (informational). FIPS 203/204/205 finals and
        // the SP 800-208 stateful hash-based signatures both qualify; FN-DSA
        // (Falcon) is recognized but not yet standardized, so it gets no
        // approval note.
        if let AlgorithmClass::PostQuantum(kind) = cls.class {
            let approval = match kind {
                PqcKind::MlKem | PqcKind::MlDsa | PqcKind::SlhDsa => Some("FIPS 203/204/205"),
                PqcKind::Lms | PqcKind::Xmss | PqcKind::Hss => {
                    Some("SP 800-208 stateful hash-based signature")
                }
                PqcKind::FnDsa => None,
            };
            if let Some(approval) = approval {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::CryptographyInfo,
                    message: format!(
                        "'{}' uses NIST-approved PQC algorithm ({approval})",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "FIPS 203/204/205: approved".to_string(),
                    rule_id: "SBOM-PQC-009",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                });
            }
        }

        // PQC-010: hybrid PQC combiner (informational)
        if algo.is_some_and(|a| a.is_hybrid_pqc()) {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' is a hybrid PQC combiner — good migration practice",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: recommended transition".to_string(),
                rule_id: "SBOM-PQC-010",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
        cls.class != AlgorithmClass::Unknown || ql == Some(0) || hybrid
    }

    /// Evaluate a protocol asset for PQC readiness: no SSL / TLS below 1.2,
    /// and no broken or quantum-vulnerable algorithms in cipher suites,
    /// IKEv2 transforms, or crypto references.
    ///
    /// Returns whether the protocol was judged — failed on its version, or
    /// had at least one algorithm classified — which is what the PQC-000
    /// inventory gate counts.
    fn check_pqc_protocol(
        comp: &Component,
        proto: &ProtocolProperties,
        sbom: &NormalizedSbom,
        index: &NormalizedSbomIndex,
        violations: &mut Vec<Violation>,
    ) -> bool {
        // PQC-PROTO-001: SSL anything, or TLS/DTLS below 1.2.
        let violations_before = violations.len();
        if is_ssl_protocol(proto) {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses SSL, which is disallowed; use TLS 1.2 or higher \
                     (SP 800-52 Rev. 2)",
                    comp.name
                ),
                element: Some(comp.name.clone()),
                requirement: "SP 800-52: protocol version".to_string(),
                rule_id: "SBOM-PQC-PROTO-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        } else if matches!(proto.protocol_type, ProtocolType::Tls | ProtocolType::Dtls)
            && let Some(version) = proto.version.as_deref()
            && tls_version_below(version, (1, 2))
        {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses {} {version}, which is disallowed; use TLS 1.2 or \
                     higher (SP 800-52 Rev. 2)",
                    comp.name,
                    proto.protocol_type.to_string().to_uppercase()
                ),
                element: Some(comp.name.clone()),
                requirement: "SP 800-52: protocol version".to_string(),
                rule_id: "SBOM-PQC-PROTO-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
        let version_rejected = violations.len() > violations_before;

        // Unverifiable evidence: opaque references and unparseable TLS
        // versions receive no effective check, so they are collected for a
        // Warning instead of silently passing the SP 800-52 / IR 8547 gates.
        let mut unverifiable: Vec<String> = Vec::new();
        if matches!(proto.protocol_type, ProtocolType::Tls | ProtocolType::Dtls)
            && let Some(version) = proto.version.as_deref()
            && parse_tls_version(version).is_none()
        {
            unverifiable.push(format!("version '{version}'"));
        }

        let mut push_proto_violation = |context: String, offenders: Vec<String>| {
            if offenders.is_empty() {
                return;
            }
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' {context} broken or quantum-vulnerable algorithms: {}",
                    comp.name,
                    offenders.join(", ")
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547 / SP 800-131A: protocol algorithms".to_string(),
                rule_id: "SBOM-PQC-PROTO-002",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        };
        // How many algorithms the classifier could identify, ready or not.
        let judged = std::cell::Cell::new(0usize);
        let record = |cls: &AlgorithmClassification, offenders: &mut Vec<String>| {
            if cls.class != AlgorithmClass::Unknown {
                judged.set(judged.get() + 1);
            }
            let tag = match cls.class {
                AlgorithmClass::Broken => Some("broken"),
                AlgorithmClass::ClassicalQuantumVulnerable => Some("quantum-vulnerable"),
                _ => None,
            };
            if let Some(tag) = tag {
                let label = format!("{} ({tag})", cls.label());
                if !offenders.contains(&label) {
                    offenders.push(label);
                }
            }
        };

        for suite in &proto.cipher_suites {
            let mut offenders = Vec::new();
            for algo_ref in &suite.algorithms {
                let (cls, _) = classify_bom_ref(algo_ref, sbom, index);
                if cls.class == AlgorithmClass::Unknown {
                    unverifiable.push(algo_ref.clone());
                } else {
                    record(&cls, &mut offenders);
                }
            }
            if let Some(name) = &suite.name {
                for cls in classify_algorithm_names(name) {
                    record(&cls, &mut offenders);
                }
            }
            push_proto_violation(
                format!(
                    "cipher suite '{}' includes",
                    suite.name.as_deref().unwrap_or("(unnamed)")
                ),
                offenders,
            );
        }

        if let Some(ike) = &proto.ikev2_transform_types {
            let mut offenders = Vec::new();
            for t in ike.judged_transforms() {
                match classify_ike_transform(&t, sbom, index) {
                    Ok((cls, _)) => record(&cls, &mut offenders),
                    Err(label) => unverifiable.push(label),
                }
            }
            push_proto_violation("IKEv2 transforms include".to_string(), offenders);
        }

        let mut offenders = Vec::new();
        for r in &proto.crypto_ref_array {
            match resolve_component(r, sbom, index) {
                Some(target) => {
                    if target
                        .crypto_properties
                        .as_ref()
                        .is_some_and(|c| c.asset_type == CryptoAssetType::Algorithm)
                    {
                        record(&classify_crypto_component(target), &mut offenders);
                    }
                }
                None => {
                    if let Some(cls) = worst_classification(classify_algorithm_names_guarded(r)) {
                        record(&cls, &mut offenders);
                    } else {
                        unverifiable.push(r.clone());
                    }
                }
            }
        }
        push_proto_violation("references".to_string(), offenders);

        // A protocol whose evidence is all opaque, or that documents nothing
        // evaluable at all, must warn rather than silently satisfying the
        // PQC-000 inventory gate — mirrors SBOM-CNSA2-ALG-UNKNOWN. For the
        // version gate only a parseable TLS/DTLS version counts as evidence
        // (SSL is substantively rejected above).
        let version_evaluated = is_ssl_protocol(proto)
            || (matches!(proto.protocol_type, ProtocolType::Tls | ProtocolType::Dtls)
                && proto
                    .version
                    .as_deref()
                    .is_some_and(|v| parse_tls_version(v).is_some()));
        let substantive = version_evaluated
            || !proto.cipher_suites.is_empty()
            || proto.ikev2_transform_types.is_some()
            || !proto.crypto_ref_array.is_empty();
        if !unverifiable.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' has crypto evidence that cannot be resolved or \
                     classified: {}; unable to verify PQC readiness",
                    comp.name,
                    unverifiable.join(", ")
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: protocol algorithm identification".to_string(),
                rule_id: "SBOM-PQC-PROTO-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        } else if judged.get() == 0 && !version_rejected {
            // Nothing the classifier can name: a TLS 1.3 asset whose suites
            // carry no recognizable algorithm used to pass silently.
            let detail = if substantive {
                format!(
                    "Protocol '{}' declares no cipher suite, transform or algorithm the \
                     classifier can name",
                    comp.name
                )
            } else {
                unevaluable_protocol_detail(&comp.name, proto)
            };
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::CryptographyInfo,
                message: format!("{detail}; its algorithms cannot be verified for PQC readiness"),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: protocol algorithm identification".to_string(),
                rule_id: "SBOM-PQC-PROTO-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
        version_rejected || judged.get() > 0
    }
}
