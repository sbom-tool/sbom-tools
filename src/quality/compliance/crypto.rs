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
//! index, word-boundary-scanning cipher-suite names, and looking up the TLS
//! groups and signature schemes each suite offers in their IANA registries.
//!
//! A PQ/T hybrid (X25519MLKEM768, an RFC 9370 IKEv2 additional key
//! exchange, composite ML-DSA) is judged by its parts, not by the weaker
//! one: NIST PQC by its post-quantum part ([`pqc_subject`]), CNSA 2.0 by
//! both ([`cnsa2_hybrid_verdict`]).
//!
//! Under `--pqc-mode deadline` both standards judge the algorithms they
//! reject by their migration deadlines instead of failing them all now
//! ([`super::pqc_calendar`]): the finding takes the severity its schedule
//! gives on the evaluation date, a certificate's on the later of that date
//! and its `notValidAfter`, and records the deadline. Readiness mode, the
//! default, is unchanged.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use super::pqc_calendar::{CalendarVerdict, PkUse};
use super::*;
use crate::model::{
    AlgorithmClass, AlgorithmClassification, AlgorithmProperties, CertificateProperties,
    CipherSuite, Component, CryptoAssetType, CryptoPrimitive, HybridParts, Ikev2Transform,
    Ikev2TransformKind, Ikev2TransformTypes, NormalizedSbomIndex, PqcKind, ProtocolProperties,
    ProtocolType, TlsRegistryEntry, classify_algorithm, classify_algorithm_names,
    classify_algorithm_names_guarded, ikev2_key_exchange_group, is_tls_grease, tls_named_group,
    tls_signature_scheme, worst_classification,
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
///
/// A declared hybrid combiner (`primitive: combiner`) whose identity names
/// no hybrid takes the one its name names, when the two agree: the family
/// "Hybrid-KEM" (no CycloneDX family) or "ML-KEM" (one of its parts) with
/// the name "X25519-ML-KEM-768" is that hybrid. A declared part keeps its
/// declared parameter set, as a declared family always does.
fn classify_crypto_component(comp: &Component) -> AlgorithmClassification {
    let cp = comp.crypto_properties.as_ref();
    let algo = cp.and_then(|c| c.algorithm_properties.as_ref());
    let cls = classify_algorithm(
        algo.and_then(|a| a.algorithm_family.as_deref()),
        Some(&comp.name),
        cp.and_then(|c| c.oid.as_deref()),
        algo.and_then(|a| a.parameter_set_identifier.as_deref()),
        algo.and_then(|a| a.elliptic_curve.as_deref()),
    );
    if cls.class == AlgorithmClass::Hybrid || !algo.is_some_and(AlgorithmProperties::is_hybrid_pqc)
    {
        return cls;
    }
    let named = classify_algorithm_names_guarded(&comp.name)
        .into_iter()
        .find_map(|m| m.hybrid.map(|parts| *parts));
    let Some(HybridParts {
        mut classical,
        mut post_quantum,
    }) = named
    else {
        return cls;
    };
    if cls.class != AlgorithmClass::Unknown {
        let declared = if cls.family == post_quantum.family {
            &mut post_quantum
        } else if cls.family == classical.family {
            &mut classical
        } else {
            return cls;
        };
        if cls.parameter.is_some() {
            declared.parameter = cls.parameter;
        }
    }
    AlgorithmClassification::hybrid(classical, post_quantum)
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
    // both judged and reported ("AES-128", not "AES"), and so does the IANA
    // group of a key exchange of the group's own family (an unsized ECDH
    // asset in group 20 is ECDH over secp384r1) — the curve or modulus
    // decides the classical half of an RFC 9370 hybrid under CNSA 2.0.
    let group = t.group.and_then(ikev2_key_exchange_group);
    let sized = |mut cls: AlgorithmClassification| {
        if cls.parameter.is_none() {
            cls.parameter = t.key_length.map(|k| k.to_string());
        }
        if cls.parameter.is_none()
            && let Some((family, Some(parameter))) = group
            && cls.family.as_deref() == Some(family)
        {
            cls.parameter = Some(parameter.to_string());
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
    if let Some((family, param)) = group {
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

/// One IKEv2 transform (or RFC 9370 hybrid) to judge: its classification
/// and declared key size, or the label to report as unverifiable.
type IkeJudged = Result<(AlgorithmClassification, Option<u32>), String>;

/// Whether an IKEv2 transform is Transform ID NONE (0), which in an
/// additional key exchange type makes that exchange optional (RFC 9370
/// §2.2.2).
fn is_none_transform(t: &Ikev2Transform) -> bool {
    t.algorithm_ref.is_none()
        && (t.group == Some(0)
            || t.name
                .as_deref()
                .is_some_and(|n| n.trim().eq_ignore_ascii_case("NONE")))
}

/// The transforms of an IKEv2 SA to judge, each classified by
/// [`classify_ike_transform`] — except that a key exchange method
/// (Transform Type 4) and the RFC 9370 additional key exchanges
/// (ADDKE1–ADDKE7) are judged together. Every SA performs one KE method in
/// IKE_SA_INIT and then one method of each proposed ADDKE type
/// (RFC 9370 §2.2.2), so a classical KE method followed by a post-quantum
/// additional exchange is a PQ/T hybrid: NSA's CNSA 2.0 IPsec profile is
/// P-384 (or a 3072/4096-bit MODP group) then ML-KEM-1024
/// (draft-guthrie-cnsa2-ipsec-profile-04 §4, §6.2). Each KE method is also
/// judged alone when every ADDKE type offers NONE, since the SA may then
/// skip them all.
fn ike_judged_transforms(
    ike: &Ikev2TransformTypes,
    sbom: &NormalizedSbom,
    index: &NormalizedSbomIndex,
) -> Vec<IkeJudged> {
    let mut judged = Vec::new();
    let mut key_exchanges = Vec::new();
    // Per ADDKE round: its methods other than NONE, and whether NONE is one.
    let mut additional: BTreeMap<u8, (Vec<IkeJudged>, bool)> = BTreeMap::new();
    for t in ike.judged_transforms() {
        if let Some(round) = t.kind.additional_key_exchange() {
            let (methods, optional) = additional.entry(round).or_default();
            if is_none_transform(&t) {
                *optional = true;
            } else {
                methods.push(classify_ike_transform(&t, sbom, index));
            }
        } else if t.kind == Ikev2TransformKind::Ke {
            key_exchanges.push(classify_ike_transform(&t, sbom, index));
        } else {
            judged.push(classify_ike_transform(&t, sbom, index));
        }
    }
    let skippable = additional.values().all(|(_, optional)| *optional);
    let added: Vec<IkeJudged> = additional
        .into_values()
        .flat_map(|(methods, _)| methods)
        .collect();
    if key_exchanges.is_empty() {
        judged.extend(added);
        return judged;
    }
    for ke in &key_exchanges {
        if skippable {
            judged.push(ke.clone());
        }
        for add in &added {
            judged.extend(paired_key_exchanges(ke, add));
        }
    }
    judged
}

/// What a KE method and an additional key exchange performed after it are
/// judged as: their hybrid when one is classical and the other
/// post-quantum, else each on its own. An exchange that cannot be
/// identified beside a classical KE method (or a post-quantum additional
/// exchange) is the hybrid's unidentified part, named by its label.
fn paired_key_exchanges(ke: &IkeJudged, add: &IkeJudged) -> Vec<IkeJudged> {
    use AlgorithmClass as C;
    let unidentified = |label: &str| AlgorithmClassification {
        family: Some(label.to_string()),
        ..AlgorithmClassification::unknown()
    };
    let hybrid = |classical: AlgorithmClassification, post_quantum: AlgorithmClassification| {
        vec![Ok((
            AlgorithmClassification::hybrid(classical, post_quantum),
            None,
        ))]
    };
    match (ke, add) {
        (Ok((k, _)), Ok((a, _))) => match (k.class, a.class) {
            (C::ClassicalQuantumVulnerable, C::PostQuantum(_)) => hybrid(k.clone(), a.clone()),
            (C::PostQuantum(_), C::ClassicalQuantumVulnerable) => hybrid(a.clone(), k.clone()),
            _ => vec![ke.clone(), add.clone()],
        },
        (Ok((k, _)), Err(label)) if k.class == C::ClassicalQuantumVulnerable => {
            hybrid(k.clone(), unidentified(label))
        }
        (Err(label), Ok((a, _))) if matches!(a.class, C::PostQuantum(_)) => {
            hybrid(unidentified(label), a.clone())
        }
        _ => vec![ke.clone(), add.clone()],
    }
}

/// One TLS group or signature scheme a cipher suite offers: the algorithm
/// it stands for, or the label to report as unverifiable.
type TlsOffer = Result<AlgorithmClassification, String>;

/// The TLS groups and the TLS signature schemes a cipher suite offers
/// (CycloneDX 1.7 `tlsGroups` and `tlsSignatureSchemes`), each list with the
/// words that name it in a finding, the suffix that tells its PROTO-002
/// finding apart from the suite's other ones (see [`cipher_suite_detail`]),
/// and what its entries are for: key agreement or signatures.
/// TLS 1.3 negotiates its key exchange and
/// its authentication through exactly these, so every entry — an
/// alternative a peer may negotiate — is judged on its own, by the
/// algorithm its IANA registry entry stands for. An entry the registry does
/// not identify, or that names an obsolete pre-standard draft (the Kyber
/// groups, which are not ML-KEM), is reported as unverifiable. A GREASE
/// value (RFC 8701 §2) is skipped: no peer negotiates it, so it is no
/// alternative at all.
fn tls_offers(
    suite: &CipherSuite,
) -> [(&'static str, &'static str, CryptoPrimitive, Vec<TlsOffer>); 2] {
    let judge = |kind: &str, ids: &[String], lookup: fn(&str) -> Option<TlsRegistryEntry>| {
        ids.iter()
            .filter(|id| !is_tls_grease(id))
            .map(|id| match lookup(id) {
                Some(TlsRegistryEntry {
                    classification: Some(cls),
                    ..
                }) => Ok(cls),
                Some(entry) => {
                    let named = if entry.name.eq_ignore_ascii_case(id.trim()) {
                        String::new()
                    } else {
                        format!("{}, ", entry.name)
                    };
                    Err(format!(
                        "{kind} '{id}' ({named}an obsolete pre-standard draft)"
                    ))
                }
                None => Err(format!("{kind} '{id}'")),
            })
            .collect()
    };
    [
        (
            "TLS groups",
            "tls-groups",
            CryptoPrimitive::KeyAgree,
            judge("TLS group", &suite.tls_groups, tls_named_group),
        ),
        (
            "TLS signature schemes",
            "tls-signature-schemes",
            CryptoPrimitive::Signature,
            judge(
                "TLS signature scheme",
                &suite.tls_signature_schemes,
                tls_signature_scheme,
            ),
        ),
    ]
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
/// size when no parameter set is present. A keyed construction (HMAC,
/// HKDF, CMAC, …) is judged by the primitive it is built on: CNSA 2.0
/// approves only SHA-384 and SHA-512 for hashing and AES-256 as the block
/// cipher (CNSA 2.0 FAQ, Dec 2024), so HMAC-SHA-384 passes and
/// HMAC-SHA-256 fails on its SHA-256.
fn cnsa2_verdict(cls: &AlgorithmClassification, classical_bits: Option<u32>) -> CnsaVerdict {
    use AlgorithmClass as C;
    if cls.family.is_none()
        && let Some(construction) = cls.construction.as_deref()
    {
        return unspecified_construction_verdict(construction);
    }
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
                    let built_with = cls
                        .construction
                        .as_deref()
                        .map(|c| format!("{c}-"))
                        .unwrap_or_default();
                    CnsaVerdict::NotApproved {
                        rule_id: "SBOM-CNSA2-ALG-001",
                        detail: format!(
                            "uses {built_with}AES-{shown}, CNSA 2.0 requires AES-256 only"
                        ),
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
            Some(_) => {
                // Name the digest itself, also when a construction wraps it:
                // "HMAC-SHA-256, built on SHA-256, a SHA-2 digest …".
                let subject = match cls.construction {
                    Some(_) => format!("{}, built on {}", cls.label(), cls.primitive_label()),
                    None => cls.label(),
                };
                CnsaVerdict::NotApproved {
                    rule_id: "SBOM-CNSA2-ALG-002",
                    detail: format!(
                        "uses {subject}, a SHA-2 digest < 384 bits, CNSA 2.0 requires \
                         SHA-384 or SHA-512"
                    ),
                }
            }
            None => CnsaVerdict::NotApproved {
                rule_id: "SBOM-CNSA2-ALG-002",
                detail: format!(
                    "uses {} with an unspecified digest size, CNSA 2.0 requires SHA-384 or \
                     SHA-512",
                    cls.label()
                ),
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
        C::Hybrid => cls.hybrid_parts().map_or(CnsaVerdict::Unknown, |parts| {
            cnsa2_hybrid_verdict(cls, parts)
        }),
        C::Unknown => CnsaVerdict::Unknown,
    }
}

/// CNSA 2.0 verdict on a PQ/T hybrid. CNSA 2.0 admits hybrids without
/// requiring them — NSA "will not require NSS developers to use hybrid
/// certified products for security purposes" (CNSA 2.0 FAQ, Dec 2024) — and
/// its IPsec profile is one: an RFC 9370 additional ML-KEM-1024 exchange
/// after a CNSA 1.0 key exchange, ECDH P-384 or a 3072/4096-bit MODP group
/// (draft-guthrie-cnsa2-ipsec-profile-04 §4, §6.2). So a hybrid is
/// approved when its post-quantum part is on the CNSA 2.0 allowlist
/// (ML-KEM-1024, ML-DSA-87, …) and its classical part is a CNSA 1.0
/// algorithm ([`cnsa1_acceptable`]); otherwise the verdict names the parts
/// that fail. A part that cannot be identified leaves the verdict unknown
/// unless the other part already fails.
///
/// This judges algorithms, not conformance to a protocol profile: NSA's
/// TLS 1.3 and SSH profiles negotiate ML-KEM-1024 alone
/// (draft-becker-cnsa2-tls-profile-05 §7.2, draft-becker-cnsa2-ssh-profile-05
/// §5.1), so SecP384r1MLKEM1024 passes here as an algorithm while a
/// profile-conformant TLS server would not offer it.
fn cnsa2_hybrid_verdict(cls: &AlgorithmClassification, parts: &HybridParts) -> CnsaVerdict {
    use AlgorithmClass as C;
    let (classical, pq) = (&parts.classical, &parts.post_quantum);
    let (pq_rule, pq_problem) = match cnsa2_verdict(pq, None) {
        CnsaVerdict::Approved => (None, None),
        CnsaVerdict::NotApproved { rule_id, .. } => {
            (Some(rule_id), Some(cnsa2_hybrid_pq_problem(pq)))
        }
        CnsaVerdict::Unknown => (
            None,
            Some(format!(
                "{} is not a recognized post-quantum algorithm",
                pq.label()
            )),
        ),
    };
    let classical_ok = cnsa1_acceptable(classical);
    let classical_fails = !classical_ok && classical.class != C::Unknown;
    if pq_problem.is_none() && classical_ok {
        return CnsaVerdict::Approved;
    }
    // Nothing that is known fails, yet a part cannot be identified.
    if !classical_fails && (pq_problem.is_none() || pq.class == C::Unknown) {
        return CnsaVerdict::Unknown;
    }
    let mut problems: Vec<String> = pq_problem.into_iter().collect();
    if !classical_ok {
        problems.push(if classical.class == C::Unknown {
            format!("{} cannot be identified", classical.label())
        } else {
            format!(
                "{} is not a CNSA 1.0 algorithm (ECDH or ECDSA over P-384, or RSA or DH of \
                 3072 bits or more)",
                classical.label()
            )
        });
    }
    CnsaVerdict::NotApproved {
        rule_id: pq_rule.unwrap_or_else(|| cnsa2_hybrid_rule(parts)),
        detail: format!(
            "uses the hybrid {}, which CNSA 2.0 does not approve: {}",
            cls.label(),
            problems.join(", and ")
        ),
    }
}

/// Why a recognized post-quantum part keeps a hybrid off the CNSA 2.0
/// allowlist.
fn cnsa2_hybrid_pq_problem(pq: &AlgorithmClassification) -> String {
    let (required, family) = match pq.class {
        AlgorithmClass::PostQuantum(PqcKind::MlKem) => ("ML-KEM-1024", "ML-KEM"),
        AlgorithmClass::PostQuantum(PqcKind::MlDsa) => ("ML-DSA-87", "ML-DSA"),
        _ => return format!("{} is not a CNSA 2.0 algorithm", pq.label()),
    };
    match pq.parameter.as_deref() {
        Some(_) => format!("{} is not {required}", pq.label()),
        None => format!("{family} of an unspecified parameter set is not shown to be {required}"),
    }
}

/// The rule a hybrid fails when its post-quantum part passes or cannot be
/// identified: the key-establishment rule for a KEM hybrid, the signature
/// rule for a composite signature (by the post-quantum part, else the
/// classical one), and the general rule when neither tells.
fn cnsa2_hybrid_rule(parts: &HybridParts) -> &'static str {
    match parts.post_quantum.class {
        AlgorithmClass::PostQuantum(PqcKind::MlKem) => "SBOM-CNSA2-ALG-003",
        AlgorithmClass::PostQuantum(_) => "SBOM-CNSA2-ALG-004",
        _ => match parts.classical.family.as_deref() {
            Some("ECDH" | "X25519" | "X448" | "DH" | "MQV" | "ECMQV") => "SBOM-CNSA2-ALG-003",
            Some("ECDSA" | "EDDSA" | "ED25519" | "ED448" | "DSA") => "SBOM-CNSA2-ALG-004",
            _ => "SBOM-CNSA2-ALG-008",
        },
    }
}

/// Whether the classical part of a hybrid is a CNSA 1.0 algorithm — what
/// NSA's IPsec profile pairs with ML-KEM-1024 (ECDH P-384, DH with a
/// 3072/4096-bit MODP group) and CNSA 1.0's signatures (ECDSA P-384, RSA
/// of 3072 bits or more). CNSA 1.0 sets RSA and DH at a 3072-bit minimum,
/// so larger moduli pass too; P-521, brainpool, X25519/X448 and EdDSA were
/// never CNSA. AES-256 and SHA-384/512 complete the CNSA 1.0 list.
fn cnsa1_acceptable(classical: &AlgorithmClassification) -> bool {
    match classical.family.as_deref() {
        Some("ECDH" | "ECDSA" | "EC") => classical.parameter.as_deref().is_some_and(|curve| {
            let curve = curve.rsplit('/').next().unwrap_or(curve);
            ["P-384", "P384", "secp384r1", "nistp384", "ansip384r1"]
                .iter()
                .any(|p384| curve.eq_ignore_ascii_case(p384))
        }),
        Some("RSA" | "DH") => classical.parameter_bits().is_some_and(|bits| bits >= 3072),
        _ => {
            matches!(
                classical.class,
                AlgorithmClass::Symmetric | AlgorithmClass::Sha2
            ) && matches!(cnsa2_verdict(classical, None), CnsaVerdict::Approved)
        }
    }
}

/// What NIST PQC readiness judges a classification by: a PQ/T hybrid by
/// its post-quantum part, anything else by itself. NIST approves the
/// combination when one part is approved — SP 800-227 §4.6.2 approves key
/// combiners when at least one shared secret comes from an approved KEM
/// such as ML-KEM, and NIST IR 8547 §3.2.2 (final, Oct 2026) accommodates
/// dual signatures "provided that at least one component digital signature
/// algorithm is NIST-approved" — while the quantum resistance is the
/// post-quantum part's alone. So a hybrid whose post-quantum part is
/// approved passes, and one whose post-quantum part is not approved or not
/// recognized is no better than that part.
fn pqc_subject(cls: &AlgorithmClassification) -> &AlgorithmClassification {
    cls.hybrid_parts().map_or(cls, |parts| &parts.post_quantum)
}

/// CNSA 2.0 verdict on a keyed construction that names no primitive: it
/// cannot be shown to be built on an approved one. Like a SHA-2 or AES
/// asset of unspecified size, it fails the rule of the primitive it is
/// missing — the hash for HMAC and the constructions built on it, the
/// block cipher for CMAC — and the general rule when it takes either.
fn unspecified_construction_verdict(construction: &str) -> CnsaVerdict {
    let (rule_id, primitive, required) = if construction.ends_with("CMAC") {
        ("SBOM-CNSA2-ALG-001", "block cipher", "AES-256")
    } else if ["HMAC", "HKDF", "PBKDF2", "PBMAC1"]
        .iter()
        .any(|hash_based| construction.ends_with(hash_based))
    {
        ("SBOM-CNSA2-ALG-002", "hash function", "SHA-384 or SHA-512")
    } else {
        (
            "SBOM-CNSA2-ALG-008",
            "hash function or block cipher",
            "SHA-384, SHA-512 or AES-256",
        )
    };
    CnsaVerdict::NotApproved {
        rule_id,
        detail: format!(
            "uses {construction} with an unspecified {primitive}, CNSA 2.0 requires {required}"
        ),
    }
}

// ════════════════════════════════════════════════════════════════════
// Deadline mode (`--pqc-mode deadline`, see `pqc_calendar`)
// ════════════════════════════════════════════════════════════════════

/// The quantum-vulnerable public-key families NIST IR 8547 lists: ECDSA,
/// EdDSA and RSA signatures (Table 2), finite-field and elliptic-curve DH
/// and MQV and RSA key establishment (Table 4), and the bare curve
/// classification EC, which names one of them. X25519 and X448 are
/// elliptic-curve DH. DSA is not listed: FIPS 186-5 no longer approves it
/// for signature generation.
const IR8547_PUBLIC_KEY_FAMILIES: &[&str] = &[
    "RSA", "ECDSA", "EDDSA", "ED25519", "ED448", "ECDH", "X25519", "X448", "DH", "MQV", "ECMQV",
    "EC",
];

/// What a component declares beside its algorithm's identity, which
/// deadline mode reads for the algorithm's use and size.
#[derive(Debug, Clone, Default)]
struct Declared {
    /// The CycloneDX `primitive`.
    primitive: Option<CryptoPrimitive>,
    /// The declared `classicalSecurityLevel`.
    classical_bits: Option<u32>,
    /// The declared `ellipticCurve`, which a declared family hides from the
    /// classification.
    curve: Option<String>,
}

impl Declared {
    fn of(comp: &Component) -> Self {
        let algo = comp
            .crypto_properties
            .as_ref()
            .and_then(|c| c.algorithm_properties.as_ref());
        Self {
            primitive: algo.map(|a| a.primitive.clone()),
            classical_bits: algo.and_then(|a| a.classical_security_level),
            curve: algo.and_then(|a| a.elliptic_curve.clone()),
        }
    }

    /// What the component a bom-ref resolves to declares. A ref that
    /// resolves nowhere declares the curve it names, if any: "ecdsa-p384"
    /// is classified as ECDSA, its first mention, beside the curve P-384.
    fn of_ref(bom_ref: &str, sbom: &NormalizedSbom, index: &NormalizedSbomIndex) -> Self {
        resolve_component(bom_ref, sbom, index).map_or_else(
            || Self {
                curve: classify_algorithm_names_guarded(bom_ref)
                    .into_iter()
                    .find(|m| m.family.as_deref() == Some("EC"))
                    .and_then(|m| m.parameter),
                ..Self::default()
            },
            Self::of,
        )
    }

    /// One whose only declaration is its primitive, as a TLS signature
    /// scheme or group declares what it is for.
    const fn used_for(primitive: CryptoPrimitive) -> Self {
        Self {
            primitive: Some(primitive),
            classical_bits: None,
            curve: None,
        }
    }

    /// Declared to sign: a signature asset, or a TLS signature scheme.
    fn signs(&self) -> bool {
        self.primitive == Some(CryptoPrimitive::Signature)
    }
}

/// What a quantum-vulnerable algorithm is used for: its declared primitive,
/// else what its family does. RSA and a bare curve can do either.
fn pk_use(cls: &AlgorithmClassification, declared: &Declared) -> PkUse {
    match &declared.primitive {
        Some(CryptoPrimitive::Signature) => return PkUse::Signature,
        Some(CryptoPrimitive::Kem | CryptoPrimitive::KeyAgree | CryptoPrimitive::Pke) => {
            return PkUse::KeyEstablishment;
        }
        _ => {}
    }
    match cls.family.as_deref() {
        Some("ECDSA" | "EDDSA" | "ED25519" | "ED448") => PkUse::Signature,
        Some("ECDH" | "X25519" | "X448" | "DH" | "MQV" | "ECMQV") => PkUse::KeyEstablishment,
        _ => PkUse::Unstated,
    }
}

/// The classical security strength of an RSA or finite-field modulus of
/// `bits` (SP 800-57 Part 1 Rev. 5 Table 2), or 0 below 1024 bits.
const fn modulus_strength(bits: u32) -> u32 {
    match bits {
        0..1024 => 0,
        1024..2048 => 80,
        2048..3072 => 112,
        3072..7680 => 128,
        7680..15360 => 192,
        _ => 256,
    }
}

/// The classical security strength of an elliptic curve, from the field
/// size its name carries ("secp192r1", "P-521", "brainpoolP256r1"; SP
/// 800-57 Part 1 Rev. 5 Table 2), and 128 or 224 bits for Curve25519 and
/// Curve448. `None` when the name carries no size.
fn curve_strength(curve: &str) -> Option<u32> {
    let name = curve.rsplit('/').next().unwrap_or(curve);
    let sizes: Vec<u32> = name
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|run| run.parse().ok())
        .collect();
    if sizes.contains(&25519) {
        return Some(128);
    }
    if sizes.contains(&448) {
        return Some(224);
    }
    let field = sizes.into_iter().find(|f| *f >= 100)?;
    Some(match field {
        0..160 => 0,
        160..224 => 80,
        224..256 => 112,
        256..384 => 128,
        384..512 => 192,
        _ => 256,
    })
}

/// Whether the SBOM shows a quantum-vulnerable algorithm below 112 bits of
/// classical security, the floor of IR 8547's transition: its declared
/// `classicalSecurityLevel`, else what its modulus or curve gives.
fn below_112_bits(cls: &AlgorithmClassification, declared: &Declared) -> bool {
    let strength = declared
        .classical_bits
        .or_else(|| match cls.family.as_deref()? {
            "RSA" | "DH" | "MQV" => cls.parameter_bits().map(modulus_strength),
            "ED25519" | "X25519" => Some(128),
            "ED448" | "X448" => Some(224),
            _ => cls
                .parameter
                .as_deref()
                .or(declared.curve.as_deref())
                .and_then(curve_strength),
        });
    strength.is_some_and(|bits| bits < 112)
}

/// How deadline mode judges, on `on`, an algorithm NIST PQC reports as
/// quantum-vulnerable: a scheme IR 8547 lists, at 112 bits or more (or of
/// unknown strength), by its transition (or the federal deadline); anything
/// else is due now.
fn nist_quantum_vulnerable(
    calendar: &Calendar,
    cls: &AlgorithmClassification,
    declared: &Declared,
    on: NaiveDate,
) -> CalendarVerdict {
    let family = cls.family.as_deref();
    if cls.class != AlgorithmClass::ClassicalQuantumVulnerable {
        return CalendarVerdict::Undated(match family {
            Some(_) => format!(
                "no transition applies: it declares quantum security level 0, and NIST IR \
                 8547 lists no transition for {}",
                cls.label()
            ),
            None => "no transition applies: its algorithm cannot be identified".to_string(),
        });
    }
    match family {
        Some("DSA") => CalendarVerdict::Undated(
            "no transition applies: FIPS 186-5 no longer approves DSA for signature \
             generation, and NIST IR 8547 lists none for it"
                .to_string(),
        ),
        Some(f) if IR8547_PUBLIC_KEY_FAMILIES.contains(&f) => {
            if below_112_bits(cls, declared) {
                CalendarVerdict::Undated(
                    "no transition applies: below 112 bits of classical security it is \
                     already disallowed (SP 800-131A Rev. 2)"
                        .to_string(),
                )
            } else {
                CalendarVerdict::Dated(calendar.public_key(pk_use(cls, declared), on))
            }
        }
        _ => CalendarVerdict::Undated(format!(
            "no transition applies: NIST IR 8547 lists none for {}",
            cls.label()
        )),
    }
}

/// How deadline mode judges, on `on`, a broken algorithm under NIST PQC:
/// SHA-1 outside a signature by IR 8547 Table 8; anything else, SHA-1
/// signatures included, is disallowed now.
fn nist_broken(cls: &AlgorithmClassification, signs: bool, on: NaiveDate) -> CalendarVerdict {
    match cls.family.as_deref() {
        Some("SHA-1") if !signs => CalendarVerdict::Dated(Calendar::sha1(on)),
        Some("SHA-1") => CalendarVerdict::Undated(
            "no transition applies: SHA-1 signatures are disallowed already \
             (SP 800-131A Rev. 2)"
                .to_string(),
        ),
        _ => CalendarVerdict::Undated(format!(
            "no transition applies: no NIST standard allows {}",
            cls.label()
        )),
    }
}

/// Whether a classified algorithm is CNSA 1.0 ([`cnsa1_acceptable`]), with
/// what its component declares standing in for what the classification
/// lacks: the `ellipticCurve` for the curve, and 128 bits of classical
/// security or more for the RSA or DH modulus (3072 bits give 128).
fn cnsa1_with_evidence(cls: &AlgorithmClassification, declared: &Declared) -> bool {
    if cnsa1_acceptable(cls) {
        return true;
    }
    match cls.family.as_deref() {
        Some("ECDH" | "ECDSA" | "EC") if cls.parameter.is_none() => {
            declared.curve.as_deref().is_some_and(|curve| {
                cnsa1_acceptable(&AlgorithmClassification {
                    parameter: Some(curve.to_string()),
                    ..cls.clone()
                })
            })
        }
        Some("RSA" | "DH") if cls.parameter_bits().is_none() => {
            declared.classical_bits.is_some_and(|bits| bits >= 128)
        }
        _ => false,
    }
}

/// How deadline mode judges, on `on`, an algorithm CNSA 2.0 does not
/// approve: a quantum-vulnerable CNSA 1.0 algorithm by the timeline of its
/// equipment category; anything else is outside CNSA 1.0 as well, and due
/// now.
fn cnsa_not_approved(
    calendar: &Calendar,
    cls: &AlgorithmClassification,
    declared: &Declared,
    on: NaiveDate,
) -> CalendarVerdict {
    if cls.class == AlgorithmClass::ClassicalQuantumVulnerable && cnsa1_with_evidence(cls, declared)
    {
        CalendarVerdict::Dated(calendar.cnsa1(on))
    } else {
        CalendarVerdict::Undated(format!(
            "no transition applies: {} is not a CNSA 1.0 algorithm",
            cls.label()
        ))
    }
}

/// A certificate's `notValidAfter`, when it falls after the evaluation date:
/// the certificate keeps its signature until it expires, so deadline mode
/// judges it on the later of the two dates.
fn certificate_expiry_after_today(
    calendar: &Calendar,
    cert: Option<&CertificateProperties>,
) -> Option<NaiveDate> {
    cert.and_then(|c| c.not_valid_after)
        .map(|expiry| expiry.date_naive())
        .filter(|expiry| *expiry > calendar.today)
}

/// What a finding takes from deadline mode: its severity, the note its
/// message ends with, and its deadline. Readiness mode keeps the Error and
/// adds neither.
struct Calendared {
    severity: ViolationSeverity,
    note: String,
    deadline: Option<Deadline>,
}

impl Calendared {
    /// The finding as `verdict` judges it (`None` in readiness mode), on a
    /// certificate's later `expiry` when it was judged on that date.
    fn of(verdict: Option<CalendarVerdict>, expiry: Option<NaiveDate>) -> Self {
        match verdict {
            None => Self {
                severity: ViolationSeverity::Error,
                note: String::new(),
                deadline: None,
            },
            Some(CalendarVerdict::Dated(dated)) => Self {
                severity: dated.severity,
                note: match expiry {
                    Some(on) => format!(
                        "; valid until {on}, so judged on that date: {}",
                        dated.status
                    ),
                    None => format!("; {}", dated.status),
                },
                deadline: Some(dated.deadline),
            },
            Some(CalendarVerdict::Undated(reason)) => Self {
                severity: ViolationSeverity::Error,
                note: format!("; {reason}"),
                deadline: None,
            },
        }
    }

    /// The finding as the most urgent of `verdicts` judges it, for a
    /// protocol finding that names several algorithms; readiness mode when
    /// there are none.
    fn most_urgent(verdicts: impl IntoIterator<Item = Option<CalendarVerdict>>) -> Self {
        let verdict = verdicts
            .into_iter()
            .flatten()
            .reduce(CalendarVerdict::most_urgent);
        Self::of(verdict, None)
    }
}

/// One algorithm a protocol finding names, and how deadline mode judges it
/// (`None` in readiness mode).
struct Offender {
    label: String,
    verdict: Option<CalendarVerdict>,
}

/// Add `label` to a protocol finding's offenders, once.
fn add_offender(
    offenders: &mut Vec<Offender>,
    label: String,
    verdict: impl FnOnce() -> Option<CalendarVerdict>,
) {
    if !offenders.iter().any(|o| o.label == label) {
        offenders.push(Offender {
            label,
            verdict: verdict(),
        });
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

/// Finding detail of a PROTO-002 finding about one cipher suite, so a
/// protocol's suites keep a finding key each: what the SBOM calls the suite
/// — its name, else its IANA identifiers, else its algorithm references.
/// The suite's TLS groups and its signature schemes are judged in findings
/// of their own, whose details add `/tls-groups` and
/// `/tls-signature-schemes` to this one ([`tls_offers`]).
fn cipher_suite_detail(suite: &CipherSuite) -> String {
    match suite.name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ if !suite.identifiers.is_empty() => suite.identifiers.join(","),
        _ => suite.algorithms.join(","),
    }
}

/// Finding details of the PROTO-002 findings that judge a protocol's IKEv2
/// transforms and its crypto references as a whole (one each per protocol,
/// beside one per cipher suite).
const IKEV2_TRANSFORMS_DETAIL: &str = "ikev2-transforms";
const CRYPTO_REFS_DETAIL: &str = "crypto-refs";

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CNSA 2.0 compliance checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_cnsa2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ComponentType;

        let index = sbom.build_index();
        // Deadline mode's calendar; `None` in readiness mode.
        let calendar = self.pqc_calendar();
        let calendar = calendar.as_ref();

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
                    if Self::check_cnsa2_algorithm(comp, cp, calendar, violations) {
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
                                // Deadline mode judges a CNSA 1.0 signature
                                // on the later of the evaluation date and
                                // the certificate's expiry.
                                let expiry = calendar.and_then(|cal| {
                                    certificate_expiry_after_today(
                                        cal,
                                        cp.certificate_properties.as_ref(),
                                    )
                                });
                                let calendared = Calendared::of(
                                    calendar.map(|cal| {
                                        let declared = Declared::of_ref(sig_ref, sbom, &index);
                                        let on = expiry.unwrap_or(cal.today);
                                        cnsa_not_approved(cal, &cls, &declared, on)
                                    }),
                                    expiry,
                                );
                                violations.push(Violation {
                                    severity: calendared.severity,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "Certificate '{}' signed with non-CNSA 2.0 algorithm: \
                                         {detail}{} (ref: {sig_ref})",
                                        comp.name, calendared.note
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Certificate".to_string(),
                                    rule_id: "SBOM-CNSA2-CERT-001",
                                    component_id: Some(comp.canonical_id.value().to_string()),
                                    counts: None,
                                    standard_refs: Vec::new(),
                                    remediation: None,
                                    finding_detail: Some(sig_ref.to_string()),
                                    deadline: calendared.deadline,
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
                                    finding_detail: Some(sig_ref.to_string()),
                                    deadline: None,
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
                        && Self::check_cnsa2_protocol(
                            comp, proto, sbom, &index, calendar, violations,
                        )
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
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// Evaluate a single algorithm asset against the CNSA 2.0 allowlist plus
    /// the declared-quantum-level rules (ALG-006/ALG-007). Returns whether
    /// the asset was judged — classified, or declared quantum-vulnerable —
    /// which is what the CNSA2-000 inventory gate counts. Deadline mode
    /// (`calendar`) dates a rejected CNSA 1.0 algorithm.
    fn check_cnsa2_algorithm(
        comp: &Component,
        cp: &crate::model::CryptoProperties,
        calendar: Option<&Calendar>,
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
                            finding_detail: None,
                            deadline: None,
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
                        finding_detail: None,
                        deadline: None,
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
                // Deadline mode: a CNSA 1.0 algorithm keeps its place until
                // its category's exclusive-use date.
                let calendared = Calendared::of(
                    calendar
                        .map(|cal| cnsa_not_approved(cal, &cls, &Declared::of(comp), cal.today)),
                    None,
                );
                violations.push(Violation {
                    severity: calendared.severity,
                    category: ViolationCategory::CryptographyInfo,
                    message: format!("'{}' {detail}{}", comp.name, calendared.note),
                    element: Some(comp.name.clone()),
                    requirement: cnsa2_requirement(rule_id).to_string(),
                    rule_id,
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: calendared.deadline,
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
                    let what = if let Some(parts) = cls.hybrid_parts() {
                        let unidentified = if parts.post_quantum.class == AlgorithmClass::Unknown {
                            &parts.post_quantum
                        } else {
                            &parts.classical
                        };
                        format!(
                            "is a hybrid ({}) whose part {} cannot be identified",
                            cls.label(),
                            unidentified.label()
                        )
                    } else if hybrid {
                        "is a hybrid combiner whose component algorithms cannot be identified"
                            .to_string()
                    } else {
                        "cannot be classified (no recognizable algorithm family, OID, or name)"
                            .to_string()
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
                        finding_detail: None,
                        deadline: None,
                    });
                }
                declared_vulnerable
            }
        }
    }

    /// Evaluate a protocol asset under CNSA 2.0: TLS 1.3 required, and every
    /// resolvable cipher-suite algorithm / offered TLS group or signature
    /// scheme / IKEv2 transform / crypto reference must be on the
    /// allowlist. Returns whether the protocol was judged —
    /// failed on its version, or had at least one algorithm classified —
    /// which is what the CNSA2-000 inventory gate counts. Deadline mode
    /// (`calendar`) dates TLS 1.2 and the CNSA 1.0 algorithms, which CNSA 1.0
    /// still allows (RFC 9151 profiles TLS 1.2 and 1.3).
    fn check_cnsa2_protocol(
        comp: &Component,
        proto: &ProtocolProperties,
        sbom: &NormalizedSbom,
        index: &NormalizedSbomIndex,
        calendar: Option<&Calendar>,
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
                finding_detail: None,
                deadline: None,
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
            // Deadline mode: TLS 1.2, which CNSA 1.0 still allows, keeps its
            // place until the category's exclusive-use date.
            let tls12 = proto.version.as_deref().and_then(parse_tls_version) == Some((1, 2));
            let calendared = Calendared::of(
                calendar
                    .filter(|_| tls12)
                    .map(|cal| CalendarVerdict::Dated(cal.cnsa1(cal.today))),
                None,
            );
            violations.push(Violation {
                severity: calendared.severity,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses {} {shown}, CNSA 2.0 requires TLS 1.3{}",
                    comp.name,
                    proto.protocol_type.to_string().to_uppercase(),
                    calendared.note
                ),
                element: Some(comp.name.clone()),
                requirement: "CNSA 2.0 Protocol".to_string(),
                rule_id: "SBOM-CNSA2-PROTO-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: calendared.deadline,
            });
        }
        let version_rejected = violations.len() > violations_before;

        // Collect non-allowlisted algorithms per source, deduplicated by label.
        // One finding per source on the protocol, which `detail` names; in
        // deadline mode it takes the most urgent of its algorithms' verdicts.
        let mut push_proto_violation =
            |context: String, detail: String, offenders: Vec<Offender>| {
                if offenders.is_empty() {
                    return;
                }
                let labels: Vec<&str> = offenders.iter().map(|o| o.label.as_str()).collect();
                let message = format!(
                    "Protocol '{}' {context} non-CNSA 2.0 algorithms: {}",
                    comp.name,
                    labels.join(", ")
                );
                let calendared = Calendared::most_urgent(offenders.into_iter().map(|o| o.verdict));
                violations.push(Violation {
                    severity: calendared.severity,
                    category: ViolationCategory::CryptographyInfo,
                    message: format!("{message}{}", calendared.note),
                    element: Some(comp.name.clone()),
                    requirement: "CNSA 2.0 Protocol".to_string(),
                    rule_id: "SBOM-CNSA2-PROTO-002",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: Some(detail),
                    deadline: calendared.deadline,
                });
            };
        // References that resolve nowhere and carry no recognizable token
        // receive no effective check — collect them so the protocol warns
        // instead of silently satisfying the CNSA2-000 inventory gate.
        let mut unverifiable: Vec<String> = Vec::new();
        // How many algorithms the classifier could identify, approved or not.
        let judged = std::cell::Cell::new(0usize);
        // Hybrids with a part that cannot be identified, and no known part
        // that fails: unverifiable, like an opaque reference.
        let unidentified_hybrids = std::cell::RefCell::new(Vec::new());
        let record = |cls: &AlgorithmClassification,
                      bits: Option<u32>,
                      declared: &Declared,
                      offenders: &mut Vec<Offender>| {
            let verdict = cnsa2_verdict(cls, bits);
            if cls.class == AlgorithmClass::Hybrid && matches!(verdict, CnsaVerdict::Unknown) {
                unidentified_hybrids.borrow_mut().push(cls.label());
                return;
            }
            if cls.class != AlgorithmClass::Unknown {
                judged.set(judged.get() + 1);
            }
            if let CnsaVerdict::NotApproved { .. } = verdict {
                add_offender(offenders, cls.label(), || {
                    calendar.map(|cal| cnsa_not_approved(cal, cls, declared, cal.today))
                });
            }
        };

        // PROTO-002: cipher suites — both the algorithm refs (resolved
        // through the index, with the referenced asset's declared
        // classicalSecurityLevel as key-size evidence, or token-scanned when
        // unresolvable) and a word-boundary scan of the suite name — and the
        // TLS groups and signature schemes each suite offers.
        for suite in &proto.cipher_suites {
            let mut offenders = Vec::new();
            for algo_ref in &suite.algorithms {
                let (cls, bits) = classify_bom_ref(algo_ref, sbom, index);
                if cls.class == AlgorithmClass::Unknown {
                    unverifiable.push(algo_ref.clone());
                } else {
                    let declared = Declared::of_ref(algo_ref, sbom, index);
                    record(&cls, bits, &declared, &mut offenders);
                }
            }
            if let Some(name) = &suite.name {
                for cls in classify_algorithm_names(name) {
                    record(&cls, None, &Declared::default(), &mut offenders);
                }
            }
            push_proto_violation(
                format!(
                    "cipher suite '{}' includes",
                    suite.name.as_deref().unwrap_or("(unnamed)")
                ),
                cipher_suite_detail(suite),
                offenders,
            );
            for (offered, detail_suffix, primitive, offers) in tls_offers(suite) {
                let declared = Declared::used_for(primitive);
                let mut offenders = Vec::new();
                for offer in offers {
                    match offer {
                        Ok(cls) => record(&cls, None, &declared, &mut offenders),
                        Err(label) => unverifiable.push(label),
                    }
                }
                push_proto_violation(
                    format!(
                        "cipher suite '{}' offers {offered} with",
                        suite.name.as_deref().unwrap_or("(unnamed)")
                    ),
                    format!("{}/{detail_suffix}", cipher_suite_detail(suite)),
                    offenders,
                );
            }
        }

        // PROTO-002: IKEv2 transform types, with RFC 9370 additional key
        // exchanges judged as hybrids with the key exchange method.
        if let Some(ike) = &proto.ikev2_transform_types {
            let mut offenders = Vec::new();
            let key_exchange = Declared::used_for(CryptoPrimitive::KeyAgree);
            for judged_transform in ike_judged_transforms(ike, sbom, index) {
                match judged_transform {
                    Ok((cls, bits)) => record(&cls, bits, &key_exchange, &mut offenders),
                    Err(label) => unverifiable.push(label),
                }
            }
            push_proto_violation(
                "IKEv2 transforms include".to_string(),
                IKEV2_TRANSFORMS_DETAIL.to_string(),
                offenders,
            );
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
                            &Declared::of(target),
                            &mut offenders,
                        );
                    }
                }
                None => {
                    if let Some(cls) = worst_classification(classify_algorithm_names_guarded(r)) {
                        let declared = Declared::of_ref(r, sbom, index);
                        record(&cls, None, &declared, &mut offenders);
                    } else {
                        unverifiable.push(r.clone());
                    }
                }
            }
        }
        push_proto_violation(
            "references".to_string(),
            CRYPTO_REFS_DETAIL.to_string(),
            offenders,
        );
        unverifiable.extend(unidentified_hybrids.take());

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
                finding_detail: None,
                deadline: None,
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
                finding_detail: None,
                deadline: None,
            });
        }
        version_rejected || judged > 0
    }

    // ════════════════════════════════════════════════════════════════════
    // NIST PQC Readiness checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_nist_pqc(&self, sbom: &NormalizedSbom, findings: &mut Findings) {
        use crate::model::ComponentType;

        let Findings {
            violations, passed, ..
        } = findings;
        let index = sbom.build_index();
        // Deadline mode's calendar; `None` in readiness mode.
        let calendar = self.pqc_calendar();
        let calendar = calendar.as_ref();

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
                    if Self::check_pqc_algorithm(comp, cp, calendar, violations, passed) {
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
                        // A composite signature is judged by its
                        // post-quantum part.
                        let subject = pqc_subject(&cls);
                        judged |= subject.class != AlgorithmClass::Unknown;
                        let problem = match subject.class {
                            AlgorithmClass::Broken => Some("broken algorithm (SP 800-131A)"),
                            AlgorithmClass::ClassicalQuantumVulnerable => {
                                Some("quantum-vulnerable algorithm, must migrate to PQC (IR 8547)")
                            }
                            _ => None,
                        };
                        if let Some(problem) = problem {
                            // Deadline mode judges the signature on the later
                            // of the evaluation date and the certificate's
                            // expiry: it signs until then.
                            let expiry = calendar.and_then(|cal| {
                                certificate_expiry_after_today(
                                    cal,
                                    cp.certificate_properties.as_ref(),
                                )
                            });
                            let calendared = Calendared::of(
                                calendar.map(|cal| {
                                    let on = expiry.unwrap_or(cal.today);
                                    let declared = Declared {
                                        primitive: Some(CryptoPrimitive::Signature),
                                        ..Declared::of_ref(sig_ref, sbom, &index)
                                    };
                                    if subject.class == AlgorithmClass::Broken {
                                        nist_broken(subject, true, on)
                                    } else {
                                        nist_quantum_vulnerable(cal, subject, &declared, on)
                                    }
                                }),
                                expiry,
                            );
                            violations.push(Violation {
                                severity: calendared.severity,
                                category: ViolationCategory::CryptographyInfo,
                                message: format!(
                                    "Certificate '{}' signed with {} — {problem}{} (ref: {sig_ref})",
                                    comp.name,
                                    cls.label(),
                                    calendared.note
                                ),
                                element: Some(comp.name.clone()),
                                requirement: "IR 8547: certificate signature".to_string(),
                                rule_id: "SBOM-PQC-CERT-001",
                                component_id: Some(comp.canonical_id.value().to_string()),
                                counts: None,
                                standard_refs: Vec::new(),
                                remediation: None,
                                finding_detail: Some(sig_ref.to_string()),
                                deadline: calendared.deadline,
                            });
                        } else if subject.class == AlgorithmClass::Unknown {
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
                                finding_detail: Some(sig_ref.to_string()),
                                deadline: None,
                            });
                        }
                    }
                    if judged {
                        crypto_assets_evaluated += 1;
                    }
                }
                CryptoAssetType::Protocol => {
                    if let Some(proto) = &cp.protocol_properties
                        && Self::check_pqc_protocol(comp, proto, sbom, &index, calendar, violations)
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
                                // Deadline mode: IR 8547 §4.1.3 disallows the
                                // 112-bit security level after 2030; a
                                // smaller key is disallowed already.
                                let calendared = Calendared::of(
                                    calendar.map(|cal| {
                                        if size >= 112 {
                                            CalendarVerdict::Dated(Calendar::symmetric_112(
                                                cal.today,
                                            ))
                                        } else {
                                            CalendarVerdict::Undated(
                                                "no transition applies: below 112 bits it is \
                                                 already disallowed (SP 800-131A Rev. 2)"
                                                    .to_string(),
                                            )
                                        }
                                    }),
                                    None,
                                );
                                violations.push(Violation {
                                    severity: calendared.severity,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' symmetric key size {} bits < 128 minimum{}",
                                        comp.name, size, calendared.note
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "NIST: minimum key size".to_string(),
                                    rule_id: "SBOM-PQC-KEY-001",
                                    component_id: Some(comp.canonical_id.value().to_string()),
                                    counts: None,
                                    standard_refs: Vec::new(),
                                    remediation: None,
                                    finding_detail: None,
                                    deadline: calendared.deadline,
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
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// Evaluate a single algorithm asset for NIST PQC readiness: problems go
    /// to `violations`, the approvals of SBOM-PQC-009 and SBOM-PQC-010 to
    /// `passed`. Returns whether the asset was judged — classified, or
    /// declared quantum-vulnerable — which is what the PQC-000 inventory gate
    /// counts. Deadline mode (`calendar`) dates the quantum-vulnerable
    /// algorithms IR 8547 lists and SHA-1.
    fn check_pqc_algorithm(
        comp: &Component,
        cp: &crate::model::CryptoProperties,
        calendar: Option<&Calendar>,
        violations: &mut Vec<Violation>,
        passed: &mut Vec<PassedCheck>,
    ) -> bool {
        let algo = cp.algorithm_properties.as_ref();
        let cls = classify_crypto_component(comp);
        let ql = algo.and_then(|a| a.nist_quantum_security_level);
        // A PQ/T hybrid is judged by its post-quantum part.
        let subject = pqc_subject(&cls);

        // PQC-ALG-UNKNOWN: an algorithm the classifier cannot name used to
        // pass silently whenever it declared a quantum level. It cannot be
        // verified, so it warns and does not count as inventory. A declared
        // level 0 is judged by PQC-001 below instead. A hybrid whose
        // post-quantum part is not recognized is as unverifiable, and so is
        // a declared hybrid combiner whose parts cannot be identified.
        let combiner = algo.is_some_and(AlgorithmProperties::is_hybrid_pqc);
        if subject.class == AlgorithmClass::Unknown && ql != Some(0) {
            let what = if cls.class == AlgorithmClass::Hybrid {
                format!(
                    "is a hybrid ({}) whose post-quantum part {} is not a recognized \
                     post-quantum algorithm",
                    cls.label(),
                    subject.label()
                )
            } else if combiner {
                "is a hybrid combiner whose component algorithms cannot be identified".to_string()
            } else {
                "cannot be classified (no recognizable algorithm family, OID, or name)".to_string()
            };
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::CryptographyInfo,
                message: format!("'{}' {what}; unable to verify PQC readiness", comp.name),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: algorithm identification".to_string(),
                rule_id: "SBOM-PQC-ALG-UNKNOWN",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
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
            // Deadline mode: IR 8547 Tables 2 and 4 (or the federal
            // deadlines) date the schemes they list.
            let calendared = Calendared::of(
                calendar
                    .map(|cal| nist_quantum_vulnerable(cal, &cls, &Declared::of(comp), cal.today)),
                None,
            );
            violations.push(Violation {
                severity: calendared.severity,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' ({shown}) is quantum-vulnerable and must migrate to PQC (IR 8547){}",
                    comp.name, calendared.note
                ),
                element: Some(comp.name.clone()),
                requirement: "IR 8547: quantum-vulnerable".to_string(),
                rule_id: "SBOM-PQC-001",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: calendared.deadline,
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
                finding_detail: None,
                deadline: None,
            });
        }

        // PQC-005: broken/disallowed algorithms per SP 800-131A, via the
        // shared classifier (catches spelling variants like "SHA1"/"TDES"/
        // "ARC4" and OID/name-only CycloneDX 1.6 assets).
        if cls.class == AlgorithmClass::Broken {
            // Deadline mode: IR 8547 Table 8 dates SHA-1 outside a
            // signature; everything else here is disallowed already.
            let signs = Declared::of(comp).signs();
            let calendared = Calendared::of(
                calendar.map(|cal| nist_broken(&cls, signs, cal.today)),
                None,
            );
            violations.push(Violation {
                severity: calendared.severity,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "'{}' ({}) is broken/disallowed per SP 800-131A{}",
                    comp.name,
                    cls.label(),
                    calendared.note
                ),
                element: Some(comp.name.clone()),
                requirement: "SP 800-131A: disallowed".to_string(),
                rule_id: "SBOM-PQC-005",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: calendared.deadline,
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
                finding_detail: None,
                deadline: None,
            });
        }

        // PQC-009: approved PQC, a passed check. FIPS 203/204/205 finals and
        // the SP 800-208 stateful hash-based signatures both qualify; FN-DSA
        // (Falcon) is recognized but not yet standardized, so it passes no
        // approval.
        if let AlgorithmClass::PostQuantum(kind) = cls.class {
            let approval = match kind {
                PqcKind::MlKem | PqcKind::MlDsa | PqcKind::SlhDsa => Some("FIPS 203/204/205"),
                PqcKind::Lms | PqcKind::Xmss | PqcKind::Hss => {
                    Some("SP 800-208 stateful hash-based signature")
                }
                PqcKind::FnDsa => None,
            };
            if let Some(approval) = approval {
                passed.push(PassedCheck {
                    rule_id: "SBOM-PQC-009",
                    message: format!(
                        "'{}' uses NIST-approved PQC algorithm ({approval})",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    component_id: Some(comp.canonical_id.value().to_string()),
                    finding_detail: None,
                    requirement: "FIPS 203/204/205: approved".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // PQC-010: a PQ/T hybrid whose post-quantum part NIST approves is an
        // approved combination, a passed check — SP 800-227 §4.6.2 for key
        // establishment, IR 8547 §3.2.2 for composite signatures — and
        // so is a declared combiner classified as an approved post-quantum
        // algorithm. A hybrid whose post-quantum part is not approved passes
        // no approval, like that part alone.
        let approval = match subject.class {
            AlgorithmClass::PostQuantum(PqcKind::MlKem) => Some("FIPS 203"),
            AlgorithmClass::PostQuantum(PqcKind::MlDsa) => Some("FIPS 204"),
            AlgorithmClass::PostQuantum(PqcKind::SlhDsa) => Some("FIPS 205"),
            AlgorithmClass::PostQuantum(PqcKind::Lms | PqcKind::Xmss | PqcKind::Hss) => {
                Some("SP 800-208")
            }
            _ => None,
        };
        if let Some(approval) = approval
            && (cls.class == AlgorithmClass::Hybrid || combiner)
        {
            let message = if cls.class == AlgorithmClass::Hybrid {
                let combination = if subject.class == AlgorithmClass::PostQuantum(PqcKind::MlKem) {
                    "SP 800-227 §4.6.2 approves the key combination"
                } else {
                    "IR 8547 §3.2.2 accepts the composite signature"
                };
                format!(
                    "'{}' is a PQ/T hybrid ({}) whose post-quantum part is NIST-approved \
                     ({approval}); {combination}",
                    comp.name,
                    cls.label()
                )
            } else {
                format!(
                    "'{}' is a hybrid PQC combiner with a NIST-approved post-quantum part \
                     ({approval}) — good migration practice",
                    comp.name
                )
            };
            passed.push(PassedCheck {
                rule_id: "SBOM-PQC-010",
                message,
                element: Some(comp.name.clone()),
                component_id: Some(comp.canonical_id.value().to_string()),
                finding_detail: None,
                requirement: "SP 800-227 / IR 8547: PQ/T hybrid".to_string(),
                standard_refs: Vec::new(),
            });
        }
        subject.class != AlgorithmClass::Unknown || ql == Some(0)
    }

    /// Evaluate a protocol asset for PQC readiness: no SSL / TLS below 1.2,
    /// and no broken or quantum-vulnerable algorithms in cipher suites, the
    /// TLS groups and signature schemes they offer, IKEv2 transforms, or
    /// crypto references. Deadline mode (`calendar`) dates those
    /// algorithms, and under the federal profile reports TLS 1.2 against
    /// the TLS 1.3 deadline (SBOM-PQC-PROTO-003).
    ///
    /// Returns whether the protocol was judged — failed on its version, or
    /// had at least one algorithm classified — which is what the PQC-000
    /// inventory gate counts.
    fn check_pqc_protocol(
        comp: &Component,
        proto: &ProtocolProperties,
        sbom: &NormalizedSbom,
        index: &NormalizedSbomIndex,
        calendar: Option<&Calendar>,
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
                finding_detail: None,
                deadline: None,
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
                finding_detail: None,
                deadline: None,
            });
        }
        let version_rejected = violations.len() > violations_before;

        // PQC-PROTO-003, under `--pqc-profile federal` only: federal
        // agencies support TLS 1.3 by 2030-01-02 (EO 14306, OMB M-26-15).
        // TLS below 1.2 already fails PQC-PROTO-001; DTLS is not named.
        if let Some(dated) = calendar.and_then(Calendar::federal_tls13)
            && proto.protocol_type == ProtocolType::Tls
            && proto.version.as_deref().and_then(parse_tls_version) == Some((1, 2))
        {
            let version = proto.version.as_deref().unwrap_or_default();
            violations.push(Violation {
                severity: dated.severity,
                category: ViolationCategory::CryptographyInfo,
                message: format!(
                    "Protocol '{}' uses TLS version {version}; {}",
                    comp.name, dated.status
                ),
                element: Some(comp.name.clone()),
                requirement: "OMB M-26-15: TLS 1.3".to_string(),
                rule_id: "SBOM-PQC-PROTO-003",
                component_id: Some(comp.canonical_id.value().to_string()),
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: Some(dated.deadline),
            });
        }

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

        // One finding per source on the protocol, which `detail` names; in
        // deadline mode it takes the most urgent of its algorithms' verdicts.
        let mut push_proto_violation =
            |context: String, detail: String, offenders: Vec<Offender>| {
                if offenders.is_empty() {
                    return;
                }
                let labels: Vec<&str> = offenders.iter().map(|o| o.label.as_str()).collect();
                let message = format!(
                    "Protocol '{}' {context} broken or quantum-vulnerable algorithms: {}",
                    comp.name,
                    labels.join(", ")
                );
                let calendared = Calendared::most_urgent(offenders.into_iter().map(|o| o.verdict));
                violations.push(Violation {
                    severity: calendared.severity,
                    category: ViolationCategory::CryptographyInfo,
                    message: format!("{message}{}", calendared.note),
                    element: Some(comp.name.clone()),
                    requirement: "IR 8547 / SP 800-131A: protocol algorithms".to_string(),
                    rule_id: "SBOM-PQC-PROTO-002",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: Some(detail),
                    deadline: calendared.deadline,
                });
            };
        // How many algorithms the classifier could identify, ready or not.
        let judged = std::cell::Cell::new(0usize);
        // Hybrids whose post-quantum part is not recognized: unverifiable,
        // like an opaque reference.
        let unidentified_hybrids = std::cell::RefCell::new(Vec::new());
        let record =
            |cls: &AlgorithmClassification, declared: &Declared, offenders: &mut Vec<Offender>| {
                // A PQ/T hybrid is judged by its post-quantum part.
                let subject = pqc_subject(cls);
                if cls.class == AlgorithmClass::Hybrid && subject.class == AlgorithmClass::Unknown {
                    unidentified_hybrids.borrow_mut().push(cls.label());
                    return;
                }
                if cls.class != AlgorithmClass::Unknown {
                    judged.set(judged.get() + 1);
                }
                let tag = match subject.class {
                    AlgorithmClass::Broken => Some("broken"),
                    AlgorithmClass::ClassicalQuantumVulnerable => Some("quantum-vulnerable"),
                    _ => None,
                };
                if let Some(tag) = tag {
                    add_offender(offenders, format!("{} ({tag})", cls.label()), || {
                        calendar.map(|cal| {
                            if subject.class == AlgorithmClass::Broken {
                                nist_broken(subject, declared.signs(), cal.today)
                            } else {
                                nist_quantum_vulnerable(cal, subject, declared, cal.today)
                            }
                        })
                    });
                }
            };

        for suite in &proto.cipher_suites {
            let mut offenders = Vec::new();
            for algo_ref in &suite.algorithms {
                let (cls, _) = classify_bom_ref(algo_ref, sbom, index);
                if cls.class == AlgorithmClass::Unknown {
                    unverifiable.push(algo_ref.clone());
                } else {
                    record(
                        &cls,
                        &Declared::of_ref(algo_ref, sbom, index),
                        &mut offenders,
                    );
                }
            }
            // A suite name's SHA is its record MAC, not a signature.
            if let Some(name) = &suite.name {
                for cls in classify_algorithm_names(name) {
                    record(&cls, &Declared::default(), &mut offenders);
                }
            }
            push_proto_violation(
                format!(
                    "cipher suite '{}' includes",
                    suite.name.as_deref().unwrap_or("(unnamed)")
                ),
                cipher_suite_detail(suite),
                offenders,
            );
            // The TLS groups and signature schemes offered with the suite.
            for (offered, detail_suffix, primitive, offers) in tls_offers(suite) {
                let declared = Declared::used_for(primitive);
                let mut offenders = Vec::new();
                for offer in offers {
                    match offer {
                        Ok(cls) => record(&cls, &declared, &mut offenders),
                        Err(label) => unverifiable.push(label),
                    }
                }
                push_proto_violation(
                    format!(
                        "cipher suite '{}' offers {offered} with",
                        suite.name.as_deref().unwrap_or("(unnamed)")
                    ),
                    format!("{}/{detail_suffix}", cipher_suite_detail(suite)),
                    offenders,
                );
            }
        }

        // IKEv2 key exchange methods establish keys; its SHA-1 is a PRF or
        // an integrity MAC.
        if let Some(ike) = &proto.ikev2_transform_types {
            let mut offenders = Vec::new();
            let key_exchange = Declared::used_for(CryptoPrimitive::KeyAgree);
            for judged_transform in ike_judged_transforms(ike, sbom, index) {
                match judged_transform {
                    Ok((cls, _)) => record(&cls, &key_exchange, &mut offenders),
                    Err(label) => unverifiable.push(label),
                }
            }
            push_proto_violation(
                "IKEv2 transforms include".to_string(),
                IKEV2_TRANSFORMS_DETAIL.to_string(),
                offenders,
            );
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
                        record(
                            &classify_crypto_component(target),
                            &Declared::of(target),
                            &mut offenders,
                        );
                    }
                }
                None => {
                    if let Some(cls) = worst_classification(classify_algorithm_names_guarded(r)) {
                        record(&cls, &Declared::of_ref(r, sbom, index), &mut offenders);
                    } else {
                        unverifiable.push(r.clone());
                    }
                }
            }
        }
        push_proto_violation(
            "references".to_string(),
            CRYPTO_REFS_DETAIL.to_string(),
            offenders,
        );
        unverifiable.extend(unidentified_hybrids.take());

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
                finding_detail: None,
                deadline: None,
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
                finding_detail: None,
                deadline: None,
            });
        }
        version_rejected || judged.get() > 0
    }
}
