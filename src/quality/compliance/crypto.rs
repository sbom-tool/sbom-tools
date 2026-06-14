//! Cryptographic-suite compliance: NSA CNSA 2.0 and NIST PQC readiness.

use super::*;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CNSA 2.0 compliance checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_cnsa2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            match cp.asset_type {
                CryptoAssetType::Algorithm => {
                    if let Some(algo) = &cp.algorithm_properties {
                        // CNSA2-ALG-007: quantum security level must be >= 5
                        if let Some(ql) = algo.nist_quantum_security_level
                            && ql < 5
                        {
                            // Check if it's a symmetric/hash (allowed at lower levels)
                            let is_symmetric_or_hash = matches!(
                                algo.primitive,
                                crate::model::CryptoPrimitive::Ae
                                    | crate::model::CryptoPrimitive::BlockCipher
                                    | crate::model::CryptoPrimitive::Hash
                                    | crate::model::CryptoPrimitive::Mac
                                    | crate::model::CryptoPrimitive::Kdf
                            );
                            if !is_symmetric_or_hash && ql == 0 {
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
                                        standard_refs: Vec::new(),
                                    });
                            } else if !is_symmetric_or_hash && ql < 5 {
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
                                    standard_refs: Vec::new(),
                                });
                            }
                        }

                        // CNSA2-ALG-001: symmetric must be AES-256
                        if let Some(family) = &algo.algorithm_family {
                            let upper = family.to_uppercase();
                            if upper == "AES"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "256"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses AES-{}, CNSA 2.0 requires AES-256 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Symmetric".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-001",
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-002: hash must be SHA-384+
                            if (upper == "SHA-2" || upper == "SHA2")
                                && let Some(param) = &algo.parameter_set_identifier
                                && param == "256"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses SHA-256, CNSA 2.0 requires SHA-384 or SHA-512",
                                        comp.name
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Hash".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-002",
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-003: KEM must be ML-KEM-1024 only
                            if upper == "ML-KEM"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "1024"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses ML-KEM-{}, CNSA 2.0 requires ML-KEM-1024 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 KEM".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-003",
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-004: signature must be ML-DSA-87 only
                            if upper == "ML-DSA"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "87"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses ML-DSA-{}, CNSA 2.0 requires ML-DSA-87 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Signature".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-004",
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-006: quantum-vulnerable families
                            const CNSA2_VULNERABLE: &[&str] = &[
                                "RSA", "DSA", "DH", "ECDSA", "ECDH", "EDDSA", "X25519", "X448",
                            ];
                            if CNSA2_VULNERABLE.iter().any(|v| upper == *v) {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' ({}) is quantum-vulnerable, must migrate to CNSA 2.0 approved algorithm",
                                        comp.name, family
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 PQC Migration".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-006",
                                    standard_refs: Vec::new(),
                                });
                            }
                        }
                    }
                }
                CryptoAssetType::Certificate => {
                    // CNSA2-CERT-001: cert must use CNSA 2.0 signature algorithm
                    if let Some(cert) = &cp.certificate_properties
                        && let Some(sig_ref) = &cert.signature_algorithm_ref
                    {
                        // Check if the referenced algorithm is a quantum-vulnerable family
                        // Exclude ML-DSA (approved PQC) and SLH-DSA from false positives
                        let sig_lower = sig_ref.to_lowercase();
                        let is_pqc_sig = sig_lower.contains("ml-dsa")
                            || sig_lower.contains("slh-dsa")
                            || sig_lower.contains("lms")
                            || sig_lower.contains("xmss");
                        if !is_pqc_sig
                            && (sig_lower.contains("rsa")
                                || sig_lower.contains("ecdsa")
                                || sig_lower.contains("dsa"))
                        {
                            violations.push(Violation {
                                severity: ViolationSeverity::Error,
                                category: ViolationCategory::CryptographyInfo,
                                message: format!(
                                    "Certificate '{}' signed with non-CNSA 2.0 algorithm (ref: {})",
                                    comp.name, sig_ref
                                ),
                                element: Some(comp.name.clone()),
                                requirement: "CNSA 2.0 Certificate".to_string(),
                                rule_id: "SBOM-CNSA2-CERT-001",
                                standard_refs: Vec::new(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // NIST PQC Readiness checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_nist_pqc(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        /// Broken/disallowed algorithms per SP 800-131A
        const BROKEN: &[&str] = &[
            "MD5", "MD4", "MD2", "SHA-1", "DES", "3DES", "TDEA", "RC2", "RC4", "BLOWFISH", "IDEA",
            "CAST5",
        ];

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            if cp.asset_type == CryptoAssetType::Algorithm
                && let Some(algo) = &cp.algorithm_properties
            {
                // PQC-001: quantum-vulnerable algorithm
                if algo.nist_quantum_security_level == Some(0) {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' has nistQuantumSecurityLevel=0, quantum-vulnerable (IR 8547)",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: quantum-vulnerable".to_string(),
                        rule_id: "SBOM-PQC-001",
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-012: missing quantum security level
                if algo.nist_quantum_security_level.is_none() {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!("'{}' missing nistQuantumSecurityLevel field", comp.name),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: quantum assessment required".to_string(),
                        rule_id: "SBOM-PQC-012",
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-005/006/007: broken algorithms
                if let Some(family) = &algo.algorithm_family {
                    let upper = family.to_uppercase();
                    if BROKEN.iter().any(|b| upper == *b) {
                        violations.push(Violation {
                            severity: ViolationSeverity::Error,
                            category: ViolationCategory::CryptographyInfo,
                            message: format!(
                                "'{}' ({}) is broken/disallowed per SP 800-131A",
                                comp.name, family
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "SP 800-131A: disallowed".to_string(),
                            rule_id: "SBOM-PQC-005",
                            standard_refs: Vec::new(),
                        });
                    }
                }

                // PQC-008: ECB mode
                if algo.mode == Some(crate::model::CryptoMode::Ecb) {
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
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-009: approved PQC (informational)
                if let Some(family) = &algo.algorithm_family {
                    let upper = family.to_uppercase();
                    if matches!(upper.as_str(), "ML-KEM" | "ML-DSA" | "SLH-DSA") {
                        violations.push(Violation {
                            severity: ViolationSeverity::Info,
                            category: ViolationCategory::CryptographyInfo,
                            message: format!(
                                "'{}' uses NIST-approved PQC algorithm (FIPS 203/204/205)",
                                comp.name
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "FIPS 203/204/205: approved".to_string(),
                            rule_id: "SBOM-PQC-009",
                            standard_refs: Vec::new(),
                        });
                    }
                }

                // PQC-010: hybrid PQC combiner (informational)
                if algo.is_hybrid_pqc() {
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
                        standard_refs: Vec::new(),
                    });
                }
            }

            // PQC-KEY-001: symmetric key < 128 bits
            if cp.asset_type == CryptoAssetType::RelatedCryptoMaterial
                && let Some(mat) = &cp.related_crypto_material_properties
                && let Some(size) = mat.size
            {
                let is_symmetric = matches!(
                    mat.material_type,
                    crate::model::CryptoMaterialType::SymmetricKey
                        | crate::model::CryptoMaterialType::SecretKey
                );
                if is_symmetric && size < 128 {
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
                        standard_refs: Vec::new(),
                    });
                }
            }
        }
    }
}
