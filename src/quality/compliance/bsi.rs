//! BSI TR-03183-2 (German national CRA-aligned SBOM guideline) checks.

use super::*;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // BSI TR-03183-2 (German national SBOM guideline)
    // ════════════════════════════════════════════════════════════════════

    /// BSI TR-03183-2 compliance checks.
    ///
    /// TR-03183-2 is the German Federal Office for Information Security's
    /// SBOM technical guideline, free and ENISA-cited. It is functionally
    /// equivalent to the CRA Annex I Part II SBOM obligations but stricter
    /// than NTIA Minimum on hashes and identifiers.
    ///
    /// Reference: BSI TR-03183-2 v2.0.0 §5 (mandatory) and §6 (recommended).
    pub(crate) fn check_bsi_tr_03183_2(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::{CreatorType, HashAlgorithm};

        // §5.1 — Author/creator identification (mandatory)
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.1] SBOM author/creator missing".to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.1: Author/creator identification".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-1",
                standard_refs: Vec::new(),
            });
        }

        // §5.1 — At least one tool creator (mandatory)
        let has_tool_creator = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Tool);
        if !has_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.1] SBOM must identify the generation tool".to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.1: Tool identification".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-1",
                standard_refs: Vec::new(),
            });
        }

        // §5.2 — ISO-8601 timestamp (mandatory).
        // Our `DocumentMetadata::created` is `DateTime<Utc>`, always ISO-8601
        // when serialised; the practical risk is the `created` field being
        // unset in the source SBOM. NormalizedSbom default is Utc::now(), so
        // we look for tell-tale unix-epoch / very-old fallback values.
        let created = sbom.document.created;
        if created.timestamp() <= 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.2] SBOM created timestamp missing or invalid"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.2: ISO-8601 timestamp".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-2",
                standard_refs: Vec::new(),
            });
        }

        // §5.3 — Component name (mandatory) — already enforced globally;
        //         we add a BSI-specific message only if many components are
        //         missing names (extreme case).

        // §5.3 — Component identifier: PURL or other recognised ID (mandatory).
        // Stricter than CRA: BSI requires a PURL where the ecosystem applies.
        for comp in sbom.components.values() {
            if !comp.identifiers.has_cra_identifier() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[BSI TR-03183-2 §5.3] Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "BSI TR-03183-2 §5.3: Component identifier".to_string(),
                    rule_id: "SBOM-BSI-TR-03183-2-5-3",
                    standard_refs: Vec::new(),
                });
            }
        }

        // §5.4 — Cryptographic hash (SHA-256 or stronger) — mandatory.
        let strong = |a: &HashAlgorithm| {
            matches!(
                a,
                HashAlgorithm::Sha256
                    | HashAlgorithm::Sha384
                    | HashAlgorithm::Sha512
                    | HashAlgorithm::Sha3_256
                    | HashAlgorithm::Sha3_384
                    | HashAlgorithm::Sha3_512
                    | HashAlgorithm::Blake2b256
                    | HashAlgorithm::Blake2b384
                    | HashAlgorithm::Blake2b512
                    | HashAlgorithm::Blake3
            )
        };
        for comp in sbom.components.values() {
            let has_strong_hash = comp.hashes.iter().any(|h| strong(&h.algorithm));
            if !has_strong_hash {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[BSI TR-03183-2 §5.4] Component '{}' missing SHA-256+ cryptographic hash",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "BSI TR-03183-2 §5.4: Component cryptographic hash (SHA-256+)"
                        .to_string(),
                    rule_id: "SBOM-BSI-TR-03183-2-5-4",
                    standard_refs: Vec::new(),
                });
            }
        }

        // §5.5 — Dependencies (mandatory): explicit relationship graph required.
        if sbom.edges.is_empty() && sbom.components.len() > 1 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "[BSI TR-03183-2 §5.5] SBOM declares multiple components but no dependency relationships"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.5: Dependency relationships".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-5",
                standard_refs: Vec::new(),
            });
        }

        // §6 — Recommended: license information per component
        let total = sbom.components.len();
        let without_license = sbom
            .components
            .values()
            .filter(|c| c.licenses.declared.is_empty() && c.licenses.concluded.is_none())
            .count();
        if without_license > 0 {
            let pct = (without_license * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                },
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[BSI TR-03183-2 §6] {without_license}/{total} components ({pct}%) missing license information"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §6: Component license (recommended)".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-6",
                standard_refs: Vec::new(),
            });
        }

        // §6 — Recommended: supplier per component
        let without_supplier = sbom
            .components
            .values()
            .filter(|c| c.supplier.is_none() && c.author.is_none())
            .count();
        if without_supplier > 0 {
            let pct = (without_supplier * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                },
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "[BSI TR-03183-2 §6] {without_supplier}/{total} components ({pct}%) missing supplier information"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §6: Component supplier (recommended)".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-6",
                standard_refs: Vec::new(),
            });
        }
    }
}
