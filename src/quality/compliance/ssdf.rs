//! NIST SP 800-218 Secure Software Development Framework checks.

use super::*;

impl ComplianceChecker {
    /// NIST SP 800-218 Secure Software Development Framework checks
    pub(crate) fn check_nist_ssdf(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ExternalRefType;

        // PS.1 — Provenance: creator/tool information
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message:
                    "SBOM must identify its creator (tool or organization) for provenance tracking"
                        .to_string(),
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — creator identification".to_string(),
                rule_id: "SBOM-SSDF-PS1",
                standard_refs: Vec::new(),
            });
        }

        let has_tool_creator = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == crate::model::CreatorType::Tool);
        if !has_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should identify the generation tool for automated provenance"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — tool identification".to_string(),
                rule_id: "SBOM-SSDF-PS1",
                standard_refs: Vec::new(),
            });
        }

        // PS.2 — Build integrity: components should have hashes
        let total = sbom.components.len();
        let without_hash = sbom
            .components
            .values()
            .filter(|c| c.hashes.is_empty())
            .count();
        if without_hash > 0 {
            let pct = (without_hash * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                },
                category: ViolationCategory::IntegrityInfo,
                message: format!(
                    "{without_hash}/{total} components ({pct}%) missing cryptographic hashes for build integrity"
                ),
                element: None,
                requirement: "NIST SSDF PS.2: Build integrity — component hashes".to_string(),
                rule_id: "SBOM-SSDF-PS2",
                standard_refs: Vec::new(),
            });
        }

        // PO.1 — VCS references: at least some components should reference their source
        let has_vcs_ref = sbom.components.values().any(|comp| {
            comp.external_refs
                .iter()
                .any(|r| matches!(r.ref_type, ExternalRefType::Vcs))
        });
        if !has_vcs_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: "No components reference a VCS repository; include source repository links for traceability"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PO.1: Source code provenance — VCS references".to_string(),
                rule_id: "SBOM-SSDF-PO1",
                standard_refs: Vec::new(),
            });
        }

        // PO.3 — Build metadata: check for build system/meta references
        let has_build_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::BuildMeta | ExternalRefType::BuildSystem
                )
            })
        });
        if !has_build_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "No build metadata references found; include build system information for reproducibility"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PO.3: Build provenance — build metadata".to_string(),
                rule_id: "SBOM-SSDF-PO3",
                standard_refs: Vec::new(),
            });
        }

        // PW.4 — Dependency management: dependency relationships required
        if sbom.components.len() > 1 && sbom.edges.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "SBOM with multiple components must include dependency relationships"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PW.4: Dependency management — relationships".to_string(),
                rule_id: "SBOM-SSDF-PW4",
                standard_refs: Vec::new(),
            });
        }

        // PW.6 — Vulnerability information
        let has_vuln_info = sbom
            .components
            .values()
            .any(|c| !c.vulnerabilities.is_empty());
        let has_security_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::Advisories
                        | ExternalRefType::SecurityContact
                        | ExternalRefType::VulnerabilityAssertion
                )
            })
        });
        if !has_vuln_info && !has_security_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: "No vulnerability or security advisory references found; \
                    include vulnerability data or security contact for incident response"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PW.6: Vulnerability information".to_string(),
                rule_id: "SBOM-SSDF-PW6",
                standard_refs: Vec::new(),
            });
        }

        // RV.1 — Component identification: unique identifiers (PURL/CPE)
        let without_id = sbom
            .components
            .values()
            .filter(|c| {
                c.identifiers.purl.is_none()
                    && c.identifiers.cpe.is_empty()
                    && c.identifiers.swid.is_none()
            })
            .count();
        if without_id > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_id}/{total} components missing unique identifier (PURL/CPE/SWID)"
                ),
                element: None,
                requirement: "NIST SSDF RV.1: Component identification — unique identifiers"
                    .to_string(),
                rule_id: "SBOM-SSDF-RV1",
                standard_refs: Vec::new(),
            });
        }

        // PS.3 — Supplier identification
        let without_supplier = sbom
            .components
            .values()
            .filter(|c| c.supplier.is_none() && c.author.is_none())
            .count();
        if without_supplier > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "{without_supplier}/{total} components missing supplier/author information"
                ),
                element: None,
                requirement: "NIST SSDF PS.3: Supplier identification".to_string(),
                rule_id: "SBOM-SSDF-PS3",
                standard_refs: Vec::new(),
            });
        }
    }
}
