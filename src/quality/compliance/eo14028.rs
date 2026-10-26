//! Executive Order 14028 Section 4 checks.

use super::ssdf::{cdxa_note, requirement_matches_id};
use super::*;
use crate::model::{AttestationRuleFamily, DefinedRequirement};

/// Which attested requirements evidence automated, provenance-tracked SBOM
/// generation (the EO 14028 §4(e) autogeneration proxy). Accepts the SSDF
/// provenance/toolchain practices (PS.1, PO.3 — the same proxies the legacy
/// tool-creator path stands in for) that EO-14028-labeled CDXA encodings
/// commonly reuse, or a requirement whose title/text names provenance
/// explicitly.
fn evidences_autogen_provenance(requirement: &DefinedRequirement) -> bool {
    requirement_matches_id(requirement, "PS.1")
        || requirement_matches_id(requirement, "PO.3")
        || [requirement.title.as_deref(), requirement.text.as_deref()]
            .into_iter()
            .flatten()
            .any(|t| t.to_lowercase().contains("provenance"))
}

impl ComplianceChecker {
    /// Executive Order 14028 Section 4 checks
    pub(crate) fn check_eo14028(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ExternalRefType;

        // The component checks below have nothing to judge without a
        // package-scoped component.
        violations.extend(inventory_absent_violation(
            sbom,
            "SBOM-EO14028-INVENTORY",
            "EO 14028 Sec 4(e): component inventory",
        ));

        // CDXA attestation evidence for the EO 14028 family (fresh and
        // fully resolved at the injectable clock). Strengthens only: the
        // legacy tool-creator path below stays a valid SelfDeclared-level
        // fallback, and documents without declarations are unaffected.
        let ctx = ComplianceContext::new(self, sbom);
        let declarations = ctx.attestation_declarations();
        let autogen_attested = ctx
            .evidence_for(AttestationRuleFamily::Eo14028)
            .iter()
            .any(|s| evidences_autogen_provenance(s.requirement));

        // Sec 4(e) — Machine-readable format: CycloneDX 1.4+, SPDX 2.2+.
        // The NTIA minimum-elements report that EO 14028 §4(e) defers to
        // names SPDX (then at 2.2) as an accepted format, so SPDX 2.2
        // documents are machine-readable under the EO. Versions compare
        // numerically ("1.10" is newer than "1.7", not "1.1"); an absent or
        // unparseable version skips the gate instead of false-failing.
        let minimum = match sbom.document.format {
            crate::model::SbomFormat::CycloneDx => crate::model::SpecVersion::new(1, 4, 0),
            crate::model::SbomFormat::Spdx => crate::model::SpecVersion::new(2, 2, 0),
        };
        let format_ok = sbom
            .document
            .spec_version_parsed()
            .is_none_or(|v| v >= minimum);
        if !format_ok {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "SBOM format {} {} does not meet EO 14028 machine-readable requirements; \
                    use CycloneDX 1.4+, SPDX 2.2+, or SPDX 3.0+",
                    sbom.document.format, sbom.document.spec_version
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Machine-readable SBOM format".to_string(),
                rule_id: "SBOM-EO14028-FORMAT",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — NTIA baseline: creation timestamp. EO 14028 §4(e)
        // incorporates the NTIA minimum elements, which include Timestamp;
        // a missing/invalid source timestamp is stored as the UNIX_EPOCH
        // sentinel (see `has_known_timestamp`).
        if !sbom.document.has_known_timestamp() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM is missing a creation timestamp (NTIA required data field)"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): Timestamp (NTIA baseline)".to_string(),
                rule_id: "SBOM-EO14028-TIMESTAMP",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Automated generation: tool creator should be present.
        // A fresh CDXA attestation of an autogeneration/provenance
        // requirement in the EO 14028 family also satisfies the rule, at
        // Structural/SignaturePresent level.
        let has_tool = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == crate::model::CreatorType::Tool);
        if !has_tool && !autogen_attested {
            let mut message =
                "SBOM should be auto-generated by a tool; no tool creator identified".to_string();
            if let Some(note) = cdxa_note(
                declarations,
                AttestationRuleFamily::Eo14028,
                &|_, r| evidences_autogen_provenance(r),
                self.now(),
                "EO 14028 automated generation / provenance",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "EO 14028 Sec 4(e): Automated SBOM generation".to_string(),
                rule_id: "SBOM-EO14028-AUTOGEN",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Creator identification
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM must identify its creator (vendor or tool)".to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): SBOM creator identification".to_string(),
                rule_id: "SBOM-EO14028-CREATOR",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Component identification with unique identifiers
        // (PURL/CPE/SWHID/SWID via `has_cra_identifier`, so SWHID-only SPDX
        // components are not flagged)
        // Package elements (identifier, version, hash, supplier) apply to
        // package-scoped components only; names apply to every component.
        let packages: Vec<_> = package_components(sbom).collect();
        let total = packages.len();
        let without_id = packages
            .iter()
            .filter(|c| !c.identifiers.has_cra_identifier())
            .count();
        if without_id > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_id}/{total} components missing unique identifier (PURL/CPE/SWHID/SWID)"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component unique identification".to_string(),
                rule_id: "SBOM-EO14028-IDENTIFIER",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_id,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — NTIA baseline: component names
        // All components: every component needs a name, package or not.
        let all_components = sbom.components.len();
        let without_name = sbom
            .components
            .values()
            .filter(|c| !known_component_name(c))
            .count();
        if without_name > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_name}/{all_components} components missing a component name"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component name (NTIA baseline)".to_string(),
                rule_id: "SBOM-EO14028-NAME",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_name,
                    total: all_components,
                }),
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Dependency relationships (between packages: crypto
        // assets and files need not join the dependency graph)
        if total > 1 && sbom.edges.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "SBOM with multiple components must include dependency relationships"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): Dependency relationships".to_string(),
                rule_id: "SBOM-EO14028-DEPENDENCY",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Version information (placeholder values such as
        // NOASSERTION do not satisfy the element)
        let without_version = packages
            .iter()
            .filter(|c| !has_known_value(&c.version))
            .count();
        if without_version > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_version}/{total} components missing version information"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component version".to_string(),
                rule_id: "SBOM-EO14028-VERSION",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_version,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Cryptographic hashes for integrity
        let without_hash = packages.iter().filter(|c| c.hashes.is_empty()).count();
        if without_hash > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::IntegrityInfo,
                message: format!("{without_hash}/{total} components missing cryptographic hashes"),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component integrity verification".to_string(),
                rule_id: "SBOM-EO14028-INTEGRITY",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_hash,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(g) — Vulnerability disclosure. Component-level refs count
        // only on the primary/root components — a dependency's upstream
        // advisories URL is not the vendor's disclosure process.
        let has_security_ref = sbom.document.security_contact.is_some()
            || sbom.document.vulnerability_disclosure_url.is_some()
            || manufacturer_scope_components(sbom).iter().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::SecurityContact | ExternalRefType::Advisories
                    )
                })
            });
        if !has_security_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SecurityInfo,
                message: "No security contact or vulnerability disclosure reference found"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(g): Vulnerability disclosure process".to_string(),
                rule_id: "SBOM-EO14028-DISCLOSURE",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
            });
        }

        // Sec 4(e) — Supplier identification (placeholder values such as
        // NOASSERTION do not satisfy the element)
        let without_supplier = packages.iter().filter(|c| !has_known_producer(c)).count();
        if without_supplier > 0 {
            // Supplier Name is a REQUIRED NTIA minimum element, and EO 14028
            // §4(e) mandates the NTIA minimum elements — so a missing supplier
            // is a gating Error (as version and unique-id already are), not a
            // Warning behind a >30% threshold.
            let pct = (without_supplier * 100) / total.max(1);
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "{without_supplier}/{total} components ({pct}%) missing supplier information"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Supplier identification".to_string(),
                rule_id: "SBOM-EO14028-SUPPLIER",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_supplier,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
            });
        }
    }
}
