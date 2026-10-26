//! NIST SP 800-218 Secure Software Development Framework checks.
//!
//! Also home of the shared CDXA attestation-evidence helpers used by the
//! SSDF / EO 14028 / CRA / EUCC integration sites (SSDF is the canonical
//! CDXA rule family, and `registry.rs`/`mod.rs` are frozen surfaces).

use super::*;
use crate::model::{
    AttestationDeclarations, AttestationRuleFamily, CdxaRef, CdxaResolution, DefinedRequirement,
    DefinedStandard,
};

// ════════════════════════════════════════════════════════════════════════
// CDXA attestation evidence helpers
//
// Contract: machine-readable attestation evidence only ever STRENGTHENS a
// rule — every legacy satisfaction path (presence bits, sidecar fields)
// remains valid as the `EvidenceLevel::SelfDeclared` fallback, and none of
// these helpers changes behavior for documents without `declarations`
// (they return `None` in that case, so messages stay byte-identical).
// ════════════════════════════════════════════════════════════════════════

/// Case-insensitive match of a defined requirement against a standard's own
/// identifier (e.g. SSDF practice "PS.1"). Exact match only — a task-level
/// identifier such as "PS.1.1" does not automatically evidence the whole
/// practice (fail closed on partial coverage).
pub(super) fn requirement_matches_id(requirement: &DefinedRequirement, id: &str) -> bool {
    requirement
        .identifier
        .as_deref()
        .is_some_and(|i| i.trim().eq_ignore_ascii_case(id))
}

/// Whether a `definitions.standards[]` entry references the EUCC / Common
/// Criteria scheme. Used by the CRA / EUCC certificate-reference sites: an
/// EUCC-relevant CDXA standard must both classify into the CRA rule family
/// (see [`AttestationRuleFamily::classify`]) AND name the scheme.
pub(super) fn standard_references_eucc(standard: &DefinedStandard) -> bool {
    let hay = format!(
        "{} {}",
        standard.name.as_deref().unwrap_or(""),
        standard.description.as_deref().unwrap_or("")
    )
    .to_lowercase();
    hay.contains("eucc") || hay.contains("common criteria") || hay.contains("common-criteria")
}

/// Why no fresh CDXA attestation supports the rule selected by `matches`
/// within `family`: the first fail-closed gate tripped by the closest
/// attestation map entry (partial conformance, counter claims/evidence,
/// dangling refs, stale evidence — the same criteria as
/// [`AttestationDeclarations::supported_requirements`], in the same order).
/// `None` when no attestation map entry targets the rule at all. Callers
/// invoke this only after `ComplianceContext::evidence_for` returned no
/// matching supported requirement, so every matching entry tripped a gate.
fn cdxa_rejection_reason(
    declarations: &AttestationDeclarations,
    family: AttestationRuleFamily,
    matches: &dyn Fn(&DefinedStandard, &DefinedRequirement) -> bool,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    for attestation in &declarations.attestations {
        for entry in &attestation.map {
            let Some(requirement_ref) = &entry.requirement else {
                continue;
            };
            if !matches!(requirement_ref.resolution, CdxaResolution::Requirement) {
                continue;
            }
            let Some((standard, requirement)) =
                declarations.requirement_by_ref(&requirement_ref.raw)
            else {
                continue;
            };
            if AttestationRuleFamily::classify(standard, requirement) != Some(family)
                || !matches(standard, requirement)
            {
                continue;
            }

            match entry.conformance_score {
                None => return Some("no conformance score is declared (fail closed)".to_string()),
                Some(score) if score < 1.0 => {
                    return Some(format!(
                        "declared conformance is partial (score {score}); partial conformance never auto-satisfies"
                    ));
                }
                Some(_) => {}
            }
            if !entry.counter_claims.is_empty() {
                return Some(format!(
                    "the requirement mapping is contested by {} counter-claim(s)",
                    entry.counter_claims.len()
                ));
            }
            if entry.claims.is_empty() {
                return Some("no claims are cited for the requirement".to_string());
            }
            let mut claim_reasons: Vec<String> = Vec::new();
            for claim_ref in &entry.claims {
                let claim = if matches!(claim_ref.resolution, CdxaResolution::Claim) {
                    declarations.claim_by_ref(&claim_ref.raw)
                } else {
                    None
                };
                let Some(claim) = claim else {
                    claim_reasons.push(format!(
                        "claim ref '{}' does not resolve (dangling)",
                        claim_ref.raw
                    ));
                    continue;
                };
                if !claim.target.as_ref().is_some_and(CdxaRef::is_resolved) {
                    claim_reasons.push(format!(
                        "claim '{}' targets an unresolvable element (dangling)",
                        claim_ref.raw
                    ));
                    continue;
                }
                if !claim.counter_evidence.is_empty() {
                    claim_reasons.push(format!(
                        "claim '{}' is contested by counter-evidence",
                        claim_ref.raw
                    ));
                    continue;
                }
                let resolved: Vec<_> = claim
                    .evidence
                    .iter()
                    .filter(|e| matches!(e.resolution, CdxaResolution::Evidence))
                    .filter_map(|e| declarations.evidence_by_ref(&e.raw))
                    .collect();
                if resolved.is_empty() {
                    claim_reasons.push(format!(
                        "claim '{}' cites no resolvable evidence (dangling refs)",
                        claim_ref.raw
                    ));
                    continue;
                }
                if resolved.iter().any(|e| e.is_fresh(as_of)) {
                    // A fully-supporting claim would have satisfied the rule
                    // upstream; keep scanning defensively rather than invent
                    // a reason.
                    continue;
                }
                if resolved
                    .iter()
                    .any(|e| e.expires.is_some_and(|expires| expires <= as_of))
                {
                    claim_reasons.push(format!(
                        "evidence for claim '{}' has expired",
                        claim_ref.raw
                    ));
                } else {
                    claim_reasons.push(format!(
                        "evidence for claim '{}' is dated after the evaluation instant",
                        claim_ref.raw
                    ));
                }
            }
            if !claim_reasons.is_empty() {
                return Some(claim_reasons.join("; "));
            }
        }
    }
    None
}

/// Suffix for a still-failing violation's message when the document carries
/// CDXA declarations: names the specific fail-closed rejection reason when a
/// matching attestation exists, otherwise points at machine-readable
/// attestation as an accepted evidence path. `None` when the document has no
/// declarations, so messages for documents without CDXA content stay
/// byte-identical (zero behavior change).
pub(super) fn cdxa_note(
    declarations: Option<&AttestationDeclarations>,
    family: AttestationRuleFamily,
    matches: &dyn Fn(&DefinedStandard, &DefinedRequirement) -> bool,
    as_of: chrono::DateTime<chrono::Utc>,
    subject: &str,
) -> Option<String> {
    let declarations = declarations?;
    Some(
        match cdxa_rejection_reason(declarations, family, matches, as_of) {
            Some(reason) => {
                format!(" — CDXA attestation covering {subject} found but rejected: {reason}")
            }
            None => format!(
                " — a machine-readable CDXA attestation covering {subject} is an accepted evidence path"
            ),
        },
    )
}

impl ComplianceChecker {
    /// NIST SP 800-218 Secure Software Development Framework checks
    pub(crate) fn check_nist_ssdf(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ExternalRefType;

        // PS.3.2 provenance data must cover the release's components; the
        // per-component practices below have nothing to judge without one.
        violations.extend(inventory_absent_violation(
            sbom,
            "SBOM-SSDF-INVENTORY",
            "NIST SSDF PS.3.2: provenance data for the release's components",
        ));

        // CDXA attestation evidence (CycloneDX 1.6 declarations): fresh,
        // fully-resolved machine-readable support for SSDF practices,
        // evaluated at the injectable clock. Evidence only strengthens —
        // every legacy check below remains a valid SelfDeclared-level
        // satisfaction path, and on documents without declarations
        // `attested()` is uniformly false (zero behavior change).
        let ctx = ComplianceContext::new(self, sbom);
        let declarations = ctx.attestation_declarations();
        let ssdf_evidence = ctx.evidence_for(AttestationRuleFamily::Ssdf);
        let attested = |practice: &str| {
            ssdf_evidence
                .iter()
                .any(|s| requirement_matches_id(s.requirement, practice))
        };
        let now = self.now();

        // PS.1 — Provenance: creator/tool information. A fresh attestation
        // of practice PS.1 satisfies the rule at Structural /
        // SignaturePresent level even when the creator fields are absent.
        let ps1_attested = attested("PS.1");
        let ps1_matcher: &dyn Fn(&DefinedStandard, &DefinedRequirement) -> bool =
            &|_, r| requirement_matches_id(r, "PS.1");
        if sbom.document.creators.is_empty() && !ps1_attested {
            let mut message =
                "SBOM must identify its creator (tool or organization) for provenance tracking"
                    .to_string();
            if let Some(note) = cdxa_note(
                declarations,
                AttestationRuleFamily::Ssdf,
                ps1_matcher,
                now,
                "SSDF practice PS.1",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — creator identification".to_string(),
                rule_id: "SBOM-SSDF-PS1",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        let has_tool_creator = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == crate::model::CreatorType::Tool);
        if !has_tool_creator && !ps1_attested {
            let mut message =
                "SBOM should identify the generation tool for automated provenance".to_string();
            if let Some(note) = cdxa_note(
                declarations,
                AttestationRuleFamily::Ssdf,
                ps1_matcher,
                now,
                "SSDF practice PS.1",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — tool identification".to_string(),
                rule_id: "SBOM-SSDF-PS1",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        // PS.2 — Build integrity: components should have hashes. Package
        // practices (hash, identifier, supplier) judge package-scoped
        // components only — crypto assets, files and services carry none.
        let packages: Vec<_> = package_components(sbom).collect();
        let total = packages.len();
        let without_hash = packages.iter().filter(|c| c.hashes.is_empty()).count();
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
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_hash,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
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
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        // PO.3 — Build metadata: check for build system/meta references.
        // Legacy path: BuildMeta/BuildSystem external refs (SelfDeclared
        // presence bits). A fresh CDXA attestation of practice PO.3 also
        // satisfies the rule.
        let has_build_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::BuildMeta | ExternalRefType::BuildSystem
                )
            })
        });
        if !has_build_ref && !attested("PO.3") {
            let mut message = "No build metadata references found; include build system information for reproducibility"
                .to_string();
            if let Some(note) = cdxa_note(
                declarations,
                AttestationRuleFamily::Ssdf,
                &|_, r| requirement_matches_id(r, "PO.3"),
                now,
                "SSDF practice PO.3",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "NIST SSDF PO.3: Build provenance — build metadata".to_string(),
                rule_id: "SBOM-SSDF-PO3",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        // PW.4 — Dependency management: dependency relationships required
        // between packages
        if total > 1 && sbom.edges.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "SBOM with multiple components must include dependency relationships"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PW.4: Dependency management — relationships".to_string(),
                rule_id: "SBOM-SSDF-PW4",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
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
        // Both legacy satisfaction paths (embedded vulnerability data;
        // Advisories / SecurityContact / VulnerabilityAssertion refs) are
        // preserved as SelfDeclared fallbacks; a fresh CDXA attestation of
        // practice PW.6 is a third, machine-readable path.
        if !has_vuln_info && !has_security_ref && !attested("PW.6") {
            let mut message = "No vulnerability or security advisory references found; \
                    include vulnerability data or security contact for incident response"
                .to_string();
            if let Some(note) = cdxa_note(
                declarations,
                AttestationRuleFamily::Ssdf,
                &|_, r| requirement_matches_id(r, "PW.6"),
                now,
                "SSDF practice PW.6",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message,
                element: None,
                requirement: "NIST SSDF PW.6: Vulnerability information".to_string(),
                rule_id: "SBOM-SSDF-PW6",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        // RV.1 — Component identification: unique identifiers
        // (PURL/CPE/SWHID/SWID via `has_cra_identifier`, so SWHID-only SPDX
        // components are not flagged)
        let without_id = packages
            .iter()
            .filter(|c| !c.identifiers.has_cra_identifier())
            .count();
        if without_id > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_id}/{total} components missing unique identifier (PURL/CPE/SWHID/SWID)"
                ),
                element: None,
                requirement: "NIST SSDF RV.1: Component identification — unique identifiers"
                    .to_string(),
                rule_id: "SBOM-SSDF-RV1",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_id,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }

        // PS.3 — Supplier identification (placeholder values such as
        // NOASSERTION do not satisfy the element)
        let without_supplier = packages.iter().filter(|c| !has_known_producer(c)).count();
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
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_supplier,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
            });
        }
    }
}
