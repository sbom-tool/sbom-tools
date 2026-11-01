//! EUCC Substantial reference-only profile checks: Implementing Regulation
//! (EU) 2024/482 as amended by Implementing Regulations (EU) 2024/3144 and
//! 2025/2462 (consolidated text of 2025-12-29).

use super::ssdf::{cdxa_note, standard_references_eucc};
use super::*;
use crate::model::AttestationRuleFamily;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // EUCC Substantial (CRA-P5.4 reference profile)
    // ════════════════════════════════════════════════════════════════════
    //
    // Reference-only profile for CRA Annex IV / EUCC products. Verifies
    // that the SBOM (or sidecar) carries the four pieces of evidence
    // notified-body auditors expect to see in a Common Criteria
    // submission. Does NOT perform a Common Criteria evaluation —
    // that's out of scope for SBOM tooling.
    //
    // Nor does it judge the SBOM's content: no inventory, component or
    // dependency check runs here, so a document listing no components
    // passes once the certificate evidence is complete. The CRA profiles
    // judge the SBOM itself (SBOM-CRA-INVENTORY and the rest); the scope is
    // pinned by eucc_runs_no_inventory_check in tests/rule_matrix_eucc.rs.

    pub(crate) fn check_eucc_substantial(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        let sidecar = self.sidecar.as_ref();

        // 1. Common Criteria Protection Profile reference
        let pp_present = sidecar
            .and_then(|s| s.eucc_protection_profile_id.as_deref())
            .is_some_and(|s| !s.is_empty());
        if !pp_present {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[EUCC] Missing Common Criteria Protection Profile reference — set sidecar `eucc_protection_profile_id`".to_string(),
                element: None,
                requirement: "EUCC Substantial: Protection Profile reference".to_string(),
                rule_id: "SBOM-EUCC-PP",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // 2. Target of Evaluation reference
        let toe_present = sidecar
            .and_then(|s| s.eucc_target_of_evaluation.as_deref())
            .is_some_and(|s| !s.is_empty());
        if !toe_present {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[EUCC] Missing Target of Evaluation reference — set sidecar `eucc_target_of_evaluation`".to_string(),
                element: None,
                requirement: "EUCC Substantial: Target of Evaluation reference".to_string(),
                rule_id: "SBOM-EUCC-TOE",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // 3. ITSEF (lab) identifier
        let itsef_present = sidecar
            .and_then(|s| s.eucc_itsef_identifier.as_deref())
            .is_some_and(|s| !s.is_empty());
        if !itsef_present {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[EUCC] Missing ITSEF (IT Security Evaluation Facility) identifier — set sidecar `eucc_itsef_identifier`".to_string(),
                element: None,
                requirement: "EUCC Substantial: ITSEF identifier".to_string(),
                rule_id: "SBOM-EUCC-ITSEF",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // 4. Valid-until date
        match sidecar.and_then(|s| s.eucc_valid_until) {
            None => {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[EUCC] Missing certificate valid-until date — set sidecar `eucc_valid_until`".to_string(),
                    element: None,
                    requirement: "EUCC Substantial: certificate valid-until date".to_string(),
                    rule_id: "SBOM-EUCC-VALIDITY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: None,
                });
            }
            Some(until) if until <= self.now() => {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[EUCC] EUCC certificate has expired (valid-until {})",
                        until.format("%Y-%m-%d")
                    ),
                    element: None,
                    requirement: "EUCC Substantial: certificate validity".to_string(),
                    rule_id: "SBOM-EUCC-VALIDITY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: observed(&until.format("%Y-%m-%d").to_string()),
                });
            }
            Some(until) if until <= self.now() + chrono::Duration::days(180) => {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[EUCC] EUCC certificate expires within 180 days ({})",
                        until.format("%Y-%m-%d")
                    ),
                    element: None,
                    requirement: "EUCC Substantial: certificate validity".to_string(),
                    rule_id: "SBOM-EUCC-VALIDITY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: observed(&until.format("%Y-%m-%d").to_string()),
                });
            }
            Some(_) => {}
        }

        // 5. EUCC Certification external ref (recommended) — checked
        // structurally; satisfied when the described product carries a
        // Certification or Attestation ref whose URL contains "eucc",
        // "common-criteria" or "commoncriteria" (`is_eucc_reference`, the
        // test the CRA Annex IV check shares; a dependency's own certificate
        // does not cover the product), OR when the document carries fresh,
        // fully-resolved CDXA attestation evidence for a CRA-classified
        // standard naming EUCC / Common Criteria (Structural/SignaturePresent
        // level; the URL-substring scan remains the SelfDeclared fallback).
        // Until v0.4.0 this check did not read "commoncriteria".
        let ctx = ComplianceContext::new(self, sbom);
        let cdxa_eucc_attested = ctx
            .evidence_for(AttestationRuleFamily::Cra)
            .iter()
            .any(|s| standard_references_eucc(s.standard));
        let eucc_ref_present =
            cdxa_eucc_attested || manufacturer_reference(sbom, is_eucc_reference);
        if !eucc_ref_present {
            let mut message = "[EUCC] No Certification/Attestation external reference points at an EUCC URL (recommended)".to_string();
            if let Some(note) = cdxa_note(
                ctx.attestation_declarations(),
                AttestationRuleFamily::Cra,
                &|s, _| standard_references_eucc(s),
                self.now(),
                "an EUCC / Common Criteria certification",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "EUCC Substantial: Certification external reference".to_string(),
                rule_id: "SBOM-EUCC-CERTREF",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
    }
}
