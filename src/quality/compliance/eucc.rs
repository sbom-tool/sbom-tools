//! EUCC Substantial (Reg. (EU) 2024/482) reference-only profile checks.

use super::*;

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
                rule_id: "SBOM-EUCC",
                standard_refs: Vec::new(),
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
                rule_id: "SBOM-EUCC",
                standard_refs: Vec::new(),
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
                rule_id: "SBOM-EUCC",
                standard_refs: Vec::new(),
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
                    rule_id: "SBOM-EUCC",
                    standard_refs: Vec::new(),
                });
            }
            Some(until) if until <= chrono::Utc::now() => {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[EUCC] EUCC certificate has expired (valid-until {})",
                        until.format("%Y-%m-%d")
                    ),
                    element: None,
                    requirement: "EUCC Substantial: certificate validity".to_string(),
                    rule_id: "SBOM-EUCC",
                    standard_refs: Vec::new(),
                });
            }
            Some(until) if until <= chrono::Utc::now() + chrono::Duration::days(180) => {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[EUCC] EUCC certificate expires within 180 days ({})",
                        until.format("%Y-%m-%d")
                    ),
                    element: None,
                    requirement: "EUCC Substantial: certificate validity".to_string(),
                    rule_id: "SBOM-EUCC",
                    standard_refs: Vec::new(),
                });
            }
            Some(_) => {}
        }

        // 5. EUCC Certification external ref (recommended) — checked
        // structurally; satisfied when any component carries a Certification
        // ref whose URL contains "eucc" or "common-criteria".
        let eucc_ref_present = sbom.components.values().any(|c| {
            c.external_refs.iter().any(|r| {
                let url = r.url.to_lowercase();
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::Certification
                        | crate::model::ExternalRefType::Attestation
                ) && (url.contains("eucc") || url.contains("common-criteria"))
            })
        });
        if !eucc_ref_present {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "[EUCC] No Certification/Attestation external reference points at an EUCC URL (recommended)".to_string(),
                element: None,
                requirement: "EUCC Substantial: Certification external reference".to_string(),
                rule_id: "SBOM-EUCC",
                standard_refs: Vec::new(),
            });
        }
    }
}
