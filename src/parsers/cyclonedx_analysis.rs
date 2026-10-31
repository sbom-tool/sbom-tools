//! The CycloneDX `vulnerabilities[].analysis` vocabulary, read one way by
//! the CycloneDX parser (an analysis embedded in an SBOM) and by the
//! CycloneDX VEX reader of `--vex` (`enrichment::vex::cyclonedx_vex`), so a
//! statement means the same wherever it comes from.
//!
//! The CycloneDX terms and their definitions are the `meta:enum` of the
//! CycloneDX 1.6 and 1.7 JSON schemas (`impactAnalysisState`,
//! `impactAnalysisJustification`, `impactAnalysisResponse`). The model's
//! five justifications are the CISA ones that OpenVEX and SPDX 3.0
//! (`VexJustificationType`) also use.

use crate::model::{VexJustification, VexResponse, VexState, VexStatus};

/// The model state for a CycloneDX `impactAnalysisState`.
///
/// `exploitable` is Affected: a live, actionable threat must not collapse
/// to UnderInvestigation. A missing or unknown state is UnderInvestigation,
/// an honest "we don't know", never a fabricated safe claim. `affected` and
/// `fixed` are no CycloneDX states but are read as their model names.
pub(crate) fn vex_state(state: Option<&str>) -> VexState {
    match state {
        Some("not_affected" | "false_positive") => VexState::NotAffected,
        Some("affected" | "exploitable") => VexState::Affected,
        Some("fixed" | "resolved" | "resolved_with_pedigree") => VexState::Fixed,
        _ => VexState::UnderInvestigation,
    }
}

/// The model justification closest to a CycloneDX
/// `impactAnalysisJustification`:
///
/// - `code_not_present` ("The code has been removed or tree-shaked"):
///   VulnerableCodeNotPresent. The component is there; its vulnerable code
///   is not, which is what ComponentNotPresent would not say.
/// - `code_not_reachable` ("The vulnerable code is not invoked at
///   runtime"): VulnerableCodeNotInExecutePath.
/// - `requires_configuration`, `requires_dependency` and
///   `requires_environment` (exploitability requires an option, a
///   dependency or an environment that is not there), and
///   `protected_at_perimeter` ("Attacks are blocked at physical, logical, or
///   network perimeter"): VulnerableCodeCannotBeControlledByAdversary. The
///   code is present, but an attacker cannot reach it to exploit it; a
///   perimeter is no protection built into the product.
/// - `protected_by_compiler` ("Exploitability requires a compiler flag to
///   be set/unset"), `protected_at_runtime` ("Exploits are prevented at
///   runtime") and `protected_by_mitigating_control` ("Preventative
///   measures have been implemented …"): InlineMitigationsAlreadyExist, the
///   built-in controls or mitigations that keep an adversary from
///   leveraging the vulnerability.
///
/// Any other string is no justification: an unrecognized value must never
/// fabricate a not-affected claim.
pub(crate) fn vex_justification(justification: &str) -> Option<VexJustification> {
    match justification {
        "code_not_present" => Some(VexJustification::VulnerableCodeNotPresent),
        "code_not_reachable" => Some(VexJustification::VulnerableCodeNotInExecutePath),
        "requires_configuration"
        | "requires_dependency"
        | "requires_environment"
        | "protected_at_perimeter" => {
            Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
        }
        "protected_by_compiler" | "protected_at_runtime" | "protected_by_mitigating_control" => {
            Some(VexJustification::InlineMitigationsAlreadyExist)
        }
        _ => None,
    }
}

/// The model response for a CycloneDX `impactAnalysisResponse`; an
/// unrecognized value is none, never a fabricated `update`.
pub(crate) fn vex_response(response: &str) -> Option<VexResponse> {
    match response {
        "can_not_fix" => Some(VexResponse::CanNotFix),
        "will_not_fix" => Some(VexResponse::WillNotFix),
        "update" => Some(VexResponse::Update),
        "rollback" => Some(VexResponse::Rollback),
        "workaround_available" => Some(VexResponse::Workaround),
        _ => None,
    }
}

/// The VEX status of a CycloneDX analysis.
///
/// `detail` is CycloneDX's one free-text field, the "Detailed description
/// of the impact including methods used during assessment" (for a
/// vulnerability that is not exploitable, why the component is not
/// impacted). It is the model's impact statement, whatever the state, and
/// stays the status detail too. It is no justification: the CRA
/// vulnerability checks count only a `justification`.
pub(crate) fn vex_status(
    state: Option<&str>,
    justification: Option<&str>,
    responses: &[String],
    detail: Option<&str>,
) -> VexStatus {
    VexStatus {
        status: vex_state(state),
        justification: justification.and_then(vex_justification),
        action_statement: None,
        impact_statement: detail.map(str::to_string),
        responses: responses.iter().filter_map(|r| vex_response(r)).collect(),
        detail: detail.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_map_to_the_model() {
        for (state, expected) in [
            (Some("not_affected"), VexState::NotAffected),
            (Some("false_positive"), VexState::NotAffected),
            (Some("exploitable"), VexState::Affected),
            (Some("affected"), VexState::Affected),
            (Some("resolved"), VexState::Fixed),
            (Some("resolved_with_pedigree"), VexState::Fixed),
            (Some("fixed"), VexState::Fixed),
            (Some("in_triage"), VexState::UnderInvestigation),
            (Some("unknown"), VexState::UnderInvestigation),
            (None, VexState::UnderInvestigation),
        ] {
            assert_eq!(vex_state(state), expected, "{state:?}");
        }
    }

    /// Every CycloneDX 1.6/1.7 justification reads as a model justification.
    #[test]
    fn every_cyclonedx_justification_maps_to_the_closest_model_justification() {
        use VexJustification as J;
        for (cdx, expected) in [
            ("code_not_present", J::VulnerableCodeNotPresent),
            ("code_not_reachable", J::VulnerableCodeNotInExecutePath),
            (
                "requires_configuration",
                J::VulnerableCodeCannotBeControlledByAdversary,
            ),
            (
                "requires_dependency",
                J::VulnerableCodeCannotBeControlledByAdversary,
            ),
            (
                "requires_environment",
                J::VulnerableCodeCannotBeControlledByAdversary,
            ),
            ("protected_by_compiler", J::InlineMitigationsAlreadyExist),
            ("protected_at_runtime", J::InlineMitigationsAlreadyExist),
            (
                "protected_at_perimeter",
                J::VulnerableCodeCannotBeControlledByAdversary,
            ),
            (
                "protected_by_mitigating_control",
                J::InlineMitigationsAlreadyExist,
            ),
        ] {
            assert_eq!(vex_justification(cdx), Some(expected), "{cdx}");
        }
        for unknown in [
            "totally_made_up",
            "component_not_present",
            "",
            "CODE_NOT_PRESENT",
        ] {
            assert_eq!(vex_justification(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn responses_map_to_the_model_and_unknown_ones_are_dropped() {
        let responses = [
            "can_not_fix",
            "will_not_fix",
            "update",
            "rollback",
            "workaround_available",
            "reboot",
        ]
        .map(str::to_string);
        assert_eq!(
            vex_status(Some("exploitable"), None, &responses, None).responses,
            vec![
                VexResponse::CanNotFix,
                VexResponse::WillNotFix,
                VexResponse::Update,
                VexResponse::Rollback,
                VexResponse::Workaround,
            ]
        );
    }

    #[test]
    fn detail_is_the_impact_statement_and_the_detail() {
        let vex = vex_status(
            Some("not_affected"),
            Some("code_not_reachable"),
            &[],
            Some("the parser is never called"),
        );
        assert_eq!(vex.status, VexState::NotAffected);
        assert_eq!(
            vex.justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
        assert_eq!(
            vex.impact_statement.as_deref(),
            Some("the parser is never called")
        );
        assert_eq!(vex.detail.as_deref(), Some("the parser is never called"));
        let bare = vex_status(Some("affected"), None, &[], None);
        assert_eq!(bare.impact_statement, None);
        assert_eq!(bare.detail, None);
    }
}
