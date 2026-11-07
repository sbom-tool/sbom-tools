//! The rules of the EUCC Substantial reference profile.

use super::*;

/// EUCC Substantial remediation, shared by the EUCC evidence rules.
const REMEDIATION_EUCC: &str = "Provide the Common Criteria evidence Implementing Regulation (EU) 2024/482 (EUCC, as amended by Implementing Regulations (EU) 2024/3144 and 2025/2462) expects alongside the SBOM: set euccProtectionProfileId (Protection Profile), euccTargetOfEvaluation (ToE), euccItsefIdentifier (evaluating ITSEF) and euccValidUntil (certificate validity) in the CRA sidecar.";

/// The EUCC regulation as the EUCC rules cite it: Implementing Regulation
/// (EU) 2024/482 with its two amendments (consolidated text of 2025-12-29).
const EUCC_AS_AMENDED: &str = "Reg. (EU) 2024/482 as amended by (EU) 2024/3144 and (EU) 2025/2462";

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
        // ---- EUCC Substantial (reference-only profile) -------------------
        "SBOM-EUCC-PP" => RuleMeta {
            sarif_id: "SBOM-EUCC-PP",
            name: "EuccProtectionProfile",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): Common Criteria Protection Profile reference — sidecar eucc_protection_profile_id",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Protection Profile")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-TOE" => RuleMeta {
            sarif_id: "SBOM-EUCC-TOE",
            name: "EuccTargetOfEvaluation",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): Target of Evaluation reference — sidecar eucc_target_of_evaluation",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ToE")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-ITSEF" => RuleMeta {
            sarif_id: "SBOM-EUCC-ITSEF",
            name: "EuccItsefIdentifier",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): ITSEF (IT Security Evaluation Facility) identifier — sidecar eucc_itsef_identifier",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ITSEF")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-VALIDITY" => RuleMeta {
            sarif_id: "SBOM-EUCC-VALIDITY",
            name: "EuccCertificateValidity",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): certificate valid-until date present, not expired, not near expiry — sidecar eucc_valid_until",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Certificate validity")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-CERTREF" => RuleMeta {
            sarif_id: "SBOM-EUCC-CERTREF",
            name: "EuccCertificationReference",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): Certification/Attestation external reference to an EUCC certificate (recommended)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, "Certification reference")],
            remediation: "Reference the EUCC certificate from the SBOM itself (recommended alongside the sidecar evidence).",
            advice: Some(&ADVICE_EUCC_CERTREF),
        },
        // Generic bucket for EUCC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-EUCC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EUCC-GENERAL",
            name: "EuccGeneralRequirement",
            short_description: "EUCC (Reg. (EU) 2024/482, as amended): general SBOM evidence requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, EUCC_AS_AMENDED)],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        _ => return None,
    };
    Some(meta)
}
