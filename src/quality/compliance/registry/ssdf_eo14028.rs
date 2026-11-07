//! The rules of the NIST SSDF (SP 800-218) and EO 14028 profiles.

use super::*;

/// SSDF practices share one remediation paragraph.
const REMEDIATION_SSDF: &str = "Follow NIST SP 800-218 SSDF practices: include tool provenance, source VCS references, build metadata, and cryptographic hashes for all components.";

/// The EO 14028 §4 SBOM practice rules share one remediation paragraph.
/// The profile follows EO 14028 practice: OMB M-26-05 (2026-01-23)
/// rescinded the M-22-18 / M-23-16 attestation mandate built on it.
const REMEDIATION_EO14028: &str = "Follow the SBOM practice of EO 14028 §4(e): use a machine-readable format (CycloneDX 1.4+, SPDX 2.2+, or SPDX 3.0+), generate the SBOM with a tool, and include unique identifiers, versions, hashes, dependencies and supplier information. This is practice, not a federal mandate: OMB M-26-05 rescinded the M-22-18 attestation requirement, though an agency may still ask for an SBOM in its contract.";

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
        // Catch-all rule keys for the SSDF / EO 14028 profiles; not currently
        // emitted by any check site but kept so the registry mirrors the full
        // SARIF rule catalogue.
        "SBOM-SSDF-GENERAL" => RuleMeta {
            sarif_id: "SBOM-SSDF-GENERAL",
            name: "SsdfGeneralRequirement",
            short_description: "NIST SSDF: General secure development requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "SP 800-218")],
            remediation: REMEDIATION_SSDF,
            advice: None,
        },
        "SBOM-EO14028-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EO14028-GENERAL",
            name: "Eo14028GeneralRequirement",
            short_description: "EO 14028: General SBOM practice",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: None,
        },
        // ---- NIST SSDF ---------------------------------------------------
        "SBOM-SSDF-PS1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1",
            name: "SsdfProvenance",
            short_description: "NIST SSDF PS.1: Provenance — SBOM creator identified",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_CREATORS),
        },
        // The PS.1 generation-tool check, a second document-level finding
        // beside the creator check above.
        "SBOM-SSDF-PS1-TOOL" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1-TOOL",
            name: "SsdfGenerationTool",
            short_description: "NIST SSDF PS.1: Tool that generated the SBOM identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: "Identify the tool that generated the SBOM, so its provenance shows how it was produced (NIST SSDF PS.1).",
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-SSDF-PS2" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS2",
            name: "SsdfBuildIntegrity",
            short_description: "NIST SSDF PS.2: Build integrity — component cryptographic hashes",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.2")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-SSDF-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-SSDF-INVENTORY",
            name: "SsdfInventory",
            short_description: "NIST SSDF PS.3.2: provenance data (SBOM) lists the release's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.3.2")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-SSDF-PS3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS3",
            name: "SsdfSupplierIdentification",
            short_description: "NIST SSDF PS.3: Supplier identification for components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.3")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-SSDF-PO1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO1",
            name: "SsdfSourceProvenance",
            short_description: "NIST SSDF PO.1: Source code provenance — VCS references",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PO.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_VCS),
        },
        "SBOM-SSDF-PO3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO3",
            name: "SsdfBuildMetadata",
            short_description: "NIST SSDF PO.3: Build provenance — build system metadata",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PO.3")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_BUILD),
        },
        "SBOM-SSDF-PW4" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW4",
            name: "SsdfDependencyManagement",
            short_description: "NIST SSDF PW.4: Dependency management — relationships",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PW.4")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-SSDF-PW6" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW6",
            name: "SsdfVulnerabilityInfo",
            short_description: "NIST SSDF PW.6: Vulnerability information and security references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PW.6")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-SSDF-RV1" => RuleMeta {
            sarif_id: "SBOM-SSDF-RV1",
            name: "SsdfComponentIdentification",
            short_description: "NIST SSDF RV.1: Component identification — unique identifiers",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "RV.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        // ---- EO 14028 ----------------------------------------------------
        "SBOM-EO14028-FORMAT" => RuleMeta {
            sarif_id: "SBOM-EO14028-FORMAT",
            name: "Eo14028MachineReadable",
            short_description: "EO 14028 §4(e) practice: Machine-readable SBOM format",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: None,
        },
        "SBOM-EO14028-AUTOGEN" => RuleMeta {
            sarif_id: "SBOM-EO14028-AUTOGEN",
            name: "Eo14028AutoGeneration",
            short_description: "EO 14028 §4(e) practice: Automated SBOM generation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-EO14028-CREATOR" => RuleMeta {
            sarif_id: "SBOM-EO14028-CREATOR",
            name: "Eo14028Creator",
            short_description: "EO 14028 §4(e) practice: SBOM creator identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-EO14028-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-IDENTIFIER",
            name: "Eo14028Identifier",
            short_description: "EO 14028 §4(e) practice: Component unique identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-EO14028-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-EO14028-DEPENDENCY",
            name: "Eo14028Dependency",
            short_description: "EO 14028 §4(e) practice: Dependency relationship information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-EO14028-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INVENTORY",
            name: "Eo14028Inventory",
            short_description: "EO 14028 §4(e) practice: SBOM lists the software's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-EO14028-VERSION" => RuleMeta {
            sarif_id: "SBOM-EO14028-VERSION",
            name: "Eo14028Version",
            short_description: "EO 14028 §4(e) practice: Component version information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-EO14028-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INTEGRITY",
            name: "Eo14028Integrity",
            short_description: "EO 14028 §4(e) practice: Component integrity verification (hashes)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-EO14028-DISCLOSURE" => RuleMeta {
            sarif_id: "SBOM-EO14028-DISCLOSURE",
            name: "Eo14028Disclosure",
            short_description: "EO 14028 §4(e)(viii) practice: Vulnerability disclosure program",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-EO14028-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-SUPPLIER",
            name: "Eo14028Supplier",
            short_description: "EO 14028 §4(e) practice: Supplier identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-EO14028-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-EO14028-TIMESTAMP",
            name: "Eo14028Timestamp",
            short_description: "EO 14028 §4(e) practice: SBOM creation timestamp (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4"), (K::NtiaMinimum, "Timestamp")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-EO14028-NAME" => RuleMeta {
            sarif_id: "SBOM-EO14028-NAME",
            name: "Eo14028ComponentName",
            short_description: "EO 14028 §4(e) practice: Component name (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (K::Eo14028, "EO 14028 §4"),
                (K::NtiaMinimum, "Component Name"),
            ],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_NAME),
        },
        _ => return None,
    };
    Some(meta)
}
