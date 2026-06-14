//! Compliance rule registry: the single source of truth for SARIF rule
//! IDs, harmonised-standard cross-references, and remediation text, keyed
//! by the stable internal `Violation::rule_id`.

use super::{StandardKind, ViolationSeverity};

/// Static metadata attached to a compliance rule. The `rule_id` on every
/// [`Violation`] indexes into [`rule_meta`]; the registry — not the
/// human-readable message — is the single source of truth for the
/// externally-visible SARIF rule ID, the harmonised-standard cross-references,
/// and the remediation text. Rewording a message can no longer silently
/// re-bucket a GitHub code-scanning rule or drop a prEN/BSI reference.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    /// Externally-visible SARIF rule ID (e.g., `SBOM-CRA-ART-13-4`). GitHub
    /// code scanning dedups on this value, so it must stay stable.
    pub sarif_id: &'static str,
    /// Documentation-default severity for the rule. Push sites may still
    /// escalate/relax the concrete [`Violation::severity`] by product class or
    /// CRA phase; this default is surfaced in the SARIF rule catalogue.
    pub default_severity: ViolationSeverity,
    /// Harmonised-standard / regulation cross-references, in display order.
    pub refs: &'static [(StandardKind, &'static str)],
    /// Remediation guidance shown in reports and the TUI.
    pub remediation: &'static str,
}

/// Generic fallback remediation, shared by rules with no bespoke guidance.
pub(crate) const REMEDIATION_GENERIC: &str = "Review the requirement and update the SBOM accordingly. Consult the EU CRA regulation (EU 2024/2847) for detailed guidance.";

/// SSDF practices share one remediation paragraph.
const REMEDIATION_SSDF: &str = "Follow NIST SP 800-218 SSDF practices: include tool provenance, source VCS references, build metadata, and cryptographic hashes for all components.";

/// EO 14028 §4 requirements share one remediation paragraph.
const REMEDIATION_EO14028: &str = "Follow EO 14028 Section 4(e) requirements: use a machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+), auto-generate the SBOM, include unique identifiers, versions, hashes, dependencies, and supplier information.";

/// EU AI Act not-applicable remediation.
const REMEDIATION_AIACT_NA: &str = "EU AI Act Annex IV readiness applies only to SBOMs that describe AI/ML systems. Add machine-learning-model or dataset components (CycloneDX 1.5+ AI/ML BOM) to enable the assessment.";

/// Look up the static [`RuleMeta`] for a stable internal rule key.
///
/// The key is the [`Violation::rule_id`] set at each check site. Returns
/// `None` for unregistered keys — the exhaustive test
/// `every_emitted_violation_has_a_registered_rule_id` guarantees no live check
/// site emits an unregistered key.
#[must_use]
pub fn rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    const CRA: K = K::CraArticle;
    const ANNEX: K = K::CraAnnex;
    const PREN: K = K::Pren40000_1_3;
    let meta = match rule_id {
        // ---- CRA Articles ------------------------------------------------
        "SBOM-CRA-ART-13-2" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(2)")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ART-13-3" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-3",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(3)")],
            remediation: "Regenerate the SBOM when components are added, removed, or updated. CRA Art. 13(3) requires timely updates reflecting the current state of the software.",
        },
        "SBOM-CRA-ART-13-4" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-4",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(4)"), (PREN, "PRE-7-RQ-04")],
            remediation: "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML), SPDX 2.3+ (JSON or tag-value), or SPDX 3.0+ (JSON-LD). Older format versions may not be recognized as machine-readable under the CRA.",
        },
        "SBOM-CRA-ART-13-5" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(5)")],
            remediation: "Ensure every component has license information. CycloneDX: use component.licenses[]. SPDX 2.x: use PackageLicenseDeclared / PackageLicenseConcluded. SPDX 3.0: use HAS_DECLARED_LICENSE / HAS_CONCLUDED_LICENSE relationships.",
        },
        "SBOM-CRA-ART-13-6-CONTACT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-6",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(6)")],
            remediation: "Add a security contact or vulnerability disclosure URL. CycloneDX: add a component externalReference with type 'security-contact' or set metadata.manufacturer.contact. SPDX: add an SECURITY external reference.",
        },
        "SBOM-CRA-ART-13-6-METADATA" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-6",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(6)")],
            remediation: "Add severity (e.g., CVSS score) and remediation details to each vulnerability entry. CycloneDX: use vulnerability.ratings[].score and vulnerability.analysis. SPDX: use annotation or externalRef.",
        },
        "SBOM-CRA-ART-13-7" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-7",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(7)"), (PREN, "RLS-2-RQ-03-RE")],
            remediation: "Reference a coordinated vulnerability disclosure policy. CycloneDX: add an externalReference of type 'advisories' linking to your disclosure policy. SPDX: add an external document reference.",
        },
        "SBOM-CRA-ART-13-8" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-8",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(8)")],
            remediation: "Specify when security updates will no longer be provided. CycloneDX 1.5+: use component.releaseNotes or metadata properties. SPDX: use an annotation with end-of-support date.",
        },
        "SBOM-CRA-ART-13-9" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-9",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(9)")],
            remediation: "Include vulnerability data or add a vulnerability-assertion external reference stating no known vulnerabilities. CycloneDX: use the vulnerabilities array. SPDX: use annotations or external references.",
        },
        "SBOM-CRA-ART-13-11" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-11",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(11)")],
            remediation: "Include lifecycle or end-of-support metadata for components. CycloneDX: use component properties (e.g., cdx:lifecycle:status). SPDX: use annotations.",
        },
        "SBOM-CRA-ART-13-12-PRODUCT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-12",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(12)")],
            remediation: "The SBOM must identify the product by name. CycloneDX: set metadata.component.name. SPDX: set documentDescribes with the primary package name.",
        },
        "SBOM-CRA-ART-13-12-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-12",
            default_severity: ViolationSeverity::Error,
            refs: &[(CRA, "Art. 13(12)"), (PREN, "PRE-7-RQ-06")],
            remediation: "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder.",
        },
        "SBOM-CRA-ART-13-15" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-15",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(15)")],
            remediation: "Identify the manufacturer/supplier. CycloneDX: set metadata.manufacturer or component.supplier. SPDX: set PackageSupplier.",
        },
        "SBOM-CRA-ART-13-15-EMAIL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-15",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(15)")],
            remediation: "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts.",
        },
        "SBOM-CRA-ART-14" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 14")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ART-24" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- CRA Annexes -------------------------------------------------
        "SBOM-CRA-ANNEX-I-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I"), (PREN, "PRE-7-RQ-07")],
            remediation: "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
        },
        "SBOM-CRA-ANNEX-I-TRACEABILITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II"), (PREN, "PRE-7-RQ-07")],
            remediation: "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
        },
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (ANNEX, "Annex I Part III"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
            ],
            remediation: "Add dependency relationships between components. CycloneDX: use the dependencies array. SPDX: use DEPENDS_ON relationships.",
        },
        "SBOM-CRA-ANNEX-I-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
        },
        "SBOM-CRA-ANNEX-I-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Add dependency relationships between components. CycloneDX: use the dependencies array. SPDX: use DEPENDS_ON relationships.",
        },
        "SBOM-CRA-ANNEX-I-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the top-level product component. CycloneDX: set metadata.component. SPDX: use documentDescribes to point to the primary package.",
        },
        "SBOM-CRA-ANNEX-I-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ANNEX-III" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-III",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex III")],
            remediation: "Add document-level integrity metadata: a serial number (CycloneDX: serialNumber, SPDX: documentNamespace), or a digital signature/attestation with a cryptographic hash.",
        },
        "SBOM-CRA-ANNEX-IV" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex IV")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ANNEX-VII" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-VII",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex VII")],
            remediation: "Reference the EU Declaration of Conformity. CycloneDX: add an externalReference of type 'attestation' or 'certification'. SPDX: add an external document reference.",
        },
        "SBOM-CRA-ANNEX-VIII" => RuleMeta {
            // Historically matched the "annex vii" substring of "annex viii".
            sarif_id: "SBOM-CRA-ANNEX-VII",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex VIII")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-PRE-8-RQ-02" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-PRE-7-RQ-07-RE" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-7-RQ-07-RE",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-07"),
                (PREN, "PRE-7-RQ-07-RE"),
            ],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
        },
        // ---- Generic CRA / document-level (no specific article) ----------
        "SBOM-CRA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- EUCC Substantial (reference-only profile) -------------------
        "SBOM-EUCC" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- EU AI Act Annex IV technical-documentation readiness --------
        "SBOM-AIACT-NA" => RuleMeta {
            sarif_id: "SBOM-AIACT-NA",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: REMEDIATION_AIACT_NA,
        },
        "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Add a general description of the AI model: architecture family/name and a model-card reference. CycloneDX: set modelCard.modelParameters.architectureFamily / modelArchitecture and an external reference of type 'model-card'.",
        },
        "SBOM-AIACT-ANNEX-IV-1-PURPOSE" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Document the intended purpose / use-cases of the AI model. CycloneDX: set modelCard.considerations.useCases.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-DATASETS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Reference the training datasets used. CycloneDX: set modelCard.modelParameters.datasets with a {ref} to a data component.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Declare a sensitivity classification for each dataset (e.g. 'none', 'pii', 'personal'). CycloneDX: set the data component's sensitiveData array.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Where training data involves personal data, document the GDPR lawful basis and data-protection measures alongside the SBOM (AI Act and GDPR apply in parallel).",
        },
        "SBOM-AIACT-ANNEX-IV-2G-METRICS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: "Record validation/testing metrics (accuracy, robustness). CycloneDX: set modelCard.quantitativeAnalysis.performanceMetrics.",
        },
        "SBOM-AIACT-ANNEX-IV-2G-ENERGY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: "Disclose computational resources / training energy. CycloneDX: set modelCard.considerations.environmentalConsiderations.energyConsumptions.",
        },
        "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-3",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §3")],
            remediation: "State the foreseeable limitations and risks of the model, including ethical and fairness considerations. CycloneDX: set modelCard.considerations.technicalLimitations / ethicalConsiderations / fairnessAssessments.",
        },
        // ---- NTIA --------------------------------------------------------
        "SBOM-NTIA-VERSION" => RuleMeta {
            sarif_id: "SBOM-NTIA-VERSION",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-NTIA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-SUPPLIER",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-NTIA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-NTIA-DEPENDENCY",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- FDA ---------------------------------------------------------
        "SBOM-FDA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPLIER",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-SUPPORT" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPORT",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-NAME" => RuleMeta {
            sarif_id: "SBOM-FDA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-VERSION" => RuleMeta {
            sarif_id: "SBOM-FDA-VERSION",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-FDA-IDENTIFIER",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-HASH" => RuleMeta {
            sarif_id: "SBOM-FDA-HASH",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        // FDA rules emitted by the `validate` NTIA/FDA fast-path
        // (`cli::validate`), which builds violations directly without
        // populating `standard_refs`.
        "SBOM-FDA-CREATOR" => RuleMeta {
            sarif_id: "SBOM-FDA-CREATOR",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-NAMESPACE" => RuleMeta {
            sarif_id: "SBOM-FDA-NAMESPACE",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-FDA-DEPENDENCY",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-SECURITY" => RuleMeta {
            sarif_id: "SBOM-FDA-SECURITY",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-FDA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-FDA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC,
        },
        // NTIA rules emitted by the `validate` fast-path.
        "SBOM-NTIA-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-NTIA-AUTHOR",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-NTIA-NAME" => RuleMeta {
            sarif_id: "SBOM-NTIA-NAME",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-NTIA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-IDENTIFIER",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-NTIA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-NTIA-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC,
        },
        // Catch-all rule keys for the SSDF / EO 14028 profiles; not currently
        // emitted by any check site but kept so the registry mirrors the full
        // SARIF rule catalogue.
        "SBOM-SSDF-GENERAL" => RuleMeta {
            sarif_id: "SBOM-SSDF-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "SP 800-218")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-EO14028-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EO14028-GENERAL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        // ---- NIST SSDF ---------------------------------------------------
        "SBOM-SSDF-PS1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PS2" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS2",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.2")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PS3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS3",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.3")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PO1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO1",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PO.1")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PO3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO3",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PO.3")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PW4" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW4",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PW.4")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PW6" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW6",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PW.6")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-RV1" => RuleMeta {
            sarif_id: "SBOM-SSDF-RV1",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "RV.1")],
            remediation: REMEDIATION_SSDF,
        },
        // ---- EO 14028 ----------------------------------------------------
        "SBOM-EO14028-FORMAT" => RuleMeta {
            sarif_id: "SBOM-EO14028-FORMAT",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-AUTOGEN" => RuleMeta {
            sarif_id: "SBOM-EO14028-AUTOGEN",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-CREATOR" => RuleMeta {
            sarif_id: "SBOM-EO14028-CREATOR",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-IDENTIFIER",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-EO14028-DEPENDENCY",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-VERSION" => RuleMeta {
            sarif_id: "SBOM-EO14028-VERSION",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INTEGRITY",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-DISCLOSURE" => RuleMeta {
            sarif_id: "SBOM-EO14028-DISCLOSURE",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-SUPPLIER",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        // ---- BSI TR-03183-2 ----------------------------------------------
        "SBOM-BSI-TR-03183-2-5-1" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-1",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.1")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-BSI-TR-03183-2-5-2" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-2",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-BSI-TR-03183-2-5-3" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-3",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.3")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-BSI-TR-03183-2-5-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-4",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.4")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-BSI-TR-03183-2-5-5" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-5",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.5")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-BSI-TR-03183-2-6" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-6",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiTr03183_2, "§6")],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- CNSA 2.0 ----------------------------------------------------
        "SBOM-CNSA2-ALG-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-001",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-ALG-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-002",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-ALG-003" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-003",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-ALG-004" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-004",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-ALG-006" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-006",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-ALG-007" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-007",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CNSA2-CERT-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-001",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- NIST PQC ----------------------------------------------------
        "SBOM-PQC-001" => RuleMeta {
            sarif_id: "SBOM-PQC-001",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-012" => RuleMeta {
            sarif_id: "SBOM-PQC-012",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-010" => RuleMeta {
            sarif_id: "SBOM-PQC-010",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-005" => RuleMeta {
            sarif_id: "SBOM-PQC-005",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-008" => RuleMeta {
            sarif_id: "SBOM-PQC-008",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-009" => RuleMeta {
            sarif_id: "SBOM-PQC-009",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "NIST PQC")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-PQC-KEY-001" => RuleMeta {
            sarif_id: "SBOM-PQC-KEY-001",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        _ => return None,
    };
    Some(meta)
}
