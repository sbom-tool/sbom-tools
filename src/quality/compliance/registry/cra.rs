//! The rules of the EU Cyber Resilience Act profiles: the CRA articles
//! and annexes, the prEN 40000-1-3 requirements, and the generic-path
//! document checks of the CRA phases and the Art. 24 steward profile.

use super::*;

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    const CRA: K = K::CraArticle;
    const ANNEX: K = K::CraAnnex;
    const PREN: K = K::Pren40000_1_3;
    const ENISA: K = K::EnisaSbomAdvisory;
    let meta = match rule_id {
        // ---- CRA Articles ------------------------------------------------
        "SBOM-CRA-ART-13-2" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-2",
            name: "CraRiskAssessment",
            short_description: "CRA Art. 13(2): Reference to the documented cybersecurity risk assessment",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(2)")],
            remediation: "Reference the documented cybersecurity risk assessment Art. 13(2) requires: set riskAssessmentUrl in the CRA sidecar to its URL or document reference.",
            advice: Some(&ADVICE_RISK_ASSESSMENT),
        },
        // SBOM freshness. Formerly cited Art. 13(3), which is the risk-
        // assessment documentation paragraph; keeping the SBOM current is
        // the Art. 13(7) systematic-documentation duty applied to the
        // Annex I Part II (1) SBOM element.
        "SBOM-CRA-SBOM-FRESHNESS" => RuleMeta {
            sarif_id: "SBOM-CRA-SBOM-FRESHNESS",
            name: "CraSbomFreshness",
            short_description: "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness — timely regeneration after changes",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (CRA, "Art. 13(7)"),
                (ANNEX, "Annex I Part II (1)"),
                (ENISA, "§3.2"),
            ],
            remediation: "Regenerate the SBOM when components are added, removed, or updated. CRA Art. 13(7) requires manufacturers to systematically document relevant cybersecurity aspects, and the Annex I Part II (1) SBOM must reflect the product's current components. A creation timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
            advice: None,
        },
        // Machine-readable SBOM format. The mandate for a 'commonly used and
        // machine-readable format' lives in Annex I Part II (1), not in
        // Art. 13(4) (which puts the risk assessment into the technical
        // documentation).
        "SBOM-CRA-MACHINE-READABLE" => RuleMeta {
            sarif_id: "SBOM-CRA-MACHINE-READABLE",
            name: "CraMachineReadableFormat",
            short_description: "CRA Annex I Part II (1): SBOM must be in a commonly used, machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+)",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II (1)"),
                (PREN, "PRE-7-RQ-04"),
                (ENISA, "§2.1.2"),
            ],
            remediation: "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML), SPDX 2.3+ (JSON or tag-value), or SPDX 3.0+ (JSON-LD). Older format versions may not be recognized as machine-readable under CRA Annex I Part II (1).",
            advice: None,
        },
        // Component licence information. The CRA does not list licences as
        // an SBOM element; they are evidence supporting the Art. 13(5)
        // third-party due-diligence obligation.
        "SBOM-CRA-ART-13-5" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5",
            name: "CraLicensedComponentTracking",
            short_description: "CRA Art. 13(5): Third-party due diligence — license information for all components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(5)"), (ENISA, "§2.1.1")],
            remediation: "Record license information for every component to support the Art. 13(5) due diligence on integrated third-party components.",
            advice: Some(&ADVICE_LICENSE),
        },
        // The SPDX 3.0 SimpleLicensing profile declaration, a document-level
        // check apart from the licence coverage above.
        "SBOM-CRA-ART-13-5-PROFILE" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5-PROFILE",
            name: "CraLicensingProfileConformance",
            short_description: "CRA Art. 13(5): SPDX 3.0 SimpleLicensing profile declared for a document that carries license data",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(5)")],
            remediation: "Declare SPDX 3.0 SimpleLicensing profile conformance when the document carries license data, so its Art. 13(5) licence evidence is conveyed completely.",
            advice: Some(&ADVICE_LICENSING_PROFILE),
        },
        // Single point of contact for vulnerability reporting. Formerly
        // cited Art. 13(6), which is the manufacturer's duty to report
        // component vulnerabilities UPSTREAM to the component maintainer;
        // the user-facing contact is Art. 13(17) / Annex I Part II (6) /
        // Annex II (2).
        "SBOM-CRA-ART-13-17-CONTACT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-17-CONTACT",
            name: "CraVulnerabilityContact",
            short_description: "CRA Art. 13(17): Single point of contact for vulnerability reporting (Annex I Part II (6), Annex II (2))",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (CRA, "Art. 13(17)"),
                (ANNEX, "Annex I Part II (6)"),
                (ANNEX, "Annex II (2)"),
            ],
            remediation: "Give the product a single point of contact for vulnerability reports (Art. 13(17)): a security contact or vulnerability-disclosure URL referenced from the product component. securityContact or vulnerabilityDisclosureUrl in the CRA sidecar lowers the finding to Info. A contact must reach someone: placeholders such as NOASSERTION, unknown, n/a or TBD, and addresses at example.com, example.net or example.org, do not count.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        // Vulnerability severity/remediation metadata. Anchored to the
        // Annex I Part II (4) duty to share information about fixed
        // vulnerabilities (description, impacts, severity, remediation).
        // One finding per vulnerability of a component, told apart by the
        // vulnerability id (`finding_detail`). The remediation-detail and
        // SPDX 3.0 profile checks report under their own ids below. Both
        // per-vulnerability checks skip an entry whose own VEX statement
        // is not_affected with a justification: the CRA FAQ (v1.4, 4.3.1)
        // lets the manufacturer document a vulnerability that cannot be
        // exploited and not fix it, and (4) covers fixed vulnerabilities.
        "SBOM-CRA-VULN-METADATA" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA",
            name: "CraVulnerabilityMetadata",
            short_description: "CRA Annex I Part II (4): Vulnerability entries carry a severity or CVSS score",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Give every vulnerability entry a severity or CVSS score (Annex I Part II (4)). An entry whose VEX statement is not_affected and names a justification needs neither: it documents a vulnerability that cannot be exploited in the product, which the CRA FAQ (v1.4, 4.3.1) says the manufacturer may decide not to fix.",
            advice: Some(&ADVICE_VULN_SEVERITY),
        },
        "SBOM-CRA-VULN-METADATA-REMEDIATION" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA-REMEDIATION",
            name: "CraVulnerabilityRemediationDetail",
            short_description: "CRA Annex I Part II (4): Vulnerability remediations name a fixed version or describe the fix",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Give every vulnerability remediation a fixed version or a description of the fix (Annex I Part II (4)). A vulnerability whose VEX statement is not_affected and names a justification is exempt: it documents a vulnerability that cannot be exploited in the product, which the CRA FAQ (v1.4, 4.3.1) says the manufacturer may decide not to fix.",
            advice: Some(&ADVICE_VULN_REMEDIATION),
        },
        "SBOM-CRA-VULN-METADATA-PROFILE" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA-PROFILE",
            name: "CraSecurityProfileConformance",
            short_description: "CRA Annex I Part II (4): SPDX 3.0 Security profile declared for a document that carries vulnerabilities",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Declare SPDX 3.0 Security profile conformance when the document carries vulnerabilities, so the vulnerability information it conveys is complete (Annex I Part II (4)).",
            advice: Some(&ADVICE_SECURITY_PROFILE),
        },
        // Coordinated vulnerability disclosure policy. Formerly cited
        // Art. 13(7) (systematic documentation); the CVD-policy duty is
        // Annex I Part II (5), reinforced by Art. 13(8).
        "SBOM-CRA-CVD-POLICY" => RuleMeta {
            sarif_id: "SBOM-CRA-CVD-POLICY",
            name: "CraCoordinatedDisclosure",
            short_description: "CRA Annex I Part II (5): Coordinated vulnerability disclosure policy reference",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II (5)"),
                (CRA, "Art. 13(8)"),
                (PREN, "RLS-2-RQ-03-RE"),
            ],
            remediation: "Reference the coordinated vulnerability disclosure policy (Annex I Part II (5)) from the product component. In the CRA sidecar, coordinatedDisclosurePolicyUrl satisfies the open-source steward profile and vulnerabilityDisclosureUrl lowers the manufacturer finding to Info. A placeholder URL or an address at example.com, example.net or example.org does not count.",
            advice: Some(&ADVICE_CVD),
        },
        "SBOM-CRA-ART-13-8" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-8",
            name: "CraSupportPeriod",
            short_description: "CRA Art. 13(8) / 13(19): Support period and security update end date (Annex II (7))",
            default_severity: ViolationSeverity::Info,
            refs: &[
                (CRA, "Art. 13(8)"),
                (CRA, "Art. 13(19)"),
                (ANNEX, "Annex II (7)"),
            ],
            remediation: "Declare when security updates end (Art. 13(8) / 13(19)): set supportEndDate in the CRA sidecar, or record the date in the SBOM.",
            advice: Some(&ADVICE_SUPPORT_END),
        },
        // Components the end-of-life data marks as no longer supported: a
        // document-level count apart from the missing support end date.
        "SBOM-CRA-ART-13-8-EOL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-8-EOL",
            name: "CraEndOfLifeComponents",
            short_description: "CRA Art. 13(8): Components past end-of-life, which receive no more security updates",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(8)")],
            remediation: "Upgrade or replace the components the end-of-life data marks as no longer supported: they receive no more security updates (Art. 13(8)).",
            advice: None,
        },
        // Documented vulnerability information. Formerly cited Art. 13(9),
        // which is actually the 10-year availability of issued security
        // updates; the documentation obligation is Annex I Part II (1).
        "SBOM-CRA-VULN-STATEMENT" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-STATEMENT",
            name: "CraKnownVulnerabilities",
            short_description: "CRA Annex I Part II (1): Documented vulnerability information — vulnerability data or assertion",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: "Include the product's known vulnerabilities in the SBOM, or reference the vulnerability disclosure report (VDR) or VEX that states them (Annex I Part II (1)).",
            advice: Some(&ADVICE_VULN_DATA),
        },
        // Component lifecycle / end-of-support. Formerly cited Art. 13(11),
        // which is about OPTIONAL public software archives; lifecycle
        // handling is the Art. 13(8) support-period duty plus the
        // Annex II (7) support end-date disclosure.
        "SBOM-CRA-LIFECYCLE" => RuleMeta {
            sarif_id: "SBOM-CRA-LIFECYCLE",
            name: "CraComponentLifecycle",
            short_description: "CRA Art. 13(8) / Annex II (7): Component lifecycle and end-of-support status",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(8)"), (ANNEX, "Annex II (7)")],
            remediation: "Record component lifecycle or end-of-support status (Art. 13(8) / Annex II (7)); supportEndDate in the CRA sidecar counts too.",
            advice: Some(&ADVICE_LIFECYCLE),
        },
        // Components the end-of-life data shows reaching end-of-life within
        // six months: a document-level count apart from the missing
        // lifecycle evidence.
        "SBOM-CRA-LIFECYCLE-APPROACHING-EOL" => RuleMeta {
            sarif_id: "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
            name: "CraApproachingEndOfLife",
            short_description: "CRA Art. 13(8) / Annex II (7): Components reaching end-of-life within six months",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(8)"), (ANNEX, "Annex II (7)")],
            remediation: "Plan replacements for the components the end-of-life data shows reaching end-of-life within six months (Art. 13(8) / Annex II (7)).",
            advice: None,
        },
        // Product identification. Formerly cited Art. 13(12) (technical
        // documentation + conformity assessment + DoC + CE marking); product
        // identification is Art. 13(15) plus Annex II (3).
        "SBOM-CRA-ART-13-15-PRODUCT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-15-PRODUCT",
            name: "CraProductIdentification",
            short_description: "CRA Art. 13(15): Product identification (Annex II (3))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(15)"), (ANNEX, "Annex II (3)")],
            remediation: "Name the product the SBOM describes (Art. 13(15)); productName in the CRA sidecar lowers this to Info, but the SBOM should carry the name itself.",
            advice: Some(&ADVICE_DOC_NAME),
        },
        // Component version. Formerly cited Art. 13(12); versions are part
        // of the Annex I Part II (1) SBOM element inventory.
        "SBOM-CRA-COMPONENT-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-VERSION",
            name: "CraComponentVersion",
            short_description: "CRA Annex I Part II (1): Component version identification",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (ANNEX, "Annex I Part II (1)"),
                (PREN, "PRE-7-RQ-06"),
                (ENISA, "§2.1.1"),
            ],
            remediation: "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-CRA-ART-24-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-24-SUPPLIER",
            name: "CraStewardComponentSupplier",
            short_description: "CRA Art. 24: Component supplier identification (open-source steward SBOM floor)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 24"), (ENISA, "§2.1.1")],
            remediation: "Identify each component's supplier as part of the Art. 24 steward SBOM floor.",
            advice: Some(&ADVICE_PRODUCER),
        },
        // Manufacturer identification. Formerly cited Art. 13(15), which is
        // PRODUCT identification (type/batch/serial number); manufacturer
        // identification (name + postal/email/website) is Art. 13(16) plus
        // Annex II (1).
        "SBOM-CRA-ART-13-16" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-16",
            name: "CraManufacturerIdentification",
            short_description: "CRA Art. 13(16): Manufacturer identification and contact information (Annex II (1))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(16)"), (ANNEX, "Annex II (1)")],
            remediation: "Identify the manufacturer (Art. 13(16)): as the manufacturer or supplier of the product component, or as an organization creator of the SBOM; placeholders such as NOASSERTION do not count. manufacturerName in the CRA sidecar lowers this to Info.",
            advice: Some(&ADVICE_MANUFACTURER),
        },
        "SBOM-CRA-ART-13-16-EMAIL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-16-EMAIL",
            name: "CraManufacturerEmail",
            short_description: "CRA Art. 13(16): Valid manufacturer contact email (Annex II (1))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(16)"), (ANNEX, "Annex II (1)")],
            remediation: "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts.",
            advice: Some(&ADVICE_ORG_EMAIL),
        },
        // Per-component supplier identification. Distinct from the
        // Art. 13(16) manufacturer-identification obligation: component
        // suppliers are part of the Annex I Part II (1) SBOM inventory.
        "SBOM-CRA-COMPONENT-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-SUPPLIER",
            name: "CraComponentSupplier",
            short_description: "CRA Annex I Part II (1): Component supplier identification",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II (1)"),
                (PREN, "PRE-7-RQ-03"),
                (ENISA, "§2.1.1"),
            ],
            remediation: "Identify each component's supplier; placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_PRODUCER),
        },
        // Art. 14 reporting readiness: one rule per channel, each read from
        // the CRA sidecar only. Formerly one SBOM-CRA-ART-14 rule whose four
        // findings on the document shared a finding key. A missing PSIRT,
        // early-warning or notification channel is a Warning since the
        // 2026-09-11 deadline (an Info before it), escalated to Error for
        // important class II and critical products; the ENISA platform
        // finding follows the same dates but is never escalated.
        "SBOM-CRA-ART-14-PSIRT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-PSIRT",
            name: "CraPsirtUrl",
            short_description: "CRA Art. 14: Public PSIRT URL that receives external vulnerability reports",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14")],
            remediation: "Document the public PSIRT URL that receives external vulnerability reports (Art. 14 reporting readiness): set psirtUrl in the CRA sidecar. This check reads only the sidecar; a placeholder such as TBD or an address at example.com, example.net or example.org does not count.",
            advice: None,
        },
        "SBOM-CRA-ART-14-EARLY-WARNING" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-EARLY-WARNING",
            name: "CraEarlyWarningChannel",
            short_description: "CRA Art. 14(2)(a) / 14(4)(a): Channel for the 24-hour early warning",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14(2)(a)"), (CRA, "Art. 14(4)(a)")],
            remediation: "Document the channel for the 24-hour early warning of an actively exploited vulnerability or a severe incident (Art. 14(2)(a) / 14(4)(a)): set earlyWarningContact in the CRA sidecar. This check reads only the sidecar; a placeholder such as TBD or an address at example.com, example.net or example.org does not count.",
            advice: None,
        },
        "SBOM-CRA-ART-14-NOTIFICATION" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-NOTIFICATION",
            name: "CraNotificationChannel",
            short_description: "CRA Art. 14(2)(b) / 14(4)(b): Channel for the 72-hour vulnerability and incident notifications",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14(2)(b)"), (CRA, "Art. 14(4)(b)")],
            remediation: "Document the channel for the 72-hour vulnerability and incident notifications (Art. 14(2)(b) / 14(4)(b)): set incidentReportContact in the CRA sidecar. This check reads only the sidecar; a placeholder such as TBD or an address at example.com, example.net or example.org does not count.",
            advice: None,
        },
        // Warning once Art. 14 applies (2026-09-11), Info before, never an
        // Error: the CRA routes every notification through the platform
        // but names no manufacturer identifier on it.
        "SBOM-CRA-ART-14-ENISA" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-ENISA",
            name: "CraEnisaPlatformIdentifier",
            short_description: "CRA Art. 14(7): How the manufacturer reaches the ENISA single reporting platform",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14(7)")],
            remediation: "Name the CSIRT designated as coordinator in enisaReportingPlatformId in the CRA sidecar: the one Art. 14(7) assigns by the manufacturer's main establishment and every notification selects on the ENISA Single Reporting Platform (https://portal.cra-srp.enisa.europa.eu/), through which Art. 14(1), (3) and (7) route notifications since 2026-09-11. Naming that CSIRT satisfies this finding. Do not register on the platform early to clear it: no registration is needed before a notification is due, and ENISA advises registering only then. A registration already made may be recorded instead. This check reads only the sidecar.",
            advice: None,
        },
        // The steward's vulnerability-handling floor is the one Art. 24
        // obligation the profile gates on: always an Error.
        "SBOM-CRA-ART-24" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-24",
            name: "CraStewardVulnerabilityHandling",
            short_description: "CRA Art. 24: Open-source steward vulnerability-handling process (security contact or disclosure URL)",
            default_severity: ViolationSeverity::Error,
            refs: &[(CRA, "Art. 24")],
            remediation: "Show the open-source steward's vulnerability-handling process (Art. 24): reference a security contact or vulnerability-disclosure URL from the product component, or set psirtUrl or vulnerabilityDisclosureUrl in the CRA sidecar. A contact must reach someone: placeholders such as NOASSERTION or n/a, and addresses at example.com, example.net or example.org, do not count.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        // ---- CRA Annexes -------------------------------------------------
        // The Annex I technical-documentation checks. They shared one SARIF
        // rule, SBOM-CRA-ANNEX-I, until v0.4.0; each is now its own.
        // Every CRA profile (both phases and the steward) emits a missing
        // component identifier as an Error.
        "SBOM-CRA-ANNEX-I-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-IDENTIFIER",
            name: "CraComponentIdentifier",
            short_description: "CRA Annex I: Unique identifier (PURL, CPE, SWHID or SWID) on every component",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (ANNEX, "Annex I"),
                (PREN, "PRE-7-RQ-07"),
                (ENISA, "§2.1.1"),
                (ENISA, "§3.2"),
            ],
            remediation: "Add a PURL, CPE, SWHID or SWID to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-CRA-ANNEX-I-TRACEABILITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-TRACEABILITY",
            name: "CraPrimaryTraceability",
            short_description: "CRA Annex I Part II (1): Primary product component traceable across updates by a PURL or CPE",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-07"),
                (ENISA, "§3.2"),
            ],
            remediation: "Give the primary product component a PURL or CPE so it can be traced across updates (Annex I Part II (1)); a SWHID or SWID alone does not satisfy this check.",
            advice: Some(&ADVICE_PRIMARY_IDENTIFIER),
        },
        "SBOM-CRA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-CRA-INVENTORY",
            name: "CraInventory",
            short_description: "CRA Annex I Part II (1): SBOM inventories the product's software components",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)"), (ENISA, "§2.1")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            name: "CraDirectDependencySupplier",
            short_description: "CRA Annex I Part II: Supplier of every direct dependency identified (PRE-7-RQ-03, mandatory)",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
                (ENISA, "§2.1.1"),
            ],
            // Emitted only by the direct-dependency supplier check in cra.rs
            // (mandatory); the guidance must talk about suppliers, not
            // dependency relationships (#347).
            remediation: "Identify the supplier of every direct dependency, one hop from the primary component or, when none is declared, from a root of the dependency graph (mandatory under PRE-7-RQ-03).",
            advice: Some(&ADVICE_PRODUCER),
        },
        // The transitive-dependency supplier check (recommended), a second
        // document-level finding beside the direct one.
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
            name: "CraTransitiveDependencySupplier",
            short_description: "CRA Annex I Part II: Suppliers of transitive dependencies identified (PRE-7-RQ-03, recommended)",
            default_severity: ViolationSeverity::Info,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
                (ENISA, "§2.1.1"),
            ],
            remediation: "Identify the suppliers of transitive dependencies as well (recommended under PRE-7-RQ-03).",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-CRA-ANNEX-I-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-INTEGRITY",
            name: "CraComponentHash",
            short_description: "CRA Annex I Part I (2)(f): Component hashes (SHA-256 or stronger) for integrity verification",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)"), (ENISA, "§2.1.1")],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-CRA-ANNEX-I-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-DEPENDENCY",
            name: "CraDependencyRelationships",
            short_description: "CRA Annex I: Dependency relationships connect the primary component to its dependencies",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I"), (ENISA, "§2.1.1")],
            remediation: "Add dependency relationships between components: connect the primary component to its direct dependencies and keep most components inside the dependency graph.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        // Several roots and no primary component: a document-level finding
        // beside the relationship gaps above.
        "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
            name: "CraAmbiguousDependencyRoots",
            short_description: "CRA Annex I: Primary component identified when the dependency graph has several roots",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the primary product component when the dependency graph has several roots, so the product's top-level dependencies are unambiguous.",
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-CRA-ANNEX-I-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-PRIMARY",
            name: "CraPrimaryComponent",
            short_description: "CRA Annex I: Top-level product component identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the top-level product component.",
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-CRA-ANNEX-I-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-CONTROLS",
            name: "CraAnnexIControlEvidence",
            short_description: "CRA Annex I Part I: Evidence URL for every control the CRA sidecar marks satisfied",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Give every control the CRA sidecar's annexIPartIControls block marks satisfied an evidenceUrl pointing at its evidence (test report, design review, scan output), or set satisfied to false until the evidence exists.",
            advice: None,
        },
        // Document-level integrity. Formerly mis-cited Annex III (the
        // important-products class list); integrity protection is Annex I
        // Part I (2)(f). The clause covers integrity only — it does not
        // mention authenticity. A signature or a hashed attestation protects
        // the document; a serial number only identifies it, and until v0.4.0
        // satisfied the check alone while the signature was not read.
        "SBOM-CRA-DOC-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-DOC-INTEGRITY",
            name: "CraDocumentIntegrity",
            short_description: "CRA Annex I Part I (2)(f): Document integrity — a digital signature, or an attestation carrying a hash",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)"), (ENISA, "§2.2.1")],
            remediation: "Protect the SBOM's integrity (Annex I Part I (2)(f)): sign the document, or reference from the product component an attestation or certification that carries the hash of the referenced document. A serial number identifies the document but does not protect its integrity.",
            advice: Some(&ADVICE_DOC_INTEGRITY),
        },
        "SBOM-CRA-ANNEX-IV" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-IV",
            name: "CraEuccCertification",
            short_description: "CRA Annex IV: EUCC (Common Criteria) certification the product class requires",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex IV")],
            remediation: "Reference the EUCC (Common Criteria) certification the product class requires: set euccProtectionProfileId, euccTargetOfEvaluation, euccItsefIdentifier or an unexpired euccValidUntil in the CRA sidecar. Once euccValidUntil has passed, the certificate is expired and none of these keys counts. The product classes are CRA Annex III (important, class I and II) and Annex IV (critical); Implementing Regulation (EU) 2025/2392 describes which products each category covers.",
            advice: Some(&ADVICE_EUCC_ALT),
        },
        "SBOM-CRA-ANNEX-V" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-V",
            name: "CraDeclarationOfConformity",
            short_description: "CRA Annex V: EU Declaration of Conformity reference",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex V")],
            remediation: "Reference the EU Declaration of Conformity (Annex V): set ceMarkingReference in the CRA sidecar to the DoC's URL or document ID.",
            advice: Some(&ADVICE_DOC_REF),
        },
        "SBOM-CRA-CYCLES" => RuleMeta {
            sarif_id: "SBOM-CRA-CYCLES",
            name: "CraDependencyCycles",
            short_description: "CRA Annex I Part II (1): Dependency graph must be an acyclic inventory — cyclic dependency declarations detected",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: "Resolve cyclic dependency declarations so the SBOM's dependency graph is a directed acyclic inventory of the product's components.",
            advice: None,
        },
        // Fires only for a pinned class whose route goes beyond Module A:
        // Warning for important class I (the default here), escalated to
        // Error for important class II and critical products. Only a
        // certification reference counts: an attestation may be a
        // self-attestation (it still serves as the Annex V DoC reference).
        "SBOM-CRA-ANNEX-VIII" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-VIII",
            name: "CraConformityAssessment",
            short_description: "CRA Annex VIII: Conformity-assessment evidence for the resolved assessment route",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex VIII")],
            remediation: "Reference the notified-body or certification-body certificate the conformity-assessment route requires — the EU-type examination certificate (Module B+C), the quality-system approval (Module H) or the EUCC certificate — as a certification external reference on the product component. An attestation reference does not count here, since it may be a self-attestation; it still serves as the Annex V Declaration of Conformity reference. The route follows the product class (Art. 32; Annex III class I and II, Annex IV critical), whose product categories Implementing Regulation (EU) 2025/2392 describes.",
            advice: Some(&ADVICE_CONFORMITY_EVIDENCE),
        },
        // The four [PRE-8-RQ-02] checks on a hardware component, one id each
        // so several gaps on one component never share a finding key. They
        // shared one SARIF rule, SBOM-CRA-PRE-8-RQ-02, until v0.4.0.
        "SBOM-CRA-PRE-8-RQ-02-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
            name: "CraHardwareProducer",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Producer of every hardware component (device, firmware, driver)",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Name the producer (supplier or author) of every hardware component: device, firmware or device driver.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
            name: "CraHardwareIdentifier",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Unique identifier on every hardware component",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every hardware component a unique identifier: a PURL, CPE, SWHID or SWID.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
            name: "CraFirmwareVersion",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Version of every firmware component",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every firmware component its firmware version.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
            name: "CraDeviceFirmware",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Every device has a version or a dependency on its firmware",
            default_severity: ViolationSeverity::Warning,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every device a version, or a dependency on the firmware component it runs.",
            advice: Some(&ADVICE_DEVICE_FIRMWARE),
        },
        "SBOM-CRA-PRE-7-RQ-07-RE" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-7-RQ-07-RE",
            name: "CraVendorHashCarryThrough",
            short_description: "CRA prEN 40000-1-3 [PRE-7-RQ-07-RE]: Upstream vendor-supplied component hashes must be carried through into the SBOM",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-07"),
                (PREN, "PRE-7-RQ-07-RE"),
            ],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
            advice: Some(&ADVICE_HASH),
        },
        // ---- Generic CRA / document-level (no specific article) ----------
        "SBOM-CRA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Fix the document-level element the finding names. The CRA profiles' generic checks look for the SBOM's creator, a document serial number, a name on every component, a spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0), well-formed element identifiers and one entry per component.",
            advice: Some(&ADVICE_CRA_GENERAL),
        },
        // The generic path's checks under the CRA profiles, one id each so
        // that two of them on one subject never share a finding key. They
        // reported as SBOM-CRA-GENERAL until v0.4.0. Each cites Annex I
        // Part II (1), the clause that asks for an SBOM of the product's
        // components in a machine-readable format: these checks test that
        // the SBOM is well formed.
        "SBOM-CRA-CREATOR" => RuleMeta {
            sarif_id: "SBOM-CRA-CREATOR",
            name: "CraSbomCreator",
            short_description: "CRA readiness: SBOM creator identified (person, organization or tool)",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)"), (ENISA, "§2.1.1")],
            remediation: REMEDIATION_CREATOR,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-CRA-SERIAL" => RuleMeta {
            sarif_id: "SBOM-CRA-SERIAL",
            name: "CraDocumentIdentifier",
            short_description: "CRA readiness: SBOM carries a unique document identifier",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)"), (ENISA, "§2.1.1")],
            remediation: REMEDIATION_SERIAL,
            advice: Some(&ADVICE_SERIAL),
        },
        "SBOM-CRA-COMPONENT-NAME" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-NAME",
            name: "CraComponentName",
            short_description: "CRA readiness: Every component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)"), (ENISA, "§2.1.1")],
            remediation: REMEDIATION_COMPONENT_NAME,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-CRA-SPEC-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-SPEC-VERSION",
            name: "CraSpecVersion",
            short_description: "CRA readiness: Spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_SPEC_VERSION,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-CRA-SPEC-VERSION-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CRA-SPEC-VERSION-UNKNOWN",
            name: "CraSpecVersionUnknown",
            short_description: "CRA readiness: SPDX document declares a valid SPDX version",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_SPEC_VERSION_UNKNOWN,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-CRA-ELEMENT-ID" => RuleMeta {
            sarif_id: "SBOM-CRA-ELEMENT-ID",
            name: "CraElementIdentifier",
            short_description: "CRA readiness: Every element has its own well-formed identifier",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_ELEMENT_ID,
            advice: Some(&ADVICE_ELEMENT_ID),
        },
        // One finding per document: the components it lists more than once,
        // whose entries were merged. Info: the merge keeps every entry's
        // data, so no verdict depends on the repeat.
        "SBOM-CRA-DUPLICATE-COMPONENT" => RuleMeta {
            sarif_id: "SBOM-CRA-DUPLICATE-COMPONENT",
            name: "CraDuplicateComponent",
            short_description: "CRA readiness: Every component is listed once",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_DUPLICATE_COMPONENT,
            advice: Some(&ADVICE_DUPLICATE_COMPONENT),
        },
        _ => return None,
    };
    Some(meta)
}
