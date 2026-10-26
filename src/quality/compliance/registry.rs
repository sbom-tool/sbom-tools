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
    /// Externally-visible SARIF rule ID (e.g., `SBOM-CRA-MACHINE-READABLE`).
    /// GitHub code scanning dedups on this value, so it must stay stable.
    pub sarif_id: &'static str,
    /// PascalCase SARIF `reportingDescriptor.name` for the externally-visible
    /// rule identified by [`RuleMeta::sarif_id`]. Internal keys that alias to
    /// a shared SARIF rule (key != `sarif_id`) carry the canonical
    /// descriptor's name, so every alias renders identically.
    pub name: &'static str,
    /// SARIF `reportingDescriptor.shortDescription` text for the
    /// externally-visible rule. Like [`RuleMeta::name`], aliased keys share
    /// the canonical descriptor's text.
    pub short_description: &'static str,
    /// Documentation-default severity for the rule. Push sites may still
    /// escalate/relax the concrete [`Violation::severity`] by product class or
    /// CRA phase. The SARIF rule catalogue is generated from this value (see
    /// `registry_severity_matches_sarif_catalogue` in
    /// tests/sarif_rule_catalogue_tests.rs).
    pub default_severity: ViolationSeverity,
    /// Harmonised-standard / regulation cross-references, in display order.
    pub refs: &'static [(StandardKind, &'static str)],
    /// Remediation guidance shown in reports and the TUI.
    pub remediation: &'static str,
}

/// NIST PQC readiness remediation, shared by the SBOM-PQC-* rules.
///
/// NIST IR 8547 is cited as its Initial Public Draft (Nov 2024) — still a
/// draft as of 2026-07; SP 800-131A is at Rev. 2 (Rev. 3 is draft-only).
const REMEDIATION_PQC: &str = "Migrate quantum-vulnerable algorithms per NIST IR 8547 ipd (Transition to Post-Quantum Cryptography Standards): adopt ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) or SP 800-208 stateful hash-based signatures, and retire algorithms disallowed by SP 800-131A Rev. 2.";

/// Generic fallback remediation, shared by rules with no bespoke guidance.
pub(crate) const REMEDIATION_GENERIC: &str = "Review the requirement and update the SBOM accordingly. Consult the EU CRA regulation (EU 2024/2847) for detailed guidance.";

/// Standard-appropriate generic fallbacks: a rule's remediation must cite the
/// regulation it belongs to, never default to the CRA (see the CNSA precedent).
const REMEDIATION_GENERIC_NTIA: &str = "Review the requirement and update the SBOM accordingly. Consult the NTIA \"Minimum Elements for an SBOM\" (July 2021) for detailed guidance.";

const REMEDIATION_GENERIC_FDA: &str = "Review the requirement and update the SBOM accordingly. Consult the FDA premarket cybersecurity guidance (edition of 2026-02-03) / FD&C \u{a7}524B for detailed guidance.";

const REMEDIATION_GENERIC_AIACT: &str = "Review the requirement and update the SBOM accordingly. Consult the EU AI Act (Regulation (EU) 2024/1689) Annex IV technical-documentation requirements for detailed guidance.";

const REMEDIATION_GENERIC_BSI: &str = "Review the requirement and update the SBOM accordingly. Consult BSI TR-03183-2 v2.1.0 for detailed guidance.";

const REMEDIATION_GENERIC_CISA2026: &str = "Review the requirement and update the SBOM accordingly. Consult the 2026 Minimum Elements for an SBOM (CISA et al., July 2026) for detailed guidance.";

const REMEDIATION_GENERIC_PCI: &str = "Review the requirement and update the SBOM accordingly. Consult PCI DSS v4.0.1 Requirement 6.3.2 and its testing procedures for detailed guidance.";

const REMEDIATION_GENERIC_FSCT: &str = "Review the requirement and update the SBOM accordingly. Consult CISA Framing Software Component Transparency, 3rd ed. (2024) for detailed guidance.";

/// SSDF practices share one remediation paragraph.
const REMEDIATION_SSDF: &str = "Follow NIST SP 800-218 SSDF practices: include tool provenance, source VCS references, build metadata, and cryptographic hashes for all components.";

/// EO 14028 §4 requirements share one remediation paragraph.
const REMEDIATION_EO14028: &str = "Follow EO 14028 Section 4(e) requirements: use a machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+), auto-generate the SBOM, include unique identifiers, versions, hashes, dependencies, and supplier information.";

/// EU AI Act not-applicable remediation.
/// Remediation for every `*-INVENTORY` rule: the document must list the
/// software components it describes.
const REMEDIATION_INVENTORY: &str = "List the software components the product is made of (CycloneDX: metadata.component and components[]; SPDX: the packages documentDescribes names and the packages they depend on). A document with no components, or with only files, snippets or cryptographic assets, is not a software inventory; validate a CBOM with --standard cnsa2 or pqc instead.";

const REMEDIATION_AIACT_NA: &str = "EU AI Act Annex IV readiness applies only to SBOMs that describe AI/ML systems. Add machine-learning-model or dataset components (CycloneDX 1.5+ AI/ML BOM) to enable the assessment.";

/// BSI/G7 SBOM-for-AI not-applicable remediation.
const REMEDIATION_BSIAI_NA: &str = "BSI/G7 SBOM-for-AI minimum-elements readiness applies only to SBOMs that describe AI/ML systems. Add machine-learning-model or dataset components (CycloneDX 1.5+ AI/ML BOM, or an SPDX 3.0 AI/Dataset profile) to enable the assessment.";

/// Mistyped-ML remediation, shared by the EU AI Act and BSI/G7 SBOM-for-AI
/// applicability guards.
const REMEDIATION_UNTYPED_ML: &str = "Components with pkg:huggingface PURLs or model-card references look like ML models; leaving them untyped hides them from every AI-BOM readiness check. Set their type to 'machine-learning-model' and attach the AI metadata (CycloneDX 1.5+ modelCard, or the SPDX 3.0 AI profile).";

/// BSI/G7 SBOM-for-AI Models-cluster remediation.
const REMEDIATION_BSIAI_MODELS: &str = "Declare the BSI/G7 SBOM-for-AI Models minimum elements for each MachineLearningModel component: name, version, a unique identifier (PURL/CPE/SWHID/SWID), a model-weight hash using a NIST-approved algorithm (SHA-256+), a model card, the architecture, training datasets, limitations, and a license.";

/// BSI/G7 SBOM-for-AI Datasets-cluster remediation.
const REMEDIATION_BSIAI_DATASETS: &str = "Declare the BSI/G7 SBOM-for-AI Datasets minimum elements for each Data component: name, a unique identifier, a hash value, a license, a sensitivity classification, and provenance / intended-use (SPDX 3.0 dataset_intendedUse / dataPreprocessing / anonymizationMethodUsed, or governance owners).";

/// BSI/G7 SBOM-for-AI document/metadata/system/infra/security remediation.
const REMEDIATION_BSIAI_GENERAL: &str = "Declare the BSI/G7 SBOM-for-AI minimum elements: document author, data-format name + version, timestamp, generation tool, and signature; the primary AI system, its producer, and its data-flow/usage; runtime/framework infrastructure links; and AI-specific security controls / exploitability references where they can be expressed.";

/// EUCC Substantial remediation, shared by the EUCC evidence rules.
const REMEDIATION_EUCC: &str = "Provide the Common Criteria evidence Implementing Regulation (EU) 2024/482 (EUCC) expects alongside the SBOM: set the sidecar fields eucc_protection_profile_id (Protection Profile), eucc_target_of_evaluation (ToE), eucc_itsef_identifier (evaluating ITSEF), and eucc_valid_until (certificate validity), and reference the EUCC certificate via a Certification/Attestation external reference.";

/// CNSA 2.0 allowlist remediation, shared by the CNSA rules.
const REMEDIATION_CNSA2: &str = "Migrate to the CNSA 2.0 suite: AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87, or SP 800-208 stateful hash-based signatures (LMS/XMSS/HSS); use TLS 1.3 for network protocols. Unclassifiable algorithms cannot be verified — declare an algorithmFamily, OID, or recognizable name.";

/// NIST PQC protocol remediation.
const REMEDIATION_PQC_PROTO: &str = "Disable SSL and TLS versions below 1.2 (SP 800-52 Rev. 2) and remove broken (SP 800-131A) or quantum-vulnerable (IR 8547) algorithms from negotiated cipher suites and IKEv2 transforms.";

/// NIST PQC certificate remediation.
const REMEDIATION_PQC_CERT: &str = "Re-issue the certificate with a NIST-approved post-quantum signature algorithm (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, or SP 800-208 LMS/XMSS/HSS).";

/// Remediation for unverifiable crypto evidence under the PQC standard.
const REMEDIATION_PQC_UNKNOWN: &str = "Declare the asset's algorithm identity (algorithmFamily, OID, or a recognizable name), make bom-refs resolvable within the SBOM, and use parseable protocol versions so signature algorithms, cipher suites, and protocol references can be verified for PQC readiness.";

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
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(2)")],
            remediation: REMEDIATION_GENERIC,
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
            refs: &[(CRA, "Art. 13(7)"), (ANNEX, "Annex I Part II (1)")],
            remediation: "Regenerate the SBOM when components are added, removed, or updated. CRA Art. 13(7) requires manufacturers to systematically document relevant cybersecurity aspects, and the Annex I Part II (1) SBOM must reflect the product's current components. A creation timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
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
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-04")],
            remediation: "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML), SPDX 2.3+ (JSON or tag-value), or SPDX 3.0+ (JSON-LD). Older format versions may not be recognized as machine-readable under CRA Annex I Part II (1).",
        },
        // Component licence information. The CRA does not list licences as
        // an SBOM element; they are evidence supporting the Art. 13(5)
        // third-party due-diligence obligation.
        "SBOM-CRA-ART-13-5" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5",
            name: "CraLicensedComponentTracking",
            short_description: "CRA Art. 13(5): Third-party due diligence — license information for all components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(5)")],
            remediation: "Record license information for every component to support the Art. 13(5) due diligence on integrated third-party components. CycloneDX: use component.licenses[]. SPDX 2.x: use PackageLicenseDeclared / PackageLicenseConcluded. SPDX 3.0: use HAS_DECLARED_LICENSE / HAS_CONCLUDED_LICENSE relationships.",
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
            remediation: "Add a security contact or vulnerability disclosure URL. CycloneDX: add a component externalReference with type 'security-contact' or set metadata.manufacturer.contact. SPDX: add an SECURITY external reference.",
        },
        // Vulnerability severity/remediation metadata. Anchored to the
        // Annex I Part II (4) duty to share information about fixed
        // vulnerabilities (description, impacts, severity, remediation).
        "SBOM-CRA-VULN-METADATA" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA",
            name: "CraVulnerabilityMetadata",
            short_description: "CRA Annex I Part II (4): Vulnerability severity and remediation metadata completeness",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Add severity (e.g., CVSS score) and remediation details to each vulnerability entry. CycloneDX: use vulnerability.ratings[].score and vulnerability.analysis. SPDX: use annotation or externalRef.",
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
            remediation: "Reference a coordinated vulnerability disclosure policy. CycloneDX: add an externalReference of type 'advisories' linking to your disclosure policy. SPDX: add an external document reference.",
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
            remediation: "Specify when security updates will no longer be provided. CycloneDX 1.5+: use component.releaseNotes or metadata properties. SPDX: use an annotation with end-of-support date.",
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
            remediation: "Include vulnerability data or add a vulnerability-assertion external reference stating no known vulnerabilities. CycloneDX: use the vulnerabilities array. SPDX: use annotations or external references.",
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
            remediation: "Include lifecycle or end-of-support metadata for components. CycloneDX: use component properties (e.g., cdx:lifecycle:status). SPDX: use annotations.",
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
            remediation: "The SBOM must identify the product by name. CycloneDX: set metadata.component.name. SPDX: set documentDescribes with the primary package name.",
        },
        // Component version. Formerly cited Art. 13(12); versions are part
        // of the Annex I Part II (1) SBOM element inventory.
        "SBOM-CRA-COMPONENT-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-VERSION",
            name: "CraComponentVersion",
            short_description: "CRA Annex I Part II (1): Component version identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-06")],
            remediation: "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder.",
        },
        "SBOM-CRA-ART-24-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-24-SUPPLIER",
            name: "CraStewardComponentSupplier",
            short_description: "CRA Art. 24: Component supplier identification (open-source steward SBOM floor)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 24")],
            remediation: "Identify each component's supplier as part of the Art. 24 steward SBOM floor. CycloneDX: set component.supplier. SPDX: set PackageSupplier.",
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
            remediation: "Identify the manufacturer. CycloneDX: set metadata.manufacturer. SPDX: add an Organization creator.",
        },
        "SBOM-CRA-ART-13-16-EMAIL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-16-EMAIL",
            name: "CraManufacturerEmail",
            short_description: "CRA Art. 13(16): Valid manufacturer contact email (Annex II (1))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(16)"), (ANNEX, "Annex II (1)")],
            remediation: "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts.",
        },
        // Per-component supplier identification. Distinct from the
        // Art. 13(16) manufacturer-identification obligation: component
        // suppliers are part of the Annex I Part II (1) SBOM inventory.
        "SBOM-CRA-COMPONENT-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-SUPPLIER",
            name: "CraComponentSupplier",
            short_description: "CRA Annex I Part II (1): Component supplier identification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-03")],
            remediation: "Identify each component's supplier. CycloneDX: set component.supplier. SPDX: set PackageSupplier.",
        },
        "SBOM-CRA-ART-14" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 14")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ART-24" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        // ---- CRA Annexes -------------------------------------------------
        // Self-descriptor for the shared SBOM-CRA-ANNEX-I SARIF rule the
        // SBOM-CRA-ANNEX-I-* keys below alias to. Never emitted by a check
        // site; it anchors the SARIF reportingDescriptor generated from the
        // registry (see `COMPLIANCE_SARIF_RULE_IDS`).
        "SBOM-CRA-ANNEX-I" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ANNEX-I-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I"), (PREN, "PRE-7-RQ-07")],
            remediation: "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
        },
        "SBOM-CRA-ANNEX-I-TRACEABILITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II"), (PREN, "PRE-7-RQ-07")],
            remediation: "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
        },
        "SBOM-CRA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-CRA-INVENTORY",
            name: "CraInventory",
            short_description: "CRA Annex I Part II (1): SBOM inventories the product's software components",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
            ],
            // Emitted only by the supplier checks in cra.rs (direct = mandatory,
            // transitive = recommended); the guidance must talk about suppliers,
            // not dependency relationships (#347).
            remediation: "Identify each component's supplier, starting with direct dependencies (mandatory under PRE-7-RQ-03; transitive dependencies are recommended). CycloneDX: set component.supplier (or authors). SPDX: set PackageSupplier (or PackageOriginator).",
        },
        "SBOM-CRA-ANNEX-I-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)")],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
        },
        "SBOM-CRA-ANNEX-I-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Add dependency relationships between components. CycloneDX: use the dependencies array. SPDX: use DEPENDS_ON relationships.",
        },
        "SBOM-CRA-ANNEX-I-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the top-level product component. CycloneDX: set metadata.component. SPDX: use documentDescribes to point to the primary package.",
        },
        "SBOM-CRA-ANNEX-I-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I",
            name: "CraTechnicalDocumentation",
            short_description: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: REMEDIATION_GENERIC,
        },
        // Document-level integrity. Formerly mis-cited Annex III (the
        // important-products class list); integrity protection is Annex I
        // Part I (2)(f). The clause covers integrity only — it does not
        // mention authenticity.
        "SBOM-CRA-DOC-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-DOC-INTEGRITY",
            name: "CraDocumentIntegrity",
            short_description: "CRA Annex I Part I (2)(f): Document integrity — serial number, hash, or digital signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)")],
            remediation: "Add document-level integrity metadata: a serial number (CycloneDX: serialNumber, SPDX: documentNamespace), or a digital signature/attestation with a cryptographic hash.",
        },
        "SBOM-CRA-ANNEX-IV" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex IV")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-ANNEX-V" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-V",
            name: "CraDeclarationOfConformity",
            short_description: "CRA Annex V: EU Declaration of Conformity reference",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex V")],
            remediation: "Reference the EU Declaration of Conformity. CycloneDX: add an externalReference of type 'attestation' or 'certification'. SPDX: add an external document reference.",
        },
        "SBOM-CRA-CYCLES" => RuleMeta {
            sarif_id: "SBOM-CRA-CYCLES",
            name: "CraDependencyCycles",
            short_description: "CRA Annex I Part II (1): Dependency graph must be an acyclic inventory — cyclic dependency declarations detected",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: "Resolve cyclic dependency declarations so the SBOM's dependency graph is a directed acyclic inventory of the product's components.",
        },
        "SBOM-CRA-ANNEX-VIII" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-VIII",
            name: "CraConformityAssessment",
            short_description: "CRA Annex VIII: Conformity-assessment evidence for the resolved assessment route",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex VIII")],
            remediation: REMEDIATION_GENERIC,
        },
        "SBOM-CRA-PRE-8-RQ-02" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02",
            name: "CraHardwareInventory",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware components must be inventoried with producer, name, identifier, and firmware version",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: REMEDIATION_GENERIC,
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
        },
        // ---- Generic CRA / document-level (no specific article) ----------
        "SBOM-CRA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_GENERIC,
        },
        // Generic bucket for quality-profile (Minimum/Standard/Comprehensive)
        // findings whose check site has no specific registry mapping. The
        // SARIF renderer re-buckets the `SBOM-CRA-GENERAL` fallback onto this
        // rule for quality runs so they never surface under a CRA identity.
        "SBOM-QUALITY-GENERAL" => RuleMeta {
            sarif_id: "SBOM-QUALITY-GENERAL",
            name: "QualityGeneralRequirement",
            short_description: "SBOM quality: general quality-profile requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Review the requirement and update the SBOM accordingly.",
        },
        // ---- EUCC Substantial (reference-only profile) -------------------
        "SBOM-EUCC-PP" => RuleMeta {
            sarif_id: "SBOM-EUCC-PP",
            name: "EuccProtectionProfile",
            short_description: "EUCC (Reg. (EU) 2024/482): Common Criteria Protection Profile reference — sidecar eucc_protection_profile_id",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Protection Profile")],
            remediation: REMEDIATION_EUCC,
        },
        "SBOM-EUCC-TOE" => RuleMeta {
            sarif_id: "SBOM-EUCC-TOE",
            name: "EuccTargetOfEvaluation",
            short_description: "EUCC (Reg. (EU) 2024/482): Target of Evaluation reference — sidecar eucc_target_of_evaluation",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ToE")],
            remediation: REMEDIATION_EUCC,
        },
        "SBOM-EUCC-ITSEF" => RuleMeta {
            sarif_id: "SBOM-EUCC-ITSEF",
            name: "EuccItsefIdentifier",
            short_description: "EUCC (Reg. (EU) 2024/482): ITSEF (IT Security Evaluation Facility) identifier — sidecar eucc_itsef_identifier",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ITSEF")],
            remediation: REMEDIATION_EUCC,
        },
        "SBOM-EUCC-VALIDITY" => RuleMeta {
            sarif_id: "SBOM-EUCC-VALIDITY",
            name: "EuccCertificateValidity",
            short_description: "EUCC (Reg. (EU) 2024/482): certificate valid-until date present, not expired, not near expiry — sidecar eucc_valid_until",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Certificate validity")],
            remediation: REMEDIATION_EUCC,
        },
        "SBOM-EUCC-CERTREF" => RuleMeta {
            sarif_id: "SBOM-EUCC-CERTREF",
            name: "EuccCertificationReference",
            short_description: "EUCC (Reg. (EU) 2024/482): Certification/Attestation external reference to an EUCC certificate (recommended)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, "Certification reference")],
            remediation: REMEDIATION_EUCC,
        },
        // Generic bucket for EUCC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-EUCC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EUCC-GENERAL",
            name: "EuccGeneralRequirement",
            short_description: "EUCC (Reg. (EU) 2024/482): general SBOM evidence requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, "Reg. (EU) 2024/482")],
            remediation: REMEDIATION_EUCC,
        },
        // ---- EU AI Act Annex IV technical-documentation readiness --------
        // Self-descriptors for the shared SBOM-AIACT-ANNEX-IV-* SARIF rules
        // that the per-element keys below alias to. Never emitted by a check
        // site; they anchor the registry-generated SARIF descriptors.
        "SBOM-AIACT-ANNEX-IV-1" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1",
            name: "AiActGeneralDescription",
            short_description: "EU AI Act Annex IV §1: general description of the AI system (architecture, intended purpose)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: REMEDIATION_GENERIC_AIACT,
        },
        "SBOM-AIACT-ANNEX-IV-2D" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            name: "AiActTrainingData",
            short_description: "EU AI Act Annex IV §2(d): training-data characteristics, provenance, and sensitivity classification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: REMEDIATION_GENERIC_AIACT,
        },
        "SBOM-AIACT-ANNEX-IV-2G" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G",
            name: "AiActValidationMetrics",
            short_description: "EU AI Act Annex IV §2(g): validation/testing metrics (accuracy, robustness)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: REMEDIATION_GENERIC_AIACT,
        },
        "SBOM-AIACT-ANNEX-IV-2C" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2C",
            name: "AiActComputationalResources",
            short_description: "EU AI Act Annex IV §2(c): computational resources / training-energy disclosure",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(c)")],
            remediation: REMEDIATION_GENERIC_AIACT,
        },
        "SBOM-AIACT-ANNEX-IV-3" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-3",
            name: "AiActLimitations",
            short_description: "EU AI Act Annex IV §3: foreseeable limitations and risks",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §3")],
            remediation: REMEDIATION_GENERIC_AIACT,
        },
        "SBOM-AIACT-NA" => RuleMeta {
            sarif_id: "SBOM-AIACT-NA",
            name: "AiActNotApplicable",
            short_description: "EU AI Act Annex IV readiness not applicable — SBOM has no ML-model or dataset components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: REMEDIATION_AIACT_NA,
        },
        "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1",
            name: "AiActGeneralDescription",
            short_description: "EU AI Act Annex IV §1: general description of the AI system (architecture, intended purpose)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Add a general description of the AI model: architecture family/name and a model-card reference. CycloneDX: set modelCard.modelParameters.architectureFamily / modelArchitecture and an external reference of type 'model-card'.",
        },
        "SBOM-AIACT-ANNEX-IV-1-PURPOSE" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1",
            name: "AiActGeneralDescription",
            short_description: "EU AI Act Annex IV §1: general description of the AI system (architecture, intended purpose)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Document the intended purpose / use-cases of the AI model. CycloneDX: set modelCard.considerations.useCases.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-DATASETS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            name: "AiActTrainingData",
            short_description: "EU AI Act Annex IV §2(d): training-data characteristics, provenance, and sensitivity classification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Reference the training datasets used. CycloneDX: set modelCard.modelParameters.datasets with a {ref} to a data component.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            name: "AiActTrainingData",
            short_description: "EU AI Act Annex IV §2(d): training-data characteristics, provenance, and sensitivity classification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Declare a sensitivity classification for each dataset (e.g. 'none', 'pii', 'personal'). CycloneDX: set the data component's sensitiveData array.",
        },
        "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D",
            name: "AiActTrainingData",
            short_description: "EU AI Act Annex IV §2(d): training-data characteristics, provenance, and sensitivity classification",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Where training data involves personal data, document the GDPR lawful basis and data-protection measures alongside the SBOM (AI Act and GDPR apply in parallel).",
        },
        "SBOM-AIACT-ANNEX-IV-2G-METRICS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G",
            name: "AiActValidationMetrics",
            short_description: "EU AI Act Annex IV §2(g): validation/testing metrics (accuracy, robustness)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: "Record validation/testing metrics (accuracy, robustness). CycloneDX: set modelCard.quantitativeAnalysis.performanceMetrics.",
        },
        // Energy / computational-resources disclosure lives in Annex IV
        // §2(c) ("the computational resources used to develop, train, test
        // and validate the AI system"), NOT §2(g), which covers validation
        // and testing procedures/metrics. Explicit energy reporting is the
        // GPAI technical documentation (Annex XI).
        "SBOM-AIACT-ANNEX-IV-2C-ENERGY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2C",
            name: "AiActComputationalResources",
            short_description: "EU AI Act Annex IV §2(c): computational resources / training-energy disclosure",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(c)")],
            remediation: "Disclose computational resources / training energy. CycloneDX: set modelCard.considerations.environmentalConsiderations.energyConsumptions.",
        },
        "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-3",
            name: "AiActLimitations",
            short_description: "EU AI Act Annex IV §3: foreseeable limitations and risks",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §3")],
            remediation: "State the foreseeable limitations and risks of the model, including ethical and fairness considerations. CycloneDX: set modelCard.considerations.technicalLimitations / ethicalConsiderations / fairnessAssessments.",
        },
        "SBOM-AIACT-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-AIACT-UNTYPED-ML",
            name: "AiActUntypedMlContent",
            short_description: "EU AI Act readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV: applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
        },
        // Generic bucket for EU-AI-Act-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-AIACT-GENERAL" => RuleMeta {
            sarif_id: "SBOM-AIACT-GENERAL",
            name: "AiActGeneralRequirement",
            short_description: "EU AI Act Annex IV: general documentation-readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: "Review the EU AI Act Annex IV documentation requirement and update the AI-BOM metadata accordingly.",
        },
        // ---- BSI/G7 SBOM-for-AI Minimum Elements readiness ---------------
        // Self-descriptors for the shared per-cluster SARIF rules the
        // element-level keys below alias to. Never emitted by a check site;
        // they anchor the registry-generated SARIF descriptors.
        "SBOM-BSIAI-META" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-SYS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS",
            name: "BsiSbomForAiSystemLevel",
            short_description: "BSI/G7 SBOM-for-AI System-Level cluster: primary AI system, producer, data flow & usage",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-MODEL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-DATASET" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-INFRA" => RuleMeta {
            sarif_id: "SBOM-BSIAI-INFRA",
            name: "BsiSbomForAiInfrastructure",
            short_description: "BSI/G7 SBOM-for-AI Infrastructure cluster: runtime / framework dependency links",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Infrastructure")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-SEC" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC",
            name: "BsiSbomForAiSecurity",
            short_description: "BSI/G7 SBOM-for-AI Security cluster: AI-specific security controls, exploitability references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-NA" => RuleMeta {
            sarif_id: "SBOM-BSIAI-NA",
            name: "BsiSbomForAiNotApplicable",
            short_description: "BSI/G7 SBOM-for-AI minimum-elements readiness not applicable — SBOM has no ML-model or dataset components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Applicability")],
            remediation: REMEDIATION_BSIAI_NA,
        },
        "SBOM-BSIAI-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-BSIAI-UNTYPED-ML",
            name: "BsiSbomForAiUntypedMlContent",
            short_description: "BSI/G7 SBOM-for-AI readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
        },
        // Metadata cluster
        "SBOM-BSIAI-META-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Author")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-META-FORMAT" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Data format name + version")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-META-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Timestamp")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-META-TOOL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Metadata / Generation tool")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-META-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META",
            name: "BsiSbomForAiMetadata",
            short_description: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Metadata / Signature")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        // System-Level cluster
        "SBOM-BSIAI-SYS-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS",
            name: "BsiSbomForAiSystemLevel",
            short_description: "BSI/G7 SBOM-for-AI System-Level cluster: primary AI system, producer, data flow & usage",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Primary AI system")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-SYS-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS",
            name: "BsiSbomForAiSystemLevel",
            short_description: "BSI/G7 SBOM-for-AI System-Level cluster: primary AI system, producer, data flow & usage",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Producer")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-SYS-DATAFLOW" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS",
            name: "BsiSbomForAiSystemLevel",
            short_description: "BSI/G7 SBOM-for-AI System-Level cluster: primary AI system, producer, data flow & usage",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "System-Level / Data flow & usage")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        // Models cluster
        "SBOM-BSIAI-MODEL-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model name")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-VERSION" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model version")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model identifier")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model hash value")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-HASH-ALGO" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Hash algorithm")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-CARD" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model card")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-ARCHITECTURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Architecture")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-DATASETS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Training datasets")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Limitations")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        "SBOM-BSIAI-MODEL-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL",
            name: "BsiSbomForAiModels",
            short_description: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model license")],
            remediation: REMEDIATION_BSIAI_MODELS,
        },
        // Datasets cluster
        "SBOM-BSIAI-DATASET-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset name")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-DATASET-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset identifier")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-DATASET-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset hash value")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-DATASET-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset license")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-DATASET-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Sensitivity classification")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        "SBOM-BSIAI-DATASET-PROVENANCE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET",
            name: "BsiSbomForAiDatasets",
            short_description: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Provenance & intended use")],
            remediation: REMEDIATION_BSIAI_DATASETS,
        },
        // Infrastructure cluster
        "SBOM-BSIAI-INFRA-RUNTIME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-INFRA",
            name: "BsiSbomForAiInfrastructure",
            short_description: "BSI/G7 SBOM-for-AI Infrastructure cluster: runtime / framework dependency links",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Infrastructure / Runtime & framework")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        // Security cluster
        "SBOM-BSIAI-SEC-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC",
            name: "BsiSbomForAiSecurity",
            short_description: "BSI/G7 SBOM-for-AI Security cluster: AI-specific security controls, exploitability references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / AI security controls")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        "SBOM-BSIAI-SEC-EXPLOITABILITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC",
            name: "BsiSbomForAiSecurity",
            short_description: "BSI/G7 SBOM-for-AI Security cluster: AI-specific security controls, exploitability references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / Exploitability reference")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        // Generic bucket for BSI/G7-SBOM-for-AI-run findings whose check site
        // has no specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-BSIAI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-GENERAL",
            name: "BsiSbomForAiGeneralRequirement",
            short_description: "BSI/G7 SBOM-for-AI: general minimum-elements requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Minimum Elements")],
            remediation: REMEDIATION_BSIAI_GENERAL,
        },
        // ---- NTIA --------------------------------------------------------
        "SBOM-NTIA-VERSION" => RuleMeta {
            sarif_id: "SBOM-NTIA-VERSION",
            name: "NtiaVersion",
            short_description: "NTIA Minimum Elements: Component version string",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-NTIA-TIMESTAMP",
            name: "NtiaTimestamp",
            short_description: "NTIA Minimum Elements: Creation timestamp",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-SUPPLIER",
            name: "NtiaSupplier",
            short_description: "NTIA Minimum Elements: Supplier name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-NTIA-DEPENDENCY",
            name: "NtiaDependency",
            short_description: "NTIA Minimum Elements: Dependency relationship",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        // ---- FDA ---------------------------------------------------------
        "SBOM-FDA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPLIER",
            name: "FdaSupplier",
            short_description: "FDA Medical Device: Component supplier/manufacturer information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-SUPPORT" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPORT",
            name: "FdaSupport",
            short_description: "FDA Medical Device: Component support/contact information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-NAME" => RuleMeta {
            sarif_id: "SBOM-FDA-GENERAL",
            name: "FdaGeneralRequirement",
            short_description: "FDA Medical Device: General SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-VERSION" => RuleMeta {
            sarif_id: "SBOM-FDA-VERSION",
            name: "FdaVersion",
            short_description: "FDA Medical Device: Component version information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-FDA-IDENTIFIER",
            name: "FdaIdentifier",
            short_description: "FDA Medical Device: Component unique identifier (PURL/CPE/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-HASH" => RuleMeta {
            sarif_id: "SBOM-FDA-HASH",
            name: "FdaHash",
            short_description: "FDA Medical Device: Component cryptographic hash",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        // FDA rules emitted by the `validate` NTIA/FDA fast-path
        // (`cli::validate`), which builds violations directly without
        // populating `standard_refs`.
        "SBOM-FDA-CREATOR" => RuleMeta {
            sarif_id: "SBOM-FDA-CREATOR",
            name: "FdaCreator",
            short_description: "FDA Medical Device: SBOM creator/manufacturer information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-NAMESPACE" => RuleMeta {
            sarif_id: "SBOM-FDA-NAMESPACE",
            name: "FdaNamespace",
            short_description: "FDA Medical Device: SBOM serial number or document namespace",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-FDA-DEPENDENCY",
            name: "FdaDependency",
            short_description: "FDA Medical Device: Dependency relationships",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-SECURITY" => RuleMeta {
            sarif_id: "SBOM-FDA-SECURITY",
            name: "FdaSecurity",
            short_description: "FDA Medical Device: Security vulnerability information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        "SBOM-FDA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-FDA-INVENTORY",
            name: "FdaInventory",
            short_description: "FDA Medical Device: SBOM inventories the device's software components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-FDA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-FDA-GENERAL",
            name: "FdaGeneralRequirement",
            short_description: "FDA Medical Device: General SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_GENERIC_FDA,
        },
        // NTIA rules emitted by the `validate` fast-path.
        "SBOM-NTIA-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-NTIA-AUTHOR",
            name: "NtiaAuthor",
            short_description: "NTIA Minimum Elements: Author/creator information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-NAME" => RuleMeta {
            sarif_id: "SBOM-NTIA-NAME",
            name: "NtiaComponentName",
            short_description: "NTIA Minimum Elements: Component name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-IDENTIFIER",
            name: "NtiaUniqueIdentifier",
            short_description: "NTIA Minimum Elements: Unique identifier (PURL/CPE/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
        "SBOM-NTIA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-NTIA-INVENTORY",
            name: "NtiaInventory",
            short_description: "NTIA Minimum Elements: SBOM inventories at least one software component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-NTIA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-NTIA-GENERAL",
            name: "NtiaGeneralRequirement",
            short_description: "NTIA Minimum Elements: General requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_GENERIC_NTIA,
        },
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
        },
        "SBOM-EO14028-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EO14028-GENERAL",
            name: "Eo14028GeneralRequirement",
            short_description: "EO 14028: General SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        // ---- NIST SSDF ---------------------------------------------------
        "SBOM-SSDF-PS1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1",
            name: "SsdfProvenance",
            short_description: "NIST SSDF PS.1: Provenance and creator identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PS2" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS2",
            name: "SsdfBuildIntegrity",
            short_description: "NIST SSDF PS.2: Build integrity — component cryptographic hashes",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.2")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-SSDF-INVENTORY",
            name: "SsdfInventory",
            short_description: "NIST SSDF PS.3.2: provenance data (SBOM) lists the release's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.3.2")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-SSDF-PS3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS3",
            name: "SsdfSupplierIdentification",
            short_description: "NIST SSDF PS.3: Supplier identification for components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.3")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PO1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO1",
            name: "SsdfSourceProvenance",
            short_description: "NIST SSDF PO.1: Source code provenance — VCS references",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PO.1")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PO3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO3",
            name: "SsdfBuildMetadata",
            short_description: "NIST SSDF PO.3: Build provenance — build system metadata",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PO.3")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PW4" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW4",
            name: "SsdfDependencyManagement",
            short_description: "NIST SSDF PW.4: Dependency management — relationships",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PW.4")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-PW6" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW6",
            name: "SsdfVulnerabilityInfo",
            short_description: "NIST SSDF PW.6: Vulnerability information and security references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PW.6")],
            remediation: REMEDIATION_SSDF,
        },
        "SBOM-SSDF-RV1" => RuleMeta {
            sarif_id: "SBOM-SSDF-RV1",
            name: "SsdfComponentIdentification",
            short_description: "NIST SSDF RV.1: Component identification — unique identifiers",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "RV.1")],
            remediation: REMEDIATION_SSDF,
        },
        // ---- EO 14028 ----------------------------------------------------
        "SBOM-EO14028-FORMAT" => RuleMeta {
            sarif_id: "SBOM-EO14028-FORMAT",
            name: "Eo14028MachineReadable",
            short_description: "EO 14028 Sec 4(e): Machine-readable SBOM format requirement",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-AUTOGEN" => RuleMeta {
            sarif_id: "SBOM-EO14028-AUTOGEN",
            name: "Eo14028AutoGeneration",
            short_description: "EO 14028 Sec 4(e): Automated SBOM generation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-CREATOR" => RuleMeta {
            sarif_id: "SBOM-EO14028-CREATOR",
            name: "Eo14028Creator",
            short_description: "EO 14028 Sec 4(e): SBOM creator identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-IDENTIFIER",
            name: "Eo14028Identifier",
            short_description: "EO 14028 Sec 4(e): Component unique identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-EO14028-DEPENDENCY",
            name: "Eo14028Dependency",
            short_description: "EO 14028 Sec 4(e): Dependency relationship information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INVENTORY",
            name: "Eo14028Inventory",
            short_description: "EO 14028 Sec 4(e): SBOM lists the software's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-EO14028-VERSION" => RuleMeta {
            sarif_id: "SBOM-EO14028-VERSION",
            name: "Eo14028Version",
            short_description: "EO 14028 Sec 4(e): Component version information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INTEGRITY",
            name: "Eo14028Integrity",
            short_description: "EO 14028 Sec 4(e): Component integrity verification (hashes)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-DISCLOSURE" => RuleMeta {
            sarif_id: "SBOM-EO14028-DISCLOSURE",
            name: "Eo14028Disclosure",
            short_description: "EO 14028 Sec 4(g): Vulnerability disclosure process",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-SUPPLIER",
            name: "Eo14028Supplier",
            short_description: "EO 14028 Sec 4(e): Supplier identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-EO14028-TIMESTAMP",
            name: "Eo14028Timestamp",
            short_description: "EO 14028 Sec 4(e): SBOM creation timestamp (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4"), (K::NtiaMinimum, "Timestamp")],
            remediation: REMEDIATION_EO14028,
        },
        "SBOM-EO14028-NAME" => RuleMeta {
            sarif_id: "SBOM-EO14028-NAME",
            name: "Eo14028ComponentName",
            short_description: "EO 14028 Sec 4(e): Component name (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (K::Eo14028, "EO 14028 §4"),
                (K::NtiaMinimum, "Component Name"),
            ],
            remediation: REMEDIATION_EO14028,
        },
        // ---- BSI TR-03183-2 (v2.1.0, 2025-08-20) --------------------------
        "SBOM-BSI-TR-03183-2-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-4",
            name: "BsiTr03183FormatEligibility",
            short_description: "BSI TR-03183-2 v2.1.0 §4: Newly generated/updated SBOMs must be CycloneDX 1.6+ or SPDX 3.0.1+",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§4"), (K::BsiTr03183_2, "§7")],
            remediation: "Regenerate the SBOM as CycloneDX 1.6+ or SPDX 3.0.1+ in JSON or XML. TR-03183-2 v2.1.0 §4 lists the eligible specifications for newly generated or updated SBOMs; the §7 transitional grace for the v2.0.0 minimums (CycloneDX 1.5 / SPDX 2.2.1) ended 2026-02-20.",
        },
        "SBOM-BSI-TR-03183-2-5-1" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-1",
            name: "BsiTr03183SbomCreator",
            short_description: "BSI TR-03183-2 §5.2.1: Creator of the SBOM (email, or URL if no email)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Identify the SBOM creator with an email address, or a URL (e.g. the creator's home page) if no email is available. CycloneDX: metadata.authors[].email or metadata.manufacturer; SPDX: CreationInfo creators.",
        },
        "SBOM-BSI-TR-03183-2-5-1-CONTACT" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-1-CONTACT",
            name: "BsiTr03183SbomCreatorContact",
            short_description: "BSI TR-03183-2 §5.2.1: SBOM creator must carry an email address or URL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Add an email address to the SBOM creator entry, or a URL (creator home page / project web page) when no email exists — a bare name does not satisfy §5.2.1.",
        },
        "SBOM-BSI-TR-03183-2-5-2" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-2",
            name: "BsiTr03183Timestamp",
            short_description: "BSI TR-03183-2 §5.2.1: Timestamp of the SBOM data compilation",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Add the date and time of the SBOM data compilation (UTC 'Zulu' timestamps recommended). CycloneDX: metadata.timestamp; SPDX: CreationInfo created.",
        },
        "SBOM-BSI-TR-03183-2-5-3" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-3",
            name: "BsiTr03183ComponentName",
            short_description: "BSI TR-03183-2 §5.2.2: Component name (fallback: actual filename)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Name every component. When the component creator assigned no name, the actual filename MUST be used instead.",
        },
        "SBOM-BSI-TR-03183-2-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-INVENTORY",
            name: "BsiTr03183Inventory",
            short_description: "BSI TR-03183-2 §5.2.2: SBOM lists at least one component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-BSI-TR-03183-2-VERSION" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-VERSION",
            name: "BsiTr03183ComponentVersion",
            short_description: "BSI TR-03183-2 §5.2.2: Component version (fallback: RFC 3339 modification date)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Version every component (SemVer/CalVer recommended). When no version is assigned, the modification date of the file as RFC 3339 date-time MUST be used instead.",
        },
        "SBOM-BSI-TR-03183-2-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-LICENSE",
            name: "BsiTr03183DistributionLicence",
            short_description: "BSI TR-03183-2 §5.2.2: Distribution licence(s) per component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2"), (K::BsiTr03183_2, "§6.1")],
            remediation: "Declare the distribution licence(s) of every component, named by SPDX licence identifier or expression (§6.1). CycloneDX: component.licenses[]; SPDX: PackageLicenseDeclared / concluded-licence relationships.",
        },
        "SBOM-BSI-TR-03183-2-LICENSE-SPDX" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
            name: "BsiTr03183SpdxLicenceNaming",
            short_description: "BSI TR-03183-2 §6.1: Licences must be named by SPDX identifier/expression",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§6.1")],
            remediation: "Name licences by SPDX identifier or expression; consult Scancode LicenseDB (LicenseRef-scancode-*) or use LicenseRef-<entity>-* for unlisted licences. Licence text MUST NOT be used as a substitute for an identifier.",
        },
        "SBOM-BSI-TR-03183-2-CREATOR" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-CREATOR",
            name: "BsiTr03183ComponentCreator",
            short_description: "BSI TR-03183-2 §5.2.2: Component creator (email, or URL if no email)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Record the component creator — the email address (or URL if no email) of the entity that created/maintains the component. CycloneDX: component.supplier / authors; SPDX: PackageSupplier / PackageOriginator.",
        },
        "SBOM-BSI-TR-03183-2-5-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-4",
            name: "BsiTr03183ComponentHash",
            short_description: "BSI TR-03183-2 §5.2.2: Hash of the deployable component as SHA-512",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Provide the hash of the deployed/deployable component as SHA-512 — §5.2.2 names the algorithm, so SHA-256 or other algorithms alone do not satisfy the required field (additional hashes may coexist).",
        },
        "SBOM-BSI-TR-03183-2-5-4-MISSING" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-4-MISSING",
            name: "BsiTr03183ComponentHashMissing",
            short_description: "BSI TR-03183-2 §5.2.2/§3.2.1: Component has no hash of the deployable form",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2"), (K::BsiTr03183_2, "§3.2.1")],
            remediation: "Add a SHA-512 hash of the deployable component. §3.2.1 permits omission only when the information cannot exist due to the way the component is assembled (e.g. logical components).",
        },
        "SBOM-BSI-TR-03183-2-5-5" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-5",
            name: "BsiTr03183Dependencies",
            short_description: "BSI TR-03183-2 §5.2.2: Dependencies on other components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Enumerate all direct dependencies of each component. CycloneDX: dependencies[]; SPDX: DEPENDS_ON / DEPENDENCY_OF relationships.",
        },
        "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
            name: "BsiTr03183DependencyCompleteness",
            short_description: "BSI TR-03183-2 §5.2.2: Completeness of the dependency enumeration must be clearly indicated",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Clearly indicate the completeness of the dependency enumeration, e.g. CycloneDX compositions[].aggregate = complete / incomplete.",
        },
        "SBOM-BSI-TR-03183-2-5-2-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-2-4",
            name: "BsiTr03183UniqueIdentifier",
            short_description: "BSI TR-03183-2 §5.2.4: Other unique identifiers (purl/CPE) — additional tier",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.4")],
            remediation: "Add unique identifiers (purl, CPE) to components. §5.2.4 is the additional tier: the field MUST be provided when an identifier exists for the component.",
        },
        "SBOM-BSI-TR-03183-2-3-1" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-3-1",
            name: "BsiTr03183NoVulnerabilityInfo",
            short_description: "BSI TR-03183-2 §3.1: An SBOM must not contain vulnerability information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§3.1")],
            remediation: "Remove vulnerability information from the SBOM and publish it separately (e.g. as CSAF advisories); a document containing both SBOM and vulnerability information does not conform to TR-03183-2.",
        },
        // Catch-all descriptor for the BSI TR-03183-2 profile; not emitted by
        // any check site, kept so the registry-generated SARIF catalogue
        // mirrors the historical hand-maintained rule table.
        "SBOM-BSI-TR-03183-2-GENERAL" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-GENERAL",
            name: "BsiTr03183General",
            short_description: "BSI TR-03183-2 general SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "TR-03183-2")],
            remediation: REMEDIATION_GENERIC_BSI,
        },
        // ---- CNSA 2.0 ----------------------------------------------------
        "SBOM-CNSA2-000" => RuleMeta {
            sarif_id: "SBOM-CNSA2-000",
            name: "Cnsa2CryptoInventory",
            short_description: "CNSA 2.0: cryptographic inventory (CBOM) with evaluable assets required — compliance cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-001",
            name: "Cnsa2SymmetricAlgorithm",
            short_description: "CNSA 2.0: symmetric encryption must be AES-256",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-002",
            name: "Cnsa2HashAlgorithm",
            short_description: "CNSA 2.0: hashing must be SHA-384 or SHA-512",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-003" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-003",
            name: "Cnsa2KeyEstablishment",
            short_description: "CNSA 2.0: key establishment must be ML-KEM-1024",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-004" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-004",
            name: "Cnsa2SignatureAlgorithm",
            short_description: "CNSA 2.0: digital signatures must be ML-DSA-87 or SP 800-208 stateful hash-based signatures",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-006" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-006",
            name: "Cnsa2QuantumVulnerable",
            short_description: "CNSA 2.0: quantum-vulnerable classical algorithm must migrate to the CNSA 2.0 suite",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-ALG-007" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-007",
            name: "Cnsa2QuantumSecurityLevel",
            short_description: "CNSA 2.0: declared quantum security level below Level 5",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Broken/legacy algorithm (SHA-1, MD5, DES, RC4, ...) under the CNSA
        // 2.0 allowlist.
        "SBOM-CNSA2-ALG-005" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-005",
            name: "Cnsa2BrokenAlgorithm",
            short_description: "CNSA 2.0: broken legacy algorithm (SHA-1, MD5, DES, RC4, …) in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Recognized algorithm that is simply not on the CNSA 2.0 allowlist
        // (ChaCha20, Camellia, SHA-3, SLH-DSA, Falcon, ...).
        "SBOM-CNSA2-ALG-008" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-008",
            name: "Cnsa2UnapprovedAlgorithm",
            short_description: "CNSA 2.0: recognized algorithm that is not on the CNSA 2.0 allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Unclassifiable algorithm asset — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-UNKNOWN",
            name: "Cnsa2UnclassifiableAlgorithm",
            short_description: "CNSA 2.0: algorithm cannot be classified, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        "SBOM-CNSA2-CERT-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-001",
            name: "Cnsa2CertificateSignature",
            short_description: "CNSA 2.0: certificate signature algorithm must be CNSA 2.0 approved",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // CNSA 2.0 compliance cannot be verified (Warning, never a silent
        // pass).
        "SBOM-CNSA2-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-UNKNOWN",
            name: "Cnsa2CertificateUnverifiable",
            short_description: "CNSA 2.0: certificate signature algorithm cannot be resolved, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Protocol version gate: CNSA 2.0 network protocols require TLS 1.3.
        "SBOM-CNSA2-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-001",
            name: "Cnsa2ProtocolVersion",
            short_description: "CNSA 2.0: network protocols must use TLS 1.3",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs must use
        // CNSA 2.0 algorithms.
        "SBOM-CNSA2-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-002",
            name: "Cnsa2ProtocolAlgorithms",
            short_description: "CNSA 2.0: protocol cipher suites / IKEv2 transforms must use CNSA 2.0 algorithms",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // or with nothing evaluable at all — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-UNKNOWN",
            name: "Cnsa2ProtocolUnverifiable",
            short_description: "CNSA 2.0: protocol names no algorithm the classifier can identify, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // Generic bucket for CNSA-2.0-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-CNSA2-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CNSA2-GENERAL",
            name: "Cnsa2GeneralRequirement",
            short_description: "CNSA 2.0: general algorithm-suite requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
        },
        // ---- NIST PQC ----------------------------------------------------
        "SBOM-PQC-000" => RuleMeta {
            sarif_id: "SBOM-PQC-000",
            name: "PqcCryptoInventory",
            short_description: "NIST PQC: cryptographic inventory (CBOM) with evaluable assets required — readiness cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-001" => RuleMeta {
            sarif_id: "SBOM-PQC-001",
            name: "PqcQuantumVulnerable",
            short_description: "NIST IR 8547: quantum-vulnerable algorithm must migrate to a NIST PQC standard",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (K::NistPqc, "IR 8547 ipd"),
                (K::NistPqc, "SP 800-131A Rev. 2"),
            ],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-012" => RuleMeta {
            sarif_id: "SBOM-PQC-012",
            name: "PqcQuantumAssessmentMissing",
            short_description: "NIST IR 8547: missing quantum security level assessment (nistQuantumSecurityLevel)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-010" => RuleMeta {
            sarif_id: "SBOM-PQC-010",
            name: "PqcHybridCombiner",
            short_description: "NIST PQC: hybrid PQC combiner — recommended transition practice (IR 8547)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "FIPS 203/204/205")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-005" => RuleMeta {
            sarif_id: "SBOM-PQC-005",
            name: "PqcDisallowedAlgorithm",
            short_description: "NIST SP 800-131A: disallowed (broken) algorithm in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-008" => RuleMeta {
            sarif_id: "SBOM-PQC-008",
            name: "PqcEcbModeDisallowed",
            short_description: "NIST SP 800-131A: ECB mode of operation disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-009" => RuleMeta {
            sarif_id: "SBOM-PQC-009",
            name: "PqcApprovedAlgorithm",
            short_description: "NIST PQC: NIST-approved post-quantum algorithm in use (FIPS 203/204/205, SP 800-208)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "FIPS 203/204/205"), (K::NistPqc, "SP 800-208")],
            remediation: REMEDIATION_PQC,
        },
        "SBOM-PQC-KEY-001" => RuleMeta {
            sarif_id: "SBOM-PQC-KEY-001",
            name: "PqcMinimumKeySize",
            short_description: "NIST SP 800-131A: key size below the approved minimum",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
        },
        // Certificate signed with a broken or quantum-vulnerable algorithm.
        "SBOM-PQC-CERT-001" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-001",
            name: "PqcCertificateSignature",
            short_description: "NIST IR 8547: certificate signed with a broken or quantum-vulnerable algorithm",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_CERT,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // PQC readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-ALG-UNKNOWN",
            name: "PqcUnclassifiableAlgorithm",
            short_description: "NIST PQC: algorithm cannot be classified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
        },
        "SBOM-PQC-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-UNKNOWN",
            name: "PqcCertificateUnverifiable",
            short_description: "NIST PQC: certificate signature algorithm cannot be resolved — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
        },
        // Protocol version gate: SSL / TLS below 1.2 disallowed.
        "SBOM-PQC-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-001",
            name: "PqcProtocolVersion",
            short_description: "NIST SP 800-52 Rev. 2: SSL and TLS below 1.2 are disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-52 Rev. 2")],
            remediation: REMEDIATION_PQC_PROTO,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs contain
        // broken or quantum-vulnerable algorithms.
        "SBOM-PQC-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-002",
            name: "PqcProtocolAlgorithms",
            short_description: "NIST PQC: protocol negotiates broken or quantum-vulnerable algorithms (SP 800-131A / IR 8547)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A / IR 8547")],
            remediation: REMEDIATION_PQC_PROTO,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // an unparseable TLS version, or nothing evaluable at all — PQC
        // readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-UNKNOWN",
            name: "PqcProtocolUnverifiable",
            short_description: "NIST PQC: protocol crypto references cannot be verified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
        },
        // Generic bucket for NIST-PQC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PQC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PQC-GENERAL",
            name: "PqcGeneralRequirement",
            short_description: "NIST PQC: general post-quantum readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
        },
        // ---- CISA 2026 Minimum Elements (v2.1, July 29, 2026) --------------
        // Successor to the NTIA 2021 Minimum Elements. Severity convention
        // mirrors the NTIA profile: required data fields = Error;
        // evidence-limited / practice checks = Warning (CISA assigns none).
        "SBOM-CISA2026-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-CISA2026-AUTHOR",
            name: "Cisa2026SbomAuthor",
            short_description: "CISA 2026: SBOM Author — a person or organization (not tool-only) created the SBOM data",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Author")],
            remediation: "Add a Person or Organization creator naming the entity that created the SBOM data — the entity operating the generation tool, not the tool itself, so tool-only creator lists do not satisfy the element. Use full names, no acronyms. CycloneDX: metadata.authors; SPDX: Creator: Person/Organization.",
        },
        "SBOM-CISA2026-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-SIGNATURE",
            name: "Cisa2026AuthorSignature",
            short_description: "CISA 2026: SBOM Author Signature — digital signature attributable to the SBOM author",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Author Signature")],
            remediation: "Sign the SBOM with a digital signature attributable to the SBOM author, using an algorithm approved per NIST DSS, ISO/IEC 14888-4:2024, or the ENISA Agreed Cryptographic Mechanisms. In-document evidence is read from CycloneDX JSF signatures and SPDX 3 verifiedUsing signature entries; SPDX 2.x has no in-document signature field and detached signatures are invisible to this check — hence Warning, not Error.",
        },
        "SBOM-CISA2026-FORMAT" => RuleMeta {
            sarif_id: "SBOM-CISA2026-FORMAT",
            name: "Cisa2026DataFormat",
            short_description: "CISA 2026: SBOM Data Format Name/Version — machine-processable format, no deprecated format versions",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (K::CisaMinimum2026, "SBOM Data Format Name"),
                (K::CisaMinimum2026, "SBOM Data Format Version"),
                (K::CisaMinimum2026, "Machine-Processable Data"),
            ],
            remediation: "Produce the SBOM in a widely used machine-processable format — SPDX (ISO/IEC 5962:2021) or CycloneDX (ECMA-424); SWID tags were dropped from the 2026 format list — and avoid format versions declared deprecated by the format maintainers. CISA names no deprecated versions: the enforced floor (CycloneDX 1.4+ / SPDX 2.2+, mirroring the repo's EO 14028 gate) is tool policy, not CISA text. Unparseable spec versions skip the gate rather than false-failing.",
        },
        "SBOM-CISA2026-GENERATION-CONTEXT" => RuleMeta {
            sarif_id: "SBOM-CISA2026-GENERATION-CONTEXT",
            name: "Cisa2026GenerationContext",
            short_description: "CISA 2026: SBOM Generation Context — software lifecycle phase at SBOM generation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Generation Context")],
            remediation: "Declare the lifecycle phase the SBOM was generated in — 'before build', 'build', 'after build', or a more specific identifier. CycloneDX 1.5+: metadata.lifecycles. SPDX 2.x has no standard field (parsers yield no phase for it), hence Warning severity.",
        },
        "SBOM-CISA2026-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TIMESTAMP",
            name: "Cisa2026Timestamp",
            short_description: "CISA 2026: SBOM Timestamp — date and time of the most recent update to the SBOM data",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Timestamp")],
            remediation: "Record the date and time of the most recent update to the SBOM data; the 2026 element targets RFC 9557 syntax (source-syntax conformance is not verified by this check — parsers normalize timestamps). CycloneDX: metadata.timestamp; SPDX: Created.",
        },
        "SBOM-CISA2026-TOOL" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TOOL",
            name: "Cisa2026ToolName",
            short_description: "CISA 2026: SBOM Tool Name — tool used to generate or amend the SBOM",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Tool Name")],
            remediation: "Identify the tool used by the SBOM author to generate or amend the SBOM (full name, no acronyms unless official). CycloneDX: metadata.tools; SPDX: 'Creator: Tool:'.",
        },
        "SBOM-CISA2026-TOOL-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TOOL-VERSION",
            name: "Cisa2026ToolVersion",
            short_description: "CISA 2026: SBOM Tool Version — version of the SBOM generation tool (or explicit unknown)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Tool Version")],
            remediation: "Declare the version of the tool named in SBOM Tool Name, or explicitly indicate it is unknown. Parsers concatenate tool name and version into one creator name, so the check is heuristic (a trailing version-like token or explicit unknown marker satisfies it) until the model grows a dedicated tool-version field.",
        },
        "SBOM-CISA2026-SBOM-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-SBOM-VERSION",
            name: "Cisa2026SbomVersion",
            short_description: "CISA 2026: SBOM Version — the document declares its own version",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Version")],
            remediation: "Declare the SBOM document's own version: CycloneDX bom.version (an omitted bom.version is treated as undeclared, not backfilled with the spec default of 1) or a version-distinguishing serial identifier (CycloneDX serialNumber / SPDX documentNamespace; RFC 9562-style UUIDs). Warning because SPDX 2.x has no dedicated document-version field.",
        },
        "SBOM-CISA2026-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-CISA2026-PRODUCER",
            name: "Cisa2026ComponentProducer",
            short_description: "CISA 2026: Component Producer — entity that creates, defines, and identifies the component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Producer")],
            remediation: "Identify each component's producer (the 2026 rename of the ambiguous Supplier Name): SPDX PackageOriginator / component author is preferred as the entity that created the component, supplier is accepted; if no clear producer exists, explicitly mark the component as of unknown provenance. File-type entries are exempt.",
        },
        "SBOM-CISA2026-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-CISA2026-INVENTORY",
            name: "Cisa2026Inventory",
            short_description: "CISA 2026: SBOM enumerates at least one software component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Coverage")],
            remediation: REMEDIATION_INVENTORY,
        },
        "SBOM-CISA2026-NAME" => RuleMeta {
            sarif_id: "SBOM-CISA2026-NAME",
            name: "Cisa2026ComponentName",
            short_description: "CISA 2026: Component Name — name assigned by the component producer",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Name")],
            remediation: "Give every enumerated component the name assigned by its producer (full names, no acronyms); alternate names belong in alias/identifier fields, which the 2026 element allows as multiple entries.",
        },
        "SBOM-CISA2026-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-VERSION",
            name: "Cisa2026ComponentVersion",
            short_description: "CISA 2026: Component Version — version present or explicitly marked unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Version")],
            remediation: "Declare each component's version; when the producer provides none, explicitly indicate the version is unknown (NOASSERTION/'unknown') per the 2026 escape hatch. An explicit unknown passes this rule — silent absence fails.",
        },
        "SBOM-CISA2026-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CISA2026-IDENTIFIER",
            name: "Cisa2026ComponentIdentifiers",
            short_description: "CISA 2026: Component Identifiers — at least one machine-processable identifier (PURL/CPE/SWHID/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Identifiers")],
            remediation: "Add at least one common machine-processable identifier per component — the document names CPE and PURL (ECMA-427); UUIDs, organization-specific identifiers, commit hashes, and intrinsic identifiers (OmniBOR, SWHID / ISO/IEC 18670:2025) also qualify. Include all known identifiers.",
        },
        "SBOM-CISA2026-HASH" => RuleMeta {
            sarif_id: "SBOM-CISA2026-HASH",
            name: "Cisa2026ComponentHash",
            short_description: "CISA 2026: Component Hash Value — cryptographic hash of the executable component artifact",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Hash Value")],
            remediation: "Provide an ASCII-hexadecimal cryptographic hash of each executable component artifact; when the SBOM author lacks access to the artifact, explicitly indicate the value is unknown.",
        },
        "SBOM-CISA2026-HASH-ALGO" => RuleMeta {
            sarif_id: "SBOM-CISA2026-HASH-ALGO",
            name: "Cisa2026HashAlgorithm",
            short_description: "CISA 2026: Component Hash Algorithm — recognized, authority-approved hash algorithm",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "Component Hash Algorithm")],
            remediation: "Identify hash algorithms using IANA Hash Function Textual Names, and use algorithms approved by a relevant authority such as NIST: MD5 is not NIST-approved; SHA-1 is deprecated and slated for withdrawal by 2030 — use SHA-256 or stronger. A component that carries one such hash passes even when it also lists MD5 or SHA-1 digests.",
        },
        "SBOM-CISA2026-LICENSE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-LICENSE",
            name: "Cisa2026ComponentLicense",
            short_description: "CISA 2026: Component License — license identifier, license pointer, or explicit unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component License")],
            remediation: "Declare each component's license(s), preferring machine-processable SPDX license identifiers; a LicenseRef-* expression or a pointer to where the full license details are available also satisfies the element, and an explicit unknown (NOASSERTION) is required when the author is unaware. Silent absence fails.",
        },
        "SBOM-CISA2026-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CISA2026-DEPENDENCY",
            name: "Cisa2026DependencyRelationship",
            short_description: "CISA 2026: Component Dependency Relationship — dependency graph or external SBOM links",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Dependency Relationship")],
            remediation: "Declare the relationships where one component is necessary for the operation of the other (CycloneDX: dependencies array; SPDX: DEPENDS_ON). Links to separate SBOM documents per dependency are acceptable alternative evidence.",
        },
        "SBOM-CISA2026-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-COVERAGE",
            name: "Cisa2026Coverage",
            short_description: "CISA 2026: Coverage / Explicitly Identifying Unknown Information — completeness declaration present",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (K::CisaMinimum2026, "Coverage"),
                (
                    K::CisaMinimum2026,
                    "Explicitly Identifying Unknown Information",
                ),
            ],
            remediation: "Declare the SBOM's completeness (CycloneDX compositions aggregate): the 2026 Coverage element expects all components including transitive dependencies, and information gaps must be explicitly stated as unknown or deliberately withheld. This rule verifies the declaration, not actual completeness — the document itself points to external repositories / binary analysis for that.",
        },
        // Generic bucket for CISA-2026-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-CISA2026-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CISA2026-GENERAL",
            name: "Cisa2026GeneralRequirement",
            short_description: "CISA 2026 Minimum Elements: general requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "Minimum Elements")],
            remediation: REMEDIATION_GENERIC_CISA2026,
        },
        "SBOM-PCI-6-3-2-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-INVENTORY",
            name: "PciDssInventory",
            short_description: "PCI DSS Req. 6.3.2: SBOM is a non-empty inventory with a resolvable primary component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "The SBOM must inventory at least one component and identify the bespoke/custom application it describes (CycloneDX: metadata.component; SPDX: documentDescribes). An empty or headless document cannot serve as the Req. 6.3.2 inventory.",
        },
        "SBOM-PCI-6-3-2-NAME" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-NAME",
            name: "PciDssComponentName",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Name every inventoried component — an unnamed entry cannot be correlated with vendor advisories or patches. File/snippet inventory records are exempt, so a file-cataloguing SBOM does not auto-fail the profile.",
        },
        "SBOM-PCI-6-3-2-VERSION" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VERSION",
            name: "PciDssComponentVersion",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a concrete version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Declare a concrete release version for every inventoried component (a version range is acceptable only for external components) — patch management, the requirement's stated purpose, is impossible without versions. File/snippet inventory records are exempt.",
        },
        "SBOM-PCI-6-3-2-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-SUPPLIER",
            name: "PciDssComponentSupplier",
            short_description: "PCI DSS Req. 6.3.2: third-party components identify their supplier/source",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Identify each third-party component's supplier (CycloneDX: component.supplier; SPDX: PackageSupplier) — or fall back to author / group / ecosystem-bearing PURL evidence — so vendor security-patch availability can be monitored.",
        },
        "SBOM-PCI-6-3-2-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-IDENTIFIER",
            name: "PciDssComponentIdentifier",
            short_description: "PCI DSS Req. 6.3.2: components carry a stable unique identifier for vulnerability correlation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Add a stable unique identifier (PURL preferred, else CPE/SWID) so the inventory can be machine-correlated with vulnerability sources per the 'facilitate vulnerability and patch management' clause. PCI DSS prescribes no identifier scheme — this is enabling evidence, not a mandated field.",
        },
        "SBOM-PCI-6-3-2-THIRD-PARTY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-THIRD-PARTY",
            name: "PciDssThirdPartyComponents",
            short_description: "PCI DSS TP 6.3.2.b: inventory enumerates incorporated third-party components, not just the application",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "Enumerate the third-party components incorporated into the bespoke/custom software, not only the application itself; a primary-only SBOM passes only when its completeness declaration is Complete (a genuinely dependency-free application). This is an inference — TP 6.3.2.b's real comparison against the software is assessor work.",
        },
        "SBOM-PCI-6-3-2-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-COMPLETENESS",
            name: "PciDssCompleteness",
            short_description: "PCI DSS TP 6.3.2.b: completeness declaration — self-declared inventory gaps flagged",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "TP 6.3.2.b")],
            remediation: "Declare the inventory Complete (CycloneDX compositions aggregate). Explicit Incomplete* declarations warn as self-declared gaps against TP 6.3.2.b; Unknown (no declaration made / explicitly unknown) and NotSpecified (declared but unrecognized, or a no-assertion value) are informational.",
        },
        "SBOM-PCI-6-3-2-FRESHNESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-FRESHNESS",
            name: "PciDssFreshness",
            short_description: "PCI DSS Req. 6.3.2: 'is maintained' — the SBOM carries a creation timestamp",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Carry a creation timestamp so the inventory's maintenance can be evidenced. The SBOM proves generation time, not the inventory process — a stale timestamp is advisory only. A timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
        },
        "SBOM-PCI-6-3-2-VULN-EVIDENCE" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VULN-EVIDENCE",
            name: "PciDssVulnerabilityEvidence",
            short_description: "PCI DSS TP 6.3.2.a: vulnerability-management hooks (embedded data, advisory refs, or security contact)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::PciDss4, "TP 6.3.2.a")],
            remediation: "Surface vulnerability-management hooks: embedded vulnerability entries, an Advisories / vulnerability-assertion / linked-VDR external reference, a security contact, or a disclosure URL. Absence is not a Req. 6.3.2 failure — the inventory may feed an external scanner; actual use of the inventory is assessor-verified.",
        },
        "SBOM-PCI-11-3-1-1-SEVERITY" => RuleMeta {
            sarif_id: "SBOM-PCI-11-3-1-1-SEVERITY",
            name: "PciDssVulnerabilityRiskRanking",
            short_description: "PCI DSS Req. 6.3.1 / 11.3.1.1: embedded vulnerability entries carry a risk ranking",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 11.3.1.1"), (K::PciDss4, "Req. 6.3.1")],
            remediation: "Give every embedded vulnerability entry a risk ranking — a Critical/High/Medium/Low severity or a CVSS score (an entry with only Info/None/Unknown severity and no CVSS is unranked) — so non-high-risk findings can be managed per the entity's Req. 6.3.1 rankings and the 11.3.1.1 targeted risk analysis. Emitted only when vulnerability data is present (no vacuous pass/fail).",
        },
        // Generic bucket for PCI-DSS-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PCI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PCI-GENERAL",
            name: "PciDssGeneralRequirement",
            short_description: "PCI DSS v4.0.1 Req. 6.3.2: general software-inventory requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: REMEDIATION_GENERIC_PCI,
        },
        "SBOM-FSCT-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-FSCT-AUTHOR",
            name: "FsctAuthorName",
            short_description: "CISA FSCT 3e §2.2.1.1 (Minimum): Author Name — person/organization author, not tool-only",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.1")],
            remediation: "Name the entity that prompted the SBOM's creation (organization, project team, or individual) with unique identification (email address or website) where possible — a tool-only creator list does not satisfy the element. CycloneDX: metadata.authors; SPDX: Creator: Person/Organization.",
        },
        "SBOM-FSCT-AUTHOR-TOOL" => RuleMeta {
            sarif_id: "SBOM-FSCT-AUTHOR-TOOL",
            name: "FsctAuthorTool",
            short_description: "CISA FSCT 3e §2.2.1.1 (Recommended): tool(s) and version(s) that assisted SBOM creation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.1.1")],
            remediation: "In addition to the authoring entity, identify the tool(s) and version(s) that assisted in creating the SBOM. CycloneDX: metadata.tools (name + version); SPDX: 'Creator: Tool: name-version'.",
        },
        "SBOM-FSCT-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-FSCT-TIMESTAMP",
            name: "FsctTimestamp",
            short_description: "CISA FSCT 3e §2.2.1.2 (Minimum): creation timestamp in a common international format (ISO 8601)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.2")],
            remediation: "Record the date and time the SBOM was produced in a common international format such as ISO 8601 (e.g., 2024-05-23T13:51:37Z), consistent across time zones and locales.",
        },
        "SBOM-FSCT-SBOM-TYPE" => RuleMeta {
            sarif_id: "SBOM-FSCT-SBOM-TYPE",
            name: "FsctSbomType",
            short_description: "CISA FSCT 3e §2.2.1.3 (optional/aspirational): SBOM Type declared (design/source/build/analyzed/deployed/runtime)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.1.3")],
            remediation: "Declare how/why the SBOM was created per the 'Types of SBOM' taxonomy. CycloneDX 1.5+: metadata.lifecycles; SPDX 3.0: Software.Sbom.sbomType. This tool currently parses neither SPDX 2.x CreatorComment type mapping nor SPDX 3.0 sbomType, so the check is gated to CycloneDX input rather than failing SPDX documents.",
        },
        "SBOM-FSCT-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-PRIMARY",
            name: "FsctPrimaryComponent",
            short_description: "CISA FSCT 3e §2.2.1.4: Primary Component (root of dependencies) identified as the subject of the SBOM",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.4")],
            remediation: "Identify the Primary Component the SBOM is about. CycloneDX: metadata.component; SPDX 2.x: documentDescribes / DESCRIBES relationship; SPDX 3.0: Software.Sbom.rootElement.",
        },
        "SBOM-FSCT-DIRECT-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-DIRECT-DEPS",
            name: "FsctDirectDependencies",
            short_description: "CISA FSCT 3e §2.2.2 / §2.3.3 (Minimum): all static direct dependencies of the Primary Component identified",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2"), (K::CisaFsct, "§2.3.3")],
            remediation: "Identify all static, direct dependencies of the Primary Component (or carry an explicit completeness declaration covering their absence), and indicate when the dependency list is incomplete. 'All' is not verifiable from the document alone — the check uses dependency edges from the primary plus the completeness declaration as its evidence.",
        },
        "SBOM-FSCT-TRANSITIVE-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-TRANSITIVE-DEPS",
            name: "FsctTransitiveDependencies",
            short_description: "CISA FSCT 3e §2.2.2 (Recommended): subcomponent levels beyond direct dependencies identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2")],
            remediation: "Identify as many levels of subcomponents beyond the direct dependencies as possible, or declare their absence via the completeness declaration. Heuristic: 'as many as possible' is not crisply verifiable — the depth>=2 threshold is profile policy.",
        },
        "SBOM-FSCT-DYNAMIC-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-DYNAMIC-DEPS",
            name: "FsctDynamicDependencies",
            short_description: "CISA FSCT 3e §2.2.2 / §2.2.2.6 (Aspirational): dynamic and/or remote dependencies uniquely identified",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2"), (K::CisaFsct, "§2.2.2.6")],
            remediation: "Make efforts to uniquely and unambiguously identify dependencies that are dynamic and/or remote. The positive signal is SPDX relationship types DYNAMIC_LINK / RUNTIME_DEPENDENCY_OF / PROVIDED_DEPENDENCY_OF (CycloneDX's parsed model cannot express it, so the check is SPDX-gated). Absence surfaces as an informational readiness note, never a failure.",
        },
        "SBOM-FSCT-COMPONENT-NAME" => RuleMeta {
            sarif_id: "SBOM-FSCT-COMPONENT-NAME",
            name: "FsctComponentName",
            short_description: "CISA FSCT 3e §2.2.2.1 (Minimum): commonly used public name declared for every component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.1")],
            remediation: "Declare the commonly used public name for every component (a namespace:name construct is acceptable for conveying the supplier); placeholder values do not satisfy the element.",
        },
        "SBOM-FSCT-VERSION" => RuleMeta {
            sarif_id: "SBOM-FSCT-VERSION",
            name: "FsctComponentVersion",
            short_description: "CISA FSCT 3e §2.2.2.2 (Minimum): supplier-provided version string (or authored hash as the documented fallback)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.2")],
            remediation: "Record the version string as provided by the Supplier (semantic versioning preferred; accurate transcription is the primary goal). A component without a unique version passes only when an author-provided cryptographic hash is present — the element's documented fallback.",
        },
        "SBOM-FSCT-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-FSCT-SUPPLIER",
            name: "FsctSupplierName",
            short_description: "CISA FSCT 3e §2.2.2.3 (Minimum): Supplier Name declared for all components (explicit 'unknown' permitted)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.3")],
            remediation: "Declare the Supplier Name for all components: the upstream supplier's legal-entity name (commercial) or project name (OSS); the domain URL / PURL namespace or an explicit 'unknown' are permitted last resorts. Silent absence fails; an explicit 'unknown' declaration satisfies the letter of the clause.",
        },
        "SBOM-FSCT-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-FSCT-IDENTIFIER",
            name: "FsctUniqueIdentifier",
            short_description: "CISA FSCT 3e §2.2.2.4 (Minimum): globally unique identifier per component (PURL/CPE/SWID/SWHID; hash accepted)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.4")],
            remediation: "Declare a globally unique identifier for each component — PURL, CPE, SWID, SWHID, UUID/GUID, or OmniBOR Artifact ID; a cryptographic hash also functions as an intrinsic identifier. Profile policy: the document's letter is satisfied by format-native IDs (SPDX namespace + SPDXID, CycloneDX serialNumber + version) and only 'prefers' global uniqueness — this profile deliberately enforces the preferred clause.",
        },
        "SBOM-FSCT-IDENTIFIER-MULTI" => RuleMeta {
            sarif_id: "SBOM-FSCT-IDENTIFIER-MULTI",
            name: "FsctIdentifierMultiplicity",
            short_description: "CISA FSCT 3e §2.2.2.4 (Recommended): as many globally unique identifiers as available",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.4")],
            remediation: "List as many globally unique identifiers as are available for the component. Heuristic: the >=2-distinct-identifier-kinds (PURL/CPE/SWHID/SWID) threshold is profile policy — 'as available' is unverifiable from the document alone.",
        },
        "SBOM-FSCT-HASH" => RuleMeta {
            sarif_id: "SBOM-FSCT-HASH",
            name: "FsctCryptographicHash",
            short_description: "CISA FSCT 3e §2.2.2.5 (Minimum): author-provided cryptographic hash with algorithm, or explicit unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.5")],
            remediation: "Provide a hash (with its algorithm, for reproducibility) for any component whose hash was provided or can be generated; otherwise indicate it as unknown. Accepted at this tier: MD5, SHA1, and SHA2 families — MD5/SHA1 are no longer recommended and are formally discontinued in 2030. Only author-provided hashes count; tool-enriched hashes are not author evidence.",
        },
        "SBOM-FSCT-HASH-PRIMARY-SHA2" => RuleMeta {
            sarif_id: "SBOM-FSCT-HASH-PRIMARY-SHA2",
            name: "FsctPrimaryHashSha2",
            short_description: "CISA FSCT 3e §2.2.2.5 (Recommended): Primary Component hashed; SHA-256-or-stronger SHA-2 hash on hashed components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.5")],
            remediation: "Provide at least one hash of the Primary Component, and use the cryptographically secure SHA-2 family (SHA-256 and higher) for hashed components; wherever less-secure hashes (MD5/SHA1) appear, add an additional cryptographically secure hash.",
        },
        "SBOM-FSCT-RELATIONSHIP" => RuleMeta {
            sarif_id: "SBOM-FSCT-RELATIONSHIP",
            name: "FsctRelationship",
            short_description: "CISA FSCT 3e §2.2.2.6 (Minimum): relationships declared for the Primary Component and its direct dependencies",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.6")],
            remediation: "Declare relationships (primary, included-in/includes) and relationship completeness for the Primary Component and its direct dependencies — the primary must be identified and connected to its direct dependencies in the edge set.",
        },
        "SBOM-FSCT-RELATIONSHIP-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-RELATIONSHIP-ALL",
            name: "FsctRelationshipAll",
            short_description: "CISA FSCT 3e §2.2.2.6 (Recommended): relationships declared for ALL included components (no orphans)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.6")],
            remediation: "Declare relationships and relationship completeness for all included components — components that appear in the inventory but in no dependency edge are orphans.",
        },
        "SBOM-FSCT-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-FSCT-COMPLETENESS",
            name: "FsctRelationshipCompleteness",
            short_description: "CISA FSCT 3e §2.2.2.6.4 (supplemental/optional): relationship-completeness assertion recorded",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.6.4"), (K::CisaFsct, "§2.3.3")],
            remediation: "Record a relationship-completeness assertion (Unknown/None/Partial/Known) — mapped to the document-level completeness declaration (CycloneDX compositions). Warning, not Error: the document labels the attribute supplemental and optional, with Unknown as the open-world default.",
        },
        "SBOM-FSCT-LICENSE-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-PRIMARY",
            name: "FsctLicensePrimary",
            short_description: "CISA FSCT 3e §2.2.2.7 (Minimum): license information for the Primary Component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for the Primary Component, using SPDX license identifiers in standard form where available; NOASSERTION placeholders do not satisfy this check.",
        },
        "SBOM-FSCT-LICENSE-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-COVERAGE",
            name: "FsctLicenseCoverage",
            short_description: "CISA FSCT 3e §2.2.2.7 (Recommended): license information for as many components as possible",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for as many components as possible. The coverage threshold is profile policy — 'as possible' is unverifiable from the document alone.",
        },
        "SBOM-FSCT-LICENSE-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-ALL",
            name: "FsctLicenseAll",
            short_description: "CISA FSCT 3e §2.2.2.7 (Aspirational): license information incl. concluded-license attestation for ALL components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for all listed components, including concluded-license attestation (SPDX PackageLicenseConcluded; the CycloneDX licenses[].acknowledgement field is not currently parsed, so the concluded prong is SPDX-gated).",
        },
        "SBOM-FSCT-COPYRIGHT-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-PRIMARY",
            name: "FsctCopyrightPrimary",
            short_description: "CISA FSCT 3e §2.2.2.8 (Minimum): copyright notice for the Primary Component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide the copyright notice for the Primary Component — it identifies the legal rights holder, and conveying notices is a standard condition of many OSS licenses. SPDX: PackageCopyrightText; CycloneDX: component copyright.",
        },
        "SBOM-FSCT-COPYRIGHT-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-COVERAGE",
            name: "FsctCopyrightCoverage",
            short_description: "CISA FSCT 3e §2.2.2.8 (Recommended): copyright notices for as many components as possible",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide copyright notices for as many components as possible. The coverage threshold is profile policy — 'as possible' is unverifiable from the document alone.",
        },
        "SBOM-FSCT-COPYRIGHT-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-ALL",
            name: "FsctCopyrightAll",
            short_description: "CISA FSCT 3e §2.2.2.8 (Aspirational): copyright notice on every listed component",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide a copyright notice for every listed SBOM component.",
        },
        "SBOM-FSCT-NOASSERTION" => RuleMeta {
            sarif_id: "SBOM-FSCT-NOASSERTION",
            name: "FsctNoAssertion",
            short_description: "CISA FSCT 3e §2.3.1 (Minimum): baseline attributes populated or explicitly declared no-assertion/no-value",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.3.1")],
            remediation: "Provide every baseline attribute, or explicitly differentiate 'no assertion' (data missing) from 'no value' (not applicable). This rule fires only where an attribute is neither populated nor explicitly (or format-default) declared — the document sanctions explicit declarations as the recommended graceful handling and lets formats treat missing attributes as default no-assertion. Placeholders never satisfy the other SBOM-FSCT-* checks.",
        },
        "SBOM-FSCT-UPSTREAM-SBOM" => RuleMeta {
            sarif_id: "SBOM-FSCT-UPSTREAM-SBOM",
            name: "FsctUpstreamSbom",
            short_description: "CISA FSCT 3e §2.3.3 (Recommended): upstream supplier SBOM data provided or linked for third-party direct dependencies",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.3.3")],
            remediation: "Obtain the upstream Supplier's SBOM and provide the component data nested within the Primary Component's SBOM or linked separately (BOM-type external references on third-party direct dependencies are the positive evidence). Advisory heuristic — contacting suppliers is unobservable in the document.",
        },
        "SBOM-FSCT-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-FSCT-SIGNATURE",
            name: "FsctSignature",
            short_description: "CISA FSCT 3e §2.4 (supplemental): SBOM carries a verifiable digital signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.4")],
            remediation: "Digitally sign the SBOM so consumers can verify authenticity and integrity (requires a digital signature plus PKI). Info severity: §2.4 is a supplemental element, not a Baseline Attribute, and SPDX has no in-band signature field.",
        },
        // Generic bucket for FSCT-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-FSCT-GENERAL" => RuleMeta {
            sarif_id: "SBOM-FSCT-GENERAL",
            name: "FsctGeneralRequirement",
            short_description: "CISA FSCT 3e: general baseline-attribute requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "Baseline Attributes")],
            remediation: REMEDIATION_GENERIC_FSCT,
        },
        _ => return None,
    };
    Some(meta)
}

/// Every stable internal rule key with a `rule_meta` match arm, in match-arm
/// order. Kept adjacent to [`rule_meta`]; the `all_rule_ids_matches_the_registry`
/// test asserts the list and the match arms stay in lockstep.
const ALL_RULE_IDS: &[&str] = &[
    "SBOM-CRA-ART-13-2",
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-24-SUPPLIER",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-ART-14",
    "SBOM-CRA-ART-24",
    "SBOM-CRA-ANNEX-I",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-TRACEABILITY",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-PRE-8-RQ-02",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-GENERAL",
    "SBOM-QUALITY-GENERAL",
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
    "SBOM-EUCC-GENERAL",
    "SBOM-AIACT-ANNEX-IV-1",
    "SBOM-AIACT-ANNEX-IV-2D",
    "SBOM-AIACT-ANNEX-IV-2G",
    "SBOM-AIACT-ANNEX-IV-2C",
    "SBOM-AIACT-ANNEX-IV-3",
    "SBOM-AIACT-NA",
    "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
    "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
    "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
    "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
    "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
    "SBOM-AIACT-ANNEX-IV-2G-METRICS",
    "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
    "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
    "SBOM-AIACT-UNTYPED-ML",
    "SBOM-AIACT-GENERAL",
    "SBOM-BSIAI-META",
    "SBOM-BSIAI-SYS",
    "SBOM-BSIAI-MODEL",
    "SBOM-BSIAI-DATASET",
    "SBOM-BSIAI-INFRA",
    "SBOM-BSIAI-SEC",
    "SBOM-BSIAI-NA",
    "SBOM-BSIAI-UNTYPED-ML",
    "SBOM-BSIAI-META-AUTHOR",
    "SBOM-BSIAI-META-FORMAT",
    "SBOM-BSIAI-META-TIMESTAMP",
    "SBOM-BSIAI-META-TOOL",
    "SBOM-BSIAI-META-SIGNATURE",
    "SBOM-BSIAI-SYS-PRIMARY",
    "SBOM-BSIAI-SYS-PRODUCER",
    "SBOM-BSIAI-SYS-DATAFLOW",
    "SBOM-BSIAI-MODEL-NAME",
    "SBOM-BSIAI-MODEL-VERSION",
    "SBOM-BSIAI-MODEL-IDENTIFIER",
    "SBOM-BSIAI-MODEL-HASH",
    "SBOM-BSIAI-MODEL-HASH-ALGO",
    "SBOM-BSIAI-MODEL-CARD",
    "SBOM-BSIAI-MODEL-ARCHITECTURE",
    "SBOM-BSIAI-MODEL-DATASETS",
    "SBOM-BSIAI-MODEL-LIMITATIONS",
    "SBOM-BSIAI-MODEL-LICENSE",
    "SBOM-BSIAI-DATASET-NAME",
    "SBOM-BSIAI-DATASET-IDENTIFIER",
    "SBOM-BSIAI-DATASET-HASH",
    "SBOM-BSIAI-DATASET-LICENSE",
    "SBOM-BSIAI-DATASET-SENSITIVITY",
    "SBOM-BSIAI-DATASET-PROVENANCE",
    "SBOM-BSIAI-INFRA-RUNTIME",
    "SBOM-BSIAI-SEC-CONTROLS",
    "SBOM-BSIAI-SEC-EXPLOITABILITY",
    "SBOM-BSIAI-GENERAL",
    "SBOM-NTIA-VERSION",
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-NTIA-SUPPLIER",
    "SBOM-NTIA-DEPENDENCY",
    "SBOM-FDA-SUPPLIER",
    "SBOM-FDA-SUPPORT",
    "SBOM-FDA-NAME",
    "SBOM-FDA-VERSION",
    "SBOM-FDA-IDENTIFIER",
    "SBOM-FDA-HASH",
    "SBOM-FDA-CREATOR",
    "SBOM-FDA-INVENTORY",
    "SBOM-FDA-NAMESPACE",
    "SBOM-FDA-DEPENDENCY",
    "SBOM-FDA-SECURITY",
    "SBOM-FDA-GENERAL",
    "SBOM-NTIA-AUTHOR",
    "SBOM-NTIA-INVENTORY",
    "SBOM-NTIA-NAME",
    "SBOM-NTIA-IDENTIFIER",
    "SBOM-NTIA-GENERAL",
    "SBOM-SSDF-GENERAL",
    "SBOM-EO14028-GENERAL",
    "SBOM-SSDF-PS1",
    "SBOM-SSDF-PS2",
    "SBOM-SSDF-PS3",
    "SBOM-SSDF-INVENTORY",
    "SBOM-SSDF-PO1",
    "SBOM-SSDF-PO3",
    "SBOM-SSDF-PW4",
    "SBOM-SSDF-PW6",
    "SBOM-SSDF-RV1",
    "SBOM-EO14028-FORMAT",
    "SBOM-EO14028-AUTOGEN",
    "SBOM-EO14028-CREATOR",
    "SBOM-EO14028-IDENTIFIER",
    "SBOM-EO14028-DEPENDENCY",
    "SBOM-EO14028-VERSION",
    "SBOM-EO14028-INTEGRITY",
    "SBOM-EO14028-DISCLOSURE",
    "SBOM-EO14028-SUPPLIER",
    "SBOM-EO14028-INVENTORY",
    "SBOM-EO14028-TIMESTAMP",
    "SBOM-EO14028-NAME",
    "SBOM-BSI-TR-03183-2-4",
    "SBOM-BSI-TR-03183-2-5-1",
    "SBOM-BSI-TR-03183-2-5-1-CONTACT",
    "SBOM-BSI-TR-03183-2-5-2",
    "SBOM-BSI-TR-03183-2-5-3",
    "SBOM-BSI-TR-03183-2-VERSION",
    "SBOM-BSI-TR-03183-2-INVENTORY",
    "SBOM-BSI-TR-03183-2-LICENSE",
    "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
    "SBOM-BSI-TR-03183-2-CREATOR",
    "SBOM-BSI-TR-03183-2-5-4",
    "SBOM-BSI-TR-03183-2-5-4-MISSING",
    "SBOM-BSI-TR-03183-2-5-5",
    "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
    "SBOM-BSI-TR-03183-2-5-2-4",
    "SBOM-BSI-TR-03183-2-3-1",
    "SBOM-BSI-TR-03183-2-GENERAL",
    "SBOM-CNSA2-000",
    "SBOM-CNSA2-ALG-001",
    "SBOM-CNSA2-ALG-002",
    "SBOM-CNSA2-ALG-003",
    "SBOM-CNSA2-ALG-004",
    "SBOM-CNSA2-ALG-006",
    "SBOM-CNSA2-ALG-007",
    "SBOM-CNSA2-ALG-005",
    "SBOM-CNSA2-ALG-008",
    "SBOM-CNSA2-ALG-UNKNOWN",
    "SBOM-CNSA2-CERT-001",
    "SBOM-CNSA2-CERT-UNKNOWN",
    "SBOM-CNSA2-PROTO-001",
    "SBOM-CNSA2-PROTO-002",
    "SBOM-CNSA2-PROTO-UNKNOWN",
    "SBOM-CNSA2-GENERAL",
    "SBOM-PQC-000",
    "SBOM-PQC-001",
    "SBOM-PQC-012",
    "SBOM-PQC-ALG-UNKNOWN",
    "SBOM-PQC-010",
    "SBOM-PQC-005",
    "SBOM-PQC-008",
    "SBOM-PQC-009",
    "SBOM-PQC-KEY-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-UNKNOWN",
    "SBOM-PQC-GENERAL",
    "SBOM-CISA2026-AUTHOR",
    "SBOM-CISA2026-SIGNATURE",
    "SBOM-CISA2026-FORMAT",
    "SBOM-CISA2026-GENERATION-CONTEXT",
    "SBOM-CISA2026-TIMESTAMP",
    "SBOM-CISA2026-TOOL",
    "SBOM-CISA2026-TOOL-VERSION",
    "SBOM-CISA2026-SBOM-VERSION",
    "SBOM-CISA2026-PRODUCER",
    "SBOM-CISA2026-INVENTORY",
    "SBOM-CISA2026-NAME",
    "SBOM-CISA2026-VERSION",
    "SBOM-CISA2026-IDENTIFIER",
    "SBOM-CISA2026-HASH",
    "SBOM-CISA2026-HASH-ALGO",
    "SBOM-CISA2026-LICENSE",
    "SBOM-CISA2026-DEPENDENCY",
    "SBOM-CISA2026-COVERAGE",
    "SBOM-CISA2026-GENERAL",
    "SBOM-PCI-6-3-2-INVENTORY",
    "SBOM-PCI-6-3-2-NAME",
    "SBOM-PCI-6-3-2-VERSION",
    "SBOM-PCI-6-3-2-SUPPLIER",
    "SBOM-PCI-6-3-2-IDENTIFIER",
    "SBOM-PCI-6-3-2-THIRD-PARTY",
    "SBOM-PCI-6-3-2-COMPLETENESS",
    "SBOM-PCI-6-3-2-FRESHNESS",
    "SBOM-PCI-6-3-2-VULN-EVIDENCE",
    "SBOM-PCI-11-3-1-1-SEVERITY",
    "SBOM-PCI-GENERAL",
    "SBOM-FSCT-AUTHOR",
    "SBOM-FSCT-AUTHOR-TOOL",
    "SBOM-FSCT-TIMESTAMP",
    "SBOM-FSCT-SBOM-TYPE",
    "SBOM-FSCT-PRIMARY",
    "SBOM-FSCT-DIRECT-DEPS",
    "SBOM-FSCT-TRANSITIVE-DEPS",
    "SBOM-FSCT-DYNAMIC-DEPS",
    "SBOM-FSCT-COMPONENT-NAME",
    "SBOM-FSCT-VERSION",
    "SBOM-FSCT-SUPPLIER",
    "SBOM-FSCT-IDENTIFIER",
    "SBOM-FSCT-IDENTIFIER-MULTI",
    "SBOM-FSCT-HASH",
    "SBOM-FSCT-HASH-PRIMARY-SHA2",
    "SBOM-FSCT-RELATIONSHIP",
    "SBOM-FSCT-RELATIONSHIP-ALL",
    "SBOM-FSCT-COMPLETENESS",
    "SBOM-FSCT-LICENSE-PRIMARY",
    "SBOM-FSCT-LICENSE-COVERAGE",
    "SBOM-FSCT-LICENSE-ALL",
    "SBOM-FSCT-COPYRIGHT-PRIMARY",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-COPYRIGHT-ALL",
    "SBOM-FSCT-NOASSERTION",
    "SBOM-FSCT-UPSTREAM-SBOM",
    "SBOM-FSCT-SIGNATURE",
    "SBOM-FSCT-GENERAL",
];

/// Enumerate every registered internal rule key, in registry order.
#[must_use]
pub fn all_rule_ids() -> &'static [&'static str] {
    ALL_RULE_IDS
}

/// Map an owned rule-id string back to the registry's `&'static str` key.
/// Used when deserializing payloads that carry a serialized `rule_id`, so a
/// round-tripped violation keeps its registry identity instead of collapsing
/// to the generic default.
#[must_use]
pub(crate) fn lookup_static_rule_id(rule_id: &str) -> Option<&'static str> {
    ALL_RULE_IDS.iter().find(|k| **k == rule_id).copied()
}

// ---------------------------------------------------------------------------
// Per-standard SARIF rule catalogues.
//
// Each slice lists, in display order, the externally-visible SARIF rule ids a
// standard's report declares as reportingDescriptors. Every id must be a
// registry key whose `sarif_id` equals the key itself (a self-descriptor);
// the `sarif_rule_slices_are_self_descriptors` test enforces this. The SARIF
// generator (src/reports/sarif.rs) renders these through `rule_meta`, so
// name / shortDescription / defaultConfiguration.level can no longer drift
// from the registry.
// ---------------------------------------------------------------------------

/// NTIA Minimum Elements SARIF rule catalogue.
pub const NTIA_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-NTIA-AUTHOR",
    "SBOM-NTIA-INVENTORY",
    "SBOM-NTIA-NAME",
    "SBOM-NTIA-VERSION",
    "SBOM-NTIA-SUPPLIER",
    "SBOM-NTIA-IDENTIFIER",
    "SBOM-NTIA-DEPENDENCY",
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-NTIA-GENERAL",
];

/// FDA premarket SARIF rule catalogue. The FDA baseline check reuses the
/// NTIA timestamp rule id (the FDA guidance incorporates the NTIA minimum
/// elements).
pub const FDA_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-FDA-INVENTORY",
    "SBOM-FDA-CREATOR",
    "SBOM-FDA-NAMESPACE",
    "SBOM-FDA-SUPPLIER",
    "SBOM-FDA-HASH",
    "SBOM-FDA-IDENTIFIER",
    "SBOM-FDA-VERSION",
    "SBOM-FDA-DEPENDENCY",
    "SBOM-FDA-SUPPORT",
    "SBOM-FDA-SECURITY",
    "SBOM-FDA-GENERAL",
];

/// NIST SSDF (SP 800-218) SARIF rule catalogue.
pub const SSDF_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-SSDF-PS1",
    "SBOM-SSDF-PS2",
    "SBOM-SSDF-PS3",
    "SBOM-SSDF-INVENTORY",
    "SBOM-SSDF-PO1",
    "SBOM-SSDF-PO3",
    "SBOM-SSDF-PW4",
    "SBOM-SSDF-PW6",
    "SBOM-SSDF-RV1",
    "SBOM-SSDF-GENERAL",
];

/// EO 14028 Section 4 SARIF rule catalogue.
pub const EO14028_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-EO14028-TIMESTAMP",
    "SBOM-EO14028-NAME",
    "SBOM-EO14028-FORMAT",
    "SBOM-EO14028-AUTOGEN",
    "SBOM-EO14028-CREATOR",
    "SBOM-EO14028-IDENTIFIER",
    "SBOM-EO14028-DEPENDENCY",
    "SBOM-EO14028-VERSION",
    "SBOM-EO14028-INTEGRITY",
    "SBOM-EO14028-DISCLOSURE",
    "SBOM-EO14028-SUPPLIER",
    "SBOM-EO14028-INVENTORY",
    "SBOM-EO14028-GENERAL",
];

/// Shared CRA / EUCC / BSI TR-03183-2 / EU AI Act / BSI-G7 SBOM-for-AI SARIF
/// rule catalogue (the default for CRA-family and readiness profiles).
pub const COMPLIANCE_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-GENERAL",
    "SBOM-CRA-PRE-8-RQ-02",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
    "SBOM-BSI-TR-03183-2-4",
    "SBOM-BSI-TR-03183-2-5-1",
    "SBOM-BSI-TR-03183-2-5-1-CONTACT",
    "SBOM-BSI-TR-03183-2-5-2",
    "SBOM-BSI-TR-03183-2-5-3",
    "SBOM-BSI-TR-03183-2-VERSION",
    "SBOM-BSI-TR-03183-2-INVENTORY",
    "SBOM-BSI-TR-03183-2-LICENSE",
    "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
    "SBOM-BSI-TR-03183-2-CREATOR",
    "SBOM-BSI-TR-03183-2-5-4",
    "SBOM-BSI-TR-03183-2-5-4-MISSING",
    "SBOM-BSI-TR-03183-2-5-5",
    "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
    "SBOM-BSI-TR-03183-2-5-2-4",
    "SBOM-BSI-TR-03183-2-3-1",
    "SBOM-BSI-TR-03183-2-GENERAL",
    "SBOM-AIACT-NA",
    "SBOM-AIACT-ANNEX-IV-1",
    "SBOM-AIACT-ANNEX-IV-2D",
    "SBOM-AIACT-ANNEX-IV-2G",
    "SBOM-AIACT-ANNEX-IV-2C",
    "SBOM-AIACT-ANNEX-IV-3",
    "SBOM-AIACT-UNTYPED-ML",
    "SBOM-BSIAI-NA",
    "SBOM-BSIAI-META",
    "SBOM-BSIAI-SYS",
    "SBOM-BSIAI-MODEL",
    "SBOM-BSIAI-DATASET",
    "SBOM-BSIAI-INFRA",
    "SBOM-BSIAI-SEC",
    "SBOM-BSIAI-UNTYPED-ML",
];

/// NSA CNSA 2.0 SARIF rule catalogue: every `SBOM-CNSA2-*` self-descriptor
/// in the registry. The `cnsa2_and_pqc_slices_cover_their_rule_families`
/// test keeps this slice in lockstep with the registry, so a CNSA 2.0 run
/// declares its own rule family instead of the CRA-family catalogue.
pub const CNSA2_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CNSA2-000",
    "SBOM-CNSA2-ALG-001",
    "SBOM-CNSA2-ALG-002",
    "SBOM-CNSA2-ALG-003",
    "SBOM-CNSA2-ALG-004",
    "SBOM-CNSA2-ALG-005",
    "SBOM-CNSA2-ALG-006",
    "SBOM-CNSA2-ALG-007",
    "SBOM-CNSA2-ALG-008",
    "SBOM-CNSA2-ALG-UNKNOWN",
    "SBOM-CNSA2-CERT-001",
    "SBOM-CNSA2-CERT-UNKNOWN",
    "SBOM-CNSA2-PROTO-001",
    "SBOM-CNSA2-PROTO-002",
    "SBOM-CNSA2-PROTO-UNKNOWN",
    "SBOM-CNSA2-GENERAL",
];

/// NIST PQC readiness SARIF rule catalogue: every `SBOM-PQC-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CNSA2_SARIF_RULE_IDS`].
pub const PQC_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-PQC-000",
    "SBOM-PQC-001",
    "SBOM-PQC-005",
    "SBOM-PQC-008",
    "SBOM-PQC-009",
    "SBOM-PQC-010",
    "SBOM-PQC-012",
    "SBOM-PQC-ALG-UNKNOWN",
    "SBOM-PQC-KEY-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-UNKNOWN",
    "SBOM-PQC-GENERAL",
];

/// CISA 2026 Minimum Elements SARIF rule catalogue: every `SBOM-CISA2026-*`
/// self-descriptor in the registry. The
/// `p4_profile_slices_cover_their_rule_families` test keeps this slice in
/// lockstep with the registry.
pub const CISA2026_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CISA2026-AUTHOR",
    "SBOM-CISA2026-SIGNATURE",
    "SBOM-CISA2026-FORMAT",
    "SBOM-CISA2026-GENERATION-CONTEXT",
    "SBOM-CISA2026-TIMESTAMP",
    "SBOM-CISA2026-TOOL",
    "SBOM-CISA2026-TOOL-VERSION",
    "SBOM-CISA2026-SBOM-VERSION",
    "SBOM-CISA2026-PRODUCER",
    "SBOM-CISA2026-INVENTORY",
    "SBOM-CISA2026-NAME",
    "SBOM-CISA2026-VERSION",
    "SBOM-CISA2026-IDENTIFIER",
    "SBOM-CISA2026-HASH",
    "SBOM-CISA2026-HASH-ALGO",
    "SBOM-CISA2026-LICENSE",
    "SBOM-CISA2026-DEPENDENCY",
    "SBOM-CISA2026-COVERAGE",
    "SBOM-CISA2026-GENERAL",
];

/// PCI DSS v4.0.1 Req. 6.3.2 SARIF rule catalogue: every `SBOM-PCI-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CISA2026_SARIF_RULE_IDS`].
pub const PCIDSS_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-PCI-6-3-2-INVENTORY",
    "SBOM-PCI-6-3-2-NAME",
    "SBOM-PCI-6-3-2-VERSION",
    "SBOM-PCI-6-3-2-SUPPLIER",
    "SBOM-PCI-6-3-2-IDENTIFIER",
    "SBOM-PCI-6-3-2-THIRD-PARTY",
    "SBOM-PCI-6-3-2-COMPLETENESS",
    "SBOM-PCI-6-3-2-FRESHNESS",
    "SBOM-PCI-6-3-2-VULN-EVIDENCE",
    "SBOM-PCI-11-3-1-1-SEVERITY",
    "SBOM-PCI-GENERAL",
];

/// CISA FSCT 3rd-edition SARIF rule catalogue: every `SBOM-FSCT-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CISA2026_SARIF_RULE_IDS`].
pub const FSCT_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-FSCT-AUTHOR",
    "SBOM-FSCT-AUTHOR-TOOL",
    "SBOM-FSCT-TIMESTAMP",
    "SBOM-FSCT-SBOM-TYPE",
    "SBOM-FSCT-PRIMARY",
    "SBOM-FSCT-DIRECT-DEPS",
    "SBOM-FSCT-TRANSITIVE-DEPS",
    "SBOM-FSCT-DYNAMIC-DEPS",
    "SBOM-FSCT-COMPONENT-NAME",
    "SBOM-FSCT-VERSION",
    "SBOM-FSCT-SUPPLIER",
    "SBOM-FSCT-IDENTIFIER",
    "SBOM-FSCT-IDENTIFIER-MULTI",
    "SBOM-FSCT-HASH",
    "SBOM-FSCT-HASH-PRIMARY-SHA2",
    "SBOM-FSCT-RELATIONSHIP",
    "SBOM-FSCT-RELATIONSHIP-ALL",
    "SBOM-FSCT-COMPLETENESS",
    "SBOM-FSCT-LICENSE-PRIMARY",
    "SBOM-FSCT-LICENSE-COVERAGE",
    "SBOM-FSCT-LICENSE-ALL",
    "SBOM-FSCT-COPYRIGHT-PRIMARY",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-COPYRIGHT-ALL",
    "SBOM-FSCT-NOASSERTION",
    "SBOM-FSCT-UPSTREAM-SBOM",
    "SBOM-FSCT-SIGNATURE",
    "SBOM-FSCT-GENERAL",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL_RULE_IDS` and the `rule_meta` match arms must stay in lockstep:
    /// every listed id resolves, every match arm is listed, no duplicates.
    /// The match arms are recovered from the source text of this file, so a
    /// new arm cannot land without being enumerated.
    #[test]
    fn all_rule_ids_matches_the_registry() {
        let src = include_str!("registry.rs");
        let mut match_arms = Vec::new();
        for line in src.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix('"')
                && let Some(id) = rest.strip_suffix("\" => RuleMeta {")
            {
                match_arms.push(id.to_string());
            }
        }
        let listed: Vec<&str> = all_rule_ids().to_vec();
        let listed_set: std::collections::BTreeSet<&str> = listed.iter().copied().collect();
        assert_eq!(
            listed.len(),
            listed_set.len(),
            "ALL_RULE_IDS contains duplicates"
        );
        let arm_set: std::collections::BTreeSet<&str> =
            match_arms.iter().map(String::as_str).collect();
        assert_eq!(
            arm_set, listed_set,
            "rule_meta match arms and ALL_RULE_IDS drifted apart"
        );
        for id in listed {
            assert!(rule_meta(id).is_some(), "listed id {id:?} does not resolve");
        }
    }

    /// CNSA 2.0 rules must remediate with CNSA 2.0 guidance, not the generic
    /// fallback: SBOM-CNSA2-ALG-001..004/006/007, -000 and -CERT-001 used
    /// `REMEDIATION_GENERIC`, which cites the EU CRA (EU 2024/2847) — a US
    /// NSA CNSA 2.0 finding pointed the user at an EU regulation.
    #[test]
    fn cnsa2_rules_cite_cnsa_not_eu_cra() {
        for id in all_rule_ids().iter().filter(|id| id.contains("CNSA2")) {
            let meta = rule_meta(id).expect("listed id resolves");
            assert!(
                !meta.remediation.contains("EU CRA"),
                "{id}: a CNSA 2.0 rule must not cite the EU CRA as its remediation source"
            );
            assert!(
                meta.remediation.contains("CNSA 2.0"),
                "{id}: CNSA 2.0 rules should carry CNSA 2.0 migration guidance"
            );
        }
    }

    /// Non-CRA standards must not fall back to the CRA-citing generic
    /// remediation: an NTIA/FDA/AI-Act/BSI finding that points the user at
    /// EU 2024/2847 cites the wrong regulation (same defect class as the
    /// CNSA case above). CRA rules keep the CRA citation.
    #[test]
    fn non_cra_rules_do_not_cite_eu_cra_as_generic_fallback() {
        for id in all_rule_ids()
            .iter()
            .filter(|id| id.contains("NTIA") || id.contains("FDA") || id.contains("AIACT"))
        {
            let meta = rule_meta(id).expect("listed id resolves");
            assert!(
                !meta.remediation.contains("EU CRA regulation"),
                "{id}: a non-CRA rule must not cite the EU CRA as its generic remediation"
            );
        }
        let bsi = rule_meta("SBOM-BSI-TR-03183-2-GENERAL").expect("BSI general rule resolves");
        assert!(
            bsi.remediation.contains("TR-03183-2"),
            "BSI general rule should cite TR-03183-2, got: {}",
            bsi.remediation
        );
    }

    /// Every id in a per-standard SARIF slice must be a self-descriptor:
    /// a registry key whose `sarif_id` is the key itself. The SARIF
    /// generator relies on this to render descriptors without aliasing.
    #[test]
    fn sarif_rule_slices_are_self_descriptors() {
        for (label, slice) in [
            ("ntia", NTIA_SARIF_RULE_IDS),
            ("fda", FDA_SARIF_RULE_IDS),
            ("ssdf", SSDF_SARIF_RULE_IDS),
            ("eo14028", EO14028_SARIF_RULE_IDS),
            ("compliance", COMPLIANCE_SARIF_RULE_IDS),
            ("cnsa2", CNSA2_SARIF_RULE_IDS),
            ("pqc", PQC_SARIF_RULE_IDS),
            ("cisa2026", CISA2026_SARIF_RULE_IDS),
            ("pci-dss", PCIDSS_SARIF_RULE_IDS),
            ("fsct", FSCT_SARIF_RULE_IDS),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for id in slice {
                assert!(seen.insert(*id), "[{label}] duplicate slice id {id}");
                let meta = rule_meta(id)
                    .unwrap_or_else(|| panic!("[{label}] slice id {id} not in registry"));
                assert_eq!(
                    meta.sarif_id, *id,
                    "[{label}] slice id {id} aliases to {}; slices must list self-descriptors",
                    meta.sarif_id
                );
            }
        }
    }

    /// The CNSA 2.0 / PQC catalogues must enumerate their entire rule
    /// family: a registry rule missing from its slice would only surface via
    /// the catalogue-completion backfill when it happens to fire, putting
    /// SARIF consumers' suppressions/baselines back on an incomplete
    /// catalogue.
    #[test]
    fn cnsa2_and_pqc_slices_cover_their_rule_families() {
        for (prefix, slice) in [
            ("SBOM-CNSA2-", CNSA2_SARIF_RULE_IDS),
            ("SBOM-PQC-", PQC_SARIF_RULE_IDS),
        ] {
            let expected: std::collections::BTreeSet<&str> = all_rule_ids()
                .iter()
                .copied()
                .filter(|id| id.starts_with(prefix))
                .collect();
            let actual: std::collections::BTreeSet<&str> = slice.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{prefix}* SARIF slice drifted from the registry"
            );
        }
    }

    /// The CISA 2026 / PCI DSS / FSCT catalogues must enumerate their entire
    /// rule family (same guarantee as the CNSA 2.0 / PQC test above): the
    /// parallel checker wave adds check sites but may not touch this file,
    /// so a family rule missing from its slice would silently fall off the
    /// upfront-declared SARIF catalogue.
    #[test]
    fn p4_profile_slices_cover_their_rule_families() {
        for (prefix, slice) in [
            ("SBOM-CISA2026-", CISA2026_SARIF_RULE_IDS),
            ("SBOM-PCI-", PCIDSS_SARIF_RULE_IDS),
            ("SBOM-FSCT-", FSCT_SARIF_RULE_IDS),
        ] {
            let expected: std::collections::BTreeSet<&str> = all_rule_ids()
                .iter()
                .copied()
                .filter(|id| id.starts_with(prefix))
                .collect();
            let actual: std::collections::BTreeSet<&str> = slice.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{prefix}* SARIF slice drifted from the registry"
            );
        }
    }

    /// Aliased keys (key != sarif_id) must carry the canonical descriptor's
    /// name and short description, so every surface renders the shared SARIF
    /// rule identically.
    #[test]
    fn aliased_keys_share_the_canonical_descriptor_text() {
        for id in all_rule_ids() {
            let meta = rule_meta(id).expect("listed id resolves");
            if meta.sarif_id == *id {
                continue;
            }
            let canonical = rule_meta(meta.sarif_id).unwrap_or_else(|| {
                panic!(
                    "{id} aliases to {} which has no self-descriptor",
                    meta.sarif_id
                )
            });
            assert_eq!(
                meta.name, canonical.name,
                "{id} name differs from its canonical descriptor {}",
                meta.sarif_id
            );
            assert_eq!(
                meta.short_description, canonical.short_description,
                "{id} short_description differs from its canonical descriptor {}",
                meta.sarif_id
            );
        }
    }
}
