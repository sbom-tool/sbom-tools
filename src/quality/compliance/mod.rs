//! SBOM Compliance checking module.
//!
//! Validates SBOMs against format requirements and industry standards.
//!
//! The public surface ([`ComplianceChecker`], [`ComplianceLevel`],
//! [`ComplianceResult`], [`Violation`], the rule registry, …) lives here; the
//! per-standard check logic is split across sibling submodules and dispatched
//! through the [`StandardChecker`] trait in [`context`].

use crate::model::{NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};

mod bsi;
mod context;
mod cra;
mod crypto;
mod eo14028;
mod eucc;
mod generic;
mod registry;
mod shared;
mod ssdf;

use context::{ComplianceContext, checker_for};
use registry::REMEDIATION_GENERIC;
pub use registry::{RuleMeta, rule_meta};
use shared::{is_valid_email_format, truncate_list};

/// CRA enforcement phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CraPhase {
    /// Phase 1: Reporting obligations — deadline 11 December 2027
    /// Basic SBOM requirements: product/component identification, manufacturer, version, format
    Phase1,
    /// Phase 2: Full compliance — deadline 11 December 2029
    /// Adds: vulnerability metadata, lifecycle/end-of-support, disclosure policy, EU `DoC`
    Phase2,
}

impl CraPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Phase1 => "Phase 1 (2027)",
            Self::Phase2 => "Phase 2 (2029)",
        }
    }

    pub const fn deadline(self) -> &'static str {
        match self {
            Self::Phase1 => "11 December 2027",
            Self::Phase2 => "11 December 2029",
        }
    }
}

/// Compliance level/profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ComplianceLevel {
    /// Minimum viable SBOM (basic identification)
    Minimum,
    /// Standard compliance (recommended fields)
    Standard,
    /// NTIA Minimum Elements compliance
    NtiaMinimum,
    /// EU CRA Phase 1 — Reporting obligations (deadline: 11 Dec 2027)
    CraPhase1,
    /// EU CRA Phase 2 — Full compliance (deadline: 11 Dec 2029)
    CraPhase2,
    /// FDA Medical Device SBOM requirements
    FdaMedicalDevice,
    /// NIST SP 800-218 Secure Software Development Framework
    NistSsdf,
    /// Executive Order 14028 Section 4 — Enhancing Software Supply Chain Security
    Eo14028,
    /// NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0
    Cnsa2,
    /// NIST PQC Readiness — Post-Quantum Cryptography migration (IR 8547 + FIPS 203/204/205)
    NistPqc,
    /// BSI TR-03183-2 (German national CRA-aligned SBOM technical guideline).
    /// Free, ENISA-cited; stricter than NTIA on hashes and identifiers.
    BsiTr03183_2,
    /// CRA Article 24 — Open-source software steward profile (lighter
    /// obligations than CraPhase1/2). SBOM, vulnerability handling process,
    /// and CVD policy are still required; manufacturer email, EU DoC, and
    /// conformity-assessment-module gating are NOT.
    CraOssSteward,
    /// EUCC Substantial assurance level (Reg. (EU) 2024/482) — reference-only
    /// profile for Annex IV products. Verifies that the SBOM/sidecar carries
    /// a Common-Criteria Protection-Profile reference, Target-of-Evaluation
    /// reference, ITSEF identifier, and a valid-until date. Does not perform
    /// a Common-Criteria evaluation itself.
    EuccSubstantial,
    /// Comprehensive compliance (all recommended fields)
    Comprehensive,
}

impl ComplianceLevel {
    /// Get human-readable name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Minimum => "Minimum",
            Self::Standard => "Standard",
            Self::NtiaMinimum => "NTIA Minimum Elements",
            Self::CraPhase1 => "EU CRA Phase 1 (2027)",
            Self::CraPhase2 => "EU CRA Phase 2 (2029)",
            Self::FdaMedicalDevice => "FDA Medical Device",
            Self::NistSsdf => "NIST SSDF (SP 800-218)",
            Self::Eo14028 => "EO 14028 Section 4",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC Readiness",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::CraOssSteward => "CRA OSS Steward (Art. 24)",
            Self::EuccSubstantial => "EUCC Substantial (Reg. 2024/482)",
            Self::Comprehensive => "Comprehensive",
        }
    }

    /// Get compact tab label (max ~8 chars) for terminal display.
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::Minimum => "Min",
            Self::Standard => "Std",
            Self::NtiaMinimum => "NTIA",
            Self::CraPhase1 => "CRA-1",
            Self::CraPhase2 => "CRA-2",
            Self::FdaMedicalDevice => "FDA",
            Self::NistSsdf => "SSDF",
            Self::Eo14028 => "EO14028",
            Self::Cnsa2 => "CNSA2",
            Self::NistPqc => "PQC",
            Self::BsiTr03183_2 => "BSI",
            Self::CraOssSteward => "OSS",
            Self::EuccSubstantial => "EUCC",
            Self::Comprehensive => "Full",
        }
    }

    /// Get description of what this level checks
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Minimum => "Basic component identification only",
            Self::Standard => "Recommended fields for general use",
            Self::NtiaMinimum => "NTIA minimum elements for software transparency",
            Self::CraPhase1 => {
                "CRA reporting obligations — product ID, SBOM format, manufacturer (deadline: 11 Dec 2027)"
            }
            Self::CraPhase2 => {
                "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (deadline: 11 Dec 2029)"
            }
            Self::FdaMedicalDevice => "FDA premarket submission requirements for medical devices",
            Self::NistSsdf => {
                "Secure Software Development Framework — provenance, build integrity, VCS references"
            }
            Self::Eo14028 => {
                "Executive Order 14028 — machine-readable SBOM, auto-generation, supply chain security"
            }
            Self::Cnsa2 => {
                "CNSA 2.0 — AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87, quantum security level 5"
            }
            Self::NistPqc => {
                "NIST PQC — quantum-vulnerable algorithm detection, FIPS 203/204/205, SP 800-131A"
            }
            Self::BsiTr03183_2 => {
                "BSI TR-03183-2 — German national SBOM guideline (free, ENISA-cited): mandatory hashes, identifiers, ISO-8601 timestamps"
            }
            Self::CraOssSteward => {
                "CRA Article 24 — Open-source software steward (lighter than full manufacturer obligations): SBOM + CVD policy + vuln-handling required, no DoC/module/manufacturer-email enforcement"
            }
            Self::EuccSubstantial => {
                "EUCC Substantial (Reg. (EU) 2024/482) — reference-only check for Common-Criteria Protection Profile, Target of Evaluation, ITSEF, and certificate valid-until date"
            }
            Self::Comprehensive => "All recommended fields and best practices",
        }
    }

    /// Get all compliance levels
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Minimum,
            Self::Standard,
            Self::NtiaMinimum,
            Self::CraPhase1,
            Self::CraPhase2,
            Self::FdaMedicalDevice,
            Self::NistSsdf,
            Self::Eo14028,
            Self::Cnsa2,
            Self::NistPqc,
            Self::BsiTr03183_2,
            Self::CraOssSteward,
            Self::EuccSubstantial,
            Self::Comprehensive,
        ]
    }

    /// Whether this level is a CRA check. Includes the lighter Article 24
    /// open-source steward profile, since stewards still operate under the
    /// regulation (just with reduced obligations).
    #[must_use]
    pub const fn is_cra(&self) -> bool {
        matches!(
            self,
            Self::CraPhase1 | Self::CraPhase2 | Self::CraOssSteward
        )
    }

    /// Get CRA phase, if applicable
    #[must_use]
    pub const fn cra_phase(&self) -> Option<CraPhase> {
        match self {
            Self::CraPhase1 => Some(CraPhase::Phase1),
            Self::CraPhase2 => Some(CraPhase::Phase2),
            _ => None,
        }
    }
}

/// Identifies the source standard a `StandardRef` points at.
///
/// The CRA harmonised-standard ecosystem references multiple parallel
/// hierarchies (the regulation itself, the prEN 40000-1-3 horizontal
/// standard, BSI TR-03183 national guidance) and a violation typically
/// maps to several at once. Notified bodies will read prEN IDs; auditors
/// quote regulation articles; engineers prefer BSI sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StandardKind {
    /// EU CRA regulation article (e.g., "Art. 13(4)")
    CraArticle,
    /// EU CRA regulation annex (e.g., "Annex I Part II 1")
    CraAnnex,
    /// prEN 40000-1-3 normative requirement ID (e.g., "PRE-7-RQ-07")
    Pren40000_1_3,
    /// BSI TR-03183-2 section reference
    BsiTr03183_2,
    /// NIST SP 800-218 SSDF practice
    NistSsdf,
    /// US Executive Order 14028 Section 4
    Eo14028,
    /// FDA premarket cybersecurity guidance
    FdaPremarket,
    /// NTIA Minimum Elements for an SBOM
    NtiaMinimum,
    /// CSAF v2.0 / ISO/IEC 20153:2025 advisory format
    Csaf2,
    /// CNSA 2.0 (NSA Commercial National Security Algorithm Suite)
    Cnsa2,
    /// NIST Post-Quantum Cryptography (FIPS 203/204/205, SP 800-131A)
    NistPqc,
    /// Other / unrecognised standard
    Other,
}

impl StandardKind {
    /// Short label for compact display (≤16 chars).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CraArticle => "CRA Article",
            Self::CraAnnex => "CRA Annex",
            Self::Pren40000_1_3 => "prEN 40000-1-3",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::NistSsdf => "NIST SSDF",
            Self::Eo14028 => "EO 14028",
            Self::FdaPremarket => "FDA",
            Self::NtiaMinimum => "NTIA",
            Self::Csaf2 => "CSAF v2.0",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC",
            Self::Other => "Other",
        }
    }
}

/// A reference to a specific clause/requirement in a published standard.
///
/// Surfaced in JSON, SARIF, Markdown, and HTML output so that downstream
/// tooling (notified-body checklists, GRC platforms, internal dashboards)
/// can map a violation directly to the standards landscape without parsing
/// the human-readable `requirement` string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StandardRef {
    /// Which standard this reference points at
    pub standard: StandardKind,
    /// The clause/requirement ID within that standard (e.g., "PRE-7-RQ-07")
    pub id: String,
    /// Optional canonical URL anchor for the clause
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

impl StandardRef {
    /// Construct a `StandardRef` and auto-populate `help_uri` with a stable
    /// canonical URL for the standard, when one is known. Pass through
    /// `with_uri()` to override.
    #[must_use]
    pub fn new(standard: StandardKind, id: impl Into<String>) -> Self {
        let id = id.into();
        let help_uri = standard.canonical_help_uri(&id);
        Self {
            standard,
            id,
            help_uri,
        }
    }

    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.help_uri = Some(uri.into());
        self
    }
}

impl StandardKind {
    /// Stable canonical URL for the standard / regulation that hosts the
    /// referenced clause. Returns `None` for `Other` (no canonical home) and
    /// for `Pren40000_1_3` because the draft EN is paywalled and CEN's URLs
    /// are not stable; CRA-P5.1 will revisit once the standard is finalised.
    ///
    /// The returned URL is the *standard's* root, not a per-clause anchor —
    /// EUR-Lex and most national standards bodies do not publish stable
    /// per-article fragments. Per-article precision lives in the
    /// `StandardRef::id` (e.g., "Art. 13(4)") rather than the URL.
    #[must_use]
    pub fn canonical_help_uri(self, _id: &str) -> Option<String> {
        let url = match self {
            // CRA Regulation (EU) 2024/2847 — EUR-Lex ELI is the canonical home.
            Self::CraArticle | Self::CraAnnex => {
                "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng"
            }
            // prEN 40000-1-3 is in development; no stable public URL yet.
            Self::Pren40000_1_3 => return None,
            // BSI TR-03183-2 (English landing page).
            Self::BsiTr03183_2 => {
                "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html"
            }
            // NIST SP 800-218 SSDF — DOI is the most stable handle.
            Self::NistSsdf => "https://doi.org/10.6028/NIST.SP.800-218",
            // EO 14028 — Federal Register short-form.
            Self::Eo14028 => "https://www.federalregister.gov/d/2021-10460",
            // FDA premarket cybersecurity guidance.
            Self::FdaPremarket => {
                "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions"
            }
            // NTIA SBOM Minimum Elements report.
            Self::NtiaMinimum => {
                "https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf"
            }
            // CSAF v2.0 OASIS standard.
            Self::Csaf2 => "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
            // CNSA 2.0 fact sheet.
            Self::Cnsa2 => {
                "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            }
            // NIST PQC project landing page.
            Self::NistPqc => "https://csrc.nist.gov/projects/post-quantum-cryptography",
            Self::Other => return None,
        };
        Some(url.to_string())
    }
}

/// A compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Severity: error, warning, info
    pub severity: ViolationSeverity,
    /// Category of the violation
    pub category: ViolationCategory,
    /// Human-readable message
    pub message: String,
    /// Component or element that violated (if applicable)
    pub element: Option<String>,
    /// Standard/requirement being violated
    pub requirement: String,
    /// Stable internal rule key, set at the check site, indexing into
    /// [`rule_meta`]. This — not the human-readable message — drives the
    /// externally-visible SARIF rule ID, the harmonised-standard references,
    /// and the remediation text. Defaults to `"SBOM-CRA-GENERAL"` for
    /// violations built outside the checker (e.g., from external config).
    ///
    /// Skipped during (de)serialization: it is a `&'static str` runtime index,
    /// not part of the JSON contract. Round-tripped payloads resolve back to
    /// the default; `standard_refs` already carries the serialized references.
    #[serde(skip, default = "default_rule_id")]
    pub rule_id: &'static str,
    /// Structured references to harmonised-standard / regulation clauses.
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// via [`rule_meta`]. Empty when a violation's rule maps to no references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standard_refs: Vec<StandardRef>,
}

/// Serde default for [`Violation::rule_id`] when deserializing payloads that
/// predate the field.
fn default_rule_id() -> &'static str {
    "SBOM-CRA-GENERAL"
}

impl Violation {
    /// Structured standard references for this violation, looked up from the
    /// rule registry by [`Violation::rule_id`].
    ///
    /// References are returned in registry order — typically the most specific
    /// harmonised-standard ID first, then the regulation reference. The
    /// registry, not the human-readable `requirement` string, is the single
    /// source of truth, so rewording a message can never silently drop a
    /// prEN/BSI cross-reference.
    ///
    /// `ComplianceChecker::check()` calls this once and stores the result in
    /// `Violation::standard_refs`, so most consumers should read the field
    /// directly rather than re-deriving.
    #[must_use]
    pub fn registry_standard_refs(&self) -> Vec<StandardRef> {
        rule_meta(self.rule_id)
            .map(|m| {
                m.refs
                    .iter()
                    .map(|(kind, id)| StandardRef::new(*kind, *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remediation guidance for this violation, looked up from the rule
    /// registry by [`Violation::rule_id`].
    #[must_use]
    pub fn remediation_guidance(&self) -> &'static str {
        rule_meta(self.rule_id).map_or(REMEDIATION_GENERIC, |m| m.remediation)
    }
}

/// Severity of a compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Must be fixed for compliance
    Error,
    /// Should be fixed, but not strictly required
    Warning,
    /// Informational recommendation
    Info,
}

/// Category of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViolationCategory {
    /// Document metadata issue
    DocumentMetadata,
    /// Component identification issue
    ComponentIdentification,
    /// Dependency information issue
    DependencyInfo,
    /// License information issue
    LicenseInfo,
    /// Supplier information issue
    SupplierInfo,
    /// Hash/integrity issue
    IntegrityInfo,
    /// Security/vulnerability disclosure info
    SecurityInfo,
    /// Format-specific requirement
    FormatSpecific,
    /// Cryptographic algorithm/key/protocol issue
    CryptographyInfo,
}

impl ViolationCategory {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Document Metadata",
            Self::ComponentIdentification => "Component Identification",
            Self::DependencyInfo => "Dependency Information",
            Self::LicenseInfo => "License Information",
            Self::SupplierInfo => "Supplier Information",
            Self::IntegrityInfo => "Integrity Information",
            Self::SecurityInfo => "Security Information",
            Self::FormatSpecific => "Format-Specific",
            Self::CryptographyInfo => "Cryptography",
        }
    }

    /// Short name suitable for compact table display (max 10 chars).
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Doc Meta",
            Self::ComponentIdentification => "Comp IDs",
            Self::DependencyInfo => "Deps",
            Self::LicenseInfo => "License",
            Self::SupplierInfo => "Supplier",
            Self::IntegrityInfo => "Integrity",
            Self::SecurityInfo => "Security",
            Self::FormatSpecific => "Format",
            Self::CryptographyInfo => "Crypto",
        }
    }

    /// All category variants in display order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SupplierInfo,
            Self::ComponentIdentification,
            Self::DocumentMetadata,
            Self::IntegrityInfo,
            Self::LicenseInfo,
            Self::DependencyInfo,
            Self::SecurityInfo,
            Self::FormatSpecific,
            Self::CryptographyInfo,
        ]
    }
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Overall compliance status
    pub is_compliant: bool,
    /// Compliance level checked against
    pub level: ComplianceLevel,
    /// All violations found
    pub violations: Vec<Violation>,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
    /// Info count
    pub info_count: usize,
    /// CRA Annex VIII conformity-assessment summary (CRA-P4.3). Populated
    /// only when the level is a CRA profile *and* a product class has been
    /// pinned (explicitly or via sidecar). `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformity_summary: Option<ConformityAssessmentSummary>,
}

/// Per-route checklist of evidence the CRA Annex VIII conformity-assessment
/// procedure expects. Surfaced in markdown / HTML / SARIF / TUI reports so
/// notified bodies and auditors see the route + the missing evidence in
/// one glance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformityAssessmentSummary {
    /// CRA Annex III/IV product class
    pub product_class: crate::model::CraProductClass,
    /// Resolved Annex VIII conformity route
    pub route: crate::model::ConformityRoute,
    /// Per-evidence checklist entries (≥1 element)
    pub evidence: Vec<ConformityEvidence>,
}

/// One row of the conformity-evidence checklist. `satisfied = true` means
/// the SBOM (or sidecar) carries the expected reference; `false` means it
/// is missing and the manufacturer should attach it before submitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformityEvidence {
    /// Short label (e.g., "EU Declaration of Conformity")
    pub label: String,
    /// Longer description of the evidence
    pub detail: String,
    /// Whether the SBOM/sidecar already provides this evidence
    pub satisfied: bool,
}

impl ComplianceResult {
    /// Create a new compliance result
    #[must_use]
    pub fn new(level: ComplianceLevel, violations: Vec<Violation>) -> Self {
        let error_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count();
        let warning_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let info_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info)
            .count();

        Self {
            is_compliant: error_count == 0,
            level,
            violations,
            conformity_summary: None,
            error_count,
            warning_count,
            info_count,
        }
    }

    /// Get violations filtered by severity
    #[must_use]
    pub fn violations_by_severity(&self, severity: ViolationSeverity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Get violations filtered by category
    #[must_use]
    pub fn violations_by_category(&self, category: ViolationCategory) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.category == category)
            .collect()
    }
}

/// Calibration check identifiers for `ComplianceChecker::class_severity()`.
///
/// Each variant corresponds to a row in the CRA-P3.2 calibration table —
/// the severity that a given finding should produce *given* the product
/// class (Default → Critical) and conformity-assessment route. `None`
/// from `class_severity()` means "this check is not applicable for the
/// given class" (typically Default doesn't carry EUCC/attestation
/// expectations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassCheck {
    /// Vendor-supplied hash coverage below threshold ([PRE-7-RQ-07-RE]).
    VendorHashCoverage,
    /// EOL component present in SBOM.
    EolComponents,
    /// Dependency cycles detected.
    Cycles,
    /// Annex VII Declaration-of-Conformity reference missing.
    DocReference,
    /// EUCC (Common Criteria) reference missing.
    EuccReference,
    /// PSIRT URL / 24h / 72h / ENISA channel missing (Art. 14).
    Psirt,
    /// Conformity-assessment-module attestation reference missing
    /// (only meaningful on Module B+C / H / EUCC routes).
    ModuleAttestation,
}

/// Compliance checker for SBOMs
#[derive(Debug, Clone)]
pub struct ComplianceChecker {
    /// Compliance level to check
    level: ComplianceLevel,
    /// Optional CRA sidecar metadata that supplements the SBOM with
    /// manufacturer / disclosure / lifecycle fields the SBOM itself doesn't
    /// carry. When set, document-metadata checks consult the sidecar before
    /// emitting "missing" violations.
    sidecar: Option<crate::model::CraSidecarMetadata>,
    /// Optional CRA Annex III/IV product class. Drives severity calibration
    /// for `class_severity()` (vendor-hash, EOL, cycles, DoC, EUCC, PSIRT,
    /// attestation). When `None`, behaves as `CraProductClass::Default`.
    product_class: Option<crate::model::CraProductClass>,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    #[must_use]
    pub const fn new(level: ComplianceLevel) -> Self {
        Self {
            level,
            sidecar: None,
            product_class: None,
        }
    }

    /// Attach CRA sidecar metadata to supplement SBOM-level fields.
    ///
    /// Sidecar values are only consulted as fallbacks — fields present in the
    /// SBOM always take precedence. Used by `validate`, `quality`, and `view`
    /// CLIs via the `--cra-sidecar` flag (with auto-discovery for adjacent
    /// `<sbom>.cra.{json,yaml}` files).
    #[must_use]
    pub fn with_sidecar(mut self, sidecar: crate::model::CraSidecarMetadata) -> Self {
        self.sidecar = Some(sidecar);
        self
    }

    /// Set the CRA Annex III/IV product class explicitly.
    ///
    /// Sidecar `productClass` (when set on the attached sidecar) wins over
    /// this; resolve via [`Self::effective_product_class`].
    #[must_use]
    pub const fn with_product_class(mut self, class: crate::model::CraProductClass) -> Self {
        self.product_class = Some(class);
        self
    }

    /// Resolve the effective product class:
    /// 1. sidecar `productClass` if present,
    /// 2. otherwise `with_product_class` value,
    /// 3. otherwise `CraProductClass::Default`.
    #[must_use]
    pub fn effective_product_class(&self) -> crate::model::CraProductClass {
        self.sidecar
            .as_ref()
            .and_then(|s| s.product_class)
            .or(self.product_class)
            .unwrap_or(crate::model::CraProductClass::Default)
    }

    /// Resolve the effective conformity-assessment route. Falls back to
    /// `CraProductClass::default_route()` when the sidecar doesn't pin one.
    #[must_use]
    pub fn effective_route(&self) -> crate::model::ConformityRoute {
        self.sidecar
            .as_ref()
            .and_then(|s| s.conformity_assessment_route)
            .unwrap_or_else(|| self.effective_product_class().default_route())
    }

    /// CRA-P3.2 calibration table — severity for a given check at the
    /// effective product class. Returns `None` when the check does not
    /// apply for that class (e.g., EUCC reference at `Default`).
    #[must_use]
    pub fn class_severity(&self, check: ClassCheck) -> Option<ViolationSeverity> {
        use crate::model::CraProductClass as C;
        let class = self.effective_product_class();
        match (check, class) {
            // Vendor-hash coverage threshold escalation handled by
            // `vendor_hash_thresholds()`; this row reflects the *severity*
            // emitted when the threshold is breached.
            (ClassCheck::VendorHashCoverage, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::VendorHashCoverage, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EolComponents, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::EolComponents, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::Cycles, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::Cycles, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::DocReference, C::Default) => Some(ViolationSeverity::Info),
            (ClassCheck::DocReference, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::DocReference, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EuccReference, C::Default | C::ImportantClass1) => None,
            (ClassCheck::EuccReference, C::ImportantClass2) => Some(ViolationSeverity::Info),
            (ClassCheck::EuccReference, C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::Psirt, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::Psirt, C::ImportantClass2 | C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::ModuleAttestation, C::Default) => None,
            (ClassCheck::ModuleAttestation, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::ModuleAttestation, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }
        }
    }

    /// Vendor-hash coverage threshold (single-stage) below which a violation
    /// fires. The severity is `class_severity(VendorHashCoverage)`. Values:
    /// Default 50%, Important-1 80%, Important-2 80%, Critical 100%.
    #[must_use]
    pub fn vendor_hash_threshold(&self) -> f64 {
        use crate::model::CraProductClass as C;
        match self.effective_product_class() {
            C::Default => 0.50,
            C::ImportantClass1 | C::ImportantClass2 => 0.80,
            C::Critical => 1.00,
        }
    }

    /// Whether a CRA product class has been explicitly configured (either
    /// via `with_product_class()` or the attached sidecar). Used by the
    /// per-check calibration to decide whether to override phase-based
    /// defaults — when no class is set, existing phase-driven behavior is
    /// preserved verbatim for backwards compatibility.
    #[must_use]
    pub fn has_explicit_product_class(&self) -> bool {
        self.product_class.is_some()
            || self
                .sidecar
                .as_ref()
                .and_then(|s| s.product_class)
                .is_some()
    }

    /// Check an SBOM for compliance.
    ///
    /// Selects the [`StandardChecker`] for the configured level (the seven
    /// dedicated profiles get their own checker; the rest take the generic
    /// path), runs it, then back-fills harmonised-standard references from the
    /// rule registry and attaches the CRA Annex VIII conformity summary when a
    /// product class has been pinned on a CRA profile.
    #[must_use]
    pub fn check(&self, sbom: &NormalizedSbom) -> ComplianceResult {
        let ctx = ComplianceContext::new(self, sbom);
        let checker = checker_for(self.level);
        debug_assert_eq!(
            checker.level(),
            self.level,
            "dispatched checker must match the configured level"
        );
        let mut violations = checker.check(&ctx);

        // Populate harmonised-standard references from the rule registry.
        for v in &mut violations {
            if v.standard_refs.is_empty() {
                v.standard_refs = v.registry_standard_refs();
            }
        }

        let mut result = ComplianceResult::new(self.level, violations);
        // Attach the CRA Annex VIII conformity summary when a product class
        // has been pinned and the level is a CRA profile.
        if self.level.is_cra() && self.has_explicit_product_class() {
            result.conformity_summary = Some(self.build_conformity_summary(sbom));
        }
        result
    }
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new(ComplianceLevel::Standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_level_names() {
        assert_eq!(ComplianceLevel::Minimum.name(), "Minimum");
        assert_eq!(ComplianceLevel::NtiaMinimum.name(), "NTIA Minimum Elements");
        assert_eq!(ComplianceLevel::CraPhase1.name(), "EU CRA Phase 1 (2027)");
        assert_eq!(ComplianceLevel::CraPhase2.name(), "EU CRA Phase 2 (2029)");
        assert_eq!(ComplianceLevel::NistSsdf.name(), "NIST SSDF (SP 800-218)");
        assert_eq!(ComplianceLevel::Eo14028.name(), "EO 14028 Section 4");
    }

    #[test]
    fn test_nist_ssdf_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::NistSsdf);
        let result = checker.check(&sbom);
        // Empty SBOM should have at least a creator violation
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PS.1"))
        );
    }

    #[test]
    fn test_eo14028_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::Eo14028);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("EO 14028"))
        );
    }

    #[test]
    fn test_compliance_result_counts() {
        let violations = vec![
            Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: "Error 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            },
            Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: "Warning 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            },
            Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: "Info 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            },
        ];

        let result = ComplianceResult::new(ComplianceLevel::Standard, violations);
        assert!(!result.is_compliant);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.info_count, 1);
    }

    fn make_crypto_sbom(algos: &[(&str, &str, Option<&str>, Option<u8>)]) -> NormalizedSbom {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        };
        let mut sbom = NormalizedSbom::default();
        for (name, family, param, ql) in algos {
            let mut c = crate::model::Component::new(name.to_string(), format!("{name}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            let mut algo = AlgorithmProperties::new(CryptoPrimitive::Ae)
                .with_algorithm_family(family.to_string());
            if let Some(p) = param {
                algo = algo.with_parameter_set_identifier(p.to_string());
            }
            if let Some(level) = ql {
                algo = algo.with_nist_quantum_security_level(*level);
            }
            c.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(algo),
            );
            sbom.add_component(c);
        }
        sbom
    }

    #[test]
    fn test_cnsa2_aes128_violation() {
        let sbom = make_crypto_sbom(&[("AES-128-GCM", "AES", Some("128"), Some(1))]);
        let checker = ComplianceChecker::new(ComplianceLevel::Cnsa2);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.message.contains("AES-128")),
            "CNSA 2.0 should flag AES-128"
        );
    }

    #[test]
    fn test_cnsa2_mlkem1024_passes() {
        let sbom = make_crypto_sbom(&[("ML-KEM-1024", "ML-KEM", Some("1024"), Some(5))]);
        let checker = ComplianceChecker::new(ComplianceLevel::Cnsa2);
        let result = checker.check(&sbom);
        let algo_errors: Vec<_> = result
            .violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Error
                    && v.element.as_deref() == Some("ML-KEM-1024")
            })
            .collect();
        assert!(algo_errors.is_empty(), "ML-KEM-1024 should pass CNSA 2.0");
    }

    #[test]
    fn test_pqc_quantum_vulnerable() {
        let sbom = make_crypto_sbom(&[("RSA-2048", "RSA", None, Some(0))]);
        let checker = ComplianceChecker::new(ComplianceLevel::NistPqc);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error
                    && v.message.contains("quantum-vulnerable")),
            "PQC should flag RSA-2048 as quantum-vulnerable"
        );
    }

    #[test]
    fn test_pqc_approved_algorithm_info() {
        let sbom = make_crypto_sbom(&[("ML-DSA-65", "ML-DSA", Some("65"), Some(3))]);
        let checker = ComplianceChecker::new(ComplianceLevel::NistPqc);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Info && v.message.contains("approved")),
            "PQC should report ML-DSA-65 as approved"
        );
    }

    fn refs_for(rule_id: &'static str) -> Vec<StandardRef> {
        let v = Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id,
            standard_refs: Vec::new(),
        };
        v.registry_standard_refs()
    }

    #[test]
    fn registry_refs_for_art_13_4_include_article_and_pren() {
        let refs = refs_for("SBOM-CRA-ART-13-4");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraArticle && r.id == "Art. 13(4)"),
            "expected CRA Art. 13(4); got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-04"),
            "expected prEN PRE-7-RQ-04; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_annex_i_identifier_include_pren_07() {
        let refs = refs_for("SBOM-CRA-ANNEX-I-IDENTIFIER");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07"),
            "expected PRE-7-RQ-07; got {refs:?}"
        );
        let pren_count = refs
            .iter()
            .filter(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07")
            .count();
        assert_eq!(pren_count, 1, "PRE-7-RQ-07 should appear exactly once");
    }

    #[test]
    fn registry_refs_for_supply_chain_include_annex_and_pren() {
        let refs = refs_for("SBOM-CRA-ANNEX-I-SUPPLY-CHAIN");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part III"),
            "expected Annex I Part III; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-01"),
            "expected PRE-7-RQ-01; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-03"),
            "expected PRE-7-RQ-03; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_art_13_7_include_pren_rls() {
        let refs = refs_for("SBOM-CRA-ART-13-7");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "RLS-2-RQ-03-RE"),
            "expected RLS-2-RQ-03-RE; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_ssdf_ps2() {
        let refs = refs_for("SBOM-SSDF-PS2");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::NistSsdf && r.id == "PS.2"),
            "expected NIST SSDF PS.2; got {refs:?}"
        );
    }

    /// Exhaustive registry coverage: every rule key emitted by the checker
    /// across all compliance levels and a representative fixture set must
    /// resolve in [`rule_meta`] — no orphan rules.
    #[test]
    fn every_emitted_violation_has_a_registered_rule_id() {
        let sbom = NormalizedSbom::default();
        for level in ComplianceLevel::all() {
            let result = ComplianceChecker::new(*level).check(&sbom);
            for v in &result.violations {
                assert!(
                    rule_meta(v.rule_id).is_some(),
                    "level {level:?}: violation {:?} has unregistered rule_id {:?}",
                    v.requirement,
                    v.rule_id
                );
            }
        }
    }

    #[test]
    fn check_populates_standard_refs_for_cra_violations() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let result = checker.check(&sbom);
        let cra_violations: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.requirement.to_lowercase().contains("cra"))
            .collect();
        assert!(
            !cra_violations.is_empty(),
            "empty SBOM should produce some CRA violations"
        );
        for v in &cra_violations {
            assert!(
                !v.standard_refs.is_empty(),
                "CRA violation {:?} should have standard_refs populated",
                v.requirement
            );
        }
    }

    #[test]
    fn sidecar_supplies_security_contact_downgrades_art_13_6() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();

        // Without sidecar: Art. 13(6) is a Warning
        let bare = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let art_13_6_warning = bare.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(6)") && v.severity == ViolationSeverity::Warning
        });
        assert!(
            art_13_6_warning.is_some(),
            "Without sidecar, Art. 13(6) should be a Warning"
        );

        // With sidecar that supplies security_contact: same finding becomes Info
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@example.com".to_string()),
            ..Default::default()
        };
        let withsc = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let art_13_6_info = withsc.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(6)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            art_13_6_info.is_some(),
            "With sidecar, Art. 13(6) should be downgraded to Info"
        );
        assert!(
            !withsc
                .violations
                .iter()
                .any(|v| v.requirement.contains("Art. 13(6)")
                    && v.severity == ViolationSeverity::Warning),
            "With sidecar, no Warning-level Art. 13(6) violation should remain"
        );
    }

    #[test]
    fn sidecar_supplies_product_name_downgrades_art_13_12() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default(); // no document name

        let sidecar = CraSidecarMetadata {
            product_name: Some("Demo Product".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(12)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar product_name should downgrade Art. 13(12) to Info"
        );
    }

    #[test]
    fn sidecar_supplies_manufacturer_downgrades_art_13_15() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("Demo Corp".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(15)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar manufacturer_name should downgrade Art. 13(15) to Info"
        );
    }

    #[test]
    fn sidecar_supplies_cvd_url_downgrades_art_13_7() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            vulnerability_disclosure_url: Some("https://example.com/security".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(7)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar CVD URL should downgrade Art. 13(7) to Info"
        );
    }

    fn vendor_component(name: &str, with_hash: bool) -> crate::model::Component {
        use crate::model::{Component, Hash, HashAlgorithm, Organization};
        let mut c = Component::new(name.to_string(), name.to_string())
            .with_purl(format!("pkg:cargo/{name}@1.0.0"));
        c.supplier = Some(Organization::new("VendorCorp".to_string()));
        if with_hash {
            c.hashes.push(Hash::new(
                HashAlgorithm::Sha256,
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ));
        }
        c
    }

    fn hw_component(
        name: &str,
        kind: crate::model::ComponentType,
        with_purl: bool,
        with_supplier: bool,
        version: Option<&str>,
    ) -> crate::model::Component {
        use crate::model::{Component, Organization};
        let mut c = Component::new(name.to_string(), name.to_string());
        c.component_type = kind;
        if with_purl {
            c = c.with_purl(format!("pkg:generic/{name}"));
        }
        if with_supplier {
            c.supplier = Some(Organization::new("HardwareCorp".to_string()));
        }
        if let Some(v) = version {
            c = c.with_version(v.to_string());
        }
        c
    }

    #[test]
    fn hardware_check_skipped_for_software_only_sbom() {
        let mut sbom = NormalizedSbom::default();
        let c = vendor_component("software", true);
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-8-RQ-02")),
            "Software-only SBOM should produce no PRE-8-RQ-02 violations"
        );
    }

    #[test]
    fn hardware_check_passes_for_complete_firmware() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component(
            "router-fw",
            ComponentType::Firmware,
            true,
            true,
            Some("1.2.3"),
        );
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-8-RQ-02")),
            "Complete firmware component should pass [PRE-8-RQ-02]"
        );
    }

    #[test]
    fn hardware_check_flags_firmware_without_version() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component("router-fw", ComponentType::Firmware, true, true, None);
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Firmware version") && v.severity == ViolationSeverity::Error
            }),
            "Firmware without version should produce an Error"
        );
    }

    #[test]
    fn hardware_check_flags_missing_producer() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component("router", ComponentType::Device, true, false, Some("1.0"));
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Hardware producer")
                    && v.severity == ViolationSeverity::Error
            }),
            "Hardware without producer should produce an Error"
        );
    }

    #[test]
    fn hardware_check_flags_synthetic_identifier() {
        use crate::model::{Component, ComponentType, Organization};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("router".to_string(), "router".to_string())
            .with_version("1.0".to_string());
        c.component_type = ComponentType::Device;
        c.supplier = Some(Organization::new("HardwareCorp".to_string()));
        // Note: no PURL/CPE/SWHID/SWID → falls back to synthetic
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Hardware identifier")
                    && v.severity == ViolationSeverity::Error
            }),
            "Hardware with synthetic ID should produce an Error"
        );
    }

    #[test]
    fn hardware_check_device_with_firmware_dep_passes() {
        use crate::model::{ComponentType, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        let device = hw_component("router", ComponentType::Device, true, true, None);
        let firmware = hw_component(
            "router-fw",
            ComponentType::Firmware,
            true,
            true,
            Some("1.2.3"),
        );
        let device_id = device.canonical_id.clone();
        let firmware_id = firmware.canonical_id.clone();
        sbom.components.insert(device_id.clone(), device);
        sbom.components.insert(firmware_id.clone(), firmware);
        sbom.edges.push(DependencyEdge::new(
            device_id,
            firmware_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| { v.requirement.contains("Device firmware association") }),
            "Device with firmware dependency should not trigger version warning"
        );
    }

    #[test]
    fn vendor_hash_coverage_full() {
        use crate::quality::HashQualityMetrics;
        let mut sbom = NormalizedSbom::default();
        for n in ["a", "b", "c", "d", "e"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let m = HashQualityMetrics::from_sbom(&sbom);
        assert_eq!(m.vendor_components_total, 5);
        assert_eq!(m.vendor_components_with_hash, 5);
        assert_eq!(m.vendor_hash_coverage(), Some(1.0));
    }

    #[test]
    fn vendor_hash_coverage_partial_triggers_warning() {
        let mut sbom = NormalizedSbom::default();
        // 7 with hashes, 3 without → 70% < 80% → Warning under CraPhase2
        for n in ["a", "b", "c", "d", "e", "f", "g"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        for n in ["h", "i", "j"] {
            let c = vendor_component(n, false);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Warning
        });
        assert!(
            v.is_some(),
            "70% vendor-hash coverage should produce a Warning under CraPhase2"
        );
    }

    #[test]
    fn vendor_hash_coverage_below_50_triggers_error() {
        let mut sbom = NormalizedSbom::default();
        // 4 with hashes, 6 without → 40% < 50% → Error under CraPhase2
        for n in ["a", "b", "c", "d"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        for n in ["e", "f", "g", "h", "i", "j"] {
            let c = vendor_component(n, false);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "40% vendor-hash coverage should produce an Error under CraPhase2"
        );
    }

    #[test]
    fn vendor_hash_coverage_no_vendor_components_no_violation() {
        // SBOM with only synthetic-ID components — no vendor classification, no violation
        let mut sbom = NormalizedSbom::default();
        use crate::model::Component;
        for n in ["a", "b", "c"] {
            let c = Component::new(n.to_string(), n.to_string());
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
            "No vendor components → no [PRE-7-RQ-07-RE] violation"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // P2 tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn art_13_2_warns_when_no_risk_assessment_referenced() {
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(2)") && v.severity == ViolationSeverity::Warning
        });
        assert!(v.is_some(), "Empty SBOM should produce Art. 13(2) Warning");
    }

    #[test]
    fn art_13_2_silenced_by_sidecar_risk_assessment_url() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            risk_assessment_url: Some("https://example.com/ra.pdf".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("Art. 13(2)")),
            "Sidecar risk_assessment_url should suppress Art. 13(2) violation"
        );
    }

    #[test]
    fn article_14_pre_deadline_emits_info_only() {
        // The check uses the wall clock; today's date in tests will be
        // before/after 2026-09-11 depending on when tests run. We assert
        // the *existence* of the readiness violations rather than exact
        // severity, then verify with-sidecar suppresses.
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let art14_count = result
            .violations
            .iter()
            .filter(|v| v.requirement.contains("Art. 14"))
            .count();
        assert!(
            art14_count >= 4,
            "Art. 14 readiness should produce ≥4 violations (PSIRT, 14(1), 14(2), 14(7)); got {art14_count}"
        );
    }

    /// Pre-deadline (mocked clock 2026-04-26): all four channels missing.
    /// PSIRT/14(1)/14(2) surface as Info; 14(7) (ENISA platform) is always Info.
    /// Total: 4 Infos, 0 Warnings, 0 Errors at Art. 14 level.
    #[test]
    fn article_14_pre_deadline_mocked_clock_emits_4_infos() {
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let mut violations = Vec::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-26T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        checker.check_article_14_readiness_at(now, &mut violations);

        let infos = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
            .count();
        let warnings = violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14")
            })
            .count();
        assert_eq!(
            infos, 4,
            "Pre-deadline expects 4 Info-level Art. 14 findings; got {infos} (full list: {violations:?})"
        );
        assert_eq!(
            warnings, 0,
            "Pre-deadline expects 0 Warning-level Art. 14 findings"
        );
    }

    /// Post-deadline (mocked clock 2026-12-01): same SBOM-less state, but
    /// PSIRT/14(1)/14(2) become Warnings; 14(7) stays Info.
    /// Total: 1 Info, 3 Warnings.
    #[test]
    fn article_14_post_deadline_mocked_clock_emits_3_warnings_1_info() {
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let mut violations = Vec::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        checker.check_article_14_readiness_at(now, &mut violations);

        let infos = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
            .count();
        let warnings = violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14")
            })
            .count();
        assert_eq!(
            warnings, 3,
            "Post-deadline expects 3 Warning-level Art. 14 findings (PSIRT/14(1)/14(2)); got {warnings} (full: {violations:?})"
        );
        assert_eq!(
            infos, 1,
            "Post-deadline expects 1 Info-level Art. 14 finding (Art. 14(7) ENISA platform stays Info regardless of date)"
        );
    }

    #[test]
    fn article_14_sidecar_suppresses_psirt_warning() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            psirt_url: Some("https://example.com/psirt".to_string()),
            early_warning_contact: Some("psirt@example.com".to_string()),
            incident_report_contact: Some("ir@example.com".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // PSIRT, 14(1), 14(2) suppressed; 14(7) (ENISA platform) remains as Info.
        let art_14_psirt = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14: PSIRT"));
        let art_14_1 = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14(1)"));
        let art_14_2 = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14(2)"));
        assert!(
            !art_14_psirt,
            "Sidecar psirt_url should suppress PSIRT check"
        );
        assert!(
            !art_14_1,
            "Sidecar early_warning_contact should suppress 14(1)"
        );
        assert!(
            !art_14_2,
            "Sidecar incident_report_contact should suppress 14(2)"
        );
    }

    #[test]
    fn direct_dep_missing_supplier_is_error_under_cra_phase2() {
        use crate::model::{Component, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        // Primary "app" with one direct dep "lib" missing supplier.
        let app = Component::new("app".to_string(), "app".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        let lib = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.edges.push(DependencyEdge::new(
            app_id,
            lib_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("Direct dependency supplier")
                && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "Direct dep without supplier should produce an Error under CraPhase2"
        );
    }

    #[test]
    fn transitive_dep_missing_supplier_is_softer_than_direct() {
        use crate::model::{Component, DependencyEdge, DependencyType, Organization};
        let mut sbom = NormalizedSbom::default();
        // app → lib (with supplier) → deep (no supplier)
        let mut app = Component::new("app".to_string(), "app".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        app.supplier = Some(Organization::new("AppCorp".to_string()));
        let mut lib = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        lib.supplier = Some(Organization::new("LibCorp".to_string()));
        let deep = Component::new("deep".to_string(), "deep".to_string())
            .with_purl("pkg:cargo/deep@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        let deep_id = deep.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.components.insert(deep_id.clone(), deep);
        sbom.edges.push(DependencyEdge::new(
            app_id,
            lib_id.clone(),
            DependencyType::DependsOn,
        ));
        sbom.edges.push(DependencyEdge::new(
            lib_id,
            deep_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let direct_err = result.violations.iter().any(|v| {
            v.requirement.contains("Direct dependency supplier")
                && v.severity == ViolationSeverity::Error
        });
        let transitive = result
            .violations
            .iter()
            .find(|v| v.requirement.contains("Transitive dependency supplier"));
        assert!(
            !direct_err,
            "No direct deps lack a supplier; should not error"
        );
        assert!(transitive.is_some(), "Transitive dep should be reported");
        assert_ne!(
            transitive.unwrap().severity,
            ViolationSeverity::Error,
            "Transitive supplier missing should never be Error (it's recommended, not mandatory)"
        );
    }

    #[test]
    fn bsi_tr_03183_2_empty_sbom_emits_errors() {
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("BSI TR-03183-2 §5.1")
                    && v.severity == ViolationSeverity::Error),
            "Empty SBOM should fail BSI §5.1"
        );
    }

    #[test]
    fn bsi_tr_03183_2_flags_missing_strong_hash() {
        use crate::model::{Component, Hash, HashAlgorithm};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        // Add only a weak hash
        c.hashes.push(Hash::new(HashAlgorithm::Md5, "0".repeat(32)));
        sbom.add_component(c);
        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("BSI TR-03183-2 §5.4")
                    && v.severity == ViolationSeverity::Error
            }),
            "Component without SHA-256+ hash should fail BSI §5.4"
        );
    }

    #[test]
    fn bsi_tr_03183_2_passes_for_complete_component() {
        use crate::model::{
            Component, Creator, CreatorType, DependencyEdge, DependencyType, Hash, HashAlgorithm,
            LicenseExpression, Organization,
        };
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "sbom-tools".to_string(),
            email: None,
        });
        let mut a = Component::new("a".to_string(), "a".to_string())
            .with_purl("pkg:cargo/a@1.0".to_string())
            .with_version("1.0".to_string());
        a.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "f".repeat(64)));
        a.supplier = Some(Organization::new("SupplierA".to_string()));
        a.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        let mut b = Component::new("b".to_string(), "b".to_string())
            .with_purl("pkg:cargo/b@1.0".to_string())
            .with_version("1.0".to_string());
        b.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "0".repeat(64)));
        b.supplier = Some(Organization::new("SupplierB".to_string()));
        b.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        sbom.components.insert(a_id.clone(), a);
        sbom.components.insert(b_id.clone(), b);
        sbom.edges
            .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));

        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        let errors: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "Complete BSI-compliant SBOM should produce no Errors; got: {errors:?}"
        );
    }

    #[test]
    fn bsi_tr_03183_2_in_compliance_level_all() {
        assert_eq!(ComplianceLevel::all().len(), 14);
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::BsiTr03183_2));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::CraOssSteward));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::EuccSubstantial));
    }

    #[test]
    fn sidecar_does_not_override_present_sbom_field() {
        use crate::model::{CraSidecarMetadata, Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "SbomDeclaredCorp".to_string(),
            email: None,
        });
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("SidecarCorp".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // No Art. 13(15) violation at all because SBOM provides org
        assert!(
            !result.violations.iter().any(|v| v
                .requirement
                .contains("Art. 13(15): Manufacturer identification")),
            "When SBOM provides manufacturer, no Art. 13(15) violation should be emitted"
        );
    }
}
