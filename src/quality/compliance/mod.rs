//! SBOM Compliance checking module.
//!
//! Validates SBOMs against format requirements and industry standards.
//!
//! The public surface ([`ComplianceChecker`], [`ComplianceLevel`],
//! [`ComplianceResult`], [`Violation`], [`PassedCheck`], the rule registry,
//! …) lives here; the per-standard check logic is split across sibling
//! submodules and dispatched through the [`StandardChecker`] trait in
//! [`context`].

use crate::model::{NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

// `pub(crate)` so the AI-readiness scorer (quality/scorer.rs) shares the exact
// ML-component applicability semantics of the AI compliance profiles instead
// of re-deriving them (and drifting, as the type-only filter once did).
pub(crate) mod ai_shared;
mod bsi;
mod bsi_sbom_for_ai;
mod catalog;
mod cisa2026;
mod context;
mod cra;
mod crypto;
mod eo14028;
mod eu_ai_act;
mod eucc;
mod finding;
mod fsct;
mod generic;
mod pci_dss;
mod pqc_calendar;
mod registry;
mod rule_settings;
mod run_config;
mod selector;
mod shared;
mod ssdf;

pub(crate) use catalog::rule_family_help_uri;
pub use catalog::{
    RuleAdvice, RuleCatalogEntry, RuleCatalogFilter, RuleFormatAdvice, RuleReference, rule_catalog,
    rule_catalog_entry,
};
use context::{ComplianceContext, Findings, NotEvaluated, checker_for};
pub(crate) use finding::compose_finding_key;
pub use finding::{
    DOCUMENT_SUBJECT, FINDING_ID_PREFIX, FindingIdentity, finding_fingerprint, finding_id,
    finding_key, finding_subject, standard_key,
};
use pqc_calendar::Calendar;
pub use pqc_calendar::{CnsaCategory, Deadline, PqcMode, PqcProfile};
pub use registry::resolve_rule_id;
pub use registry::{
    CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, EO14028_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS,
    FSCT_SARIF_RULE_IDS, FieldAdvice, FormatAdvice, NTIA_SARIF_RULE_IDS, PASS_RULE_IDS,
    PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, RemediationFormat, RuleKind, RuleMeta,
    SSDF_SARIF_RULE_IDS, all_rule_ids, rule_kind, rule_meta, rules_for_level,
};
use registry::{REMEDIATION_UNREGISTERED, lookup_static_rule_id};
pub use rule_settings::{
    RuleSetting, RuleSettings, SettingSource, SeverityOverride, SuppressedRule,
};
pub use run_config::ComplianceRunConfig;
pub use selector::StandardSelector;
// The vendor-hash metric behind SBOM-CRA-PRE-7-RQ-07-RE
// (quality/metrics.rs) classifies vendor components with the same
// sentinel-aware producer test the checks use.
pub(crate) use shared::has_known_producer;
// The same metric counts only plausible digests, as every hash rule does.
pub(crate) use shared::plausible_digest;
// The `cra-docs` dossier names the manufacturer the Art. 13(16) check
// accepts.
#[cfg(feature = "cli")]
pub(crate) use shared::manufacturer_name;
use shared::{
    SPDX2_NO_SIGNATURE, SPEC_VERSION_UNPARSED, ValueState, creator_contacts, creator_identified,
    digest_problems, document_signed, future_timestamp_violation, has_known_license,
    has_known_value, invalid_digest_note, is_contact_reference, is_declared_unknown,
    is_eucc_reference, is_placeholder, is_spdx2, is_valid_email_format, justified_not_affected,
    known_component_name, known_contact, known_value, license_state, manufacturer_identified,
    manufacturer_reference, name_with_digest_problems, observed, observed_digest,
    observed_producer, observed_unparsed_timestamp, truncate_list, unparseable_timestamp,
    unreachable_contact, unreachable_contact_note, unreachable_creator, unreachable_creator_note,
    unreachable_sidecar_note, value_state,
};

/// CRA enforcement phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CraPhase {
    /// Phase 1: Article 14 reporting obligations — apply from 11 September 2026
    /// (Reg. (EU) 2024/2847 Art. 71(2)). Basic SBOM requirements:
    /// product/component identification, manufacturer, version, format
    Phase1,
    /// Phase 2: full application of the regulation — from 11 December 2027
    /// (Art. 71(2)). Adds: vulnerability metadata, lifecycle/end-of-support,
    /// disclosure policy, EU `DoC`
    Phase2,
}

impl CraPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Phase1 => "Phase 1 (2026)",
            Self::Phase2 => "Phase 2 (2027)",
        }
    }

    pub const fn deadline(self) -> &'static str {
        match self {
            Self::Phase1 => "11 September 2026",
            Self::Phase2 => "11 December 2027",
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
    /// EU CRA Phase 1 — Art. 14 reporting obligations (apply from 11 Sep 2026)
    CraPhase1,
    /// EU CRA Phase 2 — full application of the regulation (from 11 Dec 2027)
    CraPhase2,
    /// FDA Medical Device SBOM requirements
    FdaMedicalDevice,
    /// NIST SP 800-218 Secure Software Development Framework
    NistSsdf,
    /// Executive Order 14028 Section 4 — Enhancing Software Supply Chain Security
    Eo14028,
    /// NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0,
    /// which CNSSP 15 requires for US national security systems
    Cnsa2,
    /// NIST PQC Readiness — Post-Quantum Cryptography migration (IR 8547 + FIPS 203/204/205)
    NistPqc,
    /// BSI TR-03183-2 v2.1.0 (German national CRA-aligned SBOM technical
    /// guideline, 2025-08-20). Free, ENISA-cited; stricter than NTIA on
    /// eligible formats (CycloneDX 1.6+ / SPDX 3.0.1+) and hashes (SHA-512).
    BsiTr03183_2,
    /// CRA Article 24 — Open-source software steward profile (lighter
    /// obligations than CraPhase1/2). SBOM, vulnerability handling process,
    /// and CVD policy are still required; manufacturer email, EU DoC, and
    /// conformity-assessment-module gating are NOT.
    CraOssSteward,
    /// EUCC Substantial assurance level (Implementing Regulation (EU)
    /// 2024/482, as amended by Implementing Regulations (EU) 2024/3144 and
    /// 2025/2462) — reference-only profile for Annex IV products. Verifies that the SBOM/sidecar carries
    /// a Common-Criteria Protection-Profile reference, Target-of-Evaluation
    /// reference, ITSEF identifier, and a valid-until date. Does not perform
    /// a Common-Criteria evaluation itself.
    EuccSubstantial,
    /// EU AI Act (Regulation (EU) 2024/1689, as amended by Regulation (EU)
    /// 2026/1744) Annex IV technical-documentation READINESS. Maps the Annex IV documentation obligations for high-risk AI
    /// systems onto the AI-BOM metadata sbom-tools already parses (model card,
    /// training-data characteristics, validation/testing metrics, limitations,
    /// energy disclosure). This is a documentation-readiness assessment, not a
    /// legal-conformity guarantee, and does not classify a system as high-risk.
    /// Returns N/A for SBOMs with no ML-model or dataset metadata.
    EuAiAct,
    /// BSI/G7 "SBOM for AI — Minimum Elements" (final joint G7 guidance, May 2026)
    /// READINESS. Scores an
    /// AI-BOM element-by-element against the seven clusters (Metadata,
    /// System-Level, Models, Datasets, Infrastructure, Security, plus the
    /// document-author elements) of the BSI/G7 minimum-elements guidance, using
    /// the AI-BOM metadata sbom-tools already parses (model card, training-data
    /// characteristics, weight hashes with NIST-approved algorithms, dataset
    /// provenance). This is a minimum-elements *readiness* assessment, not a
    /// legal-conformity guarantee. Returns N/A for SBOMs with no ML-model or
    /// dataset metadata.
    BsiSbomForAi,
    /// "2026 Minimum Elements for a Software Bill of Materials (SBOM)" v2.1
    /// (CISA/NSA/FBI + 15 international partners, July 29, 2026) — the
    /// finalized successor to the NTIA 2021 Minimum Elements. Adds SBOM
    /// author signature, generation context, tool name/version, SBOM
    /// version, component hashes + algorithms, and licenses to the 2021
    /// data-field floor; renames Supplier Name to Component Producer.
    /// Non-binding joint guidance (it creates no regulatory requirements).
    Cisa2026,
    /// PCI DSS v4.0.1 Requirement 6.3.2 — inventory of bespoke and custom
    /// software and incorporated third-party components, maintained to
    /// facilitate vulnerability and patch management (required in
    /// assessments since 31 March 2025). PCI DSS prescribes no SBOM format;
    /// a parseable CycloneDX/SPDX document is the industry-consensus
    /// evidence, so no format gate applies. Companion controls 6.3.1 and
    /// 11.3.1.1 are covered where the SBOM embeds vulnerability data.
    PciDss632,
    /// CISA "Framing Software Component Transparency: Establishing a Common
    /// Software Bill of Materials (SBOM)", Third Edition (2024-09-03,
    /// published 2024-10-15). Community-consensus baseline-attribute
    /// guidance with three maturity tiers mapped onto severities:
    /// Minimum Expected → Error, Recommended Practice → Warning,
    /// Aspirational Goal → Info. Non-regulatory; Error here means "fails
    /// the Minimum Expected tier", not a legal violation.
    Fsct,
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
            Self::CraPhase1 => "EU CRA Phase 1 (2026)",
            Self::CraPhase2 => "EU CRA Phase 2 (2027)",
            Self::FdaMedicalDevice => "FDA Medical Device",
            Self::NistSsdf => "NIST SSDF (SP 800-218)",
            Self::Eo14028 => "EO 14028 Section 4",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC Readiness",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::CraOssSteward => "CRA OSS Steward (Art. 24)",
            Self::EuccSubstantial => "EUCC Substantial (Reg. 2024/482)",
            Self::EuAiAct => "EU AI Act Annex IV Readiness",
            Self::BsiSbomForAi => "BSI/G7 SBOM-for-AI Minimum Elements Readiness",
            Self::Cisa2026 => "CISA 2026 Minimum Elements",
            Self::PciDss632 => "PCI DSS v4.0.1 Req. 6.3.2",
            Self::Fsct => "CISA Framing Software Component Transparency (3rd ed.)",
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
            Self::EuAiAct => "AI-Act",
            Self::BsiSbomForAi => "BSI-AI",
            Self::Cisa2026 => "CISA26",
            Self::PciDss632 => "PCI",
            Self::Fsct => "FSCT",
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
                "CRA reporting obligations — product ID, SBOM format, manufacturer (Art. 14 applies from 11 Sep 2026)"
            }
            Self::CraPhase2 => {
                "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (regulation fully applies from 11 Dec 2027)"
            }
            Self::FdaMedicalDevice => "FDA premarket submission requirements for medical devices",
            Self::NistSsdf => {
                "Secure Software Development Framework — provenance, build integrity, VCS references"
            }
            Self::Eo14028 => {
                "Executive Order 14028 §4 SBOM practice (not a federal mandate since OMB M-26-05 rescinded M-22-18 and M-23-16) — machine-readable SBOM, auto-generation, supply chain security"
            }
            Self::Cnsa2 => {
                "CNSA 2.0 (required by CNSSP 15) — AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87, quantum security level 5"
            }
            Self::NistPqc => {
                "NIST PQC — quantum-vulnerable algorithm detection, FIPS 203/204/205, SP 800-131A"
            }
            Self::BsiTr03183_2 => {
                "BSI TR-03183-2 v2.1.0 — German national SBOM guideline (free, ENISA-cited): CycloneDX 1.6+/SPDX 3.0.1+ formats, required creator/timestamp, per-component version/licences/SHA-512 hash"
            }
            Self::CraOssSteward => {
                "CRA Article 24 — Open-source software steward (lighter than full manufacturer obligations): SBOM + CVD policy + vuln-handling required, no DoC/module/manufacturer-email enforcement"
            }
            Self::EuccSubstantial => {
                "EUCC Substantial (Implementing Reg. (EU) 2024/482, as amended by 2024/3144 and 2025/2462) — reference-only check for Common-Criteria Protection Profile, Target of Evaluation, ITSEF, and certificate valid-until date"
            }
            Self::EuAiAct => {
                "EU AI Act (Reg. (EU) 2024/1689, as amended by Reg. (EU) 2026/1744) Annex IV technical-documentation READINESS — model description, training-data characteristics, validation/testing metrics, limitations (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)"
            }
            Self::BsiSbomForAi => {
                "BSI/G7 SBOM-for-AI Minimum Elements (joint G7 final, May 2026) READINESS — scores an AI-BOM element-by-element across the Metadata, System-Level, Models, Datasets, Infrastructure, and Security clusters (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)"
            }
            Self::Cisa2026 => {
                "2026 Minimum Elements for an SBOM (CISA et al., July 2026) — successor to NTIA 2021: author (person/org), signature, format name+version, generation context, timestamp, tool name+version, SBOM version, and per-component producer/name/version/identifiers/hash/license/dependencies. Frequency, distribution, and update accommodation are organizational practices with no in-document evidence and carry no rules."
            }
            Self::PciDss632 => {
                "PCI DSS v4.0.1 Req. 6.3.2 software-inventory profile (required in assessments since 31 Mar 2025) — inventory completeness, per-component name/version/supplier/identifier, freshness, and vulnerability-management usability; 6.3.1/11.3.1.1 risk-ranking checks where vulnerability data is embedded. Assessor-side testing procedures (interviews, software comparison) are out of document reach."
            }
            Self::Fsct => {
                "CISA Framing Software Component Transparency, 3rd ed. (2024) — baseline attributes (author, timestamp, primary component, name, version, supplier, identifiers, hashes, relationships, licenses, copyright) across the Minimum Expected (Error) / Recommended Practice (Warning) / Aspirational Goal (Info) maturity tiers"
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
            Self::EuAiAct,
            Self::BsiSbomForAi,
            Self::Cisa2026,
            Self::PciDss632,
            Self::Fsct,
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
    /// EU CRA regulation article (e.g., "Art. 13(8)")
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
    /// CNSA 2.0 (NSA Commercial National Security Algorithm Suite), which
    /// CNSSP 15 requires for US national security systems
    Cnsa2,
    /// NIST Post-Quantum Cryptography (FIPS 203/204/205, SP 800-131A)
    NistPqc,
    /// EU AI Act (Regulation (EU) 2024/1689, as amended by Regulation (EU)
    /// 2026/1744) — Annex IV technical documentation
    EuAiAct,
    /// BSI/G7 "SBOM for AI — Minimum Elements" (joint G7 final, May 2026)
    BsiSbomForAi,
    /// EUCC — European cybersecurity certification scheme on Common Criteria,
    /// Implementing Regulation (EU) 2024/482 as amended by Implementing
    /// Regulations (EU) 2024/3144 and 2025/2462 (consolidated text of
    /// 2025-12-29)
    Eucc,
    /// "2026 Minimum Elements for a Software Bill of Materials (SBOM)" v2.1
    /// (CISA/NSA/FBI et al., July 29, 2026)
    CisaMinimum2026,
    /// PCI DSS v4.0.1 (PCI Security Standards Council) — Requirement 6.3.2
    /// and companion controls
    PciDss4,
    /// CISA "Framing Software Component Transparency", Third Edition (2024)
    CisaFsct,
    /// "ENISA Technical Advisory for Software Bill of Materials", v1.10
    /// (2026-10-22). Non-binding guidance; cited on the CRA SBOM-content
    /// rules it gives guidance for.
    EnisaSbomAdvisory,
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
            Self::EuAiAct => "EU AI Act",
            Self::BsiSbomForAi => "BSI/G7 AI-SBOM",
            Self::Eucc => "EUCC",
            Self::CisaMinimum2026 => "CISA 2026",
            Self::PciDss4 => "PCI DSS v4",
            Self::CisaFsct => "CISA FSCT 3e",
            Self::EnisaSbomAdvisory => "ENISA SBOM TA",
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
#[non_exhaustive]
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
    /// `StandardRef::id` (e.g., "Art. 13(8)") rather than the URL.
    #[must_use]
    pub fn canonical_help_uri(self, _id: &str) -> Option<String> {
        let url = match self {
            // CRA Regulation (EU) 2024/2847 — EUR-Lex ELI is the canonical home.
            Self::CraArticle | Self::CraAnnex => {
                "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng"
            }
            // prEN 40000-1-3 is in development; no stable public URL yet.
            Self::Pren40000_1_3 => return None,
            // BSI TR-03183 (BSI's stable English shortlink, printed in the
            // v2.1.0 document imprint).
            Self::BsiTr03183_2 => "https://bsi.bund.de/dok/TR-03183-en",
            // NIST SP 800-218 SSDF — DOI is the most stable handle.
            Self::NistSsdf => "https://doi.org/10.6028/NIST.SP.800-218",
            // EO 14028 — Federal Register short-form.
            Self::Eo14028 => "https://www.federalregister.gov/d/2021-10460",
            // FDA premarket cybersecurity guidance — current edition is
            // "Cybersecurity in Medical Devices: Quality Management System
            // Considerations and Content of Premarket Submissions" (final,
            // 2026-02-03); FDA's media id is the stable handle.
            Self::FdaPremarket => "https://www.fda.gov/media/119933/download",
            // NTIA SBOM Minimum Elements report (canonical host is ntia.gov;
            // the old ntia.doc.gov URLs only survive via redirect).
            Self::NtiaMinimum => {
                "https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom"
            }
            // CSAF v2.0 OASIS standard.
            Self::Csaf2 => "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
            // CNSA 2.0 fact sheet (NSA Cybersecurity Advisory), the list of
            // algorithms the checks apply. CNSSP 15, which requires the
            // suite, is cited in the reference id.
            Self::Cnsa2 => {
                "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            }
            // NIST PQC project landing page.
            Self::NistPqc => "https://csrc.nist.gov/projects/post-quantum-cryptography",
            // EU AI Act Regulation (EU) 2024/1689 — EUR-Lex ELI is the
            // canonical home; its page links the text as amended by
            // Regulation (EU) 2026/1744.
            Self::EuAiAct => "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng",
            // BSI/G7 "SBOM for AI — Minimum Elements" — final joint G7
            // guidance (2026-05-12); CISA hosts the stable resource page.
            Self::BsiSbomForAi => {
                "https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements"
            }
            // EUCC Implementing Regulation (EU) 2024/482 — EUR-Lex ELI is the
            // canonical home; its page links the consolidated text with the
            // amendments of Implementing Regulations (EU) 2024/3144 and
            // 2025/2462.
            Self::Eucc => "https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng",
            // 2026 Minimum Elements for an SBOM — CISA's resource page is the
            // stable handle (the PDF path under /sites/default/files churns).
            Self::CisaMinimum2026 => {
                "https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom"
            }
            // PCI DSS v4.0.1 — the standard PDF is license-gated behind a
            // click-through; the document library is the stable public home.
            Self::PciDss4 => "https://www.pcisecuritystandards.org/document_library/",
            // CISA Framing Software Component Transparency (3rd ed., 2024) —
            // resource page rather than the version-pinned PDF path.
            Self::CisaFsct => {
                "https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024"
            }
            // ENISA Technical Advisory for SBOM — the publication page, which
            // serves the current version's PDF.
            Self::EnisaSbomAdvisory => {
                "https://www.enisa.europa.eu/publications/enisa-technical-advisory-for-software-bill-of-materials"
            }
            Self::Other => return None,
        };
        Some(url.to_string())
    }
}

/// A compliance violation
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Violation {
    /// Severity: error, warning, info. The one the run's rule settings give
    /// the finding's rule, if they set it (see
    /// [`Violation::severity_override`]).
    pub severity: ViolationSeverity,
    /// When the run's rule settings set the finding's rule (`--rule`, the
    /// config file's `compliance.rules`): the severity the check gave the
    /// finding and where the setting comes from. `None` for a rule the run
    /// does not set.
    ///
    /// Serialized as `default_severity` and `severity_source`, both omitted
    /// when `None`; old payloads without them deserialize to `None`.
    pub severity_override: Option<SeverityOverride>,
    /// Category of the violation
    pub category: ViolationCategory,
    /// Human-readable message
    pub message: String,
    /// Component or element that violated (if applicable).
    ///
    /// This is a human-readable *label* (usually the component name, sometimes
    /// a format id) and is not unique across versions or duplicate names — use
    /// [`Violation::component_id`] as the machine-readable join key.
    pub element: Option<String>,
    /// Canonical id of the offending component, when component-scoped.
    ///
    /// Unlike [`Violation::element`], this is a stable join key back to the
    /// SBOM component (the component's `CanonicalId`), so machine consumers
    /// can reliably correlate findings with components. `None` for
    /// document-level and aggregate findings.
    ///
    /// Serialized as `component_id`, omitted when `None`; old payloads
    /// without the field deserialize to `None`.
    pub component_id: Option<String>,
    /// What tells this finding apart from the rule's other findings on the
    /// same subject, for a rule that legitimately reports several: a value
    /// from the SBOM's own data, such as the vulnerability id of a
    /// per-vulnerability finding or the cipher suite of a per-suite one.
    /// Never message text, so rewording a message cannot change it. Where
    /// the SBOM lists one entry twice, `ComplianceChecker::check()` numbers
    /// the repeat (`CVE-2024-3094#2`).
    ///
    /// Part of the finding key (see [`finding_key`]). `None` for rules that
    /// report at most one finding per subject. Serialized as
    /// `finding_detail`, omitted when `None`; old payloads without the field
    /// deserialize to `None`.
    pub finding_detail: Option<String>,
    /// Affected/total component counts for aggregate findings.
    ///
    /// Mirrors the numbers embedded in the human-readable `message`
    /// (e.g. "7/10 components (70%)…") in structured form. `None` for
    /// non-aggregate findings.
    ///
    /// Serialized as `counts`, omitted when `None`; old payloads without the
    /// field deserialize to `None`.
    pub counts: Option<ViolationCounts>,
    /// When the algorithm a crypto finding is about must be replaced: the
    /// milestone [`PqcMode::Deadline`] judged it against and the schedule
    /// that sets it. `None` in readiness mode (the default), for a finding
    /// no schedule dates, and for every finding outside CNSA 2.0 and NIST
    /// PQC.
    ///
    /// Serialized as `deadline` (`YYYY-MM-DD`) and `deadline_source`, both
    /// omitted when `None`; old payloads without them deserialize to `None`.
    pub deadline: Option<Deadline>,
    /// Where the field the rule checks lives in the SBOM's own format: the
    /// registry's field path for the document's format (the
    /// [`FieldAdvice::field`] that `sbom-tools rules explain` shows), such as
    /// `components[].supplier.name` in CycloneDX, `packages[].supplier` in
    /// SPDX 2.x or `suppliedBy` in SPDX 3.0. For a finding about the primary
    /// component of a CycloneDX document, the path starts at
    /// `metadata.component` instead (`metadata.component.supplier.name`).
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// and the input format, as [`Violation::remediation`] is. `None` when
    /// the rule names no field in that format (the fix is the same in every
    /// format, such as an algorithm choice) and on violations built outside
    /// the checker.
    ///
    /// Serialized as `field`, omitted when `None`; old payloads without it
    /// deserialize to `None`.
    pub field: Option<String>,
    /// The value the check read from the SBOM, where there is one: the
    /// placeholder in a supplier field, a digest that does not count, a
    /// timestamp in the future, the algorithm a crypto check rejected. Kept
    /// as read, like [`Violation::message`] and [`Violation::element`], and
    /// cut to 200 characters, ending in `…` when cut: a renderer that shows
    /// it cleans it as it cleans them. `None` when the field is absent or the
    /// check reads no single value.
    ///
    /// Serialized as `observed`, omitted when `None`; old payloads without
    /// it deserialize to `None`.
    pub observed: Option<String>,
    /// Standard/requirement being violated
    pub requirement: String,
    /// Stable internal rule key, set at the check site, indexing into
    /// [`rule_meta`]. This — not the human-readable message — drives the
    /// externally-visible SARIF rule ID, the harmonised-standard references,
    /// and the remediation text. Defaults to `"SBOM-CRA-GENERAL"` for
    /// violations built outside the checker (e.g., from external config).
    ///
    /// Serialized as `rule_id` (alongside a derived `sarif_rule_id`; see the
    /// manual [`Serialize`] impl) so machine consumers get a stable rule key
    /// instead of regexing the message. Deserialization maps a known id back
    /// to its registry `&'static str` key and falls back to the generic
    /// default for unknown ids or old payloads without the field.
    pub rule_id: &'static str,
    /// Structured references to harmonised-standard / regulation clauses.
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// via [`rule_meta`]. Empty when a violation's rule maps to no references.
    pub standard_refs: Vec<StandardRef>,
    /// Remediation guidance phrased for the format of the SBOM the violation
    /// was found in (see [`RuleMeta::remediation_for`]).
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// and the input format, as [`Violation::standard_refs`] is. `None` on
    /// violations built outside the checker; read it through
    /// [`Violation::remediation_guidance`], which then falls back to the
    /// registry advice for every format.
    ///
    /// Serialized as `remediation` (always present); old payloads without
    /// the field deserialize to `None`.
    pub remediation: Option<String>,
}

/// Affected/total component counts carried by aggregate findings.
///
/// Structured mirror of the coverage numbers that aggregate checks embed in
/// the human-readable message (e.g. "7/10 components (70%)…"), so machine
/// consumers can extract them without regexing the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ViolationCounts {
    /// Numerator as printed in the message — usually the number of offending
    /// components; for coverage-style findings ("only X/Y carry …") it is the
    /// covered count, exactly as the message states it.
    pub affected: usize,
    /// Total number of components considered (the message's denominator).
    pub total: usize,
}

/// The coverage findings: rules whose [`ViolationCounts::affected`] is the
/// covered count ("only X/Y carry …"), so `total - affected` items fail.
/// Every other aggregate finding counts the failing items.
/// [`Violation::failed_checks`] reads this.
const COVERAGE_COUNT_RULE_IDS: &[&str] = &[
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-LICENSE-COVERAGE",
];

/// Serde default for [`Violation::rule_id`] when deserializing payloads that
/// predate the field.
fn default_rule_id() -> &'static str {
    "SBOM-CRA-GENERAL"
}

/// Owned mirror of [`Violation`] used for deserialization: `rule_id` arrives
/// as an owned string (or is absent in old payloads) and is mapped back to
/// its registry `&'static str` key. A derived `Deserialize` directly on
/// [`Violation`] would implicitly borrow the `&'static str` field from the
/// input (`'de: 'static`), which does not hold for streamed payloads.
#[derive(Deserialize)]
struct ViolationPayload {
    severity: ViolationSeverity,
    #[serde(default)]
    default_severity: Option<ViolationSeverity>,
    #[serde(default)]
    severity_source: Option<SettingSource>,
    category: ViolationCategory,
    message: String,
    element: Option<String>,
    #[serde(default)]
    component_id: Option<String>,
    #[serde(default)]
    finding_detail: Option<String>,
    #[serde(default)]
    counts: Option<ViolationCounts>,
    #[serde(default)]
    deadline: Option<chrono::NaiveDate>,
    #[serde(default)]
    deadline_source: Option<String>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    observed: Option<String>,
    requirement: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    standard_refs: Vec<StandardRef>,
    #[serde(default)]
    remediation: Option<String>,
}

impl<'de> Deserialize<'de> for Violation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = ViolationPayload::deserialize(deserializer)?;
        Ok(Self {
            severity: payload.severity,
            // An override is the check's severity and the setting's source
            // together.
            severity_override: payload
                .default_severity
                .zip(payload.severity_source)
                .map(|(default, source)| SeverityOverride::new(default, source)),
            category: payload.category,
            message: payload.message,
            element: payload.element,
            component_id: payload.component_id,
            finding_detail: payload.finding_detail,
            counts: payload.counts,
            // A deadline is its date and its source together.
            deadline: payload
                .deadline
                .zip(payload.deadline_source)
                .map(|(date, source)| Deadline { date, source }),
            field: payload.field,
            observed: payload.observed,
            requirement: payload.requirement,
            // Unknown ids (from newer/older registries) collapse to the
            // generic default rather than failing deserialization; the
            // serialized `sarif_rule_id` and `help_uri` companion fields are
            // derived, so they are ignored here.
            rule_id: payload
                .rule_id
                .as_deref()
                .and_then(lookup_static_rule_id)
                .unwrap_or_else(default_rule_id),
            standard_refs: payload.standard_refs,
            remediation: payload.remediation,
        })
    }
}

impl Serialize for Violation {
    /// Manual impl so the JSON carries both the stable internal `rule_id` and
    /// the externally-visible `sarif_rule_id` derived from the rule registry
    /// (never stored, so it cannot drift). Field order mirrors declaration
    /// order; `standard_refs` is skipped when empty, and `component_id` /
    /// `finding_detail` / `counts` are skipped when `None`, as their
    /// serde-derive `skip_serializing_if = "Option::is_none"` equivalents
    /// would be. A `deadline` is written as two fields, `deadline` and
    /// `deadline_source`, both skipped when `None`, and so are `field` and
    /// `observed`. A `severity_override` is written as `default_severity`
    /// and `severity_source`, right after `severity`, both skipped when
    /// `None`. `remediation` is always written (see
    /// [`Violation::remediation_guidance`]), followed by the derived
    /// `help_uri` (see [`Violation::help_uri`]), skipped when there is none.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let has_refs = !self.standard_refs.is_empty();
        let has_component_id = self.component_id.is_some();
        let has_finding_detail = self.finding_detail.is_some();
        let has_counts = self.counts.is_some();
        let help_uri = self.help_uri();
        let mut state = serializer.serialize_struct(
            "Violation",
            8 + usize::from(has_refs)
                + 2 * usize::from(self.severity_override.is_some())
                + usize::from(has_component_id)
                + usize::from(has_finding_detail)
                + usize::from(has_counts)
                + 2 * usize::from(self.deadline.is_some())
                + usize::from(self.field.is_some())
                + usize::from(self.observed.is_some())
                + usize::from(help_uri.is_some()),
        )?;
        state.serialize_field("severity", &self.severity)?;
        if let Some(severity_override) = &self.severity_override {
            state.serialize_field("default_severity", &severity_override.default)?;
            state.serialize_field("severity_source", &severity_override.source)?;
        } else {
            state.skip_field("default_severity")?;
            state.skip_field("severity_source")?;
        }
        state.serialize_field("category", &self.category)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("element", &self.element)?;
        if has_component_id {
            state.serialize_field("component_id", &self.component_id)?;
        } else {
            state.skip_field("component_id")?;
        }
        if has_finding_detail {
            state.serialize_field("finding_detail", &self.finding_detail)?;
        } else {
            state.skip_field("finding_detail")?;
        }
        if has_counts {
            state.serialize_field("counts", &self.counts)?;
        } else {
            state.skip_field("counts")?;
        }
        if let Some(deadline) = &self.deadline {
            state.serialize_field("deadline", &deadline.date)?;
            state.serialize_field("deadline_source", &deadline.source)?;
        } else {
            state.skip_field("deadline")?;
            state.skip_field("deadline_source")?;
        }
        if let Some(field) = &self.field {
            state.serialize_field("field", field)?;
        } else {
            state.skip_field("field")?;
        }
        if let Some(observed) = &self.observed {
            state.serialize_field("observed", observed)?;
        } else {
            state.skip_field("observed")?;
        }
        state.serialize_field("requirement", &self.requirement)?;
        state.serialize_field("rule_id", self.rule_id)?;
        // Same registry lookup + fallback as the SARIF renderer, so the same
        // violation carries the same external rule id on every surface.
        state.serialize_field("sarif_rule_id", self.sarif_rule_id())?;
        if has_refs {
            state.serialize_field("standard_refs", &self.standard_refs)?;
        } else {
            state.skip_field("standard_refs")?;
        }
        state.serialize_field("remediation", &self.remediation_guidance())?;
        if let Some(uri) = help_uri {
            state.serialize_field("help_uri", uri)?;
        } else {
            state.skip_field("help_uri")?;
        }
        state.end()
    }
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
        registry_refs(self.rule_id)
    }

    /// Remediation guidance for this violation: the [`Violation::remediation`]
    /// that `ComplianceChecker::check()` phrased for the input format, or —
    /// for violations built outside the checker — the registry advice for
    /// every format (see [`RuleMeta::remediation_all_formats`]).
    ///
    /// Every renderer (JSON, text, Markdown, HTML, TUI) reads remediation
    /// through this, so the same violation shows the same text everywhere.
    #[must_use]
    pub fn remediation_guidance(&self) -> Cow<'_, str> {
        match &self.remediation {
            Some(text) => Cow::Borrowed(text),
            None => Cow::Owned(rule_meta(self.rule_id).map_or_else(
                || REMEDIATION_UNREGISTERED.to_string(),
                |m| m.remediation_all_formats(),
            )),
        }
    }

    /// Registry remediation for this violation's rule, phrased for `format`.
    /// `ComplianceChecker::check()` stores the result in
    /// [`Violation::remediation`].
    #[must_use]
    pub fn registry_remediation(&self, format: RemediationFormat) -> String {
        rule_meta(self.rule_id).map_or_else(
            || REMEDIATION_UNREGISTERED.to_string(),
            |m| m.remediation_for(format),
        )
    }

    /// The documentation link of this violation's rule: the URL of the first
    /// standard reference that has one (see
    /// [`StandardKind::canonical_help_uri`]), else the page of the rule's
    /// standard family, as the rule catalogue (`sbom-tools rules`) and the
    /// SARIF rule's `helpUri` give it. Serialized as `help_uri`; `None` only
    /// for a rule of no known family.
    #[must_use]
    pub fn help_uri(&self) -> Option<&str> {
        self.standard_refs
            .iter()
            .find_map(|r| r.help_uri.as_deref())
            .or_else(|| rule_family_help_uri(self.rule_id))
    }

    /// Externally-visible SARIF rule id for this violation, looked up from
    /// the rule registry by [`Violation::rule_id`]. Every check is its own
    /// SARIF rule, so for every registered key — i.e. every violation the
    /// checkers produce — this is the key itself, and JSON and SARIF agree.
    /// Truly unregistered keys (violations built outside the checkers, e.g.
    /// from external config) fall back to the generic CRA rule here; the
    /// SARIF renderer additionally re-buckets those by standard family
    /// ([`generic_rule_id_for_level`]), which is the one residual place the
    /// two outputs can differ.
    #[must_use]
    pub fn sarif_rule_id(&self) -> &'static str {
        registry_sarif_id(self.rule_id)
    }

    /// The checks this finding failed, the unit the score counts (see
    /// [`compliance_score`]): none for an Info finding and one for a finding
    /// about one subject. An aggregate finding (one with
    /// [`Violation::counts`]) failed one check per item it reports as
    /// failing, and at least one: `counts.affected`, or `counts.total -
    /// counts.affected` for a coverage finding, whose `affected` counts the
    /// items that pass.
    #[must_use]
    pub fn failed_checks(&self) -> usize {
        if self.severity == ViolationSeverity::Info {
            return 0;
        }
        let Some(counts) = self.counts else {
            return 1;
        };
        let failing = if COVERAGE_COUNT_RULE_IDS.contains(&self.rule_id) {
            counts.total.saturating_sub(counts.affected)
        } else {
            counts.affected
        };
        failing.max(1)
    }
}

/// The harmonised-standard references the registry lists for `rule_id`, in
/// registry order; empty for an unregistered id.
fn registry_refs(rule_id: &str) -> Vec<StandardRef> {
    rule_meta(rule_id)
        .map(|m| {
            m.refs
                .iter()
                .map(|(kind, id)| StandardRef::new(*kind, *id))
                .collect()
        })
        .unwrap_or_default()
}

/// The externally-visible SARIF rule id of `rule_id`; the generic CRA rule
/// for an unregistered id.
fn registry_sarif_id(rule_id: &str) -> &'static str {
    rule_meta(rule_id).map_or("SBOM-CRA-GENERAL", |m| m.sarif_id)
}

/// Where the field `rule_id` checks lives in an SBOM of `format` (see
/// [`Violation::field`]); `None` for an unregistered id or a rule that names
/// no field in that format. The registry writes a component's field under
/// `components[]`. A CycloneDX document keeps its primary component at
/// `metadata.component`, so a finding `about_primary` names the field there.
fn registry_field(rule_id: &str, format: RemediationFormat, about_primary: bool) -> Option<String> {
    let field = rule_meta(rule_id)?.field_for(format)?;
    match field.strip_prefix("components[]") {
        Some(rest) if about_primary && format == RemediationFormat::CycloneDx => {
            Some(format!("metadata.component{rest}"))
        }
        _ => Some(field.to_string()),
    }
}

/// A check the SBOM passed: what a pass-only rule ([`RuleKind::Pass`])
/// reports, such as SBOM-PQC-009's "uses a NIST-approved PQC algorithm".
///
/// A pass is no finding to act on, so it is kept apart from the violations:
/// it has no severity, counts toward neither `info_count` nor the score, and
/// is a SARIF result only under `--sarif-include-passes` (then of
/// `kind: "pass"`). It has a finding key built like a violation's (see
/// [`finding_key`]), and the two share one key space: a rule reports either
/// violations or passes, never both.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PassedCheck {
    /// Stable internal rule key, a [`RuleKind::Pass`] rule of the registry.
    pub rule_id: &'static str,
    /// Human-readable statement of what passed.
    pub message: String,
    /// Human-readable label of the element the check is about (usually the
    /// component name). Not unique: [`PassedCheck::component_id`] is the
    /// join key.
    pub element: Option<String>,
    /// Canonical id of the component the check is about; `None` for a
    /// document-level check.
    pub component_id: Option<String>,
    /// What tells this pass apart from the rule's other passes on the same
    /// subject, like [`Violation::finding_detail`]; `None` for a rule that
    /// passes a subject at most once.
    pub finding_detail: Option<String>,
    /// The requirement the check satisfied, as text.
    pub requirement: String,
    /// References to the clauses the rule implements, populated by
    /// `ComplianceChecker::check()` from the registry.
    pub standard_refs: Vec<StandardRef>,
}

impl PassedCheck {
    /// Structured standard references for this pass, looked up from the rule
    /// registry by [`PassedCheck::rule_id`] (see
    /// [`Violation::registry_standard_refs`]).
    #[must_use]
    pub fn registry_standard_refs(&self) -> Vec<StandardRef> {
        registry_refs(self.rule_id)
    }

    /// Externally-visible SARIF rule id for this pass, looked up from the
    /// rule registry like [`Violation::sarif_rule_id`].
    #[must_use]
    pub fn sarif_rule_id(&self) -> &'static str {
        registry_sarif_id(self.rule_id)
    }
}

impl FindingIdentity for PassedCheck {
    fn rule_id(&self) -> &'static str {
        self.rule_id
    }

    fn finding_detail(&self) -> Option<&str> {
        self.finding_detail.as_deref()
    }

    fn component_id(&self) -> Option<&str> {
        self.component_id.as_deref()
    }
}

impl finding::NumberedDetail for PassedCheck {
    fn set_finding_detail(&mut self, detail: String) {
        self.finding_detail = Some(detail);
    }
}

/// Owned mirror of [`PassedCheck`] for deserialization, for the reason
/// [`ViolationPayload`] gives.
#[derive(Deserialize)]
struct PassedCheckPayload {
    message: String,
    #[serde(default)]
    element: Option<String>,
    #[serde(default)]
    component_id: Option<String>,
    #[serde(default)]
    finding_detail: Option<String>,
    #[serde(default)]
    requirement: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    standard_refs: Vec<StandardRef>,
}

impl<'de> Deserialize<'de> for PassedCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = PassedCheckPayload::deserialize(deserializer)?;
        Ok(Self {
            // Like a violation's: an unknown id collapses to the generic
            // default rather than failing deserialization, and the derived
            // `sarif_rule_id` is ignored.
            rule_id: payload
                .rule_id
                .as_deref()
                .and_then(lookup_static_rule_id)
                .unwrap_or_else(default_rule_id),
            message: payload.message,
            element: payload.element,
            component_id: payload.component_id,
            finding_detail: payload.finding_detail,
            requirement: payload.requirement,
            standard_refs: payload.standard_refs,
        })
    }
}

impl Serialize for PassedCheck {
    /// Manual impl, like [`Violation`]'s, so the JSON carries the derived
    /// `sarif_rule_id` beside the `rule_id`. Fields follow the violation's
    /// order; `component_id` and `finding_detail` are skipped when `None`,
    /// and `standard_refs` when empty.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let has_component_id = self.component_id.is_some();
        let has_finding_detail = self.finding_detail.is_some();
        let has_refs = !self.standard_refs.is_empty();
        let mut state = serializer.serialize_struct(
            "PassedCheck",
            5 + usize::from(has_component_id)
                + usize::from(has_finding_detail)
                + usize::from(has_refs),
        )?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("element", &self.element)?;
        if has_component_id {
            state.serialize_field("component_id", &self.component_id)?;
        } else {
            state.skip_field("component_id")?;
        }
        if has_finding_detail {
            state.serialize_field("finding_detail", &self.finding_detail)?;
        } else {
            state.skip_field("finding_detail")?;
        }
        state.serialize_field("requirement", &self.requirement)?;
        state.serialize_field("rule_id", self.rule_id)?;
        state.serialize_field("sarif_rule_id", self.sarif_rule_id())?;
        if has_refs {
            state.serialize_field("standard_refs", &self.standard_refs)?;
        } else {
            state.skip_field("standard_refs")?;
        }
        state.end()
    }
}

/// A check a standard did not evaluate on the SBOM, and why.
///
/// A check is listed when it applies to the SBOM but did not run: the
/// document's format or spec version cannot carry the evidence it reads (or
/// sbom-tools does not read it there), the spec version does not parse, the
/// run's inputs leave it out (no CRA product class pinned, PQC readiness
/// mode), the SBOM lists none of the component kinds it is about, or the
/// SBOM is too large to analyze. Without the entry, a check that did not run
/// reads like one that passed: neither reports a violation.
///
/// Not listed: a check that ran and found nothing to report, even over no
/// entries (a vulnerability check of an SBOM without vulnerabilities), and a
/// check of something the document's format does not have at all (an SPDX
/// version string or an SPDX 3.0 profile declaration in a CycloneDX
/// document).
///
/// A checker records one with `NotEvaluated::push` where it skips the check
/// (see `context.rs`); [`ComplianceResult::evaluated`] lists them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleEvaluation {
    /// The rule of the check: one of the rules the standard's checks report
    /// ([`rules_for_level`]).
    pub rule_id: &'static str,
    /// What became of the check.
    pub status: EvaluationStatus,
    /// Why, in sbom-tools' own words (never SBOM text), e.g. "SPDX 2.x has
    /// no field for an in-document signature".
    pub reason: String,
}

impl RuleEvaluation {
    /// The record of a check of `rule_id` that did not run, for `reason`.
    #[must_use]
    pub fn not_evaluated(rule_id: &'static str, reason: impl Into<String>) -> Self {
        Self {
            rule_id,
            status: EvaluationStatus::NotEvaluated,
            reason: reason.into(),
        }
    }
}

/// What became of the check a [`RuleEvaluation`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvaluationStatus {
    /// The check did not run on the SBOM.
    NotEvaluated,
}

/// Owned mirror of [`RuleEvaluation`] for deserialization, for the reason
/// [`ViolationPayload`] gives.
#[derive(Deserialize)]
struct RuleEvaluationPayload {
    rule_id: String,
    status: EvaluationStatus,
    #[serde(default)]
    reason: String,
}

impl<'de> Deserialize<'de> for RuleEvaluation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = RuleEvaluationPayload::deserialize(deserializer)?;
        Ok(Self {
            // Like a violation's: an unknown id collapses to the generic
            // default rather than failing deserialization.
            rule_id: lookup_static_rule_id(&payload.rule_id).unwrap_or_else(default_rule_id),
            status: payload.status,
            reason: payload.reason,
        })
    }
}

/// Family fallback rule for a compliance standard: the SARIF rule a finding
/// without a registry mapping is filed under. No check emits one, so no
/// standard's rule catalogue lists it; until v0.4.0 the generic path's
/// shared checks reported under it. Every returned id is a registered
/// self-descriptor (`rule_meta(id).sarif_id == id`), so a SARIF run that
/// files a finding here declares the rule with registry metadata.
#[must_use]
pub const fn generic_rule_id_for_level(level: ComplianceLevel) -> &'static str {
    match level {
        ComplianceLevel::Minimum | ComplianceLevel::Standard | ComplianceLevel::Comprehensive => {
            "SBOM-QUALITY-GENERAL"
        }
        ComplianceLevel::NtiaMinimum => "SBOM-NTIA-GENERAL",
        ComplianceLevel::CraPhase1
        | ComplianceLevel::CraPhase2
        | ComplianceLevel::CraOssSteward => "SBOM-CRA-GENERAL",
        ComplianceLevel::FdaMedicalDevice => "SBOM-FDA-GENERAL",
        ComplianceLevel::NistSsdf => "SBOM-SSDF-GENERAL",
        ComplianceLevel::Eo14028 => "SBOM-EO14028-GENERAL",
        ComplianceLevel::Cnsa2 => "SBOM-CNSA2-GENERAL",
        ComplianceLevel::NistPqc => "SBOM-PQC-GENERAL",
        ComplianceLevel::BsiTr03183_2 => "SBOM-BSI-TR-03183-2-GENERAL",
        ComplianceLevel::EuccSubstantial => "SBOM-EUCC-GENERAL",
        ComplianceLevel::EuAiAct => "SBOM-AIACT-GENERAL",
        ComplianceLevel::BsiSbomForAi => "SBOM-BSIAI-GENERAL",
        ComplianceLevel::Cisa2026 => "SBOM-CISA2026-GENERAL",
        ComplianceLevel::PciDss632 => "SBOM-PCI-GENERAL",
        ComplianceLevel::Fsct => "SBOM-FSCT-GENERAL",
    }
}

/// Severity of a compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ViolationSeverity {
    /// Must be fixed for compliance
    Error,
    /// Should be fixed, but not strictly required
    Warning,
    /// Informational recommendation
    Info,
}

impl ViolationSeverity {
    /// Canonical display label, matching the strings the reports layer
    /// (markdown/HTML violation tables) emits. Renderers should use this
    /// rather than the `Debug` form so the label can't silently drift.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "Error",
            Self::Warning => "Warning",
            Self::Info => "Info",
        }
    }
}

/// Category of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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

/// Whether the checked standard actually evaluated this SBOM.
///
/// Readiness profiles (EU AI Act, BSI/G7 SBOM-for-AI) do not apply to SBOMs
/// outside their scope: their result is `NotApplicable` with the reason, has
/// no violations, and keeps `is_compliant = true` for compatibility, so
/// consumers must render such runs as N/A — never as a pass. Old payloads
/// without the field deserialize as `Applicable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
#[non_exhaustive]
pub enum Applicability {
    /// The standard evaluated the SBOM; `is_compliant` is meaningful.
    #[default]
    Applicable,
    /// The standard did not apply (the string is the human-readable reason).
    NotApplicable(String),
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ComplianceResult {
    /// Overall compliance status
    pub is_compliant: bool,
    /// Compliance level checked against
    pub level: ComplianceLevel,
    /// All violations found
    pub violations: Vec<Violation>,
    /// The checks the SBOM passed (see [`PassedCheck`]), in report order.
    /// They are not violations: no severity count includes them.
    ///
    /// Serialized as `passed`, omitted when empty; old payloads without the
    /// field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passed: Vec<PassedCheck>,
    /// The checks the standard did not evaluate on this SBOM, each with the
    /// reason (see [`RuleEvaluation`]), one per rule, in the order the
    /// checks ran. Every entry is [`EvaluationStatus::NotEvaluated`]. A
    /// standard that did not apply at all lists none: its
    /// [`ComplianceResult::applicability`] says why.
    ///
    /// Serialized as `evaluated`, omitted when empty; old payloads without
    /// the field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluated: Vec<RuleEvaluation>,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
    /// Number of Info-severity violations. Passed checks are not counted:
    /// see [`ComplianceResult::passed`].
    pub info_count: usize,
    /// CRA Annex VIII conformity-assessment summary (CRA-P4.3). Populated
    /// only when the level is CRA Phase 1 or Phase 2 *and* a product class
    /// has been pinned (explicitly or via sidecar). `None` otherwise,
    /// including for the Art. 24 steward profile, which follows no
    /// conformity-assessment procedure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformity_summary: Option<ConformityAssessmentSummary>,
    /// Whether the standard actually evaluated this SBOM (see
    /// [`Applicability`]). `is_compliant` stays `true` for not-applicable
    /// runs by contract; renderers must show N/A instead of a pass.
    #[serde(default)]
    pub applicability: Applicability,
    /// The elements the standard checked, which the score is normalised by
    /// (see [`compliance_score`]): the document itself, plus each component
    /// in the standard's scope. `cnsa2` and `pqc` check cryptographic
    /// assets, `ai-act` and `bsi-ai` ML models, datasets and components that
    /// look like ML models, `eucc` only the document, and every other
    /// standard the package-scoped components it judges (those it left
    /// out for their excluded scope count in
    /// [`ComplianceResult::excluded_components`] instead).
    ///
    /// Set by `ComplianceChecker::check()`; `1` (the document alone) for a
    /// result built with [`ComplianceResult::new`]. Not serialized: the
    /// `-o json` envelope reports it as `score_basis.checked`.
    #[serde(skip, default = "document_only")]
    pub elements_checked: usize,
    /// The rules whose findings the run's rule settings turned off, by rule
    /// id, with how many findings each dropped. The dropped findings count
    /// toward no severity, the verdict or the score.
    ///
    /// Serialized as `suppressed`, omitted when empty; old payloads without
    /// the field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed: Vec<SuppressedRule>,
    /// How many components the package rules left out because their scope
    /// is excluded (CycloneDX `scope: excluded`, or an SPDX development,
    /// build or test dependency; see `Component::scope`). Zero when the run
    /// judges them too (`--include-excluded-scope`) and for a standard
    /// without package rules (CNSA 2.0, NIST PQC, EUCC and the AI profiles).
    ///
    /// Serialized as `excluded_components`, omitted when zero; old payloads
    /// without the field deserialize to zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded_components: usize,
}

/// Serde default for [`ComplianceResult::elements_checked`]: the document.
const fn document_only() -> usize {
    1
}

/// Serde helper: skip a count that is zero.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// Per-route checklist of evidence the CRA Annex VIII conformity-assessment
/// procedure expects. Surfaced in markdown / HTML / SARIF / TUI reports so
/// notified bodies and auditors see the route + the missing evidence in
/// one glance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ConformityEvidence {
    /// Short label (e.g., "EU Declaration of Conformity")
    pub label: String,
    /// Longer description of the evidence
    pub detail: String,
    /// Whether the SBOM/sidecar already provides this evidence
    pub satisfied: bool,
}

impl ComplianceResult {
    /// Create the result of a standard that evaluated the SBOM and found
    /// `violations` (and passed no check; see
    /// [`ComplianceResult::with_passed`]).
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
            passed: Vec::new(),
            evaluated: Vec::new(),
            conformity_summary: None,
            applicability: Applicability::Applicable,
            error_count,
            warning_count,
            info_count,
            elements_checked: document_only(),
            suppressed: Vec::new(),
            excluded_components: 0,
        }
    }

    /// How many findings the run's rule settings turned off: the sum of
    /// [`ComplianceResult::suppressed`].
    #[must_use]
    pub fn suppressed_count(&self) -> usize {
        self.suppressed.iter().map(|rule| rule.findings).sum()
    }

    /// This result with `passed` as its passed checks. Passes move no count,
    /// no verdict and no score.
    #[must_use]
    pub fn with_passed(mut self, passed: Vec<PassedCheck>) -> Self {
        self.passed = passed;
        self
    }

    /// This result with `elements` as its
    /// [`ComplianceResult::elements_checked`]. A count below one is raised
    /// to one: a standard always checks the document.
    #[must_use]
    pub fn with_elements_checked(mut self, elements: usize) -> Self {
        self.elements_checked = elements.max(1);
        self
    }

    /// This result with `evaluated` as the checks the standard did not
    /// evaluate. They move no count, no verdict and no score.
    #[must_use]
    pub fn with_evaluated(mut self, evaluated: Vec<RuleEvaluation>) -> Self {
        self.evaluated = evaluated;
        self
    }

    /// Create the result of a standard that does not apply to the SBOM, for
    /// `reason`: no violations, and `is_compliant` stays `true` by contract
    /// (see [`Applicability`]).
    #[must_use]
    pub fn not_applicable(level: ComplianceLevel, reason: impl Into<String>) -> Self {
        let mut result = Self::new(level, Vec::new());
        result.applicability = Applicability::NotApplicable(reason.into());
        result
    }

    /// Whether the standard actually evaluated this SBOM.
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        self.applicability == Applicability::Applicable
    }

    /// The checks the result's errors and warnings failed, the sum of their
    /// [`Violation::failed_checks`]. Info findings fail none.
    #[must_use]
    pub fn failed_checks(&self) -> usize {
        self.violations
            .iter()
            .fold(0, |sum, v| sum.saturating_add(v.failed_checks()))
    }

    /// Badge/summary compliance score (0–100): [`compliance_score`] of the
    /// checks the errors and the warnings failed, over the
    /// [`ComplianceResult::elements_checked`]. A compliant result scores
    /// 50–100 and a non-compliant one 0–49; Info findings and passed checks
    /// never move it. The JSON, SARIF, OSCAL, Markdown, HTML and TUI outputs
    /// all render this value. `None` when the standard was not applicable:
    /// an unevaluated SBOM has no score.
    #[must_use]
    pub fn score(&self) -> Option<u8> {
        if !self.is_applicable() {
            return None;
        }
        let (mut errors, mut warnings) = (0usize, 0usize);
        for v in &self.violations {
            match v.severity {
                ViolationSeverity::Error => errors = errors.saturating_add(v.failed_checks()),
                ViolationSeverity::Warning => {
                    warnings = warnings.saturating_add(v.failed_checks());
                }
                ViolationSeverity::Info => {}
            }
        }
        Some(compliance_score(errors, warnings, self.elements_checked))
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

/// The compliance score (0–100) of a result whose errors failed `errors`
/// checks and whose warnings failed `warnings` (see
/// [`Violation::failed_checks`]), over `checked` elements (see
/// [`ComplianceResult::elements_checked`]):
///
/// ```text
/// score = band + floor(50 × checked / (checked + errors + warnings))
/// band  = 50 without an error, 0 with one
/// ```
///
/// A compliant result therefore scores 50–100 and a non-compliant one 0–49,
/// so every compliant result outscores every non-compliant one. Within the
/// band the score falls with the failed checks per element: none scores
/// 100, one failed check per element halves the band (75, or 25 with an
/// error), and one failed check in an SBOM of 500,000 elements still scores
/// 99 (49 with an error). An extra failed check never raises the score.
/// The arithmetic is exact for any counts.
#[must_use]
pub fn compliance_score(errors: usize, warnings: usize, checked: usize) -> u8 {
    let failed = errors as u128 + warnings as u128;
    let band: u8 = if errors == 0 { 50 } else { 0 };
    if failed == 0 {
        return band + 50;
    }
    let checked = checked as u128;
    // Below 50: `failed` is at least 1.
    let within = u8::try_from(50 * checked / (checked + failed))
        .expect("the share of a 50-point band fits in a u8");
    band + within
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
#[non_exhaustive]
pub enum ClassCheck {
    /// Vendor-supplied hash coverage below threshold ([PRE-7-RQ-07-RE]).
    VendorHashCoverage,
    /// EOL component present in SBOM.
    EolComponents,
    /// Dependency cycles detected.
    Cycles,
    /// Annex V Declaration-of-Conformity reference missing.
    DocReference,
    /// EUCC (Common Criteria) reference missing.
    EuccReference,
    /// PSIRT URL / 24h / 72h / ENISA channel missing (Art. 14).
    Psirt,
    /// Conformity-assessment-module certificate reference missing
    /// (only meaningful on Module B+C / H / EUCC routes; SBOM-CRA-ANNEX-VIII).
    ModuleAttestation,
}

/// Compliance checker for SBOMs.
///
/// To check with a run's inputs (clock, CRA sidecar, product class) as the
/// CLI and the TUIs do, build it with [`ComplianceRunConfig::checker`], which
/// gives each level only the inputs it reads.
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
    /// Evaluation clock. `None` means wall clock; pin it (CLI `--as-of`,
    /// tests) so deadline-sensitive checks (Art. 14 readiness, SBOM age,
    /// EUCC certificate expiry) are reproducible across runs.
    as_of: Option<chrono::DateTime<chrono::Utc>>,
    /// How CNSA 2.0 and NIST PQC judge quantum-vulnerable cryptography
    /// (CLI `--pqc-mode`); readiness unless set.
    pqc_mode: PqcMode,
    /// Whose deadlines deadline mode applies under NIST PQC (CLI
    /// `--pqc-profile`).
    pqc_profile: PqcProfile,
    /// The CNSA 2.0 equipment category deadline mode applies (CLI
    /// `--cnsa-category`); `None` means the strictest.
    cnsa_category: Option<CnsaCategory>,
    /// The run's rule settings (CLI `--rule`, the config file's
    /// `compliance.rules`), applied to the findings after the checks.
    rule_settings: RuleSettings,
    /// Whether the package rules judge components whose scope is excluded
    /// too (CLI `--include-excluded-scope`); by default they leave them out.
    include_excluded_scope: bool,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    #[must_use]
    pub const fn new(level: ComplianceLevel) -> Self {
        Self {
            level,
            sidecar: None,
            product_class: None,
            as_of: None,
            pqc_mode: PqcMode::Readiness,
            pqc_profile: PqcProfile::Nist,
            cnsa_category: None,
            rule_settings: RuleSettings::new(),
            include_excluded_scope: false,
        }
    }

    /// Apply `settings` to the findings after the checks: a finding of a
    /// rule set to a severity takes it, and the findings of a rule that is
    /// off are dropped and counted in [`ComplianceResult::suppressed`]. The
    /// counts, the verdict and the score follow the severities it sets.
    #[must_use]
    pub fn with_rule_settings(mut self, settings: RuleSettings) -> Self {
        self.rule_settings = settings;
        self
    }

    /// Whether the package rules judge components whose scope is excluded
    /// too (`include`), or leave them out, the default (see
    /// [`ComplianceRunConfig::with_include_excluded_scope`]).
    #[must_use]
    pub const fn with_include_excluded_scope(mut self, include: bool) -> Self {
        self.include_excluded_scope = include;
        self
    }

    /// Whether the run leaves `comp` out of the package rules: its scope is
    /// excluded, the run does not judge such components, and it is not the
    /// document's primary component (the product itself is never left out).
    pub(crate) fn leaves_out(&self, sbom: &NormalizedSbom, comp: &crate::model::Component) -> bool {
        !self.include_excluded_scope
            && comp.scope == Some(crate::model::DependencyScope::Excluded)
            && sbom.primary_component_id.as_ref() != Some(&comp.canonical_id)
    }

    /// Whether the package rules judge `comp`: a package-scoped component
    /// (see [`crate::model::ComponentType::is_package_scoped`]) the run does
    /// not leave out for its excluded scope (see [`Self::leaves_out`]).
    pub(crate) fn judges_package(
        &self,
        sbom: &NormalizedSbom,
        comp: &crate::model::Component,
    ) -> bool {
        comp.component_type.is_package_scoped() && !self.leaves_out(sbom, comp)
    }

    /// The components package rules apply to (see [`Self::judges_package`]).
    /// Every per-component package check iterates through this or tests
    /// [`Self::judges_package`], so no standard can forget a carve-out.
    pub(crate) fn package_components<'a>(
        &'a self,
        sbom: &'a NormalizedSbom,
    ) -> impl Iterator<Item = &'a crate::model::Component> + 'a {
        sbom.components
            .values()
            .filter(move |c| self.judges_package(sbom, c))
    }

    /// How many package-scoped components this check leaves out of its
    /// package rules for their excluded scope: none for a standard without
    /// package rules (see [`ComplianceRunConfig::excluded_scope_applies`]).
    fn excluded_component_count(&self, sbom: &NormalizedSbom) -> usize {
        if !ComplianceRunConfig::excluded_scope_applies(self.level) {
            return 0;
        }
        sbom.components
            .values()
            .filter(|c| c.component_type.is_package_scoped() && self.leaves_out(sbom, c))
            .count()
    }

    /// Pin the evaluation clock. Deadline-sensitive checks (Art. 14
    /// readiness, SBOM age, EUCC certificate expiry) evaluate against this
    /// instant instead of the wall clock — reproducible CI runs, testable
    /// boundary dates.
    #[must_use]
    pub const fn with_as_of(mut self, as_of: chrono::DateTime<chrono::Utc>) -> Self {
        self.as_of = Some(as_of);
        self
    }

    /// The evaluation instant: the pinned `as_of` clock, or the wall clock.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.as_of.unwrap_or_else(chrono::Utc::now)
    }

    /// Judge quantum-vulnerable cryptography under CNSA 2.0 and NIST PQC by
    /// `mode` (CLI `--pqc-mode`). [`PqcMode::Readiness`], the default,
    /// reports every quantum-vulnerable algorithm as an Error;
    /// [`PqcMode::Deadline`] judges each by its migration deadline at the
    /// evaluation instant (see [`Self::with_as_of`]) and records the
    /// deadline on the finding ([`Violation::deadline`]).
    #[must_use]
    pub const fn with_pqc_mode(mut self, mode: PqcMode) -> Self {
        self.pqc_mode = mode;
        self
    }

    /// The deadlines [`PqcMode::Deadline`] applies under NIST PQC (CLI
    /// `--pqc-profile`): NIST IR 8547's, the default, or with
    /// [`PqcProfile::Federal`] the federal ones of EO 14412 and OMB
    /// M-26-15 as well. Readiness mode ignores it.
    #[must_use]
    pub const fn with_pqc_profile(mut self, profile: PqcProfile) -> Self {
        self.pqc_profile = profile;
        self
    }

    /// The CNSA 2.0 equipment category whose timeline [`PqcMode::Deadline`]
    /// applies under CNSA 2.0 (CLI `--cnsa-category`). Unset, the strictest
    /// applies. Readiness mode ignores it.
    #[must_use]
    pub const fn with_cnsa_category(mut self, category: CnsaCategory) -> Self {
        self.cnsa_category = Some(category);
        self
    }

    /// How CNSA 2.0 and NIST PQC judge quantum-vulnerable cryptography.
    #[must_use]
    pub const fn pqc_mode(&self) -> PqcMode {
        self.pqc_mode
    }

    /// The calendar the crypto checks judge by: `None` in readiness mode.
    pub(crate) fn pqc_calendar(&self) -> Option<Calendar> {
        (self.pqc_mode == PqcMode::Deadline).then(|| {
            Calendar::new(
                self.pqc_profile,
                self.cnsa_category,
                self.now().date_naive(),
            )
        })
    }

    /// Attach CRA sidecar metadata to supplement SBOM-level fields.
    ///
    /// Sidecar values are only consulted as fallbacks — fields present in the
    /// SBOM always take precedence. The CLI commands attach it through
    /// [`ComplianceRunConfig`] (`--cra-sidecar`, with auto-discovery for
    /// adjacent `<sbom>.cra.{json,yaml}` files), which gives it only to the
    /// levels that read it.
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
    /// Selects the [`StandardChecker`] for the configured level (the
    /// dedicated profiles get their own checker; the rest take the generic
    /// path), runs it, then back-fills harmonised-standard references (and,
    /// for violations, the remediation and the field path for the SBOM's
    /// format) from the rule registry, numbers the finding details of
    /// entries the SBOM repeats (so every violation and every passed check
    /// keeps a key of its own, see [`finding_key`]), applies the run's rule
    /// settings (see [`Self::with_rule_settings`]), records whether the
    /// standard applied, which of its checks it did not evaluate and how
    /// many components it left out for their excluded scope, and
    /// attaches the CRA Annex VIII conformity summary when a product class
    /// has been pinned on CRA Phase 1 or Phase 2.
    ///
    /// Every entry point builds its checkers through
    /// [`ComplianceRunConfig::checker`], which decides which of a run's
    /// inputs (clock, sidecar, product class) each level gets.
    #[must_use]
    pub fn check(&self, sbom: &NormalizedSbom) -> ComplianceResult {
        let ctx = ComplianceContext::new(self, sbom);
        let checker = checker_for(self.level);
        debug_assert_eq!(
            checker.level(),
            self.level,
            "dispatched checker must match the configured level"
        );
        let Findings {
            mut violations,
            mut passed,
            not_evaluated,
            applicability,
        } = checker.check(&ctx);
        let evaluated = not_evaluated.into_vec();
        debug_assert!(
            evaluated.iter().all(|e| {
                rules_for_level(self.level).contains(&e.rule_id)
                    && !violations.iter().any(|v| v.rule_id == e.rule_id)
                    && !passed.iter().any(|p| p.rule_id == e.rule_id)
            }),
            "a check not evaluated must be one of the level's rules and report nothing"
        );
        debug_assert!(
            violations
                .iter()
                .all(|v| rule_kind(v.rule_id) != Some(RuleKind::Pass)),
            "a pass-only rule must report a PassedCheck, never a violation"
        );
        debug_assert!(
            passed
                .iter()
                .all(|p| rule_kind(p.rule_id) == Some(RuleKind::Pass)),
            "a passed check must come from a registered pass-only rule"
        );

        // Populate harmonised-standard references, and the remediation and
        // the field path for the input format, from the rule registry.
        let format = RemediationFormat::of(&sbom.document);
        let primary = sbom.primary_component_id.as_ref().map(|id| id.value());
        for v in &mut violations {
            if v.standard_refs.is_empty() {
                v.standard_refs = v.registry_standard_refs();
            }
            if v.remediation.is_none() {
                v.remediation = Some(v.registry_remediation(format));
            }
            if v.field.is_none() {
                let about_primary = primary.is_some() && v.component_id.as_deref() == primary;
                v.field = registry_field(v.rule_id, format, about_primary);
            }
        }
        for p in &mut passed {
            if p.standard_refs.is_empty() {
                p.standard_refs = p.registry_standard_refs();
            }
        }
        // Every finding keeps a key of its own, also where the SBOM lists
        // one entry twice. Violations and passes never share a rule, so
        // numbering each list keeps their keys apart too.
        finding::number_repeated_details(&mut violations);
        finding::number_repeated_details(&mut passed);

        // The run's rule settings, after the checks and before the counts:
        // the verdict, the counts and the score follow the severities they
        // set, and what `off` drops is counted, never lost silently.
        let suppressed = self.rule_settings.apply(&mut violations);

        let mut result = ComplianceResult::new(self.level, violations)
            .with_passed(passed)
            .with_elements_checked(self.elements_checked(sbom))
            .with_evaluated(evaluated);
        result.applicability = applicability;
        result.suppressed = suppressed;
        result.excluded_components = self.excluded_component_count(sbom);
        // Attach the CRA Annex VIII conformity summary when a product class
        // has been pinned and the level is a CRA phase profile. Annex VIII
        // lists the manufacturer's conformity-assessment procedures; an
        // open-source steward (Art. 24, `CraOssSteward`) follows none.
        if self.level.cra_phase().is_some() && self.has_explicit_product_class() {
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

impl ComplianceChecker {
    /// The elements this check judges in `sbom`, the unit its score is
    /// normalised by (see [`ComplianceResult::elements_checked`]): the
    /// document, plus the components in the standard's scope. The package
    /// standards count the components their package rules judge, so the
    /// ones left out for their excluded scope do not count.
    fn elements_checked(&self, sbom: &NormalizedSbom) -> usize {
        let components = match self.level {
            // EUCC checks the sidecar's certification evidence, not components.
            ComplianceLevel::EuccSubstantial => 0,
            // All components: the count selects cryptographic assets by type,
            // the subjects of the CNSA 2.0 and PQC checks.
            ComplianceLevel::Cnsa2 | ComplianceLevel::NistPqc => sbom
                .components
                .values()
                .filter(|c| c.component_type == crate::model::ComponentType::Cryptographic)
                .count(),
            ComplianceLevel::EuAiAct | ComplianceLevel::BsiSbomForAi => {
                ai_shared::ai_bom_scope(sbom).component_count()
            }
            _ => self.package_components(sbom).count(),
        };
        components.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared test clock (tests/common/clock.rs). Tests that cross a
    /// date gate pin their own instant instead.
    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    fn checker(level: ComplianceLevel) -> ComplianceChecker {
        ComplianceChecker::new(level).with_as_of(as_of())
    }

    /// NTIA lists Timestamp as a required data field; it must gate. A
    /// timestamp-less SBOM (epoch sentinel) now fails NtiaMinimum.
    #[test]
    fn ntia_gates_on_missing_timestamp() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let comp = |sbom: &mut NormalizedSbom| {
            let c = Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string());
            sbom.add_component(c);
        };

        // No real timestamp (epoch sentinel) → NTIA timestamp error.
        let mut no_ts = NormalizedSbom::new(DocumentMetadata::default());
        no_ts.document.created = chrono::DateTime::UNIX_EPOCH;
        comp(&mut no_ts);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&no_ts);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-TIMESTAMP"
                    && v.severity == ViolationSeverity::Error),
            "missing timestamp must fail NTIA"
        );

        // A real timestamp → no timestamp error.
        let mut with_ts = NormalizedSbom::new(DocumentMetadata::default()); // now()
        comp(&mut with_ts);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&with_ts);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-TIMESTAMP")
        );
    }

    /// EO 14028 §4(e) requires Supplier Name (an NTIA element); a missing
    /// supplier must be a gating Error, not a sub-threshold Warning.
    #[test]
    fn eo14028_gates_on_missing_supplier() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        // Component with version + id but NO supplier.
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::Eo14028).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-SUPPLIER"
                    && v.severity == ViolationSeverity::Error),
            "missing supplier must be a gating Error under EO 14028"
        );
    }

    /// BSI TR-03183-2 §5.2.2 makes component name mandatory; the dedicated
    /// BSI checker must enforce it (it does not run the generic component
    /// check).
    #[test]
    fn bsi_gates_on_nameless_component() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut c =
            Component::new(String::new(), "ref-1".to_string()).with_version("1.0".to_string());
        c.identifiers.purl = Some("pkg:cargo/x@1.0".to_string());
        sbom.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-3"),
            "a nameless component must fail BSI §5.2.2"
        );
    }

    /// CRA Art. 24 steward vuln-handling is satisfied by a DOCUMENT-level
    /// disclosure URL — the check previously ignored doc fields (false-fail).
    #[test]
    fn cra_art24_honors_document_level_disclosure() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.vulnerability_disclosure_url =
            Some("https://acme.example/security".to_string());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
        assert!(
            !r.violations.iter().any(|v| v.rule_id == "SBOM-CRA-ART-24"),
            "a document-level disclosure URL must satisfy the Art.24 vuln-handling gate"
        );
    }

    /// "Other Unique Identifiers" is one of the seven NTIA minimum data
    /// fields; a component without PURL/CPE/SWHID/SWID must fail NtiaMinimum.
    #[test]
    fn ntia_gates_on_missing_identifier() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
        let mut without_id = NormalizedSbom::new(DocumentMetadata::default());
        let mut c =
            Component::new("lib".to_string(), "lib@1".to_string()).with_version("1.0".to_string());
        c.supplier = Some(Organization::new("LibCorp".to_string()));
        without_id.add_component(c);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&without_id);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-IDENTIFIER"
                    && v.severity == ViolationSeverity::Error),
            "missing unique identifier must fail NTIA"
        );

        let mut with_id = NormalizedSbom::new(DocumentMetadata::default());
        let mut c = Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        c.supplier = Some(Organization::new("LibCorp".to_string()));
        with_id.add_component(c);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&with_id);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-IDENTIFIER"),
            "PURL satisfies the NTIA identifier element"
        );
    }

    /// Asserted-as-unknown sentinels (NOASSERTION) must not satisfy the NTIA
    /// version and supplier gates — SPDX copies versionInfo verbatim.
    #[test]
    fn placeholder_values_do_not_satisfy_required_elements() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut c = Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("NOASSERTION".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        c.supplier = Some(Organization::new("NOASSERTION".to_string()));
        sbom.add_component(c);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-VERSION"),
            "NOASSERTION version must not satisfy the NTIA version element"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-SUPPLIER"),
            "NOASSERTION supplier must not satisfy the NTIA supplier element"
        );
    }

    /// FDA premarket guidance incorporates the NTIA baseline, so a
    /// timestamp-less SBOM must fail FdaMedicalDevice like it fails NTIA.
    #[test]
    fn fda_gates_on_missing_timestamp() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.created = chrono::DateTime::UNIX_EPOCH;
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
        assert!(
            r.violations.iter().any(
                |v| v.rule_id == "SBOM-FDA-TIMESTAMP" && v.severity == ViolationSeverity::Error
            ),
            "missing timestamp must fail FDA (NTIA baseline)"
        );
    }

    /// FDA §524B requires level-of-support / end-of-support information;
    /// its absence must at least warn, and lifecycle properties satisfy it.
    #[test]
    fn fda_warns_without_support_lifecycle() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, Property};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.requirement.contains("Level of support")),
            "missing support-lifecycle info must warn under FDA"
        );

        let mut with_eol = NormalizedSbom::new(DocumentMetadata::default());
        let mut c = Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        c.extensions.properties.push(Property {
            name: "end-of-support".to_string(),
            value: "2030-01-01".to_string(),
        });
        with_eol.add_component(c);
        let r = checker(ComplianceLevel::FdaMedicalDevice).check(&with_eol);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.requirement.contains("Level of support")),
            "component end-of-support property satisfies the FDA support check"
        );
    }

    /// The EO 14028 §4(e) practice incorporates the NTIA minimum elements, which include the
    /// creation timestamp.
    #[test]
    fn eo14028_gates_on_missing_timestamp() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.created = chrono::DateTime::UNIX_EPOCH;
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::Eo14028).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-TIMESTAMP"
                    && v.severity == ViolationSeverity::Error),
            "missing timestamp must fail EO 14028"
        );

        let mut with_ts = NormalizedSbom::new(DocumentMetadata::default());
        with_ts.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::Eo14028).check(&with_ts);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-TIMESTAMP")
        );
    }

    /// SPDX 2.2 is an NTIA-accepted format; the EO 14028 machine-readable
    /// gate must not error on it (SPDX 2.1 and older still fail).
    #[test]
    fn eo14028_accepts_spdx_2_2() {
        use crate::model::{DocumentMetadata, NormalizedSbom, SbomFormat};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.format = SbomFormat::Spdx;
        sbom.document.spec_version = "2.2".to_string();
        let r = checker(ComplianceLevel::Eo14028).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-FORMAT"),
            "SPDX 2.2 is machine-readable under EO 14028"
        );

        sbom.document.spec_version = "2.1".to_string();
        let r = checker(ComplianceLevel::Eo14028).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-FORMAT"),
            "SPDX 2.1 still fails the machine-readable gate"
        );
    }

    /// SWHID-only components carry a valid unique identifier; EO 14028 and
    /// SSDF identifier checks must not flag them.
    #[test]
    fn eo14028_and_ssdf_accept_swhid_identifiers() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, SwhidObject};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut c =
            Component::new("lib".to_string(), "lib@1".to_string()).with_version("1.0".to_string());
        c.identifiers.swhid.push(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap(),
        );
        sbom.add_component(c);
        let r = checker(ComplianceLevel::Eo14028).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-EO14028-IDENTIFIER"),
            "SWHID satisfies the EO 14028 identifier element"
        );
        let r = checker(ComplianceLevel::NistSsdf).check(&sbom);
        assert!(
            !r.violations.iter().any(|v| v.rule_id == "SBOM-SSDF-RV1"),
            "SWHID satisfies the SSDF RV.1 identifier check"
        );
    }

    /// A single token edge among many components must not satisfy the NTIA
    /// dependency-relationship element; declared-incomplete SBOMs are exempt.
    #[test]
    fn dependency_graph_orphans_warn() {
        use crate::model::{
            CompletenessDeclaration, Component, DependencyEdge, DependencyType, DocumentMetadata,
            NormalizedSbom,
        };
        let build = || {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let mut ids = Vec::new();
            for i in 0..5 {
                let c = Component::new(format!("lib{i}"), format!("lib{i}@1"))
                    .with_version("1.0".to_string())
                    .with_purl(format!("pkg:cargo/lib{i}@1.0"));
                ids.push(c.canonical_id.clone());
                sbom.add_component(c);
            }
            // One edge between two leaves; the other three stay orphaned.
            sbom.edges.push(DependencyEdge::new(
                ids[0].clone(),
                ids[1].clone(),
                DependencyType::DependsOn,
            ));
            sbom
        };

        let r = checker(ComplianceLevel::NtiaMinimum).check(&build());
        assert!(
            r.violations.iter().any(|v| v
                .message
                .contains("participate in no dependency relationship")),
            "3/5 orphaned components must produce a dependency-coverage warning"
        );

        let mut declared = build();
        declared.document.completeness_declaration = CompletenessDeclaration::Incomplete;
        let r = checker(ComplianceLevel::NtiaMinimum).check(&declared);
        assert!(
            !r.violations.iter().any(|v| v
                .message
                .contains("participate in no dependency relationship")),
            "declared-incomplete SBOMs are exempt from the orphan warning"
        );
    }

    /// The primary product component must participate in the dependency
    /// graph — a root with zero relationships does not describe the product.
    #[test]
    fn primary_component_must_participate_in_graph() {
        use crate::model::{
            Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let app = Component::new("app".to_string(), "app".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        let lib_a = Component::new("liba".to_string(), "liba".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/liba@1.0".to_string());
        let lib_b = Component::new("libb".to_string(), "libb".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/libb@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let a_id = lib_a.canonical_id.clone();
        let b_id = lib_b.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.add_component(app);
        sbom.add_component(lib_a);
        sbom.add_component(lib_b);
        // Edge between the two libs only; the primary is disconnected.
        sbom.edges.push(DependencyEdge::new(
            a_id.clone(),
            b_id,
            DependencyType::DependsOn,
        ));
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.message.contains("Primary component")
                    && v.message.contains("no dependency relationship")),
            "disconnected primary component must warn"
        );

        // Connect the primary → warning disappears.
        sbom.edges
            .push(DependencyEdge::new(app_id, a_id, DependencyType::DependsOn));
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.message.contains("Primary component")
                    && v.message.contains("no dependency relationship"))
        );
    }

    /// CRA Art. 24 steward SBOMs still need versioned, identified components
    /// and dependency relationships — the per-component gates used to skip
    /// the CraOssSteward level entirely (vacuous "SBOM completeness").
    #[test]
    fn oss_steward_enforces_component_completeness() {
        use crate::model::{Component, DocumentMetadata, ExternalRefType, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        // Steward vuln-handling satisfied so only completeness is under test.
        sbom.document.vulnerability_disclosure_url =
            Some("https://acme.example/security".to_string());
        for n in ["a", "b", "c"] {
            let mut c = Component::new(n.to_string(), n.to_string());
            c.external_refs.push(crate::model::ExternalReference {
                ref_type: ExternalRefType::Advisories,
                url: "https://acme.example/advisories".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
            sbom.add_component(c);
        }
        let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-COMPONENT-VERSION"
                    && v.severity == ViolationSeverity::Error),
            "steward components without versions must error"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ANNEX-I-IDENTIFIER"
                    && v.severity == ViolationSeverity::Error),
            "steward components without identifiers must error"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ANNEX-I-DEPENDENCY"
                    && v.severity == ViolationSeverity::Error),
            "steward SBOM without dependency edges must error"
        );
        assert!(!r.is_compliant, "incomplete steward SBOM must not pass");
    }

    /// A third-party dependency's upstream advisories/support refs must not
    /// satisfy the manufacturer's Art. 13(17) contact / Annex I Part II (5)
    /// CVD-policy obligations.
    #[test]
    fn third_party_refs_do_not_satisfy_manufacturer_obligations() {
        use crate::model::{
            Component, DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType,
            ExternalReference, NormalizedSbom,
        };
        let build = |primary_has_contact: bool| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let mut app = Component::new("app".to_string(), "app".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/app@1.0".to_string());
            if primary_has_contact {
                app.external_refs.push(ExternalReference {
                    ref_type: ExternalRefType::SecurityContact,
                    url: "https://acme.example/security".to_string(),
                    comment: None,
                    hashes: Vec::new(),
                });
                app.external_refs.push(ExternalReference {
                    ref_type: ExternalRefType::Advisories,
                    url: "https://acme.example/advisories".to_string(),
                    comment: None,
                    hashes: Vec::new(),
                });
            }
            // Third-party dep carrying its own upstream refs.
            let mut lodash = Component::new("lodash".to_string(), "lodash".to_string())
                .with_version("4.17.21".to_string())
                .with_purl("pkg:npm/lodash@4.17.21".to_string());
            lodash.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::Advisories,
                url: "https://github.com/lodash/lodash/security/advisories".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
            lodash.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::Support,
                url: "https://lodash.com/docs".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
            let app_id = app.canonical_id.clone();
            let lodash_id = lodash.canonical_id.clone();
            sbom.primary_component_id = Some(app_id.clone());
            sbom.add_component(app);
            sbom.add_component(lodash);
            sbom.edges.push(DependencyEdge::new(
                app_id,
                lodash_id,
                DependencyType::DependsOn,
            ));
            sbom
        };

        let r = checker(ComplianceLevel::CraPhase2).check(&build(false));
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
            "dep-level advisories/support refs must not satisfy Art. 13(17)"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-CVD-POLICY"),
            "dep-level advisories ref must not satisfy Annex I Part II (5)"
        );

        let r = checker(ComplianceLevel::CraPhase2).check(&build(true));
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
            "primary-component security contact satisfies Art. 13(17)"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-CVD-POLICY"),
            "primary-component advisories ref satisfies Annex I Part II (5)"
        );
    }

    /// Pinning an explicit product class must never weaken the phase-based
    /// vendor-hash gate: 40% coverage is an Error under CraPhase2 regardless
    /// of a pinned Important-1 class (whose own threshold severity is softer).
    #[test]
    fn explicit_product_class_never_weakens_vendor_hash_gate() {
        use crate::model::CraProductClass;
        let mut sbom = NormalizedSbom::default();
        for n in ["a", "b", "c", "d"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        for n in ["e", "f", "g", "h", "i", "j"] {
            let c = vendor_component(n, false);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = checker(ComplianceLevel::CraPhase2)
            .with_product_class(CraProductClass::ImportantClass1)
            .check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "40% coverage must stay an Error under CraPhase2 even with an explicit class"
        );
    }

    /// The sidecar's dedicated EUCC evidence fields must satisfy the
    /// Critical-class EUCC reference check (not just URL substrings).
    #[test]
    fn eucc_sidecar_fields_satisfy_critical_class_check() {
        use crate::model::{Component, CraProductClass, CraSidecarMetadata, DocumentMetadata};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("fw".to_string(), "fw".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:generic/fw@1.0".to_string()),
        );

        let bare = checker(ComplianceLevel::CraPhase2)
            .with_product_class(CraProductClass::Critical)
            .check(&sbom);
        assert!(
            bare.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV"),
            "Critical class without EUCC evidence must flag Annex IV"
        );

        let sidecar = CraSidecarMetadata {
            eucc_protection_profile_id: Some("PP-CC-MFR-2024-01".to_string()),
            eucc_target_of_evaluation: Some("TOE-fw-1.0".to_string()),
            ..Default::default()
        };
        let with_sidecar = checker(ComplianceLevel::CraPhase2)
            .with_product_class(CraProductClass::Critical)
            .with_sidecar(sidecar)
            .check(&sbom);
        assert!(
            !with_sidecar
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV"),
            "sidecar EUCC evidence fields must satisfy the Critical-class check"
        );
    }

    /// Genuine packages named "none"/"unknown" (corroborated by PURL) must
    /// not fail the name gate; NOASSERTION always fails it.
    #[test]
    fn genuine_none_named_package_passes_name_gate() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut c = Component::new("none".to_string(), "none@1".to_string())
            .with_version("1.0.0".to_string())
            .with_purl("pkg:npm/none@1.0.0".to_string());
        c.supplier = Some(Organization::new("Acme".to_string()));
        sbom.add_component(c);
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            !r.violations.iter().any(|v| v.rule_id == "SBOM-NTIA-NAME"),
            "npm package genuinely named 'none' must not fail the name gate"
        );

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("NOASSERTION".to_string(), "x@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:npm/realname@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            r.violations.iter().any(|v| v.rule_id == "SBOM-NTIA-NAME"),
            "NOASSERTION never satisfies the name gate"
        );
    }

    /// Lifecycle-evidence property matching is token-based with a real
    /// value — "geolocation" must not satisfy the FDA support element.
    #[test]
    fn fda_support_not_satisfied_by_incidental_eol_substring() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom, Property};
        let build = |name: &str, value: &str| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let mut c = Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string());
            c.extensions.properties.push(Property {
                name: name.to_string(),
                value: value.to_string(),
            });
            sbom.add_component(c);
            checker(ComplianceLevel::FdaMedicalDevice).check(&sbom)
        };
        assert!(
            build("geolocation", "enabled")
                .violations
                .iter()
                .any(|v| v.requirement.contains("Level of support")),
            "'geolocation' must not satisfy the support-lifecycle element"
        );
        assert!(
            build("acme:eol", "2030-01-01")
                .violations
                .iter()
                .all(|v| !v.requirement.contains("Level of support")),
            "a real eol property with a value satisfies the element"
        );
        assert!(
            build("end-of-support", "NOASSERTION")
                .violations
                .iter()
                .any(|v| v.requirement.contains("Level of support")),
            "a placeholder value must not satisfy the element"
        );
    }

    /// A primary component that positively declares "no dependencies"
    /// (CycloneDX empty dependsOn, preserved as a synthetic property) is
    /// documented — the participation warning must not fire.
    #[test]
    fn primary_with_declared_empty_deps_does_not_warn() {
        use crate::model::{
            Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom, Property,
        };
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut app = Component::new("app".to_string(), "app".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        app.extensions.properties.push(Property {
            name: crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY.to_string(),
            value: "true".to_string(),
        });
        let lib_a = Component::new("liba".to_string(), "liba".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/liba@1.0".to_string());
        let lib_b = Component::new("libb".to_string(), "libb".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/libb@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let a_id = lib_a.canonical_id.clone();
        let b_id = lib_b.canonical_id.clone();
        sbom.primary_component_id = Some(app_id);
        sbom.add_component(app);
        sbom.add_component(lib_a);
        sbom.add_component(lib_b);
        sbom.edges
            .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.message.contains("Primary component")),
            "declared-no-dependencies primary must not warn"
        );
    }

    /// FDA keeps the retired fast-path's any-orphan sensitivity; other
    /// standards only warn on a majority of orphans.
    #[test]
    fn fda_warns_on_minority_orphans() {
        use crate::model::{
            Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut ids = Vec::new();
        for i in 0..4 {
            let c = Component::new(format!("lib{i}"), format!("lib{i}@1"))
                .with_version("1.0".to_string())
                .with_purl(format!("pkg:cargo/lib{i}@1.0"));
            ids.push(c.canonical_id.clone());
            sbom.add_component(c);
        }
        // 3 of 4 connected, 1 orphan (minority).
        sbom.edges.push(DependencyEdge::new(
            ids[0].clone(),
            ids[1].clone(),
            DependencyType::DependsOn,
        ));
        sbom.edges.push(DependencyEdge::new(
            ids[1].clone(),
            ids[2].clone(),
            DependencyType::DependsOn,
        ));
        let fda = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
        assert!(
            fda.violations.iter().any(|v| v
                .message
                .contains("participate in no dependency relationship")),
            "FDA warns on any orphaned component"
        );
        let ntia = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(
            !ntia.violations.iter().any(|v| v
                .message
                .contains("participate in no dependency relationship")),
            "NTIA only warns when orphans form a majority"
        );
    }

    /// FDA rule identity: dependency, creator, and serial findings must
    /// carry FDA rule ids, not NTIA/CRA ones.
    #[test]
    fn fda_findings_carry_fda_rule_ids() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.creators.clear();
        for i in 0..2 {
            sbom.add_component(
                Component::new(format!("lib{i}"), format!("lib{i}@1"))
                    .with_version("1.0".to_string())
                    .with_purl(format!("pkg:cargo/lib{i}@1.0")),
            );
        }
        let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
        assert!(
            r.violations.iter().any(|v| v.rule_id == "SBOM-FDA-CREATOR"),
            "creators-empty must carry SBOM-FDA-CREATOR under FDA"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-FDA-DEPENDENCY"),
            "dependency findings must carry SBOM-FDA-DEPENDENCY under FDA"
        );
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-FDA-NAMESPACE"),
            "serial-number finding must carry SBOM-FDA-NAMESPACE under FDA"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-NTIA-DEPENDENCY"),
            "FDA runs must not emit NTIA dependency rule identity"
        );
    }

    /// Sidecar EUCC evidence must be live: empty strings and expired
    /// validity dates must not satisfy the Critical-class Annex IV gate.
    #[test]
    fn eucc_sidecar_empty_or_expired_evidence_does_not_satisfy() {
        use crate::model::{Component, CraProductClass, CraSidecarMetadata, DocumentMetadata};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("fw".to_string(), "fw".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:generic/fw@1.0".to_string()),
        );
        let check = |sidecar: CraSidecarMetadata| {
            checker(ComplianceLevel::CraPhase2)
                .with_product_class(CraProductClass::Critical)
                .with_sidecar(sidecar)
                .check(&sbom)
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ANNEX-IV")
        };
        assert!(
            check(CraSidecarMetadata {
                eucc_protection_profile_id: Some("  ".to_string()),
                ..Default::default()
            }),
            "an empty-string EUCC field must not satisfy the Annex IV gate"
        );
        assert!(
            check(CraSidecarMetadata {
                eucc_valid_until: Some(as_of() - chrono::Duration::days(365)),
                ..Default::default()
            }),
            "an expired EUCC validity date must not satisfy the Annex IV gate"
        );
        assert!(
            !check(CraSidecarMetadata {
                eucc_valid_until: Some(as_of() + chrono::Duration::days(365)),
                ..Default::default()
            }),
            "a live EUCC validity date satisfies the Annex IV gate"
        );
        // An expired certificate voids its identifiers: they describe a
        // certificate that no longer holds.
        assert!(
            check(CraSidecarMetadata {
                eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
                eucc_itsef_identifier: Some("ITSEF-DE-0042".to_string()),
                eucc_valid_until: Some(as_of() - chrono::Duration::days(1)),
                ..Default::default()
            }),
            "identifiers beside an expired validity date must not satisfy the Annex IV gate"
        );
        assert!(
            !check(CraSidecarMetadata {
                eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
                eucc_valid_until: Some(as_of() + chrono::Duration::days(365)),
                ..Default::default()
            }),
            "an identifier with a live validity date satisfies the Annex IV gate"
        );
        assert!(
            !check(CraSidecarMetadata {
                eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
                ..Default::default()
            }),
            "an identifier without a validity date still satisfies the Annex IV gate"
        );
    }

    /// Steward supplier findings cite Art. 24 in their structured refs, not
    /// the exempted Art. 13(16) manufacturer-identification obligation.
    #[test]
    fn steward_supplier_refs_cite_art_24() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.vulnerability_disclosure_url =
            Some("https://acme.example/security".to_string());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::CraOssSteward).check(&sbom);
        let v = r
            .violations
            .iter()
            .find(|v| v.rule_id == "SBOM-CRA-ART-24-SUPPLIER")
            .expect("steward supplier warning fires");
        assert!(
            v.standard_refs
                .iter()
                .all(|sr| sr.id != "Art. 13(15)" && sr.id != "Art. 13(16)"),
            "steward supplier refs must not cite Art. 13(15)/13(16)"
        );
        assert!(
            v.standard_refs.iter().any(|sr| sr.id == "Art. 24"),
            "steward supplier refs must cite Art. 24"
        );
    }

    /// Manufacturer scope: cyclic graphs fall back to all components, and a
    /// primary does not exclude sibling root products.
    #[test]
    fn manufacturer_scope_handles_cycles_and_sibling_roots() {
        use crate::model::{
            Component, DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType,
            ExternalReference, NormalizedSbom,
        };
        // Cyclic: a <-> b, no primary; evidence on a must still count.
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut a = Component::new("liba".to_string(), "liba".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/liba@1.0".to_string());
        a.external_refs.push(ExternalReference {
            ref_type: ExternalRefType::SecurityContact,
            url: "https://acme.example/security".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        let b = Component::new("libb".to_string(), "libb".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/libb@1.0".to_string());
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        sbom.add_component(a);
        sbom.add_component(b);
        sbom.edges.push(DependencyEdge::new(
            a_id.clone(),
            b_id.clone(),
            DependencyType::DependsOn,
        ));
        sbom.edges
            .push(DependencyEdge::new(b_id, a_id, DependencyType::DependsOn));
        let r = checker(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-ART-13-17-CONTACT"),
            "evidence in a fully-cyclic graph must still count (fallback to all components)"
        );
    }

    /// Dependency cycles fire the ClassCheck::Cycles calibration: Warning at
    /// Default class, Error at Important-2/Critical; acyclic graphs are silent.
    #[test]
    fn cra_dependency_cycles_scale_with_product_class() {
        use crate::model::{
            Component, CraProductClass, DependencyEdge, DependencyType, DocumentMetadata,
            NormalizedSbom,
        };
        let build = |cyclic: bool| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let a = Component::new("liba".to_string(), "liba".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/liba@1.0".to_string());
            let b = Component::new("libb".to_string(), "libb".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/libb@1.0".to_string());
            let a_id = a.canonical_id.clone();
            let b_id = b.canonical_id.clone();
            sbom.add_component(a);
            sbom.add_component(b);
            sbom.edges.push(DependencyEdge::new(
                a_id.clone(),
                b_id.clone(),
                DependencyType::DependsOn,
            ));
            if cyclic {
                sbom.edges
                    .push(DependencyEdge::new(b_id, a_id, DependencyType::DependsOn));
            }
            sbom
        };

        let cycles = |r: &ComplianceResult| {
            r.violations
                .iter()
                .find(|v| v.rule_id == "SBOM-CRA-CYCLES")
                .map(|v| v.severity)
        };

        let r = checker(ComplianceLevel::CraPhase2).check(&build(true));
        assert_eq!(
            cycles(&r),
            Some(ViolationSeverity::Warning),
            "cycles warn at the default class"
        );
        let r = checker(ComplianceLevel::CraPhase2)
            .with_product_class(CraProductClass::Critical)
            .check(&build(true));
        assert_eq!(
            cycles(&r),
            Some(ViolationSeverity::Error),
            "cycles error at Critical class"
        );
        let r = checker(ComplianceLevel::CraPhase2).check(&build(false));
        assert_eq!(cycles(&r), None, "acyclic graphs are silent");
    }

    /// A readiness standard that never evaluated the SBOM must expose
    /// NotApplicable and no score — is_compliant stays true by contract.
    #[test]
    fn not_applicable_result_has_no_score() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(!r.is_applicable(), "non-AI SBOM must be NotApplicable");
        assert!(
            matches!(r.applicability, Applicability::NotApplicable(_)),
            "applicability must carry the reason"
        );
        assert_eq!(r.score(), None, "unevaluated SBOMs have no score");
        assert!(r.is_compliant, "the N/A is_compliant contract is preserved");

        // An applicable run keeps a real score.
        let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
        assert!(r.is_applicable());
        assert!(r.score().is_some());
    }

    /// Info findings must not move the score: 5 errors alone and 5 errors +
    /// 20 infos once scored 16 vs 80 because infos inflated the
    /// denominator. Over the document alone, 5 errors now score
    /// floor(50 × 1 / 6) = 8.
    #[test]
    fn score_is_neutral_to_info_findings() {
        let violation = |severity| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: "x".to_string(),
            element: None,
            requirement: "x".to_string(),
            rule_id: "SBOM-CRA-GENERAL",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let errors_only = ComplianceResult::new(
            ComplianceLevel::NtiaMinimum,
            (0..5)
                .map(|_| violation(ViolationSeverity::Error))
                .collect(),
        );
        let with_infos = ComplianceResult::new(
            ComplianceLevel::NtiaMinimum,
            (0..5)
                .map(|_| violation(ViolationSeverity::Error))
                .chain((0..20).map(|_| violation(ViolationSeverity::Info)))
                .collect(),
        );
        assert_eq!(errors_only.score(), with_infos.score());
        assert_eq!(errors_only.score(), Some(8));
        let clean = ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new());
        assert_eq!(clean.score(), Some(100));
    }

    /// The score's boundaries: no finding, one and many warnings, one and
    /// many errors, and element counts up to `usize::MAX`.
    #[test]
    fn score_boundaries() {
        // No finding: 100 whatever was checked.
        for checked in [0, 1, 4, 500_001, usize::MAX] {
            assert_eq!(compliance_score(0, 0, checked), 100, "{checked}");
        }
        // Over the document and three components.
        assert_eq!(compliance_score(0, 1, 4), 90);
        assert_eq!(compliance_score(0, 3, 4), 78);
        assert_eq!(
            compliance_score(0, 4, 4),
            75,
            "one per element halves the band"
        );
        assert_eq!(compliance_score(0, 1_000, 4), 50);
        assert_eq!(compliance_score(1, 0, 4), 40);
        assert_eq!(compliance_score(1, 2, 4), 28);
        assert_eq!(compliance_score(4, 0, 4), 25);
        assert_eq!(compliance_score(1_000, 0, 4), 0);
        // Many failed checks: the band's floor, never below.
        assert_eq!(compliance_score(0, usize::MAX, 1), 50);
        assert_eq!(compliance_score(usize::MAX, usize::MAX, 1), 0);
        // A large SBOM: one finding barely moves the score.
        assert_eq!(compliance_score(0, 1, 500_001), 99);
        assert_eq!(compliance_score(1, 0, 500_001), 49);
        assert_eq!(compliance_score(0, 1, usize::MAX), 99);
        assert_eq!(compliance_score(1, 0, usize::MAX), 49);
        assert_eq!(compliance_score(0, usize::MAX, usize::MAX), 75);
        // One failed check per element of a large SBOM halves the band.
        assert_eq!(compliance_score(0, 500_001, 500_001), 75);
        assert_eq!(compliance_score(500_001, 0, 500_001), 25);
        // Nothing checked but a failure: the band's floor.
        assert_eq!(compliance_score(0, 1, 0), 50);
        assert_eq!(compliance_score(1, 0, 0), 0);
    }

    /// Over a grid of counts: every compliant result outscores every
    /// non-compliant one, an extra error or warning never raises the score,
    /// turning a warning into an error never does either, and checking more
    /// elements with the same failures never lowers it.
    #[test]
    fn score_orders_verdicts_and_is_monotone() {
        let counts = [0usize, 1, 2, 3, 5, 10, 49, 50, 99, 1_000, 500_000];
        let checked = [0usize, 1, 2, 4, 10, 100, 500_001];
        let mut lowest_compliant = u8::MAX;
        let mut highest_non_compliant = 0;
        for &c in &checked {
            for &e in &counts {
                for &w in &counts {
                    let score = compliance_score(e, w, c);
                    assert!(score <= 100);
                    if e == 0 {
                        assert!(score >= 50, "compliant ({e},{w},{c}) scored {score}");
                        assert_eq!(score == 100, w == 0, "({e},{w},{c})");
                        lowest_compliant = lowest_compliant.min(score);
                    } else {
                        assert!(score <= 49, "non-compliant ({e},{w},{c}) scored {score}");
                        highest_non_compliant = highest_non_compliant.max(score);
                    }
                    assert!(compliance_score(e + 1, w, c) <= score, "({e},{w},{c})");
                    assert!(compliance_score(e, w + 1, c) <= score, "({e},{w},{c})");
                    if w > 0 {
                        assert!(compliance_score(e + 1, w - 1, c) <= score, "({e},{w},{c})");
                    }
                    assert!(compliance_score(e, w, c + 1) >= score, "({e},{w},{c})");
                }
            }
        }
        assert!(lowest_compliant > highest_non_compliant);
    }

    /// What a finding weighs in the score: an Info finding nothing, a
    /// finding about one subject one check, an aggregate finding its failing
    /// items, and a coverage finding the items it does not cover.
    #[test]
    fn failed_checks_count_the_failing_items() {
        let finding = |severity, rule_id, counts| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: "x".to_string(),
            element: None,
            requirement: "x".to_string(),
            rule_id,
            component_id: None,
            counts,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let of = |affected, total| Some(ViolationCounts { affected, total });
        let w = ViolationSeverity::Warning;
        let e = ViolationSeverity::Error;
        assert_eq!(finding(w, "SBOM-NTIA-AUTHOR", None).failed_checks(), 1);
        assert_eq!(finding(e, "SBOM-NTIA-AUTHOR", None).failed_checks(), 1);
        assert_eq!(
            finding(ViolationSeverity::Info, "SBOM-CRA-ART-13-5", of(7, 10)).failed_checks(),
            0
        );
        assert_eq!(
            finding(e, "SBOM-BSI-TR-03183-2-LICENSE", of(7, 10)).failed_checks(),
            7
        );
        assert_eq!(
            finding(w, "SBOM-BSI-TR-03183-2-LICENSE", of(0, 10)).failed_checks(),
            1,
            "a finding fails at least one check"
        );
        for rule in COVERAGE_COUNT_RULE_IDS {
            assert!(rule_meta(rule).is_some(), "{rule} is registered");
            assert_eq!(finding(w, rule, of(3, 10)).failed_checks(), 7, "{rule}");
            assert_eq!(finding(w, rule, of(0, 10)).failed_checks(), 10, "{rule}");
            assert_eq!(finding(w, rule, of(10, 10)).failed_checks(), 1, "{rule}");
        }

        // The result sums them; Info findings stay out of the sum.
        let result = ComplianceResult::new(
            ComplianceLevel::Fsct,
            vec![
                finding(e, "SBOM-FSCT-AUTHOR", None),
                finding(w, "SBOM-FSCT-LICENSE-COVERAGE", of(1, 4)),
                finding(ViolationSeverity::Info, "SBOM-FSCT-SIGNATURE", None),
            ],
        )
        .with_elements_checked(5);
        assert_eq!(result.failed_checks(), 4);
        // floor(50 × 5 / (5 + 4)) = 27, in the non-compliant band.
        assert_eq!(result.score(), Some(27));
    }

    /// The elements a standard checks: the document, plus the components in
    /// its scope.
    #[test]
    fn elements_checked_follow_the_standards_scope() {
        use crate::model::{
            Component, ComponentType, CryptoAssetType, CryptoProperties, DocumentMetadata,
            MlModelInfo, NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for name in ["a", "b"] {
            sbom.add_component(
                Component::new(name.to_string(), format!("{name}-ref"))
                    .with_version("1.0".to_string())
                    .with_purl(format!("pkg:npm/{name}@1.0")),
            );
        }
        let mut file = Component::new("README".to_string(), "file-ref".to_string());
        file.component_type = ComponentType::File;
        sbom.add_component(file);
        let mut aes = Component::new("AES-256-GCM".to_string(), "aes-ref".to_string());
        aes.component_type = ComponentType::Cryptographic;
        aes.crypto_properties = Some(CryptoProperties::new(CryptoAssetType::Algorithm));
        sbom.add_component(aes);
        let mut model = Component::new("model".to_string(), "model-ref".to_string());
        model.component_type = ComponentType::MachineLearningModel;
        model.ml_model = Some(MlModelInfo::default());
        sbom.add_component(model);

        let checked = |level| checker(level).check(&sbom).elements_checked;
        // The document, the two libraries and the (package-scoped) model.
        assert_eq!(checked(ComplianceLevel::NtiaMinimum), 4);
        assert_eq!(checked(ComplianceLevel::CraPhase2), 4);
        assert_eq!(checked(ComplianceLevel::Fsct), 4);
        // The document and the algorithm.
        assert_eq!(checked(ComplianceLevel::Cnsa2), 2);
        assert_eq!(checked(ComplianceLevel::NistPqc), 2);
        // The document and the model.
        assert_eq!(checked(ComplianceLevel::EuAiAct), 2);
        assert_eq!(checked(ComplianceLevel::BsiSbomForAi), 2);
        // The document alone.
        assert_eq!(checked(ComplianceLevel::EuccSubstantial), 1);
        // A result built by hand checked the document.
        assert_eq!(
            ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new()).elements_checked,
            1
        );
        assert_eq!(
            ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new())
                .with_elements_checked(0)
                .elements_checked,
            1,
            "a standard always checks the document"
        );
    }

    /// A large SBOM with one gap: the old formula halved the score of a
    /// 500,000-component SBOM for one finding.
    #[test]
    fn one_gap_in_a_large_sbom_barely_moves_the_score() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let violation = |severity| Violation {
            severity,
            category: ViolationCategory::SupplierInfo,
            message: "x".to_string(),
            element: Some("lib".to_string()),
            requirement: "x".to_string(),
            rule_id: "SBOM-NTIA-SUPPLIER",
            component_id: Some("pkg:npm/lib@1.0".to_string()),
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let large = |severity| {
            ComplianceResult::new(ComplianceLevel::NtiaMinimum, vec![violation(severity)])
                .with_elements_checked(500_001)
        };
        assert_eq!(large(ViolationSeverity::Warning).score(), Some(99));
        assert_eq!(large(ViolationSeverity::Error).score(), Some(49));

        // Through the checker: a clean SBOM scores 100, and the component
        // count normalises its findings.
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let r = checker(ComplianceLevel::Minimum).check(&sbom);
        assert_eq!(r.elements_checked, 2);
        assert_eq!(
            r.score(),
            Some(compliance_score(
                r.violations
                    .iter()
                    .filter(|v| v.severity == ViolationSeverity::Error)
                    .map(Violation::failed_checks)
                    .sum(),
                r.violations
                    .iter()
                    .filter(|v| v.severity == ViolationSeverity::Warning)
                    .map(Violation::failed_checks)
                    .sum(),
                2,
            ))
        );
    }

    /// Payloads that predate the applicability field deserialize as
    /// Applicable.
    #[test]
    fn applicability_defaults_on_old_payloads() {
        let r = ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new());
        let mut json: serde_json::Value = serde_json::to_value(&r).unwrap();
        json.as_object_mut().unwrap().remove("applicability");
        let back: ComplianceResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.applicability, Applicability::Applicable);
    }

    fn passed_check() -> PassedCheck {
        PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"
                .to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: registry_refs("SBOM-PQC-009"),
        }
    }

    /// A result serializes `passed` only when it passed a check, and
    /// payloads without the field deserialize to no passes.
    #[test]
    fn passed_is_written_only_when_set_and_round_trips() {
        let none = ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new());
        let json = serde_json::to_value(&none).expect("serializes");
        assert!(json.get("passed").is_none(), "{json}");
        let back: ComplianceResult = serde_json::from_value(json).expect("deserializes");
        assert!(back.passed.is_empty());

        let one = none.with_passed(vec![passed_check()]);
        assert_eq!(one.info_count, 0, "a pass moves no count");
        assert!(one.is_compliant);
        let json = serde_json::to_value(&one).expect("serializes");
        assert_eq!(json["passed"][0]["rule_id"], "SBOM-PQC-009");
        assert_eq!(json["passed"][0]["sarif_rule_id"], "SBOM-PQC-009");
        assert!(json["passed"][0].get("finding_detail").is_none());
        assert!(
            json["passed"][0].get("severity").is_none(),
            "a pass has none"
        );
        let back: ComplianceResult = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back.passed, vec![passed_check()]);
    }

    /// The not-applicable constructor carries the reason and nothing else.
    #[test]
    fn not_applicable_constructor_has_no_findings() {
        let r = ComplianceResult::not_applicable(ComplianceLevel::BsiSbomForAi, "no ML content");
        assert_eq!(
            r.applicability,
            Applicability::NotApplicable("no ML content".to_string())
        );
        assert!(r.violations.is_empty() && r.passed.is_empty());
        assert!(r.is_compliant, "the N/A is_compliant contract is preserved");
        assert_eq!(r.score(), None);
    }

    /// The evaluation instant the remediation tests pin the checker to.
    fn remediation_test_clock() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid RFC 3339 instant")
            .with_timezone(&chrono::Utc)
    }

    /// An NTIA run over a one-component SBOM of the given format whose
    /// component names no supplier, returning the SBOM-NTIA-SUPPLIER finding.
    fn ntia_supplier_finding(format: SbomFormat, spec_version: &str) -> Violation {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.format = format;
        sbom.document.spec_version = spec_version.to_string();
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        ComplianceChecker::new(ComplianceLevel::NtiaMinimum)
            .with_as_of(remediation_test_clock())
            .check(&sbom)
            .violations
            .into_iter()
            .find(|v| v.rule_id == "SBOM-NTIA-SUPPLIER")
            .expect("a supplier-less component fails the NTIA supplier element")
    }

    /// Each violation's remediation names the fields of the format the SBOM
    /// was written in: SPDX inputs used to get CycloneDX field advice.
    #[test]
    fn remediation_follows_the_input_format() {
        for (format, spec_version, own, foreign) in [
            (
                SbomFormat::CycloneDx,
                "1.6",
                "CycloneDX: set components[].supplier.name",
                ["packages[].supplier", "suppliedBy"],
            ),
            (
                SbomFormat::Spdx,
                "2.3",
                "SPDX 2.x: set packages[].supplier",
                ["components[].supplier.name", "suppliedBy"],
            ),
            (
                SbomFormat::Spdx,
                "3.0.1",
                "SPDX 3.0: set suppliedBy",
                ["components[].supplier.name", "packages[].supplier"],
            ),
        ] {
            let v = ntia_supplier_finding(format.clone(), spec_version);
            let text = v
                .remediation
                .as_deref()
                .expect("check() stamps remediation");
            assert!(
                text.contains(own),
                "{format} {spec_version}: expected {own:?} in {text:?}"
            );
            for field in foreign {
                assert!(
                    !text.contains(field),
                    "{format} {spec_version}: {field:?} belongs to another format: {text:?}"
                );
            }
            assert_eq!(v.remediation_guidance(), text);
        }
    }

    /// JSON carries `remediation` on every violation and `help_uri` from the
    /// first standard reference that has a URL; `help_uri` is omitted when
    /// no reference has one.
    #[test]
    fn violation_json_carries_remediation_and_help_uri() {
        let v = ntia_supplier_finding(SbomFormat::CycloneDx, "1.6");
        let json = serde_json::to_value(&v).expect("violation serializes");
        assert_eq!(
            json["remediation"].as_str(),
            v.remediation.as_deref(),
            "remediation is serialized verbatim"
        );
        let first_uri = v.standard_refs.iter().find_map(|r| r.help_uri.as_deref());
        assert!(first_uri.is_some(), "NTIA references carry a URL");
        assert_eq!(json["help_uri"].as_str(), first_uri);

        // prEN 40000-1-3 has no public URL, so a prEN-only rule links the
        // page of its family, the CRA regulation, as `sbom-tools rules` and
        // the SARIF rule do — and still has a remediation.
        let hardware = Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::SupplierInfo,
            message: "m".to_string(),
            element: None,
            requirement: "r".to_string(),
            rule_id: "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
            component_id: None,
            counts: None,
            standard_refs: rule_meta("SBOM-CRA-PRE-8-RQ-02-PRODUCER")
                .expect("registered rule")
                .refs
                .iter()
                .map(|(kind, id)| StandardRef::new(*kind, *id))
                .collect(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let json = serde_json::to_value(&hardware).expect("violation serializes");
        assert_eq!(
            json["help_uri"], "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng",
            "no reference URL, the family's page: {json}"
        );
        assert_eq!(
            json["help_uri"].as_str(),
            rule_catalog_entry("SBOM-CRA-PRE-8-RQ-02-PRODUCER")
                .and_then(|entry| entry.help_uri)
                .as_deref(),
            "the rule catalogue's help URI"
        );
        assert!(
            json["remediation"]
                .as_str()
                .is_some_and(|r| r.contains("hardware component")),
            "unstamped violations still serialize the registry remediation: {json}"
        );
    }

    /// Payloads written before `remediation` and `help_uri` existed still
    /// deserialize; a payload that carries `remediation` keeps it.
    #[test]
    fn remediation_payloads_round_trip_and_old_payloads_deserialize() {
        let v = ntia_supplier_finding(SbomFormat::Spdx, "2.3");
        let mut json = serde_json::to_value(&v).expect("violation serializes");
        let back: Violation =
            serde_json::from_value(json.clone()).expect("current payload deserializes");
        assert_eq!(back.remediation, v.remediation);

        let object = json.as_object_mut().expect("violation is a JSON object");
        object.remove("remediation");
        object.remove("help_uri");
        let old: Violation = serde_json::from_value(json).expect("old payload deserializes");
        assert_eq!(old.remediation, None);
        assert_eq!(old.rule_id, "SBOM-NTIA-SUPPLIER");
        assert!(
            !old.remediation_guidance().is_empty(),
            "an old payload still renders registry remediation"
        );
    }

    /// `finding_detail` is written right after `component_id`, only when
    /// set, and round-trips; payloads without it deserialize to `None`.
    #[test]
    fn finding_detail_is_written_only_when_set_and_round_trips() {
        let mut v = ntia_supplier_finding(SbomFormat::CycloneDx, "1.6");
        let json = serde_json::to_value(&v).expect("violation serializes");
        assert!(
            json.get("finding_detail").is_none(),
            "omitted when None: {json}"
        );
        let old: Violation =
            serde_json::from_value(json).expect("payload without the field deserializes");
        assert_eq!(old.finding_detail, None);

        v.finding_detail = Some("CVE-2026-0001".to_string());
        let text = serde_json::to_string(&v).expect("violation serializes");
        assert!(
            text.contains(
                r#""component_id":"pkg:cargo/lib@1.0","finding_detail":"CVE-2026-0001","#
            ),
            "{text}"
        );
        let back: Violation = serde_json::from_str(&text).expect("payload deserializes");
        assert_eq!(back.finding_detail.as_deref(), Some("CVE-2026-0001"));
    }

    /// A violation built outside the checker has no input format, so its
    /// remediation lists every format's advice; an unregistered rule id has
    /// no registry guidance at all.
    #[test]
    fn unstamped_remediation_lists_every_format() {
        let unstamped = |rule_id: &'static str| Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::SupplierInfo,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id,
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let guidance = unstamped("SBOM-CRA-COMPONENT-SUPPLIER")
            .remediation_guidance()
            .into_owned();
        for format in RemediationFormat::ALL {
            assert!(
                guidance.contains(&format!("{}: ", format.label())),
                "{format:?} advice missing from {guidance:?}"
            );
        }
        assert_eq!(
            unstamped("SBOM-NOT-A-RULE").remediation_guidance(),
            REMEDIATION_UNREGISTERED
        );
    }

    /// A pinned evaluation clock makes deadline-sensitive checks
    /// deterministic: Art. 14 severity flips across 2026-09-11, and EUCC
    /// certificate expiry evaluates against the pinned instant.
    #[test]
    fn as_of_clock_pins_deadline_checks() {
        use crate::model::{Component, CraSidecarMetadata, DocumentMetadata, NormalizedSbom};
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let ts = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };

        // Art. 14: Info before the 2026-09-11 application date, stronger after.
        let art14_severity = |as_of: &str| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2)
                .with_as_of(ts(as_of))
                .check(&sbom)
                .violations
                .iter()
                .find(|v| v.requirement.contains("Art. 14(2)(a)"))
                .map(|v| v.severity)
        };
        assert_eq!(
            art14_severity("2026-01-01T00:00:00Z"),
            Some(ViolationSeverity::Info),
            "pre-deadline Art. 14 findings are informational"
        );
        assert_eq!(
            art14_severity("2027-01-01T00:00:00Z"),
            Some(ViolationSeverity::Warning),
            "post-deadline Art. 14 findings escalate"
        );

        // EUCC certificate expiry against the pinned clock.
        let sidecar = CraSidecarMetadata {
            eucc_protection_profile_id: Some("PP-1".to_string()),
            eucc_target_of_evaluation: Some("TOE-1".to_string()),
            eucc_itsef_identifier: Some("ITSEF-1".to_string()),
            eucc_valid_until: Some(ts("2027-06-01T00:00:00Z")),
            ..Default::default()
        };
        let eucc_expired = |as_of: &str| {
            ComplianceChecker::new(ComplianceLevel::EuccSubstantial)
                .with_sidecar(sidecar.clone())
                .with_as_of(ts(as_of))
                .check(&sbom)
                .violations
                .iter()
                .any(|v| {
                    v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-EUCC-VALIDITY"
                })
        };
        assert!(
            !eucc_expired("2027-01-01T00:00:00Z"),
            "certificate valid at the pinned instant"
        );
        assert!(
            eucc_expired("2028-01-01T00:00:00Z"),
            "certificate expired at the pinned instant"
        );
    }

    /// CRA SBOM freshness: a creation timestamp after the evaluation instant
    /// gave a negative age and passed as fresh (review finding V14). It warns
    /// like a missing timestamp now, in both CRA phases, and the document
    /// ages normally once the clock passes its timestamp.
    #[test]
    fn cra_freshness_flags_a_future_timestamp() {
        use crate::model::{Component, DocumentMetadata, NormalizedSbom};
        let ts = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .expect("test timestamp must parse")
                .with_timezone(&chrono::Utc)
        };
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.document.created = ts("2026-12-01T00:00:00Z");
        sbom.add_component(
            Component::new("lib".to_string(), "lib@1".to_string())
                .with_version("1.0".to_string())
                .with_purl("pkg:cargo/lib@1.0".to_string()),
        );
        let freshness = |level: ComplianceLevel, as_of: &str| -> Vec<(ViolationSeverity, String)> {
            ComplianceChecker::new(level)
                .with_as_of(ts(as_of))
                .check(&sbom)
                .violations
                .into_iter()
                .filter(|v| v.rule_id == "SBOM-CRA-SBOM-FRESHNESS")
                .map(|v| (v.severity, v.message))
                .collect()
        };
        for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
            let future = freshness(level, "2026-10-12T00:00:00Z");
            assert_eq!(future.len(), 1, "{level:?}: {future:?}");
            assert_eq!(future[0].0, ViolationSeverity::Warning, "{level:?}");
            assert!(
                future[0].1.contains("later than the evaluation instant"),
                "{level:?}: {}",
                future[0].1
            );
            // Two weeks after its timestamp the document is fresh...
            assert!(
                freshness(level, "2026-12-15T00:00:00Z").is_empty(),
                "{level:?}"
            );
            // ...and 120 days after it, stale.
            let stale = freshness(level, "2027-03-31T00:00:00Z");
            assert_eq!(stale.len(), 1, "{level:?}: {stale:?}");
            assert!(
                stale[0].1.contains("120 days old"),
                "{level:?}: {}",
                stale[0].1
            );
        }
    }

    #[test]
    fn test_compliance_level_names() {
        assert_eq!(ComplianceLevel::Minimum.name(), "Minimum");
        assert_eq!(ComplianceLevel::NtiaMinimum.name(), "NTIA Minimum Elements");
        assert_eq!(ComplianceLevel::CraPhase1.name(), "EU CRA Phase 1 (2026)");
        assert_eq!(ComplianceLevel::CraPhase2.name(), "EU CRA Phase 2 (2027)");
        assert_eq!(ComplianceLevel::NistSsdf.name(), "NIST SSDF (SP 800-218)");
        assert_eq!(ComplianceLevel::Eo14028.name(), "EO 14028 Section 4");
    }

    #[test]
    fn test_nist_ssdf_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let checker = checker(ComplianceLevel::NistSsdf);
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
        let checker = checker(ComplianceLevel::Eo14028);
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
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            },
            Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: "Warning 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            },
            Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: "Info 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
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
        let checker = checker(ComplianceLevel::Cnsa2);
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
        let checker = checker(ComplianceLevel::Cnsa2);
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
        let checker = checker(ComplianceLevel::NistPqc);
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

    /// A plain SBOM with NO cryptographic inventory must NOT pass PQC/CNSA2 —
    /// that was a vacuous false-pass. It now fails with an "inventory absent"
    /// Error.
    #[test]
    fn crypto_standards_fail_on_empty_inventory() {
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(crate::model::Component::new(
            "lodash".to_string(),
            "lodash@4.17.21".to_string(),
        ));
        for level in [ComplianceLevel::NistPqc, ComplianceLevel::Cnsa2] {
            let result = checker(level).check(&sbom);
            assert!(
                !result.is_compliant,
                "{level:?} must not report compliant with no crypto inventory"
            );
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.severity == ViolationSeverity::Error && v.rule_id.ends_with("-000")),
                "{level:?} must emit an inventory-absent error"
            );
        }
    }

    /// A classical quantum-vulnerable algorithm (RSA/ECDSA/DH) must fail NIST
    /// PQC even when nistQuantumSecurityLevel is UNSET (real CBOMs rarely set
    /// it to an explicit 0).
    #[test]
    fn pqc_flags_classical_crypto_with_unset_quantum_level() {
        for family in ["RSA", "ECDSA", "ECDH", "DH", "DSA"] {
            let sbom = make_crypto_sbom(&[("classical", family, None, None)]);
            let result = checker(ComplianceLevel::NistPqc).check(&sbom);
            assert!(
                !result.is_compliant,
                "{family} with unset quantum level must fail PQC"
            );
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-001"),
                "{family} must raise the quantum-vulnerable error"
            );
        }
    }

    /// SHA-224 and SHA-256 must fail CNSA 2.0 whether the size is in the family
    /// string or the parameter (previously only family "SHA-2"/param "256"
    /// was caught).
    #[test]
    fn cnsa2_flags_weak_sha2_in_either_encoding() {
        for (family, param) in [
            ("SHA-256", None),
            ("SHA-224", None),
            ("SHA-2", Some("256")),
            ("SHA-2", Some("224")),
        ] {
            let sbom = make_crypto_sbom(&[("hash", family, param, None)]);
            let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
                "{family}/{param:?} must fail CNSA 2.0 hash gate"
            );
        }
        // SHA-384 passes the hash gate.
        let ok = make_crypto_sbom(&[("hash", "SHA-384", None, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
            "SHA-384 must not trip the hash gate"
        );
    }

    #[test]
    fn test_pqc_approved_algorithm_is_a_passed_check() {
        let sbom = make_crypto_sbom(&[("ML-DSA-65", "ML-DSA", Some("65"), Some(3))]);
        let checker = checker(ComplianceLevel::NistPqc);
        let result = checker.check(&sbom);
        assert!(
            result
                .passed
                .iter()
                .any(|p| p.rule_id == "SBOM-PQC-009" && p.message.contains("approved")),
            "PQC should report ML-DSA-65 as approved: {:?}",
            result.passed
        );
        assert_eq!(result.info_count, 0, "an approval is no Info violation");
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-009"),
            "{:?}",
            result.violations
        );
        let pass = &result.passed[0];
        assert!(
            !pass.standard_refs.is_empty(),
            "check() back-fills the registry references of a pass"
        );
    }

    /// CNSA 2.0 is an exclusive allowlist: everything recognized but not on
    /// it must Error — broken hashes, classical PK (including the families the
    /// old blocklist missed: Ed25519/ECIES), non-CNSA symmetric ciphers,
    /// sub-1024 or parameterless ML-KEM, and round-3 PQC names.
    #[test]
    fn cnsa2_allowlist_rejects_non_cnsa_algorithms() {
        for (family, param, expected_rule) in [
            ("SHA-1", None, "SBOM-CNSA2-ALG-005"),
            ("DES", None, "SBOM-CNSA2-ALG-005"),
            ("ChaCha20", None, "SBOM-CNSA2-ALG-008"),
            ("Ed25519", None, "SBOM-CNSA2-ALG-006"),
            ("ECIES", None, "SBOM-CNSA2-ALG-006"),
            ("EC", None, "SBOM-CNSA2-ALG-006"),
            ("Kyber", Some("768"), "SBOM-CNSA2-ALG-003"),
            ("ML-KEM-768", None, "SBOM-CNSA2-ALG-003"),
            ("ML-KEM", None, "SBOM-CNSA2-ALG-003"), // absent parameter set
            ("ML-DSA", Some("65"), "SBOM-CNSA2-ALG-004"),
            ("SLH-DSA", None, "SBOM-CNSA2-ALG-008"),
            ("SHA-3", Some("256"), "SBOM-CNSA2-ALG-008"),
            ("AES-128", None, "SBOM-CNSA2-ALG-001"), // size in family string
        ] {
            let sbom = make_crypto_sbom(&[("asset", family, param, None)]);
            let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                result.violations.iter().any(|v| {
                    v.severity == ViolationSeverity::Error && v.rule_id == expected_rule
                }),
                "{family}/{param:?} must fail CNSA 2.0 with {expected_rule}; got {:?}",
                result
                    .violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
            assert!(!result.is_compliant, "{family} must not be CNSA compliant");
        }
    }

    /// The full CNSA 2.0 suite passes the allowlist with zero errors:
    /// AES-256, SHA-384, ML-KEM-1024, ML-DSA-87, and SP 800-208 LMS.
    #[test]
    fn cnsa2_allowlist_accepts_full_cnsa_suite() {
        let sbom = make_crypto_sbom(&[
            ("AES-256-GCM", "AES", Some("256"), Some(1)),
            ("SHA-384", "SHA-2", Some("384"), Some(2)),
            ("ML-KEM-1024", "ML-KEM", Some("1024"), Some(5)),
            ("ML-DSA-87", "ML-DSA", Some("87"), Some(5)),
            ("LMS", "LMS", None, Some(5)),
        ]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        let errors: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "full CNSA 2.0 suite must have zero errors, got {:?}",
            errors
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        assert!(result.is_compliant);
    }

    /// Unrecognizable algorithms fail CNSA 2.0 closed: it is an allowlist,
    /// so an algorithm that cannot be identified cannot be shown to comply.
    /// They also do not count as inventory, so a CBOM of unknowns fails the
    /// CNSA2-000 gate.
    #[test]
    fn cnsa2_unknown_algorithm_fails_closed() {
        let sbom = make_crypto_sbom(&[("mystery", "proprietary-frobnicator", None, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-CNSA2-ALG-UNKNOWN"
            }),
            "unknown algorithm must fail closed with SBOM-CNSA2-ALG-UNKNOWN"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-000"),
            "an unidentifiable asset must not satisfy the inventory gate"
        );
        assert!(!result.is_compliant);
    }

    /// Under NIST PQC an unrecognizable algorithm warns (it cannot be
    /// verified) instead of passing silently, and does not count as
    /// inventory.
    #[test]
    fn pqc_unknown_algorithm_warns_and_is_not_inventory() {
        let sbom = make_crypto_sbom(&[("mystery", "proprietary-frobnicator", None, Some(5))]);
        let result = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.severity == ViolationSeverity::Warning && v.rule_id == "SBOM-PQC-ALG-UNKNOWN"
            }),
            "unknown algorithm must warn with SBOM-PQC-ALG-UNKNOWN even when it declares a level"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-000"),
            "an unidentifiable asset must not satisfy the inventory gate"
        );
    }

    /// A CycloneDX 1.6-style asset (no algorithmFamily) must still be
    /// classified — via OID, or via the component name when both family and
    /// OID are absent.
    #[test]
    fn cnsa2_classifies_without_algorithm_family() {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        };
        let mut sbom = NormalizedSbom::default();
        // RSA via OID only.
        let mut rsa = crate::model::Component::new("RSA-2048".into(), "algo-1".into());
        rsa.component_type = ComponentType::Cryptographic;
        rsa.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm)
                .with_oid("1.2.840.113549.1.1.1".into())
                .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::Pke)),
        );
        sbom.add_component(rsa);
        // AES-128 via name only.
        let mut aes = crate::model::Component::new("AES-128-CBC".into(), "algo-2".into());
        aes.component_type = ComponentType::Cryptographic;
        aes.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm)
                .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::BlockCipher)),
        );
        sbom.add_component(aes);

        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006" && v.message.contains("RSA")),
            "RSA must be flagged via OID without algorithmFamily"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-001" && v.message.contains("AES-128")),
            "AES-128 must be flagged via name without algorithmFamily/OID"
        );

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-001" && v.message.contains("RSA")),
            "PQC must flag OID-only RSA as quantum-vulnerable"
        );
    }

    /// Spelling variants of broken algorithms must not escape SP 800-131A
    /// detection under PQC.
    #[test]
    fn pqc_flags_broken_spelling_variants() {
        for family in ["SHA1", "TDES", "ARC4"] {
            let sbom = make_crypto_sbom(&[("legacy", family, None, None)]);
            let result = checker(ComplianceLevel::NistPqc).check(&sbom);
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-005"),
                "{family} must fail SP 800-131A broken-algorithm detection"
            );
        }
        // Silent case: a healthy modern hash raises no broken-algorithm error.
        let ok = make_crypto_sbom(&[("hash", "SHA-384", None, None)]);
        let result = checker(ComplianceLevel::NistPqc).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-005"),
            "SHA-384 must not be reported broken"
        );
    }

    fn make_protocol_sbom(version: &str, suite_name: &str, suite_algos: &[&str]) -> NormalizedSbom {
        use crate::model::{
            CipherSuite, ComponentType, CryptoAssetType, CryptoProperties, ProtocolProperties,
            ProtocolType,
        };
        let mut sbom = NormalizedSbom::default();
        let mut c = crate::model::Component::new("tls-endpoint".into(), "proto-1".into());
        c.component_type = ComponentType::Cryptographic;
        c.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
                ProtocolProperties::new(ProtocolType::Tls)
                    .with_version(version.to_string())
                    .with_cipher_suites(vec![CipherSuite {
                        name: Some(suite_name.to_string()),
                        algorithms: suite_algos.iter().map(ToString::to_string).collect(),
                        ..CipherSuite::default()
                    }]),
            ),
        );
        sbom.add_component(c);
        sbom
    }

    /// A TLS 1.0 protocol asset with a legacy cipher suite must fail BOTH
    /// standards — previously protocols satisfied the inventory gate but
    /// received zero evaluation.
    #[test]
    fn protocol_tls10_rc4_fails_both_standards() {
        let sbom = make_protocol_sbom("1.0", "TLS_RSA_WITH_RC4_128_SHA", &[]);

        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(!cnsa.is_compliant, "TLS 1.0 must fail CNSA 2.0");
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
            "TLS 1.0 must trip the CNSA TLS-1.3 version gate"
        );
        assert!(
            cnsa.violations.iter().any(|v| {
                v.rule_id == "SBOM-CNSA2-PROTO-002"
                    && v.message.contains("RC4")
                    && v.message.contains("RSA")
            }),
            "cipher-suite scan must flag RC4 and RSA; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
        );

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(!pqc.is_compliant, "TLS 1.0 must fail PQC readiness");
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
            "TLS 1.0 must trip the PQC minimum-version gate"
        );
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-PROTO-002" && v.message.contains("broken")),
            "cipher-suite scan must flag broken algorithms under PQC"
        );
    }

    /// Silent case: TLS 1.3 with a CNSA 2.0 cipher suite passes both
    /// standards' protocol checks.
    #[test]
    fn protocol_tls13_cnsa_suite_passes() {
        let sbom = make_protocol_sbom("1.3", "TLS_AES_256_GCM_SHA384", &[]);

        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            !cnsa
                .violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-CNSA2-PROTO")),
            "TLS 1.3 + CNSA suite must raise no CNSA protocol violations; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
        );
        assert!(cnsa.is_compliant);

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            !pqc.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-PQC-PROTO")),
            "TLS 1.3 + CNSA suite must raise no PQC protocol violations"
        );
    }

    /// TLS 1.2 fails the CNSA 2.0 TLS-1.3 gate but passes the PQC
    /// minimum-version gate (>= 1.2).
    #[test]
    fn protocol_tls12_fails_cnsa_only() {
        let sbom = make_protocol_sbom("1.2", "TLS_AES_256_GCM_SHA384", &[]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
            "TLS 1.2 must fail the CNSA 2.0 version gate"
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            !pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
            "TLS 1.2 must pass the PQC minimum-version gate"
        );
    }

    /// Cipher-suite algorithm bom-refs are resolved through the SBOM index
    /// and classified — even when the ref string itself is opaque.
    #[test]
    fn protocol_resolves_cipher_suite_algorithm_refs() {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        };
        let mut sbom = make_protocol_sbom("1.3", "OPAQUE_SUITE_1", &["suite-algo-7"]);
        let mut rsa = crate::model::Component::new("legacy-kx".into(), "suite-algo-7".into());
        rsa.component_type = ComponentType::Cryptographic;
        rsa.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Pke).with_algorithm_family("RSA".into()),
            ),
        );
        sbom.add_component(rsa);

        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| { v.rule_id == "SBOM-CNSA2-PROTO-002" && v.message.contains("RSA") }),
            "resolved suite algorithm ref must be classified; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
        );
    }

    fn make_cert_sbom(sig_ref: &str, algo_family: Option<&str>) -> NormalizedSbom {
        use crate::model::{
            AlgorithmProperties, CertificateProperties, ComponentType, CryptoAssetType,
            CryptoPrimitive, CryptoProperties,
        };
        let mut sbom = NormalizedSbom::default();
        if let Some(family) = algo_family {
            let mut algo = crate::model::Component::new("sig-algorithm".into(), sig_ref.into());
            algo.component_type = ComponentType::Cryptographic;
            algo.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                    AlgorithmProperties::new(CryptoPrimitive::Signature)
                        .with_algorithm_family(family.to_string()),
                ),
            );
            sbom.add_component(algo);
        }
        let mut cert = crate::model::Component::new("server-cert".into(), "cert-1".into());
        cert.component_type = ComponentType::Cryptographic;
        cert.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Certificate).with_certificate_properties(
                CertificateProperties::new().with_signature_algorithm_ref(sig_ref.to_string()),
            ),
        );
        sbom.add_component(cert);
        sbom
    }

    /// CERT-001 must resolve an OPAQUE signature-algorithm bom-ref through
    /// the index to the referenced algorithm — the old substring heuristic
    /// ("rsa" in the ref string) gave opaque refs zero checks.
    #[test]
    fn cnsa2_cert_resolves_opaque_signature_ref() {
        let sbom = make_cert_sbom("sig-algo-42", Some("RSA"));
        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
            "opaque ref resolving to RSA must fire CERT-001; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-CERT-001"),
            "opaque ref resolving to RSA must fire the PQC certificate rule"
        );
    }

    /// Silent case: a certificate signed with ML-DSA-87 passes CERT-001, and
    /// an unresolvable ref still gets the word-boundary fallback on the raw
    /// ref string.
    #[test]
    fn cnsa2_cert_approved_and_fallback_cases() {
        let ok = make_cert_sbom("sig-algo-42", Some("ML-DSA-87"));
        let result = checker(ComplianceLevel::Cnsa2).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
            "ML-DSA-87-signed certificate must pass CERT-001"
        );

        // Unresolvable ref: fall back to token-matching the ref string.
        let dangling = make_cert_sbom("crypto/algorithm/ecdsa-p256", None);
        let result = checker(ComplianceLevel::Cnsa2).check(&dangling);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
            "unresolvable ECDSA-named ref must still fire CERT-001 via token fallback"
        );
    }

    /// Key material alone must not satisfy the crypto-inventory gate — it
    /// receives no CNSA 2.0 evaluation.
    #[test]
    fn cnsa2_key_material_alone_does_not_satisfy_inventory_gate() {
        use crate::model::{
            ComponentType, CryptoAssetType, CryptoMaterialType, CryptoProperties,
            RelatedCryptoMaterialProperties,
        };
        let mut sbom = NormalizedSbom::default();
        let mut key = crate::model::Component::new("some-key".into(), "key-1".into());
        key.component_type = ComponentType::Cryptographic;
        key.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
                .with_related_crypto_material_properties(
                    RelatedCryptoMaterialProperties::new(CryptoMaterialType::PublicKey)
                        .with_size(2048),
                ),
        );
        sbom.add_component(key);

        let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-000"),
            "unevaluable key material must not satisfy the CNSA2-000 inventory gate"
        );
        assert!(!result.is_compliant);
    }

    /// Compound algorithmFamily spellings ("DES-CBC", "AES-128-CBC") must
    /// fail both standards by their base algorithm — previously they
    /// classified Unknown and produced only a Warning (false pass).
    #[test]
    fn compound_family_spellings_fail_both_standards() {
        let sbom = make_crypto_sbom(&[("legacy-cipher", "DES-CBC", None, None)]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(!cnsa.is_compliant, "DES-CBC must not be CNSA 2.0 compliant");
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-005" && v.message.contains("DES")),
            "DES-CBC must fire the broken-algorithm rule; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations.iter().any(|v| v.rule_id == "SBOM-PQC-005"),
            "DES-CBC must fire SP 800-131A under PQC"
        );

        let sbom = make_crypto_sbom(&[("aes-cbc", "AES-128-CBC", None, None)]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-001" && v.message.contains("AES-128")),
            "AES-128-CBC must fire the AES-256-only rule"
        );

        // Silent case: a compound spelling of an approved algorithm passes.
        let ok = make_crypto_sbom(&[("aead", "AES-256-GCM", None, None)]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&ok);
        assert!(
            !cnsa
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error),
            "AES-256-GCM must pass the CNSA 2.0 allowlist; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
    }

    /// Truncated SHA-2 (SHA-512/256, SHA-512/224) must fail the CNSA 2.0
    /// hash gate by its truncated output size — previously it classified
    /// as full SHA-512 and was falsely Approved.
    #[test]
    fn cnsa2_flags_truncated_sha2_variants() {
        for family in ["SHA-512/256", "SHA-512/224"] {
            let sbom = make_crypto_sbom(&[("hash", family, None, None)]);
            let result = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
                "{family} must fail the CNSA 2.0 hash gate; got {:?}",
                result
                    .violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
        }
        // Silent case: full SHA-512 stays approved.
        let ok = make_crypto_sbom(&[("hash", "SHA-512", None, None)]);
        let result = checker(ComplianceLevel::Cnsa2).check(&ok);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-ALG-002"),
            "SHA-512 must not trip the hash gate"
        );
    }

    /// The name-only fallback must report the most severe token: a
    /// hash-first name like "sha384-rsa-signature" is quantum-vulnerable
    /// RSA, not CNSA-approved SHA-384 (previously the first token won and
    /// both standards passed).
    #[test]
    fn name_fallback_reports_most_severe_token() {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        };
        for name in ["sha384-rsa-signature", "rsa-sha384-signature"] {
            let mut sbom = NormalizedSbom::default();
            let mut c = crate::model::Component::new(name.into(), "algo-1".into());
            c.component_type = ComponentType::Cryptographic;
            c.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                    AlgorithmProperties::new(CryptoPrimitive::Signature),
                ),
            );
            sbom.add_component(c);

            let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                cnsa.violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006" && v.message.contains("RSA")),
                "'{name}' must be flagged quantum-vulnerable under CNSA 2.0; got {:?}",
                cnsa.violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
            let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
            assert!(
                pqc.violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-PQC-001" && v.message.contains("RSA")),
                "'{name}' must be flagged quantum-vulnerable under PQC"
            );
        }
    }

    /// A certificate whose signature-algorithm ref cannot be resolved or
    /// classified fails CNSA 2.0 closed and warns under PQC — previously it
    /// counted as evaluated and passed silently (certificate-only CBOMs
    /// reported 100% compliant).
    #[test]
    fn cert_unknown_signature_ref_is_flagged_by_both_standards() {
        let sbom = make_cert_sbom("sig-algo-42", None);

        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations.iter().any(|v| {
                v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-CNSA2-CERT-UNKNOWN"
            }),
            "opaque dangling sig ref must fail CNSA 2.0 closed; got {:?}",
            cnsa.violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );
        assert!(
            !cnsa
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-CERT-001"),
            "an unverifiable ref is CERT-UNKNOWN, not CERT-001"
        );

        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations.iter().any(|v| {
                v.severity == ViolationSeverity::Warning && v.rule_id == "SBOM-PQC-CERT-UNKNOWN"
            }),
            "opaque dangling sig ref must warn under PQC"
        );

        // Silent case: a resolvable ML-DSA-87 signature produces neither
        // the Warning nor an Error.
        let ok = make_cert_sbom("sig-algo-42", Some("ML-DSA-87"));
        for level in [ComplianceLevel::Cnsa2, ComplianceLevel::NistPqc] {
            let result = checker(level).check(&ok);
            assert!(
                !result
                    .violations
                    .iter()
                    .any(|v| v.rule_id.ends_with("CERT-UNKNOWN")),
                "{level:?}: resolvable approved sig ref must not warn"
            );
        }
    }

    /// A protocol asset with nothing evaluable (SSH, no version, no cipher
    /// suites, no refs) is flagged — an Error under CNSA 2.0, a Warning under
    /// PQC — instead of silently counting as evaluated and suppressing the
    /// no-inventory gate.
    #[test]
    fn protocol_without_evidence_is_flagged_by_both_standards() {
        use crate::model::{
            ComponentType, CryptoAssetType, CryptoProperties, ProtocolProperties, ProtocolType,
        };
        let mut sbom = NormalizedSbom::default();
        let mut c = crate::model::Component::new("ssh-endpoint".into(), "proto-1".into());
        c.component_type = ComponentType::Cryptographic;
        c.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Protocol)
                .with_protocol_properties(ProtocolProperties::new(ProtocolType::Ssh)),
        );
        sbom.add_component(c);

        for (level, rule, severity) in [
            (
                ComplianceLevel::Cnsa2,
                "SBOM-CNSA2-PROTO-UNKNOWN",
                ViolationSeverity::Error,
            ),
            (
                ComplianceLevel::NistPqc,
                "SBOM-PQC-PROTO-UNKNOWN",
                ViolationSeverity::Warning,
            ),
        ] {
            let result = checker(level).check(&sbom);
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| v.severity == severity && v.rule_id == rule),
                "{level:?}: evidence-free protocol must be flagged with {rule}; got {:?}",
                result
                    .violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
        }

        // Silent case: a TLS 1.3 protocol with a classifiable suite raises
        // no PROTO-UNKNOWN warning.
        let ok = make_protocol_sbom("1.3", "TLS_AES_256_GCM_SHA384", &[]);
        for level in [ComplianceLevel::Cnsa2, ComplianceLevel::NistPqc] {
            let result = checker(level).check(&ok);
            assert!(
                !result
                    .violations
                    .iter()
                    .any(|v| v.rule_id.ends_with("PROTO-UNKNOWN")),
                "{level:?}: evaluable protocol must not warn"
            );
        }
    }

    /// An IKEv2 protocol whose transform refs are all opaque and
    /// unresolvable is flagged by both standards (Error under CNSA 2.0,
    /// Warning under PQC) — previously it counted as evaluated while
    /// receiving zero effective checks (vacuous 100% compliant CBOMs).
    #[test]
    fn ikev2_opaque_transform_refs_are_flagged_by_both_standards() {
        use crate::model::{
            ComponentType, CryptoAssetType, CryptoProperties, Ikev2TransformTypes,
            ProtocolProperties, ProtocolType,
        };
        let mut sbom = NormalizedSbom::default();
        let mut c = crate::model::Component::new("ipsec-tunnel".into(), "proto-1".into());
        c.component_type = ComponentType::Cryptographic;
        c.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
                ProtocolProperties::new(ProtocolType::Ikev2).with_ikev2_transform_types(
                    Ikev2TransformTypes {
                        encr: vec!["transform-encr-7".into()],
                        prf: vec!["transform-prf-3".into()],
                        integ: vec!["transform-integ-2".into()],
                        ke: vec!["transform-ke-9".into()],
                        auth: vec![],
                        transforms: vec![],
                    },
                ),
            ),
        );
        sbom.add_component(c);

        for (level, rule, severity) in [
            (
                ComplianceLevel::Cnsa2,
                "SBOM-CNSA2-PROTO-UNKNOWN",
                ViolationSeverity::Error,
            ),
            (
                ComplianceLevel::NistPqc,
                "SBOM-PQC-PROTO-UNKNOWN",
                ViolationSeverity::Warning,
            ),
        ] {
            let result = checker(level).check(&sbom);
            assert!(
                result.violations.iter().any(|v| {
                    v.severity == severity
                        && v.rule_id == rule
                        && v.message.contains("transform-encr-7")
                }),
                "{level:?}: opaque IKEv2 transforms must be flagged with {rule}; got {:?}",
                result
                    .violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// The CNSA 2.0 TLS gate must accept legitimate spellings of TLS 1.3
    /// and share version parsing with the PQC gate, so the two standards
    /// agree on the same input (previously "TLSv1.3" was a false Error and
    /// "TLSv1.0" silently passed the PQC gate).
    #[test]
    fn tls_version_spellings_parse_tolerantly() {
        for version in ["TLSv1.3", "tls1.3", "1.3.0", " 1.3", "v1.3"] {
            let sbom = make_protocol_sbom(version, "TLS_AES_256_GCM_SHA384", &[]);
            let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                !cnsa
                    .violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
                "'{version}' must count as TLS 1.3; got {:?}",
                cnsa.violations
                    .iter()
                    .map(|v| v.message.clone())
                    .collect::<Vec<_>>()
            );
        }
        // Spelled-out old versions now fail BOTH gates.
        let sbom = make_protocol_sbom("TLSv1.0", "TLS_AES_256_GCM_SHA384", &[]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
            "TLSv1.0 must fail the CNSA 2.0 version gate"
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PQC-PROTO-001"),
            "TLSv1.0 must fail the PQC minimum-version gate (previously silent)"
        );
        // Unparseable versions: strict Error under the CNSA 2.0 allowlist,
        // cannot-verify Warning under PQC.
        let sbom = make_protocol_sbom("quantum-safe", "TLS_AES_256_GCM_SHA384", &[]);
        let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
        assert!(
            cnsa.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-001"),
            "an unparseable version cannot affirm TLS 1.3"
        );
        let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
        assert!(
            pqc.violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Warning
                    && v.rule_id == "SBOM-PQC-PROTO-UNKNOWN"
                    && v.message.contains("quantum-safe")),
            "an unparseable version must be a cannot-verify Warning under PQC"
        );
    }

    /// Reference resolution must carry the referenced asset's declared
    /// classicalSecurityLevel: an AES asset whose key size is declared only
    /// via classicalSecurityLevel=256 is Approved when evaluated directly,
    /// so it must also be Approved when reached through a protocol's
    /// cryptoRefArray (previously a false PROTO-002).
    #[test]
    fn protocol_ref_resolution_keeps_declared_security_level() {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
            ProtocolProperties, ProtocolType,
        };
        let make = |classical_level: u32| {
            let mut sbom = NormalizedSbom::default();
            let mut aes = crate::model::Component::new("aes-gcm-cipher".into(), "algo-aes".into());
            aes.component_type = ComponentType::Cryptographic;
            aes.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                    AlgorithmProperties::new(CryptoPrimitive::Ae)
                        .with_algorithm_family("AES".into())
                        .with_classical_security_level(classical_level)
                        .with_nist_quantum_security_level(5),
                ),
            );
            sbom.add_component(aes);
            let mut proto = crate::model::Component::new("tls-endpoint".into(), "proto-1".into());
            proto.component_type = ComponentType::Cryptographic;
            proto.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Protocol).with_protocol_properties(
                    ProtocolProperties::new(ProtocolType::Tls)
                        .with_version("1.3".into())
                        .with_crypto_ref_array(vec!["algo-aes".into()]),
                ),
            );
            sbom.add_component(proto);
            sbom
        };

        // AES-256 via classicalSecurityLevel only: both the direct and the
        // referenced evaluation must agree (zero errors).
        let result = checker(ComplianceLevel::Cnsa2).check(&make(256));
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error),
            "AES with classicalSecurityLevel=256 must pass via ref too; got {:?}",
            result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.message.clone()))
                .collect::<Vec<_>>()
        );

        // Firing counterpart: a declared 128-bit level fails through the
        // ref path exactly as it does directly.
        let result = checker(ComplianceLevel::Cnsa2).check(&make(128));
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CNSA2-PROTO-002" && v.message.contains("AES")),
            "AES-128 referenced from a protocol must still fire PROTO-002"
        );
    }

    /// National quantum-vulnerable algorithms (SM2 / GOST R 34.10 /
    /// brainpool) must fail PQC and CNSA 2.0 as classical crypto instead of
    /// producing only an unclassifiable Warning.
    #[test]
    fn national_algorithms_fail_both_standards() {
        for family in ["SM2", "GOST R 34.10", "brainpoolP256r1"] {
            let sbom = make_crypto_sbom(&[("national-sig", family, None, None)]);
            let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
            assert!(
                pqc.violations
                    .iter()
                    .any(|v| v.severity == ViolationSeverity::Error && v.rule_id == "SBOM-PQC-001"),
                "{family} must fire the quantum-vulnerable rule; got {:?}",
                pqc.violations
                    .iter()
                    .map(|v| (v.rule_id, v.message.clone()))
                    .collect::<Vec<_>>()
            );
            let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                cnsa.violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-ALG-006"),
                "{family} must fail the CNSA 2.0 allowlist as quantum-vulnerable"
            );
        }
        // SM4 (symmetric) and GOST hashes are recognized-but-not-approved
        // under CNSA 2.0, and not quantum-vulnerable under PQC.
        for family in ["SM4", "Streebog"] {
            let sbom = make_crypto_sbom(&[("national-prim", family, None, None)]);
            let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
            assert!(
                cnsa.violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-CNSA2-ALG-008"),
                "{family} must be recognized as not CNSA 2.0-approved"
            );
            let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
            assert!(
                !pqc.violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-PQC-001" || v.rule_id == "SBOM-PQC-005"),
                "{family} must not be reported broken or quantum-vulnerable"
            );
        }
    }

    fn refs_for(rule_id: &'static str) -> Vec<StandardRef> {
        let v = Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id,
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        v.registry_standard_refs()
    }

    #[test]
    fn registry_refs_for_machine_readable_include_annex_and_pren() {
        let refs = refs_for("SBOM-CRA-MACHINE-READABLE");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II (1)"),
            "expected CRA Annex I Part II (1); got {refs:?}"
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

    /// #347: the SUPPLY-CHAIN rule is emitted only by the supplier checks,
    /// but its remediation was copied from the DEPENDENCY rule and told the
    /// user to add DEPENDS_ON relationships.
    #[test]
    fn supply_chain_remediation_is_about_suppliers() {
        let v = Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::SupplierInfo,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let guidance = v.remediation_guidance();
        assert!(
            guidance.contains("supplier") && guidance.contains("PackageSupplier"),
            "supplier-rule guidance must name the supplier fields; got: {guidance}"
        );
        assert!(
            !guidance.contains("DEPENDS_ON"),
            "supplier-rule guidance must not be the dependency-relationship text; got: {guidance}"
        );
    }

    #[test]
    fn registry_refs_for_supply_chain_include_annex_and_pren() {
        let refs = refs_for("SBOM-CRA-ANNEX-I-SUPPLY-CHAIN");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II"),
            "expected Annex I Part II; got {refs:?}"
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
    fn registry_refs_for_cvd_policy_include_annex_and_pren_rls() {
        let refs = refs_for("SBOM-CRA-CVD-POLICY");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II (5)"),
            "expected CRA Annex I Part II (5); got {refs:?}"
        );
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
            let result = checker(*level).check(&sbom);
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
        let checker = checker(ComplianceLevel::CraPhase2);
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
    fn sidecar_supplies_security_contact_downgrades_art_13_17() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();

        // Without sidecar: Art. 13(17) is a Warning
        let bare = checker(ComplianceLevel::CraPhase2).check(&sbom);
        let art_13_17_warning = bare.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(17)") && v.severity == ViolationSeverity::Warning
        });
        assert!(
            art_13_17_warning.is_some(),
            "Without sidecar, Art. 13(17) should be a Warning"
        );

        // With sidecar that supplies security_contact: same finding becomes Info
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@acme.example".to_string()),
            ..Default::default()
        };
        let withsc = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let art_13_17_info = withsc.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(17)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            art_13_17_info.is_some(),
            "With sidecar, Art. 13(17) should be downgraded to Info"
        );
        assert!(
            !withsc
                .violations
                .iter()
                .any(|v| v.requirement.contains("Art. 13(17)")
                    && v.severity == ViolationSeverity::Warning),
            "With sidecar, no Warning-level Art. 13(17) violation should remain"
        );
    }

    #[test]
    fn sidecar_supplies_product_name_downgrades_art_13_15() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default(); // no document name

        let sidecar = CraSidecarMetadata {
            product_name: Some("Demo Product".to_string()),
            ..Default::default()
        };
        let result = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(15)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar product_name should downgrade Art. 13(15) to Info"
        );
    }

    /// An SPDX 2.x document always has a DocumentName; an empty (or
    /// placeholder) one names neither the document nor the product. The
    /// rule-matrix format axis found FDA and CRA accepting it: an SPDX 2.3
    /// document with no name passed the checks its CycloneDX twin, which has
    /// no `metadata.component`, fails.
    #[test]
    fn empty_document_name_is_no_name() {
        let spdx = |name: &str| {
            crate::parsers::parse_sbom_str(&format!(
                r#"{{
                  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
                  "SPDXID": "SPDXRef-DOCUMENT", "name": "{name}",
                  "documentNamespace": "https://acme.example/spdx/doc",
                  "creationInfo": {{
                    "created": "2026-01-15T10:00:00Z",
                    "creators": ["Tool: acme-sbom-tool-1.0.0"]
                  }},
                  "packages": []
                }}"#
            ))
            .expect("SPDX 2.3 document parses")
        };
        let fired = |sbom: &NormalizedSbom, level: ComplianceLevel, rule: &str| {
            checker(level)
                .check(sbom)
                .violations
                .iter()
                .any(|v| v.rule_id == rule)
        };
        for name in ["", "  ", "NOASSERTION"] {
            let sbom = spdx(name);
            assert!(
                fired(&sbom, ComplianceLevel::FdaMedicalDevice, "SBOM-FDA-NAME"),
                "document name {name:?} must fire SBOM-FDA-NAME"
            );
            assert!(
                fired(
                    &sbom,
                    ComplianceLevel::CraPhase2,
                    "SBOM-CRA-ART-13-15-PRODUCT"
                ),
                "document name {name:?} must fire SBOM-CRA-ART-13-15-PRODUCT"
            );
        }
        let named = spdx("acme-router-os");
        assert!(!fired(
            &named,
            ComplianceLevel::FdaMedicalDevice,
            "SBOM-FDA-NAME"
        ));
        assert!(!fired(
            &named,
            ComplianceLevel::CraPhase2,
            "SBOM-CRA-ART-13-15-PRODUCT"
        ));
    }

    #[test]
    fn sidecar_supplies_manufacturer_downgrades_art_13_16() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("Demo Corp".to_string()),
            ..Default::default()
        };
        let result = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(16)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar manufacturer_name should downgrade Art. 13(16) to Info"
        );
    }

    #[test]
    fn sidecar_supplies_cvd_url_downgrades_cvd_policy() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            vulnerability_disclosure_url: Some("https://acme.example/security".to_string()),
            ..Default::default()
        };
        let result = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Annex I Part II (5)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar CVD URL should downgrade the Annex I Part II (5) CVD-policy finding to Info"
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "40% vendor-hash coverage should produce an Error under CraPhase2"
        );
    }

    /// A supplier named NOASSERTION (or a placeholder) names no vendor: such
    /// a component is classified like one with no supplier, so it neither
    /// lowers nor props up the [PRE-7-RQ-07-RE] coverage. The raw presence
    /// test counted it as a vendor component.
    #[test]
    fn vendor_hash_coverage_ignores_sentinel_suppliers() {
        use crate::model::Organization;
        use crate::quality::HashQualityMetrics;
        let mut sbom = NormalizedSbom::default();
        let known = vendor_component("known", false);
        sbom.components.insert(known.canonical_id.clone(), known);
        for (name, supplier) in [("sentinel", "NOASSERTION"), ("placeholder", "TBD")] {
            let mut c = vendor_component(name, true);
            c.supplier = Some(Organization::new(supplier.to_string()));
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let m = HashQualityMetrics::from_sbom(&sbom);
        assert_eq!(m.vendor_components_total, 1, "only the known supplier");
        assert_eq!(m.vendor_components_with_hash, 0);
        assert_eq!(m.vendor_hash_coverage(), Some(0.0));
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2)
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
    /// PSIRT/14(1)/14(2) and 14(7) (ENISA platform) surface as Info.
    /// Total: 4 Infos, 0 Warnings, 0 Errors at Art. 14 level.
    #[test]
    fn article_14_pre_deadline_mocked_clock_emits_4_infos() {
        let checker = checker(ComplianceLevel::CraPhase2);
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
    /// all four channels become Warnings — 14(7), the ENISA platform every
    /// notification goes through, included.
    /// Total: 0 Infos, 4 Warnings.
    #[test]
    fn article_14_post_deadline_mocked_clock_emits_4_warnings() {
        let checker = checker(ComplianceLevel::CraPhase2);
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
            warnings, 4,
            "Post-deadline expects 4 Warning-level Art. 14 findings (PSIRT/14(1)/14(2)/14(7)); got {warnings} (full: {violations:?})"
        );
        assert_eq!(
            infos, 0,
            "Post-deadline expects no Info-level Art. 14 finding (the ENISA platform finding warns too)"
        );
    }

    /// An unrated vulnerability needs no severity when its own VEX statement
    /// is not_affected and names a justification (CRA FAQ v1.4, 4.3.1). The
    /// check reads the model, so a statement from an OpenVEX overlay or an
    /// SPDX 3.0 assessment counts the same as an embedded CycloneDX
    /// analysis. No other statement counts.
    #[test]
    fn cra_phase2_vuln_metadata_accepts_only_a_justified_not_affected_statement() {
        use crate::model::{
            Component, VexJustification, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource,
        };
        let warns = |vex: Option<VexStatus>| {
            let mut vuln =
                VulnerabilityRef::new("CVE-2026-2222".to_string(), VulnerabilitySource::Cve);
            vuln.vex_status = vex;
            let mut component = Component::new("libalpha".to_string(), "libalpha@1".to_string());
            component.vulnerabilities.push(vuln);
            let mut sbom = NormalizedSbom::default();
            sbom.add_component(component);
            checker(ComplianceLevel::CraPhase2)
                .check(&sbom)
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-CRA-VULN-METADATA")
        };
        let statement = |state: VexState, justified: bool, impact: Option<&str>| {
            let mut vex = VexStatus::new(state);
            if justified {
                vex.justification = Some(VexJustification::VulnerableCodeNotInExecutePath);
            }
            vex.impact_statement = impact.map(str::to_string);
            Some(vex)
        };

        assert!(
            !warns(statement(VexState::NotAffected, true, None)),
            "a justified not_affected statement documents the vulnerability"
        );
        assert!(warns(None), "an entry without a VEX statement warns");
        assert!(
            warns(statement(VexState::NotAffected, false, None)),
            "a bare not_affected claim is no record"
        );
        assert!(
            warns(statement(
                VexState::NotAffected,
                false,
                Some("the parser is never called")
            )),
            "an impact statement without a justification is not enough"
        );
        for state in [
            VexState::Affected,
            VexState::Fixed,
            VexState::UnderInvestigation,
        ] {
            assert!(
                warns(statement(state.clone(), true, None)),
                "a justification on a {state} statement does not count"
            );
        }
    }

    #[test]
    fn article_14_sidecar_suppresses_psirt_warning() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            psirt_url: Some("https://acme.example/psirt".to_string()),
            early_warning_contact: Some("psirt@acme.example".to_string()),
            incident_report_contact: Some("ir@acme.example".to_string()),
            ..Default::default()
        };
        let result = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // PSIRT, 14(1), 14(2) suppressed; 14(7) (ENISA platform) remains.
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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
        let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
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

    /// Build a component that satisfies every gating BSI v2.1.0 rule:
    /// name, version, purl, SPDX licence, supplier, SHA-512 hash.
    fn bsi_ok_component(name: &str) -> crate::model::Component {
        use crate::model::{Component, Hash, HashAlgorithm, LicenseExpression, Organization};
        let mut c = Component::new(name.to_string(), name.to_string())
            .with_purl(format!("pkg:cargo/{name}@1.0"))
            .with_version("1.0".to_string());
        c.hashes
            .push(Hash::new(HashAlgorithm::Sha512, "f".repeat(128)));
        c.supplier = Some(Organization::new(format!("{name}-vendor")));
        c.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        c
    }

    #[test]
    fn bsi_tr_03183_2_empty_sbom_emits_errors() {
        let sbom = NormalizedSbom::default();
        let result = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("BSI TR-03183-2 §5.2.1")
                    && v.severity == ViolationSeverity::Error),
            "Empty SBOM should fail BSI §5.2.1 (creator missing)"
        );
    }

    /// §5.2.2 names SHA-512 in the normative hash clause: MD5-only and
    /// SHA-256-only components must fail (expectation flip: SHA-256 used to
    /// satisfy the old "SHA-256+" reading), SHA-512 must pass, and a
    /// hash-less component is a §3.2.1-aware Warning instead of an Error.
    #[test]
    fn bsi_tr_03183_2_requires_sha512_hash() {
        use crate::model::{Hash, HashAlgorithm};
        let check = |alg: Option<HashAlgorithm>, hexlen: usize| {
            let mut sbom = NormalizedSbom::default();
            let mut c = bsi_ok_component("lib");
            c.hashes.clear();
            if let Some(alg) = alg {
                c.hashes.push(Hash::new(alg, "0".repeat(hexlen)));
            }
            sbom.add_component(c);
            checker(ComplianceLevel::BsiTr03183_2).check(&sbom)
        };

        let md5 = check(Some(HashAlgorithm::Md5), 32);
        assert!(
            md5.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                    && v.severity == ViolationSeverity::Error),
            "MD5-only component must fail the §5.2.2 SHA-512 requirement"
        );

        let sha256 = check(Some(HashAlgorithm::Sha256), 64);
        assert!(
            sha256
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                    && v.severity == ViolationSeverity::Error),
            "SHA-256-only component must now FAIL the hash rule (§5.2.2 names SHA-512)"
        );

        let sha512 = check(Some(HashAlgorithm::Sha512), 128);
        assert!(
            !sha512
                .violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-4")),
            "SHA-512 component must satisfy the hash rule"
        );

        let none = check(None, 0);
        assert!(
            none.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4-MISSING"
                    && v.severity == ViolationSeverity::Warning),
            "hash-less component must warn (§3.2.1 legitimate-omission escape)"
        );
        assert!(
            !none
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"),
            "hash-less component must not also fire the wrong-algorithm Error"
        );
    }

    /// §4 format gate: CycloneDX < 1.6 and SPDX < 3.0.1 fail; the minimums
    /// pass; versions are compared numerically, and a synthetic document
    /// with no spec_version skips the gate.
    #[test]
    fn bsi_tr_03183_2_format_gate() {
        use crate::model::SbomFormat;
        let check = |format: SbomFormat, version: &str| {
            let mut sbom = NormalizedSbom::default();
            sbom.document.format = format;
            sbom.document.spec_version = version.to_string();
            sbom.add_component(bsi_ok_component("lib"));
            let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
            r.violations.iter().any(|v| {
                v.rule_id == "SBOM-BSI-TR-03183-2-4" && v.severity == ViolationSeverity::Error
            })
        };

        assert!(
            check(SbomFormat::CycloneDx, "1.5"),
            "CycloneDX 1.5 must fail the §4 format gate"
        );
        assert!(
            !check(SbomFormat::CycloneDx, "1.6"),
            "CycloneDX 1.6 must pass the §4 format gate"
        );
        assert!(
            !check(SbomFormat::CycloneDx, "1.7"),
            "CycloneDX 1.7 must pass the §4 format gate"
        );
        assert!(
            check(SbomFormat::Spdx, "2.3"),
            "SPDX 2.3 must fail the §4 format gate"
        );
        assert!(
            check(SbomFormat::Spdx, "3.0"),
            "SPDX 3.0 is below the 3.0.1 minimum and must fail the §4 gate"
        );
        assert!(
            !check(SbomFormat::Spdx, "3.0.1"),
            "SPDX 3.0.1 must pass the §4 format gate"
        );
        assert!(
            !check(SbomFormat::CycloneDx, ""),
            "a document with no spec_version must skip the §4 gate"
        );
    }

    /// The TR mandates no generation-tool field in any tier: a Person
    /// creator with an email must satisfy §5.2.1 with no tool-related
    /// Error (expectation flip: tool absence used to be a gating Error).
    #[test]
    fn bsi_tr_03183_2_does_not_require_tool_creator() {
        use crate::model::{Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Person,
            name: "Jane Doe".to_string(),
            email: Some("jane@acme.example".to_string()),
        });
        sbom.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            !r.violations.iter().any(|v| v.message.contains("tool")),
            "no violation may demand a generation tool (not mandated in any TR tier)"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
            "a Person creator with an email satisfies §5.2.1 entirely"
        );
    }

    /// §5.2.1 creator granularity: absent entirely → Error; present without
    /// email/URL → Warning; present with email → silent.
    #[test]
    fn bsi_tr_03183_2_creator_contact_granularity() {
        use crate::model::{Creator, CreatorType};
        let base = || {
            let mut sbom = NormalizedSbom::default();
            sbom.add_component(bsi_ok_component("lib"));
            sbom
        };

        let empty = checker(ComplianceLevel::BsiTr03183_2).check(&base());
        assert!(
            empty
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"
                    && v.severity == ViolationSeverity::Error),
            "no creator at all must be a §5.2.1 Error"
        );

        let mut contactless = base();
        contactless.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "Acme".to_string(),
            email: None,
        });
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&contactless);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1-CONTACT"
                    && v.severity == ViolationSeverity::Warning),
            "a creator without email/URL must be a §5.2.1 Warning"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"),
            "a contactless creator is present — the absence Error must not fire"
        );

        let mut with_url = base();
        with_url.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "https://acme.example".to_string(),
            email: None,
        });
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&with_url);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
            "a creator URL satisfies §5.2.1 (URL fallback when no email exists)"
        );
    }

    /// §5.2.1 maps "Creator of the SBOM" to Person/Organization (CycloneDX
    /// metadata.authors/manufacturer), explicitly NOT metadata.tools: a
    /// tools-only SBOM (the default output of common generators) must fail
    /// the creator gate (expectation flip: Tool creators used to satisfy the
    /// presence test).
    #[test]
    fn bsi_tr_03183_2_tools_only_creators_fail_creator_gate() {
        use crate::model::{Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "syft 1.18.0".to_string(),
            email: None,
        });
        sbom.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"
                    && v.severity == ViolationSeverity::Error),
            "a tools-only creators list must fail the §5.2.1 creator gate"
        );

        // Silent side: adding an Organization creator with an email (the
        // metadata.manufacturer mapping) alongside the tool satisfies §5.2.1.
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "Demo Corp".to_string(),
            email: Some("sbom@demo.example".to_string()),
        });
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
            "an Organization creator with email satisfies §5.2.1 entirely"
        );
    }

    /// The §5.2.1 -CONTACT Warning must inspect only non-Tool creators: a
    /// tool whose name happens to carry contact-looking characters cannot
    /// stand in for the creator's email/URL.
    #[test]
    fn bsi_tr_03183_2_contact_warning_ignores_tool_contacts() {
        use crate::model::{Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "sbom-gen (https://sbom-gen.example)".to_string(),
            email: None,
        });
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "Acme".to_string(),
            email: None,
        });
        sbom.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1-CONTACT"
                    && v.severity == ViolationSeverity::Warning),
            "a tool's URL must not satisfy the creator contact requirement"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"),
            "the Organization creator is present — only the contact Warning may fire"
        );
    }

    /// §5.2.2 SHA-512: only author-attested hashes count. An
    /// enrichment-fetched SHA-512 is not part of the document under
    /// assessment and must not mask a missing authored SHA-512
    /// (HashProvenance::Authored exclusion).
    #[test]
    fn bsi_tr_03183_2_sha512_counts_only_authored_hashes() {
        use crate::model::{Hash, HashAlgorithm};
        let check = |hashes: Vec<Hash>| {
            let mut sbom = NormalizedSbom::default();
            let mut c = bsi_ok_component("lib");
            c.hashes = hashes;
            sbom.add_component(c);
            checker(ComplianceLevel::BsiTr03183_2).check(&sbom)
        };

        // Authored SHA-256 + ENRICHED SHA-512: the SHA-512 Error must still
        // fire — the enriched hash is not author-attested.
        let r = check(vec![
            Hash::new(HashAlgorithm::Sha256, "0".repeat(64)),
            Hash::enriched(HashAlgorithm::Sha512, "0".repeat(128)),
        ]);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                    && v.severity == ViolationSeverity::Error),
            "an enriched SHA-512 must not mask a missing authored SHA-512"
        );

        // Authored SHA-512: silent.
        let r = check(vec![Hash::new(HashAlgorithm::Sha512, "f".repeat(128))]);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-4")),
            "an authored SHA-512 satisfies §5.2.2"
        );

        // Enriched hashes only: the component counts as hash-less
        // (§3.2.1-aware Warning), not as carrying the wrong algorithm.
        let r = check(vec![Hash::enriched(HashAlgorithm::Sha512, "0".repeat(128))]);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4-MISSING"
                    && v.severity == ViolationSeverity::Warning),
            "enriched-only hashes must count as no authored hash at all"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"),
            "enriched-only hashes must not fire the wrong-algorithm Error"
        );
    }

    /// §5.2.2 component version is a required field: absence gates.
    #[test]
    fn bsi_tr_03183_2_gates_on_missing_version() {
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.version = None;
        sbom.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-VERSION"
                    && v.severity == ViolationSeverity::Error),
            "a version-less component must fail BSI §5.2.2"
        );

        let mut ok = NormalizedSbom::default();
        ok.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&ok);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-VERSION"),
            "a versioned component must not fire the version rule"
        );
    }

    /// §5.2.2 distribution licences are required (Error when absent);
    /// §6.1 requires SPDX naming (Warning when the expression is not SPDX).
    #[test]
    fn bsi_tr_03183_2_licence_rules() {
        use crate::model::LicenseExpression;
        let mut unlicensed = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.licenses.declared.clear();
        c.licenses.concluded = None;
        unlicensed.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&unlicensed);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE"
                    && v.severity == ViolationSeverity::Error),
            "a component without distribution licences must fail §5.2.2"
        );

        let mut non_spdx = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.licenses.declared.clear();
        c.licenses.add_declared(LicenseExpression::new(
            "Standard Commercial Terms, see LICENSE.txt".to_string(),
        ));
        non_spdx.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&non_spdx);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE-SPDX"
                    && v.severity == ViolationSeverity::Warning),
            "a non-SPDX licence expression must warn under §6.1"
        );
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE"),
            "a declared (non-SPDX) licence still counts as present"
        );

        let mut spdx_ok = NormalizedSbom::default();
        spdx_ok.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&spdx_ok);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-LICENSE")),
            "an SPDX-named licence satisfies both §5.2.2 and §6.1"
        );
    }

    /// §5.2.2 component creator: presence-level Warning when both supplier
    /// and author are absent.
    #[test]
    fn bsi_tr_03183_2_warns_on_missing_component_creator() {
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.supplier = None;
        c.author = None;
        sbom.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-CREATOR"
                    && v.severity == ViolationSeverity::Warning),
            "a component without supplier/author must warn under §5.2.2"
        );

        let mut ok = NormalizedSbom::default();
        ok.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&ok);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-CREATOR"),
            "a supplied component must not fire the creator rule"
        );
    }

    /// §5.2.4 puts purl/CPE in the ADDITIONAL tier ("MUST additionally …
    /// if it exists"): absence is a Warning, no longer a gating Error
    /// (expectation flip).
    #[test]
    fn bsi_tr_03183_2_identifier_is_warning_not_error() {
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.identifiers.purl = None;
        c.canonical_id = c.identifiers.canonical_id();
        sbom.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        let id_violations: Vec<_> = r
            .violations
            .iter()
            .filter(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-2-4")
            .collect();
        assert!(
            !id_violations.is_empty(),
            "a purl-less component must fire the §5.2.4 identifier rule"
        );
        assert!(
            id_violations
                .iter()
                .all(|v| v.severity == ViolationSeverity::Warning),
            "the §5.2.4 identifier rule is additional-tier: Warning, not Error"
        );
    }

    /// §5.2.2 requires the completeness of the dependency enumeration to be
    /// clearly indicated (CycloneDX compositions).
    #[test]
    fn bsi_tr_03183_2_warns_on_undeclared_completeness() {
        use crate::model::CompletenessDeclaration;
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(bsi_ok_component("lib"));
        // Default is Unknown → warn.
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS"
                    && v.severity == ViolationSeverity::Warning),
            "an SBOM without a completeness declaration must warn under §5.2.2"
        );

        sbom.document.completeness_declaration = CompletenessDeclaration::Complete;
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS"),
            "a declared completeness must not warn"
        );
    }

    /// §3.1: an SBOM MUST NOT contain vulnerability information — a combined
    /// document does not conform (Warning; enrichment may attach findings).
    #[test]
    fn bsi_tr_03183_2_warns_on_embedded_vulnerabilities() {
        use crate::model::{VulnerabilityRef, VulnerabilitySource};
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.vulnerabilities.push(VulnerabilityRef::new(
            "CVE-2026-0001".to_string(),
            VulnerabilitySource::Cve,
        ));
        sbom.add_component(c);
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-3-1"
                    && v.severity == ViolationSeverity::Warning),
            "embedded vulnerability information must warn under §3.1"
        );

        let mut clean = NormalizedSbom::default();
        clean.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&clean);
        assert!(
            !r.violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-3-1"),
            "a vulnerability-free SBOM must not fire §3.1"
        );
    }

    #[test]
    fn bsi_tr_03183_2_passes_for_complete_component() {
        use crate::model::{Creator, CreatorType, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Person,
            name: "Release Engineering".to_string(),
            email: Some("sbom@acme.example".to_string()),
        });
        let a = bsi_ok_component("a");
        let b = bsi_ok_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        sbom.components.insert(a_id.clone(), a);
        sbom.components.insert(b_id.clone(), b);
        sbom.edges
            .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));

        let result = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
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
        assert_eq!(ComplianceLevel::all().len(), 19);
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::BsiTr03183_2));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::CraOssSteward));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::EuccSubstantial));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::EuAiAct));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::BsiSbomForAi));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::Cisa2026));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::PciDss632));
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::Fsct));
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
        let result = checker(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // No Art. 13(16) violation at all because SBOM provides org
        assert!(
            !result.violations.iter().any(|v| v
                .requirement
                .contains("Art. 13(16): Manufacturer identification")),
            "When SBOM provides manufacturer, no Art. 13(16) violation should be emitted"
        );
    }
}
