//! References to the clauses of the published standards a rule
//! implements: the standard, the clause id, and the standard's URL.

use super::*;

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
