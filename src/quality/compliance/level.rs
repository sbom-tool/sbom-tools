//! Compliance levels: the standards and profiles a checker can check
//! against, the CRA phases, and each level's family fallback rule. What a
//! level's methods return is in its entry in the standards table
//! (`standards.rs`).

use super::*;

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
        self.descriptor().name
    }

    /// Get compact tab label (max ~8 chars) for terminal display.
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        self.descriptor().short_name
    }

    /// Get description of what this level checks
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.descriptor().description
    }

    /// Get all compliance levels
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &super::standards::ALL_LEVELS
    }

    /// Whether this level is a CRA check. Includes the lighter Article 24
    /// open-source steward profile, since stewards still operate under the
    /// regulation (just with reduced obligations).
    #[must_use]
    pub const fn is_cra(&self) -> bool {
        self.descriptor().cra
    }

    /// Get CRA phase, if applicable
    #[must_use]
    pub const fn cra_phase(&self) -> Option<CraPhase> {
        self.descriptor().cra_phase
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
    level.descriptor().fallback_rule
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
