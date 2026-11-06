//! The standards as data: one [`StandardDescriptor`] per
//! [`ComplianceLevel`], in [`STANDARDS`].
//!
//! What sbom-tools knows about a standard apart from its checks is one
//! entry here, and the code that needs such a fact reads the entry instead
//! of matching on the level.
//!
//! Entry `i` describes the level whose discriminant is `i`, so a lookup is
//! an index and the level's `const fn`s stay `const`. The table order is
//! the declaration order of [`ComplianceLevel`], which is also the order
//! of [`ComplianceLevel::all`] and of every list of standards shown to
//! users. A compile-time check below holds the order.

use super::{ComplianceLevel, CraPhase};

/// What sbom-tools knows about one standard, apart from its checks.
pub(crate) struct StandardDescriptor {
    /// The level this entry describes.
    pub(crate) level: ComplianceLevel,
    /// The standard's key: the `standard` of `validate -o json`, the
    /// `<standard>` part of a finding key, the SARIF category and the OSCAL
    /// target id. For a standard `--standard` selects, it is the canonical
    /// `--standard` value; the quality profiles use their lowercase level
    /// name.
    pub(crate) key: &'static str,
    /// Human-readable name.
    pub(crate) name: &'static str,
    /// Compact tab label (max ~8 chars) for terminal display.
    pub(crate) short_name: &'static str,
    /// What the standard checks, in one line.
    pub(crate) description: &'static str,
    /// Whether the standard is a CRA check, the Article 24 steward profile
    /// included.
    pub(crate) cra: bool,
    /// The CRA phase the standard checks, if it is a CRA phase.
    pub(crate) cra_phase: Option<CraPhase>,
    /// The family fallback rule: the SARIF rule a finding without a
    /// registry mapping is filed under. A registered self-descriptor.
    pub(crate) fallback_rule: &'static str,
}

/// One descriptor per [`ComplianceLevel`]; entry `i` describes the level
/// whose discriminant is `i`.
pub(crate) const STANDARDS: &[StandardDescriptor] = &[
    StandardDescriptor {
        level: ComplianceLevel::Minimum,
        key: "minimum",
        name: "Minimum",
        short_name: "Min",
        description: "Basic component identification only",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Standard,
        key: "standard",
        name: "Standard",
        short_name: "Std",
        description: "Recommended fields for general use",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::NtiaMinimum,
        key: "ntia",
        name: "NTIA Minimum Elements",
        short_name: "NTIA",
        description: "NTIA minimum elements for software transparency",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-NTIA-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::CraPhase1,
        key: "cra-phase1",
        name: "EU CRA Phase 1 (2026)",
        short_name: "CRA-1",
        description: "CRA reporting obligations — product ID, SBOM format, manufacturer (Art. 14 applies from 11 Sep 2026)",
        cra: true,
        cra_phase: Some(CraPhase::Phase1),
        fallback_rule: "SBOM-CRA-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::CraPhase2,
        key: "cra",
        name: "EU CRA Phase 2 (2027)",
        short_name: "CRA-2",
        description: "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (regulation fully applies from 11 Dec 2027)",
        cra: true,
        cra_phase: Some(CraPhase::Phase2),
        fallback_rule: "SBOM-CRA-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::FdaMedicalDevice,
        key: "fda",
        name: "FDA Medical Device",
        short_name: "FDA",
        description: "FDA premarket submission requirements for medical devices",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-FDA-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::NistSsdf,
        key: "ssdf",
        name: "NIST SSDF (SP 800-218)",
        short_name: "SSDF",
        description: "Secure Software Development Framework — provenance, build integrity, VCS references",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-SSDF-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Eo14028,
        key: "eo14028",
        name: "EO 14028 Section 4",
        short_name: "EO14028",
        description: "Executive Order 14028 §4 SBOM practice (not a federal mandate since OMB M-26-05 rescinded M-22-18 and M-23-16) — machine-readable SBOM, auto-generation, supply chain security",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-EO14028-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Cnsa2,
        key: "cnsa2",
        name: "CNSA 2.0",
        short_name: "CNSA2",
        description: "CNSA 2.0 (required by CNSSP 15) — AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87, quantum security level 5",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-CNSA2-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::NistPqc,
        key: "pqc",
        name: "NIST PQC Readiness",
        short_name: "PQC",
        description: "NIST PQC — quantum-vulnerable algorithm detection, FIPS 203/204/205, SP 800-131A",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-PQC-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::BsiTr03183_2,
        key: "bsi",
        name: "BSI TR-03183-2",
        short_name: "BSI",
        description: "BSI TR-03183-2 v2.1.0 — German national SBOM guideline (free, ENISA-cited): CycloneDX 1.6+/SPDX 3.0.1+ formats, required creator/timestamp, per-component version/licences/SHA-512 hash",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-BSI-TR-03183-2-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::CraOssSteward,
        key: "oss-steward",
        name: "CRA OSS Steward (Art. 24)",
        short_name: "OSS",
        description: "CRA Article 24 — Open-source software steward (lighter than full manufacturer obligations): SBOM + CVD policy + vuln-handling required, no DoC/module/manufacturer-email enforcement",
        cra: true,
        cra_phase: None,
        fallback_rule: "SBOM-CRA-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::EuccSubstantial,
        key: "eucc",
        name: "EUCC Substantial (Reg. 2024/482)",
        short_name: "EUCC",
        description: "EUCC Substantial (Implementing Reg. (EU) 2024/482, as amended by 2024/3144 and 2025/2462) — reference-only check for Common-Criteria Protection Profile, Target of Evaluation, ITSEF, and certificate valid-until date",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-EUCC-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::EuAiAct,
        key: "ai-act",
        name: "EU AI Act Annex IV Readiness",
        short_name: "AI-Act",
        description: "EU AI Act (Reg. (EU) 2024/1689, as amended by Reg. (EU) 2026/1744) Annex IV technical-documentation READINESS — model description, training-data characteristics, validation/testing metrics, limitations (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-AIACT-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::BsiSbomForAi,
        key: "bsi-ai",
        name: "BSI/G7 SBOM-for-AI Minimum Elements Readiness",
        short_name: "BSI-AI",
        description: "BSI/G7 SBOM-for-AI Minimum Elements (joint G7 final, May 2026) READINESS — scores an AI-BOM element-by-element across the Metadata, System-Level, Models, Datasets, Infrastructure, and Security clusters (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-BSIAI-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Cisa2026,
        key: "cisa-2026",
        name: "CISA 2026 Minimum Elements",
        short_name: "CISA26",
        description: "2026 Minimum Elements for an SBOM (CISA et al., July 2026) — successor to NTIA 2021: author (person/org), signature, format name+version, generation context, timestamp, tool name+version, SBOM version, and per-component producer/name/version/identifiers/hash/license/dependencies. Frequency, distribution, and update accommodation are organizational practices with no in-document evidence and carry no rules.",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-CISA2026-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::PciDss632,
        key: "pci-dss",
        name: "PCI DSS v4.0.1 Req. 6.3.2",
        short_name: "PCI",
        description: "PCI DSS v4.0.1 Req. 6.3.2 software-inventory profile (required in assessments since 31 Mar 2025) — inventory completeness, per-component name/version/supplier/identifier, freshness, and vulnerability-management usability; 6.3.1/11.3.1.1 risk-ranking checks where vulnerability data is embedded. Assessor-side testing procedures (interviews, software comparison) are out of document reach.",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-PCI-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Fsct,
        key: "fsct",
        name: "CISA Framing Software Component Transparency (3rd ed.)",
        short_name: "FSCT",
        description: "CISA Framing Software Component Transparency, 3rd ed. (2024) — baseline attributes (author, timestamp, primary component, name, version, supplier, identifiers, hashes, relationships, licenses, copyright) across the Minimum Expected (Error) / Recommended Practice (Warning) / Aspirational Goal (Info) maturity tiers",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-FSCT-GENERAL",
    },
    StandardDescriptor {
        level: ComplianceLevel::Comprehensive,
        key: "comprehensive",
        name: "Comprehensive",
        short_name: "Full",
        description: "All recommended fields and best practices",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
    },
];

// Entry `i` must describe the level whose discriminant is `i`: the lookup
// below indexes by discriminant.
const _: () = {
    let mut i = 0;
    while i < STANDARDS.len() {
        assert!(
            STANDARDS[i].level as usize == i,
            "STANDARDS[i] must describe the ComplianceLevel whose discriminant is i"
        );
        i += 1;
    }
};

/// The levels in table order: [`ComplianceLevel::all`].
pub(super) const ALL_LEVELS: [ComplianceLevel; STANDARDS.len()] = {
    let mut levels = [ComplianceLevel::Minimum; STANDARDS.len()];
    let mut i = 0;
    while i < STANDARDS.len() {
        levels[i] = STANDARDS[i].level;
        i += 1;
    }
    levels
};

impl ComplianceLevel {
    /// The level's entry in [`STANDARDS`].
    #[must_use]
    pub(crate) const fn descriptor(self) -> &'static StandardDescriptor {
        &STANDARDS[self as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::{RuleCatalogFilter, rule_catalog};
    use std::collections::BTreeSet;

    /// Every level, by an exhaustive match: a new level fails to compile
    /// here until it is added, and then the test below fails until it has
    /// an entry in [`STANDARDS`].
    fn every_level() -> Vec<ComplianceLevel> {
        let listed = |level: ComplianceLevel| match level {
            ComplianceLevel::Minimum
            | ComplianceLevel::Standard
            | ComplianceLevel::NtiaMinimum
            | ComplianceLevel::CraPhase1
            | ComplianceLevel::CraPhase2
            | ComplianceLevel::FdaMedicalDevice
            | ComplianceLevel::NistSsdf
            | ComplianceLevel::Eo14028
            | ComplianceLevel::Cnsa2
            | ComplianceLevel::NistPqc
            | ComplianceLevel::BsiTr03183_2
            | ComplianceLevel::CraOssSteward
            | ComplianceLevel::EuccSubstantial
            | ComplianceLevel::EuAiAct
            | ComplianceLevel::BsiSbomForAi
            | ComplianceLevel::Cisa2026
            | ComplianceLevel::PciDss632
            | ComplianceLevel::Fsct
            | ComplianceLevel::Comprehensive => level,
        };
        vec![
            listed(ComplianceLevel::Minimum),
            listed(ComplianceLevel::Standard),
            listed(ComplianceLevel::NtiaMinimum),
            listed(ComplianceLevel::CraPhase1),
            listed(ComplianceLevel::CraPhase2),
            listed(ComplianceLevel::FdaMedicalDevice),
            listed(ComplianceLevel::NistSsdf),
            listed(ComplianceLevel::Eo14028),
            listed(ComplianceLevel::Cnsa2),
            listed(ComplianceLevel::NistPqc),
            listed(ComplianceLevel::BsiTr03183_2),
            listed(ComplianceLevel::CraOssSteward),
            listed(ComplianceLevel::EuccSubstantial),
            listed(ComplianceLevel::EuAiAct),
            listed(ComplianceLevel::BsiSbomForAi),
            listed(ComplianceLevel::Cisa2026),
            listed(ComplianceLevel::PciDss632),
            listed(ComplianceLevel::Fsct),
            listed(ComplianceLevel::Comprehensive),
        ]
    }

    #[test]
    fn one_entry_per_level_in_declaration_order() {
        let levels = every_level();
        assert_eq!(STANDARDS.len(), levels.len(), "one entry per level");
        for (i, level) in levels.iter().enumerate() {
            assert_eq!(*level as usize, i, "{level:?} is declared at {i}");
            assert_eq!(STANDARDS[i].level, *level, "entry {i}");
            assert_eq!(level.descriptor().level, *level);
        }
        assert_eq!(ComplianceLevel::all(), levels.as_slice());
    }

    /// The catalogue `sbom-tools rules` prints names exactly the table's
    /// standards, by their keys.
    #[test]
    fn the_rule_catalogue_names_every_standard_by_its_key() {
        let named: BTreeSet<String> = rule_catalog(&RuleCatalogFilter::all())
            .into_iter()
            .flat_map(|entry| entry.standards)
            .map(str::to_string)
            .collect();
        let keys: BTreeSet<String> = STANDARDS.iter().map(|d| d.key.to_string()).collect();
        assert_eq!(named, keys);
    }
}
