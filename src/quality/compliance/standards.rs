//! The standards as data: one [`StandardDescriptor`] per
//! [`ComplianceLevel`], in [`STANDARDS`].
//!
//! What sbom-tools knows about a standard apart from its checks is one
//! entry here, and the code that needs such a fact reads the entry instead
//! of matching on the level. Adding a standard starts with its entry (see
//! "Adding a standard" in CONTRIBUTING.md).
//!
//! Entry `i` describes the level whose discriminant is `i`, so a lookup is
//! an index and the level's `const fn`s stay `const`. The table order is
//! the declaration order of [`ComplianceLevel`], which is also the order
//! of [`ComplianceLevel::all`] and of every list of standards shown to
//! users. A compile-time check below holds the order.

use super::context::{
    BsiSbomForAiChecker, BsiTr03183Checker, Cisa2026Checker, Cnsa2Checker, CraOssStewardChecker,
    Eo14028Checker, EuAiActChecker, EuccSubstantialChecker, FsctChecker, GenericChecker,
    NistPqcChecker, NistSsdfChecker, PciDss632Checker, StandardChecker,
};
use super::registry::{
    AIACT_SARIF_RULE_IDS, BSI_SARIF_RULE_IDS, BSIAI_SARIF_RULE_IDS, CISA2026_SARIF_RULE_IDS,
    CNSA2_SARIF_RULE_IDS, COMPREHENSIVE_SARIF_RULE_IDS, CRA_OSS_STEWARD_SARIF_RULE_IDS,
    CRA_PHASE1_SARIF_RULE_IDS, CRA_PHASE2_SARIF_RULE_IDS, EO14028_SARIF_RULE_IDS,
    EUCC_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS, FSCT_SARIF_RULE_IDS, MINIMUM_SARIF_RULE_IDS,
    NTIA_SARIF_RULE_IDS, PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, SSDF_SARIF_RULE_IDS,
    STANDARD_SARIF_RULE_IDS,
};
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
    /// How `validate --standard` and `rules --standard` select the
    /// standard; `None` for the quality profiles (Minimum, Standard,
    /// Comprehensive), which back `quality --profile` instead.
    pub(crate) cli: Option<CliNames>,
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
    /// The rules the standard's checks can report, in display order. The
    /// lists are in `registry/mod.rs`, with the comment that explains them.
    pub(crate) rules: &'static [&'static str],
    /// Builds the checker that runs the standard.
    pub(crate) checker: fn(ComplianceLevel) -> Box<dyn StandardChecker>,
    /// What the standard's checks judge.
    pub(crate) subjects: Subjects,
    /// Which of a run's inputs the standard's checker gets.
    pub(crate) inputs: RunInputs,
    /// Whether the TUI's policy view offers the standard as a preset
    /// (`tui::PolicyPreset`). A test there holds the presets to this flag.
    #[cfg_attr(not(all(test, feature = "tui")), allow(dead_code))]
    pub(crate) in_tui_presets: bool,
}

/// How `--standard` selects a standard. The canonical value is the
/// standard's [`StandardDescriptor::key`].
pub(crate) struct CliNames {
    /// The other spellings `--standard` accepts, in the order clap lists
    /// them.
    pub(crate) aliases: &'static [&'static str],
    /// The line `validate --help` shows for the value.
    pub(crate) help: &'static str,
}

/// What a standard's checks judge, besides the document: the components
/// its score counts ([`ComplianceResult::elements_checked`]).
///
/// [`ComplianceResult::elements_checked`]: super::ComplianceResult::elements_checked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subjects {
    /// The software packages: the components the package rules judge. The
    /// only standards with package rules, so the only ones whose results
    /// change with `--include-excluded-scope`.
    Packages,
    /// The cryptographic assets (CNSA 2.0, NIST PQC).
    CryptographicAssets,
    /// The ML models and datasets of an AI-BOM (the AI profiles).
    AiBom,
    /// The certification evidence in the CRA sidecar (EUCC): no component.
    CertificationEvidence,
}

/// The inputs of a run that reach a standard's checker, besides the clock
/// and the rule settings, which reach every standard.
/// [`ComplianceRunConfig::checker`] explains each row.
///
/// [`ComplianceRunConfig::checker`]: super::ComplianceRunConfig::checker
pub(crate) struct RunInputs {
    /// The CRA sidecar.
    pub(crate) sidecar: bool,
    /// The CRA product class (and the sidecar's class and route).
    pub(crate) product_class: bool,
    /// The PQC mode.
    pub(crate) pqc_mode: bool,
    /// The PQC profile.
    pub(crate) pqc_profile: bool,
    /// The CNSA 2.0 category.
    pub(crate) cnsa_category: bool,
}

impl RunInputs {
    /// None of the inputs.
    const NONE: Self = Self {
        sidecar: false,
        product_class: false,
        pqc_mode: false,
        pqc_profile: false,
        cnsa_category: false,
    };

    /// The sidecar alone.
    const SIDECAR: Self = Self {
        sidecar: true,
        ..Self::NONE
    };

    /// The CRA phases' inputs: the sidecar and the product class.
    const CRA_PHASE: Self = Self {
        sidecar: true,
        product_class: true,
        ..Self::NONE
    };
}

/// One descriptor per [`ComplianceLevel`]; entry `i` describes the level
/// whose discriminant is `i`.
pub(crate) const STANDARDS: &[StandardDescriptor] = &[
    StandardDescriptor {
        level: ComplianceLevel::Minimum,
        key: "minimum",
        cli: None,
        name: "Minimum",
        short_name: "Min",
        description: "Basic component identification only",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
        rules: MINIMUM_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::Standard,
        key: "standard",
        cli: None,
        name: "Standard",
        short_name: "Std",
        description: "Recommended fields for general use",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
        rules: STANDARD_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::NtiaMinimum,
        key: "ntia",
        cli: Some(CliNames {
            aliases: &[],
            help: "NTIA Minimum Elements for software transparency",
        }),
        name: "NTIA Minimum Elements",
        short_name: "NTIA",
        description: "NTIA minimum elements for software transparency",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-NTIA-GENERAL",
        rules: NTIA_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::CraPhase1,
        key: "cra-phase1",
        cli: Some(CliNames {
            aliases: &["cra-2026"],
            help: "EU CRA Phase 1 — Art. 14 reporting obligations (apply from 11 Sep 2026)",
        }),
        name: "EU CRA Phase 1 (2026)",
        short_name: "CRA-1",
        description: "CRA reporting obligations — product ID, SBOM format, manufacturer (Art. 14 applies from 11 Sep 2026)",
        cra: true,
        cra_phase: Some(CraPhase::Phase1),
        fallback_rule: "SBOM-CRA-GENERAL",
        rules: CRA_PHASE1_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::CRA_PHASE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::CraPhase2,
        key: "cra",
        cli: Some(CliNames {
            aliases: &["cra-phase2"],
            help: "EU CRA Phase 2 — full application of the regulation (from 11 Dec 2027). `cra` selects Phase 2; use `cra-phase1` for the 2026 reporting phase",
        }),
        name: "EU CRA Phase 2 (2027)",
        short_name: "CRA-2",
        description: "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (regulation fully applies from 11 Dec 2027)",
        cra: true,
        cra_phase: Some(CraPhase::Phase2),
        fallback_rule: "SBOM-CRA-GENERAL",
        rules: CRA_PHASE2_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::CRA_PHASE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::FdaMedicalDevice,
        key: "fda",
        cli: Some(CliNames {
            aliases: &[],
            help: "FDA premarket submission requirements for medical devices",
        }),
        name: "FDA Medical Device",
        short_name: "FDA",
        description: "FDA premarket submission requirements for medical devices",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-FDA-GENERAL",
        rules: FDA_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::NistSsdf,
        key: "ssdf",
        cli: Some(CliNames {
            aliases: &["nist-ssdf", "nist_ssdf"],
            help: "NIST SP 800-218 Secure Software Development Framework",
        }),
        name: "NIST SSDF (SP 800-218)",
        short_name: "SSDF",
        description: "Secure Software Development Framework — provenance, build integrity, VCS references",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-SSDF-GENERAL",
        rules: SSDF_SARIF_RULE_IDS,
        checker: NistSsdfChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::Eo14028,
        key: "eo14028",
        cli: Some(CliNames {
            aliases: &["eo-14028", "eo_14028"],
            help: "Executive Order 14028 Section 4 — software supply chain security practice (no federal mandate: OMB M-26-05 rescinded M-22-18)",
        }),
        name: "EO 14028 Section 4",
        short_name: "EO14028",
        description: "Executive Order 14028 §4 SBOM practice (not a federal mandate since OMB M-26-05 rescinded M-22-18 and M-23-16) — machine-readable SBOM, auto-generation, supply chain security",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-EO14028-GENERAL",
        rules: EO14028_SARIF_RULE_IDS,
        checker: Eo14028Checker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::Cnsa2,
        key: "cnsa2",
        cli: Some(CliNames {
            aliases: &["cnsa-2", "cnsa_2", "cnsa2.0"],
            help: "NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0, required for US national security systems by CNSSP 15",
        }),
        name: "CNSA 2.0",
        short_name: "CNSA2",
        description: "CNSA 2.0 (required by CNSSP 15) — AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87, quantum security level 5",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-CNSA2-GENERAL",
        rules: CNSA2_SARIF_RULE_IDS,
        checker: Cnsa2Checker::boxed,
        subjects: Subjects::CryptographicAssets,
        inputs: RunInputs {
            pqc_mode: true,
            cnsa_category: true,
            ..RunInputs::NONE
        },
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::NistPqc,
        key: "pqc",
        cli: Some(CliNames {
            aliases: &["nist-pqc", "nist_pqc"],
            help: "NIST PQC readiness (IR 8547 + FIPS 203/204/205)",
        }),
        name: "NIST PQC Readiness",
        short_name: "PQC",
        description: "NIST PQC — quantum-vulnerable algorithm detection, FIPS 203/204/205, SP 800-131A",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-PQC-GENERAL",
        rules: PQC_SARIF_RULE_IDS,
        checker: NistPqcChecker::boxed,
        subjects: Subjects::CryptographicAssets,
        inputs: RunInputs {
            pqc_mode: true,
            pqc_profile: true,
            ..RunInputs::NONE
        },
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::BsiTr03183_2,
        key: "bsi",
        cli: Some(CliNames {
            aliases: &["tr-03183", "tr03183", "bsi-tr-03183-2"],
            help: "BSI TR-03183-2 v2.1.0 (German national CRA-aligned SBOM guideline)",
        }),
        name: "BSI TR-03183-2",
        short_name: "BSI",
        description: "BSI TR-03183-2 v2.1.0 — German national SBOM guideline (free, ENISA-cited): CycloneDX 1.6+/SPDX 3.0.1+ formats, required creator/timestamp, per-component version/licences/SHA-512 hash",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-BSI-TR-03183-2-GENERAL",
        rules: BSI_SARIF_RULE_IDS,
        checker: BsiTr03183Checker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::CraOssSteward,
        key: "oss-steward",
        cli: Some(CliNames {
            aliases: &["cra-oss-steward", "cra-oss", "cra-art24", "art24"],
            help: "CRA Article 24 — open-source software steward profile",
        }),
        name: "CRA OSS Steward (Art. 24)",
        short_name: "OSS",
        description: "CRA Article 24 — Open-source software steward (lighter than full manufacturer obligations): SBOM + CVD policy + vuln-handling required, no DoC/module/manufacturer-email enforcement",
        cra: true,
        cra_phase: None,
        fallback_rule: "SBOM-CRA-GENERAL",
        rules: CRA_OSS_STEWARD_SARIF_RULE_IDS,
        checker: CraOssStewardChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::SIDECAR,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::EuccSubstantial,
        key: "eucc",
        cli: Some(CliNames {
            aliases: &["eucc-substantial", "common-criteria"],
            help: "EUCC Substantial assurance level (Reg. (EU) 2024/482 as amended by 2024/3144 and 2025/2462), reference-only",
        }),
        name: "EUCC Substantial (Reg. 2024/482)",
        short_name: "EUCC",
        description: "EUCC Substantial (Implementing Reg. (EU) 2024/482, as amended by 2024/3144 and 2025/2462) — reference-only check for Common-Criteria Protection Profile, Target of Evaluation, ITSEF, and certificate valid-until date",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-EUCC-GENERAL",
        rules: EUCC_SARIF_RULE_IDS,
        checker: EuccSubstantialChecker::boxed,
        subjects: Subjects::CertificationEvidence,
        inputs: RunInputs::SIDECAR,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::EuAiAct,
        key: "ai-act",
        cli: Some(CliNames {
            aliases: &["ai_act", "aiact", "eu-ai-act"],
            help: "EU AI Act (Reg. (EU) 2024/1689, as amended by Reg. (EU) 2026/1744) Annex IV documentation readiness",
        }),
        name: "EU AI Act Annex IV Readiness",
        short_name: "AI-Act",
        description: "EU AI Act (Reg. (EU) 2024/1689, as amended by Reg. (EU) 2026/1744) Annex IV technical-documentation READINESS — model description, training-data characteristics, validation/testing metrics, limitations (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-AIACT-GENERAL",
        rules: AIACT_SARIF_RULE_IDS,
        checker: EuAiActChecker::boxed,
        subjects: Subjects::AiBom,
        inputs: RunInputs::SIDECAR,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::BsiSbomForAi,
        key: "bsi-ai",
        cli: Some(CliNames {
            aliases: &["bsi_ai", "bsiai", "sbom-for-ai", "ai-bom"],
            help: "BSI/G7 \"SBOM for AI — Minimum Elements\" readiness",
        }),
        name: "BSI/G7 SBOM-for-AI Minimum Elements Readiness",
        short_name: "BSI-AI",
        description: "BSI/G7 SBOM-for-AI Minimum Elements (joint G7 final, May 2026) READINESS — scores an AI-BOM element-by-element across the Metadata, System-Level, Models, Datasets, Infrastructure, and Security clusters (readiness only, not a legal-conformity guarantee; N/A for non-AI SBOMs)",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-BSIAI-GENERAL",
        rules: BSIAI_SARIF_RULE_IDS,
        checker: BsiSbomForAiChecker::boxed,
        subjects: Subjects::AiBom,
        inputs: RunInputs::NONE,
        in_tui_presets: true,
    },
    StandardDescriptor {
        level: ComplianceLevel::Cisa2026,
        key: "cisa-2026",
        cli: Some(CliNames {
            aliases: &["cisa", "cisa2026", "minimum-elements-2026"],
            help: "CISA 2026 Minimum Elements for an SBOM (v2.1, July 2026; successor to the NTIA 2021 Minimum Elements)",
        }),
        name: "CISA 2026 Minimum Elements",
        short_name: "CISA26",
        description: "2026 Minimum Elements for an SBOM (CISA et al., July 2026) — successor to NTIA 2021: author (person/org), signature, format name+version, generation context, timestamp, tool name+version, SBOM version, and per-component producer/name/version/identifiers/hash/license/dependencies. Frequency, distribution, and update accommodation are organizational practices with no in-document evidence and carry no rules.",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-CISA2026-GENERAL",
        rules: CISA2026_SARIF_RULE_IDS,
        checker: Cisa2026Checker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::PciDss632,
        key: "pci-dss",
        cli: Some(CliNames {
            aliases: &["pci", "pci-dss-6-3-2", "pci-dss-4"],
            help: "PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile",
        }),
        name: "PCI DSS v4.0.1 Req. 6.3.2",
        short_name: "PCI",
        description: "PCI DSS v4.0.1 Req. 6.3.2 software-inventory profile (required in assessments since 31 Mar 2025) — inventory completeness, per-component name/version/supplier/identifier, freshness, and vulnerability-management usability; 6.3.1/11.3.1.1 risk-ranking checks where vulnerability data is embedded. Assessor-side testing procedures (interviews, software comparison) are out of document reach.",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-PCI-GENERAL",
        rules: PCIDSS_SARIF_RULE_IDS,
        checker: PciDss632Checker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::Fsct,
        key: "fsct",
        cli: Some(CliNames {
            aliases: &["fsct-3", "component-transparency"],
            help: "CISA Framing Software Component Transparency, 3rd ed. (2024)",
        }),
        name: "CISA Framing Software Component Transparency (3rd ed.)",
        short_name: "FSCT",
        description: "CISA Framing Software Component Transparency, 3rd ed. (2024) — baseline attributes (author, timestamp, primary component, name, version, supplier, identifiers, hashes, relationships, licenses, copyright) across the Minimum Expected (Error) / Recommended Practice (Warning) / Aspirational Goal (Info) maturity tiers",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-FSCT-GENERAL",
        rules: FSCT_SARIF_RULE_IDS,
        checker: FsctChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
    },
    StandardDescriptor {
        level: ComplianceLevel::Comprehensive,
        key: "comprehensive",
        cli: None,
        name: "Comprehensive",
        short_name: "Full",
        description: "All recommended fields and best practices",
        cra: false,
        cra_phase: None,
        fallback_rule: "SBOM-QUALITY-GENERAL",
        rules: COMPREHENSIVE_SARIF_RULE_IDS,
        checker: GenericChecker::boxed,
        subjects: Subjects::Packages,
        inputs: RunInputs::NONE,
        in_tui_presets: false,
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
    use crate::quality::{
        RuleCatalogFilter, StandardSelector, all_rule_ids, rule_catalog, rule_meta,
    };
    use clap::ValueEnum;
    use std::collections::{BTreeMap, BTreeSet};

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

    /// Each level's rules are registered, its fallback rule is a registered
    /// self-descriptor in no list, and every registered rule is in some
    /// level's list or is a fallback.
    #[test]
    fn every_level_has_a_registered_rule_list() {
        let mut covered = BTreeSet::new();
        for d in STANDARDS {
            assert!(!d.rules.is_empty(), "{:?} has no rules", d.level);
            for id in d.rules {
                assert!(rule_meta(id).is_some(), "{id} of {:?}", d.level);
                covered.insert(*id);
            }
            let fallback = rule_meta(d.fallback_rule).expect("registered fallback");
            assert_eq!(fallback.sarif_id, d.fallback_rule);
            assert!(!d.rules.contains(&d.fallback_rule), "{:?}", d.level);
            covered.insert(d.fallback_rule);
        }
        let registered: BTreeSet<&str> = all_rule_ids().iter().copied().collect();
        assert_eq!(covered, registered);
    }

    #[test]
    fn each_entry_builds_the_checker_of_its_level() {
        for d in STANDARDS {
            assert_eq!((d.checker)(d.level).level(), d.level);
        }
    }

    /// The facts that depend on each other agree.
    #[test]
    fn related_facts_agree() {
        for d in STANDARDS {
            let level = d.level;
            // A CRA phase is a CRA check; the product class calibrates the
            // phase checks, and the sidecar carries it.
            assert!(d.cra_phase.is_none() || d.cra, "{level:?}");
            assert_eq!(d.inputs.product_class, d.cra_phase.is_some(), "{level:?}");
            assert!(!d.inputs.product_class || d.inputs.sidecar, "{level:?}");
            // Only the crypto standards read the PQC inputs; the profile
            // and the category apply in deadline mode.
            assert_eq!(
                d.inputs.pqc_mode,
                d.subjects == Subjects::CryptographicAssets,
                "{level:?}"
            );
            assert!(!d.inputs.pqc_profile || d.inputs.pqc_mode, "{level:?}");
            assert!(!d.inputs.cnsa_category || d.inputs.pqc_mode, "{level:?}");
            // EUCC judges the sidecar's certification evidence.
            assert!(
                d.subjects != Subjects::CertificationEvidence || d.inputs.sidecar,
                "{level:?}"
            );
        }
    }

    /// The keys, the aliases and the quality profiles' keys are one
    /// namespace: `rules` and the reports name a standard by its key, and
    /// `--standard` must never read one spelling two ways.
    #[test]
    fn keys_and_cli_names_are_unique() {
        let mut seen: BTreeMap<&str, ComplianceLevel> = BTreeMap::new();
        for d in STANDARDS {
            let aliases = d.cli.as_ref().map_or(&[][..], |cli| cli.aliases);
            for name in std::iter::once(d.key).chain(aliases.iter().copied()) {
                if let Some(other) = seen.insert(name, d.level) {
                    panic!("{name} names both {other:?} and {:?}", d.level);
                }
            }
        }
        for d in STANDARDS.iter().filter(|d| d.cli.is_none()) {
            assert_eq!(d.key, d.name.to_lowercase(), "{:?}", d.level);
        }
    }

    /// Every spelling of a standard parses back to its level through the
    /// parser the CLI and the config file use (`FromStr`, which the
    /// `--standard` value parser calls) and through clap's own `ValueEnum`
    /// parser.
    #[test]
    fn every_cli_name_parses_back_to_its_level() {
        for d in STANDARDS {
            let Some(cli) = &d.cli else { continue };
            for name in std::iter::once(d.key).chain(cli.aliases.iter().copied()) {
                for spelling in [name.to_string(), name.to_uppercase()] {
                    let parsed: StandardSelector = spelling
                        .parse()
                        .unwrap_or_else(|e| panic!("{spelling} must parse: {e}"));
                    assert_eq!(parsed.level(), d.level, "{spelling}");
                    let clap = StandardSelector::from_str(&spelling, true)
                        .unwrap_or_else(|e| panic!("{spelling} must parse: {e}"));
                    assert_eq!(clap, parsed, "{spelling}");
                }
            }
        }
    }

    /// `--standard` offers exactly the entries with CLI names, once each,
    /// under the entry's key, aliases and help line.
    #[test]
    fn the_selectors_are_the_entries_with_cli_names() {
        let selectable: Vec<ComplianceLevel> = STANDARDS
            .iter()
            .filter(|d| d.cli.is_some())
            .map(|d| d.level)
            .collect();
        let selected: BTreeSet<&str> = StandardSelector::value_variants()
            .iter()
            .map(|s| s.level().descriptor().key)
            .collect();
        assert_eq!(selected.len(), StandardSelector::value_variants().len());
        assert_eq!(
            selected,
            selectable.iter().map(|l| l.descriptor().key).collect()
        );
        for selector in StandardSelector::value_variants() {
            let d = selector.level().descriptor();
            let cli = d.cli.as_ref().expect("a selector's level has CLI names");
            let value = selector
                .to_possible_value()
                .expect("every selector is offered");
            let names: Vec<&str> = value.get_name_and_aliases().collect();
            let mut expected = vec![d.key];
            expected.extend(cli.aliases);
            assert_eq!(names, expected, "{selector:?}");
            assert_eq!(
                value.get_help().map(ToString::to_string).as_deref(),
                Some(cli.help)
            );
            assert_eq!(selector.canonical_name(), d.key);
        }
    }
}
