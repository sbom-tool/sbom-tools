//! CLI-facing compliance-standard selector.
//!
//! Single source of truth for mapping user-facing standard names (and their
//! aliases) to [`ComplianceLevel`]. Everything that accepts a standard name —
//! the clap definition of `validate --standard` (help text, parse errors,
//! shell completions), the config file's `compliance.standards` section, and
//! `cli::run_validate` — parses through this type, so the accepted spellings
//! can never drift between the CLI, the config file, and the docs again.

use super::ComplianceLevel;
use clap::ValueEnum;

/// A compliance standard as selected on the command line or in the config
/// file. Each variant corresponds to one canonical `--standard` value; the
/// historical alias spellings are attached via `#[value(alias = ...)]` so
/// clap (and [`std::str::FromStr`], which delegates to the same table)
/// accepts them everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
#[non_exhaustive]
pub enum StandardSelector {
    /// NTIA Minimum Elements for software transparency
    #[value(name = "ntia")]
    Ntia,
    /// FDA premarket submission requirements for medical devices
    #[value(name = "fda")]
    Fda,
    /// EU CRA Phase 2 — full application of the regulation (from 11 Dec 2027).
    /// `cra` selects Phase 2; use `cra-phase1` for the 2026 reporting phase.
    #[value(name = "cra", alias = "cra-phase2")]
    Cra,
    /// EU CRA Phase 1 — Art. 14 reporting obligations (apply from 11 Sep 2026)
    #[value(name = "cra-phase1", alias = "cra-2026")]
    CraPhase1,
    /// NIST SP 800-218 Secure Software Development Framework
    #[value(name = "ssdf", alias = "nist-ssdf", alias = "nist_ssdf")]
    Ssdf,
    /// Executive Order 14028 Section 4 — software supply chain security
    /// practice (no federal mandate: OMB M-26-05 rescinded M-22-18)
    #[value(name = "eo14028", alias = "eo-14028", alias = "eo_14028")]
    Eo14028,
    /// NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0,
    /// required for US national security systems by CNSSP 15
    #[value(name = "cnsa2", alias = "cnsa-2", alias = "cnsa_2", alias = "cnsa2.0")]
    Cnsa2,
    /// NIST PQC readiness (IR 8547 + FIPS 203/204/205)
    #[value(name = "pqc", alias = "nist-pqc", alias = "nist_pqc")]
    Pqc,
    /// BSI TR-03183-2 v2.1.0 (German national CRA-aligned SBOM guideline)
    #[value(
        name = "bsi",
        alias = "tr-03183",
        alias = "tr03183",
        alias = "bsi-tr-03183-2"
    )]
    Bsi,
    /// CRA Article 24 — open-source software steward profile
    #[value(
        name = "oss-steward",
        alias = "cra-oss-steward",
        alias = "cra-oss",
        alias = "cra-art24",
        alias = "art24"
    )]
    OssSteward,
    /// EUCC Substantial assurance level (Reg. (EU) 2024/482 as amended by
    /// 2024/3144 and 2025/2462), reference-only
    #[value(name = "eucc", alias = "eucc-substantial", alias = "common-criteria")]
    Eucc,
    /// EU AI Act (Reg. (EU) 2024/1689, as amended by Reg. (EU) 2026/1744)
    /// Annex IV documentation readiness
    #[value(
        name = "ai-act",
        alias = "ai_act",
        alias = "aiact",
        alias = "eu-ai-act"
    )]
    AiAct,
    /// BSI/G7 "SBOM for AI — Minimum Elements" readiness
    #[value(
        name = "bsi-ai",
        alias = "bsi_ai",
        alias = "bsiai",
        alias = "sbom-for-ai",
        alias = "ai-bom"
    )]
    BsiAi,
    /// CISA 2026 Minimum Elements for an SBOM (v2.1, July 2026; successor
    /// to the NTIA 2021 Minimum Elements)
    #[value(
        name = "cisa-2026",
        alias = "cisa",
        alias = "cisa2026",
        alias = "minimum-elements-2026"
    )]
    Cisa2026,
    /// PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile
    #[value(
        name = "pci-dss",
        alias = "pci",
        alias = "pci-dss-6-3-2",
        alias = "pci-dss-4"
    )]
    PciDss,
    /// CISA Framing Software Component Transparency, 3rd ed. (2024)
    #[value(name = "fsct", alias = "fsct-3", alias = "component-transparency")]
    Fsct,
}

impl StandardSelector {
    /// The [`ComplianceLevel`] this selector maps to.
    #[must_use]
    pub const fn level(self) -> ComplianceLevel {
        match self {
            Self::Ntia => ComplianceLevel::NtiaMinimum,
            Self::Fda => ComplianceLevel::FdaMedicalDevice,
            Self::Cra => ComplianceLevel::CraPhase2,
            Self::CraPhase1 => ComplianceLevel::CraPhase1,
            Self::Ssdf => ComplianceLevel::NistSsdf,
            Self::Eo14028 => ComplianceLevel::Eo14028,
            Self::Cnsa2 => ComplianceLevel::Cnsa2,
            Self::Pqc => ComplianceLevel::NistPqc,
            Self::Bsi => ComplianceLevel::BsiTr03183_2,
            Self::OssSteward => ComplianceLevel::CraOssSteward,
            Self::Eucc => ComplianceLevel::EuccSubstantial,
            Self::AiAct => ComplianceLevel::EuAiAct,
            Self::BsiAi => ComplianceLevel::BsiSbomForAi,
            Self::Cisa2026 => ComplianceLevel::Cisa2026,
            Self::PciDss => ComplianceLevel::PciDss632,
            Self::Fsct => ComplianceLevel::Fsct,
        }
    }

    /// The canonical CLI spelling (the `#[value(name = ...)]`).
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Ntia => "ntia",
            Self::Fda => "fda",
            Self::Cra => "cra",
            Self::CraPhase1 => "cra-phase1",
            Self::Ssdf => "ssdf",
            Self::Eo14028 => "eo14028",
            Self::Cnsa2 => "cnsa2",
            Self::Pqc => "pqc",
            Self::Bsi => "bsi",
            Self::OssSteward => "oss-steward",
            Self::Eucc => "eucc",
            Self::AiAct => "ai-act",
            Self::BsiAi => "bsi-ai",
            Self::Cisa2026 => "cisa-2026",
            Self::PciDss => "pci-dss",
            Self::Fsct => "fsct",
        }
    }

    /// Comma-separated list of every canonical value, for error messages.
    #[must_use]
    pub fn valid_values() -> String {
        Self::value_variants()
            .iter()
            .map(|v| v.canonical_name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `selectors` split into the ones to check, one per level in the order
    /// each level was first selected, and the repeats, which select a level
    /// an earlier selector already did. `cra,cra-phase2` names CRA Phase 2
    /// twice: checking it twice would report every finding twice.
    #[must_use]
    pub fn dedup_by_level(selectors: &[Self]) -> (Vec<Self>, Vec<Self>) {
        let mut kept: Vec<Self> = Vec::with_capacity(selectors.len());
        let mut repeats = Vec::new();
        for selector in selectors {
            if kept.iter().any(|k| k.level() == selector.level()) {
                repeats.push(*selector);
            } else {
                kept.push(*selector);
            }
        }
        (kept, repeats)
    }
}

impl std::fmt::Display for StandardSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.canonical_name())
    }
}

impl std::str::FromStr for StandardSelector {
    type Err = String;

    /// Case-insensitive parse through the same name/alias table clap uses.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        for variant in Self::value_variants() {
            if variant
                .to_possible_value()
                .is_some_and(|pv| pv.matches(s, true))
            {
                return Ok(*variant);
            }
        }
        Err(format!(
            "unknown compliance standard '{s}'. Valid values: {} \
             (aliases such as nist-ssdf, tr-03183, cra-art24 are also accepted; \
             see `sbom-tools validate --help`)",
            Self::valid_values()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract test: every documented alias parses to the right level.
    /// This is the complete alias table formerly hand-rolled in
    /// `cli/validate.rs`; removing or re-mapping any spelling is a breaking
    /// CLI change and must fail here.
    #[test]
    fn every_documented_alias_parses_to_the_right_level() {
        let table: &[(&str, ComplianceLevel)] = &[
            ("ntia", ComplianceLevel::NtiaMinimum),
            ("fda", ComplianceLevel::FdaMedicalDevice),
            ("cra", ComplianceLevel::CraPhase2),
            ("cra-phase2", ComplianceLevel::CraPhase2),
            ("cra-phase1", ComplianceLevel::CraPhase1),
            ("cra-2026", ComplianceLevel::CraPhase1),
            ("ssdf", ComplianceLevel::NistSsdf),
            ("nist-ssdf", ComplianceLevel::NistSsdf),
            ("nist_ssdf", ComplianceLevel::NistSsdf),
            ("eo14028", ComplianceLevel::Eo14028),
            ("eo-14028", ComplianceLevel::Eo14028),
            ("eo_14028", ComplianceLevel::Eo14028),
            ("cnsa2", ComplianceLevel::Cnsa2),
            ("cnsa-2", ComplianceLevel::Cnsa2),
            ("cnsa_2", ComplianceLevel::Cnsa2),
            ("cnsa2.0", ComplianceLevel::Cnsa2),
            ("pqc", ComplianceLevel::NistPqc),
            ("nist-pqc", ComplianceLevel::NistPqc),
            ("nist_pqc", ComplianceLevel::NistPqc),
            ("bsi", ComplianceLevel::BsiTr03183_2),
            ("tr-03183", ComplianceLevel::BsiTr03183_2),
            ("tr03183", ComplianceLevel::BsiTr03183_2),
            ("bsi-tr-03183-2", ComplianceLevel::BsiTr03183_2),
            ("oss-steward", ComplianceLevel::CraOssSteward),
            ("cra-oss-steward", ComplianceLevel::CraOssSteward),
            ("cra-oss", ComplianceLevel::CraOssSteward),
            ("cra-art24", ComplianceLevel::CraOssSteward),
            ("art24", ComplianceLevel::CraOssSteward),
            ("eucc", ComplianceLevel::EuccSubstantial),
            ("eucc-substantial", ComplianceLevel::EuccSubstantial),
            ("common-criteria", ComplianceLevel::EuccSubstantial),
            ("ai-act", ComplianceLevel::EuAiAct),
            ("ai_act", ComplianceLevel::EuAiAct),
            ("aiact", ComplianceLevel::EuAiAct),
            ("eu-ai-act", ComplianceLevel::EuAiAct),
            ("bsi-ai", ComplianceLevel::BsiSbomForAi),
            ("bsi_ai", ComplianceLevel::BsiSbomForAi),
            ("bsiai", ComplianceLevel::BsiSbomForAi),
            ("sbom-for-ai", ComplianceLevel::BsiSbomForAi),
            ("ai-bom", ComplianceLevel::BsiSbomForAi),
            ("cisa-2026", ComplianceLevel::Cisa2026),
            ("cisa", ComplianceLevel::Cisa2026),
            ("cisa2026", ComplianceLevel::Cisa2026),
            ("minimum-elements-2026", ComplianceLevel::Cisa2026),
            ("pci-dss", ComplianceLevel::PciDss632),
            ("pci", ComplianceLevel::PciDss632),
            ("pci-dss-6-3-2", ComplianceLevel::PciDss632),
            ("pci-dss-4", ComplianceLevel::PciDss632),
            ("fsct", ComplianceLevel::Fsct),
            ("fsct-3", ComplianceLevel::Fsct),
            ("component-transparency", ComplianceLevel::Fsct),
        ];
        for (spelling, expected) in table {
            let parsed: StandardSelector = spelling
                .parse()
                .unwrap_or_else(|e| panic!("'{spelling}' must parse: {e}"));
            assert_eq!(
                parsed.level(),
                *expected,
                "'{spelling}' mapped to the wrong compliance level"
            );
        }
    }

    #[test]
    fn parse_is_case_insensitive_and_trims() {
        assert_eq!(
            "NTIA".parse::<StandardSelector>().unwrap(),
            StandardSelector::Ntia
        );
        assert_eq!(
            " Cra-Phase1 ".parse::<StandardSelector>().unwrap(),
            StandardSelector::CraPhase1
        );
        assert_eq!(
            "CNSA2.0".parse::<StandardSelector>().unwrap(),
            StandardSelector::Cnsa2
        );
    }

    #[test]
    fn unknown_standard_error_lists_valid_values() {
        let err = "not-a-standard".parse::<StandardSelector>().unwrap_err();
        assert!(err.contains("not-a-standard"));
        for canonical in [
            "ntia",
            "fda",
            "cra",
            "cra-phase1",
            "ssdf",
            "eo14028",
            "cnsa2",
            "pqc",
            "bsi",
            "oss-steward",
            "eucc",
            "ai-act",
            "bsi-ai",
            "cisa-2026",
            "pci-dss",
            "fsct",
        ] {
            assert!(err.contains(canonical), "error must list '{canonical}'");
        }
    }

    #[test]
    fn every_variant_has_a_level_and_canonical_name_roundtrip() {
        for variant in StandardSelector::value_variants() {
            let name = variant.canonical_name();
            let reparsed: StandardSelector = name.parse().unwrap();
            assert_eq!(reparsed, *variant, "canonical '{name}' must round-trip");
            // level() must not panic and must be a real checkable level
            let _ = variant.level().name();
        }
    }

    #[test]
    fn dedup_by_level_keeps_the_first_selection_of_each_level() {
        let parse = |s: &str| s.parse::<StandardSelector>().unwrap();
        // `cra` and `cra-phase2` (alias) select one level.
        let selected = [
            parse("cra-phase2"),
            parse("ntia"),
            parse("cra"),
            parse("cra-phase1"),
            parse("ntia"),
        ];
        let (kept, repeats) = StandardSelector::dedup_by_level(&selected);
        assert_eq!(
            kept,
            [
                StandardSelector::Cra,
                StandardSelector::Ntia,
                StandardSelector::CraPhase1
            ]
        );
        assert_eq!(repeats, [StandardSelector::Cra, StandardSelector::Ntia]);

        let (kept, repeats) = StandardSelector::dedup_by_level(&[]);
        assert!(kept.is_empty() && repeats.is_empty());
    }

    #[test]
    fn cra_selects_phase2_and_phase1_is_reachable() {
        assert_eq!(
            "cra".parse::<StandardSelector>().unwrap().level(),
            ComplianceLevel::CraPhase2
        );
        assert_eq!(
            "cra-phase1".parse::<StandardSelector>().unwrap().level(),
            ComplianceLevel::CraPhase1
        );
    }
}
