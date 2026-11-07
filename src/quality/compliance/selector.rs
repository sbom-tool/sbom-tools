//! CLI-facing compliance-standard selector.
//!
//! Single source of truth for mapping user-facing standard names (and their
//! aliases) to [`ComplianceLevel`]. Everything that accepts a standard name —
//! the clap definition of `validate --standard` (help text, parse errors,
//! shell completions), the config file's `compliance.standards` section, and
//! `cli::run_validate` — parses through this type, so the accepted spellings
//! can never drift between the CLI, the config file, and the docs again. The
//! spellings and their help lines are in each level's entry in the
//! standards table (`standards.rs`).

use super::ComplianceLevel;
use clap::ValueEnum;
use clap::builder::PossibleValue;

/// A compliance standard as selected on the command line or in the config
/// file. Each variant corresponds to one canonical `--standard` value, the
/// key of its level; the historical alias spellings come from the same
/// entry of the standards table, so clap (and [`std::str::FromStr`], which
/// delegates to the same table) accepts them everywhere. `--help` lists the
/// values in the variant order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandardSelector {
    /// `ntia`: [`ComplianceLevel::NtiaMinimum`].
    Ntia,
    /// `fda`: [`ComplianceLevel::FdaMedicalDevice`].
    Fda,
    /// `cra`: [`ComplianceLevel::CraPhase2`]. `cra` selects Phase 2; use
    /// `cra-phase1` for the 2026 reporting phase.
    Cra,
    /// `cra-phase1`: [`ComplianceLevel::CraPhase1`].
    CraPhase1,
    /// `ssdf`: [`ComplianceLevel::NistSsdf`].
    Ssdf,
    /// `eo14028`: [`ComplianceLevel::Eo14028`].
    Eo14028,
    /// `cnsa2`: [`ComplianceLevel::Cnsa2`].
    Cnsa2,
    /// `pqc`: [`ComplianceLevel::NistPqc`].
    Pqc,
    /// `bsi`: [`ComplianceLevel::BsiTr03183_2`].
    Bsi,
    /// `oss-steward`: [`ComplianceLevel::CraOssSteward`].
    OssSteward,
    /// `eucc`: [`ComplianceLevel::EuccSubstantial`].
    Eucc,
    /// `ai-act`: [`ComplianceLevel::EuAiAct`].
    AiAct,
    /// `bsi-ai`: [`ComplianceLevel::BsiSbomForAi`].
    BsiAi,
    /// `cisa-2026`: [`ComplianceLevel::Cisa2026`].
    Cisa2026,
    /// `pci-dss`: [`ComplianceLevel::PciDss632`].
    PciDss,
    /// `fsct`: [`ComplianceLevel::Fsct`].
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

    /// The canonical CLI spelling: the key of the selected level.
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        self.level().descriptor().key
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

impl ValueEnum for StandardSelector {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Ntia,
            Self::Fda,
            Self::Cra,
            Self::CraPhase1,
            Self::Ssdf,
            Self::Eo14028,
            Self::Cnsa2,
            Self::Pqc,
            Self::Bsi,
            Self::OssSteward,
            Self::Eucc,
            Self::AiAct,
            Self::BsiAi,
            Self::Cisa2026,
            Self::PciDss,
            Self::Fsct,
        ]
    }

    /// The canonical value, the aliases and the help line of the selected
    /// level's entry in the standards table.
    fn to_possible_value(&self) -> Option<PossibleValue> {
        let descriptor = self.level().descriptor();
        let cli = descriptor.cli.as_ref()?;
        Some(
            PossibleValue::new(descriptor.key)
                .help(cli.help)
                .aliases(cli.aliases.iter().copied()),
        )
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
