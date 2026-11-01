//! Per-rule settings of a run: a rule turned off, or its findings given
//! another severity (`--rule RULE=SETTING`, the config file's
//! `compliance.rules`).
//!
//! Settings are applied after the checks, in one place
//! ([`ComplianceChecker::check`](super::ComplianceChecker::check)), so the
//! verdict, the counts, the score and the exit code follow the severities a
//! run sets. A finding keeps the severity its check gave it in
//! [`Violation::severity_override`]. The findings of a rule that is off leave
//! the violations and are counted in
//! [`ComplianceResult::suppressed`](super::ComplianceResult::suppressed), so
//! nothing disappears silently.

use super::registry::resolve_rule_id;
use super::{ComplianceLevel, RuleKind, Violation, ViolationSeverity, rule_kind, rules_for_level};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a run does with the findings of one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RuleSetting {
    /// Drop the rule's findings. They count toward no severity, the verdict,
    /// the score or an exit code; the result lists how many there were.
    Off,
    /// Report the rule's findings as info.
    Info,
    /// Report the rule's findings as warnings.
    Warning,
    /// Report the rule's findings as errors.
    Error,
}

impl RuleSetting {
    /// Every setting, in the order the help text lists them.
    pub const ALL: [Self; 4] = [Self::Off, Self::Info, Self::Warning, Self::Error];

    /// The setting as the command line and the config file spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// The severity the rule's findings get; `None` for [`Self::Off`].
    #[must_use]
    pub const fn severity(self) -> Option<ViolationSeverity> {
        match self {
            Self::Off => None,
            Self::Info => Some(ViolationSeverity::Info),
            Self::Warning => Some(ViolationSeverity::Warning),
            Self::Error => Some(ViolationSeverity::Error),
        }
    }
}

impl std::fmt::Display for RuleSetting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for RuleSetting {
    type Err = String;

    /// Parse a setting, ignoring case and surrounding whitespace.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|setting| setting.name().eq_ignore_ascii_case(value.trim()))
            .ok_or_else(|| {
                format!("invalid rule setting '{value}'; valid values: off, info, warning, error")
            })
    }
}

/// Where a rule setting comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SettingSource {
    /// The config file's `compliance.rules`.
    Config,
    /// A `--rule` flag, which wins over the config file.
    Cli,
}

impl SettingSource {
    /// The source as the output names it (`severity_source`): `config` or
    /// `cli`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Cli => "cli",
        }
    }

    /// How a message names the source.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Config => "the config file",
            Self::Cli => "--rule",
        }
    }
}

/// On a finding whose rule a run set: the severity the check gave it, and
/// where the setting comes from. The finding's own `severity` is the one
/// the setting gives it. Serialized as the finding's `default_severity` and
/// `severity_source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeverityOverride {
    /// The severity the check gave the finding: the rule's registry default,
    /// or the one the check calibrated (by product class, CRA phase or PQC
    /// deadline).
    pub default: ViolationSeverity,
    /// Where the setting comes from.
    pub source: SettingSource,
}

impl SeverityOverride {
    /// The override of a finding the check reported at `default`, by a
    /// setting from `source`.
    #[must_use]
    pub const fn new(default: ViolationSeverity, source: SettingSource) -> Self {
        Self { default, source }
    }
}

/// A rule whose findings a run turned off: how many it dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SuppressedRule {
    /// The rule's id.
    pub rule_id: String,
    /// How many of the rule's findings the run dropped.
    pub findings: usize,
    /// Where the `off` setting comes from.
    pub source: SettingSource,
}

/// The rule settings of a run: for each rule set, what to do with its
/// findings and where that comes from.
///
/// Setting a rule again replaces its setting, so the `--rule` flags, set
/// after the config file's `compliance.rules`, win over the file. Hand the
/// settings to a run with
/// [`ComplianceRunConfig::with_rule_settings`](super::ComplianceRunConfig::with_rule_settings).
///
/// ```
/// use sbom_tools::quality::{RuleSetting, RuleSettings, SettingSource};
///
/// let mut settings = RuleSettings::new();
/// settings
///     .set("sbom-ntia-supplier", RuleSetting::Warning, SettingSource::Config)
///     .unwrap();
/// // A later setting of the same rule wins.
/// settings
///     .set("SBOM-NTIA-SUPPLIER", RuleSetting::Off, SettingSource::Cli)
///     .unwrap();
/// assert_eq!(
///     settings.get("SBOM-NTIA-SUPPLIER"),
///     Some((RuleSetting::Off, SettingSource::Cli))
/// );
/// assert!(settings.set("SBOM-NTIA-SUPLIER", RuleSetting::Off, SettingSource::Cli).is_err());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSettings {
    settings: BTreeMap<&'static str, (RuleSetting, SettingSource)>,
}

impl RuleSettings {
    /// No settings: every finding keeps the severity its check gives it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            settings: BTreeMap::new(),
        }
    }

    /// Set the rule `rule_id` (any case) to `setting`, from `source`,
    /// replacing an earlier setting of the rule. Returns the registry's
    /// spelling of the id.
    ///
    /// # Errors
    ///
    /// `rule_id` names no registered rule (the message names the closest
    /// one), or names a pass-only rule, whose passed checks have no severity.
    pub fn set(
        &mut self,
        rule_id: &str,
        setting: RuleSetting,
        source: SettingSource,
    ) -> Result<&'static str, String> {
        let id = resolve_rule_id(rule_id)?;
        if rule_kind(id) == Some(RuleKind::Pass) {
            return Err(format!(
                "{id} reports passed checks, which have no severity to set"
            ));
        }
        self.settings.insert(id, (setting, source));
        Ok(id)
    }

    /// The setting of the rule `rule_id` (the registry's spelling) and where
    /// it comes from, if the run sets it.
    #[must_use]
    pub fn get(&self, rule_id: &str) -> Option<(RuleSetting, SettingSource)> {
        self.settings.get(rule_id).copied()
    }

    /// Whether no rule is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    /// The number of rules set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Every rule set, by rule id: the id, its setting and where it comes
    /// from.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, RuleSetting, SettingSource)> + '_ {
        self.settings
            .iter()
            .map(|(id, (setting, source))| (*id, *setting, *source))
    }

    /// The rules set that no check of `levels` reports (see
    /// [`rules_for_level`]): settings that change nothing in a run of those
    /// levels.
    #[must_use]
    pub fn unmatched(
        &self,
        levels: &[ComplianceLevel],
    ) -> Vec<(&'static str, RuleSetting, SettingSource)> {
        self.iter()
            .filter(|(id, _, _)| {
                !levels
                    .iter()
                    .any(|level| rules_for_level(*level).contains(id))
            })
            .collect()
    }

    /// Apply the settings to the findings of one result: a finding of a rule
    /// set to a severity takes it (keeping the check's in
    /// [`Violation::severity_override`]), and the findings of a rule that is
    /// off are dropped. Returns the rules whose findings were dropped, by
    /// rule id.
    pub(crate) fn apply(&self, violations: &mut Vec<Violation>) -> Vec<SuppressedRule> {
        if self.settings.is_empty() {
            return Vec::new();
        }
        let mut dropped: BTreeMap<&'static str, (usize, SettingSource)> = BTreeMap::new();
        violations.retain_mut(|v| {
            let Some(&(setting, source)) = self.settings.get(v.rule_id) else {
                return true;
            };
            match setting.severity() {
                Some(severity) => {
                    v.severity_override = Some(SeverityOverride::new(v.severity, source));
                    v.severity = severity;
                    true
                }
                None => {
                    dropped.entry(v.rule_id).or_insert((0, source)).0 += 1;
                    false
                }
            }
        });
        dropped
            .into_iter()
            .map(|(rule_id, (findings, source))| SuppressedRule {
                rule_id: rule_id.to_string(),
                findings,
                source,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::ViolationCategory;

    fn finding(rule_id: &'static str, severity: ViolationSeverity) -> Violation {
        Violation {
            severity,
            severity_override: None,
            category: ViolationCategory::SupplierInfo,
            message: format!("{rule_id} finding"),
            element: None,
            component_id: None,
            finding_detail: None,
            counts: None,
            deadline: None,
            field: None,
            observed: None,
            requirement: "requirement".to_string(),
            rule_id,
            standard_refs: Vec::new(),
            remediation: None,
        }
    }

    #[test]
    fn settings_parse_in_any_case_and_reject_other_values() {
        for setting in RuleSetting::ALL {
            assert_eq!(setting.name().parse::<RuleSetting>(), Ok(setting));
            assert_eq!(
                setting.name().to_uppercase().parse::<RuleSetting>(),
                Ok(setting)
            );
        }
        let err = "warn".parse::<RuleSetting>().unwrap_err();
        assert!(err.contains("'warn'") && err.contains("off, info, warning, error"));
    }

    #[test]
    fn unknown_and_pass_only_rules_cannot_be_set() {
        let mut settings = RuleSettings::new();
        let err = settings
            .set("SBOM-NTIA-SUPLIER", RuleSetting::Off, SettingSource::Cli)
            .unwrap_err();
        assert!(err.contains("did you mean SBOM-NTIA-SUPPLIER?"), "{err}");
        let err = settings
            .set("SBOM-PQC-009", RuleSetting::Error, SettingSource::Cli)
            .unwrap_err();
        assert!(err.contains("passed checks"), "{err}");
        assert!(settings.is_empty());
    }

    #[test]
    fn a_later_setting_of_a_rule_wins() {
        let mut settings = RuleSettings::new();
        let id = settings
            .set(
                " sbom-ntia-supplier ",
                RuleSetting::Info,
                SettingSource::Config,
            )
            .unwrap();
        assert_eq!(id, "SBOM-NTIA-SUPPLIER");
        settings
            .set("SBOM-NTIA-SUPPLIER", RuleSetting::Error, SettingSource::Cli)
            .unwrap();
        assert_eq!(settings.len(), 1);
        assert_eq!(
            settings.get("SBOM-NTIA-SUPPLIER"),
            Some((RuleSetting::Error, SettingSource::Cli))
        );
    }

    /// Settings move severities both ways, keep the check's severity, and
    /// count what `off` drops per rule.
    #[test]
    fn apply_overrides_both_ways_and_counts_what_off_drops() {
        let mut settings = RuleSettings::new();
        settings
            .set(
                "SBOM-NTIA-SUPPLIER",
                RuleSetting::Warning,
                SettingSource::Cli,
            )
            .unwrap();
        settings
            .set(
                "SBOM-NTIA-AUTHOR",
                RuleSetting::Error,
                SettingSource::Config,
            )
            .unwrap();
        settings
            .set("SBOM-NTIA-VERSION", RuleSetting::Off, SettingSource::Config)
            .unwrap();
        let mut violations = vec![
            finding("SBOM-NTIA-SUPPLIER", ViolationSeverity::Error),
            finding("SBOM-NTIA-VERSION", ViolationSeverity::Error),
            finding("SBOM-NTIA-AUTHOR", ViolationSeverity::Warning),
            finding("SBOM-NTIA-VERSION", ViolationSeverity::Error),
            finding("SBOM-NTIA-TIMESTAMP", ViolationSeverity::Error),
        ];
        let suppressed = settings.apply(&mut violations);

        let got: Vec<_> = violations
            .iter()
            .map(|v| (v.rule_id, v.severity, v.severity_override))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "SBOM-NTIA-SUPPLIER",
                    ViolationSeverity::Warning,
                    Some(SeverityOverride::new(
                        ViolationSeverity::Error,
                        SettingSource::Cli
                    ))
                ),
                (
                    "SBOM-NTIA-AUTHOR",
                    ViolationSeverity::Error,
                    Some(SeverityOverride::new(
                        ViolationSeverity::Warning,
                        SettingSource::Config
                    ))
                ),
                ("SBOM-NTIA-TIMESTAMP", ViolationSeverity::Error, None),
            ]
        );
        assert_eq!(
            suppressed,
            vec![SuppressedRule {
                rule_id: "SBOM-NTIA-VERSION".to_string(),
                findings: 2,
                source: SettingSource::Config,
            }]
        );
    }

    #[test]
    fn unmatched_lists_the_rules_no_selected_level_reports() {
        let mut settings = RuleSettings::new();
        settings
            .set("SBOM-NTIA-SUPPLIER", RuleSetting::Off, SettingSource::Cli)
            .unwrap();
        settings
            .set("SBOM-CRA-ART-24", RuleSetting::Info, SettingSource::Config)
            .unwrap();
        // A family fallback rule: no check reports it.
        settings
            .set("SBOM-NTIA-GENERAL", RuleSetting::Info, SettingSource::Cli)
            .unwrap();
        let unmatched: Vec<&str> = settings
            .unmatched(&[ComplianceLevel::NtiaMinimum])
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        assert_eq!(unmatched, vec!["SBOM-CRA-ART-24", "SBOM-NTIA-GENERAL"]);
        let unmatched: Vec<&str> = settings
            .unmatched(ComplianceLevel::all())
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        assert_eq!(unmatched, vec!["SBOM-NTIA-GENERAL"]);
    }
}
