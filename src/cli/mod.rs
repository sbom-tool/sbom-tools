//! CLI command handlers.
//!
//! This module provides testable command handlers that are invoked by main.rs.
//! Each handler implements the business logic for a specific CLI subcommand.

#[cfg(feature = "enrichment")]
mod cache;
mod convert;
mod cra_docs;
mod cra_standards_watch;
mod diff;
#[cfg(feature = "enrichment")]
mod enrich;
mod license_check;
mod merge;
mod multi;
mod quality;
mod query;
mod rules;
#[cfg(test)]
mod run_parity_tests;
mod tailor;
mod validate;
mod verify;
mod vex;
mod view;
mod watch;

#[cfg(feature = "enrichment")]
pub use cache::{CacheAction, run_cache};
pub use convert::run_convert;
pub use cra_docs::{run_cra_docs, run_cra_docs_with_force};
pub use cra_standards_watch::{
    OnlineProbe, TrackedStandard, WatchOutputFormat, cra_catalogue, probe_cra_standards,
    run_cra_standards_watch,
};
pub use diff::run_diff;
#[cfg(feature = "enrichment")]
pub use enrich::run_enrich;
pub use license_check::run_license_check;
pub use merge::run_merge;
pub use multi::{run_diff_multi, run_matrix, run_timeline};
pub use quality::{QUALITY_OUTPUT_FORMATS, run_quality};
pub use query::{QueryFilter, run_query};
pub use rules::{RulesOutputFormat, parse_rule_id, run_rules, run_rules_explain};
pub use tailor::run_tailor;
pub use validate::{VALIDATE_OUTPUT_FORMATS, ValidateJsonSchema, run_validate};
pub use verify::{VerifyAction, run_verify};
pub use vex::{VexAction, VexExportFormat, run_vex};
pub use view::run_view;
pub use watch::run_watch;

// Re-export config types used by handlers
pub use crate::config::{DiffConfig, ViewConfig};

/// Reject an output format the given command has no real renderer for.
///
/// Each command handler declares the formats it genuinely supports and calls
/// this before doing any work, so an unsupported `(command, format)` pair
/// fails with a clear error instead of silently substituting another format
/// (e.g. `validate -o html` used to fall through to the plain-text renderer,
/// and `diff -o oscal-json` used to emit plain JSON).
pub(crate) fn ensure_output_format_supported(
    command: &str,
    requested: crate::reports::ReportFormat,
    supported: &[crate::reports::ReportFormat],
) -> anyhow::Result<()> {
    if supported.contains(&requested) {
        return Ok(());
    }
    anyhow::bail!(
        "output format '{requested}' is not supported by `sbom-tools {command}`; \
         supported formats: {}",
        supported
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Resolve the CRA sidecar for a command.
///
/// A sidecar that fails to load is a hard error whether it was **explicitly**
/// requested (CLI flag or config file) or **auto-discovered** next to the
/// SBOM: silently scoring without discovered-but-broken metadata shifts the
/// verdict with only a stderr warning, and the identical file passed via
/// `--cra-sidecar` already hard-errors — the trust decision must not depend
/// on how the file was found.
pub(crate) fn load_cra_sidecar(
    explicit: Option<&std::path::Path>,
    sbom_path: &std::path::Path,
) -> anyhow::Result<Option<crate::model::CraSidecarMetadata>> {
    match explicit {
        Some(p) => crate::model::CraSidecarMetadata::from_file(p)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("Failed to load CRA sidecar from {}: {e}", p.display())),
        None => crate::model::CraSidecarMetadata::discover_for_sbom(sbom_path)
            .map_err(|e| anyhow::anyhow!("Failed to load auto-discovered CRA sidecar: {e}")),
    }
}

/// How the CNSA 2.0 and NIST PQC checks of a run judge quantum-vulnerable
/// cryptography: the shared `--pqc-mode`, `--pqc-profile` and
/// `--cnsa-category` flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PqcOptions {
    /// `--pqc-mode`; readiness unless set.
    pub mode: crate::quality::PqcMode,
    /// `--pqc-profile`, when given.
    pub profile: Option<crate::quality::PqcProfile>,
    /// `--cnsa-category`, when given.
    pub cnsa_category: Option<crate::quality::CnsaCategory>,
}

impl PqcOptions {
    /// The PQC inputs of a run: each flag (`mode`, `profile`,
    /// `cnsa_category`), else the config file's default for it
    /// (`compliance.pqc_mode`, `compliance.pqc_profile`,
    /// `compliance.cnsa_category`). The file's profile and category are
    /// defaults of deadline mode, so a run in readiness mode, such as one
    /// `--pqc-mode readiness` sets, ignores them.
    ///
    /// # Errors
    ///
    /// A config-file value that names no mode, profile or category (the
    /// config validator rejects it first).
    pub fn with_config_defaults(
        mode: Option<crate::quality::PqcMode>,
        profile: Option<crate::quality::PqcProfile>,
        cnsa_category: Option<crate::quality::CnsaCategory>,
        file: &crate::config::ComplianceConfig,
    ) -> anyhow::Result<Self> {
        let mode = match mode {
            Some(mode) => mode,
            None => config_value("pqc_mode", file.pqc_mode.as_deref())?.unwrap_or_default(),
        };
        let deadline = mode == crate::quality::PqcMode::Deadline;
        let profile = match profile {
            Some(profile) => Some(profile),
            None if deadline => config_value("pqc_profile", file.pqc_profile.as_deref())?,
            None => None,
        };
        let cnsa_category = match cnsa_category {
            Some(category) => Some(category),
            None if deadline => config_value("cnsa_category", file.cnsa_category.as_deref())?,
            None => None,
        };
        Ok(Self {
            mode,
            profile,
            cnsa_category,
        })
    }
}

/// The config file's `compliance.<key>` value, parsed as the flag of the
/// same name parses it (any case).
fn config_value<T: clap::ValueEnum>(key: &str, value: Option<&str>) -> anyhow::Result<Option<T>> {
    value
        .map(|v| T::from_str(v, true).map_err(|e| anyhow::anyhow!("invalid compliance.{key}: {e}")))
        .transpose()
}

/// The rule settings and the component scope of a run: the shared `--rule`
/// and `--include-excluded-scope` flags over the config file's
/// `compliance.rules` and `compliance.include_excluded_scope` (see
/// [`RuleOptions::from_flags`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOptions {
    /// Per rule, off or the severity its findings get: the config file's
    /// settings, then each `--rule`, which wins for its rule.
    pub settings: crate::quality::RuleSettings,
    /// Whether the package rules judge components whose scope is excluded
    /// too; by default they leave them out.
    pub include_excluded_scope: bool,
}

impl RuleOptions {
    /// The rule options of a run: the config file's `compliance.rules`
    /// (rule id → setting), then each `--rule` value of `flags`, which wins
    /// over the file for its rule, and whether the package rules judge
    /// components whose scope is excluded (`--include-excluded-scope`, or
    /// the file's `compliance.include_excluded_scope`).
    ///
    /// # Errors
    ///
    /// A file entry that names no rule, a pass-only rule or no setting (the
    /// config validator rejects it first).
    pub fn from_flags(
        flags: &[(&'static str, crate::quality::RuleSetting)],
        include_excluded_scope: bool,
        file: &crate::config::ComplianceConfig,
    ) -> anyhow::Result<Self> {
        use crate::quality::{RuleSettings, SettingSource};
        let mut settings = RuleSettings::new();
        for (rule_id, value) in &file.rules {
            let setting = value
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid compliance.rules.{rule_id}: {e}"))?;
            settings
                .set(rule_id, setting, SettingSource::Config)
                .map_err(|e| anyhow::anyhow!("invalid compliance.rules.{rule_id}: {e}"))?;
        }
        for (rule_id, setting) in flags {
            settings
                .set(rule_id, *setting, SettingSource::Cli)
                .map_err(|e| anyhow::anyhow!("invalid --rule {rule_id}={setting}: {e}"))?;
        }
        Ok(Self {
            settings,
            include_excluded_scope: include_excluded_scope || file.include_excluded_scope,
        })
    }
}

/// Parse one `--rule RULE=SETTING` value: a rule id (any case) and `off`,
/// `info`, `warning` or `error`.
///
/// # Errors
///
/// No `=`, an unknown rule id (the message names the closest one), a
/// pass-only rule, whose passed checks have no severity, or an unknown
/// setting: a usage error (exit 3).
pub fn parse_rule_setting_arg(
    value: &str,
) -> std::result::Result<(&'static str, crate::quality::RuleSetting), String> {
    let Some((rule_id, setting)) = value.split_once('=') else {
        return Err(
            "expected RULE=SETTING, e.g. SBOM-NTIA-SUPPLIER=warning; SETTING is off, \
                    info, warning or error"
                .to_string(),
        );
    };
    let setting: crate::quality::RuleSetting = setting.parse()?;
    let rule_id = crate::quality::RuleSettings::new().set(
        rule_id,
        setting,
        crate::quality::SettingSource::Cli,
    )?;
    Ok((rule_id, setting))
}

/// Parse one `--fail-on RULE` value: a rule id (any case) that reports
/// findings.
///
/// # Errors
///
/// An unknown rule id (the message names the closest one) or a pass-only
/// rule, which never reports a finding: a usage error (exit 3).
pub fn parse_fail_on_arg(value: &str) -> std::result::Result<&'static str, String> {
    let rule_id = parse_rule_id(value)?;
    if crate::quality::rule_kind(rule_id) == Some(crate::quality::RuleKind::Pass) {
        return Err(format!(
            "{rule_id} reports passed checks, never a finding, so it can never fail a run"
        ));
    }
    Ok(rule_id)
}

/// The compliance inputs of a run, parsed strictly from the flags every
/// compliance-checking command shares: `--cra-product-class`, `--as-of`,
/// the PQC flags (`pqc`), and the rule settings and component scope
/// (`rules`). `diff`, `diff-multi`, `timeline` and `matrix` judge every
/// SBOM with these; the commands that judge one SBOM add its CRA sidecar
/// with [`compliance_run_config_for`].
///
/// # Errors
///
/// An unknown product class, an unparseable `--as-of`, or `--pqc-profile` or
/// `--cnsa-category` without `--pqc-mode deadline`, which only that mode
/// reads (usage errors, exit 3).
pub fn compliance_run_config(
    cra_product_class: Option<&str>,
    as_of: Option<&str>,
    pqc: PqcOptions,
    rules: &RuleOptions,
) -> anyhow::Result<crate::quality::ComplianceRunConfig> {
    let mut config = crate::quality::ComplianceRunConfig::new()
        .with_pqc_inputs(pqc.mode, pqc.profile, pqc.cnsa_category)
        .map_err(|_| {
            anyhow::anyhow!("--pqc-profile and --cnsa-category apply only with --pqc-mode deadline")
        })?
        .with_rule_settings(rules.settings.clone())
        .with_include_excluded_scope(rules.include_excluded_scope);
    if let Some(as_of) = as_of.map(parse_as_of).transpose()? {
        config = config.with_as_of(as_of);
    }
    if let Some(class) = parse_cra_product_class(cra_product_class)? {
        config = config.with_product_class(class);
    }
    Ok(config)
}

/// The compliance run of a command that judges the SBOM at `sbom_path`:
/// [`compliance_run_config`] plus the CRA sidecar from `explicit_sidecar`
/// (`--cra-sidecar` or the config file), else the one found next to the
/// SBOM (see [`load_cra_sidecar`]). `validate`, `quality`, `view` (and its
/// TUI) and `cra-docs` all build their run here, so they judge one SBOM with
/// the same inputs. A sidecar `productClass` that differs from
/// `--cra-product-class` wins, with a warning on stderr.
pub(crate) fn compliance_run_config_for(
    sbom_path: &std::path::Path,
    explicit_sidecar: Option<&std::path::Path>,
    cra_product_class: Option<&str>,
    as_of: Option<&str>,
    pqc: PqcOptions,
    rules: &RuleOptions,
) -> anyhow::Result<crate::quality::ComplianceRunConfig> {
    let mut config = compliance_run_config(cra_product_class, as_of, pqc, rules)?;
    if let Some(sidecar) = load_cra_sidecar(explicit_sidecar, sbom_path)? {
        config = config.with_sidecar(sidecar);
    }
    config.warn_on_product_class_conflict(sbom_path);
    Ok(config)
}

/// Parse an **explicitly** passed `--cra-product-class` value strictly.
///
/// A typo'd class used to be silently dropped (`parse_cli` → `None`, scored
/// as `Default` class), flipping CRA verdicts with zero diagnostics. An
/// unrecognized value is now a hard error listing the valid spellings —
/// matching the config-file validator. Sidecar-derived and auto-discovered
/// classes are unaffected (they never route through this helper).
pub(crate) fn parse_cra_product_class(
    value: Option<&str>,
) -> anyhow::Result<Option<crate::model::CraProductClass>> {
    value
        .map(|s| {
            crate::model::CraProductClass::parse_cli_strict(s)
                .map_err(|e| anyhow::anyhow!("invalid --cra-product-class: {e}"))
        })
        .transpose()
}

/// Check the `--sarif-base` and `--sarif-category` values before any SBOM is
/// read: the base must name a directory and the category must not be blank.
/// Only `-o sarif` reads them, so other formats skip the check.
pub(crate) fn check_sarif_flags(
    output: crate::reports::ReportFormat,
    base: Option<&std::path::Path>,
    category: Option<&str>,
) -> anyhow::Result<()> {
    if output != crate::reports::ReportFormat::Sarif {
        return Ok(());
    }
    if let Some(base) = base
        && !base.is_dir()
    {
        anyhow::bail!("invalid --sarif-base {}: not a directory", base.display());
    }
    if category.is_some_and(|c| c.trim().is_empty()) {
        anyhow::bail!("invalid --sarif-category: must not be blank");
    }
    Ok(())
}

/// The SBOM file a SARIF run's results point into: `sbom`, parsed from
/// `content` read at `path`, named relative to `sarif_base` or, by default,
/// to the repository the file is in (see
/// [`crate::reports::SarifArtifactLocation::for_sbom_path`]).
pub(crate) fn sarif_artifact(
    path: &std::path::Path,
    sarif_base: Option<&std::path::Path>,
    sbom: &crate::model::NormalizedSbom,
    content: &str,
) -> anyhow::Result<crate::reports::SarifArtifact> {
    let location =
        crate::reports::SarifArtifactLocation::for_sbom_path(path, sarif_base).map_err(|e| {
            anyhow::anyhow!(
                "cannot name {} for SARIF output relative to {}: {e}",
                path.display(),
                sarif_base
                    .map_or_else(|| "its repository".to_string(), |b| b.display().to_string())
            )
        })?;
    if location.uri_base_id().is_none() && location.uri() != "-" {
        tracing::warn!(
            "{} is outside the SARIF base directory; results name it by its absolute path",
            path.display()
        );
    }
    Ok(crate::reports::SarifArtifact::new(location, sbom, content))
}

/// Parse an `--as-of` evaluation-clock value (shared by every command that
/// takes the flag, through [`compliance_run_config`]). The spellings are the
/// library's [`crate::quality::parse_as_of`], which the C ABI's `as_of`
/// option reads too:
/// - RFC 3339 datetime with offset (`2027-01-01T00:00:00Z`, `…+02:00`)
/// - offset-less datetime, taken as UTC (`2027-01-01T00:00:00`)
/// - bare date, meaning midnight UTC (`2027-01-01`)
pub(crate) fn parse_as_of(raw: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    crate::quality::parse_as_of(raw).map_err(|e| anyhow::anyhow!("invalid --as-of {raw:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    #[test]
    fn parse_as_of_accepts_rfc3339_with_offset() {
        let t = super::parse_as_of("2027-01-01T02:00:00+02:00").unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn parse_as_of_accepts_offsetless_datetime_as_utc() {
        // Regression: this spelling used to fail with a misleading
        // "trailing input" error from the bare-date fallback.
        let t = super::parse_as_of("2027-01-01T12:30:00").unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2027, 1, 1, 12, 30, 0).unwrap());
    }

    #[test]
    fn parse_as_of_accepts_bare_date_as_midnight_utc() {
        let t = super::parse_as_of("2027-01-01").unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn parse_as_of_error_names_every_accepted_form() {
        let err = super::parse_as_of("not-a-date").unwrap_err().to_string();
        assert!(err.contains("not-a-date"));
        assert!(err.contains("RFC 3339"), "must name RFC 3339: {err}");
        assert!(
            err.contains("offset-less") && err.contains("UTC"),
            "must explain the offset-less form: {err}"
        );
        assert!(err.contains("YYYY-MM-DD"), "must name the date form: {err}");
    }

    /// The config file's PQC keys are defaults: each flag wins, and the
    /// file's profile and category reach only a run in deadline mode.
    #[test]
    fn pqc_options_take_the_config_file_as_defaults() {
        use crate::quality::{CnsaCategory, PqcMode, PqcProfile};
        let file = crate::config::ComplianceConfig {
            pqc_mode: Some("deadline".to_string()),
            pqc_profile: Some("federal".to_string()),
            cnsa_category: Some("niche".to_string()),
            ..Default::default()
        };
        let from_file = super::PqcOptions::with_config_defaults(None, None, None, &file).unwrap();
        assert_eq!(
            from_file,
            super::PqcOptions {
                mode: PqcMode::Deadline,
                profile: Some(PqcProfile::Federal),
                cnsa_category: Some(CnsaCategory::Niche),
            }
        );
        let flags = super::PqcOptions::with_config_defaults(
            None,
            Some(PqcProfile::Nist),
            Some(CnsaCategory::WebCloud),
            &file,
        )
        .unwrap();
        assert_eq!(flags.profile, Some(PqcProfile::Nist));
        assert_eq!(flags.cnsa_category, Some(CnsaCategory::WebCloud));
        // `--pqc-mode readiness` drops the file's deadline-mode defaults.
        let readiness =
            super::PqcOptions::with_config_defaults(Some(PqcMode::Readiness), None, None, &file)
                .unwrap();
        assert_eq!(readiness, super::PqcOptions::default());
        // No file value: readiness, as before.
        let none = super::PqcOptions::with_config_defaults(
            None,
            None,
            None,
            &crate::config::ComplianceConfig::default(),
        )
        .unwrap();
        assert_eq!(none, super::PqcOptions::default());
    }

    /// The `--rule` flags win over the config file's settings for their own
    /// rules, and each setting remembers where it comes from.
    #[test]
    fn rule_options_put_the_flags_over_the_file() {
        use crate::quality::{RuleSetting, SettingSource};
        let file = crate::config::ComplianceConfig {
            rules: [("sbom-ntia-supplier", "off"), ("SBOM-NTIA-VERSION", "info")]
                .into_iter()
                .map(|(id, setting)| (id.to_string(), setting.to_string()))
                .collect(),
            include_excluded_scope: true,
            ..Default::default()
        };
        let flag = super::parse_rule_setting_arg("SBOM-NTIA-SUPPLIER=Error").unwrap();
        assert_eq!(flag, ("SBOM-NTIA-SUPPLIER", RuleSetting::Error));
        let options = super::RuleOptions::from_flags(&[flag], false, &file).unwrap();
        assert!(options.include_excluded_scope, "the file's switch applies");
        assert_eq!(
            options.settings.get("SBOM-NTIA-SUPPLIER"),
            Some((RuleSetting::Error, SettingSource::Cli))
        );
        assert_eq!(
            options.settings.get("SBOM-NTIA-VERSION"),
            Some((RuleSetting::Info, SettingSource::Config))
        );

        let err = super::parse_rule_setting_arg("SBOM-NTIA-SUPPLIER:warning").unwrap_err();
        assert!(err.contains("RULE=SETTING"), "{err}");
        let err = super::parse_fail_on_arg("SBOM-PQC-009").unwrap_err();
        assert!(err.contains("never a finding"), "{err}");
        assert_eq!(
            super::parse_fail_on_arg("sbom-ntia-supplier"),
            Ok("SBOM-NTIA-SUPPLIER")
        );
    }

    #[test]
    fn parse_cra_product_class_is_strict_and_lists_valid_values() {
        assert_eq!(
            super::parse_cra_product_class(Some("critical")).unwrap(),
            Some(crate::model::CraProductClass::Critical)
        );
        assert_eq!(super::parse_cra_product_class(None).unwrap(), None);
        let err = super::parse_cra_product_class(Some("critcal"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("critcal"), "must name the bad value: {err}");
        for valid in [
            "default",
            "important-class-1",
            "important-class-2",
            "critical",
        ] {
            assert!(err.contains(valid), "must list '{valid}': {err}");
        }
    }
}
