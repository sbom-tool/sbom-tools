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

/// The compliance inputs of a run, parsed strictly from the flags every
/// compliance-checking command shares: `--cra-product-class` and `--as-of`.
/// `diff` judges both of its SBOMs with these; the commands that judge one
/// SBOM add its CRA sidecar with [`compliance_run_config_for`].
///
/// # Errors
///
/// An unknown product class or an unparseable `--as-of` (usage errors,
/// exit 3).
pub fn compliance_run_config(
    cra_product_class: Option<&str>,
    as_of: Option<&str>,
) -> anyhow::Result<crate::quality::ComplianceRunConfig> {
    let mut config = crate::quality::ComplianceRunConfig::new();
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
) -> anyhow::Result<crate::quality::ComplianceRunConfig> {
    let mut config = compliance_run_config(cra_product_class, as_of)?;
    if let Some(sidecar) = load_cra_sidecar(explicit_sidecar, sbom_path)? {
        config = config.with_sidecar(sidecar);
    }
    config.warn_on_product_class_conflict();
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
/// takes the flag, through [`compliance_run_config`], so all of them accept
/// the exact same spellings).
///
/// Accepted forms:
/// - RFC 3339 datetime with offset (`2027-01-01T00:00:00Z`, `…+02:00`)
/// - offset-less datetime, taken as UTC (`2027-01-01T00:00:00`)
/// - bare date, meaning midnight UTC (`2027-01-01`)
pub(crate) fn parse_as_of(raw: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    if let Ok(ndt) = raw.parse::<chrono::NaiveDateTime>() {
        return Ok(ndt.and_utc());
    }
    if let Ok(d) = raw.parse::<chrono::NaiveDate>() {
        return Ok(d.and_hms_opt(0, 0, 0).expect("midnight is valid").and_utc());
    }
    anyhow::bail!(
        "invalid --as-of {raw:?}: expected an RFC 3339 datetime \
         (e.g. 2027-01-01T00:00:00Z), an offset-less datetime taken as UTC \
         (e.g. 2027-01-01T00:00:00), or a date YYYY-MM-DD (midnight UTC)"
    )
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
