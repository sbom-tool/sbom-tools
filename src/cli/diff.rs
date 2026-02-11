//! Diff command handler.
//!
//! Implements the `diff` subcommand for comparing two SBOMs.

use crate::config::DiffConfig;
use crate::pipeline::{
    auto_detect_format, compute_diff, exit_codes, output_report, parse_sbom_with_context,
    OutputTarget,
};
use crate::reports::ReportFormat;
use crate::tui::{run_tui, App};
use anyhow::Result;

/// Run the diff command, returning the desired exit code.
///
/// Enrichment is handled based on the `enrichment` feature flag and the
/// `config.enrichment.enabled` setting. When the feature is disabled,
/// enrichment settings are silently ignored.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::needless_pass_by_value)]
pub fn run_diff(config: DiffConfig) -> Result<i32> {
    let quiet = config.behavior.quiet;

    // Parse SBOMs
    let mut old_parsed = parse_sbom_with_context(&config.paths.old, quiet)?;
    let mut new_parsed = parse_sbom_with_context(&config.paths.new, quiet)?;

    if !quiet {
        tracing::info!(
            "Parsed {} components from old SBOM, {} from new SBOM",
            old_parsed.sbom().component_count(),
            new_parsed.sbom().component_count()
        );
    }

    // Enrich with OSV vulnerability data if enabled (runtime feature check)
    #[cfg(feature = "enrichment")]
    let enrichment_stats = {
        if config.enrichment.enabled {
            let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
            let stats_old =
                crate::pipeline::enrich_sbom(old_parsed.sbom_mut(), &osv_config, quiet);
            let stats_new =
                crate::pipeline::enrich_sbom(new_parsed.sbom_mut(), &osv_config, quiet);
            Some((stats_old, stats_new))
        } else {
            None
        }
    };

    #[cfg(not(feature = "enrichment"))]
    {
        if config.enrichment.enabled && !quiet {
            tracing::warn!(
                "Enrichment requested but the 'enrichment' feature is not enabled. \
                 Rebuild with --features enrichment to enable vulnerability enrichment."
            );
        }
    }

    // Compute the diff
    let result = compute_diff(&config, &old_parsed.sbom, &new_parsed.sbom)?;

    // Determine exit code before potentially moving result into TUI
    let exit_code = determine_exit_code(&config, &result);

    // Route output
    let output_target = OutputTarget::from_option(config.output.file.clone());
    let effective_output = auto_detect_format(config.output.format, &output_target);

    if effective_output == ReportFormat::Tui {
        let (old_sbom, old_raw) = old_parsed.into_parts();
        let (new_sbom, new_raw) = new_parsed.into_parts();

        #[cfg(feature = "enrichment")]
        let mut app = {
            let app = App::new_diff(result, old_sbom, new_sbom, &old_raw, &new_raw);
            if let Some((stats_old, stats_new)) = enrichment_stats {
                app.with_enrichment_stats(stats_old, stats_new)
            } else {
                app
            }
        };

        #[cfg(not(feature = "enrichment"))]
        let mut app = App::new_diff(result, old_sbom, new_sbom, &old_raw, &new_raw);

        run_tui(&mut app)?;
    } else {
        old_parsed.drop_raw_content();
        new_parsed.drop_raw_content();
        output_report(&config, &result, &old_parsed.sbom, &new_parsed.sbom)?;
    }

    Ok(exit_code)
}

/// Determine the appropriate exit code based on diff results and config flags.
const fn determine_exit_code(config: &DiffConfig, result: &crate::diff::DiffResult) -> i32 {
    if config.behavior.fail_on_vuln && result.summary.vulnerabilities_introduced > 0 {
        return exit_codes::VULNS_INTRODUCED;
    }
    if config.behavior.fail_on_change && result.summary.total_changes > 0 {
        return exit_codes::CHANGES_DETECTED;
    }
    exit_codes::SUCCESS
}

#[cfg(test)]
mod tests {
    use crate::pipeline::OutputTarget;
    use std::path::PathBuf;

    #[test]
    fn test_output_target_conversion() {
        let none_target = OutputTarget::from_option(None);
        assert!(matches!(none_target, OutputTarget::Stdout));

        let some_target = OutputTarget::from_option(Some(PathBuf::from("/tmp/test.json")));
        assert!(matches!(some_target, OutputTarget::File(_)));
    }
}
