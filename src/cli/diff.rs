//! Diff command handler.
//!
//! Implements the `diff` subcommand for comparing two SBOMs.

use crate::config::DiffConfig;
use crate::pipeline::{
    OutputTarget, auto_detect_format, compute_diff, exit_codes, is_stdin_path, output_report,
    parse_sbom_with_context,
};
use crate::reports::ReportFormat;
use crate::tui::{App, run_tui};
use anyhow::{Result, bail};

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

    // Stdin can only be consumed once, so a diff can read at most one side from "-".
    if is_stdin_path(&config.paths.old) && is_stdin_path(&config.paths.new) {
        bail!("Cannot read both SBOMs from stdin ('-'); only one '-' is allowed per diff");
    }

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
    let mut enrichment_warnings: Vec<&str> = Vec::new();

    #[cfg(feature = "enrichment")]
    let enrichment_stats = {
        if config.enrichment.enabled {
            let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
            let stats_old = crate::pipeline::enrich_sbom(old_parsed.sbom_mut(), &osv_config, quiet);
            let stats_new = crate::pipeline::enrich_sbom(new_parsed.sbom_mut(), &osv_config, quiet);
            if stats_old.is_none() || stats_new.is_none() {
                enrichment_warnings.push("OSV vulnerability enrichment failed");
            }
            Some((stats_old, stats_new))
        } else {
            None
        }
    };

    // Enrich with end-of-life data if enabled
    #[cfg(feature = "enrichment")]
    {
        if config.enrichment.enable_eol {
            let eol_config = crate::enrichment::EolClientConfig {
                cache_dir: config
                    .enrichment
                    .cache_dir
                    .clone()
                    .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
                cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
                bypass_cache: config.enrichment.bypass_cache,
                timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
                ..Default::default()
            };
            let eol_old = crate::pipeline::enrich_eol(old_parsed.sbom_mut(), &eol_config, quiet);
            let eol_new = crate::pipeline::enrich_eol(new_parsed.sbom_mut(), &eol_config, quiet);
            if eol_old.is_none() || eol_new.is_none() {
                enrichment_warnings.push("EOL enrichment failed");
            }
        }
    }

    // Enrich with CISA KEV catalog (flags actively exploited vulnerabilities)
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_kev {
        let kev_config = kev_client_config(&config.enrichment);
        let kev_old = crate::pipeline::enrich_kev(old_parsed.sbom_mut(), &kev_config, quiet);
        let kev_new = crate::pipeline::enrich_kev(new_parsed.sbom_mut(), &kev_config, quiet);
        if kev_old.is_none() || kev_new.is_none() {
            enrichment_warnings.push("KEV enrichment failed");
        }
    }

    // Enrich with FIRST EPSS exploit-probability scores
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_epss {
        let epss_config = epss_client_config(&config.enrichment);
        let epss_old = crate::pipeline::enrich_epss(old_parsed.sbom_mut(), &epss_config, quiet);
        let epss_new = crate::pipeline::enrich_epss(new_parsed.sbom_mut(), &epss_config, quiet);
        if epss_old.is_none() || epss_new.is_none() {
            enrichment_warnings.push("EPSS enrichment failed");
        }
    }

    // Enrich with dependency staleness data
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_staleness {
        let staleness_config = crate::enrichment::RegistryConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::staleness_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        let stale_old =
            crate::pipeline::enrich_staleness(old_parsed.sbom_mut(), &staleness_config, quiet);
        let stale_new =
            crate::pipeline::enrich_staleness(new_parsed.sbom_mut(), &staleness_config, quiet);
        if stale_old.is_none() || stale_new.is_none() {
            enrichment_warnings.push("Staleness enrichment failed");
        }
    }

    // Enrich ML-model components with HuggingFace Hub data (weight hashes, task)
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_huggingface {
        let hf_config = huggingface_client_config(&config.enrichment);
        let hf_old = crate::pipeline::enrich_huggingface(old_parsed.sbom_mut(), &hf_config, quiet);
        let hf_new = crate::pipeline::enrich_huggingface(new_parsed.sbom_mut(), &hf_config, quiet);
        if hf_old.is_none() || hf_new.is_none() {
            enrichment_warnings.push("HuggingFace enrichment failed");
        }
    }

    // Enrich with VEX data if VEX documents provided
    #[cfg(feature = "enrichment")]
    if !config.enrichment.vex_paths.is_empty() {
        let vex_old =
            crate::pipeline::enrich_vex(old_parsed.sbom_mut(), &config.enrichment.vex_paths, quiet);
        let vex_new =
            crate::pipeline::enrich_vex(new_parsed.sbom_mut(), &config.enrichment.vex_paths, quiet);
        if vex_old.is_none() || vex_new.is_none() {
            enrichment_warnings.push("VEX enrichment failed");
        }
    }

    #[cfg(not(feature = "enrichment"))]
    {
        if config.enrichment.enabled {
            eprintln!(
                "Warning: enrichment requested but the 'enrichment' feature is not enabled. \
                 Rebuild with: cargo build --features enrichment"
            );
        }
    }

    // Compute the diff
    let mut result = compute_diff(&config, &old_parsed.sbom, &new_parsed.sbom)?;
    result.ml_regressions = find_ml_regressions(&result);

    // Determine exit code before potentially moving result into TUI
    let exit_code = determine_exit_code(&config, &result);

    // Route output
    let output_target = OutputTarget::from_option(config.output.file.clone());
    let effective_output = auto_detect_format(config.output.format, &output_target);

    if effective_output == ReportFormat::Tui {
        // Resolve the CRA sidecar (auto-discovered next to the new/"current"
        // SBOM unless it reads from stdin) so the compliance tab applies the
        // same sidecar-driven verdicts as the CLI — most importantly EU AI Act
        // high-risk escalation, which otherwise renders COMPLIANT in the TUI.
        let tui_sidecar = if is_stdin_path(&config.paths.new) {
            None
        } else {
            crate::model::CraSidecarMetadata::find_for_sbom(&config.paths.new)
        };

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

        if let Some(sc) = tui_sidecar {
            app = app.with_cra_sidecar(sc);
        }

        // Set export template if configured
        app.export_template = config.output.export_template.clone();

        // Show enrichment warnings in TUI footer
        #[cfg(feature = "enrichment")]
        if !enrichment_warnings.is_empty() {
            app.set_status_message(format!("Warning: {}", enrichment_warnings.join(", ")));
            app.status_sticky = true;
        }

        run_tui(&mut app)?;
    } else {
        old_parsed.drop_raw_content();
        new_parsed.drop_raw_content();
        output_report(&config, &result, &old_parsed.sbom, &new_parsed.sbom)?;
    }

    Ok(exit_code)
}

/// Determine the appropriate exit code based on diff results and config flags.
///
/// Priority (highest exit code wins): VEX gaps (4) > vulns introduced (2) > changes (1).
/// VEX gaps are checked first because they are more specific — a user who sets
/// `--fail-on-vex-gap` wants to know about missing VEX statements, not just
/// that vulns were introduced.
fn determine_exit_code(config: &DiffConfig, result: &crate::diff::DiffResult) -> i32 {
    if config.filtering.fail_on_ml_regression && !result.ml_regressions.is_empty() {
        for regression in &result.ml_regressions {
            eprintln!(
                "ML regression: component={} metric={} previous={} new={}",
                regression.component,
                regression.metric,
                regression.previous_value,
                regression.new_value
            );
        }
        return exit_codes::ML_REGRESSION;
    }
    // Check for VEX gaps first (most specific gate)
    if config.filtering.fail_on_vex_gap {
        let vex_summary = result.vulnerabilities.vex_summary();
        let total_gaps = vex_summary.introduced_without_vex + vex_summary.persistent_without_vex;
        if total_gaps > 0 {
            eprintln!(
                "VEX gap: {} vulnerability(ies) lack VEX statements ({} introduced, {} persistent)",
                total_gaps, vex_summary.introduced_without_vex, vex_summary.persistent_without_vex,
            );
            return exit_codes::VEX_GAPS_FOUND;
        }
    }
    // KEV gate is more specific than the generic vuln gate: an actively
    // exploited (KEV) finding is the highest-priority signal for CRA Art.14
    // reporting, so it outranks --fail-on-vuln.
    if config.behavior.fail_on_kev {
        let kev_count = result
            .vulnerabilities
            .introduced
            .iter()
            .filter(|v| v.is_kev)
            .count();
        if kev_count > 0 {
            eprintln!(
                "KEV gate: {kev_count} introduced vulnerability(ies) are in CISA's Known Exploited Vulnerabilities catalog",
            );
            return exit_codes::KEV_INTRODUCED;
        }
    }
    if config.behavior.fail_on_vuln && result.summary.vulnerabilities_introduced > 0 {
        return exit_codes::VULNS_INTRODUCED;
    }
    if config.behavior.fail_on_change && result.summary.total_changes > 0 {
        return exit_codes::CHANGES_DETECTED;
    }
    exit_codes::SUCCESS
}

fn find_ml_regressions(result: &crate::diff::DiffResult) -> Vec<crate::diff::MlRegression> {
    fn direction(metric: &str) -> Option<bool> {
        let metric = metric.split('@').next().unwrap_or(metric);
        match metric {
            "accuracy" | "f1" | "f1_score" | "precision" | "recall" | "auc" | "roc_auc"
            | "bleu" | "rouge" => Some(true),
            "loss" | "error" | "error_rate" | "perplexity" | "latency" | "latency_ms" => {
                Some(false)
            }
            _ => None,
        }
    }

    result
        .components
        .modified
        .iter()
        .flat_map(|component| {
            component.field_changes.iter().filter_map(move |change| {
                let metric = change.field.strip_prefix("ml_metric:")?;
                let higher_is_better = direction(metric)?;
                let previous_value = change.old_value.as_deref()?.parse::<f64>().ok()?;
                let new_value = change.new_value.as_deref()?.parse::<f64>().ok()?;
                let regressed = if higher_is_better {
                    new_value < previous_value
                } else {
                    new_value > previous_value
                };
                regressed.then(|| crate::diff::MlRegression {
                    component: component.name.clone(),
                    metric: metric.to_string(),
                    previous_value,
                    new_value,
                })
            })
        })
        .collect()
}

/// Build a `KevClientConfig` from the user-facing `EnrichmentConfig`, honoring
/// the cache directory, TTL, timeout, and optional URL override.
#[cfg(feature = "enrichment")]
fn kev_client_config(
    enrichment: &crate::config::EnrichmentConfig,
) -> crate::enrichment::KevClientConfig {
    let mut cfg = crate::enrichment::KevClientConfig {
        cache_dir: enrichment
            .cache_dir
            .clone()
            .unwrap_or_else(crate::pipeline::dirs::kev_cache_dir),
        cache_ttl: std::time::Duration::from_secs(enrichment.cache_ttl_hours * 3600),
        bypass_cache: enrichment.bypass_cache,
        timeout: std::time::Duration::from_secs(enrichment.timeout_secs),
        ..Default::default()
    };
    if let Some(ref url) = enrichment.kev_url {
        cfg.kev_url = url.clone();
    }
    cfg
}

/// Build an `EpssClientConfig` from the user-facing `EnrichmentConfig`, honoring
/// the cache directory, TTL, timeout, and optional URL override.
#[cfg(feature = "enrichment")]
fn epss_client_config(
    enrichment: &crate::config::EnrichmentConfig,
) -> crate::enrichment::EpssClientConfig {
    let mut cfg = crate::enrichment::EpssClientConfig {
        cache_dir: enrichment
            .cache_dir
            .clone()
            .unwrap_or_else(crate::pipeline::dirs::epss_cache_dir),
        cache_ttl: std::time::Duration::from_secs(enrichment.cache_ttl_hours * 3600),
        bypass_cache: enrichment.bypass_cache,
        timeout: std::time::Duration::from_secs(enrichment.timeout_secs),
        ..Default::default()
    };
    if let Some(ref url) = enrichment.epss_url {
        cfg.epss_url = url.clone();
    }
    cfg
}

/// Build a `HuggingFaceConfig` from the user-facing `EnrichmentConfig`, honoring
/// the cache directory, TTL, timeout, and optional URL override.
#[cfg(feature = "enrichment")]
fn huggingface_client_config(
    enrichment: &crate::config::EnrichmentConfig,
) -> crate::enrichment::HuggingFaceConfig {
    let mut cfg = crate::enrichment::HuggingFaceConfig {
        cache_dir: enrichment
            .cache_dir
            .clone()
            .unwrap_or_else(crate::pipeline::dirs::huggingface_cache_dir),
        cache_ttl: std::time::Duration::from_secs(enrichment.cache_ttl_hours * 3600),
        bypass_cache: enrichment.bypass_cache,
        timeout: std::time::Duration::from_secs(enrichment.timeout_secs),
        ..Default::default()
    };
    if let Some(ref url) = enrichment.huggingface_url {
        cfg.api_url = url.clone();
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::find_ml_regressions;
    use crate::diff::{ChangeType, ComponentChange, DiffResult, FieldChange};
    use crate::pipeline::OutputTarget;
    use std::path::PathBuf;

    #[test]
    fn test_output_target_conversion() {
        let none_target = OutputTarget::from_option(None);
        assert!(matches!(none_target, OutputTarget::Stdout));

        let some_target = OutputTarget::from_option(Some(PathBuf::from("/tmp/test.json")));
        assert!(matches!(some_target, OutputTarget::File(_)));
    }

    fn result_with_metric(metric: &str, old: &str, new: &str) -> DiffResult {
        let mut result = DiffResult::new();
        result.components.modified.push(ComponentChange {
            id: "model".to_string(),
            canonical_id: None,
            component_ref: None,
            old_canonical_id: None,
            name: "classifier".to_string(),
            old_version: None,
            new_version: None,
            ecosystem: None,
            change_type: ChangeType::Modified,
            field_changes: vec![FieldChange {
                field: format!("ml_metric:{metric}"),
                old_value: Some(old.to_string()),
                new_value: Some(new.to_string()),
            }],
            cost: 1,
            match_info: None,
        });
        result
    }

    #[test]
    fn ml_regression_respects_metric_direction() {
        assert_eq!(
            find_ml_regressions(&result_with_metric("accuracy", "0.9", "0.8")).len(),
            1
        );
        assert_eq!(
            find_ml_regressions(&result_with_metric("loss", "0.2", "0.3")).len(),
            1
        );
        assert!(find_ml_regressions(&result_with_metric("accuracy", "0.8", "0.9")).is_empty());
        assert!(find_ml_regressions(&result_with_metric("loss", "0.3", "0.2")).is_empty());
    }

    #[test]
    fn ml_regression_ignores_unknown_or_non_numeric_metrics() {
        assert!(find_ml_regressions(&result_with_metric("custom", "1", "0")).is_empty());
        assert!(find_ml_regressions(&result_with_metric("accuracy", "high", "low")).is_empty());
    }
}
