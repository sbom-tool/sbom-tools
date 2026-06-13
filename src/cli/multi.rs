//! Multi-SBOM command handlers.
//!
//! Implements the `diff-multi`, `timeline`, and `matrix` subcommands.
//! Uses the pipeline module for parsing and enrichment (shared with `diff`).

use crate::config::{MatrixConfig, MultiDiffConfig, TimelineConfig};
use crate::diff::MultiDiffEngine;
use crate::matching::FuzzyMatchConfig;
use crate::model::NormalizedSbom;
use crate::pipeline::{
    OutputTarget, auto_detect_format, enrich_sbom_full, enrich_sboms, exit_codes,
    parse_sbom_with_context, write_output,
};
use crate::reports::ReportFormat;
use crate::tui::{App, run_tui};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// Resolve output target and effective format from config.
fn resolve_output(output: &crate::config::OutputConfig) -> (OutputTarget, ReportFormat) {
    let target = OutputTarget::from_option(output.file.clone());
    let format = auto_detect_format(output.format, &target);
    (target, format)
}

/// Run the diff-multi command (1:N comparison), returning the desired exit code.
#[allow(clippy::needless_pass_by_value)]
pub fn run_diff_multi(config: MultiDiffConfig) -> Result<i32> {
    let quiet = config.behavior.quiet;

    // Parse baseline
    let mut baseline_parsed = parse_sbom_with_context(&config.baseline, quiet)?;
    // Parse and optionally enrich targets
    let (target_sboms, target_stats) =
        parse_and_enrich_sboms(&config.targets, &config.enrichment, quiet)?;

    // Enrich baseline
    let baseline_stats = enrich_sbom_full(baseline_parsed.sbom_mut(), &config.enrichment, quiet);

    tracing::info!(
        "Comparing baseline ({} components) against {} targets",
        baseline_parsed.sbom().component_count(),
        target_sboms.len()
    );

    let fuzzy_config = get_fuzzy_config(&config.matching.fuzzy_preset);

    // Prepare target references with names
    let targets = prepare_sbom_refs(&target_sboms, &config.targets);
    let target_refs: Vec<_> = targets
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run multi-diff
    let mut engine = MultiDiffEngine::new()
        .with_fuzzy_config(fuzzy_config)
        .include_unchanged(config.matching.include_unchanged);
    if config.graph_diff.enabled {
        engine = engine.with_graph_diff(crate::diff::GraphDiffConfig::default());
    }

    let baseline_name = get_sbom_name(&config.baseline);

    let result = engine.diff_multi(
        baseline_parsed.sbom(),
        &baseline_name,
        &config.baseline.to_string_lossy(),
        &target_refs,
    )?;

    tracing::info!(
        "Multi-diff complete: {} comparisons, max deviation: {:.1}%",
        result.comparisons.len(),
        result.summary.max_deviation * 100.0
    );

    // Determine exit code
    let exit_code = determine_multi_exit_code(&config.behavior, &result);

    // Output result
    let (output_target, effective_output) = resolve_output(&config.output);

    if effective_output == ReportFormat::Tui {
        let mut app = App::new_multi_diff(result);
        app.export_template = config.output.export_template.clone();

        // Show enrichment warnings if any
        let all_warnings: Vec<_> = std::iter::once(&baseline_stats)
            .chain(target_stats.iter())
            .flat_map(|s| s.warnings.iter())
            .collect();
        if !all_warnings.is_empty() {
            app.set_status_message(format!(
                "Warning: {}",
                all_warnings
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            app.status_sticky = true;
        }

        run_tui(&mut app)?;
    } else {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, &output_target, quiet)?;
    }

    Ok(exit_code)
}

/// Run the timeline command, returning the desired exit code.
#[allow(clippy::needless_pass_by_value)]
pub fn run_timeline(config: TimelineConfig) -> Result<i32> {
    let quiet = config.behavior.quiet;

    if config.sbom_paths.len() < 2 {
        bail!("Timeline analysis requires at least 2 SBOMs");
    }

    let (sboms, _enrich_stats) =
        parse_and_enrich_sboms(&config.sbom_paths, &config.enrichment, quiet)?;

    tracing::info!("Analyzing timeline of {} SBOMs", sboms.len());

    let fuzzy_config = get_fuzzy_config(&config.matching.fuzzy_preset);

    // Prepare SBOM references with names
    let sbom_data = prepare_sbom_refs(&sboms, &config.sbom_paths);
    let sbom_refs: Vec<_> = sbom_data
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run timeline analysis
    let mut engine = MultiDiffEngine::new().with_fuzzy_config(fuzzy_config);
    if config.graph_diff.enabled {
        engine = engine.with_graph_diff(crate::diff::GraphDiffConfig::default());
    }
    let result = engine.timeline(&sbom_refs)?;

    tracing::info!(
        "Timeline analysis complete: {} incremental diffs",
        result.incremental_diffs.len()
    );

    // Output result
    let (output_target, effective_output) = resolve_output(&config.output);

    // Determine exit code
    let exit_code = determine_timeline_exit_code(&config.behavior, &result);

    if effective_output == ReportFormat::Tui {
        let mut app = App::new_timeline(result);
        run_tui(&mut app)?;
    } else {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, &output_target, quiet)?;
    }

    Ok(exit_code)
}

/// Run the matrix command (N×N comparison), returning the desired exit code.
#[allow(clippy::needless_pass_by_value)]
pub fn run_matrix(config: MatrixConfig) -> Result<i32> {
    let quiet = config.behavior.quiet;

    if config.sbom_paths.len() < 2 {
        bail!("Matrix comparison requires at least 2 SBOMs");
    }

    let (sboms, _enrich_stats) =
        parse_and_enrich_sboms(&config.sbom_paths, &config.enrichment, quiet)?;

    tracing::info!(
        "Computing {}x{} comparison matrix",
        sboms.len(),
        sboms.len()
    );

    let fuzzy_config = get_fuzzy_config(&config.matching.fuzzy_preset);

    // Prepare SBOM references with names
    let sbom_data = prepare_sbom_refs(&sboms, &config.sbom_paths);
    let sbom_refs: Vec<_> = sbom_data
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run matrix comparison
    let mut engine = MultiDiffEngine::new().with_fuzzy_config(fuzzy_config);
    if config.graph_diff.enabled {
        engine = engine.with_graph_diff(crate::diff::GraphDiffConfig::default());
    }
    let result = engine.matrix(&sbom_refs, Some(config.cluster_threshold))?;

    tracing::info!(
        "Matrix comparison complete: {} pairs computed",
        result.num_pairs()
    );

    if let Some(ref clustering) = result.clustering {
        tracing::info!(
            "Found {} clusters, {} outliers",
            clustering.clusters.len(),
            clustering.outliers.len()
        );
    }

    // Output result
    let (output_target, effective_output) = resolve_output(&config.output);

    // Determine exit code
    let exit_code = determine_matrix_exit_code(&config.behavior, &result);

    if effective_output == ReportFormat::Tui {
        let mut app = App::new_matrix(result);
        run_tui(&mut app)?;
    } else {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, &output_target, quiet)?;
    }

    Ok(exit_code)
}

/// Parse and optionally enrich multiple SBOMs.
fn parse_and_enrich_sboms(
    paths: &[PathBuf],
    enrichment: &crate::config::EnrichmentConfig,
    quiet: bool,
) -> Result<(
    Vec<NormalizedSbom>,
    Vec<crate::pipeline::AggregatedEnrichmentStats>,
)> {
    let mut sboms = Vec::with_capacity(paths.len());
    for path in paths {
        let parsed = parse_sbom_with_context(path, quiet)?;
        sboms.push(parsed.into_sbom());
    }
    let stats = enrich_sboms(&mut sboms, enrichment, quiet);
    Ok((sboms, stats))
}

/// Parse multiple SBOMs without enrichment.
///
/// Used by the query command where enrichment is handled separately.
pub(crate) fn parse_multiple_sboms(paths: &[PathBuf]) -> Result<Vec<NormalizedSbom>> {
    let mut sboms = Vec::with_capacity(paths.len());
    for path in paths {
        let parsed = parse_sbom_with_context(path, false)?;
        sboms.push(parsed.into_sbom());
    }
    Ok(sboms)
}

/// Determine exit code for multi-SBOM commands based on behavior config.
fn determine_multi_exit_code(
    behavior: &crate::config::BehaviorConfig,
    result: &crate::diff::MultiDiffResult,
) -> i32 {
    let (total_introduced, total_changes) =
        result
            .comparisons
            .iter()
            .fold((0usize, 0usize), |(vi, tc), c| {
                (
                    vi + c.diff.summary.vulnerabilities_introduced,
                    tc + c.diff.summary.total_changes,
                )
            });

    if behavior.fail_on_vuln && total_introduced > 0 {
        return exit_codes::VULNS_INTRODUCED;
    }
    if behavior.fail_on_change && total_changes > 0 {
        return exit_codes::CHANGES_DETECTED;
    }
    exit_codes::SUCCESS
}

/// Determine exit code for timeline commands based on behavior config.
fn determine_timeline_exit_code(
    behavior: &crate::config::BehaviorConfig,
    result: &crate::diff::TimelineResult,
) -> i32 {
    if behavior.fail_on_vuln {
        let total_introduced: usize = result
            .incremental_diffs
            .iter()
            .map(|d| d.summary.vulnerabilities_introduced)
            .sum();
        if total_introduced > 0 {
            return exit_codes::VULNS_INTRODUCED;
        }
    }
    if behavior.fail_on_change {
        let total_changes: usize = result
            .incremental_diffs
            .iter()
            .map(|d| d.summary.total_changes)
            .sum();
        if total_changes > 0 {
            return exit_codes::CHANGES_DETECTED;
        }
    }
    exit_codes::SUCCESS
}

/// Determine exit code for matrix commands based on behavior config.
fn determine_matrix_exit_code(
    behavior: &crate::config::BehaviorConfig,
    result: &crate::diff::MatrixResult,
) -> i32 {
    if behavior.fail_on_vuln {
        let total_introduced: usize = result
            .diffs
            .iter()
            .flatten()
            .map(|d| d.summary.vulnerabilities_introduced)
            .sum();
        if total_introduced > 0 {
            return exit_codes::VULNS_INTRODUCED;
        }
    }
    if behavior.fail_on_change {
        let total_changes: usize = result
            .diffs
            .iter()
            .flatten()
            .map(|d| d.summary.total_changes)
            .sum();
        if total_changes > 0 {
            return exit_codes::CHANGES_DETECTED;
        }
    }
    exit_codes::SUCCESS
}

/// Get fuzzy matching config from preset name
fn get_fuzzy_config(preset: &crate::config::FuzzyPreset) -> FuzzyMatchConfig {
    FuzzyMatchConfig::from_preset(preset.as_str()).unwrap_or_else(|| {
        // Enum guarantees valid preset, but from_preset may not know all variants
        FuzzyMatchConfig::balanced()
    })
}

/// Get SBOM name from path
pub(crate) fn get_sbom_name(path: &Path) -> String {
    path.file_stem().map_or_else(
        || "unknown".to_string(),
        |s| s.to_string_lossy().to_string(),
    )
}

/// Prepare SBOM references with names and paths
fn prepare_sbom_refs<'a>(
    sboms: &'a [NormalizedSbom],
    paths: &[PathBuf],
) -> Vec<(&'a NormalizedSbom, String, String)> {
    sboms
        .iter()
        .zip(paths.iter())
        .map(|(sbom, path)| {
            let name = get_sbom_name(path);
            let path_str = path.to_string_lossy().to_string();
            (sbom, name, path_str)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_fuzzy_config_valid_presets() {
        let config = get_fuzzy_config(&crate::config::FuzzyPreset::Strict);
        assert!(config.threshold > 0.8);

        let config = get_fuzzy_config(&crate::config::FuzzyPreset::Balanced);
        assert!(config.threshold >= 0.7 && config.threshold <= 0.85);

        let config = get_fuzzy_config(&crate::config::FuzzyPreset::Permissive);
        assert!(config.threshold <= 0.70);
    }

    #[test]
    fn test_get_sbom_name() {
        let path = PathBuf::from("/path/to/my-sbom.cdx.json");
        assert_eq!(get_sbom_name(&path), "my-sbom.cdx");

        let path = PathBuf::from("simple.json");
        assert_eq!(get_sbom_name(&path), "simple");
    }

    #[test]
    fn test_prepare_sbom_refs() {
        let sbom1 = NormalizedSbom::default();
        let sbom2 = NormalizedSbom::default();
        let sboms = vec![sbom1, sbom2];
        let paths = vec![PathBuf::from("first.json"), PathBuf::from("second.json")];

        let refs = prepare_sbom_refs(&sboms, &paths);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].1, "first");
        assert_eq!(refs[1].1, "second");
    }
}
