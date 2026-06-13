//! Multi-SBOM command handlers.
//!
//! Implements the `diff-multi`, `timeline`, and `matrix` subcommands.
//! Uses the pipeline module for parsing and enrichment (shared with `diff`).

use crate::config::{
    FilterConfig, GraphAwareDiffConfig, MatchingRulesPathConfig, MatrixConfig, MultiDiffConfig,
    TimelineConfig,
};
use crate::diff::{DiffResult, MultiDiffEngine};
use crate::matching::{FuzzyMatchConfig, MatchingRulesConfig};
use crate::model::NormalizedSbom;
use crate::pipeline::{
    OutputTarget, apply_post_diff_filters, auto_detect_format, enrich_sbom_full, enrich_sboms,
    exit_codes, graph_diff_config_from, parse_sbom_with_context, write_output,
};
use crate::reports::ReportFormat;
use crate::tui::{App, run_tui};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// How a multi-SBOM command should emit its result.
enum MultiOutput {
    /// Launch the interactive TUI.
    Tui,
    /// Serialize to pretty JSON and write to the resolved target.
    Json(OutputTarget),
}

/// Resolve and validate the output mode for a multi-SBOM command.
///
/// Multi-SBOM results only have two real renderers: the interactive TUI and
/// pretty JSON. `auto` resolves to TUI on a terminal and JSON when piped/redirected.
/// Any other explicitly requested format (summary, table, markdown, sarif, …) has
/// no multi-SBOM renderer, so it is rejected with a clear error rather than
/// silently emitting JSON.
fn resolve_multi_output(output: &crate::config::OutputConfig) -> Result<MultiOutput> {
    let target = OutputTarget::from_option(output.file.clone());
    match output.format {
        ReportFormat::Tui => Ok(MultiOutput::Tui),
        ReportFormat::Json => Ok(MultiOutput::Json(target)),
        ReportFormat::Auto => match auto_detect_format(ReportFormat::Auto, &target) {
            ReportFormat::Tui => Ok(MultiOutput::Tui),
            // Off-TTY `auto` resolves to summary in single-diff; multi has no
            // summary renderer, so default the piped case to JSON.
            _ => Ok(MultiOutput::Json(target)),
        },
        other => bail!(
            "output format '{other}' is not supported for multi-SBOM commands \
             (diff-multi/timeline/matrix); supported formats: tui, json"
        ),
    }
}

/// Load custom matching rules from a path config, mirroring the single-diff
/// pipeline: a missing/invalid file is logged and skipped rather than aborting,
/// and dry-run mode parses-but-skips application.
fn load_multi_rules(rules: &MatchingRulesPathConfig) -> Option<MatchingRulesConfig> {
    let path = rules.rules_file.as_ref()?;
    match MatchingRulesConfig::from_file(path) {
        Ok(loaded) => {
            if rules.dry_run {
                tracing::info!("Dry-run mode: matching rules parsed but not applied");
                None
            } else {
                Some(loaded)
            }
        }
        Err(e) => {
            tracing::warn!("Failed to load matching rules: {e}");
            None
        }
    }
}

/// Build a `MultiDiffEngine` with graph diffing and matching rules wired in
/// from CLI configuration.
fn build_multi_engine(
    fuzzy_config: FuzzyMatchConfig,
    include_unchanged: bool,
    graph: &GraphAwareDiffConfig,
    rules: &MatchingRulesPathConfig,
) -> MultiDiffEngine {
    let mut engine = MultiDiffEngine::new()
        .with_fuzzy_config(fuzzy_config)
        .include_unchanged(include_unchanged);
    if graph.enabled {
        engine = engine.with_graph_diff(graph_diff_config_from(graph));
    }
    if let Some(loaded) = load_multi_rules(rules) {
        engine = engine.with_matching_rules(loaded);
    }
    engine
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

    // Validate output mode before doing work so unsupported formats fail fast.
    let output_mode = resolve_multi_output(&config.output)?;

    let fuzzy_config = get_fuzzy_config(&config.matching.fuzzy_preset);

    // Prepare target references with names
    let targets = prepare_sbom_refs(&target_sboms, &config.targets);
    let target_refs: Vec<_> = targets
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run multi-diff
    let mut engine = build_multi_engine(
        fuzzy_config,
        config.matching.include_unchanged,
        &config.graph_diff,
        &config.rules,
    );

    let baseline_name = get_sbom_name(&config.baseline);

    let mut result = engine.diff_multi(
        baseline_parsed.sbom(),
        &baseline_name,
        &config.baseline.to_string_lossy(),
        &target_refs,
    )?;

    // Apply severity/VEX/graph-impact post-processing to each pairwise diff.
    for comparison in &mut result.comparisons {
        apply_post_diff_filters(&mut comparison.diff, &config.filtering, &config.graph_diff);
    }

    tracing::info!(
        "Multi-diff complete: {} comparisons, max deviation: {:.1}%",
        result.comparisons.len(),
        result.summary.max_deviation * 100.0
    );

    // Determine exit code
    let exit_code = determine_multi_exit_code(
        &config.behavior,
        &config.filtering,
        result.comparisons.iter().map(|c| &c.diff),
    );

    if let MultiOutput::Json(ref output_target) = output_mode {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, output_target, quiet)?;
    } else {
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

    // Validate output mode before doing work so unsupported formats fail fast.
    let output_mode = resolve_multi_output(&config.output)?;

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
    let mut engine = build_multi_engine(
        fuzzy_config,
        config.matching.include_unchanged,
        &config.graph_diff,
        &config.rules,
    );
    let mut result = engine.timeline(&sbom_refs)?;

    // Apply severity/VEX/graph-impact post-processing to each incremental diff.
    for diff in result
        .incremental_diffs
        .iter_mut()
        .chain(result.cumulative_from_first.iter_mut())
    {
        apply_post_diff_filters(diff, &config.filtering, &config.graph_diff);
    }

    tracing::info!(
        "Timeline analysis complete: {} incremental diffs",
        result.incremental_diffs.len()
    );

    // Determine exit code
    let exit_code = determine_multi_exit_code(
        &config.behavior,
        &config.filtering,
        result.incremental_diffs.iter(),
    );

    if let MultiOutput::Json(ref output_target) = output_mode {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, output_target, quiet)?;
    } else {
        let mut app = App::new_timeline(result);
        run_tui(&mut app)?;
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

    // Validate output mode before doing work so unsupported formats fail fast.
    let output_mode = resolve_multi_output(&config.output)?;

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
    let mut engine = build_multi_engine(
        fuzzy_config,
        config.matching.include_unchanged,
        &config.graph_diff,
        &config.rules,
    );
    let mut result = engine.matrix(&sbom_refs, Some(config.cluster_threshold))?;

    // Apply severity/VEX/graph-impact post-processing to each pairwise diff.
    for diff in result.diffs.iter_mut().flatten() {
        apply_post_diff_filters(diff, &config.filtering, &config.graph_diff);
    }

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

    // Determine exit code
    let exit_code = determine_multi_exit_code(
        &config.behavior,
        &config.filtering,
        result.diffs.iter().flatten(),
    );

    if let MultiOutput::Json(ref output_target) = output_mode {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, output_target, quiet)?;
    } else {
        let mut app = App::new_matrix(result);
        run_tui(&mut app)?;
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

/// Determine the exit code for a multi-SBOM command from its pairwise diffs.
///
/// Aggregates VEX gaps, introduced vulnerabilities, and total changes across
/// every pairwise [`DiffResult`] the command produced. Priority mirrors the
/// single-SBOM `diff` gate (highest code wins): VEX gaps (4) > vulns (2) >
/// changes (1). `--fail-on-vex-gap` is checked first because it is the most
/// specific signal a user can ask for.
fn determine_multi_exit_code<'a, I>(
    behavior: &crate::config::BehaviorConfig,
    filtering: &FilterConfig,
    diffs: I,
) -> i32
where
    I: IntoIterator<Item = &'a DiffResult>,
{
    let mut total_introduced = 0usize;
    let mut total_changes = 0usize;
    let mut total_gaps = 0usize;
    let mut introduced_gaps = 0usize;
    let mut persistent_gaps = 0usize;

    for diff in diffs {
        total_introduced += diff.summary.vulnerabilities_introduced;
        total_changes += diff.summary.total_changes;
        if filtering.fail_on_vex_gap {
            let vex = diff.vulnerabilities.vex_summary();
            introduced_gaps += vex.introduced_without_vex;
            persistent_gaps += vex.persistent_without_vex;
            total_gaps += vex.introduced_without_vex + vex.persistent_without_vex;
        }
    }

    if filtering.fail_on_vex_gap && total_gaps > 0 {
        eprintln!(
            "VEX gap: {total_gaps} vulnerability(ies) lack VEX statements \
             ({introduced_gaps} introduced, {persistent_gaps} persistent)",
        );
        return exit_codes::VEX_GAPS_FOUND;
    }
    if behavior.fail_on_vuln && total_introduced > 0 {
        return exit_codes::VULNS_INTRODUCED;
    }
    if behavior.fail_on_change && total_changes > 0 {
        return exit_codes::CHANGES_DETECTED;
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

    fn output_config(format: ReportFormat, file: Option<PathBuf>) -> crate::config::OutputConfig {
        crate::config::OutputConfig {
            format,
            file,
            ..Default::default()
        }
    }

    #[test]
    fn resolve_multi_output_accepts_tui_and_json() {
        assert!(matches!(
            resolve_multi_output(&output_config(ReportFormat::Tui, None)).unwrap(),
            MultiOutput::Tui
        ));
        assert!(matches!(
            resolve_multi_output(&output_config(ReportFormat::Json, None)).unwrap(),
            MultiOutput::Json(_)
        ));
    }

    #[test]
    fn resolve_multi_output_auto_to_file_is_json() {
        // Writing to a file is never a TTY, so `auto` must resolve to JSON.
        let cfg = output_config(ReportFormat::Auto, Some(PathBuf::from("/tmp/out.json")));
        assert!(matches!(
            resolve_multi_output(&cfg).unwrap(),
            MultiOutput::Json(_)
        ));
    }

    #[test]
    fn resolve_multi_output_rejects_unsupported_formats() {
        for fmt in [
            ReportFormat::Table,
            ReportFormat::Markdown,
            ReportFormat::Summary,
            ReportFormat::Sarif,
            ReportFormat::Html,
            ReportFormat::Csv,
            ReportFormat::SideBySide,
        ] {
            let result = resolve_multi_output(&output_config(fmt, None));
            let msg = match result {
                Ok(_) => panic!("format {fmt} must be rejected"),
                Err(e) => e.to_string(),
            };
            assert!(
                msg.contains("not supported for multi-SBOM commands"),
                "{msg}"
            );
            assert!(msg.contains("tui, json"), "{msg}");
        }
    }

    #[test]
    fn determine_multi_exit_code_change_gate() {
        let mut diff = DiffResult::new();
        diff.summary.total_changes = 3;
        let behavior = crate::config::BehaviorConfig {
            fail_on_change: true,
            ..Default::default()
        };
        let filtering = FilterConfig::default();
        assert_eq!(
            determine_multi_exit_code(&behavior, &filtering, std::iter::once(&diff)),
            exit_codes::CHANGES_DETECTED
        );

        // Without the gate flag, the same diff is success.
        let behavior = crate::config::BehaviorConfig::default();
        assert_eq!(
            determine_multi_exit_code(&behavior, &filtering, std::iter::once(&diff)),
            exit_codes::SUCCESS
        );
    }
}
