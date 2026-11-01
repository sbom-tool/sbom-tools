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
    exit_codes, graph_diff_config_from, parse_sbom_with_context, validate_post_diff_filters,
    write_output,
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

/// Build a `MultiDiffEngine` with graph diffing, matching rules and the
/// compliance run (`--as-of`, `--cra-product-class`, the PQC flags,
/// `--rule`, `--include-excluded-scope`) wired in from CLI configuration.
fn build_multi_engine(
    fuzzy_config: FuzzyMatchConfig,
    include_unchanged: bool,
    graph: &GraphAwareDiffConfig,
    rules: &MatchingRulesPathConfig,
    compliance: &crate::quality::ComplianceRunConfig,
) -> MultiDiffEngine {
    let mut engine = MultiDiffEngine::new()
        .with_fuzzy_config(fuzzy_config)
        .include_unchanged(include_unchanged)
        .with_compliance(compliance.clone());
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

    // Validate output mode and filter values before doing work (parsing,
    // enrichment) so unsupported formats and unknown filter labels fail fast,
    // matching timeline/matrix.
    let output_mode = resolve_multi_output(&config.output)?;
    validate_post_diff_filters(&config.filtering, &config.graph_diff)?;

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

    // Prepare display names, unique across the baseline AND all targets —
    // the engine keys spreads and the vulnerability matrix by these names.
    let mut all_paths = vec![config.baseline.clone()];
    all_paths.extend(config.targets.iter().cloned());
    let mut all_names = unique_sbom_names(&all_paths);
    let baseline_name = all_names.remove(0);

    let targets: Vec<(&NormalizedSbom, String, String)> = target_sboms
        .iter()
        .zip(all_names)
        .zip(config.targets.iter())
        .map(|((sbom, name), path)| (sbom, name, path.to_string_lossy().to_string()))
        .collect();
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
        &config.compliance,
    );

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
        PairDirection::Ordered,
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

        run_tui(&mut app, config.output.no_color)?;
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

    // Validate output mode and filter values before doing work so unsupported
    // formats and unknown filter labels fail fast.
    let output_mode = resolve_multi_output(&config.output)?;
    validate_post_diff_filters(&config.filtering, &config.graph_diff)?;
    // The compliance trend checks every standard.
    config
        .compliance
        .warn_on_unmatched_rules(crate::quality::ComplianceLevel::all(), "the standards");

    let (sboms, _enrich_stats) =
        parse_and_enrich_sboms(&config.sbom_paths, &config.enrichment, quiet)?;

    tracing::info!("Analyzing timeline of {} SBOMs", sboms.len());

    // Chronological argv order (oldest first) is a documented precondition;
    // a shuffled invocation silently inverts every Initial/Removed/Downgrade
    // classification, so at least warn when document timestamps disagree.
    if !quiet {
        let out_of_order: Vec<usize> = sboms
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[1].document.created < w[0].document.created)
            .map(|(i, _)| i + 1)
            .collect();
        if !out_of_order.is_empty() {
            eprintln!(
                "Warning: SBOM document timestamps are not in chronological order \
                 (position{} {}); timeline analysis assumes oldest-first argument order",
                if out_of_order.len() == 1 { "" } else { "s" },
                out_of_order
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

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
        &config.compliance,
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
        PairDirection::Ordered,
    );

    if let MultiOutput::Json(ref output_target) = output_mode {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, output_target, quiet)?;
    } else {
        let mut app = App::new_timeline(result);
        run_tui(&mut app, config.output.no_color)?;
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

    // Validate output mode and filter values before doing work so unsupported
    // formats and unknown filter labels fail fast.
    let output_mode = resolve_multi_output(&config.output)?;
    validate_post_diff_filters(&config.filtering, &config.graph_diff)?;

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
        &config.compliance,
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
        PairDirection::Unordered,
    );

    if let MultiOutput::Json(ref output_target) = output_mode {
        let json = serde_json::to_string_pretty(&result)?;
        write_output(&json, output_target, quiet)?;
    } else {
        let mut app = App::new_matrix(result);
        run_tui(&mut app, config.output.no_color)?;
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

/// How pairwise diffs should be interpreted when aggregating gate counts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PairDirection {
    /// Pairs have a meaningful old→new orientation (diff-multi: baseline vs
    /// target; timeline: chronological order). Only vulnerabilities
    /// introduced in that direction count.
    Ordered,
    /// Pairs are unordered (matrix: the engine computes only the i<j upper
    /// triangle, so which side is "old" depends on argv order). A vuln
    /// present in exactly one side of a pair counts regardless of direction:
    /// `resolved` in diff(a,b) is `introduced` in diff(b,a), so both are
    /// counted to make `--fail-on-vuln` symmetric — `matrix a b` and
    /// `matrix b a` must agree.
    Unordered,
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
    direction: PairDirection,
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
        if direction == PairDirection::Unordered {
            // Reverse-direction introductions surface as "resolved" in the
            // single computed orientation of an unordered pair.
            total_introduced += diff.summary.vulnerabilities_resolved;
        }
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
    let names = unique_sbom_names(paths);
    sboms
        .iter()
        .zip(names)
        .zip(paths.iter())
        .map(|((sbom, name), path)| {
            let path_str = path.to_string_lossy().to_string();
            (sbom, name, path_str)
        })
        .collect()
}

/// Derive display names from paths, guaranteed unique.
///
/// The multi-diff engine keys version spreads and the vulnerability matrix by
/// display name, so duplicate names (the natural `v1/app.json v2/app.json`
/// layout collapses to one "app" key) silently erase spreads and corrupt the
/// matrix. Colliding stems get their parent directory prepended; anything
/// still colliding gets a positional ordinal.
pub(crate) fn unique_sbom_names(paths: &[PathBuf]) -> Vec<String> {
    use std::collections::HashMap;

    let stems: Vec<String> = paths.iter().map(|p| get_sbom_name(p)).collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for stem in &stems {
        *counts.entry(stem.as_str()).or_default() += 1;
    }

    let mut names: Vec<String> = stems
        .iter()
        .zip(paths.iter())
        .map(|(stem, path)| {
            if counts[stem.as_str()] > 1 {
                match path.parent().and_then(|p| p.file_name()) {
                    Some(parent) => format!("{}/{}", parent.to_string_lossy(), stem),
                    None => stem.clone(),
                }
            } else {
                stem.clone()
            }
        })
        .collect();

    // Ordinal fallback for anything still colliding (same parent dir name).
    // Ordinals are bumped until the generated name is unused ANYWHERE in the
    // final set — a plain " (1)" suffix can collide with a literal stem like
    // "app (1).json", silently re-collapsing the name-keyed maps this
    // function exists to protect.
    let mut totals: HashMap<String, usize> = HashMap::new();
    for name in &names {
        *totals.entry(name.clone()).or_default() += 1;
    }
    let mut taken: std::collections::HashSet<String> = names
        .iter()
        .filter(|n| totals[n.as_str()] == 1)
        .cloned()
        .collect();
    for name in &mut names {
        if totals[name.as_str()] > 1 {
            let mut ordinal = 1;
            while taken.contains(&format!("{name} ({ordinal})")) {
                ordinal += 1;
            }
            *name = format!("{name} ({ordinal})");
            taken.insert(name.clone());
        }
    }
    names
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

    /// Duplicate file stems (v1/app.json v2/app.json — the natural way to
    /// snapshot one application) previously collapsed to one HashMap key in
    /// the engine, erasing version spreads and corrupting the vulnerability
    /// matrix.
    #[test]
    fn test_unique_sbom_names_disambiguates_duplicates() {
        let paths = vec![
            PathBuf::from("v1/app.json"),
            PathBuf::from("v2/app.json"),
            PathBuf::from("v3/app.json"),
        ];
        assert_eq!(
            unique_sbom_names(&paths),
            vec!["v1/app", "v2/app", "v3/app"]
        );

        // Same parent directory: ordinal fallback
        let paths = vec![PathBuf::from("a/x.json"), PathBuf::from("a/x.json")];
        assert_eq!(unique_sbom_names(&paths), vec!["a/x (1)", "a/x (2)"]);

        // Distinct stems stay untouched
        let paths = vec![PathBuf::from("old.json"), PathBuf::from("new.json")];
        assert_eq!(unique_sbom_names(&paths), vec!["old", "new"]);

        // Audit regression: an ordinal-suffixed name must not collide with a
        // literal stem — "app (1).json" is a real browser-download name.
        let paths = vec![
            PathBuf::from("app.json"),
            PathBuf::from("app.xml"),
            PathBuf::from("app (1).json"),
        ];
        let names = unique_sbom_names(&paths);
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "names must be unique even against literal ordinal-style stems: {names:?}"
        );
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
            determine_multi_exit_code(
                &behavior,
                &filtering,
                std::iter::once(&diff),
                PairDirection::Ordered
            ),
            exit_codes::CHANGES_DETECTED
        );

        // Without the gate flag, the same diff is success.
        let behavior = crate::config::BehaviorConfig::default();
        assert_eq!(
            determine_multi_exit_code(
                &behavior,
                &filtering,
                std::iter::once(&diff),
                PairDirection::Ordered
            ),
            exit_codes::SUCCESS
        );
    }

    /// Matrix pairs are unordered (the engine only computes the i<j upper
    /// triangle), so `--fail-on-vuln` must fire when a vuln exists in either
    /// side of a pair but not the other — otherwise `matrix a b` and
    /// `matrix b a` disagree on the exit code.
    #[test]
    fn determine_multi_exit_code_vuln_gate_symmetric_for_unordered_pairs() {
        let behavior = crate::config::BehaviorConfig {
            fail_on_vuln: true,
            ..Default::default()
        };
        let filtering = FilterConfig::default();

        // `matrix a vuln.json` computes diff(a, vuln): vulns are "introduced".
        let mut forward = DiffResult::new();
        forward.summary.vulnerabilities_introduced = 1;
        // `matrix vuln.json a` computes diff(vuln, a): same vulns are "resolved".
        let mut reverse = DiffResult::new();
        reverse.summary.vulnerabilities_resolved = 1;

        for diff in [&forward, &reverse] {
            assert_eq!(
                determine_multi_exit_code(
                    &behavior,
                    &filtering,
                    std::iter::once(diff),
                    PairDirection::Unordered
                ),
                exit_codes::VULNS_INTRODUCED,
                "matrix vuln gate must be argument-order independent"
            );
        }

        // Ordered commands (diff-multi/timeline) keep directional semantics:
        // a resolved vuln is progress, not a gate failure.
        assert_eq!(
            determine_multi_exit_code(
                &behavior,
                &filtering,
                std::iter::once(&reverse),
                PairDirection::Ordered
            ),
            exit_codes::SUCCESS
        );
    }
}
