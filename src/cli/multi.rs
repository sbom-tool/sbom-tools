//! Multi-SBOM command handlers.
//!
//! Implements the `diff-multi`, `timeline`, and `matrix` subcommands.

use crate::diff::MultiDiffEngine;
use crate::matching::FuzzyMatchConfig;
use crate::model::NormalizedSbom;
use crate::parsers::parse_sbom;
use crate::pipeline::{write_output, OutputTarget};
use crate::reports::ReportFormat;
use crate::tui::{run_tui, App};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Run the diff-multi command (1:N comparison)
#[allow(clippy::needless_pass_by_value)]
pub fn run_diff_multi(
    baseline_path: PathBuf,
    target_paths: Vec<PathBuf>,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    fuzzy_preset: String,
    include_unchanged: bool,
) -> Result<()> {
    tracing::info!("Parsing baseline SBOM: {:?}", baseline_path);
    let baseline_sbom = parse_sbom(&baseline_path)
        .with_context(|| format!("Failed to parse baseline SBOM: {}", baseline_path.display()))?;

    let target_sboms = parse_multiple_sboms(&target_paths)?;

    tracing::info!(
        "Comparing baseline ({} components) against {} targets",
        baseline_sbom.component_count(),
        target_sboms.len()
    );

    let fuzzy_config = get_fuzzy_config(&fuzzy_preset);

    // Prepare target references with names
    let targets = prepare_sbom_refs(&target_sboms, &target_paths);
    let target_refs: Vec<_> = targets
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run multi-diff
    let mut engine = MultiDiffEngine::new()
        .with_fuzzy_config(fuzzy_config)
        .include_unchanged(include_unchanged);

    let baseline_name = get_sbom_name(&baseline_path);

    let result = engine.diff_multi(
        &baseline_sbom,
        &baseline_name,
        &baseline_path.to_string_lossy(),
        &target_refs,
    );

    tracing::info!(
        "Multi-diff complete: {} comparisons, max deviation: {:.1}%",
        result.comparisons.len(),
        result.summary.max_deviation * 100.0
    );

    // Output result
    output_multi_result(output, output_file, || {
        let mut app = App::new_multi_diff(result.clone());
        run_tui(&mut app).map_err(Into::into)
    }, || {
        serde_json::to_string_pretty(&result).map_err(Into::into)
    })
}

/// Run the timeline command
#[allow(clippy::needless_pass_by_value)]
pub fn run_timeline(
    sbom_paths: Vec<PathBuf>,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    fuzzy_preset: String,
) -> Result<()> {
    if sbom_paths.len() < 2 {
        bail!("Timeline analysis requires at least 2 SBOMs");
    }

    let sboms = parse_multiple_sboms(&sbom_paths)?;

    tracing::info!("Analyzing timeline of {} SBOMs", sboms.len());

    let fuzzy_config = get_fuzzy_config(&fuzzy_preset);

    // Prepare SBOM references with names
    let sbom_data = prepare_sbom_refs(&sboms, &sbom_paths);
    let sbom_refs: Vec<_> = sbom_data
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run timeline analysis
    let mut engine = MultiDiffEngine::new().with_fuzzy_config(fuzzy_config);
    let result = engine.timeline(&sbom_refs);

    tracing::info!(
        "Timeline analysis complete: {} incremental diffs",
        result.incremental_diffs.len()
    );

    // Output result
    output_multi_result(output, output_file, || {
        let mut app = App::new_timeline(result.clone());
        run_tui(&mut app).map_err(Into::into)
    }, || {
        serde_json::to_string_pretty(&result).map_err(Into::into)
    })
}

/// Run the matrix command (N×N comparison)
#[allow(clippy::needless_pass_by_value)]
pub fn run_matrix(
    sbom_paths: Vec<PathBuf>,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    fuzzy_preset: String,
    cluster_threshold: f64,
) -> Result<()> {
    if sbom_paths.len() < 2 {
        bail!("Matrix comparison requires at least 2 SBOMs");
    }

    let sboms = parse_multiple_sboms(&sbom_paths)?;

    tracing::info!(
        "Computing {}x{} comparison matrix",
        sboms.len(),
        sboms.len()
    );

    let fuzzy_config = get_fuzzy_config(&fuzzy_preset);

    // Prepare SBOM references with names
    let sbom_data = prepare_sbom_refs(&sboms, &sbom_paths);
    let sbom_refs: Vec<_> = sbom_data
        .iter()
        .map(|(sbom, name, path)| (*sbom, name.as_str(), path.as_str()))
        .collect();

    // Run matrix comparison
    let mut engine = MultiDiffEngine::new().with_fuzzy_config(fuzzy_config);
    let result = engine.matrix(&sbom_refs, Some(cluster_threshold));

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
    output_multi_result(output, output_file, || {
        let mut app = App::new_matrix(result.clone());
        run_tui(&mut app).map_err(Into::into)
    }, || {
        serde_json::to_string_pretty(&result).map_err(Into::into)
    })
}

/// Parse multiple SBOMs from paths
fn parse_multiple_sboms(paths: &[PathBuf]) -> Result<Vec<NormalizedSbom>> {
    let mut sboms = Vec::with_capacity(paths.len());
    for path in paths {
        tracing::info!("Parsing SBOM: {:?}", path);
        let sbom = parse_sbom(path).with_context(|| format!("Failed to parse SBOM: {}", path.display()))?;
        sboms.push(sbom);
    }
    Ok(sboms)
}

/// Get fuzzy matching config from preset name
fn get_fuzzy_config(preset: &str) -> FuzzyMatchConfig {
    FuzzyMatchConfig::from_preset(preset).unwrap_or_else(|| {
        tracing::warn!(
            "Unknown fuzzy preset '{}', using 'balanced'. Valid options: strict, balanced, permissive",
            preset
        );
        FuzzyMatchConfig::balanced()
    })
}

/// Get SBOM name from path
fn get_sbom_name(path: &Path) -> String {
    path.file_stem().map_or_else(|| "unknown".to_string(), |s| s.to_string_lossy().to_string())
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

/// Output multi-SBOM result with TUI or JSON fallback
fn output_multi_result<F, G>(
    output: ReportFormat,
    output_file: Option<PathBuf>,
    run_tui_fn: F,
    generate_json: G,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
    G: FnOnce() -> Result<String>,
{
    if output == ReportFormat::Tui {
        run_tui_fn()
    } else {
        let json = generate_json()?;
        let target = OutputTarget::from_option(output_file);
        write_output(&json, &target, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_fuzzy_config_valid_presets() {
        let config = get_fuzzy_config("strict");
        assert!(config.threshold > 0.8);

        let config = get_fuzzy_config("balanced");
        assert!(config.threshold >= 0.7 && config.threshold <= 0.85);

        let config = get_fuzzy_config("permissive");
        assert!(config.threshold <= 0.70);
    }

    #[test]
    fn test_get_fuzzy_config_invalid_preset() {
        // Should fall back to balanced
        let config = get_fuzzy_config("invalid");
        let balanced = FuzzyMatchConfig::balanced();
        assert_eq!(config.threshold, balanced.threshold);
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
        let paths = vec![
            PathBuf::from("first.json"),
            PathBuf::from("second.json"),
        ];

        let refs = prepare_sbom_refs(&sboms, &paths);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].1, "first");
        assert_eq!(refs[1].1, "second");
    }
}
