//! Diff computation stage.
//!
//! Encapsulates the core diff logic: building the engine, applying matching
//! rules, running the diff, and post-processing (severity/VEX filtering).

use crate::config::{DiffConfig, FilterConfig, GraphAwareDiffConfig};
use crate::diff::{DiffEngine, DiffResult, GraphDiffConfig};
use crate::matching::{FuzzyMatchConfig, MatchingRulesConfig};
use crate::model::NormalizedSbom;
use anyhow::{Result, bail};

/// Labels accepted by `--severity` and `--graph-impact-threshold`.
const VALID_LEVELS: [&str; 4] = ["critical", "high", "medium", "low"];

/// Validate user-supplied post-diff filter values up front.
///
/// Previously an unknown `--severity` value silently filtered nothing (an
/// unrecognized label coerces to rank 0, so every vulnerability passes the
/// `>=` check) and an unknown `--graph-impact-threshold` silently coerced to
/// `low`. Both are now hard errors (operational error, exit 3 via `main`)
/// listing the valid values.
///
/// # Errors
///
/// Returns an error if `filtering.min_severity` or `graph.impact_threshold`
/// is not one of `critical`, `high`, `medium`, `low`.
pub fn validate_post_diff_filters(
    filtering: &FilterConfig,
    graph: &GraphAwareDiffConfig,
) -> Result<()> {
    if let Some(ref sev) = filtering.min_severity
        && !VALID_LEVELS.contains(&sev.to_lowercase().as_str())
    {
        bail!("invalid --severity value '{sev}'; valid values: critical, high, medium, low");
    }
    if let Some(ref threshold) = graph.impact_threshold
        && !VALID_LEVELS.contains(&threshold.to_lowercase().as_str())
    {
        bail!(
            "invalid --graph-impact-threshold value '{threshold}'; \
             valid values: critical, high, medium, low"
        );
    }
    Ok(())
}

/// Convert a [`GraphAwareDiffConfig`] (CLI/config representation) into the
/// engine-level [`GraphDiffConfig`] consumed by the diff engine.
///
/// Shared between the single-SBOM pipeline and the multi-SBOM commands so that
/// `--graph-max-depth`, `--graph-relations`, and reparenting/depth toggles take
/// effect identically in both paths.
#[must_use]
pub fn graph_diff_config_from(config: &GraphAwareDiffConfig) -> GraphDiffConfig {
    GraphDiffConfig {
        detect_reparenting: config.detect_reparenting,
        detect_depth_changes: config.detect_depth_changes,
        max_depth: config.max_depth,
        relation_filter: config.relation_filter.clone(),
    }
}

/// Apply the graph impact threshold to an already-computed [`DiffResult`].
///
/// Mirrors the post-processing the single-SBOM pipeline performs after the
/// engine runs. Recomputes the graph summary and overall summary so the result
/// stays internally consistent.
fn apply_graph_impact_threshold(result: &mut DiffResult, threshold: &str) {
    let min_impact = crate::diff::GraphChangeImpact::from_label(threshold);
    let impact_rank = |i: &crate::diff::GraphChangeImpact| match i {
        crate::diff::GraphChangeImpact::Critical => 4,
        crate::diff::GraphChangeImpact::High => 3,
        crate::diff::GraphChangeImpact::Medium => 2,
        crate::diff::GraphChangeImpact::Low => 1,
    };
    let min_rank = impact_rank(&min_impact);
    result
        .graph_changes
        .retain(|c| impact_rank(&c.impact) >= min_rank);
    result.graph_summary = Some(crate::diff::GraphChangeSummary::from_changes(
        &result.graph_changes,
    ));
    result.calculate_summary();
}

/// Apply severity, VEX, and graph-impact post-processing filters to a
/// [`DiffResult`], driven by filtering and graph configuration.
///
/// Shared between the single-SBOM pipeline and the multi-SBOM commands so that
/// `--severity`, `--exclude-vex-resolved`, and `--graph-impact-threshold` are
/// honored consistently across `diff`, `diff-multi`, `timeline`, and `matrix`.
pub fn apply_post_diff_filters(
    result: &mut DiffResult,
    filtering: &FilterConfig,
    graph: &GraphAwareDiffConfig,
) {
    if graph.enabled
        && let Some(ref threshold) = graph.impact_threshold
    {
        apply_graph_impact_threshold(result, threshold);
    }
    if let Some(ref sev) = filtering.min_severity {
        result.filter_by_severity(sev);
    }
    if filtering.exclude_vex_resolved {
        result.filter_by_vex();
    }
}

/// Run the core diff computation between two SBOMs.
///
/// This builds the diff engine with the configured options, runs the diff,
/// and applies any post-processing filters (severity, VEX).
pub fn compute_diff(
    config: &DiffConfig,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
) -> Result<DiffResult> {
    let quiet = config.behavior.quiet;
    let fuzzy_config = config.matching.to_fuzzy_config();

    // Reject unknown filter values before doing any work. Callers that want
    // to fail before parsing validate earlier as well; this is the backstop
    // for any path that reaches the diff stage directly.
    validate_post_diff_filters(&config.filtering, &config.graph_diff)?;

    // Load matching rules if specified
    let matching_rules = load_matching_rules(config)?;

    if !quiet {
        tracing::info!("Computing semantic diff...");
    }

    // Build the diff engine
    let mut engine = DiffEngine::new()
        .with_fuzzy_config(fuzzy_config.clone())
        .include_unchanged(config.matching.include_unchanged);

    // Enable graph-aware diffing if requested
    if config.graph_diff.enabled {
        if !quiet {
            tracing::info!("Graph-aware diffing enabled");
        }
        engine = engine.with_graph_diff(graph_diff_config_from(&config.graph_diff));
    }

    // Apply matching rules if loaded and not in dry-run mode
    if let Some(rules) = matching_rules
        && !config.rules.dry_run
    {
        let rule_engine = crate::matching::RuleEngine::new(rules)
            .map_err(|e| anyhow::anyhow!("Failed to initialize matching rule engine: {e}"))?;
        engine = engine.with_rule_engine(rule_engine);
    }

    let mut result = engine
        .diff(old_sbom, new_sbom)
        .map_err(|e| super::PipelineError::DiffFailed { source: e.into() })?;

    apply_post_diff_filters(&mut result, &config.filtering, &config.graph_diff);

    if !quiet {
        if config.graph_diff.enabled {
            if let Some(ref threshold) = config.graph_diff.impact_threshold {
                tracing::info!("Filtered graph changes to impact >= {threshold}");
            }
            if let Some(ref summary) = result.graph_summary {
                tracing::info!(
                    "Graph changes: {} total ({} added, {} removed, {} reparented, {} depth changes)",
                    summary.total_changes,
                    summary.dependencies_added,
                    summary.dependencies_removed,
                    summary.reparented,
                    summary.depth_changed
                );
            }
        }
        if let Some(ref sev) = config.filtering.min_severity {
            tracing::info!("Filtered vulnerabilities to severity >= {}", sev);
        }
        if config.filtering.exclude_vex_resolved {
            tracing::info!("Filtered out vulnerabilities with VEX status not_affected or fixed");
        }
    }

    if !quiet {
        tracing::info!(
            "Diff complete: {} changes, semantic score: {:.1}",
            result.summary.total_changes,
            result.semantic_score
        );
    }

    // Print match explanations if requested
    if config.behavior.explain_matches {
        print_match_explanations(&result);
    }

    // Recommend optimal threshold if requested (consumes fuzzy_config)
    if config.behavior.recommend_threshold {
        print_threshold_recommendation(old_sbom, new_sbom, fuzzy_config);
    }

    // Compute quality delta. Profile-aware: a CBOM side is scored by the CBOM
    // engine so the delta's categories are the crypto categories the scorer
    // actually used (matching the TUI's per-side detection in
    // `App::new_diff`). AI-BOMs deliberately stay on Standard here — the
    // AI-readiness scoring path zeroes all 8 standard category scores, which
    // would make every per-category delta vacuous.
    {
        let profile_for = |sbom: &crate::model::NormalizedSbom| {
            if crate::model::BomProfile::detect(sbom) == crate::model::BomProfile::Cbom {
                crate::quality::ScoringProfile::Cbom
            } else {
                crate::quality::ScoringProfile::Standard
            }
        };
        // Scored with the run's shared compliance inputs (the `--as-of`
        // clock dates the time-sensitive metrics), as the TUI scores them.
        let score = |sbom: &crate::model::NormalizedSbom| {
            crate::quality::QualityScorer::new(profile_for(sbom))
                .with_compliance(config.compliance.clone())
                .score(sbom)
        };
        let old_report = score(old_sbom);
        let new_report = score(new_sbom);
        result.quality_delta = Some(crate::diff::QualityDelta::from_reports(
            &old_report,
            &new_report,
        ));
    }

    Ok(result)
}

/// Load matching rules from file if specified.
fn load_matching_rules(config: &DiffConfig) -> Result<Option<MatchingRulesConfig>> {
    let quiet = config.behavior.quiet;

    config.rules.rules_file.as_ref().map_or_else(
        || Ok(None),
        |rules_path| {
            if !quiet {
                tracing::info!("Loading matching rules from {:?}", rules_path);
            }
            match MatchingRulesConfig::from_file(rules_path) {
                Ok(rules) => {
                    let summary = rules.summary();
                    if !quiet {
                        tracing::info!("Loaded {}", summary);
                    }
                    if config.rules.dry_run {
                        tracing::info!("Dry-run mode: rules will be shown but not applied");
                    }
                    Ok(Some(rules))
                }
                Err(e) => {
                    tracing::warn!("Failed to load matching rules: {}", e);
                    Ok(None)
                }
            }
        },
    )
}

/// Print match explanations for modified components to STDERR.
///
/// This is user-facing CLI diagnostic output triggered by `--explain-matches`.
/// It must go to stderr: the report itself (including `-o json`/`sarif`/`csv`)
/// is written to stdout, and interleaving these blocks there corrupts
/// machine-parseable output.
fn print_match_explanations(result: &DiffResult) {
    eprintln!("\n=== Match Explanations ===\n");
    for change in &result.components.modified {
        if let Some(ref match_info) = change.match_info {
            eprintln!("Component: {}", change.name);
            eprintln!("  Score: {:.2} ({})", match_info.score, match_info.method);
            eprintln!("  Reason: {}", match_info.reason);
            if !match_info.score_breakdown.is_empty() {
                eprintln!("  Score breakdown:");
                for component in &match_info.score_breakdown {
                    eprintln!(
                        "    - {}: {:.2} x {:.2} = {:.2}",
                        component.name,
                        component.raw_score,
                        component.weight,
                        component.weighted_score
                    );
                }
            }
            if !match_info.normalizations.is_empty() {
                eprintln!("  Normalizations: {}", match_info.normalizations.join(", "));
            }
            eprintln!();
        }
    }
}

/// Print threshold recommendation based on SBOMs to STDERR.
///
/// This is user-facing CLI diagnostic output triggered by
/// `--recommend-threshold`. It must go to stderr: the report itself (including
/// `-o json`/`sarif`/`csv`) is written to stdout, and interleaving this block
/// there corrupts machine-parseable output.
fn print_threshold_recommendation(
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    fuzzy_config: FuzzyMatchConfig,
) {
    use crate::matching::{AdaptiveThreshold, AdaptiveThresholdConfig, FuzzyMatcher};

    let adaptive = AdaptiveThreshold::new(AdaptiveThresholdConfig::default());
    let matcher = FuzzyMatcher::new(fuzzy_config);

    let recommendation = adaptive.compute_threshold(old_sbom, new_sbom, &matcher);
    eprintln!("\n=== Threshold Recommendation ===\n");
    eprintln!("Recommended threshold: {:.2}", recommendation.threshold);
    eprintln!("Confidence: {:.0}%", recommendation.confidence * 100.0);
    eprintln!("Method used: {:?}", recommendation.method);
    eprintln!("Samples analyzed: {}", recommendation.samples);
    eprintln!(
        "Match ratio at threshold: {:.1}%",
        recommendation.match_ratio * 100.0
    );
    eprintln!("\nScore distribution:");
    eprintln!("  Mean: {:.3}", recommendation.score_stats.mean);
    eprintln!("  Std dev: {:.3}", recommendation.score_stats.std_dev);
    eprintln!("  Median: {:.3}", recommendation.score_stats.median);
    eprintln!(
        "  Min: {:.3}, Max: {:.3}",
        recommendation.score_stats.min, recommendation.score_stats.max
    );
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filtering(min_severity: Option<&str>) -> FilterConfig {
        FilterConfig {
            min_severity: min_severity.map(str::to_string),
            ..Default::default()
        }
    }

    fn graph(threshold: Option<&str>) -> GraphAwareDiffConfig {
        GraphAwareDiffConfig {
            impact_threshold: threshold.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn validate_accepts_known_severity_labels_case_insensitively() {
        for sev in ["critical", "high", "medium", "low", "HIGH", "Critical"] {
            validate_post_diff_filters(&filtering(Some(sev)), &graph(None)).unwrap();
        }
        // No filters at all is fine.
        validate_post_diff_filters(&filtering(None), &graph(None)).unwrap();
    }

    #[test]
    fn validate_rejects_unknown_severity() {
        let err = validate_post_diff_filters(&filtering(Some("bogus")), &graph(None)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--severity"), "{msg}");
        assert!(msg.contains("bogus"), "{msg}");
        assert!(msg.contains("critical, high, medium, low"), "{msg}");
    }

    #[test]
    fn validate_rejects_unknown_graph_impact_threshold() {
        // The threshold must be validated even when graph diffing is not
        // enabled — the old behavior silently coerced unknown labels to
        // `low`, which is exactly the silent no-op being fixed.
        let err = validate_post_diff_filters(&filtering(None), &graph(Some("bogus"))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--graph-impact-threshold"), "{msg}");
        assert!(msg.contains("bogus"), "{msg}");
        assert!(msg.contains("critical, high, medium, low"), "{msg}");
    }

    #[test]
    fn validate_accepts_known_graph_impact_thresholds() {
        for level in ["critical", "high", "medium", "low"] {
            validate_post_diff_filters(&filtering(None), &graph(Some(level))).unwrap();
        }
    }
}
