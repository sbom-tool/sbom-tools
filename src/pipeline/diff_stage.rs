//! Diff computation stage.
//!
//! Encapsulates the core diff logic: building the engine, applying matching
//! rules, running the diff, and post-processing (severity/VEX filtering).

use crate::config::DiffConfig;
use crate::diff::{DiffEngine, DiffResult, GraphDiffConfig};
use crate::matching::{FuzzyMatchConfig, MatchingRulesConfig};
use crate::model::NormalizedSbom;
use anyhow::{Context, Result};

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
        engine = engine.with_graph_diff(GraphDiffConfig {
            detect_reparenting: config.graph_diff.detect_reparenting,
            detect_depth_changes: config.graph_diff.detect_depth_changes,
            max_depth: 0, // 0 = unlimited depth traversal
        });
    }

    // Apply matching rules if loaded and not in dry-run mode
    if let Some(rules) = matching_rules {
        if !config.rules.dry_run {
            let rule_engine = crate::matching::RuleEngine::new(rules)
                .map_err(|e| anyhow::anyhow!("Failed to initialize matching rule engine: {e}"))?;
            engine = engine.with_rule_engine(rule_engine);
        }
    }

    let mut result = engine
        .diff(old_sbom, new_sbom)
        .context("Failed to compute diff")?;

    // Report on graph changes if enabled
    if config.graph_diff.enabled && !quiet {
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

    // Apply severity filtering if specified
    if let Some(ref sev) = config.filtering.min_severity {
        result.filter_by_severity(sev);
        if !quiet {
            tracing::info!("Filtered vulnerabilities to severity >= {}", sev);
        }
    }

    // Apply VEX filtering if requested
    if config.filtering.exclude_vex_resolved {
        result.filter_by_vex();
        if !quiet {
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

/// Print match explanations for modified components to stdout.
///
/// Uses `println!()` intentionally — this is user-facing CLI diagnostic output
/// triggered by `--explain-matches`, not a log message.
fn print_match_explanations(result: &DiffResult) {
    println!("\n=== Match Explanations ===\n");
    for change in &result.components.modified {
        if let Some(ref match_info) = change.match_info {
            println!("Component: {}", change.name);
            println!("  Score: {:.2} ({})", match_info.score, match_info.method);
            println!("  Reason: {}", match_info.reason);
            if !match_info.score_breakdown.is_empty() {
                println!("  Score breakdown:");
                for component in &match_info.score_breakdown {
                    println!(
                        "    - {}: {:.2} x {:.2} = {:.2}",
                        component.name,
                        component.raw_score,
                        component.weight,
                        component.weighted_score
                    );
                }
            }
            if !match_info.normalizations.is_empty() {
                println!(
                    "  Normalizations: {}",
                    match_info.normalizations.join(", ")
                );
            }
            println!();
        }
    }
}

/// Print threshold recommendation based on SBOMs to stdout.
///
/// Uses `println!()` intentionally — this is user-facing CLI diagnostic output
/// triggered by `--recommend-threshold`, not a log message.
fn print_threshold_recommendation(
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    fuzzy_config: FuzzyMatchConfig,
) {
    use crate::matching::{AdaptiveThreshold, AdaptiveThresholdConfig, FuzzyMatcher};

    let adaptive = AdaptiveThreshold::new(AdaptiveThresholdConfig::default());
    let matcher = FuzzyMatcher::new(fuzzy_config);

    let recommendation = adaptive.compute_threshold(old_sbom, new_sbom, &matcher);
    println!("\n=== Threshold Recommendation ===\n");
    println!("Recommended threshold: {:.2}", recommendation.threshold);
    println!("Confidence: {:.0}%", recommendation.confidence * 100.0);
    println!("Method used: {:?}", recommendation.method);
    println!("Samples analyzed: {}", recommendation.samples);
    println!(
        "Match ratio at threshold: {:.1}%",
        recommendation.match_ratio * 100.0
    );
    println!("\nScore distribution:");
    println!("  Mean: {:.3}", recommendation.score_stats.mean);
    println!("  Std dev: {:.3}", recommendation.score_stats.std_dev);
    println!("  Median: {:.3}", recommendation.score_stats.median);
    println!(
        "  Min: {:.3}, Max: {:.3}",
        recommendation.score_stats.min, recommendation.score_stats.max
    );
    println!();
}
