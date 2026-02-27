//! Calibration tests for the software complexity index.
//!
//! These tests ARE the spec — weights in `compute_complexity` must be tuned
//! until all assertions pass. Each fixture SBOM has a known structure that
//! should produce reasonable complexity values.

use sbom_tools::parse_sbom;
use sbom_tools::quality::{DependencyMetrics, QualityScorer, ScoringProfile};
use std::path::Path;

/// Helper: compute dependency metrics from a fixture file
fn metrics_for(fixture: &str) -> DependencyMetrics {
    let sbom = parse_sbom(Path::new(fixture)).unwrap_or_else(|e| panic!("{fixture}: {e}"));
    DependencyMetrics::from_sbom(&sbom)
}

/// Helper: get simplicity index, panicking if None
fn simplicity_for(fixture: &str) -> f32 {
    let m = metrics_for(fixture);
    m.software_complexity_index
        .unwrap_or_else(|| panic!("{fixture}: complexity was None (graph_analysis_skipped)"))
}

// ============================================================================
// Minimal / empty SBOMs should be very simple
// ============================================================================

#[test]
fn minimal_cyclonedx_is_simple() {
    let s = simplicity_for("tests/fixtures/cyclonedx/minimal.cdx.json");
    assert!(
        s >= 70.0,
        "Minimal CycloneDX simplicity {s} should be >= 70"
    );
}

#[test]
fn minimal_spdx_is_simple() {
    let s = simplicity_for("tests/fixtures/spdx/minimal.spdx.json");
    assert!(s >= 70.0, "Minimal SPDX simplicity {s} should be >= 70");
}

#[test]
fn with_vulnerabilities_is_simple() {
    let s = simplicity_for("tests/fixtures/cyclonedx/with-vulnerabilities.cdx.json");
    assert!(
        s >= 70.0,
        "With-vulnerabilities simplicity {s} should be >= 70"
    );
}

// ============================================================================
// Demo SBOMs should produce non-degenerate complexity (20-95 range)
// ============================================================================

#[test]
fn demo_sboms_in_range() {
    let fixtures = [
        "tests/fixtures/demo-old.cdx.json",
        "tests/fixtures/demo-new.cdx.json",
        "tests/fixtures/demo-eol-old.cdx.json",
        "tests/fixtures/demo-eol-new.cdx.json",
    ];

    for fixture in &fixtures {
        let s = simplicity_for(fixture);
        assert!(
            (20.0..=95.0).contains(&s),
            "{fixture}: simplicity {s} should be in 20-95 range"
        );
    }
}

// ============================================================================
// Complexity fields are populated when graph analysis runs
// ============================================================================

#[test]
fn complexity_fields_populated() {
    let m = metrics_for("tests/fixtures/demo-new.cdx.json");
    assert!(
        !m.graph_analysis_skipped,
        "Graph analysis should not be skipped for demo fixture"
    );
    assert!(m.software_complexity_index.is_some());
    assert!(m.complexity_level.is_some());
    assert!(m.complexity_factors.is_some());

    let factors = m.complexity_factors.unwrap();
    // All factors should be in [0, 1]
    for (name, val) in [
        ("dependency_volume", factors.dependency_volume),
        ("normalized_depth", factors.normalized_depth),
        ("fanout_concentration", factors.fanout_concentration),
        ("cycle_ratio", factors.cycle_ratio),
        ("fragmentation", factors.fragmentation),
    ] {
        assert!(
            (0.0..=1.0).contains(&val),
            "Factor {name} = {val} should be in [0, 1]"
        );
    }
}

// ============================================================================
// Recommendations generated for complex SBOMs
// ============================================================================

#[test]
fn recommendations_include_complexity_when_applicable() {
    // Score a demo SBOM and check that complexity recommendations exist
    // when the complexity level warrants it
    let sbom = parse_sbom(Path::new("tests/fixtures/demo-new.cdx.json")).unwrap();
    let scorer = QualityScorer::new(ScoringProfile::Standard);
    let report = scorer.score(&sbom);

    // The report should have dependency_metrics with complexity
    assert!(
        report
            .dependency_metrics
            .software_complexity_index
            .is_some()
    );

    // If complexity is High or VeryHigh, there should be a matching recommendation
    if let Some(level) = &report.dependency_metrics.complexity_level {
        use sbom_tools::quality::ComplexityLevel;
        if matches!(level, ComplexityLevel::High | ComplexityLevel::VeryHigh) {
            let has_complexity_rec = report
                .recommendations
                .iter()
                .any(|r| r.message.contains("complex"));
            assert!(
                has_complexity_rec,
                "High/VeryHigh complexity should produce a recommendation"
            );
        }
    }
}

// ============================================================================
// max_out_degree is always populated
// ============================================================================

#[test]
fn max_out_degree_for_graph_with_edges() {
    let m = metrics_for("tests/fixtures/cyclonedx/minimal.cdx.json");
    // Minimal CycloneDX has 1 edge, so max_out_degree should be 1
    assert_eq!(
        m.max_out_degree, 1,
        "max_out_degree should be 1 for minimal fixture with 1 edge"
    );
}
