//! Hot-path benchmarks across the full pipeline: parsing, the fuzzy matcher tier
//! cascade, quality graph analysis (Tarjan/cycle/depth), quality scoring, and
//! report generation.
//!
//! Run with: `cargo bench --bench hot_paths`
//!
//! Fixtures come from `benches/support` and are GRAPH-SHAPED and deterministic,
//! so samples are comparable across commits. Full-diff benches are capped at
//! ~5K components (a 40K full diff runs into minutes); the dependency-graph
//! analysis bench runs at 40K because it is near-linear and is exactly the
//! deep-graph case we want covered.

mod support;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sbom_tools::diff::{DiffEngine, LargeSbomConfig};
use sbom_tools::matching::{FuzzyMatchConfig, FuzzyMatcher};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{DependencyMetrics, QualityScorer, ScoringProfile};
use sbom_tools::reports::{JsonReporter, ReportConfig, ReportGenerator, SarifReporter};
use std::hint::black_box;
use support::{Topology, cyclonedx_json, generate_graph_pair, generate_graph_sbom};

// ── Parsing ────────────────────────────────────────────────────────────────

/// Parse a CycloneDX JSON document (format detection + full deserialisation +
/// dependency-edge resolution) across a small/medium/large sweep.
fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_sbom_str");
    for &size in &[100usize, 1_000, 5_000] {
        let json = cyclonedx_json(size);
        // Sanity: ensure the generated document actually parses, so a regression
        // in the generator fails loudly instead of benchmarking an error path.
        assert!(parse_sbom_str(&json).is_ok());
        group.throughput(criterion::Throughput::Bytes(json.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("cyclonedx_json", size),
            &json,
            |b, json| {
                b.iter(|| {
                    let _ = black_box(parse_sbom_str(black_box(json)));
                });
            },
        );
    }
    group.finish();
}

// ── Fuzzy matcher tier cascade ───────────────────────────────────────────────

/// Exercise the `FuzzyMatcher` tier cascade (exact PURL → alias → ecosystem rule
/// → fuzzy/multi-field) over pairs that resolve at each tier, so every layer is
/// represented rather than only the early exit.
fn bench_matcher_cascade(c: &mut Criterion) {
    let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

    // Two graph SBOMs sharing names but with bumped versions. Half the candidate
    // pairs match on exact PURL (same node), the other half fall through to the
    // fuzzy/ecosystem tiers (different version → no exact PURL).
    let a = generate_graph_sbom("old", 1_000, Topology::Mixed);
    let b = generate_graph_sbom("new", 1_000, Topology::Mixed);
    let a_comps: Vec<_> = a.components.values().collect();
    let b_comps: Vec<_> = b.components.values().collect();

    c.bench_function("matcher_tier_cascade_1000_pairs", |bencher| {
        bencher.iter(|| {
            let mut acc = 0.0f64;
            for (ca, cb) in a_comps.iter().zip(&b_comps) {
                acc += matcher.match_components(black_box(ca), black_box(cb));
                // Cross pair (offset by one) drives the lower tiers more often.
            }
            black_box(acc);
        });
    });
}

// ── Diff engine across the LSH / sparse-solver boundary ──────────────────────

/// Diff across the `lsh_threshold` boundary (default 500). Below the threshold
/// the direct matcher path runs; above it the LSH batch generator + sparse
/// assignment path runs. Capped at ~5K components so a full diff stays well
/// under a minute.
fn bench_diff_boundary(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_lsh_boundary");
    group.sample_size(20);

    // 300 (below default lsh_threshold=500) → direct path.
    // 1_000 / 5_000 (above) → LSH batch + sparse assignment path.
    for &size in &[300usize, 1_000, 5_000] {
        let (old, new) = generate_graph_pair(size, 10.0, Topology::Mixed);
        let engine = DiffEngine::new();
        group.bench_with_input(BenchmarkId::new("graph_pair", size), &size, |b, _| {
            b.iter(|| {
                let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
            });
        });
    }
    group.finish();

    // Hungarian/sparse worst case: disjoint ids force full fuzzy assignment with
    // the dense-trigger path explicitly engaged. Heavy per-iter → tiny sample.
    let mut heavy = c.benchmark_group("diff_hungarian_disjoint");
    heavy.sample_size(10);
    let config = LargeSbomConfig {
        lsh_threshold: 1_000_000, // force the ComponentIndex (dense-trigger) path
        ..LargeSbomConfig::default()
    };
    for &size in &[2_000usize, 4_000] {
        let (old, new) = support::generate_disjoint_pair(size);
        let engine = DiffEngine::new().with_large_sbom_config(config.clone());
        heavy.bench_with_input(BenchmarkId::new("disjoint", size), &size, |b, _| {
            b.iter(|| {
                let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
            });
        });
    }
    heavy.finish();
}

// ── Quality: dependency-graph analysis (Tarjan / cycle / BFS depth) ──────────

/// `DependencyMetrics::from_sbom` runs the Tarjan SCC / cycle detection,
/// union-find island count, and BFS depth. Run at 40K nodes (with edges) to
/// cover the deep-graph case — this path is near-linear, so a full 40K run is
/// practical, unlike a 40K full diff.
fn bench_dependency_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("dependency_metrics_from_sbom");
    group.sample_size(20);

    for &(label, topology) in &[
        ("chain", Topology::Chain),
        ("diamond", Topology::Diamond),
        ("cyclic", Topology::Cyclic),
        ("mixed", Topology::Mixed),
    ] {
        let sbom = generate_graph_sbom("g", 40_000, topology);
        group.bench_function(label, |b| {
            b.iter(|| {
                let _ = black_box(DependencyMetrics::from_sbom(black_box(&sbom)));
            });
        });
    }
    group.finish();
}

// ── Quality scoring ──────────────────────────────────────────────────────────

/// Full `QualityScorer::score` over a graph SBOM (all 8 categories, including
/// the dependency metrics above). Run on a medium fixture to keep wall time low.
fn bench_quality_score(c: &mut Criterion) {
    let sbom = generate_graph_sbom("g", 5_000, Topology::Mixed);

    let mut group = c.benchmark_group("quality_score");
    for &(label, profile) in &[
        ("standard", ScoringProfile::Standard),
        ("security", ScoringProfile::Security),
        ("comprehensive", ScoringProfile::Comprehensive),
    ] {
        let scorer = QualityScorer::new(profile);
        group.bench_function(label, |b| {
            b.iter(|| {
                let _ = black_box(scorer.score(black_box(&sbom)));
            });
        });
    }
    group.finish();
}

// ── Report generation (JSON + SARIF) ─────────────────────────────────────────

/// Generate JSON and SARIF diff reports from a real (non-trivial) diff result.
/// Reuses one diff result across both reporters so we measure rendering, not the
/// diff itself.
fn bench_report_generation(c: &mut Criterion) {
    let (old, new) = generate_graph_pair(2_000, 25.0, Topology::Mixed);
    let engine = DiffEngine::new();
    let result = engine.diff(&old, &new).expect("bench diff should succeed");
    let config = ReportConfig::default();

    let json = JsonReporter::new();
    let sarif = SarifReporter::new();

    let mut group = c.benchmark_group("report_generation");
    group.bench_function("json", |b| {
        b.iter(|| {
            let _ = black_box(json.generate_diff_report(
                black_box(&result),
                black_box(&old),
                black_box(&new),
                black_box(&config),
            ));
        });
    });
    group.bench_function("sarif", |b| {
        b.iter(|| {
            let _ = black_box(sarif.generate_diff_report(
                black_box(&result),
                black_box(&old),
                black_box(&new),
                black_box(&config),
            ));
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_matcher_cascade,
    bench_diff_boundary,
    bench_dependency_metrics,
    bench_quality_score,
    bench_report_generation,
);
criterion_main!(benches);
