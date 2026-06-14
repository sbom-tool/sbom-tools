//! Benchmarks for the diff engine (small/medium) and cost model.
//!
//! Graph-shaped, deterministic fixtures come from the shared `benches/support`
//! module (which replaces the two duplicated `generate_sbom` helpers that used
//! to live here and in `large_sbom.rs`).

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use sbom_tools::diff::{CostModel, DiffEngine, LargeSbomConfig};
use std::hint::black_box;
use support::{Topology, generate_disjoint_pair, generate_graph_pair};

fn benchmark_diff_small(c: &mut Criterion) {
    let (old, new) = generate_graph_pair(50, 10.0, Topology::Mixed);
    let engine = DiffEngine::new();

    c.bench_function("diff_50_components_10pct", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

fn benchmark_diff_medium(c: &mut Criterion) {
    let (old, new) = generate_graph_pair(200, 20.0, Topology::Mixed);
    let engine = DiffEngine::new();

    c.bench_function("diff_200_components_20pct", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

/// Worst-case fuzzy assignment: two large SBOMs with disjoint canonical IDs, so
/// every component enters fuzzy assignment over the full candidate edge list.
///
/// `lsh_threshold` is raised so the `ComponentIndex` path runs (this is the path
/// that previously built a dense n×n cost matrix and ran `kuhn_munkres` on it —
/// ~200MB and ~10^11 ops near the 5000 threshold, an effective hang). The
/// sparse solver instead works over only the candidate edges. Two sizes lock in
/// the scaling: the dense path's cost grew ~n³, the sparse path with the edge
/// count.
fn benchmark_diff_disjoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_disjoint_ids");
    // Each iteration is heavy (full fuzzy assignment); keep samples small so the
    // bench stays practical to run.
    group.sample_size(10);

    // Force the dense-matrix-trigger path (ComponentIndex assignment).
    let config = LargeSbomConfig {
        lsh_threshold: 1_000_000,
        ..LargeSbomConfig::default()
    };

    for size in [2_000usize, 4_000] {
        let (old, new) = generate_disjoint_pair(size);
        let engine = DiffEngine::new().with_large_sbom_config(config.clone());
        group.bench_function(format!("{size}_components_disjoint"), |b| {
            b.iter(|| {
                let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
            })
        });
    }

    group.finish();
}

fn benchmark_cost_model(c: &mut Criterion) {
    let model = CostModel::default();

    c.bench_function("cost_model_semantic_score", |b| {
        b.iter(|| {
            let score = model.calculate_semantic_score(
                black_box(10),
                black_box(5),
                black_box(15),
                black_box(3),
                black_box(2),
                black_box(1),
                black_box(20),
                black_box(8),
            );
            black_box(score);
        })
    });
}

criterion_group!(
    benches,
    benchmark_diff_small,
    benchmark_diff_medium,
    benchmark_diff_disjoint,
    benchmark_cost_model,
);
criterion_main!(benches);
