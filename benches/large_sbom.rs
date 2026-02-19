//! Performance benchmarks for large SBOM operations.
//!
//! Run with: cargo bench --bench large_sbom
//!
//! These benchmarks test the performance improvements from:
//! 1. Incremental diffing with caching
//! 2. BatchCandidateGenerator with LSH for large SBOMs

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sbom_tools::diff::{DiffEngine, IncrementalDiffEngine, LargeSbomConfig};
use sbom_tools::model::{Component, DocumentMetadata, Ecosystem, NormalizedSbom};
use std::hint::black_box;

/// Generate a test SBOM with the specified number of components.
fn generate_sbom(prefix: &str, count: usize, ecosystem: Ecosystem) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

    for i in 0..count {
        let name = format!("{}-component-{}", prefix, i);
        let mut comp = Component::new(name.clone(), format!("{}-{}", prefix, name));
        comp.version = Some(format!("1.{}.{}", i % 10, i % 100));
        comp.ecosystem = Some(ecosystem.clone());
        comp.identifiers.purl = Some(format!(
            "pkg:npm/{}/{}@{}",
            prefix,
            name.replace("-", ""),
            comp.version.as_ref().unwrap()
        ));
        sbom.add_component(comp);
    }

    sbom
}

/// Generate two related SBOMs with some components changed.
fn generate_sbom_pair(size: usize, change_percent: f64) -> (NormalizedSbom, NormalizedSbom) {
    let old = generate_sbom("old", size, Ecosystem::Npm);

    let mut new = NormalizedSbom::new(DocumentMetadata::default());
    let changes = (size as f64 * change_percent / 100.0) as usize;

    // Copy most components unchanged
    for (i, (_, comp)) in old.components.iter().enumerate() {
        if i < size - changes {
            // Keep unchanged
            new.add_component(comp.clone());
        }
    }

    // Add some new components
    for i in 0..changes {
        let name = format!("new-component-{}", i);
        let mut comp = Component::new(name.clone(), format!("new-{}", name));
        comp.version = Some(format!("2.0.{}", i));
        comp.ecosystem = Some(Ecosystem::Npm);
        new.add_component(comp);
    }

    (old, new)
}

fn bench_diff_small(c: &mut Criterion) {
    let (old, new) = generate_sbom_pair(100, 10.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_100_components", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

fn bench_diff_medium(c: &mut Criterion) {
    let (old, new) = generate_sbom_pair(500, 10.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_500_components", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

fn bench_diff_large(c: &mut Criterion) {
    let (old, new) = generate_sbom_pair(1000, 10.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_1000_components", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

fn bench_diff_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_scaling");

    for size in [100, 250, 500, 750, 1000].iter() {
        let (old, new) = generate_sbom_pair(*size, 10.0);
        let engine = DiffEngine::new();

        group.bench_with_input(BenchmarkId::new("standard", size), size, |b, _| {
            b.iter(|| {
                let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
            })
        });
    }

    group.finish();
}

fn bench_lsh_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("lsh_threshold");

    let (old, new) = generate_sbom_pair(600, 10.0);

    // Without LSH (high threshold)
    let engine_no_lsh = DiffEngine::new().with_large_sbom_config(LargeSbomConfig {
        lsh_threshold: 10000, // Effectively disable LSH
        max_candidates: 100,
        ..LargeSbomConfig::default()
    });

    group.bench_function("without_lsh", |b| {
        b.iter(|| {
            let _ = black_box(engine_no_lsh.diff(black_box(&old), black_box(&new)));
        })
    });

    // With LSH
    let engine_with_lsh = DiffEngine::new().with_large_sbom_config(LargeSbomConfig::default());

    group.bench_function("with_lsh", |b| {
        b.iter(|| {
            let _ = black_box(engine_with_lsh.diff(black_box(&old), black_box(&new)));
        })
    });

    group.finish();
}

fn bench_incremental_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_cache");

    let (old, new) = generate_sbom_pair(500, 10.0);
    let engine = DiffEngine::new();
    let incremental = IncrementalDiffEngine::new(engine);

    // First diff (cold)
    group.bench_function("cold_diff", |b| {
        b.iter(|| {
            incremental.clear_cache();
            let result = incremental.diff(black_box(&old), black_box(&new));
            black_box(result);
        })
    });

    // Pre-warm the cache
    let _ = incremental.diff(&old, &new);

    // Cached diff (hot)
    group.bench_function("cached_diff", |b| {
        b.iter(|| {
            let result = incremental.diff(black_box(&old), black_box(&new));
            black_box(result);
        })
    });

    group.finish();
}

fn bench_repeated_diffs(c: &mut Criterion) {
    let mut group = c.benchmark_group("repeated_diffs");

    let (old, new) = generate_sbom_pair(500, 10.0);

    // Standard engine - repeated diffs
    let standard_engine = DiffEngine::new();
    group.bench_function("standard_5x", |b| {
        b.iter(|| {
            for _ in 0..5 {
                let _ = black_box(standard_engine.diff(black_box(&old), black_box(&new)));
            }
        })
    });

    // Incremental engine - repeated diffs
    let incremental_engine = IncrementalDiffEngine::new(DiffEngine::new());
    group.bench_function("incremental_5x", |b| {
        b.iter(|| {
            incremental_engine.clear_cache();
            for _ in 0..5 {
                let _ = black_box(incremental_engine.diff(black_box(&old), black_box(&new)));
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_diff_small,
    bench_diff_medium,
    bench_diff_large,
    bench_diff_scaling,
    bench_lsh_threshold,
    bench_incremental_cache,
    bench_repeated_diffs,
);

criterion_main!(benches);
