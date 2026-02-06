//! Benchmarks for the diff engine (small/medium) and cost model.

use criterion::{criterion_group, criterion_main, Criterion};
use sbom_tools::diff::{CostModel, DiffEngine};
use sbom_tools::model::{Component, DocumentMetadata, Ecosystem, NormalizedSbom};
use std::hint::black_box;

/// Generate a test SBOM with specified component count.
fn generate_sbom(prefix: &str, count: usize) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    for i in 0..count {
        let name = format!("{prefix}-component-{i}");
        let mut comp = Component::new(name.clone(), format!("{prefix}-{name}"));
        comp.version = Some(format!("1.{}.{}", i % 10, i % 100));
        comp.ecosystem = Some(Ecosystem::Npm);
        comp.identifiers.purl = Some(format!(
            "pkg:npm/{prefix}/{}@{}",
            name.replace('-', ""),
            comp.version.as_ref().unwrap()
        ));
        sbom.add_component(comp);
    }
    sbom
}

/// Generate two related SBOMs with a percentage of components changed.
fn generate_pair(size: usize, change_pct: f64) -> (NormalizedSbom, NormalizedSbom) {
    let old = generate_sbom("old", size);
    let mut new_sbom = NormalizedSbom::new(DocumentMetadata::default());
    let changes = (size as f64 * change_pct / 100.0) as usize;

    for (i, (_, comp)) in old.components.iter().enumerate() {
        if i < size - changes {
            new_sbom.add_component(comp.clone());
        }
    }
    for i in 0..changes {
        let name = format!("new-component-{i}");
        let mut comp = Component::new(name.clone(), format!("new-{name}"));
        comp.version = Some(format!("2.0.{i}"));
        comp.ecosystem = Some(Ecosystem::Npm);
        new_sbom.add_component(comp);
    }

    (old, new_sbom)
}

fn benchmark_diff_small(c: &mut Criterion) {
    let (old, new) = generate_pair(50, 10.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_50_components_10pct", |b| {
        b.iter(|| {
            let result = engine.diff(black_box(&old), black_box(&new));
            black_box(result);
        })
    });
}

fn benchmark_diff_medium(c: &mut Criterion) {
    let (old, new) = generate_pair(200, 20.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_200_components_20pct", |b| {
        b.iter(|| {
            let result = engine.diff(black_box(&old), black_box(&new));
            black_box(result);
        })
    });
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
    benchmark_cost_model,
);
criterion_main!(benches);
