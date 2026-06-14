//! Benchmarks for the diff engine (small/medium) and cost model.

use criterion::{Criterion, criterion_group, criterion_main};
use sbom_tools::diff::{CostModel, DiffEngine, LargeSbomConfig};
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

/// Generate two SBOMs with the same packages but DISJOINT canonical IDs.
///
/// Each component's canonical ID comes only from its (unstable) format id, so
/// using different format ids between the two documents shares zero canonical
/// IDs — every component is forced through the full fuzzy assignment path. This
/// is the cross-format / regenerated-bom-ref worst case the sparse solver
/// targets. Names are distinct but version-bumped, so each old component has
/// exactly one strong fuzzy match in the new SBOM. Generation is deterministic.
fn generate_disjoint_pair(size: usize) -> (NormalizedSbom, NormalizedSbom) {
    let mut old = NormalizedSbom::new(DocumentMetadata::default());
    let mut new = NormalizedSbom::new(DocumentMetadata::default());

    for i in 0..size {
        // Distinct, fuzzy-matchable name (numeric token framed by letters).
        let name = format!("comp{i:06}lib");
        let eco = if i % 2 == 0 {
            Ecosystem::Npm
        } else {
            Ecosystem::PyPi
        };

        let mut old_comp = Component::new(name.clone(), format!("old-ref-{i}"));
        old_comp.version = Some("1.0.0".to_string());
        old_comp.ecosystem = Some(eco.clone());
        old.add_component(old_comp);

        // Same name + ecosystem, bumped version, fresh ref → disjoint ID.
        let mut new_comp = Component::new(name, format!("new-ref-{i}"));
        new_comp.version = Some("2.0.0".to_string());
        new_comp.ecosystem = Some(eco);
        new.add_component(new_comp);
    }

    (old, new)
}

fn benchmark_diff_small(c: &mut Criterion) {
    let (old, new) = generate_pair(50, 10.0);
    let engine = DiffEngine::new();

    c.bench_function("diff_50_components_10pct", |b| {
        b.iter(|| {
            let _ = black_box(engine.diff(black_box(&old), black_box(&new)));
        })
    });
}

fn benchmark_diff_medium(c: &mut Criterion) {
    let (old, new) = generate_pair(200, 20.0);
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
