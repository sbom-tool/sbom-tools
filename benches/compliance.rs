//! Compliance-engine benchmarks.
//!
//! Run with: cargo bench --bench compliance
//!
//! * `compliance_10k_mixed` — every compliance level on a 10,000-component
//!   graph, the cost of `validate` across all standards.
//! * `fsct_flat_direct_deps` — FSCT on a wide, flat star graph (one primary
//!   component with N direct dependencies, no deeper edges), N from 10,000 to
//!   80,000. Each direct dependency used to be checked against every edge,
//!   which was quadratic on this shape (3.7 s at 80,000); the set of edge
//!   sources is now computed once, so time grows linearly with N.
//!
//! Fixtures come from the shared, deterministic `benches/support` generators.

mod support;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sbom_tools::model::{Component, DependencyEdge, DependencyType, NormalizedSbom};
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};
use std::hint::black_box;
use support::{Topology, generate_flat_sbom, generate_graph_sbom};

fn bench_all_levels(c: &mut Criterion) {
    let sbom = generate_graph_sbom("cmp", 10_000, Topology::Mixed);
    let mut group = c.benchmark_group("compliance_10k_mixed");
    group.sample_size(10);
    for level in ComplianceLevel::all() {
        let checker = ComplianceChecker::new(*level);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{level:?}")),
            &sbom,
            |b, sbom| b.iter(|| black_box(checker.check(black_box(sbom)))),
        );
    }
    group.finish();
}

/// One primary component depending directly on `direct` flat components.
fn star_sbom(direct: usize) -> NormalizedSbom {
    let mut sbom = generate_flat_sbom("star", direct);
    let leaves: Vec<_> = sbom.components.keys().cloned().collect();
    let primary = Component::new("app".to_string(), "star-primary".to_string());
    let primary_id = primary.canonical_id.clone();
    sbom.add_component(primary);
    sbom.primary_component_id = Some(primary_id.clone());
    for leaf in leaves {
        sbom.add_edge(DependencyEdge::new(
            primary_id.clone(),
            leaf,
            DependencyType::DependsOn,
        ));
    }
    sbom
}

fn bench_fsct_wide(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsct_flat_direct_deps");
    group.sample_size(10);
    for direct in [10_000usize, 20_000, 40_000, 80_000] {
        let sbom = star_sbom(direct);
        let checker = ComplianceChecker::new(ComplianceLevel::Fsct);
        group.bench_with_input(BenchmarkId::from_parameter(direct), &sbom, |b, sbom| {
            b.iter(|| black_box(checker.check(black_box(sbom))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_all_levels, bench_fsct_wide);
criterion_main!(benches);
