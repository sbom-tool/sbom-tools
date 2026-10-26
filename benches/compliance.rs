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
//! * `sarif_locator_50k` — the `-o sarif` locator pass (SBOM ids to source
//!   lines) on a 50,000-component CycloneDX JSON document, minified and
//!   pretty-printed, against parsing the same text.
//!
//! Fixtures come from the shared, deterministic `benches/support` generators.

mod support;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sbom_tools::model::{Component, DependencyEdge, DependencyType, NormalizedSbom};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};
use sbom_tools::reports::{
    SarifArtifact, SarifArtifactLocation, SarifOptions, SbomLocator, generate_compliance_sarif_with,
};
use std::hint::black_box;
use support::{Topology, cyclonedx_json, generate_flat_sbom, generate_graph_sbom};

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

/// The SARIF locator on a 50,000-component CycloneDX document, minified (one
/// line) and pretty-printed: the scan alone, and the scan joined with the
/// parsed components (`SarifArtifact::new`, what `-o sarif` runs once per
/// SBOM). Parsing the same text is the reference: the locator is one linear
/// pass and should stay well below it. The last two rows render NTIA SARIF
/// for the same document with and without locations.
fn bench_sarif_locator(c: &mut Criterion) {
    let minified = cyclonedx_json(50_000);
    let value: serde_json::Value = serde_json::from_str(&minified).expect("generated JSON");
    let pretty = serde_json::to_string_pretty(&value).expect("pretty JSON");
    let sbom = parse_sbom_str(&minified).expect("generated SBOM parses");
    let location = SarifArtifactLocation::relative("sbom.cdx.json");
    let artifact = SarifArtifact::new(location.clone(), &sbom, &pretty);
    assert!(
        sbom.components
            .keys()
            .all(|id| artifact.component_line(id.value()).is_some()),
        "the locator finds every generated component"
    );
    let mut group = c.benchmark_group("sarif_locator_50k");
    group.sample_size(10);
    group.bench_function("parse_minified", |b| {
        b.iter(|| black_box(parse_sbom_str(black_box(&minified))));
    });
    for (label, text) in [("minified", &minified), ("pretty", &pretty)] {
        group.bench_function(format!("scan_{label}"), |b| {
            b.iter(|| black_box(SbomLocator::scan(black_box(text))));
        });
        group.bench_function(format!("artifact_{label}"), |b| {
            b.iter(|| black_box(SarifArtifact::new(location.clone(), &sbom, black_box(text))));
        });
    }
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(&sbom);
    let unlocated = SarifOptions::new();
    let located = SarifOptions::new().with_artifact(artifact);
    group.bench_function("ntia_sarif_without_locations", |b| {
        b.iter(|| black_box(generate_compliance_sarif_with(&result, &unlocated)));
    });
    group.bench_function("ntia_sarif_with_locations", |b| {
        b.iter(|| black_box(generate_compliance_sarif_with(&result, &located)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_all_levels,
    bench_fsct_wide,
    bench_sarif_locator
);
criterion_main!(benches);
