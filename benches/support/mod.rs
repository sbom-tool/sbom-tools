//! Shared, deterministic SBOM fixture generators for the criterion benches.
//!
//! This module is compiled independently into each bench binary (`mod support;`),
//! so every public item is reachable from at least one bench but may look unused
//! from another — hence the crate-level `dead_code` allow below.
//!
//! # Why graph-shaped fixtures
//!
//! The original benches synthesised FLAT, edge-less SBOMs, so nothing exercised
//! the graph-analysis hot paths (Tarjan SCC / cycle detection / BFS depth in
//! `quality::DependencyMetrics`) or the graph-aware diff. The generators here
//! attach real dependency edges in four named topologies:
//!
//! * **chain**    — a deep linear chain (`c0 → c1 → … → cN`), stresses BFS depth.
//! * **diamond**  — overlapping diamond lattices, stresses re-convergence/island
//!   union-find and high in-degree.
//! * **cyclic**   — many small back-edge cycles, stresses SCC detection.
//! * **mixed**    — a realistic blend of all three across multiple ecosystems.
//!
//! # Determinism
//!
//! There is no RNG. Every field is a pure function of the node index, so two runs
//! (and the old/new sides of a diff) are byte-for-byte comparable. This keeps
//! criterion samples and any saved baselines meaningful across commits.

#![allow(dead_code)]

use sbom_tools::model::{
    CanonicalId, Component, DependencyEdge, DependencyType, DocumentMetadata, Ecosystem,
    NormalizedSbom,
};

/// Dependency-graph topology to synthesise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// No edges (the legacy flat shape) — useful as a baseline.
    Flat,
    /// A single deep linear chain `c0 → c1 → … → c(n-1)`.
    Chain,
    /// Overlapping diamonds: each node points at the next two, which reconverge.
    Diamond,
    /// Many short back-edge cycles (every `CYCLE_LEN`-th node closes a loop).
    Cyclic,
    /// A realistic blend: chains, diamonds, and cycles interleaved.
    Mixed,
}

/// Span of the largest cycle introduced by [`Topology::Cyclic`] / [`Topology::Mixed`].
const CYCLE_LEN: usize = 7;

/// Rotate through a spread of ecosystems so multi-ecosystem code paths (PURL
/// type parsing, per-ecosystem matching rules) are exercised. Order is fixed.
const ECOSYSTEMS: [Ecosystem; 6] = [
    Ecosystem::Npm,
    Ecosystem::PyPi,
    Ecosystem::Cargo,
    Ecosystem::Maven,
    Ecosystem::Golang,
    Ecosystem::Nuget,
];

/// purl `pkg:` type token matching each [`ECOSYSTEMS`] entry (same index).
const PURL_TYPES: [&str; 6] = ["npm", "pypi", "cargo", "maven", "golang", "nuget"];

/// Build one deterministic component for node `i`, tagged with `prefix`.
///
/// The format id embeds `prefix` so two SBOMs built with different prefixes have
/// disjoint canonical ids (the cross-format worst case), while the name/purl stay
/// stable enough to fuzzy-match. A populated purl + version + ecosystem also give
/// the quality scorer real fields to grade.
fn make_component(prefix: &str, i: usize) -> Component {
    let eco_idx = i % ECOSYSTEMS.len();
    let purl_type = PURL_TYPES[eco_idx];
    let name = format!("comp{i:06}lib");
    let version = format!("1.{}.{}", i % 10, i % 100);

    let mut comp = Component::new(name.clone(), format!("{prefix}-ref-{i}"));
    comp.version = Some(version.clone());
    comp.ecosystem = Some(ECOSYSTEMS[eco_idx].clone());
    comp.identifiers.purl = Some(format!("pkg:{purl_type}/{name}@{version}"));
    comp
}

/// Attach edges for the requested topology over `ids` (in node order).
///
/// `ids` are the canonical ids of the already-added components. Edges are added
/// in index order so the edge list is identical across runs.
fn add_topology_edges(sbom: &mut NormalizedSbom, ids: &[CanonicalId], topology: Topology) {
    let n = ids.len();
    let edge = |from: &CanonicalId, to: &CanonicalId| {
        DependencyEdge::new(from.clone(), to.clone(), DependencyType::DependsOn)
    };

    match topology {
        Topology::Flat => {}
        Topology::Chain => {
            for i in 0..n.saturating_sub(1) {
                sbom.add_edge(edge(&ids[i], &ids[i + 1]));
            }
        }
        Topology::Diamond => {
            // Each node fans out to the next two; they reconverge one step later,
            // producing a lattice of overlapping diamonds (high in/out degree).
            for i in 0..n {
                if i + 1 < n {
                    sbom.add_edge(edge(&ids[i], &ids[i + 1]));
                }
                if i + 2 < n {
                    sbom.add_edge(edge(&ids[i], &ids[i + 2]));
                }
            }
        }
        Topology::Cyclic => {
            // Forward chain plus a back-edge closing every CYCLE_LEN-node window,
            // yielding many small SCCs for Tarjan to find.
            for i in 0..n.saturating_sub(1) {
                sbom.add_edge(edge(&ids[i], &ids[i + 1]));
            }
            let mut i = CYCLE_LEN - 1;
            while i < n {
                sbom.add_edge(edge(&ids[i], &ids[i - (CYCLE_LEN - 1)]));
                i += CYCLE_LEN;
            }
        }
        Topology::Mixed => {
            // Interleave the three shapes by node position so the graph has a
            // realistic blend of depth, reconvergence, and cycles.
            for i in 0..n {
                match i % 3 {
                    0 if i + 1 < n => sbom.add_edge(edge(&ids[i], &ids[i + 1])),
                    1 if i + 2 < n => sbom.add_edge(edge(&ids[i], &ids[i + 2])),
                    _ => {}
                }
            }
            let mut i = CYCLE_LEN - 1;
            while i < n {
                sbom.add_edge(edge(&ids[i], &ids[i - (CYCLE_LEN - 1)]));
                i += CYCLE_LEN;
            }
        }
    }
}

/// Generate a deterministic graph-shaped SBOM with `count` nodes and the given
/// topology, tagged with `prefix` (controls canonical-id namespacing).
#[must_use]
pub fn generate_graph_sbom(prefix: &str, count: usize, topology: Topology) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let comp = make_component(prefix, i);
        ids.push(comp.canonical_id.clone());
        sbom.add_component(comp);
    }
    add_topology_edges(&mut sbom, &ids, topology);
    sbom
}

/// Convenience: a flat, edge-less SBOM (the legacy shape both old benches built).
///
/// Replaces the two duplicated `generate_sbom` helpers that previously lived in
/// `diff_benchmark.rs` and `large_sbom.rs`.
#[must_use]
pub fn generate_flat_sbom(prefix: &str, count: usize) -> NormalizedSbom {
    generate_graph_sbom(prefix, count, Topology::Flat)
}

/// Generate two related SBOMs that share canonical ids, with `change_pct` of the
/// `new` side replaced by fresh components. Both sides carry the same topology so
/// the graph diff has structure to compare. Deterministic.
#[must_use]
pub fn generate_graph_pair(
    size: usize,
    change_pct: f64,
    topology: Topology,
) -> (NormalizedSbom, NormalizedSbom) {
    let old = generate_graph_sbom("old", size, topology);

    let mut new = NormalizedSbom::new(DocumentMetadata::default());
    let changes = ((size as f64) * change_pct / 100.0) as usize;
    let kept = size - changes;

    let mut ids = Vec::with_capacity(size);
    // Carry over the unchanged prefix of `old` (same canonical ids → matched).
    for (i, comp) in old.components.values().enumerate() {
        if i < kept {
            ids.push(comp.canonical_id.clone());
            new.add_component(comp.clone());
        }
    }
    // Append fresh components for the changed tail (distinct ids → added/removed).
    for i in 0..changes {
        let comp = make_component("new", size + i);
        ids.push(comp.canonical_id.clone());
        new.add_component(comp);
    }
    add_topology_edges(&mut new, &ids, topology);

    (old, new)
}

/// Generate two SBOMs with the same package names but DISJOINT canonical ids, so
/// every component is forced through the full fuzzy-assignment path (the
/// cross-format / regenerated-bom-ref worst case). Names + ecosystems line up so
/// each old component has exactly one strong fuzzy match. Deterministic.
#[must_use]
pub fn generate_disjoint_pair(size: usize) -> (NormalizedSbom, NormalizedSbom) {
    let mut old = NormalizedSbom::new(DocumentMetadata::default());
    let mut new = NormalizedSbom::new(DocumentMetadata::default());

    for i in 0..size {
        let name = format!("comp{i:06}lib");
        let eco = ECOSYSTEMS[i % ECOSYSTEMS.len()].clone();

        let mut old_comp = Component::new(name.clone(), format!("old-ref-{i}"));
        old_comp.version = Some("1.0.0".to_string());
        old_comp.ecosystem = Some(eco.clone());
        old.add_component(old_comp);

        let mut new_comp = Component::new(name, format!("new-ref-{i}"));
        new_comp.version = Some("2.0.0".to_string());
        new_comp.ecosystem = Some(eco);
        new.add_component(new_comp);
    }

    (old, new)
}

/// Serialise a deterministic graph-shaped SBOM to a CycloneDX 1.5 JSON string
/// with `count` components and a `dependencies` block (a linear chain), for the
/// `parse_sbom_str` benchmark. Hand-built (there is no CycloneDX writer in the
/// crate) but byte-stable for a given `count`.
#[must_use]
pub fn cyclonedx_json(count: usize) -> String {
    let mut out = String::with_capacity(count * 220);
    out.push_str(
        r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"application","name":"bench-root","version":"1.0.0","bom-ref":"bench-root@1.0.0"}},"components":["#,
    );
    for i in 0..count {
        let eco_idx = i % PURL_TYPES.len();
        let purl_type = PURL_TYPES[eco_idx];
        let name = format!("comp{i:06}lib");
        let version = format!("1.{}.{}", i % 10, i % 100);
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            r#"{{"type":"library","bom-ref":"{name}@{version}","name":"{name}","version":"{version}","purl":"pkg:{purl_type}/{name}@{version}","licenses":[{{"license":{{"id":"MIT"}}}}]}}"#,
        ));
    }
    out.push_str(r#"],"dependencies":["#);
    // Root depends on the first component; then a linear chain across the rest.
    out.push_str(r#"{"ref":"bench-root@1.0.0","dependsOn":["comp000000lib@1.0.0"]}"#);
    for i in 0..count.saturating_sub(1) {
        let from = format!("comp{i:06}lib@1.{}.{}", i % 10, i % 100);
        let j = i + 1;
        let to = format!("comp{j:06}lib@1.{}.{}", j % 10, j % 100);
        out.push_str(&format!(r#",{{"ref":"{from}","dependsOn":["{to}"]}}"#));
    }
    out.push_str("]}");
    out
}
