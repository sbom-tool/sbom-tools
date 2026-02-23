//! Integration tests for graph-aware diffing.

use sbom_tools::diff::{
    DependencyChangeType, DiffEngine, DiffResult, GraphChangeImpact, GraphDiffConfig,
    diff_dependency_graph,
};
use sbom_tools::model::{
    CanonicalId, Component, DependencyEdge, DependencyScope, DependencyType, DocumentMetadata,
    NormalizedSbom,
};
use std::collections::HashMap;

/// Helper to create a test component
fn make_component(name: &str) -> Component {
    Component::new(name.to_string(), name.to_string())
}

/// Helper to build a simple SBOM with components and edges
fn make_sbom(
    components: Vec<Component>,
    edges: Vec<(CanonicalId, CanonicalId, DependencyType)>,
) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    for comp in components {
        sbom.add_component(comp);
    }
    for (from, to, rel) in edges {
        sbom.add_edge(DependencyEdge::new(from, to, rel));
    }
    sbom.calculate_content_hash();
    sbom
}

/// Build a test SBOM with a fixed (shared) document metadata for hash comparisons
fn make_sbom_with_meta(
    meta: DocumentMetadata,
    components: Vec<Component>,
    edges: Vec<(CanonicalId, CanonicalId, DependencyType)>,
) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(meta);
    for comp in components {
        sbom.add_component(comp);
    }
    for (from, to, rel) in edges {
        sbom.add_edge(DependencyEdge::new(from, to, rel));
    }
    sbom.calculate_content_hash();
    sbom
}

#[test]
fn test_graph_diff_detects_added_dependency() {
    let root = make_component("root");
    let lib = make_component("lib");
    let root_id = root.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();

    let old = make_sbom(vec![root.clone()], vec![]);
    let new = make_sbom(
        vec![root.clone(), lib],
        vec![(root_id.clone(), lib_id, DependencyType::DependsOn)],
    );

    let mut matches = HashMap::new();
    matches.insert(root_id.clone(), Some(root_id));

    let config = GraphDiffConfig::default();
    let (changes, summary) = diff_dependency_graph(&old, &new, &matches, &config);

    assert!(
        summary.dependencies_added > 0,
        "Should detect added dep: {changes:?}"
    );
}

#[test]
fn test_graph_diff_detects_removed_dependency() {
    let root = make_component("root");
    let lib = make_component("lib");
    let root_id = root.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();

    let old = make_sbom(
        vec![root.clone(), lib.clone()],
        vec![(root_id.clone(), lib_id.clone(), DependencyType::DependsOn)],
    );
    let new = make_sbom(vec![root.clone(), lib], vec![]);

    let mut matches = HashMap::new();
    matches.insert(root_id.clone(), Some(root_id));
    matches.insert(lib_id.clone(), Some(lib_id));

    let config = GraphDiffConfig::default();
    let (changes, summary) = diff_dependency_graph(&old, &new, &matches, &config);

    assert!(
        summary.dependencies_removed > 0,
        "Should detect removed dep: {changes:?}"
    );
}

#[test]
fn test_graph_diff_detects_reparenting() {
    // Child moves from parent1 to parent2, where parent1 and parent2 are both
    // present in old and new but child's parent changes
    let p1 = make_component("parent1");
    let p2 = make_component("parent2");
    let child = make_component("child");

    let p1_id = p1.canonical_id.clone();
    let p2_id = p2.canonical_id.clone();
    let child_id = child.canonical_id.clone();

    let old = make_sbom(
        vec![p1.clone(), p2.clone(), child.clone()],
        vec![(p1_id.clone(), child_id.clone(), DependencyType::DependsOn)],
    );
    let new = make_sbom(
        vec![p1.clone(), p2.clone(), child.clone()],
        vec![(p2_id.clone(), child_id.clone(), DependencyType::DependsOn)],
    );

    // Both parents map to themselves — they're different logical components
    let mut matches = HashMap::new();
    matches.insert(p1_id.clone(), Some(p1_id));
    matches.insert(p2_id.clone(), Some(p2_id));
    matches.insert(child_id.clone(), Some(child_id));

    let config = GraphDiffConfig::default();
    let (changes, summary) = diff_dependency_graph(&old, &new, &matches, &config);

    assert!(
        summary.reparented > 0,
        "Should detect reparenting: {changes:?}"
    );
}

#[test]
fn test_graph_diff_detects_depth_change() {
    // Old: root -> A -> B (B is at depth 3)
    // New: root -> B (B promoted to depth 2)
    let root = make_component("root");
    let a = make_component("a");
    let b = make_component("b");

    let root_id = root.canonical_id.clone();
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();

    let old = make_sbom(
        vec![root.clone(), a.clone(), b.clone()],
        vec![
            (root_id.clone(), a_id.clone(), DependencyType::DependsOn),
            (a_id.clone(), b_id.clone(), DependencyType::DependsOn),
        ],
    );
    let new = make_sbom(
        vec![root.clone(), a.clone(), b.clone()],
        vec![
            (root_id.clone(), a_id.clone(), DependencyType::DependsOn),
            (root_id.clone(), b_id.clone(), DependencyType::DependsOn),
        ],
    );

    let mut matches = HashMap::new();
    matches.insert(root_id.clone(), Some(root_id));
    matches.insert(a_id.clone(), Some(a_id));
    matches.insert(b_id.clone(), Some(b_id));

    let config = GraphDiffConfig::default();
    let (changes, summary) = diff_dependency_graph(&old, &new, &matches, &config);

    assert!(
        summary.depth_changed > 0,
        "Should detect depth change: {changes:?}"
    );
}

#[test]
fn test_edge_with_different_relationship_types_detected() {
    // Two edges between same components but different relationship types
    let a = make_component("a");
    let b = make_component("b");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();

    let old = make_sbom(
        vec![a.clone(), b.clone()],
        vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
    );
    let new = make_sbom(
        vec![a.clone(), b.clone()],
        vec![(a_id.clone(), b_id.clone(), DependencyType::DevDependsOn)],
    );

    let engine = DiffEngine::new().with_graph_diff(GraphDiffConfig::default());
    let result = engine.diff(&old, &new).expect("diff should succeed");

    // The dependency change computer should detect the relationship type change
    assert!(
        !result.dependencies.added.is_empty() || !result.dependencies.removed.is_empty(),
        "Should detect relationship type change as add+remove: added={}, removed={}",
        result.dependencies.added.len(),
        result.dependencies.removed.len()
    );
}

#[test]
fn test_content_hash_deterministic_edge_order() {
    let a = make_component("a");
    let b = make_component("b");
    let c = make_component("c");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();
    let c_id = c.canonical_id.clone();

    // Use shared metadata so timestamps don't differ
    let meta = DocumentMetadata::default();

    // SBOM 1: edges in order A->B, A->C
    let sbom1 = make_sbom_with_meta(
        meta.clone(),
        vec![a.clone(), b.clone(), c.clone()],
        vec![
            (a_id.clone(), b_id.clone(), DependencyType::DependsOn),
            (a_id.clone(), c_id.clone(), DependencyType::DependsOn),
        ],
    );

    // SBOM 2: edges in reversed order A->C, A->B
    let sbom2 = make_sbom_with_meta(
        meta,
        vec![a, b, c],
        vec![
            (a_id.clone(), c_id, DependencyType::DependsOn),
            (a_id, b_id, DependencyType::DependsOn),
        ],
    );

    assert_eq!(
        sbom1.content_hash, sbom2.content_hash,
        "Same edges in different order should produce same hash"
    );
}

#[test]
fn test_content_hash_includes_relationship() {
    let a = make_component("a");
    let b = make_component("b");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();

    let meta = DocumentMetadata::default();

    let sbom1 = make_sbom_with_meta(
        meta.clone(),
        vec![a.clone(), b.clone()],
        vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
    );

    let sbom2 = make_sbom_with_meta(
        meta,
        vec![a, b],
        vec![(a_id, b_id, DependencyType::DevDependsOn)],
    );

    assert_ne!(
        sbom1.content_hash, sbom2.content_hash,
        "Different relationship types should produce different hash"
    );
}

#[test]
fn test_total_changes_includes_graph_changes() {
    let root = make_component("root");
    let lib = make_component("lib");
    let root_id = root.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();

    // Old: just root. New: root -> lib (added dependency)
    let old = make_sbom(vec![root.clone()], vec![]);
    let new = make_sbom(
        vec![root.clone(), lib],
        vec![(root_id.clone(), lib_id, DependencyType::DependsOn)],
    );

    let engine = DiffEngine::new().with_graph_diff(GraphDiffConfig::default());
    let result = engine.diff(&old, &new).expect("diff should succeed");

    assert!(
        result.summary.total_changes > 0,
        "total_changes should include graph and dependency changes: {}",
        result.summary.total_changes
    );
}

#[test]
fn test_fail_on_change_triggered_by_graph_changes() {
    // Verify that has_changes() returns true when only graph changes exist
    let mut result = DiffResult::new();
    result
        .graph_changes
        .push(sbom_tools::diff::DependencyGraphChange {
            component_id: CanonicalId::from_name_version("test", Some("1.0")),
            component_name: "test".to_string(),
            change: DependencyChangeType::DependencyAdded {
                dependency_id: CanonicalId::from_name_version("dep", Some("1.0")),
                dependency_name: "dep".to_string(),
            },
            impact: GraphChangeImpact::Low,
        });
    result.calculate_summary();

    assert!(
        result.has_changes(),
        "has_changes() should be true with graph-only changes"
    );
    assert!(
        result.summary.total_changes > 0,
        "total_changes should be > 0 with graph changes"
    );
}

#[test]
fn test_content_hash_includes_scope() {
    let a = make_component("a");
    let b = make_component("b");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();

    let meta = DocumentMetadata::default();

    // SBOM 1: A -> B with Required scope
    let mut sbom1 = NormalizedSbom::new(meta.clone());
    sbom1.add_component(a.clone());
    sbom1.add_component(b.clone());
    sbom1.add_edge(
        DependencyEdge::new(a_id.clone(), b_id.clone(), DependencyType::DependsOn)
            .with_scope(DependencyScope::Required),
    );
    sbom1.calculate_content_hash();

    // SBOM 2: A -> B with Optional scope (same relationship, different scope)
    let mut sbom2 = NormalizedSbom::new(meta);
    sbom2.add_component(a);
    sbom2.add_component(b);
    sbom2.add_edge(
        DependencyEdge::new(a_id, b_id, DependencyType::DependsOn)
            .with_scope(DependencyScope::Optional),
    );
    sbom2.calculate_content_hash();

    assert_ne!(
        sbom1.content_hash, sbom2.content_hash,
        "Different scopes should produce different content hash"
    );
}

#[test]
fn test_graph_diff_detects_relationship_change() {
    // Old: A -[DependsOn]-> B. New: A -[DevDependsOn]-> B.
    // Graph diff should detect RelationshipChanged.
    let a = make_component("a");
    let b = make_component("b");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();

    let old = make_sbom(
        vec![a.clone(), b.clone()],
        vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
    );
    let new = make_sbom(
        vec![a, b],
        vec![(a_id.clone(), b_id.clone(), DependencyType::DevDependsOn)],
    );

    let mut matches = HashMap::new();
    matches.insert(a_id.clone(), Some(a_id));
    matches.insert(b_id.clone(), Some(b_id));

    let config = GraphDiffConfig::default();
    let (changes, summary) = diff_dependency_graph(&old, &new, &matches, &config);

    assert!(
        summary.relationship_changed > 0,
        "Graph diff should detect relationship change: {changes:?}"
    );

    // Verify it's a RelationshipChanged, not add+remove
    let has_rel_change = changes
        .iter()
        .any(|c| matches!(c.change, DependencyChangeType::RelationshipChanged { .. }));
    assert!(
        has_rel_change,
        "Should have RelationshipChanged variant: {changes:?}"
    );
}
