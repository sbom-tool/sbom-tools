//! Graph-aware dependency diffing module.
//!
//! This module provides functionality to detect structural changes in the
//! dependency graph between two SBOMs, going beyond simple component-level
//! comparisons to identify:
//! - Dependencies being added or removed
//! - Dependencies being reparented (moved from one parent to another)
//! - Depth changes (transitive becoming direct or vice versa)

use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{CanonicalId, DependencyScope, DependencyType, NormalizedSbom};

use super::result::{
    DependencyChangeType, DependencyGraphChange, GraphChangeImpact, GraphChangeSummary,
};

/// Sentinel depth for nodes unreachable from any root via BFS (e.g., pure cycles).
/// Distinct from real depths (1=root, 2=direct, 3+=transitive) so impact assessment
/// can handle them separately.
const CYCLIC_SENTINEL_DEPTH: u32 = u32::MAX;

/// Configuration for graph-aware diffing
#[derive(Debug, Clone)]
pub struct GraphDiffConfig {
    /// Whether to detect reparenting (computationally more expensive)
    pub detect_reparenting: bool,
    /// Whether to track depth changes
    pub detect_depth_changes: bool,
    /// Maximum depth to analyze (0 = unlimited)
    pub max_depth: u32,
    /// Relationship type filter — only include edges matching these types (empty = all)
    pub relation_filter: Vec<String>,
}

impl Default for GraphDiffConfig {
    fn default() -> Self {
        Self {
            detect_reparenting: true,
            detect_depth_changes: true,
            max_depth: 0,
            relation_filter: Vec::new(),
        }
    }
}

/// Edge attributes (relationship type and scope) for a dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeAttrs {
    relationship: DependencyType,
    scope: Option<DependencyScope>,
}

/// Internal representation of dependency graph for diffing
struct DependencyGraph<'a> {
    /// Reference to the SBOM
    sbom: &'a NormalizedSbom,
    /// `parent_id` -> Vec<`child_id`>
    edges: HashMap<CanonicalId, Vec<CanonicalId>>,
    /// `child_id` -> Vec<`parent_id`> (reverse index)
    reverse_edges: HashMap<CanonicalId, Vec<CanonicalId>>,
    /// `(from_id, to_id)` -> edge attributes
    edge_attrs: HashMap<(CanonicalId, CanonicalId), EdgeAttrs>,
    /// `component_id` -> minimum depth from root (1 = direct)
    /// Uses minimum depth when multiple paths exist (diamond dependencies)
    depths: HashMap<CanonicalId, u32>,
    /// `component_id` -> has vulnerabilities
    vulnerable_components: HashSet<CanonicalId>,
}

impl<'a> DependencyGraph<'a> {
    fn from_sbom(sbom: &'a NormalizedSbom, config: &GraphDiffConfig) -> Self {
        let mut edges: HashMap<CanonicalId, Vec<CanonicalId>> = HashMap::new();
        let mut reverse_edges: HashMap<CanonicalId, Vec<CanonicalId>> = HashMap::new();
        let mut edge_attrs: HashMap<(CanonicalId, CanonicalId), EdgeAttrs> = HashMap::new();
        let mut vulnerable_components = HashSet::new();

        // Build edge maps from SBOM edges, applying relation filter if set
        for edge in &sbom.edges {
            if !config.relation_filter.is_empty()
                && !config
                    .relation_filter
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(&edge.relationship.to_string()))
            {
                continue; // Skip edges not matching the filter
            }

            edges
                .entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());

            reverse_edges
                .entry(edge.to.clone())
                .or_default()
                .push(edge.from.clone());

            edge_attrs.insert(
                (edge.from.clone(), edge.to.clone()),
                EdgeAttrs {
                    relationship: edge.relationship.clone(),
                    scope: edge.scope.clone(),
                },
            );
        }

        // Identify vulnerable components
        for (id, comp) in &sbom.components {
            if !comp.vulnerabilities.is_empty() {
                vulnerable_components.insert(id.clone());
            }
        }

        // Calculate depths via BFS from roots (respecting max_depth limit)
        let all_components: HashSet<_> = sbom.components.keys().cloned().collect();
        let depths =
            Self::calculate_depths(&edges, &reverse_edges, &all_components, config.max_depth);

        Self {
            sbom,
            edges,
            reverse_edges,
            edge_attrs,
            depths,
            vulnerable_components,
        }
    }

    /// Calculate minimum depths from roots via BFS.
    ///
    /// Uses minimum depth when multiple paths exist (diamond dependencies),
    /// which gives the most accurate "direct vs transitive" classification.
    /// Respects `max_depth` limit (0 = unlimited).
    fn calculate_depths(
        edges: &HashMap<CanonicalId, Vec<CanonicalId>>,
        reverse_edges: &HashMap<CanonicalId, Vec<CanonicalId>>,
        all_components: &HashSet<CanonicalId>,
        max_depth: u32,
    ) -> HashMap<CanonicalId, u32> {
        let mut depths = HashMap::new();

        // BFS to calculate minimum depths
        // We use a queue that may revisit nodes if a shorter path is found
        let mut queue: VecDeque<(CanonicalId, u32)> = all_components
            .iter()
            .filter(|id| reverse_edges.get(*id).is_none_or(std::vec::Vec::is_empty))
            .cloned()
            .map(|id| (id, 1))
            .collect();

        while let Some((id, depth)) = queue.pop_front() {
            // Check if we've found a shorter path to this node
            if let Some(&existing_depth) = depths.get(&id)
                && depth >= existing_depth
            {
                continue; // Already have a shorter or equal path
            }

            // Record this depth (it's either new or shorter than existing)
            depths.insert(id.clone(), depth);

            // Stop traversing if we've reached max_depth (0 = unlimited)
            if max_depth > 0 && depth >= max_depth {
                continue;
            }

            if let Some(children) = edges.get(&id) {
                for child_id in children {
                    let child_depth = depth + 1;
                    // Only queue if this might be a shorter path
                    let dominated = depths.get(child_id).is_some_and(|&d| d <= child_depth);
                    if !dominated {
                        queue.push_back((child_id.clone(), child_depth));
                    }
                }
            }
        }

        // Assign sentinel depth to unreachable/cyclic-only nodes so they
        // participate in impact assessment but are NOT confused with real roots.
        // u32::MAX means "unreachable from any root via BFS".
        for id in all_components {
            depths.entry(id.clone()).or_insert(CYCLIC_SENTINEL_DEPTH);
        }

        depths
    }

    fn get_parents(&self, component_id: &CanonicalId) -> Vec<CanonicalId> {
        self.reverse_edges
            .get(component_id)
            .cloned()
            .unwrap_or_default()
    }

    fn get_children(&self, component_id: &CanonicalId) -> Vec<CanonicalId> {
        self.edges.get(component_id).cloned().unwrap_or_default()
    }

    fn get_edge_attrs(&self, from: &CanonicalId, to: &CanonicalId) -> Option<&EdgeAttrs> {
        self.edge_attrs.get(&(from.clone(), to.clone()))
    }

    fn get_depth(&self, component_id: &CanonicalId) -> Option<u32> {
        self.depths.get(component_id).copied()
    }

    fn is_vulnerable(&self, component_id: &CanonicalId) -> bool {
        self.vulnerable_components.contains(component_id)
    }

    fn get_component_name(&self, component_id: &CanonicalId) -> String {
        self.sbom.components.get(component_id).map_or_else(
            || component_id.to_string(),
            |c| {
                c.version
                    .as_ref()
                    .map_or_else(|| c.name.clone(), |v| format!("{}@{}", c.name, v))
            },
        )
    }
}

/// Perform graph-aware diff between two SBOMs
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn diff_dependency_graph(
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    component_matches: &HashMap<CanonicalId, Option<CanonicalId>>,
    config: &GraphDiffConfig,
) -> (Vec<DependencyGraphChange>, GraphChangeSummary) {
    let old_graph = DependencyGraph::from_sbom(old_sbom, config);
    let new_graph = DependencyGraph::from_sbom(new_sbom, config);

    let mut changes = Vec::new();

    // Iterate through matched components to find dependency changes
    for (old_id, new_id_option) in component_matches {
        if let Some(new_id) = new_id_option {
            let component_name = new_graph.get_component_name(new_id);

            // Get children in both graphs, mapping old children through component_matches
            // so we compare in the new-SBOM ID space.
            // Children not in the match map or matched to None (removed) are excluded —
            // they have no new-space representation and should not participate in comparison.
            let old_children_mapped: HashSet<CanonicalId> = old_graph
                .get_children(old_id)
                .into_iter()
                .filter_map(|old_child| {
                    component_matches
                        .get(&old_child)
                        .and_then(|opt| opt.clone())
                })
                .collect();
            let new_children: HashSet<_> = new_graph.get_children(new_id).into_iter().collect();

            // Build a reverse map from new-space child to old-space child for attr lookup
            let old_child_to_new: HashMap<CanonicalId, CanonicalId> = old_graph
                .get_children(old_id)
                .into_iter()
                .filter_map(|old_child| {
                    component_matches
                        .get(&old_child)
                        .and_then(|opt| opt.clone())
                        .map(|new_child_id| (new_child_id, old_child))
                })
                .collect();

            // Detect added dependencies
            for child_id in new_children.difference(&old_children_mapped) {
                let dep_name = new_graph.get_component_name(child_id);
                let impact = assess_impact_added(&new_graph, child_id);

                changes.push(DependencyGraphChange {
                    component_id: new_id.clone(),
                    component_name: component_name.clone(),
                    change: DependencyChangeType::DependencyAdded {
                        dependency_id: child_id.clone(),
                        dependency_name: dep_name,
                    },
                    impact,
                });
            }

            // Detect removed dependencies
            for child_id in old_children_mapped.difference(&new_children) {
                let dep_name = new_graph.get_component_name(child_id);

                changes.push(DependencyGraphChange {
                    component_id: new_id.clone(),
                    component_name: component_name.clone(),
                    change: DependencyChangeType::DependencyRemoved {
                        dependency_id: child_id.clone(),
                        dependency_name: dep_name,
                    },
                    impact: GraphChangeImpact::Low,
                });
            }

            // Detect relationship/scope changes for children present in both
            for child_id in old_children_mapped.intersection(&new_children) {
                // Look up old edge attrs: old_id → old_child_id (in old-space)
                let old_attrs = old_child_to_new
                    .get(child_id)
                    .and_then(|old_child_id| old_graph.get_edge_attrs(old_id, old_child_id));
                let new_attrs = new_graph.get_edge_attrs(new_id, child_id);

                if let (Some(old_a), Some(new_a)) = (old_attrs, new_attrs) {
                    if old_a != new_a {
                        let dep_name = new_graph.get_component_name(child_id);
                        changes.push(DependencyGraphChange {
                            component_id: new_id.clone(),
                            component_name: component_name.clone(),
                            change: DependencyChangeType::RelationshipChanged {
                                dependency_id: child_id.clone(),
                                dependency_name: dep_name,
                                old_relationship: old_a.relationship.to_string(),
                                new_relationship: new_a.relationship.to_string(),
                                old_scope: old_a.scope.as_ref().map(ToString::to_string),
                                new_scope: new_a.scope.as_ref().map(ToString::to_string),
                            },
                            impact: GraphChangeImpact::Medium,
                        });
                    }
                }
            }
        }
    }

    // Detect depth changes
    if config.detect_depth_changes {
        detect_depth_changes(&old_graph, &new_graph, component_matches, &mut changes);
    }

    // Detect reparenting (post-process to find moved dependencies)
    if config.detect_reparenting {
        detect_reparenting(&old_graph, &new_graph, component_matches, &mut changes);
    }

    // Sort changes by impact (critical first)
    changes.sort_by(|a, b| {
        let impact_order = |i: &GraphChangeImpact| match i {
            GraphChangeImpact::Critical => 0,
            GraphChangeImpact::High => 1,
            GraphChangeImpact::Medium => 2,
            GraphChangeImpact::Low => 3,
        };
        impact_order(&a.impact).cmp(&impact_order(&b.impact))
    });

    let summary = GraphChangeSummary::from_changes(&changes);
    (changes, summary)
}

/// Assess the impact of adding a dependency.
///
/// Depth numbering: 1 = root (no incoming edges), 2 = direct dep, 3+ = transitive.
/// `CYCLIC_SENTINEL_DEPTH` = unreachable from root (cyclic-only), treated as transitive.
/// A direct dependency (depth <= 2) that is vulnerable is Critical impact.
fn assess_impact_added(graph: &DependencyGraph, component_id: &CanonicalId) -> GraphChangeImpact {
    let depth = graph
        .get_depth(component_id)
        .unwrap_or(CYCLIC_SENTINEL_DEPTH);
    let is_direct = depth > 0 && depth <= 2 && depth != CYCLIC_SENTINEL_DEPTH;

    if graph.is_vulnerable(component_id) {
        if is_direct {
            GraphChangeImpact::Critical
        } else {
            GraphChangeImpact::High
        }
    } else if is_direct {
        GraphChangeImpact::Medium
    } else {
        GraphChangeImpact::Low
    }
}

/// Detect depth changes between matched components.
///
/// Ignores sentinel↔sentinel transitions (both unreachable).
/// Reports sentinel→real or real→sentinel transitions appropriately.
fn detect_depth_changes(
    old_graph: &DependencyGraph,
    new_graph: &DependencyGraph,
    matches: &HashMap<CanonicalId, Option<CanonicalId>>,
    changes: &mut Vec<DependencyGraphChange>,
) {
    for (old_id, new_id_opt) in matches {
        if let Some(new_id) = new_id_opt {
            let old_depth = old_graph.get_depth(old_id);
            let new_depth = new_graph.get_depth(new_id);

            if let (Some(od), Some(nd)) = (old_depth, new_depth)
                && od != nd
            {
                // Skip sentinel↔sentinel (both unreachable, no meaningful change)
                if od == CYCLIC_SENTINEL_DEPTH && nd == CYCLIC_SENTINEL_DEPTH {
                    continue;
                }

                let component_name = new_graph.get_component_name(new_id);

                let impact =
                    if nd < od && nd != CYCLIC_SENTINEL_DEPTH && new_graph.is_vulnerable(new_id) {
                        // Vulnerable component moved closer to root
                        GraphChangeImpact::High
                    } else if nd <= 2 && (od > 2 || od == CYCLIC_SENTINEL_DEPTH) {
                        // Became direct dependency (from transitive or unreachable)
                        GraphChangeImpact::Medium
                    } else {
                        GraphChangeImpact::Low
                    };

                changes.push(DependencyGraphChange {
                    component_id: new_id.clone(),
                    component_name,
                    change: DependencyChangeType::DepthChanged {
                        old_depth: od,
                        new_depth: nd,
                    },
                    impact,
                });
            }
        }
    }
}

/// Detect reparented components (moved from one parent to another).
///
/// Handles single-parent, multi-parent, root promotion, and root demotion cases.
/// For multi-parent scenarios, compares the mapped old parent set against the new
/// parent set. A "reparenting" requires at least one removed parent AND at least
/// one added parent. Only the specific add/remove entries involved in the
/// reparenting are suppressed — unrelated add/remove entries for the same child
/// are preserved.
fn detect_reparenting(
    old_graph: &DependencyGraph,
    new_graph: &DependencyGraph,
    matches: &HashMap<CanonicalId, Option<CanonicalId>>,
    changes: &mut Vec<DependencyGraphChange>,
) {
    for (old_id, new_id_opt) in matches {
        if let Some(new_id) = new_id_opt {
            let old_parents = old_graph.get_parents(old_id);
            let new_parents = new_graph.get_parents(new_id);

            // Skip if both have no parents (both are roots — no change)
            if old_parents.is_empty() && new_parents.is_empty() {
                continue;
            }

            // Map old parents through component_matches to new-SBOM ID space.
            // Parents not in the match map or matched to None (removed) are excluded.
            let old_parents_mapped: HashSet<CanonicalId> = old_parents
                .iter()
                .filter_map(|old_parent| matches.get(old_parent).and_then(|opt| opt.clone()))
                .collect();
            let new_parents_set: HashSet<CanonicalId> = new_parents.into_iter().collect();

            // Check if parents differ
            if old_parents_mapped == new_parents_set {
                continue;
            }

            // Determine which parents were removed and added
            let removed_parents: Vec<_> = old_parents_mapped.difference(&new_parents_set).collect();
            let added_parents: Vec<_> = new_parents_set.difference(&old_parents_mapped).collect();

            // Need at least one removed AND one added parent for a proper reparenting.
            // Pure parent-add or parent-remove without the other side is just a
            // dependency add/remove, which is already captured in the main diff loop.
            if removed_parents.is_empty() || added_parents.is_empty() {
                continue;
            }

            let old_parent = removed_parents[0];
            let new_parent = added_parents[0];

            let component_name = new_graph.get_component_name(new_id);
            let old_parent_name = new_graph.get_component_name(old_parent);
            let new_parent_name = new_graph.get_component_name(new_parent);

            // Only suppress the specific add/remove entries for the primary
            // reparenting pair (old_parent→child removed, new_parent→child added).
            // Other add/remove entries for the same child but different parents
            // are preserved.
            changes.retain(|c| match &c.change {
                DependencyChangeType::DependencyAdded { dependency_id, .. } => {
                    !(dependency_id == new_id && c.component_id == *new_parent)
                }
                DependencyChangeType::DependencyRemoved { dependency_id, .. } => {
                    !(dependency_id == new_id && c.component_id == *old_parent)
                }
                _ => true,
            });

            changes.push(DependencyGraphChange {
                component_id: new_id.clone(),
                component_name,
                change: DependencyChangeType::Reparented {
                    dependency_id: new_id.clone(),
                    dependency_name: new_graph.get_component_name(new_id),
                    old_parent_id: old_parent.clone(),
                    old_parent_name,
                    new_parent_id: new_parent.clone(),
                    new_parent_name,
                },
                impact: GraphChangeImpact::Medium,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, DependencyEdge, DependencyType, NormalizedSbom, VulnerabilityRef,
        VulnerabilitySource,
    };

    /// Helper to create a test component with a given name
    fn make_component(name: &str) -> Component {
        Component::new(name.to_string(), name.to_string())
    }

    /// Helper to create a component with version
    fn make_component_v(name: &str, version: &str) -> Component {
        Component::new(name.to_string(), format!("{name}@{version}"))
            .with_version(version.to_string())
    }

    /// Helper to build a simple SBOM with given components and edges
    fn make_sbom(
        components: Vec<Component>,
        edges: Vec<(CanonicalId, CanonicalId)>,
    ) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for comp in components {
            sbom.add_component(comp);
        }
        for (from, to) in edges {
            sbom.add_edge(DependencyEdge::new(from, to, DependencyType::DependsOn));
        }
        sbom
    }

    /// Helper to build an SBOM with explicit relationship types on edges
    fn make_sbom_with_rel(
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
        sbom
    }

    #[test]
    fn test_graph_diff_config_default() {
        let config = GraphDiffConfig::default();
        assert!(config.detect_reparenting);
        assert!(config.detect_depth_changes);
        assert_eq!(config.max_depth, 0);
    }

    #[test]
    fn test_graph_change_impact_display() {
        assert_eq!(GraphChangeImpact::Critical.as_str(), "critical");
        assert_eq!(GraphChangeImpact::High.as_str(), "high");
        assert_eq!(GraphChangeImpact::Medium.as_str(), "medium");
        assert_eq!(GraphChangeImpact::Low.as_str(), "low");
    }

    #[test]
    fn test_children_mapped_through_component_matches() {
        // Old SBOM: A -> B (old IDs)
        let a_old = make_component("a-old");
        let b_old = make_component("b-old");
        let a_old_id = a_old.canonical_id.clone();
        let b_old_id = b_old.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![a_old, b_old],
            vec![(a_old_id.clone(), b_old_id.clone())],
        );

        // New SBOM: A -> B (new IDs, same logical components)
        let a_new = make_component("a-new");
        let b_new = make_component("b-new");
        let a_new_id = a_new.canonical_id.clone();
        let b_new_id = b_new.canonical_id.clone();

        let new_sbom = make_sbom(
            vec![a_new, b_new],
            vec![(a_new_id.clone(), b_new_id.clone())],
        );

        // Map: a-old -> a-new, b-old -> b-new
        let mut matches = HashMap::new();
        matches.insert(a_old_id, Some(a_new_id));
        matches.insert(b_old_id, Some(b_new_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        // No changes expected: same logical graph structure
        assert_eq!(summary.dependencies_added, 0, "No false add: {changes:?}");
        assert_eq!(
            summary.dependencies_removed, 0,
            "No false remove: {changes:?}"
        );
    }

    #[test]
    fn test_depth_linear_chain() {
        // A -> B -> C -> D
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");
        let d = make_component("d");

        let ids: Vec<_> = [&a, &b, &c, &d]
            .iter()
            .map(|c| c.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![a, b, c, d],
            vec![
                (ids[0].clone(), ids[1].clone()),
                (ids[1].clone(), ids[2].clone()),
                (ids[2].clone(), ids[3].clone()),
            ],
        );

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        assert_eq!(graph.get_depth(&ids[0]), Some(1)); // root
        assert_eq!(graph.get_depth(&ids[1]), Some(2));
        assert_eq!(graph.get_depth(&ids[2]), Some(3));
        assert_eq!(graph.get_depth(&ids[3]), Some(4));
    }

    #[test]
    fn test_depth_diamond_dependency() {
        // A -> B, A -> C, B -> D, C -> D
        // D should have min depth 3 (via A->B->D or A->C->D)
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");
        let d = make_component("d");

        let ids: Vec<_> = [&a, &b, &c, &d]
            .iter()
            .map(|c| c.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![a, b, c, d],
            vec![
                (ids[0].clone(), ids[1].clone()),
                (ids[0].clone(), ids[2].clone()),
                (ids[1].clone(), ids[3].clone()),
                (ids[2].clone(), ids[3].clone()),
            ],
        );

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        assert_eq!(graph.get_depth(&ids[0]), Some(1));
        assert_eq!(graph.get_depth(&ids[1]), Some(2));
        assert_eq!(graph.get_depth(&ids[2]), Some(2));
        assert_eq!(graph.get_depth(&ids[3]), Some(3)); // min of both paths
    }

    #[test]
    fn test_depth_rootless_cycle() {
        // A -> B -> C -> A (pure cycle, no roots)
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");

        let ids: Vec<_> = [&a, &b, &c]
            .iter()
            .map(|c| c.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![a, b, c],
            vec![
                (ids[0].clone(), ids[1].clone()),
                (ids[1].clone(), ids[2].clone()),
                (ids[2].clone(), ids[0].clone()),
            ],
        );

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        // All nodes should get sentinel depth (unreachable from root)
        for (i, id) in ids.iter().enumerate() {
            let depth = graph.get_depth(id);
            assert!(depth.is_some(), "Node {i} should have depth");
            assert_eq!(
                depth.unwrap(),
                CYCLIC_SENTINEL_DEPTH,
                "Cyclic node {i} should get sentinel depth, not 0"
            );
        }
    }

    #[test]
    fn test_depth_cycle_reachable_from_root() {
        // Root -> A -> B -> C -> B (cycle B→C→B reachable from root)
        let root = make_component("root");
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");

        let ids: Vec<_> = [&root, &a, &b, &c]
            .iter()
            .map(|comp| comp.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![root, a, b, c],
            vec![
                (ids[0].clone(), ids[1].clone()), // root → A
                (ids[1].clone(), ids[2].clone()), // A → B
                (ids[2].clone(), ids[3].clone()), // B → C
                (ids[3].clone(), ids[2].clone()), // C → B (cycle)
            ],
        );

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        assert_eq!(graph.get_depth(&ids[0]), Some(1)); // root
        assert_eq!(graph.get_depth(&ids[1]), Some(2)); // A (direct)
        assert_eq!(graph.get_depth(&ids[2]), Some(3)); // B (transitive, reachable)
        assert_eq!(graph.get_depth(&ids[3]), Some(4)); // C (transitive, reachable)
        // Despite being in a cycle, B and C have real depths because
        // they are reachable from root via BFS
    }

    #[test]
    fn test_depth_disconnected_subgraphs() {
        // Subgraph 1: R1 -> A
        // Subgraph 2: R2 -> B -> C
        // Independent depth computation for each
        let r1 = make_component("r1");
        let a = make_component("a");
        let r2 = make_component("r2");
        let b = make_component("b");
        let c = make_component("c");

        let ids: Vec<_> = [&r1, &a, &r2, &b, &c]
            .iter()
            .map(|comp| comp.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![r1, a, r2, b, c],
            vec![
                (ids[0].clone(), ids[1].clone()), // R1 → A
                (ids[2].clone(), ids[3].clone()), // R2 → B
                (ids[3].clone(), ids[4].clone()), // B → C
            ],
        );

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        assert_eq!(graph.get_depth(&ids[0]), Some(1)); // R1
        assert_eq!(graph.get_depth(&ids[1]), Some(2)); // A
        assert_eq!(graph.get_depth(&ids[2]), Some(1)); // R2
        assert_eq!(graph.get_depth(&ids[3]), Some(2)); // B
        assert_eq!(graph.get_depth(&ids[4]), Some(3)); // C
    }

    #[test]
    fn test_self_referencing_edge_no_infinite_loop() {
        // A -> A (self-loop)
        let a = make_component("a");
        let a_id = a.canonical_id.clone();

        let sbom = make_sbom(vec![a], vec![(a_id.clone(), a_id.clone())]);

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        // A is its own parent, but it's also a root (no OTHER incoming edges
        // that would remove it from the root set... actually it HAS an incoming
        // edge from itself). With the self-loop, A has an incoming edge so it's
        // NOT a root → gets sentinel depth.
        let depth = graph.get_depth(&a_id);
        assert!(depth.is_some(), "A should have a depth");
        // Self-loop means A has incoming edges, so not a root → sentinel
        assert_eq!(
            depth.unwrap(),
            CYCLIC_SENTINEL_DEPTH,
            "Self-referencing node should get sentinel depth"
        );
    }

    #[test]
    fn test_depth_max_depth_limit() {
        // A -> B -> C -> D with max_depth 2
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");
        let d = make_component("d");

        let ids: Vec<_> = [&a, &b, &c, &d]
            .iter()
            .map(|c| c.canonical_id.clone())
            .collect();
        let sbom = make_sbom(
            vec![a, b, c, d],
            vec![
                (ids[0].clone(), ids[1].clone()),
                (ids[1].clone(), ids[2].clone()),
                (ids[2].clone(), ids[3].clone()),
            ],
        );

        let config = GraphDiffConfig {
            max_depth: 2,
            ..Default::default()
        };
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        assert_eq!(graph.get_depth(&ids[0]), Some(1));
        assert_eq!(graph.get_depth(&ids[1]), Some(2));
        // C and D get sentinel depth since BFS stops at depth 2
        // and they're unreachable from root BFS at that limit
        assert_eq!(graph.get_depth(&ids[2]), Some(CYCLIC_SENTINEL_DEPTH));
        assert_eq!(graph.get_depth(&ids[3]), Some(CYCLIC_SENTINEL_DEPTH));
    }

    #[test]
    fn test_reparenting_single_parent() {
        // Old: P1 -> C (P2 exists but not parent of C)
        // New: P2 -> C (P1 exists but not parent of C)
        // P1 and P2 are distinct components present in both SBOMs.
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );
        let new_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), child.clone()],
            vec![(p2_id.clone(), child_id.clone())],
        );

        // Both parents map to themselves — they are distinct logical components
        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id));
        matches.insert(p2_id.clone(), Some(p2_id));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.reparented > 0,
            "Should detect reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_renamed_parent_is_not_reparenting() {
        // Old: P1 -> C. New: P2 -> C. P1 matched to P2 (same logical component).
        // This is a rename, not reparenting — no structural change.
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1, child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );
        let new_sbom = make_sbom(
            vec![p2, child.clone()],
            vec![(p2_id.clone(), child_id.clone())],
        );

        let mut matches = HashMap::new();
        matches.insert(p1_id, Some(p2_id));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert_eq!(
            summary.reparented, 0,
            "Renamed parent should not be reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_reparenting_multi_parent() {
        // Old: P1 -> C, P2 -> C
        // New: P1 -> C, P3 -> C
        // P2 and P3 are distinct components (P2 removed, P3 added).
        // All components exist in both SBOMs to enable proper matching.
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let p3 = make_component("p3");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let p3_id = p3.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), p3.clone(), child.clone()],
            vec![
                (p1_id.clone(), child_id.clone()),
                (p2_id.clone(), child_id.clone()),
            ],
        );
        let new_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), p3.clone(), child.clone()],
            vec![
                (p1_id.clone(), child_id.clone()),
                (p3_id.clone(), child_id.clone()),
            ],
        );

        // All map to themselves — they are distinct logical components
        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id));
        matches.insert(p2_id.clone(), Some(p2_id));
        matches.insert(p3_id.clone(), Some(p3_id));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.reparented > 0,
            "Should detect multi-parent reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_vulnerable_direct_dep_is_critical() {
        // A -> V where V has vulnerabilities and depth=1 (direct)
        let a = make_component("root");
        let mut vuln_comp = make_component("vuln-lib");
        vuln_comp.vulnerabilities.push(VulnerabilityRef {
            id: "CVE-2024-0001".to_string(),
            source: VulnerabilitySource::Osv,
            severity: None,
            cvss: vec![],
            affected_versions: vec![],
            remediation: None,
            description: None,
            cwes: vec![],
            published: None,
            modified: None,
            is_kev: false,
            kev_info: None,
            vex_status: None,
        });

        let a_id = a.canonical_id.clone();
        let v_id = vuln_comp.canonical_id.clone();

        let old_sbom = make_sbom(vec![a.clone()], vec![]);
        let new_sbom = make_sbom(
            vec![a.clone(), vuln_comp],
            vec![(a_id.clone(), v_id.clone())],
        );

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));

        let config = GraphDiffConfig::default();
        let (changes, _) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        let critical = changes
            .iter()
            .any(|c| c.impact == GraphChangeImpact::Critical);
        assert!(
            critical,
            "Vulnerable direct dep should be critical impact: {changes:?}"
        );
    }

    #[test]
    fn test_empty_sboms_no_changes() {
        let old_sbom = NormalizedSbom::default();
        let new_sbom = NormalizedSbom::default();
        let matches = HashMap::new();
        let config = GraphDiffConfig::default();

        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);
        assert!(changes.is_empty());
        assert_eq!(summary.total_changes, 0);
    }

    #[test]
    fn test_identical_graphs_no_changes() {
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let sbom = make_sbom(vec![a, b], vec![(a_id.clone(), b_id.clone())]);

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&sbom, &sbom, &matches, &config);

        // No added/removed (depth might diff trivially due to same-SBOM comparison)
        assert_eq!(summary.dependencies_added, 0, "No false adds: {changes:?}");
        assert_eq!(
            summary.dependencies_removed, 0,
            "No false removes: {changes:?}"
        );
    }

    #[test]
    fn test_removed_child_not_false_positive() {
        // Old: A -> B_v1, New: A -> B_v2 (different canonical IDs for B)
        // B_v1 is matched to B_v2 in the mapping.
        // Should detect no structural change (same logical edge, just version bump).
        let a = make_component("a");
        let b_v1 = make_component_v("b", "1.0");
        let b_v2 = make_component_v("b", "2.0");

        let a_id = a.canonical_id.clone();
        let b_v1_id = b_v1.canonical_id.clone();
        let b_v2_id = b_v2.canonical_id.clone();

        let old_sbom = make_sbom(vec![a.clone(), b_v1], vec![(a_id.clone(), b_v1_id.clone())]);
        let new_sbom = make_sbom(vec![a.clone(), b_v2], vec![(a_id.clone(), b_v2_id.clone())]);

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_v1_id, Some(b_v2_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert_eq!(
            summary.dependencies_added, 0,
            "Version bump should not be false add: {changes:?}"
        );
        assert_eq!(
            summary.dependencies_removed, 0,
            "Version bump should not be false remove: {changes:?}"
        );
    }

    #[test]
    fn test_unmatched_old_child_excluded_from_comparison() {
        // Old: A -> B, A -> C. New: A -> B. C is removed (matched to None).
        // Should detect: C removed as dependency of A. Not: false add of B.
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");

        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        let c_id = c.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![a.clone(), b.clone(), c],
            vec![(a_id.clone(), b_id.clone()), (a_id.clone(), c_id.clone())],
        );
        let new_sbom = make_sbom(
            vec![a.clone(), b.clone()],
            vec![(a_id.clone(), b_id.clone())],
        );

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));
        matches.insert(c_id, None); // C is removed

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        // C was removed, so it's excluded from old_children_mapped.
        // B is in both → no change for B.
        // The graph diff tracks children per matched parent. Since C is excluded from
        // the mapped set, it won't appear in the difference. This is correct because
        // the component-level diff already reports C as removed.
        assert_eq!(summary.dependencies_added, 0, "No false adds: {changes:?}");
    }

    #[test]
    fn test_reparenting_with_removed_parent() {
        // Old: P1 -> C, P2 -> C. New: P1 -> C. P2 removed (matched to None).
        // Should NOT report reparenting — parent set simply lost a removed node.
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), p2, child.clone()],
            vec![
                (p1_id.clone(), child_id.clone()),
                (p2_id.clone(), child_id.clone()),
            ],
        );
        let new_sbom = make_sbom(
            vec![p1.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );

        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id));
        matches.insert(p2_id, None); // P2 removed
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert_eq!(
            summary.reparented, 0,
            "Removed parent should not trigger reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_relationship_change_detected() {
        // Old: A -[DependsOn]-> B. New: A -[DevDependsOn]-> B.
        // Same endpoints, different relationship → RelationshipChanged.
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let old_sbom = make_sbom_with_rel(
            vec![a.clone(), b.clone()],
            vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
        );
        let new_sbom = make_sbom_with_rel(
            vec![a, b],
            vec![(a_id.clone(), b_id.clone(), DependencyType::DevDependsOn)],
        );

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.relationship_changed > 0,
            "Should detect relationship change: {changes:?}"
        );
        // Should NOT report add+remove for same endpoints
        assert_eq!(
            summary.dependencies_added, 0,
            "Relationship change is not an add: {changes:?}"
        );
        assert_eq!(
            summary.dependencies_removed, 0,
            "Relationship change is not a remove: {changes:?}"
        );
    }

    #[test]
    fn test_scope_change_detected() {
        // Old: A -[DependsOn, Required]-> B. New: A -[DependsOn, Optional]-> B.
        // Same endpoints and relationship, different scope → RelationshipChanged.
        use crate::model::DependencyScope;

        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let mut old_sbom = NormalizedSbom::default();
        old_sbom.add_component(a.clone());
        old_sbom.add_component(b.clone());
        old_sbom.add_edge(
            DependencyEdge::new(a_id.clone(), b_id.clone(), DependencyType::DependsOn)
                .with_scope(DependencyScope::Required),
        );

        let mut new_sbom = NormalizedSbom::default();
        new_sbom.add_component(a);
        new_sbom.add_component(b);
        new_sbom.add_edge(
            DependencyEdge::new(a_id.clone(), b_id.clone(), DependencyType::DependsOn)
                .with_scope(DependencyScope::Optional),
        );

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.relationship_changed > 0,
            "Should detect scope change: {changes:?}"
        );
    }

    #[test]
    fn test_reparenting_does_not_suppress_unrelated_add() {
        // Reparenting C from P1→P2 should NOT suppress "C added to P3".
        // Old: P1 -> C, P2 exists, P3 exists
        // New: P2 -> C, P3 -> C
        // P1→C removed, P2→C added (reparenting), P3→C added (unrelated, must survive)
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let p3 = make_component("p3");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let p3_id = p3.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), p3.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );
        let new_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), p3.clone(), child.clone()],
            vec![
                (p2_id.clone(), child_id.clone()),
                (p3_id.clone(), child_id.clone()),
            ],
        );

        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id));
        matches.insert(p2_id.clone(), Some(p2_id.clone()));
        matches.insert(p3_id.clone(), Some(p3_id.clone()));
        matches.insert(child_id.clone(), Some(child_id.clone()));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        // Should have reparenting (P1→P2)
        assert!(
            summary.reparented > 0,
            "Should detect reparenting: {changes:?}"
        );

        // The reparenting picks one of {P2, P3} as the new parent. The OTHER one's
        // DependencyAdded entry must survive — it's unrelated to the reparenting.
        let reparent = changes
            .iter()
            .find(|c| matches!(&c.change, DependencyChangeType::Reparented { .. }))
            .expect("Should have a reparent entry");
        let reparent_new_parent = match &reparent.change {
            DependencyChangeType::Reparented { new_parent_id, .. } => new_parent_id.clone(),
            _ => unreachable!(),
        };
        let other_parent = if reparent_new_parent == p2_id {
            &p3_id
        } else {
            &p2_id
        };

        let other_added = changes.iter().any(|c| {
            c.component_id == *other_parent
                && matches!(
                    &c.change,
                    DependencyChangeType::DependencyAdded { dependency_id, .. }
                    if *dependency_id == child_id
                )
        });
        assert!(
            other_added,
            "The non-reparented parent's add should not be suppressed: {changes:?}"
        );
    }

    #[test]
    fn test_root_promotion_not_skipped() {
        // Old: P1 -> C (C has a parent)
        // New: C is a root (no parents)
        // This is NOT reparenting (no added parent), but the code should
        // not skip it entirely — it should still detect the parent removal.
        let p1 = make_component("p1");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );
        let new_sbom = make_sbom(vec![p1.clone(), child.clone()], vec![]);

        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id.clone()));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        // Should detect the removed dependency (P1→C removed)
        assert!(
            summary.dependencies_removed > 0,
            "Root promotion: dependency removal should be detected: {changes:?}"
        );
        // Should NOT report reparenting (no new parent added)
        assert_eq!(
            summary.reparented, 0,
            "Root promotion is not reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_root_demotion_not_skipped() {
        // Old: C is a root (no parents)
        // New: P1 -> C (C now has a parent)
        // This is NOT reparenting, just a dependency addition.
        let p1 = make_component("p1");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(vec![p1.clone(), child.clone()], vec![]);
        let new_sbom = make_sbom(
            vec![p1.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );

        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id.clone()));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        // Should detect the added dependency
        assert!(
            summary.dependencies_added > 0,
            "Root demotion: dependency addition should be detected: {changes:?}"
        );
        // Should NOT report reparenting (no old parent removed)
        assert_eq!(
            summary.reparented, 0,
            "Root demotion is not reparenting: {changes:?}"
        );
    }

    #[test]
    fn test_parent_added_multi_parent_not_reparenting() {
        // Old: P1 -> C. New: P1 -> C, P2 -> C.
        // C gains a parent but keeps the old one — this is NOT reparenting.
        let p1 = make_component("p1");
        let p2 = make_component("p2");
        let child = make_component("child");

        let p1_id = p1.canonical_id.clone();
        let p2_id = p2.canonical_id.clone();
        let child_id = child.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), child.clone()],
            vec![(p1_id.clone(), child_id.clone())],
        );
        let new_sbom = make_sbom(
            vec![p1.clone(), p2.clone(), child.clone()],
            vec![
                (p1_id.clone(), child_id.clone()),
                (p2_id.clone(), child_id.clone()),
            ],
        );

        let mut matches = HashMap::new();
        matches.insert(p1_id.clone(), Some(p1_id));
        matches.insert(p2_id.clone(), Some(p2_id));
        matches.insert(child_id.clone(), Some(child_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert_eq!(
            summary.reparented, 0,
            "Adding a new parent while keeping old is not reparenting: {changes:?}"
        );
        // But the P2→C addition should still be detected
        assert!(
            summary.dependencies_added > 0,
            "P2→C should be detected as added: {changes:?}"
        );
    }

    #[test]
    fn test_same_relationship_no_change() {
        // Old: A -[DependsOn]-> B. New: A -[DependsOn]-> B.
        // Same everything → no change.
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let old_sbom = make_sbom_with_rel(
            vec![a.clone(), b.clone()],
            vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
        );
        let new_sbom = make_sbom_with_rel(
            vec![a, b],
            vec![(a_id.clone(), b_id.clone(), DependencyType::DependsOn)],
        );

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert_eq!(
            summary.relationship_changed, 0,
            "Same relationship should not be a change: {changes:?}"
        );
    }

    #[test]
    fn test_duplicate_edges_different_types() {
        // A -[DependsOn]-> B and A -[DevDependsOn]-> B in same SBOM.
        // The last edge wins in the edge_attrs map (HashMap insert semantics).
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let mut sbom = NormalizedSbom::default();
        sbom.add_component(a);
        sbom.add_component(b);
        sbom.add_edge(DependencyEdge::new(
            a_id.clone(),
            b_id.clone(),
            DependencyType::DependsOn,
        ));
        sbom.add_edge(DependencyEdge::new(
            a_id.clone(),
            b_id.clone(),
            DependencyType::DevDependsOn,
        ));

        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        // B should appear as child of A (possibly duplicated in children list)
        let children = graph.get_children(&a_id);
        assert!(children.contains(&b_id), "B should be a child of A");

        // Edge attrs should have one entry (last-write-wins for same pair)
        let attrs = graph.get_edge_attrs(&a_id, &b_id);
        assert!(attrs.is_some(), "Should have edge attrs for A→B");
    }

    #[test]
    fn test_large_graph_completes() {
        // 500 nodes in a chain: root → n1 → n2 → ... → n499
        let mut components = Vec::new();
        let mut edges = Vec::new();
        let mut ids = Vec::new();

        for i in 0..500 {
            let comp = make_component(&format!("node-{i}"));
            ids.push(comp.canonical_id.clone());
            components.push(comp);
        }
        for i in 0..499 {
            edges.push((ids[i].clone(), ids[i + 1].clone()));
        }

        let sbom = make_sbom(components, edges);
        let config = GraphDiffConfig::default();
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        // Root should have depth 1, last node should have depth 500
        assert_eq!(graph.get_depth(&ids[0]), Some(1));
        assert_eq!(graph.get_depth(&ids[499]), Some(500));
    }

    #[test]
    fn test_empty_vs_nonempty_graph() {
        // Old: no edges. New: A → B. All deps should be "added".
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let old_sbom = make_sbom(vec![a.clone(), b.clone()], vec![]);
        let new_sbom = make_sbom(vec![a, b], vec![(a_id.clone(), b_id.clone())]);

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.dependencies_added > 0,
            "Should detect added dependency: {changes:?}"
        );
        assert_eq!(
            summary.dependencies_removed, 0,
            "No false removes: {changes:?}"
        );
    }

    #[test]
    fn test_nonempty_vs_empty_graph() {
        // Old: A → B. New: no edges. All deps should be "removed".
        let a = make_component("a");
        let b = make_component("b");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();

        let old_sbom = make_sbom(
            vec![a.clone(), b.clone()],
            vec![(a_id.clone(), b_id.clone())],
        );
        let new_sbom = make_sbom(vec![a, b], vec![]);

        let mut matches = HashMap::new();
        matches.insert(a_id.clone(), Some(a_id));
        matches.insert(b_id.clone(), Some(b_id));

        let config = GraphDiffConfig::default();
        let (changes, summary) = diff_dependency_graph(&old_sbom, &new_sbom, &matches, &config);

        assert!(
            summary.dependencies_removed > 0,
            "Should detect removed dependency: {changes:?}"
        );
        assert_eq!(summary.dependencies_added, 0, "No false adds: {changes:?}");
    }

    #[test]
    fn test_relation_filter() {
        // Graph with DependsOn and DevDependsOn edges.
        // Filtering to only DependsOn should exclude DevDependsOn edges.
        let a = make_component("a");
        let b = make_component("b");
        let c = make_component("c");
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        let c_id = c.canonical_id.clone();

        let mut sbom = NormalizedSbom::default();
        sbom.add_component(a);
        sbom.add_component(b);
        sbom.add_component(c);
        sbom.add_edge(DependencyEdge::new(
            a_id.clone(),
            b_id.clone(),
            DependencyType::DependsOn,
        ));
        sbom.add_edge(DependencyEdge::new(
            a_id.clone(),
            c_id.clone(),
            DependencyType::DevDependsOn,
        ));

        let config = GraphDiffConfig {
            relation_filter: vec!["depends-on".to_string()],
            ..Default::default()
        };
        let graph = DependencyGraph::from_sbom(&sbom, &config);

        let children = graph.get_children(&a_id);
        assert!(
            children.contains(&b_id),
            "DependsOn edge should be included"
        );
        assert!(
            !children.contains(&c_id),
            "DevDependsOn edge should be excluded by filter"
        );
    }
}
