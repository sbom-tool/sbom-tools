//! Graph-aware dependency diffing module.
//!
//! This module provides functionality to detect structural changes in the
//! dependency graph between two SBOMs, going beyond simple component-level
//! comparisons to identify:
//! - Dependencies being added or removed
//! - Dependencies being reparented (moved from one parent to another)
//! - Depth changes (transitive becoming direct or vice versa)

use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{CanonicalId, NormalizedSbom};

use super::result::{
    DependencyChangeType, DependencyGraphChange, GraphChangeImpact, GraphChangeSummary,
};

/// Configuration for graph-aware diffing
#[derive(Debug, Clone)]
pub struct GraphDiffConfig {
    /// Whether to detect reparenting (computationally more expensive)
    pub detect_reparenting: bool,
    /// Whether to track depth changes
    pub detect_depth_changes: bool,
    /// Maximum depth to analyze (0 = unlimited)
    pub max_depth: u32,
}

impl Default for GraphDiffConfig {
    fn default() -> Self {
        Self {
            detect_reparenting: true,
            detect_depth_changes: true,
            max_depth: 0,
        }
    }
}

/// Internal representation of dependency graph for diffing
struct DependencyGraph<'a> {
    /// Reference to the SBOM
    sbom: &'a NormalizedSbom,
    /// `parent_id` -> Vec<`child_id`>
    edges: HashMap<CanonicalId, Vec<CanonicalId>>,
    /// `child_id` -> Vec<`parent_id`> (reverse index)
    reverse_edges: HashMap<CanonicalId, Vec<CanonicalId>>,
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
        let mut vulnerable_components = HashSet::new();

        // Build edge maps from SBOM edges
        for edge in &sbom.edges {
            edges
                .entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());

            reverse_edges
                .entry(edge.to.clone())
                .or_default()
                .push(edge.from.clone());
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

            // Get children in both graphs
            let old_children: HashSet<_> = old_graph.get_children(old_id).into_iter().collect();
            let new_children: HashSet<_> = new_graph.get_children(new_id).into_iter().collect();

            // Detect added dependencies
            for child_id in new_children.difference(&old_children) {
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
            for child_id in old_children.difference(&new_children) {
                let dep_name = old_graph.get_component_name(child_id);

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

/// Assess the impact of adding a dependency
fn assess_impact_added(graph: &DependencyGraph, component_id: &CanonicalId) -> GraphChangeImpact {
    if graph.is_vulnerable(component_id) {
        if graph.get_depth(component_id) == Some(1) {
            GraphChangeImpact::Critical
        } else {
            GraphChangeImpact::High
        }
    } else if graph.get_depth(component_id) == Some(1) {
        GraphChangeImpact::Medium
    } else {
        GraphChangeImpact::Low
    }
}

/// Detect depth changes between matched components
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
                let component_name = new_graph.get_component_name(new_id);

                let impact = if nd < od && new_graph.is_vulnerable(new_id) {
                    // Vulnerable component moved closer to root
                    GraphChangeImpact::High
                } else if nd == 1 && od > 1 {
                    // Became direct dependency
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

/// Detect reparented components (moved from one parent to another)
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

            // Only consider reparenting if exactly one parent in both
            if old_parents.len() == 1 && new_parents.len() == 1 {
                let old_parent = &old_parents[0];
                let new_parent = &new_parents[0];

                // Check if the parents are different (accounting for component matching)
                let old_parent_matched = matches.get(old_parent).and_then(|opt| opt.as_ref());

                let is_reparented = !old_parent_matched
                    .is_some_and(|old_parent_in_new| old_parent_in_new == new_parent);

                if is_reparented {
                    let component_name = new_graph.get_component_name(new_id);
                    let old_parent_name = old_graph.get_component_name(old_parent);
                    let new_parent_name = new_graph.get_component_name(new_parent);

                    // Remove any corresponding Added/Removed entries for this component
                    // as they will be replaced by the Reparented entry
                    changes.retain(|c| match &c.change {
                        DependencyChangeType::DependencyAdded { dependency_id, .. }
                        | DependencyChangeType::DependencyRemoved { dependency_id, .. } => {
                            dependency_id != new_id
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
