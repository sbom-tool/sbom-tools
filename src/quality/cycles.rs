//! Dependency cycles, counted in linear time.
//!
//! A cycle is a strongly connected component of the dependency graph with
//! more than one node, or a node that depends on itself. Tarjan's algorithm
//! finds every strongly connected component in O(nodes + edges); this
//! version keeps its own stacks instead of recursing, so no graph depth can
//! overflow the call stack, and reads the graph from a compact adjacency
//! array, so it evaluates graphs of any size (the CRA cycle check used to
//! skip graphs above 1,000,000 edges, and pass them).

use crate::model::NormalizedSbom;
use std::collections::HashMap;

/// The number of dependency cycles in `sbom`: the strongly connected
/// components of its dependency edges with more than one node, plus the
/// nodes with an edge to themselves. Every edge counts, whatever its
/// relationship type, and an edge may name an id no component has.
#[must_use]
pub(crate) fn dependency_cycle_count(sbom: &NormalizedSbom) -> usize {
    let mut node_of: HashMap<&str, usize> = HashMap::new();
    let mut edges = Vec::with_capacity(sbom.edges.len());
    for edge in &sbom.edges {
        let next = node_of.len();
        let from = *node_of.entry(edge.from.value()).or_insert(next);
        let next = node_of.len();
        let to = *node_of.entry(edge.to.value()).or_insert(next);
        edges.push((from, to));
    }
    count_cycles(node_of.len(), &edges)
}

/// The number of cycles of the directed graph over nodes `0..node_count`
/// with `edges` (`from`, `to`): each strongly connected component of more
/// than one node, plus each node with a self-loop. Repeated edges count
/// once. Iterative Tarjan, O(nodes + edges).
///
/// # Panics
///
/// When an edge names a node outside `0..node_count`.
pub(crate) fn count_cycles(node_count: usize, edges: &[(usize, usize)]) -> usize {
    // Adjacency in compressed sparse row form: the targets of node `n` are
    // `targets[offsets[n]..offsets[n + 1]]`.
    let mut offsets = vec![0usize; node_count + 1];
    for &(from, _) in edges {
        offsets[from + 1] += 1;
    }
    for n in 0..node_count {
        offsets[n + 1] += offsets[n];
    }
    let mut targets = vec![0usize; edges.len()];
    let mut self_loop = vec![false; node_count];
    let mut fill = offsets[..node_count].to_vec();
    for &(from, to) in edges {
        targets[fill[from]] = to;
        fill[from] += 1;
        if from == to {
            self_loop[from] = true;
        }
    }
    drop(fill);

    const UNVISITED: usize = usize::MAX;
    // Discovery order and lowest reachable discovery order of each node.
    let mut order = vec![UNVISITED; node_count];
    let mut lowlink = vec![0usize; node_count];
    let mut on_stack = vec![false; node_count];
    let mut component_stack: Vec<usize> = Vec::new();
    // The explicit call stack: a node and the position of the next edge of
    // it to follow.
    let mut call_stack: Vec<(usize, usize)> = Vec::new();
    let mut next_order = 0usize;
    let mut cycles = 0usize;

    for start in 0..node_count {
        if order[start] != UNVISITED {
            continue;
        }
        order[start] = next_order;
        lowlink[start] = next_order;
        next_order += 1;
        component_stack.push(start);
        on_stack[start] = true;
        call_stack.push((start, offsets[start]));

        while let Some(frame) = call_stack.last_mut() {
            let node = frame.0;
            if frame.1 < offsets[node + 1] {
                let target = targets[frame.1];
                frame.1 += 1;
                if order[target] == UNVISITED {
                    order[target] = next_order;
                    lowlink[target] = next_order;
                    next_order += 1;
                    component_stack.push(target);
                    on_stack[target] = true;
                    call_stack.push((target, offsets[target]));
                } else if on_stack[target] {
                    lowlink[node] = lowlink[node].min(order[target]);
                }
                continue;
            }
            // Every edge of `node` is followed: return to its caller.
            call_stack.pop();
            if let Some(&(caller, _)) = call_stack.last() {
                lowlink[caller] = lowlink[caller].min(lowlink[node]);
            }
            if lowlink[node] == order[node] {
                // `node` roots a strongly connected component: pop it.
                let mut size = 0usize;
                while let Some(member) = component_stack.pop() {
                    on_stack[member] = false;
                    size += 1;
                    if member == node {
                        break;
                    }
                }
                if size > 1 || self_loop[node] {
                    cycles += 1;
                }
            }
        }
    }
    cycles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CanonicalId, DependencyEdge, DependencyType};

    /// The edges of a chain 0 → 1 → … → `len`.
    fn chain(len: usize) -> Vec<(usize, usize)> {
        (0..len).map(|n| (n, n + 1)).collect()
    }

    #[test]
    fn a_graph_without_edges_has_no_cycle() {
        assert_eq!(count_cycles(0, &[]), 0);
        assert_eq!(count_cycles(3, &[]), 0);
    }

    #[test]
    fn a_self_loop_is_one_cycle() {
        assert_eq!(count_cycles(1, &[(0, 0)]), 1);
        // A self-loop inside a larger component counts once with it.
        assert_eq!(count_cycles(2, &[(0, 0), (0, 1), (1, 0)]), 1);
        // Repeated, it is still one.
        assert_eq!(count_cycles(2, &[(0, 0), (0, 0), (0, 1)]), 1);
    }

    #[test]
    fn each_strongly_connected_component_is_one_cycle() {
        // 0 ⇄ 1 and 2 → 3 → 4 → 2, joined by 1 → 2: two cycles.
        let edges = [(0, 1), (1, 0), (1, 2), (2, 3), (3, 4), (4, 2)];
        assert_eq!(count_cycles(5, &edges), 2);
        // Many back edges in one component still make one cycle.
        let dense = [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)];
        assert_eq!(count_cycles(3, &dense), 1);
    }

    #[test]
    fn a_diamond_is_acyclic() {
        assert_eq!(count_cycles(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]), 0);
    }

    /// A chain deep enough to overflow a recursive search.
    #[test]
    fn a_long_chain_is_acyclic_without_recursion() {
        let len = 1_000_000;
        assert_eq!(count_cycles(len + 1, &chain(len)), 0);
    }

    /// A 2,000,000-edge DAG, built here: every node of a 1,000,001-node
    /// chain also skips one node ahead.
    #[test]
    fn a_two_million_edge_dag_is_acyclic() {
        let nodes = 1_000_001;
        let mut edges = chain(nodes - 1);
        edges.extend((0..nodes - 2).map(|n| (n, n + 2)));
        edges.push((0, nodes - 1));
        assert_eq!(edges.len(), 2_000_000);
        assert_eq!(count_cycles(nodes, &edges), 0);
    }

    /// A 2,000,000-edge graph, built here, whose only cycle closes at its
    /// very end: the old check skipped every graph above 1,000,000 edges.
    #[test]
    fn a_cycle_at_the_end_of_a_two_million_edge_graph_is_found() {
        let len = 1_999_999;
        let mut edges = chain(len);
        edges.push((len, len - 1));
        assert_eq!(edges.len(), 2_000_000);
        assert_eq!(count_cycles(len + 1, &edges), 1);
        // A self-loop on the last node instead.
        edges.pop();
        edges.push((len, len));
        assert_eq!(count_cycles(len + 1, &edges), 1);
    }

    #[test]
    fn the_sbom_count_reads_every_edge_and_dangling_ids() {
        let id = CanonicalId::from_format_id;
        let edge =
            |from: &str, to: &str| DependencyEdge::new(id(from), id(to), DependencyType::DependsOn);
        let mut sbom = NormalizedSbom::default();
        // No component exists for any id: edges alone make the graph.
        sbom.add_edge(edge("app", "lib"));
        sbom.add_edge(edge("lib", "app"));
        sbom.add_edge(edge("lib", "util"));
        sbom.add_edge(DependencyEdge::new(
            id("util"),
            id("util"),
            DependencyType::Contains,
        ));
        assert_eq!(dependency_cycle_count(&sbom), 2);
        assert_eq!(dependency_cycle_count(&NormalizedSbom::default()), 0);
    }
}
