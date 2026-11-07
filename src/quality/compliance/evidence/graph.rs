//! Dependency-graph facts, kept per component position instead of in sets
//! of ids, so no walk depends on the order of a hash set.

use crate::model::{Component, NormalizedSbom};

/// The dependency-graph facts of an SBOM.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GraphFacts {
    /// Per component: whether a dependency relationship names it, at either
    /// end.
    pub(crate) touched: Box<[bool]>,
    /// Per component: whether it positively declares it has no
    /// dependencies (a CycloneDX dependency entry with an empty `dependsOn`,
    /// which the parser marks with a property).
    pub(crate) declares_no_dependencies: Box<[bool]>,
    /// How many components no dependency relationship points at: the roots
    /// of the graph, of every type.
    pub(crate) root_count: usize,
}

impl GraphFacts {
    pub(super) fn collect(sbom: &NormalizedSbom) -> Self {
        let count = sbom.components.len();
        let mut touched = vec![false; count];
        let mut has_incoming = vec![false; count];
        for edge in &sbom.edges {
            if let Some(from) = sbom.components.get_index_of(&edge.from) {
                touched[from] = true;
            }
            if let Some(to) = sbom.components.get_index_of(&edge.to) {
                touched[to] = true;
                has_incoming[to] = true;
            }
        }
        let declares_no_dependencies = sbom
            .components
            .values()
            .map(declares_no_dependencies)
            .collect();
        Self {
            touched: touched.into_boxed_slice(),
            declares_no_dependencies,
            root_count: has_incoming.iter().filter(|incoming| !**incoming).count(),
        }
    }
}

/// Whether `component` positively declares it has no dependencies.
fn declares_no_dependencies(component: &Component) -> bool {
    component
        .extensions
        .properties
        .iter()
        .any(|p| p.name == crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY)
}
