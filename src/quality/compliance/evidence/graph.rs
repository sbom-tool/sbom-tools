//! Dependency-graph facts, kept per component position instead of in sets
//! of ids, so no walk depends on the order of a hash set.

use super::ComponentIx;
use crate::model::{CanonicalId, Component, ComponentType, DependencyType, NormalizedSbom};

/// The dependency-graph facts of an SBOM.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GraphFacts<'a> {
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
    /// Per component: whether a dependency relationship starts at it.
    pub(crate) has_outgoing: Box<[bool]>,
    /// How many dependency relationships start at the primary component,
    /// counting each one, whether or not its target is in the inventory.
    pub(crate) direct_edge_count: usize,
    /// The primary component's direct dependencies that are in the
    /// inventory, in the order of the relationships, each once.
    pub(crate) direct: Box<[ComponentIx]>,
    /// The targets of the primary component's relationships that name no
    /// component, in the order of the relationships.
    pub(crate) unresolved_direct: Box<[&'a CanonicalId]>,
    /// Whether any relationship is a dynamic link, a runtime dependency or
    /// a provided dependency.
    pub(crate) dynamic_edge: bool,
}

impl<'a> GraphFacts<'a> {
    pub(super) fn collect(sbom: &'a NormalizedSbom) -> Self {
        let count = sbom.components.len();
        let primary = sbom
            .primary_component_id
            .as_ref()
            .and_then(|id| sbom.components.get_index_of(id));
        let mut touched = vec![false; count];
        let mut has_incoming = vec![false; count];
        let mut has_outgoing = vec![false; count];
        let mut direct_edge_count = 0;
        let mut direct = Vec::new();
        let mut is_direct = vec![false; if primary.is_some() { count } else { 0 }];
        let mut unresolved_direct = Vec::new();
        let mut dynamic_edge = false;
        for edge in &sbom.edges {
            let from = sbom.components.get_index_of(&edge.from);
            if let Some(from) = from {
                touched[from] = true;
                has_outgoing[from] = true;
            }
            let to = sbom.components.get_index_of(&edge.to);
            if let Some(to) = to {
                touched[to] = true;
                has_incoming[to] = true;
            }
            if from.is_some() && from == primary {
                direct_edge_count += 1;
                match to {
                    Some(to) if !is_direct[to] => {
                        is_direct[to] = true;
                        direct.push(ComponentIx(to));
                    }
                    Some(_) => {}
                    None => unresolved_direct.push(&edge.to),
                }
            }
            dynamic_edge |= matches!(
                edge.relationship,
                DependencyType::DynamicLink
                    | DependencyType::RuntimeDependsOn
                    | DependencyType::ProvidedDependsOn
            );
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
            has_outgoing: has_outgoing.into_boxed_slice(),
            direct_edge_count,
            direct: direct.into_boxed_slice(),
            unresolved_direct: unresolved_direct.into_boxed_slice(),
            dynamic_edge,
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

/// Per component: whether a dependency relationship leads from it to a
/// firmware component.
pub(super) fn firmware_dependencies(sbom: &NormalizedSbom) -> Box<[bool]> {
    let mut depends = vec![false; sbom.components.len()];
    for edge in &sbom.edges {
        let to_firmware = sbom
            .components
            .get(&edge.to)
            .is_some_and(|c| matches!(c.component_type, ComponentType::Firmware));
        if to_firmware && let Some(from) = sbom.components.get_index_of(&edge.from) {
            depends[from] = true;
        }
    }
    depends.into_boxed_slice()
}
