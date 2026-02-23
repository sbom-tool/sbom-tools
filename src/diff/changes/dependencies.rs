//! Dependency change computer implementation.

use crate::diff::DependencyChange;
use crate::diff::traits::{ChangeComputer, ComponentMatches, DependencyChangeSet};
use crate::model::NormalizedSbom;
use std::collections::HashSet;

/// Computes dependency-level changes between SBOMs.
pub struct DependencyChangeComputer;

impl DependencyChangeComputer {
    /// Create a new dependency change computer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DependencyChangeComputer {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeComputer for DependencyChangeComputer {
    type ChangeSet = DependencyChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
    ) -> DependencyChangeSet {
        let mut result = DependencyChangeSet::new();

        // Edge key includes (from, to, relationship, scope) for full identity comparison
        type EdgeKey = (String, String, String, Option<String>);

        // Map old edges to their canonical form for comparison
        let mut normalized_old_edges: HashSet<EdgeKey> = HashSet::new();
        for edge in &old.edges {
            let from = matches
                .get(&edge.from)
                .and_then(|v| v.as_ref())
                .map_or_else(|| edge.from.to_string(), std::string::ToString::to_string);
            let to = matches
                .get(&edge.to)
                .and_then(|v| v.as_ref())
                .map_or_else(|| edge.to.to_string(), std::string::ToString::to_string);
            normalized_old_edges.insert((
                from,
                to,
                edge.relationship.to_string(),
                edge.scope.as_ref().map(std::string::ToString::to_string),
            ));
        }

        // Find added dependencies
        for edge in &new.edges {
            let key: EdgeKey = (
                edge.from.to_string(),
                edge.to.to_string(),
                edge.relationship.to_string(),
                edge.scope.as_ref().map(std::string::ToString::to_string),
            );
            if !normalized_old_edges.contains(&key) {
                result.added.push(DependencyChange::added(edge));
            }
        }

        // Map new edges for comparison with old
        let mut normalized_new_edges: HashSet<EdgeKey> = HashSet::new();
        for edge in &new.edges {
            normalized_new_edges.insert((
                edge.from.to_string(),
                edge.to.to_string(),
                edge.relationship.to_string(),
                edge.scope.as_ref().map(std::string::ToString::to_string),
            ));
        }

        // Find removed dependencies
        for edge in &old.edges {
            let from = matches
                .get(&edge.from)
                .and_then(|v| v.as_ref())
                .map_or_else(|| edge.from.to_string(), std::string::ToString::to_string);
            let to = matches
                .get(&edge.to)
                .and_then(|v| v.as_ref())
                .map_or_else(|| edge.to.to_string(), std::string::ToString::to_string);

            let key: EdgeKey = (
                from,
                to,
                edge.relationship.to_string(),
                edge.scope.as_ref().map(std::string::ToString::to_string),
            );
            if !normalized_new_edges.contains(&key) {
                result.removed.push(DependencyChange::removed(edge));
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "DependencyChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_change_computer_default() {
        let computer = DependencyChangeComputer;
        assert_eq!(computer.name(), "DependencyChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = DependencyChangeComputer;
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }
}
