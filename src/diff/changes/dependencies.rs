//! Dependency change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentMatches, DependencyChangeSet};
use crate::diff::DependencyChange;
use crate::model::NormalizedSbom;
use std::collections::HashSet;

/// Computes dependency-level changes between SBOMs.
pub struct DependencyChangeComputer;

impl DependencyChangeComputer {
    /// Create a new dependency change computer.
    pub fn new() -> Self {
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

        // Map old edges to their canonical form for comparison
        let mut normalized_old_edges: HashSet<(String, String)> = HashSet::new();
        for edge in &old.edges {
            let from = matches
                .get(&edge.from)
                .and_then(|v| v.as_ref())
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| edge.from.to_string());
            let to = matches
                .get(&edge.to)
                .and_then(|v| v.as_ref())
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| edge.to.to_string());
            normalized_old_edges.insert((from, to));
        }

        // Find added dependencies
        for edge in &new.edges {
            let from = edge.from.to_string();
            let to = edge.to.to_string();
            if !normalized_old_edges.contains(&(from, to)) {
                result.added.push(DependencyChange::added(edge));
            }
        }

        // Map new edges for comparison with old
        let mut normalized_new_edges: HashSet<(String, String)> = HashSet::new();
        for edge in &new.edges {
            normalized_new_edges.insert((edge.from.to_string(), edge.to.to_string()));
        }

        // Find removed dependencies
        for edge in &old.edges {
            let from = matches
                .get(&edge.from)
                .and_then(|v| v.as_ref())
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| edge.from.to_string());
            let to = matches
                .get(&edge.to)
                .and_then(|v| v.as_ref())
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| edge.to.to_string());

            if !normalized_new_edges.contains(&(from, to)) {
                result.removed.push(DependencyChange::removed(edge));
            }
        }

        result
    }

    fn name(&self) -> &str {
        "DependencyChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_change_computer_default() {
        let computer = DependencyChangeComputer::default();
        assert_eq!(computer.name(), "DependencyChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = DependencyChangeComputer::default();
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }
}
