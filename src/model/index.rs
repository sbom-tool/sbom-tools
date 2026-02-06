//! Index structures for efficient SBOM querying.
//!
//! This module provides `NormalizedSbomIndex`, a precomputed index for fast
//! lookups and sorting operations on SBOMs. Building the index once avoids
//! repeated O(n) scans and string allocations during TUI operations.
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::model::{NormalizedSbom, NormalizedSbomIndex};
//!
//! let sbom = parse_sbom(&path)?;
//! let index = NormalizedSbomIndex::build(&sbom);
//!
//! // Fast dependency lookup - O(1) instead of O(edges)
//! let deps = index.dependencies_of(&component_id);
//!
//! // Fast case-insensitive name search - O(1) instead of O(components)
//! let matches = index.find_by_name_lower("openssl");
//! ```

use super::{CanonicalId, Component, DependencyEdge, NormalizedSbom};
use std::collections::HashMap;

/// Precomputed index for efficient SBOM queries.
///
/// This index is built once per SBOM and provides O(1) lookups for:
/// - Dependencies of a component (edges by source)
/// - Dependents of a component (edges by target)
/// - Components by lowercased name
/// - Pre-computed sort keys to avoid repeated string allocations
#[derive(Debug, Clone)]
#[must_use]
pub struct NormalizedSbomIndex {
    /// Edge indices by source component ID (for fast dependency lookup)
    edges_by_source: HashMap<CanonicalId, Vec<usize>>,
    /// Edge indices by target component ID (for fast dependent lookup)
    edges_by_target: HashMap<CanonicalId, Vec<usize>>,
    /// Component IDs by lowercased name (for case-insensitive search)
    by_name_lower: HashMap<String, Vec<CanonicalId>>,
    /// Pre-computed sort keys for each component
    sort_keys: HashMap<CanonicalId, ComponentSortKey>,
    /// Total component count
    component_count: usize,
    /// Total edge count
    edge_count: usize,
}

/// Pre-computed lowercase strings for sorting without repeated allocations.
#[derive(Debug, Clone, Default)]
pub struct ComponentSortKey {
    /// Lowercased component name
    pub name_lower: String,
    /// Lowercased version string
    pub version_lower: String,
    /// Lowercased ecosystem name
    pub ecosystem_lower: String,
    /// Lowercased canonical ID
    pub id_lower: String,
    /// Lowercased PURL (if available)
    pub purl_lower: String,
    /// Lowercased group/namespace
    pub group_lower: String,
}

impl ComponentSortKey {
    /// Build sort key from a component
    pub fn from_component(comp: &Component) -> Self {
        Self {
            name_lower: comp.name.to_lowercase(),
            version_lower: comp.version.as_deref().unwrap_or("").to_lowercase(),
            ecosystem_lower: comp
                .ecosystem
                .as_ref()
                .map(|e| e.to_string().to_lowercase())
                .unwrap_or_default(),
            id_lower: comp.canonical_id.value().to_lowercase(),
            purl_lower: comp
                .identifiers
                .purl
                .as_deref()
                .unwrap_or("")
                .to_lowercase(),
            group_lower: comp.group.as_deref().unwrap_or("").to_lowercase(),
        }
    }

    /// Check if any field contains the query (case-insensitive)
    pub fn contains(&self, query_lower: &str) -> bool {
        self.name_lower.contains(query_lower)
            || self.version_lower.contains(query_lower)
            || self.purl_lower.contains(query_lower)
            || self.id_lower.contains(query_lower)
    }

    /// Check if name contains the query
    pub fn name_contains(&self, query_lower: &str) -> bool {
        self.name_lower.contains(query_lower)
    }
}

impl NormalizedSbomIndex {
    /// Build an index from a normalized SBOM.
    ///
    /// This is an O(n + m) operation where n = components and m = edges.
    /// The resulting index provides O(1) lookups.
    pub fn build(sbom: &NormalizedSbom) -> Self {
        let mut edges_by_source: HashMap<CanonicalId, Vec<usize>> = HashMap::new();
        let mut edges_by_target: HashMap<CanonicalId, Vec<usize>> = HashMap::new();
        let mut by_name_lower: HashMap<String, Vec<CanonicalId>> = HashMap::new();
        let mut sort_keys: HashMap<CanonicalId, ComponentSortKey> = HashMap::new();

        // Index edges
        for (idx, edge) in sbom.edges.iter().enumerate() {
            edges_by_source
                .entry(edge.from.clone())
                .or_default()
                .push(idx);
            edges_by_target
                .entry(edge.to.clone())
                .or_default()
                .push(idx);
        }

        // Index components
        for (id, comp) in &sbom.components {
            // Index by lowercased name
            let name_lower = comp.name.to_lowercase();
            by_name_lower
                .entry(name_lower)
                .or_default()
                .push(id.clone());

            // Build sort key
            sort_keys.insert(id.clone(), ComponentSortKey::from_component(comp));
        }

        Self {
            edges_by_source,
            edges_by_target,
            by_name_lower,
            sort_keys,
            component_count: sbom.components.len(),
            edge_count: sbom.edges.len(),
        }
    }

    /// Get edge indices for dependencies of a component (outgoing edges).
    ///
    /// Returns empty slice if component has no dependencies.
    /// O(1) lookup instead of O(edges).
    pub fn dependency_indices(&self, id: &CanonicalId) -> &[usize] {
        self.edges_by_source
            .get(id)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Get edge indices for dependents of a component (incoming edges).
    ///
    /// Returns empty slice if component has no dependents.
    /// O(1) lookup instead of O(edges).
    pub fn dependent_indices(&self, id: &CanonicalId) -> &[usize] {
        self.edges_by_target
            .get(id)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Get dependencies of a component as edges.
    ///
    /// O(k) where k = number of dependencies (much faster than O(edges)).
    pub fn dependencies_of<'a>(
        &self,
        id: &CanonicalId,
        edges: &'a [DependencyEdge],
    ) -> Vec<&'a DependencyEdge> {
        self.dependency_indices(id)
            .iter()
            .filter_map(|&idx| edges.get(idx))
            .collect()
    }

    /// Get dependents of a component as edges.
    ///
    /// O(k) where k = number of dependents (much faster than O(edges)).
    pub fn dependents_of<'a>(
        &self,
        id: &CanonicalId,
        edges: &'a [DependencyEdge],
    ) -> Vec<&'a DependencyEdge> {
        self.dependent_indices(id)
            .iter()
            .filter_map(|&idx| edges.get(idx))
            .collect()
    }

    /// Find component IDs by lowercased name.
    ///
    /// O(1) lookup instead of O(components).
    pub fn find_by_name_lower(&self, name_lower: &str) -> &[CanonicalId] {
        self.by_name_lower
            .get(name_lower)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Find component IDs whose name contains the query (case-insensitive).
    ///
    /// O(unique_names) - still iterates but only over unique lowercased names,
    /// not all components.
    pub fn search_by_name(&self, query_lower: &str) -> Vec<CanonicalId> {
        self.by_name_lower
            .iter()
            .filter(|(name, _)| name.contains(query_lower))
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect()
    }

    /// Get the pre-computed sort key for a component.
    ///
    /// O(1) lookup, avoids repeated to_lowercase() calls during sorting.
    pub fn sort_key(&self, id: &CanonicalId) -> Option<&ComponentSortKey> {
        self.sort_keys.get(id)
    }

    /// Get all sort keys for iteration.
    pub fn sort_keys(&self) -> &HashMap<CanonicalId, ComponentSortKey> {
        &self.sort_keys
    }

    /// Check if component has any dependencies.
    pub fn has_dependencies(&self, id: &CanonicalId) -> bool {
        self.edges_by_source
            .get(id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Check if component has any dependents.
    pub fn has_dependents(&self, id: &CanonicalId) -> bool {
        self.edges_by_target
            .get(id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Get count of dependencies for a component.
    pub fn dependency_count(&self, id: &CanonicalId) -> usize {
        self.edges_by_source
            .get(id)
            .map(std::vec::Vec::len)
            .unwrap_or(0)
    }

    /// Get count of dependents for a component.
    pub fn dependent_count(&self, id: &CanonicalId) -> usize {
        self.edges_by_target.get(id).map(std::vec::Vec::len).unwrap_or(0)
    }

    /// Get total component count.
    pub fn component_count(&self) -> usize {
        self.component_count
    }

    /// Get total edge count.
    pub fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// Get count of root components (no incoming edges).
    pub fn root_count(&self) -> usize {
        self.component_count
            .saturating_sub(self.edges_by_target.len())
            + self
                .edges_by_target
                .values()
                .filter(|v| v.is_empty())
                .count()
    }

    /// Get count of leaf components (no outgoing edges).
    pub fn leaf_count(&self) -> usize {
        self.component_count
            .saturating_sub(self.edges_by_source.len())
            + self
                .edges_by_source
                .values()
                .filter(|v| v.is_empty())
                .count()
    }
}

/// Builder for creating indexes with optional features.
#[derive(Debug, Default)]
#[must_use]
pub struct SbomIndexBuilder {
    /// Whether to build name index
    index_names: bool,
    /// Whether to build sort keys
    build_sort_keys: bool,
}

impl SbomIndexBuilder {
    /// Create a new builder with all features enabled.
    pub fn new() -> Self {
        Self {
            index_names: true,
            build_sort_keys: true,
        }
    }

    /// Create a minimal builder (edges only).
    pub fn minimal() -> Self {
        Self {
            index_names: false,
            build_sort_keys: false,
        }
    }

    /// Enable name indexing.
    pub fn with_name_index(mut self) -> Self {
        self.index_names = true;
        self
    }

    /// Enable sort key building.
    pub fn with_sort_keys(mut self) -> Self {
        self.build_sort_keys = true;
        self
    }

    /// Build the index with configured options.
    pub fn build(&self, sbom: &NormalizedSbom) -> NormalizedSbomIndex {
        let mut edges_by_source: HashMap<CanonicalId, Vec<usize>> = HashMap::new();
        let mut edges_by_target: HashMap<CanonicalId, Vec<usize>> = HashMap::new();
        let mut by_name_lower: HashMap<String, Vec<CanonicalId>> = HashMap::new();
        let mut sort_keys: HashMap<CanonicalId, ComponentSortKey> = HashMap::new();

        // Always index edges
        for (idx, edge) in sbom.edges.iter().enumerate() {
            edges_by_source
                .entry(edge.from.clone())
                .or_default()
                .push(idx);
            edges_by_target
                .entry(edge.to.clone())
                .or_default()
                .push(idx);
        }

        // Optionally index components
        if self.index_names || self.build_sort_keys {
            for (id, comp) in &sbom.components {
                if self.index_names {
                    let name_lower = comp.name.to_lowercase();
                    by_name_lower
                        .entry(name_lower)
                        .or_default()
                        .push(id.clone());
                }

                if self.build_sort_keys {
                    sort_keys.insert(id.clone(), ComponentSortKey::from_component(comp));
                }
            }
        }

        NormalizedSbomIndex {
            edges_by_source,
            edges_by_target,
            by_name_lower,
            sort_keys,
            component_count: sbom.components.len(),
            edge_count: sbom.edges.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DependencyType, DocumentMetadata};

    fn make_test_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        // Add components
        let comp_a = Component::new("ComponentA".to_string(), "comp-a".to_string());
        let comp_b = Component::new("ComponentB".to_string(), "comp-b".to_string());
        let comp_c = Component::new("componentb".to_string(), "comp-c".to_string()); // Same name lowercase

        let id_a = comp_a.canonical_id.clone();
        let id_b = comp_b.canonical_id.clone();
        let id_c = comp_c.canonical_id.clone();

        sbom.add_component(comp_a);
        sbom.add_component(comp_b);
        sbom.add_component(comp_c);

        // Add edges: A -> B, A -> C
        sbom.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_b.clone(),
            DependencyType::DependsOn,
        ));
        sbom.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_c.clone(),
            DependencyType::DependsOn,
        ));

        sbom
    }

    #[test]
    fn test_build_index() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        assert_eq!(index.component_count(), 3);
        assert_eq!(index.edge_count(), 2);
    }

    #[test]
    fn test_dependency_lookup() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        let comp_a_id = sbom.components.keys().next().unwrap();

        // A has 2 dependencies
        assert_eq!(index.dependency_count(comp_a_id), 2);

        // Get actual edges
        let deps = index.dependencies_of(comp_a_id, &sbom.edges);
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_dependent_lookup() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // B and C should have 1 dependent each (A)
        let comp_b_id = sbom.components.keys().nth(1).unwrap();
        assert_eq!(index.dependent_count(comp_b_id), 1);
    }

    #[test]
    fn test_name_lookup() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // "componentb" should match both ComponentB and componentb
        let matches = index.find_by_name_lower("componentb");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_name_search() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Search for "component" should match all 3
        let matches = index.search_by_name("component");
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_sort_keys() {
        let sbom = make_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        let comp_a_id = sbom.components.keys().next().unwrap();
        let sort_key = index.sort_key(comp_a_id).unwrap();

        assert_eq!(sort_key.name_lower, "componenta");
    }

    #[test]
    fn test_sort_key_contains() {
        let mut comp = Component::new("MyPackage".to_string(), "pkg-1".to_string());
        comp.version = Some("1.2.3".to_string());
        let key = ComponentSortKey::from_component(&comp);

        assert!(key.contains("mypack"));
        assert!(key.contains("1.2.3"));
        assert!(!key.contains("notfound"));
    }

    #[test]
    fn test_builder_minimal() {
        let sbom = make_test_sbom();
        let index = SbomIndexBuilder::minimal().build(&sbom);

        // Edges should still be indexed
        assert_eq!(index.edge_count(), 2);

        // But name lookup returns empty (not indexed)
        let matches = index.find_by_name_lower("componenta");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let index = NormalizedSbomIndex::build(&sbom);

        assert_eq!(index.component_count(), 0);
        assert_eq!(index.edge_count(), 0);
    }
}
