//! Trait definitions for diff computation strategies.
//!
//! This module provides abstractions for computing different types of changes,
//! enabling modular and testable diff operations.

use super::{ComponentChange, DependencyChange, LicenseChange, VulnerabilityDetail};
use crate::model::{CanonicalId, NormalizedSbom};
use std::collections::HashMap;

/// Result of matching components between two SBOMs.
pub type ComponentMatches = HashMap<CanonicalId, Option<CanonicalId>>;

/// Trait for computing a specific type of change between SBOMs.
///
/// Implementors provide logic for detecting a particular category of changes
/// (components, dependencies, licenses, vulnerabilities).
pub trait ChangeComputer: Send + Sync {
    /// The type of changes this computer produces.
    type ChangeSet;

    /// Compute changes between old and new SBOMs given component matches.
    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
    ) -> Self::ChangeSet;

    /// Get the name of this change computer for logging/debugging.
    fn name(&self) -> &str;
}

/// Container for component changes (added, removed, modified).
#[derive(Debug, Clone, Default)]
pub struct ComponentChangeSet {
    pub added: Vec<ComponentChange>,
    pub removed: Vec<ComponentChange>,
    pub modified: Vec<ComponentChange>,
}

impl ComponentChangeSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    #[must_use] 
    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

/// Container for dependency changes (added, removed).
#[derive(Debug, Clone, Default)]
pub struct DependencyChangeSet {
    pub added: Vec<DependencyChange>,
    pub removed: Vec<DependencyChange>,
}

impl DependencyChangeSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    #[must_use] 
    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len()
    }
}

/// Container for license changes.
#[derive(Debug, Clone, Default)]
pub struct LicenseChangeSet {
    pub new_licenses: Vec<LicenseChange>,
    pub removed_licenses: Vec<LicenseChange>,
    pub component_changes: Vec<(String, String, String)>, // (component, old_license, new_license)
}

impl LicenseChangeSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.new_licenses.is_empty()
            && self.removed_licenses.is_empty()
            && self.component_changes.is_empty()
    }
}

/// Container for vulnerability changes.
#[derive(Debug, Clone, Default)]
pub struct VulnerabilityChangeSet {
    pub introduced: Vec<VulnerabilityDetail>,
    pub resolved: Vec<VulnerabilityDetail>,
    pub persistent: Vec<VulnerabilityDetail>,
}

impl VulnerabilityChangeSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.introduced.is_empty() && self.resolved.is_empty()
    }

    /// Sort vulnerabilities by severity (critical first).
    pub fn sort_by_severity(&mut self) {
        let severity_order = |s: &str| match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        };

        self.introduced
            .sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
        self.resolved
            .sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_change_set_empty() {
        let set = ComponentChangeSet::new();
        assert!(set.is_empty());
        assert_eq!(set.total(), 0);
    }

    #[test]
    fn test_dependency_change_set_empty() {
        let set = DependencyChangeSet::new();
        assert!(set.is_empty());
        assert_eq!(set.total(), 0);
    }

    #[test]
    fn test_license_change_set_empty() {
        let set = LicenseChangeSet::new();
        assert!(set.is_empty());
    }

    #[test]
    fn test_vulnerability_change_set_empty() {
        let set = VulnerabilityChangeSet::new();
        assert!(set.is_empty());
    }
}
