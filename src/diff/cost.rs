//! Cost model for diff operations.

use serde::{Deserialize, Serialize};

/// Cost model configuration for semantic diff operations.
///
/// Costs are used to determine the minimum-cost alignment between two SBOMs.
/// Higher costs indicate more significant changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostModel {
    /// Cost for adding a new component
    pub component_added: u32,
    /// Cost for removing a component
    pub component_removed: u32,
    /// Cost for patch version change
    pub version_patch: u32,
    /// Cost for minor version change
    pub version_minor: u32,
    /// Cost for major version change
    pub version_major: u32,
    /// Cost for license change
    pub license_changed: u32,
    /// Cost for supplier change
    pub supplier_changed: u32,
    /// Cost for introducing a vulnerability
    pub vulnerability_introduced: u32,
    /// Reward (negative cost) for resolving a vulnerability
    pub vulnerability_resolved: i32,
    /// Cost for adding a dependency
    pub dependency_added: u32,
    /// Cost for removing a dependency
    pub dependency_removed: u32,
    /// Cost for hash mismatch (integrity concern)
    pub hash_mismatch: u32,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            component_added: 10,
            component_removed: 10,
            version_patch: 2,
            version_minor: 4,
            version_major: 7,
            license_changed: 6,
            supplier_changed: 4,
            vulnerability_introduced: 15,
            vulnerability_resolved: -3,
            dependency_added: 5,
            dependency_removed: 5,
            hash_mismatch: 8,
        }
    }
}

impl CostModel {
    /// Create a security-focused cost model
    pub fn security_focused() -> Self {
        Self {
            vulnerability_introduced: 25,
            vulnerability_resolved: -5,
            hash_mismatch: 15,
            supplier_changed: 8,
            ..Default::default()
        }
    }

    /// Create a compliance-focused cost model
    pub fn compliance_focused() -> Self {
        Self {
            license_changed: 12,
            supplier_changed: 8,
            ..Default::default()
        }
    }

    /// Get cost for version change based on semver
    pub fn version_change_cost(
        &self,
        old: &Option<semver::Version>,
        new: &Option<semver::Version>,
    ) -> u32 {
        match (old, new) {
            (Some(old_ver), Some(new_ver)) => {
                if old_ver.major != new_ver.major {
                    self.version_major
                } else if old_ver.minor != new_ver.minor {
                    self.version_minor
                } else if old_ver.patch != new_ver.patch {
                    self.version_patch
                } else {
                    0
                }
            }
            (None, Some(_)) | (Some(_), None) => self.version_minor,
            (None, None) => 0,
        }
    }

    /// Calculate total semantic score from change counts
    #[allow(clippy::too_many_arguments)]
    pub fn calculate_semantic_score(
        &self,
        components_added: usize,
        components_removed: usize,
        version_changes: usize,
        license_changes: usize,
        vulns_introduced: usize,
        vulns_resolved: usize,
        deps_added: usize,
        deps_removed: usize,
    ) -> f64 {
        let score = (components_added as u32 * self.component_added)
            + (components_removed as u32 * self.component_removed)
            + (version_changes as u32 * self.version_minor)
            + (license_changes as u32 * self.license_changed)
            + (vulns_introduced as u32 * self.vulnerability_introduced)
            + (deps_added as u32 * self.dependency_added)
            + (deps_removed as u32 * self.dependency_removed);

        let reward = vulns_resolved as i32 * self.vulnerability_resolved;

        (score as i32 + reward) as f64
    }
}
