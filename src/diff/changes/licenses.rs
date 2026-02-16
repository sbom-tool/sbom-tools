//! License change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentMatches, LicenseChangeSet};
use crate::diff::LicenseChange;
use crate::model::NormalizedSbom;
use std::collections::HashMap;

/// Computes license-level changes between SBOMs.
pub struct LicenseChangeComputer;

impl LicenseChangeComputer {
    /// Create a new license change computer.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }
}

impl Default for LicenseChangeComputer {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeComputer for LicenseChangeComputer {
    type ChangeSet = LicenseChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        _matches: &ComponentMatches,
    ) -> LicenseChangeSet {
        let mut result = LicenseChangeSet::new();

        // Collect all licenses from old SBOM
        let mut old_licenses: HashMap<String, Vec<String>> = HashMap::new();
        for (_id, comp) in &old.components {
            for lic in &comp.licenses.declared {
                old_licenses
                    .entry(lic.expression.clone())
                    .or_default()
                    .push(comp.name.clone());
            }
        }

        // Collect all licenses from new SBOM
        let mut new_licenses: HashMap<String, Vec<String>> = HashMap::new();
        for (_id, comp) in &new.components {
            for lic in &comp.licenses.declared {
                new_licenses
                    .entry(lic.expression.clone())
                    .or_default()
                    .push(comp.name.clone());
            }
        }

        // Find new licenses
        for (license, components) in &new_licenses {
            if !old_licenses.contains_key(license) {
                result.new_licenses.push(LicenseChange {
                    license: license.clone(),
                    components: components.clone(),
                    family: "Unknown".to_string(), // Would need license analysis
                });
            }
        }

        // Find removed licenses
        for (license, components) in &old_licenses {
            if !new_licenses.contains_key(license) {
                result.removed_licenses.push(LicenseChange {
                    license: license.clone(),
                    components: components.clone(),
                    family: "Unknown".to_string(),
                });
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "LicenseChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_change_computer_default() {
        let computer = LicenseChangeComputer;
        assert_eq!(computer.name(), "LicenseChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = LicenseChangeComputer;
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }
}
