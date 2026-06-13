//! License change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentMatches, LicenseChangeSet};
use crate::diff::{ComponentLicenseChange, LicenseChange};
use crate::model::NormalizedSbom;
use std::collections::{BTreeSet, HashMap};

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

    /// Computes global license-set changes plus per-component license
    /// transitions for matched pairs.
    ///
    /// Only declared licenses are compared: parsers for SPDX documents
    /// populate both declared and concluded, so including concluded would
    /// double-flag the same transition.
    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
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

        // Per-component license transitions for matched pairs
        for (old_id, new_id_opt) in matches {
            if let Some(new_id) = new_id_opt
                && let (Some(old_comp), Some(new_comp)) =
                    (old.components.get(old_id), new.components.get(new_id))
            {
                // Content hash covers declared licenses; equal hashes mean no change
                if old_comp.content_hash == new_comp.content_hash {
                    continue;
                }

                let old_set: BTreeSet<&str> = old_comp
                    .licenses
                    .declared
                    .iter()
                    .map(|lic| lic.expression.as_str())
                    .collect();
                let new_set: BTreeSet<&str> = new_comp
                    .licenses
                    .declared
                    .iter()
                    .map(|lic| lic.expression.as_str())
                    .collect();

                if old_set != new_set {
                    result.component_changes.push(ComponentLicenseChange {
                        component_id: new_id.to_string(),
                        component_name: new_comp.name.clone(),
                        old_licenses: old_set.into_iter().map(String::from).collect(),
                        new_licenses: new_set.into_iter().map(String::from).collect(),
                    });
                }
            }
        }

        result.component_changes.sort_by(|a, b| {
            (&a.component_name, &a.component_id).cmp(&(&b.component_name, &b.component_id))
        });

        result
    }

    fn name(&self) -> &'static str {
        "LicenseChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, LicenseExpression};

    fn component_with_licenses(name: &str, format_id: &str, licenses: &[&str]) -> Component {
        let mut comp = Component::new(name.to_string(), format_id.to_string());
        for lic in licenses {
            comp.licenses
                .add_declared(LicenseExpression::new((*lic).to_string()));
        }
        // Mirror parser behavior: the hash-skip guard requires real hashes
        comp.calculate_content_hash();
        comp
    }

    fn sbom_with(components: Vec<Component>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for comp in components {
            sbom.add_component(comp);
        }
        sbom
    }

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

    #[test]
    fn matched_pair_license_transition() {
        let old_comp = component_with_licenses("a", "a@1.0", &["MIT"]);
        let new_comp = component_with_licenses("a", "a@1.0", &["GPL-3.0-only"]);
        let mut matches = ComponentMatches::new();
        matches.insert(
            old_comp.canonical_id.clone(),
            Some(new_comp.canonical_id.clone()),
        );
        let old = sbom_with(vec![old_comp]);
        let new = sbom_with(vec![new_comp]);

        let result = LicenseChangeComputer::new().compute(&old, &new, &matches);

        assert_eq!(result.component_changes.len(), 1);
        let change = &result.component_changes[0];
        assert_eq!(change.component_name, "a");
        assert_eq!(change.old_licenses, vec!["MIT".to_string()]);
        assert_eq!(change.new_licenses, vec!["GPL-3.0-only".to_string()]);
        assert_eq!(result.new_licenses.len(), 1);
        assert_eq!(result.new_licenses[0].license, "GPL-3.0-only");
        assert_eq!(result.removed_licenses.len(), 1);
        assert_eq!(result.removed_licenses[0].license, "MIT");
    }

    #[test]
    fn renamed_but_matched_component_included() {
        let old_comp = component_with_licenses("a-old", "a-old@1.0", &["MIT"]);
        let new_comp = component_with_licenses("a-new", "a-new@1.0", &["Apache-2.0"]);
        let mut matches = ComponentMatches::new();
        matches.insert(
            old_comp.canonical_id.clone(),
            Some(new_comp.canonical_id.clone()),
        );
        let new_id = new_comp.canonical_id.clone();
        let old = sbom_with(vec![old_comp]);
        let new = sbom_with(vec![new_comp]);

        let result = LicenseChangeComputer::new().compute(&old, &new, &matches);

        assert_eq!(result.component_changes.len(), 1);
        assert_eq!(result.component_changes[0].component_name, "a-new");
        assert_eq!(result.component_changes[0].component_id, new_id.to_string());
    }

    #[test]
    fn unmatched_add_remove_not_in_component_changes() {
        let old_comp = component_with_licenses("a", "a@1.0", &["MIT"]);
        let new_comp = component_with_licenses("b", "b@1.0", &["Apache-2.0"]);
        let mut matches = ComponentMatches::new();
        matches.insert(old_comp.canonical_id.clone(), None);
        let old = sbom_with(vec![old_comp]);
        let new = sbom_with(vec![new_comp]);

        let result = LicenseChangeComputer::new().compute(&old, &new, &matches);

        assert!(result.component_changes.is_empty());
        assert_eq!(result.new_licenses.len(), 1);
        assert_eq!(result.removed_licenses.len(), 1);
    }

    #[test]
    fn identical_license_sets_not_reported() {
        let old_comp = component_with_licenses("a", "a@1.0", &["MIT"]);
        let mut new_comp = component_with_licenses("a", "a@1.0", &["MIT"]);
        new_comp.version = Some("2.0.0".to_string());
        new_comp.calculate_content_hash();
        let mut matches = ComponentMatches::new();
        matches.insert(
            old_comp.canonical_id.clone(),
            Some(new_comp.canonical_id.clone()),
        );
        let old = sbom_with(vec![old_comp]);
        let new = sbom_with(vec![new_comp]);

        let result = LicenseChangeComputer::new().compute(&old, &new, &matches);

        assert!(result.component_changes.is_empty());
    }
}
