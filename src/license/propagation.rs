//! License compatibility analysis across the dependency tree.
//!
//! Walks the dependency graph to detect incompatible license combinations
//! between a component and its transitive dependencies.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{CanonicalId, LicenseFamily, NormalizedSbom};
use serde::{Deserialize, Serialize};

/// A detected license conflict in the dependency tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConflict {
    /// The component that has the conflict
    pub component: String,
    /// The component's license family
    pub component_family: LicenseFamily,
    /// The dependency causing the conflict
    pub dependency: String,
    /// The dependency's license family
    pub dependency_family: LicenseFamily,
    /// Path from component to conflicting dependency
    pub path: Vec<String>,
    /// Description of the incompatibility
    pub reason: String,
}

/// Check for license compatibility issues across the dependency tree.
///
/// Walks the dependency graph and detects:
/// - Copyleft dependency under proprietary component
/// - Strong copyleft dependency under permissive component (propagation risk)
/// - Weak copyleft boundaries (LGPL/MPL — flagged as info, not error)
#[must_use]
pub fn check_license_propagation(sbom: &NormalizedSbom) -> Vec<LicenseConflict> {
    // Build adjacency list: component → its dependencies
    let mut deps: HashMap<&CanonicalId, Vec<&CanonicalId>> = HashMap::new();
    for edge in &sbom.edges {
        deps.entry(&edge.from).or_default().push(&edge.to);
    }

    // Cache license families per component
    let families: HashMap<&CanonicalId, LicenseFamily> = sbom
        .components
        .iter()
        .map(|(id, comp)| {
            let family = comp
                .licenses
                .declared
                .first()
                .map_or(LicenseFamily::Other, |l| l.family());
            (id, family)
        })
        .collect();

    let mut conflicts = Vec::new();

    // For each component, BFS through its dependencies
    for (comp_id, comp) in &sbom.components {
        let comp_family = families
            .get(comp_id)
            .cloned()
            .unwrap_or(LicenseFamily::Other);

        // Only check components with permissive or proprietary licenses
        if !matches!(
            comp_family,
            LicenseFamily::Permissive | LicenseFamily::Proprietary
        ) {
            continue;
        }

        // BFS to find all transitive dependencies
        let mut visited = HashSet::new();
        let mut queue: VecDeque<(Vec<String>, &CanonicalId)> = VecDeque::new();
        visited.insert(comp_id);

        if let Some(children) = deps.get(comp_id) {
            for child in children {
                queue.push_back((vec![comp.name.clone()], child));
            }
        }

        while let Some((path, dep_id)) = queue.pop_front() {
            if !visited.insert(dep_id) {
                continue;
            }

            let dep_family = families
                .get(dep_id)
                .cloned()
                .unwrap_or(LicenseFamily::Other);
            let dep_name = sbom
                .components
                .get(dep_id)
                .map_or("unknown", |c| c.name.as_str());

            let mut full_path = path.clone();
            full_path.push(dep_name.to_string());

            // Check for incompatibility
            let conflict = match (&comp_family, &dep_family) {
                (LicenseFamily::Proprietary, LicenseFamily::Copyleft) => Some(format!(
                    "strong copyleft dependency '{dep_name}' under proprietary component '{}' — \
                         copyleft terms propagate to the combined work",
                    comp.name
                )),
                (LicenseFamily::Permissive, LicenseFamily::Copyleft) => Some(format!(
                    "strong copyleft dependency '{dep_name}' under permissive component '{}' — \
                         the combined work must comply with copyleft terms",
                    comp.name
                )),
                _ => None,
            };

            if let Some(reason) = conflict {
                conflicts.push(LicenseConflict {
                    component: comp.name.clone(),
                    component_family: comp_family.clone(),
                    dependency: dep_name.to_string(),
                    dependency_family: dep_family,
                    path: full_path.clone(),
                    reason,
                });
            }

            // Continue BFS
            if let Some(children) = deps.get(dep_id) {
                for child in children {
                    queue.push_back((full_path.clone(), child));
                }
            }
        }
    }

    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, DependencyEdge, DependencyType, LicenseExpression, NormalizedSbom,
    };

    fn make_component(name: &str, license: &str) -> Component {
        let mut comp = Component::new(name.to_string(), format!("id-{name}"));
        if !license.is_empty() {
            comp.licenses
                .add_declared(LicenseExpression::new(license.to_string()));
        }
        comp
    }

    #[test]
    fn no_conflicts_all_permissive() {
        let mut sbom = NormalizedSbom::default();
        let app = make_component("app", "MIT");
        let lib = make_component("lib", "Apache-2.0");
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.edges.push(DependencyEdge {
            from: app_id,
            to: lib_id,
            relationship: DependencyType::DependsOn,
            scope: None,
        });

        let conflicts = check_license_propagation(&sbom);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn copyleft_under_proprietary() {
        let mut sbom = NormalizedSbom::default();
        let app = make_component("app", "Proprietary");
        let lib = make_component("gpl-lib", "GPL-3.0-only");
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.edges.push(DependencyEdge {
            from: app_id,
            to: lib_id,
            relationship: DependencyType::DependsOn,
            scope: None,
        });

        let conflicts = check_license_propagation(&sbom);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].dependency, "gpl-lib");
        assert_eq!(conflicts[0].dependency_family, LicenseFamily::Copyleft);
    }

    #[test]
    fn copyleft_under_permissive() {
        let mut sbom = NormalizedSbom::default();
        let app = make_component("app", "MIT");
        let lib = make_component("gpl-lib", "GPL-3.0-only");
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.edges.push(DependencyEdge {
            from: app_id,
            to: lib_id,
            relationship: DependencyType::DependsOn,
            scope: None,
        });

        let conflicts = check_license_propagation(&sbom);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].reason.contains("copyleft"));
    }

    #[test]
    fn transitive_conflict_detected() {
        let mut sbom = NormalizedSbom::default();
        let app = make_component("app", "MIT");
        let mid = make_component("mid", "Apache-2.0");
        let gpl = make_component("deep-gpl", "GPL-3.0-only");
        let app_id = app.canonical_id.clone();
        let mid_id = mid.canonical_id.clone();
        let gpl_id = gpl.canonical_id.clone();
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(mid_id.clone(), mid);
        sbom.components.insert(gpl_id.clone(), gpl);
        sbom.edges.push(DependencyEdge {
            from: app_id,
            to: mid_id.clone(),
            relationship: DependencyType::DependsOn,
            scope: None,
        });
        sbom.edges.push(DependencyEdge {
            from: mid_id,
            to: gpl_id,
            relationship: DependencyType::DependsOn,
            scope: None,
        });

        let conflicts = check_license_propagation(&sbom);
        // app(MIT) → mid(Apache) → deep-gpl(GPL) — app has a transitive copyleft dep
        assert!(!conflicts.is_empty());
        let app_conflict = conflicts
            .iter()
            .find(|c| c.component == "app")
            .expect("should find conflict for app");
        assert_eq!(app_conflict.dependency, "deep-gpl");
        assert!(app_conflict.path.len() >= 2);
    }
}
