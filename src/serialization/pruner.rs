//! SBOM tailoring / filtering.
//!
//! Removes components from an SBOM based on filter criteria,
//! preserving the original format structure.

use crate::model::{LicenseFamily, NormalizedSbom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configuration for SBOM tailoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailorConfig {
    /// Include only components matching these license families
    pub include_license_families: Vec<LicenseFamily>,
    /// Exclude components matching these ecosystems
    pub exclude_ecosystems: Vec<String>,
    /// Include only these component types (library, application, etc.)
    pub include_types: Vec<String>,
    /// Include only components matching this name pattern
    pub include_name_pattern: Option<String>,
    /// Strip vulnerability data from output
    pub strip_vulns: bool,
    /// Strip extension/property data
    pub strip_extensions: bool,
}

/// Tailor (filter) an SBOM by removing components that don't match the criteria.
///
/// Operates on raw JSON to preserve original format structure.
///
/// # Errors
///
/// Returns error if JSON parsing fails.
pub fn tailor_sbom_json(
    raw_json: &str,
    sbom: &NormalizedSbom,
    config: &TailorConfig,
) -> anyhow::Result<String> {
    let mut doc: Value = serde_json::from_str(raw_json)?;

    // Collect component names/IDs to remove
    let mut remove_ids: Vec<String> = Vec::new();

    for comp in sbom.components.values() {
        let mut keep = true;

        // Filter by license family
        if !config.include_license_families.is_empty() {
            let family = comp
                .licenses
                .declared
                .first()
                .map(|l| l.family())
                .unwrap_or(LicenseFamily::Other);
            if !config.include_license_families.contains(&family) {
                keep = false;
            }
        }

        // Filter by ecosystem
        if !config.exclude_ecosystems.is_empty() {
            if let Some(eco) = &comp.ecosystem {
                let eco_str = format!("{eco:?}").to_lowercase();
                if config
                    .exclude_ecosystems
                    .iter()
                    .any(|e| e.to_lowercase() == eco_str)
                {
                    keep = false;
                }
            }
        }

        // Filter by component type
        if !config.include_types.is_empty() {
            let type_str = format!("{:?}", comp.component_type).to_lowercase();
            if !config
                .include_types
                .iter()
                .any(|t| t.to_lowercase() == type_str)
            {
                keep = false;
            }
        }

        // Filter by name pattern
        if let Some(pattern) = &config.include_name_pattern {
            let pattern_lower = pattern.to_lowercase();
            if !comp.name.to_lowercase().contains(&pattern_lower) {
                keep = false;
            }
        }

        if !keep {
            // Track both format_id and name for removal
            if !comp.identifiers.format_id.is_empty() {
                remove_ids.push(comp.identifiers.format_id.clone());
            }
            remove_ids.push(comp.name.clone());
        }
    }

    // Prune from CycloneDX
    if doc.get("bomFormat").is_some() {
        prune_cyclonedx(&mut doc, &remove_ids, config);
    } else if doc.get("@context").is_some() {
        prune_spdx3(&mut doc, &remove_ids, config);
    } else {
        prune_spdx2(&mut doc, &remove_ids, config);
    }

    Ok(serde_json::to_string_pretty(&doc)?)
}

fn prune_cyclonedx(doc: &mut Value, remove_ids: &[String], config: &TailorConfig) {
    // Remove components
    if let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut) {
        components.retain(|comp| {
            let name = comp.get("name").and_then(Value::as_str).unwrap_or("");
            let bom_ref = comp.get("bom-ref").and_then(Value::as_str).unwrap_or("");
            !remove_ids.iter().any(|id| id == name || id == bom_ref)
        });
    }

    // Remove corresponding dependency entries
    if let Some(deps) = doc.get_mut("dependencies").and_then(Value::as_array_mut) {
        deps.retain(|dep| {
            let ref_val = dep.get("ref").and_then(Value::as_str).unwrap_or("");
            !remove_ids.iter().any(|id| id == ref_val)
        });

        // Also remove from dependsOn arrays
        for dep in deps.iter_mut() {
            if let Some(depends_on) = dep.get_mut("dependsOn").and_then(Value::as_array_mut) {
                depends_on.retain(|d| {
                    let s = d.as_str().unwrap_or("");
                    !remove_ids.iter().any(|id| id == s)
                });
            }
        }
    }

    // Strip vulnerabilities if requested
    if config.strip_vulns {
        doc.as_object_mut().map(|o| o.remove("vulnerabilities"));
    }

    // Strip extensions/properties if requested
    if config.strip_extensions {
        if let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut) {
            for comp in components {
                comp.as_object_mut().map(|o| o.remove("properties"));
            }
        }
    }
}

fn prune_spdx3(doc: &mut Value, remove_ids: &[String], config: &TailorConfig) {
    let key = if doc.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let elements = doc.get_mut(key).and_then(Value::as_array_mut);

    if let Some(elems) = elements {
        elems.retain(|elem| {
            let name = elem.get("name").and_then(Value::as_str).unwrap_or("");
            let elem_type = elem.get("type").and_then(Value::as_str).unwrap_or("");

            // Only filter software packages, keep relationships and other elements
            if !elem_type.contains("Package") && !elem_type.contains("package") {
                // If stripping vulns, also remove vulnerability elements
                if config.strip_vulns && elem_type.contains("Vulnerability") {
                    return false;
                }
                return true;
            }

            !remove_ids.iter().any(|id| id == name)
        });
    }
}

fn prune_spdx2(doc: &mut Value, remove_ids: &[String], config: &TailorConfig) {
    // Remove packages
    if let Some(packages) = doc.get_mut("packages").and_then(Value::as_array_mut) {
        packages.retain(|pkg| {
            let name = pkg.get("name").and_then(Value::as_str).unwrap_or("");
            let spdx_id = pkg.get("SPDXID").and_then(Value::as_str).unwrap_or("");
            !remove_ids.iter().any(|id| id == name || id == spdx_id)
        });
    }

    // Remove relationships referencing removed packages
    if let Some(rels) = doc.get_mut("relationships").and_then(Value::as_array_mut) {
        rels.retain(|rel| {
            let elem = rel
                .get("spdxElementId")
                .and_then(Value::as_str)
                .unwrap_or("");
            let related = rel
                .get("relatedSpdxElement")
                .and_then(Value::as_str)
                .unwrap_or("");
            !remove_ids.iter().any(|id| id == elem || id == related)
        });
    }

    if config.strip_vulns {
        doc.as_object_mut().map(|o| o.remove("annotations"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    #[test]
    fn tailor_by_name_pattern() {
        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"keep-me","version":"1.0"},
            {"name":"remove-me","version":"2.0"}
        ]}"#;

        let mut sbom = NormalizedSbom::default();
        let keep = Component::new("keep-me".to_string(), "id-keep".to_string());
        let remove = Component::new("remove-me".to_string(), "id-remove".to_string());
        sbom.components.insert(keep.canonical_id.clone(), keep);
        sbom.components.insert(remove.canonical_id.clone(), remove);

        let config = TailorConfig {
            include_name_pattern: Some("keep".to_string()),
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        assert!(result.contains("keep-me"));
        assert!(!result.contains("remove-me"));
    }

    #[test]
    fn strip_vulns() {
        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"vulnerabilities":[{"id":"CVE-1"}]}"#;
        let sbom = NormalizedSbom::default();
        let config = TailorConfig {
            strip_vulns: true,
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        assert!(!result.contains("vulnerabilities"));
    }
}
