//! SBOM merging.
//!
//! Combines multiple SBOMs into a single document, deduplicating
//! components based on configurable strategies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

/// Configuration for SBOM merging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeConfig {
    /// Deduplication strategy
    pub dedup_strategy: DeduplicationStrategy,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            dedup_strategy: DeduplicationStrategy::Name,
        }
    }
}

/// Strategy for deduplicating components during merge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeduplicationStrategy {
    /// Deduplicate by package name + version
    Name,
    /// Deduplicate by PURL (exact match)
    Purl,
    /// Keep all components (no dedup)
    None,
}

/// Merge two SBOM JSON documents into one.
///
/// The primary SBOM provides the document metadata; components from both
/// are merged with deduplication.
///
/// Both SBOMs must be the same format (CycloneDX or SPDX).
///
/// # Errors
///
/// Returns error if the SBOMs are different formats or JSON parsing fails.
pub fn merge_sbom_json(
    primary_json: &str,
    secondary_json: &str,
    config: &MergeConfig,
) -> anyhow::Result<String> {
    let mut primary: Value = serde_json::from_str(primary_json)?;
    let secondary: Value = serde_json::from_str(secondary_json)?;

    let primary_is_cdx = primary.get("bomFormat").is_some();
    let secondary_is_cdx = secondary.get("bomFormat").is_some();
    let primary_is_spdx3 = primary.get("@context").is_some();
    let secondary_is_spdx3 = secondary.get("@context").is_some();

    // Verify same format family
    if primary_is_cdx != secondary_is_cdx {
        anyhow::bail!("cannot merge CycloneDX and SPDX SBOMs — both must be the same format");
    }

    if primary_is_cdx {
        merge_cyclonedx(&mut primary, &secondary, config)?;
    } else if primary_is_spdx3 {
        if !secondary_is_spdx3 {
            anyhow::bail!("cannot merge SPDX 3.0 and SPDX 2.x SBOMs");
        }
        merge_spdx3(&mut primary, &secondary, config)?;
    } else {
        merge_spdx2(&mut primary, &secondary, config)?;
    }

    Ok(serde_json::to_string_pretty(&primary)?)
}

fn merge_cyclonedx(
    primary: &mut Value,
    secondary: &Value,
    config: &MergeConfig,
) -> anyhow::Result<()> {
    let primary_components = primary.get_mut("components").and_then(Value::as_array_mut);

    let secondary_components = secondary.get("components").and_then(Value::as_array);

    if let (Some(p_comps), Some(s_comps)) = (primary_components, secondary_components) {
        if config.dedup_strategy == DeduplicationStrategy::None {
            // No deduplication — keep all components
            for comp in s_comps {
                p_comps.push(comp.clone());
            }
        } else {
            // Build dedup set from primary
            let mut seen = build_seen_set(p_comps, config);

            // Add non-duplicate components from secondary
            for comp in s_comps {
                let key = component_key(comp, config);
                if seen.insert(key) {
                    p_comps.push(comp.clone());
                }
            }
        }
    }

    // Merge dependencies
    let primary_deps = primary
        .get_mut("dependencies")
        .and_then(Value::as_array_mut);

    let secondary_deps = secondary.get("dependencies").and_then(Value::as_array);

    if let (Some(p_deps), Some(s_deps)) = (primary_deps, secondary_deps) {
        let existing_refs: HashSet<String> = p_deps
            .iter()
            .filter_map(|d| d.get("ref").and_then(Value::as_str).map(String::from))
            .collect();

        for dep in s_deps {
            let dep_ref = dep.get("ref").and_then(Value::as_str).unwrap_or("");
            if !existing_refs.contains(dep_ref) {
                p_deps.push(dep.clone());
            }
        }
    }

    // Merge vulnerabilities
    merge_array_field(primary, secondary, "vulnerabilities");

    Ok(())
}

fn merge_spdx3(primary: &mut Value, secondary: &Value, config: &MergeConfig) -> anyhow::Result<()> {
    let primary_key = if primary.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let primary_elements = primary.get_mut(primary_key).and_then(Value::as_array_mut);

    let secondary_key = if secondary.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let secondary_elements = secondary.get(secondary_key).and_then(Value::as_array);

    if let (Some(p_elems), Some(s_elems)) = (primary_elements, secondary_elements) {
        let mut seen: HashSet<String> = p_elems
            .iter()
            .filter_map(|e| e.get("spdxId").and_then(Value::as_str).map(String::from))
            .collect();

        for elem in s_elems {
            let spdx_id = elem.get("spdxId").and_then(Value::as_str).unwrap_or("");

            // For packages, apply dedup logic
            let elem_type = elem.get("type").and_then(Value::as_str).unwrap_or("");
            if elem_type.contains("Package") || elem_type.contains("package") {
                let key = component_key(elem, config);
                if !seen.insert(key) {
                    continue;
                }
            } else if !seen.insert(spdx_id.to_string()) {
                continue;
            }

            p_elems.push(elem.clone());
        }
    }

    Ok(())
}

fn merge_spdx2(primary: &mut Value, secondary: &Value, config: &MergeConfig) -> anyhow::Result<()> {
    // Merge packages
    if let (Some(p_pkgs), Some(s_pkgs)) = (
        primary.get_mut("packages").and_then(Value::as_array_mut),
        secondary.get("packages").and_then(Value::as_array),
    ) {
        if config.dedup_strategy == DeduplicationStrategy::None {
            for pkg in s_pkgs {
                p_pkgs.push(pkg.clone());
            }
        } else {
            let mut seen = build_seen_set(p_pkgs, config);
            for pkg in s_pkgs {
                let key = component_key(pkg, config);
                if seen.insert(key) {
                    p_pkgs.push(pkg.clone());
                }
            }
        }
    }

    // Merge relationships
    merge_array_field(primary, secondary, "relationships");

    Ok(())
}

/// Build a set of dedup keys from existing components
fn build_seen_set(components: &[Value], config: &MergeConfig) -> HashSet<String> {
    components
        .iter()
        .map(|c| component_key(c, config))
        .collect()
}

/// Generate a deduplication key for a component
fn component_key(comp: &Value, config: &MergeConfig) -> String {
    match config.dedup_strategy {
        DeduplicationStrategy::Purl => {
            // Try purl field directly
            if let Some(purl) = comp.get("purl").and_then(Value::as_str) {
                return purl.to_string();
            }
            // Try externalReferences for PURL
            if let Some(refs) = comp.get("externalReferences").and_then(Value::as_array) {
                for r in refs {
                    if r.get("type").and_then(Value::as_str) == Some("purl") {
                        if let Some(url) = r.get("url").and_then(Value::as_str) {
                            return url.to_string();
                        }
                    }
                }
            }
            // Fall back to name-version
            name_version_key(comp)
        }
        DeduplicationStrategy::Name | DeduplicationStrategy::None => name_version_key(comp),
    }
}

fn name_version_key(comp: &Value) -> String {
    let name = comp.get("name").and_then(Value::as_str).unwrap_or("");
    let version = comp
        .get("version")
        .or_else(|| comp.get("versionInfo"))
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}@{version}")
}

/// Merge an array field from secondary into primary (append new entries)
fn merge_array_field(primary: &mut Value, secondary: &Value, field: &str) {
    if let Some(s_arr) = secondary.get(field).and_then(Value::as_array) {
        let p_arr = primary.as_object_mut().and_then(|o| {
            o.entry(field)
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
        });
        if let Some(p) = p_arr {
            for item in s_arr {
                p.push(item.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_cyclonedx_dedup() {
        let primary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"},
            {"name":"bar","version":"2.0"}
        ]}"#;

        let secondary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"},
            {"name":"baz","version":"3.0"}
        ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 3); // foo, bar, baz (foo deduped)
    }

    #[test]
    fn merge_different_formats_fails() {
        let cdx = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
        let spdx = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}"#;

        let result = merge_sbom_json(cdx, spdx, &MergeConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn merge_no_dedup() {
        let a = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"}
        ]}"#;
        let b = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"}
        ]}"#;

        let config = MergeConfig {
            dedup_strategy: DeduplicationStrategy::None,
        };
        let result = merge_sbom_json(a, b, &config).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        // None strategy keeps all components, including duplicates
        assert_eq!(components.len(), 2);
    }
}
