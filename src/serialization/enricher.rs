//! SBOM enrichment serializer.
//!
//! Injects vulnerability, EOL, and VEX data into the raw SBOM JSON,
//! producing an enriched SBOM in its original format.

use crate::model::NormalizedSbom;
use serde_json::Value;

/// Enrich a raw SBOM JSON with vulnerability and EOL data from the parsed model.
///
/// Takes the raw JSON content and the enriched `NormalizedSbom`, then injects
/// vulnerability and EOL data back into the original JSON structure.
///
/// # Errors
///
/// Returns error if JSON parsing or injection fails.
pub fn enrich_sbom_json(raw_json: &str, sbom: &NormalizedSbom) -> anyhow::Result<String> {
    let mut doc: Value = serde_json::from_str(raw_json)?;

    // Detect format
    let is_cyclonedx = doc.get("bomFormat").is_some();
    let is_spdx3 = doc.get("@context").is_some();

    if is_cyclonedx {
        inject_cyclonedx_vulns(&mut doc, sbom);
        inject_cyclonedx_eol(&mut doc, sbom);
    } else if is_spdx3 {
        inject_spdx3_vulns(&mut doc, sbom);
    } else {
        // SPDX 2.x — add external document refs for vuln data
        inject_spdx2_annotations(&mut doc, sbom);
    }

    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Inject vulnerability data into CycloneDX format.
///
/// Adds/updates the top-level `vulnerabilities` array.
fn inject_cyclonedx_vulns(doc: &mut Value, sbom: &NormalizedSbom) {
    let mut vulns = Vec::new();

    for comp in sbom.components.values() {
        for vuln in &comp.vulnerabilities {
            let mut vuln_obj = serde_json::json!({
                "id": vuln.id,
            });

            if let Some(desc) = &vuln.description {
                vuln_obj["description"] = Value::String(desc.clone());
            }

            if let Some(severity) = &vuln.severity {
                vuln_obj["ratings"] = serde_json::json!([{
                    "severity": format!("{severity:?}").to_lowercase(),
                }]);
            }

            // Link to affected component via bom-ref
            let bom_ref = if comp.identifiers.format_id.is_empty() {
                &comp.name
            } else {
                &comp.identifiers.format_id
            };
            vuln_obj["affects"] = serde_json::json!([{
                "ref": bom_ref,
            }]);

            if let Some(vex) = &vuln.vex_status {
                vuln_obj["analysis"] = serde_json::json!({
                    "state": format!("{:?}", vex.status).to_lowercase(),
                });
            }

            vulns.push(vuln_obj);
        }
    }

    if !vulns.is_empty() {
        doc["vulnerabilities"] = Value::Array(vulns);
    }
}

/// Inject EOL data as properties on CycloneDX components.
fn inject_cyclonedx_eol(doc: &mut Value, sbom: &NormalizedSbom) {
    if let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut) {
        for comp_val in components {
            let name = comp_val.get("name").and_then(Value::as_str).unwrap_or("");

            // Find matching component in our model
            let matching = sbom
                .components
                .values()
                .find(|c| c.name == name || c.identifiers.format_id == name);

            if let Some(comp) = matching {
                if let Some(eol) = &comp.eol {
                    let properties = comp_val.as_object_mut().and_then(|o| {
                        o.entry("properties")
                            .or_insert_with(|| Value::Array(Vec::new()))
                            .as_array_mut()
                    });
                    if let Some(props) = properties {
                        props.push(serde_json::json!({
                            "name": "sbom-tools:eol:status",
                            "value": format!("{:?}", eol.status),
                        }));
                        props.push(serde_json::json!({
                            "name": "sbom-tools:eol:product",
                            "value": eol.product,
                        }));
                        if let Some(date) = eol.eol_date {
                            props.push(serde_json::json!({
                                "name": "sbom-tools:eol:date",
                                "value": date.to_string(),
                            }));
                        }
                    }
                }
            }
        }
    }
}

/// Inject vulnerability data into SPDX 3.0 as security elements.
fn inject_spdx3_vulns(doc: &mut Value, sbom: &NormalizedSbom) {
    let key = if doc.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let elements = doc.get_mut(key).and_then(Value::as_array_mut);

    if let Some(elems) = elements {
        for comp in sbom.components.values() {
            for vuln in &comp.vulnerabilities {
                elems.push(serde_json::json!({
                    "type": "security_Vulnerability",
                    "spdxId": format!("urn:sbom-tools:vuln:{}", vuln.id),
                    "name": vuln.id,
                    "summary": vuln.description.as_deref().unwrap_or(""),
                    "externalIdentifier": [{
                        "externalIdentifierType": "cpe",
                        "identifier": vuln.id,
                    }],
                }));
            }
        }
    }
}

/// Inject vulnerability data into SPDX 2.x as annotations.
fn inject_spdx2_annotations(doc: &mut Value, sbom: &NormalizedSbom) {
    let annotations = doc.as_object_mut().and_then(|o| {
        o.entry("annotations")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
    });

    if let Some(annots) = annotations {
        for comp in sbom.components.values() {
            for vuln in &comp.vulnerabilities {
                annots.push(serde_json::json!({
                    "annotator": "Tool: sbom-tools",
                    "annotationDate": chrono::Utc::now().to_rfc3339(),
                    "annotationType": "REVIEW",
                    "comment": format!(
                        "Vulnerability {}: {}",
                        vuln.id,
                        vuln.description.as_deref().unwrap_or("No summary")
                    ),
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_empty_cyclonedx() {
        let raw = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}"#;
        let sbom = NormalizedSbom::default();
        let result = enrich_sbom_json(raw, &sbom).unwrap();
        assert!(result.contains("bomFormat"));
    }

    #[test]
    fn enrich_empty_spdx() {
        let raw = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let sbom = NormalizedSbom::default();
        let result = enrich_sbom_json(raw, &sbom).unwrap();
        assert!(result.contains("spdxVersion"));
    }
}
