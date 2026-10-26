//! SBOM enrichment serializer.
//!
//! Injects vulnerability, EOL, and VEX data into the raw SBOM JSON,
//! producing an enriched SBOM in its original format.

use crate::model::{NormalizedSbom, VexJustification, VexState, VexStatus, VulnerabilityRef};
use crate::parsers::cyclonedx_analysis;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::ValueExt;

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

/// The CycloneDX `analysis.state` spelling for a model [`VexState`].
///
/// Every emitted string is a valid CycloneDX `impactAnalysisState` AND parses
/// back to the same model state through the CycloneDX parser (which reads
/// unknown states as `UnderInvestigation`), so VEX suppression survives a
/// round-trip. The previous Debug-lowercase spellings ("notaffected",
/// "underinvestigation") were spec-invalid and round-tripped every state to
/// `UnderInvestigation`, resurfacing suppressed CVEs.
const fn vex_state_cdx_str(state: &VexState) -> &'static str {
    match state {
        VexState::NotAffected => "not_affected",
        VexState::Affected => "exploitable",
        VexState::Fixed => "resolved",
        VexState::UnderInvestigation => "in_triage",
    }
}

/// The CycloneDX `analysis.justification` spelling for a model
/// [`VexJustification`]. Each string round-trips through the parser; the model
/// has no CycloneDX-native `component_not_present`, so `ComponentNotPresent`
/// emits the closest valid claim (`code_not_present`).
const fn vex_justification_cdx_str(justification: &VexJustification) -> &'static str {
    match justification {
        VexJustification::ComponentNotPresent | VexJustification::VulnerableCodeNotPresent => {
            "code_not_present"
        }
        VexJustification::VulnerableCodeNotInExecutePath => "code_not_reachable",
        VexJustification::VulnerableCodeCannotBeControlledByAdversary => "requires_configuration",
        VexJustification::InlineMitigationsAlreadyExist => "protected_by_mitigating_control",
    }
}

/// Build a CycloneDX `analysis` object from a model VEX status.
fn build_cdx_analysis(vex: &VexStatus) -> Value {
    let mut analysis = serde_json::json!({
        "state": vex_state_cdx_str(&vex.status),
    });
    if let Some(justification) = &vex.justification {
        analysis["justification"] = Value::String(vex_justification_cdx_str(justification).into());
    }
    analysis
}

/// KEV / EPSS overlay properties for a vulnerability, surfaced so the enriched
/// output SBOM actually carries the data the `--kev` / `--epss` flags produced
/// (it would otherwise be dropped on serialization).
fn enrichment_properties(vuln: &VulnerabilityRef) -> Vec<Value> {
    let mut props = Vec::new();
    if vuln.is_kev {
        props.push(serde_json::json!({
            "name": "sbom-tools:kev",
            "value": "true",
        }));
        if let Some(kev) = &vuln.kev_info {
            props.push(serde_json::json!({
                "name": "sbom-tools:kev:ransomware",
                "value": kev.known_ransomware_use.to_string(),
            }));
        }
    }
    if let Some(score) = vuln.epss_score {
        props.push(serde_json::json!({
            "name": "sbom-tools:epss:score",
            "value": score.to_string(),
        }));
    }
    props
}

/// A vulnerability aggregated across every component it affects, with the
/// bom-ref to emit per component plus that component's other identifiers
/// (name, purl) for the "already referenced?" check.
struct AggregatedVuln<'a> {
    vuln: &'a VulnerabilityRef,
    /// `(bom-ref to emit, all identifiers of that component)`
    targets: Vec<(String, Vec<String>)>,
}

/// Inject vulnerability data into CycloneDX format.
///
/// MERGES into the input's own `vulnerabilities` array: every field of a
/// pre-existing entry (cwes, source, CVSS score/vector/method,
/// `affects[].versions`, ...) is preserved verbatim, and only data enrichment
/// actually added is appended or patched in. The previous implementation
/// rebuilt the array from the minimal normalized model, silently dropping
/// everything the model doesn't carry.
fn inject_cyclonedx_vulns(doc: &mut Value, sbom: &NormalizedSbom) {
    // Aggregate model vulnerabilities by id: a vulnerability shared by N
    // components becomes ONE entry with N affects refs, not N duplicates.
    let mut aggs: Vec<(String, AggregatedVuln)> = Vec::new();
    let mut agg_index: HashMap<String, usize> = HashMap::new();

    for comp in sbom.components.values() {
        let emit_ref = if comp.identifiers.format_id.is_empty() {
            comp.name.clone()
        } else {
            comp.identifiers.format_id.clone()
        };
        let mut aliases = vec![emit_ref.clone(), comp.name.clone()];
        if let Some(purl) = &comp.identifiers.purl {
            aliases.push(purl.clone());
        }

        for vuln in &comp.vulnerabilities {
            let idx = *agg_index.entry(vuln.id.clone()).or_insert_with(|| {
                aggs.push((
                    vuln.id.clone(),
                    AggregatedVuln {
                        vuln,
                        targets: Vec::new(),
                    },
                ));
                aggs.len() - 1
            });
            let agg = &mut aggs[idx].1;
            // Prefer an occurrence that carries a VEX status so `--vex`
            // overlays are never lost to per-component clone ordering.
            if agg.vuln.vex_status.is_none() && vuln.vex_status.is_some() {
                agg.vuln = vuln;
            }
            if !agg.targets.iter().any(|(r, _)| r == &emit_ref) {
                agg.targets.push((emit_ref.clone(), aliases.clone()));
            }
        }
    }

    // Start from the input's own vulnerabilities array (verbatim baseline).
    let mut vulns: Vec<Value> = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let index_by_id: HashMap<String, usize> = vulns
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            v.get("id")
                .and_then(Value::as_str)
                .map(|id| (id.to_string(), i))
        })
        .collect();

    for (id, agg) in &aggs {
        if let Some(&i) = index_by_id.get(id) {
            patch_existing_vuln(&mut vulns[i], agg);
        } else {
            vulns.push(build_new_vuln(id, agg));
        }
    }

    if !vulns.is_empty() {
        doc["vulnerabilities"] = Value::Array(vulns);
    }
}

/// Patch enrichment data into a pre-existing vulnerability entry without
/// disturbing anything the input already declared.
fn patch_existing_vuln(entry: &mut Value, agg: &AggregatedVuln) {
    let vuln = agg.vuln;
    let Some(obj) = entry.as_object_mut() else {
        return;
    };

    // Fill description / ratings only when absent — never overwrite.
    if !obj.contains_key("description")
        && let Some(desc) = &vuln.description
    {
        obj.insert("description".into(), Value::String(desc.clone()));
    }
    if !obj.contains_key("ratings")
        && let Some(severity) = &vuln.severity
    {
        obj.insert(
            "ratings".into(),
            serde_json::json!([{
                "severity": format!("{severity:?}").to_lowercase(),
            }]),
        );
    }

    // Append affects refs only for components not already referenced by ANY
    // of their identifiers (bom-ref, name, purl) — existing entries (and
    // their `versions`) are left untouched.
    let existing_refs: HashSet<String> = obj
        .get("affects")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("ref").and_then(Value::as_str))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<&String> = agg
        .targets
        .iter()
        .filter(|(_, aliases)| !aliases.iter().any(|alias| existing_refs.contains(alias)))
        .map(|(emit_ref, _)| emit_ref)
        .collect();
    if !missing.is_empty()
        && let Some(affects) = obj
            .entry("affects")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
    {
        for r in missing {
            affects.push(serde_json::json!({ "ref": r }));
        }
    }

    // Analysis: insert when absent; when present, rewrite the state only if
    // enrichment actually changed the parsed status (e.g. a `--vex` overlay),
    // so the input's own spelling ("false_positive", ...) round-trips.
    if let Some(vex) = &vuln.vex_status {
        match obj.get_mut("analysis") {
            None => {
                obj.insert("analysis".into(), build_cdx_analysis(vex));
            }
            Some(analysis) => {
                // The parser's own reading of the state (`cyclonedx_analysis`),
                // to tell whether the entry already expresses the model's
                // status: then the input spelling (e.g. `false_positive`)
                // is kept verbatim instead of being rewritten.
                let current =
                    cyclonedx_analysis::vex_state(analysis.get("state").and_then(Value::as_str));
                if current != vex.status {
                    analysis["state"] = Value::String(vex_state_cdx_str(&vex.status).into());
                    if let Some(justification) = &vex.justification {
                        analysis["justification"] =
                            Value::String(vex_justification_cdx_str(justification).into());
                    }
                }
            }
        }
    }

    // KEV / EPSS overlay properties — append only those not already present.
    let new_props = enrichment_properties(vuln);
    if new_props.is_empty() {
        return;
    }
    let existing_names: HashSet<String> = obj
        .get("properties")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("name").and_then(Value::as_str))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let to_add: Vec<Value> = new_props
        .into_iter()
        .filter(|p| {
            p.get("name")
                .and_then(Value::as_str)
                .is_none_or(|n| !existing_names.contains(n))
        })
        .collect();
    if !to_add.is_empty()
        && let Some(props) = obj
            .entry("properties")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
    {
        props.extend(to_add);
    }
}

/// Build a brand-new vulnerability entry for data enrichment discovered.
fn build_new_vuln(id: &str, agg: &AggregatedVuln) -> Value {
    let vuln = agg.vuln;
    let mut vuln_obj = serde_json::json!({ "id": id });

    if let Some(desc) = &vuln.description {
        vuln_obj["description"] = Value::String(desc.clone());
    }

    if let Some(severity) = &vuln.severity {
        vuln_obj["ratings"] = serde_json::json!([{
            "severity": format!("{severity:?}").to_lowercase(),
        }]);
    }

    let affects: Vec<Value> = agg
        .targets
        .iter()
        .map(|(emit_ref, _)| serde_json::json!({ "ref": emit_ref }))
        .collect();
    vuln_obj["affects"] = Value::Array(affects);

    if let Some(vex) = &vuln.vex_status {
        vuln_obj["analysis"] = build_cdx_analysis(vex);
    }

    let props = enrichment_properties(vuln);
    if !props.is_empty() {
        vuln_obj["properties"] = Value::Array(props);
    }

    vuln_obj
}

/// Inject EOL data as properties on CycloneDX components.
fn inject_cyclonedx_eol(doc: &mut Value, sbom: &NormalizedSbom) {
    if let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut) {
        for comp_val in components {
            let name = comp_val.str_field("name");

            // Find matching component in our model
            let matching = sbom
                .components
                .values()
                .find(|c| c.name == name || c.identifiers.format_id == name);

            if let Some(comp) = matching
                && let Some(eol) = &comp.eol
            {
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

    /// A no-flag enrich run (model parsed straight from the input) must
    /// preserve every pre-existing vulnerability field verbatim: cwes,
    /// source, CVSS score/vector/method, affects[].versions.
    #[test]
    fn enrich_preserves_existing_vuln_fields_verbatim() {
        let raw = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [
                {"bom-ref": "pkg-a", "type": "library", "name": "pkg-a",
                 "version": "1.0.0", "purl": "pkg:npm/pkg-a@1.0.0"}
            ],
            "vulnerabilities": [{
                "id": "CVE-2024-0001",
                "source": {"name": "NVD", "url": "https://nvd.example/CVE-2024-0001"},
                "description": "A bad bug",
                "cwes": [79, 89],
                "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31",
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
                "affects": [{"ref": "pkg-a",
                             "versions": [{"version": "1.0.0", "status": "affected"}]}]
            }]
        }"#;
        let sbom = crate::parsers::parse_sbom_str(raw).unwrap();
        let enriched = enrich_sbom_json(raw, &sbom).unwrap();

        let input: Value = serde_json::from_str(raw).unwrap();
        let output: Value = serde_json::from_str(&enriched).unwrap();
        assert_eq!(
            output["vulnerabilities"], input["vulnerabilities"],
            "no-flag enrichment must not alter pre-existing vulnerability entries"
        );
    }

    /// `--vex` suppression must survive a round-trip: the emitted
    /// analysis.state must be a spelling the parser reads back as the same
    /// state (the old Debug-lowercase "notaffected" parsed as
    /// UnderInvestigation, resurfacing suppressed CVEs).
    #[test]
    fn enrich_vex_states_round_trip_through_parser() {
        use crate::model::{Component, VulnerabilitySource};

        let states = [
            (VexState::NotAffected, "not_affected"),
            (VexState::Affected, "exploitable"),
            (VexState::Fixed, "resolved"),
            (VexState::UnderInvestigation, "in_triage"),
        ];
        for (state, expected) in states {
            let raw = r#"{
                "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                "components": [{"bom-ref": "c", "type": "library", "name": "c", "version": "1.0"}]
            }"#;
            let mut sbom = crate::parsers::parse_sbom_str(raw).unwrap();
            let vuln = VulnerabilityRef::new("CVE-1".into(), VulnerabilitySource::Cve)
                .with_vex_status(VexStatus::new(state.clone()));
            sbom.components.values_mut().for_each(|c: &mut Component| {
                c.vulnerabilities.push(vuln.clone());
            });

            let enriched = enrich_sbom_json(raw, &sbom).unwrap();
            let doc: Value = serde_json::from_str(&enriched).unwrap();
            assert_eq!(
                doc["vulnerabilities"][0]["analysis"]["state"],
                Value::String(expected.into()),
                "emitted state must be the CycloneDX spec spelling"
            );

            let reparsed = crate::parsers::parse_sbom_str(&enriched).unwrap();
            let comp = reparsed.components.values().next().unwrap();
            assert_eq!(
                comp.vulnerabilities[0]
                    .vex_status
                    .as_ref()
                    .expect("vex status must survive round-trip")
                    .status,
                state,
                "state must parse back to the same model state"
            );
        }
    }

    /// Justification must be emitted alongside the state and round-trip.
    #[test]
    fn enrich_vex_justification_round_trips() {
        use crate::model::{Component, VulnerabilitySource};

        let raw = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"bom-ref": "c", "type": "library", "name": "c", "version": "1.0"}]
        }"#;
        let mut sbom = crate::parsers::parse_sbom_str(raw).unwrap();
        let mut vex = VexStatus::new(VexState::NotAffected);
        vex.justification = Some(VexJustification::VulnerableCodeNotInExecutePath);
        let vuln =
            VulnerabilityRef::new("CVE-1".into(), VulnerabilitySource::Cve).with_vex_status(vex);
        sbom.components.values_mut().for_each(|c: &mut Component| {
            c.vulnerabilities.push(vuln.clone());
        });

        let enriched = enrich_sbom_json(raw, &sbom).unwrap();
        let doc: Value = serde_json::from_str(&enriched).unwrap();
        assert_eq!(
            doc["vulnerabilities"][0]["analysis"]["justification"],
            Value::String("code_not_reachable".into()),
        );

        let reparsed = crate::parsers::parse_sbom_str(&enriched).unwrap();
        let comp = reparsed.components.values().next().unwrap();
        assert_eq!(
            comp.vulnerabilities[0]
                .vex_status
                .as_ref()
                .unwrap()
                .justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath),
        );
    }

    /// A VEX overlay that CHANGES the status of a pre-existing entry must
    /// rewrite analysis.state (while an unchanged status leaves the input's
    /// own spelling alone — covered by the verbatim test above, where
    /// "false_positive" style spellings are preserved).
    #[test]
    fn enrich_vex_overlay_updates_existing_analysis() {
        let raw = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"bom-ref": "c", "type": "library", "name": "c", "version": "1.0"}],
            "vulnerabilities": [{
                "id": "CVE-1",
                "affects": [{"ref": "c"}],
                "analysis": {"state": "exploitable"}
            }]
        }"#;
        let mut sbom = crate::parsers::parse_sbom_str(raw).unwrap();
        // Simulate a --vex overlay flipping the status to not_affected.
        for comp in sbom.components.values_mut() {
            for vuln in &mut comp.vulnerabilities {
                vuln.vex_status = Some(VexStatus::new(VexState::NotAffected));
            }
        }

        let enriched = enrich_sbom_json(raw, &sbom).unwrap();
        let doc: Value = serde_json::from_str(&enriched).unwrap();
        assert_eq!(
            doc["vulnerabilities"][0]["analysis"]["state"],
            Value::String("not_affected".into()),
        );
    }

    /// New vulnerabilities from enrichment are appended (deduped by id across
    /// components), and existing entries gain affects refs for newly-found
    /// components without their original affects entries being touched.
    #[test]
    fn enrich_appends_new_vulns_and_patches_affects() {
        use crate::model::VulnerabilitySource;

        let raw = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [
                {"bom-ref": "a", "type": "library", "name": "a", "version": "1.0"},
                {"bom-ref": "b", "type": "library", "name": "b", "version": "2.0"}
            ],
            "vulnerabilities": [{
                "id": "CVE-1",
                "affects": [{"ref": "a", "versions": [{"version": "1.0", "status": "affected"}]}]
            }]
        }"#;
        let mut sbom = crate::parsers::parse_sbom_str(raw).unwrap();
        // Simulate enrichment: CVE-1 also affects b; CVE-2 is newly found on
        // both components.
        for comp in sbom.components.values_mut() {
            if comp.name == "b" {
                comp.vulnerabilities.push(VulnerabilityRef::new(
                    "CVE-1".into(),
                    VulnerabilitySource::Cve,
                ));
            }
            comp.vulnerabilities.push(VulnerabilityRef::new(
                "CVE-2".into(),
                VulnerabilitySource::Cve,
            ));
        }

        let enriched = enrich_sbom_json(raw, &sbom).unwrap();
        let doc: Value = serde_json::from_str(&enriched).unwrap();
        let vulns = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 2, "CVE-2 appended once, not per-component");

        let cve1 = vulns.iter().find(|v| v["id"] == "CVE-1").unwrap();
        let affects = cve1["affects"].as_array().unwrap();
        assert_eq!(affects.len(), 2);
        assert_eq!(
            affects[0]["versions"][0]["version"],
            Value::String("1.0".into()),
            "original affects entry (with versions) preserved verbatim"
        );
        assert_eq!(affects[1]["ref"], Value::String("b".into()));

        let cve2 = vulns.iter().find(|v| v["id"] == "CVE-2").unwrap();
        let refs: Vec<&str> = cve2["affects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["ref"].as_str())
            .collect();
        assert_eq!(refs, vec!["a", "b"]);
    }
}
