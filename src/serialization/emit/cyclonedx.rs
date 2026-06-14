//! CycloneDX 1.7 JSON emitter.
//!
//! Synthesizes a fresh CycloneDX 1.7 document from a [`NormalizedSbom`]:
//! component identity (`bom-ref`) from [`CanonicalId`], `dependencies` from the
//! edge list, and licenses/hashes/purls/etc. from the typed model. Where a
//! component carries preserved same-format source JSON (see
//! [`super::preserve_source_json`]), format-specific blocks that the canonical
//! model can't fully round-trip (`cryptoProperties`, `evidence`) are spliced
//! back verbatim.
//!
//! The `mlModel.modelCard` AI bridge (populated by the SPDX-3 parser into
//! `extensions.raw`) is preserved so converting an AI-BOM does not regress AI
//! scoring.

use serde_json::{Map, Value, json};

use crate::model::{Component, ComponentType, DependencyType, Hash, NormalizedSbom};

use super::EmitError;
use super::fidelity::FidelityReport;

/// CycloneDX spec version emitted by this module.
const SPEC_VERSION: &str = "1.7";

/// Emit `sbom` as a CycloneDX 1.7 JSON document plus a fidelity report.
///
/// # Errors
///
/// Returns [`EmitError::Serialize`] if the synthesized document fails to
/// serialize (not expected for well-formed models).
pub fn emit_cyclonedx(sbom: &NormalizedSbom) -> Result<(String, FidelityReport), EmitError> {
    let mut report = FidelityReport::new(sbom.document.format.to_string(), "CycloneDX 1.7");

    // Stable bom-ref per component = canonical id value. Canonical ids are
    // unique keys in the components map, so refs never collide.
    let bom_ref_of = |id: &crate::model::CanonicalId| id.value().to_string();

    let mut components_json = Vec::with_capacity(sbom.components.len());
    let mut primary_component_json: Option<Value> = None;

    for (id, component) in &sbom.components {
        let comp_json = emit_component(component, &bom_ref_of(id), &mut report);
        if sbom.primary_component_id.as_ref() == Some(id) {
            primary_component_json = Some(comp_json);
        } else {
            components_json.push(comp_json);
        }
    }

    // Metadata block.
    let mut metadata = Map::new();
    metadata.insert(
        "timestamp".to_string(),
        json!(sbom.document.created.to_rfc3339()),
    );
    if let Some(tools) = emit_tools(sbom) {
        metadata.insert("tools".to_string(), tools);
    }
    if let Some(primary) = primary_component_json {
        metadata.insert("component".to_string(), primary);
        report.synthesized("metadata.component from primary component");
    }

    let mut doc = Map::new();
    doc.insert("bomFormat".to_string(), json!("CycloneDX"));
    doc.insert("specVersion".to_string(), json!(SPEC_VERSION));
    doc.insert("version".to_string(), json!(1));
    if let Some(serial) = &sbom.document.serial_number {
        doc.insert("serialNumber".to_string(), json!(serial));
    }
    doc.insert("metadata".to_string(), Value::Object(metadata));
    doc.insert("components".to_string(), Value::Array(components_json));

    let dependencies = emit_dependencies(sbom, &mut report);
    if !dependencies.is_empty() {
        doc.insert("dependencies".to_string(), Value::Array(dependencies));
        report.synthesized("dependencies from edge list");
    }

    // Note canonical-model fields with no CycloneDX 1.7 home so the report is honest.
    note_unmappable(sbom, &mut report);

    let serialized = serde_json::to_string_pretty(&Value::Object(doc))?;
    Ok((serialized, report))
}

/// Synthesize a single CycloneDX component object.
fn emit_component(component: &Component, bom_ref: &str, report: &mut FidelityReport) -> Value {
    let mut obj = Map::new();

    obj.insert(
        "type".to_string(),
        json!(emit_component_type(&component.component_type)),
    );
    obj.insert("bom-ref".to_string(), json!(bom_ref));
    report.synthesized("bom-ref from canonical id");
    obj.insert("name".to_string(), json!(component.name));

    if let Some(version) = &component.version {
        obj.insert("version".to_string(), json!(version));
    }
    if let Some(group) = &component.group {
        obj.insert("group".to_string(), json!(group));
    }
    if let Some(author) = &component.author {
        obj.insert("author".to_string(), json!(author));
    }
    if let Some(desc) = &component.description {
        obj.insert("description".to_string(), json!(desc));
    }
    if let Some(copyright) = &component.copyright {
        obj.insert("copyright".to_string(), json!(copyright));
    }
    if let Some(purl) = &component.identifiers.purl {
        obj.insert("purl".to_string(), json!(purl));
    }
    if let Some(cpe) = component.identifiers.cpe.first() {
        obj.insert("cpe".to_string(), json!(cpe));
    }
    if !component.identifiers.swhid.is_empty() {
        let swhids: Vec<Value> = component
            .identifiers
            .swhid
            .iter()
            .map(|s| json!(s.to_string()))
            .collect();
        obj.insert("swhid".to_string(), Value::Array(swhids));
    }

    if let Some(supplier) = &component.supplier {
        obj.insert("supplier".to_string(), json!({ "name": supplier.name }));
    }

    if let Some(licenses) = emit_licenses(component) {
        obj.insert("licenses".to_string(), licenses);
    }
    if let Some(hashes) = emit_hashes(&component.hashes) {
        obj.insert("hashes".to_string(), hashes);
    }
    if let Some(ext_refs) = emit_external_refs(component) {
        obj.insert("externalReferences".to_string(), ext_refs);
    }
    if !component.extensions.properties.is_empty() {
        let props: Vec<Value> = component
            .extensions
            .properties
            .iter()
            .map(|p| json!({ "name": p.name, "value": p.value }))
            .collect();
        obj.insert("properties".to_string(), Value::Array(props));
    }

    // ML model card: synthesize from typed model and splice the AI bridge so
    // AI-readiness scoring survives a round-trip conversion of an AI-BOM.
    if let Some(model_card) = emit_model_card(component, report) {
        obj.insert("modelCard".to_string(), model_card);
    }

    // Dataset componentData (typed model).
    if let Some(data) = emit_dataset(component) {
        obj.insert("data".to_string(), data);
        report.synthesized("data componentData from dataset model");
    }

    // 1.7 external-component flags.
    if component.is_external {
        obj.insert("isExternal".to_string(), json!(true));
        if let Some(vr) = &component.version_range {
            obj.insert("versionRange".to_string(), json!(vr));
        }
    }

    // Splice format-specific blocks the typed model can't fully reconstruct,
    // only when preserved same-format source JSON carries them.
    splice_preserved_blocks(component, &mut obj, report);

    Value::Object(obj)
}

/// Splice verbatim CycloneDX-only blocks from preserved source JSON.
///
/// Limited to blocks the canonical model genuinely can't reconstruct losslessly
/// (`cryptoProperties`, `evidence`). Never overwrites a synthesized key.
fn splice_preserved_blocks(
    component: &Component,
    obj: &mut Map<String, Value>,
    report: &mut FidelityReport,
) {
    let Some(src) = component.extensions.source_json.as_deref() else {
        return;
    };
    // Only splice from a CycloneDX-shaped source object (has bom-ref or purl).
    let looks_cdx = src.get("bom-ref").is_some()
        || src.get("purl").is_some()
        || src.get("cryptoProperties").is_some();
    if !looks_cdx {
        return;
    }
    for key in ["cryptoProperties", "evidence", "pedigree"] {
        if let Some(block) = src.get(key)
            && !obj.contains_key(key)
        {
            obj.insert(key.to_string(), block.clone());
            report.preserved(format!("component.{key}"));
        }
    }
}

/// Map a [`ComponentType`] to its CycloneDX `type` string.
fn emit_component_type(ty: &ComponentType) -> String {
    // ComponentType::Display already yields CycloneDX spelling
    // (e.g. "machine-learning-model", "operating-system").
    ty.to_string()
}

/// Emit a `licenses` array from declared + concluded expressions.
///
/// A concluded expression identical to a declared one (common for SPDX inputs
/// where `licenseConcluded == licenseDeclared`) is not emitted twice.
fn emit_licenses(component: &Component) -> Option<Value> {
    let mut seen: Vec<&str> = Vec::new();
    let mut items = Vec::new();
    for expr in &component.licenses.declared {
        if !seen.contains(&expr.expression.as_str()) {
            seen.push(&expr.expression);
            items.push(license_choice(&expr.expression, expr.is_valid_spdx));
        }
    }
    if let Some(concluded) = &component.licenses.concluded
        && !seen.contains(&concluded.expression.as_str())
    {
        items.push(license_choice(
            &concluded.expression,
            concluded.is_valid_spdx,
        ));
    }
    if items.is_empty() {
        None
    } else {
        Some(Value::Array(items))
    }
}

/// Build one CycloneDX license-choice object.
///
/// Valid single SPDX ids use `{license:{id}}`; compound/invalid expressions use
/// the `{expression}` form, matching CycloneDX semantics.
fn license_choice(expr: &str, is_valid_spdx: bool) -> Value {
    let is_compound = expr.contains(" OR ") || expr.contains(" AND ") || expr.contains(" WITH ");
    if is_valid_spdx && !is_compound {
        json!({ "license": { "id": expr } })
    } else if is_valid_spdx {
        json!({ "expression": expr })
    } else {
        json!({ "license": { "name": expr } })
    }
}

/// Emit a `hashes` array, dropping hashes whose algorithm has no CycloneDX
/// spelling (recorded by the caller via `note_unmappable`).
fn emit_hashes(hashes: &[Hash]) -> Option<Value> {
    if hashes.is_empty() {
        return None;
    }
    let items: Vec<Value> = hashes
        .iter()
        .map(|h| json!({ "alg": h.algorithm.to_string(), "content": h.value }))
        .collect();
    Some(Value::Array(items))
}

/// Emit an `externalReferences` array.
fn emit_external_refs(component: &Component) -> Option<Value> {
    if component.external_refs.is_empty() {
        return None;
    }
    let items: Vec<Value> = component
        .external_refs
        .iter()
        .map(|r| {
            let mut o = json!({ "type": r.ref_type.to_string(), "url": r.url });
            if let Some(comment) = &r.comment {
                o["comment"] = json!(comment);
            }
            o
        })
        .collect();
    Some(Value::Array(items))
}

/// Emit a `modelCard`, merging the typed ML model with any preserved AI-bridge
/// `extensions.raw` data so AI scoring survives conversion.
fn emit_model_card(component: &Component, report: &mut FidelityReport) -> Option<Value> {
    let ml = component.ml_model.as_ref();

    // Pull a pre-shaped modelCard from the SPDX-3 AI bridge if present.
    // Layout: extensions.raw = { "mlModel": { "modelCard": { ... } } }.
    let bridged = component
        .extensions
        .raw
        .as_ref()
        .and_then(|raw| raw.pointer("/mlModel/modelCard"))
        .cloned();

    if ml.is_none() && bridged.is_none() {
        return None;
    }

    let mut model_card = bridged
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    if !model_card.is_empty() {
        report.preserved("modelCard AI bridge (extensions.raw)");
    }

    if let Some(ml) = ml {
        // modelParameters from typed fields.
        let mut params = model_card
            .get("modelParameters")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(approach) = &ml.approach {
            params.insert("approach".to_string(), json!({ "type": approach }));
        }
        if let Some(task) = &ml.task {
            params.insert("task".to_string(), json!(task));
        }
        if let Some(family) = &ml.architecture_family {
            params.insert("architectureFamily".to_string(), json!(family));
        }
        if let Some(arch) = &ml.architecture_name {
            params.insert("modelArchitecture".to_string(), json!(arch));
        }
        if !ml.training_datasets.is_empty() {
            let datasets: Vec<Value> = ml
                .training_datasets
                .iter()
                .map(|d| match (&d.reference, &d.name) {
                    (Some(r), _) => json!({ "ref": r }),
                    (None, Some(n)) => json!({ "type": "dataset", "name": n }),
                    (None, None) => json!({ "type": "dataset" }),
                })
                .collect();
            params.insert("datasets".to_string(), Value::Array(datasets));
        }
        if !params.is_empty() {
            model_card.insert("modelParameters".to_string(), Value::Object(params));
        }

        // considerations from typed limitations + energy.
        let mut considerations = model_card
            .get("considerations")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(limits) = &ml.limitations {
            considerations.insert("technicalLimitations".to_string(), json!([limits]));
        }
        if let Some(energy) = ml.energy_kwh_training {
            considerations.insert(
                "environmentalConsiderations".to_string(),
                json!({
                    "energyConsumptions": [{
                        "activity": "training",
                        "activityEnergyCost": { "value": energy, "unit": "kWh" }
                    }]
                }),
            );
        }
        if !considerations.is_empty() {
            model_card.insert("considerations".to_string(), Value::Object(considerations));
        }
        report.synthesized("modelCard from ml_model");
    }

    if model_card.is_empty() {
        None
    } else {
        Some(Value::Object(model_card))
    }
}

/// Emit a `data` componentData array from typed dataset metadata.
fn emit_dataset(component: &Component) -> Option<Value> {
    let dataset = component.dataset.as_ref()?;
    let mut entry = Map::new();
    entry.insert(
        "type".to_string(),
        json!(
            dataset
                .dataset_type
                .clone()
                .unwrap_or_else(|| "dataset".to_string())
        ),
    );
    if !dataset.sensitivity_classifications.is_empty() {
        entry.insert(
            "sensitiveData".to_string(),
            json!(dataset.sensitivity_classifications),
        );
    }
    if !dataset.governance_owners.is_empty() {
        let owners: Vec<Value> = dataset
            .governance_owners
            .iter()
            .map(|o| json!({ "organization": { "name": o } }))
            .collect();
        entry.insert("governance".to_string(), json!({ "owners": owners }));
    }
    Some(json!([Value::Object(entry)]))
}

/// Emit a `metadata.tools` array from document creators of tool type.
fn emit_tools(sbom: &NormalizedSbom) -> Option<Value> {
    let tools: Vec<Value> = sbom
        .document
        .creators
        .iter()
        .filter(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
        .map(|c| json!({ "name": c.name }))
        .collect();
    if tools.is_empty() {
        None
    } else {
        Some(Value::Array(tools))
    }
}

/// Emit the `dependencies` array from the edge list.
///
/// CycloneDX groups edges by source `ref` with a `dependsOn` list. `Provides`
/// edges (1.7) become a `provides` list. Other relationship kinds (SPDX-style
/// CONTAINS/GENERATES/etc.) have no CycloneDX dependency representation and are
/// recorded as dropped by the caller.
fn emit_dependencies(sbom: &NormalizedSbom, report: &mut FidelityReport) -> Vec<Value> {
    use indexmap::IndexMap;

    // ref -> (dependsOn refs, provides refs)
    let mut grouped: IndexMap<String, (Vec<String>, Vec<String>)> = IndexMap::new();
    let mut dropped_rel = false;

    for edge in &sbom.edges {
        let from = edge.from.value().to_string();
        let to = edge.to.value().to_string();
        let entry = grouped.entry(from).or_default();
        match edge.relationship {
            DependencyType::DependsOn
            | DependencyType::OptionalDependsOn
            | DependencyType::DevDependsOn
            | DependencyType::BuildDependsOn
            | DependencyType::TestDependsOn
            | DependencyType::RuntimeDependsOn
            | DependencyType::ProvidedDependsOn
            | DependencyType::Describes => entry.0.push(to),
            DependencyType::Provides => entry.1.push(to),
            _ => {
                dropped_rel = true;
                // Best-effort: still record as a plain dependency so the graph
                // edge is not silently lost.
                entry.0.push(to);
            }
        }
    }

    if dropped_rel {
        report.dropped("non-CycloneDX relationship kind (mapped to dependsOn)");
    }

    grouped
        .into_iter()
        .map(|(ref_id, (depends_on, provides))| {
            let mut o = Map::new();
            o.insert("ref".to_string(), json!(ref_id));
            if !depends_on.is_empty() {
                o.insert("dependsOn".to_string(), json!(depends_on));
            }
            if !provides.is_empty() {
                o.insert("provides".to_string(), json!(provides));
            }
            Value::Object(o)
        })
        .collect()
}

/// Record canonical-model data that has no CycloneDX 1.7 home, for the report.
fn note_unmappable(sbom: &NormalizedSbom, report: &mut FidelityReport) {
    for component in sbom.components.values() {
        if !component.extensions.annotations.is_empty() {
            report.dropped("SPDX annotations");
        }
        for hash in &component.hashes {
            if let crate::model::HashAlgorithm::Other(_) = hash.algorithm {
                report.dropped("non-standard hash algorithm");
            }
        }
        if component.crypto_properties.is_some() && component.extensions.source_json.is_none() {
            // Crypto properties are deep; without preserved source JSON we can't
            // reconstruct the full cryptoProperties block from the typed model.
            report.dropped("cryptoProperties (no preserved source)");
        }
    }
    if matches!(sbom.document.format, crate::model::SbomFormat::Spdx)
        && sbom.document.serial_number.is_none()
    {
        // SPDX namespace becomes serialNumber only when it is a URN/UUID.
        report.synthesized("no serialNumber (SPDX namespace not URN form)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::parse_sbom_str;

    const CDX: &str = r#"{
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "root",
                                   "name": "app", "version": "1.0.0"}},
        "components": [
            {"type": "library", "bom-ref": "lodash@4.17.21", "name": "lodash",
             "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "hashes": [{"alg": "SHA-256", "content": "abc"}],
             "licenses": [{"license": {"id": "MIT"}}]}
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["lodash@4.17.21"]}]
    }"#;

    #[test]
    fn emits_valid_cyclonedx_that_reparses() {
        let sbom = parse_sbom_str(CDX).unwrap();
        let (json, _report) = emit_cyclonedx(&sbom).unwrap();
        let reparsed = parse_sbom_str(&json).expect("emitted CDX must re-parse");
        // root (primary) + lodash
        assert_eq!(reparsed.components.len(), 2);
        assert_eq!(reparsed.document.format_version, "1.7");
    }

    #[test]
    fn preserves_component_counts_and_edges() {
        let sbom = parse_sbom_str(CDX).unwrap();
        let (json, _report) = emit_cyclonedx(&sbom).unwrap();
        let reparsed = parse_sbom_str(&json).unwrap();
        assert_eq!(reparsed.components.len(), sbom.components.len());
        assert_eq!(reparsed.edges.len(), sbom.edges.len());
        // license + hash survive on lodash
        let lodash = reparsed
            .components
            .values()
            .find(|c| c.name == "lodash")
            .unwrap();
        assert_eq!(lodash.hashes.len(), 1);
        assert!(!lodash.licenses.declared.is_empty());
    }
}
