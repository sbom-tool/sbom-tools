//! Opt-in capture of verbatim component source JSON for conversion fidelity.
//!
//! This is the *only* writer of
//! [`ComponentExtensions::source_json`](crate::model::ComponentExtensions::source_json).
//! It runs solely on the `convert` path so the memory cost (a clone of each
//! component's source object) is bounded to conversion time and never paid on
//! the normal parse hot path.

use std::collections::HashMap;

use serde_json::Value;

use crate::model::NormalizedSbom;

/// Populate each component's `source_json` slot from the raw input JSON.
///
/// Matches raw component/package objects back to parsed components by their
/// format-native identity field (CycloneDX `bom-ref`, SPDX `SPDXID`/`spdxId`),
/// falling back to PURL then name. Unmatched objects are left untouched. This is
/// best-effort: when no key matches, the emitter simply synthesizes that
/// component entirely from the typed model.
///
/// Silently does nothing if `raw_json` is not valid JSON (the typed model is
/// still fully usable for synthesis-only emission).
pub fn preserve_source_json(raw_json: &str, sbom: &mut NormalizedSbom) {
    let Ok(doc): Result<Value, _> = serde_json::from_str(raw_json) else {
        return;
    };

    // Build an index: source identity key → source JSON object.
    let mut by_key: HashMap<String, Value> = HashMap::new();
    index_cyclonedx(&doc, &mut by_key);
    index_spdx2(&doc, &mut by_key);
    index_spdx3(&doc, &mut by_key);

    if by_key.is_empty() {
        return;
    }

    for component in sbom.components.values_mut() {
        // Tiered lookup mirrors how the parsers derive identity: native id
        // (bom-ref / SPDXID, stored as format_id) first, then PURL, then name.
        let candidates = [
            Some(component.identifiers.format_id.as_str()),
            component.identifiers.purl.as_deref(),
            Some(component.name.as_str()),
        ];
        for key in candidates.into_iter().flatten() {
            if let Some(obj) = by_key.get(key) {
                component.extensions.source_json = Some(Box::new(obj.clone()));
                break;
            }
        }
    }
}

/// Index CycloneDX `components[]` and `metadata.component` by `bom-ref`/purl/name.
fn index_cyclonedx(doc: &Value, by_key: &mut HashMap<String, Value>) {
    if doc.get("bomFormat").is_none() {
        return;
    }
    if let Some(meta_comp) = doc.pointer("/metadata/component") {
        index_cdx_component(meta_comp, by_key);
    }
    if let Some(components) = doc.get("components").and_then(Value::as_array) {
        for comp in components {
            index_cdx_component(comp, by_key);
        }
    }
}

fn index_cdx_component(comp: &Value, by_key: &mut HashMap<String, Value>) {
    // bom-ref is the parser's primary identity (stored as format_id).
    if let Some(bom_ref) = comp.get("bom-ref").and_then(Value::as_str) {
        by_key.entry(bom_ref.to_string()).or_insert(comp.clone());
    }
    if let Some(purl) = comp.get("purl").and_then(Value::as_str) {
        by_key.entry(purl.to_string()).or_insert(comp.clone());
    }
    if let Some(name) = comp.get("name").and_then(Value::as_str) {
        by_key.entry(name.to_string()).or_insert(comp.clone());
    }
}

/// Index SPDX 2.x `packages[]` by `SPDXID`/purl/name.
fn index_spdx2(doc: &Value, by_key: &mut HashMap<String, Value>) {
    if doc.get("spdxVersion").is_none() {
        return;
    }
    if let Some(packages) = doc.get("packages").and_then(Value::as_array) {
        for pkg in packages {
            if let Some(id) = pkg.get("SPDXID").and_then(Value::as_str) {
                by_key.entry(id.to_string()).or_insert(pkg.clone());
            }
            if let Some(name) = pkg.get("name").and_then(Value::as_str) {
                by_key.entry(name.to_string()).or_insert(pkg.clone());
            }
            // purl lives in externalRefs[referenceType=purl]
            if let Some(purl) = spdx2_purl(pkg) {
                by_key.entry(purl).or_insert(pkg.clone());
            }
        }
    }
}

fn spdx2_purl(pkg: &Value) -> Option<String> {
    pkg.get("externalRefs")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("referenceType").and_then(Value::as_str) == Some("purl"))
        .and_then(|r| r.get("referenceLocator").and_then(Value::as_str))
        .map(str::to_string)
}

/// Index SPDX 3.0 (JSON-LD) graph elements by `spdxId`/name.
fn index_spdx3(doc: &Value, by_key: &mut HashMap<String, Value>) {
    if doc.get("@context").is_none() {
        return;
    }
    // Elements may live in a top-level array, an `@graph`, or be a single object.
    let graph: Vec<&Value> = if let Some(arr) = doc.as_array() {
        arr.iter().collect()
    } else if let Some(arr) = doc.get("@graph").and_then(Value::as_array) {
        arr.iter().collect()
    } else {
        std::slice::from_ref(doc).iter().collect()
    };
    for el in graph {
        if let Some(id) = el.get("spdxId").and_then(Value::as_str) {
            by_key.entry(id.to_string()).or_insert(el.clone());
        }
        if let Some(name) = el.get("name").and_then(Value::as_str) {
            by_key.entry(name.to_string()).or_insert(el.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::parse_sbom_str;

    const CDX: &str = r#"{
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [
            {"type": "library", "bom-ref": "lodash@4.17.21", "name": "lodash",
             "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "x-custom-field": "preserve-me"}
        ]
    }"#;

    #[test]
    fn captures_source_json_for_cyclonedx() {
        let mut sbom = parse_sbom_str(CDX).unwrap();
        assert!(
            sbom.components
                .values()
                .all(|c| c.extensions.source_json.is_none())
        );

        preserve_source_json(CDX, &mut sbom);

        let comp = sbom.components.values().next().unwrap();
        let src = comp.extensions.source_json.as_ref().expect("preserved");
        assert_eq!(
            src.get("x-custom-field").and_then(Value::as_str),
            Some("preserve-me")
        );
    }

    #[test]
    fn invalid_json_is_noop() {
        let mut sbom = parse_sbom_str(CDX).unwrap();
        preserve_source_json("{not json", &mut sbom);
        assert!(
            sbom.components
                .values()
                .all(|c| c.extensions.source_json.is_none())
        );
    }

    #[test]
    fn captures_source_json_for_spdx2() {
        let spdx = r#"{
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/x",
            "creationInfo": {"created": "2026-01-04T12:00:00Z",
                             "creators": ["Tool: t-1.0"]},
            "packages": [
                {"SPDXID": "SPDXRef-Package-lodash", "name": "lodash",
                 "versionInfo": "4.17.21",
                 "downloadLocation": "NOASSERTION",
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                   "referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.21"}]}
            ]
        }"#;
        let mut sbom = parse_sbom_str(spdx).unwrap();
        preserve_source_json(spdx, &mut sbom);
        assert!(
            sbom.components
                .values()
                .any(|c| c.extensions.source_json.is_some())
        );
    }
}
