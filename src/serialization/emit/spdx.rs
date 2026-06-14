//! SPDX 2.3 (JSON) emitter.
//!
//! Synthesizes a fresh SPDX 2.3 document from a [`NormalizedSbom`]: package
//! `SPDXID`s from [`CanonicalId`] (sanitized into `SPDXRef-*` form), the
//! `relationships` array from the edge list (`DEPENDS_ON`, `CONTAINS`, …), and
//! a `DESCRIBES` relationship for the primary component. Each package carries
//! name/version/downloadLocation/license/checksums and a `purl` external ref.
//! Where a component carries preserved same-format SPDX source JSON (see
//! [`super::preserve_source_json`]), non-clobbering SPDX-only fields are spliced
//! back verbatim.
//!
//! The output re-parses through the SPDX 2.x parser ([`crate::parsers::spdx`]).

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::model::{
    CanonicalId, Component, DependencyType, Hash, HashAlgorithm, LicenseExpression, NormalizedSbom,
};

use super::EmitError;
use super::fidelity::FidelityReport;

/// SPDX spec version emitted by this module.
const SPDX_VERSION: &str = "SPDX-2.3";
/// Document `SPDXID`.
const DOC_SPDX_ID: &str = "SPDXRef-DOCUMENT";

/// Emit `sbom` as an SPDX 2.3 JSON document plus a fidelity report.
///
/// # Errors
///
/// Returns [`EmitError::Serialize`] if the synthesized document fails to
/// serialize (not expected for well-formed models).
pub fn emit_spdx(sbom: &NormalizedSbom) -> Result<(String, FidelityReport), EmitError> {
    let mut report = FidelityReport::new(sbom.document.format.to_string(), "SPDX 2.3");

    // Assign a unique, valid SPDXID to every canonical id up front so packages
    // and relationships agree on the same identifiers.
    let id_assigner = SpdxIdAssigner::build(sbom);

    let mut packages = Vec::with_capacity(sbom.components.len());
    for (id, component) in &sbom.components {
        let spdx_id = id_assigner.id_for(id);
        packages.push(emit_package(component, spdx_id, &mut report));
    }

    let mut doc = Map::new();
    doc.insert("spdxVersion".to_string(), json!(SPDX_VERSION));
    doc.insert("dataLicense".to_string(), json!("CC0-1.0"));
    doc.insert("SPDXID".to_string(), json!(DOC_SPDX_ID));
    doc.insert(
        "name".to_string(),
        json!(
            sbom.document
                .name
                .clone()
                .unwrap_or_else(|| "converted-sbom".to_string())
        ),
    );
    doc.insert(
        "documentNamespace".to_string(),
        json!(document_namespace(sbom)),
    );
    doc.insert(
        "creationInfo".to_string(),
        emit_creation_info(sbom, &mut report),
    );
    doc.insert("packages".to_string(), Value::Array(packages));

    let relationships = emit_relationships(sbom, &id_assigner, &mut report);
    doc.insert("relationships".to_string(), Value::Array(relationships));

    note_unmappable(sbom, &mut report);

    let serialized = serde_json::to_string_pretty(&Value::Object(doc))?;
    Ok((serialized, report))
}

/// Maps each canonical id to a unique, SPDX-conformant `SPDXRef-*` identifier.
///
/// SPDX requires `SPDXID` to match `SPDXRef-[0-9a-zA-Z.-]+`. Canonical id values
/// (often PURLs) contain characters outside that set, so they are sanitized and
/// de-duplicated with a numeric suffix on collision.
struct SpdxIdAssigner {
    map: std::collections::HashMap<CanonicalId, String>,
}

impl SpdxIdAssigner {
    fn build(sbom: &NormalizedSbom) -> Self {
        let mut map = std::collections::HashMap::with_capacity(sbom.components.len());
        let mut used: HashSet<String> = HashSet::new();
        // DOC_SPDX_ID is reserved for the document element.
        used.insert(DOC_SPDX_ID.to_string());

        for (index, (id, component)) in sbom.components.iter().enumerate() {
            let base = sanitize_spdx_id(&component.name, id, index);
            let mut candidate = format!("SPDXRef-{base}");
            let mut suffix = 1usize;
            while used.contains(&candidate) {
                candidate = format!("SPDXRef-{base}-{suffix}");
                suffix += 1;
            }
            used.insert(candidate.clone());
            map.insert(id.clone(), candidate);
        }
        Self { map }
    }

    fn id_for(&self, id: &CanonicalId) -> &str {
        // Build() populated an entry for every component id; a missing edge
        // endpoint (dangling reference) is handled by the caller.
        self.map
            .get(id)
            .map_or(DOC_SPDX_ID, std::string::String::as_str)
    }

    fn contains(&self, id: &CanonicalId) -> bool {
        self.map.contains_key(id)
    }
}

/// Produce an SPDX-id fragment from a component name, falling back to the
/// canonical id, then to a positional index. Only `[0-9a-zA-Z.-]` survive.
fn sanitize_spdx_id(name: &str, id: &CanonicalId, index: usize) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    // Name yielded nothing usable: derive from the canonical id value instead.
    let from_id: String = id
        .value()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let from_id = from_id.trim_matches('-');
    if from_id.is_empty() {
        format!("Package-{index}")
    } else {
        from_id.to_string()
    }
}

/// Synthesize one SPDX package object.
fn emit_package(component: &Component, spdx_id: &str, report: &mut FidelityReport) -> Value {
    let mut obj = Map::new();
    obj.insert("SPDXID".to_string(), json!(spdx_id));
    report.synthesized("SPDXID from canonical id");
    obj.insert("name".to_string(), json!(component.name));

    if let Some(version) = &component.version {
        obj.insert("versionInfo".to_string(), json!(version));
    }

    // downloadLocation is required by the SPDX 2.x schema; the canonical model
    // has no general download field, so synthesize NOASSERTION.
    obj.insert(
        "downloadLocation".to_string(),
        json!(download_location(component)),
    );
    obj.insert("filesAnalyzed".to_string(), json!(false));

    // Licenses: declared + concluded. SPDX wants a single expression per slot;
    // the model holds a list, so join multiple declared expressions with AND
    // (conservative) and fall back to NOASSERTION when empty.
    let declared = license_field(&component.licenses.declared);
    obj.insert("licenseDeclared".to_string(), json!(declared));
    let concluded = component
        .licenses
        .concluded
        .as_ref()
        .map_or_else(|| declared.clone(), |c| c.expression.clone());
    obj.insert("licenseConcluded".to_string(), json!(concluded));

    if let Some(copyright) = &component.copyright {
        obj.insert("copyrightText".to_string(), json!(copyright));
    }
    if let Some(desc) = &component.description {
        obj.insert("description".to_string(), json!(desc));
    }
    if let Some(supplier) = &component.supplier {
        obj.insert(
            "supplier".to_string(),
            json!(format!("Organization: {}", supplier.name)),
        );
    }

    if let Some(checksums) = emit_checksums(&component.hashes) {
        obj.insert("checksums".to_string(), checksums);
    }

    if let Some(ext_refs) = emit_external_refs(component) {
        obj.insert("externalRefs".to_string(), ext_refs);
    }

    splice_preserved_fields(component, &mut obj, report);

    Value::Object(obj)
}

/// Best-effort download location: a VCS/distribution external ref URL if present,
/// otherwise `NOASSERTION` (a valid SPDX sentinel).
fn download_location(component: &Component) -> String {
    use crate::model::ExternalRefType;
    component
        .external_refs
        .iter()
        .find(|r| {
            matches!(
                r.ref_type,
                ExternalRefType::Vcs
                    | ExternalRefType::SourceDistribution
                    | ExternalRefType::BinaryDistribution
                    | ExternalRefType::Website
            )
        })
        .map_or_else(|| "NOASSERTION".to_string(), |r| r.url.clone())
}

/// Collapse a list of declared license expressions into a single SPDX field.
///
/// Empty → `NOASSERTION`. One → its expression. Multiple → joined with `AND`
/// (matches SPDX's conjunctive default for multiple declarations).
fn license_field(declared: &[LicenseExpression]) -> String {
    let exprs: Vec<&str> = declared.iter().map(|e| e.expression.as_str()).collect();
    if exprs.is_empty() {
        "NOASSERTION".to_string()
    } else if exprs.len() == 1 {
        exprs[0].to_string()
    } else {
        // Parenthesize each term so compound sub-expressions stay well-formed.
        exprs
            .iter()
            .map(|e| format!("({e})"))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
}

/// Emit a `checksums` array using SPDX algorithm spellings.
///
/// Algorithms with no SPDX 2.x representation are skipped (recorded as dropped
/// by `note_unmappable`).
fn emit_checksums(hashes: &[Hash]) -> Option<Value> {
    let items: Vec<Value> = hashes
        .iter()
        .filter_map(|h| {
            spdx_algorithm(&h.algorithm)
                .map(|alg| json!({ "algorithm": alg, "checksumValue": h.value }))
        })
        .collect();
    if items.is_empty() {
        None
    } else {
        Some(Value::Array(items))
    }
}

/// Map a [`HashAlgorithm`] to its SPDX 2.3 checksum-algorithm spelling.
///
/// The SPDX parser uppercases and matches these exact strings (e.g. `SHA256`,
/// `BLAKE2b-256`), so round-tripping requires the SPDX form rather than the
/// CycloneDX-flavoured [`HashAlgorithm`] `Display`. Algorithms absent from the
/// SPDX 2.3 enumeration return `None` and are dropped.
fn spdx_algorithm(alg: &HashAlgorithm) -> Option<&'static str> {
    Some(match alg {
        HashAlgorithm::Md5 => "MD5",
        HashAlgorithm::Sha1 => "SHA1",
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha384 => "SHA384",
        HashAlgorithm::Sha512 => "SHA512",
        HashAlgorithm::Sha3_256 => "SHA3-256",
        HashAlgorithm::Sha3_384 => "SHA3-384",
        HashAlgorithm::Sha3_512 => "SHA3-512",
        HashAlgorithm::Blake2b256 => "BLAKE2b-256",
        HashAlgorithm::Blake2b384 => "BLAKE2b-384",
        HashAlgorithm::Blake2b512 => "BLAKE2b-512",
        HashAlgorithm::Blake3 => "BLAKE3",
        // BLAKE2b enum values exist in SPDX 2.3; Streebog / Other do not.
        HashAlgorithm::Streebog256 | HashAlgorithm::Streebog512 | HashAlgorithm::Other(_) => {
            return None;
        }
    })
}

/// Emit an `externalRefs` array. The PURL becomes a `PACKAGE-MANAGER`/`purl`
/// ref; SWHIDs become `PERSISTENT-ID`/`swh` refs (mirrors the parser).
fn emit_external_refs(component: &Component) -> Option<Value> {
    let mut items = Vec::new();
    if let Some(purl) = &component.identifiers.purl {
        items.push(json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }));
    }
    for swhid in &component.identifiers.swhid {
        items.push(json!({
            "referenceCategory": "PERSISTENT-ID",
            "referenceType": "swh",
            "referenceLocator": swhid.to_string(),
        }));
    }
    for cpe in &component.identifiers.cpe {
        let ref_type = if cpe.starts_with("cpe:2.3:") {
            "cpe23Type"
        } else {
            "cpe22Type"
        };
        items.push(json!({
            "referenceCategory": "SECURITY",
            "referenceType": ref_type,
            "referenceLocator": cpe,
        }));
    }
    if items.is_empty() {
        None
    } else {
        Some(Value::Array(items))
    }
}

/// Splice non-clobbering SPDX-only fields from preserved source JSON.
///
/// Only runs when the preserved source looks SPDX-shaped (has `SPDXID`). Fields
/// the typed model can't reconstruct (`primaryPackagePurpose`, `homepage`,
/// `sourceInfo`, `comment`, …) are copied if not already synthesized.
fn splice_preserved_fields(
    component: &Component,
    obj: &mut Map<String, Value>,
    report: &mut FidelityReport,
) {
    let Some(src) = component.extensions.source_json.as_deref() else {
        return;
    };
    let looks_spdx = src.get("SPDXID").is_some() || src.get("spdxId").is_some();
    if !looks_spdx {
        return;
    }
    for key in [
        "primaryPackagePurpose",
        "homepage",
        "sourceInfo",
        "comment",
        "summary",
        "originator",
        "packageFileName",
        "builtDate",
        "releaseDate",
        "validUntilDate",
    ] {
        if let Some(block) = src.get(key)
            && !obj.contains_key(key)
        {
            obj.insert(key.to_string(), block.clone());
            report.preserved(format!("package.{key}"));
        }
    }
}

/// Build a stable `documentNamespace`: reuse a URI-shaped serial number,
/// otherwise synthesize a deterministic `urn:` from the content hash.
fn document_namespace(sbom: &NormalizedSbom) -> String {
    if let Some(serial) = &sbom.document.serial_number
        && (serial.starts_with("http://")
            || serial.starts_with("https://")
            || serial.starts_with("urn:"))
    {
        return serial.clone();
    }
    let name = sbom.document.name.as_deref().unwrap_or("converted-sbom");
    format!(
        "https://spdx.org/spdxdocs/{}-{:016x}",
        sanitize_namespace(name),
        sbom.content_hash
    )
}

fn sanitize_namespace(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "sbom".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Emit the SPDX `creationInfo` block from document metadata.
fn emit_creation_info(sbom: &NormalizedSbom, report: &mut FidelityReport) -> Value {
    use crate::model::CreatorType;

    let mut creators: Vec<String> = sbom
        .document
        .creators
        .iter()
        .map(|c| {
            let prefix = match c.creator_type {
                CreatorType::Tool => "Tool",
                CreatorType::Organization => "Organization",
                CreatorType::Person => "Person",
            };
            format!("{prefix}: {}", c.name)
        })
        .collect();
    if creators.is_empty() {
        // SPDX requires at least one creator.
        creators.push("Tool: sbom-tools".to_string());
        report.synthesized("creationInfo.creators (default tool)");
    }

    json!({
        "created": sbom.document.created.to_rfc3339(),
        "creators": creators,
    })
}

/// Emit the `relationships` array: a `DESCRIBES` for the primary component plus
/// one relationship per edge mapped to the closest SPDX relationship type.
fn emit_relationships(
    sbom: &NormalizedSbom,
    id_assigner: &SpdxIdAssigner,
    report: &mut FidelityReport,
) -> Vec<Value> {
    let mut rels = Vec::new();

    // DESCRIBES for the primary component (SPDX documentDescribes idiom).
    if let Some(primary) = &sbom.primary_component_id
        && id_assigner.contains(primary)
    {
        rels.push(json!({
            "spdxElementId": DOC_SPDX_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": id_assigner.id_for(primary),
        }));
        report.synthesized("DESCRIBES for primary component");
    }

    let mut dropped_rel = false;
    for edge in &sbom.edges {
        // Skip dangling edges whose endpoints are not real components.
        if !id_assigner.contains(&edge.from) || !id_assigner.contains(&edge.to) {
            continue;
        }
        let from = id_assigner.id_for(&edge.from);
        let to = id_assigner.id_for(&edge.to);

        let rel_type = match spdx_relationship_type(&edge.relationship) {
            Some(t) => t,
            None => {
                dropped_rel = true;
                "OTHER"
            }
        };
        // A Describes edge is already covered by the synthesized DESCRIBES above
        // when it originates at the primary; still emit it for non-primary roots.
        rels.push(json!({
            "spdxElementId": from,
            "relationshipType": rel_type,
            "relatedSpdxElement": to,
        }));
    }
    if dropped_rel {
        report.dropped("relationship kind with no SPDX mapping (emitted as OTHER)");
    }
    report.synthesized("relationships from edge list");

    rels
}

/// Map a [`DependencyType`] to its SPDX 2.3 relationship type.
///
/// These spellings are the ones the SPDX parser recognises in
/// [`crate::parsers::spdx`] (`DEPENDS_ON`, `CONTAINS`, …) so the output
/// round-trips. Types absent from SPDX 2.3 return `None`.
fn spdx_relationship_type(rel: &DependencyType) -> Option<&'static str> {
    Some(match rel {
        // All *DependsOn flavours collapse to DEPENDS_ON; SPDX 2.3 has scoped
        // *_DEPENDENCY_OF (inverse) variants but DEPENDS_ON preserves direction.
        DependencyType::DependsOn
        | DependencyType::OptionalDependsOn
        | DependencyType::DevDependsOn
        | DependencyType::BuildDependsOn
        | DependencyType::TestDependsOn
        | DependencyType::RuntimeDependsOn
        | DependencyType::ProvidedDependsOn => "DEPENDS_ON",
        DependencyType::Describes => "DESCRIBES",
        DependencyType::Generates => "GENERATES",
        DependencyType::Contains | DependencyType::Provides => "CONTAINS",
        DependencyType::AncestorOf => "ANCESTOR_OF",
        DependencyType::VariantOf => "VARIANT_OF",
        DependencyType::DistributionArtifact => "DISTRIBUTION_ARTIFACT",
        DependencyType::PatchFor => "PATCH_FOR",
        DependencyType::CopyOf => "COPY_OF",
        DependencyType::FileAdded => "FILE_ADDED",
        DependencyType::FileDeleted => "FILE_DELETED",
        DependencyType::FileModified => "FILE_MODIFIED",
        DependencyType::DynamicLink => "DYNAMIC_LINK",
        DependencyType::StaticLink => "STATIC_LINK",
        DependencyType::Other(_) => return None,
    })
}

/// Record canonical-model data with no SPDX 2.3 home, for the report.
fn note_unmappable(sbom: &NormalizedSbom, report: &mut FidelityReport) {
    for component in sbom.components.values() {
        for hash in &component.hashes {
            if spdx_algorithm(&hash.algorithm).is_none() {
                report.dropped("checksum algorithm with no SPDX spelling");
            }
        }
        // SPDX 2.3 has no native ML model / dataset / crypto block.
        if component.ml_model.is_some() {
            report.dropped("ML model metadata (no SPDX 2.3 representation)");
        }
        if component.dataset.is_some() {
            report.dropped("dataset metadata (no SPDX 2.3 representation)");
        }
        if component.crypto_properties.is_some() {
            report.dropped("cryptoProperties (no SPDX 2.3 representation)");
        }
        if !component.extensions.properties.is_empty() {
            report.dropped("CycloneDX properties (no SPDX 2.3 representation)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::parse_sbom_str;

    const SPDX: &str = r#"{
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "app",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/app",
        "creationInfo": {"created": "2026-01-04T12:00:00Z",
                         "creators": ["Tool: t-1.0"]},
        "packages": [
            {"SPDXID": "SPDXRef-Package-lodash", "name": "lodash",
             "versionInfo": "4.17.21", "downloadLocation": "NOASSERTION",
             "licenseDeclared": "MIT", "licenseConcluded": "MIT",
             "checksums": [{"algorithm": "SHA256", "checksumValue": "abc"}],
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                               "referenceType": "purl",
                               "referenceLocator": "pkg:npm/lodash@4.17.21"}]},
            {"SPDXID": "SPDXRef-Package-express", "name": "express",
             "versionInfo": "4.18.2", "downloadLocation": "NOASSERTION",
             "licenseDeclared": "MIT", "licenseConcluded": "MIT"}
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Package-express"},
            {"spdxElementId": "SPDXRef-Package-express", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-Package-lodash"}
        ]
    }"#;

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
    fn emits_valid_spdx_that_reparses() {
        let sbom = parse_sbom_str(SPDX).unwrap();
        let (json, _report) = emit_spdx(&sbom).unwrap();
        let reparsed = parse_sbom_str(&json).expect("emitted SPDX must re-parse");
        assert_eq!(reparsed.document.format.to_string(), "SPDX");
        assert_eq!(reparsed.document.format_version, "2.3");
    }

    #[test]
    fn spdx_round_trip_preserves_counts() {
        let sbom = parse_sbom_str(SPDX).unwrap();
        let (json, _report) = emit_spdx(&sbom).unwrap();
        let reparsed = parse_sbom_str(&json).unwrap();
        assert_eq!(reparsed.components.len(), sbom.components.len());
        assert_eq!(reparsed.edges.len(), sbom.edges.len());

        let lodash = reparsed
            .components
            .values()
            .find(|c| c.name == "lodash")
            .unwrap();
        assert_eq!(lodash.hashes.len(), 1);
        assert!(!lodash.licenses.declared.is_empty());
        assert_eq!(
            lodash.identifiers.purl.as_deref(),
            Some("pkg:npm/lodash@4.17.21")
        );
    }

    #[test]
    fn cross_family_cdx_to_spdx_maps_components() {
        let sbom = parse_sbom_str(CDX).unwrap();
        let (json, _report) = emit_spdx(&sbom).unwrap();
        let reparsed = parse_sbom_str(&json).expect("CDX→SPDX output must re-parse");

        let names: Vec<&str> = reparsed
            .components
            .values()
            .map(|c| c.name.as_str())
            .collect();
        assert!(names.contains(&"app"), "primary mapped: {names:?}");
        assert!(names.contains(&"lodash"), "lodash mapped: {names:?}");
        // app depends-on lodash survives as a relationship.
        assert!(!reparsed.edges.is_empty(), "dependency edges mapped");
    }

    #[test]
    fn sanitizes_purl_spdx_ids() {
        // A PURL-based canonical id contains '/', '@', ':' — all illegal in SPDXID.
        let sbom = parse_sbom_str(CDX).unwrap();
        let (json, _report) = emit_spdx(&sbom).unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        for pkg in doc["packages"].as_array().unwrap() {
            let id = pkg["SPDXID"].as_str().unwrap();
            assert!(id.starts_with("SPDXRef-"), "bad SPDXID {id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
                "SPDXID {id} has illegal chars"
            );
        }
    }
}
