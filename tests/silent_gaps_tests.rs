//! Silent gaps that changed or hid verdicts, now handled and reported:
//!
//! 1. A component the document lists twice is merged, in an order-free way,
//!    and reported by one Info finding per document (the
//!    `SBOM-*-DUPLICATE-COMPONENT` rules); the last entry used to overwrite
//!    the others.
//! 2. The CRA cycle check evaluates graphs of every size; it skipped (and
//!    passed) every graph above 1,000,000 dependency edges.
//! 3. A creation timestamp that does not parse is reported as unparseable,
//!    with its value, instead of as missing.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{CanonicalId, Component, DependencyEdge, DependencyType, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, DependencyMetrics, Violation, ViolationSeverity,
};

/// A CycloneDX 1.6 document whose `components` are the given JSON objects.
fn cyclonedx(components: &[serde_json::Value]) -> String {
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T10:00:00Z",
            "tools": { "components": [{ "type": "application", "name": "acme-sbom", "version": "1.0" }] },
            "component": {
                "type": "application", "bom-ref": "app", "name": "app", "version": "1.0.0",
                "purl": "pkg:npm/app@1.0.0"
            }
        },
        "components": components,
        "dependencies": [{ "ref": "app", "dependsOn": ["lodash-a"] }]
    })
    .to_string()
}

/// An entry of lodash 4.17.21 under `bom_ref`, with `extra` fields.
fn lodash(bom_ref: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "type": "library", "bom-ref": bom_ref, "name": "lodash", "version": "4.17.21",
        "purl": "pkg:npm/lodash@4.17.21"
    });
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    entry
}

/// Three entries of one component that between them carry a hash, a licence
/// and a supplier, and disagree on a description.
fn lodash_entries() -> Vec<serde_json::Value> {
    vec![
        lodash(
            "lodash-a",
            serde_json::json!({
                "description": "Lodash utilities",
                "hashes": [{ "alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }]
            }),
        ),
        lodash(
            "lodash-b",
            serde_json::json!({
                "description": "A utility library",
                "licenses": [{ "license": { "id": "MIT" } }]
            }),
        ),
        lodash(
            "lodash-a",
            serde_json::json!({ "supplier": { "name": "OpenJS Foundation" } }),
        ),
    ]
}

/// Every result's verdict, as compared across documents: the results'
/// JSON serialization.
fn verdicts(sbom: &NormalizedSbom) -> Vec<serde_json::Value> {
    ComplianceLevel::all()
        .iter()
        .map(|level| serde_json::to_value(checker(*level).check(sbom)).expect("serializes"))
        .collect()
}

fn findings<'a>(result: &'a ComplianceResult, rule_id: &str) -> Vec<&'a Violation> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule_id)
        .collect()
}

// ── 1. Duplicate components ─────────────────────────────────────────────

#[test]
fn every_order_of_duplicate_entries_gets_the_same_verdicts() {
    let entries = lodash_entries();
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let all: Vec<Vec<serde_json::Value>> = orders
        .iter()
        .map(|order| {
            let listed: Vec<serde_json::Value> =
                order.iter().map(|i| entries[*i].clone()).collect();
            verdicts(&parse_sbom_str(&cyclonedx(&listed)).expect("parses"))
        })
        .collect();
    for other in &all[1..] {
        assert_eq!(other, &all[0], "the verdicts depend on the entry order");
    }
}

#[test]
fn the_merged_component_keeps_every_entrys_data() {
    let sbom = parse_sbom_str(&cyclonedx(&lodash_entries())).expect("parses");
    let lodash: Vec<&Component> = sbom
        .components
        .values()
        .filter(|c| c.name == "lodash")
        .collect();
    assert_eq!(lodash.len(), 1, "one component for three entries");
    let c = lodash[0];
    assert_eq!(c.hashes.len(), 1);
    assert_eq!(c.licenses.declared.len(), 1);
    assert_eq!(
        c.supplier.as_ref().map(|s| s.name.as_str()),
        Some("OpenJS Foundation")
    );
    assert_eq!(c.description.as_deref(), Some("A utility library"));
    let record = &sbom.duplicate_components[&c.canonical_id];
    assert_eq!(record.entries, 3);
    assert_eq!(record.format_ids, ["lodash-a", "lodash-b"]);
    assert_eq!(record.conflicts, ["description"]);
    assert_eq!(sbom.collision_count, 2);
}

/// One Info per document, under each generic family's own rule, naming the
/// duplicated ids (five, then a count) and the fields in conflict.
#[test]
fn one_info_finding_names_the_duplicated_components() {
    let mut components = lodash_entries();
    for name in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        let entry = serde_json::json!({
            "type": "library", "bom-ref": name, "name": name, "version": "1.0.0",
            "purl": format!("pkg:npm/{name}@1.0.0")
        });
        components.push(entry.clone());
        components.push(entry);
    }
    let sbom = parse_sbom_str(&cyclonedx(&components)).expect("parses");
    for (level, rule) in [
        (ComplianceLevel::Minimum, "SBOM-QUALITY-DUPLICATE-COMPONENT"),
        (
            ComplianceLevel::Standard,
            "SBOM-QUALITY-DUPLICATE-COMPONENT",
        ),
        (
            ComplianceLevel::Comprehensive,
            "SBOM-QUALITY-DUPLICATE-COMPONENT",
        ),
        (
            ComplianceLevel::NtiaMinimum,
            "SBOM-NTIA-DUPLICATE-COMPONENT",
        ),
        (ComplianceLevel::CraPhase1, "SBOM-CRA-DUPLICATE-COMPONENT"),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-DUPLICATE-COMPONENT"),
        (
            ComplianceLevel::CraOssSteward,
            "SBOM-CRA-DUPLICATE-COMPONENT",
        ),
        (
            ComplianceLevel::FdaMedicalDevice,
            "SBOM-FDA-DUPLICATE-COMPONENT",
        ),
    ] {
        let result = checker(level).check(&sbom);
        let found = findings(&result, rule);
        assert_eq!(found.len(), 1, "[{level:?}] one {rule} finding");
        let v = found[0];
        assert_eq!(v.severity, ViolationSeverity::Info);
        assert!(v.component_id.is_none(), "a document-level finding");
        let counts = v.counts.expect("counts");
        assert_eq!((counts.affected, counts.total), (7, 8));
        assert!(
            v.message
                .starts_with("7/8 components are listed more than once (15 entries)"),
            "{}",
            v.message
        );
        assert!(
            v.message
                .contains("pkg:npm/lodash@4.17.21 (3 entries), pkg:npm/alpha@1.0.0 (2 entries)"),
            "{}",
            v.message
        );
        assert!(v.message.contains("…and 2 more"), "{}", v.message);
        assert!(
            v.message.contains("disagree on description"),
            "{}",
            v.message
        );
    }
    // The dedicated standards judge the merged component, with no finding
    // of their own.
    let bsi = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        bsi.violations
            .iter()
            .all(|v| !v.rule_id.ends_with("DUPLICATE-COMPONENT"))
    );
}

#[test]
fn a_document_without_duplicates_reports_none() {
    let sbom =
        parse_sbom_str(&cyclonedx(&[lodash("lodash-a", serde_json::json!({}))])).expect("parses");
    assert!(sbom.duplicate_components.is_empty());
    for level in ComplianceLevel::all() {
        let result = checker(*level).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .all(|v| !v.rule_id.ends_with("DUPLICATE-COMPONENT")),
            "[{level:?}]"
        );
    }
}

// ── 2. Cycles in graphs above 1,000,000 edges ───────────────────────────

/// 1,000,001 edges, built here: a million `app → lib` edges and the one
/// `lib → app` edge that closes a cycle at the end. Graph metrics still skip
/// a graph this size, but the CRA cycle check no longer does.
#[test]
fn the_cycle_check_evaluates_a_graph_above_a_million_edges() {
    let mut sbom = NormalizedSbom::default();
    for name in ["app", "lib"] {
        sbom.add_component(Component::new(name.to_string(), name.to_string()));
    }
    let app = CanonicalId::from_format_id("app");
    let lib = CanonicalId::from_format_id("lib");
    sbom.edges =
        vec![DependencyEdge::new(app.clone(), lib.clone(), DependencyType::DependsOn); 1_000_000];
    sbom.edges
        .push(DependencyEdge::new(lib, app, DependencyType::DependsOn));
    assert!(DependencyMetrics::from_sbom(&sbom).graph_analysis_skipped);

    for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
        let result = checker(level).check(&sbom);
        let cycles = findings(&result, "SBOM-CRA-CYCLES");
        assert_eq!(cycles.len(), 1, "[{level:?}] the cycle must be found");
        assert_eq!(cycles[0].severity, ViolationSeverity::Warning);
        assert!(cycles[0].message.contains("contains 1 cycle(s)"));
    }
}

// ── 3. Unparseable creation timestamps ──────────────────────────────────

/// One document per parser (CycloneDX JSON and XML, SPDX 2.3 JSON and
/// tag-value, SPDX 3.0 JSON-LD) with the creation timestamp `ts`.
fn documents(ts: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "CycloneDX JSON",
            serde_json::json!({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": { "timestamp": ts },
                "components": [{ "type": "library", "bom-ref": "lib", "name": "lib", "version": "1.0" }]
            })
            .to_string(),
        ),
        (
            "CycloneDX XML",
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata><timestamp>{ts}</timestamp></metadata>
  <components>
    <component type="library" bom-ref="lib"><name>lib</name><version>1.0</version></component>
  </components>
</bom>"#
            ),
        ),
        (
            "SPDX 2.3 JSON",
            serde_json::json!({
                "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "doc", "documentNamespace": "https://acme.example/spdx/doc",
                "creationInfo": { "created": ts, "creators": ["Tool: acme-1.0"] },
                "packages": [{
                    "SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "1.0",
                    "downloadLocation": "NOASSERTION"
                }]
            })
            .to_string(),
        ),
        (
            "SPDX 2.3 tag-value",
            format!(
                "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n\
                 DocumentName: doc\nDocumentNamespace: https://acme.example/spdx/doc\n\
                 Creator: Tool: acme-1.0\nCreated: {ts}\n\n\
                 PackageName: lib\nSPDXID: SPDXRef-lib\nPackageVersion: 1.0\n\
                 PackageDownloadLocation: NOASSERTION\n"
            ),
        ),
        (
            "SPDX 3.0 JSON-LD",
            serde_json::json!({
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "@graph": [
                    {
                        "type": "CreationInfo", "@id": "_:creationinfo",
                        "specVersion": "3.0.1", "created": ts,
                        "createdBy": ["https://acme.example/agent"]
                    },
                    {
                        "type": "Tool", "spdxId": "https://acme.example/agent",
                        "name": "acme", "creationInfo": "_:creationinfo"
                    },
                    {
                        "type": "SpdxDocument", "spdxId": "https://acme.example/doc",
                        "creationInfo": "_:creationinfo", "rootElement": ["https://acme.example/lib"]
                    },
                    {
                        "type": "software_Package", "spdxId": "https://acme.example/lib",
                        "name": "lib", "software_packageVersion": "1.0",
                        "creationInfo": "_:creationinfo"
                    }
                ]
            })
            .to_string(),
        ),
    ]
}

/// Every timestamp rule, at a level that reads it. SBOM-BSIAI-META-TIMESTAMP
/// is left out: the SBOM-for-AI profile applies only to a document with AI
/// content (its matrix row pins the unparseable case).
const TIMESTAMP_RULES: &[(ComplianceLevel, &str)] = &[
    (ComplianceLevel::NtiaMinimum, "SBOM-NTIA-TIMESTAMP"),
    (ComplianceLevel::FdaMedicalDevice, "SBOM-NTIA-TIMESTAMP"),
    (ComplianceLevel::Comprehensive, "SBOM-NTIA-TIMESTAMP"),
    (ComplianceLevel::Eo14028, "SBOM-EO14028-TIMESTAMP"),
    (ComplianceLevel::CraPhase2, "SBOM-CRA-SBOM-FRESHNESS"),
    (ComplianceLevel::BsiTr03183_2, "SBOM-BSI-TR-03183-2-5-2"),
    (ComplianceLevel::Cisa2026, "SBOM-CISA2026-TIMESTAMP"),
    (ComplianceLevel::PciDss632, "SBOM-PCI-6-3-2-FRESHNESS"),
    (ComplianceLevel::Fsct, "SBOM-FSCT-TIMESTAMP"),
];

#[test]
fn every_parser_keeps_an_unparseable_timestamp() {
    for (label, text) in documents("2026-13-45 noon") {
        let sbom = parse_sbom_str(&text).unwrap_or_else(|e| panic!("{label} parses: {e}"));
        assert_eq!(
            sbom.document.created_unparsed.as_deref(),
            Some("2026-13-45 noon"),
            "{label}"
        );
        assert!(
            !sbom.document.has_known_timestamp(),
            "{label}: the epoch sentinel stays"
        );
    }
    for (label, text) in documents("2026-01-15T10:00:00Z") {
        let sbom = parse_sbom_str(&text).unwrap_or_else(|e| panic!("{label} parses: {e}"));
        assert!(sbom.document.created_unparsed.is_none(), "{label}");
        assert!(sbom.document.has_known_timestamp(), "{label}");
    }
}

#[test]
fn every_timestamp_rule_quotes_an_unparseable_value() {
    for (label, text) in documents("2026-13-45 noon") {
        let sbom = parse_sbom_str(&text).unwrap_or_else(|e| panic!("{label} parses: {e}"));
        for (level, rule) in TIMESTAMP_RULES {
            let result = checker(*level).check(&sbom);
            let found = findings(&result, rule);
            assert_eq!(found.len(), 1, "{label} [{level:?}] {rule}");
            assert!(
                found[0]
                    .message
                    .contains("unparseable creation timestamp '2026-13-45 noon'"),
                "{label} [{level:?}] {rule}: {}",
                found[0].message
            );
            assert!(
                !found[0].message.contains("missing"),
                "{}",
                found[0].message
            );
        }
    }
}

/// A blank timestamp is no value: it is reported missing, as before.
#[test]
fn a_blank_timestamp_is_missing() {
    let (_, text) = documents("  ").remove(0);
    let sbom = parse_sbom_str(&text).expect("parses");
    assert!(sbom.document.created_unparsed.is_none());
    let result = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    let found = findings(&result, "SBOM-NTIA-TIMESTAMP");
    assert_eq!(found.len(), 1);
    assert!(found[0].message.contains("missing"), "{}", found[0].message);
}

/// A long value is cut in the message, with an ellipsis.
#[test]
fn a_long_unparseable_value_is_cut() {
    let long = "x".repeat(500);
    let (_, text) = documents(&long).remove(0);
    let sbom = parse_sbom_str(&text).expect("parses");
    assert_eq!(
        sbom.document.created_unparsed.as_deref(),
        Some(long.as_str())
    );
    let result = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    let message = &findings(&result, "SBOM-NTIA-TIMESTAMP")[0].message;
    assert!(
        message.contains(&format!("'{}…'", "x".repeat(64))),
        "{message}"
    );
    assert!(message.len() < 200, "{message}");
}
