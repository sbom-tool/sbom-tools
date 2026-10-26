//! CycloneDX XML twins: the XML encoding of a JSON fixture must normalize to
//! the same model and reach the same compliance verdicts.
//!
//! Review finding V10: the XML parser dropped document metadata the JSON
//! parser reads (authors, manufacturer, lifecycles, tools in the 1.5+
//! components/services form, compositions, the signature), so an XML SBOM
//! failed NTIA and CISA 2026 rules its JSON twin passed.
//!
//! A twin is `<name>.cdx.xml` next to `<name>.cdx.json` anywhere under
//! `tests/fixtures`; every pair found is checked, so a new twin needs no test
//! change. Twins are validated against the official `bom-1.x.xsd` when they
//! are added; here each is checked to be well-formed XML whose root is `bom`
//! in the namespace of its JSON twin's specVersion. The signatures in the
//! twins (XML-DSig in XML, a JSF signature naming the same algorithm URI in
//! JSON) are structural placeholders: nothing verifies them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sbom_tools::model::{CompletenessDeclaration, CraSidecarMetadata, CreatorType, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use sbom_tools::serialization::normalized_sbom_json;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Evaluation instant for every check (the v0.3.0 review date).
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// One JSON fixture and its XML twin.
struct Twin {
    /// Fixture path relative to `tests/fixtures`, without `.json`/`.xml`.
    name: String,
    json: PathBuf,
    xml: PathBuf,
}

/// Every `*.cdx.json` under the fixtures with a `*.cdx.xml` sibling, sorted.
fn twins() -> Vec<Twin> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.to_string_lossy().ends_with(".cdx.json") {
                out.push(path);
            }
        }
    }
    let root = Path::new(FIXTURES_DIR);
    let mut json_files = Vec::new();
    walk(root, &mut json_files);
    let mut twins: Vec<Twin> = json_files
        .into_iter()
        .filter_map(|json| {
            let xml = json.with_extension("xml");
            xml.is_file().then(|| Twin {
                name: json
                    .with_extension("")
                    .strip_prefix(root)
                    .expect("under fixtures")
                    .to_string_lossy()
                    .replace('\\', "/"),
                json,
                xml,
            })
        })
        .collect();
    twins.sort_by(|a, b| a.name.cmp(&b.name));
    twins
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn parse(path: &Path) -> NormalizedSbom {
    parse_sbom_str(&read(path)).unwrap_or_else(|e| panic!("{} must parse: {e}", path.display()))
}

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc)
}

fn check(
    sbom: &NormalizedSbom,
    level: ComplianceLevel,
    sidecar: Option<&CraSidecarMetadata>,
) -> ComplianceResult {
    let mut checker = ComplianceChecker::new(level).with_as_of(as_of());
    if let Some(sc) = sidecar {
        checker = checker.with_sidecar(sc.clone());
    }
    checker.check(sbom)
}

/// JSON pointers of every place two values differ, for a readable failure.
fn differences(a: &serde_json::Value, b: &serde_json::Value, path: &str, out: &mut Vec<String>) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                match (x.get(k), y.get(k)) {
                    (Some(xv), Some(yv)) => differences(xv, yv, &format!("{path}/{k}"), out),
                    _ => out.push(format!("{path}/{k}: present in one twin only")),
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (xv, yv)) in x.iter().zip(y).enumerate() {
                differences(xv, yv, &format!("{path}/{i}"), out);
            }
        }
        _ if a != b => out.push(format!("{path}: {a} != {b}")),
        _ => {}
    }
}

#[test]
fn every_twin_is_well_formed_cyclonedx_xml_for_its_spec_version() {
    use quick_xml::events::Event;

    let twins = twins();
    assert!(!twins.is_empty(), "no CycloneDX XML twins found");
    for twin in &twins {
        let json: serde_json::Value =
            serde_json::from_str(&read(&twin.json)).expect("JSON twin is JSON");
        let spec_version = json["specVersion"].as_str().expect("specVersion");
        let expected_ns = format!("http://cyclonedx.org/schema/bom/{spec_version}");

        let xml = read(&twin.xml);
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut root_ns = None;
        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) if root_ns.is_none() => {
                    assert_eq!(e.local_name().as_ref(), "bom", "{}: root", twin.name);
                    let ns = e
                        .try_get_attribute("xmlns")
                        .expect("readable attributes")
                        .map(|a| a.value.into_owned());
                    root_ns = Some(ns);
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => panic!("{}: not well-formed XML: {e}", twin.name),
            }
        }
        assert_eq!(
            root_ns.flatten().as_deref(),
            Some(expected_ns.as_str()),
            "{}: the XML namespace must match the JSON specVersion",
            twin.name
        );
    }
}

/// The library function behind `convert --to normalized`: identical bytes.
#[test]
fn xml_twin_normalizes_to_the_json_model() {
    for twin in twins() {
        let from_json = normalized_sbom_json(&parse(&twin.json)).expect("serialize JSON twin");
        let from_xml = normalized_sbom_json(&parse(&twin.xml)).expect("serialize XML twin");
        if from_json != from_xml {
            let a: serde_json::Value = serde_json::from_str(&from_json).expect("valid JSON");
            let b: serde_json::Value = serde_json::from_str(&from_xml).expect("valid JSON");
            let mut diffs = Vec::new();
            differences(&a, &b, "", &mut diffs);
            panic!(
                "{}: the XML twin normalizes differently (JSON != XML):\n  {}",
                twin.name,
                diffs.join("\n  ")
            );
        }
    }
}

/// Every level, with and without the auto-discovered CRA sidecar: the XML
/// twin passes exactly the standards its JSON twin passes, with the same
/// findings.
#[test]
fn xml_twin_reaches_the_json_verdicts_at_every_level() {
    for twin in twins() {
        let json_sbom = parse(&twin.json);
        let xml_sbom = parse(&twin.xml);
        let sidecar = CraSidecarMetadata::discover_for_sbom(&twin.json).expect("sidecar loads");
        let xml_sidecar = CraSidecarMetadata::discover_for_sbom(&twin.xml).expect("sidecar loads");
        assert_eq!(
            sidecar.is_some(),
            xml_sidecar.is_some(),
            "{}: both twins must discover the same CRA sidecar",
            twin.name
        );
        for sc in [None, sidecar.as_ref()] {
            for level in ComplianceLevel::all() {
                let from_json = check(&json_sbom, *level, sc);
                let from_xml = check(&xml_sbom, *level, sc);
                let label = format!(
                    "{} [{level:?}{}]",
                    twin.name,
                    if sc.is_some() { " + sidecar" } else { "" }
                );
                assert_eq!(
                    from_json.is_compliant, from_xml.is_compliant,
                    "{label}: JSON twin compliant = {}, XML twin compliant = {}",
                    from_json.is_compliant, from_xml.is_compliant
                );
                let a = serde_json::to_value(&from_json).expect("serialize");
                let b = serde_json::to_value(&from_xml).expect("serialize");
                if a != b {
                    let mut diffs = Vec::new();
                    differences(&a, &b, "", &mut diffs);
                    panic!(
                        "{label}: findings differ (JSON != XML):\n  {}",
                        diffs.join("\n  ")
                    );
                }
            }
        }
    }
}

/// Keeps the twin set meaningful: every spec version 1.4–1.7 has a twin that
/// passes NTIA and CISA 2026 in JSON (the standards V10 broke for XML), and
/// together the XML twins populate every document field the XML parser now
/// reads. (The parser's unit tests cover each element form.)
#[test]
fn twins_cover_each_spec_version_and_metadata_field() {
    let mut passing_versions = BTreeSet::new();
    let mut fields = BTreeSet::new();
    for twin in twins() {
        let json_sbom = parse(&twin.json);
        let passes = |level| check(&json_sbom, level, None).is_compliant;
        if passes(ComplianceLevel::NtiaMinimum) && passes(ComplianceLevel::Cisa2026) {
            passing_versions.insert(json_sbom.document.spec_version.clone());
        }

        let doc = parse(&twin.xml).document;
        for creator in &doc.creators {
            fields.insert(match creator.creator_type {
                CreatorType::Person => "authors",
                CreatorType::Organization => "manufacturer",
                CreatorType::Tool => "tools",
            });
        }
        if doc.lifecycle_phase.is_some() {
            fields.insert("lifecycles");
        }
        if doc.completeness_declaration != CompletenessDeclaration::Unknown {
            fields.insert("compositions");
        }
        if doc.signature.as_ref().is_some_and(|s| s.has_value) {
            fields.insert("signature");
        }
        if doc.distribution_classification.is_some() {
            fields.insert("distributionConstraints");
        }
    }
    assert_eq!(
        passing_versions,
        ["1.4", "1.5", "1.6", "1.7"]
            .into_iter()
            .map(String::from)
            .collect(),
        "a twin passing NTIA and CISA 2026 is needed for every spec version"
    );
    assert_eq!(
        fields,
        [
            "authors",
            "compositions",
            "distributionConstraints",
            "lifecycles",
            "manufacturer",
            "signature",
            "tools",
        ]
        .into_iter()
        .collect(),
        "the XML twins must populate every metadata field"
    );
}
