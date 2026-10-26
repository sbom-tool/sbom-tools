//! CycloneDX XML twins: the XML encoding of a JSON fixture must normalize to
//! the same model and reach the same compliance verdicts.
//!
//! Review finding V10: the XML parser dropped document metadata the JSON
//! parser reads (authors, manufacturer, lifecycles, tools in the 1.5+
//! components/services form, compositions, the signature), so an XML SBOM
//! failed NTIA and CISA 2026 rules its JSON twin passed. The XML crypto path
//! failed a CBOM outright when an algorithm listed `<cryptoFunctions>`, read
//! `<cipherSuites>` as one empty suite, and dropped `<cryptoRef>` and the
//! 1.7 `isExternal` attribute, so CNSA 2.0 and NIST PQC saw less than in
//! JSON (plan work package 1.4b).
//!
//! A twin is `<name>.cdx.xml` next to `<name>.cdx.json` anywhere under
//! `tests/fixtures`; every pair found is checked, so a new twin needs no test
//! change. Twins are validated against the official `bom-1.x.xsd` when they
//! are added; here each is checked to be well-formed XML whose root is `bom`
//! in the namespace of its JSON twin's specVersion. A twin keeps every value
//! of its JSON twin, including the few the JSON schema rejects as well (the
//! CBOM fixtures' `key-pair`, `symmetric-key` and `ikev2` types, and
//! `cbom-1.7`'s `version` next to `versionRange`): those are the only XSD
//! errors. The signatures in the twins (XML-DSig in XML, a JSF signature
//! naming the same algorithm URI in JSON) are structural placeholders:
//! nothing verifies them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sbom_tools::model::{
    CompletenessDeclaration, CraSidecarMetadata, CreatorType, CryptoFunction, CryptoPrimitive,
    NormalizedSbom,
};
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

/// The document that showed the crypto gap (work package 1.4): an XSD-valid
/// 1.6 algorithm listing its crypto functions. As XML it did not load at all
/// ("cannot deserialize primitive type from mixed content", exit 3); now it
/// normalizes byte for byte like its JSON twin.
#[test]
fn xml_crypto_functions_document_normalizes_like_json() {
    let json = r#"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "alg",
      "name": "AES-256-GCM",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "ae",
          "parameterSetIdentifier": "256",
          "mode": "gcm",
          "executionEnvironment": "software-plain-ram",
          "implementationPlatform": "x86_64",
          "certificationLevel": ["none"],
          "cryptoFunctions": ["encrypt", "decrypt"],
          "classicalSecurityLevel": 256,
          "nistQuantumSecurityLevel": 1
        }
      }
    }
  ]
}"#;
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="cryptographic-asset" bom-ref="alg">
      <name>AES-256-GCM</name>
      <cryptoProperties>
        <assetType>algorithm</assetType>
        <algorithmProperties>
          <primitive>ae</primitive>
          <parameterSetIdentifier>256</parameterSetIdentifier>
          <executionEnvironment>software-plain-ram</executionEnvironment>
          <implementationPlatform>x86_64</implementationPlatform>
          <certificationLevel>none</certificationLevel>
          <mode>gcm</mode>
          <cryptoFunctions>
            <cryptoFunction>encrypt</cryptoFunction>
            <cryptoFunction>decrypt</cryptoFunction>
          </cryptoFunctions>
          <classicalSecurityLevel>256</classicalSecurityLevel>
          <nistQuantumSecurityLevel>1</nistQuantumSecurityLevel>
        </algorithmProperties>
      </cryptoProperties>
    </component>
  </components>
</bom>"#;
    let from_json = parse_sbom_str(json).expect("the JSON document parses");
    let from_xml = parse_sbom_str(xml).expect("the XML document parses");
    assert_eq!(
        normalized_sbom_json(&from_xml).expect("serialize XML"),
        normalized_sbom_json(&from_json).expect("serialize JSON")
    );
    let functions = from_xml
        .components
        .values()
        .find_map(|c| c.crypto_properties.as_ref()?.algorithm_properties.as_ref())
        .map(|a| a.crypto_functions.clone());
    assert_eq!(
        functions,
        Some(vec![CryptoFunction::Encrypt, CryptoFunction::Decrypt])
    );
}

/// Keeps the CBOM twins meaningful: together their XML populates every crypto
/// property the parser reads, in its 1.6 and 1.7 forms, so a property both
/// encodings dropped cannot pass for parity. (The parser's unit tests cover
/// each element form.)
#[test]
fn twins_cover_every_crypto_property() {
    let mut fields = BTreeSet::new();
    for twin in twins() {
        let sbom = parse(&twin.xml);
        let is_17 = sbom.document.spec_version == "1.7";
        let mut seen = |present: bool, field: &'static str| {
            if present {
                fields.insert(field);
            }
        };
        for comp in sbom.components.values() {
            seen(comp.is_external, "isExternal");
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };
            seen(cp.oid.is_some(), "oid");
            if let Some(a) = &cp.algorithm_properties {
                seen(a.primitive != CryptoPrimitive::Unknown, "primitive");
                seen(a.algorithm_family.is_some(), "algorithmFamily");
                seen(
                    a.parameter_set_identifier.is_some(),
                    "parameterSetIdentifier",
                );
                seen(a.elliptic_curve.is_some() && !is_17, "curve (1.6)");
                seen(a.elliptic_curve.is_some() && is_17, "ellipticCurve (1.7)");
                seen(a.execution_environment.is_some(), "executionEnvironment");
                seen(
                    a.implementation_platform.is_some(),
                    "implementationPlatform",
                );
                seen(!a.certification_level.is_empty(), "certificationLevel");
                seen(a.mode.is_some(), "mode");
                seen(a.padding.is_some(), "padding");
                seen(!a.crypto_functions.is_empty(), "cryptoFunctions");
                seen(
                    a.classical_security_level.is_some() && a.nist_quantum_security_level.is_some(),
                    "securityLevels",
                );
            }
            if let Some(c) = &cp.certificate_properties {
                seen(
                    c.subject_name.is_some() && c.not_valid_after.is_some(),
                    "certificate subject and validity",
                );
                seen(c.certificate_extension.is_some(), "certificateExtension");
                seen(
                    c.related_crypto_assets.is_empty() && c.signature_algorithm_ref.is_some(),
                    "certificate refs (1.6)",
                );
                seen(
                    !c.related_crypto_assets.is_empty(),
                    "certificate relatedCryptographicAssets (1.7)",
                );
            }
            if let Some(m) = &cp.related_crypto_material_properties {
                seen(
                    m.state.is_some() && m.size.is_some(),
                    "material state and size",
                );
                seen(m.secured_by.is_some(), "securedBy");
                seen(
                    m.related_crypto_assets.is_empty() && m.algorithm_ref.is_some(),
                    "material algorithmRef (1.6)",
                );
                seen(
                    !m.related_crypto_assets.is_empty(),
                    "material relatedCryptographicAssets (1.7)",
                );
            }
            if let Some(p) = &cp.protocol_properties {
                seen(
                    p.cipher_suites.iter().any(|s| {
                        s.name.is_some() && !s.algorithms.is_empty() && !s.identifiers.is_empty()
                    }),
                    "cipherSuites",
                );
                seen(
                    p.cipher_suites.iter().any(|s| !s.tls_groups.is_empty()),
                    "tlsGroups (1.7)",
                );
                seen(
                    p.cipher_suites
                        .iter()
                        .any(|s| !s.tls_signature_schemes.is_empty()),
                    "tlsSignatureSchemes (1.7)",
                );
                seen(
                    p.related_crypto_assets.is_empty() && !p.crypto_ref_array.is_empty(),
                    "cryptoRef",
                );
                seen(
                    !p.related_crypto_assets.is_empty(),
                    "protocol relatedCryptographicAssets (1.7)",
                );
                let transforms = p
                    .ikev2_transform_types
                    .as_ref()
                    .map_or(&[][..], |ike| &ike.transforms[..]);
                seen(
                    transforms.iter().any(|t| {
                        t.name.is_none() && t.group.is_none() && t.algorithm_ref.is_some()
                    }),
                    "ikev2 bom-ref form (1.6)",
                );
                seen(
                    transforms
                        .iter()
                        .any(|t| t.name.is_some() || t.group.is_some()),
                    "ikev2 object form (1.7)",
                );
            }
        }
    }
    assert_eq!(
        fields,
        [
            "algorithmFamily",
            "certificate refs (1.6)",
            "certificate relatedCryptographicAssets (1.7)",
            "certificate subject and validity",
            "certificateExtension",
            "certificationLevel",
            "cipherSuites",
            "cryptoFunctions",
            "cryptoRef",
            "curve (1.6)",
            "ellipticCurve (1.7)",
            "executionEnvironment",
            "ikev2 bom-ref form (1.6)",
            "ikev2 object form (1.7)",
            "implementationPlatform",
            "isExternal",
            "material algorithmRef (1.6)",
            "material relatedCryptographicAssets (1.7)",
            "material state and size",
            "mode",
            "oid",
            "padding",
            "parameterSetIdentifier",
            "primitive",
            "protocol relatedCryptographicAssets (1.7)",
            "securedBy",
            "securityLevels",
            "tlsGroups (1.7)",
            "tlsSignatureSchemes (1.7)",
        ]
        .into_iter()
        .collect(),
        "the XML twins must populate every crypto property"
    );
}
