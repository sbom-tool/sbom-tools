//! `validate -o oscal-json` against the OSCAL release it declares.
//!
//! The OSCAL 1.2.3 assessment-results JSON schema is vendored verbatim under
//! `tests/fixtures/schemas/oscal/1.2.3/` (see the README there for its source
//! and digest) and checked with the in-repo validator in
//! `tests/common/json_schema.rs`, extended for the draft-07 keywords the
//! schema uses.
//!
//! The writer's output for every SBOM fixture is validated at every
//! compliance level, along with what the schema cannot express: references
//! that resolve (findings to observations, observations to their subjects),
//! UUIDs unique across the document, one UUID per component. A hostile SBOM
//! and the CLI path are covered too. The validator's own checks are
//! exercised at the bottom of this file: each one must be able to fail.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sbom_tools::model::{CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceLevel, ComplianceResult, ComplianceRunConfig};
use sbom_tools::reports::oscal::{generate_assessment_results, generate_assessment_results_at};
use serde_json::{Value, json};

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/schemas/oscal/1.2.3/oscal_assessment-results_schema.json"
);

/// SHA-256 of the vendored schema: the digest GitHub publishes for the
/// `oscal_assessment-results_schema.json` asset of the v1.2.3 release.
const SCHEMA_SHA256: &str = "4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c";

/// The release the writer declares in `metadata.oscal-version`.
const OSCAL_VERSION: &str = "1.2.3";

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Fixture directories that hold SBOMs (as in tests/compliance_snapshots.rs).
const SBOM_DIRS: &[&str] = &[
    "aibom",
    "compliance/regressions",
    "cra",
    "cyclonedx",
    "showcase",
    "spdx",
    "spdx3",
];

fn schema() -> Value {
    let text = std::fs::read_to_string(SCHEMA_PATH).expect("schema readable");
    serde_json::from_str(&text).expect("schema is JSON")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn assert_valid(schema: &Value, document: &Value, label: &str) {
    if let Err(errors) = json_schema::validate(schema, document) {
        panic!(
            "{label}: {} schema violation(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// The vendored schema
// ---------------------------------------------------------------------------

#[test]
fn vendored_schema_is_the_published_release_asset() {
    let bytes = std::fs::read(SCHEMA_PATH).expect("schema readable");
    assert_eq!(
        sha256_hex(&bytes),
        SCHEMA_SHA256,
        "the vendored schema must stay byte-identical to the release asset"
    );
    let readme =
        std::fs::read_to_string(std::path::Path::new(SCHEMA_PATH).with_file_name("README.md"))
            .expect("README readable");
    assert!(
        readme.contains(SCHEMA_SHA256),
        "the README must record the digest"
    );
    let schema = schema();
    assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
    assert_eq!(
        schema["$id"],
        format!("http://csrc.nist.gov/ns/oscal/{OSCAL_VERSION}/oscal-ar-schema.json")
    );
}

// ---------------------------------------------------------------------------
// The writer: every level on every SBOM fixture
// ---------------------------------------------------------------------------

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

/// Files under the SBOM directories that are not SBOMs (sidecars, docs,
/// scanner configs).
fn is_non_sbom(rel: &str) -> bool {
    [
        ".cra.json",
        ".cra.yaml",
        ".md",
        ".toml",
        "corpus.json",
        ".openvex.json",
    ]
    .iter()
    .any(|suffix| rel.ends_with(suffix))
}

/// A parseable SBOM fixture with its digest and auto-discovered sidecar.
struct Fixture {
    rel: String,
    digest: String,
    sbom: NormalizedSbom,
    sidecar: Option<CraSidecarMetadata>,
}

/// Every parseable SBOM fixture, sorted.
fn fixtures() -> Vec<Fixture> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let root = Path::new(FIXTURES_DIR);
    let mut paths = Vec::new();
    for dir in SBOM_DIRS {
        walk(&root.join(dir), &mut paths);
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let rel = path.strip_prefix(root).ok()?.to_string_lossy().into_owned();
            if is_non_sbom(&rel) {
                return None;
            }
            let raw = std::fs::read_to_string(&path).ok()?;
            let sbom = parse_sbom_str(&raw).ok()?;
            let sidecar = CraSidecarMetadata::discover_for_sbom(&path)
                .unwrap_or_else(|e| panic!("{rel}: sidecar does not load: {e}"));
            Some(Fixture {
                rel,
                digest: sha256_hex(raw.as_bytes()),
                sbom,
                sidecar,
            })
        })
        .collect()
}

/// `level` checked at the pinned instant through the shared run
/// configuration, with `sidecar` where a run hands `level` one (as
/// `validate` does).
fn check(
    sbom: &NormalizedSbom,
    level: ComplianceLevel,
    sidecar: Option<&CraSidecarMetadata>,
) -> ComplianceResult {
    let mut run = ComplianceRunConfig::new().with_as_of(as_of());
    if let Some(sc) = sidecar {
        run = run.with_sidecar(sc.clone());
    }
    run.check(level, sbom)
}

/// The reproducible OSCAL document for `results`, parsed.
fn oscal(fixture: &Fixture, results: &[ComplianceResult]) -> Value {
    let text =
        generate_assessment_results_at(results, &fixture.sbom, &fixture.digest, Some(as_of()))
            .expect("OSCAL serializes");
    serde_json::from_str(&text).expect("OSCAL is JSON")
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value[field].as_array().map_or(&[], Vec::as_slice)
}

fn uuid_of(value: &Value) -> &str {
    value["uuid"].as_str().expect("uuid is a string")
}

/// Every OSCAL markup string in `value` with its path: the `title`,
/// `description` and `remarks` fields at any depth. Property values are plain
/// strings, not markup.
fn markup_fields<'a>(value: &'a Value, path: &str, out: &mut Vec<(String, &'a str)>) {
    match value {
        Value::Object(map) => {
            for (key, field) in map {
                let field_path = format!("{path}/{key}");
                match (key.as_str(), field) {
                    ("title" | "description" | "remarks", Value::String(text)) => {
                        out.push((field_path, text));
                    }
                    _ => markup_fields(field, &field_path, out),
                }
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                markup_fields(item, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// Whether `needle` occurs in `markdown` with its first character live. A
/// character is escaped only by an odd run of backslashes before it: `\\` is
/// an escaped backslash, which leaves the character after it live.
fn contains_live(markdown: &str, needle: &str) -> bool {
    markdown.match_indices(needle).any(|(at, _)| {
        markdown[..at]
            .chars()
            .rev()
            .take_while(|&c| c == '\\')
            .count()
            % 2
            == 0
    })
}

/// Whether a one-line markup field opens a Markdown block of its own: a
/// heading, bullet or ordered list item, quote, or HTML block.
fn opens_a_block(markdown: &str) -> bool {
    let line = markdown.trim_start();
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let ordered = (1..=9).contains(&digits)
        && matches!(line.as_bytes().get(digits), Some(b'.' | b')'))
        && matches!(line.as_bytes().get(digits + 1), None | Some(b' ' | b'\t'));
    line.starts_with(['#', '-', '*', '+', '>', '<']) || ordered
}

/// The S1 rule for OSCAL markup: no field holds a live HTML tag or link
/// bracket, or opens a Markdown block of its own.
fn assert_markup_is_inert(document: &Value, label: &str) {
    let mut fields = Vec::new();
    markup_fields(document, "", &mut fields);
    assert!(!fields.is_empty(), "{label}: no markup fields found");
    for (path, text) in fields {
        for live in ["<", "[", "]"] {
            assert!(
                !contains_live(text, live),
                "{label}: {path} holds a live {live:?}: {text:?}"
            );
        }
        assert!(
            !opens_a_block(text),
            "{label}: {path} opens a Markdown block: {text:?}"
        );
    }
}

/// The SBOM document's `rlink`: present exactly when its document id is an
/// absolute URI, with that href and, as OSCAL's hash-length constraint
/// requires, the 64-digit SHA-256 also given as the `sha256` property.
fn assert_rlink(resource: &Value, label: &str) {
    let identifier = resource["document-ids"][0]["identifier"].as_str();
    let uri =
        regex::Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")
            .expect("valid regex");
    let rlinks = array(resource, "rlinks");
    assert_eq!(
        rlinks.len(),
        usize::from(identifier.is_some_and(|id| uri.is_match(id))),
        "{label}: an rlink exactly when the document id {identifier:?} is a URI"
    );
    if let Some(rlink) = rlinks.first() {
        assert_eq!(rlink["href"].as_str(), identifier, "{label}");
        let sha256 = array(resource, "props")
            .iter()
            .find(|p| p["name"] == "sha256")
            .and_then(|p| p["value"].as_str())
            .expect("sha256 prop");
        assert_eq!(sha256.len(), 64, "{label}: SHA-256 is 64 hex digits");
        assert!(sha256.bytes().all(|b| b.is_ascii_hexdigit()), "{label}");
        assert_eq!(
            rlink["hashes"],
            json!([{ "algorithm": "SHA-256", "value": sha256 }]),
            "{label}"
        );
    }
}

/// What the JSON schema cannot express: the declared release, the
/// observation type, per-assessment UUIDs unique across the document,
/// findings whose related observations exist in their result, and subjects
/// that resolve: the SBOM document to the one back-matter resource, a
/// component to its result's local definitions (OSCAL's
/// `oscal-unique-ar-local-definitions-component` keeps those unique), with
/// one UUID per component across results. Also the SBOM resource's `rlink`
/// ([`assert_rlink`]) and inert markup ([`assert_markup_is_inert`]).
fn assert_invariants(document: &Value, results: &[ComplianceResult], label: &str) {
    let ar = &document["assessment-results"];
    assert_eq!(ar["metadata"]["oscal-version"], OSCAL_VERSION, "{label}");
    let entries = array(ar, "results");
    assert_eq!(
        entries.len(),
        results.len().max(1),
        "{label}: one per standard"
    );
    let resources = array(&ar["back-matter"], "resources");
    assert_eq!(resources.len(), 1, "{label}: the SBOM document resource");
    let document_uuid = uuid_of(&resources[0]);
    assert_rlink(&resources[0], label);
    assert_markup_is_inert(document, label);

    let mut uuids = vec![uuid_of(ar)];
    let mut component_ids: std::collections::HashMap<&str, &str> = Default::default();
    for (i, entry) in entries.iter().enumerate() {
        let passed = results.get(i).map_or(0, |result| result.passed.len());
        let mut control_objectives = 0usize;
        uuids.push(uuid_of(entry));
        let mut local = HashSet::new();
        for component in array(&entry["local-definitions"], "components") {
            assert!(
                local.insert(uuid_of(component)),
                "{label}: component {} defined twice in one result",
                uuid_of(component)
            );
            let id = component["props"]
                .as_array()
                .and_then(|props| props.iter().find(|p| p["name"] == "component-id"))
                .and_then(|p| p["value"].as_str())
                .unwrap_or("");
            let first = *component_ids.entry(uuid_of(component)).or_insert(id);
            assert_eq!(first, id, "{label}: one UUID, two components");
        }
        let mut named = HashSet::new();
        let observations: HashSet<&str> = array(entry, "observations")
            .iter()
            .map(|observation| {
                // OSCAL 1.2 deprecates the `finding` observation type in favour
                // of `discovery`, the type of a violation's observation; a
                // passed check's is about a `control-objective`.
                if observation["types"] == json!(["control-objective"]) {
                    control_objectives += 1;
                } else {
                    assert_eq!(observation["types"], json!(["discovery"]), "{label}");
                }
                let subjects = array(observation, "subjects");
                assert_eq!(subjects[0]["type"], "resource", "{label}");
                assert_eq!(subjects[0]["subject-uuid"], document_uuid, "{label}");
                for subject in &subjects[1..] {
                    assert_eq!(subject["type"], "component", "{label}");
                    let uuid = subject["subject-uuid"].as_str().expect("uuid");
                    assert!(
                        local.contains(uuid),
                        "{label}: subject {uuid} is not a local component"
                    );
                    named.insert(uuid);
                }
                uuid_of(observation)
            })
            .collect();
        assert_eq!(named, local, "{label}: every local component is named");
        assert_eq!(
            control_objectives, passed,
            "{label}: one control-objective observation per passed check"
        );
        uuids.extend(observations.iter().copied());
        for finding in array(entry, "findings") {
            uuids.push(uuid_of(finding));
            for related in array(finding, "related-observations") {
                let target = related["observation-uuid"].as_str().expect("uuid");
                assert!(
                    observations.contains(target),
                    "{label}: finding {} relates to unknown observation {target}",
                    uuid_of(finding)
                );
            }
        }
    }
    uuids.push(document_uuid);
    uuids.extend(component_ids.keys().copied());
    let unique: HashSet<&str> = uuids.iter().copied().collect();
    assert_eq!(unique.len(), uuids.len(), "{label}: duplicate UUIDs");
}

#[test]
fn every_level_on_every_fixture_matches_the_oscal_schema() {
    let schema = schema();
    let fixtures = fixtures();
    assert!(fixtures.len() > 50, "fixture walk found {}", fixtures.len());
    let mut documents = 0;
    for fixture in &fixtures {
        let all: Vec<ComplianceResult> = ComplianceLevel::all()
            .iter()
            .map(|level| check(&fixture.sbom, *level, None))
            .collect();
        // One document per level, as `validate --standard <one>` writes it,
        // and one with every level.
        let mut runs: Vec<(String, Vec<ComplianceResult>)> = all
            .iter()
            .map(|result| {
                (
                    format!("{} [{:?}]", fixture.rel, result.level),
                    vec![result.clone()],
                )
            })
            .collect();
        runs.push((format!("{} [all levels]", fixture.rel), all));
        if let Some(sc) = &fixture.sidecar {
            runs.push((
                format!("{} [sidecar levels + sidecar]", fixture.rel),
                ComplianceLevel::all()
                    .iter()
                    .filter(|level| ComplianceRunConfig::sidecar_applies(**level))
                    .map(|level| check(&fixture.sbom, *level, Some(sc)))
                    .collect(),
            ));
        }
        for (label, results) in runs {
            let document = oscal(fixture, &results);
            assert_valid(&schema, &document, &label);
            assert_invariants(&document, &results, &label);
            documents += 1;
        }
    }
    assert!(
        documents > fixtures.len() * ComplianceLevel::all().len(),
        "validated {documents} documents"
    );
}

#[test]
fn a_run_without_standards_matches_the_oscal_schema() {
    let fixture = fixtures().into_iter().next().expect("a fixture");
    let document = oscal(&fixture, &[]);
    assert_valid(&schema(), &document, "no standards");
    assert_invariants(&document, &[], "no standards");
}

#[test]
fn the_wall_clock_variant_matches_the_oscal_schema() {
    let fixture = fixtures().into_iter().next().expect("a fixture");
    let results: Vec<ComplianceResult> = ComplianceLevel::all()
        .iter()
        .map(|level| check(&fixture.sbom, *level, None))
        .collect();
    let text = generate_assessment_results(&results).expect("OSCAL serializes");
    let document: Value = serde_json::from_str(&text).expect("OSCAL is JSON");
    assert_valid(&schema(), &document, "wall clock");
    assert_invariants(&document, &results, "wall clock");
}

/// An SBOM whose names, versions and identifiers carry what OSCAL `string`
/// and `markup-line` fields reject: edge whitespace, every ECMA line
/// terminator, a lone byte-order mark, and text that is only whitespace.
const HOSTILE_SBOM: &str = r##"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "evil-app\n## Forged product <img src=x onerror=alert(1)>",
      "bom-ref": "app"
    }
  },
  "components": [
    { "type": "library", "name": " lodash\n", "version": "\u2028 4.17.21 ", "bom-ref": " ref\r1 " },
    { "type": "library", "name": "\ufeff", "bom-ref": "\t" },
    { "type": "library", "name": "line\u2029break", "version": " ", "bom-ref": "lb" },
    { "type": "library", "name": "tab\tinside", "version": "1.0", "purl": "pkg:npm/tab-inside@1.0" },
    { "type": "library", "name": "<img src=x onerror=alert(1)>", "version": "*1*", "bom-ref": "img" },
    { "type": "library", "name": "<script>alert(1)</script>", "bom-ref": "script" },
    { "type": "library", "name": "[x](javascript:alert(1))", "bom-ref": "link" },
    { "type": "library", "name": "\\<img src=x onerror=alert(2)>", "bom-ref": "backslash" },
    { "type": "library", "name": "# Forged heading", "bom-ref": "heading" },
    { "type": "library", "name": "- Forged item", "bom-ref": "dash" },
    { "type": "library", "name": "* Forged item", "bom-ref": "star" },
    { "type": "library", "name": "+ Forged item", "bom-ref": "plus" },
    { "type": "library", "name": "1. Forged item", "bom-ref": "ordered" },
    { "type": "library", "name": "> Forged quote", "bom-ref": "quote" }
  ]
}"##;

/// SBOM text reaches OSCAL `string` and markup fields. Whatever it holds,
/// every level's document stays schema-valid, and its markup stays inert:
/// no crafted value opens an HTML tag or a link, or starts a heading, list
/// item or quote of its own, even behind a backslash that would cancel the
/// escape after it (the S1 rule for human-readable output, here applied to
/// the Markdown that OSCAL viewers render). The text is escaped in place,
/// not dropped, and property values keep it plain.
#[test]
fn hostile_sbom_text_keeps_every_level_schema_valid_and_inert() {
    let sbom = parse_sbom_str(HOSTILE_SBOM).expect("hostile SBOM parses");
    let results: Vec<ComplianceResult> = ComplianceLevel::all()
        .iter()
        .map(|level| check(&sbom, *level, None))
        .collect();
    let digest = sha256_hex(HOSTILE_SBOM.as_bytes());
    let text = generate_assessment_results_at(&results, &sbom, &digest, Some(as_of()))
        .expect("OSCAL serializes");
    let document: Value = serde_json::from_str(&text).expect("OSCAL is JSON");
    assert_valid(&schema(), &document, "hostile SBOM");
    // Includes assert_markup_is_inert and assert_rlink.
    assert_invariants(&document, &results, "hostile SBOM");

    let mut fields = Vec::new();
    markup_fields(&document, "", &mut fields);
    for (path, text) in &fields {
        for raw in ["<img", "<script", "[x](javascript"] {
            assert!(
                !contains_live(text, raw),
                "{path}: unescaped {raw:?} in {text:?}"
            );
        }
    }

    let entries = array(&document["assessment-results"], "results");
    let elements: HashSet<&str> = entries
        .iter()
        .flat_map(|entry| array(entry, "observations"))
        .flat_map(|observation| array(observation, "props"))
        .filter(|p| p["name"] == "sbom-element")
        .filter_map(|p| p["value"].as_str())
        .collect();
    // Properties are plain strings: normalized, never escaped.
    for plain in [
        "lodash",
        "line break",
        "tab\tinside",
        "evil-app ## Forged product <img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "- Forged item",
    ] {
        assert!(
            elements.contains(plain),
            "expected the label {plain:?} among {elements:?}"
        );
    }
    let titles: HashSet<&str> = entries
        .iter()
        .flat_map(|entry| array(&entry["local-definitions"], "components"))
        .filter_map(|component| component["title"].as_str())
        .collect();
    for escaped in [
        "lodash 4.17.21",
        "line break",
        "tab\tinside 1.0",
        "evil-app \\#\\# Forged product \\<img src=x onerror=alert(1)\\>",
        "\\<img src=x onerror=alert(1)\\> \\*1\\*",
        "\\<script\\>alert(1)\\</script\\>",
        "\\[x\\](javascript:alert(1))",
        "\\\\\\<img src=x onerror=alert(2)\\>",
        "\\# Forged heading",
        "\\- Forged item",
        "\\* Forged item",
        "\\+ Forged item",
        "1\\. Forged item",
        "\\> Forged quote",
    ] {
        assert!(
            titles.contains(escaped),
            "expected the component title {escaped:?} among {titles:?}"
        );
    }
    let descriptions: Vec<&str> = entries
        .iter()
        .flat_map(|entry| array(entry, "observations"))
        .filter_map(|observation| observation["description"].as_str())
        .collect();
    assert!(
        descriptions
            .iter()
            .any(|d| d.contains("'\\<script\\>alert(1)\\</script\\>'")),
        "violation messages are escaped in place: {descriptions:?}"
    );

    let resource = &document["assessment-results"]["back-matter"]["resources"][0];
    assert_eq!(
        resource["title"],
        "evil-app \\#\\# Forged product \\<img src=x onerror=alert(1)\\> (CycloneDX 1.6 SBOM)"
    );
    assert_eq!(
        resource["rlinks"],
        json!([{
            "href": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "hashes": [{ "algorithm": "SHA-256", "value": digest }]
        }])
    );
}

/// `validate -o oscal-json` end to end: the binary hands the writer the
/// parsed SBOM and the digest of the bytes it read, and the document is
/// schema-valid and byte-identical across runs.
#[test]
fn validate_oscal_json_is_schema_valid_and_reproducible() {
    let path = Path::new(FIXTURES_DIR).join("cyclonedx/minimal.cdx.json");
    let run = || {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
            .args(["--no-color", "validate"])
            .arg(&path)
            .args(["--standard", "ntia,cra", "-o", "oscal-json"])
            .args(["--as-of", "2026-10-12T00:00:00Z"])
            .env("RUST_LOG", "error")
            .output()
            .expect("validate runs");
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "validate must complete: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("stdout is UTF-8")
    };
    let first = run();
    assert_eq!(first, run(), "validate -o oscal-json differs between runs");
    let document: Value = serde_json::from_str(&first).expect("stdout is JSON");
    assert_valid(&schema(), &document, "validate -o oscal-json");

    let resource = &document["assessment-results"]["back-matter"]["resources"][0];
    assert_eq!(resource["title"], "test-app (CycloneDX 1.5 SBOM)");
    let digest = sha256_hex(&std::fs::read(&path).expect("fixture readable"));
    assert!(
        array(resource, "props")
            .iter()
            .any(|p| p["name"] == "sha256" && p["value"] == digest.as_str()),
        "the document subject carries the SHA-256 of the SBOM bytes"
    );
    let entries = array(&document["assessment-results"], "results");
    assert_eq!(entries.len(), 2, "ntia and cra");
    let titles: HashSet<&str> = array(&entries[0]["local-definitions"], "components")
        .iter()
        .filter_map(|component| component["title"].as_str())
        .collect();
    assert!(
        titles.contains("lodash 4.17.21"),
        "components are described from the SBOM: {titles:?}"
    );
}

/// Finding targets are `token`s built from rule ids (`target-id` is the
/// lowercased id), so every registry id must make one.
#[test]
fn every_rule_id_makes_a_valid_oscal_token() {
    let schema = schema();
    let token = &schema["definitions"]["TokenDatatype"];
    assert!(token.is_object(), "the schema defines TokenDatatype");
    for rule_id in sbom_tools::quality::all_rule_ids() {
        let target_id = rule_id.to_ascii_lowercase();
        assert!(
            json_schema::validate(token, &json!(target_id)).is_ok(),
            "{rule_id} does not make an OSCAL token"
        );
    }
}

// ---------------------------------------------------------------------------
// The validator on the OSCAL schema: each check must be able to fail.
// ---------------------------------------------------------------------------

/// A small but complete assessment-results document: one result with an
/// observation, the finding that judges it, a local component the
/// observation names as its subject, and a back-matter resource.
fn minimal_document() -> Value {
    json!({
        "assessment-results": {
            "uuid": "8d1f9a7e-2b4c-5d3e-9f60-718293a4b5c6",
            "metadata": {
                "title": "Assessment results",
                "last-modified": "2026-10-12T00:00:00Z",
                "version": "0.4.0",
                "oscal-version": "1.2.3"
            },
            "import-ap": { "href": "urn:sbom-tools:assessment-plan:validation" },
            "results": [{
                "uuid": "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9",
                "title": "Validation — NTIA",
                "description": "Results.",
                "start": "2026-10-12T00:00:00Z",
                "reviewed-controls": {
                    "control-selections": [{ "include-all": {} }]
                },
                "local-definitions": {
                    "components": [{
                        "uuid": "2c3d4e5f-6071-4829-93a4-b5c6d7e8f901",
                        "type": "software",
                        "title": "lodash 4.17.21",
                        "description": "A component.",
                        "props": [{ "name": "version", "value": "4.17.21" }],
                        "status": { "state": "other" }
                    }]
                },
                "observations": [{
                    "uuid": "3d4e5f60-7182-493a-a4b5-c6d7e8f90123",
                    "title": "SBOM-NTIA-SUPPLIER",
                    "description": "Component 'lodash' missing supplier",
                    "methods": ["EXAMINE"],
                    "types": ["discovery"],
                    "subjects": [{
                        "subject-uuid": "2c3d4e5f-6071-4829-93a4-b5c6d7e8f901",
                        "type": "component"
                    }],
                    "collected": "2026-10-12T00:00:00Z",
                    "props": [{
                        "name": "größe",
                        "ns": "https://sbom.tools/ns/oscal",
                        "value": "a value"
                    }]
                }],
                "findings": [{
                    "uuid": "4e5f6071-8293-4a4b-b5c6-d7e8f9012345",
                    "title": "SBOM-NTIA-SUPPLIER",
                    "description": "Component 'lodash' missing supplier",
                    "target": {
                        "type": "objective-id",
                        "target-id": "sbom-ntia-supplier",
                        "status": { "state": "not-satisfied" }
                    },
                    "related-observations": [{
                        "observation-uuid": "3d4e5f60-7182-493a-a4b5-c6d7e8f90123"
                    }]
                }]
            }],
            "back-matter": {
                "resources": [{
                    "uuid": "5f607182-93a4-4b5c-86d7-e8f901234567",
                    "title": "test-app (CycloneDX 1.6 SBOM)",
                    "props": [{ "name": "type", "value": "artifact" }]
                }]
            }
        }
    })
}

#[test]
fn validator_accepts_the_minimal_document() {
    assert_valid(&schema(), &minimal_document(), "minimal");
}

/// An edit that makes the minimal document invalid.
type Breakage = fn(&mut Value);

/// Each case names the error fragment it must produce, so a breakage cannot
/// pass the test by failing for an unrelated reason.
#[test]
fn validator_rejects_each_kind_of_oscal_violation() {
    let schema = schema();
    let cases: Vec<(&str, &str, Breakage)> = vec![
        ("undeclared field", "oscal_version: undeclared field", |d| {
            d["assessment-results"]["metadata"]["oscal_version"] = json!("1.2.3");
        }),
        (
            "missing required field",
            "missing required field `oscal-version`",
            |d| {
                d["assessment-results"]["metadata"]
                    .as_object_mut()
                    .expect("object")
                    .remove("oscal-version");
            },
        ),
        ("empty array", "observations: fewer than 1 items", |d| {
            d["assessment-results"]["results"][0]["observations"] = json!([]);
        }),
        ("UUID of version 1", "does not match ^[0-9A-Fa-f]{8}", |d| {
            d["assessment-results"]["uuid"] = json!("8d1f9a7e-2b4c-1d3e-9f60-718293a4b5c6");
        }),
        (
            "closed enum under allOf",
            "\"not-applicable\" is not one of",
            |d| {
                d["assessment-results"]["results"][0]["findings"][0]["target"]["status"]["state"] =
                    json!("not-applicable");
            },
        ),
        (
            "neither anyOf alternative",
            "matches none of the 2 anyOf alternatives",
            |d| {
                d["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"]
                    [0] = json!({ "description": "no selection" });
            },
        ),
        (
            "token that starts with a digit",
            "\"1st\" does not match ^(\\p{L}|_)",
            |d| {
                d["assessment-results"]["results"][0]["observations"][0]["props"][0]["name"] =
                    json!("1st");
            },
        ),
        (
            "string with trailing whitespace",
            "\"a value \" does not match ^\\S(.*\\S)?$",
            |d| {
                d["assessment-results"]["results"][0]["observations"][0]["props"][0]["value"] =
                    json!("a value ");
            },
        ),
        (
            "string with a U+2028 line separator (ECMA `.`)",
            "does not match ^\\S(.*\\S)?$",
            |d| {
                d["assessment-results"]["results"][0]["observations"][0]["props"][0]["value"] =
                    json!("a\u{2028}value");
            },
        ),
        (
            "multi-line markup-line title",
            "\"two\\nlines\" does not match",
            |d| {
                d["assessment-results"]["results"][0]["title"] = json!("two\nlines");
            },
        ),
        (
            "uri-reference with a space",
            "\"not a uri\" is not a valid uri-reference",
            |d| {
                d["assessment-results"]["import-ap"]["href"] = json!("not a uri");
            },
        ),
        (
            "timestamp without a timezone",
            "is not a valid date-time",
            |d| {
                d["assessment-results"]["metadata"]["last-modified"] = json!("2026-10-12T00:00:00");
            },
        ),
        (
            "component without its required status",
            "missing required field `status`",
            |d| {
                d["assessment-results"]["results"][0]["local-definitions"]["components"][0]
                    .as_object_mut()
                    .expect("object")
                    .remove("status");
            },
        ),
        (
            "subject reference without a type",
            "missing required field `type`",
            |d| {
                d["assessment-results"]["results"][0]["observations"][0]["subjects"][0]
                    .as_object_mut()
                    .expect("object")
                    .remove("type");
            },
        ),
    ];
    for (what, expected, mutate) in cases {
        let mut document = minimal_document();
        mutate(&mut document);
        let errors = json_schema::validate(&schema, &document)
            .expect_err(&format!("{what} must fail validation"));
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "{what}: expected an error containing {expected:?}, got:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn validator_accepts_what_the_oscal_types_allow() {
    let schema = schema();
    let cases: Vec<(&str, Breakage)> = vec![
        // `types` items are anyOf(token, enum): any token is allowed, and the
        // deprecated `finding` is still in the enum.
        ("an observation type outside the enum", |d| {
            d["assessment-results"]["results"][0]["observations"][0]["types"] =
                json!(["finding", "control-objective", "custom-type"]);
        }),
        ("a non-ASCII token (\\p{L})", |d| {
            d["assessment-results"]["results"][0]["observations"][0]["props"][0]["name"] =
                json!("éléments_1.2-x");
        }),
        ("a bare-fragment uri-reference", |d| {
            d["assessment-results"]["import-ap"]["href"] =
                json!("#5f607182-93a4-4b5c-86d7-e8f901234567");
        }),
        ("a timestamp with an offset", |d| {
            d["assessment-results"]["metadata"]["last-modified"] =
                json!("2026-10-12T05:30:00+05:30");
        }),
    ];
    for (what, mutate) in cases {
        let mut document = minimal_document();
        mutate(&mut document);
        assert_valid(&schema, &document, what);
    }
}

// ---------------------------------------------------------------------------
// The validator's draft-07 and ECMA-262 semantics, in isolation
// ---------------------------------------------------------------------------

#[test]
fn draft_07_ref_hides_its_siblings_and_later_drafts_apply_them() {
    let body = json!({
        "definitions": { "text": { "type": "string" } },
        "$ref": "#/definitions/text",
        "minLength": 5
    });
    let mut draft_07 = body.clone();
    draft_07["$schema"] = json!("http://json-schema.org/draft-07/schema#");
    assert!(
        json_schema::validate(&draft_07, &json!("abc")).is_ok(),
        "draft-07 ignores minLength next to $ref"
    );
    assert!(json_schema::validate(&draft_07, &json!(3)).is_err());
    let mut draft_2020 = body;
    draft_2020["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    assert!(
        json_schema::validate(&draft_2020, &json!("abc")).is_err(),
        "2020-12 applies minLength next to $ref"
    );
}

#[test]
fn any_of_and_all_of() {
    let any_of = json!({ "anyOf": [{ "type": "string" }, { "minimum": 10 }] });
    assert!(json_schema::validate(&any_of, &json!("x")).is_ok());
    assert!(json_schema::validate(&any_of, &json!(12)).is_ok());
    assert!(json_schema::validate(&any_of, &json!(3)).is_err());
    let all_of = json!({ "allOf": [{ "type": "integer" }, { "minimum": 10 }] });
    assert!(json_schema::validate(&all_of, &json!(12)).is_ok());
    assert!(json_schema::validate(&all_of, &json!(3)).is_err());
    assert!(json_schema::validate(&all_of, &json!("12")).is_err());
}

#[test]
fn patterns_follow_ecma_262_not_regex_crate_syntax() {
    let matches = |pattern: &str, s: &str| {
        json_schema::validate(&json!({ "pattern": pattern }), &json!(s)).is_ok()
    };
    // `.` excludes every ECMA line terminator; `regex` only excludes \n.
    for terminator in ["\n", "\r", "\u{2028}", "\u{2029}"] {
        assert!(
            !matches("^a.b$", &format!("a{terminator}b")),
            "{terminator:?}"
        );
    }
    assert!(
        matches("^a.b$", "a\u{85}b"),
        "NEL is not an ECMA line terminator"
    );
    // `\s` is ECMA's whitespace set: U+FEFF in, U+0085 out.
    assert!(matches(r"^\s$", "\u{feff}"));
    assert!(!matches(r"^\s$", "\u{85}"));
    assert!(matches(r"^\S$", "\u{85}"));
    // `\d` and `\w` are ASCII-only.
    assert!(!matches(r"^\d$", "\u{663}"), "ARABIC-INDIC DIGIT THREE");
    assert!(!matches(r"^\w$", "é"));
    assert!(matches(r"^[\w.]+$", "a_1.b"));
    // Unicode property escapes keep their meaning.
    assert!(matches(r"^\p{L}+$", "größe"));
    assert!(!matches(r"^\p{L}+$", "x1"));
    // Inside a class, `[` is a literal.
    assert!(matches(r"^[[a]+$", "[a["));
    // The OSCAL string datatype rejects edge whitespace, including U+FEFF.
    let string_datatype = r"^\S(.*\S)?$";
    assert!(matches(string_datatype, "a b"));
    assert!(!matches(string_datatype, " a"));
    assert!(!matches(string_datatype, "a\u{feff}"));
    assert!(!matches(string_datatype, "a\rb"));
}

#[test]
#[should_panic(expected = "unsupported in pattern")]
fn patterns_whose_ecma_meaning_cannot_be_translated_panic() {
    json_schema::ecma_to_rust("^[^]$");
}

#[test]
fn formats_are_asserted() {
    let valid = |format: &str, s: &str| {
        json_schema::validate(&json!({ "format": format }), &json!(s)).is_ok()
    };
    assert!(valid("date-time", "2026-10-12T00:00:00Z"));
    assert!(valid("date-time", "2026-10-12T00:00:00.5-04:00"));
    assert!(!valid("date-time", "2026-10-12"));
    assert!(!valid("date-time", "2026-02-30T00:00:00Z"));
    assert!(valid("uri", "https://sbom.tools/ns/oscal"));
    assert!(valid(
        "uri",
        "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
    ));
    assert!(!valid("uri", "relative/path"));
    assert!(!valid("uri", "https://example.com/a b"));
    assert!(!valid("uri", "1http://example.com"));
    assert!(valid("uri-reference", "relative/path?q=1#frag"));
    assert!(valid(
        "uri-reference",
        "#5f607182-93a4-4b5c-86d7-e8f901234567"
    ));
    assert!(valid("uri-reference", "%41"));
    assert!(!valid("uri-reference", "%4"));
    assert!(!valid("uri-reference", "a#b#c"));
    assert!(
        !valid("uri-reference", "1a:b"),
        "a relative ref has no colon in its first segment"
    );
    assert!(valid("email", "security@example.com"));
    assert!(!valid("email", "no-at-sign"));
    assert!(!valid("email", "a b@example.com"));
}

#[test]
#[should_panic(expected = "unsupported JSON Schema format `ipv4`")]
fn validator_refuses_formats_it_does_not_implement() {
    let _ = json_schema::validate(&json!({ "format": "ipv4" }), &json!("127.0.0.1"));
}
