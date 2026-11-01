//! The `sbom-tools/compliance/v2` envelope against its published schema.
//!
//! Every compliance level is rendered for every SBOM fixture and validated
//! twice: against `schemas/compliance/v2.schema.json` as published, and
//! against a strict copy that rejects undeclared fields, so a field the
//! envelope starts emitting cannot ship without a schema entry. The CLI side
//! (`validate -o json` for every `--standard`) is covered in
//! tests/cli_contract_tests.rs.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::path::{Path, PathBuf};

use sbom_tools::model::{CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    CnsaCategory, ComplianceChecker, ComplianceLevel, ComplianceResult, DOCUMENT_SUBJECT, PqcMode,
    PqcProfile, RuleKind, finding_id, rule_kind, standard_key,
};
use sbom_tools::reports::{
    AssessedSbom, COMPLIANCE_JSON_SCHEMA, generate_compliance_json, generate_compliance_json_at,
};
use serde_json::{Value, json};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/compliance/v2.schema.json"
);

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

/// A parseable SBOM fixture: its path, text, parsed document and
/// auto-discovered sidecar.
type Fixture = (String, String, NormalizedSbom, Option<CraSidecarMetadata>);

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
            Some((rel, raw, sbom, sidecar))
        })
        .collect()
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

/// `level` under `--pqc-mode deadline` at `as_of`.
fn deadline_check(
    sbom: &NormalizedSbom,
    level: ComplianceLevel,
    as_of: &str,
    profile: PqcProfile,
    category: Option<CnsaCategory>,
) -> ComplianceResult {
    let instant = chrono::DateTime::parse_from_rfc3339(as_of)
        .expect("valid instant")
        .with_timezone(&chrono::Utc);
    let mut checker = ComplianceChecker::new(level)
        .with_as_of(instant)
        .with_pqc_mode(PqcMode::Deadline)
        .with_pqc_profile(profile);
    if let Some(category) = category {
        checker = checker.with_cnsa_category(category);
    }
    checker.check(sbom)
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

/// The envelope `validate` writes for `results` about `raw`, the text of
/// the SBOM at `rel`, judged at the pinned instant.
fn envelope_at(results: &[ComplianceResult], sbom: &NormalizedSbom, raw: &str, rel: &str) -> Value {
    let assessed = AssessedSbom::new(sbom, raw.as_bytes()).with_file_name(rel);
    let json = generate_compliance_json_at(results, &assessed, as_of()).expect("serializes");
    serde_json::from_str(&json).expect("envelope is JSON")
}

/// The subject states the SBOM's digest, format, version and file name, and
/// counts what the parser read; `as_of` states the pinned instant.
fn assert_subject(envelope: &Value, sbom: &NormalizedSbom, raw: &str, rel: &str, label: &str) {
    use sha2::{Digest, Sha256};
    let subject = &envelope["subject"];
    let digest: String = Sha256::digest(raw.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(envelope["as_of"], "2026-10-12T00:00:00Z", "{label}");
    assert_eq!(subject["sha256"], digest, "{label}");
    assert_eq!(
        subject["format"],
        sbom.document.format.to_string(),
        "{label}"
    );
    assert_eq!(
        subject["spec_version"], sbom.document.spec_version,
        "{label}"
    );
    let name = rel.rsplit('/').next().expect("a file name");
    assert_eq!(subject["file_name"], name, "{label}");
    assert_eq!(subject["components"], sbom.component_count(), "{label}");
    let duplicates = &subject["duplicates"];
    assert_eq!(
        duplicates["components"],
        sbom.duplicate_components.len(),
        "{label}"
    );
    let entries: usize = sbom.duplicate_components.values().map(|d| d.entries).sum();
    assert_eq!(duplicates["entries"], entries, "{label}");
    assert_eq!(
        subject["timestamp_unparsed"],
        sbom.document.created_unparsed.is_some(),
        "{label}"
    );
}

/// The invariants the schema cannot express on its own.
fn assert_envelope_invariants(envelope: &Value, results: &[ComplianceResult], label: &str) {
    assert_eq!(envelope["schema"], COMPLIANCE_JSON_SCHEMA, "{label}");
    let entries = envelope["results"].as_array().expect("results array");
    assert_eq!(entries.len(), results.len(), "{label}");
    for (entry, result) in entries.iter().zip(results) {
        let standard = standard_key(result.level);
        assert_eq!(entry["standard"], standard, "{label}");
        assert_eq!(entry["name"], result.level.name(), "{label}");
        let applicable = entry["applicable"].as_bool().expect("applicable");
        assert_eq!(applicable, result.is_applicable(), "{label}");
        assert_eq!(
            entry["not_applicable_reason"].is_string(),
            !applicable,
            "{label}: a reason exactly when N/A"
        );
        assert_eq!(
            entry["score"].is_null(),
            !applicable,
            "{label}: a null score exactly when N/A"
        );
        assert_eq!(
            entry.get("score_basis").is_some(),
            applicable,
            "{label}: a score basis exactly when applicable"
        );
        if applicable {
            // The documented formula, from the envelope's own fields.
            let basis = &entry["score_basis"];
            let checked = basis["checked"].as_u64().expect("checked");
            let failed = basis["failed"].as_u64().expect("failed");
            assert!(checked >= 1, "{label}: the document is always checked");
            let band = if entry["compliant"] == true { 50 } else { 0 };
            let within = if failed == 0 {
                50
            } else {
                50 * checked / (checked + failed)
            };
            assert_eq!(entry["score"], band + within, "{label}: {standard}");
        }
        let violations = entry["violations"].as_array().expect("violations");
        for severity in ["Error", "Warning", "Info"] {
            let counted = violations
                .iter()
                .filter(|v| v["severity"] == severity)
                .count();
            assert_eq!(
                entry["counts"][severity.to_ascii_lowercase()],
                counted,
                "{label}: counts.{severity}"
            );
        }
        let passed = entry["passed"].as_array().expect("passed");
        assert_eq!(entry["counts"]["passed"], passed.len(), "{label}");
        assert_eq!(passed.len(), result.passed.len(), "{label}");
        for v in violations {
            let rule = v["rule_id"].as_str().expect("rule_id");
            assert_eq!(
                rule_kind(rule),
                Some(RuleKind::Finding),
                "{label}: {rule} is a pass-only rule reported as a violation"
            );
        }
        for p in passed {
            let rule = p["rule_id"].as_str().expect("rule_id");
            assert_eq!(
                rule_kind(rule),
                Some(RuleKind::Pass),
                "{label}: {rule} reports a pass but is no pass-only rule"
            );
        }
        // Violations and passes share one key space: SARIF and OSCAL key
        // both by finding id.
        let mut keys = std::collections::BTreeSet::new();
        for v in violations.iter().chain(passed) {
            let key = v["finding_key"].as_str().expect("finding_key");
            assert!(keys.insert(key), "{label}: {key} repeats");
            assert_eq!(v["finding_id"], finding_id(key).as_str(), "{label}");
            let subject = match v["component_id"].as_str() {
                None => DOCUMENT_SUBJECT.to_string(),
                Some(id)
                    if id == DOCUMENT_SUBJECT
                        || id.starts_with("edge:")
                        || id.starts_with("component:") =>
                {
                    format!("component:{id}")
                }
                Some(id) => id.to_string(),
            };
            let rule = v["rule_id"].as_str().expect("rule_id");
            let detail = v["finding_detail"].as_str().map_or_else(String::new, |d| {
                let encoded = d
                    .replace('%', "%25")
                    .replace('|', "%7C")
                    .replace(':', "%3A");
                format!(":{encoded}")
            });
            assert_eq!(
                key,
                format!("{standard}|{rule}{detail}|{subject}"),
                "{label}"
            );
        }
    }
}

#[test]
fn every_level_on_every_fixture_matches_the_schema_and_its_strict_copy() {
    let schema = schema();
    let strict = json_schema::strict_copy(&schema);
    let fixtures = fixtures();
    assert!(fixtures.len() > 50, "fixture walk found {}", fixtures.len());
    let mut documents = 0;
    for (rel, raw, sbom, sidecar) in &fixtures {
        // The envelope has no per-count branch, so one envelope carrying
        // every level covers each level's result.
        let mut envelopes: Vec<(String, Vec<ComplianceResult>)> = vec![(
            format!("{rel} [all levels]"),
            ComplianceLevel::all()
                .iter()
                .map(|level| check(sbom, *level, None))
                .collect(),
        )];
        // The crypto standards in deadline mode, which is where `deadline`
        // and `deadline_source` appear: the federal profile in the 2030
        // deprecation window (Warnings and Errors) and a CNSA 2.0 category
        // still before its milestones (Infos).
        envelopes.push((
            format!("{rel} [--pqc-mode deadline]"),
            vec![
                deadline_check(
                    sbom,
                    ComplianceLevel::NistPqc,
                    "2031-06-01T00:00:00Z",
                    PqcProfile::Federal,
                    None,
                ),
                deadline_check(
                    sbom,
                    ComplianceLevel::Cnsa2,
                    "2026-10-12T00:00:00Z",
                    PqcProfile::Nist,
                    Some(CnsaCategory::Niche),
                ),
            ],
        ));
        // The CRA family with the fixture's sidecar, which is where
        // `conformity_summary` appears.
        if let Some(sc) = sidecar {
            let with_sidecar = [
                ComplianceLevel::CraPhase1,
                ComplianceLevel::CraPhase2,
                ComplianceLevel::CraOssSteward,
            ]
            .iter()
            .map(|level| check(sbom, *level, Some(sc)))
            .collect();
            envelopes.push((format!("{rel} [CRA + sidecar]"), with_sidecar));
        }
        for (label, results) in envelopes {
            let document = envelope_at(&results, sbom, raw, rel);
            assert_valid(&schema, &document, &label);
            assert_valid(&strict, &document, &format!("{label} (strict)"));
            assert_envelope_invariants(&document, &results, &label);
            assert_subject(&document, sbom, raw, rel, &label);
            // Without the SBOM, the envelope says nothing about the run.
            let bare: Value = serde_json::from_str(
                &generate_compliance_json(&results).expect("envelope serializes"),
            )
            .expect("envelope is JSON");
            assert_valid(&strict, &bare, &format!("{label} (strict, no subject)"));
            assert!(bare.get("subject").is_none() && bare.get("as_of").is_none());
            documents += 1;
        }
    }
    assert!(
        documents > fixtures.len(),
        "validated {documents} envelopes"
    );
}

#[test]
fn conformity_summary_is_declared_by_the_schema() {
    // Pinning a product class attaches the Annex VIII checklist; the walk
    // above only sees it where a fixture ships a sidecar with a class.
    let raw = std::fs::read_to_string(Path::new(FIXTURES_DIR).join("demo-new.cdx.json"))
        .expect("fixture readable");
    let sbom = parse_sbom_str(&raw).expect("fixture parses");
    let schema = schema();
    let strict = json_schema::strict_copy(&schema);
    for class in [
        sbom_tools::model::CraProductClass::Default,
        sbom_tools::model::CraProductClass::ImportantClass1,
        sbom_tools::model::CraProductClass::ImportantClass2,
        sbom_tools::model::CraProductClass::Critical,
    ] {
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_as_of(as_of())
            .with_product_class(class)
            .check(&sbom);
        assert!(result.conformity_summary.is_some(), "{class:?}");
        let document: Value = serde_json::from_str(
            &generate_compliance_json(std::slice::from_ref(&result)).expect("serializes"),
        )
        .expect("JSON");
        assert!(
            document["results"][0]["conformity_summary"].is_object(),
            "{class:?}"
        );
        assert_valid(&schema, &document, &format!("{class:?}"));
        assert_valid(&strict, &document, &format!("{class:?} (strict)"));
    }
}

/// Forward compatibility: later releases add fields without a version bump,
/// so the published schema itself must not reject unknown fields.
#[test]
fn published_schema_accepts_unknown_fields() {
    fn walk(value: &Value, path: &str) {
        match value {
            Value::Object(map) => {
                assert_ne!(
                    map.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{path} closes the object"
                );
                for (key, sub) in map {
                    walk(sub, &format!("{path}/{key}"));
                }
            }
            Value::Array(items) => {
                for (i, sub) in items.iter().enumerate() {
                    walk(sub, &format!("{path}/{i}"));
                }
            }
            _ => {}
        }
    }
    let schema = schema();
    walk(&schema, "#");
    assert_eq!(
        schema["properties"]["schema"]["const"],
        COMPLIANCE_JSON_SCHEMA
    );

    let mut document = minimal_envelope();
    document["new_top_level_field"] = json!(1);
    document["results"][0]["new_result_field"] = json!("x");
    document["results"][0]["violations"][0]["new_violation_field"] = json!(true);
    assert_valid(&schema, &document, "unknown fields");
}

/// The violation fields the rule registry fills are declared.
#[test]
fn schema_declares_the_announced_optional_fields() {
    let schema = schema();
    let mut document = minimal_envelope();
    document["results"][0]["violations"][0]["remediation"] = json!("Add a supplier.");
    document["results"][0]["violations"][0]["help_uri"] = json!("https://example.com/rule");
    assert_valid(
        &json_schema::strict_copy(&schema),
        &document,
        "announced fields",
    );
}

/// A passed check, with every field it can carry, is declared.
#[test]
fn schema_declares_passed_checks() {
    let schema = schema();
    let document = envelope_with_pass();
    assert_valid(&schema, &document, "passed check");
    assert_valid(
        &json_schema::strict_copy(&schema),
        &document,
        "passed check (strict)",
    );
}

/// A finding with a detail: `finding_detail` is declared, and the key keeps
/// the pattern because the detail's own `|` and `:` are encoded.
#[test]
fn schema_declares_finding_detail() {
    let schema = schema();
    let key = "ntia|SBOM-NTIA-AUTHOR:a%7Cb%3Ac|document";
    let mut document = minimal_envelope();
    let violation = &mut document["results"][0]["violations"][0];
    violation["finding_detail"] = json!("a|b:c");
    violation["finding_key"] = json!(key);
    violation["finding_id"] = json!(finding_id(key));
    assert_valid(
        &json_schema::strict_copy(&schema),
        &document,
        "finding_detail",
    );
}

/// [`minimal_envelope`] with a violation's `field` and `observed`, and the
/// result's checks not evaluated.
fn envelope_with_explainability() -> Value {
    let mut document = minimal_envelope();
    let violation = &mut document["results"][0]["violations"][0];
    violation["field"] = json!("metadata.authors[]");
    violation["observed"] = json!("NOASSERTION");
    document["results"][0]["evaluated"] = json!([{
        "rule_id": "SBOM-NTIA-SPEC-VERSION",
        "status": "not_evaluated",
        "reason": "the document's spec version does not parse, so its range cannot be checked"
    }]);
    document
}

/// `field`, `observed` and `evaluated` are declared, so the strict copy
/// accepts them.
#[test]
fn schema_declares_explainability_fields() {
    let schema = schema();
    let document = envelope_with_explainability();
    assert_valid(&schema, &document, "explainability");
    assert_valid(
        &json_schema::strict_copy(&schema),
        &document,
        "explainability (strict)",
    );
    let cases: Vec<(&str, Breakage)> = vec![
        ("observed over 200 characters", |d| {
            d["results"][0]["violations"][0]["observed"] = json!("x".repeat(201));
        }),
        ("unknown evaluation status", |d| {
            d["results"][0]["evaluated"][0]["status"] = json!("passed");
        }),
        ("evaluation without a reason", |d| {
            d["results"][0]["evaluated"][0]
                .as_object_mut()
                .expect("object")
                .remove("reason");
        }),
        ("empty evaluated list", |d| {
            d["results"][0]["evaluated"] = json!([])
        }),
    ];
    for (what, mutate) in cases {
        let mut document = envelope_with_explainability();
        mutate(&mut document);
        assert!(
            json_schema::validate(&schema, &document).is_err(),
            "{what} must fail validation"
        );
    }
    let strict = json_schema::strict_copy(&schema);
    let mut document = envelope_with_explainability();
    document["results"][0]["evaluated"][0]["undeclared"] = json!(0);
    assert!(
        json_schema::validate(&strict, &document).is_err(),
        "an undeclared field in an evaluation must fail the strict copy"
    );
}

/// A CycloneDX document that lists one component twice, with two
/// descriptions, and whose creation timestamp does not parse.
const DUPLICATES: &str = r#"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-13-45 noon",
    "component": { "type": "application", "name": "app", "version": "1.0", "bom-ref": "app" }
  },
  "components": [
    { "type": "library", "name": "lodash", "version": "4.17.21", "bom-ref": "a",
      "purl": "pkg:npm/lodash@4.17.21", "description": "one" },
    { "type": "library", "name": "lodash", "version": "4.17.21", "bom-ref": "b",
      "purl": "pkg:npm/lodash@4.17.21", "description": "two" }
  ]
}"#;

/// The subject says how the document was read: one component in two
/// entries, merged with a conflict, and a timestamp that does not parse.
/// Every standard's envelope says it, not only those whose checks report
/// the duplicate.
#[test]
fn the_subject_says_how_the_document_was_read() {
    let sbom = parse_sbom_str(DUPLICATES).expect("parses");
    let strict = json_schema::strict_copy(&schema());
    for level in [ComplianceLevel::NtiaMinimum, ComplianceLevel::Cnsa2] {
        let label = format!("{level:?}");
        let result = check(&sbom, level, None);
        let document = envelope_at(
            std::slice::from_ref(&result),
            &sbom,
            DUPLICATES,
            "dup.cdx.json",
        );
        assert_valid(&strict, &document, &label);
        assert_subject(&document, &sbom, DUPLICATES, "dup.cdx.json", &label);
        assert_eq!(
            document["subject"]["duplicates"],
            json!({"components": 1, "entries": 2, "conflicts": ["description"]}),
            "{label}"
        );
        assert_eq!(document["subject"]["timestamp_unparsed"], true, "{label}");
        assert_eq!(
            document["subject"]["components"], 2,
            "the product and lodash"
        );
    }
}

fn minimal_envelope() -> Value {
    json!({
        "schema": "sbom-tools/compliance/v2",
        "tool": {"name": "sbom-tools", "version": "0.4.0"},
        "results": [{
            "standard": "ntia",
            "name": "NTIA Minimum Elements",
            "applicable": true,
            "compliant": false,
            "score": 25,
            "score_basis": {"checked": 1, "failed": 1},
            "counts": {"error": 1, "warning": 0, "info": 0, "passed": 0},
            "violations": [{
                "finding_id": "sbomtools:v1:60072ae05d1ef4b8",
                "finding_key": "ntia|SBOM-NTIA-AUTHOR|document",
                "severity": "Error",
                "category": "DocumentMetadata",
                "message": "SBOM must have creator/tool information",
                "element": null,
                "requirement": "NTIA Minimum Elements: Author",
                "rule_id": "SBOM-NTIA-AUTHOR",
                "sarif_rule_id": "SBOM-NTIA-AUTHOR"
            }],
            "passed": []
        }]
    })
}

/// [`minimal_envelope`] with one passed check carrying every field a pass
/// can carry.
fn envelope_with_pass() -> Value {
    let key = "ntia|SBOM-PQC-009:alg%3A1|crypto/algorithm/ml-kem-1024";
    let mut document = minimal_envelope();
    document["results"][0]["counts"]["passed"] = json!(1);
    document["results"][0]["passed"] = json!([{
        "finding_id": finding_id(key),
        "finding_key": key,
        "message": "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)",
        "element": "ML-KEM-1024",
        "component_id": "crypto/algorithm/ml-kem-1024",
        "finding_detail": "alg:1",
        "requirement": "FIPS 203/204/205: approved",
        "rule_id": "SBOM-PQC-009",
        "sarif_rule_id": "SBOM-PQC-009",
        "standard_refs": [{"standard": "NistPqc", "id": "FIPS 203/204/205"}]
    }]);
    document
}

// ---------------------------------------------------------------------------
// The validator itself: each check must be able to fail.
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_the_minimal_envelope() {
    let schema = schema();
    assert_valid(&schema, &minimal_envelope(), "minimal");
    assert_valid(
        &json_schema::strict_copy(&schema),
        &minimal_envelope(),
        "minimal strict",
    );
}

/// An edit that makes the minimal envelope invalid.
type Breakage = fn(&mut Value);

#[test]
fn validator_rejects_each_kind_of_violation() {
    let schema = schema();
    let cases: Vec<(&str, Breakage)> = vec![
        ("wrong schema const", |d| {
            d["schema"] = json!("sbom-tools/compliance/v1")
        }),
        ("missing required", |d| {
            d.as_object_mut().expect("object").remove("tool");
        }),
        ("wrong type", |d| d["results"][0]["score"] = json!("50")),
        ("integer expected", |d| {
            d["results"][0]["counts"]["error"] = json!(1.5)
        }),
        ("below minimum", |d| {
            d["results"][0]["counts"]["error"] = json!(-1)
        }),
        ("above maximum", |d| d["results"][0]["score"] = json!(101)),
        ("not in enum", |d| {
            d["results"][0]["violations"][0]["severity"] = json!("Fatal")
        }),
        ("pattern mismatch", |d| {
            d["results"][0]["violations"][0]["finding_id"] = json!("sbomtools:v1:XYZ");
        }),
        ("empty results", |d| d["results"] = json!([])),
        ("too short", |d| d["tool"]["version"] = json!("")),
        ("nested required", |d| {
            d["results"][0]["violations"][0]
                .as_object_mut()
                .expect("object")
                .remove("finding_key");
        }),
        ("passed missing", |d| {
            d["results"][0]
                .as_object_mut()
                .expect("object")
                .remove("passed");
        }),
        ("passed count missing", |d| {
            d["results"][0]["counts"]
                .as_object_mut()
                .expect("object")
                .remove("passed");
        }),
        ("passed check without identity", |d| {
            d["results"][0]["passed"] = json!([{"message": "m", "element": null,
                "requirement": "r", "rule_id": "SBOM-PQC-009", "sarif_rule_id": "SBOM-PQC-009"}]);
        }),
    ];
    for (what, mutate) in cases {
        let mut document = minimal_envelope();
        mutate(&mut document);
        assert!(
            json_schema::validate(&schema, &document).is_err(),
            "{what} must fail validation"
        );
    }
}

/// [`envelope_with_pass`] with the run's instant and subject.
fn envelope_with_subject() -> Value {
    let mut document = envelope_with_pass();
    document["as_of"] = json!("2026-10-12T00:00:00Z");
    document["subject"] = json!({
        "sha256": "be7995c235de8f84244baf2d5cd4a217deb705904ffe2e874647f3e3c0824d96",
        "format": "CycloneDX",
        "spec_version": "1.5",
        "file_name": "minimal.cdx.json",
        "components": 3,
        "duplicates": {"components": 0, "entries": 0, "conflicts": []},
        "timestamp_unparsed": false
    });
    document
}

#[test]
fn schema_declares_the_subject() {
    let schema = schema();
    let document = envelope_with_subject();
    assert_valid(&schema, &document, "subject");
    assert_valid(
        &json_schema::strict_copy(&schema),
        &document,
        "subject (strict)",
    );
    let cases: Vec<(&str, Breakage)> = vec![
        ("a digest that is no SHA-256", |d| {
            d["subject"]["sha256"] = json!("abc123")
        }),
        ("an unknown format", |d| {
            d["subject"]["format"] = json!("SWID")
        }),
        ("an instant that is no date-time", |d| {
            d["as_of"] = json!("2026-10-12")
        }),
        ("a repeated conflict", |d| {
            d["subject"]["duplicates"]["conflicts"] = json!(["description", "description"])
        }),
        ("no duplicate counts", |d| {
            d["subject"]
                .as_object_mut()
                .expect("object")
                .remove("duplicates");
        }),
    ];
    for (what, mutate) in cases {
        let mut document = envelope_with_subject();
        mutate(&mut document);
        assert!(
            json_schema::validate(&schema, &document).is_err(),
            "{what} must fail validation"
        );
    }
}

#[test]
fn strict_copy_rejects_undeclared_fields_at_every_level() {
    let strict = json_schema::strict_copy(&schema());
    for pointer in [
        "",
        "/tool",
        "/subject",
        "/subject/duplicates",
        "/results/0",
        "/results/0/counts",
        "/results/0/violations/0",
        "/results/0/passed/0",
    ] {
        let mut document = envelope_with_subject();
        document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("object at pointer")
            .insert("undeclared".to_string(), json!(0));
        assert!(
            json_schema::validate(&strict, &document).is_err(),
            "undeclared field at {pointer:?} must fail the strict copy"
        );
    }
}

#[test]
#[should_panic(expected = "unsupported JSON Schema keyword `not`")]
fn validator_refuses_keywords_it_does_not_implement() {
    let schema = json!({"not": {"type": "number"}});
    let _ = json_schema::validate(&schema, &json!("x"));
}
