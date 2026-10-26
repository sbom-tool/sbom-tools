//! Every `-o sarif` writer against the SARIF 2.1.0 schema it declares.
//!
//! The OASIS SARIF 2.1.0 schema (Errata 01) is vendored verbatim under
//! `tests/fixtures/schemas/sarif/2.1.0/` (see the README there for its source
//! and digest) and checked with the in-repo validator in
//! `tests/common/json_schema.rs`, extended for the draft-04 keywords the
//! schema uses (`oneOf`, `uniqueItems`, `default`, `id`).
//!
//! Covered: `validate` (one standard and several) at every level on every
//! SBOM fixture, `quality` for every scoring profile, the AI-readiness
//! profile, and the `diff` and `view` reporters. The validator's draft-04
//! keywords are exercised at the bottom: each check must be able to fail.

#[path = "common/json_schema.rs"]
mod json_schema;
#[path = "common/sbom_fixtures.rs"]
mod sbom_fixtures;

use sbom_tools::quality::{ComplianceLevel, ComplianceResult, QualityScorer, ScoringProfile};
use sbom_tools::reports::{
    ReportConfig, ReportGenerator, SARIF_SCHEMA_URI, SarifArtifact, SarifArtifactLocation,
    SarifOptions, SarifReporter, generate_ai_readiness_sarif_with, generate_compliance_sarif_with,
    generate_multi_compliance_sarif, generate_multi_compliance_sarif_with,
    generate_quality_sarif_with,
};
use sbom_tools::{DiffEngine, parse_sbom_str};
use serde_json::{Value, json};

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/schemas/sarif/2.1.0/sarif-schema-2.1.0.json"
);

/// SHA-256 of the vendored schema as published by OASIS.
const SCHEMA_SHA256: &str = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e";

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

/// Parse `sarif` and check it against the schema, failing with every
/// violation found.
fn assert_valid(schema: &Value, sarif: &str, label: &str) -> Value {
    let document: Value =
        serde_json::from_str(sarif).unwrap_or_else(|e| panic!("{label}: not JSON: {e}"));
    if let Err(errors) = json_schema::validate(schema, &document) {
        panic!(
            "{label}: {} schema violation(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
    assert_eq!(document["$schema"], SARIF_SCHEMA_URI, "{label}");
    assert_eq!(document["version"], "2.1.0", "{label}");
    document
}

// ---------------------------------------------------------------------------
// The vendored schema
// ---------------------------------------------------------------------------

#[test]
fn vendored_schema_is_the_published_oasis_schema() {
    let bytes = std::fs::read(SCHEMA_PATH).expect("schema readable");
    assert_eq!(
        sha256_hex(&bytes),
        SCHEMA_SHA256,
        "the vendored schema must stay byte-identical to the OASIS publication"
    );
    let readme =
        std::fs::read_to_string(std::path::Path::new(SCHEMA_PATH).with_file_name("README.md"))
            .expect("README readable");
    assert!(
        readme.contains(SCHEMA_SHA256),
        "the README must record the digest"
    );
    let schema = schema();
    assert_eq!(schema["$schema"], "http://json-schema.org/draft-04/schema#");
    assert_eq!(
        schema["id"], SARIF_SCHEMA_URI,
        "the writers declare the schema's own id as their $schema"
    );
}

// ---------------------------------------------------------------------------
// The writers
// ---------------------------------------------------------------------------

/// The SBOM file of `fixture`, named as the CLI names it from the
/// repository root.
fn options(fixture: &sbom_fixtures::Fixture) -> SarifOptions {
    SarifOptions::new().with_artifact(SarifArtifact::new(
        SarifArtifactLocation::relative(format!("tests/fixtures/{}", fixture.rel)),
        &fixture.sbom,
        &fixture.raw,
    ))
}

#[test]
fn validate_sarif_matches_the_schema_at_every_level_on_every_fixture() {
    let schema = schema();
    let fixtures = sbom_fixtures::fixtures();
    assert!(fixtures.len() > 100, "the SBOM fixtures were not found");
    for fixture in &fixtures {
        let options = options(fixture);
        let results: Vec<ComplianceResult> = ComplianceLevel::all()
            .iter()
            .map(|level| fixture.check(*level))
            .collect();
        for result in &results {
            let label = format!("{} @ {:?}", fixture.rel, result.level);
            let sarif = generate_compliance_sarif_with(result, &options).expect("SARIF serializes");
            assert_valid(&schema, &sarif, &label);
        }
        let sarif =
            generate_multi_compliance_sarif_with(&results, &options).expect("SARIF serializes");
        assert_valid(&schema, &sarif, &format!("{} @ every level", fixture.rel));
        // `--sarif-include-passes`: passed checks are results of kind "pass".
        let sarif =
            generate_multi_compliance_sarif_with(&results, &options.clone().with_passes(true))
                .expect("SARIF serializes");
        assert_valid(
            &schema,
            &sarif,
            &format!("{} @ every level, with passes", fixture.rel),
        );
        // Without the SBOM file, results keep only logical locations.
        let sarif = generate_multi_compliance_sarif(&results).expect("SARIF serializes");
        assert_valid(
            &schema,
            &sarif,
            &format!("{} @ every level, no artifact", fixture.rel),
        );
    }
}

#[test]
fn quality_sarif_matches_the_schema_for_every_profile() {
    let schema = schema();
    let fixtures = sbom_fixtures::fixtures();
    let picked = [
        "cyclonedx/minimal.cdx.json",
        "cra/cra-compliant.cdx.json",
        "cyclonedx/cbom-1.7.cdx.json",
        "spdx/minimal.spdx.json",
        "spdx3/minimal.spdx3.json",
        "cyclonedx/aibom-complete.cdx.json",
        "showcase/license-risk.cdx.json",
    ];
    for rel in picked {
        let fixture = fixtures
            .iter()
            .find(|f| f.rel == rel)
            .unwrap_or_else(|| panic!("fixture {rel} missing"));
        for profile in [
            ScoringProfile::Minimal,
            ScoringProfile::Standard,
            ScoringProfile::Security,
            ScoringProfile::LicenseCompliance,
            ScoringProfile::Cra,
            ScoringProfile::BsiTr03183_2,
            ScoringProfile::Comprehensive,
            ScoringProfile::Cbom,
            ScoringProfile::AiReadiness,
        ] {
            let report = QualityScorer::new(profile).score(&fixture.sbom);
            let label = format!("{rel} @ quality --profile {profile}");
            let sarif =
                generate_quality_sarif_with(&report, rel, &profile.to_string(), &options(fixture))
                    .expect("SARIF serializes");
            assert_valid(&schema, &sarif, &label);
            if let Some(metrics) = report.ai_readiness_metrics.as_ref() {
                let sarif = generate_ai_readiness_sarif_with(
                    metrics,
                    rel,
                    &profile.to_string(),
                    Some(report.overall_score),
                    report.grade.letter(),
                    &options(fixture),
                )
                .expect("SARIF serializes");
                assert_valid(&schema, &sarif, &format!("{label} (AI readiness)"));
            }
        }
    }
}

#[test]
fn diff_and_view_sarif_match_the_schema() {
    let schema = schema();
    let pairs = [
        ("demo-old.cdx.json", "demo-new.cdx.json"),
        ("demo-eol-old.cdx.json", "demo-eol-new.cdx.json"),
        (
            "showcase/supply-chain-baseline.cdx.json",
            "showcase/supply-chain-incident.cdx.json",
        ),
        ("cyclonedx/minimal.cdx.json", "spdx/minimal.spdx.json"),
    ];
    let read = |rel: &str| {
        let path = std::path::Path::new(sbom_fixtures::FIXTURES_DIR).join(rel);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let sbom = parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"));
        let artifact = SarifArtifact::new(
            SarifArtifactLocation::relative(format!("tests/fixtures/{rel}")),
            &sbom,
            &raw,
        );
        (sbom, artifact)
    };
    for (old_rel, new_rel) in pairs {
        let ((old, old_artifact), (new, new_artifact)) = (read(old_rel), read(new_rel));
        let diff = DiffEngine::new().diff(&old, &new).expect("diff succeeds");
        let reporter = SarifReporter::new();
        let config = ReportConfig {
            old_sarif_artifact: Some(old_artifact.clone()),
            new_sarif_artifact: Some(new_artifact.clone()),
            ..ReportConfig::all()
        };
        let sarif = reporter
            .generate_diff_report(&diff, &old, &new, &config)
            .expect("diff SARIF");
        assert_valid(&schema, &sarif, &format!("diff {old_rel} {new_rel}"));
        for (rel, sbom, artifact) in [(old_rel, &old, old_artifact), (new_rel, &new, new_artifact)]
        {
            let config = ReportConfig {
                view_sarif_artifact: Some(artifact),
                ..ReportConfig::all()
            };
            let sarif = reporter
                .generate_view_report(sbom, &config)
                .expect("view SARIF");
            assert_valid(&schema, &sarif, &format!("view {rel}"));
        }
    }
}

// ---------------------------------------------------------------------------
// The validator's draft-04 keywords, in isolation
// ---------------------------------------------------------------------------

#[test]
fn draft_04_ref_hides_its_siblings() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "definitions": { "text": { "type": "string" } },
        "$ref": "#/definitions/text",
        "minLength": 5
    });
    assert!(
        json_schema::validate(&schema, &json!("abc")).is_ok(),
        "draft-04 ignores minLength next to $ref"
    );
    assert!(json_schema::validate(&schema, &json!(3)).is_err());
}

#[test]
fn one_of_requires_exactly_one_alternative() {
    let schema = json!({ "oneOf": [{ "required": ["a"] }, { "required": ["b"] }] });
    assert!(json_schema::validate(&schema, &json!({ "a": 1 })).is_ok());
    assert!(json_schema::validate(&schema, &json!({ "b": 1 })).is_ok());
    assert!(
        json_schema::validate(&schema, &json!({ "a": 1, "b": 1 })).is_err(),
        "both alternatives match"
    );
    assert!(
        json_schema::validate(&schema, &json!({ "c": 1 })).is_err(),
        "no alternative matches"
    );
}

#[test]
fn unique_items_rejects_equal_items() {
    let schema = json!({ "type": "array", "uniqueItems": true });
    assert!(json_schema::validate(&schema, &json!([1, 2, { "a": 1 }, { "a": 2 }])).is_ok());
    assert!(json_schema::validate(&schema, &json!([{ "a": 1 }, { "a": 1 }])).is_err());
    let allowed = json!({ "type": "array", "uniqueItems": false });
    assert!(json_schema::validate(&allowed, &json!([1, 1])).is_ok());
}

#[test]
fn default_and_draft_04_id_only_annotate() {
    let schema = json!({ "id": "https://example.com/s.json", "default": 3, "type": "integer" });
    assert!(json_schema::validate(&schema, &json!(7)).is_ok());
    assert!(json_schema::validate(&schema, &json!("7")).is_err());
}

/// A SARIF log with a duplicated rule descriptor, an unknown result field
/// and a region without a line: each must fail against the real schema.
#[test]
fn the_sarif_schema_rejects_what_sarif_forbids() {
    let schema = schema();
    let valid = json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "t", "rules": [{ "id": "R1" }] } },
            "results": [{
                "ruleId": "R1",
                "ruleIndex": 0,
                "message": { "text": "m" },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": "sbom.json", "uriBaseId": "SRCROOT" },
                        "region": { "startLine": 1 }
                    }
                }],
                "partialFingerprints": { "x/v1": "abc" }
            }]
        }]
    });
    assert!(
        json_schema::validate(&schema, &valid).is_ok(),
        "{:?}",
        json_schema::validate(&schema, &valid)
    );
    let mut duplicate_rule = valid.clone();
    duplicate_rule["runs"][0]["tool"]["driver"]["rules"] = json!([{ "id": "R1" }, { "id": "R1" }]);
    assert!(json_schema::validate(&schema, &duplicate_rule).is_err());
    let mut unknown_field = valid.clone();
    unknown_field["runs"][0]["results"][0]["findingKey"] = json!("k");
    assert!(json_schema::validate(&schema, &unknown_field).is_err());
    let mut no_line = valid.clone();
    no_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = json!({});
    assert!(json_schema::validate(&schema, &no_line).is_err());
    let mut zero_line = valid;
    zero_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] =
        json!({ "startLine": 0 });
    assert!(json_schema::validate(&schema, &zero_line).is_err());
}
