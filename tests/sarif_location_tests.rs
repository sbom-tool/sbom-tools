//! Every SARIF result points at the SBOM and carries a fingerprint of its
//! finding identity, and the fingerprints survive the SBOM's lines moving.
//!
//! - Every result of every writer (`validate` at every level, `quality`,
//!   `diff`, `view`) on every SBOM fixture has a physical location (the SBOM
//!   file and a line) and a fingerprint; no two results about one SBOM file
//!   share one; `ruleIndex` names the rule of `ruleId`; `findingId` and the
//!   fingerprints are the digests of `findingKey`.
//! - A component result points at the line that states the component's id.
//! - Re-serializing an SBOM (minified, re-indented, with lines inserted)
//!   moves every line but keeps every fingerprint; minified JSON puts every
//!   result on line 1.
//! - The CLI names the SBOM relative to its repository or `--sarif-base`.

#[path = "common/json_schema.rs"]
mod json_schema;
#[path = "common/sbom_fixtures.rs"]
mod sbom_fixtures;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::process::Command;

use sbom_tools::DiffEngine;
use sbom_tools::model::NormalizedSbom;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, QualityScorer, ScoringProfile, finding_fingerprint,
    finding_id,
};
use sbom_tools::reports::SbomLocator;
use sbom_tools::reports::{
    ReportConfig, ReportGenerator, SarifArtifact, SarifArtifactLocation, SarifOptions,
    SarifReporter, generate_multi_compliance_sarif_with, generate_quality_sarif_with,
};
use serde_json::Value;

fn artifact(rel: &str, sbom: &NormalizedSbom, raw: &str) -> SarifArtifact {
    SarifArtifact::new(
        SarifArtifactLocation::relative(format!("tests/fixtures/{rel}")),
        sbom,
        raw,
    )
}

fn as_of() -> chrono::DateTime<chrono::Utc> {
    sbom_fixtures::as_of()
}

fn check_all_levels(sbom: &NormalizedSbom) -> Vec<ComplianceResult> {
    ComplianceLevel::all()
        .iter()
        .map(|level| {
            sbom_tools::quality::ComplianceChecker::new(*level)
                .with_as_of(as_of())
                .check(sbom)
        })
        .collect()
}

/// The invariants every SARIF run must hold, returning each result's
/// `(findingKey, uri, line)`.
fn assert_located_and_fingerprinted(sarif: &str, label: &str) -> Vec<(String, String, u64)> {
    let doc: Value = serde_json::from_str(sarif).unwrap_or_else(|e| panic!("{label}: {e}"));
    let run = &doc["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let category = run["automationDetails"]["id"].as_str().expect("category");
    assert!(
        category.starts_with("sbom-tools/") && category.ends_with('/'),
        "{label}: automationDetails.id {category}"
    );
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for result in run["results"].as_array().expect("results") {
        let rule_id = result["ruleId"].as_str().expect("ruleId");
        let index = result["ruleIndex"].as_u64().expect("ruleIndex") as usize;
        assert_eq!(
            rules[index]["id"].as_str(),
            Some(rule_id),
            "{label}: ruleIndex {index} does not name {rule_id}"
        );
        let physical = &result["locations"][0]["physicalLocation"];
        let uri = physical["artifactLocation"]["uri"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: {rule_id} has no physical location"))
            .to_string();
        let line = physical["region"]["startLine"]
            .as_u64()
            .unwrap_or_else(|| panic!("{label}: {rule_id} has no line"));
        assert!(line >= 1, "{label}: {rule_id} line {line}");
        let key = result["properties"]["findingKey"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: {rule_id} has no findingKey"))
            .to_string();
        assert_eq!(
            result["properties"]["findingId"].as_str(),
            Some(finding_id(&key).as_str()),
            "{label}: {key}"
        );
        let fingerprint = finding_fingerprint(&key);
        let fingerprints = &result["partialFingerprints"];
        assert_eq!(
            fingerprints["sbomToolsFinding/v1"].as_str(),
            Some(fingerprint.as_str()),
            "{label}: {key}"
        );
        assert_eq!(
            fingerprints["primaryLocationLineHash"].as_str(),
            Some(format!("{}:1", &fingerprint[..16]).as_str()),
            "{label}: {key}"
        );
        assert!(
            seen.insert((uri.clone(), fingerprint)),
            "{label}: two results about {uri} share the fingerprint of {key}"
        );
        out.push((key, uri, line));
    }
    out
}

#[test]
fn every_validate_result_has_a_location_and_a_fingerprint_on_every_fixture() {
    let fixtures = sbom_fixtures::fixtures();
    assert!(fixtures.len() > 100, "the SBOM fixtures were not found");
    let mut total = 0usize;
    for fixture in &fixtures {
        let results = check_all_levels(&fixture.sbom);
        let options =
            SarifOptions::new().with_artifact(artifact(&fixture.rel, &fixture.sbom, &fixture.raw));
        let sarif = generate_multi_compliance_sarif_with(&results, &options).expect("SARIF");
        let located = assert_located_and_fingerprinted(&sarif, &fixture.rel);
        let violations: usize = results.iter().map(|r| r.violations.len()).sum();
        assert_eq!(
            located.len(),
            violations,
            "{}: one result per violation",
            fixture.rel
        );
        total += located.len();
    }
    assert!(total > 1000, "only {total} results were checked");
}

#[test]
fn every_quality_result_has_a_location_and_a_fingerprint() {
    for fixture in sbom_fixtures::fixtures()
        .iter()
        .filter(|f| f.rel.starts_with("cyclonedx/") || f.rel.starts_with("spdx"))
    {
        for profile in [
            ScoringProfile::Standard,
            ScoringProfile::Cra,
            ScoringProfile::Comprehensive,
        ] {
            let report = QualityScorer::new(profile)
                .with_as_of(as_of())
                .score(&fixture.sbom);
            let options = SarifOptions::new().with_artifact(artifact(
                &fixture.rel,
                &fixture.sbom,
                &fixture.raw,
            ));
            let sarif =
                generate_quality_sarif_with(&report, &fixture.rel, &profile.to_string(), &options)
                    .expect("SARIF");
            assert_located_and_fingerprinted(&sarif, &format!("{} @ {profile}", fixture.rel));
        }
    }
}

#[test]
fn every_diff_and_view_result_has_a_location_and_a_fingerprint() {
    let fixtures = sbom_fixtures::fixtures();
    let by_rel: HashMap<&str, &sbom_fixtures::Fixture> =
        fixtures.iter().map(|f| (f.rel.as_str(), f)).collect();
    let read = |rel: &str| -> (NormalizedSbom, String) {
        let raw = std::fs::read_to_string(Path::new(sbom_fixtures::FIXTURES_DIR).join(rel))
            .unwrap_or_else(|e| panic!("{rel}: {e}"));
        (parse_sbom_str(&raw).expect("parses"), raw)
    };
    let mut pairs: Vec<(String, String)> = vec![
        ("demo-old.cdx.json".into(), "demo-new.cdx.json".into()),
        (
            "demo-eol-old.cdx.json".into(),
            "demo-eol-new.cdx.json".into(),
        ),
    ];
    for (old, new) in [
        ("showcase/fleet-v1.cdx.json", "showcase/fleet-v2.cdx.json"),
        ("showcase/fleet-v2.cdx.json", "showcase/fleet-v3.cdx.json"),
        (
            "showcase/supply-chain-baseline.cdx.json",
            "showcase/supply-chain-incident.cdx.json",
        ),
        (
            "cyclonedx/minimal.cdx.json",
            "cyclonedx/with-vulnerabilities.cdx.json",
        ),
        ("spdx/minimal.spdx.json", "spdx3/minimal.spdx3.json"),
    ] {
        assert!(
            by_rel.contains_key(old) && by_rel.contains_key(new),
            "{old} {new}"
        );
        pairs.push((old.into(), new.into()));
    }
    let reporter = SarifReporter::new();
    for (old_rel, new_rel) in &pairs {
        let (old, old_raw) = read(old_rel);
        let (new, new_raw) = read(new_rel);
        let diff = DiffEngine::new().diff(&old, &new).expect("diff");
        let config = ReportConfig {
            old_sarif_artifact: Some(artifact(old_rel, &old, &old_raw)),
            new_sarif_artifact: Some(artifact(new_rel, &new, &new_raw)),
            ..ReportConfig::all()
        };
        let sarif = reporter
            .generate_diff_report(&diff, &old, &new, &config)
            .expect("SARIF");
        let located =
            assert_located_and_fingerprinted(&sarif, &format!("diff {old_rel} {new_rel}"));
        assert!(!located.is_empty());
        // Results about the old SBOM point into the old file.
        for (key, uri, _) in &located {
            if key.starts_with("diff|SBOM-TOOLS-002") || key.starts_with("diff|SBOM-TOOLS-006") {
                assert_eq!(uri, &format!("tests/fixtures/{old_rel}"), "{key}");
            }
        }
        for (rel, sbom, raw) in [(old_rel, &old, &old_raw), (new_rel, &new, &new_raw)] {
            let config = ReportConfig {
                view_sarif_artifact: Some(artifact(rel, sbom, raw)),
                ..ReportConfig::all()
            };
            let sarif = reporter.generate_view_report(sbom, &config).expect("SARIF");
            assert_located_and_fingerprinted(&sarif, &format!("view {rel}"));
        }
    }
}

/// A component result points at the line that states the component's id;
/// a document result at the metadata / creation-information line.
#[test]
fn component_results_point_at_their_component() {
    for fixture in sbom_fixtures::fixtures() {
        let locator = SbomLocator::scan(&fixture.raw);
        let results = check_all_levels(&fixture.sbom);
        let options =
            SarifOptions::new().with_artifact(artifact(&fixture.rel, &fixture.sbom, &fixture.raw));
        let sarif = generate_multi_compliance_sarif_with(&results, &options).expect("SARIF");
        let doc: Value = serde_json::from_str(&sarif).expect("JSON");
        let document_line = u64::from(locator.document_line().unwrap_or(1));
        for result in doc["runs"][0]["results"].as_array().expect("results") {
            let line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
                .as_u64()
                .expect("line");
            match result["properties"]["componentId"].as_str() {
                None => assert_eq!(line, document_line, "{}", fixture.rel),
                Some(id) => {
                    let component = fixture
                        .sbom
                        .components
                        .iter()
                        .find(|(cid, _)| cid.value() == id)
                        .map(|(_, c)| c);
                    let Some(component) = component else {
                        continue;
                    };
                    if let Some(expected) = locator.line_of(&component.identifiers.format_id) {
                        assert_eq!(line, u64::from(expected), "{}: {id}", fixture.rel);
                    }
                    let logical = result["locations"][0]["logicalLocations"][0]["name"]
                        .as_str()
                        .expect("logical location");
                    let expected = component
                        .identifiers
                        .purl
                        .as_deref()
                        .filter(|p| !p.is_empty())
                        .unwrap_or(&component.identifiers.format_id);
                    assert_eq!(logical, expected, "{}: {id}", fixture.rel);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fingerprints survive line moves
// ---------------------------------------------------------------------------

/// `(findingKey → fingerprint)` and `(findingKey → line)` of `raw` checked at
/// every level.
fn fingerprints_and_lines(raw: &str) -> (BTreeMap<String, String>, BTreeMap<String, u64>) {
    let sbom = parse_sbom_str(raw).expect("parses");
    let results = check_all_levels(&sbom);
    let options = SarifOptions::new().with_artifact(SarifArtifact::new(
        SarifArtifactLocation::relative("sbom.json"),
        &sbom,
        raw,
    ));
    let sarif = generate_multi_compliance_sarif_with(&results, &options).expect("SARIF");
    let doc: Value = serde_json::from_str(&sarif).expect("JSON");
    let mut fingerprints = BTreeMap::new();
    let mut lines = BTreeMap::new();
    for result in doc["runs"][0]["results"].as_array().expect("results") {
        let key = result["properties"]["findingKey"]
            .as_str()
            .expect("key")
            .to_string();
        let fingerprint = result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .expect("fingerprint")
            .to_string();
        let line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .expect("line");
        fingerprints.insert(key.clone(), fingerprint);
        lines.insert(key, line);
    }
    (fingerprints, lines)
}

/// Re-serializing a JSON SBOM moves its lines — minified, re-indented, or
/// with blank lines at the top — and every finding keeps its fingerprint.
#[test]
fn json_fingerprints_survive_line_moves() {
    for rel in [
        "cyclonedx/minimal.cdx.json",
        "cra/cra-compliant.cdx.json",
        "cyclonedx/with-vulnerabilities.cdx.json",
        "spdx/minimal.spdx.json",
        "spdx3/minimal.spdx3.json",
        "showcase/fleet-v1.cdx.json",
    ] {
        let raw = std::fs::read_to_string(Path::new(sbom_fixtures::FIXTURES_DIR).join(rel))
            .expect("fixture");
        let value: Value = serde_json::from_str(&raw).expect("JSON");
        let minified = serde_json::to_string(&value).expect("minify");
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"        ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&value, &mut ser).expect("re-indent");
        let reindented = format!("\n\n\n{}", String::from_utf8(buf).expect("utf-8"));

        let (base, base_lines) = fingerprints_and_lines(&raw);
        assert!(!base.is_empty(), "{rel}: no findings to compare");
        let (min, min_lines) = fingerprints_and_lines(&minified);
        let (re, re_lines) = fingerprints_and_lines(&reindented);
        assert_eq!(min, base, "{rel}: minifying changed a fingerprint");
        assert_eq!(re, base, "{rel}: re-indenting changed a fingerprint");
        assert!(
            min_lines.values().all(|&line| line == 1),
            "{rel}: minified JSON puts every result on line 1"
        );
        assert_ne!(re_lines, base_lines, "{rel}: the lines did not move");
    }
}

/// An SPDX 2.3 tag-value document whose packages lack suppliers.
const TAG_VALUE: &str = "SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: tag-value
DocumentNamespace: https://example.com/spdx/tag-value
Creator: Tool: example-generator-1.0
Created: 2026-01-01T00:00:00Z

PackageName: alpha
SPDXID: SPDXRef-Package-alpha
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageComment: <text>a comment
that spans lines</text>

PackageName: beta
SPDXID: SPDXRef-Package-beta
PackageDownloadLocation: NOASSERTION
";

/// XML and tag-value SBOMs keep their fingerprints when lines are inserted.
#[test]
fn xml_and_tag_value_fingerprints_survive_inserted_lines() {
    let mut documents: Vec<(String, String)> = [
        "cyclonedx/minimal-1.6.cdx.xml",
        "cra/cra-compliant.cdx.xml",
        "spdx/minimal.spdx.rdf.xml",
    ]
    .iter()
    .map(|rel| {
        let raw = std::fs::read_to_string(Path::new(sbom_fixtures::FIXTURES_DIR).join(rel))
            .unwrap_or_else(|e| panic!("fixture {rel}: {e}"));
        ((*rel).to_string(), raw)
    })
    .collect();
    documents.push(("tag-value".to_string(), TAG_VALUE.to_string()));
    for (rel, raw) in documents {
        let moved = if rel.ends_with(".xml") {
            // Blank lines after the XML declaration and between elements.
            let (declaration, rest) = raw.split_once('\n').expect("declaration line");
            format!("{declaration}\n\n\n{}", rest.replace("><", ">\n\n<"))
        } else {
            format!(
                "\n\n\n{}",
                raw.replace("\n\nPackageName", "\n\n\n\nPackageName")
            )
        };
        let (base, base_lines) = fingerprints_and_lines(&raw);
        assert!(!base.is_empty(), "{rel}: no findings to compare");
        let (after, after_lines) = fingerprints_and_lines(&moved);
        assert_eq!(after, base, "{rel}: inserting lines changed a fingerprint");
        assert_ne!(after_lines, base_lines, "{rel}: the lines did not move");
    }
}

/// In tag-value, a package's results point at its `SPDXID:` line.
#[test]
fn tag_value_results_point_at_the_spdxid_line() {
    let sbom = parse_sbom_str(TAG_VALUE).expect("tag-value parses");
    let locator = SbomLocator::scan(TAG_VALUE);
    assert_eq!(locator.line_of("SPDXRef-Package-alpha"), Some(10));
    assert_eq!(locator.line_of("SPDXRef-Package-beta"), Some(17));
    let (_, lines) = fingerprints_and_lines(TAG_VALUE);
    let beta = sbom
        .components
        .iter()
        .find(|(_, c)| c.name == "beta")
        .map(|(id, _)| id.value().to_string())
        .expect("beta");
    let beta_lines: HashSet<u64> = lines
        .iter()
        .filter(|(key, _)| key.ends_with(&format!("|{beta}")))
        .map(|(_, line)| *line)
        .collect();
    assert_eq!(beta_lines, HashSet::from([17]), "{lines:?}");
}

// ---------------------------------------------------------------------------
// The CLI
// ---------------------------------------------------------------------------

fn sbom_tools() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd
}

/// A repository with `sboms/app.cdx.json` in it.
fn repository() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir(repo.path().join(".git")).expect(".git");
    std::fs::create_dir(repo.path().join("sboms")).expect("sboms");
    std::fs::copy(
        Path::new(sbom_fixtures::FIXTURES_DIR).join("cyclonedx/minimal.cdx.json"),
        repo.path().join("sboms/app.cdx.json"),
    )
    .expect("copy");
    repo
}

fn sarif_uris(stdout: &[u8]) -> HashSet<String> {
    let doc: Value = serde_json::from_slice(stdout).expect("SARIF JSON");
    doc["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .expect("uri")
                .to_string()
        })
        .collect()
}

#[test]
fn cli_names_the_sbom_relative_to_its_repository_or_sarif_base() {
    let repo = repository();
    let sbom = repo.path().join("sboms/app.cdx.json");

    let output = sbom_tools()
        .args(["validate", "-o", "sarif"])
        .arg(&sbom)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("runs");
    assert!(output.status.code().is_some_and(|c| c <= 1), "{output:?}");
    assert_eq!(
        sarif_uris(&output.stdout),
        HashSet::from(["sboms/app.cdx.json".to_string()])
    );

    let output = sbom_tools()
        .args(["validate", "-o", "sarif", "--sarif-base"])
        .arg(repo.path().join("sboms"))
        .arg(&sbom)
        .output()
        .expect("runs");
    assert_eq!(
        sarif_uris(&output.stdout),
        HashSet::from(["app.cdx.json".to_string()])
    );

    for command in [vec!["quality", "-o", "sarif"], vec!["view", "-o", "sarif"]] {
        let output = sbom_tools()
            .args(&command)
            .arg(&sbom)
            .output()
            .expect("runs");
        assert_eq!(
            sarif_uris(&output.stdout),
            HashSet::from(["sboms/app.cdx.json".to_string()]),
            "{command:?}"
        );
    }

    let old = repo.path().join("sboms/old.cdx.json");
    std::fs::copy(
        Path::new(sbom_fixtures::FIXTURES_DIR).join("demo-old.cdx.json"),
        &old,
    )
    .expect("copy");
    let output = sbom_tools()
        .args(["diff", "-o", "sarif"])
        .arg(&old)
        .arg(&sbom)
        .output()
        .expect("runs");
    assert_eq!(
        sarif_uris(&output.stdout),
        HashSet::from([
            "sboms/old.cdx.json".to_string(),
            "sboms/app.cdx.json".to_string()
        ])
    );
}

#[test]
fn cli_rejects_a_sarif_base_that_is_not_a_directory() {
    let repo = repository();
    for command in [vec!["validate"], vec!["quality"], vec!["view"]] {
        let output = sbom_tools()
            .args(&command)
            .args(["-o", "sarif", "--sarif-base"])
            .arg(repo.path().join("missing"))
            .arg(repo.path().join("sboms/app.cdx.json"))
            .output()
            .expect("runs");
        assert_eq!(output.status.code(), Some(3), "{command:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--sarif-base"),
            "{command:?}"
        );
    }
}

#[test]
fn cli_sarif_output_matches_the_schema() {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/schemas/sarif/2.1.0/sarif-schema-2.1.0.json"
        ))
        .expect("schema"),
    )
    .expect("schema JSON");
    let repo = repository();
    let output = sbom_tools()
        .args(["validate", "-o", "sarif", "--standard", "ntia,cra,fsct"])
        .arg(repo.path().join("sboms/app.cdx.json"))
        .output()
        .expect("runs");
    let doc: Value = serde_json::from_slice(&output.stdout).expect("SARIF JSON");
    if let Err(errors) = json_schema::validate(&schema, &doc) {
        panic!("{}", errors.join("\n"));
    }
    assert_eq!(
        doc["runs"][0]["automationDetails"]["id"],
        "sbom-tools/cra+fsct+ntia/"
    );
}
