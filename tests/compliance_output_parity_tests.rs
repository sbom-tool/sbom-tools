//! Output parity: `-o json`, `-o sarif` and `-o oscal-json` say the same
//! about one run.
//!
//! Every finding appears in all three with the same finding id and key,
//! rule, severity (and, for a rule a setting set, the check's severity and
//! the setting's source), component, counts, deadline, field and observed
//! value, standard references, remediation and help URI. Every standard's
//! verdict reads the same in all three: its key and name, applicability,
//! compliance, score, the findings the run's settings turned off, the
//! components it left out, the checks it did not evaluate and the CRA
//! conformity summary. The JSON subject and the OSCAL SBOM resource describe
//! the same SBOM.
//!
//! The runs are the pinned fixtures of the byte snapshots
//! (tests/compliance_snapshots.rs), checked as `validate` checks them, and
//! again with inputs that give the rarer fields a value: rule settings, PQC
//! deadline mode and a CRA product class. SARIF lists the passed checks
//! (`--sarif-include-passes`), so every finding has a SARIF result.
//!
//! Each output is read as a consumer reads it: SARIF result and run
//! properties, OSCAL properties, links and remarks. OSCAL writes a severity
//! in lowercase and its remarks as Markdown, which the readers map back.

use std::collections::BTreeMap;
use std::path::Path;

use sbom_tools::model::{CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, ComplianceRunConfig, PqcMode, RuleSetting, RuleSettings,
    SettingSource, StandardSelector,
};
use sbom_tools::reports::oscal::generate_assessment_results_at;
use sbom_tools::reports::{
    AssessedSbom, SarifArtifact, SarifArtifactLocation, SarifOptions, generate_compliance_json_at,
    generate_compliance_sarif_with, generate_multi_compliance_sarif_with,
};
use serde_json::Value;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The pinned fixtures of the byte snapshots, each with its standards, and
/// an SBOM without ML components, to which the AI standards do not apply.
const PINNED: &[(&str, &[&str])] = &[
    ("cyclonedx/minimal.cdx.json", &["ntia", "cisa-2026"]),
    ("cra/cra-compliant.cdx.json", &["cra", "cra-phase1"]),
    ("cyclonedx/cbom-1.7.cdx.json", &["cnsa2", "pqc"]),
    ("spdx/minimal.spdx.json", &["ntia", "fsct"]),
    ("spdx3/minimal.spdx3.json", &["bsi", "eo14028"]),
    ("cyclonedx/aibom-complete.cdx.json", &["ai-act", "bsi-ai"]),
    ("cyclonedx/minimal.cdx.json", &["ai-act", "bsi-ai"]),
];

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

/// Rule settings that set severities and turn rules off in the pinned
/// fixtures' standards.
fn settings() -> RuleSettings {
    let mut settings = RuleSettings::new();
    for (rule, setting) in [
        ("SBOM-NTIA-SUPPLIER", RuleSetting::Warning),
        ("SBOM-NTIA-DEPENDENCY", RuleSetting::Off),
        ("SBOM-CISA2026-HASH", RuleSetting::Info),
        ("SBOM-CRA-ELEMENT-ID", RuleSetting::Error),
        ("SBOM-FSCT-SUPPLIER", RuleSetting::Off),
    ] {
        settings
            .set(rule, setting, SettingSource::Cli)
            .expect("a registered rule");
    }
    settings
}

/// The runs each fixture is checked with: as `validate` checks it, with
/// rule settings, and with PQC deadline mode and a CRA product class.
fn runs(sidecar: Option<&CraSidecarMetadata>) -> Vec<(&'static str, ComplianceRunConfig)> {
    let mut plain = ComplianceRunConfig::new().with_as_of(as_of());
    if let Some(sidecar) = sidecar {
        plain = plain.with_sidecar(sidecar.clone());
    }
    vec![
        ("validate", plain.clone()),
        (
            "rule settings",
            plain.clone().with_rule_settings(settings()),
        ),
        (
            "deadline mode and a product class",
            plain
                .with_pqc_mode(PqcMode::Deadline)
                .with_product_class(CraProductClass::Critical),
        ),
    ]
}

/// One run's results and its three outputs, parsed.
struct Outputs {
    label: String,
    results: Vec<ComplianceResult>,
    json: Value,
    sarif: Value,
    oscal: Value,
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("the output is JSON")
}

/// Every pinned fixture under every run.
fn outputs() -> Vec<Outputs> {
    let mut all = Vec::new();
    for (rel, standards) in PINNED {
        let path = Path::new(FIXTURES_DIR).join(rel);
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        let sbom = parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"));
        let sidecar = CraSidecarMetadata::discover_for_sbom(&path).expect("sidecar loads");
        let levels: Vec<ComplianceLevel> = standards
            .iter()
            .map(|name| {
                name.parse::<StandardSelector>()
                    .expect("known standard")
                    .level()
            })
            .collect();
        for (run_label, run) in runs(sidecar.as_ref()) {
            let results = run.check_levels(&levels, &sbom);
            all.push(render(
                &format!("{rel} [{run_label}]"),
                &sbom,
                &raw,
                rel,
                results,
            ));
        }
    }
    all
}

fn render(
    label: &str,
    sbom: &NormalizedSbom,
    raw: &str,
    rel: &str,
    results: Vec<ComplianceResult>,
) -> Outputs {
    let assessed = AssessedSbom::new(sbom, raw.as_bytes()).with_file_name(rel);
    let json = generate_compliance_json_at(&results, &assessed, as_of()).expect("JSON");
    // As `validate` writes it: the SBOM file the results point into, what
    // the run judged, and the passed checks.
    let options = SarifOptions::new()
        .with_artifact(SarifArtifact::new(
            SarifArtifactLocation::relative(format!("tests/fixtures/{rel}")),
            sbom,
            raw,
        ))
        .with_subject(&assessed, as_of())
        .with_passes(true);
    let sarif = generate_multi_compliance_sarif_with(&results, &options).expect("SARIF");
    let oscal = generate_assessment_results_at(&results, &assessed, as_of()).expect("OSCAL");
    Outputs {
        label: label.to_string(),
        json: parse(&json),
        sarif: parse(&sarif),
        oscal: parse(&oscal),
        results,
    }
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

/// The values of the OSCAL properties of `entry` named `name`.
fn props<'v>(entry: &'v Value, name: &str) -> Vec<&'v Value> {
    array(&entry["props"])
        .iter()
        .filter(|p| p["name"] == name)
        .collect()
}

/// The value of the one OSCAL property of `entry` named `name`.
fn prop(entry: &Value, name: &str) -> Option<String> {
    let found = props(entry, name);
    assert!(found.len() <= 1, "{name} repeats in {entry}");
    found.first().and_then(|p| text(&p["value"]))
}

fn prop_count(entry: &Value, name: &str) -> Option<u64> {
    prop(entry, name).map(|v| v.parse().unwrap_or_else(|_| panic!("{name}: {v}")))
}

/// The hrefs of `entry`'s OSCAL links of relation `rel`.
fn links(entry: &Value, rel: &str) -> Vec<String> {
    array(&entry["links"])
        .iter()
        .filter(|l| l["rel"] == rel)
        .filter_map(|l| text(&l["href"]))
        .collect()
}

/// OSCAL markup read as plain text: each backslash escape is the character
/// it escapes.
fn unescape(markup: &str) -> String {
    let mut plain = String::with_capacity(markup.len());
    let mut chars = markup.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => plain.extend(chars.next()),
            c => plain.push(c),
        }
    }
    plain
}

/// The `-o json` severity an OSCAL severity is: OSCAL writes it in
/// lowercase.
fn json_severity(oscal: &str) -> String {
    match oscal {
        "error" => "Error",
        "warning" => "Warning",
        "info" => "Info",
        other => panic!("OSCAL severity {other:?}"),
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// A finding's audit fields, as one output gives them.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    key: String,
    rule: String,
    severity: Option<String>,
    default_severity: Option<String>,
    severity_source: Option<String>,
    component_id: Option<String>,
    affected: Option<u64>,
    total: Option<u64>,
    deadline: Option<String>,
    deadline_source: Option<String>,
    field: Option<String>,
    observed: Option<String>,
    /// `(standard, clause)` of each reference.
    references: Vec<(String, String)>,
    /// The URL of each reference that has one.
    reference_uris: Vec<String>,
    remediation: Option<String>,
    help_uri: Option<String>,
}

/// The findings of `-o json`, by finding id.
fn json_findings(envelope: &Value) -> BTreeMap<String, Finding> {
    let mut findings = BTreeMap::new();
    for result in array(&envelope["results"]) {
        for f in array(&result["violations"])
            .iter()
            .chain(array(&result["passed"]))
        {
            let refs = array(&f["standard_refs"]);
            let finding = Finding {
                key: text(&f["finding_key"]).expect("finding_key"),
                rule: text(&f["rule_id"]).expect("rule_id"),
                severity: text(&f["severity"]),
                default_severity: text(&f["default_severity"]),
                severity_source: text(&f["severity_source"]),
                component_id: text(&f["component_id"]),
                affected: f["counts"]["affected"].as_u64(),
                total: f["counts"]["total"].as_u64(),
                deadline: text(&f["deadline"]),
                deadline_source: text(&f["deadline_source"]),
                field: text(&f["field"]),
                observed: text(&f["observed"]),
                references: refs
                    .iter()
                    .map(|r| {
                        (
                            text(&r["standard"]).expect("standard"),
                            text(&r["id"]).expect("id"),
                        )
                    })
                    .collect(),
                reference_uris: refs.iter().filter_map(|r| text(&r["help_uri"])).collect(),
                remediation: text(&f["remediation"]),
                help_uri: text(&f["help_uri"]),
            };
            let id = text(&f["finding_id"]).expect("finding_id");
            assert!(
                findings.insert(id, finding).is_none(),
                "a finding id repeats"
            );
        }
    }
    findings
}

/// The findings of `-o sarif`, by finding id. A result's level is its
/// severity in SARIF's words, and a pass is `kind: pass` at level `none`.
fn sarif_findings(sarif: &Value) -> BTreeMap<String, Finding> {
    let mut findings = BTreeMap::new();
    for r in array(&sarif["runs"][0]["results"]) {
        let p = &r["properties"];
        let severity = text(&p["severity"]);
        let level = match severity.as_deref() {
            Some("Error") => "error",
            Some("Warning") => "warning",
            Some("Info") => "note",
            None => {
                assert_eq!(r["kind"], "pass", "a result without a severity is a pass");
                "none"
            }
            Some(other) => panic!("SARIF severity {other:?}"),
        };
        assert_eq!(r["level"], level, "{r}");
        assert_eq!(
            r["ruleId"], p["ruleId"],
            "every finding's rule is registered"
        );
        let refs = array(&p["standardRefs"]);
        let finding = Finding {
            key: text(&p["findingKey"]).expect("findingKey"),
            rule: text(&p["ruleId"]).expect("ruleId"),
            severity,
            default_severity: text(&p["defaultSeverity"]),
            severity_source: text(&p["severitySource"]),
            component_id: text(&p["componentId"]),
            affected: p["affected"].as_u64(),
            total: p["total"].as_u64(),
            deadline: text(&p["deadline"]),
            deadline_source: text(&p["deadlineSource"]),
            field: text(&p["field"]),
            observed: text(&p["observed"]),
            references: refs
                .iter()
                .map(|r| {
                    (
                        text(&r["standard"]).expect("standard"),
                        text(&r["id"]).expect("id"),
                    )
                })
                .collect(),
            reference_uris: refs.iter().filter_map(|r| text(&r["helpUri"])).collect(),
            remediation: text(&p["remediation"]),
            help_uri: text(&p["helpUri"]),
        };
        let id = text(&p["findingId"]).expect("findingId");
        assert!(
            findings.insert(id, finding).is_none(),
            "a finding id repeats"
        );
    }
    findings
}

/// The findings of `-o oscal-json`, by finding id: each finding but the
/// roll-ups, with the observation it relates to.
fn oscal_findings(document: &Value) -> BTreeMap<String, Finding> {
    let mut findings = BTreeMap::new();
    for entry in array(&document["assessment-results"]["results"]) {
        let observations: BTreeMap<&str, &Value> = array(&entry["observations"])
            .iter()
            .map(|o| (o["uuid"].as_str().expect("uuid"), o))
            .collect();
        for finding in array(&entry["findings"]) {
            let Some(id) = prop(finding, "finding-id") else {
                assert!(
                    finding["target"]["target-id"]
                        .as_str()
                        .is_some_and(|t| t.ends_with("-compliance")),
                    "only a roll-up has no finding id: {finding}"
                );
                continue;
            };
            let related = array(&finding["related-observations"]);
            assert_eq!(related.len(), 1, "{finding}");
            let uuid = related[0]["observation-uuid"].as_str().expect("uuid");
            let o = observations[uuid];
            let help = links(finding, "help");
            assert!(help.len() <= 1, "{finding}");
            let read = Finding {
                key: prop(finding, "finding-key").expect("finding-key"),
                rule: prop(o, "rule-id").expect("rule-id"),
                severity: prop(o, "severity").as_deref().map(json_severity),
                default_severity: prop(o, "default-severity").as_deref().map(json_severity),
                severity_source: prop(o, "severity-source"),
                component_id: prop(o, "component-id"),
                affected: prop_count(o, "affected"),
                total: prop_count(o, "total"),
                deadline: prop(o, "deadline"),
                deadline_source: prop(o, "deadline-source"),
                field: prop(o, "field"),
                observed: prop(o, "observed"),
                references: props(o, "standard-ref")
                    .iter()
                    .map(|p| {
                        (
                            text(&p["class"]).expect("a reference's standard"),
                            text(&p["value"]).expect("a reference's clause"),
                        )
                    })
                    .collect(),
                reference_uris: links(o, "reference"),
                remediation: finding["remarks"].as_str().map(unescape),
                help_uri: help.into_iter().next(),
            };
            assert!(findings.insert(id, read).is_none(), "a finding id repeats");
        }
    }
    findings
}

/// Every finding appears in JSON, SARIF and OSCAL with the same audit
/// fields, and no output has a finding the others lack.
#[test]
fn every_finding_reads_the_same_in_json_sarif_and_oscal() {
    let mut findings = 0;
    let mut seen = BTreeMap::<&str, bool>::new();
    for out in outputs() {
        let json = json_findings(&out.json);
        let expected: usize = out
            .results
            .iter()
            .map(|r| r.violations.len() + r.passed.len())
            .sum();
        assert_eq!(json.len(), expected, "{}", out.label);
        let sarif = sarif_findings(&out.sarif);
        let oscal = oscal_findings(&out.oscal);
        for (id, finding) in &json {
            assert_eq!(sarif.get(id), Some(finding), "{} SARIF {id}", out.label);
            assert_eq!(oscal.get(id), Some(finding), "{} OSCAL {id}", out.label);
            for (field, present) in [
                ("default_severity", finding.default_severity.is_some()),
                ("counts", finding.affected.is_some()),
                ("deadline", finding.deadline.is_some()),
                ("observed", finding.observed.is_some()),
                ("pass", finding.severity.is_none()),
            ] {
                *seen.entry(field).or_default() |= present;
            }
        }
        assert_eq!(
            sarif.len(),
            json.len(),
            "{}: SARIF has extra results",
            out.label
        );
        assert_eq!(
            oscal.len(),
            json.len(),
            "{}: OSCAL has extra findings",
            out.label
        );
        findings += json.len();
    }
    assert!(findings > 100, "compared {findings} findings");
    for (field, present) in seen {
        assert!(present, "no run exercises {field}");
    }
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// A standard's verdict, as one output gives it.
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    standard: String,
    name: String,
    applicable: bool,
    compliant: bool,
    /// The error, warning, info and passed counts.
    counts: [Option<u64>; 4],
    score: Option<u64>,
    suppressed: u64,
    excluded_components: u64,
    /// `(rule, reason)` of each check not evaluated.
    not_evaluated: Vec<(String, String)>,
    /// `(rule, findings, source)` of each rule turned off.
    suppressed_rules: Vec<(String, u64, String)>,
    conformity: Option<Conformity>,
}

/// A CRA conformity summary: the product class, the route, and each piece
/// of evidence as `(label, detail, satisfied)`.
type Conformity = (String, String, Vec<(String, String, bool)>);

fn json_verdicts(envelope: &Value) -> Vec<Verdict> {
    array(&envelope["results"])
        .iter()
        .map(|r| Verdict {
            standard: text(&r["standard"]).expect("standard"),
            name: text(&r["name"]).expect("name"),
            applicable: r["applicable"].as_bool().expect("applicable"),
            compliant: r["compliant"].as_bool().expect("compliant"),
            counts: ["error", "warning", "info", "passed"].map(|kind| r["counts"][kind].as_u64()),
            score: r["score"].as_u64(),
            suppressed: r["counts"]["suppressed"].as_u64().unwrap_or(0),
            excluded_components: r["excluded_components"].as_u64().unwrap_or(0),
            not_evaluated: array(&r["evaluated"])
                .iter()
                .map(|e| {
                    assert_eq!(e["status"], "not_evaluated");
                    (
                        text(&e["rule_id"]).expect("rule_id"),
                        text(&e["reason"]).expect("reason"),
                    )
                })
                .collect(),
            suppressed_rules: array(&r["suppressed"])
                .iter()
                .map(|s| {
                    (
                        text(&s["rule_id"]).expect("rule_id"),
                        s["findings"].as_u64().expect("findings"),
                        text(&s["source"]).expect("source"),
                    )
                })
                .collect(),
            conformity: r.get("conformity_summary").map(|c| {
                (
                    text(&c["product_class"]).expect("product_class"),
                    text(&c["route"]).expect("route"),
                    array(&c["evidence"])
                        .iter()
                        .map(|e| {
                            (
                                text(&e["label"]).expect("label"),
                                text(&e["detail"]).expect("detail"),
                                e["satisfied"].as_bool().expect("satisfied"),
                            )
                        })
                        .collect(),
                )
            }),
        })
        .collect()
}

/// A verdict of the SARIF run properties: a run's own for one standard, a
/// `standards[]` entry for several.
fn sarif_verdict(v: &Value) -> Verdict {
    Verdict {
        standard: text(&v["standard"]).expect("standard"),
        name: text(&v["profile"]).expect("profile"),
        applicable: v["applicable"].as_bool().expect("applicable"),
        compliant: v["compliant"].as_bool().expect("compliant"),
        counts: ["errorCount", "warningCount", "infoCount", "passedCount"]
            .map(|kind| v[kind].as_u64()),
        score: v["overallScore"].as_f64().map(|s| {
            assert_eq!(s.fract(), 0.0, "a whole score");
            s as u64
        }),
        suppressed: v["suppressed"].as_u64().unwrap_or(0),
        excluded_components: v["excludedComponents"].as_u64().unwrap_or(0),
        not_evaluated: array(&v["notEvaluated"])
            .iter()
            .map(|e| {
                (
                    text(&e["ruleId"]).expect("ruleId"),
                    text(&e["reason"]).expect("reason"),
                )
            })
            .collect(),
        suppressed_rules: array(&v["suppressedRules"])
            .iter()
            .map(|s| {
                (
                    text(&s["ruleId"]).expect("ruleId"),
                    s["findings"].as_u64().expect("findings"),
                    text(&s["source"]).expect("source"),
                )
            })
            .collect(),
        conformity: v.get("conformitySummary").map(|c| {
            (
                text(&c["productClass"]).expect("productClass"),
                text(&c["route"]).expect("route"),
                array(&c["evidence"])
                    .iter()
                    .map(|e| {
                        (
                            text(&e["label"]).expect("label"),
                            text(&e["detail"]).expect("detail"),
                            e["satisfied"].as_bool().expect("satisfied"),
                        )
                    })
                    .collect(),
            )
        }),
    }
}

fn oscal_verdicts(document: &Value) -> Vec<Verdict> {
    array(&document["assessment-results"]["results"])
        .iter()
        .map(|entry| {
            // A rule turned off is three properties of one group.
            let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
            for p in array(&entry["props"]) {
                let name = p["name"].as_str().expect("name");
                if let Some(part) = name.strip_prefix("suppressed-")
                    && part != "count"
                {
                    let group = text(&p["group"]).expect("a group");
                    groups
                        .entry(group)
                        .or_default()
                        .insert(part.to_string(), text(&p["value"]).expect("value"));
                }
            }
            let class = prop(entry, "conformity-product-class");
            Verdict {
                standard: prop(entry, "standard").expect("standard"),
                name: prop(entry, "standard-name").expect("standard-name"),
                applicable: match prop(entry, "applicability").as_deref() {
                    Some("applicable") => true,
                    Some("not-applicable") => false,
                    other => panic!("applicability {other:?}"),
                },
                compliant: prop(entry, "is-compliant").expect("is-compliant") == "true",
                counts: ["error-count", "warning-count", "info-count", "passed-count"]
                    .map(|name| prop_count(entry, name)),
                score: prop_count(entry, "score"),
                suppressed: prop_count(entry, "suppressed-count").unwrap_or(0),
                excluded_components: prop_count(entry, "excluded-components").unwrap_or(0),
                not_evaluated: props(entry, "not-evaluated")
                    .iter()
                    .map(|p| {
                        (
                            text(&p["value"]).expect("value"),
                            unescape(p["remarks"].as_str().expect("a reason")),
                        )
                    })
                    .collect(),
                suppressed_rules: groups
                    .into_values()
                    .map(|g| {
                        (
                            g["rule"].clone(),
                            g["findings"].parse().expect("a count"),
                            g["source"].clone(),
                        )
                    })
                    .collect(),
                conformity: class.map(|class| {
                    (
                        class,
                        prop(entry, "conformity-route").expect("route"),
                        props(entry, "conformity-evidence")
                            .iter()
                            .map(|p| {
                                (
                                    text(&p["value"]).expect("label"),
                                    unescape(p["remarks"].as_str().expect("detail")),
                                    match p["class"].as_str() {
                                        Some("satisfied") => true,
                                        Some("not-satisfied") => false,
                                        other => panic!("evidence class {other:?}"),
                                    },
                                )
                            })
                            .collect(),
                    )
                }),
            }
        })
        .collect()
}

/// Each standard's verdict reads the same in JSON, SARIF and OSCAL, in a
/// run of several standards and in a run of one.
#[test]
fn every_verdict_reads_the_same_in_json_sarif_and_oscal() {
    let mut seen = BTreeMap::<&str, bool>::new();
    for out in outputs() {
        let json = json_verdicts(&out.json);
        let sarif: Vec<Verdict> = array(&out.sarif["runs"][0]["properties"]["standards"])
            .iter()
            .map(sarif_verdict)
            .collect();
        assert_eq!(sarif, json, "{} SARIF", out.label);
        assert_eq!(oscal_verdicts(&out.oscal), json, "{} OSCAL", out.label);
        for (result, verdict) in out.results.iter().zip(&json) {
            let single: Value = serde_json::from_str(
                &generate_compliance_sarif_with(result, &SarifOptions::new()).expect("SARIF"),
            )
            .expect("JSON");
            assert_eq!(
                &sarif_verdict(&single["runs"][0]["properties"]),
                verdict,
                "{} one standard",
                out.label
            );
            for (field, present) in [
                ("not applicable", !verdict.applicable),
                ("suppressed", !verdict.suppressed_rules.is_empty()),
                ("not evaluated", !verdict.not_evaluated.is_empty()),
                ("conformity summary", verdict.conformity.is_some()),
            ] {
                *seen.entry(field).or_default() |= present;
            }
        }
    }
    for (field, present) in seen {
        assert!(present, "no run exercises {field}");
    }
}

// ---------------------------------------------------------------------------
// The SBOM
// ---------------------------------------------------------------------------

/// The JSON subject and the OSCAL SBOM resource describe the same SBOM.
#[test]
fn the_subject_reads_the_same_in_json_and_oscal() {
    for out in outputs() {
        let subject = &out.json["subject"];
        let resource = &out.oscal["assessment-results"]["back-matter"]["resources"][0];
        let label = &out.label;
        for (json, oscal) in [
            ("sha256", "sha256"),
            ("format", "format"),
            ("spec_version", "spec-version"),
            ("file_name", "file-name"),
        ] {
            assert_eq!(
                text(&subject[json]),
                prop(resource, oscal),
                "{label}: {json}"
            );
        }
        for (json, oscal) in [
            (&subject["components"], "component-count"),
            (&subject["duplicates"]["components"], "duplicate-components"),
            (&subject["duplicates"]["entries"], "duplicate-entries"),
        ] {
            assert_eq!(
                json.as_u64(),
                prop_count(resource, oscal),
                "{label}: {oscal}"
            );
        }
        let conflicts: Vec<String> = array(&subject["duplicates"]["conflicts"])
            .iter()
            .filter_map(text)
            .collect();
        let oscal_conflicts: Vec<String> = props(resource, "duplicate-conflict")
            .iter()
            .filter_map(|p| text(&p["value"]))
            .collect();
        assert_eq!(conflicts, oscal_conflicts, "{label}");
        assert_eq!(
            subject["timestamp_unparsed"]
                .as_bool()
                .map(|b| b.to_string()),
            prop(resource, "timestamp-unparsed"),
            "{label}"
        );
        assert_eq!(
            text(&out.json["as_of"]),
            text(&out.oscal["assessment-results"]["metadata"]["last-modified"]),
            "{label}: one instant"
        );
    }
}

/// SARIF states the same SBOM and instant: the SBOM artifact, at the file
/// the results point into, with the SHA-256 as its `sha-256` hash, and
/// `asOf` and `subject` as run properties.
#[test]
fn the_subject_reads_the_same_in_json_and_sarif() {
    for out in outputs() {
        let label = &out.label;
        let subject = &out.json["subject"];
        let run = &out.sarif["runs"][0];
        let artifacts = array(&run["artifacts"]);
        assert_eq!(artifacts.len(), 1, "{label}: the SBOM is the one artifact");
        assert_eq!(
            artifacts[0]["hashes"]["sha-256"], subject["sha256"],
            "{label}"
        );
        let uri = artifacts[0]["location"]["uri"].as_str().expect("uri");
        let name = subject["file_name"].as_str().expect("file_name");
        assert!(uri.ends_with(&format!("/{name}")), "{label}: {uri}");
        for result in array(&run["results"]) {
            assert_eq!(
                uri, result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "{label}: the file the results point into"
            );
        }
        let properties = &run["properties"];
        assert_eq!(properties["asOf"], out.json["as_of"], "{label}");
        let sarif = &properties["subject"];
        for (json, sarif_name) in [
            ("format", "format"),
            ("spec_version", "specVersion"),
            ("components", "components"),
            ("duplicates", "duplicates"),
            ("timestamp_unparsed", "timestampUnparsed"),
        ] {
            assert_eq!(sarif[sarif_name], subject[json], "{label}: {json}");
        }
        assert!(
            sarif.get("sha256").is_none() && sarif.get("fileName").is_none(),
            "{label}: the artifact carries those"
        );
    }
}
