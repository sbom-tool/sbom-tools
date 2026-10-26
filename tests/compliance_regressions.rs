//! False-pass regression corpus.
//!
//! Every repro from the v0.3.0 compliance review lives under
//! `tests/fixtures/compliance/regressions/` and is listed in `corpus.json`
//! with the verdict each standard must reach. A check marked `"xfail"` is a
//! known, still-reproduced defect: until the work package it names fixes it,
//! this runner asserts the expectation does NOT hold. The fix therefore has
//! to flip the manifest entry in the same PR, and a fix that lands without
//! updating the manifest fails here too ("now passes; remove xfail").

use std::path::{Path, PathBuf};

use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceChecker, ComplianceResult, StandardSelector, Violation};
use serde::Deserialize;

const CORPUS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/compliance/regressions"
);

/// Every check is evaluated at this instant, the review's evaluation date.
const AS_OF: &str = "2026-10-12T00:00:00Z";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    #[allow(dead_code)]
    description: String,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    review_id: String,
    fixture: String,
    #[serde(default)]
    sidecar: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    checks: Vec<Check>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    standard: String,
    /// Work package expected to fix this check, while it still fails.
    #[serde(default)]
    xfail: Option<String>,
    expect: Expect,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Expect {
    #[serde(default)]
    compliant: Option<bool>,
    /// Exact error count.
    #[serde(default)]
    errors: Option<usize>,
    /// Rules that must report a violation (at the severity, when given).
    #[serde(default)]
    rules_present: Vec<RuleMatch>,
    /// Pass-only rules that must report a passed check.
    #[serde(default)]
    rules_passed: Vec<String>,
    /// Rules that must report neither a violation nor a passed check.
    #[serde(default)]
    rules_absent: Vec<String>,
    #[serde(default)]
    rule_counts: Vec<RuleCount>,
    #[serde(default)]
    message_excludes: Vec<MessageExclude>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMatch {
    rule: String,
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleCount {
    rule: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    affected: Option<usize>,
    #[serde(default)]
    total: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageExclude {
    rule: String,
    text: Vec<String>,
}

fn load_corpus() -> Corpus {
    let path = Path::new(CORPUS_DIR).join("corpus.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid corpus.json: {e}"))
}

fn resolve(relative: &str) -> PathBuf {
    Path::new(CORPUS_DIR).join(relative)
}

fn severity_name(v: &Violation) -> &'static str {
    match v.severity {
        sbom_tools::quality::ViolationSeverity::Error => "error",
        sbom_tools::quality::ViolationSeverity::Warning => "warning",
        sbom_tools::quality::ViolationSeverity::Info => "info",
        other => panic!("the corpus names no severity {other:?}"),
    }
}

fn matches_rule(v: &Violation, rule: &str, severity: Option<&str>) -> bool {
    v.rule_id == rule && severity.is_none_or(|s| severity_name(v) == s)
}

/// Every way `result` departs from `expect`, empty when it meets it.
fn failures(result: &ComplianceResult, expect: &Expect) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(compliant) = expect.compliant
        && result.is_compliant != compliant
    {
        out.push(format!(
            "compliant: expected {compliant}, got {}",
            result.is_compliant
        ));
    }
    if let Some(errors) = expect.errors
        && result.error_count != errors
    {
        out.push(format!(
            "errors: expected {errors}, got {}",
            result.error_count
        ));
    }
    for m in &expect.rules_present {
        if !result
            .violations
            .iter()
            .any(|v| matches_rule(v, &m.rule, m.severity.as_deref()))
        {
            out.push(format!(
                "rule {} ({}) expected but absent",
                m.rule,
                m.severity.as_deref().unwrap_or("any severity")
            ));
        }
    }
    for rule in &expect.rules_passed {
        if !result.passed.iter().any(|p| p.rule_id == rule) {
            out.push(format!("passed check {rule} expected but absent"));
        }
    }
    for rule in &expect.rules_absent {
        if result.violations.iter().any(|v| v.rule_id == rule)
            || result.passed.iter().any(|p| p.rule_id == rule)
        {
            out.push(format!("rule {rule} expected absent but present"));
        }
    }
    for c in &expect.rule_counts {
        let counted = result
            .violations
            .iter()
            .filter(|v| matches_rule(v, &c.rule, c.severity.as_deref()))
            .find_map(|v| v.counts.as_ref());
        match counted {
            None => out.push(format!("rule {} with counts not found", c.rule)),
            Some(counts) => {
                if let Some(affected) = c.affected
                    && counts.affected != affected
                {
                    out.push(format!(
                        "rule {}: affected expected {affected}, got {}",
                        c.rule, counts.affected
                    ));
                }
                if let Some(total) = c.total
                    && counts.total != total
                {
                    out.push(format!(
                        "rule {}: total expected {total}, got {}",
                        c.rule, counts.total
                    ));
                }
            }
        }
    }
    for m in &expect.message_excludes {
        for v in result.violations.iter().filter(|v| v.rule_id == m.rule) {
            for text in &m.text {
                if v.message.contains(text.as_str()) {
                    out.push(format!(
                        "rule {} message names {text:?}: {}",
                        m.rule, v.message
                    ));
                }
            }
        }
    }
    out
}

fn evaluate(entry: &Entry, check: &Check) -> ComplianceResult {
    let path = resolve(&entry.fixture);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: cannot read {}: {e}", entry.id, path.display()));
    let sbom = parse_sbom_str(&raw)
        .unwrap_or_else(|e| panic!("{}: {} does not parse: {e}", entry.id, path.display()));
    let selector: StandardSelector = check
        .standard
        .parse()
        .unwrap_or_else(|e| panic!("{}: {e}", entry.id));
    let as_of = chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc);
    let mut checker = ComplianceChecker::new(selector.level()).with_as_of(as_of);
    if let Some(sidecar) = &entry.sidecar {
        let sidecar_path = resolve(sidecar);
        let metadata = CraSidecarMetadata::from_file(&sidecar_path)
            .unwrap_or_else(|e| panic!("{}: sidecar {}: {e}", entry.id, sidecar_path.display()));
        checker = checker.with_sidecar(metadata);
    }
    checker.check(&sbom)
}

#[test]
fn regression_corpus_matches_manifest() {
    let corpus = load_corpus();
    let mut problems = Vec::new();
    for entry in &corpus.entries {
        for check in &entry.checks {
            let result = evaluate(entry, check);
            let failed = failures(&result, &check.expect);
            let label = format!("{} [{}] {}", entry.id, entry.review_id, check.standard);
            match (&check.xfail, failed.is_empty()) {
                (None, false) => {
                    problems.push(format!("{label}: regressed\n    {}", failed.join("\n    ")));
                }
                (Some(fix), true) => problems.push(format!(
                    "{label}: now meets its expectation; remove \"xfail\": \"{fix}\" from corpus.json"
                )),
                _ => {}
            }
        }
    }
    assert!(
        problems.is_empty(),
        "regression corpus out of step with corpus.json:\n  {}",
        problems.join("\n  ")
    );
}

/// The manifest and the directory must agree: a fixture nobody checks is
/// dead weight, and a missing fixture must fail rather than skip.
#[test]
fn every_corpus_fixture_is_listed_and_present() {
    let corpus = load_corpus();
    let mut listed = std::collections::BTreeSet::new();
    for entry in &corpus.entries {
        for file in std::iter::once(&entry.fixture).chain(entry.sidecar.iter()) {
            assert!(
                resolve(file).is_file(),
                "{}: listed file {file} is missing",
                entry.id
            );
            listed.insert(resolve(file).canonicalize().expect("listed file resolves"));
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for entry in &corpus.entries {
        assert!(ids.insert(&entry.id), "duplicate corpus id {}", entry.id);
    }
    for dirent in std::fs::read_dir(CORPUS_DIR).expect("corpus dir") {
        let path = dirent.expect("dir entry").path();
        if path.file_name().is_some_and(|n| n == "corpus.json") {
            continue;
        }
        let canonical = path.canonicalize().expect("fixture resolves");
        assert!(
            listed.contains(&canonical),
            "{} is not referenced by corpus.json",
            path.display()
        );
    }
}
