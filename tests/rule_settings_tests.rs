//! Per-rule settings (`--rule`, `compliance.rules`), `--fail-on`, the
//! components whose scope is excluded, and the run inputs of the
//! multi-SBOM commands (WP 1.17).
//!
//! A rule setting is applied after the checks, through the run
//! configuration, so the verdict, the counts, the score and the exit code
//! follow it on every entry point. A component whose scope is excluded
//! (CycloneDX `scope: excluded`, an SPDX development, build or test
//! dependency) is left out of the package rules unless the run includes
//! it, and each result counts it.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sbom_tools::model::{DependencyScope, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, ComplianceRunConfig, RuleSetting, RuleSettings,
    SettingSource, ViolationSeverity, compliance_score,
};
use serde_json::Value;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// The CycloneDX fixture whose `jest` and `eslint` components have scope
/// `excluded` and would fail NTIA's supplier and version rules.
const SCOPED_JSON: &str = "cyclonedx/scope-excluded.cdx.json";
/// Its XML twin.
const SCOPED_XML: &str = "cyclonedx/scope-excluded.cdx.xml";

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn parse(name: &str) -> NormalizedSbom {
    let raw = std::fs::read_to_string(fixture(name)).expect("fixture readable");
    parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{name} must parse: {e}"))
}

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc)
}

fn run() -> ComplianceRunConfig {
    ComplianceRunConfig::new().with_as_of(as_of())
}

fn settings(entries: &[(&str, RuleSetting)]) -> RuleSettings {
    let mut settings = RuleSettings::new();
    for (rule_id, setting) in entries {
        settings
            .set(rule_id, *setting, SettingSource::Config)
            .expect("a registered rule");
    }
    settings
}

fn count(result: &ComplianceResult, rule_id: &str) -> usize {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule_id)
        .count()
}

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "warn");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

/// Run `sbom-tools` with `args` and no config file.
fn run_cli(args: &[&str]) -> Output {
    base_command()
        .arg("--no-config")
        .args(args)
        .output()
        .expect("sbom-tools runs")
}

/// Run `sbom-tools` with `args` and `config` as its config file.
fn run_cli_with_config(config: &str, args: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("sbom-tools.yaml");
    std::fs::write(&path, config).expect("config written");
    base_command()
        .arg("--config")
        .arg(&path)
        .args(args)
        .output()
        .expect("sbom-tools runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output))
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {}", stderr(output)))
}

fn validate_json(args: &[&str]) -> (Output, Value) {
    let mut all = vec!["validate"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["--as-of", AS_OF, "-o", "json"]);
    let output = run_cli(&all);
    let value = json(&output);
    (output, value)
}

/// Every `-o json` document these tests print is a valid compliance/v2
/// envelope, against the strict schema too.
fn assert_schema_valid(envelope: &Value) {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/compliance/v2.schema.json"
    ))
    .expect("schema readable");
    let schema: Value = serde_json::from_str(&text).expect("schema is JSON");
    for schema in [schema.clone(), json_schema::strict_copy(&schema)] {
        if let Err(errors) = json_schema::validate(&schema, envelope) {
            panic!("schema violations:\n{}", errors.join("\n"));
        }
    }
}

// ============================================================================
// Rule settings, through the library
// ============================================================================

/// A setting moves a rule's findings both ways, keeps the check's severity,
/// and the verdict and the counts follow the severity it sets.
#[test]
fn settings_move_severities_both_ways_and_the_verdict_follows() {
    let sbom = parse(SCOPED_JSON);
    let judged = run().with_include_excluded_scope(true);
    let before = judged.check(ComplianceLevel::NtiaMinimum, &sbom);
    assert!(!before.is_compliant, "jest and eslint name no supplier");
    assert_eq!(count(&before, "SBOM-NTIA-SUPPLIER"), 2);

    // Down: the supplier errors become warnings, so the SBOM complies.
    let relaxed = judged.clone().with_rule_settings(settings(&[
        ("SBOM-NTIA-SUPPLIER", RuleSetting::Warning),
        ("SBOM-NTIA-VERSION", RuleSetting::Info),
    ]));
    let after = relaxed.check(ComplianceLevel::NtiaMinimum, &sbom);
    assert!(after.is_compliant, "{:?}", after.violations);
    assert_eq!(after.error_count, before.error_count - 3);
    assert_eq!(after.warning_count, before.warning_count + 2);
    assert_eq!(after.info_count, before.info_count + 1);
    for v in after
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-NTIA-SUPPLIER")
    {
        assert_eq!(v.severity, ViolationSeverity::Warning);
        let o = v.severity_override.expect("a set rule records the check's");
        assert_eq!(o.default, ViolationSeverity::Error);
        assert_eq!(o.source, SettingSource::Config);
    }
    // A rule the run does not set keeps no override.
    assert!(
        after
            .violations
            .iter()
            .filter(|v| v.rule_id != "SBOM-NTIA-SUPPLIER" && v.rule_id != "SBOM-NTIA-VERSION")
            .all(|v| v.severity_override.is_none())
    );
    // An overridden finding keeps everything else it says: what it is
    // about, what it read and where.
    let what = |result: &ComplianceResult| -> Vec<(String, Option<String>, Option<String>)> {
        let mut v: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.rule_id == "SBOM-NTIA-SUPPLIER" || v.rule_id == "SBOM-NTIA-VERSION")
            .map(|v| (v.message.clone(), v.field.clone(), v.observed.clone()))
            .collect();
        v.sort();
        v
    };
    assert_eq!(what(&after), what(&before));
    assert!(
        what(&after).iter().all(|(_, field, _)| field.is_some()),
        "the package findings name the field they read: {:?}",
        what(&after)
    );

    // Up: a warning-only SBOM fails once its warnings are errors.
    let warnings_only = parse("cyclonedx/ntia-warnings-only.cdx.json");
    let plain = run().check(ComplianceLevel::NtiaMinimum, &warnings_only);
    assert!(plain.is_compliant);
    assert!(count(&plain, "SBOM-NTIA-DEPENDENCY") > 0);
    let strict = run()
        .with_rule_settings(settings(&[("SBOM-NTIA-DEPENDENCY", RuleSetting::Error)]))
        .check(ComplianceLevel::NtiaMinimum, &warnings_only);
    assert!(!strict.is_compliant);
    assert_eq!(strict.error_count, count(&plain, "SBOM-NTIA-DEPENDENCY"));
    assert_eq!(
        strict.warning_count,
        plain.warning_count - strict.error_count
    );
}

/// `off` drops a rule's findings and counts them per rule: no severity
/// count, no verdict and no score sees them.
#[test]
fn off_drops_the_findings_and_counts_them() {
    let sbom = parse(SCOPED_JSON);
    let judged = run().with_include_excluded_scope(true);
    let before = judged.check(ComplianceLevel::NtiaMinimum, &sbom);
    let off = judged
        .with_rule_settings(settings(&[
            ("SBOM-NTIA-SUPPLIER", RuleSetting::Off),
            ("SBOM-NTIA-VERSION", RuleSetting::Off),
        ]))
        .check(ComplianceLevel::NtiaMinimum, &sbom);
    assert_eq!(count(&off, "SBOM-NTIA-SUPPLIER"), 0);
    assert_eq!(count(&off, "SBOM-NTIA-VERSION"), 0);
    assert!(off.is_compliant);
    assert_eq!(off.error_count, before.error_count - 3);
    assert_eq!(off.suppressed_count(), 3);
    let suppressed: Vec<(&str, usize)> = off
        .suppressed
        .iter()
        .map(|rule| (rule.rule_id.as_str(), rule.findings))
        .collect();
    assert_eq!(
        suppressed,
        [("SBOM-NTIA-SUPPLIER", 2), ("SBOM-NTIA-VERSION", 1)]
    );
    // The score reads the remaining findings only: as if the dropped
    // findings were never reported.
    assert!(off.score() > before.score());
}

/// The score reads the effective severities, as documented: `band +
/// floor(50 × checked / (checked + failed))`, with the 50-point band only
/// without an error, and Info findings failing no check. Turning the
/// errors into warnings keeps the failed checks and gains the band; turning
/// them into info, or off, leaves no failed check.
#[test]
fn an_override_moves_the_score_as_documented() {
    let sbom = parse(SCOPED_JSON);
    let judged = run().with_include_excluded_scope(true);
    let score = |settings: &[(&str, RuleSetting)]| {
        let result = judged
            .clone()
            .with_rule_settings(self::settings(settings))
            .check(ComplianceLevel::NtiaMinimum, &sbom);
        // The document and the five package components.
        assert_eq!(result.elements_checked, 6);
        (
            result.score().expect("NTIA applies"),
            result.failed_checks(),
        )
    };
    // jest and eslint name no supplier; eslint has no version.
    let (before, failed) = score(&[]);
    assert_eq!(failed, 3);
    assert_eq!(before, compliance_score(3, 0, 6));
    assert_eq!(before, 33, "no band, floor(50 × 6 / 9)");

    let warnings = [
        ("SBOM-NTIA-SUPPLIER", RuleSetting::Warning),
        ("SBOM-NTIA-VERSION", RuleSetting::Warning),
    ];
    let (warned, failed) = score(&warnings);
    assert_eq!(failed, 3, "a warning fails its check as an error does");
    assert_eq!(warned, compliance_score(0, 3, 6));
    assert_eq!(warned, before + 50, "the compliant band");

    let info = [
        ("SBOM-NTIA-SUPPLIER", RuleSetting::Info),
        ("SBOM-NTIA-VERSION", RuleSetting::Info),
    ];
    assert_eq!(score(&info), (100, 0), "info findings fail no check");
    let off = [
        ("SBOM-NTIA-SUPPLIER", RuleSetting::Off),
        ("SBOM-NTIA-VERSION", RuleSetting::Off),
    ];
    assert_eq!(score(&off), (100, 0));

    // Up: a warning made an error drops the band.
    let warnings_only = parse("cyclonedx/ntia-warnings-only.cdx.json");
    let plain = run().check(ComplianceLevel::NtiaMinimum, &warnings_only);
    let strict = run()
        .with_rule_settings(settings(&[("SBOM-NTIA-DEPENDENCY", RuleSetting::Error)]))
        .check(ComplianceLevel::NtiaMinimum, &warnings_only);
    assert_eq!(plain.failed_checks(), strict.failed_checks());
    assert_eq!(
        strict.score().expect("applies") + 50,
        plain.score().expect("applies")
    );

    // Leaving the excluded components out shrinks `checked` and drops their
    // failed checks.
    let default = run().check(ComplianceLevel::NtiaMinimum, &sbom);
    assert_eq!(default.elements_checked, 4);
    assert_eq!(default.score(), Some(100));
}

/// A setting reaches every level that reports its rule, and no other: the
/// CRA family's version rule is the rule of the two CRA phases and the
/// steward profile, while NTIA and the quality profiles have version rules
/// of their own.
#[test]
fn a_setting_reaches_every_level_reporting_its_rule() {
    let sbom = parse(SCOPED_JSON);
    let judged = run()
        .with_include_excluded_scope(true)
        .with_rule_settings(settings(&[(
            "SBOM-CRA-COMPONENT-VERSION",
            RuleSetting::Info,
        )]));
    for level in [
        ComplianceLevel::CraPhase1,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::CraOssSteward,
    ] {
        let result = judged.check(level, &sbom);
        let versions: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.rule_id == "SBOM-CRA-COMPONENT-VERSION")
            .collect();
        assert!(!versions.is_empty(), "{level:?} reports the version rule");
        assert!(
            versions
                .iter()
                .all(|v| v.severity == ViolationSeverity::Info && v.severity_override.is_some()),
            "{level:?}"
        );
    }
    for (level, own_rule) in [
        (ComplianceLevel::NtiaMinimum, "SBOM-NTIA-VERSION"),
        (ComplianceLevel::Standard, "SBOM-QUALITY-VERSION"),
    ] {
        let result = judged.check(level, &sbom);
        let own: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.rule_id == own_rule)
            .collect();
        assert!(!own.is_empty(), "{level:?} reports {own_rule}");
        assert!(
            own.iter()
                .all(|v| v.severity == ViolationSeverity::Error && v.severity_override.is_none()),
            "{level:?}: the CRA setting does not reach {own_rule}"
        );
    }
}

// ============================================================================
// Rule settings, through the command line
// ============================================================================

/// The JSON envelope carries the effective severity, the check's
/// (`default_severity`) and the setting's source, and lists what `off`
/// dropped under `suppressed` and `counts.suppressed`.
#[test]
fn json_shows_the_default_severity_and_what_off_dropped() {
    let (output, envelope) = validate_json(&[
        fixture(SCOPED_JSON).to_str().expect("utf-8 path"),
        "--include-excluded-scope",
        "--rule",
        "sbom-ntia-supplier=warning",
        "--rule",
        "SBOM-NTIA-VERSION=off",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_schema_valid(&envelope);
    let result = &envelope["results"][0];
    assert_eq!(result["compliant"], true);
    assert_eq!(result["counts"]["suppressed"], 1);
    assert_eq!(
        result["suppressed"],
        serde_json::json!([{"rule_id": "SBOM-NTIA-VERSION", "findings": 1, "source": "cli"}])
    );
    let suppliers: Vec<&Value> = result["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .filter(|v| v["rule_id"] == "SBOM-NTIA-SUPPLIER")
        .collect();
    assert_eq!(suppliers.len(), 2);
    for v in suppliers {
        assert_eq!(v["severity"], "Warning");
        assert_eq!(v["default_severity"], "Error");
        assert_eq!(v["severity_source"], "cli");
    }
}

/// The exit code follows the severities a setting sets: errors made
/// warnings exit 0, or 2 under `--fail-on-warning`; warnings made errors
/// exit 1.
#[test]
fn exit_codes_follow_the_set_severities() {
    let scoped = fixture(SCOPED_JSON);
    let scoped = scoped.to_str().expect("utf-8 path");
    let code = |args: &[&str]| {
        let mut all = vec!["validate", "--as-of", AS_OF, "--summary"];
        all.extend_from_slice(args);
        let output = run_cli(&all);
        output
            .status
            .code()
            .unwrap_or_else(|| panic!("{}", stderr(&output)))
    };
    assert_eq!(code(&[scoped, "--include-excluded-scope"]), 1);
    let relax = [
        scoped,
        "--include-excluded-scope",
        "--rule",
        "SBOM-NTIA-SUPPLIER=warning",
        "--rule",
        "SBOM-NTIA-VERSION=warning",
    ];
    assert_eq!(code(&relax), 0);
    let mut strict = relax.to_vec();
    strict.push("--fail-on-warning");
    assert_eq!(code(&strict), 2);

    let warnings_only = fixture("cyclonedx/ntia-warnings-only.cdx.json");
    let warnings_only = warnings_only.to_str().expect("utf-8 path");
    assert_eq!(code(&[warnings_only]), 0);
    assert_eq!(
        code(&[warnings_only, "--rule", "SBOM-NTIA-DEPENDENCY=error"]),
        1
    );
    assert_eq!(
        code(&[
            warnings_only,
            "--fail-on-warning",
            "--rule",
            "SBOM-NTIA-DEPENDENCY=off"
        ]),
        0
    );
}

/// An unknown rule id is a usage error (exit 3) on the command line and in
/// the config file, and the message names the closest id. So is a setting
/// that is not off, info, warning or error, and a pass-only rule.
#[test]
fn unknown_rules_and_settings_are_usage_errors() {
    let scoped = fixture(SCOPED_JSON);
    let scoped = scoped.to_str().expect("utf-8 path");
    for (args, expected) in [
        (
            vec!["--rule", "SBOM-NTIA-SUPLIER=warning"],
            "did you mean SBOM-NTIA-SUPPLIER?",
        ),
        (
            vec!["--rule", "SBOM-NTIA-SUPPLIER=warn"],
            "off, info, warning, error",
        ),
        (vec!["--rule", "SBOM-NTIA-SUPPLIER"], "RULE=SETTING"),
        (vec!["--rule", "SBOM-PQC-009=error"], "passed checks"),
        (
            vec!["--fail-on", "SBOM-NTIA-SUPLIER"],
            "did you mean SBOM-NTIA-SUPPLIER?",
        ),
        (vec!["--fail-on", "SBOM-PQC-010"], "never a finding"),
    ] {
        let mut all = vec!["validate", scoped];
        all.extend_from_slice(&args);
        let output = run_cli(&all);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(expected),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    // The same in the config file.
    for (config, expected) in [
        (
            "compliance:\n  rules:\n    SBOM-NTIA-SUPLIER: warning\n",
            "did you mean SBOM-NTIA-SUPPLIER?",
        ),
        (
            "compliance:\n  rules:\n    SBOM-NTIA-SUPPLIER: loud\n",
            "off, info, warning, error",
        ),
        (
            "compliance:\n  fail_on: [SBOM-NTIA-SUPLIER]\n",
            "did you mean SBOM-NTIA-SUPPLIER?",
        ),
    ] {
        let output = run_cli_with_config(config, &["validate", scoped]);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{config}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(expected),
            "{config}: {}",
            stderr(&output)
        );
    }
}

/// A `--rule` flag wins over the config file for its own rule; the file's
/// other settings stay.
#[test]
fn a_rule_flag_wins_over_the_config_file_for_its_rule() {
    let scoped = fixture(SCOPED_JSON);
    let config = "compliance:\n  include_excluded_scope: true\n  rules:\n    \
                  SBOM-NTIA-SUPPLIER: off\n    SBOM-NTIA-VERSION: info\n";
    let output = run_cli_with_config(
        config,
        &[
            "validate",
            scoped.to_str().expect("utf-8 path"),
            "--as-of",
            AS_OF,
            "-o",
            "json",
            "--rule",
            "SBOM-NTIA-SUPPLIER=error",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let envelope = json(&output);
    assert_schema_valid(&envelope);
    let result = &envelope["results"][0];
    let by_rule = |rule: &str| -> Vec<Value> {
        result["violations"]
            .as_array()
            .expect("violations")
            .iter()
            .filter(|v| v["rule_id"] == rule)
            .cloned()
            .collect()
    };
    let suppliers = by_rule("SBOM-NTIA-SUPPLIER");
    assert_eq!(
        suppliers.len(),
        2,
        "the flag turned the file's `off` back on"
    );
    assert!(suppliers.iter().all(|v| v["severity_source"] == "cli"));
    let versions = by_rule("SBOM-NTIA-VERSION");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["severity"], "Info");
    assert_eq!(versions[0]["severity_source"], "config");
    assert!(result.get("suppressed").is_none());
}

/// `--fail-on RULE` fails the run (exit 1) on any finding of the rule,
/// whatever its severity, ahead of `--fail-on-warning`'s 2. A rule with no
/// finding, or one that is off, does not trip it.
#[test]
fn fail_on_exits_1_on_a_finding_of_any_severity() {
    let warnings_only = fixture("cyclonedx/ntia-warnings-only.cdx.json");
    let warnings_only = warnings_only.to_str().expect("utf-8 path");
    let run_validate = |args: &[&str]| {
        let mut all = vec!["validate", warnings_only, "--as-of", AS_OF, "--summary"];
        all.extend_from_slice(args);
        run_cli(&all)
    };
    let code = |args: &[&str]| run_validate(args).status.code();
    // The fixture's only NTIA findings are dependency warnings.
    assert_eq!(code(&["--fail-on", "SBOM-NTIA-DEPENDENCY"]), Some(1));
    assert_eq!(
        code(&["--fail-on", "SBOM-NTIA-DEPENDENCY", "--fail-on-warning"]),
        Some(1)
    );
    assert_eq!(code(&["--fail-on-warning"]), Some(2));
    assert_eq!(
        code(&[
            "--fail-on",
            "SBOM-NTIA-DEPENDENCY",
            "--rule",
            "SBOM-NTIA-DEPENDENCY=info"
        ]),
        Some(1),
        "an info finding trips it too"
    );
    assert_eq!(code(&["--fail-on", "SBOM-NTIA-SUPPLIER"]), Some(0));

    // A rule that is off reports no finding: the gate cannot trip, and the
    // run says so.
    let off = run_validate(&[
        "--fail-on",
        "SBOM-NTIA-DEPENDENCY",
        "--rule",
        "SBOM-NTIA-DEPENDENCY=off",
    ]);
    assert_eq!(off.status.code(), Some(0), "{}", stderr(&off));
    assert!(
        stderr(&off).contains("--fail-on SBOM-NTIA-DEPENDENCY can never fail this run"),
        "{}",
        stderr(&off)
    );

    // The config file's `fail_on` gates the same way.
    let output = run_cli_with_config(
        "compliance:\n  fail_on: [SBOM-NTIA-DEPENDENCY]\n",
        &["validate", warnings_only, "--as-of", AS_OF, "--summary"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

/// A setting or a `--fail-on` rule that no selected standard reports
/// changes nothing, and the run warns about it.
#[test]
fn settings_that_can_never_match_warn() {
    let output = run_cli(&[
        "validate",
        fixture(SCOPED_JSON).to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
        "--summary",
        "--rule",
        "SBOM-CRA-ART-24=off",
        "--fail-on",
        "SBOM-PQC-001",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains(
            "rule setting SBOM-CRA-ART-24=off (from --rule) changes nothing: the selected \
             standards report no SBOM-CRA-ART-24 finding"
        ),
        "{err}"
    );
    assert!(
        err.contains("--fail-on SBOM-PQC-001 can never fail this run"),
        "{err}"
    );
}

/// `quality` applies the settings to its embedded compliance check.
#[test]
fn quality_applies_the_settings_to_its_compliance_check() {
    let scoped = fixture(SCOPED_JSON);
    let scoped = scoped.to_str().expect("utf-8 path");
    let compliant = |args: &[&str]| {
        let mut all = vec![
            "quality",
            scoped,
            "--profile",
            "standard",
            "--as-of",
            AS_OF,
            "-o",
            "json",
            "--include-excluded-scope",
        ];
        all.extend_from_slice(args);
        let output = run_cli(&all);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        json(&output)["report"]["compliance"]["is_compliant"].clone()
    };
    assert_eq!(compliant(&[]), false);
    assert_eq!(compliant(&["--rule", "SBOM-QUALITY-VERSION=warning"]), true);
}

// ============================================================================
// Components whose scope is excluded
// ============================================================================

/// The CycloneDX parsers read the component scope, JSON and XML alike.
#[test]
fn cyclonedx_json_and_xml_read_the_component_scope() {
    for name in [SCOPED_JSON, SCOPED_XML] {
        let sbom = parse(name);
        let scope = |component: &str| {
            sbom.components
                .values()
                .find(|c| c.name == component)
                .unwrap_or_else(|| panic!("{name}: {component}"))
                .scope
                .clone()
        };
        assert_eq!(scope("express"), Some(DependencyScope::Required), "{name}");
        assert_eq!(scope("fsevents"), Some(DependencyScope::Optional), "{name}");
        assert_eq!(scope("jest"), Some(DependencyScope::Excluded), "{name}");
        assert_eq!(scope("eslint"), Some(DependencyScope::Excluded), "{name}");
        assert_eq!(scope("scoped-app"), None, "{name}");
    }
}

/// The package rules leave excluded components out, each result counts
/// them, and `--include-excluded-scope` judges them: in JSON and XML alike.
#[test]
fn package_rules_leave_excluded_components_out_by_default() {
    for name in [SCOPED_JSON, SCOPED_XML] {
        let sbom = parse(name);
        let default = run().check(ComplianceLevel::NtiaMinimum, &sbom);
        assert!(default.is_compliant, "{name}: {:?}", default.violations);
        assert_eq!(default.excluded_components, 2, "{name}");
        assert!(
            default.violations.iter().all(|v| !v
                .component_id
                .as_deref()
                .is_some_and(|id| id.contains("jest") || id.contains("eslint"))),
            "{name}: {:?}",
            default.violations
        );

        let included = run()
            .with_include_excluded_scope(true)
            .check(ComplianceLevel::NtiaMinimum, &sbom);
        assert!(!included.is_compliant, "{name}");
        assert_eq!(included.excluded_components, 0, "{name}");
        assert_eq!(count(&included, "SBOM-NTIA-SUPPLIER"), 2, "{name}");
        assert_eq!(count(&included, "SBOM-NTIA-VERSION"), 1, "{name}");

        // A standard without package rules leaves nothing out.
        for level in [ComplianceLevel::NistPqc, ComplianceLevel::EuccSubstantial] {
            assert_eq!(
                run().check(level, &sbom).excluded_components,
                0,
                "{name}: {level:?}"
            );
        }
    }
}

/// Every standard with package rules leaves the excluded components out.
#[test]
fn every_package_standard_leaves_the_excluded_components_out() {
    let sbom = parse(SCOPED_JSON);
    for level in ComplianceLevel::all() {
        let result = run().check(*level, &sbom);
        let expected = if ComplianceRunConfig::excluded_scope_applies(*level) {
            2
        } else {
            0
        };
        assert_eq!(result.excluded_components, expected, "{level:?}");
        if expected > 0 {
            assert!(
                result.violations.iter().all(|v| {
                    v.component_id.as_deref() != Some("pkg:npm/jest@29.7.0")
                        && v.component_id.as_deref() != Some("pkg:npm/eslint")
                }),
                "{level:?}: {:?}",
                result.violations
            );
        }
    }
}

/// On the command line: the JSON envelope counts the excluded components,
/// and the flag or the config file's `include_excluded_scope` judges them.
#[test]
fn the_cli_counts_excluded_components_and_can_include_them() {
    for name in [SCOPED_JSON, SCOPED_XML] {
        let path = fixture(name);
        let path = path.to_str().expect("utf-8 path");
        let (output, envelope) = validate_json(&[path]);
        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert_schema_valid(&envelope);
        assert_eq!(envelope["results"][0]["excluded_components"], 2, "{name}");

        let (output, envelope) = validate_json(&[path, "--include-excluded-scope"]);
        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        assert!(envelope["results"][0].get("excluded_components").is_none());

        let output = run_cli_with_config(
            "compliance:\n  include_excluded_scope: true\n",
            &["validate", path, "--as-of", AS_OF, "--summary"],
        );
        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
    }

    // The text report says what it left out.
    let output = run_cli(&[
        "validate",
        fixture(SCOPED_JSON).to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
    ]);
    assert!(
        stdout(&output).contains("Excluded: 2 components with scope excluded"),
        "{}",
        stdout(&output)
    );
}

/// A component the document lists twice, once `excluded` and once
/// `required`, stays judged whichever entry comes first: an excluded entry
/// never hides one the product needs.
#[test]
fn an_excluded_duplicate_never_hides_a_required_entry() {
    let document = |first: &str, second: &str| {
        format!(
            r#"{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {{
    "timestamp": "2026-10-01T12:00:00Z",
    "authors": [{{ "name": "Release Engineering" }}],
    "component": {{
      "type": "application", "bom-ref": "app", "name": "app", "version": "1.0.0",
      "purl": "pkg:npm/app@1.0.0", "supplier": {{ "name": "Acme Corp" }}
    }}
  }},
  "components": [
    {{ "type": "library", "bom-ref": "jest-a", "name": "jest", "version": "29.7.0",
       "purl": "pkg:npm/jest@29.7.0", "scope": "{first}" }},
    {{ "type": "library", "bom-ref": "jest-b", "name": "jest", "version": "29.7.0",
       "purl": "pkg:npm/jest@29.7.0", "scope": "{second}" }}
  ],
  "dependencies": [{{ "ref": "app", "dependsOn": ["jest-a", "jest-b"] }}]
}}"#
        )
    };
    for (first, second) in [("excluded", "required"), ("required", "excluded")] {
        let sbom = parse_sbom_str(&document(first, second)).expect("the document parses");
        let jest: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.name == "jest")
            .collect();
        assert_eq!(jest.len(), 1, "the two entries merge into one component");
        assert_eq!(
            jest[0].scope,
            Some(DependencyScope::Required),
            "{first}, {second}"
        );
        let result = run().check(ComplianceLevel::NtiaMinimum, &sbom);
        assert_eq!(result.excluded_components, 0, "{first}, {second}");
        assert_eq!(
            count(&result, "SBOM-NTIA-SUPPLIER"),
            1,
            "{first}, {second}: jest is judged"
        );
    }
}

/// SPDX 2.3: a development dependency, and what only it brings in, is not
/// needed at runtime; the components the product depends on are.
#[test]
fn spdx_dev_dependencies_are_excluded_with_what_they_bring_in() {
    let sbom = parse("spdx/dev-dependencies.spdx.json");
    let scope = |component: &str| {
        sbom.components
            .values()
            .find(|c| c.name == component)
            .unwrap_or_else(|| panic!("{component}"))
            .scope
            .clone()
    };
    assert_eq!(scope("jest"), Some(DependencyScope::Excluded));
    assert_eq!(scope("@babel/core"), Some(DependencyScope::Excluded));
    assert_eq!(scope("express"), None);
    assert_eq!(scope("scoped-app"), None);

    let default = run().check(ComplianceLevel::NtiaMinimum, &sbom);
    assert!(default.is_compliant, "{:?}", default.violations);
    assert_eq!(default.excluded_components, 2);
    let included = run()
        .with_include_excluded_scope(true)
        .check(ComplianceLevel::NtiaMinimum, &sbom);
    assert!(!included.is_compliant);
}

/// SPDX 3.0: a lifecycle-scoped relationship of scope `test` or `build`
/// brings in a component the product does not need at runtime; one of
/// scope `runtime` does not.
#[test]
fn spdx3_lifecycle_scopes_mark_build_and_test_dependencies() {
    let sbom = parse("spdx3/lifecycle-scope.spdx3.json");
    let component = |name: &str| {
        sbom.components
            .values()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    assert_eq!(component("jest").scope, Some(DependencyScope::Excluded));
    assert_eq!(component("webpack").scope, Some(DependencyScope::Excluded));
    assert_eq!(component("express").scope, None);
    // The edges keep the relationship's lifecycle scope.
    let express_edge = sbom
        .edges
        .iter()
        .find(|e| e.to == component("express").canonical_id)
        .expect("the runtime edge");
    assert_eq!(express_edge.scope, Some(DependencyScope::Required));

    let default = run().check(ComplianceLevel::NtiaMinimum, &sbom);
    assert_eq!(default.excluded_components, 2);
    assert_eq!(count(&default, "SBOM-NTIA-SUPPLIER"), 0);
    let included = run()
        .with_include_excluded_scope(true)
        .check(ComplianceLevel::NtiaMinimum, &sbom);
    assert!(count(&included, "SBOM-NTIA-SUPPLIER") >= 2);
}

// ============================================================================
// Run inputs of the multi-SBOM commands
// ============================================================================

/// `timeline` takes the shared run inputs: `--as-of` pins its compliance
/// trend and `--rule` applies to it.
#[test]
fn timeline_takes_the_shared_run_inputs() {
    let old = fixture("demo-old.cdx.json");
    let new = fixture("demo-new.cdx.json");
    let trend = |args: &[&str]| {
        let mut all = vec![
            "timeline",
            old.to_str().expect("utf-8 path"),
            new.to_str().expect("utf-8 path"),
            "-o",
            "json",
        ];
        all.extend_from_slice(args);
        let output = run_cli(&all);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        json(&output)["evolution_summary"]["compliance_trend"].clone()
    };
    let standard = |trend: &Value, name: &str| -> Value {
        trend[0]["scores"]
            .as_array()
            .expect("scores")
            .iter()
            .find(|s| s["standard"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} in the trend"))
    };
    let pinned = trend(&["--as-of", AS_OF]);
    assert_eq!(pinned, trend(&["--as-of", AS_OF]), "a pinned trend repeats");
    // CRA Art. 14 reporting applies from 2026-09-11: before it, its
    // findings are info; after, warnings.
    let before = trend(&["--as-of", "2026-01-01"]);
    let cra = "EU CRA Phase 1 (2026)";
    assert!(
        standard(&before, cra)["warning_count"].as_u64()
            < standard(&pinned, cra)["warning_count"].as_u64(),
        "before: {}\nafter: {}",
        standard(&before, cra),
        standard(&pinned, cra)
    );

    // The rule settings reach the trend: the demo SBOM's NTIA errors
    // include supplier errors, which `off` drops.
    let ntia = "NTIA Minimum Elements";
    let off = trend(&["--as-of", AS_OF, "--rule", "SBOM-NTIA-SUPPLIER=off"]);
    assert!(
        standard(&off, ntia)["error_count"].as_u64()
            < standard(&pinned, ntia)["error_count"].as_u64(),
        "off: {}\npinned: {}",
        standard(&off, ntia),
        standard(&pinned, ntia)
    );
}

/// `diff-multi` and `matrix` accept the shared run inputs too.
#[test]
fn diff_multi_and_matrix_accept_the_shared_run_inputs() {
    let old = fixture("demo-old.cdx.json");
    let new = fixture("demo-new.cdx.json");
    let old = old.to_str().expect("utf-8 path");
    let new = new.to_str().expect("utf-8 path");
    for command in ["diff-multi", "matrix"] {
        let output = run_cli(&[
            command,
            old,
            new,
            "-o",
            "json",
            "--as-of",
            AS_OF,
            "--cra-product-class",
            "important-class-1",
            "--rule",
            "SBOM-NTIA-SUPPLIER=warning",
        ]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command}: {}",
            stderr(&output)
        );
        let output = run_cli(&[command, old, new, "-o", "json", "--as-of", "not-a-date"]);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{command}: {}",
            stderr(&output)
        );
    }
}

/// `diff` names the SBOM its product-class warning is about, once per side.
#[test]
fn diff_names_the_sbom_of_a_product_class_mismatch() {
    let dir = tempfile::tempdir().expect("temp dir");
    for side in ["old", "new"] {
        std::fs::copy(
            fixture("cra/cra-compliant.cdx.json"),
            dir.path().join(format!("{side}.cdx.json")),
        )
        .expect("SBOM copied");
        // Its sidecar says important-class-1.
        std::fs::copy(
            fixture("cra/cra-compliant.cra.json"),
            dir.path().join(format!("{side}.cra.json")),
        )
        .expect("sidecar copied");
    }
    let old = dir.path().join("old.cdx.json");
    let new = dir.path().join("new.cdx.json");
    let output = run_cli(&[
        "diff",
        old.to_str().expect("utf-8 path"),
        new.to_str().expect("utf-8 path"),
        "-o",
        "json",
        "--cra-product-class",
        "critical",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let err = stderr(&output);
    for path in [&old, &new] {
        assert!(
            err.contains(&format!(
                "CRA product class mismatch for {}",
                path.display()
            )),
            "{err}"
        );
    }
}

// ============================================================================
// PQC defaults in the config file
// ============================================================================

/// `compliance.pqc_mode` is the default of `--pqc-mode`; a profile or a
/// category outside deadline mode is a config error (exit 3); the flag
/// wins over the file.
#[test]
fn the_config_file_sets_the_pqc_defaults() {
    let cbom = fixture("cyclonedx/cbom-pqc-calendar.cdx.json");
    let cbom = cbom.to_str().expect("utf-8 path");
    let args = [
        "validate",
        cbom,
        "--standard",
        "pqc",
        "--as-of",
        "2031-06-01",
        "-o",
        "json",
    ];
    let dated = |output: &Output| {
        json(output)["results"][0]["violations"]
            .as_array()
            .expect("violations")
            .iter()
            .any(|v| v.get("deadline").is_some())
    };
    let deadline = run_cli_with_config("compliance:\n  pqc_mode: deadline\n", &args);
    assert!(dated(&deadline), "{}", stderr(&deadline));

    let mut readiness_args = args.to_vec();
    readiness_args.extend_from_slice(&["--pqc-mode", "readiness"]);
    let readiness = run_cli_with_config(
        "compliance:\n  pqc_mode: deadline\n  pqc_profile: federal\n",
        &readiness_args,
    );
    assert!(
        !readiness.stdout.is_empty(),
        "--pqc-mode readiness drops the file's deadline-mode profile: {}",
        stderr(&readiness)
    );
    assert!(!dated(&readiness));

    let federal = run_cli_with_config(
        "compliance:\n  pqc_mode: deadline\n  pqc_profile: federal\n",
        &args,
    );
    let federal_rules: Vec<String> = json(&federal)["results"][0]["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .filter_map(|v| v["rule_id"].as_str().map(str::to_string))
        .collect();
    assert!(
        federal_rules.iter().any(|id| id == "SBOM-PQC-PROTO-003"),
        "the federal profile reports TLS 1.2: {federal_rules:?}"
    );

    let invalid = run_cli_with_config("compliance:\n  pqc_profile: federal\n", &args);
    assert_eq!(invalid.status.code(), Some(3), "{}", stderr(&invalid));
    assert!(
        stderr(&invalid).contains("compliance.pqc_profile"),
        "{}",
        stderr(&invalid)
    );
}
