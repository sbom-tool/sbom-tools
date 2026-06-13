//! CLI contract tests: per-command exit codes, typed value-enum parse
//! validation, and NDJSON output wiring.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be utf-8")
}

#[test]
fn validate_fail_on_warning_returns_exit_code_2() {
    // minimal.cdx.json has 0 NTIA errors but several warnings (missing
    // version/supplier), so --fail-on-warning must exit with code 2.
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/minimal.cdx.json"))
        .args(["--standard", "ntia", "--summary", "--fail-on-warning"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn validate_without_fail_on_warning_returns_exit_code_0_when_warnings_only() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/minimal.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn validate_with_errors_returns_exit_code_1() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn quality_below_min_score_returns_exit_code_1() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--min-score", "100", "-o", "json"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn quality_meeting_min_score_returns_exit_code_0() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--min-score", "0", "-o", "json"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn query_no_match_returns_exit_code_1() {
    let output = base_command()
        .arg("query")
        .arg("zzz-no-such-component-zzz")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("query command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn query_match_returns_exit_code_0() {
    let output = base_command()
        .arg("query")
        .arg("lodash")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("query command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn invalid_fuzzy_preset_is_rejected_at_parse() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--fuzzy-preset", "not-a-preset"])
        .output()
        .expect("diff command should run");

    // clap exits with code 2 on argument parse errors.
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-preset'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list the valid presets (did-you-mean hint): {err}"
    );
}

#[test]
fn invalid_merge_dedup_strategy_is_rejected_at_parse() {
    let output = base_command()
        .arg("merge")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--dedup", "not-a-strategy"])
        .output()
        .expect("merge command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-strategy'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("name") && err.contains("purl"),
        "stderr should list valid dedup strategies: {err}"
    );
}

#[test]
fn diff_ndjson_output_emits_one_json_object_per_line() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "ndjson"])
        .output()
        .expect("diff command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);

    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 2, "expected multiple NDJSON lines: {text}");

    // Every non-empty line must be a standalone JSON object.
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line is not valid json: {line}: {e}"));
        assert!(
            value.is_object(),
            "each NDJSON line should be an object: {line}"
        );
    }

    // The first record is the metadata header; a summary record follows.
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first line json");
    assert_eq!(first["type"], "metadata");
    assert!(
        lines
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .any(|v| v["type"] == "summary"),
        "expected a summary NDJSON record: {text}"
    );
}
