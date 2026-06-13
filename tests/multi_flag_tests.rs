//! End-to-end checks that multi-SBOM commands honor their advertised flags.
//!
//! Covers the contract fixed in `fix(cli): multi-SBOM commands honor
//! graph/filter/rules flags and output formats`:
//! - `--graph-max-depth` actually changes graph-diff output,
//! - `--fail-on-vex-gap` can reach exit code 4 for multi commands,
//! - an unsupported `-o` value fails with a clear, actionable error.

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

/// Parse the JSON object emitted on stdout (skipping any leading log noise).
fn json_stdout(output: &Output) -> serde_json::Value {
    let text = stdout(output);
    let start = text.find('{').expect("stdout should contain a JSON object");
    serde_json::from_str(&text[start..]).expect("stdout payload should be valid json")
}

fn first_comparison_graph_change_count(value: &serde_json::Value) -> usize {
    value["comparisons"][0]["diff"]["graph_changes"]
        .as_array()
        .map_or(0, Vec::len)
}

#[test]
fn diff_multi_graph_max_depth_changes_output() {
    let baseline = fixture_path("showcase/graph-baseline.cdx.json");
    let reorg = fixture_path("showcase/graph-reorg.cdx.json");

    let unlimited = base_command()
        .arg("diff-multi")
        .arg(&baseline)
        .arg(&reorg)
        .args(["-o", "json", "--graph-diff", "--graph-max-depth", "0"])
        .output()
        .expect("diff-multi should run");
    assert!(unlimited.status.success(), "{}", stderr(&unlimited));

    let shallow = base_command()
        .arg("diff-multi")
        .arg(&baseline)
        .arg(&reorg)
        .args(["-o", "json", "--graph-diff", "--graph-max-depth", "1"])
        .output()
        .expect("diff-multi should run");
    assert!(shallow.status.success(), "{}", stderr(&shallow));

    let unlimited_changes = first_comparison_graph_change_count(&json_stdout(&unlimited));
    let shallow_changes = first_comparison_graph_change_count(&json_stdout(&shallow));

    // Limiting the analysis depth must prune deeper graph changes; if the flag
    // were ignored (the old GraphDiffConfig::default() bug) the two counts
    // would be identical.
    assert!(
        shallow_changes < unlimited_changes,
        "--graph-max-depth 1 ({shallow_changes}) should yield fewer graph changes \
         than unlimited ({unlimited_changes})"
    );
}

#[test]
fn diff_multi_fail_on_vex_gap_returns_exit_4() {
    let baseline = fixture_path("showcase/supply-chain-baseline.cdx.json");
    let incident = fixture_path("showcase/supply-chain-incident.cdx.json");

    let output = base_command()
        .arg("diff-multi")
        .arg(&baseline)
        .arg(&incident)
        .args(["-o", "json", "--fail-on-vex-gap"])
        .output()
        .expect("diff-multi should run");

    assert_eq!(
        output.status.code(),
        Some(4),
        "introduced vulns without VEX should yield exit 4; stderr: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("VEX gap"),
        "stderr should explain the VEX gap: {}",
        stderr(&output)
    );
}

#[test]
fn diff_multi_rejects_unsupported_output_format() {
    let baseline = fixture_path("showcase/graph-baseline.cdx.json");
    let reorg = fixture_path("showcase/graph-reorg.cdx.json");

    let output = base_command()
        .arg("diff-multi")
        .arg(&baseline)
        .arg(&reorg)
        .args(["-o", "table"])
        .output()
        .expect("diff-multi should run");

    assert!(
        !output.status.success(),
        "an unsupported -o value should fail rather than emit JSON"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported for multi-SBOM commands"),
        "error should name the limitation: {err}"
    );
    assert!(
        err.contains("tui, json"),
        "error should list the supported formats: {err}"
    );
}

#[test]
fn matrix_rejects_unsupported_output_format() {
    let a = fixture_path("showcase/fleet-v1.cdx.json");
    let b = fixture_path("showcase/fleet-v2.cdx.json");

    let output = base_command()
        .arg("matrix")
        .arg(&a)
        .arg(&b)
        .args(["-o", "markdown"])
        .output()
        .expect("matrix should run");

    assert!(
        !output.status.success(),
        "an unsupported -o value should fail rather than emit JSON"
    );
    assert!(
        stderr(&output).contains("not supported for multi-SBOM commands"),
        "error should name the limitation: {}",
        stderr(&output)
    );
}
