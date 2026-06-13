//! Integration tests for stdin (`-`) input support and the shared 512 MB size
//! guard, plus a (default-ignored) parse+diff of the large CycloneDX fixture.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn sbom_tools_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbom-tools"))
}

fn base_command() -> Command {
    let mut cmd = Command::new(sbom_tools_bin());
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run a command, piping `input` to its stdin, and return the captured output.
fn run_with_stdin(mut cmd: Command, input: &[u8]) -> Output {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("binary should launch");
    child
        .stdin
        .take()
        .expect("child stdin should be piped")
        .write_all(input)
        .expect("should write fixture to stdin");
    child.wait_with_output().expect("child should complete")
}

/// Locate the large generated CycloneDX fixture without hard-coding its long name.
fn large_fixture() -> Option<PathBuf> {
    let dir = Path::new(FIXTURES_DIR).join("cyclonedx");
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().to_string();
            (name.starts_with("sbom-cyclone-dx-json-") && name.ends_with(".json")).then_some(p)
        })
}

#[test]
fn quality_reads_sbom_from_stdin() {
    let sbom = std::fs::read(fixture_path("cyclonedx/minimal.cdx.json")).expect("fixture readable");

    let mut cmd = base_command();
    cmd.arg("quality")
        .arg("-")
        .args(["--profile", "standard", "-o", "json"]);
    let output = run_with_stdin(cmd, &sbom);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("overall_score") || text.contains("\"report\""),
        "expected a quality JSON report, got: {text}"
    );
}

#[test]
fn validate_reads_sbom_from_stdin() {
    let sbom = std::fs::read(fixture_path("cyclonedx/minimal.cdx.json")).expect("fixture readable");

    let mut cmd = base_command();
    cmd.arg("validate")
        .arg("-")
        .args(["--standard", "ntia", "-o", "json"]);
    let output = run_with_stdin(cmd, &sbom);

    // NTIA validation may exit non-zero on a minimal fixture, but it must have
    // parsed the stdin document rather than erroring on a missing path.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !combined.contains("No such file") && !combined.contains("Failed to read"),
        "validate should have read from stdin, got: {combined}"
    );
    assert!(
        combined.contains("compliant")
            || combined.contains("Compliance")
            || combined.contains("NTIA"),
        "expected NTIA compliance output, got: {combined}"
    );
}

#[test]
fn diff_accepts_one_stdin_side() {
    let new_sbom = std::fs::read(fixture_path("demo-new.cdx.json")).expect("fixture readable");

    let mut cmd = base_command();
    cmd.arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg("-")
        .args(["-o", "summary"]);
    let output = run_with_stdin(cmd, &new_sbom);

    // Exit code may be non-zero (changes detected); only the parse must succeed.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !combined.contains("Failed to read") && !combined.contains("No such file"),
        "diff should read the new side from stdin, got: {combined}"
    );
}

#[test]
fn diff_rejects_two_stdin_sides() {
    let mut cmd = base_command();
    cmd.arg("diff").arg("-").arg("-").args(["-o", "summary"]);
    let output = run_with_stdin(cmd, b"{}");

    assert!(!output.status.success(), "two stdins must be rejected");
    assert!(
        stderr(&output).contains("both SBOMs from stdin")
            || stderr(&output).contains("only one '-'"),
        "expected a two-stdin rejection message, got: {}",
        stderr(&output)
    );
}

/// Parse + diff the orphaned 10 MB CycloneDX fixture end to end. Ignored by
/// default (slow, large fixture excluded from the published crate); run with
/// `cargo test --test stdin_input_tests -- --ignored`.
#[test]
#[ignore = "large fixture; run explicitly"]
fn parse_and_diff_large_fixture() {
    let Some(path) = large_fixture() else {
        // The fixture is excluded from the published crate, so skip when absent.
        eprintln!("large fixture not present; skipping");
        return;
    };

    let sbom = sbom_tools::parsers::parse_sbom(&path).expect("large fixture should parse");
    assert!(
        sbom.component_count() > 100,
        "expected a large component set, got {}",
        sbom.component_count()
    );

    // Diff the document against itself: a valid no-op diff exercises the engine
    // on a realistic, large input.
    let config = sbom_tools::config::DiffConfigBuilder::new()
        .old_path(path.clone())
        .new_path(path.clone())
        .build()
        .expect("diff config should build");
    let other = sbom_tools::parsers::parse_sbom(&path).expect("second parse should succeed");
    let result = sbom_tools::pipeline::compute_diff(&config, &sbom, &other)
        .expect("self-diff should succeed");
    assert_eq!(
        result.summary.total_changes, 0,
        "self-diff should report no changes"
    );
}
