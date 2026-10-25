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
    // ntia-warnings-only.cdx.json has 0 NTIA errors but dependency-coverage
    // warnings (sparse graph), so --fail-on-warning must exit with code 2.
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["--standard", "ntia", "--summary", "--fail-on-warning"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn validate_without_fail_on_warning_returns_exit_code_0_when_warnings_only() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
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

// ---------------------------------------------------------------------------
// Typed --standard / --profile parsing (P2-D CLI & config coherence)
// ---------------------------------------------------------------------------

/// Every canonical `--standard` value must be enumerated in `validate --help`
/// (clap generates the list from the ValueEnum, so this guards the wiring).
#[test]
fn validate_help_enumerates_every_canonical_standard() {
    let output = base_command()
        .args(["validate", "--help"])
        .output()
        .expect("validate --help should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let help = stdout(&output);
    for canonical in [
        "ntia",
        "fda",
        "cra",
        "cra-phase1",
        "ssdf",
        "eo14028",
        "cnsa2",
        "pqc",
        "bsi",
        "oss-steward",
        "eucc",
        "ai-act",
        "bsi-ai",
        "cisa-2026",
        "pci-dss",
        "fsct",
    ] {
        assert!(
            help.contains(canonical),
            "validate --help must list standard '{canonical}':\n{help}"
        );
    }
}

/// Every canonical `--profile` value must be enumerated in `quality --help`.
#[test]
fn quality_help_enumerates_every_canonical_profile() {
    let output = base_command()
        .args(["quality", "--help"])
        .output()
        .expect("quality --help should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let help = stdout(&output);
    for canonical in [
        "minimal",
        "standard",
        "security",
        "license-compliance",
        "cra",
        "bsi",
        "comprehensive",
        "cbom",
        "ai-readiness",
    ] {
        assert!(
            help.contains(canonical),
            "quality --help must list profile '{canonical}':\n{help}"
        );
    }
}

#[test]
fn invalid_standard_is_rejected_at_parse_with_possible_values() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "not-a-standard"])
        .output()
        .expect("validate command should run");

    // clap exits with code 2 on argument parse errors.
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-standard'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list valid standards: {err}"
    );
}

#[test]
fn invalid_profile_is_rejected_at_parse_with_possible_values() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "not-a-profile"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-profile'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list valid profiles: {err}"
    );
}

/// CraPhase1 is reachable from the CLI: `--standard cra-phase1` selects the
/// Phase 1 (2026) profile, while plain `cra` keeps meaning Phase 2 (2027).
#[test]
fn validate_standard_cra_phase1_is_reachable_and_cra_means_phase2() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra-phase1,cra", "--summary"])
        .output()
        .expect("validate command should run");

    // Exit code depends on the fixture's compliance; only the parse/report
    // wiring is asserted here.
    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    let standards: Vec<String> = json
        .as_array()
        .expect("multi-standard summary array")
        .iter()
        .map(|s| s["standard"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        standards.iter().any(|s| s.contains("Phase 1")),
        "cra-phase1 must select the Phase 1 profile: {standards:?}"
    );
    assert!(
        standards.iter().any(|s| s.contains("Phase 2")),
        "plain cra must keep meaning Phase 2: {standards:?}"
    );
}

/// Alias spellings and case-insensitivity work end-to-end through clap.
#[test]
fn validate_standard_aliases_parse_through_clap() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "NIST-SSDF,cra-2026,Tr03183", "--summary"])
        .output()
        .expect("validate command should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert_eq!(
        json.as_array().map(Vec::len),
        Some(3),
        "three aliased standards must produce three results: {json}"
    );
}

/// Regression: the pre-typed hand parser split on ',' and trimmed, so quoted
/// lists with spaces (`--standard "ntia, cra"`) parsed. The typed parser must
/// keep accepting them instead of exiting 2 (which the documented contract
/// reads as "warnings found").
#[test]
fn validate_standard_list_with_spaces_after_commas_parses() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "ntia, cra", "--summary"])
        .output()
        .expect("validate command should run");

    let err = stderr(&output);
    assert_ne!(
        output.status.code(),
        Some(2),
        "'ntia, cra' must not be a usage error: {err}"
    );
    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    let standards: Vec<String> = json
        .as_array()
        .expect("multi-standard summary array")
        .iter()
        .map(|s| s["standard"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(standards.len(), 2, "both standards must run: {standards:?}");
    assert!(
        standards.iter().any(|s| s.contains("NTIA")) && standards.iter().any(|s| s.contains("CRA")),
        "expected NTIA + CRA results: {standards:?}"
    );
}

// ---------------------------------------------------------------------------
// --summary overrides --output (documented), so the format gate is skipped
// ---------------------------------------------------------------------------

#[test]
fn validate_summary_overrides_unsupported_output_format() {
    // `--summary` is documented as "(overrides --output)"; a stray `-o html`
    // must not hard-error and the compact JSON summary must be emitted.
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "ntia", "--summary", "-o", "html"])
        .output()
        .expect("validate command should run");

    let err = stderr(&output);
    assert!(
        !err.contains("not supported by"),
        "--summary must skip the format gate: {err}"
    );
    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert!(
        json["standard"].is_string(),
        "expected the compact summary JSON: {json}"
    );
}

// ---------------------------------------------------------------------------
// Typo'd --cra-product-class is a hard error at every accepting command
// ---------------------------------------------------------------------------

fn assert_rejects_typod_product_class(output: &Output, command: &str) {
    assert!(
        !output.status.success(),
        "{command}: a typo'd --cra-product-class must be a hard error"
    );
    let err = stderr(output);
    assert!(
        err.contains("critcal"),
        "{command}: error must name the bad value: {err}"
    );
    for valid in [
        "default",
        "important-class-1",
        "important-class-2",
        "critical",
    ] {
        assert!(
            err.contains(valid),
            "{command}: error must list '{valid}': {err}"
        );
    }
}

#[test]
fn validate_rejects_typod_cra_product_class() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra", "--cra-product-class", "critcal"])
        .arg("--summary")
        .output()
        .expect("validate command should run");
    assert_rejects_typod_product_class(&output, "validate");
}

#[test]
fn quality_rejects_typod_cra_product_class() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "cra", "--cra-product-class", "critcal"])
        .output()
        .expect("quality command should run");
    assert_rejects_typod_product_class(&output, "quality");
}

#[test]
fn view_rejects_typod_cra_product_class() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json", "--cra-product-class", "critcal"])
        .output()
        .expect("view command should run");
    assert_rejects_typod_product_class(&output, "view");
}

#[test]
fn cra_docs_rejects_typod_cra_product_class() {
    let dir = tempfile::tempdir().expect("temp dir");
    let output = base_command()
        .arg("cra-docs")
        .arg(fixture_path("demo-new.cdx.json"))
        .arg("--output")
        .arg(dir.path().join("dossier"))
        .args(["--cra-product-class", "critcal"])
        .output()
        .expect("cra-docs command should run");
    assert_rejects_typod_product_class(&output, "cra-docs");
}

#[test]
fn validate_accepts_valid_cra_product_class() {
    // Accepting case for the strict parser: a canonical spelling still runs
    // (exit code reflects compliance, not a parse failure).
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra", "--cra-product-class", "critical"])
        .arg("--summary")
        .output()
        .expect("validate command should run");

    let err = stderr(&output);
    assert!(
        !err.contains("Invalid product class"),
        "valid class must parse: {err}"
    );
    serde_json::from_str::<serde_json::Value>(stdout(&output).trim())
        .expect("summary should be JSON");
}

// ---------------------------------------------------------------------------
// quality gates are N/A-aware and its compliance clock is pinnable
// ---------------------------------------------------------------------------

#[test]
fn quality_fail_on_noncompliant_exits_0_on_na_ai_readiness_run() {
    // Regression: an N/A AI-readiness run (non-ML SBOM) used to exit 1 on a
    // hidden Comprehensive-level check that no renderer displays.
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "ai-readiness", "--fail-on-noncompliant"])
        .output()
        .expect("quality command should run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "N/A run must not trip --fail-on-noncompliant; stderr:\n{}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("N/A"),
        "the rendered report should say N/A: {}",
        stdout(&output)
    );
}

#[test]
fn quality_accepts_as_of_like_validate() {
    // `quality --as-of` pins the embedded compliance clock (parity with
    // validate); the offset-less spelling is taken as UTC.
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "cra", "--as-of", "2027-01-01T00:00:00"])
        .output()
        .expect("quality command should run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "quality --as-of must parse and run; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn quality_rejects_invalid_as_of_with_a_clear_error() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "cra", "--as-of", "not-a-date"])
        .output()
        .expect("quality command should run");

    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains("invalid --as-of") && err.contains("RFC 3339"),
        "error must explain the accepted forms: {err}"
    );
}

// ---------------------------------------------------------------------------
// Unsupported (command, format) combinations are rejected, not substituted
// ---------------------------------------------------------------------------

#[test]
fn diff_rejects_oscal_json_output() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("diff command should run");

    assert!(
        !output.status.success(),
        "diff -o oscal-json must fail instead of emitting plain JSON"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools diff`"),
        "stderr should name the unsupported combination: {err}"
    );
}

#[test]
fn view_rejects_oscal_json_output() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("view command should run");

    assert!(
        !output.status.success(),
        "view -o oscal-json must fail instead of emitting plain JSON"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools view`"),
        "stderr should name the unsupported combination: {err}"
    );
}

#[test]
fn validate_rejects_html_output_and_lists_supported_formats() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "ntia", "-o", "html"])
        .output()
        .expect("validate command should run");

    assert!(
        !output.status.success(),
        "validate -o html must fail instead of silently emitting text"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools validate`"),
        "stderr should name the unsupported combination: {err}"
    );
    assert!(
        err.contains("oscal-json"),
        "stderr should list the formats validate does support: {err}"
    );
}

#[test]
fn quality_rejects_oscal_json_output() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("quality command should run");

    assert!(
        !output.status.success(),
        "quality -o oscal-json must fail instead of silently emitting text"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools quality`"),
        "stderr should name the unsupported combination: {err}"
    );
}

// ---------------------------------------------------------------------------
// Explicit --cra-sidecar failures are hard errors; sidecar typos are named
// ---------------------------------------------------------------------------

#[test]
fn quality_explicit_missing_sidecar_is_hard_error() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args([
            "--profile",
            "cra",
            "--cra-sidecar",
            "/nonexistent/side.cra.json",
        ])
        .output()
        .expect("quality command should run");

    assert!(
        !output.status.success(),
        "an explicitly passed broken sidecar must abort quality"
    );
    assert!(
        stderr(&output).contains("Failed to load CRA sidecar"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn view_explicit_missing_sidecar_is_hard_error() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json", "--cra-sidecar", "/nonexistent/side.cra.json"])
        .output()
        .expect("view command should run");

    assert!(
        !output.status.success(),
        "an explicitly passed broken sidecar must abort view"
    );
    assert!(
        stderr(&output).contains("Failed to load CRA sidecar"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn validate_sidecar_with_snake_case_typo_names_key_and_hints_camel_case() {
    let dir = tempfile::tempdir().expect("temp dir");
    let sidecar = dir.path().join("typo.cra.json");
    std::fs::write(&sidecar, r#"{"security_contact": "security@example.com"}"#)
        .expect("write sidecar");

    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra", "--summary"])
        .arg("--cra-sidecar")
        .arg(&sidecar)
        .output()
        .expect("validate command should run");

    assert!(
        !output.status.success(),
        "a typo'd sidecar key must fail loudly instead of deserializing to all-None"
    );
    let err = stderr(&output);
    assert!(
        err.contains("security_contact"),
        "error must name the offending key: {err}"
    );
    assert!(
        err.contains("camelCase"),
        "error must hint at camelCase keys: {err}"
    );
}

/// `--no-color` must suppress ANSI escapes in EVERY colored format.
///
/// The side-by-side reporter honoured its own `no_colors()` builder, but the
/// reporter factory never called it for this format, so redirected/CI-captured
/// side-by-side output was polluted with escape sequences.
#[test]
fn side_by_side_honours_no_color_flag() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "side-by-side"])
        .output()
        .expect("diff command should run");

    let rendered = stdout(&output);
    // Guard against a vacuous pass: the report must actually have rendered.
    assert!(
        rendered.contains("lodash"),
        "expected side-by-side content, got:\n{rendered}\n{}",
        stderr(&output)
    );
    assert!(
        !rendered.contains('\u{1b}'),
        "--no-color must suppress ANSI escapes in side-by-side output:\n{}",
        stderr(&output)
    );
}

/// The `NO_COLOR` convention is honoured for side-by-side too (the flag and
/// the environment variable resolve through the same helper).
#[test]
fn side_by_side_honours_no_color_env() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.env("RUST_LOG", "error");
    cmd.env("NO_COLOR", "1");
    let output = cmd
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "side-by-side"])
        .output()
        .expect("diff command should run");

    let rendered = stdout(&output);
    assert!(
        rendered.contains("lodash"),
        "expected side-by-side content, got:\n{rendered}\n{}",
        stderr(&output)
    );
    assert!(
        !rendered.contains('\u{1b}'),
        "NO_COLOR=1 must suppress ANSI escapes in side-by-side output:\n{}",
        stderr(&output)
    );
}

/// `-o sbomqs-json` is a `quality` renderer. `diff` and `view` used to accept
/// it and silently emit ordinary JSON — the caller asked for one format and
/// got another, the same defect the `oscal-json` guard beside it prevents.
#[test]
fn sbomqs_json_is_rejected_by_diff_and_view() {
    let old = fixture_path("demo-old.cdx.json");
    let new = fixture_path("demo-new.cdx.json");

    let diff = base_command()
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .args(["-o", "sbomqs-json"])
        .output()
        .expect("diff should run");
    assert!(
        !diff.status.success(),
        "diff must reject sbomqs-json instead of emitting diff JSON: {}",
        stdout(&diff)
    );
    assert!(
        stderr(&diff).contains("quality -o sbomqs-json"),
        "the error should point at the command that renders it: {}",
        stderr(&diff)
    );

    let view = base_command()
        .arg("view")
        .arg(&new)
        .args(["-o", "sbomqs-json"])
        .output()
        .expect("view should run");
    assert!(
        !view.status.success(),
        "view must reject sbomqs-json: {}",
        stdout(&view)
    );
}

/// An empty `NO_COLOR=` means "not set" per the convention. Reports treated
/// it as set and stripped color while logs and the TUI kept it, so a single
/// invocation disagreed with itself.
#[test]
fn empty_no_color_env_is_treated_as_unset() {
    // Colour also requires a TTY, which the test harness does not provide, so
    // assert on the resolver rather than on rendered bytes.
    unsafe { std::env::set_var("NO_COLOR", "") };
    let empty = sbom_tools::pipeline::should_use_color(false);
    unsafe { std::env::set_var("NO_COLOR", "1") };
    let set = sbom_tools::pipeline::should_use_color(false);
    unsafe { std::env::remove_var("NO_COLOR") };
    let unset = sbom_tools::pipeline::should_use_color(false);

    assert_eq!(
        empty, unset,
        "an empty NO_COLOR= must behave exactly like an unset one"
    );
    assert!(!set, "a non-empty NO_COLOR must disable colour");
}

// ---------------------------------------------------------------------------
// Untrusted SBOM text in line-oriented output (review S1)
// ---------------------------------------------------------------------------

/// A component name built to forge a GitHub Actions annotation, plus an ANSI
/// colour sequence, a bell and a right-to-left override.
const HOSTILE_NAME: &str =
    "lib\\n::error file=src/main.rs,line=1::FORGED\\u001b[31m\\u0007\\u202ered";

fn write_hostile_sbom(dir: &Path, file: &str, with_hostile: bool) -> PathBuf {
    let extra = if with_hostile {
        format!(r#",{{"type":"library","name":"{HOSTILE_NAME}"}}"#)
    } else {
        String::new()
    };
    let json = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
        "metadata":{{"timestamp":"2026-01-01T00:00:00Z","authors":[{{"name":"Example"}}]}},
        "components":[{{"type":"library","name":"base","version":"1.0.0",
        "purl":"pkg:npm/base@1.0.0","supplier":{{"name":"Example"}}}}{extra}]}}"#
    );
    let path = dir.join(file);
    std::fs::write(&path, json).expect("write fixture");
    path
}

fn assert_no_injected_lines(text: &str) {
    for line in text.lines() {
        assert!(
            !line.trim_start().starts_with("::"),
            "a line starts a workflow command: {line:?}\n---\n{text}"
        );
    }
    for (needle, what) in [('\u{1b}', "ESC"), ('\u{7}', "BEL"), ('\u{202E}', "RLO")] {
        assert!(!text.contains(needle), "{what} reached the output:\n{text}");
    }
}

/// The default `validate` text output used to print element and message
/// verbatim, so a newline in a component name produced a line that GitHub
/// Actions renders as an `::error` annotation.
#[test]
fn validate_text_output_cannot_forge_ci_annotations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sbom = write_hostile_sbom(dir.path(), "hostile.cdx.json", true);

    let output = base_command()
        .arg("validate")
        .arg(&sbom)
        .args(["--standard", "ntia"])
        .output()
        .expect("validate should run");
    let text = stdout(&output);

    assert!(
        text.contains("lib\\n::error"),
        "the hostile name must still be visible, escaped:\n{text}"
    );
    assert_no_injected_lines(&text);

    // JSON output keeps the exact value (serde escapes it).
    let json_out = base_command()
        .arg("validate")
        .arg(&sbom)
        .args(["--standard", "ntia", "-o", "json"])
        .output()
        .expect("validate -o json should run");
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&json_out)).expect("validate -o json is JSON");
    assert!(
        value.to_string().contains("::error file=src/main.rs"),
        "JSON must carry the original text: {value}"
    );
}

/// The `diff` table report sanitized names but kept their newlines.
#[test]
fn diff_table_output_cannot_forge_ci_annotations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let old = write_hostile_sbom(dir.path(), "old.cdx.json", false);
    let new = write_hostile_sbom(dir.path(), "new.cdx.json", true);

    let output = base_command()
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .args(["-o", "table"])
        .output()
        .expect("diff should run");
    let text = stdout(&output);

    assert!(
        text.contains("lib\\n::error"),
        "the added component must be listed, escaped:\n{text}"
    );
    assert_no_injected_lines(&text);
}
