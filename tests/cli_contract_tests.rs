//! CLI contract tests: per-command exit codes, typed value-enum parse
//! validation, NDJSON output wiring, and the `validate -o json` envelope.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

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

// ---------------------------------------------------------------------------
// Usage errors exit 3 in every command; --help and --version exit 0
// ---------------------------------------------------------------------------

fn run(args: &[&str]) -> Output {
    base_command()
        .args(args)
        .output()
        .expect("sbom-tools should run")
}

fn fixture_arg(name: &str) -> String {
    fixture_path(name)
        .to_str()
        .expect("fixture paths are UTF-8")
        .to_string()
}

fn assert_usage_error(args: &[&str], output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(3),
        "{args:?} must be a usage error (exit 3): {}",
        stderr(output)
    );
    assert!(stdout(output).is_empty(), "{args:?} wrote to stdout");
    assert!(
        stderr(output).starts_with("error:") || stderr(output).contains("Usage:"),
        "{args:?} must keep clap's message: {}",
        stderr(output)
    );
}

/// Exit 2 used to mean both "warnings found" and "clap rejected the command
/// line", so a pipeline that tolerated warnings also passed a mistyped
/// standard.
#[test]
fn mistyped_standard_or_flag_value_exits_3_in_validate_and_diff() {
    let new = fixture_arg("demo-new.cdx.json");
    let old = fixture_arg("demo-old.cdx.json");
    let (new, old) = (new.as_str(), old.as_str());
    let cases = [
        vec!["validate", new, "--standard", "ntai"],
        vec!["validate", new, "--standard", "ntai", "--fail-on-warning"],
        vec!["validate", new, "--standard", "ntia,cra-phase3"],
        vec!["validate", new, "--json-schema", "v3"],
        // `diff` takes no --standard, so passing one is an unknown argument.
        vec!["diff", old, new, "--standard", "ntia"],
        vec!["diff", old, new, "--fuzzy-preset", "balancd"],
        vec!["diff", old, new, "--graph-impact-threshold", "hgh"],
    ];
    for args in &cases {
        assert_usage_error(args, &run(args));
    }
}

#[test]
fn unknown_flag_exits_3_in_every_command() {
    let sbom = fixture_arg("demo-new.cdx.json");
    let sbom = sbom.as_str();
    let commands = [
        vec![],
        vec!["validate", sbom],
        vec!["diff", sbom, sbom],
        vec!["view", sbom],
        vec!["quality", sbom],
        vec!["query", "lodash", sbom],
        vec!["diff-multi", sbom, sbom],
        vec!["timeline", sbom, sbom],
        vec!["matrix", sbom, sbom],
        vec!["license-check", sbom],
        vec!["vex", "status", sbom],
        vec!["verify", "hash", sbom],
        vec!["merge", sbom, sbom],
        vec!["convert", sbom, "--to", "spdx"],
        vec!["tailor", sbom],
        vec!["cra-docs", sbom],
        vec!["cra-standards-watch"],
        vec!["rules"],
        vec!["rules", "explain", "SBOM-CRA-ART-24"],
        vec!["watch", "--dir", "."],
        vec!["config", "show"],
        vec!["config-schema"],
        vec!["completions", "bash"],
        vec!["man"],
    ];
    for command in commands {
        let mut args = command;
        args.push("--no-such-flag");
        let output = run(&args);
        assert_usage_error(&args, &output);
        assert!(
            stderr(&output).contains("unexpected argument '--no-such-flag'"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn help_and_version_exit_0_on_stdout() {
    for args in [
        vec!["--help"],
        vec!["-h"],
        vec!["--version"],
        vec!["-V"],
        vec!["help"],
        vec!["help", "validate"],
        vec!["validate", "--help"],
        vec!["diff", "-h"],
        vec!["vex", "help", "status"],
        vec!["rules", "explain", "-h"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            !stdout(&output).trim().is_empty(),
            "{args:?} printed nothing"
        );
        assert!(stderr(&output).is_empty(), "{args:?}: {}", stderr(&output));
    }
}

/// Help printed because a required argument or subcommand is missing is a
/// usage error, not a help request.
#[test]
fn missing_arguments_exit_3_even_when_clap_prints_help() {
    let old = fixture_arg("demo-old.cdx.json");
    for args in [
        vec![],
        vec!["vex"],
        vec!["verify"],
        vec!["validate"],
        vec!["diff", old.as_str()],
        vec!["query"],
        vec!["rules", "explain"],
    ] {
        assert_usage_error(&args, &run(&args));
    }
    // With no argument at all (not even the `--no-color` every other run
    // passes), clap prints the full help, to stderr, and it still fails.
    let bare = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .output()
        .expect("sbom-tools should run");
    assert_usage_error(&[], &bare);
    assert!(
        stderr(&bare).contains("Commands:"),
        "a bare invocation still shows the help: {}",
        stderr(&bare)
    );
}

// ---------------------------------------------------------------------------
// validate --require-applicable
// ---------------------------------------------------------------------------

#[test]
fn require_applicable_makes_a_not_applicable_standard_exit_1() {
    // demo-new has no ML components, so both AI readiness profiles are N/A.
    let plain = fixture_arg("demo-new.cdx.json");
    let plain = plain.as_str();
    for standard in ["ai-act", "bsi-ai"] {
        let args = ["validate", plain, "--standard", standard, "--summary"];
        let without = run(&args);
        assert_eq!(
            without.status.code(),
            Some(0),
            "{standard}: N/A exits 0 by default: {}",
            stderr(&without)
        );
        let json: Value = serde_json::from_str(stdout(&without).trim()).expect("summary JSON");
        assert_eq!(
            json["applicable"], false,
            "{standard} must be N/A for this fixture: {json}"
        );

        let with = run(&[&args[..], &["--require-applicable"][..]].concat());
        assert_eq!(
            with.status.code(),
            Some(1),
            "{standard}: N/A is non-compliant under --require-applicable: {}",
            stderr(&with)
        );
        assert_eq!(
            stdout(&with),
            stdout(&without),
            "the flag changes the exit code, not the report"
        );
    }

    // With several standards, one N/A standard is enough; ntia alone only
    // has warnings here, so it passes without --fail-on-warning.
    let warnings_only = fixture_arg("cyclonedx/ntia-warnings-only.cdx.json");
    let warnings_only = warnings_only.as_str();
    let both = [
        "validate",
        warnings_only,
        "--standard",
        "ntia,ai-act",
        "--summary",
    ];
    assert_eq!(run(&both).status.code(), Some(0));
    assert_eq!(
        run(&[&both[..], &["--require-applicable"][..]].concat())
            .status
            .code(),
        Some(1)
    );
    // An applicable standard is unaffected by the flag.
    let ntia = [
        "validate",
        warnings_only,
        "--standard",
        "ntia",
        "--require-applicable",
    ];
    assert_eq!(run(&ntia).status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// validate -o json: envelope v2 and --json-schema v1
// ---------------------------------------------------------------------------

/// Pinned evaluation instant, so every run sees the same deadlines.
const AS_OF: &str = "2026-10-12T00:00:00Z";

const CANONICAL_STANDARDS: [&str; 16] = [
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
];

fn compliance_schema() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/compliance/v2.schema.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("schema readable"))
        .expect("schema is JSON")
}

/// `stdout` of a `validate -o json` run, validated against the published
/// schema and against a strict copy that rejects undeclared fields.
fn validated_envelope(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "{args:?} must complete a validation: {}",
        stderr(&output)
    );
    let json: Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|e| panic!("{args:?}: stdout is not JSON: {e}"));
    let schema = compliance_schema();
    for (kind, schema) in [
        ("schema", schema.clone()),
        ("strict schema", json_schema::strict_copy(&schema)),
    ] {
        if let Err(errors) = json_schema::validate(&schema, &json) {
            panic!("{args:?} violates the {kind}:\n{}", errors.join("\n"));
        }
    }
    json
}

fn standards_of(json: &Value) -> Vec<String> {
    json["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["standard"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn validate_json_is_one_schema_valid_envelope_for_every_standard() {
    let plain = fixture_arg("demo-new.cdx.json");
    for standard in CANONICAL_STANDARDS {
        let json = validated_envelope(&[
            "validate",
            plain.as_str(),
            "--standard",
            standard,
            "-o",
            "json",
            "--as-of",
            AS_OF,
        ]);
        assert_eq!(json["schema"], "sbom-tools/compliance/v2");
        assert_eq!(standards_of(&json), [standard], "{standard}");
    }

    let all = CANONICAL_STANDARDS.join(",");
    for fixture in [
        "demo-new.cdx.json",
        "cyclonedx/aibom-complete.cdx.json",
        "cyclonedx/cbom-1.7.cdx.json",
        "spdx/minimal.spdx.json",
        // Auto-discovers a sidecar that pins a product class, so the CRA
        // results carry `conformity_summary`.
        "cra/cra-compliant.cdx.json",
    ] {
        let path = fixture_arg(fixture);
        let json = validated_envelope(&[
            "validate",
            path.as_str(),
            "--standard",
            all.as_str(),
            "-o",
            "json",
            "--as-of",
            AS_OF,
        ]);
        assert_eq!(standards_of(&json), CANONICAL_STANDARDS, "{fixture}");
        if fixture.starts_with("cra/") {
            assert!(
                json["results"][2]["conformity_summary"].is_object(),
                "{fixture}: cra must carry the conformity summary"
            );
        }
    }

    // SBOM text with line breaks and control characters stays valid JSON.
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, hostile) = write_hostile_pair(dir.path());
    let hostile = hostile.to_str().expect("utf-8");
    validated_envelope(&[
        "validate",
        hostile,
        "--standard",
        all.as_str(),
        "-o",
        "json",
    ]);
}

/// `--json-schema v1` prints exactly what `validate -o json` printed before
/// v0.4: the bare result for one standard, a bare array for several.
#[test]
fn json_schema_v1_keeps_the_pre_0_4_shape() {
    use sbom_tools::quality::{ComplianceChecker, ComplianceResult, StandardSelector};

    let path = fixture_path("demo-new.cdx.json");
    let raw = std::fs::read_to_string(&path).expect("fixture readable");
    let sbom = sbom_tools::parse_sbom_str(&raw).expect("fixture parses");
    let as_of = chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid instant")
        .with_timezone(&chrono::Utc);
    let check = |standard: &str| -> ComplianceResult {
        let level = standard
            .parse::<StandardSelector>()
            .expect("known standard")
            .level();
        ComplianceChecker::new(level).with_as_of(as_of).check(&sbom)
    };
    let path = path.to_str().expect("utf-8");
    let v1 = |standards: &str| {
        run(&[
            "validate",
            path,
            "--standard",
            standards,
            "-o",
            "json",
            "--json-schema",
            "v1",
            "--as-of",
            AS_OF,
        ])
    };

    let single = v1("ntia");
    assert_eq!(single.status.code(), Some(1), "{}", stderr(&single));
    assert_eq!(
        stdout(&single),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&check("ntia")).expect("serializes")
        )
    );

    let multi = v1("ntia,ai-act");
    assert_eq!(
        stdout(&multi),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&[check("ntia"), check("ai-act")]).expect("serializes")
        )
    );

    // The v1 layout predates passed checks: they simply stop appearing
    // there (they used to be Info violations), and no `passed` field joins.
    // Nor does `evaluated`, the checks a standard did not evaluate (PQC's
    // federal TLS check, outside deadline mode).
    let cbom = fixture_path("cyclonedx/cbom-quantum-ready.cdx.json");
    let cbom_raw = std::fs::read_to_string(&cbom).expect("fixture readable");
    let cbom_sbom = sbom_tools::parse_sbom_str(&cbom_raw).expect("fixture parses");
    let mut pqc = ComplianceChecker::new(StandardSelector::Pqc.level())
        .with_as_of(as_of)
        .check(&cbom_sbom);
    assert!(!pqc.passed.is_empty(), "the fixture passes PQC checks");
    assert!(!pqc.evaluated.is_empty(), "PQC skips its federal TLS check");
    pqc.passed.clear();
    pqc.evaluated.clear();
    let cbom = cbom.to_str().expect("utf-8");
    let pqc_v1 = run(&[
        "validate",
        cbom,
        "--standard",
        "pqc",
        "-o",
        "json",
        "--json-schema",
        "v1",
        "--as-of",
        AS_OF,
    ]);
    assert_eq!(
        stdout(&pqc_v1),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&pqc).expect("serializes")
        )
    );
    let json: Value = serde_json::from_str(&stdout(&pqc_v1)).expect("v1 is JSON");
    assert!(json.get("passed").is_none(), "{json}");
    assert!(json.get("evaluated").is_none(), "{json}");
    assert_eq!(json["info_count"], 0, "{json}");

    // The deprecation note goes to stderr, never into the JSON.
    let noisy = base_command()
        .env("RUST_LOG", "warn")
        .args([
            "validate",
            path,
            "--standard",
            "ntia",
            "-o",
            "json",
            "--json-schema",
            "v1",
            "--as-of",
            AS_OF,
        ])
        .output()
        .expect("validate should run");
    assert!(
        stderr(&noisy).contains("--json-schema v1 is deprecated"),
        "{}",
        stderr(&noisy)
    );
    assert_eq!(stdout(&noisy), stdout(&single));
}

/// A pass is no finding: `-o sarif` reports none by default, and
/// `--sarif-include-passes` reports each as a `kind: "pass"` result at level
/// `none`. cbom-quantum-ready passes eight NIST PQC checks and has no Info.
#[test]
fn sarif_reports_passes_only_on_request() {
    let path = fixture_arg("cyclonedx/cbom-quantum-ready.cdx.json");
    let sarif = |extra: &[&str]| -> Value {
        let mut args = vec![
            "validate",
            path.as_str(),
            "--standard",
            "pqc",
            "-o",
            "sarif",
            "--as-of",
            AS_OF,
        ];
        args.extend_from_slice(extra);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        serde_json::from_str(&stdout(&output)).expect("SARIF is JSON")
    };
    let results = |sarif: &Value| -> Vec<Value> {
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .clone()
    };

    let plain = sarif(&[]);
    assert!(
        results(&plain).is_empty(),
        "no SARIF result may describe a pass: {plain}"
    );

    let with_passes = sarif(&["--sarif-include-passes"]);
    let passes = results(&with_passes);
    assert_eq!(passes.len(), 8, "{with_passes}");
    for pass in &passes {
        assert_eq!(pass["kind"], "pass", "{pass}");
        assert_eq!(pass["level"], "none", "{pass}");
        assert_eq!(pass["ruleId"], "SBOM-PQC-009", "{pass}");
    }

    // The JSON envelope agrees: 0 Info, 8 passed.
    let json = validated_envelope(&[
        "validate",
        path.as_str(),
        "--standard",
        "pqc",
        "-o",
        "json",
        "--as-of",
        AS_OF,
    ]);
    let entry = &json["results"][0];
    assert_eq!(entry["counts"]["info"], 0, "{entry}");
    assert_eq!(entry["counts"]["passed"], 8, "{entry}");
    assert_eq!(entry["passed"].as_array().map(Vec::len), Some(8), "{entry}");
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

    // Argument parse errors are usage errors: exit 3, never a gate code.
    assert_eq!(output.status.code(), Some(3), "{}", stdout(&output));
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

    assert_eq!(output.status.code(), Some(3), "{}", stdout(&output));
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

    // A usage error, not the warnings gate (2) a pipeline may tolerate.
    assert_eq!(output.status.code(), Some(3), "{}", stdout(&output));
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

    assert_eq!(output.status.code(), Some(3), "{}", stdout(&output));
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
/// keep accepting them instead of failing with a usage error.
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
        Some(3),
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
fn diff_rejects_typod_cra_product_class() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json", "--cra-product-class", "critcal"])
        .output()
        .expect("diff command should run");
    assert_rejects_typod_product_class(&output, "diff");
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

/// Every compliance-checking command takes `validate`'s `--as-of` (one
/// shared definition and parser): `view` and `diff` (and their TUIs) and
/// `cra-docs` pin the clock of their compliance checks with it.
#[test]
fn every_compliance_command_parses_as_of_like_validate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let old = fixture_arg("demo-old.cdx.json");
    let new = fixture_arg("demo-new.cdx.json");
    let dossier = dir.path().join("dossier");
    let dossier = dossier.to_str().expect("UTF-8 temp path");
    let commands: [&[&str]; 4] = [
        &["validate", &new, "--standard", "cra", "--summary"],
        &["view", &new, "-o", "json"],
        &["diff", &old, &new, "-o", "json"],
        &["cra-docs", &new, "--output", dossier, "--force"],
    ];
    for args in commands {
        let ok = base_command()
            .args(args)
            .args(["--as-of", "2027-01-01"])
            .output()
            .expect("command should run");
        assert_ne!(
            ok.status.code(),
            Some(3),
            "{}: --as-of 2027-01-01 must parse; stderr:\n{}",
            args[0],
            stderr(&ok)
        );
        let bad = base_command()
            .args(args)
            .args(["--as-of", "not-a-date"])
            .output()
            .expect("command should run");
        assert_eq!(bad.status.code(), Some(3), "{}", args[0]);
        let err = stderr(&bad);
        assert!(
            err.contains("invalid --as-of") && err.contains("RFC 3339"),
            "{}: error must explain the accepted forms: {err}",
            args[0]
        );
    }
}

/// `--standard cra,cra-phase2` names CRA Phase 2 twice: it is checked once,
/// with a warning on stderr naming the repeat.
#[test]
fn validate_checks_a_twice_selected_standard_once() {
    let output = base_command()
        .env("RUST_LOG", "warn")
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra,cra-phase2", "--summary"])
        .output()
        .expect("validate command should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert!(
        json.is_object(),
        "one standard checked, one summary object: {json}"
    );
    let err = stderr(&output);
    assert!(
        err.contains("standard cra") && err.contains("selected more than once"),
        "the dropped repeat must be named on stderr: {err}"
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

/// A value a check read is SBOM text: `-o json` carries it as read, like the
/// message and the element, and the text report neutralizes it.
#[test]
fn observed_values_are_raw_in_json_and_neutralized_in_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A component whose bom-ref is its name reads as missing a bom-ref, and
    // the finding observes the bom-ref.
    let crafted = "::warning::forged\u{1b}[31m\u{7}\nx";
    let document = serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z", "authors": [{"name": "Example"}]},
        "components": [{"type": "library", "bom-ref": crafted, "name": crafted,
                        "version": "1.0.0", "purl": "pkg:npm/x@1.0.0",
                        "supplier": {"name": "Example"}}]
    });
    let sbom = dir.path().join("crafted.cdx.json");
    std::fs::write(&sbom, document.to_string()).expect("write fixture");
    let validate = |extra: &[&str]| {
        base_command()
            .arg("validate")
            .arg(&sbom)
            .args(["--standard", "ntia", "--as-of", AS_OF])
            .args(extra)
            .output()
            .expect("validate should run")
    };

    let json: Value = serde_json::from_str(&stdout(&validate(&["-o", "json"])))
        .expect("validate -o json is JSON");
    let observed: Vec<&str> = json["results"][0]["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .filter(|v| v["rule_id"] == "SBOM-NTIA-ELEMENT-ID")
        .filter_map(|v| v["observed"].as_str())
        .collect();
    assert_eq!(observed, [crafted], "{json}");

    let text = stdout(&validate(&[]));
    assert!(
        text.contains("\n  observed: \"\\::warning::forged[31m\\nx\" in bom-ref\n"),
        "{text}"
    );
    assert_no_injected_lines(&text);
}

/// Two SBOMs whose names, versions, suppliers, licenses and vulnerability IDs
/// try every way SBOM text can break out of its field: a line break followed
/// by a workflow command, a value that starts with one (a field printed first
/// on a line needs no line break, since the runner trims blanks), ANSI, BEL
/// and bidi controls, and a multi-byte name long enough to be truncated.
fn write_hostile_pair(dir: &Path) -> (PathBuf, PathBuf) {
    use serde_json::json;
    let nl = "lib\n::error file=src/main.rs,line=1::FORGED";
    let ls = "::warning::FORGED at line start";
    let cc = "\u{1b}[31mred\u{1b}[0m\u{7}\u{202E}rlo";
    let long = "é".repeat(80);
    let doc = |suffix: &str, added: bool| {
        let mut components = vec![
            json!({"type": "library", "bom-ref": "c-nl", "name": nl,
                   "version": format!("1.0{suffix}"), "purl": format!("pkg:npm/nl@1.0{suffix}"),
                   "supplier": {"name": nl}, "licenses": [{"expression": "MIT"}],
                   "description": nl}),
            json!({"type": "library", "bom-ref": "c-ls", "name": ls, "version": ls,
                   "supplier": {"name": ls}, "licenses": [{"license": {"name": ls}}]}),
            json!({"type": "library", "bom-ref": "c-cc", "name": cc,
                   "version": format!("2.0{suffix}"), "supplier": {"name": cc},
                   "licenses": [{"license": {"name": cc}}]}),
            json!({"type": "library", "bom-ref": "c-long", "name": long,
                   "version": format!("3.0{suffix}")}),
        ];
        if added {
            components.push(json!({"type": "library", "bom-ref": "c-new",
                                   "name": format!("{ls} added"), "version": nl}));
        }
        json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "metadata": {"timestamp": "2026-01-01T00:00:00Z",
                            "component": {"type": "application", "bom-ref": "root",
                                          "name": ls, "version": nl},
                            "authors": [{"name": nl}]},
               "components": components,
               "dependencies": [{"ref": "root", "dependsOn": ["c-nl", "c-ls", "c-cc", "c-long"]}],
               "vulnerabilities": [
                   {"id": format!("CVE-2026-0001{suffix}"), "bom-ref": "v1", "description": nl,
                    "ratings": [{"severity": "high"}], "affects": [{"ref": "c-nl"}],
                    "analysis": {"state": "not_affected", "justification": "code_not_reachable",
                                 "detail": nl}},
                   {"id": ls, "bom-ref": "v2", "ratings": [{"severity": "low"}],
                    "affects": [{"ref": "c-ls"}]}]})
    };
    let write = |file: &str, value: serde_json::Value| {
        let path = dir.join(file);
        std::fs::write(&path, value.to_string()).expect("write fixture");
        path
    };
    (
        write("old.cdx.json", doc("", false)),
        write("new.cdx.json", doc(".1", true)),
    )
}

/// No line of `text` may start a workflow command built from the fixture's
/// text, and no control or bidi character may survive (a CRLF line ending is
/// allowed).
fn assert_neutralized(label: &str, stream: &str, text: &str) {
    for line in text.split(['\n', '\r']) {
        assert!(
            !(line.trim_start().starts_with("::") && line.contains("FORGED")),
            "{label} ({stream}): a line starts a workflow command: {line:?}"
        );
    }
    let bad: Vec<String> = text
        .replace("\r\n", "\n")
        .chars()
        .filter(|&c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    assert!(
        bad.is_empty(),
        "{label} ({stream}): {bad:?} reached the output"
    );
}

/// Every human-readable output neutralizes SBOM text: summary, table,
/// side-by-side, Markdown, CSV and HTML reports, every `validate` standard,
/// `quality`, `query`, `license-check` and `vex`. JSON-family formats are
/// exempt: serde escapes control characters, and a JSON line cannot start
/// with `::`. `RUST_LOG=info` (the default level) also covers stderr logs.
#[test]
fn every_text_output_neutralizes_sbom_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (old, new) = write_hostile_pair(dir.path());
    let (old, new) = (old.to_str().expect("utf-8"), new.to_str().expect("utf-8"));

    let mut runs: Vec<Vec<&str>> = Vec::new();
    for standard in [
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
        runs.push(vec!["validate", new, "--standard", standard]);
    }
    for format in [
        "summary",
        "table",
        "side-by-side",
        "markdown",
        "csv",
        "html",
    ] {
        runs.push(vec!["diff", old, new, "-o", format]);
        runs.push(vec!["view", new, "-o", format]);
    }
    runs.push(vec!["view", new, "--validate-ntia", "-o", "summary"]);
    runs.push(vec!["quality", new]);
    runs.push(vec!["quality", new, "--profile", "cbom"]);
    for format in ["summary", "table", "csv"] {
        runs.push(vec!["query", "FORGED", old, new, "-o", format]);
    }
    runs.push(vec!["license-check", new]);
    runs.push(vec!["vex", "status", new]);
    runs.push(vec!["vex", "filter", new]);

    for args in &runs {
        let label = args
            .iter()
            .map(|a| {
                if a.ends_with(".cdx.json") {
                    "<sbom>"
                } else {
                    a
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let output = base_command()
            .env("RUST_LOG", "info")
            .args(args)
            .output()
            .expect("command should run");
        let code = output.status.code();
        assert!(
            !matches!(code, None | Some(3 | 101)),
            "{label}: exit {code:?}\n{}",
            stderr(&output)
        );
        let out = stdout(&output);
        assert!(!out.trim().is_empty(), "{label}: printed nothing");
        assert_neutralized(&label, "stdout", &out);
        assert_neutralized(&label, "stderr", &stderr(&output));
        // The remediation line under each finding goes through the same
        // sanitizer; it must be present for every finding. A standard that
        // does not apply (the AI profiles on this SBOM) reports none.
        if args[0] == "validate" && out.contains("Status: NOT APPLICABLE") {
            assert!(
                out.contains("No violations found."),
                "{label}: an N/A standard reports no finding:\n{out}"
            );
        } else if args[0] == "validate" {
            assert_fix_line_per_finding(&label, &out, &["[ERROR] ", "[WARN] ", "[INFO] "], 2);
        } else if args.contains(&"--validate-ntia") {
            assert_fix_line_per_finding(&label, &out, &["  - "], 1);
        }
    }
}

/// Every finding line (one starting with a `markers` prefix) is followed,
/// `offset` lines later, by a non-empty `fix:` line with its remediation.
/// The finding's `observed:` and `deadline:` lines, when it has them, come
/// before the `fix:` line and do not count toward the offset.
fn assert_fix_line_per_finding(label: &str, text: &str, markers: &[&str], offset: usize) {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            !(line.starts_with("observed: ") || line.starts_with("deadline: "))
        })
        .collect();
    let findings: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| markers.iter().any(|m| line.starts_with(m)))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !findings.is_empty(),
        "{label}: no findings printed:\n{text}"
    );
    for i in findings {
        let fix = lines.get(i + offset).map_or("", |l| l.trim_start());
        assert!(
            fix.strip_prefix("fix: ")
                .is_some_and(|r| !r.trim().is_empty()),
            "{label}: finding {:?} has no fix line (got {fix:?})",
            lines[i]
        );
    }
}

/// `validate` gives every violation a remediation in JSON and a `fix:` line
/// in text, phrased for the input format: SPDX documents get SPDX field
/// paths, never CycloneDX ones.
#[test]
fn validate_remediation_follows_the_input_format() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (rel, standard, expected) in [
        (
            "spdx/minimal.spdx.json",
            "ntia",
            "SPDX 2.x: set packages[].supplier",
        ),
        (
            "spdx3/minimal.spdx3.json",
            "bsi",
            "SPDX 3.0: add a hasDeclaredLicense",
        ),
    ] {
        let sbom = fixtures.join(rel);
        let text = stdout(
            &base_command()
                .arg("validate")
                .arg(&sbom)
                .args(["--standard", standard])
                .output()
                .expect("validate should run"),
        );
        assert_fix_line_per_finding(rel, &text, &["[ERROR] ", "[WARN] ", "[INFO] "], 2);
        assert!(
            text.contains(expected),
            "{rel}: expected {expected:?}:\n{text}"
        );
        for cyclonedx_field in ["components[]", "metadata.component", "externalReferences"] {
            assert!(
                !text.contains(cyclonedx_field),
                "{rel}: CycloneDX field {cyclonedx_field:?} in SPDX remediation:\n{text}"
            );
        }

        let json: serde_json::Value = serde_json::from_str(&stdout(
            &base_command()
                .arg("validate")
                .arg(&sbom)
                .args(["--standard", standard, "-o", "json"])
                .output()
                .expect("validate -o json should run"),
        ))
        .expect("validate -o json is JSON");
        let violations = json["results"][0]["violations"]
            .as_array()
            .expect("violations array in the v2 envelope");
        assert!(!violations.is_empty(), "{rel}: expected violations");
        for v in violations {
            assert!(
                v["remediation"].as_str().is_some_and(|r| !r.is_empty()),
                "{rel}: violation without remediation: {v}"
            );
        }
    }
}

/// `validate` text names the rule of each finding, so it matches the SARIF
/// alert and the JSON entry, and lists the checks the standard did not
/// evaluate, with the reason.
#[test]
fn validate_text_names_rules_and_lists_checks_not_evaluated() {
    let sbom = fixture_path("spdx/minimal.spdx.json");
    let text = stdout(
        &base_command()
            .arg("validate")
            .arg(&sbom)
            .args(["--standard", "cisa-2026", "--as-of", AS_OF])
            .output()
            .expect("validate should run"),
    );
    let findings: Vec<&str> = text
        .lines()
        .filter(|l| {
            ["[ERROR] ", "[WARN] ", "[INFO] "]
                .iter()
                .any(|m| l.starts_with(m))
        })
        .collect();
    assert!(!findings.is_empty(), "{text}");
    for line in findings {
        let rule = line
            .split(" | ")
            .next()
            .and_then(|head| head.split_once("] "))
            .map(|(_, rule)| rule);
        assert!(
            rule.is_some_and(|r| r.starts_with("SBOM-CISA2026-")),
            "the finding line names no rule: {line:?}"
        );
    }
    assert!(
        text.contains(
            "\nNot evaluated:\n  SBOM-CISA2026-SIGNATURE: SPDX 2.x cannot carry a document \
             signature\n"
        ),
        "{text}"
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
