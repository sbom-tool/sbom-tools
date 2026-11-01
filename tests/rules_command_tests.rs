//! `sbom-tools rules` and `sbom-tools rules explain`: the rule catalogue on
//! the command line. Output formats, `--standard` aliases, the
//! `sbom-tools/rules/v1` JSON against its schema, and the exit-code contract
//! (an unknown rule id or standard is a usage error, exit 3).

#[path = "common/json_schema.rs"]
mod json_schema;

use sbom_tools::quality::{
    ComplianceLevel, all_rule_ids, generic_rule_id_for_level, rules_for_level,
};
use serde_json::Value;
use std::process::{Command, Output};

const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/rules/v1.schema.json");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .arg("--no-color")
        .args(args)
        .env("RUST_LOG", "error")
        .env("RUST_LOG_STYLE", "never")
        .output()
        .expect("sbom-tools should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// Run `args`, which must succeed with output on stdout only.
fn success(args: &[&str]) -> String {
    let output = run(args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{args:?}: {}",
        stderr(&output)
    );
    assert!(stderr(&output).is_empty(), "{args:?}: {}", stderr(&output));
    let out = stdout(&output);
    assert!(!out.trim().is_empty(), "{args:?} printed nothing");
    out
}

/// Run `args`, which must be a usage error: exit 3, nothing on stdout, and
/// clap's message on stderr.
fn usage_error(args: &[&str]) -> String {
    let output = run(args);
    assert_eq!(
        output.status.code(),
        Some(3),
        "{args:?} must exit 3: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty(), "{args:?} wrote to stdout");
    let err = stderr(&output);
    assert!(err.starts_with("error:"), "{args:?}: {err}");
    err
}

fn schema() -> Value {
    let text = std::fs::read_to_string(SCHEMA_PATH).expect("schema readable");
    serde_json::from_str(&text).expect("schema is JSON")
}

/// Parse `json` and validate it against the published schema and its strict
/// copy.
fn valid_document(json: &str, label: &str) -> Value {
    let document: Value = serde_json::from_str(json).expect("rules -o json is JSON");
    let schema = schema();
    for (name, schema) in [
        ("schema", schema.clone()),
        ("strict", json_schema::strict_copy(&schema)),
    ] {
        if let Err(errors) = json_schema::validate(&schema, &document) {
            panic!("{label} ({name}): {}", errors.join("\n"));
        }
    }
    assert_eq!(document["schema"], "sbom-tools/rules/v1", "{label}");
    document
}

fn ids(document: &Value) -> Vec<String> {
    document["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().expect("rule id").to_string())
        .collect()
}

#[test]
fn rules_lists_every_registered_rule() {
    let document = valid_document(&success(&["rules", "-o", "json"]), "rules -o json");
    assert_eq!(ids(&document), all_rule_ids());

    let text = success(&["rules"]);
    assert!(
        text.starts_with(&format!(
            "Compliance rules: every rule in the registry ({})\n",
            all_rule_ids().len()
        )),
        "{text}"
    );
    for id in all_rule_ids() {
        assert!(
            text.contains(&format!("\n{id} · ")),
            "text output lacks {id}"
        );
    }
}

/// `--standard` takes the names and aliases `validate --standard` takes,
/// comma-separated or repeated, and lists those standards' rules in their
/// SARIF order, then their fallback rules.
#[test]
fn rules_for_a_standard_follow_its_list_whatever_the_spelling() {
    let bsi = valid_document(
        &success(&["rules", "--standard", "bsi", "-o", "json"]),
        "rules --standard bsi",
    );
    let mut expected: Vec<&str> = rules_for_level(ComplianceLevel::BsiTr03183_2).to_vec();
    expected.push(generic_rule_id_for_level(ComplianceLevel::BsiTr03183_2));
    assert_eq!(ids(&bsi), expected);
    for alias in ["tr-03183", "TR03183", "bsi-tr-03183-2"] {
        assert_eq!(
            success(&["rules", "--standard", alias, "-o", "json"]),
            success(&["rules", "--standard", "bsi", "-o", "json"]),
            "{alias}"
        );
    }

    let both = success(&["rules", "--standard", "cra-art24,cra", "-o", "json"]);
    assert_eq!(
        both,
        success(&[
            "rules",
            "--standard",
            "oss-steward",
            "--standard",
            "cra-phase2",
            "-o",
            "json"
        ])
    );
    let both = valid_document(&both, "rules --standard cra-art24,cra");
    let ids = ids(&both);
    assert_eq!(
        ids.first().map(String::as_str),
        rules_for_level(ComplianceLevel::CraOssSteward)
            .first()
            .copied()
    );
    assert_eq!(ids.last().map(String::as_str), Some("SBOM-CRA-GENERAL"));
    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "a rule two standards share appears once"
    );
}

#[test]
fn rules_markdown_is_one_table_row_per_rule() {
    let markdown = success(&["rules", "--standard", "eucc", "-o", "markdown"]);
    assert!(markdown.starts_with("# Compliance rules\n"), "{markdown}");
    assert!(
        markdown.contains(
            "| Rule | Name | Default severity | Standards | References | Remediation |\n|---|---|---|---|---|---|\n"
        ),
        "{markdown}"
    );
    let rows = markdown
        .lines()
        .filter(|line| line.starts_with("| `SBOM-"))
        .count();
    assert_eq!(
        rows,
        rules_for_level(ComplianceLevel::EuccSubstantial).len() + 1
    );
}

#[test]
fn explain_shows_one_rule_in_full() {
    let text = success(&["rules", "explain", "SBOM-CRA-ART-24"]);
    for expected in [
        "SBOM-CRA-ART-24 · CraStewardVulnerabilityHandling\n",
        "Default severity: Error\n",
        "Standards:\n  oss-steward  CRA OSS Steward (Art. 24)\n",
        "References:\n  CRA Art. 24 <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>\n",
        "\nRemediation:\n  Show the open-source steward's vulnerability-handling process",
        "\nWhere the fix goes:\n  CycloneDX: ",
        "  SPDX 2.x: ",
        "  SPDX 3.0: ",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }

    // The id is case-insensitive; JSON is the catalogue document with one rule.
    let document = valid_document(
        &success(&["rules", "explain", "sbom-cra-art-24", "-o", "json"]),
        "rules explain -o json",
    );
    assert_eq!(ids(&document), ["SBOM-CRA-ART-24"]);
    assert_eq!(document["rules"][0]["standards"][0], "oss-steward");
    assert_eq!(
        document["rules"][0]["references"][0]["help_uri"],
        "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng"
    );

    let markdown = success(&["rules", "explain", "SBOM-CRA-ART-24", "-o", "markdown"]);
    assert!(
        markdown.starts_with("## `SBOM-CRA-ART-24` CraStewardVulnerabilityHandling\n"),
        "{markdown}"
    );
}

/// An unknown rule id or standard, or a standard given with `explain`, is a
/// usage error under the exit-code contract.
#[test]
fn unknown_rule_ids_and_standards_are_usage_errors() {
    let err = usage_error(&["rules", "explain", "SBOM-CRA-ART-25"]);
    assert!(
        err.contains("invalid value 'SBOM-CRA-ART-25' for '<RULE_ID>'"),
        "{err}"
    );
    assert!(err.contains("did you mean SBOM-CRA-ART-24?"), "{err}");
    assert!(
        err.contains("`sbom-tools rules` lists every rule id"),
        "{err}"
    );

    let err = usage_error(&["rules", "explain", "not-a-rule-at-all-xyz"]);
    assert!(!err.contains("did you mean"), "{err}");

    let err = usage_error(&["rules", "--standard", "ntai"]);
    assert!(err.contains("[possible values: ntia,"), "{err}");

    usage_error(&["rules", "--standard", "bsi", "explain", "SBOM-CRA-ART-24"]);
    usage_error(&["rules", "explain"]);
    usage_error(&["rules", "-o", "yaml"]);
    usage_error(&["rules", "explain", "SBOM-CRA-ART-24", "--no-such-flag"]);
}

/// `rules` reads no configuration, so a broken config file cannot block it.
#[test]
fn a_broken_config_file_does_not_block_rules() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("broken.yaml");
    std::fs::write(&config, "compliance: [this is not: valid").expect("write config");
    let config = config.to_str().expect("UTF-8 path");
    success(&["--config", config, "rules", "--standard", "ntia"]);
    success(&["--config", config, "rules", "explain", "SBOM-NTIA-AUTHOR"]);
}

#[test]
fn help_documents_the_command() {
    let help = success(&["rules", "--help"]);
    for expected in [
        "sbom-tools/rules/v1",
        "schemas/rules/v1.schema.json",
        "3  Usage error (unknown flag, standard or rule id, missing argument)",
        "--standard <STANDARD>",
        "- markdown:",
    ] {
        assert!(help.contains(expected), "missing {expected:?} in:\n{help}");
    }
    let explain = success(&["rules", "explain", "--help"]);
    assert!(explain.contains("<RULE_ID>"), "{explain}");
    let root = success(&["--help"]);
    assert!(
        root.contains("rules ") && root.contains("sbom-tools rules --standard cra"),
        "{root}"
    );
}
