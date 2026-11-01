//! The CLI-parity calls of the C ABI: `sbom_tools_validate_json`,
//! `sbom_tools_score_sbom_with_options_json` and
//! `sbom_tools_rule_catalog_json`.
//!
//! The parity tests run the CLI binary on the same inputs and compare
//! bytes: the validate envelope must be exactly what `validate - -o json`
//! writes, the score report what `quality - -o json` writes, and the
//! catalogue what `rules -o json` prints, so the ABI cannot drift from the
//! command line. The SBOM reaches the CLI on standard input, as it reaches
//! the ABI: as content, with no file name (`file_name` cases pass the file).

mod common;

#[path = "common/json_schema.rs"]
mod json_schema;

use common::ffi_helpers::{consume_result, into_c_string};
use sbom_tools::ffi::{
    SbomToolsErrorCode, sbom_tools_rule_catalog_json, sbom_tools_score_sbom_with_options_json,
    sbom_tools_validate_json,
};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).expect("fixture readable")
}

type AbiResult = Result<String, (SbomToolsErrorCode, String)>;

fn validate(sbom: &str, options: &Value) -> AbiResult {
    let sbom = into_c_string(sbom);
    let options = into_c_string(&options.to_string());
    consume_result(sbom_tools_validate_json(sbom.as_ptr(), options.as_ptr()))
}

fn rule_catalog(filter: &Value) -> AbiResult {
    let filter = into_c_string(&filter.to_string());
    consume_result(sbom_tools_rule_catalog_json(filter.as_ptr()))
}

fn score(sbom: &str, options: &Value) -> AbiResult {
    let sbom = into_c_string(sbom);
    let options = into_c_string(&options.to_string());
    consume_result(sbom_tools_score_sbom_with_options_json(
        sbom.as_ptr(),
        options.as_ptr(),
    ))
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("the ABI returns JSON")
}

/// Run the CLI with `args`, ignoring any config file, piping `stdin` in.
fn cli(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(["--no-color", "--no-config"])
        .args(args)
        .env("RUST_LOG", "error")
        .env("RUST_LOG_STYLE", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin)
        .expect("the SBOM is written to stdin");
    child.wait_with_output().expect("the CLI finishes")
}

/// What `validate - <flags> -o json` writes for the SBOM `name`, read from
/// standard input, as bytes. `-O` writes the envelope exactly; stdout would
/// add a newline.
fn cli_validate(name: &str, flags: &[&str]) -> String {
    let dir = tempfile::tempdir().expect("temporary directory");
    let out = dir.path().join("envelope.json");
    let out_arg = out.to_string_lossy().into_owned();
    let mut args = vec!["validate", "-"];
    args.extend_from_slice(flags);
    args.extend_from_slice(&["-o", "json", "-O", &out_arg]);
    let output = cli(&args, fixture(name).as_bytes());
    // 0, 1 and 2 are verdicts; 3 is a usage error.
    assert!(
        matches!(output.status.code(), Some(0..=2)),
        "validate {flags:?} failed on {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(&out).expect("validate wrote the envelope")
}

/// One input set: an SBOM, the CLI flags, and the same inputs as ABI
/// options.
struct Case {
    sbom: &'static str,
    flags: Vec<&'static str>,
    options: Value,
}

fn sidecar(name: &str) -> Value {
    json(&fixture(name))
}

fn parity_cases() -> Vec<Case> {
    vec![
        // The default standard (ntia).
        Case {
            sbom: "cyclonedx/minimal.cdx.json",
            flags: vec!["--as-of", "2027-01-01"],
            options: json!({"as_of": "2027-01-01"}),
        },
        // A sidecar (inline for the ABI) and both CRA phases.
        Case {
            sbom: "cra/cra-compliant.cdx.json",
            flags: vec![
                "--standard",
                "cra,cra-phase1,eucc,ai-act",
                "--cra-sidecar",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/cra/cra-compliant.cra.json"
                ),
                "--as-of",
                "2027-12-11T00:00:00Z",
            ],
            options: json!({
                "standards": ["cra", "cra-phase1", "eucc", "ai-act"],
                "sidecar": sidecar("cra/cra-compliant.cra.json"),
                "as_of": "2027-12-11T00:00:00Z",
            }),
        },
        // Aliases, a level named twice, a product class and rule settings.
        Case {
            sbom: "demo-new.cdx.json",
            flags: vec![
                "--standard",
                "NTIA,cra-phase2,cra,bsi-tr-03183-2,fda",
                "--cra-product-class",
                "important-class-1",
                "--rule",
                "SBOM-NTIA-SUPPLIER=warning",
                "--rule",
                "sbom-ntia-version=off",
                "--as-of",
                "2026-12-01T08:30:00",
            ],
            options: json!({
                "standards": ["NTIA", "cra-phase2", "cra", "bsi-tr-03183-2", "fda"],
                "product_class": "important-class-1",
                "rules": {"SBOM-NTIA-SUPPLIER": "warning", "sbom-ntia-version": "off"},
                "as_of": "2026-12-01T08:30:00",
            }),
        },
        // PQC deadline mode with a profile and a CNSA 2.0 category.
        Case {
            sbom: "cyclonedx/cbom-pqc-calendar.cdx.json",
            flags: vec![
                "--standard",
                "pqc,cnsa2",
                "--pqc-mode",
                "deadline",
                "--pqc-profile",
                "federal",
                "--cnsa-category",
                "networking",
                "--as-of",
                "2031-06-01",
            ],
            options: json!({
                "standards": ["pqc", "cnsa2"],
                "pqc_mode": "deadline",
                "pqc_profile": "federal",
                "cnsa_category": "networking",
                "as_of": "2031-06-01",
            }),
        },
        // Components whose scope is excluded, judged too.
        Case {
            sbom: "cyclonedx/scope-excluded.cdx.json",
            flags: vec![
                "--standard",
                "ntia,cisa-2026,pci-dss",
                "--include-excluded-scope",
                "--as-of",
                "2026-11-01",
            ],
            options: json!({
                "standards": ["ntia", "cisa-2026", "pci-dss"],
                "include_excluded_scope": true,
                "as_of": "2026-11-01",
            }),
        },
        // SPDX 2.3, SPDX 3 and CycloneDX XML documents.
        Case {
            sbom: "spdx/minimal.spdx.json",
            flags: vec!["--standard", "fsct,eo14028,ssdf", "--as-of", "2026-11-01"],
            options: json!({"standards": ["fsct", "eo14028", "ssdf"], "as_of": "2026-11-01"}),
        },
        Case {
            sbom: "spdx3/security-profile.spdx3.json",
            flags: vec!["--standard", "cisa-2026,cra", "--as-of", "2026-11-01"],
            options: json!({"standards": ["cisa-2026", "cra"], "as_of": "2026-11-01"}),
        },
        Case {
            sbom: "cra/bsi-compliant.cdx.xml",
            flags: vec!["--standard", "bsi,oss-steward", "--as-of", "2026-11-01"],
            options: json!({"standards": ["bsi", "oss-steward"], "as_of": "2026-11-01"}),
        },
    ]
}

/// The envelope the ABI returns is, byte for byte, the one
/// `validate - -o json` writes for the same SBOM and inputs.
#[test]
fn validate_is_byte_identical_to_the_cli() {
    for case in parity_cases() {
        let sbom = fixture(case.sbom);
        let abi = validate(&sbom, &case.options)
            .unwrap_or_else(|e| panic!("{}: validate failed: {e:?}", case.sbom));
        let cli = cli_validate(case.sbom, &case.flags);
        assert_eq!(
            abi, cli,
            "{} {:?}: the ABI envelope and `validate -o json` diverged",
            case.sbom, case.flags
        );
    }
}

/// With `file_name`, the envelope is the one `validate <FILE> -o json`
/// writes: its subject names the file, without its directory.
#[test]
fn validate_names_the_file_as_the_cli_does() {
    let name = "cyclonedx/minimal.cdx.json";
    let path = fixture_path(name);
    let dir = tempfile::tempdir().expect("temporary directory");
    let out = dir.path().join("envelope.json");
    let output = cli(
        &[
            "validate",
            &path.to_string_lossy(),
            "--as-of",
            "2027-01-01",
            "-o",
            "json",
            "-O",
            &out.to_string_lossy(),
        ],
        b"",
    );
    assert!(
        matches!(output.status.code(), Some(0..=2)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli = std::fs::read_to_string(&out).expect("validate wrote the envelope");
    for file_name in [
        path.to_string_lossy().into_owned(),
        "minimal.cdx.json".to_string(),
    ] {
        let abi = validate(
            &fixture(name),
            &json!({"file_name": file_name, "as_of": "2027-01-01"}),
        )
        .expect("validates");
        assert_eq!(abi, cli, "file_name {file_name}");
    }
    assert_eq!(json(&cli)["subject"]["file_name"], "minimal.cdx.json");
}

/// The subject's digest is over the exact bytes passed in, and without
/// `as_of` the envelope states the instant the call judged at, to the
/// second.
#[test]
fn validate_states_the_bytes_and_the_instant_it_judged() {
    use sha2::{Digest, Sha256};
    let content = fixture("cyclonedx/minimal.cdx.json");
    // The same document with other bytes is another subject.
    let reformatted = format!("{content}\n\n");
    for bytes in [&content, &reformatted] {
        let before = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
        let envelope = json(&validate(bytes, &json!({})).expect("validates"));
        let after = chrono::Utc::now();
        let digest: String = Sha256::digest(bytes.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(envelope["subject"]["sha256"], digest.as_str());
        assert!(envelope["subject"].get("file_name").is_none(), "{envelope}");
        let as_of = envelope["as_of"].as_str().expect("as_of");
        let judged = chrono::DateTime::parse_from_rfc3339(as_of)
            .expect("RFC 3339")
            .with_timezone(&chrono::Utc);
        assert!(before <= judged && judged <= after, "{as_of}");
        assert!(!as_of.contains('.'), "to the second: {as_of}");
    }
}

/// A key whose value is `null` counts as not given.
#[test]
fn null_options_are_not_given() {
    let sbom = fixture("cyclonedx/minimal.cdx.json");
    let plain = validate(&sbom, &json!({"as_of": "2027-01-01"})).expect("validates");
    let nulls = validate(
        &sbom,
        &json!({
            "as_of": "2027-01-01",
            "standards": null,
            "file_name": null,
            "sidecar": null,
            "product_class": null,
            "pqc_mode": null,
            "pqc_profile": null,
            "cnsa_category": null,
            "rules": null,
            "include_excluded_scope": null,
        }),
    )
    .expect("validates");
    assert_eq!(plain, nulls);
}

/// The envelope matches the published schema and its strict copy.
#[test]
fn validate_output_matches_the_v2_schema() {
    let schema: Value = json(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/compliance/v2.schema.json"
        ))
        .expect("schema readable"),
    );
    let strict = json_schema::strict_copy(&schema);
    for case in parity_cases() {
        let envelope = json(&validate(&fixture(case.sbom), &case.options).expect("validates"));
        for schema in [&schema, &strict] {
            if let Err(errors) = json_schema::validate(schema, &envelope) {
                panic!("{}: {}", case.sbom, errors.join("\n"));
            }
        }
    }
}

fn expect_invalid(options: &Value, needle: &str) {
    let sbom = fixture("cyclonedx/minimal.cdx.json");
    let (code, message) = validate(&sbom, options).expect_err("the options are invalid");
    assert_eq!(code, SbomToolsErrorCode::Validation, "{options}: {message}");
    assert!(
        message.contains(needle),
        "{options}: expected {needle:?} in {message:?}"
    );
}

/// Every value the CLI rejects is a validation error, as is an unknown key
/// or a value of the wrong type.
#[test]
fn invalid_options_are_validation_errors() {
    let cases: &[(Value, &str)] = &[
        (json!({"standard": ["ntia"]}), "unknown option `standard`"),
        (
            json!({"standard": ["ntia"]}),
            "valid options: standards, file_name, as_of",
        ),
        (json!({"profile": "standard"}), "unknown option `profile`"),
        (
            json!({"file_name": 7}),
            "`file_name` in options_json must be a string",
        ),
        (json!(["ntia"]), "must be a JSON object"),
        (
            json!({"standards": "ntia"}),
            "`standards` in options_json must be an array of strings",
        ),
        (
            json!({"standards": ["ntia", 3]}),
            "must be an array of strings",
        ),
        (
            json!({"standards": ["ntai"]}),
            "unknown compliance standard 'ntai'",
        ),
        (json!({"standards": []}), "no compliance standard selected"),
        (
            json!({"as_of": 20270101}),
            "`as_of` in options_json must be a string",
        ),
        (
            json!({"as_of": "01/01/2027"}),
            "invalid as_of \"01/01/2027\": expected an RFC 3339",
        ),
        (
            json!({"product_class": "important"}),
            "invalid product_class: Invalid product class",
        ),
        (
            json!({"pqc_mode": "strict"}),
            "invalid pqc_mode \"strict\"; valid values: readiness, deadline",
        ),
        (
            json!({"pqc_profile": "federal"}),
            "apply only with `pqc_mode` \"deadline\"",
        ),
        (
            json!({"pqc_mode": "readiness", "cnsa_category": "niche"}),
            "apply only with `pqc_mode` \"deadline\"",
        ),
        (
            json!({"rules": ["SBOM-NTIA-SUPPLIER=off"]}),
            "`rules` in options_json must be a JSON object",
        ),
        (
            json!({"rules": {"SBOM-NTIA-SUPLIER": "off"}}),
            "did you mean SBOM-NTIA-SUPPLIER?",
        ),
        (
            json!({"rules": {"SBOM-NTIA-SUPPLIER": "warn"}}),
            "invalid rule setting 'warn'",
        ),
        (
            json!({"rules": {"SBOM-NTIA-SUPPLIER": 2}}),
            "the setting must be a string",
        ),
        (json!({"rules": {"SBOM-PQC-009": "error"}}), "passed checks"),
        (
            json!({"rules": {"SBOM-NTIA-SUPPLIER": "off", "sbom-ntia-supplier": "info"}}),
            "rules names SBOM-NTIA-SUPPLIER twice",
        ),
        (
            json!({"include_excluded_scope": "yes"}),
            "must be true or false",
        ),
        (
            json!({"sidecar": "app.cra.json"}),
            "must be a JSON object (a CRA sidecar's keys)",
        ),
        (
            json!({"sidecar": {"security_contact": "security@example.com"}}),
            "invalid sidecar: unknown field `security_contact`",
        ),
    ];
    for (options, needle) in cases {
        expect_invalid(options, needle);
    }

    let sbom = into_c_string(&fixture("cyclonedx/minimal.cdx.json"));
    for text in ["{", "", "null"] {
        let options = into_c_string(text);
        let (code, message) =
            consume_result(sbom_tools_validate_json(sbom.as_ptr(), options.as_ptr()))
                .expect_err("not an options object");
        assert_eq!(code, SbomToolsErrorCode::Validation, "{text:?}: {message}");
    }
}

#[test]
fn null_pointers_and_unparseable_sboms_fail() {
    let options = into_c_string("{}");
    let (code, message) =
        consume_result(sbom_tools_validate_json(std::ptr::null(), options.as_ptr()))
            .expect_err("null sbom");
    assert_eq!(code, SbomToolsErrorCode::Validation);
    assert!(
        message.contains("sbom pointer must not be null"),
        "{message}"
    );

    let sbom = into_c_string(&fixture("cyclonedx/minimal.cdx.json"));
    let (code, message) = consume_result(sbom_tools_validate_json(sbom.as_ptr(), std::ptr::null()))
        .expect_err("null options");
    assert_eq!(code, SbomToolsErrorCode::Validation);
    assert!(message.contains("options_json"), "{message}");

    let (code, _) =
        consume_result(sbom_tools_rule_catalog_json(std::ptr::null())).expect_err("null filter");
    assert_eq!(code, SbomToolsErrorCode::Validation);

    let (code, _) = validate("this is not an SBOM", &json!({})).expect_err("no SBOM");
    assert_eq!(code, SbomToolsErrorCode::Unsupported);
    let (code, _) = validate(
        r#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": 7}"#,
        &json!({}),
    )
    .expect_err("broken CycloneDX");
    assert_ne!(code, SbomToolsErrorCode::Ok);
}

/// The catalogue is, byte for byte, what `rules -o json` prints, without
/// its final newline: every rule, or the rules of the standards named.
#[test]
fn rule_catalog_is_byte_identical_to_the_cli() {
    let cases: &[(Value, &[&str])] = &[
        (json!({}), &[]),
        (json!({"standards": null}), &[]),
        (json!({"standards": []}), &[]),
        (
            json!({"standards": ["cra", "NTIA", "cra-phase2", "ai-act"]}),
            &["--standard", "cra,NTIA,cra-phase2,ai-act"],
        ),
        (json!({"standards": ["pqc"]}), &["--standard", "pqc"]),
    ];
    for (filter, flags) in cases {
        let abi = rule_catalog(filter).unwrap_or_else(|e| panic!("{filter}: {e:?}"));
        let mut args = vec!["rules"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["-o", "json"]);
        let output = cli(&args, b"");
        assert!(output.status.success(), "rules {flags:?} failed");
        let cli = String::from_utf8(output.stdout).expect("UTF-8 output");
        assert_eq!(
            format!("{abi}\n"),
            cli,
            "{filter}: the ABI catalogue and `rules -o json` diverged"
        );
    }
}

#[test]
fn rule_catalog_rejects_bad_filters() {
    for (filter, needle) in [
        (json!({"standard": ["cra"]}), "unknown option `standard`"),
        (json!({"standards": "cra"}), "must be an array of strings"),
        (
            json!({"standards": ["crab"]}),
            "unknown compliance standard 'crab'",
        ),
        (json!({"as_of": "2027-01-01"}), "valid options: standards"),
    ] {
        let (code, message) = rule_catalog(&filter).expect_err("bad filter");
        assert_eq!(code, SbomToolsErrorCode::Validation, "{filter}");
        assert!(message.contains(needle), "{filter}: {message}");
    }
}

/// What `quality <SBOM> <flags> -o json` writes, as bytes. With `-` as the
/// SBOM, `name` is read from standard input; `-O` writes the document
/// exactly, where stdout would add a newline.
fn cli_quality(sbom: &str, name: &str, flags: &[&str]) -> String {
    let dir = tempfile::tempdir().expect("temporary directory");
    let out = dir.path().join("quality.json");
    let out_arg = out.to_string_lossy().into_owned();
    let mut args = vec!["quality", sbom];
    args.extend_from_slice(flags);
    args.extend_from_slice(&["-o", "json", "-O", &out_arg]);
    let output = cli(&args, fixture(name).as_bytes());
    assert!(
        output.status.success(),
        "quality {flags:?} failed on {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(&out).expect("quality wrote the report")
}

fn score_parity_cases() -> Vec<Case> {
    vec![
        // The default profile (standard).
        Case {
            sbom: "demo-new.cdx.json",
            flags: vec!["--as-of", "2027-01-01"],
            options: json!({"as_of": "2027-01-01"}),
        },
        // An alias in another case, a sidecar, a product class and a rule
        // setting.
        Case {
            sbom: "cra/cra-compliant.cdx.json",
            flags: vec![
                "--profile",
                "cra",
                "--cra-sidecar",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/cra/cra-compliant.cra.json"
                ),
                "--cra-product-class",
                "critical",
                "--rule",
                "SBOM-CRA-SBOM-FRESHNESS=error",
                "--as-of",
                "2027-12-11",
            ],
            options: json!({
                "profile": "Cyber-Resilience",
                "sidecar": sidecar("cra/cra-compliant.cra.json"),
                "product_class": "critical",
                "rules": {"SBOM-CRA-SBOM-FRESHNESS": "error"},
                "as_of": "2027-12-11",
            }),
        },
        // PQC deadline mode with the federal profile.
        Case {
            sbom: "cyclonedx/cbom-pqc-calendar.cdx.json",
            flags: vec![
                "--profile",
                "cbom",
                "--pqc-mode",
                "deadline",
                "--pqc-profile",
                "federal",
                "--as-of",
                "2031-06-01",
            ],
            options: json!({
                "profile": "cbom",
                "pqc_mode": "deadline",
                "pqc_profile": "federal",
                "as_of": "2031-06-01",
            }),
        },
        // AI readiness on an SBOM without ML components (not applicable),
        // and on an AI-BOM.
        Case {
            sbom: "cyclonedx/minimal.cdx.json",
            flags: vec!["--profile", "ai-readiness", "--as-of", "2027-01-01"],
            options: json!({"profile": "ai-readiness", "as_of": "2027-01-01"}),
        },
        Case {
            sbom: "cyclonedx/aibom-complete.cdx.json",
            flags: vec!["--profile", "ai_readiness", "--as-of", "2027-01-01"],
            options: json!({"profile": "ai_readiness", "as_of": "2027-01-01"}),
        },
        // BSI on CycloneDX XML, and components whose scope is excluded.
        Case {
            sbom: "cra/bsi-compliant.cdx.xml",
            flags: vec!["--profile", "bsi", "--as-of", "2026-11-01"],
            options: json!({"profile": "bsi", "as_of": "2026-11-01"}),
        },
        Case {
            sbom: "cyclonedx/scope-excluded.cdx.json",
            flags: vec![
                "--profile",
                "comprehensive",
                "--include-excluded-scope",
                "--as-of",
                "2026-11-01",
            ],
            options: json!({
                "profile": "comprehensive",
                "include_excluded_scope": true,
                "as_of": "2026-11-01",
            }),
        },
        // The other profiles, on SPDX 2.3, SPDX 3 and CycloneDX 1.7.
        Case {
            sbom: "spdx/minimal.spdx.json",
            flags: vec!["--profile", "security", "--as-of", "2026-11-01"],
            options: json!({"profile": "security", "as_of": "2026-11-01"}),
        },
        Case {
            sbom: "spdx3/security-profile.spdx3.json",
            flags: vec!["--profile", "license", "--as-of", "2026-11-01"],
            options: json!({"profile": "license", "as_of": "2026-11-01"}),
        },
        Case {
            sbom: "cyclonedx/minimal-1.7.cdx.json",
            flags: vec!["--profile", "minimal", "--as-of", "2026-11-01"],
            options: json!({"profile": "minimal", "as_of": "2026-11-01"}),
        },
    ]
}

/// Scoring with options returns, byte for byte, what `quality - -o json`
/// writes for the same SBOM, profile and inputs.
#[test]
fn score_with_options_is_byte_identical_to_quality() {
    for case in score_parity_cases() {
        let abi = score(&fixture(case.sbom), &case.options)
            .unwrap_or_else(|e| panic!("{}: score failed: {e:?}", case.sbom));
        let cli = cli_quality("-", case.sbom, &case.flags);
        assert_eq!(
            abi, cli,
            "{} {:?}: the ABI report and `quality -o json` diverged",
            case.sbom, case.flags
        );
        assert_eq!(json(&abi)["sbom"], "-", "{}", case.sbom);
    }
}

/// An AI-readiness profile that does not apply has no score, as in
/// `quality -o json`, rather than a failing 0.0 and F.
#[test]
fn score_with_options_reports_a_profile_that_does_not_apply() {
    let output = json(
        &score(
            &fixture("cyclonedx/minimal.cdx.json"),
            &json!({"profile": "ai-readiness", "as_of": "2027-01-01"}),
        )
        .expect("scores"),
    );
    assert_eq!(output["profile"], "ai-readiness");
    assert_eq!(output["applicable"], false);
    assert!(output["report"]["overall_score"].is_null(), "{output}");
    assert_eq!(output["report"]["grade"], "N/A");
}

/// With `file_name`, the report is the one `quality <FILE> -o json` writes:
/// `sbom` names the file, without its directory.
#[test]
fn score_with_options_names_the_file_as_the_cli_does() {
    let name = "cyclonedx/minimal.cdx.json";
    let path = fixture_path(name);
    let cli = cli_quality(
        &path.to_string_lossy(),
        name,
        &["--profile", "cra", "--as-of", "2027-01-01"],
    );
    for file_name in [
        path.to_string_lossy().into_owned(),
        "minimal.cdx.json".to_string(),
    ] {
        let abi = score(
            &fixture(name),
            &json!({"profile": "cra", "file_name": file_name, "as_of": "2027-01-01"}),
        )
        .expect("scores");
        assert_eq!(abi, cli, "file_name {file_name}");
    }
    assert_eq!(json(&cli)["sbom"], "minimal.cdx.json");
}

/// The options pin the clock: the same call twice gives the same report,
/// and a later instant judges the SBOM's age differently.
#[test]
fn score_with_options_reads_the_pinned_clock() {
    let sbom = fixture("demo-new.cdx.json");
    let early = score(&sbom, &json!({"as_of": "2026-01-01"})).expect("scores");
    assert_eq!(
        early,
        score(&sbom, &json!({"as_of": "2026-01-01"})).expect("scores")
    );
    let late = score(&sbom, &json!({"as_of": "2036-01-01"})).expect("scores");
    assert_ne!(
        json(&early)["report"]["provenance_metrics"],
        json(&late)["report"]["provenance_metrics"]
    );
}

#[test]
fn score_with_options_rejects_bad_options() {
    let sbom = fixture("cyclonedx/minimal.cdx.json");
    for (options, needle) in [
        (
            json!({"profile": "strict"}),
            "unknown scoring profile 'strict'",
        ),
        (json!({"standards": ["ntia"]}), "unknown option `standards`"),
        (
            json!({"file_name": 7}),
            "`file_name` in options_json must be a string",
        ),
        (json!({"as_of": "tomorrow"}), "invalid as_of"),
        (
            json!({"cnsa_category": "niche"}),
            "apply only with `pqc_mode` \"deadline\"",
        ),
    ] {
        let (code, message) = score(&sbom, &options).expect_err("bad options");
        assert_eq!(code, SbomToolsErrorCode::Validation, "{options}");
        assert!(message.contains(needle), "{options}: {message}");
    }
    let (code, _) = score("this is not an SBOM", &json!({})).expect_err("no SBOM");
    assert_eq!(code, SbomToolsErrorCode::Unsupported);
}
