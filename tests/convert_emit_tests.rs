//! Tests for cross-format emission (`convert` subcommand + emit library).
//!
//! Covers: CycloneDX round-trip fidelity (counts preserved), SPDX → CycloneDX
//! cross-family mapping, the CLI binary producing valid output + a fidelity
//! report, and the invariant that converting an AI-BOM does not regress the
//! `mlModel` AI bridge / AI-readiness scoring.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::serialization::emit::{self, EmitTarget, preserve_source_json};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).expect("fixture should exist")
}

// ---------------------------------------------------------------------------
// Library-level round-trip and cross-family tests
// ---------------------------------------------------------------------------

#[test]
fn cyclonedx_round_trip_preserves_counts() {
    let raw = read_fixture("cyclonedx/minimal.cdx.json");
    let original = parse_sbom_str(&raw).unwrap();

    let (emitted, report) = emit::emit(&original, EmitTarget::CycloneDx).unwrap();
    let reparsed = parse_sbom_str(&emitted).expect("emitted CycloneDX must re-parse");

    assert_eq!(
        reparsed.components.len(),
        original.components.len(),
        "component count preserved"
    );
    assert_eq!(
        reparsed.edges.len(),
        original.edges.len(),
        "edge count preserved"
    );

    // license + purl counts preserved per matching component.
    for orig in original.components.values() {
        let Some(reparsed_comp) = reparsed.components.get(&orig.canonical_id) else {
            panic!("component {} missing after round-trip", orig.name);
        };
        assert_eq!(
            reparsed_comp.licenses.declared.len(),
            orig.licenses.declared.len(),
            "license count for {}",
            orig.name
        );
        assert_eq!(
            reparsed_comp.identifiers.purl, orig.identifiers.purl,
            "purl for {}",
            orig.name
        );
    }

    // Same-format round-trip must not be lossy.
    assert!(
        !report.is_lossy(),
        "round-trip report:\n{}",
        report.render()
    );
}

#[test]
fn cyclonedx_round_trip_preserves_hashes() {
    let raw = read_fixture("spdx/minimal.spdx.json");
    let original = parse_sbom_str(&raw).unwrap();
    let total_hashes: usize = original.components.values().map(|c| c.hashes.len()).sum();
    assert!(total_hashes > 0, "fixture has at least one checksum");

    let (emitted, _report) = emit::emit(&original, EmitTarget::CycloneDx).unwrap();
    let reparsed = parse_sbom_str(&emitted).unwrap();
    let reparsed_hashes: usize = reparsed.components.values().map(|c| c.hashes.len()).sum();
    assert_eq!(reparsed_hashes, total_hashes, "hash count preserved");
}

#[test]
fn spdx_cross_family_to_cyclonedx_maps_components() {
    let raw = read_fixture("spdx/minimal.spdx.json");
    let spdx = parse_sbom_str(&raw).unwrap();

    let (emitted, _report) = emit::emit(&spdx, EmitTarget::CycloneDx).unwrap();

    // Emitted document is genuine CycloneDX.
    assert!(emitted.contains("\"bomFormat\": \"CycloneDX\""));
    assert!(emitted.contains("\"specVersion\": \"1.7\""));

    let reparsed = parse_sbom_str(&emitted).expect("SPDX→CDX output must re-parse as CycloneDX");
    assert_eq!(reparsed.document.format_version, "1.7");

    // lodash and express map across.
    let names: Vec<&str> = reparsed
        .components
        .values()
        .map(|c| c.name.as_str())
        .collect();
    assert!(names.contains(&"lodash"), "lodash mapped: {names:?}");
    assert!(names.contains(&"express"), "express mapped: {names:?}");
    // express depends-on lodash edge survives.
    assert!(!reparsed.edges.is_empty(), "dependency edges mapped");
}

#[test]
fn spdx_target_is_not_yet_implemented() {
    let raw = read_fixture("cyclonedx/minimal.cdx.json");
    let sbom = parse_sbom_str(&raw).unwrap();
    let err = emit::emit(&sbom, EmitTarget::Spdx).unwrap_err();
    assert!(
        err.to_string().contains("not yet implemented"),
        "got: {err}"
    );
}

#[test]
fn ai_bom_convert_preserves_ml_bridge() {
    // Converting an AI-BOM must keep the modelCard so AI scoring does not regress.
    let raw = read_fixture("cyclonedx/minimal-mlbom.cdx.json");
    let mut sbom = parse_sbom_str(&raw).unwrap();
    preserve_source_json(&raw, &mut sbom);

    let (emitted, report) = emit::emit(&sbom, EmitTarget::CycloneDx).unwrap();
    let reparsed = parse_sbom_str(&emitted).unwrap();

    // ML components survive with their ml_model metadata.
    let ml_components: Vec<_> = reparsed
        .components
        .values()
        .filter(|c| c.ml_model.is_some())
        .collect();
    assert_eq!(ml_components.len(), 2, "both ML models preserved");

    // architectureFamily (AI-002) and a model card survive on bert-base.
    let bert = reparsed
        .components
        .values()
        .find(|c| c.name == "bert-base")
        .expect("bert-base present");
    let ml = bert.ml_model.as_ref().unwrap();
    assert_eq!(ml.architecture_family.as_deref(), Some("transformer"));
    assert!(!ml.training_datasets.is_empty(), "datasets preserved");
    assert!(
        ml.energy_kwh_training.is_some(),
        "training energy preserved"
    );

    // Pure CycloneDX→CycloneDX of a typed model is not lossy.
    assert!(!report.is_lossy(), "report:\n{}", report.render());
}

#[test]
fn preserve_flag_round_trips_crypto_properties() {
    // CBOM cryptoProperties cannot be fully reconstructed from the typed model;
    // --preserve must splice them back verbatim.
    let raw = read_fixture("cyclonedx/cbom-1.7.cdx.json");
    let mut sbom = parse_sbom_str(&raw).unwrap();

    // Without preserve, the report flags cryptoProperties as dropped.
    let (_no_pres, report_no_pres) = emit::emit(&sbom, EmitTarget::CycloneDx).unwrap();
    assert!(
        report_no_pres.is_lossy(),
        "crypto without preserve should be lossy"
    );

    // With preserve, cryptoProperties survive into the output.
    preserve_source_json(&raw, &mut sbom);
    let (emitted, _report) = emit::emit(&sbom, EmitTarget::CycloneDx).unwrap();
    assert!(
        emitted.contains("cryptoProperties"),
        "cryptoProperties spliced back with --preserve"
    );
    parse_sbom_str(&emitted).expect("preserved CBOM output re-parses");
}

// ---------------------------------------------------------------------------
// CLI binary tests
// ---------------------------------------------------------------------------

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf-8")
}

#[test]
fn cli_convert_emits_valid_cyclonedx_and_fidelity_report() {
    let output = base_command()
        .arg("convert")
        .arg(fixture_path("spdx/minimal.spdx.json"))
        .args(["--to", "cyclonedx"])
        .output()
        .expect("convert command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    // stdout is valid, re-parseable CycloneDX.
    let out = stdout(&output);
    let reparsed = parse_sbom_str(&out).expect("CLI output must be valid CycloneDX");
    assert_eq!(reparsed.document.format_version, "1.7");
    assert!(reparsed.component_count() >= 2);

    // Fidelity report goes to stderr, not stdout.
    let err = stderr(&output);
    assert!(err.contains("Fidelity report"), "stderr:\n{err}");
    assert!(!out.contains("Fidelity report"), "report leaked to stdout");
}

#[test]
fn cli_convert_to_spdx_errors_clearly() {
    let output = base_command()
        .arg("convert")
        .arg(fixture_path("cyclonedx/minimal.cdx.json"))
        .args(["--to", "spdx"])
        .output()
        .expect("convert command should run");

    assert_ne!(output.status.code(), Some(0), "spdx target should fail");
    let err = stderr(&output);
    assert!(
        err.contains("not yet implemented"),
        "expected clear error, got:\n{err}"
    );
}

#[test]
fn cli_convert_quiet_suppresses_report() {
    let output = base_command()
        .arg("--quiet")
        .arg("convert")
        .arg(fixture_path("cyclonedx/minimal.cdx.json"))
        .args(["--to", "cyclonedx"])
        .output()
        .expect("convert command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("Fidelity report"),
        "quiet should suppress the report"
    );
}
