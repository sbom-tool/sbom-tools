//! Regression tests for FFI binding and multi-format SBOM parsing.
//!
//! These tests verify that the FFI interface properly handles all supported SBOM formats
//! and edge cases, covering changes from PR #113 (workspace isolation, feature-gating, multi-format).

mod common;

use common::ffi_helpers::{consume_result, into_c_string};
use sbom_tools::ffi::{
    SbomToolsErrorCode, SbomToolsScoringProfile, sbom_tools_diff_sboms_json,
    sbom_tools_parse_sbom_path_json, sbom_tools_parse_sbom_str_json, sbom_tools_score_sbom_json,
};
use std::ffi::CString;
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-format regression tests (SPDX 2.x, SPDX 3.0, CycloneDX)
// ─────────────────────────────────────────────────────────────────────────────

/// Regression: SPDX JSON (v2.3) parses through FFI.
#[test]
fn regression_spdx_json_parses_through_ffi() {
    let fixture = fixture_path("spdx/minimal.spdx.json");
    let path_c = into_c_string(fixture.to_string_lossy().as_ref());

    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path_c.as_ptr()))
        .expect("SPDX JSON should parse");

    let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed is JSON");
    assert_eq!(value["document"]["format"], "Spdx", "format should be Spdx");
    assert!(
        value["components"].is_array(),
        "components should be present and be an array"
    );
}

/// Regression: SPDX RDF/XML (v2.3) parses through FFI.
#[test]
fn regression_spdx_rdf_parses_through_ffi() {
    let fixture = fixture_path("spdx/minimal.spdx.rdf.xml");
    let path_c = into_c_string(fixture.to_string_lossy().as_ref());

    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path_c.as_ptr()))
        .expect("SPDX RDF should parse");

    let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed is JSON");
    assert!(
        value["document"]["format"].as_str().is_some(),
        "format should be present"
    );
}

/// Regression: SPDX 3.0 JSON-LD parses through FFI.
#[test]
fn regression_spdx3_parses_through_ffi() {
    let fixture = fixture_path("spdx3/minimal.spdx3.json");
    let path_c = into_c_string(fixture.to_string_lossy().as_ref());

    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path_c.as_ptr()))
        .expect("SPDX 3.0 should parse");

    let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed is JSON");
    assert!(
        value["components"].is_array(),
        "components should be present"
    );
}

/// Regression: CycloneDX 1.7 JSON parses through FFI.
#[test]
fn regression_cyclonedx_1_7_parses_through_ffi() {
    let fixture = fixture_path("cyclonedx/minimal-1.7.cdx.json");
    let path_c = into_c_string(fixture.to_string_lossy().as_ref());

    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path_c.as_ptr()))
        .expect("CycloneDX 1.7 should parse");

    let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed is JSON");
    assert_eq!(
        value["document"]["format"], "CycloneDx",
        "format should be CycloneDx"
    );
}

/// Regression: cross-format diff (CycloneDX vs SPDX) works through FFI.
#[test]
fn regression_cross_format_diff_cyclonedx_vs_spdx() {
    let cdx_fixture = fixture_path("cyclonedx/minimal.cdx.json");
    let spdx_fixture = fixture_path("spdx/minimal.spdx.json");

    let cdx_path_c = into_c_string(cdx_fixture.to_string_lossy().as_ref());
    let spdx_path_c = into_c_string(spdx_fixture.to_string_lossy().as_ref());

    let cdx_parsed = consume_result(sbom_tools_parse_sbom_path_json(cdx_path_c.as_ptr()))
        .expect("CycloneDX should parse");
    let spdx_parsed = consume_result(sbom_tools_parse_sbom_path_json(spdx_path_c.as_ptr()))
        .expect("SPDX should parse");

    let cdx_c = into_c_string(&cdx_parsed);
    let spdx_c = into_c_string(&spdx_parsed);

    let diff = consume_result(sbom_tools_diff_sboms_json(cdx_c.as_ptr(), spdx_c.as_ptr()))
        .expect("cross-format diff should succeed");

    let value: serde_json::Value = serde_json::from_str(&diff).expect("diff is JSON");
    assert!(
        value["summary"].is_object(),
        "diff should have a summary object"
    );
}

/// Regression: scoring a 40K-component linear dependency chain through FFI
/// must not abort the host process (cycle detection is iterative, not recursive).
#[test]
fn regression_score_deep_dependency_chain_does_not_abort() {
    let n = 40_000usize;
    let components: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            serde_json::json!({
                "type": "library",
                "bom-ref": format!("ref-{i}"),
                "name": format!("node-{i}"),
                "version": "1.0.0"
            })
        })
        .collect();
    let dependencies: Vec<serde_json::Value> = (0..n - 1)
        .map(|i| {
            serde_json::json!({
                "ref": format!("ref-{i}"),
                "dependsOn": [format!("ref-{}", i + 1)]
            })
        })
        .collect();
    let bom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
        "dependencies": dependencies
    });

    let content_c = into_c_string(&bom.to_string());
    let parsed = consume_result(sbom_tools_parse_sbom_str_json(content_c.as_ptr()))
        .expect("deep-chain CycloneDX should parse");
    let parsed_c = into_c_string(&parsed);

    let score_json = consume_result(sbom_tools_score_sbom_json(
        parsed_c.as_ptr(),
        SbomToolsScoringProfile::Standard,
    ))
    .expect("scoring deep chain should succeed");

    let value: serde_json::Value = serde_json::from_str(&score_json).expect("score is JSON");
    assert_eq!(
        value["dependency_metrics"]["cycle_count"].as_u64(),
        Some(0),
        "linear chain has no cycles"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path regression tests (IO errors, parse errors, edge cases)
// ─────────────────────────────────────────────────────────────────────────────

/// Regression: nonexistent file path returns IO error code 4.
#[test]
fn regression_io_error_path_returns_error_code_4() {
    let nonexistent = into_c_string("/nonexistent/sbom-that-cannot-exist-abc123.json");
    let (code, _msg) = consume_result(sbom_tools_parse_sbom_path_json(nonexistent.as_ptr()))
        .expect_err("nonexistent path should fail");

    assert_eq!(
        code,
        SbomToolsErrorCode::Io,
        "nonexistent file should return IO error code"
    );
}

/// Regression: binary garbage input triggers validation error.
#[test]
fn regression_parse_error_on_binary_garbage_input() {
    // Use invalid UTF-8 that forms a valid C string (no interior NUL).
    // \xff\xfe is invalid UTF-8 prefix caught at validation (read_input UTF-8 check).
    let garbage = CString::new(b"\xff\xfe garbage binary".to_vec()).expect("no interior NUL");
    let (code, _msg) = consume_result(sbom_tools_parse_sbom_str_json(garbage.as_ptr()))
        .expect_err("binary garbage should fail");

    assert_eq!(
        code,
        SbomToolsErrorCode::Validation,
        "garbage input should return validation error (invalid UTF-8)"
    );
}

/// Regression: diffing same SBOM against itself yields zero changes.
#[test]
fn regression_diff_on_same_sbom_has_zero_changes() {
    let fixture = fixture_path("demo-old.cdx.json");
    let content = std::fs::read_to_string(&fixture).expect("fixture should exist");
    let content_c = into_c_string(&content);

    // Parse once
    let parsed = consume_result(sbom_tools_parse_sbom_str_json(content_c.as_ptr()))
        .expect("parse should succeed");
    let parsed_c = into_c_string(&parsed);

    // Diff against itself
    let diff = consume_result(sbom_tools_diff_sboms_json(
        parsed_c.as_ptr(),
        parsed_c.as_ptr(),
    ))
    .expect("self-diff should succeed");

    let value: serde_json::Value = serde_json::from_str(&diff).expect("diff is JSON");

    // Core assertion: diffing the same SBOM produces zero changes
    let total_changes = value["summary"]["total_changes"].as_u64().unwrap_or(1); // default to 1 to fail if missing
    assert_eq!(
        total_changes, 0,
        "diffing same SBOM should have zero changes"
    );
}
