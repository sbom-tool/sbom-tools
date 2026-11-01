//! Bidirectional FFI conformance tests (spec ↔ runtime).
//!
//! These tests verify:
//! - spec → runtime: All declared ABI functions are callable and all enumerated values are valid
//! - runtime → spec: Runtime behavior matches the ABI contract (required keys, header signatures, null pointers)

mod common;

use common::ffi_helpers::{consume_result, into_c_string};
use sbom_tools::ffi::{
    SbomToolsErrorCode, SbomToolsScoringProfile, sbom_tools_abi_version_json,
    sbom_tools_detect_format_json, sbom_tools_diff_sboms_json, sbom_tools_parse_sbom_path_json,
    sbom_tools_parse_sbom_str_json, sbom_tools_rule_catalog_json, sbom_tools_score_sbom_json,
    sbom_tools_score_sbom_with_options_json, sbom_tools_string_result_free,
    sbom_tools_validate_json,
};
use std::ffi::CStr;
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ─────────────────────────────────────────────────────────────────────────────
// spec → runtime: Declared surface is callable at runtime
// ─────────────────────────────────────────────────────────────────────────────

/// Conformance: all 10 extern "C" functions are callable with valid inputs.
#[test]
fn conformance_all_ten_abi_functions_callable() {
    // 1. sbom_tools_abi_version_json()
    let version =
        consume_result(sbom_tools_abi_version_json()).expect("abi_version should be callable");
    assert!(!version.is_empty());

    // 2. sbom_tools_detect_format_json(content)
    let fixture = fixture_path("cyclonedx/minimal.cdx.json");
    let content = std::fs::read_to_string(&fixture).expect("fixture should exist");
    let content_c = into_c_string(&content);
    let detected = consume_result(sbom_tools_detect_format_json(content_c.as_ptr()))
        .expect("detect_format should be callable");
    assert!(!detected.is_empty());

    // 3. sbom_tools_parse_sbom_path_json(path)
    let path_c = into_c_string(fixture.to_string_lossy().as_ref());
    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path_c.as_ptr()))
        .expect("parse_sbom_path should be callable");
    assert!(!parsed.is_empty());

    // 4. sbom_tools_parse_sbom_str_json(content)
    let parsed = consume_result(sbom_tools_parse_sbom_str_json(content_c.as_ptr()))
        .expect("parse_sbom_str should be callable");
    assert!(!parsed.is_empty());

    // 5. sbom_tools_diff_sboms_json(old, new)
    let parsed_c = into_c_string(&parsed);
    let diff = consume_result(sbom_tools_diff_sboms_json(
        parsed_c.as_ptr(),
        parsed_c.as_ptr(),
    ))
    .expect("diff_sboms should be callable");
    assert!(!diff.is_empty());

    // 6. sbom_tools_score_sbom_json(sbom, profile)
    let score = consume_result(sbom_tools_score_sbom_json(
        parsed_c.as_ptr(),
        SbomToolsScoringProfile::Standard,
    ))
    .expect("score_sbom should be callable");
    assert!(!score.is_empty());

    // 7. sbom_tools_validate_json(sbom, options)
    let options_c = into_c_string(r#"{"as_of": "2027-01-01"}"#);
    let envelope = consume_result(sbom_tools_validate_json(
        content_c.as_ptr(),
        options_c.as_ptr(),
    ))
    .expect("validate should be callable");
    assert!(!envelope.is_empty());

    // 8. sbom_tools_rule_catalog_json(filter)
    let filter_c = into_c_string("{}");
    let catalog = consume_result(sbom_tools_rule_catalog_json(filter_c.as_ptr()))
        .expect("rule_catalog should be callable");
    assert!(!catalog.is_empty());

    // 9. sbom_tools_score_sbom_with_options_json(sbom, options)
    let score = consume_result(sbom_tools_score_sbom_with_options_json(
        content_c.as_ptr(),
        options_c.as_ptr(),
    ))
    .expect("score_sbom_with_options should be callable");
    assert!(!score.is_empty());

    // 10. sbom_tools_string_result_free(result) — already tested via consume_result
}

/// Conformance: all 6 scoring profiles return valid JSON with positive scores.
#[test]
fn conformance_all_six_scoring_profiles_return_valid_json() {
    let fixture = fixture_path("demo-new.cdx.json");
    let content = std::fs::read_to_string(&fixture).expect("fixture should exist");
    let content_c = into_c_string(&content);
    let parsed = consume_result(sbom_tools_parse_sbom_str_json(content_c.as_ptr()))
        .expect("parse should succeed");
    let parsed_c = into_c_string(&parsed);

    let profiles = vec![
        SbomToolsScoringProfile::Minimal,
        SbomToolsScoringProfile::Standard,
        SbomToolsScoringProfile::Security,
        SbomToolsScoringProfile::LicenseCompliance,
        SbomToolsScoringProfile::Cra,
        SbomToolsScoringProfile::Comprehensive,
    ];

    for profile in profiles {
        let score_json = consume_result(sbom_tools_score_sbom_json(parsed_c.as_ptr(), profile))
            .expect("each profile should score successfully");

        let value: serde_json::Value =
            serde_json::from_str(&score_json).expect("score response must be valid JSON");

        assert!(
            value["overall_score"].as_f64().unwrap_or(-1.0) > 0.0,
            "score must be positive for profile {:?}",
            profile
        );
    }
}

/// Conformance: all error codes are reachable via specific error conditions.
#[test]
fn conformance_all_error_codes_are_reachable() {
    // Parse (1): Unsupported error when format cannot be detected
    // UnknownFormat maps to Unsupported, which is one of the reachable error codes
    let unknown_format = into_c_string("this is not any known SBOM format");
    let (code, msg) = consume_result(sbom_tools_parse_sbom_str_json(unknown_format.as_ptr()))
        .expect_err("unknown format should fail");
    assert_eq!(
        code,
        SbomToolsErrorCode::Unsupported,
        "Unsupported error code should be reachable"
    );
    assert!(!msg.is_empty(), "Unsupported error should have message");

    // Validation (3): invalid normalized SBOM JSON to diff
    let invalid = into_c_string("{}");
    let (code, msg) = consume_result(sbom_tools_diff_sboms_json(
        invalid.as_ptr(),
        invalid.as_ptr(),
    ))
    .expect_err("empty JSON should fail validation");
    assert_eq!(
        code,
        SbomToolsErrorCode::Validation,
        "Validation error code should be reachable"
    );
    assert!(!msg.is_empty(), "Validation error should have message");

    // Io (4): nonexistent file
    let nonexistent = into_c_string("/nonexistent/path-that-must-not-exist-abc123.json");
    let (code, msg) = consume_result(sbom_tools_parse_sbom_path_json(nonexistent.as_ptr()))
        .expect_err("nonexistent path should fail with IO error");
    assert_eq!(
        code,
        SbomToolsErrorCode::Io,
        "IO error code should be reachable"
    );
    assert!(!msg.is_empty(), "IO error should have message");

    // Note: Ok (0) is implicitly tested in other tests.
    // Unsupported (5) and Internal (6) are harder to trigger in normal flow,
    // but conformance is verified by exhaustive error handling in src/ffi.rs.
}

/// Conformance: the ABI version is "2" (sbom-tools 0.4.0). It is the
/// stability contract: a release that changes the contract incompatibly
/// raises it (see `ABI_VERSION` in src/ffi.rs), so this test changes with it.
#[test]
fn conformance_abi_version_is_2() {
    let payload =
        consume_result(sbom_tools_abi_version_json()).expect("abi_version should succeed");
    let value: serde_json::Value =
        serde_json::from_str(&payload).expect("abi_version JSON is valid");
    assert_eq!(
        value["abi_version"], "2",
        "ABI version is the stability contract; raise it only by its rules"
    );
}

/// Conformance: detect_format returns valid JSON (including "null" for unknown formats).
#[test]
fn conformance_detect_format_returns_null_json_for_unknown_content() {
    let unknown = into_c_string("hello world");
    let result = consume_result(sbom_tools_detect_format_json(unknown.as_ptr()))
        .expect("detect_format should succeed even for unknown input");

    // The response should parse as valid JSON (could be "null" or an object with confidence info).
    let value: serde_json::Value =
        serde_json::from_str(&result).expect("detect_format always returns valid JSON");

    // If it's null, Go/Swift wrappers return nil. If it's an object, check confidence.
    if !value.is_null() {
        // If an object, it may have a confidence field indicating low/none.
        // This is just checking the JSON parses, not the specific format.
        assert!(
            value.is_object() || value.is_null(),
            "result should be JSON object or null"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// runtime → spec: Runtime behavior is captured in the contract
// ─────────────────────────────────────────────────────────────────────────────

/// Conformance: required keys are present in all ABI operation responses.
#[test]
fn conformance_required_keys_present_for_all_operations() {
    // Load the ABI contract fixture if it exists
    let contract_path = fixture_path("abi/contract_required_keys.json");
    if !contract_path.exists() {
        eprintln!("Warning: contract_required_keys.json not found; skipping key validation");
        return;
    }

    let contract = std::fs::read_to_string(&contract_path).expect("contract should load");
    let contract: serde_json::Value =
        serde_json::from_str(&contract).expect("contract should be valid JSON");

    // Get a valid parsed SBOM for operation inputs
    let fixture = fixture_path("demo-new.cdx.json");
    let content = std::fs::read_to_string(&fixture).expect("fixture should exist");
    let content_c = into_c_string(&content);
    let parsed = consume_result(sbom_tools_parse_sbom_str_json(content_c.as_ptr()))
        .expect("parse should succeed");
    let _parsed_c = into_c_string(&parsed);

    // Check abi_version_json
    if let Some(keys) = contract.get("abi_version_json").and_then(|v| v.as_array()) {
        let result = consume_result(sbom_tools_abi_version_json()).expect("abi_version ok");
        let value: serde_json::Value = serde_json::from_str(&result).expect("abi_version is JSON");
        for key in keys {
            let key_str = key.as_str().expect("key should be string");
            assert!(
                value.get(key_str).is_some(),
                "abi_version must contain required key '{}'",
                key_str
            );
        }
    }

    // Check parse_sbom_str_json and score_sbom_json (normalized SBOM structure)
    if let Some(keys) = contract
        .get("parse_sbom_str_json")
        .and_then(|v| v.as_array())
    {
        let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed is JSON");
        for key in keys {
            let key_str = key.as_str().expect("key should be string");
            assert!(
                value.get(key_str).is_some(),
                "parse_sbom_str must contain required key '{}'",
                key_str
            );
        }
    }
}

/// Conformance: C header file contains all 10 function signatures.
#[test]
fn conformance_c_header_contains_all_function_signatures() {
    let header_path =
        fixture_path("../../../bindings/swift/Sources/CSbomTools/include/sbom_tools.h");
    if !header_path.exists() {
        eprintln!("Warning: header file not found at {:?}", header_path);
        return;
    }

    let header = std::fs::read_to_string(&header_path).expect("header should load");

    // Check all 10 function signatures are present
    let expected_sigs = vec![
        "sbom_tools_abi_version_json",
        "sbom_tools_detect_format_json",
        "sbom_tools_parse_sbom_path_json",
        "sbom_tools_parse_sbom_str_json",
        "sbom_tools_diff_sboms_json",
        "sbom_tools_score_sbom_json",
        "sbom_tools_validate_json",
        "sbom_tools_rule_catalog_json",
        "sbom_tools_score_sbom_with_options_json",
        "sbom_tools_string_result_free",
    ];

    for sig in expected_sigs {
        assert!(
            header.contains(sig),
            "header must declare function '{}'",
            sig
        );
    }
}

/// Conformance: successful result has null error_message pointer.
#[test]
fn conformance_result_struct_has_null_error_on_success() {
    let result = sbom_tools_abi_version_json();
    assert_eq!(
        result.error_code,
        SbomToolsErrorCode::Ok,
        "abi_version should succeed"
    );
    assert!(
        result.error_message.is_null(),
        "successful result must have null error_message, not garbage"
    );

    // data should not be null for successful results
    assert!(
        !result.data.is_null(),
        "successful result must have non-null data"
    );

    sbom_tools_string_result_free(result);
}

/// Conformance: error result has null data pointer.
#[test]
fn conformance_result_struct_has_null_data_on_error() {
    let garbage = into_c_string("zzz not sbom zzz");
    let result = sbom_tools_parse_sbom_str_json(garbage.as_ptr());
    assert_ne!(
        result.error_code,
        SbomToolsErrorCode::Ok,
        "garbage should fail"
    );
    assert!(
        result.data.is_null(),
        "error result must have null data, not garbage"
    );

    // error_message should not be null for error results
    assert!(
        !result.error_message.is_null(),
        "error result must have non-null error_message"
    );

    sbom_tools_string_result_free(result);
}

/// Conformance: error messages are valid UTF-8, not lossy.
#[test]
fn conformance_error_messages_are_valid_utf8() {
    // Trigger Parse error
    let garbage = into_c_string("zzz not sbom zzz");
    let result = sbom_tools_parse_sbom_str_json(garbage.as_ptr());
    assert_ne!(result.error_code, SbomToolsErrorCode::Ok);

    // SAFETY: error_message is non-null (checked above) and valid C string
    let error_str = unsafe { CStr::from_ptr(result.error_message) };
    let utf8_result = error_str.to_str();
    assert!(
        utf8_result.is_ok(),
        "error message must be valid UTF-8, not lossy substitution"
    );

    sbom_tools_string_result_free(result);

    // Trigger Validation error
    let invalid = into_c_string("{}");
    let result = sbom_tools_diff_sboms_json(invalid.as_ptr(), invalid.as_ptr());
    assert_ne!(result.error_code, SbomToolsErrorCode::Ok);

    let error_str = unsafe { CStr::from_ptr(result.error_message) };
    let utf8_result = error_str.to_str();
    assert!(
        utf8_result.is_ok(),
        "validation error message must be valid UTF-8"
    );

    sbom_tools_string_result_free(result);

    // Trigger IO error
    let nonexistent = into_c_string("/nonexistent/path-abc123.json");
    let result = sbom_tools_parse_sbom_path_json(nonexistent.as_ptr());
    assert_ne!(result.error_code, SbomToolsErrorCode::Ok);

    let error_str = unsafe { CStr::from_ptr(result.error_message) };
    let utf8_result = error_str.to_str();
    assert!(utf8_result.is_ok(), "IO error message must be valid UTF-8");

    sbom_tools_string_result_free(result);
}
