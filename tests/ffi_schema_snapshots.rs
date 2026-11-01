mod common;

use common::ffi_helpers::{consume_result, into_c_string};
use sbom_tools::ffi::{
    SbomToolsScoringProfile, sbom_tools_abi_version_json, sbom_tools_detect_format_json,
    sbom_tools_diff_sboms_json, sbom_tools_parse_sbom_path_json, sbom_tools_rule_catalog_json,
    sbom_tools_score_sbom_json, sbom_tools_score_sbom_with_options_json, sbom_tools_validate_json,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn assert_required_keys(payload: &str, required: &[String]) {
    let value: serde_json::Value = serde_json::from_str(payload).expect("ABI JSON should be valid");
    let object = value
        .as_object()
        .expect("ABI response should be a JSON object");
    for key in required {
        assert!(
            object.contains_key(key),
            "ABI payload is missing required key '{key}': {payload}"
        );
    }
}

#[test]
fn abi_contract_snapshots_are_enforced() {
    let contract_path = fixture_path("abi/contract_required_keys.json");
    let contract_raw =
        std::fs::read_to_string(contract_path).expect("snapshot fixture should exist");
    let contract: HashMap<String, HashMap<String, Vec<String>>> =
        serde_json::from_str(&contract_raw).expect("snapshot fixture should parse");

    let abi_version = consume_result(sbom_tools_abi_version_json()).expect("ABI version payload");
    assert_required_keys(&abi_version, &contract["abi_version_json"]["required_keys"]);

    let detect_input = into_c_string(r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#);
    let detection = consume_result(sbom_tools_detect_format_json(detect_input.as_ptr()))
        .expect("detected format payload");
    assert_required_keys(
        &detection,
        &contract["detected_format_json"]["required_keys"],
    );

    let old_path = into_c_string(fixture_path("demo-old.cdx.json").to_string_lossy().as_ref());
    let new_path = into_c_string(fixture_path("demo-new.cdx.json").to_string_lossy().as_ref());
    let old_payload = consume_result(sbom_tools_parse_sbom_path_json(old_path.as_ptr()))
        .expect("old normalized SBOM payload");
    let new_payload = consume_result(sbom_tools_parse_sbom_path_json(new_path.as_ptr()))
        .expect("new normalized SBOM payload");

    assert_required_keys(
        &old_payload,
        &contract["normalized_sbom_json"]["required_keys"],
    );

    let old_payload_c = into_c_string(&old_payload);
    let new_payload_c = into_c_string(&new_payload);
    let diff_payload = consume_result(sbom_tools_diff_sboms_json(
        old_payload_c.as_ptr(),
        new_payload_c.as_ptr(),
    ))
    .expect("diff payload");
    assert_required_keys(
        &diff_payload,
        &contract["diff_result_json"]["required_keys"],
    );

    let quality_payload = consume_result(sbom_tools_score_sbom_json(
        new_payload_c.as_ptr(),
        SbomToolsScoringProfile::Standard,
    ))
    .expect("quality payload");
    assert_required_keys(
        &quality_payload,
        &contract["quality_report_json"]["required_keys"],
    );

    let options = into_c_string(r#"{"as_of": "2027-01-01"}"#);
    let raw = into_c_string(
        &std::fs::read_to_string(fixture_path("demo-new.cdx.json")).expect("fixture readable"),
    );
    let envelope = consume_result(sbom_tools_validate_json(raw.as_ptr(), options.as_ptr()))
        .expect("compliance envelope payload");
    assert_required_keys(
        &envelope,
        &contract["compliance_envelope_json"]["required_keys"],
    );

    let filter = into_c_string("{}");
    let catalog = consume_result(sbom_tools_rule_catalog_json(filter.as_ptr()))
        .expect("rule catalogue payload");
    assert_required_keys(&catalog, &contract["rule_catalog_json"]["required_keys"]);

    let score_report = consume_result(sbom_tools_score_sbom_with_options_json(
        raw.as_ptr(),
        options.as_ptr(),
    ))
    .expect("score report payload");
    assert_required_keys(
        &score_report,
        &contract["score_report_json"]["required_keys"],
    );
}

#[test]
fn c_header_signatures_snapshot_is_enforced() {
    let header = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bindings/swift/Sources/CSbomTools/include/sbom_tools.h"
    ))
    .expect("header should exist");

    let expected = std::fs::read_to_string(fixture_path("abi/header_signatures.txt"))
        .expect("header signatures snapshot should exist");

    for signature in expected.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            header.contains(signature),
            "Header is missing expected signature: {signature}"
        );
    }
}

/// `convert --to normalized` must emit exactly the bytes the ABI returns for
/// the same input (issue #366): both go through
/// `serialization::NormalizedSbomPayload`, and this pins that they stay
/// wired to the same serializer.
#[test]
fn cli_normalized_payload_is_byte_identical_to_abi_payload() {
    for name in ["demo-new.cdx.json", "cyclonedx/cbom-1.6.cdx.json"] {
        let path = fixture_path(name);
        let c_path = into_c_string(path.to_string_lossy().as_ref());
        let abi = consume_result(sbom_tools_parse_sbom_path_json(c_path.as_ptr()))
            .expect("ABI normalized payload");

        let sbom = sbom_tools::parse_sbom(&path).expect("parse fixture");
        let (cli, _) = sbom_tools::serialization::emit(
            &sbom,
            sbom_tools::serialization::EmitTarget::Normalized,
        )
        .expect("emit normalized");

        assert_eq!(cli, abi, "{name}: CLI and ABI normalized payloads diverged");
    }
}
