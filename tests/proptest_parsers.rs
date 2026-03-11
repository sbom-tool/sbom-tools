//! Property-based tests for SBOM parsers.
//!
//! Ensures parsers don't panic on arbitrary input, including random strings,
//! JSON-like fragments, and XML-like fragments.

use proptest::prelude::*;
use sbom_tools::parsers::{detect_format, parse_sbom_str};

proptest! {
    // 500 cases balances coverage vs speed for parser fuzz tests.
    // Parser tests intentionally only assert no-panic (not result correctness)
    // since random input is expected to produce Err in almost all cases.
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn parse_sbom_str_doesnt_panic(s in "\\PC{0,2000}") {
        // Random input should always return Err, never panic
        let result = parse_sbom_str(&s);
        prop_assert!(result.is_err(), "Random input should not parse successfully: {:?}", s);
    }

    #[test]
    fn detect_format_doesnt_panic(s in "\\PC{0,2000}") {
        let _ = detect_format(&s);
    }

    #[test]
    fn json_like_input_doesnt_panic(
        s in prop::string::string_regex(r#"\{[^\}]{0,500}\}"#)
            .expect("invalid JSON-like regex for proptest")
    ) {
        let _ = parse_sbom_str(&s);
    }

    #[test]
    fn xml_like_input_doesnt_panic(
        tag in "[A-Za-z][A-Za-z0-9_-]{0,19}",
        content in "\\PC{0,200}",
    ) {
        let s = format!("<{tag}>{content}</{tag}>");
        let _ = parse_sbom_str(&s);
    }

    #[test]
    fn spdx_tag_value_like_doesnt_panic(
        key in "[A-Za-z]{1,20}",
        value in "\\PC{0,100}",
    ) {
        let input = format!("{}: {}", key, value);
        let _ = parse_sbom_str(&input);
        let _ = detect_format(&input);
    }

    #[test]
    fn empty_and_whitespace_doesnt_panic(s in "\\s{0,100}") {
        let _ = parse_sbom_str(&s);
        let _ = detect_format(&s);
    }

    #[test]
    fn cyclonedx_partial_json_doesnt_panic(
        version in "1\\.[4-7]",
        extra in "\\PC{0,200}",
    ) {
        let input = format!(r#"{{"bomFormat": "CycloneDX", "specVersion": "{}", {}}}"#, version, extra);
        let _ = parse_sbom_str(&input);
    }

    #[test]
    fn spdx_partial_json_doesnt_panic(
        version in "SPDX-[0-9]\\.[0-9]",
        extra in "\\PC{0,200}",
    ) {
        let input = format!(r#"{{"spdxVersion": "{}", "SPDXID": "SPDXRef-DOCUMENT", {}}}"#, version, extra);
        let _ = parse_sbom_str(&input);
    }

    #[test]
    fn spdx3_partial_json_doesnt_panic(
        extra in "\\PC{0,200}",
    ) {
        let input = format!(
            r#"{{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "type": "SpdxDocument", "spdxId": "urn:test", {extra}}}"#
        );
        let _ = parse_sbom_str(&input);
        let _ = detect_format(&input);
    }

    #[test]
    fn spdx3_security_profile_doesnt_panic(
        score in 0.0f32..10.0f32,
        vector in "[A-Z:/0-9]{0,50}",
        extra in "\\PC{0,100}",
    ) {
        let input = format!(
            r#"{{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "type": "SpdxDocument", "spdxId": "urn:test", "element": [
                {{"type": "software_Package", "spdxId": "urn:pkg:a", "name": "a"}},
                {{"type": "security_Vulnerability", "spdxId": "urn:vuln:1", "name": "CVE-TEST"}},
                {{"type": "security_CvssV3VulnAssessmentRelationship", "spdxId": "urn:assess:1", "from": "urn:vuln:1", "assessedElement": "urn:pkg:a", "score": {score}, "vector": "{vector}", {extra}}}
            ]}}"#
        );
        let _ = parse_sbom_str(&input);
    }
}
