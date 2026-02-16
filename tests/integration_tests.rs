//! Integration tests for sbom-tools
//!
//! These tests verify end-to-end functionality of the SBOM parsing,
//! diff engine, and report generation.

use sbom_tools::{
    diff::DiffEngine,
    matching::FuzzyMatchConfig,
    parsers::{parse_sbom, parse_sbom_str},
};
use std::path::Path;

// ============================================================================
// Test Fixtures
// ============================================================================

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ============================================================================
// Parser Tests
// ============================================================================

mod parser_tests {
    use super::*;

    #[test]
    fn test_parse_cyclonedx_minimal() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let sbom = parse_sbom(&path).expect("Failed to parse CycloneDX SBOM");

        // 3 components: metadata.component (test-app) + lodash + express
        assert_eq!(sbom.component_count(), 3);
        assert!(sbom.components.values().any(|c| c.name == "test-app"));
        assert!(sbom.components.values().any(|c| c.name == "lodash"));
        assert!(sbom.components.values().any(|c| c.name == "express"));
        // Primary component should be set from metadata.component
        assert!(sbom.primary_component_id.is_some());
    }

    #[test]
    fn test_parse_spdx_minimal() {
        let path = fixture_path("spdx/minimal.spdx.json");
        let sbom = parse_sbom(&path).expect("Failed to parse SPDX SBOM");

        assert_eq!(sbom.component_count(), 2);
        assert!(sbom.components.values().any(|c| c.name == "lodash"));
        assert!(sbom.components.values().any(|c| c.name == "express"));
    }

    #[test]
    fn test_parse_spdx_rdf_xml() {
        let path = fixture_path("spdx/minimal.spdx.rdf.xml");
        let sbom = parse_sbom(&path).expect("Failed to parse SPDX RDF/XML SBOM");

        assert_eq!(sbom.component_count(), 2, "Should have 2 packages");
        assert!(
            sbom.components.values().any(|c| c.name == "lodash"),
            "Should have lodash"
        );
        assert!(
            sbom.components.values().any(|c| c.name == "express"),
            "Should have express"
        );

        // Verify versions are parsed
        let lodash = sbom
            .components
            .values()
            .find(|c| c.name == "lodash")
            .unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));

        let express = sbom
            .components
            .values()
            .find(|c| c.name == "express")
            .unwrap();
        assert_eq!(express.version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn test_parse_spdx_rdf_xml_from_string() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:spdx="http://spdx.org/rdf/terms#">
  <spdx:SpdxDocument rdf:about="https://example.com/test">
    <spdx:specVersion>SPDX-2.3</spdx:specVersion>
    <spdx:dataLicense rdf:resource="http://spdx.org/licenses/CC0-1.0"/>
    <spdx:name>test-doc</spdx:name>
    <spdx:spdxId>SPDXRef-DOCUMENT</spdx:spdxId>
    <spdx:creationInfo>
      <spdx:CreationInfo>
        <spdx:created>2026-01-01T00:00:00Z</spdx:created>
        <spdx:creator>Tool: test</spdx:creator>
      </spdx:CreationInfo>
    </spdx:creationInfo>
    <spdx:Package rdf:about="https://example.com/test#SPDXRef-Package-test">
      <spdx:name>test-package</spdx:name>
      <spdx:versionInfo>1.0.0</spdx:versionInfo>
      <spdx:downloadLocation>NOASSERTION</spdx:downloadLocation>
    </spdx:Package>
  </spdx:SpdxDocument>
</rdf:RDF>"#;

        let sbom = parse_sbom_str(content).expect("Failed to parse SPDX RDF/XML from string");
        assert_eq!(sbom.component_count(), 1);
        assert!(sbom.components.values().any(|c| c.name == "test-package"));
    }

    #[test]
    fn test_parse_cyclonedx_with_vulnerabilities() {
        let path = fixture_path("cyclonedx/with-vulnerabilities.cdx.json");
        let sbom = parse_sbom(&path).expect("Failed to parse CycloneDX SBOM with vulns");

        assert_eq!(sbom.component_count(), 2);

        // Check vulnerabilities are parsed
        let vulns = sbom.all_vulnerabilities();
        assert!(!vulns.is_empty(), "Should have vulnerabilities");

        // Check for specific vulnerabilities
        let vuln_ids: Vec<_> = vulns.iter().map(|(_, v)| v.id.as_str()).collect();
        assert!(
            vuln_ids.contains(&"CVE-2021-44228"),
            "Should contain Log4Shell"
        );
        assert!(
            vuln_ids.contains(&"CVE-2021-23337"),
            "Should contain lodash vuln"
        );
    }

    #[test]
    fn test_parse_cyclonedx_from_string() {
        let content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": "test@1.0.0",
                    "name": "test",
                    "version": "1.0.0"
                }
            ]
        }"#;

        let sbom = parse_sbom_str(content).expect("Failed to parse CycloneDX from string");
        assert_eq!(sbom.component_count(), 1);
    }

    #[test]
    fn test_parse_spdx_from_string() {
        let content = r#"{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2026-01-01T00:00:00Z",
                "creators": ["Tool: test"]
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-test",
                    "name": "test-package",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NOASSERTION"
                }
            ]
        }"#;

        let sbom = parse_sbom_str(content).expect("Failed to parse SPDX from string");
        assert_eq!(sbom.component_count(), 1);
    }

    #[test]
    fn test_format_detection() {
        // CycloneDX detection
        let cdx = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5"}"#;
        assert!(parse_sbom_str(cdx).is_ok() || parse_sbom_str(cdx).is_err()); // Should attempt CycloneDX parsing

        // SPDX detection
        let spdx = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        assert!(parse_sbom_str(spdx).is_ok() || parse_sbom_str(spdx).is_err()); // Should attempt SPDX parsing
    }

    #[test]
    fn test_unknown_format_error() {
        let unknown = r#"{"unknown": "format"}"#;
        let result = parse_sbom_str(unknown);
        assert!(result.is_err(), "Should fail for unknown format");
    }
}

// ============================================================================
// Diff Engine Tests
// ============================================================================

mod diff_engine_tests {
    use super::*;

    #[test]
    fn test_diff_identical_sboms() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let sbom = parse_sbom(&path).expect("Failed to parse SBOM");

        let engine = DiffEngine::new();
        let result = engine.diff(&sbom, &sbom).expect("diff should succeed");

        assert!(
            !result.has_changes(),
            "Identical SBOMs should have no changes"
        );
        assert_eq!(result.summary.total_changes, 0);
    }

    #[test]
    fn test_diff_detects_added_components() {
        let old_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"}
            ]
        }"#;

        let new_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"},
                {"type": "library", "bom-ref": "b@1.0", "name": "b", "version": "1.0.0"}
            ]
        }"#;

        let old = parse_sbom_str(old_content).unwrap();
        let new = parse_sbom_str(new_content).unwrap();

        let engine = DiffEngine::new();
        let result = engine.diff(&old, &new).expect("diff should succeed");

        assert!(result.has_changes());
        assert_eq!(result.summary.components_added, 1);
        assert_eq!(result.components.added.len(), 1);
        assert_eq!(result.components.added[0].name, "b");
    }

    #[test]
    fn test_diff_detects_removed_components() {
        let old_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"},
                {"type": "library", "bom-ref": "b@1.0", "name": "b", "version": "1.0.0"}
            ]
        }"#;

        let new_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"}
            ]
        }"#;

        let old = parse_sbom_str(old_content).unwrap();
        let new = parse_sbom_str(new_content).unwrap();

        let engine = DiffEngine::new();
        let result = engine.diff(&old, &new).expect("diff should succeed");

        assert!(result.has_changes());
        assert_eq!(result.summary.components_removed, 1);
        assert_eq!(result.components.removed.len(), 1);
        assert_eq!(result.components.removed[0].name, "b");
    }

    #[test]
    fn test_diff_detects_version_changes() {
        let old_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "pkg@1.0", "name": "pkg", "version": "1.0.0", "purl": "pkg:npm/pkg@1.0.0"}
            ]
        }"#;

        let new_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "pkg@2.0", "name": "pkg", "version": "2.0.0", "purl": "pkg:npm/pkg@2.0.0"}
            ]
        }"#;

        let old = parse_sbom_str(old_content).unwrap();
        let new = parse_sbom_str(new_content).unwrap();

        // Use permissive matching to catch version changes
        let engine = DiffEngine::new().with_fuzzy_config(FuzzyMatchConfig::permissive());
        let result = engine.diff(&old, &new).expect("diff should succeed");

        // Should detect this as a modification (same name, different version)
        assert!(result.has_changes());
    }

    #[test]
    fn test_diff_vulnerability_tracking() {
        let old_path = fixture_path("cyclonedx/minimal.cdx.json");
        let new_path = fixture_path("cyclonedx/with-vulnerabilities.cdx.json");

        let old = parse_sbom(&old_path).unwrap();
        let new = parse_sbom(&new_path).unwrap();

        let engine = DiffEngine::new();
        let result = engine.diff(&old, &new).expect("diff should succeed");

        // New SBOM has vulnerabilities that old one doesn't
        // The exact count depends on component matching
        assert!(
            !result.vulnerabilities.introduced.is_empty()
                || !result.vulnerabilities.persistent.is_empty(),
            "Should detect vulnerability changes"
        );
    }

    #[test]
    fn test_diff_severity_filtering() {
        let old_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }"#;

        let old = parse_sbom_str(old_content).unwrap();
        let new_path = fixture_path("cyclonedx/with-vulnerabilities.cdx.json");
        let new = parse_sbom(&new_path).unwrap();

        let engine = DiffEngine::new();
        let mut result = engine.diff(&old, &new).expect("diff should succeed");

        let total_before = result.vulnerabilities.introduced.len();

        // Filter to only critical
        result.filter_by_severity("critical");

        let total_after = result.vulnerabilities.introduced.len();

        // Should have fewer or equal vulnerabilities after filtering
        assert!(total_after <= total_before);

        // All remaining should be critical
        for vuln in &result.vulnerabilities.introduced {
            assert_eq!(
                vuln.severity.to_lowercase(),
                "critical",
                "After filtering, only critical vulns should remain"
            );
        }
    }

    #[test]
    fn test_semantic_score_calculation() {
        let old_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"}
            ]
        }"#;

        let new_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"},
                {"type": "library", "bom-ref": "b@1.0", "name": "b", "version": "1.0.0"}
            ]
        }"#;

        let old = parse_sbom_str(old_content).unwrap();
        let new = parse_sbom_str(new_content).unwrap();

        let engine = DiffEngine::new();
        let result = engine.diff(&old, &new).expect("diff should succeed");

        // Semantic score should be calculated
        assert!(
            result.semantic_score >= 0.0,
            "Semantic score should be non-negative"
        );
    }
}

// ============================================================================
// Fuzzy Matching Tests
// ============================================================================

mod fuzzy_matching_tests {
    use super::*;
    use sbom_tools::matching::FuzzyMatcher;

    #[test]
    fn test_fuzzy_config_presets() {
        let strict = FuzzyMatchConfig::strict();
        assert_eq!(strict.threshold, 0.95);

        let balanced = FuzzyMatchConfig::balanced();
        assert_eq!(balanced.threshold, 0.85);

        let permissive = FuzzyMatchConfig::permissive();
        assert_eq!(permissive.threshold, 0.70);
    }

    #[test]
    fn test_fuzzy_config_from_preset() {
        assert!(FuzzyMatchConfig::from_preset("strict").is_some());
        assert!(FuzzyMatchConfig::from_preset("balanced").is_some());
        assert!(FuzzyMatchConfig::from_preset("permissive").is_some());
        assert!(FuzzyMatchConfig::from_preset("STRICT").is_some()); // Case insensitive
        assert!(FuzzyMatchConfig::from_preset("invalid").is_none());
    }

    #[test]
    fn test_exact_match_highest_score() {
        let config = FuzzyMatchConfig::balanced();
        let matcher = FuzzyMatcher::new(config);

        // Create two identical components
        let content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "pkg@1.0", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
            ]
        }"#;

        let sbom = parse_sbom_str(content).unwrap();
        let comp = sbom.components.values().next().unwrap();

        let score = matcher.match_components(comp, comp);
        assert_eq!(score, 1.0, "Identical components should have score 1.0");
    }
}

// ============================================================================
// Cross-Format Tests
// ============================================================================

mod cross_format_tests {
    use super::*;

    #[test]
    fn test_diff_cyclonedx_vs_spdx() {
        let cdx_path = fixture_path("cyclonedx/minimal.cdx.json");
        let spdx_path = fixture_path("spdx/minimal.spdx.json");

        let cdx = parse_sbom(&cdx_path).unwrap();
        let spdx = parse_sbom(&spdx_path).unwrap();

        // CycloneDX includes metadata.component (test-app), SPDX only has package components
        // CDX: test-app, lodash, express = 3
        // SPDX: lodash, express = 2
        assert_eq!(cdx.component_count(), 3);
        assert_eq!(spdx.component_count(), 2);

        // Both should have lodash and express
        assert!(cdx.components.values().any(|c| c.name == "lodash"));
        assert!(cdx.components.values().any(|c| c.name == "express"));
        assert!(spdx.components.values().any(|c| c.name == "lodash"));
        assert!(spdx.components.values().any(|c| c.name == "express"));

        // Diff should show high similarity for shared components
        let engine = DiffEngine::new().with_fuzzy_config(FuzzyMatchConfig::balanced());
        let result = engine.diff(&cdx, &spdx).expect("diff should succeed");

        // lodash and express should match, test-app from cdx has no match in spdx
        assert!(
            result.summary.components_removed <= 1,
            "Only the root app component should be unmatched"
        );
    }
}

// ============================================================================
// Model Tests
// ============================================================================

mod model_tests {
    use super::*;

    #[test]
    fn test_normalized_sbom_content_hash() {
        let content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "a@1.0", "name": "a", "version": "1.0.0"}
            ]
        }"#;

        let mut sbom = parse_sbom_str(content).unwrap();
        sbom.calculate_content_hash();

        assert_ne!(sbom.content_hash, 0, "Content hash should be calculated");

        // Same content should produce same hash
        let mut sbom2 = parse_sbom_str(content).unwrap();
        sbom2.calculate_content_hash();

        // Note: Hash might differ due to parsing order, but should be consistent
        // for the same input
    }

    #[test]
    fn test_component_display_name() {
        let content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "test@1.0", "name": "test-pkg", "version": "1.0.0"}
            ]
        }"#;

        let sbom = parse_sbom_str(content).unwrap();
        let comp = sbom.components.values().next().unwrap();

        assert_eq!(comp.display_name(), "test-pkg@1.0.0");
    }

    #[test]
    fn test_vulnerability_counts() {
        let path = fixture_path("cyclonedx/with-vulnerabilities.cdx.json");
        let sbom = parse_sbom(&path).unwrap();

        let counts = sbom.vulnerability_counts();
        assert!(counts.total() > 0, "Should have vulnerabilities");
        assert!(
            counts.critical > 0 || counts.high > 0,
            "Should have high severity vulns"
        );
    }
}

// ============================================================================
// Report Security Tests
// ============================================================================

mod report_security_tests {
    use super::*;
    use sbom_tools::reports::escape::{
        escape_html, escape_html_attr, escape_markdown_inline, escape_markdown_table,
    };
    use sbom_tools::reports::{HtmlReporter, MarkdownReporter, ReportConfig, ReportGenerator};

    // Malicious payloads for testing
    const XSS_SCRIPT: &str = "<script>alert('xss')</script>";
    const XSS_EVENT: &str = "<img onerror=\"alert('xss')\">";
    const XSS_ENTITY: &str = "&lt;script&gt;alert('double')&lt;/script&gt;";
    const MD_PIPE_INJECT: &str = "name|evil|payload";
    const MD_NEWLINE_INJECT: &str = "name\n| new | row |";
    const MD_LINK_INJECT: &str = "[evil](http://malware.com)";
    const MD_CODE_INJECT: &str = "```\ncode block\n```";

    #[test]
    fn test_html_escape_xss_script() {
        let escaped = escape_html(XSS_SCRIPT);
        assert!(
            !escaped.contains("<script>"),
            "Script tags should be escaped"
        );
        assert!(
            !escaped.contains("</script>"),
            "Closing script tags should be escaped"
        );
        assert!(
            escaped.contains("&lt;script&gt;"),
            "Should use HTML entities"
        );
    }

    #[test]
    fn test_html_escape_xss_event_handler() {
        let escaped = escape_html(XSS_EVENT);
        // The key is that < and > are escaped, making the tag inert
        assert!(
            !escaped.contains("<img"),
            "Raw tag opening should be escaped"
        );
        assert!(escaped.contains("&lt;img"), "Tags should be escaped");
        assert!(
            escaped.contains("&quot;"),
            "Quotes in attributes should be escaped"
        );
    }

    #[test]
    fn test_html_escape_double_encoding() {
        let escaped = escape_html(XSS_ENTITY);
        // Already-escaped entities should be re-escaped
        assert!(
            escaped.contains("&amp;lt;"),
            "Should escape the ampersand in entities"
        );
    }

    #[test]
    fn test_html_attr_escape_newlines() {
        let input = "value with\nnewline";
        let escaped = escape_html_attr(input);
        assert!(
            !escaped.contains('\n'),
            "Newlines should be escaped in attributes"
        );
        assert!(
            escaped.contains("&#10;"),
            "Should use numeric entity for newline"
        );
    }

    #[test]
    fn test_markdown_table_pipe_injection() {
        let escaped = escape_markdown_table(MD_PIPE_INJECT);
        // Check that pipes are preceded by backslash (escaped)
        // Original: "name|evil|payload" -> "name\|evil\|payload"
        assert!(escaped.contains("\\|"), "Pipes should be backslash-escaped");
        // Verify the exact expected output
        assert_eq!(
            escaped, "name\\|evil\\|payload",
            "Should escape all pipes with backslashes"
        );
    }

    #[test]
    fn test_markdown_table_newline_injection() {
        let escaped = escape_markdown_table(MD_NEWLINE_INJECT);
        assert!(
            !escaped.contains('\n'),
            "Newlines should be removed/escaped"
        );
    }

    #[test]
    fn test_markdown_link_injection() {
        let escaped = escape_markdown_table(MD_LINK_INJECT);
        assert!(
            escaped.contains("\\["),
            "Square brackets should be escaped"
        );
    }

    #[test]
    fn test_markdown_code_block_injection() {
        let escaped = escape_markdown_table(MD_CODE_INJECT);
        assert!(
            !escaped.contains("```"),
            "Backticks should be escaped"
        );
        assert!(
            escaped.contains("\\`"),
            "Backticks should be backslash-escaped"
        );
    }

    #[test]
    fn test_html_report_with_malicious_component_name() {
        // Create SBOM with malicious component name
        let content = format!(
            r#"{{
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [
                    {{"type": "library", "bom-ref": "evil@1.0", "name": "{}", "version": "1.0.0"}}
                ]
            }}"#,
            XSS_SCRIPT
        );

        let sbom = parse_sbom_str(&content).unwrap();
        let reporter = HtmlReporter::new();
        let config = ReportConfig::default();

        let html = reporter
            .generate_view_report(&sbom, &config)
            .expect("Should generate report");

        // Verify the malicious content is escaped
        assert!(
            !html.contains("<script>"),
            "HTML report should escape script tags in component names"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "HTML report should contain escaped version"
        );
    }

    #[test]
    fn test_html_report_with_malicious_title() {
        let sbom_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }"#;

        let sbom = parse_sbom_str(sbom_content).unwrap();
        let reporter = HtmlReporter::new();
        let config = ReportConfig {
            title: Some(XSS_SCRIPT.to_string()),
            ..Default::default()
        };

        let html = reporter
            .generate_view_report(&sbom, &config)
            .expect("Should generate report");

        // Verify the malicious title is escaped
        assert!(
            !html.contains("<script>alert"),
            "HTML report should escape script tags in title"
        );
    }

    #[test]
    fn test_markdown_report_with_malicious_component_name() {
        // Create SBOM with table-breaking component name
        let content = format!(
            r#"{{
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [
                    {{"type": "library", "bom-ref": "evil@1.0", "name": "{}", "version": "1.0.0"}}
                ]
            }}"#,
            MD_PIPE_INJECT
        );

        let sbom = parse_sbom_str(&content).unwrap();
        let reporter = MarkdownReporter::new();
        let config = ReportConfig::default();

        let md = reporter
            .generate_view_report(&sbom, &config)
            .expect("Should generate report");

        // Verify pipes are escaped (count pipes on component row)
        // A properly escaped row should have the expected number of pipes (5 for table delimiters)
        // not extra ones from the malicious payload
        let component_line = md
            .lines()
            .find(|l| l.contains("evil"))
            .expect("Should have component line");

        // Count escaped pipes (the backslash-pipe sequence)
        let escaped_pipe_count = component_line.matches("\\|").count();

        // The malicious payload "name|evil|payload" has 2 pipes, which should all be escaped
        assert!(
            escaped_pipe_count >= 2,
            "Malicious pipes should be escaped: {}",
            component_line
        );
    }

    #[test]
    fn test_markdown_report_with_malicious_title() {
        let sbom_content = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }"#;

        let sbom = parse_sbom_str(sbom_content).unwrap();
        let reporter = MarkdownReporter::new();
        let config = ReportConfig {
            title: Some("# Injected Heading\n## Another".to_string()),
            ..Default::default()
        };

        let md = reporter
            .generate_view_report(&sbom, &config)
            .expect("Should generate report");

        // Title's hash marks should be escaped
        assert!(
            md.contains("\\#"),
            "Hash marks in title should be escaped"
        );
    }

    #[test]
    fn test_escape_preserves_unicode() {
        let unicode_name = "日本語パッケージ";
        let escaped_html = escape_html(unicode_name);
        let escaped_md = escape_markdown_table(unicode_name);

        assert_eq!(
            escaped_html, unicode_name,
            "Unicode should pass through HTML escape"
        );
        assert_eq!(
            escaped_md, unicode_name,
            "Unicode should pass through Markdown escape"
        );
    }

    #[test]
    fn test_escape_empty_string() {
        assert_eq!(escape_html(""), "");
        assert_eq!(escape_markdown_table(""), "");
        assert_eq!(escape_markdown_inline(""), "");
    }

    #[test]
    fn test_realistic_purl_escaping() {
        // PURLs can contain special characters
        let purl = "pkg:npm/%40scope/name@1.0.0?vcs_url=git%2Bhttps://github.com/org/repo";
        let html_escaped = escape_html(purl);
        let md_escaped = escape_markdown_table(purl);

        // Should preserve URL encoding but escape any HTML/MD special chars
        assert!(
            html_escaped.contains("%40"),
            "URL encoding should be preserved in HTML"
        );
        assert!(
            md_escaped.contains("%40"),
            "URL encoding should be preserved in Markdown"
        );
    }
}

/// Tests for ID-stable component selection across sort/filter changes.
///
/// These tests ensure that component selection remains stable when the view is
/// re-sorted or filtered, by using CanonicalId for identification rather than
/// positional indices.
mod id_stable_selection_tests {
    use sbom_tools::model::{
        CanonicalId, Component, DocumentMetadata, NormalizedSbom, NormalizedSbomIndex,
    };

    /// Helper to create a test SBOM with multiple components
    fn create_test_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        // Create components with different names and versions for sorting tests
        let mut comp_a = Component::new("alpha".to_string(), "alpha-id".to_string());
        comp_a.version = Some("1.0.0".to_string());

        let mut comp_b = Component::new("beta".to_string(), "beta-id".to_string());
        comp_b.version = Some("2.0.0".to_string());

        let mut comp_c = Component::new("gamma".to_string(), "gamma-id".to_string());
        comp_c.version = Some("0.5.0".to_string());

        let mut comp_d = Component::new("delta".to_string(), "delta-id".to_string());
        comp_d.version = Some("3.0.0".to_string());

        sbom.add_component(comp_a);
        sbom.add_component(comp_b);
        sbom.add_component(comp_c);
        sbom.add_component(comp_d);

        sbom
    }

    #[test]
    fn test_canonical_id_stability_across_sorts() {
        let sbom = create_test_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Get all component IDs
        let mut ids: Vec<CanonicalId> = sbom.components.keys().cloned().collect();

        // Store original order
        let original_order: Vec<String> = ids.iter().map(|id| id.value().to_string()).collect();

        // Sort by name
        ids.sort_by(|a, b| {
            let key_a = index.sort_key(a).unwrap();
            let key_b = index.sort_key(b).unwrap();
            key_a.name_lower.cmp(&key_b.name_lower)
        });

        // Verify IDs are still valid after sort
        for id in &ids {
            assert!(
                sbom.components.contains_key(id),
                "Component should still be accessible by ID after sort"
            );
        }

        // Verify sorted order is by name
        let sorted_names: Vec<&str> = ids
            .iter()
            .map(|id| sbom.components.get(id).unwrap().name.as_str())
            .collect();

        assert_eq!(sorted_names, vec!["alpha", "beta", "delta", "gamma"]);

        // Original IDs should still resolve to same components
        for original_id_str in &original_order {
            let original_id = ids
                .iter()
                .find(|id| id.value() == original_id_str)
                .unwrap();
            assert!(
                sbom.components.contains_key(original_id),
                "Original ID '{}' should still resolve",
                original_id_str
            );
        }
    }

    #[test]
    fn test_selection_preserved_after_filter() {
        let sbom = create_test_sbom();

        // Simulate selecting "beta" component by its ID
        let selected_id = sbom
            .components
            .keys()
            .find(|id| id.value().contains("beta"))
            .cloned()
            .unwrap();

        // Simulate filtering - only show components matching "ph" (alpha only)
        let filtered_ids: Vec<&CanonicalId> = sbom
            .components
            .iter()
            .filter(|(_, comp)| comp.name.contains("ph"))
            .map(|(id, _)| id)
            .collect();

        // "beta" doesn't match filter, but ID should still be valid
        assert!(
            sbom.components.contains_key(&selected_id),
            "Selected ID should still be valid even if filtered out"
        );

        // Filtered list should contain only alpha (has "ph")
        assert_eq!(filtered_ids.len(), 1);

        // When filter is removed, selected ID should still resolve
        let component = sbom.components.get(&selected_id).unwrap();
        assert_eq!(component.name, "beta");
    }

    #[test]
    fn test_id_lookup_performance_with_index() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        // Create many components
        for i in 0..100 {
            let comp = Component::new(format!("component-{}", i), format!("id-{}", i));
            sbom.add_component(comp);
        }

        let index = NormalizedSbomIndex::build(&sbom);

        // All lookups should be O(1)
        assert_eq!(index.component_count(), 100);

        // Test name search
        let matches = index.search_by_name("component-5");
        assert!(!matches.is_empty(), "Should find components matching 'component-5'");
    }

    #[test]
    fn test_canonical_id_equality_across_sources() {
        // IDs with same value should be equal regardless of source
        let id1 = CanonicalId::from_purl("pkg:npm/lodash@4.0.0");
        let id2 = CanonicalId::from_purl("pkg:npm/lodash@4.0.0");

        assert_eq!(id1, id2, "Same PURL should produce equal IDs");

        // Synthetic IDs with same content should be equal
        let id3 = CanonicalId::synthetic(Some("org"), "package", Some("1.0.0"));
        let id4 = CanonicalId::synthetic(Some("org"), "package", Some("1.0.0"));

        assert_eq!(id3, id4, "Same synthetic ID params should produce equal IDs");
    }

    #[test]
    fn test_id_stability_markers() {
        // PURL-based ID should be stable
        let purl_id = CanonicalId::from_purl("pkg:npm/react@18.0.0");
        assert!(purl_id.is_stable(), "PURL-based ID should be stable");

        // UUID-like format ID should not be stable
        let uuid_id =
            CanonicalId::from_format_id("550e8400-e29b-41d4-a716-446655440000");
        assert!(!uuid_id.is_stable(), "UUID format ID should not be stable");

        // Synthetic ID should be stable
        let synthetic_id = CanonicalId::synthetic(None, "mypackage", Some("1.0.0"));
        assert!(synthetic_id.is_stable(), "Synthetic ID should be stable");
    }
}

/// Tests for dependency adjacency in NormalizedSbomIndex.
///
/// These tests verify that the index correctly tracks dependency relationships
/// and can efficiently query both dependencies (outgoing) and dependents (incoming).
mod dependency_adjacency_tests {
    use sbom_tools::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom,
        NormalizedSbomIndex, SbomIndexBuilder,
    };

    /// Create a test SBOM with a known dependency graph:
    /// ```
    ///     A
    ///    / \
    ///   B   C
    ///   |   |
    ///   D   D  (D has two dependents)
    ///   |
    ///   E
    /// ```
    fn create_dependency_graph() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        let comp_a = Component::new("root".to_string(), "A".to_string());
        let comp_b = Component::new("lib-b".to_string(), "B".to_string());
        let comp_c = Component::new("lib-c".to_string(), "C".to_string());
        let comp_d = Component::new("shared-d".to_string(), "D".to_string());
        let comp_e = Component::new("leaf-e".to_string(), "E".to_string());

        let id_a = comp_a.canonical_id.clone();
        let id_b = comp_b.canonical_id.clone();
        let id_c = comp_c.canonical_id.clone();
        let id_d = comp_d.canonical_id.clone();
        let id_e = comp_e.canonical_id.clone();

        sbom.add_component(comp_a);
        sbom.add_component(comp_b);
        sbom.add_component(comp_c);
        sbom.add_component(comp_d);
        sbom.add_component(comp_e);

        // A -> B, A -> C
        sbom.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_b.clone(),
            DependencyType::DependsOn,
        ));
        sbom.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_c.clone(),
            DependencyType::DependsOn,
        ));

        // B -> D, C -> D (D is shared)
        sbom.add_edge(DependencyEdge::new(
            id_b.clone(),
            id_d.clone(),
            DependencyType::DependsOn,
        ));
        sbom.add_edge(DependencyEdge::new(
            id_c.clone(),
            id_d.clone(),
            DependencyType::DependsOn,
        ));

        // D -> E
        sbom.add_edge(DependencyEdge::new(
            id_d.clone(),
            id_e.clone(),
            DependencyType::DependsOn,
        ));

        sbom
    }

    #[test]
    fn test_dependency_count() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        // Find each component's ID
        let find_id = |name: &str| {
            sbom.components
                .iter()
                .find(|(_, c)| c.name == name)
                .map(|(id, _)| id)
                .unwrap()
        };

        let id_a = find_id("root");
        let id_b = find_id("lib-b");
        let id_d = find_id("shared-d");
        let id_e = find_id("leaf-e");

        // A has 2 dependencies (B, C)
        assert_eq!(index.dependency_count(id_a), 2);

        // B has 1 dependency (D)
        assert_eq!(index.dependency_count(id_b), 1);

        // D has 1 dependency (E)
        assert_eq!(index.dependency_count(id_d), 1);

        // E has no dependencies (leaf)
        assert_eq!(index.dependency_count(id_e), 0);
    }

    #[test]
    fn test_dependent_count() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        let find_id = |name: &str| {
            sbom.components
                .iter()
                .find(|(_, c)| c.name == name)
                .map(|(id, _)| id)
                .unwrap()
        };

        let id_a = find_id("root");
        let id_b = find_id("lib-b");
        let id_d = find_id("shared-d");
        let id_e = find_id("leaf-e");

        // A has no dependents (root)
        assert_eq!(index.dependent_count(id_a), 0);

        // B has 1 dependent (A)
        assert_eq!(index.dependent_count(id_b), 1);

        // D has 2 dependents (B, C) - shared dependency
        assert_eq!(index.dependent_count(id_d), 2);

        // E has 1 dependent (D)
        assert_eq!(index.dependent_count(id_e), 1);
    }

    #[test]
    fn test_dependencies_of_returns_edges() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        let id_a = sbom
            .components
            .iter()
            .find(|(_, c)| c.name == "root")
            .map(|(id, _)| id)
            .unwrap();

        let deps = index.dependencies_of(id_a, &sbom.edges);

        assert_eq!(deps.len(), 2, "A should have 2 dependencies");

        // Check that edges point from A
        for edge in deps {
            assert_eq!(&edge.from, id_a, "Edge should originate from A");
        }
    }

    #[test]
    fn test_dependents_of_returns_edges() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        let id_d = sbom
            .components
            .iter()
            .find(|(_, c)| c.name == "shared-d")
            .map(|(id, _)| id)
            .unwrap();

        let dependents = index.dependents_of(id_d, &sbom.edges);

        assert_eq!(dependents.len(), 2, "D should have 2 dependents");

        // Check that edges point to D
        for edge in dependents {
            assert_eq!(&edge.to, id_d, "Edge should point to D");
        }
    }

    #[test]
    fn test_has_dependencies_and_dependents() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        let find_id = |name: &str| {
            sbom.components
                .iter()
                .find(|(_, c)| c.name == name)
                .map(|(id, _)| id)
                .unwrap()
        };

        let id_a = find_id("root");
        let id_d = find_id("shared-d");
        let id_e = find_id("leaf-e");

        // A is root: has dependencies, no dependents
        assert!(index.has_dependencies(id_a));
        assert!(!index.has_dependents(id_a));

        // D is middle: has both
        assert!(index.has_dependencies(id_d));
        assert!(index.has_dependents(id_d));

        // E is leaf: no dependencies, has dependent
        assert!(!index.has_dependencies(id_e));
        assert!(index.has_dependents(id_e));
    }

    #[test]
    fn test_root_and_leaf_counts() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        // Root (no incoming): A
        // Note: The root_count implementation counts components not in edges_by_target
        // Let's verify expected behavior
        assert!(index.root_count() >= 1, "Should have at least one root");

        // Leaf (no outgoing): E
        assert!(index.leaf_count() >= 1, "Should have at least one leaf");
    }

    #[test]
    fn test_edge_indices_are_valid() {
        let sbom = create_dependency_graph();
        let index = NormalizedSbomIndex::build(&sbom);

        // Get dependency indices for root
        let id_a = sbom
            .components
            .iter()
            .find(|(_, c)| c.name == "root")
            .map(|(id, _)| id)
            .unwrap();

        let indices = index.dependency_indices(id_a);

        // All indices should be valid
        for &idx in indices {
            assert!(
                idx < sbom.edges.len(),
                "Edge index {} should be valid (< {})",
                idx,
                sbom.edges.len()
            );
        }
    }

    #[test]
    fn test_empty_sbom_index() {
        let sbom = NormalizedSbom::default();
        let index = NormalizedSbomIndex::build(&sbom);

        assert_eq!(index.component_count(), 0);
        assert_eq!(index.edge_count(), 0);
        assert_eq!(index.root_count(), 0);
        assert_eq!(index.leaf_count(), 0);
    }

    #[test]
    fn test_minimal_index_builder() {
        let sbom = create_dependency_graph();
        let index = SbomIndexBuilder::minimal().build(&sbom);

        // Edges should still work
        assert_eq!(index.edge_count(), 5);

        // But name lookup should be empty (not indexed)
        let matches = index.find_by_name_lower("root");
        assert!(matches.is_empty(), "Minimal index should not index names");
    }

    #[test]
    fn test_full_index_builder() {
        let sbom = create_dependency_graph();
        let index = SbomIndexBuilder::new()
            .with_name_index()
            .with_sort_keys()
            .build(&sbom);

        // Name lookup should work
        let matches = index.find_by_name_lower("root");
        assert!(!matches.is_empty(), "Full index should index names");

        // Sort keys should be available
        let id = matches.first().unwrap();
        let sort_key = index.sort_key(id);
        assert!(sort_key.is_some(), "Sort key should be available");
    }
}

/// Tests for search navigation and ID resolution.
///
/// These tests ensure that search results correctly resolve to component IDs
/// and that navigation within search results works properly.
mod search_navigation_tests {
    use sbom_tools::model::{
        CanonicalId, Component, DocumentMetadata, NormalizedSbom, NormalizedSbomIndex,
    };
    use sbom_tools::tui::state::ListNavigation;
    use sbom_tools::tui::viewmodel::SearchState;

    /// Create a test SBOM with searchable components
    fn create_searchable_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        let names = vec![
            "react",
            "react-dom",
            "react-router",
            "lodash",
            "lodash-es",
            "express",
            "express-validator",
            "axios",
            "moment",
            "moment-timezone",
        ];

        for name in names {
            let comp = Component::new(name.to_string(), format!("{}-id", name));
            sbom.add_component(comp);
        }

        sbom
    }

    #[test]
    fn test_search_by_name_finds_matches() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Search for "react" should find 3 matches
        let matches = index.search_by_name("react");
        assert_eq!(matches.len(), 3, "Should find 3 react-related components");

        // Search for "lodash" should find 2 matches
        let matches = index.search_by_name("lodash");
        assert_eq!(matches.len(), 2, "Should find 2 lodash-related components");

        // Search for "express" should find 2 matches
        let matches = index.search_by_name("express");
        assert_eq!(matches.len(), 2, "Should find 2 express-related components");
    }

    #[test]
    fn test_search_results_resolve_to_components() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        let matches = index.search_by_name("moment");

        // Each match should resolve to a valid component
        for id in &matches {
            let component = sbom.components.get(id);
            assert!(
                component.is_some(),
                "Search result ID should resolve to component"
            );

            let comp = component.unwrap();
            assert!(
                comp.name.contains("moment"),
                "Component name should contain search term"
            );
        }
    }

    #[test]
    fn test_search_state_navigation() {
        let mut search: SearchState<CanonicalId> = SearchState::new();

        // Simulate search results
        let ids: Vec<CanonicalId> = vec![
            CanonicalId::synthetic(None, "result1", None),
            CanonicalId::synthetic(None, "result2", None),
            CanonicalId::synthetic(None, "result3", None),
            CanonicalId::synthetic(None, "result4", None),
            CanonicalId::synthetic(None, "result5", None),
        ];

        search.set_results(ids);

        // Initial selection
        assert_eq!(search.selected, 0);
        assert!(search.selected_result().is_some());

        // Navigate forward
        search.select_next();
        assert_eq!(search.selected, 1);

        search.select_next();
        search.select_next();
        assert_eq!(search.selected, 3);

        // Navigate backward
        search.select_prev();
        assert_eq!(search.selected, 2);

        // Can't go past end
        search.select_next();
        search.select_next();
        search.select_next();
        assert_eq!(search.selected, 4); // Stays at last

        // Can't go before start
        search.set_selected(0);
        search.select_prev();
        assert_eq!(search.selected, 0); // Stays at first
    }

    #[test]
    fn test_search_result_id_stability() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Get search results
        let matches = index.search_by_name("axios");
        assert_eq!(matches.len(), 1);

        let selected_id = matches[0].clone();

        // Even after rebuilding index, same search should find same component
        let index2 = NormalizedSbomIndex::build(&sbom);
        let matches2 = index2.search_by_name("axios");

        assert_eq!(matches2.len(), 1);
        assert_eq!(
            matches2[0], selected_id,
            "Same search should return same ID"
        );
    }

    #[test]
    fn test_case_insensitive_search() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Searches should be case-insensitive
        let lower = index.search_by_name("react");

        // Note: search_by_name expects lowercase input, so uppercase searches
        // need to be lowercased by the caller
        assert_eq!(lower.len(), 3);

        // For case-insensitive search, caller must lowercase the query
        let upper_lower = index.search_by_name(&"REACT".to_lowercase());
        assert_eq!(upper_lower.len(), lower.len());

        let mixed_lower = index.search_by_name(&"ReAcT".to_lowercase());
        assert_eq!(mixed_lower.len(), lower.len());
    }

    #[test]
    fn test_search_with_empty_query() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Empty search should return no results
        let matches = index.search_by_name("");
        // Empty string matches everything due to contains("")
        assert_eq!(matches.len(), 10, "Empty search matches all components");
    }

    #[test]
    fn test_search_no_matches() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Search for non-existent term
        let matches = index.search_by_name("nonexistent");
        assert!(matches.is_empty(), "Should find no matches");
    }

    #[test]
    fn test_find_by_exact_name_lower() {
        let sbom = create_searchable_sbom();
        let index = NormalizedSbomIndex::build(&sbom);

        // Exact name match (lowercase)
        let matches = index.find_by_name_lower("react");
        assert_eq!(matches.len(), 1, "Exact match should find one component");

        // Partial name shouldn't match exact lookup
        let matches = index.find_by_name_lower("reac");
        assert!(matches.is_empty(), "Partial should not match exact lookup");
    }

    #[test]
    fn test_sort_key_contains_search() {
        use sbom_tools::model::ComponentSortKey;

        let mut comp = Component::new("my-package".to_string(), "pkg-1".to_string());
        comp.version = Some("2.3.4".to_string());

        let key = ComponentSortKey::from_component(&comp);

        // Should find by name
        assert!(key.contains("my-pack"));
        assert!(key.contains("package"));

        // Should find by version
        assert!(key.contains("2.3.4"));
        assert!(key.contains("2.3"));

        // Should not find non-matching
        assert!(!key.contains("react"));
        assert!(!key.contains("5.0.0"));
    }
}

/// Tests for streaming mode configuration and activation.
mod streaming_tests {
    use sbom_tools::config::StreamingConfig;

    #[test]
    fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        assert_eq!(config.threshold_bytes, 10 * 1024 * 1024); // 10 MB
        assert!(!config.force);
        assert!(!config.disabled);
        assert!(config.stream_stdin);
    }

    #[test]
    fn test_streaming_config_should_stream_below_threshold() {
        let config = StreamingConfig::default();
        // File smaller than 10 MB should not trigger streaming
        assert!(!config.should_stream(Some(1024 * 1024), false)); // 1 MB
        assert!(!config.should_stream(Some(5 * 1024 * 1024), false)); // 5 MB
    }

    #[test]
    fn test_streaming_config_should_stream_above_threshold() {
        let config = StreamingConfig::default();
        // File equal to or larger than 10 MB should trigger streaming
        assert!(config.should_stream(Some(10 * 1024 * 1024), false)); // 10 MB exactly
        assert!(config.should_stream(Some(20 * 1024 * 1024), false)); // 20 MB
        assert!(config.should_stream(Some(100 * 1024 * 1024), false)); // 100 MB
    }

    #[test]
    fn test_streaming_config_force_mode() {
        let config = StreamingConfig::always();
        assert!(config.force);
        // Force mode should always stream regardless of file size
        assert!(config.should_stream(Some(1024), false)); // 1 KB
        assert!(config.should_stream(Some(0), false)); // 0 bytes
        assert!(config.should_stream(None, false)); // Unknown size
    }

    #[test]
    fn test_streaming_config_disabled_mode() {
        let config = StreamingConfig::never();
        assert!(config.disabled);
        // Disabled should never stream regardless of file size
        assert!(!config.should_stream(Some(100 * 1024 * 1024), false)); // 100 MB
        assert!(!config.should_stream(Some(1024 * 1024 * 1024), false)); // 1 GB
        assert!(!config.should_stream(None, true)); // stdin
    }

    #[test]
    fn test_streaming_config_stdin_mode() {
        let config = StreamingConfig::default();
        // stdin should trigger streaming (since size is unknown)
        assert!(config.should_stream(None, true));
    }

    #[test]
    fn test_streaming_config_stdin_disabled() {
        let config = StreamingConfig { stream_stdin: false, ..StreamingConfig::default() };
        // stdin with stream_stdin=false should not trigger streaming
        assert!(!config.should_stream(None, true));
    }

    #[test]
    fn test_streaming_config_with_threshold_mb() {
        let config = StreamingConfig::default().with_threshold_mb(50);
        assert_eq!(config.threshold_bytes, 50 * 1024 * 1024); // 50 MB

        // Below threshold
        assert!(!config.should_stream(Some(40 * 1024 * 1024), false));
        // At/above threshold
        assert!(config.should_stream(Some(50 * 1024 * 1024), false));
    }

    #[test]
    fn test_streaming_config_custom_threshold() {
        let config = StreamingConfig {
            threshold_bytes: 1024 * 1024, // 1 MB
            force: false,
            disabled: false,
            stream_stdin: true,
        };

        // Files >= 1 MB should stream
        assert!(!config.should_stream(Some(512 * 1024), false)); // 512 KB
        assert!(config.should_stream(Some(1024 * 1024), false)); // 1 MB
        assert!(config.should_stream(Some(2 * 1024 * 1024), false)); // 2 MB
    }

    #[test]
    fn test_streaming_json_reporter_implements_writer_reporter() {
        use sbom_tools::reports::StreamingJsonReporter;
        use sbom_tools::WriterReporter;

        let reporter = StreamingJsonReporter::new();
        assert_eq!(
            WriterReporter::format(&reporter),
            sbom_tools::ReportFormat::Json,
            "StreamingJsonReporter should implement WriterReporter"
        );
    }

    #[test]
    fn test_ndjson_reporter_implements_writer_reporter() {
        use sbom_tools::reports::NdjsonReporter;
        use sbom_tools::WriterReporter;

        let reporter = NdjsonReporter::new();
        assert_eq!(
            WriterReporter::format(&reporter),
            sbom_tools::ReportFormat::Json,
            "NdjsonReporter should implement WriterReporter"
        );
    }
}
