//! Pipeline and CLI integration tests.
//!
//! These tests exercise the full parse → diff → report pipeline,
//! error handling paths, and CLI command handlers with real fixture files.

use sbom_tools::config::DiffConfigBuilder;
use sbom_tools::pipeline::{
    auto_detect_format, compute_diff, output_report, parse_sbom_with_context, write_output,
    OutputTarget, PipelineError,
};
use sbom_tools::reports::ReportFormat;
use std::path::{Path, PathBuf};

// ============================================================================
// Test Fixtures
// ============================================================================

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ============================================================================
// Pipeline Parse Stage Tests
// ============================================================================

mod parse_stage {
    use super::*;

    #[test]
    fn parse_cyclonedx_fixture() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let parsed = parse_sbom_with_context(&path, true).expect("parse should succeed");

        assert_eq!(parsed.sbom().component_count(), 3);
        assert!(!parsed.raw_content().is_empty());
    }

    #[test]
    fn parse_spdx_fixture() {
        let path = fixture_path("spdx/minimal.spdx.json");
        let parsed = parse_sbom_with_context(&path, true).expect("parse should succeed");

        assert_eq!(parsed.sbom().component_count(), 2);
    }

    #[test]
    fn parse_preserves_raw_content() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let parsed = parse_sbom_with_context(&path, true).expect("parse should succeed");
        let raw = parsed.raw_content();

        // Raw content should be valid JSON containing CycloneDX markers
        assert!(raw.contains("bomFormat"));
        assert!(raw.contains("CycloneDX"));
    }

    #[test]
    fn parse_into_parts_roundtrip() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let parsed = parse_sbom_with_context(&path, true).expect("parse should succeed");
        let count = parsed.sbom().component_count();

        let (sbom, raw) = parsed.into_parts();
        assert_eq!(sbom.component_count(), count);
        assert!(!raw.is_empty());
    }

    #[test]
    fn parse_drop_raw_content_frees_memory() {
        let path = fixture_path("cyclonedx/minimal.cdx.json");
        let mut parsed = parse_sbom_with_context(&path, true).expect("parse should succeed");

        assert!(!parsed.raw_content().is_empty());
        parsed.drop_raw_content();
        assert!(parsed.raw_content().is_empty());
        // SBOM data is still intact
        assert_eq!(parsed.sbom().component_count(), 3);
    }

    #[test]
    fn parse_missing_file_returns_pipeline_error() {
        let path = PathBuf::from("/nonexistent/path/to/sbom.json");
        let result = parse_sbom_with_context(&path, true);
        assert!(result.is_err(), "Missing file should return error");

        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("Parse failed") || msg.contains("nonexistent"),
            "Error message should mention parse failure or path: {msg}"
        );
    }

    #[test]
    fn parse_invalid_content_returns_error() {
        // Create a temp file with invalid SBOM content
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("invalid.json");
        std::fs::write(&path, r#"{"not": "an sbom"}"#).expect("write temp file");

        let result = parse_sbom_with_context(&path, true);
        assert!(result.is_err(), "Invalid SBOM should return error");

        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("Parse failed"),
            "Error should indicate parse failure: {msg}"
        );
    }
}

// ============================================================================
// Pipeline Diff Stage Tests
// ============================================================================

mod diff_stage {
    use super::*;

    fn demo_diff_config(old: &str, new: &str) -> sbom_tools::DiffConfig {
        DiffConfigBuilder::new()
            .old_path(fixture_path(old))
            .new_path(fixture_path(new))
            .output_format(ReportFormat::Json)
            .build()
            .expect("valid config")
    }

    #[test]
    fn compute_diff_demo_sboms() {
        let config = demo_diff_config("demo-old.cdx.json", "demo-new.cdx.json");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff should succeed");

        // Demo SBOMs have version changes and added/removed components
        assert!(
            result.summary.total_changes > 0,
            "Demo diff should have changes"
        );
        assert!(result.semantic_score >= 0.0 && result.semantic_score <= 100.0);
    }

    #[test]
    fn compute_diff_identical_sboms() {
        let config = demo_diff_config("cyclonedx/minimal.cdx.json", "cyclonedx/minimal.cdx.json");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff should succeed");

        assert_eq!(
            result.summary.total_changes, 0,
            "Identical SBOMs should have no changes"
        );
    }

    #[test]
    fn compute_diff_cross_format() {
        // CycloneDX vs SPDX - same libraries should match
        let config =
            demo_diff_config("cyclonedx/minimal.cdx.json", "spdx/minimal.spdx.json");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff should succeed");

        // Both have lodash and express, CycloneDX also has test-app (primary)
        // Should detect some matches via fuzzy matching
        assert!(result.semantic_score > 0.0, "Cross-format diff should find some similarity");
    }

    #[test]
    fn compute_diff_with_include_unchanged() {
        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .new_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .include_unchanged(true)
            .build()
            .expect("valid config");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff should succeed");

        // With include_unchanged, modified list captures unchanged-but-matched components
        // and total changes should be 0 for identical SBOMs
        assert_eq!(
            result.summary.total_changes, 0,
            "Identical SBOMs should have 0 changes even with include_unchanged"
        );
    }
}

// ============================================================================
// Pipeline Report Stage Tests
// ============================================================================

mod report_stage {
    use super::*;

    fn diff_result_for_demo() -> (
        sbom_tools::DiffConfig,
        sbom_tools::DiffResult,
        sbom_tools::NormalizedSbom,
        sbom_tools::NormalizedSbom,
    ) {
        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .new_path(fixture_path("demo-new.cdx.json"))
            .output_format(ReportFormat::Json)
            .build()
            .expect("valid config");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff");
        (config, result, old, new)
    }

    #[test]
    fn output_report_json_to_file() {
        let (mut config, result, old, new) = diff_result_for_demo();

        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("report.json");
        config.output.format = ReportFormat::Json;
        config.output.file = Some(out_path.clone());

        output_report(&config, &result, &old, &new).expect("report should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert!(content.starts_with('{'), "JSON report should start with {{");

        // Should contain diff-related fields
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert!(
            json.get("summary").is_some() || json.get("metadata").is_some(),
            "JSON report should have summary or metadata"
        );
    }

    #[test]
    fn output_report_summary_to_file() {
        let (mut config, result, old, new) = diff_result_for_demo();

        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("report.txt");
        config.output.format = ReportFormat::Summary;
        config.output.file = Some(out_path.clone());

        output_report(&config, &result, &old, &new).expect("report should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert!(!content.is_empty(), "Summary report should not be empty");
    }

    #[test]
    fn output_report_markdown_to_file() {
        let (mut config, result, old, new) = diff_result_for_demo();

        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("report.md");
        config.output.format = ReportFormat::Markdown;
        config.output.file = Some(out_path.clone());

        output_report(&config, &result, &old, &new).expect("report should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert!(
            content.contains('#'),
            "Markdown report should contain headings"
        );
    }

    #[test]
    fn output_report_sarif_to_file() {
        let (mut config, result, old, new) = diff_result_for_demo();

        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("report.sarif.json");
        config.output.format = ReportFormat::Sarif;
        config.output.file = Some(out_path.clone());

        output_report(&config, &result, &old, &new).expect("report should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        let schema = json.get("$schema").and_then(|s| s.as_str()).unwrap_or("");
        assert!(
            schema.contains("sarif-schema"),
            "SARIF report should have SARIF schema, got: {schema}"
        );
    }

    #[test]
    fn output_report_csv_to_file() {
        let (mut config, result, old, new) = diff_result_for_demo();

        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("report.csv");
        config.output.format = ReportFormat::Csv;
        config.output.file = Some(out_path.clone());

        output_report(&config, &result, &old, &new).expect("report should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert!(
            !content.is_empty(),
            "CSV report should not be empty"
        );
    }

    #[test]
    fn write_output_to_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("test.txt");
        let target = OutputTarget::File(out_path.clone());

        write_output("hello world", &target, true).expect("write should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert_eq!(content, "hello world");
    }
}

// ============================================================================
// Pipeline End-to-End Tests
// ============================================================================

mod end_to_end {
    use super::*;

    #[test]
    fn full_pipeline_parse_diff_report() {
        // Full pipeline: parse two SBOMs → diff → JSON report to file
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("e2e-report.json");

        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .new_path(fixture_path("demo-new.cdx.json"))
            .output_format(ReportFormat::Json)
            .output_file(Some(out_path.clone()))
            .build()
            .expect("valid config");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff");
        output_report(&config, &result, &old, &new).expect("report");

        let content = std::fs::read_to_string(&out_path).expect("read report");
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");

        // Verify the full pipeline produced a complete report
        assert!(json.get("summary").is_some(), "Report should have summary");
        assert!(
            json["summary"]["total_changes"].as_u64().unwrap_or(0) > 0,
            "Demo SBOMs should produce changes"
        );
    }

    #[test]
    fn full_pipeline_with_vulnerability_fixture() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("vuln-report.json");

        // Use vuln fixture as new, minimal as old
        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .new_path(fixture_path("cyclonedx/with-vulnerabilities.cdx.json"))
            .output_format(ReportFormat::Json)
            .output_file(Some(out_path.clone()))
            .build()
            .expect("valid config");

        let old = parse_sbom_with_context(&config.paths.old, true)
            .expect("parse old")
            .into_sbom();
        let new = parse_sbom_with_context(&config.paths.new, true)
            .expect("parse new")
            .into_sbom();

        let result = compute_diff(&config, &old, &new).expect("diff");
        output_report(&config, &result, &old, &new).expect("report");

        let content = std::fs::read_to_string(&out_path).expect("read report");
        assert!(
            serde_json::from_str::<serde_json::Value>(&content).is_ok(),
            "Report should be valid JSON"
        );
    }
}

// ============================================================================
// CLI Handler Tests
// ============================================================================

mod cli_handlers {
    use super::*;

    #[test]
    fn run_diff_json_output() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("diff-output.json");

        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .new_path(fixture_path("demo-new.cdx.json"))
            .output_format(ReportFormat::Json)
            .output_file(Some(out_path.clone()))
            .build()
            .expect("valid config");

        let exit_code = sbom_tools::cli::run_diff(config).expect("run_diff should succeed");

        // Default: no fail-on-change, so exit 0
        assert_eq!(exit_code, 0);

        let content = std::fs::read_to_string(&out_path).expect("read output");
        assert!(
            serde_json::from_str::<serde_json::Value>(&content).is_ok(),
            "Output should be valid JSON"
        );
    }

    #[test]
    fn run_diff_fail_on_change() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("diff-output.json");

        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .new_path(fixture_path("demo-new.cdx.json"))
            .output_format(ReportFormat::Json)
            .output_file(Some(out_path))
            .fail_on_change(true)
            .build()
            .expect("valid config");

        let exit_code = sbom_tools::cli::run_diff(config).expect("run_diff should succeed");

        // Demo SBOMs have changes, so exit code should be 1
        assert_eq!(
            exit_code, 1,
            "Should exit 1 when fail-on-change and changes exist"
        );
    }

    #[test]
    fn run_diff_no_changes_exit_zero() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("diff-output.json");

        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .new_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .output_format(ReportFormat::Json)
            .output_file(Some(out_path))
            .fail_on_change(true)
            .build()
            .expect("valid config");

        let exit_code = sbom_tools::cli::run_diff(config).expect("run_diff should succeed");

        assert_eq!(exit_code, 0, "Identical SBOMs should exit 0");
    }

    #[test]
    fn run_diff_missing_file() {
        let config = DiffConfigBuilder::new()
            .old_path(PathBuf::from("/nonexistent/old.json"))
            .new_path(fixture_path("cyclonedx/minimal.cdx.json"))
            .output_format(ReportFormat::Json)
            .build()
            .expect("valid config");

        let err = sbom_tools::cli::run_diff(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Parse failed") || msg.contains("nonexistent"),
            "Error should mention parse failure: {msg}"
        );
    }
}

// ============================================================================
// Multi-Diff Pipeline Tests
// ============================================================================

mod multi_diff_pipeline {
    use super::*;

    #[test]
    fn run_diff_multi_json_output() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("multi-diff.json");

        let result = sbom_tools::cli::run_diff_multi(
            fixture_path("demo-old.cdx.json"),
            vec![
                fixture_path("demo-new.cdx.json"),
                fixture_path("cyclonedx/minimal.cdx.json"),
            ],
            ReportFormat::Json,
            Some(out_path.clone()),
            "balanced".to_string(),
            false,
        );

        result.expect("multi-diff should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert!(
            json.get("comparisons").is_some(),
            "Multi-diff output should have comparisons"
        );
    }

    #[test]
    fn run_timeline_json_output() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("timeline.json");

        let result = sbom_tools::cli::run_timeline(
            vec![
                fixture_path("demo-old.cdx.json"),
                fixture_path("demo-new.cdx.json"),
            ],
            ReportFormat::Json,
            Some(out_path.clone()),
            "balanced".to_string(),
        );

        result.expect("timeline should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert!(
            json.get("incremental_diffs").is_some(),
            "Timeline output should have incremental_diffs"
        );
    }

    #[test]
    fn run_timeline_requires_two_sboms() {
        let result = sbom_tools::cli::run_timeline(
            vec![fixture_path("demo-old.cdx.json")],
            ReportFormat::Json,
            None,
            "balanced".to_string(),
        );

        assert!(result.is_err(), "Timeline with 1 SBOM should fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("at least 2"),
            "Error should mention minimum: {msg}"
        );
    }

    #[test]
    fn run_matrix_json_output() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let out_path = dir.path().join("matrix.json");

        let result = sbom_tools::cli::run_matrix(
            vec![
                fixture_path("demo-old.cdx.json"),
                fixture_path("demo-new.cdx.json"),
                fixture_path("cyclonedx/minimal.cdx.json"),
            ],
            ReportFormat::Json,
            Some(out_path.clone()),
            "balanced".to_string(),
            0.7,
        );

        result.expect("matrix should succeed");

        let content = std::fs::read_to_string(&out_path).expect("read output");
        let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert!(
            json.get("sboms").is_some(),
            "Matrix output should have sboms field"
        );
        assert!(
            json.get("similarity_scores").is_some(),
            "Matrix output should have similarity_scores"
        );
    }

    #[test]
    fn run_matrix_requires_two_sboms() {
        let result = sbom_tools::cli::run_matrix(
            vec![fixture_path("demo-old.cdx.json")],
            ReportFormat::Json,
            None,
            "balanced".to_string(),
            0.7,
        );

        assert!(result.is_err(), "Matrix with 1 SBOM should fail");
    }
}

// ============================================================================
// Pipeline Error Type Tests
// ============================================================================

mod pipeline_errors {
    use super::*;

    #[test]
    fn pipeline_error_parse_failed_display() {
        let err = PipelineError::ParseFailed {
            path: "/path/to/sbom.json".to_string(),
            source: anyhow::anyhow!("file not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("Parse failed"));
        assert!(msg.contains("/path/to/sbom.json"));
    }

    #[test]
    fn pipeline_error_diff_failed_display() {
        let err = PipelineError::DiffFailed {
            source: anyhow::anyhow!("matching failed"),
        };
        let msg = err.to_string();
        assert!(msg.contains("Diff failed"));
    }

    #[test]
    fn pipeline_error_enrichment_failed_display() {
        let err = PipelineError::EnrichmentFailed {
            reason: "API timeout".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Enrichment failed"));
        assert!(msg.contains("API timeout"));
    }

    #[test]
    fn pipeline_error_report_failed_display() {
        let err = PipelineError::ReportFailed {
            source: anyhow::anyhow!("write error"),
        };
        let msg = err.to_string();
        assert!(msg.contains("Report failed"));
    }
}

// ============================================================================
// Output Utility Tests
// ============================================================================

mod output_utils {
    use super::*;

    #[test]
    fn auto_detect_format_respects_explicit() {
        let target = OutputTarget::Stdout;
        assert_eq!(
            auto_detect_format(ReportFormat::Json, &target),
            ReportFormat::Json
        );
        assert_eq!(
            auto_detect_format(ReportFormat::Csv, &target),
            ReportFormat::Csv
        );
        assert_eq!(
            auto_detect_format(ReportFormat::Sarif, &target),
            ReportFormat::Sarif
        );
    }

    #[test]
    fn auto_detect_format_file_target_auto() {
        let target = OutputTarget::File(PathBuf::from("/tmp/report.json"));
        // File target is never a terminal → Auto resolves to Summary
        assert_eq!(
            auto_detect_format(ReportFormat::Auto, &target),
            ReportFormat::Summary
        );
    }

    #[test]
    fn write_output_to_nonexistent_dir_fails() {
        let target = OutputTarget::File(PathBuf::from("/nonexistent/dir/report.json"));
        let result = write_output("content", &target, true);
        assert!(result.is_err(), "Writing to nonexistent dir should fail");
    }
}

// ============================================================================
// DiffConfig Builder Tests
// ============================================================================

mod config_builder {
    use super::*;

    #[test]
    fn builder_produces_valid_config() {
        let config = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .new_path(fixture_path("demo-new.cdx.json"))
            .output_format(ReportFormat::Json)
            .include_unchanged(true)
            .fail_on_change(true)
            .no_color(true)
            .build()
            .expect("valid config");

        assert!(config.paths.old.exists());
        assert!(config.paths.new.exists());
        assert_eq!(config.output.format, ReportFormat::Json);
        assert!(config.matching.include_unchanged);
        assert!(config.behavior.fail_on_change);
        assert!(config.output.no_color);
    }

    #[test]
    fn builder_missing_old_path_fails() {
        let result = DiffConfigBuilder::new()
            .new_path(fixture_path("demo-new.cdx.json"))
            .build();

        assert!(result.is_err(), "Missing old path should fail");
    }

    #[test]
    fn builder_missing_new_path_fails() {
        let result = DiffConfigBuilder::new()
            .old_path(fixture_path("demo-old.cdx.json"))
            .build();

        assert!(result.is_err(), "Missing new path should fail");
    }
}
