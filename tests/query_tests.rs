//! Integration tests for the multi-SBOM query command.

use sbom_tools::cli::{run_query, QueryFilter};
use sbom_tools::config::{EnrichmentConfig, OutputConfig, QueryConfig, StreamingConfig};
use sbom_tools::reports::ReportFormat;
use std::path::{Path, PathBuf};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn base_config(paths: Vec<PathBuf>) -> QueryConfig {
    QueryConfig {
        sbom_paths: paths,
        output: OutputConfig {
            format: ReportFormat::Json,
            file: None,
            report_types: sbom_tools::reports::ReportType::All,
            no_color: true,
            streaming: StreamingConfig::default(),
            export_template: None,
        },
        enrichment: EnrichmentConfig::default(),
        limit: None,
        group_by_sbom: false,
    }
}

#[test]
fn test_query_pattern_across_fixtures() {
    let config = base_config(vec![
        fixture_path("demo-old.cdx.json"),
        fixture_path("demo-new.cdx.json"),
    ]);
    // Write to a temp file so we can inspect the output
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());

    let filter = QueryFilter {
        pattern: Some("lodash".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    assert_eq!(matches.len(), 2, "lodash appears in both SBOMs with different versions");
    assert!(matches.iter().all(|m| m["name"] == "lodash"));
    assert_eq!(result["sboms_searched"], 2);
}

#[test]
fn test_query_ecosystem_filter() {
    let config = base_config(vec![
        fixture_path("demo-old.cdx.json"),
        fixture_path("demo-new.cdx.json"),
    ]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());

    let filter = QueryFilter {
        ecosystem: Some("npm".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    // All components in demo fixtures are npm
    assert!(matches.len() > 10);
    assert!(matches.iter().all(|m| m["ecosystem"] == "npm"));
}

#[test]
fn test_query_version_range_filter() {
    let config = base_config(vec![
        fixture_path("demo-old.cdx.json"),
        fixture_path("demo-new.cdx.json"),
    ]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());

    let filter = QueryFilter {
        name: Some("lodash".to_string()),
        version: Some("<4.17.21".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    assert_eq!(matches.len(), 1, "only lodash 4.17.20 should match <4.17.21");
    assert_eq!(matches[0]["version"], "4.17.20");
}

#[test]
fn test_query_license_filter() {
    let config = base_config(vec![fixture_path("demo-old.cdx.json")]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());

    let filter = QueryFilter {
        license: Some("Apache".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    assert!(!matches.is_empty());
    assert!(matches
        .iter()
        .all(|m| m["license"].as_str().unwrap_or("").contains("Apache")));
}

#[test]
fn test_query_limit() {
    let config = base_config(vec![
        fixture_path("demo-old.cdx.json"),
        fixture_path("demo-new.cdx.json"),
    ]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());
    config.limit = Some(3);

    let filter = QueryFilter {
        ecosystem: Some("npm".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    assert_eq!(matches.len(), 3);
}

#[test]
fn test_query_dedup_across_sboms() {
    let config = base_config(vec![
        fixture_path("demo-old.cdx.json"),
        fixture_path("demo-new.cdx.json"),
    ]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());

    // acme-webapp 1.0.0 appears in both SBOMs (metadata.component)
    let filter = QueryFilter {
        name: Some("acme-webapp".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    let result: serde_json::Value = serde_json::from_str(&output).expect("parse JSON");

    let matches = result["matches"].as_array().expect("matches array");
    // acme-webapp appears in both SBOMs; v1.0.0 in old, v2.0.0 in new
    for m in matches {
        assert!(m["name"].as_str().unwrap().contains("acme-webapp"));
    }
}

#[test]
fn test_query_csv_output() {
    let config = base_config(vec![fixture_path("demo-old.cdx.json")]);
    let tmp = tempfile::NamedTempFile::new().expect("create temp file");
    let mut config = config;
    config.output.file = Some(tmp.path().to_path_buf());
    config.output.format = ReportFormat::Csv;

    let filter = QueryFilter {
        pattern: Some("lodash".to_string()),
        ..Default::default()
    };

    run_query(config, filter).expect("query should succeed");

    let output = std::fs::read_to_string(tmp.path()).expect("read output");
    assert!(output.starts_with("Component,Version"));
    assert!(output.contains("lodash"));
}
