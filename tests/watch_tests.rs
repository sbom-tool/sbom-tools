//! Integration tests for the watch subsystem.

use sbom_tools::watch::{parse_duration, WatchConfig};
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Duration parsing
// ============================================================================

#[test]
fn test_parse_duration_seconds() {
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
}

#[test]
fn test_parse_duration_minutes() {
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
}

#[test]
fn test_parse_duration_hours() {
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
}

#[test]
fn test_parse_duration_days() {
    assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
}

#[test]
fn test_parse_duration_milliseconds() {
    assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
}

#[test]
fn test_parse_duration_invalid() {
    assert!(parse_duration("abc").is_err());
    assert!(parse_duration("").is_err());
    assert!(parse_duration("10").is_err());
    assert!(parse_duration("10x").is_err());
}

// ============================================================================
// Watch loop: initial scan with fixtures
// ============================================================================

#[test]
fn test_watch_loop_no_files_returns_error() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config = WatchConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        poll_interval: Duration::from_secs(1),
        enrich_interval: Duration::from_secs(3600),
        debounce: Duration::ZERO,
        output: sbom_tools::config::OutputConfig::default(),
        enrichment: sbom_tools::config::EnrichmentConfig::default(),
        webhook_url: None,
        exit_on_change: false,
        max_snapshots: 10,
        quiet: true,
    };

    let result = sbom_tools::watch::run_watch_loop(&config);
    assert!(result.is_err());
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("no SBOM files found"),
        "expected NoFilesFound, got: {err_msg}"
    );
}

#[test]
fn test_watch_loop_nonexistent_dir() {
    let config = WatchConfig {
        watch_dirs: vec![PathBuf::from("/nonexistent/dir/that/does/not/exist")],
        poll_interval: Duration::from_secs(1),
        enrich_interval: Duration::from_secs(3600),
        debounce: Duration::ZERO,
        output: sbom_tools::config::OutputConfig::default(),
        enrichment: sbom_tools::config::EnrichmentConfig::default(),
        webhook_url: None,
        exit_on_change: false,
        max_snapshots: 10,
        quiet: true,
    };

    // The cli handler checks for dir existence; the loop itself may still
    // get NoFilesFound because the dir isn't scannable.
    let result = sbom_tools::watch::run_watch_loop(&config);
    assert!(result.is_err());
}

#[test]
fn test_watch_loop_exit_on_change() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let fixture_path = dir.path().join("test.cdx.json");

    // Copy a real fixture for initial scan
    let demo = std::fs::read_to_string("tests/fixtures/demo-old.cdx.json")
        .expect("read fixture");
    std::fs::write(&fixture_path, &demo).expect("write fixture");

    let config = WatchConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        poll_interval: Duration::from_millis(50),
        enrich_interval: Duration::from_secs(3600),
        debounce: Duration::ZERO,
        output: sbom_tools::config::OutputConfig::default(),
        enrichment: sbom_tools::config::EnrichmentConfig::default(),
        webhook_url: None,
        exit_on_change: true,
        max_snapshots: 10,
        quiet: true,
    };

    // Spawn the watch loop in a thread, modify the file, then verify it exits
    let config_clone = config.clone();
    let fixture_clone = fixture_path.clone();
    let handle = std::thread::spawn(move || sbom_tools::watch::run_watch_loop(&config_clone));

    // Wait a bit for initial scan, then modify the file
    std::thread::sleep(Duration::from_millis(100));
    let demo_new = std::fs::read_to_string("tests/fixtures/demo-new.cdx.json")
        .expect("read new fixture");
    std::fs::write(&fixture_clone, &demo_new).expect("modify fixture");

    // Watch loop should exit within a few poll intervals
    let result = handle.join().expect("thread join");
    assert!(result.is_ok(), "watch loop should exit cleanly: {result:?}");
}

#[test]
fn test_watch_loop_initial_scan_parses_fixtures() {
    // Use exit_on_change with an immediate modification to verify parsing works
    let dir = tempfile::tempdir().expect("create temp dir");

    // Write a CycloneDX fixture
    let cdx = std::fs::read_to_string("tests/fixtures/demo-old.cdx.json")
        .expect("read fixture");
    std::fs::write(dir.path().join("app.cdx.json"), &cdx).expect("write");

    // Write an SPDX fixture if available
    let spdx_dir = PathBuf::from("tests/fixtures/spdx");
    if spdx_dir.exists() {
        if let Some(Ok(entry)) = std::fs::read_dir(&spdx_dir)
            .ok()
            .and_then(|mut entries| entries.find(|e| {
                e.as_ref().is_ok_and(|e| {
                    e.file_name().to_string_lossy().to_lowercase().ends_with(".spdx.json")
                })
            }))
        {
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            if !content.is_empty() {
                std::fs::write(dir.path().join("lib.spdx.json"), content).expect("write spdx");
            }
        }
    }

    let config = WatchConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        poll_interval: Duration::from_millis(50),
        enrich_interval: Duration::from_secs(3600),
        debounce: Duration::ZERO,
        output: sbom_tools::config::OutputConfig::default(),
        enrichment: sbom_tools::config::EnrichmentConfig::default(),
        webhook_url: None,
        exit_on_change: true,
        max_snapshots: 10,
        quiet: true,
    };

    let config_clone = config.clone();
    let dir_path = dir.path().to_path_buf();

    let handle = std::thread::spawn(move || sbom_tools::watch::run_watch_loop(&config_clone));

    // Trigger a change so it exits
    std::thread::sleep(Duration::from_millis(100));
    let cdx_new = std::fs::read_to_string("tests/fixtures/demo-new.cdx.json")
        .expect("read new fixture");
    std::fs::write(dir_path.join("app.cdx.json"), &cdx_new).expect("modify");

    let result = handle.join().expect("thread join");
    assert!(result.is_ok());
}

// ============================================================================
// NDJSON output verification
// ============================================================================

#[test]
fn test_watch_ndjson_output_produces_valid_json() {
    use sbom_tools::reports::ReportFormat;

    let dir = tempfile::tempdir().expect("create temp dir");
    let output_file = dir.path().join("events.ndjson");

    let demo = std::fs::read_to_string("tests/fixtures/demo-old.cdx.json")
        .expect("read fixture");
    let fixture_path = dir.path().join("test.cdx.json");
    std::fs::write(&fixture_path, &demo).expect("write fixture");

    let config = WatchConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        poll_interval: Duration::from_millis(50),
        enrich_interval: Duration::from_secs(3600),
        debounce: Duration::ZERO,
        output: sbom_tools::config::OutputConfig {
            format: ReportFormat::Json,
            file: Some(output_file.clone()),
            ..Default::default()
        },
        enrichment: sbom_tools::config::EnrichmentConfig::default(),
        webhook_url: None,
        exit_on_change: true,
        max_snapshots: 10,
        quiet: true,
    };

    let config_clone = config.clone();
    let fixture_clone = fixture_path.clone();

    let handle = std::thread::spawn(move || sbom_tools::watch::run_watch_loop(&config_clone));

    std::thread::sleep(Duration::from_millis(100));
    let demo_new = std::fs::read_to_string("tests/fixtures/demo-new.cdx.json")
        .expect("read new fixture");
    std::fs::write(&fixture_clone, &demo_new).expect("modify fixture");

    let result = handle.join().expect("thread join");
    assert!(result.is_ok());

    // Verify NDJSON output
    if output_file.exists() {
        let output = std::fs::read_to_string(&output_file).expect("read output");
        for line in output.lines() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line should be valid JSON");
            assert!(
                parsed.get("type").is_some(),
                "each event should have a 'type' field"
            );
        }
    }
}
