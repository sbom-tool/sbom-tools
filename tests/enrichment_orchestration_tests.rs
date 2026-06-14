//! Regression tests for routing every enrichment entry point through the
//! unified [`enrich_sbom_full`] orchestrator.
//!
//! Pre-fix defects these tests lock down:
//! - `enrich --kev` parsed `--kev` but never ran it, so KEV data was silently
//!   dropped from the output SBOM. We assert the mocked KEV catalog IS fetched
//!   and the enriched output carries the KEV marker.
//! - `query --offline` reset the process-wide offline flag (the orchestrator's
//!   unconditional `set_offline(config.offline=false)` overwrote the global
//!   `--offline=true`), permitting network egress. This is the BLOCKER: we
//!   assert `query --offline` makes ZERO network requests.
//! - `query` ignored the global `--config` file's `enrichment:`/`offline:`
//!   block (no ValueSource precedence). We assert a config-file `offline: true`
//!   suppresses all network access for `query`.
//! - DEFENSIVE: a library `enrich_sbom_full` call with `config.offline=false`
//!   must NEVER re-enable egress once the process is globally offline.

#![cfg(feature = "enrichment")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use httpmock::prelude::*;
use sbom_tools::config::EnrichmentConfig;
use sbom_tools::enrichment::source::{is_offline, set_offline};
use sbom_tools::model::{Component, NormalizedSbom};
use sbom_tools::pipeline::enrich_sbom_full;

/// Serializes every test that flips the process-wide offline switch so parallel
/// threads don't race on the global flag. Recovers from a poisoned lock.
static OFFLINE_LOCK: Mutex<()> = Mutex::new(());
fn offline_lock() -> std::sync::MutexGuard<'static, ()> {
    OFFLINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const CVE: &str = "CVE-2021-44228";

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbom-tools"))
}

/// Point the platform cache-dir env var at `base` so the binary's cache root
/// resolves under a temp dir without using the `--cache-dir` CLI flag (which
/// `seed_enrichment` treats as "CLI touched enrichment", discarding the config
/// file's `enrichment:` block). Mirrors `enrichment::source::cache_dir`.
fn cache_env(base: &Path) -> Vec<(String, String)> {
    let base = base.to_string_lossy().into_owned();
    if cfg!(target_os = "macos") {
        vec![("HOME".to_string(), format!("{base}/home"))]
    } else if cfg!(target_os = "windows") {
        vec![("LOCALAPPDATA".to_string(), base)]
    } else {
        vec![("XDG_CACHE_HOME".to_string(), base)]
    }
}

/// A CISA KEV catalog body containing a single entry for `cve`.
fn kev_catalog_body(cve: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.06.01",
        "dateReleased": "2026-06-01T12:00:00.000Z",
        "count": 1,
        "vulnerabilities": [{
            "cveID": cve,
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "RCE in Log4j2.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": ""
        }]
    })
}

/// A CycloneDX SBOM with one component already carrying `CVE` so KEV can flag it
/// without needing OSV. Written to `dir/name`.
fn write_vuln_sbom(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let body = format!(
        r#"{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {{ "timestamp": "2026-01-04T12:00:00Z" }},
  "components": [
    {{ "type": "library", "bom-ref": "log4j@2.14.0", "name": "log4j", "version": "2.14.0",
       "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0" }}
  ],
  "vulnerabilities": [
    {{ "id": "{CVE}", "source": {{ "name": "NVD" }}, "affects": [ {{ "ref": "log4j@2.14.0" }} ] }}
  ]
}}"#
    );
    std::fs::write(&path, body).unwrap();
    path
}

// ============================================================================
// FIX #1 — `enrich --kev` actually runs KEV and writes it into the output SBOM
// ============================================================================

/// The old `run_enrich` parsed `--kev` but only applied OSV/EOL/VEX, dropping
/// KEV entirely. Now it routes through `enrich_sbom_full`: the mocked KEV
/// catalog IS fetched and the enriched output SBOM carries the KEV marker.
#[test]
fn enrich_kev_writes_kev_data_into_output() {
    let server = MockServer::start();
    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200).json_body(kev_catalog_body(CVE));
    });

    let work = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let sbom = write_vuln_sbom(work.path(), "in.cdx.json");
    let out = work.path().join("out.cdx.json");
    let kev_url = format!("{}/kev.json", server.base_url());

    let output = Command::new(bin_path())
        .arg("--no-color")
        .env("RUST_LOG", "error")
        .env("SBOM_TOOLS_KEV_URL", &kev_url)
        .args(["enrich", &sbom.to_string_lossy(), "--kev"])
        .arg("-O")
        .arg(&out)
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .expect("enrich --kev should run");

    assert!(
        output.status.success(),
        "enrich --kev failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The KEV catalog was fetched (proves --kev is wired through enrich now).
    kev_mock.assert_hits(1);

    // The enriched output SBOM carries the KEV marker injected by the serializer.
    let enriched = std::fs::read_to_string(&out).expect("output SBOM written");
    let doc: serde_json::Value = serde_json::from_str(&enriched).unwrap();
    let vulns = doc["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities[]");
    let kev_prop = vulns
        .iter()
        .flat_map(|v| v["properties"].as_array().into_iter().flatten())
        .any(|p| p["name"] == "sbom-tools:kev" && p["value"] == "true");
    assert!(
        kev_prop,
        "enriched output SBOM must carry the sbom-tools:kev property:\n{enriched}"
    );
}

// ============================================================================
// FIX #3 — `query --offline` makes ZERO network calls (the BLOCKER)
// ============================================================================

/// With `--offline`, `query --kev` must serve nothing from the network: the
/// pre-fix bug let the orchestrator reset the global offline flag, so the KEV
/// mock would be hit. Now the mock must see ZERO requests.
#[test]
fn query_offline_makes_zero_network_calls() {
    let server = MockServer::start();
    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200).json_body(kev_catalog_body(CVE));
    });

    let work = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let sbom = write_vuln_sbom(work.path(), "in.cdx.json");
    let kev_url = format!("{}/kev.json", server.base_url());

    let output = Command::new(bin_path())
        .arg("--no-color")
        .arg("--offline")
        .env("RUST_LOG", "error")
        .env("SBOM_TOOLS_KEV_URL", &kev_url)
        // Pattern "log4j" + the SBOM path; --kev would normally fetch the catalog.
        .args(["query", "log4j", &sbom.to_string_lossy(), "--kev"])
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .expect("query --offline should run");

    assert!(
        output.status.success(),
        "query --offline failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // THE BLOCKER ASSERTION: offline mode must make no network requests at all.
    kev_mock.assert_hits(0);
}

// ============================================================================
// FIX #4 — `query` honors the global --config file's enrichment/offline block
// ============================================================================

/// A config file's `enrichment:` block must take effect for `query`, even when
/// no enrichment flag is passed on the CLI. Pre-fix, the Query arm built
/// enrichment from raw `args.enrichment` and ignored the config file, so the
/// file's `enable_kev` was a no-op. Here the config enables KEV (no `--kev` on
/// the CLI) and points at the mock: the catalog MUST be fetched.
#[test]
fn query_honors_config_file_enrichment() {
    let server = MockServer::start();
    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200).json_body(kev_catalog_body(CVE));
    });

    let work = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let sbom = write_vuln_sbom(work.path(), "in.cdx.json");
    let kev_url = format!("{}/kev.json", server.base_url());

    // Config file enables KEV and points it at the mock; offline is false.
    let cfg = work.path().join("cfg.yaml");
    std::fs::write(
        &cfg,
        format!("enrichment:\n  enabled: false\n  enable_kev: true\n  kev_url: {kev_url}\n"),
    )
    .unwrap();

    let output = Command::new(bin_path())
        .arg("--no-color")
        .args(["--config", &cfg.to_string_lossy()])
        .env("RUST_LOG", "error")
        .envs(cache_env(cache_dir.path()))
        // NOTE: no --kev here; the config file must supply it.
        .args(["query", "log4j", &sbom.to_string_lossy()])
        .output()
        .expect("query with config should run");

    assert!(
        output.status.success(),
        "query with config failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The config file's enable_kev must have driven a KEV fetch.
    kev_mock.assert_hits(1);
}

/// A config file with `enrichment.offline: true` must suppress all network
/// access for `query`, even though `--offline` was not passed on the CLI.
#[test]
fn query_honors_config_file_offline() {
    let server = MockServer::start();
    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200).json_body(kev_catalog_body(CVE));
    });

    let work = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let sbom = write_vuln_sbom(work.path(), "in.cdx.json");
    let kev_url = format!("{}/kev.json", server.base_url());

    // Config file enables KEV + offline; KEV would fetch the catalog if online.
    let cfg = work.path().join("cfg.yaml");
    std::fs::write(
        &cfg,
        format!(
            "enrichment:\n  enabled: false\n  enable_kev: true\n  offline: true\n  kev_url: {kev_url}\n",
        ),
    )
    .unwrap();

    let output = Command::new(bin_path())
        .arg("--no-color")
        .args(["--config", &cfg.to_string_lossy()])
        .env("RUST_LOG", "error")
        .envs(cache_env(cache_dir.path()))
        .args(["query", "log4j", &sbom.to_string_lossy()])
        .output()
        .expect("query with config should run");

    assert!(
        output.status.success(),
        "query with offline config failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The config file's offline:true must have suppressed the KEV fetch.
    kev_mock.assert_hits(0);
}

// ============================================================================
// FIX #3 (defensive) — enrich_sbom_full can never re-enable a global offline
// ============================================================================

fn lodash_sbom() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    sbom.add_component(
        Component::new("lodash".to_string(), "lodash@4.17.20".to_string())
            .with_purl("pkg:npm/lodash@4.17.20".to_string())
            .with_version("4.17.20".to_string()),
    );
    sbom
}

/// Once the process is globally offline, a later `enrich_sbom_full` call whose
/// own `config.offline` is false must NOT flip the process back online. This
/// hardens the whole class so no future caller can accidentally re-enable
/// egress.
#[test]
fn enrich_sbom_full_cannot_disable_global_offline() {
    let _guard = offline_lock();

    // Simulate `main` having set the global offline flag from --offline.
    set_offline(true);
    assert!(is_offline());

    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();
    let osv_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(serde_json::json!({ "results": [] }));
    });

    // A per-call config with offline=false (the dangerous case).
    let config = EnrichmentConfig::osv()
        .with_api_base(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf());
    assert!(!config.offline, "this call's config is online");

    let mut sbom = lodash_sbom();
    let _ = enrich_sbom_full(&mut sbom, &config, true);

    // The global offline flag survived, and no OSV request was attempted.
    assert!(
        is_offline(),
        "enrich_sbom_full must not re-enable network egress when globally offline"
    );
    osv_mock.assert_hits(0);

    set_offline(false);
}
