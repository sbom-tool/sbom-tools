//! Integration tests for offline mode + the `cache` subcommand.
//!
//! Covers:
//! - a warm OSV cache serving an offline `enrich_sbom_full` with **zero**
//!   network requests (httpmock asserts no extra hits in offline mode),
//! - a TTL-expired cache entry being served *stale* (not evicted) when offline,
//!   while the online path still evicts it,
//! - the CLI `cache` subcommand: `status`, `warm`, and an `export` + `import`
//!   round-trip, plus an end-to-end offline KEV run served purely from cache.
//!
//! Offline mode is a process-wide switch ([`set_offline`]), so the tests that
//! toggle it are serialized through a single mutex to keep parallel test threads
//! from racing on the global flag. The CLI tests run in their own subprocess and
//! need no such guard.

#![cfg(feature = "enrichment")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use httpmock::prelude::*;
use sbom_tools::config::EnrichmentConfig;
use sbom_tools::enrichment::source::{JsonCache, is_offline, set_offline};
use sbom_tools::enrichment::{CacheKey, FileCache};
use sbom_tools::model::{
    Component, NormalizedSbom, Severity, VulnerabilityRef, VulnerabilitySource,
};
use sbom_tools::pipeline::enrich_sbom_full;

/// Serializes every test that flips the process-wide offline switch.
static OFFLINE_LOCK: Mutex<()> = Mutex::new(());

/// Lock the offline serialization mutex, recovering from a prior panic's poison
/// so one failing test does not cascade into the others.
fn offline_lock() -> std::sync::MutexGuard<'static, ()> {
    OFFLINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const VULN_ID: &str = "GHSA-jf85-cpcp-j695";

fn querybatch_stub_body(ids: &[&str]) -> serde_json::Value {
    let vulns: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| serde_json::json!({"id": id, "modified": "2026-01-10T00:00:00Z"}))
        .collect();
    serde_json::json!({ "results": [ { "vulns": vulns } ] })
}

fn full_vuln_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "summary": "Prototype pollution in lodash",
        "modified": "2026-01-10T00:00:00Z",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [{
            "package": {"name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
        }],
        "database_specific": {"severity": "CRITICAL"}
    })
}

fn lodash_sbom() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    sbom.add_component(
        Component::new("lodash".to_string(), "lodash@4.17.20".to_string())
            .with_purl("pkg:npm/lodash@4.17.20".to_string())
            .with_version("4.17.20".to_string()),
    );
    sbom
}

/// A warm OSV cache must serve an offline run without any network request.
#[test]
fn offline_run_serves_warm_cache_without_network() {
    let _guard = offline_lock();
    set_offline(false);

    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200).json_body(querybatch_stub_body(&[VULN_ID]));
    });
    let vuln_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    // 1. Online warm-up populates the cache.
    let online = EnrichmentConfig::osv()
        .with_api_base(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf());
    let mut sbom = lodash_sbom();
    let stats = enrich_sbom_full(&mut sbom, &online, true);
    assert!(stats.osv.is_some(), "online enrichment should run");
    batch_mock.assert_hits(1);
    vuln_mock.assert_hits(1);

    // 2. Offline run is served entirely from the warm cache: ZERO new requests.
    let offline = EnrichmentConfig::osv()
        .with_api_base(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_offline();
    let mut sbom2 = lodash_sbom();
    let stats2 = enrich_sbom_full(&mut sbom2, &offline, true);

    // The mocks must not have been hit again.
    batch_mock.assert_hits(1);
    vuln_mock.assert_hits(1);

    let osv = stats2.osv.expect("offline OSV stats present");
    assert_eq!(osv.api_calls, 0, "offline mode must make no API calls");
    let comp = sbom2.components.values().next().unwrap();
    assert_eq!(
        comp.vulnerabilities[0].severity,
        Some(Severity::Critical),
        "the cached, enriched vulnerability is served offline"
    );

    set_offline(false);
}

/// In offline mode a TTL-expired entry is served stale (not evicted); the online
/// path still evicts it.
#[test]
fn expired_entry_served_stale_when_offline() {
    let _guard = offline_lock();
    set_offline(false);

    let tmp = tempfile::tempdir().unwrap();
    let ttl = Duration::from_millis(50);
    let cache: JsonCache<String> = JsonCache::new(tmp.path().to_path_buf(), ttl).unwrap();
    cache.set_named("entry", &"payload".to_string()).unwrap();

    // Let the entry age past its TTL.
    std::thread::sleep(Duration::from_millis(150));

    // Offline: the expired entry is RETURNED with a staleness signal and kept.
    set_offline(true);
    let (value, stale_by) = cache
        .get_named_allow_stale("entry")
        .expect("stale entry must be served offline");
    assert_eq!(value, "payload");
    assert!(
        stale_by.is_some(),
        "an expired-but-served entry reports how far past TTL it is"
    );
    assert!(
        cache.path_for("entry").exists(),
        "offline must NOT evict the stale entry"
    );

    // Online: the same expired entry is a miss and gets evicted.
    set_offline(false);
    assert!(
        cache.get_named("entry").is_none(),
        "online path treats an expired entry as a miss"
    );
    assert!(
        !cache.path_for("entry").exists(),
        "online path evicts the expired entry"
    );

    set_offline(false);
}

/// The offline HTTP guard refuses a fresh fetch (cache miss) with a clear error
/// rather than attempting a network call.
#[test]
fn offline_cache_miss_makes_no_request() {
    let _guard = offline_lock();
    set_offline(false);

    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();
    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200).json_body(querybatch_stub_body(&[VULN_ID]));
    });

    // Offline with an EMPTY cache: nothing is served and nothing is fetched.
    let offline = EnrichmentConfig::osv()
        .with_api_base(server.base_url())
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_offline();
    let mut sbom = lodash_sbom();
    let _stats = enrich_sbom_full(&mut sbom, &offline, true);

    // The offline guard refused the fetch: the OSV mock saw no request at all.
    batch_mock.assert_hits(0);
    assert!(
        is_offline(),
        "enrich_sbom_full sets the process-wide offline flag"
    );
    let comp = sbom.components.values().next().unwrap();
    assert!(
        comp.vulnerabilities.is_empty(),
        "an offline cache miss yields no enrichment"
    );

    set_offline(false);
}

// ============================================================================
// CLI `cache` subcommand
// ============================================================================

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbom-tools"))
}

fn write_sbom(dir: &Path, name: &str, components: &str) -> PathBuf {
    let path = dir.join(name);
    let body = format!(
        r#"{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {{ "timestamp": "2026-01-04T12:00:00Z" }},
  {components}
}}"#
    );
    std::fs::write(&path, body).unwrap();
    path
}

/// Seed a cache directory tree with one fake OSV entry so `status`/`export`
/// have something to report without any network access.
fn seed_osv_cache(sbom_tools_root: &Path) -> CacheKey {
    let osv_dir = sbom_tools_root.join("osv");
    let cache = FileCache::new(osv_dir, Duration::from_secs(3600)).unwrap();
    let key = CacheKey::new(
        Some("pkg:npm/lodash@4.17.20".to_string()),
        "lodash".to_string(),
        Some("npm".to_string()),
        Some("4.17.20".to_string()),
    );
    let mut vuln = VulnerabilityRef::new(VULN_ID.to_string(), VulnerabilitySource::Osv);
    vuln.severity = Some(Severity::Critical);
    cache.set(&key, std::slice::from_ref(&vuln)).unwrap();
    key
}

/// The `sbom-tools` cache root the binary resolves to for a given env base,
/// matching `enrichment::source::cache_dir` precedence.
fn resolved_root(base: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        base.join("home")
            .join("Library")
            .join("Caches")
            .join("sbom-tools")
    } else {
        base.join("sbom-tools")
    }
}

#[test]
fn cli_cache_status_reports_seeded_entries() {
    let base = tempfile::tempdir().unwrap();
    seed_osv_cache(&resolved_root(base.path()));

    let output = Command::new(bin_path())
        .arg("cache")
        .arg("status")
        .envs(cache_env(base.path()))
        .env("RUST_LOG", "error")
        .output()
        .expect("cache status should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("osv"),
        "status lists the osv source: {stdout}"
    );
    assert!(
        stdout.contains("ENTRIES"),
        "status prints a header: {stdout}"
    );
}

#[test]
fn cli_cache_warm_succeeds_without_queryable_components() {
    // An SBOM whose components have no PURL/ecosystem produces no OSV queries,
    // so `cache warm` completes with no network access — exercising the warm
    // command path end-to-end through the binary.
    let work = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let sbom = write_sbom(
        work.path(),
        "sbom.cdx.json",
        r#""components": [
    { "type": "library", "bom-ref": "internal-thing", "name": "internal-thing" }
  ]"#,
    );

    let output = Command::new(bin_path())
        .args(["cache", "warm"])
        .arg(&sbom)
        .envs(cache_env(base.path()))
        .env("RUST_LOG", "error")
        .output()
        .expect("cache warm should run");

    assert!(
        output.status.success(),
        "warm stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Warmed cache"),
        "warm prints a summary: {stdout}"
    );
}

#[test]
fn cli_cache_warm_rejects_offline() {
    // Warming requires the network, so it must refuse to run in offline mode.
    let work = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let sbom = write_sbom(
        work.path(),
        "sbom.cdx.json",
        r#""components": [
    { "type": "library", "bom-ref": "x", "name": "x" }
  ]"#,
    );

    let output = Command::new(bin_path())
        .arg("--offline")
        .args(["cache", "warm"])
        .arg(&sbom)
        .envs(cache_env(base.path()))
        .env("RUST_LOG", "error")
        .output()
        .expect("cache warm should run");

    assert!(
        !output.status.success(),
        "offline warm must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("offline"),
        "error explains the offline conflict: {stderr}"
    );
}

#[test]
fn cli_cache_export_import_roundtrip() {
    let base = tempfile::tempdir().unwrap();
    seed_osv_cache(&resolved_root(base.path()));
    let export_dir = tempfile::tempdir().unwrap();

    // Export the seeded cache to a portable directory bundle.
    let export = Command::new(bin_path())
        .args(["cache", "export"])
        .arg(export_dir.path())
        .envs(cache_env(base.path()))
        .env("RUST_LOG", "error")
        .output()
        .expect("cache export should run");
    assert!(
        export.status.success(),
        "export stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(
        export_dir.path().join("osv").exists(),
        "export copies the osv namespace dir"
    );

    // Import into a fresh, empty cache root.
    let import_base = tempfile::tempdir().unwrap();
    let import = Command::new(bin_path())
        .args(["cache", "import"])
        .arg(export_dir.path())
        .envs(cache_env(import_base.path()))
        .env("RUST_LOG", "error")
        .output()
        .expect("cache import should run");
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    // The imported tree mirrors the original: the osv entry is present.
    let imported_osv = resolved_root(import_base.path()).join("osv");
    assert!(
        imported_osv.exists() && std::fs::read_dir(&imported_osv).unwrap().count() >= 1,
        "imported cache contains the osv entry"
    );
}

/// An end-to-end offline run served purely from a warm KEV cache: the KEV mock
/// is hit once during the online warm-up and ZERO times during the offline run.
#[test]
fn cli_offline_kev_served_from_warm_cache() {
    let server = MockServer::start();
    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200).json_body(serde_json::json!({
            "title": "CISA KEV",
            "catalogVersion": "2026.06.01",
            "dateReleased": "2026-06-01T12:00:00.000Z",
            "count": 1,
            "vulnerabilities": [{
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "shortDescription": "RCE",
                "requiredAction": "Patch",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": ""
            }]
        }));
    });
    let cache_dir = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    let sbom = write_sbom(
        work.path(),
        "sbom.cdx.json",
        r#""components": [
    { "type": "library", "bom-ref": "log4j@2.14.0", "name": "log4j", "version": "2.14.0", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0" }
  ],
  "vulnerabilities": [
    { "id": "CVE-2021-44228", "source": { "name": "NVD" }, "affects": [ { "ref": "log4j@2.14.0" } ] }
  ]"#,
    );

    let kev_url = format!("{}/kev.json", server.base_url());

    // 1. Online warm-up: fetch + cache the KEV catalog.
    let warm = Command::new(bin_path())
        .arg("--no-color")
        .env("RUST_LOG", "error")
        .env("SBOM_TOOLS_KEV_URL", &kev_url)
        .args(["view", &sbom.to_string_lossy(), "-o", "summary", "--kev"])
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .expect("warm view should run");
    assert!(
        warm.status.success() || warm.status.code() == Some(0),
        "warm stderr: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
    kev_mock.assert_hits(1);

    // 2. Offline run: KEV is served from the warm cache, no new request.
    let offline = Command::new(bin_path())
        .arg("--no-color")
        .arg("--offline")
        .env("RUST_LOG", "error")
        .env("SBOM_TOOLS_KEV_URL", &kev_url)
        .args(["view", &sbom.to_string_lossy(), "-o", "summary", "--kev"])
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .expect("offline view should run");
    assert!(
        offline.status.success(),
        "offline stderr: {}",
        String::from_utf8_lossy(&offline.stderr)
    );
    // The KEV mock must NOT have been hit a second time.
    kev_mock.assert_hits(1);
}

/// Set the platform cache-dir env var so `root_cache_dir()` resolves under
/// `resolved_root(base)`. Mirrors the precedence in
/// `enrichment::source::cache_dir`.
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
