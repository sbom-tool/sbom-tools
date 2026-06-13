//! HTTP-level integration tests for OSV enrichment.
//!
//! Uses httpmock to simulate the OSV API and verify that querybatch results
//! (which carry only `{id, modified}` stubs) are hydrated into full
//! vulnerability records, that the client retries transient failures, and
//! that cache expiry combined with network failures behaves as documented.

#![cfg(feature = "enrichment")]

use httpmock::prelude::*;
use sbom_tools::enrichment::osv::response::OsvQuery;
use sbom_tools::enrichment::osv::{OsvClient, OsvClientConfig};
use sbom_tools::enrichment::{
    CacheKey, FileCache, OsvEnricher, OsvEnricherConfig, VulnerabilityEnricher,
};
use sbom_tools::model::{Component, Severity, VulnerabilityRef, VulnerabilitySource};
use std::path::PathBuf;
use std::time::Duration;

const VULN_ID: &str = "GHSA-jf85-cpcp-j695";

fn querybatch_stub_body(vuln_ids_per_result: &[&[&str]]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = vuln_ids_per_result
        .iter()
        .map(|ids| {
            let vulns: Vec<serde_json::Value> = ids
                .iter()
                .map(|id| serde_json::json!({"id": id, "modified": "2026-01-10T00:00:00Z"}))
                .collect();
            serde_json::json!({"vulns": vulns})
        })
        .collect();
    serde_json::json!({ "results": results })
}

fn full_vuln_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "summary": "Prototype pollution in lodash",
        "details": "Versions of lodash before 4.17.21 are vulnerable to prototype pollution.",
        "aliases": ["CVE-2026-0001"],
        "published": "2026-01-05T00:00:00Z",
        "modified": "2026-01-10T00:00:00Z",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [{
            "package": {"name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
        }],
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-1321"]}
    })
}

fn make_component(name: &str, version: &str) -> Component {
    Component::new(name.to_string(), format!("{name}@{version}"))
        .with_purl(format!("pkg:npm/{name}@{version}"))
        .with_version(version.to_string())
}

fn enricher_config(server: &MockServer, cache_dir: PathBuf) -> OsvEnricherConfig {
    OsvEnricherConfig {
        cache_dir,
        cache_ttl: Duration::from_secs(3600),
        bypass_cache: false,
        timeout: Duration::from_secs(5),
        api_base: server.base_url(),
        max_retries: 0,
    }
}

fn client_config(server: &MockServer, max_retries: u8, timeout: Duration) -> OsvClientConfig {
    OsvClientConfig {
        api_base: server.base_url(),
        timeout,
        max_retries,
        batch_size: 1000,
    }
}

// ============================================================================
// Hydration: querybatch stubs must be expanded via /v1/vulns/{id}
// ============================================================================

#[test]
fn enriched_vulnerabilities_carry_severity_and_cvss() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[VULN_ID]]));
    });
    let vuln_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    let enricher =
        OsvEnricher::new(enricher_config(&server, cache_dir.path().to_path_buf())).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];
    let stats = enricher.enrich(&mut components).unwrap();

    batch_mock.assert();
    vuln_mock.assert();
    assert_eq!(stats.components_with_vulns, 1);
    assert_eq!(stats.total_vulns_found, 1);
    assert!(!stats.has_errors());

    let vuln = &components[0].vulnerabilities[0];
    assert_eq!(vuln.id, VULN_ID);
    assert_eq!(vuln.severity, Some(Severity::Critical));
    assert_eq!(vuln.cvss.len(), 1);
    assert!((vuln.cvss[0].base_score - 9.8).abs() < 1e-4);
    assert!(
        vuln.description
            .as_deref()
            .unwrap()
            .contains("prototype pollution")
    );
    assert_eq!(
        vuln.remediation.as_ref().unwrap().fixed_version.as_deref(),
        Some("4.17.21")
    );
    assert_eq!(vuln.cwes, vec!["CWE-1321".to_string()]);
}

#[test]
fn shared_vulnerability_details_fetched_once() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[VULN_ID], &[VULN_ID]]));
    });
    let vuln_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    let enricher =
        OsvEnricher::new(enricher_config(&server, cache_dir.path().to_path_buf())).unwrap();
    let mut components = vec![
        make_component("lodash", "4.17.20"),
        make_component("lodash-es", "4.17.20"),
    ];
    let stats = enricher.enrich(&mut components).unwrap();

    batch_mock.assert();
    // The second component's record is served from the per-vuln cache.
    vuln_mock.assert_hits(1);
    assert_eq!(stats.components_with_vulns, 2);
    for component in &components {
        assert_eq!(
            component.vulnerabilities[0].severity,
            Some(Severity::Critical)
        );
        assert!((component.vulnerabilities[0].cvss[0].base_score - 9.8).abs() < 1e-4);
    }
}

#[test]
fn cached_component_results_skip_network() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[VULN_ID]]));
    });
    let vuln_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    let config = enricher_config(&server, cache_dir.path().to_path_buf());
    let enricher = OsvEnricher::new(config.clone()).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];
    enricher.enrich(&mut components).unwrap();

    let enricher = OsvEnricher::new(config).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];
    let stats = enricher.enrich(&mut components).unwrap();

    batch_mock.assert_hits(1);
    vuln_mock.assert_hits(1);
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.api_calls, 0);
    assert_eq!(
        components[0].vulnerabilities[0].severity,
        Some(Severity::Critical)
    );
}

#[test]
fn repeated_enrichment_does_not_duplicate_vulnerabilities() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[VULN_ID]]));
    });
    server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    let enricher =
        OsvEnricher::new(enricher_config(&server, cache_dir.path().to_path_buf())).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];

    enricher.enrich(&mut components).unwrap();
    assert_eq!(components[0].vulnerabilities.len(), 1);

    enricher.enrich(&mut components).unwrap();
    assert_eq!(
        components[0].vulnerabilities.len(),
        1,
        "re-enrichment must not duplicate vulnerabilities"
    );
}

#[test]
fn failed_hydration_keeps_stub_and_is_not_cached() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let batch_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[VULN_ID]]));
    });
    let mut failing_vuln = server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(500).body("internal error");
    });

    let config = enricher_config(&server, cache_dir.path().to_path_buf());
    let enricher = OsvEnricher::new(config).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];
    let stats = enricher.enrich(&mut components).unwrap();

    // The id-only stub is kept so the finding is not silently dropped.
    assert!(stats.has_errors());
    assert_eq!(components[0].vulnerabilities.len(), 1);
    assert_eq!(components[0].vulnerabilities[0].id, VULN_ID);
    assert_eq!(components[0].vulnerabilities[0].severity, None);

    failing_vuln.delete();
    server.mock(|when, then| {
        when.method(GET).path(format!("/v1/vulns/{VULN_ID}"));
        then.status(200).json_body(full_vuln_body(VULN_ID));
    });

    // Nothing was cached for the component, so the next run re-queries and
    // picks up the full record.
    let mut components = vec![make_component("lodash", "4.17.20")];
    let stats = enricher.enrich(&mut components).unwrap();
    assert!(!stats.has_errors());
    assert_eq!(
        components[0].vulnerabilities[0].severity,
        Some(Severity::Critical)
    );
    batch_mock.assert_hits(2);
}

// ============================================================================
// Retry behavior on querybatch
// ============================================================================

#[test]
fn querybatch_retries_on_429_then_fails() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(429).body("rate limited");
    });

    let client = OsvClient::new(client_config(&server, 2, Duration::from_secs(5))).unwrap();
    let queries = vec![OsvQuery::from_purl("pkg:npm/lodash@4.17.20".to_string())];
    let result = client.query_batch(&queries);

    assert!(result.is_err());
    // Initial attempt + 2 retries
    mock.assert_hits(3);
    let err = result.unwrap_err();
    let source = std::error::Error::source(&err).unwrap();
    assert!(source.to_string().contains("429"));
}

#[test]
fn querybatch_recovers_after_server_error_clears() {
    let server = MockServer::start();
    let mut failing = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(500).body("internal error");
    });

    let client = OsvClient::new(client_config(&server, 1, Duration::from_secs(5))).unwrap();
    let queries = vec![OsvQuery::from_purl("pkg:npm/lodash@4.17.20".to_string())];

    assert!(client.query_batch(&queries).is_err());
    failing.assert_hits(2);
    failing.delete();

    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200).json_body(querybatch_stub_body(&[&[]]));
    });
    let responses = client.query_batch(&queries).unwrap();
    assert_eq!(responses.len(), 1);
    assert!(responses[0].results[0].vulns.is_empty());
}

#[test]
fn querybatch_times_out_and_retries() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .json_body(querybatch_stub_body(&[&[]]))
            .delay(Duration::from_millis(500));
    });

    let client = OsvClient::new(client_config(&server, 1, Duration::from_millis(50))).unwrap();
    let queries = vec![OsvQuery::from_purl("pkg:npm/lodash@4.17.20".to_string())];
    let result = client.query_batch(&queries);

    assert!(result.is_err());
    // Wait for the delayed mock responses to finish before counting hits.
    std::thread::sleep(Duration::from_millis(1200));
    mock.assert_hits(2);
}

// ============================================================================
// Cache TTL expiry + network failure
// ============================================================================

#[test]
fn expired_cache_with_network_failure_yields_no_vulns_and_error() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(503).body("unavailable");
    });

    // Pre-populate the component-level cache entry, then let it expire.
    let ttl = Duration::from_millis(50);
    let cache = FileCache::new(cache_dir.path().to_path_buf(), ttl).unwrap();
    let key = CacheKey::new(
        Some("pkg:npm/lodash@4.17.20".to_string()),
        "lodash".to_string(),
        Some("npm".to_string()),
        Some("4.17.20".to_string()),
    );
    let mut stale = VulnerabilityRef::new(VULN_ID.to_string(), VulnerabilitySource::Osv);
    stale.severity = Some(Severity::Critical);
    cache.set(&key, std::slice::from_ref(&stale)).unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let mut config = enricher_config(&server, cache_dir.path().to_path_buf());
    config.cache_ttl = ttl;
    let enricher = OsvEnricher::new(config).unwrap();
    let mut components = vec![make_component("lodash", "4.17.20")];
    let stats = enricher.enrich(&mut components).unwrap();

    // Current behavior: the expired entry is evicted (never served stale),
    // the network failure is recorded as an error, and the component stays
    // unenriched until a later run succeeds.
    mock.assert();
    assert_eq!(stats.cache_hits, 0);
    assert!(stats.has_errors());
    assert!(components[0].vulnerabilities.is_empty());
    assert!(cache.get(&key).is_none());
}
