//! Integration tests for KEV and staleness enrichment wiring.
//!
//! Covers:
//! - `enrich_sbom_full` flagging a matching vulnerability via a mocked CISA KEV
//!   catalog (httpmock),
//! - the `diff --fail-on-kev` exit-code gate end-to-end through the CLI binary,
//! - staleness data flowing into the Lifecycle quality metric.

#![cfg(feature = "enrichment")]

use sbom_tools::config::EnrichmentConfig;
use sbom_tools::model::{
    Component, NormalizedSbom, StalenessInfo, StalenessLevel, VulnerabilityRef, VulnerabilitySource,
};
use sbom_tools::pipeline::enrich_sbom_full;
use sbom_tools::quality::LifecycleMetrics;

use httpmock::prelude::*;
use std::path::PathBuf;
use std::process::Command;

/// A CISA KEV catalog body containing a single entry for the given CVE.
fn kev_catalog_body(cve_id: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.06.01",
        "dateReleased": "2026-06-01T12:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": cve_id,
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains a vulnerability allowing RCE.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": ""
            }
        ]
    })
}

fn component_with_vuln(name: &str, version: &str, cve_id: &str) -> Component {
    let mut comp = Component::new(name.to_string(), format!("{name}@{version}"))
        .with_purl(format!("pkg:maven/{name}@{version}"))
        .with_version(version.to_string());
    comp.vulnerabilities.push(VulnerabilityRef::new(
        cve_id.to_string(),
        VulnerabilitySource::Nvd,
    ));
    comp
}

#[test]
fn enrich_sbom_full_flags_kev_vulnerability() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let kev_mock = server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200)
            .json_body(kev_catalog_body("CVE-2021-44228"));
    });

    let mut sbom = NormalizedSbom::default();
    sbom.add_component(component_with_vuln(
        "log4j-core",
        "2.14.0",
        "CVE-2021-44228",
    ));
    // A non-KEV CVE that must remain unflagged.
    sbom.add_component(component_with_vuln("lodash", "4.17.20", "CVE-2021-23337"));

    let config = EnrichmentConfig::default()
        .with_kev()
        .with_kev_url(format!("{}/kev.json", server.base_url()))
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();

    let stats = enrich_sbom_full(&mut sbom, &config, true);

    kev_mock.assert();
    let kev_stats = stats.kev.expect("KEV stats should be produced");
    assert_eq!(
        kev_stats.kev_matches, 1,
        "exactly one CVE is in the catalog"
    );

    let log4j = sbom
        .components
        .values()
        .find(|c| c.name == "log4j-core")
        .expect("log4j component present");
    assert!(
        log4j.vulnerabilities[0].is_kev,
        "the KEV-listed CVE must be flagged is_kev"
    );
    assert!(
        log4j.vulnerabilities[0].kev_info.is_some(),
        "KEV metadata must be attached"
    );

    let lodash = sbom
        .components
        .values()
        .find(|c| c.name == "lodash")
        .expect("lodash component present");
    assert!(
        !lodash.vulnerabilities[0].is_kev,
        "a non-KEV CVE must stay unflagged"
    );
}

/// A FIRST EPSS CSV body scoring the given CVE, plus an unrelated low-score row.
fn epss_csv_body(cve_id: &str) -> String {
    format!(
        "#model_version:v2023.03.01,score_date:2026-06-01T00:00:00+0000\n\
         cve,epss,percentile\n\
         {cve_id},0.91234,0.99876\n\
         CVE-2000-0001,0.00010,0.01234\n"
    )
}

#[test]
fn enrich_sbom_full_sets_epss_score() {
    let server = MockServer::start();
    let cache_dir = tempfile::tempdir().unwrap();

    let epss_mock = server.mock(|when, then| {
        when.method(GET).path("/epss.csv");
        then.status(200)
            .header("content-type", "text/csv")
            .body(epss_csv_body("CVE-2021-44228"));
    });

    let mut sbom = NormalizedSbom::default();
    sbom.add_component(component_with_vuln(
        "log4j-core",
        "2.14.0",
        "CVE-2021-44228",
    ));
    // A CVE absent from the dataset must stay unscored.
    sbom.add_component(component_with_vuln("lodash", "4.17.20", "CVE-2021-23337"));

    let config = EnrichmentConfig::default()
        .with_epss()
        .with_epss_url(format!("{}/epss.csv", server.base_url()))
        .with_cache_dir(cache_dir.path().to_path_buf())
        .with_bypass_cache();

    let stats = enrich_sbom_full(&mut sbom, &config, true);

    epss_mock.assert();
    let epss_stats = stats.epss.expect("EPSS stats should be produced");
    assert_eq!(
        epss_stats.epss_matches, 1,
        "exactly one CVE is in the dataset"
    );
    assert_eq!(epss_stats.high_probability, 1, "the match scores >= 0.5");

    let log4j = sbom
        .components
        .values()
        .find(|c| c.name == "log4j-core")
        .expect("log4j component present");
    assert_eq!(
        log4j.vulnerabilities[0].epss_score,
        Some(0.91234),
        "the dataset score must be applied"
    );
    assert_eq!(
        log4j.vulnerabilities[0].epss_percentile,
        Some(0.99876),
        "the dataset percentile must be applied"
    );

    let lodash = sbom
        .components
        .values()
        .find(|c| c.name == "lodash")
        .expect("lodash component present");
    assert!(
        lodash.vulnerabilities[0].epss_score.is_none(),
        "a CVE absent from the dataset must stay unscored"
    );
}

#[test]
fn staleness_enrichment_feeds_lifecycle_metric() {
    // A component carrying staleness data (as the staleness enricher would
    // populate) must register in the Lifecycle quality metric.
    let mut sbom = NormalizedSbom::default();

    let mut fresh = Component::new("fresh-lib".to_string(), "fresh-lib@1.0.0".to_string())
        .with_version("1.0.0".to_string());
    fresh.staleness = Some(StalenessInfo::new(StalenessLevel::Fresh));
    sbom.add_component(fresh);

    let mut stale = Component::new("stale-lib".to_string(), "stale-lib@0.1.0".to_string())
        .with_version("0.1.0".to_string());
    let mut stale_info = StalenessInfo::new(StalenessLevel::Stale);
    stale_info.is_deprecated = true;
    stale.staleness = Some(stale_info);
    sbom.add_component(stale);

    let metrics = LifecycleMetrics::from_sbom(&sbom);

    assert_eq!(
        metrics.enriched_components, 2,
        "both components have lifecycle (staleness) data"
    );
    assert_eq!(metrics.stale_components, 1, "one component is Stale");
    assert!(
        metrics.enrichment_coverage > 0.0,
        "coverage must be non-zero so Lifecycle is no longer N/A"
    );
}

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbom-tools"))
}

fn write_sbom(dir: &std::path::Path, name: &str, components: &str) -> PathBuf {
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

#[test]
fn diff_fail_on_kev_returns_exit_code_6() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/kev.json");
        then.status(200)
            .json_body(kev_catalog_body("CVE-2021-44228"));
    });
    let cache_dir = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    // Old SBOM has only lodash; new SBOM adds a log4j component carrying an
    // embedded, KEV-listed CVE, so CVE-2021-44228 is "introduced".
    let old = write_sbom(
        work.path(),
        "old.cdx.json",
        r#""components": [
    { "type": "library", "bom-ref": "lodash@4.17.21", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21" }
  ]"#,
    );
    let new = write_sbom(
        work.path(),
        "new.cdx.json",
        r#""components": [
    { "type": "library", "bom-ref": "lodash@4.17.21", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21" },
    { "type": "library", "bom-ref": "log4j@2.14.0", "name": "log4j", "version": "2.14.0", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0" }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": { "name": "NVD" },
      "ratings": [ { "score": 10.0, "severity": "critical", "method": "CVSSv31" } ],
      "affects": [ { "ref": "log4j@2.14.0" } ]
    }
  ]"#,
    );

    let output = Command::new(bin_path())
        .arg("--no-color")
        .env("RUST_LOG", "error")
        .env(
            "SBOM_TOOLS_KEV_URL",
            format!("{}/kev.json", server.base_url()),
        )
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .args(["-o", "summary"])
        .args(["--kev", "--fail-on-kev", "--refresh"])
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .expect("diff command should run");

    assert_eq!(
        output.status.code(),
        Some(6),
        "introduced KEV vuln must yield exit code 6\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
