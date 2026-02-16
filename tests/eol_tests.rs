//! End-of-life (EOL) detection integration tests.
//!
//! Tests the full EOL enrichment pipeline: data model, product mapping,
//! version-to-cycle matching, status computation, report integration,
//! and quality scoring.

use sbom_tools::enrichment::eol::{EolClientConfig, EolEnrichmentStats};
use sbom_tools::model::{
    Component, EolInfo, EolStatus, NormalizedSbom,
};

// ============================================================================
// Helper: build components with EOL data pre-attached
// ============================================================================

fn make_component(name: &str, version: &str, purl: Option<&str>) -> Component {
    let mut comp = Component::new(name.to_string(), format!("pkg:{name}"));
    comp.version = Some(version.to_string());
    if let Some(p) = purl {
        comp = comp.with_purl(p.to_string());
    }
    comp
}

fn make_eol_info(
    status: EolStatus,
    product: &str,
    cycle: &str,
    eol_date: Option<&str>,
    days_until_eol: Option<i64>,
) -> EolInfo {
    EolInfo {
        status,
        product: product.to_string(),
        cycle: cycle.to_string(),
        eol_date: eol_date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()),
        support_end_date: None,
        is_lts: false,
        latest_in_cycle: None,
        latest_release_date: None,
        days_until_eol,
    }
}

fn make_eol_sbom() -> NormalizedSbom {
    use sbom_tools::model::DocumentMetadata;

    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

    // 1. EOL component: Python 2.7 (long past EOL)
    let mut python27 = make_component("python", "2.7.18", Some("pkg:pypi/python@2.7.18"));
    python27.eol = Some(EolInfo {
        status: EolStatus::EndOfLife,
        product: "python".to_string(),
        cycle: "2.7".to_string(),
        eol_date: chrono::NaiveDate::from_ymd_opt(2020, 1, 1),
        support_end_date: chrono::NaiveDate::from_ymd_opt(2020, 1, 1),
        is_lts: false,
        latest_in_cycle: Some("2.7.18".to_string()),
        latest_release_date: chrono::NaiveDate::from_ymd_opt(2020, 4, 20),
        days_until_eol: Some(-2200),
    });
    sbom.add_component(python27);

    // 2. Approaching EOL: Node.js 18 (close to EOL)
    let mut node18 = make_component("nodejs", "18.19.0", Some("pkg:npm/nodejs@18.19.0"));
    node18.eol = Some(EolInfo {
        status: EolStatus::ApproachingEol,
        product: "nodejs".to_string(),
        cycle: "18".to_string(),
        eol_date: chrono::NaiveDate::from_ymd_opt(2025, 4, 30),
        support_end_date: chrono::NaiveDate::from_ymd_opt(2023, 10, 18),
        is_lts: true,
        latest_in_cycle: Some("18.20.1".to_string()),
        latest_release_date: chrono::NaiveDate::from_ymd_opt(2024, 3, 26),
        days_until_eol: Some(90),
    });
    sbom.add_component(node18);

    // 3. Security-only: Django 4.2 (active support ended, security updates continue)
    let mut django42 = make_component("django", "4.2.8", Some("pkg:pypi/django@4.2.8"));
    django42.eol = Some(EolInfo {
        status: EolStatus::SecurityOnly,
        product: "django".to_string(),
        cycle: "4.2".to_string(),
        eol_date: chrono::NaiveDate::from_ymd_opt(2026, 4, 1),
        support_end_date: chrono::NaiveDate::from_ymd_opt(2023, 12, 1),
        is_lts: true,
        latest_in_cycle: Some("4.2.11".to_string()),
        latest_release_date: chrono::NaiveDate::from_ymd_opt(2024, 3, 4),
        days_until_eol: Some(500),
    });
    sbom.add_component(django42);

    // 4. Supported: React (actively supported)
    let mut react = make_component("react", "18.2.0", Some("pkg:npm/react@18.2.0"));
    react.eol = Some(make_eol_info(
        EolStatus::Supported,
        "react",
        "18",
        Some("2099-12-31"),
        Some(27000),
    ));
    sbom.add_component(react);

    // 5. Unknown cycle: a component that was found but version didn't match
    let mut mystery = make_component("some-tool", "99.0.0", None);
    mystery.eol = Some(make_eol_info(EolStatus::Unknown, "some-tool", "", None, None));
    sbom.add_component(mystery);

    // 6. No EOL data: component without enrichment
    let lodash = make_component("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"));
    sbom.add_component(lodash);

    sbom
}

// ============================================================================
// Data Model Tests
// ============================================================================

mod model_tests {
    use super::*;

    #[test]
    fn eol_status_labels() {
        assert_eq!(EolStatus::Supported.label(), "Supported");
        assert_eq!(EolStatus::SecurityOnly.label(), "Security Only");
        assert_eq!(EolStatus::ApproachingEol.label(), "Approaching EOL");
        assert_eq!(EolStatus::EndOfLife.label(), "End of Life");
        assert_eq!(EolStatus::Unknown.label(), "Unknown");
    }

    #[test]
    fn eol_status_icons() {
        assert_eq!(EolStatus::Supported.icon(), "✓");
        assert_eq!(EolStatus::EndOfLife.icon(), "⛔");
        assert_eq!(EolStatus::ApproachingEol.icon(), "⚠");
    }

    #[test]
    fn eol_status_severity_ordering() {
        assert!(EolStatus::Supported.severity() < EolStatus::SecurityOnly.severity());
        assert!(EolStatus::SecurityOnly.severity() < EolStatus::ApproachingEol.severity());
        assert!(EolStatus::ApproachingEol.severity() < EolStatus::EndOfLife.severity());
    }

    #[test]
    fn eol_status_display() {
        assert_eq!(format!("{}", EolStatus::EndOfLife), "End of Life");
        assert_eq!(format!("{}", EolStatus::Supported), "Supported");
    }

    #[test]
    fn eol_info_serialization_roundtrip() {
        let info = EolInfo {
            status: EolStatus::ApproachingEol,
            product: "python".to_string(),
            cycle: "3.11".to_string(),
            eol_date: chrono::NaiveDate::from_ymd_opt(2027, 10, 31),
            support_end_date: chrono::NaiveDate::from_ymd_opt(2024, 4, 1),
            is_lts: false,
            latest_in_cycle: Some("3.11.8".to_string()),
            latest_release_date: chrono::NaiveDate::from_ymd_opt(2024, 2, 6),
            days_until_eol: Some(1200),
        };

        let json = serde_json::to_string(&info).expect("serialize");
        let roundtrip: EolInfo = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(roundtrip.status, EolStatus::ApproachingEol);
        assert_eq!(roundtrip.product, "python");
        assert_eq!(roundtrip.cycle, "3.11");
        assert_eq!(roundtrip.eol_date, info.eol_date);
        assert!(!roundtrip.is_lts);
        assert_eq!(roundtrip.latest_in_cycle.as_deref(), Some("3.11.8"));
        assert_eq!(roundtrip.days_until_eol, Some(1200));
    }

    #[test]
    fn component_eol_field_default_none() {
        let comp = Component::new("test".to_string(), "pkg:test".to_string());
        assert!(comp.eol.is_none());
    }

    #[test]
    fn component_with_eol_data() {
        let mut comp = make_component("python", "3.11.5", Some("pkg:pypi/python@3.11.5"));
        comp.eol = Some(make_eol_info(
            EolStatus::Supported,
            "python",
            "3.11",
            Some("2027-10-31"),
            Some(1200),
        ));

        assert!(comp.eol.is_some());
        let eol = comp.eol.as_ref().unwrap();
        assert_eq!(eol.status, EolStatus::Supported);
        assert_eq!(eol.product, "python");
        assert_eq!(eol.cycle, "3.11");
    }
}

// ============================================================================
// Product Mapping Tests
// ============================================================================

mod mapping_tests {
    use super::*;
    use sbom_tools::enrichment::eol::ProductMapper;

    #[test]
    fn mapper_resolve_purl_django() {
        let mapper = ProductMapper::new(vec!["django".to_string()]);
        let comp = make_component("Django", "4.2.8", Some("pkg:pypi/django@4.2.8"));
        let resolved = mapper.resolve(&comp);

        assert!(resolved.is_some());
        let r = resolved.unwrap();
        assert_eq!(r.product, "django");
        assert_eq!(r.version, "4.2.8");
    }

    #[test]
    fn mapper_resolve_purl_angular() {
        let mapper = ProductMapper::new(vec!["angular".to_string()]);
        // Scoped npm packages use %40 encoding for @ in proper PURLs
        let comp = make_component(
            "@angular/core",
            "16.0.0",
            Some("pkg:npm/%40angular/core@16.0.0"),
        );
        let resolved = mapper.resolve(&comp);

        assert!(resolved.is_some());
        let r = resolved.unwrap();
        assert_eq!(r.product, "angular");
    }

    #[test]
    fn mapper_resolve_system_package() {
        let mapper = ProductMapper::new(vec!["postgresql".to_string()]);
        // System packages without namespace in PURL
        let comp = make_component(
            "postgresql-15",
            "15.4",
            Some("pkg:deb/postgresql-15@15.4"),
        );
        let resolved = mapper.resolve(&comp);

        assert!(resolved.is_some());
        let r = resolved.unwrap();
        assert_eq!(r.product, "postgresql");
    }

    #[test]
    fn mapper_no_version_returns_none() {
        let mapper = ProductMapper::new(vec!["django".to_string()]);
        let comp = Component::new("django".to_string(), "pkg:django".to_string());
        // No version set
        assert!(mapper.resolve(&comp).is_none());
    }

    #[test]
    fn mapper_unknown_package_returns_none() {
        let mapper = ProductMapper::new(vec!["django".to_string()]);
        let comp = make_component(
            "my-internal-lib",
            "1.0.0",
            Some("pkg:cargo/my-internal-lib@1.0.0"),
        );
        assert!(mapper.resolve(&comp).is_none());
    }

    #[test]
    fn mapper_fuzzy_match_case_insensitive() {
        let mapper = ProductMapper::new(vec![
            "django".to_string(),
            "redis".to_string(),
            "nginx".to_string(),
        ]);
        // Component without PURL, uses fuzzy matching
        let mut comp = Component::new("Redis".to_string(), "pkg:redis".to_string());
        comp.version = Some("7.0.0".to_string());
        let resolved = mapper.resolve(&comp);

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().product, "redis");
    }
}

// ============================================================================
// SBOM-Level Tests (EOL Counts & Filtering)
// ============================================================================

mod sbom_tests {
    use super::*;

    #[test]
    fn eol_sbom_has_correct_component_count() {
        let sbom = make_eol_sbom();
        assert_eq!(sbom.component_count(), 6);
    }

    #[test]
    fn eol_sbom_status_distribution() {
        let sbom = make_eol_sbom();

        let mut eol_count = 0;
        let mut approaching = 0;
        let mut security_only = 0;
        let mut supported = 0;
        let mut unknown = 0;
        let mut no_data = 0;

        for comp in sbom.components.values() {
            match &comp.eol {
                Some(info) => match info.status {
                    EolStatus::EndOfLife => eol_count += 1,
                    EolStatus::ApproachingEol => approaching += 1,
                    EolStatus::SecurityOnly => security_only += 1,
                    EolStatus::Supported => supported += 1,
                    EolStatus::Unknown => unknown += 1,
                    _ => {} // non_exhaustive
                },
                None => no_data += 1,
            }
        }

        assert_eq!(eol_count, 1, "Python 2.7 is EOL");
        assert_eq!(approaching, 1, "Node.js 18 is approaching EOL");
        assert_eq!(security_only, 1, "Django 4.2 is security-only");
        assert_eq!(supported, 1, "React 18 is supported");
        assert_eq!(unknown, 1, "some-tool has unknown cycle");
        assert_eq!(no_data, 1, "lodash has no EOL data");
    }

    #[test]
    fn eol_filter_eol_only() {
        let sbom = make_eol_sbom();
        let eol_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| {
                c.eol
                    .as_ref()
                    .is_some_and(|e| e.status == EolStatus::EndOfLife)
            })
            .collect();
        assert_eq!(eol_components.len(), 1);
        assert_eq!(eol_components[0].name, "python");
    }

    #[test]
    fn eol_filter_risk() {
        let sbom = make_eol_sbom();
        let risk_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| {
                c.eol.as_ref().is_some_and(|e| {
                    matches!(
                        e.status,
                        EolStatus::EndOfLife | EolStatus::ApproachingEol | EolStatus::SecurityOnly
                    )
                })
            })
            .collect();
        assert_eq!(risk_components.len(), 3, "python + nodejs + django");
    }

    #[test]
    fn eol_lts_tracking() {
        let sbom = make_eol_sbom();

        let lts_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.eol.as_ref().is_some_and(|e| e.is_lts))
            .collect();

        assert_eq!(lts_components.len(), 2, "Node.js 18 and Django 4.2 are LTS");
    }

    #[test]
    fn eol_update_available_detection() {
        let sbom = make_eol_sbom();

        // Node.js 18.19.0 has latest_in_cycle = 18.20.1 → update available
        let nodejs = sbom.components.values().find(|c| c.name == "nodejs").unwrap();
        let eol = nodejs.eol.as_ref().unwrap();
        let current_version = nodejs.version.as_deref().unwrap();
        let latest = eol.latest_in_cycle.as_deref().unwrap();
        assert_ne!(current_version, latest, "Node.js 18 has an update available");

        // Python 2.7.18 has latest_in_cycle = 2.7.18 → up to date (within cycle)
        let python = sbom.components.values().find(|c| c.name == "python").unwrap();
        let eol = python.eol.as_ref().unwrap();
        let current_version = python.version.as_deref().unwrap();
        let latest = eol.latest_in_cycle.as_deref().unwrap();
        assert_eq!(current_version, latest, "Python 2.7 is at latest in cycle");
    }
}

// ============================================================================
// Configuration Tests
// ============================================================================

mod config_tests {
    use super::*;

    #[test]
    fn eol_client_config_defaults() {
        let config = EolClientConfig::default();
        assert!(!config.bypass_cache);
        assert_eq!(config.base_url, "https://endoflife.date");
        assert_eq!(config.cache_ttl.as_secs(), 24 * 3600);
        assert_eq!(config.product_list_ttl.as_secs(), 7 * 24 * 3600);
    }

    #[test]
    fn enrichment_config_eol_default_disabled() {
        let config = sbom_tools::config::EnrichmentConfig::default();
        assert!(!config.enable_eol, "EOL enrichment should be disabled by default");
    }

    #[test]
    fn enricher_config_eol_default_disabled() {
        let config = sbom_tools::enrichment::EnricherConfig::default();
        assert!(!config.enable_eol, "EOL enrichment should be disabled by default");
    }

    #[test]
    fn eol_enrichment_stats_default() {
        let stats = EolEnrichmentStats::default();
        assert_eq!(stats.components_checked, 0);
        assert_eq!(stats.components_enriched, 0);
        assert_eq!(stats.eol_count, 0);
        assert_eq!(stats.approaching_eol_count, 0);
        assert_eq!(stats.supported_count, 0);
        assert_eq!(stats.security_only_count, 0);
        assert_eq!(stats.unknown_count, 0);
        assert_eq!(stats.api_calls, 0);
        assert_eq!(stats.cache_hits, 0);
        assert!(stats.errors.is_empty());
        assert_eq!(stats.skipped_count, 0);
    }
}

// ============================================================================
// Report Integration Tests
// ============================================================================

mod report_tests {
    use super::*;
    use sbom_tools::parsers::parse_sbom;
    use sbom_tools::reports::{create_reporter, ReportConfig, ReportFormat};
    use std::path::Path;

    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture_path(name: &str) -> std::path::PathBuf {
        Path::new(FIXTURES_DIR).join(name)
    }

    #[test]
    fn json_report_includes_eol_fields() {
        let sbom = make_eol_sbom();
        let reporter = create_reporter(ReportFormat::Json);
        let config = ReportConfig::default();
        let report = reporter.generate_view_report(&sbom, &config);

        assert!(report.is_ok());
        let output = report.unwrap();

        // Verify EOL fields are present in JSON
        assert!(output.contains("eol_status"), "JSON should include eol_status field");
        assert!(output.contains("End of Life"), "JSON should contain EOL status value");
        assert!(output.contains("Approaching EOL"), "JSON should contain Approaching EOL");
        assert!(output.contains("Supported"), "JSON should contain Supported status");
    }

    #[test]
    fn csv_report_includes_eol_columns() {
        let sbom = make_eol_sbom();
        let reporter = create_reporter(ReportFormat::Csv);
        let config = ReportConfig::default();
        let report = reporter.generate_view_report(&sbom, &config);

        assert!(report.is_ok());
        let output = report.unwrap();

        // CSV header should include EOL columns
        let first_line = output.lines().next().unwrap_or("");
        assert!(first_line.contains("EOL Status"), "CSV header should include EOL Status");
        assert!(first_line.contains("EOL Date"), "CSV header should include EOL Date");

        // Data rows should contain EOL values
        assert!(output.contains("End of Life"), "CSV should contain EOL status");
        assert!(output.contains("2020-01-01"), "CSV should contain Python 2.7 EOL date");
    }

    #[test]
    fn summary_diff_report_includes_eol_section() {
        // EOL summary is in the diff report (not the view summary)
        let old_sbom = make_eol_sbom();
        let mut new_sbom = make_eol_sbom();

        // Add another EOL component to new SBOM to ensure counts differ
        let mut extra = make_component("ruby", "2.7.8", Some("pkg:gem/ruby@2.7.8"));
        extra.eol = Some(make_eol_info(
            EolStatus::EndOfLife,
            "ruby",
            "2.7",
            Some("2023-03-31"),
            Some(-1000),
        ));
        new_sbom.add_component(extra);

        let engine = sbom_tools::diff::DiffEngine::default();
        let diff = engine.diff(&old_sbom, &new_sbom).expect("diff should succeed");

        let reporter = create_reporter(ReportFormat::Summary);
        let config = ReportConfig::default();
        let report = reporter.generate_diff_report(&diff, &old_sbom, &new_sbom, &config);

        assert!(report.is_ok());
        let output = report.unwrap();

        assert!(
            output.contains("End-of-Life") || output.contains("EOL"),
            "Summary diff should mention End-of-Life: {output}"
        );
    }

    #[test]
    fn diff_report_includes_eol_data() {
        // Parse two real SBOMs, add EOL data, and diff
        let old_path = fixture_path("demo-old.cdx.json");
        let new_path = fixture_path("demo-new.cdx.json");

        let old_sbom = parse_sbom(&old_path).expect("parse old");
        let mut new_sbom = parse_sbom(&new_path).expect("parse new");

        // Add EOL data to a component in the new SBOM
        for comp in new_sbom.components.values_mut() {
            if comp.name.contains("express") || comp.name.contains("lodash") {
                comp.eol = Some(make_eol_info(
                    EolStatus::EndOfLife,
                    &comp.name,
                    "4",
                    Some("2024-01-01"),
                    Some(-400),
                ));
                break;
            }
        }

        let engine = sbom_tools::diff::DiffEngine::default();
        let diff = engine.diff(&old_sbom, &new_sbom).expect("diff should succeed");
        let config = ReportConfig::default();

        // Markdown report
        let md_reporter = create_reporter(ReportFormat::Markdown);
        let md_report = md_reporter.generate_diff_report(&diff, &old_sbom, &new_sbom, &config);
        assert!(md_report.is_ok());

        // HTML report
        let html_reporter = create_reporter(ReportFormat::Html);
        let html_report = html_reporter.generate_diff_report(&diff, &old_sbom, &new_sbom, &config);
        assert!(html_report.is_ok());

        // SARIF report
        let sarif_reporter = create_reporter(ReportFormat::Sarif);
        let sarif_report = sarif_reporter.generate_diff_report(&diff, &old_sbom, &new_sbom, &config);
        assert!(sarif_report.is_ok());
        let sarif_output = sarif_report.unwrap();
        // SARIF rules should include EOL rules
        assert!(
            sarif_output.contains("SBOM-EOL-001") || sarif_output.contains("SBOM-EOL-002")
                || sarif_output.contains("ComponentEndOfLife") || sarif_output.contains("ComponentApproachingEol"),
            "SARIF should contain EOL rules definitions"
        );
    }
}

// ============================================================================
// Quality / Compliance Integration Tests
// ============================================================================

mod quality_tests {
    use super::*;
    use sbom_tools::quality::{QualityScorer, ScoringProfile};

    #[test]
    fn quality_scorer_handles_eol_components() {
        let sbom = make_eol_sbom();
        let scorer = QualityScorer::new(ScoringProfile::Standard);
        let report = scorer.score(&sbom);

        // Quality report should complete without errors and produce a valid score
        assert!(report.overall_score >= 0.0);
        assert!(report.overall_score <= 100.0);
    }
}

// ============================================================================
// TUI State Tests are in src/tui/app_states/components.rs (unit tests)
// since ComponentFilter/ComponentsState are crate-private.
// ============================================================================
