//! Integration tests for VEX (Vulnerability Exploitability eXchange) support.

use sbom_tools::parsers::parse_sbom;
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

#[cfg(feature = "enrichment")]
mod vex_enrichment {
    use super::*;
    use sbom_tools::enrichment::VexEnricher;

    #[test]
    fn test_parse_openvex_document() {
        let vex_path = fixture_path("vex/openvex-sample.json");
        let enricher = VexEnricher::from_files(&[vex_path]).expect("Failed to parse VEX");
        let stats = enricher.stats();
        assert_eq!(stats.documents_loaded, 1);
        assert_eq!(stats.statements_parsed, 4);
    }

    #[test]
    fn test_vex_enrichment_applies_status() {
        let sbom_path = fixture_path("demo-old.cdx.json");
        let mut sbom = parse_sbom(&sbom_path).expect("Failed to parse SBOM");

        let vex_path = fixture_path("vex/openvex-sample.json");
        let mut enricher = VexEnricher::from_files(&[vex_path]).expect("Failed to parse VEX");
        let result_stats = enricher.enrich_sbom(&mut sbom);

        assert_eq!(result_stats.documents_loaded, 1);
        assert!(result_stats.statements_parsed > 0);
    }

    #[test]
    fn test_vex_pipeline_integration() {
        let sbom_path = fixture_path("demo-old.cdx.json");
        let mut sbom = parse_sbom(&sbom_path).expect("Failed to parse SBOM");

        let vex_path = fixture_path("vex/openvex-sample.json");
        let result = sbom_tools::pipeline::enrich_vex(&mut sbom, &[vex_path], true);

        assert!(result.is_some());
        let stats = result.unwrap();
        assert_eq!(stats.documents_loaded, 1);
    }

    #[test]
    fn test_vex_enrichment_stats_tracking() {
        let vex_path = fixture_path("vex/openvex-sample.json");
        let enricher = VexEnricher::from_files(&[vex_path]).expect("Failed to parse VEX");
        let stats = enricher.stats();

        // Our sample fixture has 4 statements
        assert_eq!(stats.statements_parsed, 4);
        assert_eq!(stats.vulns_matched, 0);
        assert_eq!(stats.components_with_vex, 0);
    }

    #[test]
    fn test_vex_multiple_files_override() {
        let vex_path = fixture_path("vex/openvex-sample.json");
        let enricher =
            VexEnricher::from_files(&[vex_path.clone(), vex_path]).expect("Failed to parse VEX");
        let stats = enricher.stats();
        assert_eq!(stats.documents_loaded, 2);
    }
}

#[cfg(feature = "enrichment")]
mod vex_diff_filter {
    use super::*;
    use sbom_tools::diff::DiffEngine;

    #[test]
    fn test_diff_result_filter_by_vex_no_data() {
        let old_path = fixture_path("demo-old.cdx.json");
        let new_path = fixture_path("demo-new.cdx.json");

        let old_sbom = parse_sbom(&old_path).expect("Failed to parse old SBOM");
        let new_sbom = parse_sbom(&new_path).expect("Failed to parse new SBOM");

        let engine = DiffEngine::new();
        let mut result = engine.diff(&old_sbom, &new_sbom).expect("Diff failed");

        let intro_count_before = result.vulnerabilities.introduced.len();

        // filter_by_vex with no VEX data should not remove any vulns
        result.filter_by_vex();

        assert_eq!(result.vulnerabilities.introduced.len(), intro_count_before);
    }
}

#[cfg(feature = "enrichment")]
mod vex_cyclonedx_format {
    use super::*;
    use sbom_tools::enrichment::VexEnricher;

    #[test]
    fn test_parse_cyclonedx_vex_document() {
        let vex_path = fixture_path("vex/cyclonedx-vex-sample.json");
        let enricher = VexEnricher::from_files(&[vex_path]).expect("Failed to parse CycloneDX VEX");
        let stats = enricher.stats();
        assert_eq!(stats.documents_loaded, 1);
        assert_eq!(stats.statements_parsed, 4);
    }

    #[test]
    fn test_cyclonedx_vex_enrichment() {
        let sbom_path = fixture_path("demo-old.cdx.json");
        let mut sbom = parse_sbom(&sbom_path).expect("Failed to parse SBOM");

        let vex_path = fixture_path("vex/cyclonedx-vex-sample.json");
        let mut enricher =
            VexEnricher::from_files(&[vex_path]).expect("Failed to parse CycloneDX VEX");
        let stats = enricher.enrich_sbom(&mut sbom);

        assert_eq!(stats.documents_loaded, 1);
        assert!(stats.statements_parsed > 0);
    }

    #[test]
    fn test_mixed_vex_formats() {
        // Load both OpenVEX and CycloneDX VEX in the same enricher
        let openvex_path = fixture_path("vex/openvex-sample.json");
        let cdx_vex_path = fixture_path("vex/cyclonedx-vex-sample.json");

        let enricher = VexEnricher::from_files(&[openvex_path, cdx_vex_path])
            .expect("Failed to parse mixed VEX");
        let stats = enricher.stats();
        assert_eq!(stats.documents_loaded, 2);
        // OpenVEX: 4 statements + CycloneDX VEX: 4 statements
        assert_eq!(stats.statements_parsed, 8);
    }
}

#[cfg(feature = "enrichment")]
mod vex_coverage_summary {
    use super::*;
    use sbom_tools::diff::DiffEngine;

    #[test]
    fn test_vex_summary_no_vex_data() {
        let old_path = fixture_path("demo-old.cdx.json");
        let new_path = fixture_path("demo-new.cdx.json");

        let old_sbom = parse_sbom(&old_path).expect("Failed to parse old SBOM");
        let new_sbom = parse_sbom(&new_path).expect("Failed to parse new SBOM");

        let engine = DiffEngine::new();
        let result = engine.diff(&old_sbom, &new_sbom).expect("Diff failed");
        let vex_summary = result.vulnerabilities.vex_summary();

        // Without VEX enrichment, no vulns should have VEX
        assert_eq!(vex_summary.with_vex, 0);
        // All vulns should be actionable (no VEX = actionable)
        assert_eq!(vex_summary.actionable, vex_summary.total_vulns);
        // If no vulns exist, coverage is 100% (nothing to cover)
        if vex_summary.total_vulns > 0 {
            assert_eq!(vex_summary.coverage_pct, 0.0);
        }
    }

    #[test]
    fn test_vex_summary_empty_vulns() {
        let changes = sbom_tools::diff::VulnerabilityChanges::default();
        let summary = changes.vex_summary();
        assert_eq!(summary.total_vulns, 0);
        assert_eq!(summary.coverage_pct, 100.0);
    }
}

#[cfg(feature = "enrichment")]
mod vex_exit_codes {
    use sbom_tools::diff::{VulnerabilityChanges, VulnerabilityDetail};
    use sbom_tools::model::VexState;
    use sbom_tools::pipeline::exit_codes;

    /// Helper to create a minimal VulnerabilityDetail for testing.
    fn make_vuln(id: &str, vex_state: Option<VexState>) -> VulnerabilityDetail {
        VulnerabilityDetail {
            id: id.to_string(),
            source: String::new(),
            severity: String::new(),
            cvss_score: None,
            component_id: String::new(),
            component_canonical_id: None,
            component_ref: None,
            component_name: String::new(),
            version: None,
            cwes: Vec::new(),
            description: None,
            remediation: None,
            is_kev: false,
            component_depth: None,
            published_date: None,
            kev_due_date: None,
            days_since_published: None,
            days_until_due: None,
            vex_state,
            vex_justification: None,
            vex_impact_statement: None,
        }
    }

    #[test]
    fn test_vex_summary_introduced_without_vex() {
        let mut vulns = VulnerabilityChanges::default();
        vulns.introduced.push(make_vuln("CVE-2024-0001", None));
        vulns
            .introduced
            .push(make_vuln("CVE-2024-0002", Some(VexState::NotAffected)));

        let summary = vulns.vex_summary();
        assert_eq!(summary.total_vulns, 2);
        assert_eq!(summary.with_vex, 1);
        assert_eq!(summary.without_vex, 1);
        assert_eq!(summary.introduced_without_vex, 1);
        assert_eq!(summary.coverage_pct, 50.0);
    }

    #[test]
    fn test_vex_summary_actionable_counts() {
        let mut vulns = VulnerabilityChanges::default();
        // NotAffected — not actionable
        vulns
            .persistent
            .push(make_vuln("CVE-1", Some(VexState::NotAffected)));
        // Fixed — not actionable
        vulns
            .resolved
            .push(make_vuln("CVE-2", Some(VexState::Fixed)));
        // Affected — actionable
        vulns
            .introduced
            .push(make_vuln("CVE-3", Some(VexState::Affected)));
        // No VEX — actionable
        vulns.introduced.push(make_vuln("CVE-4", None));

        let summary = vulns.vex_summary();
        assert_eq!(summary.total_vulns, 4);
        assert_eq!(summary.actionable, 2); // CVE-3 (Affected) + CVE-4 (None)
        assert_eq!(summary.with_vex, 3);
        assert_eq!(summary.introduced_without_vex, 1); // only CVE-4
    }

    #[test]
    fn test_vex_summary_persistent_without_vex() {
        let mut vulns = VulnerabilityChanges::default();
        vulns.persistent.push(make_vuln("CVE-1", None));
        vulns
            .persistent
            .push(make_vuln("CVE-2", Some(VexState::Affected)));
        vulns.introduced.push(make_vuln("CVE-3", None));

        let summary = vulns.vex_summary();
        assert_eq!(summary.persistent_without_vex, 1); // CVE-1
        assert_eq!(summary.introduced_without_vex, 1); // CVE-3
    }

    #[test]
    fn test_vex_gaps_found_exit_code_value() {
        assert_eq!(exit_codes::VEX_GAPS_FOUND, 4);
        assert_ne!(exit_codes::VEX_GAPS_FOUND, exit_codes::VULNS_INTRODUCED);
        assert_ne!(exit_codes::VEX_GAPS_FOUND, exit_codes::CHANGES_DETECTED);
        assert_ne!(exit_codes::VEX_GAPS_FOUND, exit_codes::ERROR);
    }

    #[test]
    fn test_vex_summary_by_state_keys() {
        let mut vulns = VulnerabilityChanges::default();
        vulns
            .introduced
            .push(make_vuln("CVE-1", Some(VexState::Affected)));
        vulns
            .introduced
            .push(make_vuln("CVE-2", Some(VexState::Affected)));
        vulns
            .resolved
            .push(make_vuln("CVE-3", Some(VexState::Fixed)));

        let summary = vulns.vex_summary();
        assert_eq!(summary.by_state.get(&VexState::Affected), Some(&2));
        assert_eq!(summary.by_state.get(&VexState::Fixed), Some(&1));
        assert_eq!(summary.by_state.get(&VexState::NotAffected), None);
    }
}

mod vex_model {
    use sbom_tools::model::{VexState, VexStatus};

    #[test]
    fn test_vex_state_variants() {
        let states = [
            VexState::NotAffected,
            VexState::Fixed,
            VexState::Affected,
            VexState::UnderInvestigation,
        ];
        assert_eq!(states.len(), 4);
    }

    #[test]
    fn test_vex_status_construction() {
        let status = VexStatus {
            status: VexState::NotAffected,
            justification: None,
            action_statement: None,
            impact_statement: Some("Not used in our code".to_string()),
            responses: Vec::new(),
            detail: None,
        };
        assert_eq!(status.status, VexState::NotAffected);
        assert!(status.impact_statement.is_some());
    }
}
