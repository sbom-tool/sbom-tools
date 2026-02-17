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

        assert_eq!(
            result.vulnerabilities.introduced.len(),
            intro_count_before
        );
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
            response: None,
            detail: None,
        };
        assert_eq!(status.status, VexState::NotAffected);
        assert!(status.impact_statement.is_some());
    }
}
