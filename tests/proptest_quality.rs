//! Property-based tests for quality scoring and SBOM merge invariants.
//!
//! Verifies that `QualityScorer` produces bounded scores with grades
//! consistent with the score across all scoring profiles, and that merging
//! an SBOM with itself (raw-JSON layer) preserves the component count.

use proptest::prelude::*;
use sbom_tools::model::{Component, DocumentMetadata, NormalizedSbom};
use sbom_tools::quality::{QualityGrade, QualityScorer, ScoringProfile};
use sbom_tools::serialization::{MergeConfig, merge_sbom_json};

/// Generate an arbitrary component with random fields.
///
/// Mirrors `arb_component` in `proptest_matching.rs`: names are at least
/// 3 characters with no hyphens to avoid known alias-table asymmetries.
fn arb_component() -> impl Strategy<Value = Component> {
    (
        "[a-z][a-z0-9]{2}[a-z0-9]{0,17}", // name (min 3 chars, no hyphens to avoid alias asymmetry)
        prop::option::of("[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}"), // version
        prop::option::of(prop::sample::select(vec![
            "npm", "pypi", "maven", "cargo", "golang",
        ])),
    )
        .prop_map(|(name, version, ecosystem)| {
            let format_id = format!("test:{name}");
            let mut comp = Component::new(name, format_id);
            if let Some(v) = version {
                comp = comp.with_version(v);
            }
            if let Some(eco) = ecosystem {
                comp.ecosystem = Some(sbom_tools::model::Ecosystem::from_purl_type(eco));
            }
            comp
        })
}

fn build_sbom(components: Vec<Component>) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    for mut comp in components {
        comp.calculate_content_hash();
        sbom.add_component(comp);
    }
    sbom
}

const ALL_PROFILES: [ScoringProfile; 9] = [
    ScoringProfile::Minimal,
    ScoringProfile::Standard,
    ScoringProfile::Security,
    ScoringProfile::LicenseCompliance,
    ScoringProfile::Cra,
    ScoringProfile::BsiTr03183_2,
    ScoringProfile::Comprehensive,
    ScoringProfile::Cbom,
    ScoringProfile::AiReadiness,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn quality_score_bounded_with_consistent_grade(
        components in prop::collection::vec(arb_component(), 0..60),
    ) {
        let sbom = build_sbom(components);

        for profile in ALL_PROFILES {
            let report = QualityScorer::new(profile).score(&sbom);

            prop_assert!(
                report.overall_score.is_finite()
                    && (0.0..=100.0).contains(&report.overall_score),
                "score out of range for {:?}: {}",
                profile,
                report.overall_score
            );
            prop_assert_eq!(
                report.grade,
                QualityGrade::from_score(report.overall_score),
                "grade {:?} inconsistent with score {} for {:?}",
                report.grade,
                report.overall_score,
                profile
            );
        }
    }

    #[test]
    fn merge_with_self_preserves_component_count(
        components in prop::collection::vec(arb_component(), 0..40),
    ) {
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components
                .iter()
                .map(|c| serde_json::json!({"name": c.name, "version": c.version}))
                .collect::<Vec<_>>(),
        });
        let doc_str = doc.to_string();

        let merged = merge_sbom_json(&doc_str, &doc_str, &MergeConfig::default())
            .expect("merge should succeed");
        let merged_doc: serde_json::Value =
            serde_json::from_str(&merged).expect("merged output should be valid JSON");
        let merged_count = merged_doc["components"].as_array().map_or(0, Vec::len);

        prop_assert_eq!(merged_count, components.len());
    }
}
