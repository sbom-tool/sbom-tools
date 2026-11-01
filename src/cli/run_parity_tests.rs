//! One compliance run, every entry point: `validate`, the `view` TUI and the
//! `diff` TUI report identical results for the same SBOM, CRA sidecar,
//! product class and `--as-of`. Each path builds its run the way its command
//! does, and each is compared through the `-o json` envelope `validate`
//! writes.

use super::{ValidateJsonSchema, compliance_run_config, run_validate};
use crate::config::{DiffConfigBuilder, EnrichmentConfig, OutputConfig, ViewConfig};
use crate::diff::DiffResult;
use crate::model::{BomProfile, CraProductClass};
use crate::pipeline::parse_sbom_with_context;
use crate::quality::{
    ComplianceLevel, ComplianceResult, StandardSelector, Violation, ViolationSeverity,
};
use crate::reports::{ReportFormat, generate_compliance_json};
use crate::tui::{App, ViewApp};
use clap::ValueEnum;
use std::path::{Path, PathBuf};

/// Before the CRA Art. 14 gate (2026-09-11): the wall clock would judge the
/// reporting channels differently.
const AS_OF: &str = "2026-06-01";

/// `--cra-product-class`: the sidecar names none, so the flag applies.
const PRODUCT_CLASS: &str = "critical";

/// A sidecar with no product class, and a support end date that FDA's
/// lifecycle check would read if a run handed FDA the sidecar.
const SIDECAR: &str = r#"{
  "securityContact": "security@example.com",
  "manufacturerName": "ExampleCorp",
  "supportEndDate": "2031-01-15T00:00:00Z"
}"#;

/// The CRA-compliant fixture as `app.cdx.json`, with `SIDECAR` next to it
/// for auto-discovery.
fn fixture(dir: &Path) -> PathBuf {
    let sbom = dir.join("app.cdx.json");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cra/cra-compliant.cdx.json"
        ),
        &sbom,
    )
    .expect("fixture copies");
    std::fs::write(dir.join("app.cra.json"), SIDECAR).expect("sidecar writes");
    sbom
}

/// Every level `validate --standard` can select, in selector order.
fn validate_levels() -> Vec<ComplianceLevel> {
    StandardSelector::value_variants()
        .iter()
        .map(|selector| selector.level())
        .collect()
}

/// `validate -o json` for every standard, with the sidecar auto-discovered.
fn validate_envelope(sbom: &Path, out: &Path) -> String {
    run_validate(
        sbom.to_path_buf(),
        StandardSelector::value_variants().to_vec(),
        ReportFormat::Json,
        Some(out.to_path_buf()),
        false,
        false,
        None,
        Some(PRODUCT_CLASS.to_string()),
        Some(AS_OF),
        false,
        ValidateJsonSchema::V2,
        None,
        None,
        false,
        crate::reports::DEFAULT_SARIF_MAX_RESULTS,
    )
    .expect("validate runs");
    std::fs::read_to_string(out).expect("validate wrote the envelope")
}

/// The envelope `validate` would write for `results` (a TUI's results for
/// every level), restricted to the levels `validate` checked.
fn envelope_of(results: &[ComplianceResult]) -> String {
    let picked: Vec<ComplianceResult> = validate_levels()
        .iter()
        .map(|level| {
            results
                .iter()
                .find(|r| r.level == *level)
                .unwrap_or_else(|| panic!("the TUI checks {level:?}"))
                .clone()
        })
        .collect();
    generate_compliance_json(&picked).expect("envelope serializes")
}

fn result(results: &[ComplianceResult], level: ComplianceLevel) -> &ComplianceResult {
    results
        .iter()
        .find(|r| r.level == level)
        .unwrap_or_else(|| panic!("{level:?} result"))
}

fn rules<'a>(result: &'a ComplianceResult, prefix: &str) -> Vec<&'a Violation> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id.starts_with(prefix))
        .collect()
}

#[test]
fn validate_and_both_tuis_judge_one_run_alike() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sbom_path = fixture(dir.path());
    let validate_json = validate_envelope(&sbom_path, &dir.path().join("validate.json"));

    let (sbom, raw) = parse_sbom_with_context(&sbom_path, false)
        .expect("fixture parses")
        .into_parts();

    // `view`: the run `run_view` builds from its flags.
    let view_config = ViewConfig {
        sbom_path: sbom_path.clone(),
        output: OutputConfig {
            format: ReportFormat::Tui,
            ..OutputConfig::default()
        },
        validate_ntia: false,
        min_severity: None,
        vulnerable_only: false,
        ecosystem_filter: None,
        fail_on_vuln: false,
        bom_profile: None,
        enrichment: EnrichmentConfig::default(),
        cra_sidecar_path: None,
        cra_product_class: Some(PRODUCT_CLASS.to_string()),
        as_of: Some(AS_OF.to_string()),
    };
    let view_run = super::view::compliance_run(&view_config).expect("view run resolves");
    let mut view = ViewApp::new_with_compliance(sbom.clone(), &raw, BomProfile::Sbom, view_run);
    view.ensure_compliance_results();
    let view_results = view.compliance_results.clone().expect("view results");
    assert_eq!(
        envelope_of(&view_results),
        validate_json,
        "the view TUI must report what validate reports"
    );

    // `diff`: the shared inputs `main` parses into `DiffConfig::compliance`,
    // and each side's run as `run_diff` builds it for the TUI.
    let diff_config = DiffConfigBuilder::new()
        .old_path(sbom_path.clone())
        .new_path(sbom_path.clone())
        .compliance(
            compliance_run_config(Some(PRODUCT_CLASS), Some(AS_OF)).expect("diff inputs parse"),
        )
        .build()
        .expect("diff config");
    let old_run = crate::pipeline::side_compliance(&diff_config.compliance, &diff_config.paths.old)
        .expect("old run resolves");
    let new_run = crate::pipeline::side_compliance(&diff_config.compliance, &diff_config.paths.new)
        .expect("new run resolves");
    let mut diff = App::new_diff_with_compliance(
        DiffResult::new(),
        sbom.clone(),
        sbom,
        &raw,
        &raw,
        old_run,
        new_run,
    );
    diff.ensure_compliance_results();
    for (side, results) in [
        ("old", diff.data.old_compliance_results.clone()),
        ("new", diff.data.new_compliance_results.clone()),
    ] {
        assert_eq!(
            envelope_of(&results.expect("diff results")),
            validate_json,
            "the diff TUI must report what validate reports ({side} side)"
        );
    }
    // The summary card's CRA Phase 2 verdict is the compliance tab's.
    let card = diff.data.new_cra_compliance.clone().expect("summary card");
    assert_eq!(
        generate_compliance_json(&[card]).expect("card serializes"),
        generate_compliance_json(&[result(&view_results, ComplianceLevel::CraPhase2).clone()])
            .expect("tab serializes"),
    );

    // Every input took effect, so the comparison is not vacuous.
    let phase2 = result(&view_results, ComplianceLevel::CraPhase2);
    assert_eq!(
        phase2.conformity_summary.as_ref().map(|s| s.product_class),
        Some(CraProductClass::Critical),
        "the product class reaches CRA Phase 2"
    );
    let art_14 = rules(phase2, "SBOM-CRA-ART-14-");
    assert!(
        !art_14.is_empty() && art_14.iter().all(|v| v.severity == ViolationSeverity::Info),
        "Art. 14 findings are judged before the gate, at --as-of"
    );
    assert!(
        phase2
            .violations
            .iter()
            .all(|v| v.rule_id != "SBOM-CRA-ART-13-8"),
        "the sidecar's support end date reaches CRA Phase 2"
    );
    assert!(
        result(&view_results, ComplianceLevel::CraOssSteward)
            .conformity_summary
            .is_none(),
        "no Annex VIII summary for the steward profile"
    );
    assert_eq!(
        rules(
            result(&view_results, ComplianceLevel::FdaMedicalDevice),
            "SBOM-FDA-SUPPORT"
        )
        .len(),
        1,
        "FDA does not read the CRA sidecar"
    );
}
