//! One compliance run, every entry point: `validate`, the `view` TUI and the
//! `diff` TUI report identical results for the same SBOM, CRA sidecar,
//! product class, `--as-of` and PQC flags. Each path builds its run the way
//! its command does, and each is compared through the `-o json` envelope
//! `validate` writes.

use super::{PqcOptions, ValidateJsonSchema, compliance_run_config, run_validate};
use crate::config::{DiffConfigBuilder, EnrichmentConfig, OutputConfig, ViewConfig};
use crate::diff::DiffResult;
use crate::model::{BomProfile, CraProductClass};
use crate::pipeline::parse_sbom_with_context;
use crate::quality::{
    CnsaCategory, ComplianceLevel, ComplianceResult, PqcMode, PqcProfile, StandardSelector,
    Violation, ViolationSeverity,
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
fn validate_envelope(sbom: &Path, out: &Path, as_of: &str, pqc: PqcOptions) -> String {
    run_validate(
        sbom.to_path_buf(),
        StandardSelector::value_variants().to_vec(),
        ReportFormat::Json,
        Some(out.to_path_buf()),
        false,
        false,
        None,
        Some(PRODUCT_CLASS.to_string()),
        Some(as_of),
        false,
        ValidateJsonSchema::V2,
        None,
        None,
        false,
        crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        pqc,
        &crate::cli::RuleOptions::default(),
        &[],
    )
    .expect("validate runs");
    std::fs::read_to_string(out).expect("validate wrote the envelope")
}

/// The `view` command's flags for `sbom`: a TUI, the product class, `as_of`
/// and `pqc`.
fn view_config(sbom: &Path, as_of: &str, pqc: PqcOptions) -> ViewConfig {
    ViewConfig {
        sbom_path: sbom.to_path_buf(),
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
        as_of: Some(as_of.to_string()),
        pqc_mode: Some(pqc.mode),
        pqc_profile: pqc.profile,
        cnsa_category: pqc.cnsa_category,
        rule_settings: crate::quality::RuleSettings::new(),
        include_excluded_scope: false,
    }
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
    let validate_json = validate_envelope(
        &sbom_path,
        &dir.path().join("validate.json"),
        AS_OF,
        PqcOptions::default(),
    );

    let (sbom, raw) = parse_sbom_with_context(&sbom_path, false)
        .expect("fixture parses")
        .into_parts();

    // `view`: the run `run_view` builds from its flags.
    let view_config = view_config(&sbom_path, AS_OF, PqcOptions::default());
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
            compliance_run_config(
                Some(PRODUCT_CLASS),
                Some(AS_OF),
                PqcOptions::default(),
                &crate::cli::RuleOptions::default(),
            )
            .expect("diff inputs parse"),
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

/// `--pqc-mode deadline` reaches every entry point: the calendar CBOM, in
/// 2031 under the federal profile and the networking-equipment CNSA 2.0
/// timeline, reads the same through `validate`, the `view` TUI and the
/// `diff` TUI.
#[test]
fn deadline_mode_reaches_validate_and_both_tuis() {
    const IN_2031: &str = "2031-06-01";
    let pqc = PqcOptions {
        mode: PqcMode::Deadline,
        profile: Some(PqcProfile::Federal),
        cnsa_category: Some(CnsaCategory::Networking),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let sbom_path = dir.path().join("cbom.cdx.json");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cyclonedx/cbom-pqc-calendar.cdx.json"
        ),
        &sbom_path,
    )
    .expect("fixture copies");
    let validate_json =
        validate_envelope(&sbom_path, &dir.path().join("validate.json"), IN_2031, pqc);
    let (sbom, raw) = parse_sbom_with_context(&sbom_path, false)
        .expect("fixture parses")
        .into_parts();

    let view_run = super::view::compliance_run(&view_config(&sbom_path, IN_2031, pqc))
        .expect("view run resolves");
    let mut view = ViewApp::new_with_compliance(sbom.clone(), &raw, BomProfile::Sbom, view_run);
    view.ensure_compliance_results();
    let view_results = view.compliance_results.clone().expect("view results");
    assert_eq!(
        envelope_of(&view_results),
        validate_json,
        "the view TUI must judge deadline mode as validate does"
    );

    let diff_config = DiffConfigBuilder::new()
        .old_path(sbom_path.clone())
        .new_path(sbom_path.clone())
        .compliance(
            compliance_run_config(
                Some(PRODUCT_CLASS),
                Some(IN_2031),
                pqc,
                &crate::cli::RuleOptions::default(),
            )
            .expect("diff inputs parse"),
        )
        .build()
        .expect("diff config");
    let new_run = crate::pipeline::side_compliance(&diff_config.compliance, &diff_config.paths.new)
        .expect("new run resolves");
    let old_run = crate::pipeline::side_compliance(&diff_config.compliance, &diff_config.paths.old)
        .expect("old run resolves");
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
    assert_eq!(
        envelope_of(
            &diff
                .data
                .new_compliance_results
                .clone()
                .expect("diff results")
        ),
        validate_json,
        "the diff TUI must judge deadline mode as validate does"
    );

    // Every PQC input took effect, so the comparison is not vacuous.
    let pqc_result = result(&view_results, ComplianceLevel::NistPqc);
    assert!(
        rules(pqc_result, "SBOM-PQC-PROTO-003")
            .iter()
            .all(|v| v.severity == ViolationSeverity::Error),
        "the federal TLS 1.3 deadline (2030-01-02) has passed"
    );
    assert!(!rules(pqc_result, "SBOM-PQC-PROTO-003").is_empty());
    let cnsa_sources: Vec<&str> = result(&view_results, ComplianceLevel::Cnsa2)
        .violations
        .iter()
        .filter_map(|v| v.deadline.as_ref().map(|d| d.source.as_str()))
        .collect();
    assert!(
        !cnsa_sources.is_empty()
            && cnsa_sources
                .iter()
                .all(|s| *s == "CNSA 2.0 timeline: traditional networking equipment"),
        "{cnsa_sources:?}"
    );
    assert!(
        result(&view_results, ComplianceLevel::CraPhase2)
            .violations
            .iter()
            .all(|v| v.deadline.is_none()),
        "no other standard reads the PQC inputs"
    );
}

/// `validate -o json --json-schema v1` for one standard: the result's own
/// serialization, the shape the TUI's compliance JSON export writes.
fn validate_v1(sbom: &Path, out: &Path, standard: StandardSelector) -> String {
    run_validate(
        sbom.to_path_buf(),
        vec![standard],
        ReportFormat::Json,
        Some(out.to_path_buf()),
        false,
        false,
        None,
        Some(PRODUCT_CLASS.to_string()),
        Some(AS_OF),
        false,
        ValidateJsonSchema::V1,
        None,
        None,
        false,
        crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        PqcOptions::default(),
        &crate::cli::RuleOptions::default(),
        &[],
    )
    .expect("validate runs");
    std::fs::read_to_string(out).expect("validate wrote the result")
}

/// `view --vulnerable-only` lists the two vulnerable components of the demo
/// SBOM, but its compliance tab, the tab's JSON export and the quality score
/// judge all nine components: what `validate` and `quality` report for the
/// SBOM. Each path is built the way `run_view` builds it.
#[test]
fn a_filtered_view_judges_the_whole_sbom_as_validate_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sbom_path = dir.path().join("app.cdx.json");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/demo-new.cdx.json"
        ),
        &sbom_path,
    )
    .expect("fixture copies");
    std::fs::write(dir.path().join("app.cra.json"), SIDECAR).expect("sidecar writes");
    let validate_json = validate_envelope(
        &sbom_path,
        &dir.path().join("validate.json"),
        AS_OF,
        PqcOptions::default(),
    );

    let config = ViewConfig {
        vulnerable_only: true,
        ..view_config(&sbom_path, AS_OF, PqcOptions::default())
    };
    let run = super::view::compliance_run(&config).expect("view run resolves");
    let mut parsed = parse_sbom_with_context(&sbom_path, false).expect("fixture parses");
    let whole = super::view::filter_view(&mut parsed, &config).expect("the filters apply");
    let profile = BomProfile::detect(whole.as_ref().expect("the filter removes components"));
    let mut view = super::view::view_app(parsed, whole, profile, run.clone());
    assert_eq!(view.filtered_out(), Some((7, 9)), "two of nine listed");

    view.ensure_compliance_results();
    let results = view.compliance_results.clone().expect("view results");
    assert_eq!(
        envelope_of(&results),
        validate_json,
        "a filtered view must report what validate reports for the whole SBOM"
    );

    // The compliance tab's JSON export, of CRA Phase 2, is the result
    // `validate --standard cra --json-schema v1` writes.
    let selected = ComplianceLevel::all()
        .iter()
        .position(|level| *level == ComplianceLevel::CraPhase2)
        .expect("the TUI lists CRA Phase 2");
    let export = crate::tui::export::export_compliance(
        crate::tui::export::ExportFormat::Json,
        &results,
        selected,
        dir.path().to_str(),
        Some("tab-export"),
    );
    assert!(export.success, "{}", export.message);
    let exported = std::fs::read_to_string(&export.path).expect("the export is written");
    let validated = validate_v1(
        &sbom_path,
        &dir.path().join("validate-v1.json"),
        StandardSelector::Cra,
    );
    assert_eq!(
        exported.trim_end(),
        validated.trim_end(),
        "the filtered view's compliance export must equal validate's"
    );

    // The quality score is the whole SBOM's, as `quality` scores it.
    let whole_sbom = parse_sbom_with_context(&sbom_path, false)
        .expect("fixture parses")
        .into_sbom();
    let scorer = crate::quality::QualityScorer::new(crate::tui::scoring_profile_for(profile))
        .with_compliance(run.clone());
    assert_eq!(
        view.quality_report.overall_score,
        scorer.score(&whole_sbom).overall_score
    );

    // Judging the listed components instead reports otherwise, so the
    // comparisons above are not vacuous.
    let listed = run.check_levels(ComplianceLevel::all(), &view.sbom);
    assert_ne!(envelope_of(&listed), validate_json);
}
