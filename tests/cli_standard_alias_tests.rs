//! CLI standard-alias contract (audit P3): every documented spelling of
//! `validate --standard` must parse through clap and dispatch to the intended
//! engine standard, end-to-end through the real binary. The unit test in
//! src/quality/compliance/selector.rs pins the FromStr table; this test pins
//! the CLI wiring on top of it (clap value parsing, run_validate dispatch,
//! and the summary output naming the profile).

use std::path::{Path, PathBuf};
use std::process::Command;

use sbom_tools::quality::ComplianceLevel;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

/// The complete documented alias table for `--standard` (mirrors the
/// `#[value(name/alias = …)]` attributes on `StandardSelector`). Removing or
/// re-mapping any spelling is a breaking CLI change and must fail here.
fn alias_table() -> Vec<(&'static str, ComplianceLevel)> {
    vec![
        ("ntia", ComplianceLevel::NtiaMinimum),
        ("fda", ComplianceLevel::FdaMedicalDevice),
        ("cra", ComplianceLevel::CraPhase2),
        ("cra-phase2", ComplianceLevel::CraPhase2),
        ("cra-phase1", ComplianceLevel::CraPhase1),
        ("cra-2026", ComplianceLevel::CraPhase1),
        ("ssdf", ComplianceLevel::NistSsdf),
        ("nist-ssdf", ComplianceLevel::NistSsdf),
        ("nist_ssdf", ComplianceLevel::NistSsdf),
        ("eo14028", ComplianceLevel::Eo14028),
        ("eo-14028", ComplianceLevel::Eo14028),
        ("eo_14028", ComplianceLevel::Eo14028),
        ("cnsa2", ComplianceLevel::Cnsa2),
        ("cnsa-2", ComplianceLevel::Cnsa2),
        ("cnsa_2", ComplianceLevel::Cnsa2),
        ("cnsa2.0", ComplianceLevel::Cnsa2),
        ("pqc", ComplianceLevel::NistPqc),
        ("nist-pqc", ComplianceLevel::NistPqc),
        ("nist_pqc", ComplianceLevel::NistPqc),
        ("bsi", ComplianceLevel::BsiTr03183_2),
        ("tr-03183", ComplianceLevel::BsiTr03183_2),
        ("tr03183", ComplianceLevel::BsiTr03183_2),
        ("bsi-tr-03183-2", ComplianceLevel::BsiTr03183_2),
        ("oss-steward", ComplianceLevel::CraOssSteward),
        ("cra-oss-steward", ComplianceLevel::CraOssSteward),
        ("cra-oss", ComplianceLevel::CraOssSteward),
        ("cra-art24", ComplianceLevel::CraOssSteward),
        ("art24", ComplianceLevel::CraOssSteward),
        ("eucc", ComplianceLevel::EuccSubstantial),
        ("eucc-substantial", ComplianceLevel::EuccSubstantial),
        ("common-criteria", ComplianceLevel::EuccSubstantial),
        ("ai-act", ComplianceLevel::EuAiAct),
        ("ai_act", ComplianceLevel::EuAiAct),
        ("aiact", ComplianceLevel::EuAiAct),
        ("eu-ai-act", ComplianceLevel::EuAiAct),
        ("bsi-ai", ComplianceLevel::BsiSbomForAi),
        ("bsi_ai", ComplianceLevel::BsiSbomForAi),
        ("bsiai", ComplianceLevel::BsiSbomForAi),
        ("sbom-for-ai", ComplianceLevel::BsiSbomForAi),
        ("ai-bom", ComplianceLevel::BsiSbomForAi),
        ("cisa-2026", ComplianceLevel::Cisa2026),
        ("cisa", ComplianceLevel::Cisa2026),
        ("cisa2026", ComplianceLevel::Cisa2026),
        ("minimum-elements-2026", ComplianceLevel::Cisa2026),
        ("pci-dss", ComplianceLevel::PciDss632),
        ("pci", ComplianceLevel::PciDss632),
        ("pci-dss-6-3-2", ComplianceLevel::PciDss632),
        ("pci-dss-4", ComplianceLevel::PciDss632),
        ("fsct", ComplianceLevel::Fsct),
        ("fsct-3", ComplianceLevel::Fsct),
        ("component-transparency", ComplianceLevel::Fsct),
    ]
}

/// Each alias must complete a real validation (exit 0 or 1 — never a usage
/// error) and the summary must name the engine standard the alias is
/// documented to select.
#[test]
fn every_documented_standard_alias_dispatches_to_its_engine_standard() {
    let fixture = fixture_path("demo-new.cdx.json");
    for (alias, level) in alias_table() {
        let output = base_command()
            .arg("validate")
            .arg(&fixture)
            .args(["--standard", alias, "--summary"])
            .output()
            .unwrap_or_else(|e| panic!("validate --standard {alias} should run: {e}"));

        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let code = output.status.code();
        assert!(
            matches!(code, Some(0 | 1)),
            "--standard {alias} must complete a validation (exit 0 on pass / 1 on \
             compliance errors), got {code:?}; stderr:\n{stderr}"
        );

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("--standard {alias} must emit the compact summary JSON: {e}\nstdout:\n{stdout}")
        });
        assert_eq!(
            json["standard"].as_str(),
            Some(level.name()),
            "--standard {alias} must run the {expected:?} engine standard; summary: {json}",
            expected = level.name()
        );
    }
}

/// Aliases also compose in a comma-separated multi-standard list, producing
/// one summary entry per selected standard, in order.
#[test]
fn comma_separated_alias_list_runs_each_selected_standard() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args([
            "--standard",
            "nist-ssdf,eo_14028,common-criteria",
            "--summary",
        ])
        .output()
        .expect("validate command should run");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("multi-standard summary should be JSON");
    let standards: Vec<&str> = json
        .as_array()
        .expect("multi-standard summary array")
        .iter()
        .filter_map(|s| s["standard"].as_str())
        .collect();
    assert_eq!(
        standards,
        vec![
            ComplianceLevel::NistSsdf.name(),
            ComplianceLevel::Eo14028.name(),
            ComplianceLevel::EuccSubstantial.name(),
        ],
        "aliased multi-standard list must dispatch each entry in order"
    );
}
