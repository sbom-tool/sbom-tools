//! Registry-driven per-rule matrix for `ComplianceLevel::Standard`
//! (audit P3: no test anywhere instantiated the Standard profile).
//!
//! Standard runs on the generic checker path, and every check it runs is a
//! rule of its own (the NTIA version rule and the `SBOM-QUALITY-*` rules
//! below). The universe is declared locally (derived from the
//! Standard-level match arms in src/quality/compliance/generic.rs);
//! `run_matrix` requires it to equal the registry's list for the level
//! (`rules_for_level`), and the matrix sweep enforces that no fixture ever
//! emits an id outside it — if a new Standard-level check site lands, this
//! file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, RuleEntry, SPDX_VERSION_CASE, SbomFixture,
    assert_no_violations_in, assert_spdx_version_unknown, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Standard;

/// Every SARIF rule id the Standard profile can emit (generic.rs): the NTIA
/// component version (Error), document creator (Error), serial number
/// (Warning), component inventory and name (Error), unique identifier
/// (Warning), license (Warning), and the CycloneDX/SPDX format-specific
/// checks.
const STANDARD_RULE_UNIVERSE: &[&str] = &[
    "SBOM-NTIA-VERSION",
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-SERIAL",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-IDENTIFIER",
    "SBOM-QUALITY-LICENSE",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
];

/// A component that also satisfies the Standard-level license check.
fn comp(name: &str) -> ComponentFixture {
    let mut c = ComponentFixture::conforming(name);
    c.licenses = vec!["MIT".to_string()];
    c
}

/// A fixture that satisfies every Standard-level element: creator, serial
/// number, and named/versioned/identified/licensed components on CycloneDX
/// 1.5 with real bom-refs.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: Vec::new(),
        manufacturer: None,
        primary: None,
        components: vec![comp("libalpha"), comp("libbeta")],
        dependencies: vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])],
        vulnerabilities: Vec::new(),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The conforming Standard fixture must pass with a clean verdict in every
/// encoding.
#[test]
fn standard_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL);
}

#[test]
fn standard_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // Standard shares the NTIA version rule id via the generic version
        // check's fallback arm.
        RuleEntry::tested(
            "SBOM-NTIA-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-QUALITY-CREATOR",
            Sev::Error,
            broken(|s| s.tools.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-QUALITY-SERIAL",
            Sev::Warning,
            broken(|s| s.serial_number = None),
            base(),
        ),
        // No software component at all: the per-component rules have
        // nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-QUALITY-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        // "unknown" without a corroborating PURL name segment does not count
        // as a real component name.
        RuleEntry::tested(
            "SBOM-QUALITY-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-QUALITY-IDENTIFIER",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-QUALITY-LICENSE",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").licenses.clear()),
            base(),
        ),
        // CycloneDX newer than the latest version read (1.7) or SPDX newer
        // than 3.0 warns; an outdated CycloneDX version is an Info. Each
        // version case runs in the format whose version it sets.
        RuleEntry::tested(
            "SBOM-QUALITY-SPEC-VERSION",
            Sev::Warning,
            broken(|s| s.spec_version = "1.8".to_string()),
            base(),
        )
        .with_departing_firing(
            "CycloneDX 1.3 is outdated",
            Sev::Info,
            broken(|s| s.spec_version = "1.3".to_string()),
        )
        .with_firing(
            "SPDX 3.1 is newer than any version read",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("3.1".to_string())),
        )
        .case_only("firing", Encoding::CYCLONEDX, CYCLONEDX_VERSION_CASE)
        .case_only(
            "CycloneDX 1.3 is outdated",
            Encoding::CYCLONEDX,
            CYCLONEDX_VERSION_CASE,
        )
        .case_only(
            "SPDX 3.1 is newer than any version read",
            Encoding::SPDX,
            SPDX_VERSION_CASE,
        ),
        // An SPDX version that is neither 2.x nor 3.x.
        RuleEntry::tested(
            "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("4.0".to_string())),
            base(),
        )
        .case_only("firing", Encoding::SPDX, SPDX_VERSION_CASE),
        // A component whose bom-ref collapses to its name.
        RuleEntry::tested(
            "SBOM-QUALITY-ELEMENT-ID",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha").bom_ref = "libalpha".to_string();
                s.dependencies = vec![("libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
            base(),
        ),
    ];

    run_matrix(LEVEL, STANDARD_RULE_UNIVERSE, &entries);
}

/// SBOM-QUALITY-SPEC-VERSION-UNKNOWN reads only SPDX input: its matrix row
/// fires it in SPDX 2.3 JSON and SPDX 3; this pins SPDX tag-value.
#[test]
fn standard_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-QUALITY-SPEC-VERSION-UNKNOWN");
}
