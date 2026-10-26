//! Registry-driven per-rule matrix for `ComplianceLevel::Standard`
//! (audit P3: no test anywhere instantiated the Standard profile).
//!
//! Standard has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path, and every check it runs is a rule of its own (the
//! NTIA version rule and the `SBOM-QUALITY-*` rules below). The universe is
//! therefore declared locally
//! (derived from the Standard-level match arms in
//! src/quality/compliance/generic.rs) and the matrix sweep enforces that no
//! fixture ever emits an id outside it — if a new Standard-level check site
//! lands, this file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, assert_spdx_version_unknown,
    run_matrix,
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

/// The conforming Standard fixture must pass with a clean verdict.
#[test]
fn standard_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
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
        // CycloneDX newer than the latest version read (1.7) warns; an
        // outdated version is an Info.
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
        ),
        RuleEntry::skipped(
            "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
            "an SPDX version that is neither 2.x nor 3.x is an SPDX-only check, out of \
             the CycloneDX-only DSL's reach; standard_spec_version_unknown_reads_only_spdx \
             below fires it on SPDX 4.0 and keeps it silent on SPDX 2.3",
        ),
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

/// SBOM-QUALITY-SPEC-VERSION-UNKNOWN reads only SPDX input, so its matrix
/// row is skipped.
#[test]
fn standard_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-QUALITY-SPEC-VERSION-UNKNOWN");
}
