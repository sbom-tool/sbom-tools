//! Registry-driven per-rule matrix for `ComplianceLevel::Standard`
//! (audit P3: no test anywhere instantiated the Standard profile).
//!
//! Standard has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path, and every rule it can emit funnels into the two ids
//! below. The universe is therefore declared locally (derived from the
//! Standard-level match arms in src/quality/compliance/generic.rs) and the
//! matrix sweep enforces that no fixture ever emits an id outside it — if a
//! new Standard-level check site lands, this file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, run_matrix};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Standard;

/// Every SARIF rule id the Standard profile can emit (generic.rs):
/// * `SBOM-NTIA-VERSION` — missing component version (Error);
/// * `SBOM-QUALITY-GENERAL` — the quality-family SARIF rule of every other
///   Standard-level check, each under its own `SBOM-QUALITY-*` id: document
///   creator (Error), serial number (Warning), component name (Error),
///   unique identifier (Warning), license (Warning), and the CycloneDX/SPDX
///   format-specific Infos.
const STANDARD_RULE_UNIVERSE: &[&str] = &["SBOM-NTIA-VERSION", "SBOM-QUALITY-GENERAL"];

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
        // The quality-family generic bucket, exercised site by site. The
        // registry default is Warning; the creator and component-name sites
        // escalate to Error.
        RuleEntry::tested(
            "SBOM-QUALITY-GENERAL",
            Sev::Warning,
            broken(|s| s.serial_number = None),
            base(),
        )
        .with_departing_firing(
            "document creator missing",
            Sev::Error,
            broken(|s| s.tools.clear()),
        )
        .with_firing(
            "license missing",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").licenses.clear()),
        )
        .with_firing(
            "unique identifier missing",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").purl = None),
        )
        .with_departing_firing(
            "placeholder component name",
            Sev::Error,
            // "unknown" without a corroborating PURL name segment does not
            // count as a real component name.
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
        ),
    ];

    run_matrix(LEVEL, STANDARD_RULE_UNIVERSE, &entries);
}
