//! Registry-driven per-rule matrix for `ComplianceLevel::Minimum` (no test
//! previously instantiated the Minimum profile's rules one by one).
//!
//! Minimum has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path, and every rule it can emit funnels into the
//! quality-family generic id. The universe is therefore declared locally
//! (derived from the Minimum-level match arms in
//! src/quality/compliance/generic.rs) and the matrix sweep enforces that no
//! fixture ever emits an id outside it — if a new Minimum-level check site
//! lands, this file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, run_matrix};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Minimum;

/// Every rule id the Minimum profile can emit (generic.rs):
/// * `SBOM-QUALITY-GENERAL` — the quality-family generic id stamped by every
///   Minimum-level site: document creator (Warning — the one level that does
///   not escalate it), component inventory (Error), component name (Error),
///   and the CycloneDX/SPDX format-specific notes.
const MINIMUM_RULE_UNIVERSE: &[&str] = &["SBOM-QUALITY-GENERAL"];

/// A fixture that satisfies every Minimum-level element: a tool creator and
/// named components with real bom-refs on CycloneDX 1.5.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        components: vec![
            ComponentFixture::conforming("libalpha"),
            ComponentFixture::conforming("libbeta"),
        ],
        dependencies: vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])],
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The conforming Minimum fixture must pass with a clean verdict.
#[test]
fn minimum_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

/// Minimum is "basic identification only": a document with no timestamp,
/// serial number or dependencies, whose components carry nothing but a
/// name and a bom-ref, still passes.
#[test]
fn minimum_requires_only_a_creator_and_named_components() {
    let bare = broken(|s| {
        s.timestamp = None;
        s.dependencies.clear();
        for c in &mut s.components {
            c.version = None;
            c.purl = None;
            c.supplier = None;
            c.hashes.clear();
        }
    });
    assert_no_violations(LEVEL, &bare);
}

#[test]
fn minimum_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // The quality-family generic bucket, exercised site by site. A
        // creator-less SBOM stays a Warning at Minimum (every other level
        // escalates it to Error).
        RuleEntry::tested(
            "SBOM-QUALITY-GENERAL",
            Sev::Warning,
            broken(|s| s.tools.clear()),
            base(),
        )
        .with_departing_firing(
            "no software component (inventory)",
            Sev::Error,
            broken(|s| {
                s.components.clear();
                s.dependencies.clear();
            }),
        )
        .with_departing_firing(
            "placeholder component name",
            Sev::Error,
            // "unknown" without a corroborating PURL name segment does not
            // count as a real component name.
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
        )
        .with_firing(
            "CycloneDX newer than the latest version read (1.7)",
            Sev::Warning,
            broken(|s| s.spec_version = "1.8".to_string()),
        )
        .with_departing_firing(
            "CycloneDX 1.3 is outdated",
            Sev::Info,
            broken(|s| s.spec_version = "1.3".to_string()),
        )
        .with_departing_firing(
            "component may be missing bom-ref",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha").bom_ref = "libalpha".to_string();
                s.dependencies = vec![("libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
        ),
    ];

    run_matrix(LEVEL, MINIMUM_RULE_UNIVERSE, &entries);
}
