//! Registry-driven per-rule matrix for `ComplianceLevel::Minimum` (no test
//! previously instantiated the Minimum profile's rules one by one).
//!
//! Minimum has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path, and every check it runs is an `SBOM-QUALITY-*` rule
//! of its own. The universe is therefore declared locally (derived from the
//! Minimum-level match arms in src/quality/compliance/generic.rs) and the
//! matrix sweep enforces that no fixture ever emits an id outside it — if a
//! new Minimum-level check site lands, this file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, RuleEntry, SbomFixture,
    assert_no_violations_in, assert_spdx_version_unknown, check_in, render_violations, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Minimum;

/// Every SARIF rule id the Minimum profile can emit (generic.rs): document
/// creator (Warning — the one level that does not escalate it), component
/// inventory (Error), component name (Error), and the CycloneDX/SPDX
/// format-specific notes.
const MINIMUM_RULE_UNIVERSE: &[&str] = &[
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
];

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

/// The conforming Minimum fixture must pass with a clean verdict in every
/// encoding.
#[test]
fn minimum_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL);
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
    assert_no_violations_in(LEVEL, &bare, Encoding::ALL);
}

#[test]
fn minimum_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        RuleEntry::skipped(
            "SBOM-QUALITY-CREATOR",
            "a creator-less SBOM is a Warning at Minimum, the one level that does not \
             escalate it, while the registry default is the Error that Standard and \
             Comprehensive emit, so no Minimum case can meet run_matrix's rule that a \
             tested row fires at the registry default; \
             minimum_creator_gap_stays_a_warning below pins the Warning and its silent case",
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
        // CycloneDX newer than the latest version read (1.7) warns; an
        // outdated version is an Info. Both cases are about a CycloneDX
        // version.
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
        .case_only("firing", Encoding::CYCLONEDX, CYCLONEDX_VERSION_CASE)
        .case_only(
            "CycloneDX 1.3 is outdated",
            Encoding::CYCLONEDX,
            CYCLONEDX_VERSION_CASE,
        ),
        RuleEntry::skipped(
            "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
            "an SPDX version that is neither 2.x nor 3.x is an SPDX-only check, out of \
             the DSL's reach (it sets no SPDX version); minimum_spec_version_unknown_reads_only_spdx \
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

    run_matrix(LEVEL, MINIMUM_RULE_UNIVERSE, &entries);
}

/// A creator-less SBOM stays a Warning at Minimum (Standard and
/// Comprehensive escalate it to the Error the registry documents), so the
/// matrix row of SBOM-QUALITY-CREATOR is skipped here; this pins the
/// Minimum Warning, in every encoding. A tool creator alone satisfies it.
#[test]
fn minimum_creator_gap_stays_a_warning() {
    for &encoding in Encoding::ALL {
        let fired = |fixture: &SbomFixture| -> Vec<Sev> {
            check_in(LEVEL, fixture, encoding)
                .violations
                .iter()
                .filter(|v| v.rule_id == "SBOM-QUALITY-CREATOR")
                .map(|v| v.severity)
                .collect()
        };
        let creatorless = broken(|s| s.tools.clear());
        assert_eq!(
            fired(&creatorless),
            vec![Sev::Warning],
            "a creator-less SBOM must fire SBOM-QUALITY-CREATOR once as a Warning in {}:\n{}",
            encoding.name(),
            render_violations(&check_in(LEVEL, &creatorless, encoding))
        );
        assert!(
            fired(&base()).is_empty(),
            "a tool creator must keep SBOM-QUALITY-CREATOR silent in {}",
            encoding.name()
        );
    }
}

/// SBOM-QUALITY-SPEC-VERSION-UNKNOWN reads only SPDX input, of a version the
/// DSL cannot set, so its matrix row is skipped.
#[test]
fn minimum_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-QUALITY-SPEC-VERSION-UNKNOWN");
}
