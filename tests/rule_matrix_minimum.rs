//! Registry-driven per-rule matrix for `ComplianceLevel::Minimum` (no test
//! previously instantiated the Minimum profile's rules one by one).
//!
//! Minimum has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path, and every rule it can emit shares the
//! quality-family SARIF rule. The universe is therefore declared locally
//! (derived from the Minimum-level match arms in
//! src/quality/compliance/generic.rs) and the matrix sweep enforces that no
//! fixture ever emits an id outside it — if a new Minimum-level check site
//! lands, this file fails and must be extended.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, assert_spdx_version_unknown,
    check, render_violations, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Minimum;

/// Every SARIF rule id the Minimum profile can emit (generic.rs):
/// * `SBOM-QUALITY-GENERAL` — the quality-family SARIF rule of every
///   Minimum-level check, each under its own `SBOM-QUALITY-*` id: document
///   creator (Warning — the one level that does not escalate it), component
///   inventory (Error), component name (Error), and the CycloneDX/SPDX
///   format-specific notes.
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
        // The quality-family generic bucket: every Minimum-level check
        // reports an alias key of its own (per-key rows below).
        RuleEntry::skipped(
            "SBOM-QUALITY-GENERAL",
            "no check emits SBOM-QUALITY-GENERAL under its own key since WP 1.8b: every \
             Minimum-level check reports an alias key of its own (CREATOR, INVENTORY, \
             NAME, SPEC-VERSION, SPEC-VERSION-UNKNOWN, ELEMENT-ID), each with a per-key row",
        ),
        // ── Per-key rows ─────────────────────────────────────────────────
        RuleEntry::key_skipped(
            "SBOM-QUALITY-CREATOR",
            "a creator-less SBOM is a Warning at Minimum, the one level that does not \
             escalate it, while the registry default is the Error that Standard and \
             Comprehensive emit, so no Minimum case can meet run_matrix's rule that a \
             tested row fires at the registry default; \
             minimum_creator_gap_stays_a_warning below pins the Warning and its silent case",
        ),
        // No software component at all: the per-component rules have
        // nothing to judge, which is a finding.
        RuleEntry::key_tested(
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
        RuleEntry::key_tested(
            "SBOM-QUALITY-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        // CycloneDX newer than the latest version read (1.7) warns; an
        // outdated version is an Info.
        RuleEntry::key_tested(
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
        RuleEntry::key_skipped(
            "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
            "an SPDX version that is neither 2.x nor 3.x is an SPDX-only check, out of \
             the CycloneDX-only DSL's reach; minimum_spec_version_unknown_reads_only_spdx \
             below fires it on SPDX 4.0 and keeps it silent on SPDX 2.3",
        ),
        // A component whose bom-ref collapses to its name.
        RuleEntry::key_tested(
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
/// Minimum Warning. A tool creator alone satisfies it.
#[test]
fn minimum_creator_gap_stays_a_warning() {
    let fired = |fixture: &SbomFixture| -> Vec<Sev> {
        check(LEVEL, fixture)
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
        "a creator-less SBOM must fire SBOM-QUALITY-CREATOR once as a Warning:\n{}",
        render_violations(&check(LEVEL, &creatorless))
    );
    assert!(
        fired(&base()).is_empty(),
        "a tool creator must keep SBOM-QUALITY-CREATOR silent"
    );
}

/// SBOM-QUALITY-SPEC-VERSION-UNKNOWN reads only SPDX input, so its per-key
/// row is skipped.
#[test]
fn minimum_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-QUALITY-SPEC-VERSION-UNKNOWN");
}
