//! Registry-driven per-rule matrix for `ComplianceLevel::Comprehensive`
//! (audit P3: no test anywhere instantiated the Comprehensive profile, so a
//! diff casualty dropping Comprehensive from the NTIA-timestamp or hash match
//! arms in generic.rs would have shipped unnoticed).
//!
//! Comprehensive has no dedicated SARIF slice in the registry: it runs on the
//! generic checker path and shares the NTIA rule ids for its gating elements,
//! with an `SBOM-QUALITY-*` rule of its own for every other check. The
//! universe is declared locally (derived from the Comprehensive-level match arms in
//! src/quality/compliance/generic.rs) and the matrix sweep enforces that no
//! fixture ever emits an id outside it.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, RuleEntry, SbomFixture, assert_no_violations, assert_spdx_version_unknown,
    run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Comprehensive;

/// Every SARIF rule id the Comprehensive profile can emit (generic.rs):
/// * `SBOM-NTIA-TIMESTAMP` — missing creation timestamp (Error);
/// * `SBOM-NTIA-VERSION` — missing component version (Error);
/// * `SBOM-NTIA-SUPPLIER` — missing component supplier (Error);
/// * `SBOM-NTIA-DEPENDENCY` — dependency-relationship gaps (Error/Warning);
/// * the `SBOM-QUALITY-*` rules of the remaining checks: document creator
///   (Error), serial number (Warning), component inventory and name (Error),
///   unique identifier (Warning), license (Warning), hashes (Warning), and
///   the format-specific checks.
const COMPREHENSIVE_RULE_UNIVERSE: &[&str] = &[
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-NTIA-VERSION",
    "SBOM-NTIA-SUPPLIER",
    "SBOM-NTIA-DEPENDENCY",
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-SERIAL",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-IDENTIFIER",
    "SBOM-QUALITY-LICENSE",
    "SBOM-QUALITY-HASH",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
];

/// A component that also satisfies the Comprehensive license check.
fn comp(name: &str) -> ComponentFixture {
    let mut c = ComponentFixture::conforming(name);
    c.licenses = vec!["MIT".to_string()];
    c
}

/// A fixture that satisfies every Comprehensive element: timestamp, creator,
/// serial number, fully attributed/hashed/licensed components, and a
/// dependency graph with no orphans.
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

/// The conforming Comprehensive fixture must pass with a clean verdict — the
/// strictest generic profile previously had no passing-case test at all.
#[test]
fn comprehensive_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

#[test]
fn comprehensive_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // Comprehensive shares the NTIA timestamp gate (the match arm the
        // audit flagged as an easy diff casualty).
        RuleEntry::tested(
            "SBOM-NTIA-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-NTIA-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-NTIA-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
        // Missing relationships gate as Error; a mostly-disconnected graph
        // (orphan majority) warns at the same rule id.
        RuleEntry::tested(
            "SBOM-NTIA-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        )
        .with_departing_firing(
            "orphan majority (3 of 5 components disconnected)",
            Sev::Warning,
            broken(|s| {
                s.components.push(comp("libgamma"));
                s.components.push(comp("libdelta"));
                s.components.push(comp("libepsilon"));
                // Only libalpha -> libbeta stays connected.
            }),
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
        // The hash site is Comprehensive-specific (FDA is the only other
        // level in that match arm — the exact list the audit flagged).
        RuleEntry::tested(
            "SBOM-QUALITY-HASH",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
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
             the CycloneDX-only DSL's reach; \
             comprehensive_spec_version_unknown_reads_only_spdx below fires it on SPDX 4.0 \
             and keeps it silent on SPDX 2.3",
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

    run_matrix(LEVEL, COMPREHENSIVE_RULE_UNIVERSE, &entries);
}

/// SBOM-QUALITY-SPEC-VERSION-UNKNOWN reads only SPDX input, so its matrix
/// row is skipped.
#[test]
fn comprehensive_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-QUALITY-SPEC-VERSION-UNKNOWN");
}
