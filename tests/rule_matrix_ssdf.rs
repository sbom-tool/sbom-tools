//! Registry-driven per-rule matrix for `ComplianceLevel::NistSsdf`
//! (audit P3: 7 of 8 SSDF rule sites were untested and no fixture ever
//! produced a passing SSDF verdict).
//!
//! Every rule id in `SSDF_SARIF_RULE_IDS` gets a firing fixture and a silent
//! fixture (rendered in each of the four encodings and run through the real
//! parser), or an explicit skip-with-reason; exhaustiveness is enforced
//! against the registry slice. SPDX 2.3 names no VCS, build-metadata or VDR
//! reference type, so the PO.1, PO.3 and PW.6 references that silence those
//! rules elsewhere leave them firing there.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, Encoding, IMPLAUSIBLE_SHA256_DIGESTS, Outcome, RuleEntry, SbomFixture,
    assert_no_violations_in, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, SSDF_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::NistSsdf;

/// A fixture that satisfies every SP 800-218 practice the checker maps:
/// tool provenance (PS.1), hashes on every component (PS.2), suppliers
/// (PS.3), a VCS reference (PO.1), build metadata (PO.3), a dependency graph
/// (PW.4), a security-advisories reference (PW.6), and PURLs (RV.1).
fn base() -> SbomFixture {
    let mut libalpha = ComponentFixture::conforming("libalpha");
    libalpha.external_refs = vec![
        (
            "vcs".to_string(),
            "https://github.com/acme/libalpha".to_string(),
        ),
        (
            "build-meta".to_string(),
            "https://ci.acme.example/builds/libalpha/123".to_string(),
        ),
        (
            "advisories".to_string(),
            "https://acme.example/security/advisories".to_string(),
        ),
    ];
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: None,
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: Vec::new(),
        manufacturer: None,
        primary: None,
        components: vec![libalpha, ComponentFixture::conforming("libbeta")],
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

/// The conforming SSDF fixture must pass with a clean verdict — previously a
/// checker that always errored would have kept the suite green. SPDX 2.3
/// cannot carry its VCS and build-metadata references (the PO.1 and PO.3
/// rows).
#[test]
fn ssdf_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL_BUT_SPDX23);
}

/// SPDX 2.3 reads a VCS reference nowhere: the download location is a
/// source distribution, and an OTHER `vcs` reference is no reference type
/// the parser knows.
const SPDX23_NO_VCS_REFERENCE: &str = "SPDX 2.3 has no VCS reference type: the parser reads \
     downloadLocation as a source distribution and an OTHER vcs reference as unrecognized";
/// SPDX 2.3 reads no build-metadata reference.
const SPDX23_NO_BUILD_REFERENCE: &str = "SPDX 2.3 has no build-metadata or build-system \
     reference type: an OTHER build-meta reference is unrecognized";
/// SPDX 2.3 names no VDR.
const SPDX23_NO_VDR_REFERENCE: &str = "SPDX 2.3 has no reference category for a VDR or VEX: an \
     OTHER vulnerability-assertion reference is unrecognized";

#[test]
fn ssdf_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No software component at all (no primary, no components): the
        // per-component rules have nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-SSDF-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        // PS.1 has two checks, each its own rule: a creator-less SBOM
        // (Error, this row) and a missing tool creator (SBOM-SSDF-PS1-TOOL,
        // row below; a creator-less SBOM draws both).
        RuleEntry::tested(
            "SBOM-SSDF-PS1",
            Sev::Error,
            broken(|s| s.tools.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-SSDF-PS1-TOOL",
            Sev::Warning,
            broken(|s| {
                s.tools.clear();
                s.authors = vec![("Dana Author".to_string(), None)];
            }),
            base(),
        ),
        // PS.2: >50% of components without hashes is an Error; at or below
        // the threshold it relaxes to Warning.
        RuleEntry::tested(
            "SBOM-SSDF-PS2",
            Sev::Error,
            broken(|s| {
                s.component_mut("libalpha").hashes.clear();
                s.component_mut("libbeta").hashes.clear();
            }),
            base(),
        )
        .with_departing_firing(
            "half the components missing hashes (at threshold)",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
        )
        // Only plausible digests count.
        .with_implausible_digests(Sev::Error, &IMPLAUSIBLE_SHA256_DIGESTS, |alg, value| {
            broken(|s| {
                for name in ["libalpha", "libbeta"] {
                    s.component_mut(name).hashes = vec![(alg.to_string(), value.to_string())];
                }
            })
        }),
        RuleEntry::tested(
            "SBOM-SSDF-PS3",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-SSDF-PO1",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha")
                    .external_refs
                    .retain(|(t, _)| t != "vcs");
            }),
            base(),
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Warning),
            SPDX23_NO_VCS_REFERENCE,
        ),
        RuleEntry::tested(
            "SBOM-SSDF-PO3",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha")
                    .external_refs
                    .retain(|(t, _)| t != "build-meta");
            }),
            base(),
        )
        .with_silent(
            "build-system reference instead of build-meta",
            broken(|s| {
                let refs = &mut s.component_mut("libalpha").external_refs;
                refs.retain(|(t, _)| t != "build-meta");
                refs.push((
                    "build-system".to_string(),
                    "https://ci.acme.example/pipelines/libalpha".to_string(),
                ));
            }),
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_BUILD_REFERENCE,
        )
        .case_differs(
            "build-system reference instead of build-meta",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_BUILD_REFERENCE,
        ),
        RuleEntry::tested(
            "SBOM-SSDF-PW4",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-SSDF-PW6",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha")
                    .external_refs
                    .retain(|(t, _)| t != "advisories");
            }),
            base(),
        )
        // A contact reference that reaches nobody counts nowhere: an
        // address at a documentation domain (until v0.4.0 it did here).
        .with_firing(
            "advisories reference at example.com",
            Sev::Info,
            broken(|s| {
                for (ref_type, url) in &mut s.component_mut("libalpha").external_refs {
                    if ref_type == "advisories" {
                        *url = "https://example.com/security/advisories".to_string();
                    }
                }
            }),
        )
        .with_silent(
            "vulnerability-assertion (VDR) reference instead of advisories",
            broken(|s| {
                let refs = &mut s.component_mut("libalpha").external_refs;
                refs.retain(|(t, _)| t != "advisories");
                refs.push((
                    "vulnerability-assertion".to_string(),
                    "https://acme.example/security/vdr.json".to_string(),
                ));
            }),
        )
        .case_differs(
            "vulnerability-assertion (VDR) reference instead of advisories",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_VDR_REFERENCE,
        ),
        RuleEntry::tested(
            "SBOM-SSDF-RV1",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
    ];

    run_matrix(LEVEL, SSDF_SARIF_RULE_IDS, &entries);
}
