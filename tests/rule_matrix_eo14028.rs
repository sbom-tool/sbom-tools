//! Registry-driven per-rule matrix for `ComplianceLevel::Eo14028`
//! (audit P3: 8 of 9 EO 14028 rule sites had no behavioral test and no
//! fixture ever passed the framework).
//!
//! Every rule id in `EO14028_SARIF_RULE_IDS` gets a firing fixture and a
//! silent fixture (rendered in each of the four encodings and run through
//! the real parser), or an explicit skip-with-reason; exhaustiveness is
//! enforced against the registry slice.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, RuleEntry, SPDX_VERSION_CASE, SbomFixture,
    assert_no_violations_in, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, EO14028_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::Eo14028;

/// A fixture that satisfies every EO 14028 §4 element the checker maps:
/// machine-readable CycloneDX 1.5, timestamp, tool creator (auto-generation),
/// PURLs, names, versions, hashes, a dependency graph, supplier attribution,
/// and a vulnerability-disclosure reference on the root component.
fn base() -> SbomFixture {
    let mut libalpha = ComponentFixture::conforming("libalpha");
    // §4(g) disclosure evidence must sit on a manufacturer-scope (root)
    // component; libalpha is the root of the dependency graph below.
    libalpha.external_refs = vec![(
        "advisories".to_string(),
        "https://acme.example/security/advisories".to_string(),
    )];
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

/// The conforming EO 14028 fixture must pass with a clean verdict in every
/// encoding — no test previously observed `is_compliant == true` for this
/// framework.
#[test]
fn eo14028_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL);
}

#[test]
fn eo14028_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No software component at all (no primary, no components): the
        // per-component rules have nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-EO14028-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-NAME",
            Sev::Error,
            // "unknown" without a corroborating PURL name segment does not
            // count as a real component name (the PURL still satisfies the
            // IDENTIFIER element, isolating the NAME rule).
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        // The §4(e) machine-readable gate: CycloneDX <= 1.3 and SPDX
        // before 2.2 must fail.
        RuleEntry::tested(
            "SBOM-EO14028-FORMAT",
            Sev::Error,
            broken(|s| s.spec_version = "1.3".to_string()),
            base(),
        )
        .with_firing(
            "SPDX 2.1 is below the SPDX 2.2 floor",
            Sev::Error,
            broken(|s| s.spdx_version = Some("2.1".to_string())),
        )
        .case_only("firing", Encoding::CYCLONEDX, CYCLONEDX_VERSION_CASE)
        .case_only(
            "SPDX 2.1 is below the SPDX 2.2 floor",
            Encoding::SPDX,
            SPDX_VERSION_CASE,
        ),
        RuleEntry::tested(
            "SBOM-EO14028-AUTOGEN",
            Sev::Warning,
            broken(|s| {
                // Creators stay non-empty (no CREATOR error) but carry no
                // generation tool.
                s.tools.clear();
                s.authors = vec![(
                    "Dana Author".to_string(),
                    Some("dana@acme.example".to_string()),
                )];
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-CREATOR",
            Sev::Error,
            broken(|s| s.tools.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-INTEGRITY",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-DISCLOSURE",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").external_refs.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-EO14028-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
    ];

    run_matrix(LEVEL, EO14028_SARIF_RULE_IDS, &entries);
}
