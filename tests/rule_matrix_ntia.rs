//! Registry-driven per-rule matrix for `ComplianceLevel::NtiaMinimum` — the
//! default `validate` gate, which previously had no per-rule matrix (the
//! Error-level SBOM-NTIA-AUTHOR was never asserted anywhere).
//!
//! Every rule id in `NTIA_SARIF_RULE_IDS` gets a firing fixture (a minimal
//! SBOM, rendered in each of the four encodings and parsed through the real
//! parser, that must surface the rule) and a silent fixture (one that must
//! not), or an explicit skip-with-reason. The runner enforces exhaustiveness
//! against the registry's NTIA SARIF slice, so a new NTIA rule cannot land
//! untested.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, RuleEntry, SPDX_VERSION_CASE, SbomFixture,
    UNPARSEABLE_TIMESTAMP, assert_no_violations_in, assert_spdx_version_unknown, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, NTIA_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::NtiaMinimum;

/// A fixture that satisfies all seven NTIA minimum data fields: a tool
/// creator (Author), a timestamp, and named, versioned, supplier-attributed,
/// PURL-identified components connected by a dependency edge.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        components: vec![
            ComponentFixture::conforming("libalpha"),
            ComponentFixture::conforming("libbeta"),
        ],
        dependencies: vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])],
        ..SbomFixture::default()
    }
}

/// Clone the conforming baseline and break exactly one aspect.
fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The conforming NTIA fixture must pass with a clean verdict in every
/// encoding.
#[test]
fn ntia_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL);
}

#[test]
fn ntia_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No creator of any kind. A tool creator alone satisfies the 2021
        // Author element (unlike SBOM-CISA2026-AUTHOR), so base() is silent.
        RuleEntry::tested(
            "SBOM-NTIA-AUTHOR",
            Sev::Error,
            broken(|s| s.tools.clear()),
            base(),
        ),
        // No software component at all: the per-component rules have
        // nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-NTIA-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        // "unknown" without a corroborating PURL name segment does not count
        // as a component name (the PURL still satisfies IDENTIFIER).
        RuleEntry::tested(
            "SBOM-NTIA-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        // Silent absence fails, and so does an explicit NOASSERTION — the
        // 2021 element has no explicit-unknown escape hatch.
        RuleEntry::tested(
            "SBOM-NTIA-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        )
        .with_firing(
            "NOASSERTION version",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = Some("NOASSERTION".to_string())),
        ),
        RuleEntry::tested(
            "SBOM-NTIA-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_firing(
            "NOASSERTION supplier",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = Some("NOASSERTION".to_string())),
        ),
        RuleEntry::tested(
            "SBOM-NTIA-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        // No relationships at all gates as Error; a primary outside the
        // graph and an orphan majority warn at the same rule id.
        RuleEntry::tested(
            "SBOM-NTIA-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        )
        .with_departing_firing(
            "primary component in no relationship",
            Sev::Warning,
            broken(|s| s.primary = Some(ComponentFixture::conforming("acme-app"))),
        )
        .with_departing_firing(
            "orphan majority (3 of 5 components disconnected)",
            Sev::Warning,
            broken(|s| {
                s.components.push(ComponentFixture::conforming("libgamma"));
                s.components.push(ComponentFixture::conforming("libdelta"));
                s.components
                    .push(ComponentFixture::conforming("libepsilon"));
            }),
        ),
        RuleEntry::tested(
            "SBOM-NTIA-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        )
        .with_firing(
            "unparseable timestamp",
            Sev::Error,
            broken(|s| s.timestamp = Some(UNPARSEABLE_TIMESTAMP.to_string())),
        ),
        // A CycloneDX or SPDX version newer than any this tool reads warns;
        // an outdated CycloneDX version is an Info. Each version case runs
        // in the format whose version it sets.
        RuleEntry::tested(
            "SBOM-NTIA-SPEC-VERSION",
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
            "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("4.0".to_string())),
            base(),
        )
        .case_only("firing", Encoding::SPDX, SPDX_VERSION_CASE),
        // A component whose bom-ref collapses to its name.
        RuleEntry::tested(
            "SBOM-NTIA-ELEMENT-ID",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha").bom_ref = "libalpha".to_string();
                s.dependencies = vec![("libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
            base(),
        ),
        // A component listed twice, under a second bom-ref or under its own
        // bom-ref again: the entries are merged, and one Info names it.
        RuleEntry::tested(
            "SBOM-NTIA-DUPLICATE-COMPONENT",
            Sev::Info,
            broken(|s| s.list_twice("libalpha", false)),
            base(),
        )
        .with_firing(
            "the same bom-ref twice",
            Sev::Info,
            broken(|s| s.list_twice("libalpha", true)),
        ),
    ];

    run_matrix(LEVEL, NTIA_SARIF_RULE_IDS, &entries);
}

/// SBOM-NTIA-SPEC-VERSION-UNKNOWN reads only SPDX input: its matrix row
/// fires it in SPDX 2.3 JSON and SPDX 3; this pins SPDX tag-value.
#[test]
fn ntia_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-NTIA-SPEC-VERSION-UNKNOWN");
}
