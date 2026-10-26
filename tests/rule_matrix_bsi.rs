//! Registry-driven per-rule matrix for `ComplianceLevel::BsiTr03183_2`
//! (BSI TR-03183-2 v2.1.0). The Error-level §5.2.1 timestamp (5-2) and
//! §5.2.2 dependency (5-5) rules were previously never asserted.
//!
//! BSI shares the CRA-family `COMPLIANCE_SARIF_RULE_IDS` catalogue, so its
//! universe is that slice's `SBOM-BSI-TR-03183-2-*` ids: a BSI rule added to
//! the slice cannot land without a row here. Every id gets a firing fixture
//! and a silent fixture (rendered in each of the four encodings and run
//! through the real parser), or an explicit skip-with-reason. §4 admits SPDX
//! from 3.0.1 only, so every SPDX 2.3 rendering also fails SBOM-BSI-TR-03183-2-4.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, Encoding, Outcome, RuleEntry, SHA256_FILLER, SHA512_FILLER,
    SPDX_VERSION_CASE, SPDX3_AGENT_EMAILS_NOT_READ, SPDX23_HAS_NO_COMPLETENESS,
    SPDX23_HAS_NO_VULNERABILITIES, SbomFixture, assert_no_violations_in, run_matrix,
};
use sbom_tools::quality::{COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::BsiTr03183_2;

/// The BSI rules of the shared CRA-family SARIF catalogue.
fn bsi_universe() -> Vec<&'static str> {
    COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-BSI-TR-03183-2-"))
        .collect()
}

/// A component carrying every §5.2.2 / §5.2.4 field: name, version, SPDX
/// licence, creator (supplier), a SHA-512 hash, and a PURL.
fn comp(name: &str) -> ComponentFixture {
    let mut c = ComponentFixture::conforming(name);
    c.hashes = vec![("SHA-512".to_string(), SHA512_FILLER.to_string())];
    c.licenses = vec!["Apache-2.0".to_string()];
    c
}

/// A fixture that satisfies every TR-03183-2 element the engine checks:
/// CycloneDX 1.6 (§4), a Person creator with an email and a timestamp
/// (§5.2.1), fully attributed components with dependencies and a declared
/// complete enumeration (§5.2.2), PURLs (§5.2.4), and no vulnerability data
/// (§3.1).
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: vec![(
            "Dana Author".to_string(),
            Some("dana@acme.example".to_string()),
        )],
        components: vec![comp("libalpha"), comp("libbeta")],
        dependencies: vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])],
        completeness: Some("complete".to_string()),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The conforming BSI fixture must pass with a clean verdict, in CycloneDX:
/// SPDX 2.3 is no eligible format and cannot declare completeness, and the
/// SPDX 3 parser reads no creator email (the §4, §5.2.2 completeness and
/// §5.2.1 contact rows).
#[test]
fn bsi_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::CYCLONEDX);
}

#[test]
fn bsi_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // §4: CycloneDX >= 1.6 or SPDX >= 3.0.1 for newly generated SBOMs
        // (the §7 grace for CycloneDX 1.5 / SPDX 2.2.1 ended 2026-02-20).
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-4",
            Sev::Error,
            broken(|s| s.spec_version = "1.5".to_string()),
            base(),
        )
        .with_firing(
            "SPDX 3.0 predates the eligible 3.0.1",
            Sev::Error,
            broken(|s| s.spdx_version = Some("3.0".to_string())),
        )
        .case_only(
            "firing",
            Encoding::ALL_BUT_SPDX3,
            "the case is about the CycloneDX 1.6 floor, which an SPDX 3.0.1 rendering does not \
             meet or miss (an SPDX 2.3 rendering fails the SPDX floor, as the silent case shows)",
        )
        .case_only(
            "SPDX 3.0 predates the eligible 3.0.1",
            Encoding::SPDX,
            SPDX_VERSION_CASE,
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Error),
            "§4 admits SPDX from 3.0.1 only, so an SPDX 2.3 document is no eligible format",
        ),
        // §5.2.1: tools do not satisfy "Creator of the SBOM" — a tools-only
        // document has no creator in the TR's sense.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-1",
            Sev::Error,
            broken(|s| s.authors.clear()),
            base(),
        ),
        // A creator is present but carries neither an email nor a URL.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-1-CONTACT",
            Sev::Warning,
            broken(|s| s.authors = vec![("Dana Author".to_string(), None)]),
            base(),
        )
        .case_only(
            "silent",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_AGENT_EMAILS_NOT_READ,
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-2",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        // "unknown" without a corroborating PURL name segment is no name.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-3",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-LICENSE",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").licenses.clear()),
            base(),
        ),
        // §6.1: a licence that is not an SPDX identifier or expression.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").licenses = vec!["Acme-Proprietary-1.0".to_string()];
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-CREATOR",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
        // §5.2.2 names the algorithm: a SHA-256 hash alone does not satisfy
        // the field.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-4",
            Sev::Error,
            broken(|s| {
                s.component_mut("libalpha").hashes =
                    vec![("SHA-256".to_string(), SHA256_FILLER.to_string())];
            }),
            base(),
        ),
        // No hash at all is a Warning (§3.2.1 allows omission when the
        // information cannot exist for the component).
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-4-MISSING",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-5",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        ),
        // Completeness of the dependency enumeration: undeclared and
        // declared-not-specified both warn; "complete" satisfies.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
            Sev::Warning,
            broken(|s| s.completeness = None),
            base(),
        )
        .with_firing(
            "compositions aggregate not_specified",
            Sev::Warning,
            broken(|s| s.completeness = Some("not_specified".to_string())),
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Warning),
            SPDX23_HAS_NO_COMPLETENESS,
        ),
        // §5.2.4 additional tier: identifiers MUST be given when they exist,
        // which the document cannot prove — a Warning.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-5-2-4",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        // §3.1: an SBOM must not carry vulnerability information.
        RuleEntry::tested(
            "SBOM-BSI-TR-03183-2-3-1",
            Sev::Warning,
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-0001".to_string(),
                    "high".to_string(),
                    "ref-libalpha".to_string(),
                )];
            }),
            base(),
        )
        .case_only(
            "firing",
            Encoding::ALL_BUT_SPDX23,
            SPDX23_HAS_NO_VULNERABILITIES,
        ),
    ];

    run_matrix(LEVEL, &bsi_universe(), &entries);
}
