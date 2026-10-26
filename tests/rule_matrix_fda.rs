//! Registry-driven per-rule matrix for `ComplianceLevel::FdaMedicalDevice`
//! (audit P3: the FDA framework previously had zero behavioral tests).
//!
//! Every rule id in `FDA_SARIF_RULE_IDS` gets a firing fixture (a minimal
//! CycloneDX document, parsed through the real parser, that must surface the
//! rule) and a silent fixture (one that must not), or an explicit
//! skip-with-reason. The runner enforces exhaustiveness against the
//! registry's FDA SARIF slice, so a new FDA rule cannot land untested.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, MD5_FILLER, RuleEntry, SbomFixture, assert_no_violations, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, FDA_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::FdaMedicalDevice;

/// A fixture that satisfies every FDA premarket element the engine checks:
/// timestamp, tool + manufacturer creators with a contact email, serial
/// number, named primary product with end-of-support evidence, and fully
/// attributed/hashed/connected components.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-device");
    // Level-of-support evidence: the parser lifts this primary-component
    // property into document.support_end_date.
    primary
        .properties
        .push(("endOfSupport".to_string(), "2030-01-01".to_string()));
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: Vec::new(),
        manufacturer: Some((
            "Acme Medical Inc".to_string(),
            Some("security@acme.example".to_string()),
        )),
        primary: Some(primary),
        components: vec![
            ComponentFixture::conforming("libalpha"),
            ComponentFixture::conforming("libbeta"),
        ],
        dependencies: vec![(
            "ref-acme-device".to_string(),
            vec!["ref-libalpha".to_string(), "ref-libbeta".to_string()],
        )],
        vulnerabilities: Vec::new(),
    }
}

/// Clone the conforming baseline and break exactly one aspect.
fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The conforming FDA fixture must pass with a clean verdict — no test in the
/// repo previously observed `is_compliant == true` for FdaMedicalDevice.
#[test]
fn fda_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(LEVEL, &base());
}

#[test]
fn fda_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No software component at all (no primary, no components): the
        // per-component rules have nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-FDA-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        // FDA incorporates the NTIA baseline: a missing/invalid source
        // timestamp (epoch sentinel) must gate.
        RuleEntry::tested(
            "SBOM-NTIA-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        // Registry default is Warning; the shared creator gate escalates a
        // fully creator-less SBOM to Error for every non-Minimum level.
        RuleEntry::tested_departing(
            "SBOM-FDA-CREATOR",
            Sev::Error,
            broken(|s| {
                s.tools.clear();
                s.manufacturer = None;
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-FDA-NAMESPACE",
            Sev::Warning,
            broken(|s| s.serial_number = None),
            base(),
        ),
        // Component-level missing supplier is the gating Error; the
        // document-level "manufacturer should be an organization creator"
        // site shares the rule id at Warning.
        RuleEntry::tested(
            "SBOM-FDA-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_departing_firing(
            "no organization creator (document-level site)",
            Sev::Warning,
            broken(|s| {
                s.manufacturer = None;
                // Person author keeps creators non-empty (no FDA-CREATOR) and
                // carries the contact email (no FDA-CONTACT).
                s.authors = vec![(
                    "Dana Author".to_string(),
                    Some("dana@acme.example".to_string()),
                )];
            }),
        ),
        // Missing hash is the gating Error; a weak-only (MD5) hash relaxes
        // to Warning at the same rule id.
        RuleEntry::tested(
            "SBOM-FDA-HASH",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        )
        .with_departing_firing(
            "weak hash only (MD5)",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").hashes =
                    vec![("MD5".to_string(), MD5_FILLER.to_string())];
            }),
        ),
        RuleEntry::tested(
            "SBOM-FDA-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-FDA-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        // No dependencies at all is the gating Error; FDA keeps any-orphan
        // sensitivity, so a single disconnected component warns at the same
        // rule id.
        RuleEntry::tested(
            "SBOM-FDA-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        )
        .with_departing_firing(
            "one orphan component (any-orphan sensitivity)",
            Sev::Warning,
            broken(|s| {
                // libbeta loses its only incoming edge and becomes an orphan.
                s.dependencies = vec![(
                    "ref-acme-device".to_string(),
                    vec!["ref-libalpha".to_string()],
                )];
            }),
        ),
        // Two checks report under the SBOM-FDA-SUPPORT SARIF rule at Warning:
        // the creator contact email (SBOM-FDA-CONTACT) and level-of-support /
        // end-of-support evidence.
        RuleEntry::tested(
            "SBOM-FDA-SUPPORT",
            Sev::Warning,
            broken(|s| {
                // Drop the only contact email; end-of-support evidence stays.
                s.manufacturer = Some(("Acme Medical Inc".to_string(), None));
            }),
            base(),
        )
        .with_firing(
            "no level-of-support / end-of-support evidence",
            Sev::Warning,
            broken(|s| {
                if let Some(primary) = &mut s.primary {
                    primary.properties.clear();
                }
            }),
        ),
        // Fires on unresolved critical/high vulnerabilities; medium ones must
        // stay silent.
        RuleEntry::tested(
            "SBOM-FDA-SECURITY",
            Sev::Warning,
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-0001".to_string(),
                    "critical".to_string(),
                    "ref-libalpha".to_string(),
                )];
            }),
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-0002".to_string(),
                    "medium".to_string(),
                    "ref-libalpha".to_string(),
                )];
            }),
        ),
        // The FDA generic bucket: a missing document name emits the aliased
        // SBOM-FDA-NAME key at Warning; a placeholder component name emits
        // the aliased SBOM-FDA-COMPONENT-NAME key, escalated to Error.
        RuleEntry::tested(
            "SBOM-FDA-GENERAL",
            Sev::Warning,
            broken(|s| s.primary = None),
            base(),
        )
        .with_departing_firing(
            "placeholder component name",
            Sev::Error,
            broken(|s| {
                // "unknown" without a corroborating PURL name segment does
                // not count as a real component name.
                s.component_mut("libalpha").name = "unknown".to_string();
            }),
        ),
    ];

    run_matrix(LEVEL, FDA_SARIF_RULE_IDS, &entries);
}
