//! Registry-driven per-rule matrix for `ComplianceLevel::FdaMedicalDevice`
//! (audit P3: the FDA framework previously had zero behavioral tests).
//!
//! Every rule id in `FDA_SARIF_RULE_IDS` gets a firing fixture (a minimal
//! SBOM, rendered in each of the four encodings and parsed through the real
//! parser, that must surface the rule) and a silent fixture (one that must
//! not), or an explicit skip-with-reason. The runner enforces exhaustiveness
//! against the registry's FDA SARIF slice, so a new FDA rule cannot land
//! untested.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, IMPLAUSIBLE_SHA256_DIGESTS, MD5_FILLER,
    RuleEntry, SPDX_VERSION_CASE, SPDX3_AGENT_EMAILS_NOT_READ, SPDX3_VALID_UNTIL_NOT_READ,
    SPDX23_HAS_NO_VULNERABILITIES, SbomFixture, UNPARSEABLE_TIMESTAMP, VulnAnalysisFixture,
    assert_no_violations_in, assert_spdx_version_unknown, run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, FDA_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::FdaMedicalDevice;

/// A fixture that satisfies every FDA premarket element the engine checks:
/// timestamp, tool + manufacturer creators with a contact email, serial
/// number, named primary product with end-of-support evidence, and fully
/// attributed/hashed/connected components.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-device");
    // Level-of-support evidence: the parsers lift the primary component's
    // end of support into document.support_end_date.
    primary.support_end = Some("2030-01-01".to_string());
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
        ..SbomFixture::default()
    }
}

/// Clone the conforming baseline and break exactly one aspect.
fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The id of [`critical_vulnerability`].
const CRITICAL_CVE: &str = "CVE-2026-0001";

/// A critical vulnerability of libalpha.
fn critical_vulnerability() -> (String, String, String) {
    (
        CRITICAL_CVE.to_string(),
        "critical".to_string(),
        "ref-libalpha".to_string(),
    )
}

/// A VEX `not_affected` analysis, naming the CycloneDX `justification`
/// when one is given.
fn not_affected(justification: Option<&str>) -> VulnAnalysisFixture {
    VulnAnalysisFixture {
        state: Some("not_affected".to_string()),
        justification: justification.map(str::to_string),
        ..VulnAnalysisFixture::default()
    }
}

/// Only CycloneDX names the document's supplier.
const CYCLONEDX_DOCUMENT_SUPPLIER: &str = "the document's supplier: CycloneDX \
     metadata.supplier has no SPDX counterpart (SPDX keeps the supplier on the described \
     package)";

/// Neither an organization creator nor the device's supplier names the
/// manufacturer. A person author keeps the creators non-empty (no
/// FDA-CREATOR) and carries the contact email (no FDA-CONTACT).
fn without_manufacturer(s: &mut SbomFixture) {
    s.manufacturer = None;
    s.authors = vec![(
        "Dana Author".to_string(),
        Some("dana@acme.example".to_string()),
    )];
    s.primary_mut().supplier = None;
}

/// The conforming FDA fixture must pass with a clean verdict — no test in the
/// repo previously observed `is_compliant == true` for FdaMedicalDevice. In
/// SPDX 3 the parser reads neither the creators' emails nor the end of
/// support (the SBOM-FDA-CONTACT and SBOM-FDA-SUPPORT rows).
#[test]
fn fda_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &base(), Encoding::ALL_BUT_SPDX3);
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
        // timestamp (epoch sentinel) must gate, under an FDA id of its own
        // (SBOM-NTIA-TIMESTAMP until v0.4.0).
        RuleEntry::tested(
            "SBOM-FDA-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        )
        .with_firing(
            "unparseable timestamp",
            Sev::Error,
            broken(|s| s.timestamp = Some(UNPARSEABLE_TIMESTAMP.to_string())),
        ),
        // The creator gate emits a fully creator-less SBOM as an Error.
        RuleEntry::tested(
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
        // A component without a supplier, manufacturer or author.
        RuleEntry::tested(
            "SBOM-FDA-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_firing(
            "placeholder component supplier (NOASSERTION)",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = Some("NOASSERTION".to_string())),
        ),
        // The device manufacturer, a document-level rule of its own
        // (SBOM-FDA-SUPPLIER until v0.4.0, the id the per-component supplier
        // element keeps). An organization creator, the product's supplier
        // (CycloneDX metadata.supplier), or the device's own supplier or
        // manufacturer (CycloneDX 1.6+) names the manufacturer; a
        // placeholder names nobody.
        RuleEntry::tested(
            "SBOM-FDA-MANUFACTURER",
            Sev::Warning,
            broken(without_manufacturer),
            base(),
        )
        .with_firing(
            "placeholder device supplier",
            Sev::Warning,
            broken(|s| {
                without_manufacturer(s);
                s.primary_mut().supplier = Some("NOASSERTION".to_string());
            }),
        )
        .with_firing(
            "placeholder product supplier (metadata.supplier)",
            Sev::Warning,
            broken(|s| {
                without_manufacturer(s);
                s.supplier = Some("N/A".to_string());
            }),
        )
        .with_silent(
            "manufacturer named only as the device's supplier",
            broken(|s| {
                without_manufacturer(s);
                s.primary_mut().supplier = Some("Acme Medical Inc".to_string());
            }),
        )
        .with_silent(
            "manufacturer named only as the device's manufacturer",
            broken(|s| {
                without_manufacturer(s);
                s.primary_mut().manufacturer = Some("Acme Medical Inc".to_string());
            }),
        )
        .with_silent(
            "manufacturer named only as the product's supplier (metadata.supplier)",
            broken(|s| {
                without_manufacturer(s);
                s.supplier = Some("Acme Medical Inc".to_string());
            }),
        )
        .case_only(
            "placeholder product supplier (metadata.supplier)",
            Encoding::CYCLONEDX,
            CYCLONEDX_DOCUMENT_SUPPLIER,
        )
        .case_only(
            "manufacturer named only as the device's manufacturer",
            Encoding::CYCLONEDX,
            "a component manufacturer: CycloneDX 1.6+ component.manufacturer has no SPDX \
             counterpart the parsers read",
        )
        .case_only(
            "manufacturer named only as the product's supplier (metadata.supplier)",
            Encoding::CYCLONEDX,
            CYCLONEDX_DOCUMENT_SUPPLIER,
        ),
        // Missing hash is the gating Error; a weak-only (MD5) hash relaxes
        // to Warning at the same rule id. Only plausible digests count: a
        // component whose hashes are all empty or garbage has none, and an
        // MD5 beside a garbage SHA-256 is weak-only.
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
        )
        .with_implausible_digests(Sev::Error, &IMPLAUSIBLE_SHA256_DIGESTS, |alg, value| {
            broken(|s| {
                s.component_mut("libalpha").hashes = vec![(alg.to_string(), value.to_string())];
            })
        })
        .with_departing_firing(
            "weak hash beside an empty SHA-256 digest",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").hashes = vec![
                    ("MD5".to_string(), MD5_FILLER.to_string()),
                    ("SHA-256".to_string(), String::new()),
                ];
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
        // Level-of-support / end-of-support evidence. The creator contact
        // email, which shared this SARIF rule until v0.4.0, is
        // SBOM-FDA-CONTACT (row below).
        RuleEntry::tested(
            "SBOM-FDA-SUPPORT",
            Sev::Warning,
            broken(|s| {
                if let Some(primary) = &mut s.primary {
                    primary.support_end = None;
                }
            }),
            base(),
        )
        .case_only(
            "silent",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_VALID_UNTIL_NOT_READ,
        ),
        // Fires on unresolved critical/high vulnerabilities; medium ones must
        // stay silent. A justified VEX not_affected statement resolves one,
        // as under the CRA profiles (until v0.4.0 it still counted); a bare
        // not_affected claim does not.
        RuleEntry::tested(
            "SBOM-FDA-SECURITY",
            Sev::Warning,
            broken(|s| s.vulnerabilities = vec![critical_vulnerability()]),
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-0002".to_string(),
                    "medium".to_string(),
                    "ref-libalpha".to_string(),
                )];
            }),
        )
        .with_firing(
            "critical vulnerability with a bare not_affected statement",
            Sev::Warning,
            broken(|s| {
                s.vulnerabilities = vec![critical_vulnerability()];
                s.vulnerability_analyses
                    .push((CRITICAL_CVE.to_string(), not_affected(None)));
            }),
        )
        .with_silent(
            "critical vulnerability with a justified not_affected statement",
            broken(|s| {
                s.vulnerabilities = vec![critical_vulnerability()];
                s.vulnerability_analyses.push((
                    CRITICAL_CVE.to_string(),
                    not_affected(Some("code_not_reachable")),
                ));
            }),
        )
        .only(Encoding::ALL_BUT_SPDX23, SPDX23_HAS_NO_VULNERABILITIES),
        // A missing document name (no primary component to lift it from).
        RuleEntry::tested(
            "SBOM-FDA-NAME",
            Sev::Warning,
            broken(|s| s.primary = None),
            base(),
        ),
        // "unknown" without a corroborating PURL name segment does not count
        // as a real component name.
        RuleEntry::tested(
            "SBOM-FDA-COMPONENT-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        // A CycloneDX or SPDX version newer than any this tool reads warns;
        // an outdated CycloneDX version is an Info. Each version case runs
        // in the format whose version it sets.
        RuleEntry::tested(
            "SBOM-FDA-SPEC-VERSION",
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
            "SBOM-FDA-SPEC-VERSION-UNKNOWN",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("4.0".to_string())),
            base(),
        )
        .case_only("firing", Encoding::SPDX, SPDX_VERSION_CASE),
        // A component whose bom-ref collapses to its name.
        RuleEntry::tested(
            "SBOM-FDA-ELEMENT-ID",
            Sev::Info,
            broken(|s| {
                s.component_mut("libalpha").bom_ref = "libalpha".to_string();
                s.dependencies = vec![(
                    "ref-acme-device".to_string(),
                    vec!["libalpha".to_string(), "ref-libbeta".to_string()],
                )];
            }),
            base(),
        ),
        // No creator carries a contact email; a person author's email
        // counts as well as the manufacturer's.
        RuleEntry::tested(
            "SBOM-FDA-CONTACT",
            Sev::Warning,
            broken(|s| {
                // Drop the only contact email; end-of-support evidence stays.
                s.manufacturer = Some(("Acme Medical Inc".to_string(), None));
            }),
            base(),
        )
        .with_silent(
            "contact email on a person author only",
            broken(|s| {
                s.manufacturer = Some(("Acme Medical Inc".to_string(), None));
                s.authors = vec![(
                    "Dana Author".to_string(),
                    Some("dana@acme.example".to_string()),
                )];
            }),
        )
        // A contact must reach someone, as in every contact check.
        .with_firing(
            "the only contact email is a placeholder",
            Sev::Warning,
            broken(|s| {
                s.manufacturer = Some(("Acme Medical Inc".to_string(), Some("n/a".to_string())));
            }),
        )
        .with_firing(
            "the only contact email is at a documentation domain",
            Sev::Warning,
            broken(|s| {
                s.manufacturer = Some((
                    "Acme Medical Inc".to_string(),
                    Some("security@example.com".to_string()),
                ));
            }),
        )
        .case_only(
            "silent",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_AGENT_EMAILS_NOT_READ,
        )
        .case_only(
            "contact email on a person author only",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_AGENT_EMAILS_NOT_READ,
        ),
        // A component listed twice, under a second bom-ref or under its own
        // bom-ref again: the entries are merged, and one Info names it.
        RuleEntry::tested(
            "SBOM-FDA-DUPLICATE-COMPONENT",
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

    run_matrix(LEVEL, FDA_SARIF_RULE_IDS, &entries);
}

/// SBOM-FDA-SPEC-VERSION-UNKNOWN reads only SPDX input: its matrix row
/// fires it in SPDX 2.3 JSON and SPDX 3; this pins SPDX tag-value.
#[test]
fn fda_spec_version_unknown_reads_only_spdx() {
    assert_spdx_version_unknown(LEVEL, "SBOM-FDA-SPEC-VERSION-UNKNOWN");
}
