//! Registry-driven per-rule matrix for `ComplianceLevel::PciDss632`
//! (PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile).
//!
//! Every rule id in `PCIDSS_SARIF_RULE_IDS` gets a firing fixture (a minimal
//! SBOM, rendered in each of the four encodings and parsed through the real
//! parser, that must surface the rule) and a silent fixture (one that must
//! not), or an explicit skip-with-reason. The runner enforces exhaustiveness
//! against the registry's PCI SARIF slice, so a new PCI rule cannot land
//! untested.
//!
//! One profile-specific wrinkle: the checker treats an absent CycloneDX
//! compositions aggregate (`CompletenessDeclaration::Unknown`, the serde
//! default) as an Info-level "no completeness declaration" finding, and a
//! declared-Complete primary-only inventory suppresses the third-party
//! inference. `base()` therefore leaves the aggregate undeclared, so every
//! fixture built from it carries exactly that one Info; the fully-conforming
//! zero-violation fixture declares its inventory Complete, and the
//! SBOM-PCI-6-3-2-COMPLETENESS row (plus the tests at the bottom of this
//! file) covers the declaration variants. SPDX 2.3 has no completeness
//! declaration, so every SPDX 2.3 rendering carries that Info.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::as_of;
use rule_matrix::{
    ComponentFixture, Encoding, Outcome, RuleEntry, SPDX23_HAS_NO_COMPLETENESS,
    SPDX23_HAS_NO_VULNERABILITIES, SbomFixture, assert_no_violations_in, check, render_violations,
    run_matrix,
};
use sbom_tools::quality::{ComplianceLevel, PCIDSS_SARIF_RULE_IDS, ViolationSeverity as Sev};

const LEVEL: ComplianceLevel = ComplianceLevel::PciDss632;

/// A recent RFC 3339 timestamp (the day before the pinned test clock), so
/// the tool-policy staleness advisory never trips the fixtures.
fn recent_timestamp() -> String {
    (as_of() - chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A timestamp 30 days after the pinned test clock, i.e. after the
/// evaluation instant.
fn future_timestamp() -> String {
    (as_of() + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fixture that satisfies every PCI DSS 6.3.2 element the engine checks —
/// except the completeness declaration, which it leaves undeclared (see the
/// module docs): named/versioned/identified primary with an advisories
/// reference (vulnerability-management hook), supplier-attributed
/// third-party components, and a fresh timestamp.
fn base() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-payments");
    primary.external_refs.push((
        "advisories".to_string(),
        "https://acme.example/security/advisories".to_string(),
    ));
    SbomFixture {
        spec_version: "1.5".to_string(),
        timestamp: Some(recent_timestamp()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: Vec::new(),
        manufacturer: None,
        primary: Some(primary),
        components: vec![
            ComponentFixture::conforming("libalpha"),
            ComponentFixture::conforming("libbeta"),
        ],
        dependencies: vec![(
            "ref-acme-payments".to_string(),
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

/// `base()` with the given compositions aggregate declared.
fn declared(aggregate: &str) -> SbomFixture {
    broken(|s| s.completeness = Some(aggregate.to_string()))
}

/// The conforming PCI fixture must pass with a clean verdict. It declares
/// its inventory Complete (compositions aggregate) on top of `base()`; an
/// undeclared inventory keeps an Info-level completeness finding by design,
/// which is why no SPDX 2.3 rendering is clean.
#[test]
fn pci_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(LEVEL, &declared("complete"), Encoding::ALL_BUT_SPDX23);
}

#[test]
fn pci_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // An empty document cannot serve as the inventory; a document with
        // components but no resolvable primary fails the same rule.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        )
        .with_firing(
            "components but no resolvable primary",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.dependencies =
                    vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
        ),
        // "unknown" without a corroborating PURL name segment is a
        // placeholder, not a real component name.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        // Supplier evidence includes the ecosystem-bearing PURL fallback, so
        // the firing case must drop both supplier and PURL (the PURL loss
        // additionally fires the identifier rule — same universe).
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-SUPPLIER",
            Sev::Warning,
            broken(|s| {
                let comp = s.component_mut("libalpha");
                comp.supplier = None;
                comp.purl = None;
            }),
            base(),
        ),
        // Dropping only the PURL keeps the supplier rule silent (supplier
        // organization still present) and isolates the identifier rule.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-IDENTIFIER",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        // Primary-only inventory (no undeclared-Complete escape hatch in the
        // DSL fixtures) plus the indistinguishable-components variant.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-THIRD-PARTY",
            Sev::Warning,
            broken(|s| {
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        )
        .with_firing(
            "components beyond primary but none distinguishable as third-party",
            Sev::Warning,
            broken(|s| {
                for name in ["libalpha", "libbeta"] {
                    let comp = s.component_mut(name);
                    comp.supplier = None;
                    comp.purl = None;
                }
            }),
        ),
        // Explicit incomplete* aggregates are self-declared inventory gaps
        // (TP 6.3.2.b) and warn; an absent or not_specified declaration is
        // informational; complete is silent.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-COMPLETENESS",
            Sev::Warning,
            declared("incomplete"),
            declared("complete"),
        )
        .with_departing_firing("no declaration", Sev::Info, base())
        .with_departing_firing(
            "aggregate not_specified",
            Sev::Info,
            declared("not_specified"),
        )
        .case_differs(
            "firing",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_HAS_NO_COMPLETENESS,
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_HAS_NO_COMPLETENESS,
        ),
        // Missing timestamp (epoch sentinel) warns, and so does one dated
        // after the evaluation instant; the stale-timestamp Info advisory is
        // pinned-clock-tested in pci_dss.rs unit tests (fixtures here are
        // dated the day before the runner's pinned clock).
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-FRESHNESS",
            Sev::Warning,
            broken(|s| s.timestamp = None),
            base(),
        )
        .with_firing(
            "future-dated",
            Sev::Warning,
            broken(|s| s.timestamp = Some(future_timestamp())),
        ),
        // No vulnerability-management hook anywhere: no embedded data, no
        // advisories/assertion/VDR reference, no contact.
        RuleEntry::tested(
            "SBOM-PCI-6-3-2-VULN-EVIDENCE",
            Sev::Info,
            broken(|s| {
                if let Some(primary) = &mut s.primary {
                    primary.external_refs.clear();
                }
            }),
            base(),
        )
        .with_silent(
            "vulnerability-assertion (VDR) reference as the only hook",
            broken(|s| {
                if let Some(primary) = &mut s.primary {
                    primary.external_refs = vec![(
                        "vulnerability-assertion".to_string(),
                        "https://acme.example/security/vdr.json".to_string(),
                    )];
                }
            }),
        )
        .case_differs(
            "vulnerability-assertion (VDR) reference as the only hook",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            "SPDX 2.3 has no reference category for a VDR: an OTHER vulnerability-assertion \
             reference is unrecognized",
        )
        // A support link is no vulnerability-management hook in any format
        // (before v0.4.0 the CycloneDX parser made the product's support
        // link its disclosure URL).
        .with_firing(
            "support reference as the only link",
            Sev::Info,
            broken(|s| {
                if let Some(primary) = &mut s.primary {
                    primary.external_refs = vec![(
                        "support".to_string(),
                        "https://acme.example/support".to_string(),
                    )];
                }
            }),
        ),
        // An embedded entry whose only rating severity is "unknown" (and no
        // CVSS score) is unranked; a "medium" entry is ranked and must stay
        // silent — the rule is otherwise not applicable without any
        // vulnerability data (covered by every other fixture here).
        RuleEntry::tested(
            "SBOM-PCI-11-3-1-1-SEVERITY",
            Sev::Warning,
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-0001".to_string(),
                    "unknown".to_string(),
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
        )
        .only(Encoding::ALL_BUT_SPDX23, SPDX23_HAS_NO_VULNERABILITIES),
    ];

    run_matrix(LEVEL, PCIDSS_SARIF_RULE_IDS, &entries);
}

// ────────────────────────────────────────────────────────────────────────
// SBOM-PCI-6-3-2-COMPLETENESS declaration variants
// ────────────────────────────────────────────────────────────────────────

/// Explicit `incomplete*` aggregates are self-declared inventory gaps
/// against TP 6.3.2.b and warn (the registry default severity).
#[test]
fn pci_completeness_incomplete_declarations_warn() {
    for aggregate in [
        "incomplete",
        "incomplete_first_party_only",
        "incomplete_third_party_only",
    ] {
        let result = check(LEVEL, &declared(aggregate));
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.sarif_rule_id() == "SBOM-PCI-6-3-2-COMPLETENESS"
                    && v.severity == Sev::Warning),
            "aggregate {aggregate:?} must warn:\n{}",
            render_violations(&result)
        );
    }
}

/// `not_specified` (declared but unrecognized / no-assertion) and an absent
/// compositions section (`Unknown`, the parser default) are informational,
/// not gaps; `complete` is silent (proved by the conforming-fixture test).
#[test]
fn pci_completeness_not_specified_and_absent_are_informational() {
    let not_specified = check(LEVEL, &declared("not_specified"));
    assert!(
        not_specified
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == "SBOM-PCI-6-3-2-COMPLETENESS" && v.severity == Sev::Info),
        "not_specified must be informational:\n{}",
        render_violations(&not_specified)
    );

    let absent = check(LEVEL, &base());
    assert!(
        absent
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == "SBOM-PCI-6-3-2-COMPLETENESS" && v.severity == Sev::Info),
        "an absent compositions section must be informational:\n{}",
        render_violations(&absent)
    );
    // And it must be the only finding on the otherwise-conforming fixture.
    assert!(
        absent
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() == "SBOM-PCI-6-3-2-COMPLETENESS"),
        "the undeclared baseline must carry only the completeness Info:\n{}",
        render_violations(&absent)
    );
}
