//! Registry-driven per-rule matrix for `ComplianceLevel::PciDss632`
//! (PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile).
//!
//! Every rule id in `PCIDSS_SARIF_RULE_IDS` gets a firing fixture (a minimal
//! CycloneDX document, parsed through the real parser, that must surface the
//! rule) and a silent fixture (one that must not), or an explicit
//! skip-with-reason. The runner enforces exhaustiveness against the
//! registry's PCI SARIF slice, so a new PCI rule cannot land untested.
//!
//! One profile-specific wrinkle: the checker treats an absent CycloneDX
//! compositions aggregate (`CompletenessDeclaration::Unknown`, the serde
//! default) as an Info-level "no completeness declaration" finding, so every
//! DSL-built fixture in this matrix carries exactly that one Info. The
//! fully-conforming zero-violation fixture therefore declares its inventory
//! Complete via a raw-JSON compositions injection (the shared DSL cannot
//! render compositions), and the SBOM-PCI-6-3-2-COMPLETENESS variants are
//! covered by the dedicated raw-JSON tests at the bottom of this file.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{ComponentFixture, RuleEntry, SbomFixture, render_violations, run_matrix};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, PCIDSS_SARIF_RULE_IDS,
    ViolationSeverity as Sev,
};

const LEVEL: ComplianceLevel = ComplianceLevel::PciDss632;

/// A recent (wall-clock-relative) RFC 3339 timestamp, so the tool-policy
/// staleness advisory can never trip the fixtures as the calendar advances
/// (the repo's known wall-clock snapshot gotcha).
fn recent_timestamp() -> String {
    (chrono::Utc::now() - chrono::Duration::days(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A timestamp 30 days ahead of the wall clock: after the evaluation
/// instant whether the runner uses the wall clock or pins an earlier one.
fn future_timestamp() -> String {
    (chrono::Utc::now() + chrono::Duration::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fixture that satisfies every PCI DSS 6.3.2 element the engine checks —
/// except the completeness declaration, which the DSL cannot express (see
/// the module docs): named/versioned/identified primary with an advisories
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
    }
}

/// Clone the conforming baseline and break exactly one aspect.
fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// Render the fixture and inject a CycloneDX compositions aggregate — the
/// one document feature the shared DSL cannot express — then re-serialize.
fn json_with_compositions(fixture: &SbomFixture, aggregate: &str) -> String {
    let mut doc: serde_json::Value =
        serde_json::from_str(&fixture.to_json_string()).expect("fixture JSON re-parses");
    doc["compositions"] = serde_json::json!([{ "aggregate": aggregate }]);
    serde_json::to_string(&doc).expect("augmented fixture serializes")
}

/// Run the PCI profile over raw CycloneDX JSON through the real parser.
fn check_json(json: &str) -> ComplianceResult {
    let sbom = parse_sbom_str(json).expect("raw fixture must parse as CycloneDX");
    ComplianceChecker::new(LEVEL).check(&sbom)
}

/// The conforming PCI fixture must pass with a clean verdict. It declares
/// its inventory Complete (compositions aggregate) on top of `base()`; an
/// undeclared inventory keeps an Info-level completeness finding by design.
#[test]
fn pci_conforming_fixture_is_compliant_with_zero_violations() {
    let result = check_json(&json_with_compositions(&base(), "complete"));
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "[{LEVEL:?}] conforming fixture must pass with zero violations; got \
         is_compliant={compliant}:\n{violations}",
        compliant = result.is_compliant,
        violations = render_violations(&result)
    );
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
        RuleEntry::skipped(
            "SBOM-PCI-6-3-2-COMPLETENESS",
            "requires a CycloneDX compositions aggregate, which the shared fixture \
             DSL cannot render; all declaration variants (Complete silent, \
             Incomplete* Warning, Unknown/NotSpecified Info) are covered by the \
             dedicated raw-JSON tests in this file and the unit tests in \
             src/quality/compliance/pci_dss.rs",
        ),
        // Missing timestamp (epoch sentinel) warns, and so does one dated
        // after the evaluation instant; the stale-timestamp Info advisory is
        // pinned-clock-tested in pci_dss.rs unit tests (the matrix runner
        // uses the wall clock, and fixtures stay fresh by construction).
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
        ),
        RuleEntry::skipped(
            "SBOM-PCI-GENERAL",
            "registry catch-all for the PCI DSS family: no check site in \
             check_pci_dss_6_3_2 emits it (registry.rs keeps it as the SARIF \
             re-bucketing target); it cannot fire from document content",
        ),
    ];

    run_matrix(LEVEL, PCIDSS_SARIF_RULE_IDS, &entries);
}

// ────────────────────────────────────────────────────────────────────────
// SBOM-PCI-6-3-2-COMPLETENESS coverage (raw-JSON compositions, real parser)
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
        let result = check_json(&json_with_compositions(&base(), aggregate));
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
    let not_specified = check_json(&json_with_compositions(&base(), "not_specified"));
    assert!(
        not_specified
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == "SBOM-PCI-6-3-2-COMPLETENESS" && v.severity == Sev::Info),
        "not_specified must be informational:\n{}",
        render_violations(&not_specified)
    );

    let absent = check_json(&base().to_json_string());
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
