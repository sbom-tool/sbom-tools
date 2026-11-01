//! Registry-driven per-rule matrices for the EU CRA family:
//! `ComplianceLevel::CraPhase1`, `CraPhase2` and `CraOssSteward`. None of the
//! three had a per-rule matrix (the Error-level hardware rule
//! SBOM-CRA-PRE-8-RQ-02 was never asserted).
//!
//! Each universe below is declared locally, from the check sites in
//! generic.rs and cra.rs; `run_matrix` requires it to equal the registry's
//! list for the level (`rules_for_level`), and
//! `cra_universes_cover_the_cra_family` ties the three to the `SBOM-CRA-*`
//! rule family. Every check is a rule of its own (until v0.4.0 most CRA
//! findings shared the `SBOM-CRA-ANNEX-I` and `SBOM-CRA-GENERAL` SARIF
//! rules), so every row names the rule one check reports. The Phase 2-only
//! checks (`SBOM-CRA-LIFECYCLE`, `SBOM-CRA-VULN-METADATA` and the others the
//! Phase 2 universe adds) are in no Phase 1 row: no Phase 1 check emits
//! them.
//!
//! The manufacturer fixtures carry a CRA sidecar with the Art. 14 reporting
//! channels (the only place they can be declared); the pinned clock is past
//! the 2026-09-11 Art. 14 deadline.
//!
//! Every case runs in all four encodings unless its row says otherwise. SPDX
//! 2.3 carries no vulnerability data and names no attestation,
//! certification-report, risk-assessment, VDR or VEX reference type, so the
//! references that silence those rows elsewhere leave them firing there.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::{as_of, checker};
use rule_matrix::{
    CYCLONEDX_VERSION_CASE, ComponentFixture, Encoding, Outcome, RuleEntry, SHA256_FILLER,
    SPDX_REFERENCES_CARRY_NO_HASH, SPDX_VERSION_CASE, SPDX3_AGENT_EMAILS_NOT_READ,
    SPDX3_VALID_UNTIL_NOT_READ, SPDX23_HAS_NO_VULNERABILITIES, SbomFixture, VulnAnalysisFixture,
    assert_no_violations_in, assert_spdx_version_unknown, check, render_violations, run_matrix,
};
use sbom_tools::model::{
    ConformityRoute, ControlAssertion, CraProductClass, CraSidecarMetadata, EolStatus,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ViolationSeverity as Sev, all_rule_ids, generic_rule_id_for_level,
};
use std::collections::BTreeSet;

const PHASE1: ComplianceLevel = ComplianceLevel::CraPhase1;
const PHASE2: ComplianceLevel = ComplianceLevel::CraPhase2;
const STEWARD: ComplianceLevel = ComplianceLevel::CraOssSteward;

/// Every rule id CRA Phase 1 can emit (generic.rs + cra.rs): the document,
/// component, dependency and format checks, the CRA gap checks, Art. 14
/// readiness, class-pinned conformity checks, and the hardware checks.
const PHASE1_RULE_UNIVERSE: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA-PROFILE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-5-PROFILE",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-ART-13-8-EOL",
    "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-TRACEABILITY",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ART-14-PSIRT",
    "SBOM-CRA-ART-14-EARLY-WARNING",
    "SBOM-CRA-ART-14-NOTIFICATION",
    "SBOM-CRA-ART-14-ENISA",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-CYCLES",
];

/// Phase 2 adds the full-application checks: vulnerability severity and
/// remediation (Annex I Part II (4)), CVD policy (Annex I Part II (5)),
/// lifecycle evidence (Annex II (7)), the EU Declaration of Conformity
/// reference (Annex V) and the risk assessment (Art. 13(2)).
const PHASE2_RULE_UNIVERSE: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-VULN-METADATA-REMEDIATION",
    "SBOM-CRA-VULN-METADATA-PROFILE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-5-PROFILE",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-ART-13-8-EOL",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-TRACEABILITY",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-ART-13-2",
    "SBOM-CRA-ART-14-PSIRT",
    "SBOM-CRA-ART-14-EARLY-WARNING",
    "SBOM-CRA-ART-14-NOTIFICATION",
    "SBOM-CRA-ART-14-ENISA",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-CYCLES",
];

/// Every rule id the Art. 24 steward profile can emit (check_cra_oss_steward
/// runs the component, dependency and format checks plus the two steward
/// floors — no document-metadata, gap, Art. 14 or hardware checks).
const STEWARD_RULE_UNIVERSE: &[&str] = &[
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-ART-24",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-ART-24-SUPPLIER",
    "SBOM-CRA-CYCLES",
];

/// RFC 3339 timestamp `days` before the pinned test clock.
fn days_before_clock(days: i64) -> String {
    (as_of() - chrono::Duration::days(days)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A component that also carries a licence (Art. 13(5) due diligence).
fn comp(name: &str) -> ComponentFixture {
    let mut c = ComponentFixture::conforming(name);
    c.licenses = vec!["MIT".to_string()];
    c
}

/// The product: a licensed application whose security-contact and
/// advisories references the parser lifts into the document's contact and
/// disclosure URL, and whose end-of-support property it lifts into the
/// document's support end date.
fn primary() -> ComponentFixture {
    let mut p = comp("acme-router-os");
    p.component_type = "application".to_string();
    p.external_refs = vec![
        (
            "security-contact".to_string(),
            "mailto:psirt@acme.example".to_string(),
        ),
        (
            "advisories".to_string(),
            "https://acme.example/security/advisories".to_string(),
        ),
    ];
    p.support_end = Some("2031-12-31".to_string());
    p
}

/// The manufacturer sidecar: the four Art. 14 reporting channels, the
/// Art. 13(2) risk assessment and the Annex V DoC reference.
fn manufacturer_sidecar() -> CraSidecarMetadata {
    CraSidecarMetadata {
        psirt_url: Some("https://acme.example/psirt".to_string()),
        early_warning_contact: Some("early-warning@acme.example".to_string()),
        incident_report_contact: Some("incidents@acme.example".to_string()),
        enisa_reporting_platform_id: Some("EU-MFR-12345".to_string()),
        risk_assessment_url: Some("https://acme.example/docs/risk-assessment.pdf".to_string()),
        ce_marking_reference: Some("EU-DoC-2026-001".to_string()),
        ..CraSidecarMetadata::default()
    }
}

/// A fixture that satisfies every CRA element of both manufacturer phases:
/// a fresh (11-day-old) CycloneDX 1.6 document with a serial number, a tool
/// and an organization creator with a valid email, the product as primary
/// component wired to fully attributed, licensed and hashed components, an
/// embedded (rated) vulnerability as the documented vulnerability
/// information, and the manufacturer sidecar.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some(days_before_clock(11)),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        manufacturer: Some((
            "Acme Networks GmbH".to_string(),
            Some("psirt@acme.example".to_string()),
        )),
        primary: Some(primary()),
        components: vec![comp("libalpha"), comp("libbeta")],
        dependencies: vec![(
            "ref-acme-router-os".to_string(),
            vec!["ref-libalpha".to_string(), "ref-libbeta".to_string()],
        )],
        vulnerabilities: vec![(
            "CVE-2026-1111".to_string(),
            "low".to_string(),
            "ref-libalpha".to_string(),
        )],
        sidecar: Some(manufacturer_sidecar()),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// The steward fixture: the manufacturer baseline without a sidecar (a
/// steward owes no Art. 14 channels; the advisories reference is its CVD
/// policy and vulnerability-handling contact).
fn steward_base() -> SbomFixture {
    broken(|s| s.sidecar = None)
}

fn steward_broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = steward_base();
    mutate(&mut fixture);
    fixture
}

/// Pin the CRA product class (and optionally the conformity route) in the
/// sidecar.
fn pin_class(s: &mut SbomFixture, class: CraProductClass, route: Option<ConformityRoute>) {
    let sidecar = s.sidecar.get_or_insert_with(CraSidecarMetadata::default);
    sidecar.product_class = Some(class);
    sidecar.conformity_assessment_route = route;
}

/// A dependency cycle between the two libraries.
fn add_cycle(s: &mut SbomFixture) {
    s.dependencies
        .push(("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()]));
    s.dependencies
        .push(("ref-libbeta".to_string(), vec!["ref-libalpha".to_string()]));
}

/// Remove the hashes of the named components.
fn strip_hashes(s: &mut SbomFixture, names: &[&str]) {
    for name in names {
        s.component_mut(name).hashes.clear();
    }
}

/// Add `count` supplier-less transitive dependencies under libalpha.
fn add_transitive_without_supplier(s: &mut SbomFixture, count: usize) {
    let names = ["libgamma", "libdelta", "libepsilon"];
    let mut refs = Vec::new();
    for name in &names[..count] {
        let mut c = comp(name);
        c.supplier = None;
        refs.push(c.bom_ref.clone());
        s.components.push(c);
    }
    s.dependencies.push(("ref-libalpha".to_string(), refs));
}

/// A conforming firmware component wired under the product.
fn firmware() -> ComponentFixture {
    let mut fw = comp("acme-fw");
    fw.component_type = "firmware".to_string();
    fw
}

fn with_firmware(s: &mut SbomFixture, fw: ComponentFixture) {
    s.dependencies[0].1.push(fw.bom_ref.clone());
    s.components.push(fw);
}

/// The primary removed; the libraries stay wired among themselves.
fn without_primary(s: &mut SbomFixture) {
    s.primary = None;
    s.dependencies = vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
}

/// Add an external reference of `ref_type` to the product component.
fn with_product_ref(s: &mut SbomFixture, ref_type: &str, url: &str) {
    s.primary_mut()
        .external_refs
        .push((ref_type.to_string(), url.to_string()));
}

/// Declare a VEX `analysis.response` on the baseline's embedded
/// vulnerability (CVE-2026-1111), with an optional remediation text member
/// (`recommendation` or `workaround`) as `(member, text)`.
fn with_response(s: &mut SbomFixture, response: &str, text: Option<(&str, &str)>) {
    let mut analysis = VulnAnalysisFixture {
        state: Some("exploitable".to_string()),
        responses: vec![response.to_string()],
        ..VulnAnalysisFixture::default()
    };
    match text {
        Some(("recommendation", value)) => analysis.recommendation = Some(value.to_string()),
        Some(("workaround", value)) => analysis.workaround = Some(value.to_string()),
        Some((member, _)) => panic!("no remediation text member {member:?}"),
        None => {}
    }
    s.vulnerability_analyses
        .push(("CVE-2026-1111".to_string(), analysis));
}

/// The id of [`unrated_vulnerability`].
const UNRATED_CVE: &str = "CVE-2026-2222";

/// A vulnerability of libalpha with no rating: no severity, no CVSS score.
fn unrated_vulnerability() -> (String, String, String) {
    (
        UNRATED_CVE.to_string(),
        String::new(), // unrated
        "ref-libalpha".to_string(),
    )
}

/// Declare a VEX analysis on the embedded vulnerability `id`.
fn with_analysis(s: &mut SbomFixture, id: &str, analysis: VulnAnalysisFixture) {
    s.vulnerability_analyses.push((id.to_string(), analysis));
}

/// A bare VEX `not_affected` analysis: no justification, no detail.
fn not_affected() -> VulnAnalysisFixture {
    VulnAnalysisFixture {
        state: Some("not_affected".to_string()),
        ..VulnAnalysisFixture::default()
    }
}

/// A VEX `not_affected` analysis that names its justification: the
/// vulnerable code is never reached in the product.
fn justified_not_affected() -> VulnAnalysisFixture {
    VulnAnalysisFixture {
        justification: Some("code_not_reachable".to_string()),
        ..not_affected()
    }
}

/// The unrated vulnerability, stated `not_affected` with the CycloneDX
/// justification `justification`.
fn not_affected_justified_by(s: &mut SbomFixture, justification: &str) {
    s.vulnerabilities = vec![unrated_vulnerability()];
    let analysis = VulnAnalysisFixture {
        justification: Some(justification.to_string()),
        ..not_affected()
    };
    with_analysis(s, UNRATED_CVE, analysis);
}

/// Add an external reference of `ref_type` carrying the SHA-256 of the
/// referenced document to the product component.
fn with_hashed_product_ref(s: &mut SbomFixture, ref_type: &str, url: &str) {
    s.primary_mut().hashed_external_refs.push((
        ref_type.to_string(),
        url.to_string(),
        vec![("SHA-256".to_string(), SHA256_FILLER.to_string())],
    ));
}

/// Give the named component a bom-ref equal to its name (the shape the
/// CycloneDX "may be missing bom-ref" note reads), rewriting the
/// dependencies and vulnerabilities that reference it.
fn bom_ref_is_name(s: &mut SbomFixture, name: &str) {
    let old = std::mem::replace(&mut s.component_mut(name).bom_ref, name.to_string());
    for (from, to) in &mut s.dependencies {
        for r in std::iter::once(from).chain(to.iter_mut()) {
            if *r == old {
                *r = name.to_string();
            }
        }
    }
    for (_, _, affected) in &mut s.vulnerabilities {
        if *affected == old {
            *affected = name.to_string();
        }
    }
}

/// A device component without a version (prEN 40000-1-3 [PRE-8-RQ-02]
/// accepts a device version or an associated firmware component).
fn unversioned_device() -> ComponentFixture {
    let mut device = comp("acme-board");
    device.component_type = "device".to_string();
    device.version = None;
    device
}

/// SPDX 2.3 has no reference category for the document a case references
/// (an OTHER reference is no type the parser knows).
const SPDX23_NO_REFERENCE_TYPE: &str = "SPDX 2.3 has no reference category for an attestation, \
     a certification report, a risk assessment, a VDR or a VEX: an OTHER reference of that \
     type is unrecognized";
/// SPDX 2.3 cannot state the vulnerability information.
const SPDX23_NO_VULNERABILITY_STATEMENT: &str = "SPDX 2.3 carries no vulnerability data and \
     names no VDR or VEX reference, so it cannot state the vulnerability information";
/// Only SPDX 3 declares profile conformance.
const SPDX3_PROFILES: &str = "only SPDX 3 documents declare profile conformance";
/// SPDX 3 states no VEX response.
const SPDX3_NO_VEX_RESPONSE: &str = "the case is about a VEX response: SPDX 3 has no response \
     field (the parser infers one from the action statement text and builds no remediation \
     record from SPDX 3, as the registry advice says)";
/// SPDX 3 justifies only a not_affected statement.
const SPDX3_JUSTIFICATION_ON_NOT_AFFECTED_ONLY: &str = "the case is about a justification on \
     another state: SPDX 3 carries a justification only on a \
     VexNotAffectedVulnAssessmentRelationship";

/// Rows whose behaviour is identical under CRA Phase 1 and Phase 2.
fn manufacturer_rows() -> Vec<RuleEntry> {
    vec![
        // ── SARIF rows ─────────────────────────────────────────────────────
        // A missing timestamp and a >90-day-old SBOM warn; 31–90 days is an
        // Info.
        RuleEntry::tested(
            "SBOM-CRA-SBOM-FRESHNESS",
            Sev::Warning,
            broken(|s| s.timestamp = None),
            base(),
        )
        .with_firing(
            "SBOM older than 90 days",
            Sev::Warning,
            broken(|s| s.timestamp = Some(days_before_clock(133))),
        )
        .with_departing_firing(
            "SBOM 31 to 90 days old",
            Sev::Info,
            broken(|s| s.timestamp = Some(days_before_clock(41))),
        ),
        // Tool policy floor: CycloneDX 1.4+ / SPDX 2.3+.
        RuleEntry::tested(
            "SBOM-CRA-MACHINE-READABLE",
            Sev::Warning,
            broken(|s| s.spec_version = "1.3".to_string()),
            base(),
        )
        .with_firing(
            "SPDX 2.2 is below the SPDX 2.3 floor",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("2.2".to_string())),
        )
        .case_only("firing", Encoding::CYCLONEDX, CYCLONEDX_VERSION_CASE)
        .case_only(
            "SPDX 2.2 is below the SPDX 2.3 floor",
            Encoding::SPDX,
            SPDX_VERSION_CASE,
        ),
        // Only manufacturer-scope references count; the sidecar fallback
        // relaxes to an Info.
        RuleEntry::tested(
            "SBOM-CRA-ART-13-17-CONTACT",
            Sev::Warning,
            broken(|s| s.primary_mut().external_refs.clear()),
            base(),
        )
        .with_departing_firing(
            "security contact provided via the CRA sidecar",
            Sev::Info,
            broken(|s| {
                s.primary_mut().external_refs.clear();
                s.sidecar_mut().security_contact = Some("psirt@acme.example".to_string());
            }),
        ),
        // Over half the components without a licence warns; fewer is an
        // Info.
        RuleEntry::tested(
            "SBOM-CRA-ART-13-5",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").licenses.clear();
                s.component_mut("libbeta").licenses.clear();
            }),
            base(),
        )
        .with_departing_firing(
            "a third of the components without a licence",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").licenses.clear()),
        ),
        // No support end date is an Info; the sidecar's supportEndDate
        // declares it too (silent). An end-of-life component reports
        // SBOM-CRA-ART-13-8-EOL (row below).
        RuleEntry::tested(
            "SBOM-CRA-ART-13-8",
            Sev::Info,
            broken(|s| s.primary_mut().support_end = None),
            broken(|s| {
                s.primary_mut().support_end = None;
                s.sidecar_mut().support_end_date = Some(as_of() + chrono::Duration::days(1800));
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-13-15-PRODUCT",
            Sev::Warning,
            broken(without_primary),
            base(),
        )
        .with_departing_firing(
            "product name provided via the CRA sidecar",
            Sev::Info,
            broken(|s| {
                without_primary(s);
                s.sidecar_mut().product_name = Some("acme-router-os".to_string());
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-VERSION",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-13-16",
            Sev::Warning,
            broken(|s| s.manufacturer = None),
            base(),
        )
        .with_departing_firing(
            "manufacturer provided via the CRA sidecar",
            Sev::Info,
            broken(|s| {
                s.manufacturer = None;
                s.sidecar_mut().manufacturer_name = Some("Acme Networks GmbH".to_string());
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-13-16-EMAIL",
            Sev::Warning,
            broken(|s| {
                s.manufacturer = Some((
                    "Acme Networks GmbH".to_string(),
                    Some("psirt-at-acme".to_string()),
                ));
            }),
            base(),
        )
        .case_differs(
            "firing",
            &[Encoding::Spdx23Json],
            Outcome::Silent,
            "SPDX 2.3 marks a creator email only by its parenthesized position, which the \
             parser reads as an email only when it holds an @: this malformed address reads \
             as part of the organization name",
        )
        .case_only(
            "firing",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_AGENT_EMAILS_NOT_READ,
        ),
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-SUPPLIER",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
        // A VDR or VEX reference states the vulnerability information
        // instead of embedded entries.
        RuleEntry::tested(
            "SBOM-CRA-VULN-STATEMENT",
            Sev::Info,
            broken(|s| s.vulnerabilities.clear()),
            base(),
        )
        .with_silent(
            "vulnerability-assertion (VDR) reference, no embedded vulnerabilities",
            broken(|s| {
                s.vulnerabilities.clear();
                with_product_ref(
                    s,
                    "vulnerability-assertion",
                    "https://acme.example/vdr.json",
                );
            }),
        )
        .with_silent(
            "exploitability-statement (VEX) reference, no embedded vulnerabilities",
            broken(|s| {
                s.vulnerabilities.clear();
                with_product_ref(
                    s,
                    "exploitability-statement",
                    "https://acme.example/vex.json",
                );
            }),
        )
        .case_differs(
            "silent",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_VULNERABILITY_STATEMENT,
        )
        .case_differs(
            "vulnerability-assertion (VDR) reference, no embedded vulnerabilities",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_VULNERABILITY_STATEMENT,
        )
        .case_differs(
            "exploitability-statement (VEX) reference, no embedded vulnerabilities",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_VULNERABILITY_STATEMENT,
        ),
        RuleEntry::tested(
            "SBOM-CRA-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
                s.vulnerabilities.clear();
            }),
            base(),
        ),
        // Without a serial number, an attestation or certification
        // reference that carries the hash of the referenced document is the
        // integrity metadata; the same reference without a hash is not.
        RuleEntry::tested(
            "SBOM-CRA-DOC-INTEGRITY",
            Sev::Info,
            broken(|s| s.serial_number = None),
            base(),
        )
        .with_firing(
            "attestation reference without a hash",
            Sev::Info,
            broken(|s| {
                s.serial_number = None;
                with_product_ref(s, "attestation", "https://acme.example/eu-doc-2026-001.pdf");
            }),
        )
        .with_silent(
            "attestation reference with a hash",
            broken(|s| {
                s.serial_number = None;
                with_hashed_product_ref(
                    s,
                    "attestation",
                    "https://acme.example/eu-doc-2026-001.pdf",
                );
            }),
        )
        .with_silent(
            "certification-report reference with a hash",
            broken(|s| {
                s.serial_number = None;
                with_hashed_product_ref(
                    s,
                    "certification-report",
                    "https://notified-body.example/certificates/eu-type-0815.pdf",
                );
            }),
        )
        .case_only(
            "attestation reference with a hash",
            Encoding::CYCLONEDX,
            SPDX_REFERENCES_CARRY_NO_HASH,
        )
        .case_only(
            "certification-report reference with a hash",
            Encoding::CYCLONEDX,
            SPDX_REFERENCES_CARRY_NO_HASH,
        ),
        // Severity scales with the product class.
        RuleEntry::tested("SBOM-CRA-CYCLES", Sev::Warning, broken(add_cycle), base())
            .with_departing_firing(
                "important class II product",
                Sev::Error,
                broken(|s| {
                    add_cycle(s);
                    pin_class(s, CraProductClass::ImportantClass2, None);
                }),
            ),
        // Only routes beyond Module A need the notified-body or
        // certification-body certificate: Warning for important class I (the
        // registry default), Error for class II and critical products. A
        // certification-report reference is that evidence; an attestation
        // reference alone is not (it may be a self-attestation).
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-VIII",
            Sev::Warning,
            broken(|s| {
                pin_class(
                    s,
                    CraProductClass::ImportantClass1,
                    Some(ConformityRoute::ModuleBC),
                );
            }),
            broken(|s| {
                pin_class(
                    s,
                    CraProductClass::ImportantClass1,
                    Some(ConformityRoute::ModuleA),
                );
            }),
        )
        .with_departing_firing(
            "important class II product (Module B+C by default)",
            Sev::Error,
            broken(|s| pin_class(s, CraProductClass::ImportantClass2, None)),
        )
        .with_silent(
            "certification-report reference for the Module B+C route",
            broken(|s| {
                pin_class(
                    s,
                    CraProductClass::ImportantClass1,
                    Some(ConformityRoute::ModuleBC),
                );
                with_product_ref(
                    s,
                    "certification-report",
                    "https://notified-body.example/certificates/eu-type-0815.pdf",
                );
            }),
        )
        .with_silent(
            "certification-report reference for an important class II product",
            broken(|s| {
                pin_class(s, CraProductClass::ImportantClass2, None);
                with_product_ref(
                    s,
                    "certification-report",
                    "https://notified-body.example/certificates/qms-approval-0815.pdf",
                );
            }),
        )
        .with_firing(
            "attestation reference only, Module B+C route",
            Sev::Warning,
            broken(|s| {
                pin_class(
                    s,
                    CraProductClass::ImportantClass1,
                    Some(ConformityRoute::ModuleBC),
                );
                with_product_ref(
                    s,
                    "attestation",
                    "https://acme.example/attestations/eu-type.pdf",
                );
            }),
        )
        .with_departing_firing(
            "attestation reference only, important class II product",
            Sev::Error,
            broken(|s| {
                pin_class(s, CraProductClass::ImportantClass2, None);
                with_product_ref(
                    s,
                    "attestation",
                    "https://acme.example/attestations/qms.pdf",
                );
            }),
        )
        .case_differs(
            "certification-report reference for the Module B+C route",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Warning),
            SPDX23_NO_REFERENCE_TYPE,
        )
        .case_differs(
            "certification-report reference for an important class II product",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Error),
            SPDX23_NO_REFERENCE_TYPE,
        ),
        // ── The generic path's checks ──────────────────────────────────────
        // Document metadata: no creator at all gates; a missing serial
        // number warns (SBOM-CRA-DOC-INTEGRITY reports it beside).
        RuleEntry::tested(
            "SBOM-CRA-CREATOR",
            Sev::Error,
            broken(|s| {
                s.tools.clear();
                s.manufacturer = None;
            }),
            base(),
        )
        .with_silent("a tool creator alone", broken(|s| s.manufacturer = None)),
        RuleEntry::tested(
            "SBOM-CRA-SERIAL",
            Sev::Warning,
            broken(|s| s.serial_number = None),
            base(),
        ),
        // "unknown" without a corroborating PURL name segment does not count
        // as a component name.
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-NAME",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        // Format notes: a CycloneDX or SPDX version newer than any this tool
        // reads warns, an outdated CycloneDX one is an Info
        // (SBOM-CRA-MACHINE-READABLE reports the 1.3 floor beside it), and an
        // SPDX version that is neither 2.x nor 3.x warns.
        RuleEntry::tested(
            "SBOM-CRA-SPEC-VERSION",
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
        RuleEntry::tested(
            "SBOM-CRA-SPEC-VERSION-UNKNOWN",
            Sev::Warning,
            broken(|s| s.spdx_version = Some("4.0".to_string())),
            base(),
        )
        .case_only("firing", Encoding::SPDX, SPDX_VERSION_CASE),
        RuleEntry::tested(
            "SBOM-CRA-ELEMENT-ID",
            Sev::Info,
            broken(|s| bom_ref_is_name(s, "libalpha")),
            base(),
        ),
        // Art. 14 channels past the 2026-09-11 deadline (the pinned clock):
        // each missing channel warns, escalated to Error for important class
        // II and critical products, and the ENISA platform finding warns at
        // every class — never an Error. art_14_findings_escalate_on_2026_09_11
        // and enisa_platform_finding_escalates_but_never_errors
        // (tests/pinned_clock_tests.rs) cover the pre-deadline Infos.
        RuleEntry::tested(
            "SBOM-CRA-ART-14-PSIRT",
            Sev::Warning,
            broken(|s| s.sidecar_mut().psirt_url = None),
            base(),
        )
        .with_departing_firing(
            "important class II product",
            Sev::Error,
            broken(|s| {
                s.sidecar_mut().psirt_url = None;
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-14-EARLY-WARNING",
            Sev::Warning,
            broken(|s| s.sidecar_mut().early_warning_contact = None),
            base(),
        )
        .with_departing_firing(
            "important class II product",
            Sev::Error,
            broken(|s| {
                s.sidecar_mut().early_warning_contact = None;
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-14-NOTIFICATION",
            Sev::Warning,
            broken(|s| s.sidecar_mut().incident_report_contact = None),
            base(),
        )
        .with_departing_firing(
            "important class II product",
            Sev::Error,
            broken(|s| {
                s.sidecar_mut().incident_report_contact = None;
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-14-ENISA",
            Sev::Warning,
            broken(|s| s.sidecar_mut().enisa_reporting_platform_id = None),
            base(),
        )
        .with_firing(
            "important class II product",
            Sev::Warning,
            broken(|s| {
                s.sidecar_mut().enisa_reporting_platform_id = None;
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        )
        .with_firing(
            "critical product",
            Sev::Warning,
            broken(|s| {
                s.sidecar_mut().enisa_reporting_platform_id = None;
                pin_class(s, CraProductClass::Critical, None);
            }),
        ),
        // prEN 40000-1-3 [PRE-8-RQ-02] hardware checks: a conforming
        // firmware component is silent.
        RuleEntry::tested(
            "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.supplier = None;
                with_firmware(s, fw);
            }),
            broken(|s| with_firmware(s, firmware())),
        ),
        RuleEntry::tested(
            "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.purl = None;
                with_firmware(s, fw);
            }),
            broken(|s| with_firmware(s, firmware())),
        ),
        RuleEntry::tested(
            "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.version = None;
                with_firmware(s, fw);
            }),
            broken(|s| with_firmware(s, firmware())),
        ),
        // A device needs a version or an associated firmware component.
        RuleEntry::tested(
            "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
            Sev::Warning,
            broken(|s| with_firmware(s, unversioned_device())),
            broken(|s| {
                let mut device = unversioned_device();
                device.version = Some("2.1.0".to_string());
                with_firmware(s, device);
            }),
        )
        .with_silent(
            "device without a version, wired to a firmware component",
            broken(|s| {
                let device = unversioned_device();
                let fw = firmware();
                s.dependencies
                    .push((device.bom_ref.clone(), vec![fw.bom_ref.clone()]));
                with_firmware(s, device);
                with_firmware(s, fw);
            }),
        ),
        // EOL enrichment: an end-of-life component warns (Error for
        // important class II and critical products); one approaching
        // end-of-life is an Info.
        RuleEntry::tested(
            "SBOM-CRA-ART-13-8-EOL",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::EndOfLife)),
            base(),
        )
        .with_departing_firing(
            "important class II product",
            Sev::Error,
            broken(|s| {
                s.component_mut("libalpha").eol = Some(EolStatus::EndOfLife);
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        )
        .with_silent(
            "component approaching end-of-life",
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::ApproachingEol)),
        ),
        RuleEntry::tested(
            "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::ApproachingEol)),
            base(),
        )
        .with_silent(
            "end-of-life component",
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::EndOfLife)),
        ),
        // SPDX 3.0 profile-conformance notes: a document that tracks
        // licences without declaring the SimpleLicensing profile, and one
        // that carries vulnerabilities without declaring the Security one.
        RuleEntry::tested(
            "SBOM-CRA-ART-13-5-PROFILE",
            Sev::Info,
            broken(|s| s.undeclared_spdx3_profiles = vec!["simpleLicensing".to_string()]),
            base(),
        )
        .case_only("firing", &[Encoding::Spdx3JsonLd], SPDX3_PROFILES),
        RuleEntry::tested(
            "SBOM-CRA-VULN-METADATA-PROFILE",
            Sev::Info,
            broken(|s| s.undeclared_spdx3_profiles = vec!["security".to_string()]),
            base(),
        )
        .case_only("firing", &[Encoding::Spdx3JsonLd], SPDX3_PROFILES),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-TRACEABILITY",
            Sev::Warning,
            broken(|s| s.primary_mut().purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-INTEGRITY",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        ),
        // No relationships at all gates; a primary outside the graph and an
        // orphan majority warn.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        )
        .with_departing_firing(
            "primary component in no relationship",
            Sev::Warning,
            broken(|s| {
                s.dependencies =
                    vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
        )
        .with_departing_firing(
            "orphan majority (3 of 5 components disconnected, primary included)",
            Sev::Warning,
            broken(|s| {
                s.dependencies =
                    vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
                s.components.push(comp("libgamma"));
                s.components.push(comp("libdelta"));
            }),
        ),
        // Several root components and no primary to tell the product apart;
        // a single root needs no primary.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
            Sev::Warning,
            broken(|s| {
                without_primary(s);
                s.components.push(comp("libgamma"));
            }),
            base(),
        )
        .with_silent("one root component and no primary", broken(without_primary)),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-PRIMARY",
            Sev::Warning,
            broken(without_primary),
            base(),
        ),
        // A control claimed satisfied without evidence; an evidenced claim
        // is silent.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-CONTROLS",
            Sev::Warning,
            broken(|s| {
                s.sidecar_mut().annex_i_part_i_controls.insert(
                    "1.a".to_string(),
                    ControlAssertion {
                        satisfied: true,
                        ..ControlAssertion::default()
                    },
                );
            }),
            broken(|s| {
                s.sidecar_mut().annex_i_part_i_controls.insert(
                    "1.a".to_string(),
                    ControlAssertion {
                        satisfied: true,
                        evidence_url: Some("https://acme.example/evidence/1a.pdf".to_string()),
                        ..ControlAssertion::default()
                    },
                );
            }),
        ),
        // Class-pinned EUCC reference: Info for important class II, Error
        // for critical; live sidecar EUCC evidence satisfies it, and an
        // expired certificate voids the identifiers beside it.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-IV",
            Sev::Info,
            broken(|s| pin_class(s, CraProductClass::ImportantClass2, None)),
            broken(|s| {
                pin_class(s, CraProductClass::ImportantClass2, None);
                s.sidecar_mut().eucc_protection_profile_id = Some("PP-CC-ROUTER-01".to_string());
            }),
        )
        .with_firing(
            "Protection Profile id beside an expired certificate",
            Sev::Info,
            broken(|s| {
                pin_class(s, CraProductClass::ImportantClass2, None);
                let sidecar = s.sidecar_mut();
                sidecar.eucc_protection_profile_id = Some("PP-CC-ROUTER-01".to_string());
                sidecar.eucc_valid_until = Some(as_of() - chrono::Duration::days(1));
            }),
        )
        .with_departing_firing(
            "critical product",
            Sev::Error,
            broken(|s| pin_class(s, CraProductClass::Critical, None)),
        )
        // The external-reference fallback: a certification or attestation
        // reference counts only when its URL names the EUCC scheme.
        .with_departing_firing(
            "critical product, certification-report reference naming no EUCC scheme",
            Sev::Error,
            broken(|s| {
                pin_class(s, CraProductClass::Critical, None);
                with_product_ref(
                    s,
                    "certification-report",
                    "https://notified-body.example/certificates/0815.pdf",
                );
            }),
        )
        .with_silent(
            "critical product, certification-report reference to an EUCC certificate",
            broken(|s| {
                pin_class(s, CraProductClass::Critical, None);
                with_product_ref(
                    s,
                    "certification-report",
                    "https://certification.enisa.europa.eu/eucc/certificates/EUCC-1234.pdf",
                );
            }),
        )
        .case_differs(
            "critical product, certification-report reference to an EUCC certificate",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Error),
            SPDX23_NO_REFERENCE_TYPE,
        ),
    ]
}

/// The conforming manufacturer fixture passes both phases with a clean
/// verdict in CycloneDX. SPDX 2.3 cannot carry its vulnerability information
/// (SBOM-CRA-VULN-STATEMENT); the SPDX 3 parser reads no end of support
/// (SBOM-CRA-ART-13-8, SBOM-CRA-LIFECYCLE) and, at Phase 2, gives its rated
/// vulnerability an unrated twin (WP 1.8c).
#[test]
fn cra_phase1_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(PHASE1, &base(), Encoding::CYCLONEDX);
}

#[test]
fn cra_phase2_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(PHASE2, &base(), Encoding::CYCLONEDX);
}

/// The steward fixture passes with a clean verdict in every encoding.
#[test]
fn cra_oss_steward_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations_in(STEWARD, &steward_base(), Encoding::ALL);
}

#[test]
fn cra_phase1_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let mut entries = manufacturer_rows();
    entries.extend([
        // A direct dependency without a supplier warns at Phase 1; a
        // transitive one is an Info under a key of its own.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_silent(
            "transitive dependency without a supplier",
            broken(|s| add_transitive_without_supplier(s, 1)),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
            Sev::Info,
            broken(|s| add_transitive_without_supplier(s, 1)),
            base(),
        )
        .with_firing(
            "transitive dependencies without a supplier above 30%",
            Sev::Info,
            broken(|s| add_transitive_without_supplier(s, 2)),
        )
        .with_silent(
            "direct dependency without a supplier",
            broken(|s| s.component_mut("libalpha").supplier = None),
        ),
        // Phase 1 gates only below 50% vendor-hash coverage: 1 of 3 warns,
        // 2 of 3 is silent.
        RuleEntry::tested(
            "SBOM-CRA-PRE-7-RQ-07-RE",
            Sev::Warning,
            broken(|s| strip_hashes(s, &["libalpha", "libbeta"])),
            broken(|s| strip_hashes(s, &["libalpha"])),
        ),
    ]);

    run_matrix(PHASE1, PHASE1_RULE_UNIVERSE, &entries);
}

/// Every CycloneDX justification but `code_not_reachable`, the one the
/// row's `justified not_affected statement` case uses, as (case label,
/// justification). The CycloneDX parser and the `--vex` reader map all nine
/// (src/parsers/cyclonedx_analysis.rs), so each exempts the unrated entry;
/// before WP 1.9, protected_by_compiler, protected_at_runtime and
/// protected_at_perimeter read as none in the parser, and code_not_present
/// as another justification in the `--vex` reader.
const OTHER_CYCLONEDX_JUSTIFICATIONS: [(&str, &str); 8] = [
    (
        "not_affected statement justified by code_not_present",
        "code_not_present",
    ),
    (
        "not_affected statement justified by requires_configuration",
        "requires_configuration",
    ),
    (
        "not_affected statement justified by requires_dependency",
        "requires_dependency",
    ),
    (
        "not_affected statement justified by requires_environment",
        "requires_environment",
    ),
    (
        "not_affected statement justified by protected_by_compiler",
        "protected_by_compiler",
    ),
    (
        "not_affected statement justified by protected_at_runtime",
        "protected_at_runtime",
    ),
    (
        "not_affected statement justified by protected_at_perimeter",
        "protected_at_perimeter",
    ),
    (
        "not_affected statement justified by protected_by_mitigating_control",
        "protected_by_mitigating_control",
    ),
];

/// The CRA Phase 2 SBOM-CRA-VULN-METADATA row.
///
/// An unrated vulnerability lacks the severity Annex I Part II (4) asks
/// for. A VEX not_affected statement that names a justification documents
/// a vulnerability that cannot be exploited, which the CRA FAQ (v1.4,
/// 4.3.1) lets the manufacturer leave unfixed; (4) covers fixed
/// vulnerabilities, so the entry needs no severity, whichever CycloneDX
/// justification it names. A bare not_affected claim, a free-text detail
/// without a justification, a justification on another state and a
/// justified statement on another vulnerability of the component are no
/// such record.
fn vuln_metadata_row() -> RuleEntry {
    let mut row = RuleEntry::tested(
        "SBOM-CRA-VULN-METADATA",
        Sev::Warning,
        broken(|s| s.vulnerabilities = vec![unrated_vulnerability()]),
        base(),
    )
    .with_firing(
        "unjustified not_affected statement",
        Sev::Warning,
        broken(|s| {
            s.vulnerabilities = vec![unrated_vulnerability()];
            with_analysis(s, UNRATED_CVE, not_affected());
        }),
    )
    .with_firing(
        "not_affected statement with a detail but no justification",
        Sev::Warning,
        broken(|s| {
            s.vulnerabilities = vec![unrated_vulnerability()];
            let mut analysis = not_affected();
            analysis.detail = Some("libalpha's XML parser is never called".to_string());
            with_analysis(s, UNRATED_CVE, analysis);
        }),
    )
    .with_firing(
        "justification on an exploitable statement",
        Sev::Warning,
        broken(|s| {
            s.vulnerabilities = vec![unrated_vulnerability()];
            let mut analysis = justified_not_affected();
            analysis.state = Some("exploitable".to_string());
            with_analysis(s, UNRATED_CVE, analysis);
        }),
    )
    .with_firing(
        "justified not_affected statement on another vulnerability of the component",
        Sev::Warning,
        broken(|s| {
            s.vulnerabilities.push(unrated_vulnerability());
            with_analysis(s, "CVE-2026-1111", justified_not_affected());
        }),
    )
    .with_silent(
        "justified not_affected statement",
        broken(|s| {
            s.vulnerabilities = vec![unrated_vulnerability()];
            with_analysis(s, UNRATED_CVE, justified_not_affected());
        }),
    );
    for (label, justification) in OTHER_CYCLONEDX_JUSTIFICATIONS {
        row = row.with_silent(
            label,
            broken(move |s| not_affected_justified_by(s, justification)),
        );
    }
    row.only(Encoding::ALL_BUT_SPDX23, SPDX23_HAS_NO_VULNERABILITIES)
        .case_only(
            "justification on an exploitable statement",
            Encoding::CYCLONEDX,
            SPDX3_JUSTIFICATION_ON_NOT_AFFECTED_ONLY,
        )
}

#[test]
fn cra_phase2_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let mut entries = manufacturer_rows();
    entries.extend([
        vuln_metadata_row(),
        // A declared remediation (analysis.response update or
        // workaround_available) with no recommendation or workaround text
        // gives users nothing to apply: an Info. CycloneDX has no
        // fixed-version field, so the text is the only detail.
        RuleEntry::tested(
            "SBOM-CRA-VULN-METADATA-REMEDIATION",
            Sev::Info,
            broken(|s| with_response(s, "update", None)),
            base(),
        )
        .with_firing(
            "workaround_available response without a workaround text",
            Sev::Info,
            broken(|s| with_response(s, "workaround_available", None)),
        )
        .with_silent(
            "update response with a recommendation",
            broken(|s| {
                with_response(
                    s,
                    "update",
                    Some(("recommendation", "Upgrade libalpha to 1.2.4")),
                );
            }),
        )
        .with_silent(
            "workaround_available response with a workaround text",
            broken(|s| {
                with_response(
                    s,
                    "workaround_available",
                    Some(("workaround", "Disable the libalpha XML parser")),
                );
            }),
        )
        .with_silent(
            "will_not_fix response declares no remediation",
            broken(|s| with_response(s, "will_not_fix", None)),
        )
        // A justified not_affected statement exempts the entry (see the
        // SBOM-CRA-VULN-METADATA row); a bare one does not.
        .with_firing(
            "update response on an unjustified not_affected statement",
            Sev::Info,
            broken(|s| {
                let mut analysis = not_affected();
                analysis.responses = vec!["update".to_string()];
                with_analysis(s, "CVE-2026-1111", analysis);
            }),
        )
        .with_silent(
            "update response on a justified not_affected statement",
            broken(|s| {
                let mut analysis = justified_not_affected();
                analysis.responses = vec!["update".to_string()];
                with_analysis(s, "CVE-2026-1111", analysis);
            }),
        )
        .only(Encoding::ALL_BUT_SPDX23, SPDX23_HAS_NO_VULNERABILITIES)
        .case_only("firing", Encoding::CYCLONEDX, SPDX3_NO_VEX_RESPONSE)
        .case_only(
            "workaround_available response without a workaround text",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        )
        .case_only(
            "update response with a recommendation",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        )
        .case_only(
            "workaround_available response with a workaround text",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        )
        .case_only(
            "will_not_fix response declares no remediation",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        )
        .case_only(
            "update response on an unjustified not_affected statement",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        )
        .case_only(
            "update response on a justified not_affected statement",
            Encoding::CYCLONEDX,
            SPDX3_NO_VEX_RESPONSE,
        ),
        // Phase 2 also asks for lifecycle evidence. An approaching-EOL
        // component reports SBOM-CRA-LIFECYCLE-APPROACHING-EOL (its row is in
        // manufacturer_rows).
        RuleEntry::tested(
            "SBOM-CRA-LIFECYCLE",
            Sev::Info,
            broken(|s| s.primary_mut().support_end = None),
            base(),
        )
        .case_only(
            "silent",
            Encoding::ALL_BUT_SPDX3,
            SPDX3_VALID_UNTIL_NOT_READ,
        ),
        // Phase 2 makes direct-dependency suppliers mandatory (Error); over
        // 30% transitive gaps warn, fewer are an Info.
        RuleEntry::skipped(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            "at Phase 2 a direct dependency without a supplier is always an Error \
             ([PRE-7-RQ-03] makes direct-dependency suppliers mandatory), never the \
             registry default Warning that Phase 1 emits, so no Phase 2 case can meet \
             run_matrix's rule that a tested row fires at the registry default; \
             cra_phase2_direct_dependency_supplier_gap_is_an_error below pins the Error \
             and its silent cases",
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
            Sev::Info,
            broken(|s| add_transitive_without_supplier(s, 1)),
            base(),
        )
        .with_departing_firing(
            "transitive dependencies without a supplier above 30%",
            Sev::Warning,
            broken(|s| add_transitive_without_supplier(s, 2)),
        )
        .with_silent(
            "direct dependency without a supplier",
            broken(|s| s.component_mut("libalpha").supplier = None),
        ),
        // Phase 2: below 50% vendor-hash coverage gates, below 80% warns.
        RuleEntry::tested_departing(
            "SBOM-CRA-PRE-7-RQ-07-RE",
            Sev::Error,
            broken(|s| strip_hashes(s, &["libalpha", "libbeta"])),
            base(),
        )
        .with_firing(
            "vendor hash coverage between 50% and 80%",
            Sev::Warning,
            broken(|s| strip_hashes(s, &["libalpha"])),
        ),
        RuleEntry::tested(
            "SBOM-CRA-CVD-POLICY",
            Sev::Warning,
            broken(|s| {
                s.primary_mut()
                    .external_refs
                    .retain(|(t, _)| t != "advisories");
            }),
            base(),
        )
        .with_departing_firing(
            "CVD policy URL provided via the CRA sidecar",
            Sev::Info,
            broken(|s| {
                s.primary_mut()
                    .external_refs
                    .retain(|(t, _)| t != "advisories");
                s.sidecar_mut().vulnerability_disclosure_url =
                    Some("https://acme.example/security/cvd".to_string());
            }),
        ),
        // Severity scales with the product class.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-V",
            Sev::Info,
            broken(|s| s.sidecar_mut().ce_marking_reference = None),
            base(),
        )
        .with_departing_firing(
            "important class I product",
            Sev::Warning,
            broken(|s| {
                s.sidecar_mut().ce_marking_reference = None;
                pin_class(s, CraProductClass::ImportantClass1, None);
            }),
        )
        .with_departing_firing(
            "critical product",
            Sev::Error,
            broken(|s| {
                s.sidecar_mut().ce_marking_reference = None;
                pin_class(s, CraProductClass::Critical, None);
            }),
        )
        .with_silent(
            "attestation reference as the EU DoC reference",
            broken(|s| {
                s.sidecar_mut().ce_marking_reference = None;
                with_product_ref(s, "attestation", "https://acme.example/eu-doc-2026-001.pdf");
            }),
        )
        .with_silent(
            "certification-report reference, critical product",
            broken(|s| {
                s.sidecar_mut().ce_marking_reference = None;
                pin_class(s, CraProductClass::Critical, None);
                with_product_ref(
                    s,
                    "certification-report",
                    "https://certification.enisa.europa.eu/eucc/certificates/EUCC-1234.pdf",
                );
            }),
        )
        .case_differs(
            "attestation reference as the EU DoC reference",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Info),
            SPDX23_NO_REFERENCE_TYPE,
        )
        .case_differs(
            "certification-report reference, critical product",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Error),
            SPDX23_NO_REFERENCE_TYPE,
        ),
        RuleEntry::tested(
            "SBOM-CRA-ART-13-2",
            Sev::Warning,
            broken(|s| s.sidecar_mut().risk_assessment_url = None),
            base(),
        )
        .with_silent(
            "risk-assessment reference instead of the sidecar key",
            broken(|s| {
                s.sidecar_mut().risk_assessment_url = None;
                with_product_ref(
                    s,
                    "risk-assessment",
                    "https://acme.example/docs/risk-assessment.pdf",
                );
            }),
        )
        .case_differs(
            "risk-assessment reference instead of the sidecar key",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Warning),
            SPDX23_NO_REFERENCE_TYPE,
        ),
    ]);

    run_matrix(PHASE2, PHASE2_RULE_UNIVERSE, &entries);
}

#[test]
fn cra_oss_steward_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── SARIF rows ─────────────────────────────────────────────────────
        RuleEntry::tested(
            "SBOM-CRA-INVENTORY",
            Sev::Error,
            steward_broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
                s.vulnerabilities.clear();
            }),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-VERSION",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").version = None),
            steward_base(),
        ),
        // Stewards are exempt from Art. 13(16), so the supplier rule cites
        // Art. 24.
        RuleEntry::tested(
            "SBOM-CRA-ART-24-SUPPLIER",
            Sev::Warning,
            steward_broken(|s| s.component_mut("libalpha").supplier = None),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-CYCLES",
            Sev::Warning,
            steward_broken(add_cycle),
            steward_base(),
        ),
        // Silent: the steward-specific sidecar field.
        RuleEntry::tested(
            "SBOM-CRA-CVD-POLICY",
            Sev::Warning,
            steward_broken(|s| {
                s.primary_mut()
                    .external_refs
                    .retain(|(t, _)| t != "advisories");
            }),
            steward_broken(|s| {
                s.primary_mut()
                    .external_refs
                    .retain(|(t, _)| t != "advisories");
                s.sidecar = Some(CraSidecarMetadata {
                    coordinated_disclosure_policy_url: Some(
                        "https://acme.example/security/cvd-policy".to_string(),
                    ),
                    ..CraSidecarMetadata::default()
                });
            }),
        ),
        // ── The steward floors and the generic path's checks ───────────────
        // The vulnerability-handling floor is an Error.
        RuleEntry::tested(
            "SBOM-CRA-ART-24",
            Sev::Error,
            steward_broken(|s| s.primary_mut().external_refs.clear()),
            steward_base(),
        )
        .with_silent(
            "vulnerability-assertion (VDR) reference as the handling process",
            steward_broken(|s| {
                s.primary_mut().external_refs = vec![(
                    "vulnerability-assertion".to_string(),
                    "https://acme.example/vdr.json".to_string(),
                )];
            }),
        )
        .case_differs(
            "vulnerability-assertion (VDR) reference as the handling process",
            &[Encoding::Spdx23Json],
            Outcome::Fires(Sev::Error),
            SPDX23_NO_REFERENCE_TYPE,
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-IDENTIFIER",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").purl = None),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-INTEGRITY",
            Sev::Info,
            steward_broken(|s| s.component_mut("libalpha").hashes.clear()),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-DEPENDENCY",
            Sev::Error,
            steward_broken(|s| s.dependencies.clear()),
            steward_base(),
        )
        .with_departing_firing(
            "primary component in no relationship",
            Sev::Warning,
            steward_broken(|s| {
                s.dependencies =
                    vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
            Sev::Warning,
            steward_broken(|s| {
                without_primary(s);
                s.components.push(comp("libgamma"));
            }),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-NAME",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-SPEC-VERSION",
            Sev::Warning,
            steward_broken(|s| s.spec_version = "1.8".to_string()),
            steward_base(),
        )
        .with_departing_firing(
            "CycloneDX 1.3 is outdated",
            Sev::Info,
            steward_broken(|s| s.spec_version = "1.3".to_string()),
        )
        .with_firing(
            "SPDX 3.1 is newer than any version read",
            Sev::Warning,
            steward_broken(|s| s.spdx_version = Some("3.1".to_string())),
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
        RuleEntry::tested(
            "SBOM-CRA-SPEC-VERSION-UNKNOWN",
            Sev::Warning,
            steward_broken(|s| s.spdx_version = Some("4.0".to_string())),
            steward_base(),
        )
        .case_only("firing", Encoding::SPDX, SPDX_VERSION_CASE),
        RuleEntry::tested(
            "SBOM-CRA-ELEMENT-ID",
            Sev::Info,
            steward_broken(|s| bom_ref_is_name(s, "libalpha")),
            steward_base(),
        ),
    ];

    run_matrix(STEWARD, STEWARD_RULE_UNIVERSE, &entries);
}

/// Pinned scope decision: the Art. 24 steward profile runs no
/// document-metadata check, so a steward SBOM without a creator, a timestamp
/// or a serial number draws exactly the findings of the complete one. Art.
/// 24 obliges a steward to a cybersecurity policy and to vulnerability
/// handling, not to the manufacturer's Art. 13 documentation, and
/// check_cra_oss_steward runs only the component, dependency and format
/// checks plus the two steward floors. The manufacturer phases report the
/// same gaps, each under its own rule (no creator: an SBOM-CRA-CREATOR
/// Error; no serial number: SBOM-CRA-SERIAL; no timestamp:
/// SBOM-CRA-SBOM-FRESHNESS).
#[test]
fn steward_profile_runs_no_document_metadata_check() {
    let bare = steward_broken(|s| {
        s.tools.clear();
        s.authors.clear();
        s.manufacturer = None;
        s.timestamp = None;
        s.serial_number = None;
    });
    let findings = |fixture: &SbomFixture| -> Vec<(String, Sev)> {
        let mut found: Vec<(String, Sev)> = check(STEWARD, fixture)
            .violations
            .iter()
            .map(|v| (v.rule_id.to_string(), v.severity))
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    };
    assert_eq!(
        findings(&bare),
        findings(&steward_base()),
        "no creator, timestamp or serial number must change the steward verdict:\n{}",
        render_violations(&check(STEWARD, &bare))
    );
    let phase2 = check(PHASE2, &bare);
    for rule in [
        "SBOM-CRA-SBOM-FRESHNESS",
        "SBOM-CRA-CREATOR",
        "SBOM-CRA-SERIAL",
    ] {
        assert!(
            phase2.violations.iter().any(|v| v.rule_id == rule),
            "the manufacturer phase reports {rule} for the same document:\n{}",
            render_violations(&phase2)
        );
    }
}

/// The CRA universes cover the CRA rule family: together they hold every
/// `SBOM-CRA-*` rule but the fallback rule, which no check emits, and each
/// universe holds only CRA rules.
#[test]
fn cra_universes_cover_the_cra_family() {
    let family: BTreeSet<&str> = all_rule_ids()
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-CRA-") && *id != generic_rule_id_for_level(PHASE2))
        .collect();
    let universes: BTreeSet<&str> = PHASE1_RULE_UNIVERSE
        .iter()
        .chain(PHASE2_RULE_UNIVERSE)
        .chain(STEWARD_RULE_UNIVERSE)
        .copied()
        .collect();
    assert_eq!(
        universes, family,
        "the CRA universes must hold exactly the SBOM-CRA-* rules but the fallback"
    );
}

/// Two CRA notes read only SPDX 3.0 input: a document that carries
/// vulnerabilities without declaring the Security profile
/// (SBOM-CRA-VULN-METADATA-PROFILE, at Phase 1 the only
/// SBOM-CRA-VULN-METADATA site) and one that tracks licences without
/// declaring the SimpleLicensing profile (SBOM-CRA-ART-13-5-PROFILE). Both
/// manufacturer phases run them; their matrix rows cover the DSL rendering,
/// and this pins the corpus fixture. The fixture carries vulnerabilities and
/// a declared licence and declares both profiles (silent); dropping one
/// profile fires its note, and only that one, as an Info.
#[test]
fn cra_spdx3_profile_notes_fire_without_their_profile() {
    const SECURITY: &str = "SBOM-CRA-VULN-METADATA-PROFILE";
    const LICENSING: &str = "SBOM-CRA-ART-13-5-PROFILE";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/spdx3/security-profile.spdx3.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("SPDX 3.0 fixture {path} must exist: {e}"));
    let run = |level: ComplianceLevel, profiles: &[&str]| {
        let mut doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
        doc["profileConformance"] = serde_json::json!(profiles);
        let sbom = parse_sbom_str(&doc.to_string()).expect("fixture parses as SPDX 3.0");
        checker(level).check(&sbom)
    };
    let fired = |result: &sbom_tools::quality::ComplianceResult, key: &str| -> Vec<Sev> {
        result
            .violations
            .iter()
            .filter(|v| v.rule_id == key)
            .map(|v| v.severity)
            .collect()
    };

    for level in [PHASE1, PHASE2] {
        let declared = run(level, &["core", "software", "security", "simpleLicensing"]);
        for key in [SECURITY, LICENSING] {
            assert!(
                fired(&declared, key).is_empty(),
                "[{level:?}] both profiles declared must keep {key} silent:\n{}",
                render_violations(&declared)
            );
        }
        for (profiles, key, other) in [
            (["core", "software", "simpleLicensing"], SECURITY, LICENSING),
            (["core", "software", "security"], LICENSING, SECURITY),
        ] {
            let result = run(level, &profiles);
            assert_eq!(
                fired(&result, key),
                vec![Sev::Info],
                "[{level:?}] profiles {profiles:?} must fire {key} once as an Info:\n{}",
                render_violations(&result)
            );
            assert!(
                fired(&result, other).is_empty(),
                "[{level:?}] profiles {profiles:?} must keep {other} silent:\n{}",
                render_violations(&result)
            );
        }
    }
}

/// At Phase 2 a direct dependency without a supplier is always an Error,
/// so the matrix row of SBOM-CRA-ANNEX-I-SUPPLY-CHAIN cannot fire at the
/// registry default (the Phase 1 Warning) and is skipped there; this pins
/// the Phase 2 Error. A supplier on every component, and a supplier-less
/// transitive dependency (SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE), keep
/// it silent.
#[test]
fn cra_phase2_direct_dependency_supplier_gap_is_an_error() {
    const KEY: &str = "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN";
    let fired = |fixture: &SbomFixture| -> Vec<Sev> {
        check(PHASE2, fixture)
            .violations
            .iter()
            .filter(|v| v.rule_id == KEY)
            .map(|v| v.severity)
            .collect()
    };
    let direct = broken(|s| s.component_mut("libalpha").supplier = None);
    assert_eq!(
        fired(&direct),
        vec![Sev::Error],
        "a direct dependency without a supplier must fire {KEY} once as an Error:\n{}",
        render_violations(&check(PHASE2, &direct))
    );
    for (label, fixture) in [
        ("every component has a supplier", base()),
        (
            "transitive dependency without a supplier",
            broken(|s| add_transitive_without_supplier(s, 1)),
        ),
    ] {
        assert!(
            fired(&fixture).is_empty(),
            "{label}: {KEY} must stay silent:\n{}",
            render_violations(&check(PHASE2, &fixture))
        );
    }
}

/// SBOM-CRA-PRE-8-RQ-02-IDENTIFIER reads a hardware component's own
/// identifiers, as SBOM-CRA-ANNEX-I-IDENTIFIER does, not the source of its
/// canonical id. Two firmware components that share a purl but differ in
/// name collide on their canonical id, and the parser re-keys the second
/// with its bom-ref: a format-specific canonical id on a component that
/// still has its purl. Neither component is missing an identifier, at Phase
/// 1 or Phase 2.
#[test]
fn cra_hardware_identifier_reads_the_purl_of_a_re_keyed_component() {
    use sbom_tools::model::IdSource;
    const PURL: &str = "pkg:npm/acme-fw@1.2.3";
    let fixture = broken(|s| {
        let mut recovery = firmware();
        recovery.name = "acme-fw-recovery".to_string();
        recovery.bom_ref = "ref-acme-fw-recovery".to_string();
        with_firmware(s, firmware());
        with_firmware(s, recovery);
    });

    let sbom = fixture.parse();
    let components: Vec<_> = sbom
        .components
        .values()
        .filter(|c| c.name.starts_with("acme-fw"))
        .collect();
    let sources: Vec<(&str, &IdSource)> = components
        .iter()
        .map(|c| (c.name.as_str(), c.canonical_id.source()))
        .collect();
    assert_eq!(
        sources,
        [
            ("acme-fw", &IdSource::Purl),
            ("acme-fw-recovery", &IdSource::FormatSpecific)
        ],
        "the second firmware component must be re-keyed on the collision"
    );
    for comp in &components {
        assert_eq!(
            comp.identifiers.purl.as_deref(),
            Some(PURL),
            "{}",
            comp.name
        );
    }

    for level in [PHASE1, PHASE2] {
        let result = check(level, &fixture);
        let fired: Vec<(&str, Option<&str>)> = result
            .violations
            .iter()
            .filter(|v| {
                matches!(
                    v.rule_id,
                    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER" | "SBOM-CRA-ANNEX-I-IDENTIFIER"
                )
            })
            .map(|v| (v.rule_id, v.component_id.as_deref()))
            .collect();
        assert!(
            fired.is_empty(),
            "[{level:?}] both firmware components have a purl, yet {fired:?} fired:\n{}",
            render_violations(&result)
        );
    }
}

/// SBOM-CRA-PRE-7-RQ-07-RE counts a vendor component by its own
/// identifiers, as the CRA identifier checks do, not by the source of its
/// canonical id. Two vendor libraries that share a purl but differ in name
/// collide on their canonical id, and the parser re-keys the second. Both
/// are vendor components without a hash, so three of the five vendor
/// components carry one: the product, libalpha and libbeta.
#[test]
fn cra_vendor_hash_coverage_counts_a_re_keyed_component() {
    use sbom_tools::model::IdSource;
    use sbom_tools::quality::HashQualityMetrics;
    let fixture = broken(|s| {
        for name in ["libgamma", "libgamma-fork"] {
            let mut lib = comp(name);
            lib.purl = Some("pkg:npm/libgamma@1.2.3".to_string());
            lib.hashes.clear();
            s.dependencies[0].1.push(lib.bom_ref.clone());
            s.components.push(lib);
        }
    });

    let sbom = fixture.parse();
    let sources: Vec<(&str, &IdSource)> = sbom
        .components
        .values()
        .filter(|c| c.name.starts_with("libgamma"))
        .map(|c| (c.name.as_str(), c.canonical_id.source()))
        .collect();
    assert_eq!(
        sources,
        [
            ("libgamma", &IdSource::Purl),
            ("libgamma-fork", &IdSource::FormatSpecific)
        ],
        "the second library must be re-keyed on the collision"
    );
    let metrics = HashQualityMetrics::from_sbom(&sbom);
    assert_eq!(
        (
            metrics.vendor_components_with_hash,
            metrics.vendor_components_total
        ),
        (3, 5),
        "both libgamma components are vendor components"
    );

    let result = check(PHASE2, &fixture);
    let fired: Vec<(Sev, usize, usize)> = result
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-CRA-PRE-7-RQ-07-RE")
        .map(|v| {
            let counts = v.counts.expect("a coverage finding carries counts");
            (v.severity, counts.affected, counts.total)
        })
        .collect();
    assert_eq!(
        fired,
        [(Sev::Warning, 3, 5)],
        "3/5 vendor components carry a hash, below the 80% Phase 2 threshold:\n{}",
        render_violations(&result)
    );
}

/// SBOM-CRA-SPEC-VERSION-UNKNOWN reads only SPDX input (a version that is
/// neither 2.x nor 3.x): its matrix rows fire it in SPDX 2.3 JSON and SPDX
/// 3; this pins SPDX tag-value at every CRA level.
#[test]
fn cra_spec_version_unknown_reads_only_spdx() {
    for level in [PHASE1, PHASE2, STEWARD] {
        assert_spdx_version_unknown(level, "SBOM-CRA-SPEC-VERSION-UNKNOWN");
    }
}
