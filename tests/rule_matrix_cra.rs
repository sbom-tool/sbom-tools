//! Registry-driven per-rule matrices for the EU CRA family:
//! `ComplianceLevel::CraPhase1`, `CraPhase2` and `CraOssSteward`. None of the
//! three had a per-rule matrix (the Error-level hardware rule
//! SBOM-CRA-PRE-8-RQ-02 was never asserted).
//!
//! The CRA profiles have no dedicated SARIF slice: they share the CRA-family
//! `COMPLIANCE_SARIF_RULE_IDS` catalogue with BSI, EUCC and the AI profiles,
//! and emit three CRA ids the slice does not enumerate (`SBOM-CRA-CYCLES`,
//! `SBOM-CRA-ANNEX-VIII`, `SBOM-CRA-ART-24-SUPPLIER`). Each universe below
//! is therefore declared locally, from the check sites in generic.rs and
//! cra.rs; `cra_universes_cover_the_cra_slice` ties them back to the slice.
//! Most CRA findings share the `SBOM-CRA-ANNEX-I` and `SBOM-CRA-GENERAL`
//! SARIF rules through alias keys, so each alias key also gets a per-key
//! row.
//!
//! The manufacturer fixtures carry a CRA sidecar with the Art. 14 reporting
//! channels (the only place they can be declared); the pinned clock is past
//! the 2026-09-11 Art. 14 deadline.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::{as_of, checker};
use rule_matrix::{
    ComponentFixture, RuleEntry, SHA256_FILLER, SbomFixture, assert_no_violations, check,
    render_violations, run_matrix,
};
use sbom_tools::model::{
    ConformityRoute, ControlAssertion, CraProductClass, CraSidecarMetadata, EolStatus,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel, ViolationSeverity as Sev};
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
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-GENERAL",
    "SBOM-CRA-PRE-8-RQ-02",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-VIII",
];

/// Phase 2 adds the full-application checks: CVD policy (Annex I Part II
/// (5)) and the EU Declaration of Conformity reference (Annex V).
const PHASE2_RULE_UNIVERSE: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-GENERAL",
    "SBOM-CRA-PRE-8-RQ-02",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-VIII",
];

/// Every rule id the Art. 24 steward profile can emit (check_cra_oss_steward
/// runs the component, dependency and format checks plus the two steward
/// floors — no document-metadata, gap, Art. 14 or hardware checks).
const STEWARD_RULE_UNIVERSE: &[&str] = &[
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-GENERAL",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ANNEX-I",
    "SBOM-CRA-ART-24-SUPPLIER",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-CVD-POLICY",
];

/// The CRA ids the shared slice does not enumerate (documented as
/// slice-less in tests/rule_matrix_registry.rs).
const SLICELESS_CRA_IDS: &[&str] = &[
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-ART-24-SUPPLIER",
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
    p.properties = vec![("endOfSupport".to_string(), "2031-12-31".to_string())];
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
    let mut extra = serde_json::json!({
        "analysis": { "state": "exploitable", "response": [response] },
    });
    if let Some((member, value)) = text {
        extra[member] = serde_json::json!(value);
    }
    s.vulnerability_extras
        .push(("CVE-2026-1111".to_string(), extra));
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

/// Rows whose behaviour is identical under CRA Phase 1 and Phase 2.
fn manufacturer_rows() -> Vec<RuleEntry> {
    vec![
        // ── SARIF rows ────────────────────────────────────────────────────
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
        // Tool policy floor: CycloneDX 1.4+.
        RuleEntry::tested(
            "SBOM-CRA-MACHINE-READABLE",
            Sev::Warning,
            broken(|s| s.spec_version = "1.3".to_string()),
            base(),
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
        // declares it too (silent). An end-of-life component (EOL
        // enrichment) warns at the same rule id.
        RuleEntry::tested(
            "SBOM-CRA-ART-13-8",
            Sev::Info,
            broken(|s| s.primary_mut().properties.clear()),
            broken(|s| {
                s.primary_mut().properties.clear();
                s.sidecar_mut().support_end_date = Some(as_of() + chrono::Duration::days(1800));
            }),
        )
        .with_departing_firing(
            "end-of-life component (EOL enrichment)",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::EndOfLife)),
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
        ),
        // The Annex I bucket, by severity: traceability (Warning), a missing
        // identifier (Error), a missing hash (Info). Each site has its own
        // per-key row below.
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I",
            Sev::Warning,
            broken(|s| s.primary_mut().purl = None),
            base(),
        )
        .with_departing_firing(
            "component without a unique identifier",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
        )
        .with_departing_firing(
            "component without a hash",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
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
        ),
        // The CRA generic bucket: serial number (Warning), no creator at all
        // (Error), a placeholder component name (Error), and the format notes
        // (Info). The Art. 14 / Annex IV / Art. 13(2) sites share it through
        // per-key rows below.
        RuleEntry::tested(
            "SBOM-CRA-GENERAL",
            Sev::Warning,
            broken(|s| s.serial_number = None),
            base(),
        )
        .with_departing_firing(
            "no creator at all",
            Sev::Error,
            broken(|s| {
                s.tools.clear();
                s.manufacturer = None;
            }),
        )
        .with_departing_firing(
            "placeholder component name",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
        )
        .with_departing_firing(
            "CycloneDX 1.3 is outdated",
            Sev::Info,
            broken(|s| s.spec_version = "1.3".to_string()),
        ),
        // prEN 40000-1-3 [PRE-8-RQ-02] hardware: a conforming firmware
        // component is silent.
        RuleEntry::tested(
            "SBOM-CRA-PRE-8-RQ-02",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.version = None;
                with_firmware(s, fw);
            }),
            broken(|s| with_firmware(s, firmware())),
        )
        .with_firing(
            "hardware component without a producer",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.supplier = None;
                with_firmware(s, fw);
            }),
        )
        .with_firing(
            "hardware component without a unique identifier",
            Sev::Error,
            broken(|s| {
                let mut fw = firmware();
                fw.purl = None;
                with_firmware(s, fw);
            }),
        )
        .with_departing_firing(
            "device with no version and no firmware",
            Sev::Warning,
            broken(|s| {
                let mut device = comp("acme-board");
                device.component_type = "device".to_string();
                device.version = None;
                with_firmware(s, device);
            }),
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
        ),
        // ── Per-key rows ─────────────────────────────────────────────────
        // Art. 14 channels past the 2026-09-11 deadline: missing channels
        // warn (Error for important class II+); the ENISA platform id stays
        // an Info (the registry default documents the pre-deadline Info).
        RuleEntry::key_tested(
            "SBOM-CRA-ART-14",
            Sev::Info,
            broken(|s| s.sidecar_mut().enisa_reporting_platform_id = None),
            base(),
        )
        .with_departing_firing(
            "PSIRT URL missing",
            Sev::Warning,
            broken(|s| s.sidecar_mut().psirt_url = None),
        )
        .with_departing_firing(
            "24-hour early-warning channel missing",
            Sev::Warning,
            broken(|s| s.sidecar_mut().early_warning_contact = None),
        )
        .with_departing_firing(
            "72-hour notification channel missing",
            Sev::Warning,
            broken(|s| s.sidecar_mut().incident_report_contact = None),
        )
        .with_departing_firing(
            "important class II product",
            Sev::Error,
            broken(|s| {
                s.sidecar_mut().psirt_url = None;
                pin_class(s, CraProductClass::ImportantClass2, None);
            }),
        ),
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-TRACEABILITY",
            Sev::Warning,
            broken(|s| s.primary_mut().purl = None),
            base(),
        ),
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-INTEGRITY",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        ),
        // No relationships at all gates; a primary outside the graph, several
        // roots without a primary, and an orphan majority warn.
        RuleEntry::key_tested(
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
            "several root components and no primary",
            Sev::Warning,
            broken(|s| {
                without_primary(s);
                s.components.push(comp("libgamma"));
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
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-PRIMARY",
            Sev::Warning,
            broken(without_primary),
            base(),
        ),
        // A control claimed satisfied without evidence; an evidenced claim
        // is silent.
        RuleEntry::key_tested(
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
        RuleEntry::key_tested(
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
        ),
    ]
}

/// The conforming manufacturer fixture passes both phases with a clean
/// verdict.
#[test]
fn cra_phase1_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(PHASE1, &base());
}

#[test]
fn cra_phase2_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(PHASE2, &base());
}

#[test]
fn cra_oss_steward_conforming_fixture_is_compliant_with_zero_violations() {
    assert_no_violations(STEWARD, &steward_base());
}

#[test]
fn cra_phase1_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let mut entries = manufacturer_rows();
    entries.extend([
        RuleEntry::skipped(
            "SBOM-CRA-VULN-METADATA",
            "at Phase 1 the only site is the SPDX 3.0 Security-profile \
             conformance note in check_cra_gaps, which the CycloneDX-only DSL \
             cannot reach; covered by the raw SPDX 3.0 test \
             cra_phase1_vuln_metadata_is_the_spdx3_security_profile_note below",
        ),
        // At Phase 1 only the approaching-EOL site (EOL enrichment) exists.
        RuleEntry::tested(
            "SBOM-CRA-LIFECYCLE",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::ApproachingEol)),
            base(),
        ),
        // A direct dependency without a supplier warns at Phase 1; a
        // transitive one is an Info.
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            Sev::Warning,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_departing_firing(
            "transitive dependency without a supplier",
            Sev::Info,
            broken(|s| add_transitive_without_supplier(s, 1)),
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

#[test]
fn cra_phase2_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let mut entries = manufacturer_rows();
    entries.extend([
        // An unrated vulnerability lacks the severity Annex I Part II (4)
        // asks for. A declared remediation (analysis.response update or
        // workaround_available) with no recommendation or workaround text
        // gives users nothing to apply: an Info. CycloneDX has no
        // fixed-version field, so the text is the only detail.
        RuleEntry::tested(
            "SBOM-CRA-VULN-METADATA",
            Sev::Warning,
            broken(|s| {
                s.vulnerabilities = vec![(
                    "CVE-2026-2222".to_string(),
                    String::new(), // unrated
                    "ref-libalpha".to_string(),
                )];
            }),
            base(),
        )
        .with_departing_firing(
            "update response without a recommendation",
            Sev::Info,
            broken(|s| with_response(s, "update", None)),
        )
        .with_departing_firing(
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
        ),
        // Phase 2 also asks for lifecycle evidence; an approaching-EOL
        // component (EOL enrichment) is an Info at the same rule id.
        RuleEntry::tested(
            "SBOM-CRA-LIFECYCLE",
            Sev::Info,
            broken(|s| s.primary_mut().properties.clear()),
            base(),
        )
        .with_firing(
            "component approaching end-of-life (EOL enrichment)",
            Sev::Info,
            broken(|s| s.component_mut("libalpha").eol = Some(EolStatus::ApproachingEol)),
        ),
        // Phase 2 makes direct-dependency suppliers mandatory (Error); over
        // 30% transitive gaps warn, fewer are an Info.
        RuleEntry::key_tested_departing(
            "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        )
        .with_firing(
            "transitive dependencies without a supplier above 30%",
            Sev::Warning,
            broken(|s| add_transitive_without_supplier(s, 2)),
        )
        .with_departing_firing(
            "transitive dependency without a supplier at or below 30%",
            Sev::Info,
            broken(|s| add_transitive_without_supplier(s, 1)),
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
        ),
        RuleEntry::key_tested(
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
        ),
    ]);

    run_matrix(PHASE2, PHASE2_RULE_UNIVERSE, &entries);
}

#[test]
fn cra_oss_steward_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── SARIF rows ────────────────────────────────────────────────────
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
        // The steward profile runs no document-metadata check, so the
        // generic bucket carries only the component-name and format sites
        // (plus the Art. 24 per-key row below).
        RuleEntry::tested(
            "SBOM-CRA-GENERAL",
            Sev::Warning,
            steward_broken(|s| s.spec_version = "1.8".to_string()),
            steward_base(),
        )
        .with_departing_firing(
            "placeholder component name",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
        )
        .with_departing_firing(
            "CycloneDX 1.3 is outdated",
            Sev::Info,
            steward_broken(|s| s.spec_version = "1.3".to_string()),
        ),
        RuleEntry::tested(
            "SBOM-CRA-COMPONENT-VERSION",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").version = None),
            steward_base(),
        ),
        RuleEntry::tested(
            "SBOM-CRA-ANNEX-I",
            Sev::Warning,
            steward_broken(|s| {
                s.dependencies =
                    vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])];
            }),
            steward_base(),
        )
        .with_departing_firing(
            "component without a unique identifier",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").purl = None),
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
        // ── Per-key rows ─────────────────────────────────────────────────
        // The vulnerability-handling floor is an Error.
        RuleEntry::key_tested(
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
        ),
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-IDENTIFIER",
            Sev::Error,
            steward_broken(|s| s.component_mut("libalpha").purl = None),
            steward_base(),
        ),
        RuleEntry::key_tested(
            "SBOM-CRA-ANNEX-I-INTEGRITY",
            Sev::Info,
            steward_broken(|s| s.component_mut("libalpha").hashes.clear()),
            steward_base(),
        ),
        RuleEntry::key_tested(
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
/// same gaps (no creator: an SBOM-CRA-GENERAL Error; no timestamp:
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
    for rule in ["SBOM-CRA-SBOM-FRESHNESS", "SBOM-CRA-GENERAL"] {
        assert!(
            phase2.violations.iter().any(|v| v.rule_id == rule),
            "the manufacturer phase reports {rule} for the same document:\n{}",
            render_violations(&phase2)
        );
    }
}

/// The CRA universes are tied back to the shared slice: together they cover
/// every `SBOM-CRA-*` id the slice enumerates, and the only ids they add are
/// the documented slice-less ones.
#[test]
fn cra_universes_cover_the_cra_slice() {
    let slice: BTreeSet<&str> = COMPLIANCE_SARIF_RULE_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("SBOM-CRA-"))
        .collect();
    let universes: BTreeSet<&str> = PHASE1_RULE_UNIVERSE
        .iter()
        .chain(PHASE2_RULE_UNIVERSE)
        .chain(STEWARD_RULE_UNIVERSE)
        .copied()
        .collect();
    let sliceless: BTreeSet<&str> = SLICELESS_CRA_IDS.iter().copied().collect();
    assert_eq!(
        universes
            .difference(&slice)
            .copied()
            .collect::<BTreeSet<_>>(),
        sliceless,
        "CRA universe ids outside the shared slice must be exactly the slice-less ones"
    );
    assert!(
        slice.is_subset(&universes),
        "every SBOM-CRA-* id of the shared slice must sit in a CRA universe; missing: {:?}",
        slice.difference(&universes).collect::<Vec<_>>()
    );
}

/// At Phase 1, SBOM-CRA-VULN-METADATA has a single site: an SPDX 3.0
/// document that carries vulnerabilities without declaring the Security
/// profile. The fixture declares it (silent); dropping it fires the Info.
#[test]
fn cra_phase1_vuln_metadata_is_the_spdx3_security_profile_note() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/spdx3/security-profile.spdx3.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("SPDX 3.0 fixture {path} must exist: {e}"));
    let run = |profiles: &[&str]| {
        let mut doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
        doc["profileConformance"] = serde_json::json!(profiles);
        let sbom = parse_sbom_str(&doc.to_string()).expect("fixture parses as SPDX 3.0");
        checker(PHASE1).check(&sbom)
    };
    let metadata = |result: &sbom_tools::quality::ComplianceResult| -> Vec<Sev> {
        result
            .violations
            .iter()
            .filter(|v| v.sarif_rule_id() == "SBOM-CRA-VULN-METADATA")
            .map(|v| v.severity)
            .collect()
    };

    let declared = run(&["core", "software", "security", "simpleLicensing"]);
    assert!(
        metadata(&declared).is_empty(),
        "a declared Security profile must keep VULN-METADATA silent:\n{}",
        render_violations(&declared)
    );
    let undeclared = run(&["core", "software", "simpleLicensing"]);
    assert_eq!(
        metadata(&undeclared),
        vec![Sev::Info],
        "vulnerabilities without the Security profile must fire one Info:\n{}",
        render_violations(&undeclared)
    );
}
