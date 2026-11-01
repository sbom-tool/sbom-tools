//! Cross-standard consistency (WP 1.11): the same SBOM evidence gives the
//! same answer in every standard that checks it.
//!
//! Each group below names one piece of evidence, the checks of every
//! standard that read it, and the evidence variants the checks must judge
//! alike: a licence, a contact (a vulnerability contact or the SBOM
//! creator's email), an EUCC certificate URL, a VEX `not_affected`
//! statement and a document signature. A variant either satisfies every
//! check of its group or none of them; the only exceptions are the ones a
//! standard's text makes, named in the group. Until v0.4.0 the standards
//! disagreed: a NOASSERTION licence passed the Standard profile but failed
//! CRA Art. 13(5), CRA Art. 13(17), EO 14028, FDA and BSI took any contact
//! while PCI DSS rejected placeholders, the CRA and EUCC checks read
//! different EUCC URL keywords, and FDA and PCI DSS counted vulnerabilities
//! the CRA profiles exempt.
//!
//! Every case renders as CycloneDX JSON and XML, which carry each variant
//! as written, and runs through the real parser and checker at the pinned
//! test clock. The rule matrices hold each check in the other encodings.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, Encoding, SbomFixture, VulnAnalysisFixture, check_in, render_violations,
};
use sbom_tools::model::{CraProductClass, CraSidecarMetadata};
use sbom_tools::quality::{ComplianceLevel, ComplianceResult};

/// One standard's check of the group's evidence: the level and the rule id
/// it reports.
type Check = (ComplianceLevel, &'static str);

/// Whether `rule` fires in `result`.
fn fires(result: &ComplianceResult, rule: &str) -> bool {
    result.violations.iter().any(|v| v.rule_id == rule)
}

/// Run `checks` over `fixture` in both CycloneDX encodings, and record a
/// mismatch for every check whose verdict is not `expect_fire(check)`.
fn judge(
    variant: &str,
    fixture: &SbomFixture,
    checks: &[Check],
    expect_fire: impl Fn(&Check) -> bool,
    mismatches: &mut Vec<String>,
) {
    for &encoding in Encoding::CYCLONEDX {
        for check in checks {
            let (level, rule) = *check;
            let result = check_in(level, fixture, encoding);
            let expected = expect_fire(check);
            if fires(&result, rule) != expected {
                mismatches.push(format!(
                    "{variant} in {}: [{level:?}] {rule} must {} it:\n{}",
                    encoding.name(),
                    if expected { "fire on" } else { "accept" },
                    render_violations(&result)
                ));
            }
        }
    }
}

fn assert_consistent(group: &str, mismatches: &[String]) {
    assert!(
        mismatches.is_empty(),
        "{group}: {} check(s) disagree with the other standards:\n\n{}",
        mismatches.len(),
        mismatches.join("\n\n")
    );
}

/// A product with two libraries, each carrying `license` (none when
/// `None`), and otherwise the elements the checks below need.
fn product(primary_refs: Vec<(String, String)>, license: Option<&str>) -> SbomFixture {
    let with_license = |mut c: ComponentFixture| {
        c.licenses = license.map(|l| vec![l.to_string()]).unwrap_or_default();
        c
    };
    let mut primary = with_license(ComponentFixture::conforming("acme-app"));
    primary.component_type = "application".to_string();
    primary.external_refs = primary_refs;
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        manufacturer: Some((
            "Acme Networks GmbH".to_string(),
            Some("sbom@acme.example".to_string()),
        )),
        primary: Some(primary),
        components: vec![
            with_license(ComponentFixture::conforming("libalpha")),
            with_license(ComponentFixture::conforming("libbeta")),
        ],
        dependencies: vec![(
            "ref-acme-app".to_string(),
            vec!["ref-libalpha".to_string(), "ref-libbeta".to_string()],
        )],
        ..SbomFixture::default()
    }
}

/// The product's security-contact and advisories references.
fn contact_refs(security_contact: &str, advisories: &str) -> Vec<(String, String)> {
    vec![
        ("security-contact".to_string(), security_contact.to_string()),
        ("advisories".to_string(), advisories.to_string()),
    ]
}

/// A product whose security contact and advisories references are
/// `contact` and `advisories`, and whose manufacturer, the SBOM's only
/// creator besides the tool, gives `contact` (without a `mailto:` prefix)
/// as its email: every contact check reads the same address.
fn contactable(contact: &str, advisories: &str) -> SbomFixture {
    let mut fixture = product(contact_refs(contact, advisories), Some("MIT"));
    let email = contact.strip_prefix("mailto:").unwrap_or(contact);
    fixture.manufacturer = Some(("Acme Networks GmbH".to_string(), Some(email.to_string())));
    fixture
}

/// Every licence check: a known SPDX expression or LicenseRef-* id
/// satisfies all of them; a placeholder or no licence satisfies none. The
/// explicit unknown NOASSERTION satisfies only CISA 2026, whose Component
/// License element names it as the way to declare an unknown licence.
#[test]
fn licence_evidence_gets_one_answer() {
    const CHECKS: &[Check] = &[
        (ComplianceLevel::Standard, "SBOM-QUALITY-LICENSE"),
        (ComplianceLevel::Comprehensive, "SBOM-QUALITY-LICENSE"),
        (ComplianceLevel::CraPhase1, "SBOM-CRA-ART-13-5"),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-ART-13-5"),
        (ComplianceLevel::BsiTr03183_2, "SBOM-BSI-TR-03183-2-LICENSE"),
        (ComplianceLevel::Fsct, "SBOM-FSCT-LICENSE-PRIMARY"),
        (ComplianceLevel::Cisa2026, "SBOM-CISA2026-LICENSE"),
    ];
    let cisa = |check: &Check| check.0 == ComplianceLevel::Cisa2026;
    let mut mismatches = Vec::new();
    for license in ["MIT", "Apache-2.0 OR MIT", "LicenseRef-acme-proprietary"] {
        let fixture = product(Vec::new(), Some(license));
        judge(license, &fixture, CHECKS, |_| false, &mut mismatches);
    }
    judge(
        "NOASSERTION",
        &product(Vec::new(), Some("NOASSERTION")),
        CHECKS,
        |check| !cisa(check),
        &mut mismatches,
    );
    for placeholder in ["TBD", "N/A"] {
        let fixture = product(Vec::new(), Some(placeholder));
        judge(placeholder, &fixture, CHECKS, |_| true, &mut mismatches);
    }
    judge(
        "no licence",
        &product(Vec::new(), None),
        CHECKS,
        |_| true,
        &mut mismatches,
    );
    assert_consistent("licence", &mismatches);
}

/// Every check that reads a contact, a vulnerability contact or the SBOM
/// creator's email: a contact that reaches someone satisfies all of them; a
/// placeholder, or an address at a documentation domain (example.com,
/// example.net, example.org), satisfies none. The RFC 2606 `.example`
/// top-level domain stays a real one, as test data uses it.
#[test]
fn contact_evidence_gets_one_answer() {
    const CHECKS: &[Check] = &[
        (ComplianceLevel::CraPhase1, "SBOM-CRA-ART-13-17-CONTACT"),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-ART-13-17-CONTACT"),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-CVD-POLICY"),
        (ComplianceLevel::CraOssSteward, "SBOM-CRA-ART-24"),
        (ComplianceLevel::CraOssSteward, "SBOM-CRA-CVD-POLICY"),
        (ComplianceLevel::Eo14028, "SBOM-EO14028-DISCLOSURE"),
        (ComplianceLevel::PciDss632, "SBOM-PCI-6-3-2-VULN-EVIDENCE"),
        (ComplianceLevel::NistSsdf, "SBOM-SSDF-PW6"),
        (ComplianceLevel::FdaMedicalDevice, "SBOM-FDA-CONTACT"),
        (
            ComplianceLevel::BsiTr03183_2,
            "SBOM-BSI-TR-03183-2-5-1-CONTACT",
        ),
    ];
    let mut mismatches = Vec::new();
    for (variant, contact, advisories) in [
        (
            "contacts at the manufacturer's domain",
            "mailto:psirt@acme.example",
            "https://acme.example/security/advisories",
        ),
        (
            "contacts at a domain that ends like a documentation domain",
            "mailto:psirt@notexample.com",
            "https://security.example.com.acme.example/advisories",
        ),
    ] {
        let fixture = contactable(contact, advisories);
        judge(variant, &fixture, CHECKS, |_| false, &mut mismatches);
    }
    for placeholder in ["NOASSERTION", "unknown", "n/a", "TBD", "mailto:"] {
        let fixture = contactable(placeholder, placeholder);
        judge(placeholder, &fixture, CHECKS, |_| true, &mut mismatches);
    }
    for (variant, contact, advisories) in [
        (
            "contacts at example.com",
            "mailto:security@example.com",
            "https://example.com/security/advisories",
        ),
        (
            "contacts under example.org and at example.net",
            "Security Team <security@example.net>",
            "https://psirt.example.org/advisories",
        ),
    ] {
        let fixture = contactable(contact, advisories);
        judge(variant, &fixture, CHECKS, |_| true, &mut mismatches);
    }
    assert_consistent("contact", &mismatches);
}

/// A critical product whose certification-report reference points at
/// `url`: the class makes the CRA Annex IV check and the EUCC route of the
/// conformity summary read it.
fn certified(url: &str) -> SbomFixture {
    let mut fixture = product(
        vec![("certification-report".to_string(), url.to_string())],
        Some("MIT"),
    );
    fixture.sidecar = Some(CraSidecarMetadata {
        product_class: Some(CraProductClass::Critical),
        ..CraSidecarMetadata::default()
    });
    fixture
}

/// Whether the CRA Phase 2 conformity summary of `fixture` marks its EUCC
/// certificate row satisfied, in `encoding`.
fn eucc_row_satisfied(fixture: &SbomFixture, encoding: Encoding) -> bool {
    let result = check_in(ComplianceLevel::CraPhase2, fixture, encoding);
    result
        .conformity_summary
        .as_ref()
        .and_then(|summary| {
            summary
                .evidence
                .iter()
                .find(|row| row.label == "EUCC / Common Criteria certificate")
        })
        .is_some_and(|row| row.satisfied)
}

/// Every check that reads an EUCC certificate reference: a URL naming the
/// scheme (`eucc`, `common-criteria` or `commoncriteria`, in any case)
/// satisfies all of them, and the summary's EUCC row; any other URL none.
#[test]
fn eucc_url_evidence_gets_one_answer() {
    const CHECKS: &[Check] = &[
        (ComplianceLevel::CraPhase2, "SBOM-CRA-ANNEX-IV"),
        (ComplianceLevel::EuccSubstantial, "SBOM-EUCC-CERTREF"),
    ];
    let mut mismatches = Vec::new();
    let cases = [
        (
            "https://certification.enisa.europa.eu/eucc/certificates/EUCC-1234.pdf",
            true,
        ),
        (
            "https://lab.acme.example/common-criteria/certificates/CC-1234.pdf",
            true,
        ),
        (
            "https://www.commoncriteriaportal.org/files/epfiles/acme-cert.pdf",
            true,
        ),
        ("https://LAB.ACME.EXAMPLE/CommonCriteria/CC-1234.PDF", true),
        (
            "https://notified-body.acme.example/certificates/eu-type-0815.pdf",
            false,
        ),
    ];
    for (url, is_eucc) in cases {
        let fixture = certified(url);
        judge(url, &fixture, CHECKS, |_| !is_eucc, &mut mismatches);
        for &encoding in Encoding::CYCLONEDX {
            if eucc_row_satisfied(&fixture, encoding) != is_eucc {
                mismatches.push(format!(
                    "{url} in {}: the conformity summary's EUCC row must be {}",
                    encoding.name(),
                    if is_eucc { "satisfied" } else { "unsatisfied" }
                ));
            }
        }
    }
    assert_consistent("EUCC URL", &mismatches);
}

/// The VEX analysis cases every open-vulnerability check must judge alike,
/// as (label, analysis, whether the vulnerability stays open).
fn vex_statements() -> Vec<(&'static str, Option<VulnAnalysisFixture>, bool)> {
    let not_affected = VulnAnalysisFixture {
        state: Some("not_affected".to_string()),
        ..VulnAnalysisFixture::default()
    };
    vec![
        ("no VEX statement", None, true),
        ("bare not_affected", Some(not_affected.clone()), true),
        (
            "not_affected with a detail but no justification",
            Some(VulnAnalysisFixture {
                detail: Some("the parser is never called".to_string()),
                ..not_affected.clone()
            }),
            true,
        ),
        (
            "justification on an exploitable statement",
            Some(VulnAnalysisFixture {
                state: Some("exploitable".to_string()),
                justification: Some("code_not_reachable".to_string()),
                ..VulnAnalysisFixture::default()
            }),
            true,
        ),
        (
            "justified not_affected",
            Some(VulnAnalysisFixture {
                justification: Some("code_not_reachable".to_string()),
                ..not_affected
            }),
            false,
        ),
    ]
}

/// Every check that asks whether a vulnerability is still open: a
/// vulnerability whose own VEX statement is `not_affected` and names a
/// justification is not, in any of them (until v0.4.0 FDA and PCI DSS
/// counted it); any other statement leaves it open. Each check gets the
/// vulnerability it looks for: FDA a critical or high one, CRA Phase 2 and
/// PCI DSS an unrated one.
#[test]
fn vex_not_affected_evidence_gets_one_answer() {
    const CHECKS: &[(ComplianceLevel, &str, &str)] = &[
        (
            ComplianceLevel::FdaMedicalDevice,
            "SBOM-FDA-SECURITY",
            "critical",
        ),
        (
            ComplianceLevel::FdaMedicalDevice,
            "SBOM-FDA-SECURITY",
            "high",
        ),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-VULN-METADATA", ""),
        (ComplianceLevel::PciDss632, "SBOM-PCI-11-3-1-1-SEVERITY", ""),
    ];
    let mut mismatches = Vec::new();
    for (label, analysis, open) in vex_statements() {
        for &(level, rule, rating) in CHECKS {
            let mut fixture = product(Vec::new(), Some("MIT"));
            fixture.vulnerabilities = vec![(
                "CVE-2026-3333".to_string(),
                rating.to_string(),
                "ref-libalpha".to_string(),
            )];
            if let Some(analysis) = &analysis {
                fixture
                    .vulnerability_analyses
                    .push(("CVE-2026-3333".to_string(), analysis.clone()));
            }
            let variant = format!("{label} on a vulnerability rated {rating:?}");
            judge(
                &variant,
                &fixture,
                &[(level, rule)],
                |_| open,
                &mut mismatches,
            );
        }
    }
    assert_consistent("VEX not_affected", &mismatches);
}

/// Every check that reads the document signature: a signature with a value
/// satisfies all of them; none, or one without a value, satisfies none.
#[test]
fn signature_evidence_gets_one_answer() {
    const CHECKS: &[Check] = &[
        (ComplianceLevel::CraPhase1, "SBOM-CRA-DOC-INTEGRITY"),
        (ComplianceLevel::CraPhase2, "SBOM-CRA-DOC-INTEGRITY"),
        (ComplianceLevel::Cisa2026, "SBOM-CISA2026-SIGNATURE"),
        (ComplianceLevel::Fsct, "SBOM-FSCT-SIGNATURE"),
    ];
    let mut mismatches = Vec::new();
    for (variant, signature, unsigned) in [
        (
            "signature with a value",
            Some(("ES256", "c2lnbmF0dXJlLXZhbHVl")),
            false,
        ),
        ("signature without a value", Some(("ES256", "")), true),
        ("no signature", None, true),
    ] {
        let mut fixture = product(Vec::new(), Some("MIT"));
        fixture.signature = signature.map(|(alg, value)| (alg.to_string(), value.to_string()));
        judge(variant, &fixture, CHECKS, |_| unsigned, &mut mismatches);
    }
    assert_consistent("signature", &mismatches);
}
