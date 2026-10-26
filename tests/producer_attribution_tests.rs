//! CycloneDX 1.6 introduced component `authors` (deprecating the `author`
//! string) and `manufacturer`. A component whose producer is named only
//! through either must satisfy the supplier/producer element of every
//! standard, exactly like `supplier` or `author` — previously both were
//! dropped by the parser and such components false-failed.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::{
    model::NormalizedSbom,
    parsers::parse_sbom,
    quality::{ComplianceLevel, ViolationCategory},
};
use std::path::Path;

fn fixture() -> NormalizedSbom {
    parse_sbom(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cyclonedx/producer-manufacturer-authors-1.6.cdx.json"),
    )
    .expect("fixture parses")
}

/// The leading `N` of an aggregate "N/total component(s) missing …" message.
fn missing_count(message: &str) -> Option<u32> {
    let slash = message.find('/')?;
    let digits: String = message[..slash]
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

#[test]
fn authors_and_manufacturer_are_parsed() {
    let sbom = fixture();
    let comp = |name: &str| {
        sbom.components
            .values()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{name} present"))
    };
    assert_eq!(
        comp("maker-lib")
            .manufacturer
            .as_ref()
            .map(|m| m.name.as_str()),
        Some("Maker GmbH")
    );
    assert_eq!(
        comp("authored-lib").author.as_deref(),
        Some("Jane Dev; ops@authored.example")
    );
    assert!(!comp("anon-lib").has_producer());
}

#[test]
fn manufacturer_or_authors_satisfy_supplier_element_across_standards() {
    let sbom = fixture();
    for level in [
        ComplianceLevel::NtiaMinimum,
        ComplianceLevel::FdaMedicalDevice,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::Cisa2026,
        ComplianceLevel::Eo14028,
        ComplianceLevel::NistSsdf,
        ComplianceLevel::BsiTr03183_2,
    ] {
        let supplier_findings: Vec<_> = checker(level)
            .check(&sbom)
            .violations
            .into_iter()
            .filter(|v| v.category == ViolationCategory::SupplierInfo)
            .collect();
        for v in &supplier_findings {
            for named in ["maker-lib", "authored-lib"] {
                assert!(
                    v.element.as_deref() != Some(named) && !v.message.contains(named),
                    "{level:?}: {named} names its producer and must not be flagged: {v:?}"
                );
            }
            if let Some(n) = missing_count(&v.message) {
                assert_eq!(n, 1, "{level:?}: only anon-lib lacks a producer: {v:?}");
            }
        }
        assert!(
            supplier_findings
                .iter()
                .any(|v| v.element.as_deref() == Some("anon-lib")
                    || v.message.contains("anon-lib")
                    || missing_count(&v.message) == Some(1)),
            "{level:?}: the producer-less control must still be flagged: {supplier_findings:?}"
        );
    }
}
