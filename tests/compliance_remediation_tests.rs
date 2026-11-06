//! Remediation on every violation, phrased for the input format.
//!
//! Every compliance level runs over an SPDX 2.3, an SPDX 3.0 and a CycloneDX
//! fixture. Each violation's JSON must carry `remediation` — the rule's
//! guidance plus, for rules whose fix lives in a format-specific field, the
//! input format's field path — and `help_uri`, the rule's documentation
//! link: the URL of the first standard reference that has one, else the
//! page of the rule's family, as the rule catalogue gives it. SPDX inputs
//! used to get CycloneDX field advice.

use std::path::Path;

use sbom_tools::model::NormalizedSbom;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, RemediationFormat, rule_catalog_entry,
    rule_meta,
};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Evaluation instant for every run (the v0.3.0 review date).
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// The fixtures, each with the format family its remediation must use.
const FIXTURES: &[(&str, RemediationFormat)] = &[
    ("spdx/minimal.spdx.json", RemediationFormat::Spdx2),
    ("spdx3/minimal.spdx3.json", RemediationFormat::Spdx3),
    ("cyclonedx/minimal.cdx.json", RemediationFormat::CycloneDx),
];

/// Field paths that belong to one format only.
const CYCLONEDX_FIELDS: &[&str] = &[
    "components[]",
    "metadata.component",
    "metadata.authors",
    "metadata.tools",
    "externalReferences",
    "compositions",
    "modelCard",
];
const SPDX_FIELDS: &[&str] = &[
    "packages[]",
    "creationInfo.creators",
    "suppliedBy",
    "software_",
    "verifiedUsing",
    "hasDeclaredLicense",
];

fn parse(rel: &str) -> NormalizedSbom {
    let raw = std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel)).expect("fixture readable");
    parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"))
}

fn check_all_levels(sbom: &NormalizedSbom) -> Vec<ComplianceResult> {
    let as_of = chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc);
    ComplianceLevel::all()
        .iter()
        .map(|level| ComplianceChecker::new(*level).with_as_of(as_of).check(sbom))
        .collect()
}

/// Every violation's JSON carries the registry remediation for the input
/// format, and the rule catalogue's documentation link as `help_uri`: the
/// first standard-reference URL when a reference has one.
#[test]
fn every_violation_carries_remediation_for_its_format() {
    for (rel, format) in FIXTURES {
        let sbom = parse(rel);
        assert_eq!(RemediationFormat::of(&sbom.document), *format, "{rel}");
        let mut advised = 0;
        for result in check_all_levels(&sbom) {
            let json = serde_json::to_value(&result).expect("result serializes");
            let violations = json["violations"].as_array().expect("violations array");
            assert_eq!(violations.len(), result.violations.len());
            for (v, value) in result.violations.iter().zip(violations) {
                let meta = rule_meta(v.rule_id).expect("emitted rules are registered");
                let remediation = value["remediation"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{rel} {}: no remediation in {value}", v.rule_id));
                assert_eq!(remediation, meta.remediation_for(*format), "{rel}");
                if let Some(advice) = meta.advice {
                    advised += 1;
                    assert!(
                        remediation.contains(&format!(
                            "{}: {}",
                            format.label(),
                            advice.get(*format).text
                        )),
                        "{rel} {}: format advice missing from {remediation:?}",
                        v.rule_id
                    );
                }
                let foreign = match format {
                    RemediationFormat::CycloneDx => SPDX_FIELDS,
                    RemediationFormat::Spdx2 | RemediationFormat::Spdx3 => CYCLONEDX_FIELDS,
                    other => panic!("no foreign fields listed for {other:?}"),
                };
                for field in foreign {
                    assert!(
                        !remediation.contains(field),
                        "{rel} {}: {field:?} is another format's field: {remediation:?}",
                        v.rule_id
                    );
                }
                let help_uri = value.get("help_uri").and_then(|u| u.as_str());
                let catalogued = rule_catalog_entry(v.rule_id).and_then(|entry| entry.help_uri);
                assert_eq!(
                    help_uri,
                    catalogued.as_deref(),
                    "{rel} {}: help_uri must be the rule catalogue's",
                    v.rule_id
                );
                if let Some(first_uri) = v.standard_refs.iter().find_map(|r| r.help_uri.as_deref())
                {
                    assert_eq!(
                        help_uri,
                        Some(first_uri),
                        "{rel} {}: help_uri must be the first standard-reference URL",
                        v.rule_id
                    );
                }
            }
        }
        assert!(
            advised > 0,
            "{rel}: no violation exercised per-format advice"
        );
    }
}

/// Spot checks on what the user is told to set, per format.
#[test]
fn spdx_inputs_get_spdx_field_paths() {
    let remediation = |rel: &str, level: ComplianceLevel, rule_id: &str| -> String {
        check_all_levels(&parse(rel))
            .into_iter()
            .find(|r| r.level == level)
            .and_then(|r| r.violations.into_iter().find(|v| v.rule_id == rule_id))
            .and_then(|v| v.remediation)
            .unwrap_or_else(|| panic!("{rel}: {level:?} must emit {rule_id}"))
    };

    // SPDX 2.3: the packages name no supplier.
    let text = remediation(
        "spdx/minimal.spdx.json",
        ComplianceLevel::NtiaMinimum,
        "SBOM-NTIA-SUPPLIER",
    );
    assert!(
        text.contains("SPDX 2.x: set packages[].supplier (PackageSupplier)"),
        "{text}"
    );

    // SPDX 3.0: a package without a licence, a SHA-256-only hash, and a
    // tool-only creator list.
    let rel = "spdx3/minimal.spdx3.json";
    let text = remediation(
        rel,
        ComplianceLevel::BsiTr03183_2,
        "SBOM-BSI-TR-03183-2-LICENSE",
    );
    assert!(
        text.contains("SPDX 3.0: add a hasDeclaredLicense"),
        "{text}"
    );
    let text = remediation(
        rel,
        ComplianceLevel::BsiTr03183_2,
        "SBOM-BSI-TR-03183-2-5-4",
    );
    assert!(
        text.contains("verifiedUsing[] Hash entry with algorithm sha512"),
        "{text}"
    );
    let text = remediation(
        rel,
        ComplianceLevel::BsiTr03183_2,
        "SBOM-BSI-TR-03183-2-5-1",
    );
    assert!(
        text.contains("SPDX 3.0: set creationInfo.createdBy"),
        "{text}"
    );

    // CycloneDX keeps CycloneDX paths.
    let text = remediation(
        "cyclonedx/minimal.cdx.json",
        ComplianceLevel::NtiaMinimum,
        "SBOM-NTIA-SUPPLIER",
    );
    assert!(
        text.contains("CycloneDX: set components[].supplier.name"),
        "{text}"
    );
}
