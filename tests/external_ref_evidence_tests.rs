//! External references as compliance evidence, through the real parsers.
//!
//! The CRA, EUCC, SSDF and PCI DSS checks accept certain external
//! references as evidence: an attestation or certification report (EU
//! Declaration of Conformity, notified-body certificate, EUCC certificate),
//! a risk assessment, a vulnerability disclosure report (VDR) or VEX, a
//! build system. Until v0.4.0 the CycloneDX parser mapped `attestation`,
//! `certification-report`, `risk-assessment`, `vulnerability-assertion`,
//! `exploitability-statement` and `build-system` to `ExternalRefType::Other`,
//! and the SPDX 3.0 parser did the same with their counterparts, so no
//! document could satisfy those checks through a reference (WP 1.2 finding
//! B1). Every case below parses the same product three times — CycloneDX
//! JSON, CycloneDX XML and SPDX 3.0 — with and without the reference, and
//! asserts that the reference silences the rule in all three.

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{ConformityRoute, CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{ComplianceLevel, ComplianceResult};

/// One external reference, spelled in each format's vocabulary.
#[derive(Clone, Copy)]
struct Reference {
    /// CycloneDX `externalReferences[].type`.
    cyclonedx: &'static str,
    /// SPDX 3.0.1 `externalRef[].externalRefType`.
    spdx3: &'static str,
    url: &'static str,
}

const ATTESTATION: Reference = Reference {
    cyclonedx: "attestation",
    spdx3: "secureSoftwareAttestation",
    url: "https://acme.example/attestations/eu-doc-2026-001.pdf",
};
const CERTIFICATION: Reference = Reference {
    cyclonedx: "certification-report",
    spdx3: "certificationReport",
    url: "https://notified-body.example/certificates/eu-type-0815.pdf",
};
const EUCC_CERTIFICATE: Reference = Reference {
    cyclonedx: "certification-report",
    spdx3: "certificationReport",
    url: "https://certification.enisa.europa.eu/eucc/certificates/EUCC-DE-2026-0042.pdf",
};
const RISK_ASSESSMENT: Reference = Reference {
    cyclonedx: "risk-assessment",
    spdx3: "riskAssessment",
    url: "https://acme.example/docs/risk-assessment.pdf",
};
const VDR: Reference = Reference {
    cyclonedx: "vulnerability-assertion",
    spdx3: "vulnerabilityDisclosureReport",
    url: "https://acme.example/security/vdr.json",
};
const VEX: Reference = Reference {
    cyclonedx: "exploitability-statement",
    spdx3: "vulnerabilityExploitabilityAssessment",
    url: "https://acme.example/security/vex.json",
};
const BUILD_SYSTEM: Reference = Reference {
    cyclonedx: "build-system",
    spdx3: "buildSystem",
    url: "https://ci.acme.example/pipelines/acme-router-os",
};

/// The product as a CycloneDX 1.6 JSON document: a timestamped, serialized
/// SBOM whose `metadata.component` carries `refs`.
fn cyclonedx_json(refs: &[Reference]) -> String {
    let refs: Vec<serde_json::Value> = refs
        .iter()
        .map(|r| serde_json::json!({ "type": r.cyclonedx, "url": r.url }))
        .collect();
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T00:00:00Z",
            "tools": [{ "name": "acme-sbom-tool", "version": "1.0.0" }],
            "manufacturer": { "name": "Acme Networks GmbH" },
            "component": {
                "type": "application",
                "bom-ref": "acme-router-os",
                "name": "acme-router-os",
                "version": "4.2.0",
                "purl": "pkg:generic/acme/acme-router-os@4.2.0",
                "supplier": { "name": "Acme Networks GmbH" },
                "externalReferences": refs,
            },
        },
        "components": [],
    })
    .to_string()
}

/// The same product as a CycloneDX 1.6 XML document.
fn cyclonedx_xml(refs: &[Reference]) -> String {
    let refs: String = refs
        .iter()
        .map(|r| {
            format!(
                r#"<reference type="{}"><url>{}</url></reference>"#,
                r.cyclonedx, r.url
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1">
  <metadata>
    <timestamp>2026-10-01T00:00:00Z</timestamp>
    <tools><tool><name>acme-sbom-tool</name><version>1.0.0</version></tool></tools>
    <manufacturer><name>Acme Networks GmbH</name></manufacturer>
    <component type="application" bom-ref="acme-router-os">
      <supplier><name>Acme Networks GmbH</name></supplier>
      <name>acme-router-os</name>
      <version>4.2.0</version>
      <purl>pkg:generic/acme/acme-router-os@4.2.0</purl>
      <externalReferences>{refs}</externalReferences>
    </component>
  </metadata>
  <components/>
</bom>"#
    )
}

/// The same product as an SPDX 3.0.1 JSON-LD document, the package as its
/// root element.
fn spdx3(refs: &[Reference]) -> String {
    let refs: Vec<serde_json::Value> = refs
        .iter()
        .map(|r| serde_json::json!({ "externalRefType": r.spdx3, "locator": [r.url] }))
        .collect();
    serde_json::json!({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "type": "SpdxDocument",
        "spdxId": "urn:spdx:doc:acme-router-os",
        "creationInfo": {
            "specVersion": "3.0.1",
            "created": "2026-10-01T00:00:00Z",
            "createdBy": ["urn:spdx:agent:acme"],
        },
        "profileConformance": ["core", "software"],
        "rootElement": ["urn:spdx:pkg:acme-router-os"],
        "element": [
            { "type": "Organization", "spdxId": "urn:spdx:agent:acme", "name": "Acme Networks GmbH" },
            {
                "type": "software_Package",
                "spdxId": "urn:spdx:pkg:acme-router-os",
                "name": "acme-router-os",
                "software_packageVersion": "4.2.0",
                "software_packageUrl": "pkg:generic/acme/acme-router-os@4.2.0",
                "software_primaryPurpose": "application",
                "suppliedBy": ["urn:spdx:agent:acme"],
                "externalRef": refs,
            },
        ],
    })
    .to_string()
}

/// The product parsed from each format, labelled.
fn documents(refs: &[Reference]) -> Vec<(&'static str, NormalizedSbom)> {
    [
        ("CycloneDX JSON", cyclonedx_json(refs)),
        ("CycloneDX XML", cyclonedx_xml(refs)),
        ("SPDX 3.0", spdx3(refs)),
    ]
    .into_iter()
    .map(|(label, text)| {
        let sbom = parse_sbom_str(&text).unwrap_or_else(|e| panic!("{label} must parse: {e}"));
        (label, sbom)
    })
    .collect()
}

fn fires(result: &ComplianceResult, rule_id: &str) -> bool {
    result.violations.iter().any(|v| v.rule_id == rule_id)
}

/// `rule_id` fires on the product without `reference` and stays silent with
/// it, in every format.
fn assert_reference_satisfies(
    rule_id: &str,
    reference: Reference,
    run: impl Fn(&NormalizedSbom) -> ComplianceResult,
) {
    for (label, sbom) in documents(&[]) {
        assert!(
            fires(&run(&sbom), rule_id),
            "{label}: {rule_id} must fire without a {} reference",
            reference.cyclonedx
        );
    }
    for (label, sbom) in documents(&[reference]) {
        let result = run(&sbom);
        assert!(
            !fires(&result, rule_id),
            "{label}: a {} / {} reference must satisfy {rule_id}; got {:?}",
            reference.cyclonedx,
            reference.spdx3,
            result
                .violations
                .iter()
                .filter(|v| v.rule_id == rule_id)
                .map(|v| v.message.as_str())
                .collect::<Vec<_>>()
        );
    }
}

/// A sidecar pinning the product class and, optionally, the route.
fn class_sidecar(class: CraProductClass, route: Option<ConformityRoute>) -> CraSidecarMetadata {
    CraSidecarMetadata {
        product_class: Some(class),
        conformity_assessment_route: route,
        ..CraSidecarMetadata::default()
    }
}

#[test]
fn attestation_and_certification_references_are_the_annex_v_doc_reference() {
    for reference in [ATTESTATION, CERTIFICATION] {
        assert_reference_satisfies("SBOM-CRA-ANNEX-V", reference, |sbom| {
            checker(ComplianceLevel::CraPhase2).check(sbom)
        });
    }
}

#[test]
fn certification_and_attestation_references_are_the_annex_viii_route_evidence() {
    for reference in [CERTIFICATION, ATTESTATION] {
        assert_reference_satisfies("SBOM-CRA-ANNEX-VIII", reference, |sbom| {
            checker(ComplianceLevel::CraPhase1)
                .with_sidecar(class_sidecar(
                    CraProductClass::ImportantClass1,
                    Some(ConformityRoute::ModuleBC),
                ))
                .check(sbom)
        });
    }
}

/// The Annex IV fallback reads the reference URL: only a certificate that
/// names the EUCC scheme counts.
#[test]
fn an_eucc_certificate_reference_is_the_annex_iv_reference() {
    let critical = |sbom: &NormalizedSbom| {
        checker(ComplianceLevel::CraPhase2)
            .with_sidecar(class_sidecar(CraProductClass::Critical, None))
            .check(sbom)
    };
    assert_reference_satisfies("SBOM-CRA-ANNEX-IV", EUCC_CERTIFICATE, critical);
    for (label, sbom) in documents(&[CERTIFICATION]) {
        assert!(
            fires(&critical(&sbom), "SBOM-CRA-ANNEX-IV"),
            "{label}: a certificate whose URL names no EUCC scheme is not an EUCC reference"
        );
    }
}

#[test]
fn a_risk_assessment_reference_is_the_art_13_2_reference() {
    assert_reference_satisfies("SBOM-CRA-ART-13-2", RISK_ASSESSMENT, |sbom| {
        checker(ComplianceLevel::CraPhase2).check(sbom)
    });
}

#[test]
fn vdr_and_vex_references_are_the_documented_vulnerability_information() {
    for reference in [VDR, VEX] {
        assert_reference_satisfies("SBOM-CRA-VULN-STATEMENT", reference, |sbom| {
            checker(ComplianceLevel::CraPhase1).check(sbom)
        });
    }
}

#[test]
fn a_vdr_reference_is_the_stewards_vulnerability_handling_process() {
    assert_reference_satisfies("SBOM-CRA-ART-24", VDR, |sbom| {
        checker(ComplianceLevel::CraOssSteward).check(sbom)
    });
}

#[test]
fn an_eucc_certificate_reference_is_the_eucc_certification_reference() {
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-CC-ROUTER-01".to_string()),
        eucc_target_of_evaluation: Some("acme-router-os 4.2.0".to_string()),
        eucc_itsef_identifier: Some("ITSEF-DE-0042".to_string()),
        eucc_valid_until: Some(clock::as_of() + chrono::Duration::days(730)),
        ..CraSidecarMetadata::default()
    };
    assert_reference_satisfies("SBOM-EUCC-CERTREF", EUCC_CERTIFICATE, |sbom| {
        checker(ComplianceLevel::EuccSubstantial)
            .with_sidecar(sidecar.clone())
            .check(sbom)
    });
}

#[test]
fn a_build_system_reference_is_ssdf_build_provenance() {
    assert_reference_satisfies("SBOM-SSDF-PO3", BUILD_SYSTEM, |sbom| {
        checker(ComplianceLevel::NistSsdf).check(sbom)
    });
}

#[test]
fn a_vdr_reference_is_ssdf_vulnerability_information() {
    assert_reference_satisfies("SBOM-SSDF-PW6", VDR, |sbom| {
        checker(ComplianceLevel::NistSsdf).check(sbom)
    });
}

#[test]
fn a_vdr_reference_is_a_pci_dss_vulnerability_management_hook() {
    assert_reference_satisfies("SBOM-PCI-6-3-2-VULN-EVIDENCE", VDR, |sbom| {
        checker(ComplianceLevel::PciDss632).check(sbom)
    });
}

/// The Annex VIII conformity summary reads the same references: each route's
/// evidence rows are satisfied by a parsed reference, in every format.
#[test]
fn parsed_references_satisfy_the_conformity_summary_rows() {
    let rows = |sbom: &NormalizedSbom, class: CraProductClass, route: Option<ConformityRoute>| {
        checker(ComplianceLevel::CraPhase2)
            .with_sidecar(class_sidecar(class, route))
            .check(sbom)
            .conformity_summary
            .expect("a pinned class attaches the summary")
            .evidence
            .into_iter()
            .map(|row| (row.label, row.satisfied))
            .collect::<Vec<_>>()
    };
    let module_bc_rows = [
        "EU Declaration of Conformity",
        "EU-type examination certificate (Module B)",
        "Production conformity statement (Module C)",
    ];
    let eucc_rows = [
        "EU Declaration of Conformity",
        "EUCC / Common Criteria certificate",
        "Target of Evaluation reference",
    ];
    let cases: [(CraProductClass, Option<ConformityRoute>, Reference, &[&str]); 3] = [
        (
            CraProductClass::ImportantClass1,
            Some(ConformityRoute::ModuleBC),
            CERTIFICATION,
            &module_bc_rows,
        ),
        (
            CraProductClass::ImportantClass2,
            Some(ConformityRoute::ModuleBC),
            ATTESTATION,
            &module_bc_rows,
        ),
        (
            CraProductClass::Critical,
            None,
            EUCC_CERTIFICATE,
            &eucc_rows,
        ),
    ];
    for (class, route, reference, labels) in cases {
        for (label, sbom) in documents(&[]) {
            let without = rows(&sbom, class, route);
            for row in labels {
                assert!(
                    without.iter().any(|(l, satisfied)| l == row && !satisfied),
                    "{label} {class:?}: row {row:?} must be unsatisfied without a reference: \
                     {without:?}"
                );
            }
        }
        for (label, sbom) in documents(&[reference]) {
            let with = rows(&sbom, class, route);
            for row in labels {
                assert!(
                    with.iter().any(|(l, satisfied)| l == row && *satisfied),
                    "{label} {class:?}: a {} reference must satisfy row {row:?}: {with:?}",
                    reference.cyclonedx
                );
            }
        }
    }
}
