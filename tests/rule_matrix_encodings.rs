//! The format axis of the rule matrix, tested on its own: each encoding is
//! read by its own parser, the renderers leave out exactly the fields
//! `Encoding::no_counterpart` lists (so an omission can never hide a missing
//! renderer), and one fixture normalizes to the same components, licences,
//! hashes, creators and dependency graph in all four encodings, to the same
//! model metadata in the three that carry a model card, and to the same VEX
//! statement in the three that carry vulnerability data.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::{
    ComponentFixture, CryptoAssetFixture, DatasetFixture, Encoding, MD5_FILLER, SHA256_FILLER,
    SbomFixture, VulnAnalysisFixture,
};
use sbom_tools::model::{CreatorType, NormalizedSbom, VexJustification, VexState};
use std::collections::BTreeSet;

/// A plain software SBOM: a primary product with two libraries, every
/// per-component field set, a manufacturer, an author and a tool.
fn software() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-app");
    primary.component_type = "application".to_string();
    primary.licenses = vec!["Apache-2.0".to_string()];
    primary.support_end = Some("2030-01-01".to_string());
    primary.external_refs = vec![(
        "advisories".to_string(),
        "https://acme.example/security/advisories".to_string(),
    )];
    let mut liba = ComponentFixture::conforming("liba");
    liba.licenses = vec!["MIT".to_string()];
    liba.cpe = Some("cpe:2.3:a:acme:liba:1.2.3:*:*:*:*:*:*:*".to_string());
    liba.copyright = Some("Copyright (c) 2026 Acme Components Ltd".to_string());
    liba.description = Some("A library".to_string());
    let mut libb = ComponentFixture::conforming("libb");
    libb.hashes
        .push(("MD5".to_string(), MD5_FILLER.to_string()));
    SbomFixture {
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: vec![("Dana Author".to_string(), None)],
        manufacturer: Some(("Acme Networks GmbH".to_string(), None)),
        primary: Some(primary),
        components: vec![liba, libb],
        dependencies: vec![
            ("ref-acme-app".to_string(), vec!["ref-liba".to_string()]),
            ("ref-liba".to_string(), vec!["ref-libb".to_string()]),
        ],
        ..SbomFixture::default()
    }
}

/// A fixture setting every DSL field to a value some encoding cannot carry.
fn everything() -> SbomFixture {
    let mut s = software();
    s.spec_version = String::new();
    s.spdx_version = Some("2.3".to_string());
    s.doc_version = Some(2);
    s.lifecycles = vec!["build".to_string()];
    s.completeness = Some("complete".to_string());
    s.signature = Some(("ES256".to_string(), "c2lnbmF0dXJl".to_string()));
    s.undeclared_spdx3_profiles = vec!["security".to_string()];
    s.dynamic_links = vec![("ref-acme-app".to_string(), "ref-libb".to_string())];
    s.vulnerabilities = vec![
        (
            "CVE-2026-0001".to_string(),
            "unknown".to_string(),
            "ref-liba".to_string(),
        ),
        (
            "CVE-2026-0002".to_string(),
            "low".to_string(),
            "ref-libb".to_string(),
        ),
    ];
    s.vulnerability_analyses = vec![
        (
            "CVE-2026-0001".to_string(),
            VulnAnalysisFixture {
                state: Some("exploitable".to_string()),
                responses: vec!["update".to_string()],
                ..VulnAnalysisFixture::default()
            },
        ),
        // A not_affected analysis carrying every analysis field: SPDX 3
        // renders the state, the justification and the detail, and has no
        // field for the response or the remediation texts.
        (
            "CVE-2026-0002".to_string(),
            VulnAnalysisFixture {
                state: Some("not_affected".to_string()),
                justification: Some("code_not_reachable".to_string()),
                responses: vec!["will_not_fix".to_string()],
                detail: Some("libb's parser is never called".to_string()),
                recommendation: Some("Upgrade libb to 2.0".to_string()),
                workaround: Some("Disable the libb parser".to_string()),
            },
        ),
    ];
    s.crypto_assets = vec![CryptoAssetFixture::algorithm("algo-aes", "AES")];
    s.supplier = Some("Acme Distribution GmbH".to_string());
    s.described = vec!["ref-libb".to_string()];
    let liba = s.component_mut("liba");
    liba.manufacturer = Some("Acme Components Ltd".to_string());
    liba.concluded_license = Some("MIT".to_string());
    liba.properties = vec![("acme:build".to_string(), "42".to_string())];
    liba.hashed_external_refs = vec![(
        "attestation".to_string(),
        "https://acme.example/attestation.pdf".to_string(),
        vec![("SHA-256".to_string(), SHA256_FILLER.to_string())],
    )];
    liba.external_refs.push((
        "bom".to_string(),
        "https://acme.example/sboms/liba.cdx.json".to_string(),
    ));
    // AI fields on a library (only an SPDX 3 AI package or dataset package
    // carries them).
    liba.model_card = Some(rule_matrix::ModelCardFixture::complete());
    liba.dataset = Some(DatasetFixture::complete());
    let model = ComponentFixture::ml_model("model");
    let mut data = ComponentFixture::dataset("data");
    let evidence = data.dataset_mut();
    evidence.data_type = "configuration".to_string();
    evidence.sensitive_data = vec!["internal".to_string()];
    let mut driver = ComponentFixture::conforming("driver");
    driver.component_type = "device-driver".to_string();
    s.components.extend([model, data, driver]);
    s
}

/// The only shape of the SPDX 3 completeness gap: a declaration and no
/// package to state it on.
fn completeness_without_packages() -> SbomFixture {
    SbomFixture {
        completeness: Some("complete".to_string()),
        ..SbomFixture::default()
    }
}

#[test]
fn every_rendering_is_read_by_its_own_parser() {
    for &encoding in Encoding::ALL {
        for fixture in [software(), everything(), completeness_without_packages()] {
            // parse_in panics when the detector picks another parser.
            let sbom = fixture.parse_in(encoding);
            assert!(
                sbom.components.len() >= fixture.components.len(),
                "{}: the rendering lost components",
                encoding.name()
            );
        }
    }
}

/// The renderers leave out exactly the fields each encoding's
/// no-counterpart list names: no list entry is stale, and no renderer drops
/// a field the list does not name (`Drops::drop_field` panics on one).
#[test]
fn renderers_drop_exactly_the_fields_their_formats_cannot_carry() {
    for &encoding in Encoding::ALL {
        let dropped: BTreeSet<&str> = [everything(), completeness_without_packages()]
            .iter()
            .flat_map(|f| f.render(encoding).dropped)
            .collect();
        let listed: BTreeSet<&str> = encoding
            .no_counterpart()
            .iter()
            .map(|(field, _)| *field)
            .collect();
        assert_eq!(
            dropped,
            listed,
            "{}: the fields the renderer drops must be the no-counterpart list \
             (left = dropped, right = listed)",
            encoding.name()
        );
        for (field, reason) in encoding.no_counterpart() {
            assert!(
                !reason.trim().is_empty(),
                "{}: {field} needs a reason",
                encoding.name()
            );
        }
    }
}

/// A fixture at its defaults, with plain software content, renders whole in
/// every encoding.
#[test]
fn plain_software_renders_without_a_drop() {
    for &encoding in Encoding::ALL {
        let rendered = software().render(encoding);
        assert!(
            rendered.dropped.is_empty(),
            "{}: dropped {:?}",
            encoding.name(),
            rendered.dropped
        );
    }
}

/// A justified not_affected analysis reads as one vulnerability record with
/// the same VEX state, justification and impact statement in every encoding
/// that carries vulnerability data: SPDX 3 states it as a not_affected
/// assessment instead of an AFFECTS relationship, which would contradict it.
#[test]
fn not_affected_analysis_reads_alike_in_every_encoding_with_vulnerabilities() {
    let mut s = software();
    s.vulnerabilities = vec![(
        "CVE-2026-0002".to_string(),
        String::new(),
        "ref-liba".to_string(),
    )];
    s.vulnerability_analyses = vec![(
        "CVE-2026-0002".to_string(),
        VulnAnalysisFixture {
            state: Some("not_affected".to_string()),
            justification: Some("code_not_reachable".to_string()),
            detail: Some("liba's parser is never called".to_string()),
            ..VulnAnalysisFixture::default()
        },
    )];
    for &encoding in Encoding::ALL_BUT_SPDX23 {
        let rendered = s.render(encoding);
        assert!(
            rendered.dropped.is_empty(),
            "{}: dropped {:?}",
            encoding.name(),
            rendered.dropped
        );
        let sbom = s.parse_in(encoding);
        let records: Vec<_> = sbom
            .all_vulnerabilities()
            .into_iter()
            .filter(|(_, v)| v.id == "CVE-2026-0002")
            .collect();
        assert_eq!(records.len(), 1, "{}: one record", encoding.name());
        let vex = records[0]
            .1
            .vex_status
            .as_ref()
            .unwrap_or_else(|| panic!("{}: no VEX status", encoding.name()));
        assert_eq!(vex.status, VexState::NotAffected, "{}", encoding.name());
        assert_eq!(
            vex.justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath),
            "{}",
            encoding.name()
        );
        assert_eq!(
            vex.impact_statement.as_deref(),
            Some("liba's parser is never called"),
            "{}",
            encoding.name()
        );
    }
}

/// What one component normalizes to, format ids aside.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentSummary {
    name: String,
    version: Option<String>,
    purl: Option<String>,
    cpes: Vec<String>,
    supplier: Option<String>,
    hashes: Vec<String>,
    declared: Vec<String>,
    copyright: Option<String>,
    description: Option<String>,
}

fn summary(sbom: &NormalizedSbom) -> (Vec<ComponentSummary>, Vec<(String, String)>) {
    let mut components: Vec<ComponentSummary> = sbom
        .components
        .values()
        .map(|c| ComponentSummary {
            name: c.name.clone(),
            version: c.version.clone(),
            purl: c.identifiers.purl.clone(),
            cpes: c.identifiers.cpe.clone(),
            supplier: c.supplier.as_ref().map(|s| s.name.clone()),
            hashes: c
                .hashes
                .iter()
                .map(|h| format!("{:?}:{}", h.algorithm, h.value))
                .collect(),
            declared: c
                .licenses
                .declared
                .iter()
                .map(|l| l.expression.clone())
                .collect(),
            copyright: c.copyright.clone(),
            description: c.description.clone(),
        })
        .collect();
    components.sort();
    let name = |id| {
        sbom.components
            .get(id)
            .map_or_else(String::new, |c| c.name.clone())
    };
    let mut edges: Vec<(String, String)> = sbom
        .edges
        .iter()
        .map(|e| (name(&e.from), name(&e.to)))
        .collect();
    edges.sort();
    (components, edges)
}

/// The renderers write every field where the parsers read it: plain software
/// normalizes to the same components and graph, the same creators, and the
/// same document name, serial number, timestamp, disclosure URL and support
/// end date in every encoding — but for the end of support, which the SPDX
/// 3 parser does not lift from the root package (an open gap the matrices
/// name). Since v0.4.0 every parser lifts the disclosure URL by one rule:
/// the primary's URL-shaped advisories reference.
#[test]
fn plain_software_normalizes_alike_in_every_encoding() {
    let reference = software().parse_in(Encoding::CycloneDxJson);
    let creators = |sbom: &NormalizedSbom| -> Vec<(CreatorType, String)> {
        let mut c: Vec<_> = sbom
            .document
            .creators
            .iter()
            .map(|c| (c.creator_type.clone(), c.name.replace(['-', ' '], "")))
            .collect();
        c.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        c
    };
    for &encoding in Encoding::ALL {
        let sbom = software().parse_in(encoding);
        let enc = encoding.name();
        assert_eq!(
            summary(&sbom),
            summary(&reference),
            "{enc}: components and graph"
        );
        assert_eq!(creators(&sbom), creators(&reference), "{enc}: creators");
        let doc = &sbom.document;
        assert_eq!(doc.name, reference.document.name, "{enc}: document name");
        assert_eq!(
            doc.serial_number, reference.document.serial_number,
            "{enc}: serial number"
        );
        assert_eq!(doc.created, reference.document.created, "{enc}: timestamp");
        assert!(
            sbom.primary_component_id.is_some(),
            "{enc}: the primary component"
        );
        assert_eq!(
            doc.vulnerability_disclosure_url.as_deref(),
            Some("https://acme.example/security/advisories"),
            "{enc}: disclosure URL"
        );
        if encoding != Encoding::Spdx3JsonLd {
            assert_eq!(
                doc.support_end_date, reference.document.support_end_date,
                "{enc}: support end date"
            );
        }
    }
}

/// The manufacturer evidence of the described product normalizes alike
/// where a format has it: a component manufacturer and the document's
/// supplier in both CycloneDX encodings, the primary's supplier in all
/// four, and a second described product in both SPDX encodings.
#[test]
fn manufacturer_evidence_normalizes_alike_where_a_format_has_it() {
    let mut s = software();
    s.supplier = Some("Acme Distribution GmbH".to_string());
    s.primary_mut().manufacturer = Some("Acme Networks GmbH".to_string());
    for &encoding in Encoding::CYCLONEDX {
        let sbom = s.parse_in(encoding);
        let enc = encoding.name();
        let primary = sbom.primary_component().expect("the primary");
        assert_eq!(
            primary.manufacturer.as_ref().map(|m| m.name.as_str()),
            Some("Acme Networks GmbH"),
            "{enc}: component manufacturer"
        );
        assert_eq!(
            sbom.document.supplier.as_ref().map(|o| o.name.as_str()),
            Some("Acme Distribution GmbH"),
            "{enc}: document supplier"
        );
    }
    for &encoding in Encoding::ALL {
        let sbom = s.parse_in(encoding);
        assert_eq!(
            sbom.primary_component()
                .and_then(|p| p.supplier.as_ref())
                .map(|o| o.name.as_str()),
            Some("Acme Components Ltd"),
            "{}: the primary's supplier",
            encoding.name()
        );
    }

    let mut s = software();
    s.described = vec!["ref-libb".to_string()];
    for &encoding in Encoding::SPDX {
        let sbom = s.parse_in(encoding);
        let described: Vec<&str> = sbom
            .described_components()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            described,
            vec!["acme-app", "libb"],
            "{}: described components",
            encoding.name()
        );
    }
}

/// An AI-BOM: a model whose card declares every element the AI profiles
/// read, and the dataset it was trained on.
fn ai_bom() -> SbomFixture {
    let mut primary = ComponentFixture::conforming("acme-assistant");
    primary.component_type = "application".to_string();
    SbomFixture {
        timestamp: Some("2026-10-01T00:00:00Z".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        primary: Some(primary),
        components: vec![
            ComponentFixture::ml_model("sentiment-bert"),
            ComponentFixture::dataset("reviews"),
        ],
        dependencies: vec![(
            "ref-acme-assistant".to_string(),
            vec!["ref-sentiment-bert".to_string()],
        )],
        ..SbomFixture::default()
    }
}

/// The model card normalizes alike in every encoding that has one: the
/// architecture family, training datasets, use case, limitation, metric and
/// training energy of the CycloneDX JSON card come out of the XML
/// `<modelCard>` and the SPDX 3 AI package too.
#[test]
fn model_card_normalizes_alike_in_every_encoding_with_an_ai_profile() {
    let model = |encoding: Encoding| {
        let sbom = ai_bom().parse_in(encoding);
        let c = sbom
            .components
            .values()
            .find(|c| c.name == "sentiment-bert")
            .expect("the model")
            .clone();
        let ml = c.ml_model.expect("model metadata");
        let metrics: Vec<(Option<String>, Option<String>)> = ml
            .performance_metrics
            .iter()
            .map(|m| (m.metric_type.clone(), m.value.clone()))
            .collect();
        (
            ml.architecture_family,
            ml.training_datasets.len(),
            ml.use_cases,
            ml.limitations,
            metrics,
            ml.energy_kwh_training,
        )
    };
    let reference = model(Encoding::CycloneDxJson);
    assert_eq!(reference.0.as_deref(), Some("transformer"));
    for &encoding in Encoding::ALL_BUT_SPDX23 {
        assert_eq!(model(encoding), reference, "{}", encoding.name());
    }
}

/// A bom-ref equal to its component's name stands for a component with no
/// identifier of its own, in every encoding; any other becomes the format's
/// own element id.
#[test]
fn element_ids_follow_each_format() {
    let mut fixture = software();
    fixture.component_mut("libb").bom_ref = "libb".to_string();
    fixture.dependencies[1].1 = vec!["libb".to_string()];
    for &encoding in Encoding::ALL {
        let sbom = fixture.parse_in(encoding);
        let id = |name: &str| {
            sbom.components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.identifiers.format_id.clone())
                .expect("component present")
        };
        let expected = match encoding {
            Encoding::CycloneDxJson | Encoding::CycloneDxXml => "ref-liba".to_string(),
            Encoding::Spdx23Json => "SPDXRef-ref-liba".to_string(),
            Encoding::Spdx3JsonLd => "https://acme.example/spdx/rule-matrix/ref-liba".to_string(),
        };
        assert_eq!(id("liba"), expected, "{}", encoding.name());
        assert_eq!(id("libb"), "libb", "{}", encoding.name());
    }
}
