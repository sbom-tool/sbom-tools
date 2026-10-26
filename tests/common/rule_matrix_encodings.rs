//! The format axis of the rule matrix: one [`SbomFixture`] rendered as
//! CycloneDX JSON, CycloneDX XML, SPDX 2.3 JSON or SPDX 3.0.1 JSON-LD.
//!
//! Each renderer writes every DSL field to the element its format has for
//! it, named and shaped the way the parsers in `src/parsers/` read it, so a
//! verdict that differs between two encodings of one fixture is either a
//! format difference a matrix row declares or a bug. Where a format has a
//! field the parser does not read (SPDX 3 `software_sbomType`, agent emails,
//! `validUntilTime`, `hasDynamicLink`; CycloneDX
//! `licenses[].acknowledgement`), the renderer still writes it: a parser gap
//! must show up as a failing case, never as a field the renderer quietly
//! left out.
//!
//! A field the format has no counterpart for at all is left out and reported
//! in [`Rendered::dropped`]. [`Encoding::no_counterpart`] lists every such
//! field with the reason, and a renderer that drops a field the list does
//! not name panics, so the list stays the complete account of what each
//! encoding cannot say. Fields at their [`SbomFixture::default`] value are
//! not reported: every fixture sets them, and they decide no case.

use super::{
    ComponentFixture, CryptoAssetFixture, DatasetFixture, ModelCardFixture, SbomFixture,
    VulnAnalysisFixture,
};
use sbom_tools::parsers::ParserKind;
use std::collections::{BTreeMap, BTreeSet};

/// One of the four encodings every matrix entry runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// CycloneDX JSON, the DSL's reference encoding.
    CycloneDxJson,
    /// CycloneDX XML.
    CycloneDxXml,
    /// SPDX 2.3 JSON.
    Spdx23Json,
    /// SPDX 3.0.1 JSON-LD in the canonical `@graph` serialization.
    Spdx3JsonLd,
}

impl Encoding {
    /// Every encoding, in matrix order.
    pub const ALL: &'static [Self] = &[
        Self::CycloneDxJson,
        Self::CycloneDxXml,
        Self::Spdx23Json,
        Self::Spdx3JsonLd,
    ];
    /// The two CycloneDX encodings.
    pub const CYCLONEDX: &'static [Self] = &[Self::CycloneDxJson, Self::CycloneDxXml];
    /// The two SPDX encodings.
    pub const SPDX: &'static [Self] = &[Self::Spdx23Json, Self::Spdx3JsonLd];
    /// Every encoding but SPDX 2.3.
    pub const ALL_BUT_SPDX23: &'static [Self] =
        &[Self::CycloneDxJson, Self::CycloneDxXml, Self::Spdx3JsonLd];
    /// Every encoding but SPDX 3.
    pub const ALL_BUT_SPDX3: &'static [Self] =
        &[Self::CycloneDxJson, Self::CycloneDxXml, Self::Spdx23Json];

    pub fn name(self) -> &'static str {
        match self {
            Self::CycloneDxJson => "CycloneDX JSON",
            Self::CycloneDxXml => "CycloneDX XML",
            Self::Spdx23Json => "SPDX 2.3 JSON",
            Self::Spdx3JsonLd => "SPDX 3 JSON-LD",
        }
    }

    /// The parser and variant the format detector must pick for a
    /// rendering, so a fixture never runs through the wrong parser.
    pub fn expected_detection(self) -> (ParserKind, &'static str) {
        match self {
            Self::CycloneDxJson => (ParserKind::CycloneDx, "JSON"),
            Self::CycloneDxXml => (ParserKind::CycloneDx, "XML"),
            Self::Spdx23Json => (ParserKind::Spdx, "JSON"),
            Self::Spdx3JsonLd => (ParserKind::Spdx3, "JSON-LD"),
        }
    }

    /// The DSL fields this encoding has no counterpart for, with the reason.
    /// A renderer leaves such a field out when a fixture sets it, and reports
    /// it in [`Rendered::dropped`].
    pub fn no_counterpart(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::CycloneDxJson => CYCLONEDX_JSON_GAPS,
            Self::CycloneDxXml => CYCLONEDX_XML_GAPS,
            Self::Spdx23Json => SPDX23_GAPS,
            Self::Spdx3JsonLd => SPDX3_GAPS,
        }
    }
}

const SPDX_VERSION_GAP: (&str, &str) = (
    "spdx_version",
    "CycloneDX documents carry a CycloneDX specVersion, not an SPDX version",
);
const PROFILES_GAP: (&str, &str) = (
    "undeclared_spdx3_profiles",
    "only SPDX 3 documents declare profile conformance",
);
const DYNAMIC_LINKS_GAP: (&str, &str) = (
    "dynamic_links",
    "CycloneDX dependencies carry no link type; dynamic links are SPDX relationships",
);
const CONCLUDED_LICENSE_GAP: (&str, &str) = (
    "component.concluded_license",
    "a concluded licence before CycloneDX 1.6, which introduced licenses[].acknowledgement \
     (the parser reads it as no more than a licence, as it reads every CycloneDX licence)",
);

const CYCLONEDX_JSON_GAPS: &[(&str, &str)] = &[
    SPDX_VERSION_GAP,
    PROFILES_GAP,
    DYNAMIC_LINKS_GAP,
    CONCLUDED_LICENSE_GAP,
];

const CYCLONEDX_XML_GAPS: &[(&str, &str)] = &[
    (
        "spec_version",
        "an empty specVersion: XML carries the version in the bom namespace, and a namespace \
         without one reads as 1.4",
    ),
    SPDX_VERSION_GAP,
    PROFILES_GAP,
    DYNAMIC_LINKS_GAP,
    CONCLUDED_LICENSE_GAP,
];

const SPDX_SPEC_VERSION_GAP: (&str, &str) = (
    "spec_version",
    "a CycloneDX specVersion outside 1.4-1.7 (the versions no CycloneDX note or floor singles \
     out): SPDX documents carry their own version, set by spdx_version",
);
const SPDX_DOC_VERSION_GAP: (&str, &str) = (
    "doc_version",
    "a document revision other than 1: SPDX has no document revision counter",
);
const SPDX_CRYPTO_GAP: (&str, &str) = (
    "crypto_assets",
    "SPDX 2.3 and SPDX 3.0 have no cryptographic-asset model (CycloneDX 1.6+ cryptoProperties)",
);
const SPDX_PROPERTIES_GAP: (&str, &str) = (
    "component.properties",
    "SPDX packages carry no name/value properties",
);
const SPDX_REF_HASHES_GAP: (&str, &str) = (
    "component.hashed_external_refs.hashes",
    "SPDX external references carry no hash of the referenced document",
);

const SPDX23_GAPS: &[(&str, &str)] = &[
    SPDX_SPEC_VERSION_GAP,
    SPDX_DOC_VERSION_GAP,
    (
        "lifecycles",
        "SPDX 2.3 has no lifecycle phase field (CISA 2026 and FSCT ask none of SPDX 2.x)",
    ),
    ("completeness", "SPDX 2.3 has no completeness declaration"),
    ("signature", "SPDX 2.3 has no in-document signature"),
    (
        "vulnerabilities",
        "SPDX 2.3 documents carry no vulnerability data",
    ),
    (
        "vulnerability_analyses",
        "SPDX 2.3 documents carry no vulnerability data",
    ),
    SPDX_CRYPTO_GAP,
    PROFILES_GAP,
    (
        "component.type",
        "a component type no SPDX 2.3 primaryPackagePurpose names (machine-learning-model, \
         platform, cryptographic-asset, …)",
    ),
    SPDX_PROPERTIES_GAP,
    SPDX_REF_HASHES_GAP,
    ("component.model_card", "SPDX 2.3 has no AI profile"),
    ("component.dataset", "SPDX 2.3 has no dataset profile"),
];

const SPDX3_GAPS: &[(&str, &str)] = &[
    SPDX_SPEC_VERSION_GAP,
    SPDX_DOC_VERSION_GAP,
    (
        "completeness",
        "SPDX 3 states completeness on relationships, and a document without packages has none \
         to carry it",
    ),
    (
        "vulnerabilities.rating",
        "a rating severity CVSS has no band for (e.g. unknown): the parser reads a severity only \
         from a CVSS assessment's score",
    ),
    (
        "vulnerability_analyses",
        "an analysis in a state other than not_affected, which is rendered as a \
         VexNotAffectedVulnAssessmentRelationship: every case that sets another state is about \
         a VEX response, and SPDX 3 has no VEX response field (the parser infers a response \
         from the action statement text and builds no remediation record from SPDX 3)",
    ),
    (
        "vulnerability_analyses.responses",
        "a VEX response on a not_affected analysis: SPDX 3 has no VEX response field",
    ),
    (
        "vulnerability_analyses.recommendation",
        "a recommendation on a not_affected analysis: an SPDX 3 not_affected assessment \
         carries no action statement",
    ),
    (
        "vulnerability_analyses.workaround",
        "a workaround on a not_affected analysis: an SPDX 3 not_affected assessment carries \
         no action statement",
    ),
    SPDX_CRYPTO_GAP,
    (
        "component.type",
        "a component type no SPDX 3.0.1 software_primaryPurpose names (cryptographic-asset, …)",
    ),
    SPDX_PROPERTIES_GAP,
    SPDX_REF_HASHES_GAP,
    (
        "component.external_refs",
        "a CycloneDX reference type with no SPDX 3.0.1 externalRefType term (bom, …)",
    ),
    (
        "component.model_card",
        "AI fields on a component that is no machine-learning-model: SPDX 3 carries them only \
         on an ai_AIPackage",
    ),
    (
        "component.dataset",
        "dataset fields on a component that is no data component: SPDX 3 carries them only on a \
         dataset_DatasetPackage",
    ),
    (
        "component.dataset.data_type",
        "a componentData type other than dataset: dataset_datasetType is a data modality, not a \
         kind of data",
    ),
    (
        "component.dataset.sensitive_data",
        "a sensitivity classification other than public or personal data: SPDX 3 classifies a \
         dataset only by a TLP confidentiality level and a personal-information flag",
    ),
];

/// A fixture rendered in one encoding.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub encoding: Encoding,
    pub text: String,
    /// The DSL fields the fixture sets that this encoding has no
    /// counterpart for, which the renderer left out.
    pub dropped: BTreeSet<&'static str>,
}

/// The drops of one rendering, held to the encoding's no-counterpart list.
struct Drops {
    encoding: Encoding,
    fields: BTreeSet<&'static str>,
}

impl Drops {
    fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            fields: BTreeSet::new(),
        }
    }

    fn drop_field(&mut self, field: &'static str) {
        assert!(
            self.encoding
                .no_counterpart()
                .iter()
                .any(|(listed, _)| *listed == field),
            "the {} renderer dropped `{field}`, which Encoding::no_counterpart does not list: \
             render it, or list it with the reason the format cannot carry it",
            self.encoding.name()
        );
        self.fields.insert(field);
    }
}

impl SbomFixture {
    /// Render the fixture in `encoding`.
    pub fn render(&self, encoding: Encoding) -> Rendered {
        let mut drops = Drops::new(encoding);
        let text = match encoding {
            Encoding::CycloneDxJson => self.cyclonedx_json(&mut drops),
            Encoding::CycloneDxXml => self.cyclonedx_xml(&mut drops),
            Encoding::Spdx23Json => self.spdx23_json(&mut drops),
            Encoding::Spdx3JsonLd => self.spdx3_json_ld(&mut drops),
        };
        Rendered {
            encoding,
            text,
            dropped: drops.fields,
        }
    }

    /// Render the CycloneDX JSON document.
    pub fn to_json_string(&self) -> String {
        self.render(Encoding::CycloneDxJson).text
    }

    /// Every component of the document, depth first: the primary, then the
    /// listed components, each followed by its nested children.
    pub(super) fn all_components(&self) -> Vec<&ComponentFixture> {
        fn walk<'a>(c: &'a ComponentFixture, out: &mut Vec<&'a ComponentFixture>) {
            out.push(c);
            for child in &c.children {
                walk(child, out);
            }
        }
        let mut out = Vec::new();
        for c in self.primary.iter().chain(&self.components) {
            walk(c, &mut out);
        }
        out
    }

    /// The element id `encoding` gives the component (or crypto asset) a
    /// bom-ref names. A bom-ref equal to its component's name stands for a
    /// component without an identifier of its own (the CycloneDX parser
    /// falls back to the name), so it is written verbatim: no `SPDXRef-`
    /// prefix in SPDX 2.3, no IRI in SPDX 3.
    pub(super) fn element_id(&self, encoding: Encoding, bom_ref: &str) -> String {
        let verbatim = self
            .all_components()
            .iter()
            .any(|c| c.bom_ref == bom_ref && c.name == bom_ref);
        match encoding {
            Encoding::CycloneDxJson | Encoding::CycloneDxXml => bom_ref.to_string(),
            _ if verbatim => bom_ref.to_string(),
            Encoding::Spdx23Json => format!("SPDXRef-{}", spdx2_id_chars(bom_ref)),
            Encoding::Spdx3JsonLd => format!("{SPDX3_NS}{bom_ref}"),
        }
    }

    fn drop_neutral_fields(&self, drops: &mut Drops) {
        let cdx = matches!(
            drops.encoding,
            Encoding::CycloneDxJson | Encoding::CycloneDxXml
        );
        if cdx {
            if self.spdx_version.is_some() {
                drops.drop_field("spdx_version");
            }
            if !self.undeclared_spdx3_profiles.is_empty() {
                drops.drop_field("undeclared_spdx3_profiles");
            }
            if !self.dynamic_links.is_empty() {
                drops.drop_field("dynamic_links");
            }
            if !self.has_license_acknowledgement()
                && self
                    .all_components()
                    .iter()
                    .any(|c| c.concluded_license.is_some())
            {
                drops.drop_field("component.concluded_license");
            }
        } else {
            if !NEUTRAL_CDX_VERSIONS.contains(&self.spec_version.as_str()) {
                drops.drop_field("spec_version");
            }
            if self.doc_version.is_some_and(|v| v != 1) {
                drops.drop_field("doc_version");
            }
            if !self.crypto_assets.is_empty() {
                drops.drop_field("crypto_assets");
            }
            if self
                .all_components()
                .iter()
                .any(|c| !c.properties.is_empty())
            {
                drops.drop_field("component.properties");
            }
            if self.all_components().iter().any(|c| {
                c.hashed_external_refs
                    .iter()
                    .any(|(_, _, hashes)| !hashes.is_empty())
            }) {
                drops.drop_field("component.hashed_external_refs.hashes");
            }
        }
    }

    /// Whether the CycloneDX version has `licenses[].acknowledgement`
    /// (1.6+), the counterpart of a concluded licence.
    fn has_license_acknowledgement(&self) -> bool {
        let mut parts = self.spec_version.split('.').map(str::parse::<u32>);
        matches!(
            (parts.next(), parts.next()),
            (Some(Ok(major)), Some(Ok(minor))) if (major, minor) >= (1, 6)
        )
    }
}

/// CycloneDX versions that no CycloneDX format note, version floor or
/// version gate singles out; the SPDX renderers write their own version for
/// these, and report any other as dropped.
const NEUTRAL_CDX_VERSIONS: &[&str] = &["1.4", "1.5", "1.6", "1.7"];

/// The CycloneDX 1.5+ lifecycle phases (anything else is a named lifecycle).
const CDX_LIFECYCLE_PHASES: &[&str] = &[
    "design",
    "pre-build",
    "build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
];

fn cdx_lifecycle_json(lifecycle: &str) -> serde_json::Value {
    if CDX_LIFECYCLE_PHASES.contains(&lifecycle) {
        serde_json::json!({ "phase": lifecycle })
    } else {
        serde_json::json!({ "name": lifecycle })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CycloneDX JSON
// ═══════════════════════════════════════════════════════════════════════

impl SbomFixture {
    fn cyclonedx_json(&self, drops: &mut Drops) -> String {
        self.drop_neutral_fields(drops);
        let mut doc = serde_json::Map::new();
        doc.insert("bomFormat".into(), serde_json::json!("CycloneDX"));
        doc.insert("specVersion".into(), serde_json::json!(self.spec_version));
        if let Some(version) = self.doc_version {
            doc.insert("version".into(), serde_json::json!(version));
        }
        if let Some(serial) = &self.serial_number {
            doc.insert("serialNumber".into(), serde_json::json!(serial));
        }

        let mut metadata = serde_json::Map::new();
        if let Some(ts) = &self.timestamp {
            metadata.insert("timestamp".into(), serde_json::json!(ts));
        }
        if !self.lifecycles.is_empty() {
            let lifecycles: Vec<_> = self
                .lifecycles
                .iter()
                .map(|l| cdx_lifecycle_json(l))
                .collect();
            metadata.insert("lifecycles".into(), serde_json::json!(lifecycles));
        }
        if !self.tools.is_empty() {
            let tools: Vec<_> = self
                .tools
                .iter()
                .map(|(name, version)| serde_json::json!({ "name": name, "version": version }))
                .collect();
            metadata.insert("tools".into(), serde_json::json!(tools));
        }
        if !self.authors.is_empty() {
            let authors: Vec<_> = self
                .authors
                .iter()
                .map(|(name, email)| {
                    let mut a = serde_json::Map::new();
                    a.insert("name".into(), serde_json::json!(name));
                    if let Some(email) = email {
                        a.insert("email".into(), serde_json::json!(email));
                    }
                    serde_json::Value::Object(a)
                })
                .collect();
            metadata.insert("authors".into(), serde_json::json!(authors));
        }
        if let Some((name, email)) = &self.manufacturer {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), serde_json::json!(name));
            if let Some(email) = email {
                m.insert("contact".into(), serde_json::json!([{ "email": email }]));
            }
            metadata.insert("manufacturer".into(), serde_json::Value::Object(m));
        }
        let acknowledgement = self.has_license_acknowledgement();
        if let Some(primary) = &self.primary {
            metadata.insert("component".into(), primary.cyclonedx_json(acknowledgement));
        }
        if !metadata.is_empty() {
            doc.insert("metadata".into(), serde_json::Value::Object(metadata));
        }

        let components: Vec<_> = self
            .components
            .iter()
            .map(|c| c.cyclonedx_json(acknowledgement))
            .chain(
                self.crypto_assets
                    .iter()
                    .map(CryptoAssetFixture::cyclonedx_json),
            )
            .collect();
        doc.insert("components".into(), serde_json::json!(components));

        if !self.dependencies.is_empty() {
            let deps: Vec<_> = self
                .dependencies
                .iter()
                .map(|(from, depends_on)| {
                    serde_json::json!({ "ref": from, "dependsOn": depends_on })
                })
                .collect();
            doc.insert("dependencies".into(), serde_json::json!(deps));
        }

        if !self.vulnerabilities.is_empty() {
            let vulns: Vec<_> = self
                .vulnerabilities
                .iter()
                .map(|(id, severity, affected_ref)| {
                    let mut v = serde_json::Map::new();
                    v.insert("id".into(), serde_json::json!(id));
                    if !severity.is_empty() {
                        v.insert(
                            "ratings".into(),
                            serde_json::json!([{ "severity": severity }]),
                        );
                    }
                    if let Some(analysis) = self.analysis_of(id) {
                        if let Some(text) = &analysis.recommendation {
                            v.insert("recommendation".into(), serde_json::json!(text));
                        }
                        if let Some(text) = &analysis.workaround {
                            v.insert("workaround".into(), serde_json::json!(text));
                        }
                        let mut a = serde_json::Map::new();
                        if let Some(state) = &analysis.state {
                            a.insert("state".into(), serde_json::json!(state));
                        }
                        if let Some(justification) = &analysis.justification {
                            a.insert("justification".into(), serde_json::json!(justification));
                        }
                        if !analysis.responses.is_empty() {
                            a.insert("response".into(), serde_json::json!(analysis.responses));
                        }
                        if let Some(detail) = &analysis.detail {
                            a.insert("detail".into(), serde_json::json!(detail));
                        }
                        if !a.is_empty() {
                            v.insert("analysis".into(), serde_json::Value::Object(a));
                        }
                    }
                    v.insert(
                        "affects".into(),
                        serde_json::json!([{ "ref": affected_ref }]),
                    );
                    serde_json::Value::Object(v)
                })
                .collect();
            doc.insert("vulnerabilities".into(), serde_json::json!(vulns));
        }

        if let Some(aggregate) = &self.completeness {
            doc.insert(
                "compositions".into(),
                serde_json::json!([{ "aggregate": aggregate }]),
            );
        }

        if let Some((algorithm, value)) = &self.signature {
            doc.insert(
                "signature".into(),
                serde_json::json!({ "algorithm": algorithm, "value": value }),
            );
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(doc))
            .expect("fixture JSON must serialize")
    }

    /// The analysis declared for the embedded vulnerability `id`, if any.
    fn analysis_of(&self, id: &str) -> Option<&VulnAnalysisFixture> {
        self.vulnerability_analyses
            .iter()
            .find(|(vuln_id, _)| vuln_id == id)
            .map(|(_, analysis)| analysis)
    }
}

impl ComponentFixture {
    /// The component; `acknowledgement` says whether the CycloneDX version
    /// can mark a licence concluded (1.6+).
    fn cyclonedx_json(&self, acknowledgement: bool) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), serde_json::json!(self.component_type));
        obj.insert("bom-ref".into(), serde_json::json!(self.bom_ref));
        obj.insert("name".into(), serde_json::json!(self.name));
        if let Some(version) = &self.version {
            obj.insert("version".into(), serde_json::json!(version));
        }
        if let Some(purl) = &self.purl {
            obj.insert("purl".into(), serde_json::json!(purl));
        }
        if let Some(cpe) = &self.cpe {
            obj.insert("cpe".into(), serde_json::json!(cpe));
        }
        if let Some(supplier) = &self.supplier {
            obj.insert("supplier".into(), serde_json::json!({ "name": supplier }));
        }
        if let Some(description) = &self.description {
            obj.insert("description".into(), serde_json::json!(description));
        }
        if let Some(copyright) = &self.copyright {
            obj.insert("copyright".into(), serde_json::json!(copyright));
        }
        if !self.hashes.is_empty() {
            obj.insert("hashes".into(), cdx_hashes_json(&self.hashes));
        }
        if !self.external_refs.is_empty() || !self.hashed_external_refs.is_empty() {
            let hashed = self
                .hashed_external_refs
                .iter()
                .map(|(ref_type, url, hashes)| {
                    serde_json::json!({ "type": ref_type, "url": url, "hashes": cdx_hashes_json(hashes) })
                });
            let refs: Vec<_> = self
                .external_refs
                .iter()
                .map(|(ref_type, url)| serde_json::json!({ "type": ref_type, "url": url }))
                .chain(hashed)
                .collect();
            obj.insert("externalReferences".into(), serde_json::json!(refs));
        }
        let concluded = self.concluded_license.iter().filter(|_| acknowledgement);
        if !self.licenses.is_empty() || concluded.clone().next().is_some() {
            let licenses: Vec<_> = self
                .licenses
                .iter()
                .map(|id| serde_json::json!({ "license": { "id": id } }))
                .chain(concluded.map(|id| {
                    serde_json::json!({ "license": { "id": id, "acknowledgement": "concluded" } })
                }))
                .collect();
            obj.insert("licenses".into(), serde_json::json!(licenses));
        }
        let properties = self.cyclonedx_properties();
        if !properties.is_empty() {
            let props: Vec<_> = properties
                .iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect();
            obj.insert("properties".into(), serde_json::json!(props));
        }
        if let Some(card) = &self.model_card {
            obj.insert("modelCard".into(), card.cyclonedx_json());
        }
        if let Some(dataset) = &self.dataset {
            obj.insert("data".into(), serde_json::json!([dataset.cyclonedx_json()]));
        }
        if !self.children.is_empty() {
            let children: Vec<_> = self
                .children
                .iter()
                .map(|c| c.cyclonedx_json(acknowledgement))
                .collect();
            obj.insert("components".into(), serde_json::json!(children));
        }
        serde_json::Value::Object(obj)
    }

    /// The CycloneDX properties: the end of support (which the parser lifts
    /// from the primary component into the document's support end date),
    /// then the free-form ones.
    fn cyclonedx_properties(&self) -> Vec<(String, String)> {
        self.support_end
            .iter()
            .map(|date| ("endOfSupport".to_string(), date.clone()))
            .chain(self.properties.iter().cloned())
            .collect()
    }
}

fn cdx_hashes_json(hashes: &[(String, String)]) -> serde_json::Value {
    let hashes: Vec<_> = hashes
        .iter()
        .map(|(alg, content)| serde_json::json!({ "alg": alg, "content": content }))
        .collect();
    serde_json::json!(hashes)
}

impl ModelCardFixture {
    fn cyclonedx_json(&self) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        if let Some(family) = &self.architecture_family {
            params.insert("architectureFamily".into(), serde_json::json!(family));
        }
        if let Some(architecture) = &self.model_architecture {
            params.insert("modelArchitecture".into(), serde_json::json!(architecture));
        }
        if !self.datasets.is_empty() {
            let datasets: Vec<_> = self
                .datasets
                .iter()
                .map(|r| serde_json::json!({ "ref": r }))
                .collect();
            params.insert("datasets".into(), serde_json::json!(datasets));
        }

        let mut considerations = serde_json::Map::new();
        if !self.use_cases.is_empty() {
            considerations.insert("useCases".into(), serde_json::json!(self.use_cases));
        }
        if !self.technical_limitations.is_empty() {
            considerations.insert(
                "technicalLimitations".into(),
                serde_json::json!(self.technical_limitations),
            );
        }
        if let Some(kwh) = self.training_energy_kwh {
            considerations.insert(
                "environmentalConsiderations".into(),
                serde_json::json!({
                    "energyConsumptions": [{
                        "activity": "training",
                        "activityEnergyCost": { "value": kwh, "unit": "kWh" },
                    }],
                }),
            );
        }

        let mut card = serde_json::Map::new();
        if !params.is_empty() {
            card.insert("modelParameters".into(), serde_json::Value::Object(params));
        }
        if !considerations.is_empty() {
            card.insert(
                "considerations".into(),
                serde_json::Value::Object(considerations),
            );
        }
        if !self.performance_metrics.is_empty() {
            let metrics: Vec<_> = self
                .performance_metrics
                .iter()
                .map(|(metric, value)| serde_json::json!({ "type": metric, "value": value }))
                .collect();
            card.insert(
                "quantitativeAnalysis".into(),
                serde_json::json!({ "performanceMetrics": metrics }),
            );
        }
        serde_json::Value::Object(card)
    }
}

impl DatasetFixture {
    fn cyclonedx_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), serde_json::json!(self.data_type));
        if !self.sensitive_data.is_empty() {
            obj.insert(
                "sensitiveData".into(),
                serde_json::json!(self.sensitive_data),
            );
        }
        if !self.governance_owners.is_empty() {
            let owners: Vec<_> = self
                .governance_owners
                .iter()
                .map(|name| serde_json::json!({ "organization": { "name": name } }))
                .collect();
            obj.insert("governance".into(), serde_json::json!({ "owners": owners }));
        }
        serde_json::Value::Object(obj)
    }
}

impl CryptoAssetFixture {
    fn cyclonedx_json(&self) -> serde_json::Value {
        let mut crypto = serde_json::Map::new();
        crypto.insert("assetType".into(), serde_json::json!(self.asset_type));
        if let Some(oid) = &self.oid {
            crypto.insert("oid".into(), serde_json::json!(oid));
        }
        if let Some(algo) = &self.algorithm {
            let mut props = serde_json::json!({
                "primitive": algo.primitive,
                "algorithmFamily": algo.family,
                "parameterSetIdentifier": algo.parameter_set,
                "mode": algo.mode,
                "ellipticCurve": algo.curve,
                "classicalSecurityLevel": algo.classical_level,
                "nistQuantumSecurityLevel": algo.quantum_level,
            });
            // Unset properties are omitted, not rendered as null.
            props
                .as_object_mut()
                .expect("algorithm properties are an object")
                .retain(|_, v| !v.is_null());
            crypto.insert("algorithmProperties".into(), props);
        }
        if let Some(sig_ref) = &self.signature_algorithm_ref {
            crypto.insert(
                "certificateProperties".into(),
                serde_json::json!({
                    "subjectName": format!("CN={}", self.name),
                    "signatureAlgorithmRef": sig_ref,
                }),
            );
        }
        if let Some((material_type, size)) = &self.material {
            let mut mat = serde_json::Map::new();
            mat.insert("type".into(), serde_json::json!(material_type));
            if let Some(size) = size {
                mat.insert("size".into(), serde_json::json!(size));
            }
            crypto.insert(
                "relatedCryptoMaterialProperties".into(),
                serde_json::Value::Object(mat),
            );
        }
        if let Some(proto) = &self.protocol {
            let mut props = serde_json::Map::new();
            props.insert("type".into(), serde_json::json!(proto.protocol_type));
            if let Some(version) = &proto.version {
                props.insert("version".into(), serde_json::json!(version));
            }
            if !proto.cipher_suites.is_empty() {
                let suites: Vec<_> = proto
                    .cipher_suites
                    .iter()
                    .map(|suite| {
                        let mut s = serde_json::json!({
                            "name": suite.name,
                            "algorithms": suite.algorithms,
                        });
                        if !suite.tls_groups.is_empty() {
                            s["tlsGroups"] = serde_json::json!(suite.tls_groups);
                        }
                        if !suite.tls_signature_schemes.is_empty() {
                            s["tlsSignatureSchemes"] =
                                serde_json::json!(suite.tls_signature_schemes);
                        }
                        s
                    })
                    .collect();
                props.insert("cipherSuites".into(), serde_json::json!(suites));
            }
            if !proto.crypto_refs.is_empty() {
                props.insert(
                    "cryptoRefArray".into(),
                    serde_json::json!(proto.crypto_refs),
                );
            }
            crypto.insert(
                "protocolProperties".into(),
                serde_json::Value::Object(props),
            );
        }
        serde_json::json!({
            "type": "cryptographic-asset",
            "bom-ref": self.bom_ref,
            "name": self.name,
            "cryptoProperties": serde_json::Value::Object(crypto),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CycloneDX XML
// ═══════════════════════════════════════════════════════════════════════

/// A minimal XML writer: escaped text and attributes, two-space indent.
struct Xml {
    out: String,
    depth: usize,
}

impl Xml {
    fn new() -> Self {
        Self {
            out: String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
            depth: 0,
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    fn start_tag(&mut self, tag: &str, attrs: &[(&str, &str)]) {
        self.indent();
        self.out.push('<');
        self.out.push_str(tag);
        for (name, value) in attrs {
            self.out.push(' ');
            self.out.push_str(name);
            self.out.push_str("=\"");
            self.out.push_str(&xml_escape(value));
            self.out.push('"');
        }
    }

    fn open(&mut self, tag: &str, attrs: &[(&str, &str)]) {
        self.start_tag(tag, attrs);
        self.out.push_str(">\n");
        self.depth += 1;
    }

    fn close(&mut self, tag: &str) {
        self.depth -= 1;
        self.indent();
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push_str(">\n");
    }

    fn leaf(&mut self, tag: &str, attrs: &[(&str, &str)], text: &str) {
        self.start_tag(tag, attrs);
        self.out.push('>');
        self.out.push_str(&xml_escape(text));
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push_str(">\n");
    }

    fn text(&mut self, tag: &str, text: &str) {
        self.leaf(tag, &[], text);
    }

    fn opt(&mut self, tag: &str, text: Option<&str>) {
        if let Some(text) = text {
            self.text(tag, text);
        }
    }

    fn empty(&mut self, tag: &str, attrs: &[(&str, &str)]) {
        self.start_tag(tag, attrs);
        self.out.push_str("/>\n");
    }

    /// `<wrapper><item>…</item>…</wrapper>`, or nothing for no items.
    fn list(&mut self, wrapper: &str, item: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }
        self.open(wrapper, &[]);
        for value in values {
            self.text(item, value);
        }
        self.close(wrapper);
    }
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

impl SbomFixture {
    fn cyclonedx_xml(&self, drops: &mut Drops) -> String {
        self.drop_neutral_fields(drops);
        if self.spec_version.is_empty() {
            drops.drop_field("spec_version");
        }
        let mut x = Xml::new();
        let xmlns = format!("http://cyclonedx.org/schema/bom/{}", self.spec_version);
        let version = self.doc_version.map(|v| v.to_string());
        let mut attrs: Vec<(&str, &str)> = vec![("xmlns", &xmlns)];
        if let Some(serial) = &self.serial_number {
            attrs.push(("serialNumber", serial));
        }
        if let Some(version) = &version {
            attrs.push(("version", version));
        }
        x.open("bom", &attrs);

        let has_metadata = self.timestamp.is_some()
            || !self.lifecycles.is_empty()
            || !self.tools.is_empty()
            || !self.authors.is_empty()
            || self.primary.is_some()
            || self.manufacturer.is_some();
        if has_metadata {
            x.open("metadata", &[]);
            x.opt("timestamp", self.timestamp.as_deref());
            if !self.lifecycles.is_empty() {
                x.open("lifecycles", &[]);
                for lifecycle in &self.lifecycles {
                    x.open("lifecycle", &[]);
                    let tag = if CDX_LIFECYCLE_PHASES.contains(&lifecycle.as_str()) {
                        "phase"
                    } else {
                        "name"
                    };
                    x.text(tag, lifecycle);
                    x.close("lifecycle");
                }
                x.close("lifecycles");
            }
            if !self.tools.is_empty() {
                x.open("tools", &[]);
                for (name, version) in &self.tools {
                    x.open("tool", &[]);
                    x.text("name", name);
                    x.text("version", version);
                    x.close("tool");
                }
                x.close("tools");
            }
            if !self.authors.is_empty() {
                x.open("authors", &[]);
                for (name, email) in &self.authors {
                    x.open("author", &[]);
                    x.text("name", name);
                    x.opt("email", email.as_deref());
                    x.close("author");
                }
                x.close("authors");
            }
            if let Some(primary) = &self.primary {
                primary.cyclonedx_xml(&mut x, self.has_license_acknowledgement());
            }
            if let Some((name, email)) = &self.manufacturer {
                x.open("manufacturer", &[]);
                x.text("name", name);
                if let Some(email) = email {
                    x.open("contact", &[]);
                    x.text("email", email);
                    x.close("contact");
                }
                x.close("manufacturer");
            }
            x.close("metadata");
        }

        x.open("components", &[]);
        for c in &self.components {
            c.cyclonedx_xml(&mut x, self.has_license_acknowledgement());
        }
        for asset in &self.crypto_assets {
            asset.cyclonedx_xml(&mut x);
        }
        x.close("components");

        if !self.dependencies.is_empty() {
            x.open("dependencies", &[]);
            for (from, depends_on) in &self.dependencies {
                if depends_on.is_empty() {
                    x.empty("dependency", &[("ref", from)]);
                    continue;
                }
                x.open("dependency", &[("ref", from)]);
                for to in depends_on {
                    x.empty("dependency", &[("ref", to)]);
                }
                x.close("dependency");
            }
            x.close("dependencies");
        }

        if let Some(aggregate) = &self.completeness {
            x.open("compositions", &[]);
            x.open("composition", &[]);
            x.text("aggregate", aggregate);
            x.close("composition");
            x.close("compositions");
        }

        if !self.vulnerabilities.is_empty() {
            x.open("vulnerabilities", &[]);
            for (id, severity, affected_ref) in &self.vulnerabilities {
                x.open("vulnerability", &[]);
                x.text("id", id);
                if !severity.is_empty() {
                    x.open("ratings", &[]);
                    x.open("rating", &[]);
                    x.text("severity", severity);
                    x.close("rating");
                    x.close("ratings");
                }
                let analysis = self.analysis_of(id);
                if let Some(analysis) = analysis {
                    x.opt("recommendation", analysis.recommendation.as_deref());
                    x.opt("workaround", analysis.workaround.as_deref());
                    if analysis.state.is_some()
                        || analysis.justification.is_some()
                        || !analysis.responses.is_empty()
                        || analysis.detail.is_some()
                    {
                        // The schema's order: state, justification,
                        // responses, detail.
                        x.open("analysis", &[]);
                        x.opt("state", analysis.state.as_deref());
                        x.opt("justification", analysis.justification.as_deref());
                        x.list("responses", "response", &analysis.responses);
                        x.opt("detail", analysis.detail.as_deref());
                        x.close("analysis");
                    }
                }
                x.open("affects", &[]);
                x.open("target", &[]);
                x.text("ref", affected_ref);
                x.close("target");
                x.close("affects");
                x.close("vulnerability");
            }
            x.close("vulnerabilities");
        }

        if let Some((algorithm, value)) = &self.signature {
            // An enveloped XML-DSig signature, read for its method and the
            // presence of a value (as JSON reads the JSF object).
            x.open(
                "Signature",
                &[("xmlns", "http://www.w3.org/2000/09/xmldsig#")],
            );
            x.open("SignedInfo", &[]);
            x.empty("SignatureMethod", &[("Algorithm", algorithm)]);
            x.close("SignedInfo");
            x.text("SignatureValue", value);
            x.close("Signature");
        }

        x.close("bom");
        x.out
    }
}

impl ComponentFixture {
    /// The component; `acknowledgement` says whether the CycloneDX version
    /// can mark a licence concluded (1.6+).
    fn cyclonedx_xml(&self, x: &mut Xml, acknowledgement: bool) {
        x.open(
            "component",
            &[("type", &self.component_type), ("bom-ref", &self.bom_ref)],
        );
        if let Some(supplier) = &self.supplier {
            x.open("supplier", &[]);
            x.text("name", supplier);
            x.close("supplier");
        }
        x.text("name", &self.name);
        x.opt("version", self.version.as_deref());
        x.opt("description", self.description.as_deref());
        if !self.hashes.is_empty() {
            cdx_hashes_xml(x, &self.hashes);
        }
        let concluded = self.concluded_license.iter().filter(|_| acknowledgement);
        if !self.licenses.is_empty() || concluded.clone().next().is_some() {
            x.open("licenses", &[]);
            for id in &self.licenses {
                x.open("license", &[]);
                x.text("id", id);
                x.close("license");
            }
            for id in concluded {
                x.open("license", &[("acknowledgement", "concluded")]);
                x.text("id", id);
                x.close("license");
            }
            x.close("licenses");
        }
        x.opt("copyright", self.copyright.as_deref());
        x.opt("cpe", self.cpe.as_deref());
        x.opt("purl", self.purl.as_deref());
        if !self.external_refs.is_empty() || !self.hashed_external_refs.is_empty() {
            x.open("externalReferences", &[]);
            for (ref_type, url) in &self.external_refs {
                x.open("reference", &[("type", ref_type)]);
                x.text("url", url);
                x.close("reference");
            }
            for (ref_type, url, hashes) in &self.hashed_external_refs {
                x.open("reference", &[("type", ref_type)]);
                x.text("url", url);
                cdx_hashes_xml(x, hashes);
                x.close("reference");
            }
            x.close("externalReferences");
        }
        let properties = self.cyclonedx_properties();
        if !properties.is_empty() {
            x.open("properties", &[]);
            for (name, value) in &properties {
                x.leaf("property", &[("name", name)], value);
            }
            x.close("properties");
        }
        if !self.children.is_empty() {
            x.open("components", &[]);
            for child in &self.children {
                child.cyclonedx_xml(x, acknowledgement);
            }
            x.close("components");
        }
        if let Some(card) = &self.model_card {
            card.cyclonedx_xml(x);
        }
        if let Some(dataset) = &self.dataset {
            dataset.cyclonedx_xml(x);
        }
        x.close("component");
    }
}

fn cdx_hashes_xml(x: &mut Xml, hashes: &[(String, String)]) {
    x.open("hashes", &[]);
    for (alg, content) in hashes {
        x.leaf("hash", &[("alg", alg)], content);
    }
    x.close("hashes");
}

impl ModelCardFixture {
    fn cyclonedx_xml(&self, x: &mut Xml) {
        x.open("modelCard", &[]);
        let has_params = self.architecture_family.is_some()
            || self.model_architecture.is_some()
            || !self.datasets.is_empty();
        if has_params {
            x.open("modelParameters", &[]);
            x.opt("architectureFamily", self.architecture_family.as_deref());
            x.opt("modelArchitecture", self.model_architecture.as_deref());
            x.list("datasets", "ref", &self.datasets);
            x.close("modelParameters");
        }
        if !self.performance_metrics.is_empty() {
            x.open("quantitativeAnalysis", &[]);
            x.open("performanceMetrics", &[]);
            for (metric, value) in &self.performance_metrics {
                x.open("performanceMetric", &[]);
                x.text("type", metric);
                x.text("value", value);
                x.close("performanceMetric");
            }
            x.close("performanceMetrics");
            x.close("quantitativeAnalysis");
        }
        let has_considerations = !self.use_cases.is_empty()
            || !self.technical_limitations.is_empty()
            || self.training_energy_kwh.is_some();
        if has_considerations {
            x.open("considerations", &[]);
            x.list("useCases", "useCase", &self.use_cases);
            x.list(
                "technicalLimitations",
                "technicalLimitation",
                &self.technical_limitations,
            );
            if let Some(kwh) = self.training_energy_kwh {
                x.open("environmentalConsiderations", &[]);
                x.open("energyConsumptions", &[]);
                x.open("energyConsumption", &[]);
                x.text("activity", "training");
                x.open("activityEnergyCost", &[]);
                x.text("value", &kwh.to_string());
                x.text("unit", "kWh");
                x.close("activityEnergyCost");
                x.close("energyConsumption");
                x.close("energyConsumptions");
                x.close("environmentalConsiderations");
            }
            x.close("considerations");
        }
        x.close("modelCard");
    }
}

impl DatasetFixture {
    fn cyclonedx_xml(&self, x: &mut Xml) {
        x.open("data", &[]);
        x.text("type", &self.data_type);
        for classification in &self.sensitive_data {
            x.text("sensitiveData", classification);
        }
        if !self.governance_owners.is_empty() {
            x.open("governance", &[]);
            x.open("owners", &[]);
            for owner in &self.governance_owners {
                x.open("owner", &[]);
                x.open("organization", &[]);
                x.text("name", owner);
                x.close("organization");
                x.close("owner");
            }
            x.close("owners");
            x.close("governance");
        }
        x.close("data");
    }
}

impl CryptoAssetFixture {
    fn cyclonedx_xml(&self, x: &mut Xml) {
        x.open(
            "component",
            &[("type", "cryptographic-asset"), ("bom-ref", &self.bom_ref)],
        );
        x.text("name", &self.name);
        x.open("cryptoProperties", &[]);
        x.text("assetType", &self.asset_type);
        if let Some(algo) = &self.algorithm {
            x.open("algorithmProperties", &[]);
            x.opt("primitive", algo.primitive.as_deref());
            x.opt("algorithmFamily", algo.family.as_deref());
            x.opt("parameterSetIdentifier", algo.parameter_set.as_deref());
            x.opt("ellipticCurve", algo.curve.as_deref());
            x.opt("mode", algo.mode.as_deref());
            if let Some(level) = algo.classical_level {
                x.text("classicalSecurityLevel", &level.to_string());
            }
            if let Some(level) = algo.quantum_level {
                x.text("nistQuantumSecurityLevel", &level.to_string());
            }
            x.close("algorithmProperties");
        }
        if let Some(sig_ref) = &self.signature_algorithm_ref {
            x.open("certificateProperties", &[]);
            x.text("subjectName", &format!("CN={}", self.name));
            x.text("signatureAlgorithmRef", sig_ref);
            x.close("certificateProperties");
        }
        if let Some((material_type, size)) = &self.material {
            x.open("relatedCryptoMaterialProperties", &[]);
            x.text("type", material_type);
            if let Some(size) = size {
                x.text("size", &size.to_string());
            }
            x.close("relatedCryptoMaterialProperties");
        }
        if let Some(proto) = &self.protocol {
            x.open("protocolProperties", &[]);
            x.text("type", &proto.protocol_type);
            x.opt("version", proto.version.as_deref());
            if !proto.cipher_suites.is_empty() {
                x.open("cipherSuites", &[]);
                for suite in &proto.cipher_suites {
                    x.open("cipherSuite", &[]);
                    x.text("name", &suite.name);
                    x.list("algorithms", "algorithm", &suite.algorithms);
                    x.list("tlsGroups", "group", &suite.tls_groups);
                    x.list(
                        "tlsSignatureSchemes",
                        "signatureScheme",
                        &suite.tls_signature_schemes,
                    );
                    x.close("cipherSuite");
                }
                x.close("cipherSuites");
            }
            for crypto_ref in &proto.crypto_refs {
                x.text("cryptoRef", crypto_ref);
            }
            x.close("protocolProperties");
        }
        x.opt("oid", self.oid.as_deref());
        x.close("cryptoProperties");
        x.close("component");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SPDX shared
// ═══════════════════════════════════════════════════════════════════════

/// The characters an SPDX 2.3 `SPDXRef-` identifier allows (letters,
/// digits, `.` and `-`); any other becomes `-`.
fn spdx2_id_chars(bom_ref: &str) -> String {
    bom_ref
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// The namespace of the SPDX 3 element IRIs.
const SPDX3_NS: &str = "https://acme.example/spdx/rule-matrix/";
/// SPDX 3.0.1 `NoneElement`: the `to` of a relationship stating that there
/// are none ("this package has no dependencies").
const SPDX3_NONE_ELEMENT: &str = "https://spdx.org/rdf/3.0.1/terms/Core/NoneElement";
/// SPDX 3.0.1 `NoAssertionElement`: an agent the document declines to name.
const SPDX3_NO_ASSERTION_ELEMENT: &str = "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement";

/// A CycloneDX hash algorithm name as SPDX 2.3 spells it (`SHA-256` →
/// `SHA256`); names SPDX 2.3 does not list are kept verbatim.
fn spdx2_hash_algorithm(alg: &str) -> String {
    match alg.to_ascii_uppercase().as_str() {
        "SHA-1" => "SHA1".to_string(),
        "SHA-256" => "SHA256".to_string(),
        "SHA-384" => "SHA384".to_string(),
        "SHA-512" => "SHA512".to_string(),
        _ => alg.to_string(),
    }
}

/// A CycloneDX hash algorithm name as an SPDX 3.0.1 `HashAlgorithm` term
/// (`SHA-256` → `sha256`, `SHA3-256` → `sha3_256`).
fn spdx3_hash_algorithm(alg: &str) -> String {
    match alg.to_ascii_uppercase().as_str() {
        "SHA-1" => "sha1".to_string(),
        "SHA-256" => "sha256".to_string(),
        "SHA-384" => "sha384".to_string(),
        "SHA-512" => "sha512".to_string(),
        "SHA3-256" => "sha3_256".to_string(),
        "SHA3-384" => "sha3_384".to_string(),
        "SHA3-512" => "sha3_512".to_string(),
        "BLAKE2B-256" => "blake2b256".to_string(),
        "BLAKE2B-384" => "blake2b384".to_string(),
        "BLAKE2B-512" => "blake2b512".to_string(),
        _ => alg.to_ascii_lowercase(),
    }
}

/// An end-of-support date (`YYYY-MM-DD`) as the RFC 3339 date-time SPDX
/// `validUntilDate` / `validUntilTime` take.
fn spdx_date_time(date: &str) -> String {
    if date.contains('T') {
        date.to_string()
    } else {
        format!("{date}T00:00:00Z")
    }
}

/// Whether a dataset sensitivity classification denotes personal data.
fn is_personal_data(classification: &str) -> bool {
    let c = classification.to_ascii_lowercase();
    c.contains("personal") || c.contains("pii")
}

impl SbomFixture {
    /// The document name: the primary component's, as the CycloneDX parser
    /// lifts it from `metadata.component`.
    fn document_name(&self) -> Option<&str> {
        self.primary.as_ref().map(|p| p.name.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SPDX 2.3 JSON
// ═══════════════════════════════════════════════════════════════════════

/// The SPDX 2.3 `primaryPackagePurpose` of a CycloneDX component type, if
/// the enumeration has one.
fn spdx2_purpose(component_type: &str) -> Option<&'static str> {
    Some(match component_type {
        "application" => "APPLICATION",
        "library" => "LIBRARY",
        "framework" => "FRAMEWORK",
        "container" => "CONTAINER",
        "operating-system" => "OPERATING-SYSTEM",
        "device" => "DEVICE",
        "firmware" => "FIRMWARE",
        "data" => "DATA",
        _ => return None,
    })
}

impl SbomFixture {
    fn spdx23_json(&self, drops: &mut Drops) -> String {
        self.drop_neutral_fields(drops);
        if !self.lifecycles.is_empty() {
            drops.drop_field("lifecycles");
        }
        if self.completeness.is_some() {
            drops.drop_field("completeness");
        }
        if self.signature.is_some() {
            drops.drop_field("signature");
        }
        if !self.vulnerabilities.is_empty() {
            drops.drop_field("vulnerabilities");
        }
        if !self.vulnerability_analyses.is_empty() {
            drops.drop_field("vulnerability_analyses");
        }
        if !self.undeclared_spdx3_profiles.is_empty() {
            drops.drop_field("undeclared_spdx3_profiles");
        }

        let id = |bom_ref: &str| self.element_id(Encoding::Spdx23Json, bom_ref);
        let mut creators = Vec::new();
        for (name, version) in &self.tools {
            creators.push(if version.is_empty() {
                format!("Tool: {name}")
            } else {
                format!("Tool: {name}-{version}")
            });
        }
        for (name, email) in &self.authors {
            creators.push(match email {
                Some(email) => format!("Person: {name} ({email})"),
                None => format!("Person: {name}"),
            });
        }
        if let Some((name, email)) = &self.manufacturer {
            creators.push(match email {
                Some(email) => format!("Organization: {name} ({email})"),
                None => format!("Organization: {name}"),
            });
        }
        let mut creation_info = serde_json::Map::new();
        if let Some(ts) = &self.timestamp {
            creation_info.insert("created".into(), serde_json::json!(ts));
        }
        creation_info.insert("creators".into(), serde_json::json!(creators));

        let packages: Vec<_> = self
            .all_components()
            .into_iter()
            .map(|c| c.spdx23_json(self, drops))
            .collect();

        let mut relationships = Vec::new();
        let rel = |from: String, kind: &str, to: String| {
            serde_json::json!({
                "spdxElementId": from,
                "relationshipType": kind,
                "relatedSpdxElement": to,
            })
        };
        if let Some(primary) = &self.primary {
            relationships.push(rel(
                "SPDXRef-DOCUMENT".to_string(),
                "DESCRIBES",
                id(&primary.bom_ref),
            ));
        }
        for c in self.all_components() {
            for child in &c.children {
                relationships.push(rel(id(&c.bom_ref), "CONTAINS", id(&child.bom_ref)));
            }
        }
        for (from, depends_on) in &self.dependencies {
            if depends_on.is_empty() {
                // SPDX 2.3 §11: "NONE" states that there are no dependencies.
                relationships.push(rel(id(from), "DEPENDS_ON", "NONE".to_string()));
            }
            for to in depends_on {
                relationships.push(rel(id(from), "DEPENDS_ON", id(to)));
            }
        }
        for (from, to) in &self.dynamic_links {
            relationships.push(rel(id(from), "DYNAMIC_LINK", id(to)));
        }

        let mut doc = serde_json::Map::new();
        let version = self.spdx_version.as_deref().unwrap_or("2.3");
        doc.insert(
            "spdxVersion".into(),
            serde_json::json!(format!("SPDX-{version}")),
        );
        doc.insert("dataLicense".into(), serde_json::json!("CC0-1.0"));
        doc.insert("SPDXID".into(), serde_json::json!("SPDXRef-DOCUMENT"));
        // The name is mandatory in SPDX 2.3; a document without a primary
        // component has no name to give.
        doc.insert(
            "name".into(),
            serde_json::json!(self.document_name().unwrap_or("")),
        );
        if let Some(serial) = &self.serial_number {
            doc.insert("documentNamespace".into(), serde_json::json!(serial));
        }
        doc.insert(
            "creationInfo".into(),
            serde_json::Value::Object(creation_info),
        );
        doc.insert("packages".into(), serde_json::json!(packages));
        doc.insert("relationships".into(), serde_json::json!(relationships));
        serde_json::to_string_pretty(&serde_json::Value::Object(doc))
            .expect("fixture JSON must serialize")
    }
}

impl ComponentFixture {
    fn spdx23_json(&self, fixture: &SbomFixture, drops: &mut Drops) -> serde_json::Value {
        let mut pkg = serde_json::Map::new();
        pkg.insert(
            "SPDXID".into(),
            serde_json::json!(fixture.element_id(Encoding::Spdx23Json, &self.bom_ref)),
        );
        pkg.insert("name".into(), serde_json::json!(self.name));
        if let Some(version) = &self.version {
            pkg.insert("versionInfo".into(), serde_json::json!(version));
        }
        if let Some(supplier) = &self.supplier {
            let value = if supplier == "NOASSERTION" {
                supplier.clone()
            } else {
                format!("Organization: {supplier}")
            };
            pkg.insert("supplier".into(), serde_json::json!(value));
        }
        pkg.insert("downloadLocation".into(), serde_json::json!("NOASSERTION"));
        pkg.insert("filesAnalyzed".into(), serde_json::json!(false));
        match spdx2_purpose(&self.component_type) {
            Some(purpose) => {
                pkg.insert("primaryPackagePurpose".into(), serde_json::json!(purpose));
            }
            None => drops.drop_field("component.type"),
        }
        if !self.hashes.is_empty() {
            let checksums: Vec<_> = self
                .hashes
                .iter()
                .map(|(alg, content)| {
                    serde_json::json!({
                        "algorithm": spdx2_hash_algorithm(alg),
                        "checksumValue": content,
                    })
                })
                .collect();
            pkg.insert("checksums".into(), serde_json::json!(checksums));
        }
        let mut refs = Vec::new();
        if let Some(purl) = &self.purl {
            refs.push(serde_json::json!({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }));
        }
        if let Some(cpe) = &self.cpe {
            refs.push(serde_json::json!({
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": cpe,
            }));
        }
        let all_refs = self.external_refs.iter().cloned().chain(
            self.hashed_external_refs
                .iter()
                .map(|(ref_type, url, _)| (ref_type.clone(), url.clone())),
        );
        for (ref_type, url) in all_refs {
            // Annex F names advisories (SECURITY advisory); every other
            // CycloneDX type is a free-form OTHER reference.
            let (category, kind) = match ref_type.as_str() {
                "advisories" => ("SECURITY", "advisory".to_string()),
                other => ("OTHER", other.to_string()),
            };
            refs.push(serde_json::json!({
                "referenceCategory": category,
                "referenceType": kind,
                "referenceLocator": url,
            }));
        }
        if !refs.is_empty() {
            pkg.insert("externalRefs".into(), serde_json::json!(refs));
        }
        if !self.licenses.is_empty() {
            pkg.insert(
                "licenseDeclared".into(),
                serde_json::json!(self.licenses.join(" AND ")),
            );
        }
        if let Some(concluded) = &self.concluded_license {
            pkg.insert("licenseConcluded".into(), serde_json::json!(concluded));
        }
        if let Some(copyright) = &self.copyright {
            pkg.insert("copyrightText".into(), serde_json::json!(copyright));
        }
        if let Some(description) = &self.description {
            pkg.insert("description".into(), serde_json::json!(description));
        }
        if let Some(date) = &self.support_end {
            pkg.insert(
                "validUntilDate".into(),
                serde_json::json!(spdx_date_time(date)),
            );
        }
        if self.model_card.is_some() {
            drops.drop_field("component.model_card");
        }
        if self.dataset.is_some() {
            drops.drop_field("component.dataset");
        }
        serde_json::Value::Object(pkg)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SPDX 3.0.1 JSON-LD
// ═══════════════════════════════════════════════════════════════════════

/// The SPDX 3.0.1 `externalRefType` term of a CycloneDX reference type, the
/// inverse of the parser's `map_spdx3_external_ref_type`. A model card is a
/// `documentation` reference, which the parser reads as an AI package's
/// model card.
fn spdx3_ref_type(cdx_type: &str) -> Option<&'static str> {
    Some(match cdx_type {
        "vcs" => "vcs",
        "issue-tracker" => "issueTracker",
        "documentation" | "model-card" => "documentation",
        "advisories" => "securityAdvisory",
        "build-meta" => "buildMeta",
        "build-system" => "buildSystem",
        "certification-report" => "certificationReport",
        "risk-assessment" => "riskAssessment",
        "attestation" => "secureSoftwareAttestation",
        "vulnerability-assertion" => "vulnerabilityDisclosureReport",
        "exploitability-statement" => "vulnerabilityExploitabilityAssessment",
        "security-contact" => "securityPolicy",
        "threat-model" => "securityThreatModel",
        "adversary-model" => "securityAdversaryModel",
        "pentest-report" => "securityPenTestReport",
        "static-analysis-report" => "staticAnalysisReport",
        "dynamic-analysis-report" => "dynamicAnalysisReport",
        "runtime-analysis-report" => "runtimeAnalysisReport",
        "component-analysis-report" => "componentAnalysisReport",
        "quality-metrics" => "qualityAssessmentReport",
        "release-notes" => "releaseNotes",
        "license" => "license",
        "support" => "support",
        "chat" => "chat",
        "mailing-list" => "mailingList",
        "social" => "socialMedia",
        _ => return None,
    })
}

/// The SPDX 3.0.1 `software_primaryPurpose` of a CycloneDX component type.
fn spdx3_purpose(component_type: &str) -> Option<&'static str> {
    Some(match component_type {
        "application" => "application",
        "library" => "library",
        "framework" => "framework",
        "container" => "container",
        "operating-system" => "operatingSystem",
        "device" => "device",
        "firmware" => "firmware",
        "data" => "data",
        "machine-learning-model" => "model",
        "platform" => "platform",
        _ => return None,
    })
}

/// The SPDX 3.0.1 `software_sbomType` of a CycloneDX lifecycle phase (the
/// CISA "Types of SBOM" mapping); a named lifecycle keeps its name.
fn spdx3_sbom_type(lifecycle: &str) -> String {
    match lifecycle {
        "pre-build" => "source".to_string(),
        "post-build" => "analyzed".to_string(),
        "operations" => "deployed".to_string(),
        "discovery" => "runtime".to_string(),
        other => other.to_string(),
    }
}

/// The SPDX 3 relationship completeness of a CycloneDX composition
/// aggregate (SPDX 3 has `complete`, `incomplete` and `noAssertion`).
fn spdx3_completeness(aggregate: &str) -> Option<&'static str> {
    match aggregate {
        "complete" => Some("complete"),
        a if a.starts_with("incomplete") => Some("incomplete"),
        "not_specified" => Some("noAssertion"),
        _ => None,
    }
}

/// A CVSS v3.1 base score and vector for a rating severity band: the SPDX 3
/// parser reads a vulnerability's severity only from a CVSS assessment's
/// score.
fn spdx3_cvss(severity: &str) -> Option<(f64, &'static str)> {
    Some(match severity.to_ascii_lowercase().as_str() {
        "critical" => (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "high" => (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "medium" => (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "low" => (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "none" => (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
        _ => return None,
    })
}

/// The SPDX 3.0.1 `VexJustificationType` for a CycloneDX
/// impactAnalysisJustification: the justification the CycloneDX parser
/// reads the CycloneDX value as (src/parsers/cyclonedx_analysis.rs), so a
/// fixture means the same in both.
fn spdx3_justification(cdx: &str) -> &'static str {
    match cdx {
        "code_not_present" => "vulnerableCodeNotPresent",
        "code_not_reachable" => "vulnerableCodeNotInExecutePath",
        "requires_configuration"
        | "requires_dependency"
        | "requires_environment"
        | "protected_at_perimeter" => "vulnerableCodeCannotBeControlledByAdversary",
        "protected_by_compiler" | "protected_at_runtime" | "protected_by_mitigating_control" => {
            "inlineMitigationsAlreadyExist"
        }
        other => panic!("{other:?} is no CycloneDX justification"),
    }
}

/// The `@graph` of an SPDX 3 document under construction.
struct Spdx3Graph {
    nodes: Vec<serde_json::Value>,
    /// spdxIds of every element, for the Sbom and SpdxDocument `element`.
    ids: Vec<String>,
    /// Organization agents by name (suppliers, governance owners), so each
    /// name is one element.
    organizations: BTreeMap<String, String>,
    next_relationship: usize,
}

impl Spdx3Graph {
    fn new() -> Self {
        Self {
            nodes: vec![serde_json::Value::Null], // the CreationInfo, set last
            ids: Vec::new(),
            organizations: BTreeMap::new(),
            next_relationship: 0,
        }
    }

    /// Add an element, stamping its creation info.
    fn element(&mut self, mut node: serde_json::Value) {
        node["creationInfo"] = serde_json::json!("_:creationinfo");
        if let Some(id) = node["spdxId"].as_str() {
            self.ids.push(id.to_string());
        }
        self.nodes.push(node);
    }

    fn relationship(
        &mut self,
        from: &str,
        kind: &str,
        to: Vec<String>,
        completeness: Option<&str>,
    ) {
        self.next_relationship += 1;
        let mut node = serde_json::json!({
            "type": "Relationship",
            "spdxId": format!("{SPDX3_NS}relationship/{}", self.next_relationship),
            "from": from,
            "relationshipType": kind,
            "to": to,
        });
        if let Some(completeness) = completeness {
            node["completeness"] = serde_json::json!(completeness);
        }
        self.element(node);
    }

    /// The Organization element named `name`, created on first use.
    fn organization(&mut self, name: &str) -> String {
        if let Some(id) = self.organizations.get(name) {
            return id.clone();
        }
        let id = format!("{SPDX3_NS}agent/organization-{}", self.organizations.len());
        self.element(serde_json::json!({
            "type": "Organization",
            "spdxId": id,
            "name": name,
        }));
        self.organizations.insert(name.to_string(), id.clone());
        id
    }
}

fn spdx3_email_identifier(email: &str) -> serde_json::Value {
    serde_json::json!([{
        "type": "ExternalIdentifier",
        "externalIdentifierType": "email",
        "identifier": email,
    }])
}

impl SbomFixture {
    fn spdx3_json_ld(&self, drops: &mut Drops) -> String {
        self.drop_neutral_fields(drops);
        let id = |bom_ref: &str| self.element_id(Encoding::Spdx3JsonLd, bom_ref);
        let mut g = Spdx3Graph::new();

        // ── Creators ────────────────────────────────────────────────────
        let mut created_by = Vec::new();
        let mut created_using = Vec::new();
        for (i, (name, email)) in self.authors.iter().enumerate() {
            let agent = format!("{SPDX3_NS}agent/person-{i}");
            let mut node = serde_json::json!({ "type": "Person", "spdxId": agent, "name": name });
            if let Some(email) = email {
                node["externalIdentifier"] = spdx3_email_identifier(email);
            }
            g.element(node);
            created_by.push(agent);
        }
        if let Some((name, email)) = &self.manufacturer {
            let agent = format!("{SPDX3_NS}agent/manufacturer");
            let mut node =
                serde_json::json!({ "type": "Organization", "spdxId": agent, "name": name });
            if let Some(email) = email {
                node["externalIdentifier"] = spdx3_email_identifier(email);
            }
            g.element(node);
            created_by.push(agent);
        }
        for (i, (name, version)) in self.tools.iter().enumerate() {
            let tool = format!("{SPDX3_NS}agent/tool-{i}");
            g.element(serde_json::json!({
                "type": "Tool",
                "spdxId": tool,
                "name": format!("{name} {version}").trim(),
            }));
            created_using.push(tool);
        }

        // ── Packages ────────────────────────────────────────────────────
        let mut licenses = 0usize;
        let mut uses_ai = false;
        let mut uses_dataset = false;
        for c in self.all_components() {
            let (node, kind) = c.spdx3_package(self, &mut g, drops);
            uses_ai |= kind == "ai_AIPackage";
            uses_dataset |= kind == "dataset_DatasetPackage";
            g.element(node);
            let pkg = id(&c.bom_ref);
            for (license, relationship) in
                c.licenses.iter().map(|l| (l, "hasDeclaredLicense")).chain(
                    c.concluded_license
                        .iter()
                        .map(|l| (l, "hasConcludedLicense")),
                )
            {
                licenses += 1;
                let expression = format!("{SPDX3_NS}license/{licenses}");
                g.element(serde_json::json!({
                    "type": "simplelicensing_LicenseExpression",
                    "spdxId": expression,
                    "simplelicensing_licenseExpression": license,
                }));
                g.relationship(&pkg, relationship, vec![expression], None);
            }
            for child in &c.children {
                g.relationship(&pkg, "contains", vec![id(&child.bom_ref)], None);
            }
            if let Some(card) = &c.model_card {
                for dataset in &card.datasets {
                    g.relationship(&pkg, "trainedOn", vec![id(dataset)], None);
                }
            }
        }

        // ── Dependencies ────────────────────────────────────────────────
        let completeness = self.completeness.as_deref().and_then(spdx3_completeness);
        for (from, depends_on) in &self.dependencies {
            let to = if depends_on.is_empty() {
                vec![SPDX3_NONE_ELEMENT.to_string()]
            } else {
                depends_on.iter().map(|r| id(r)).collect()
            };
            g.relationship(&id(from), "dependsOn", to, completeness);
        }
        if let Some(completeness) = completeness
            && self.dependencies.is_empty()
        {
            // No dependency relationship to state completeness on: state
            // that the root has none, completely.
            match self.all_components().first() {
                Some(root) => g.relationship(
                    &id(&root.bom_ref),
                    "dependsOn",
                    vec![SPDX3_NONE_ELEMENT.to_string()],
                    Some(completeness),
                ),
                None => drops.drop_field("completeness"),
            }
        }
        for (from, to) in &self.dynamic_links {
            g.relationship(&id(from), "hasDynamicLink", vec![id(to)], None);
        }

        // ── Vulnerabilities ─────────────────────────────────────────────
        for (i, (vuln_id, severity, affected_ref)) in self.vulnerabilities.iter().enumerate() {
            let vuln = format!("{SPDX3_NS}vulnerability/{i}");
            let identifier_type = if vuln_id.starts_with("CVE-") {
                "cve"
            } else {
                "securityOther"
            };
            g.element(serde_json::json!({
                "type": "security_Vulnerability",
                "spdxId": vuln,
                "name": vuln_id,
                "externalIdentifier": [{
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": identifier_type,
                    "identifier": vuln_id,
                }],
            }));
            let affected = id(affected_ref);
            match self.analysis_of(vuln_id) {
                // A not_affected analysis is a VEX assessment, which takes
                // the place of the AFFECTS relationship: the parser keeps
                // the two apart as statements that contradict each other.
                Some(analysis) if analysis.state.as_deref() == Some("not_affected") => {
                    let mut node = serde_json::json!({
                        "type": "security_VexNotAffectedVulnAssessmentRelationship",
                        "spdxId": format!("{SPDX3_NS}vex/{i}"),
                        "from": vuln,
                        "relationshipType": "doesNotAffect",
                        "to": [affected.clone()],
                        "security_assessedElement": affected.clone(),
                    });
                    if let Some(justification) = &analysis.justification {
                        node["security_justificationType"] =
                            serde_json::json!(spdx3_justification(justification));
                    }
                    if let Some(detail) = &analysis.detail {
                        node["security_impactStatement"] = serde_json::json!(detail);
                    }
                    if !analysis.responses.is_empty() {
                        drops.drop_field("vulnerability_analyses.responses");
                    }
                    if analysis.recommendation.is_some() {
                        drops.drop_field("vulnerability_analyses.recommendation");
                    }
                    if analysis.workaround.is_some() {
                        drops.drop_field("vulnerability_analyses.workaround");
                    }
                    g.element(node);
                }
                analysis => {
                    if analysis.is_some() {
                        drops.drop_field("vulnerability_analyses");
                    }
                    g.relationship(&vuln, "affects", vec![affected.clone()], None);
                }
            }
            if severity.is_empty() {
                continue;
            }
            match spdx3_cvss(severity) {
                Some((score, vector)) => g.element(serde_json::json!({
                    "type": "security_CvssV3VulnAssessmentRelationship",
                    "spdxId": format!("{SPDX3_NS}assessment/{i}"),
                    "from": vuln,
                    "relationshipType": "hasAssessmentFor",
                    "to": [affected],
                    "security_assessedElement": affected,
                    "security_score": score,
                    "security_severity": severity.to_ascii_lowercase(),
                    "security_vectorString": vector,
                })),
                None => drops.drop_field("vulnerabilities.rating"),
            }
        }

        // ── Profiles, Sbom, document ────────────────────────────────────
        let mut profiles = vec!["core", "software"];
        if licenses > 0 {
            profiles.push("simpleLicensing");
        }
        if !self.vulnerabilities.is_empty() {
            profiles.push("security");
        }
        if uses_ai {
            profiles.push("ai");
        }
        if uses_dataset {
            profiles.push("dataset");
        }
        profiles.retain(|p| !self.undeclared_spdx3_profiles.iter().any(|u| u == p));

        let data_license = format!("{SPDX3_NS}license/data");
        g.element(serde_json::json!({
            "type": "simplelicensing_LicenseExpression",
            "spdxId": data_license,
            "simplelicensing_licenseExpression": "CC0-1.0",
        }));

        let sbom = format!("{SPDX3_NS}sbom");
        let mut sbom_node = serde_json::json!({
            "type": "software_Sbom",
            "spdxId": sbom,
            "rootElement": self.primary.iter().map(|p| id(&p.bom_ref)).collect::<Vec<_>>(),
            "element": g.ids.clone(),
        });
        if !self.lifecycles.is_empty() {
            let types: Vec<_> = self.lifecycles.iter().map(|l| spdx3_sbom_type(l)).collect();
            sbom_node["software_sbomType"] = serde_json::json!(types);
        }
        g.element(sbom_node);

        let mut document = serde_json::json!({
            "type": "SpdxDocument",
            "dataLicense": data_license,
            "profileConformance": profiles,
            "rootElement": [sbom],
            "element": g.ids.clone(),
        });
        // The SpdxDocument's spdxId is read as the serial identifier.
        if let Some(serial) = &self.serial_number {
            document["spdxId"] = serde_json::json!(serial);
        }
        if let Some(name) = self.document_name() {
            document["name"] = serde_json::json!(name);
        }
        // SPDX 3.0.1 defines no signature integrity method; the parser (and
        // the registry advice) read a verifiedUsing entry of type signature
        // on the SpdxDocument as the document's signature.
        if let Some((algorithm, value)) = &self.signature {
            document["verifiedUsing"] = serde_json::json!([{
                "type": "signature",
                "algorithm": algorithm,
                "hashValue": value,
            }]);
        }
        g.element(document);

        let mut creation_info = serde_json::json!({
            "type": "CreationInfo",
            "@id": "_:creationinfo",
            "specVersion": self.spdx_version.as_deref().unwrap_or("3.0.1"),
            "createdBy": created_by,
            "createdUsing": created_using,
        });
        if let Some(ts) = &self.timestamp {
            creation_info["created"] = serde_json::json!(ts);
        }
        g.nodes[0] = creation_info;

        serde_json::to_string_pretty(&serde_json::json!({
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": g.nodes,
        }))
        .expect("fixture JSON must serialize")
    }
}

impl ComponentFixture {
    /// The component's package element and its type.
    fn spdx3_package(
        &self,
        fixture: &SbomFixture,
        g: &mut Spdx3Graph,
        drops: &mut Drops,
    ) -> (serde_json::Value, &'static str) {
        let ml = self.component_type == "machine-learning-model";
        let data = self.component_type == "data" && self.dataset.is_some();
        let kind = if ml {
            "ai_AIPackage"
        } else if data {
            "dataset_DatasetPackage"
        } else {
            "software_Package"
        };
        let mut pkg = serde_json::json!({
            "type": kind,
            "spdxId": fixture.element_id(Encoding::Spdx3JsonLd, &self.bom_ref),
            "name": self.name,
        });
        match spdx3_purpose(&self.component_type) {
            Some(purpose) => pkg["software_primaryPurpose"] = serde_json::json!(purpose),
            None => drops.drop_field("component.type"),
        }
        if let Some(version) = &self.version {
            pkg["software_packageVersion"] = serde_json::json!(version);
        }
        if let Some(purl) = &self.purl {
            pkg["software_packageUrl"] = serde_json::json!(purl);
        }
        if let Some(cpe) = &self.cpe {
            pkg["externalIdentifier"] = serde_json::json!([{
                "type": "ExternalIdentifier",
                "externalIdentifierType": "cpe23",
                "identifier": cpe,
            }]);
        }
        if let Some(supplier) = &self.supplier {
            let agent = if supplier == "NOASSERTION" {
                SPDX3_NO_ASSERTION_ELEMENT.to_string()
            } else {
                g.organization(supplier)
            };
            pkg["suppliedBy"] = serde_json::json!(agent);
        }
        if !self.hashes.is_empty() {
            let hashes: Vec<_> = self
                .hashes
                .iter()
                .map(|(alg, content)| {
                    serde_json::json!({
                        "type": "Hash",
                        "algorithm": spdx3_hash_algorithm(alg),
                        "hashValue": content,
                    })
                })
                .collect();
            pkg["verifiedUsing"] = serde_json::json!(hashes);
        }
        let mut refs = Vec::new();
        let all_refs = self.external_refs.iter().cloned().chain(
            self.hashed_external_refs
                .iter()
                .map(|(ref_type, url, _)| (ref_type.clone(), url.clone())),
        );
        for (ref_type, url) in all_refs {
            match spdx3_ref_type(&ref_type) {
                Some(term) => refs.push(serde_json::json!({
                    "type": "ExternalRef",
                    "externalRefType": term,
                    "locator": [url],
                })),
                None => drops.drop_field("component.external_refs"),
            }
        }
        if !refs.is_empty() {
            pkg["externalRef"] = serde_json::json!(refs);
        }
        if let Some(copyright) = &self.copyright {
            pkg["software_copyrightText"] = serde_json::json!(copyright);
        }
        if let Some(description) = &self.description {
            pkg["description"] = serde_json::json!(description);
        }
        if let Some(date) = &self.support_end {
            pkg["validUntilTime"] = serde_json::json!(spdx_date_time(date));
        }
        match (&self.model_card, ml) {
            (Some(card), true) => card.spdx3_fields(&mut pkg),
            (Some(_), false) => drops.drop_field("component.model_card"),
            (None, _) => {}
        }
        match (&self.dataset, data) {
            (Some(dataset), true) => dataset.spdx3_fields(&mut pkg, g, drops),
            (Some(_), false) => drops.drop_field("component.dataset"),
            (None, _) => {}
        }
        (pkg, kind)
    }
}

impl ModelCardFixture {
    /// The AI-profile properties of the card (`modelParameters.datasets`
    /// become `trainedOn` relationships).
    fn spdx3_fields(&self, pkg: &mut serde_json::Value) {
        // ai_typeOfModel records the type of model; the parser reads its
        // first entry as the architecture family.
        let types: Vec<&String> = self
            .architecture_family
            .iter()
            .chain(&self.model_architecture)
            .collect();
        if !types.is_empty() {
            pkg["ai_typeOfModel"] = serde_json::json!(types);
        }
        if let Some((first, rest)) = self.use_cases.split_first() {
            pkg["ai_informationAboutApplication"] = serde_json::json!(first);
            if !rest.is_empty() {
                pkg["ai_domain"] = serde_json::json!(rest);
            }
        }
        if !self.technical_limitations.is_empty() {
            pkg["ai_limitation"] = serde_json::json!(self.technical_limitations.join("; "));
        }
        if !self.performance_metrics.is_empty() {
            let metrics: Vec<_> = self
                .performance_metrics
                .iter()
                .map(|(metric, value)| {
                    serde_json::json!({ "type": "DictionaryEntry", "key": metric, "value": value })
                })
                .collect();
            pkg["ai_metric"] = serde_json::json!(metrics);
        }
        if let Some(kwh) = self.training_energy_kwh {
            pkg["ai_energyConsumption"] = serde_json::json!({
                "type": "ai_EnergyConsumption",
                "ai_trainingEnergyConsumption": [{
                    "type": "ai_EnergyConsumptionDescription",
                    "ai_energyQuantity": kwh,
                    "ai_energyUnit": "kilowattHour",
                }],
            });
        }
    }
}

impl DatasetFixture {
    fn spdx3_fields(&self, pkg: &mut serde_json::Value, g: &mut Spdx3Graph, drops: &mut Drops) {
        if self.data_type != "dataset" {
            drops.drop_field("component.dataset.data_type");
        }
        // The modality of the data is not part of the DSL.
        pkg["dataset_datasetType"] = serde_json::json!(["noAssertion"]);
        for classification in &self.sensitive_data {
            if is_personal_data(classification) {
                pkg["dataset_hasSensitivePersonalInformation"] = serde_json::json!("yes");
            } else if classification == "public" {
                pkg["dataset_confidentialityLevel"] = serde_json::json!("clear");
            } else {
                drops.drop_field("component.dataset.sensitive_data");
            }
        }
        if !self.governance_owners.is_empty() {
            let owners: Vec<_> = self
                .governance_owners
                .iter()
                .map(|owner| g.organization(owner))
                .collect();
            pkg["originatedBy"] = serde_json::json!(owners);
        }
    }
}
