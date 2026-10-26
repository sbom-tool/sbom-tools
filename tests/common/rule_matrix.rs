//! Registry-driven per-rule compliance test harness (audit P3).
//!
//! Provides three things to the `tests/rule_matrix_*.rs` integration tests:
//!
//! 1. **A minimal fixture DSL** ([`SbomFixture`] / [`ComponentFixture`] /
//!    [`CryptoAssetFixture`]) that renders a small CycloneDX JSON document
//!    and feeds it through the *real* parser (`parse_sbom_str`), so every
//!    matrix case exercises the same normalization path a production
//!    `validate` run does — not a hand-built `NormalizedSbom` that may drift
//!    from what parsers actually produce. A fixture can also carry a CRA
//!    sidecar, attached to the checker like `--cra-sidecar`.
//!
//! 2. **A table-driven matrix runner** ([`run_matrix`]): every SARIF rule id
//!    in a standard's rule universe gets at least one *firing* case (a
//!    minimal SBOM that must surface the rule, with the expected severity)
//!    and one *silent* case (a minimal SBOM that must not surface it), or an
//!    explicit skip-with-reason entry. A pass-only rule (`RuleKind::Pass`,
//!    such as SBOM-PQC-009) gets *passing* cases instead of firing ones: the
//!    rule must appear among the result's passed checks, never among its
//!    violations. No silent omissions: the runner fails if the entry table
//!    and the declared universe differ. Registry keys that exist only as
//!    aliases of a shared SARIF rule (e.g. `SBOM-CRA-ANNEX-I-DEPENDENCY` →
//!    `SBOM-CRA-ANNEX-I`) get per-key rows that match the internal
//!    `Violation::rule_id` instead.
//!
//! 3. **A universe sweep**: every violation and every passed check emitted
//!    by every fixture in a matrix must map (via its registry SARIF identity)
//!    into the standard's declared rule universe, and every alias key a
//!    fixture emits must have its own per-key row — a new check site that
//!    emits a new rule id forces the matrix to be extended instead of
//!    silently escaping it.

// Each per-standard matrix binary uses a subset of the DSL (mirrors the
// existing tests/common/ffi_helpers.rs posture).
#![allow(dead_code)]

#[path = "clock.rs"]
pub mod clock;

#[path = "info_classification.rs"]
pub mod info_classification;

use sbom_tools::model::{CraSidecarMetadata, EolInfo, EolStatus, NormalizedSbom};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, PassedCheck, RuleKind, Violation, ViolationSeverity,
    rule_kind, rule_meta,
};
use std::collections::BTreeSet;

/// Filler SHA-256 digest (64 hex chars) for conforming components.
pub const SHA256_FILLER: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Filler SHA-512 digest (128 hex chars) for the BSI TR-03183-2 hash field.
pub const SHA512_FILLER: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// Filler MD5 digest (32 hex chars) for weak-hash cases.
pub const MD5_FILLER: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// One component of a [`SbomFixture`], rendered into the CycloneDX
/// `components[]` array (or `metadata.component` for the primary).
#[derive(Debug, Clone)]
pub struct ComponentFixture {
    /// CycloneDX `bom-ref`. Kept distinct from `name` so the generic
    /// "may be missing bom-ref" Info check stays silent unless a case
    /// deliberately collapses the two.
    pub bom_ref: String,
    /// CycloneDX component `type` (`library` unless a case changes it).
    pub component_type: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// `supplier.name`.
    pub supplier: Option<String>,
    /// `description`.
    pub description: Option<String>,
    /// `(alg, content)` pairs, e.g. `("SHA-256", SHA256_FILLER)`.
    pub hashes: Vec<(String, String)>,
    /// `(type, url)` external references, e.g. `("vcs", "https://…")`.
    pub external_refs: Vec<(String, String)>,
    /// External references that carry `hashes[]`, rendered after
    /// [`Self::external_refs`]: `(type, url, (alg, content) pairs)`.
    pub hashed_external_refs: Vec<(String, String, Vec<(String, String)>)>,
    /// SPDX license ids rendered as `{"license": {"id": …}}` entries.
    pub licenses: Vec<String>,
    /// `(name, value)` CycloneDX properties.
    pub properties: Vec<(String, String)>,
    /// `modelCard` (CycloneDX 1.5+ AI/ML-BOM).
    pub model_card: Option<ModelCardFixture>,
    /// `data[0]` (CycloneDX 1.5+ componentData): dataset evidence.
    pub dataset: Option<DatasetFixture>,
    /// End-of-life status attached after parsing, the way EOL enrichment
    /// sets it — no document field carries it.
    pub eol: Option<EolStatus>,
    /// Nested `components[]` (an assembly); the parser joins them to the
    /// inventory with a `contains` edge from this component.
    pub children: Vec<ComponentFixture>,
}

impl ComponentFixture {
    /// A component that satisfies every per-component element the generic /
    /// FDA / SSDF / EO 14028 checkers look for: real name, version, PURL,
    /// supplier, and a strong (SHA-256) hash.
    pub fn conforming(name: &str) -> Self {
        Self {
            bom_ref: format!("ref-{name}"),
            component_type: "library".to_string(),
            name: name.to_string(),
            version: Some("1.2.3".to_string()),
            purl: Some(format!("pkg:npm/{name}@1.2.3")),
            supplier: Some("Acme Components Ltd".to_string()),
            description: None,
            hashes: vec![("SHA-256".to_string(), SHA256_FILLER.to_string())],
            external_refs: Vec::new(),
            hashed_external_refs: Vec::new(),
            licenses: Vec::new(),
            properties: Vec::new(),
            model_card: None,
            dataset: None,
            eol: None,
            children: Vec::new(),
        }
    }

    /// A `machine-learning-model` component with a HuggingFace PURL, a
    /// license, and a model card declaring every element the AI profiles
    /// read ([`ModelCardFixture::complete`]).
    pub fn ml_model(name: &str) -> Self {
        let mut c = Self::conforming(name);
        c.component_type = "machine-learning-model".to_string();
        c.purl = Some(format!("pkg:huggingface/acme/{name}@1.2.3"));
        c.licenses = vec!["Apache-2.0".to_string()];
        c.model_card = Some(ModelCardFixture::complete());
        c
    }

    /// A `data` component with a PURL, a hash, a license, and dataset
    /// evidence declaring a sensitivity classification and an owner
    /// ([`DatasetFixture::complete`]).
    pub fn dataset(name: &str) -> Self {
        let mut c = Self::conforming(name);
        c.component_type = "data".to_string();
        c.purl = Some(format!("pkg:huggingface/datasets/{name}@1.2.3"));
        c.licenses = vec!["CC-BY-4.0".to_string()];
        c.dataset = Some(DatasetFixture::complete());
        c
    }

    /// Mutable access to the model card (panics when absent, so a case that
    /// edits a card on a non-model component fails loudly).
    pub fn model_card_mut(&mut self) -> &mut ModelCardFixture {
        let name = self.name.clone();
        self.model_card
            .as_mut()
            .unwrap_or_else(|| panic!("component {name:?} has no model card"))
    }

    /// Mutable access to the dataset evidence (panics when absent).
    pub fn dataset_mut(&mut self) -> &mut DatasetFixture {
        let name = self.name.clone();
        self.dataset
            .as_mut()
            .unwrap_or_else(|| panic!("component {name:?} has no dataset evidence"))
    }

    fn to_json(&self) -> serde_json::Value {
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
        if let Some(supplier) = &self.supplier {
            obj.insert("supplier".into(), serde_json::json!({ "name": supplier }));
        }
        if let Some(description) = &self.description {
            obj.insert("description".into(), serde_json::json!(description));
        }
        if !self.hashes.is_empty() {
            let hashes: Vec<_> = self
                .hashes
                .iter()
                .map(|(alg, content)| serde_json::json!({ "alg": alg, "content": content }))
                .collect();
            obj.insert("hashes".into(), serde_json::json!(hashes));
        }
        if !self.external_refs.is_empty() || !self.hashed_external_refs.is_empty() {
            let hashed = self
                .hashed_external_refs
                .iter()
                .map(|(ref_type, url, hashes)| {
                    let hashes: Vec<_> = hashes
                        .iter()
                        .map(|(alg, content)| serde_json::json!({ "alg": alg, "content": content }))
                        .collect();
                    serde_json::json!({ "type": ref_type, "url": url, "hashes": hashes })
                });
            let refs: Vec<_> = self
                .external_refs
                .iter()
                .map(|(ref_type, url)| serde_json::json!({ "type": ref_type, "url": url }))
                .chain(hashed)
                .collect();
            obj.insert("externalReferences".into(), serde_json::json!(refs));
        }
        if !self.licenses.is_empty() {
            let licenses: Vec<_> = self
                .licenses
                .iter()
                .map(|id| serde_json::json!({ "license": { "id": id } }))
                .collect();
            obj.insert("licenses".into(), serde_json::json!(licenses));
        }
        if !self.properties.is_empty() {
            let props: Vec<_> = self
                .properties
                .iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect();
            obj.insert("properties".into(), serde_json::json!(props));
        }
        if let Some(card) = &self.model_card {
            obj.insert("modelCard".into(), card.to_json());
        }
        if let Some(dataset) = &self.dataset {
            obj.insert("data".into(), serde_json::json!([dataset.to_json()]));
        }
        if !self.children.is_empty() {
            let children: Vec<_> = self.children.iter().map(Self::to_json).collect();
            obj.insert("components".into(), serde_json::json!(children));
        }
        serde_json::Value::Object(obj)
    }
}

/// A CycloneDX `modelCard`. Every field is optional in the schema; an empty
/// card (`ModelCardFixture::default()`) still marks the component as carrying
/// ML-model metadata.
#[derive(Debug, Clone, Default)]
pub struct ModelCardFixture {
    /// `modelParameters.architectureFamily`.
    pub architecture_family: Option<String>,
    /// `modelParameters.modelArchitecture`.
    pub model_architecture: Option<String>,
    /// `modelParameters.datasets[]` data references (`{ "ref": … }`).
    pub datasets: Vec<String>,
    /// `considerations.useCases`.
    pub use_cases: Vec<String>,
    /// `considerations.technicalLimitations`.
    pub technical_limitations: Vec<String>,
    /// `quantitativeAnalysis.performanceMetrics[]` as `(type, value)`.
    pub performance_metrics: Vec<(String, String)>,
    /// Training energy in kWh
    /// (`considerations.environmentalConsiderations.energyConsumptions`).
    pub training_energy_kwh: Option<f64>,
}

impl ModelCardFixture {
    /// A card declaring architecture, a training-dataset reference, intended
    /// use, limitations, a performance metric, and training energy.
    pub fn complete() -> Self {
        Self {
            architecture_family: Some("transformer".to_string()),
            model_architecture: Some("BERT-base".to_string()),
            datasets: vec!["ref-reviews".to_string()],
            use_cases: vec!["sentiment-analysis".to_string()],
            technical_limitations: vec!["English-language input only".to_string()],
            performance_metrics: vec![("accuracy".to_string(), "0.94".to_string())],
            training_energy_kwh: Some(1200.0),
        }
    }

    fn to_json(&self) -> serde_json::Value {
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

/// A CycloneDX `componentData` entry (`component.data[0]`): the dataset
/// evidence the AI profiles require before they treat a component as an AI
/// dataset.
#[derive(Debug, Clone)]
pub struct DatasetFixture {
    /// componentData `type` (e.g. `dataset`).
    pub data_type: String,
    /// `sensitiveData` classifications.
    pub sensitive_data: Vec<String>,
    /// `governance.owners[].organization.name`.
    pub governance_owners: Vec<String>,
}

impl DatasetFixture {
    /// Dataset evidence with a (non-personal) sensitivity classification and
    /// a governance owner.
    pub fn complete() -> Self {
        Self {
            data_type: "dataset".to_string(),
            sensitive_data: vec!["public".to_string()],
            governance_owners: vec!["Acme Data Office".to_string()],
        }
    }

    fn to_json(&self) -> serde_json::Value {
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

/// `cryptoProperties.algorithmProperties` of a [`CryptoAssetFixture`].
#[derive(Debug, Clone, Default)]
pub struct AlgorithmFixture {
    /// `algorithmFamily` (CycloneDX 1.7).
    pub family: Option<String>,
    /// `primitive` (e.g. `block-cipher`, `signature`, `kem`, `combiner`).
    pub primitive: Option<String>,
    /// `parameterSetIdentifier`.
    pub parameter_set: Option<String>,
    /// `mode` (e.g. `gcm`, `ecb`).
    pub mode: Option<String>,
    /// `ellipticCurve` (CycloneDX 1.7).
    pub curve: Option<String>,
    /// `classicalSecurityLevel` in bits.
    pub classical_level: Option<u32>,
    /// `nistQuantumSecurityLevel` (0–6).
    pub quantum_level: Option<u8>,
}

/// `cryptoProperties.protocolProperties` of a [`CryptoAssetFixture`].
#[derive(Debug, Clone, Default)]
pub struct ProtocolFixture {
    /// Protocol `type` (e.g. `tls`, `ssh`, or an unlisted name such as
    /// `ssl`).
    pub protocol_type: String,
    pub version: Option<String>,
    /// `cipherSuites[]`.
    pub cipher_suites: Vec<CipherSuiteFixture>,
    /// `cryptoRefArray` bom-refs.
    pub crypto_refs: Vec<String>,
}

/// One `cipherSuites[]` entry of a [`ProtocolFixture`].
#[derive(Debug, Clone, Default)]
pub struct CipherSuiteFixture {
    pub name: String,
    /// `algorithms` bom-refs.
    pub algorithms: Vec<String>,
    /// `tlsGroups` (CycloneDX 1.7): IANA names or codepoints.
    pub tls_groups: Vec<String>,
    /// `tlsSignatureSchemes` (CycloneDX 1.7): IANA names or codepoints.
    pub tls_signature_schemes: Vec<String>,
}

/// A CycloneDX 1.6+ `cryptographic-asset` component: an algorithm, a
/// certificate, key material, or a protocol. Rendered into `components[]`
/// after the [`SbomFixture::components`]; reference other assets by
/// `bom_ref`.
#[derive(Debug, Clone)]
pub struct CryptoAssetFixture {
    pub bom_ref: String,
    pub name: String,
    /// `cryptoProperties.assetType`.
    pub asset_type: String,
    /// `cryptoProperties.oid`.
    pub oid: Option<String>,
    pub algorithm: Option<AlgorithmFixture>,
    /// `certificateProperties.signatureAlgorithmRef`.
    pub signature_algorithm_ref: Option<String>,
    /// `relatedCryptoMaterialProperties` as `(type, size in bits)`.
    pub material: Option<(String, Option<u32>)>,
    pub protocol: Option<ProtocolFixture>,
}

impl CryptoAssetFixture {
    fn new(bom_ref: &str, asset_type: &str) -> Self {
        Self {
            bom_ref: bom_ref.to_string(),
            name: bom_ref.to_string(),
            asset_type: asset_type.to_string(),
            oid: None,
            algorithm: None,
            signature_algorithm_ref: None,
            material: None,
            protocol: None,
        }
    }

    /// An algorithm asset named `bom_ref` with the given `algorithmFamily`
    /// (no other properties).
    pub fn algorithm(bom_ref: &str, family: &str) -> Self {
        let mut asset = Self::new(bom_ref, "algorithm");
        asset.algorithm = Some(AlgorithmFixture {
            family: Some(family.to_string()),
            ..AlgorithmFixture::default()
        });
        asset
    }

    /// An algorithm asset with no `algorithmFamily` — identified only by
    /// whatever the case adds (OID, curve, name) or by nothing at all.
    pub fn unidentified_algorithm(bom_ref: &str) -> Self {
        let mut asset = Self::new(bom_ref, "algorithm");
        asset.algorithm = Some(AlgorithmFixture::default());
        asset
    }

    /// A certificate asset whose signature algorithm is the asset (or raw
    /// reference) `signature_algorithm_ref`.
    pub fn certificate(bom_ref: &str, signature_algorithm_ref: &str) -> Self {
        let mut asset = Self::new(bom_ref, "certificate");
        asset.signature_algorithm_ref = Some(signature_algorithm_ref.to_string());
        asset
    }

    /// A key-material asset (`relatedCryptoMaterialProperties`), e.g.
    /// `("session-key", "symmetric-key", Some(256))`.
    pub fn material(bom_ref: &str, material_type: &str, size: Option<u32>) -> Self {
        let mut asset = Self::new(bom_ref, "related-crypto-material");
        asset.material = Some((material_type.to_string(), size));
        asset
    }

    /// A protocol asset of the given type and version.
    pub fn protocol(bom_ref: &str, protocol_type: &str, version: Option<&str>) -> Self {
        let mut asset = Self::new(bom_ref, "protocol");
        asset.protocol = Some(ProtocolFixture {
            protocol_type: protocol_type.to_string(),
            version: version.map(str::to_string),
            ..ProtocolFixture::default()
        });
        asset
    }

    /// Mutable access to the algorithm properties (panics on a non-algorithm
    /// asset).
    pub fn algorithm_mut(&mut self) -> &mut AlgorithmFixture {
        let bom_ref = self.bom_ref.clone();
        self.algorithm
            .as_mut()
            .unwrap_or_else(|| panic!("crypto asset {bom_ref:?} is not an algorithm"))
    }

    /// Mutable access to the protocol properties (panics on a non-protocol
    /// asset).
    pub fn protocol_mut(&mut self) -> &mut ProtocolFixture {
        let bom_ref = self.bom_ref.clone();
        self.protocol
            .as_mut()
            .unwrap_or_else(|| panic!("crypto asset {bom_ref:?} is not a protocol"))
    }

    /// Set the component name (defaults to the bom-ref).
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    /// Set `cryptoProperties.oid`.
    #[must_use]
    pub fn oid(mut self, oid: &str) -> Self {
        self.oid = Some(oid.to_string());
        self
    }

    /// Set the algorithm `primitive`.
    #[must_use]
    pub fn primitive(mut self, primitive: &str) -> Self {
        self.algorithm_mut().primitive = Some(primitive.to_string());
        self
    }

    /// Set the algorithm `parameterSetIdentifier`.
    #[must_use]
    pub fn parameter_set(mut self, parameter_set: &str) -> Self {
        self.algorithm_mut().parameter_set = Some(parameter_set.to_string());
        self
    }

    /// Set the algorithm `mode`.
    #[must_use]
    pub fn mode(mut self, mode: &str) -> Self {
        self.algorithm_mut().mode = Some(mode.to_string());
        self
    }

    /// Set the algorithm `ellipticCurve`.
    #[must_use]
    pub fn curve(mut self, curve: &str) -> Self {
        self.algorithm_mut().curve = Some(curve.to_string());
        self
    }

    /// Set the algorithm `classicalSecurityLevel`.
    #[must_use]
    pub fn classical_level(mut self, bits: u32) -> Self {
        self.algorithm_mut().classical_level = Some(bits);
        self
    }

    /// Set the algorithm `nistQuantumSecurityLevel`.
    #[must_use]
    pub fn quantum_level(mut self, level: u8) -> Self {
        self.algorithm_mut().quantum_level = Some(level);
        self
    }

    /// Add a protocol cipher suite with the given algorithm bom-refs.
    #[must_use]
    pub fn cipher_suite(mut self, name: &str, algorithm_refs: &[&str]) -> Self {
        self.protocol_mut().cipher_suites.push(CipherSuiteFixture {
            name: name.to_string(),
            algorithms: algorithm_refs.iter().map(|r| (*r).to_string()).collect(),
            ..CipherSuiteFixture::default()
        });
        self
    }

    /// Set the `tlsGroups` the last cipher suite offers.
    #[must_use]
    pub fn tls_groups(mut self, groups: &[&str]) -> Self {
        self.last_cipher_suite().tls_groups = groups.iter().map(|g| (*g).to_string()).collect();
        self
    }

    /// Set the `tlsSignatureSchemes` the last cipher suite offers.
    #[must_use]
    pub fn tls_signature_schemes(mut self, schemes: &[&str]) -> Self {
        self.last_cipher_suite().tls_signature_schemes =
            schemes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// The cipher suite added last (panics when there is none).
    fn last_cipher_suite(&mut self) -> &mut CipherSuiteFixture {
        let bom_ref = self.bom_ref.clone();
        self.protocol_mut()
            .cipher_suites
            .last_mut()
            .unwrap_or_else(|| panic!("protocol {bom_ref:?} has no cipher suite"))
    }

    /// Add a protocol `cryptoRefArray` entry.
    #[must_use]
    pub fn crypto_ref(mut self, bom_ref: &str) -> Self {
        self.protocol_mut().crypto_refs.push(bom_ref.to_string());
        self
    }

    fn to_json(&self) -> serde_json::Value {
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

/// A minimal CycloneDX document, rendered to JSON and parsed through the real
/// parser. All fields are public so a test can clone a conforming baseline
/// and break exactly one aspect per case. `SbomFixture::default()` is an
/// empty CycloneDX 1.6 document; baselines spell out the fields they rely
/// on and take the rest from it (`..SbomFixture::default()`).
#[derive(Debug, Clone)]
pub struct SbomFixture {
    pub spec_version: String,
    /// RFC 3339 `metadata.timestamp`; `None` → the parser stores the
    /// UNIX-epoch "unknown" sentinel (`has_known_timestamp() == false`).
    pub timestamp: Option<String>,
    /// Top-level `serialNumber`.
    pub serial_number: Option<String>,
    /// `metadata.tools` entries `(name, version)` → `CreatorType::Tool`.
    pub tools: Vec<(String, String)>,
    /// `metadata.authors` entries `(name, email)` → `CreatorType::Person`.
    pub authors: Vec<(String, Option<String>)>,
    /// `metadata.manufacturer` `(name, contact email)` →
    /// `CreatorType::Organization`.
    pub manufacturer: Option<(String, Option<String>)>,
    /// `metadata.component` → `document.name` + primary component (joins
    /// `sbom.components` like any other component).
    pub primary: Option<ComponentFixture>,
    pub components: Vec<ComponentFixture>,
    /// Cryptographic assets, rendered into `components[]` after
    /// [`Self::components`].
    pub crypto_assets: Vec<CryptoAssetFixture>,
    /// `dependencies[]` entries: `(ref, dependsOn refs)`.
    pub dependencies: Vec<(String, Vec<String>)>,
    /// Document `vulnerabilities[]`: `(id, rating severity, affected
    /// bom-ref)`. An empty severity renders no `ratings` at all (an unrated
    /// vulnerability).
    pub vulnerabilities: Vec<(String, String, String)>,
    /// Extra members merged into the rendered `vulnerabilities[]` entry with
    /// the given id, e.g. `("CVE-…", json!({ "recommendation": "…" }))`.
    pub vulnerability_extras: Vec<(String, serde_json::Value)>,
    /// `compositions[0].aggregate` (e.g. `complete`, `incomplete`).
    pub completeness: Option<String>,
    /// Top-level JSF `signature` as `(algorithm, value)`.
    pub signature: Option<(String, String)>,
    /// CRA sidecar metadata, attached to the checker by [`check`] the way
    /// `validate --cra-sidecar` attaches it.
    pub sidecar: Option<CraSidecarMetadata>,
}

impl Default for SbomFixture {
    fn default() -> Self {
        Self {
            spec_version: "1.6".to_string(),
            timestamp: None,
            serial_number: None,
            tools: Vec::new(),
            authors: Vec::new(),
            manufacturer: None,
            primary: None,
            components: Vec::new(),
            crypto_assets: Vec::new(),
            dependencies: Vec::new(),
            vulnerabilities: Vec::new(),
            vulnerability_extras: Vec::new(),
            completeness: None,
            signature: None,
            sidecar: None,
        }
    }
}

impl SbomFixture {
    /// Mutable access to a listed component by name (panics when absent, so a
    /// typo in a test case fails loudly instead of silently testing nothing).
    pub fn component_mut(&mut self, name: &str) -> &mut ComponentFixture {
        self.components
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("fixture has no component named {name:?}"))
    }

    /// Mutable access to the primary component (panics when absent).
    pub fn primary_mut(&mut self) -> &mut ComponentFixture {
        self.primary
            .as_mut()
            .expect("fixture has no primary component")
    }

    /// Mutable access to a crypto asset by bom-ref (panics when absent).
    pub fn crypto_mut(&mut self, bom_ref: &str) -> &mut CryptoAssetFixture {
        self.crypto_assets
            .iter_mut()
            .find(|a| a.bom_ref == bom_ref)
            .unwrap_or_else(|| panic!("fixture has no crypto asset {bom_ref:?}"))
    }

    /// Mutable access to the CRA sidecar (panics when absent).
    pub fn sidecar_mut(&mut self) -> &mut CraSidecarMetadata {
        self.sidecar.as_mut().expect("fixture has no CRA sidecar")
    }

    /// Render the CycloneDX JSON document.
    pub fn to_json_string(&self) -> String {
        let mut doc = serde_json::Map::new();
        doc.insert("bomFormat".into(), serde_json::json!("CycloneDX"));
        doc.insert("specVersion".into(), serde_json::json!(self.spec_version));
        doc.insert("version".into(), serde_json::json!(1));
        if let Some(serial) = &self.serial_number {
            doc.insert("serialNumber".into(), serde_json::json!(serial));
        }

        let mut metadata = serde_json::Map::new();
        if let Some(ts) = &self.timestamp {
            metadata.insert("timestamp".into(), serde_json::json!(ts));
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
        if let Some(primary) = &self.primary {
            metadata.insert("component".into(), primary.to_json());
        }
        if !metadata.is_empty() {
            doc.insert("metadata".into(), serde_json::Value::Object(metadata));
        }

        let components: Vec<_> = self
            .components
            .iter()
            .map(ComponentFixture::to_json)
            .chain(self.crypto_assets.iter().map(CryptoAssetFixture::to_json))
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
                    v.insert(
                        "affects".into(),
                        serde_json::json!([{ "ref": affected_ref }]),
                    );
                    for (extra_id, extra) in &self.vulnerability_extras {
                        if extra_id != id {
                            continue;
                        }
                        let members = extra
                            .as_object()
                            .expect("vulnerability extras are JSON objects");
                        for (key, value) in members {
                            v.insert(key.clone(), value.clone());
                        }
                    }
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

    /// Parse the rendered document through the real CycloneDX parser, then
    /// attach the EOL status of every component that declares one (what EOL
    /// enrichment would add after parsing).
    pub fn parse(&self) -> NormalizedSbom {
        let json = self.to_json_string();
        let mut sbom = parse_sbom_str(&json)
            .unwrap_or_else(|e| panic!("fixture must parse as CycloneDX: {e}\n{json}"));
        for fixture in self.primary.iter().chain(&self.components) {
            let Some(status) = fixture.eol else {
                continue;
            };
            let comp = sbom
                .components
                .values_mut()
                .find(|c| c.identifiers.format_id == fixture.bom_ref)
                .unwrap_or_else(|| panic!("parsed SBOM lost component {:?}", fixture.bom_ref));
            comp.eol = Some(EolInfo {
                status,
                product: fixture.name.clone(),
                cycle: fixture.version.clone().unwrap_or_default(),
                eol_date: None,
                support_end_date: None,
                is_lts: false,
                latest_in_cycle: None,
                latest_release_date: None,
                days_until_eol: None,
            });
        }
        sbom
    }
}

/// Run one compliance standard over a fixture (real parser → real checker),
/// at the pinned test clock, with the fixture's CRA sidecar attached.
pub fn check(level: ComplianceLevel, fixture: &SbomFixture) -> ComplianceResult {
    let mut checker = clock::checker(level);
    if let Some(sidecar) = &fixture.sidecar {
        checker = checker.with_sidecar(sidecar.clone());
    }
    checker.check(&fixture.parse())
}

/// Render a result's violations, then its passed checks, for assertion
/// messages.
pub fn render_violations(result: &ComplianceResult) -> String {
    if result.violations.is_empty() && result.passed.is_empty() {
        return "  (no violations)".to_string();
    }
    let violations = result.violations.iter().map(|v| {
        format!(
            "  [{sev}] {rule} (sarif {sarif}): {msg}",
            sev = v.severity.name(),
            rule = v.rule_id,
            sarif = v.sarif_rule_id(),
            msg = v.message
        )
    });
    let passes = result.passed.iter().map(|p| {
        format!(
            "  [Pass] {rule} (sarif {sarif}): {msg}",
            rule = p.rule_id,
            sarif = p.sarif_rule_id(),
            msg = p.message
        )
    });
    violations.chain(passes).collect::<Vec<_>>().join("\n")
}

/// A minimal SPDX tag-value document whose `SPDXVersion` line reads
/// `SPDX-{version}`: one named, versioned, supplier-attributed package. The
/// fixture DSL renders CycloneDX only, so the format checks that read only
/// SPDX input are asserted through this document instead.
pub fn spdx_tag_value(version: &str) -> String {
    format!(
        "SPDXVersion: SPDX-{version}\n\
         DataLicense: CC0-1.0\n\
         SPDXID: SPDXRef-DOCUMENT\n\
         DocumentName: rule-matrix-spdx\n\
         DocumentNamespace: https://acme.example/spdxdocs/rule-matrix-spdx\n\
         Creator: Tool: acme-sbom-tool-1.0.0\n\
         Created: 2026-01-15T10:00:00Z\n\
         \n\
         PackageName: libalpha\n\
         SPDXID: SPDXRef-libalpha\n\
         PackageVersion: 1.0.0\n\
         PackageSupplier: Organization: Acme Components Ltd\n\
         PackageDownloadLocation: NOASSERTION\n\
         FilesAnalyzed: false\n\
         PackageLicenseDeclared: MIT\n\
         \n\
         Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-libalpha\n"
    )
}

/// Assert that `key`, a family's `SBOM-*-SPEC-VERSION-UNKNOWN` id, fires at
/// `level` once, as a Warning, on an SPDX document claiming version 4.0
/// (neither 2.x nor 3.x), and stays silent on SPDX 2.3. Both documents go
/// through the real parser and the checker at the pinned clock.
pub fn assert_spdx_version_unknown(level: ComplianceLevel, key: &str) {
    let run = |version: &str| {
        let sbom = parse_sbom_str(&spdx_tag_value(version))
            .unwrap_or_else(|e| panic!("SPDX-{version} tag-value document must parse: {e}"));
        clock::checker(level).check(&sbom)
    };
    let fired = |result: &ComplianceResult| -> Vec<ViolationSeverity> {
        result
            .violations
            .iter()
            .filter(|v| v.rule_id == key)
            .map(|v| v.severity)
            .collect()
    };
    let unknown = run("4.0");
    assert_eq!(
        fired(&unknown),
        vec![ViolationSeverity::Warning],
        "[{level:?}] an SPDX 4.0 document must fire {key} once as a Warning:\n{}",
        render_violations(&unknown)
    );
    let known = run("2.3");
    assert!(
        fired(&known).is_empty(),
        "[{level:?}] an SPDX 2.3 document must not fire {key}:\n{}",
        render_violations(&known)
    );
}

/// Assert a fully-conforming fixture yields a clean, compliant verdict.
pub fn assert_no_violations(level: ComplianceLevel, fixture: &SbomFixture) {
    let result = check(level, fixture);
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "[{level:?}] conforming fixture must pass with zero violations; got \
         is_compliant={compliant}:\n{violations}",
        compliant = result.is_compliant,
        violations = render_violations(&result)
    );
}

/// One firing case: a minimal fixture that must surface the rule at the
/// stated severity.
pub struct FiringCase {
    pub label: &'static str,
    pub severity: ViolationSeverity,
    /// `true` when the push site intentionally emits a severity different
    /// from the registry's documented default (registry doc: "Push sites may
    /// still escalate/relax"). The runner enforces this flag's consistency,
    /// so deviations stay explicit instead of accidental.
    pub departs_from_registry_default: bool,
    pub fixture: SbomFixture,
}

/// A firing or silent case a row cannot assert yet, kept in the matrix with
/// the reason (the bug or limitation that blocks it) so it is never dropped
/// silently.
pub struct SkippedCase {
    pub label: &'static str,
    pub reason: &'static str,
}

/// Another satisfying shape that must not surface the rule, beside the
/// row's main silent fixture (e.g. a document reference that satisfies a
/// rule the main fixture satisfies through the CRA sidecar).
pub struct SilentCase {
    pub label: &'static str,
    pub fixture: SbomFixture,
}

/// One passing case of a pass-only rule: a minimal fixture whose SBOM passes
/// the check, so the rule must be reported among the result's passed checks
/// (and never among its violations).
pub struct PassingCase {
    pub label: &'static str,
    pub fixture: SbomFixture,
}

/// Coverage for one rule of a standard's universe. The silent fixture is
/// boxed to keep the variants comparable in size
/// (clippy::large_enum_variant).
pub enum RuleCoverage {
    Tested {
        firing: Vec<FiringCase>,
        silent: Box<SbomFixture>,
        extra_silent: Vec<SilentCase>,
        skipped_cases: Vec<SkippedCase>,
    },
    /// A pass-only rule (`RuleKind::Pass`): each passing case must report
    /// the rule among the result's passed checks, and the silent cases must
    /// report it nowhere. A pass has no severity; see [`run_matrix`] for
    /// what the registry-default rule means here.
    Passing {
        passing: Vec<PassingCase>,
        silent: Box<SbomFixture>,
        extra_silent: Vec<SilentCase>,
    },
    /// The rule genuinely cannot fire from document content alone (or has no
    /// emitting check site, or a bug blocks it); the reason is part of the
    /// matrix.
    Skipped { reason: &'static str },
}

/// Which identity of an emitted violation a row matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleScope {
    /// The externally-visible SARIF rule id (`Violation::sarif_rule_id`).
    /// These rows must cover the standard's universe exactly.
    Sarif,
    /// The internal registry key (`Violation::rule_id`) of a key that exists
    /// only as an alias of a shared SARIF rule; asserting the SARIF id alone
    /// cannot tell such keys apart.
    Key,
}

/// One row of the per-standard matrix.
pub struct RuleEntry {
    /// SARIF rule id ([`RuleScope::Sarif`]) or registry key
    /// ([`RuleScope::Key`]).
    pub id: &'static str,
    pub scope: RuleScope,
    pub coverage: RuleCoverage,
}

impl RuleEntry {
    fn tested_case(
        id: &'static str,
        scope: RuleScope,
        severity: ViolationSeverity,
        departs_from_registry_default: bool,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self {
            id,
            scope,
            coverage: RuleCoverage::Tested {
                firing: vec![FiringCase {
                    label: "firing",
                    severity,
                    departs_from_registry_default,
                    fixture: firing,
                }],
                silent: Box::new(silent),
                extra_silent: Vec::new(),
                skipped_cases: Vec::new(),
            },
        }
    }

    /// Rule with a firing case at the registry's default severity plus a
    /// silent case.
    pub fn tested(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(sarif_id, RuleScope::Sarif, severity, false, firing, silent)
    }

    /// Rule whose main firing case intentionally departs from the registry's
    /// documented default severity (push-site escalation/relaxation).
    pub fn tested_departing(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(sarif_id, RuleScope::Sarif, severity, true, firing, silent)
    }

    /// Per-key row: the alias key `key` (matched on `Violation::rule_id`)
    /// fires at the key's registry default severity; the silent fixture must
    /// not emit the key.
    pub fn key_tested(
        key: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(key, RuleScope::Key, severity, false, firing, silent)
    }

    /// Per-key row whose main firing case departs from the key's registry
    /// default severity.
    pub fn key_tested_departing(
        key: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(key, RuleScope::Key, severity, true, firing, silent)
    }

    fn passing_case(
        id: &'static str,
        scope: RuleScope,
        passing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self {
            id,
            scope,
            coverage: RuleCoverage::Passing {
                passing: vec![PassingCase {
                    label: "passing",
                    fixture: passing,
                }],
                silent: Box::new(silent),
                extra_silent: Vec::new(),
            },
        }
    }

    /// Pass-only rule (`RuleKind::Pass`): a passing case, whose SBOM passes
    /// the check, plus a silent case.
    pub fn passing(sarif_id: &'static str, passing: SbomFixture, silent: SbomFixture) -> Self {
        Self::passing_case(sarif_id, RuleScope::Sarif, passing, silent)
    }

    /// Per-key row for a pass-only alias key (matched on
    /// `PassedCheck::rule_id`).
    pub fn key_passing(key: &'static str, passing: SbomFixture, silent: SbomFixture) -> Self {
        Self::passing_case(key, RuleScope::Key, passing, silent)
    }

    /// Additional passing case of a pass-only row.
    #[must_use]
    pub fn with_passing(mut self, label: &'static str, fixture: SbomFixture) -> Self {
        match &mut self.coverage {
            RuleCoverage::Passing { passing, .. } => passing.push(PassingCase { label, fixture }),
            _ => panic!("{} is no pass-only row; add a firing case instead", self.id),
        }
        self
    }

    /// Additional firing case at the registry's default severity.
    #[must_use]
    pub fn with_firing(
        mut self,
        label: &'static str,
        severity: ViolationSeverity,
        fixture: SbomFixture,
    ) -> Self {
        self.push_firing(FiringCase {
            label,
            severity,
            departs_from_registry_default: false,
            fixture,
        });
        self
    }

    /// Additional firing case at a push-site severity that departs from the
    /// registry default.
    #[must_use]
    pub fn with_departing_firing(
        mut self,
        label: &'static str,
        severity: ViolationSeverity,
        fixture: SbomFixture,
    ) -> Self {
        self.push_firing(FiringCase {
            label,
            severity,
            departs_from_registry_default: true,
            fixture,
        });
        self
    }

    /// Additional silent case: another satisfying fixture that must not emit
    /// the row's identity.
    #[must_use]
    pub fn with_silent(mut self, label: &'static str, fixture: SbomFixture) -> Self {
        match &mut self.coverage {
            RuleCoverage::Tested { extra_silent, .. }
            | RuleCoverage::Passing { extra_silent, .. } => {
                extra_silent.push(SilentCase { label, fixture });
            }
            RuleCoverage::Skipped { .. } => {
                panic!("cannot add a silent case to skipped rule {}", self.id)
            }
        }
        self
    }

    /// A case the row cannot assert yet; `reason` names the bug or
    /// limitation precisely.
    #[must_use]
    pub fn with_skipped_case(mut self, label: &'static str, reason: &'static str) -> Self {
        match &mut self.coverage {
            RuleCoverage::Tested { skipped_cases, .. } => {
                skipped_cases.push(SkippedCase { label, reason });
            }
            RuleCoverage::Passing { .. } => {
                panic!("pass-only row {} takes no skipped case", self.id)
            }
            RuleCoverage::Skipped { .. } => {
                panic!("cannot add a skipped case to skipped rule {}", self.id)
            }
        }
        self
    }

    fn push_firing(&mut self, case: FiringCase) {
        match &mut self.coverage {
            RuleCoverage::Tested { firing, .. } => firing.push(case),
            RuleCoverage::Passing { .. } => {
                panic!(
                    "pass-only row {} fires no violation; add a passing case",
                    self.id
                )
            }
            RuleCoverage::Skipped { .. } => {
                panic!("cannot add a firing case to skipped rule {}", self.id)
            }
        }
    }

    /// Explicit skip-with-reason entry (counted by the exhaustiveness gate).
    pub fn skipped(sarif_id: &'static str, reason: &'static str) -> Self {
        Self {
            id: sarif_id,
            scope: RuleScope::Sarif,
            coverage: RuleCoverage::Skipped { reason },
        }
    }

    /// Explicit skip-with-reason entry for an alias key.
    pub fn key_skipped(key: &'static str, reason: &'static str) -> Self {
        Self {
            id: key,
            scope: RuleScope::Key,
            coverage: RuleCoverage::Skipped { reason },
        }
    }

    /// Whether `v` carries this row's identity.
    fn matches(&self, v: &Violation) -> bool {
        match self.scope {
            RuleScope::Sarif => v.sarif_rule_id() == self.id,
            RuleScope::Key => v.rule_id == self.id,
        }
    }

    /// Whether the passed check `p` carries this row's identity.
    fn matches_pass(&self, p: &PassedCheck) -> bool {
        match self.scope {
            RuleScope::Sarif => p.sarif_rule_id() == self.id,
            RuleScope::Key => p.rule_id == self.id,
        }
    }
}

/// Run a per-standard rule matrix:
///
/// 1. exhaustiveness — the SARIF rows must cover `universe` exactly (every
///    rule id tested or explicitly skipped, no duplicates, no strays); each
///    per-key row must name a registered alias key whose SARIF identity is
///    in `universe`;
/// 2. per rule — each firing fixture surfaces the row's id at the expected
///    severity (with registry-default consistency enforced), each passing
///    fixture of a pass-only row reports the row's id among its passed
///    checks and never as a violation, and each silent fixture stays silent
///    for that id (no violation, no pass);
/// 3. sweep — every violation and every passed check any fixture emits maps
///    into `universe`, every alias key a fixture emits has its own per-key
///    row, and every Info violation is a rule classified in
///    tests/common/info_classification.rs.
///
/// The registry default severity is what the SARIF rule catalogue
/// advertises, so a finding row needs a firing case at it (WP 1.2 finding
/// B6). A pass has no severity: a pass-only row instead needs a passing
/// case, its rule must be a `RuleKind::Pass` rule of the registry (and a
/// finding row's a `RuleKind::Finding` one), and its registry default must
/// be `Info`, the convention under which the catalogue declares a pass-only
/// rule at `note` while its `--sarif-include-passes` results carry
/// `kind: "pass"` at level `none`.
pub fn run_matrix(level: ComplianceLevel, universe: &[&str], entries: &[RuleEntry]) {
    let universe_set: BTreeSet<&str> = universe.iter().copied().collect();
    assert_eq!(
        universe.len(),
        universe_set.len(),
        "[{level:?}] rule universe contains duplicates"
    );

    let mut covered: BTreeSet<&str> = BTreeSet::new();
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        match entry.scope {
            RuleScope::Sarif => assert!(
                covered.insert(entry.id),
                "[{level:?}] duplicate matrix entry for {}",
                entry.id
            ),
            RuleScope::Key => {
                assert!(
                    keys.insert(entry.id),
                    "[{level:?}] duplicate per-key entry for {}",
                    entry.id
                );
                let meta = rule_meta(entry.id).unwrap_or_else(|| {
                    panic!(
                        "[{level:?}] per-key row {} is not a registered key",
                        entry.id
                    )
                });
                assert_ne!(
                    meta.sarif_id, entry.id,
                    "[{level:?}] per-key row {} is its own SARIF rule; use a SARIF row",
                    entry.id
                );
                assert!(
                    universe_set.contains(meta.sarif_id),
                    "[{level:?}] per-key row {} aliases {} outside the rule universe",
                    entry.id,
                    meta.sarif_id
                );
            }
        }
        match &entry.coverage {
            RuleCoverage::Skipped { reason } => assert!(
                !reason.trim().is_empty(),
                "[{level:?}] {} is skipped without a reason",
                entry.id
            ),
            RuleCoverage::Tested { skipped_cases, .. } => {
                for case in skipped_cases {
                    assert!(
                        !case.reason.trim().is_empty(),
                        "[{level:?}] {} ({}) is skipped without a reason",
                        entry.id,
                        case.label
                    );
                }
            }
            RuleCoverage::Passing { .. } => {}
        }
    }
    assert_eq!(
        covered, universe_set,
        "[{level:?}] the matrix must cover the standard's rule universe \
         exactly: every rule id is tested or explicitly skipped with a reason \
         (left = matrix entries, right = universe)"
    );

    for entry in entries {
        let (firing, silent, extra_silent) = match &entry.coverage {
            RuleCoverage::Tested {
                firing,
                silent,
                extra_silent,
                ..
            } => (firing, silent, extra_silent),
            RuleCoverage::Passing {
                passing,
                silent,
                extra_silent,
            } => {
                check_passing_row(level, entry, passing, silent, extra_silent);
                continue;
            }
            // Skip-with-reason rows carry their justification inline.
            RuleCoverage::Skipped { .. } => continue,
        };
        let id = entry.id;
        let meta = rule_meta(id)
            .unwrap_or_else(|| panic!("[{level:?}] {id} does not resolve in the rule registry"));
        assert_eq!(
            rule_kind(id),
            Some(RuleKind::Finding),
            "[{level:?}] {id} is a pass-only rule: give it a RuleEntry::passing row"
        );

        assert!(!firing.is_empty(), "[{level:?}] {id} has no firing case");
        // The registry default is what the SARIF rule catalogue advertises,
        // so some check must emit it: a rule whose severity is not context-
        // dependent emits only its default, and one that escalates or relaxes
        // by product class, phase or context still emits its default in its
        // most common case. A row whose every firing case departs from the
        // default documents a level no check emits (WP 1.2 finding B6).
        assert!(
            firing
                .iter()
                .any(|case| !case.departs_from_registry_default),
            "[{level:?}] {id}: no firing case is at the registry default severity \
             {default:?} (emitted: {emitted:?}) — the SARIF catalogue would advertise a \
             level no check emits; align the registry default with the emitted severity \
             (the most common one when it depends on context) and document the escalation",
            default = meta.default_severity,
            emitted = firing.iter().map(|case| case.severity).collect::<Vec<_>>(),
        );
        for case in firing {
            // The flag keeps severity expectations honest against the
            // registry: an expectation that silently matches (or silently
            // departs from) the documented default fails here.
            assert_eq!(
                case.severity == meta.default_severity,
                !case.departs_from_registry_default,
                "[{level:?}] {id} ({label}): expected severity {expected:?} vs registry \
                 default {default:?} — update the departs_from_registry_default flag \
                 (or the expectation) so the deviation is explicit",
                label = case.label,
                expected = case.severity,
                default = meta.default_severity,
            );

            let result = check(level, &case.fixture);
            let hits: Vec<_> = result
                .violations
                .iter()
                .filter(|v| entry.matches(v))
                .collect();
            assert!(
                !hits.is_empty(),
                "[{level:?}] {id} ({label}): the violating fixture must fire this rule; \
                 emitted:\n{violations}",
                label = case.label,
                violations = render_violations(&result)
            );
            assert!(
                hits.iter().any(|v| v.severity == case.severity),
                "[{level:?}] {id} ({label}): rule fired but not at {expected:?}; \
                 emitted:\n{violations}",
                label = case.label,
                expected = case.severity,
                violations = render_violations(&result)
            );
        }

        assert_silent(level, entry, silent, extra_silent);
    }

    // Universe sweep: no fixture in this matrix may emit a rule outside the
    // declared universe, or an alias key without its own per-key row. A new
    // check site for this standard must extend the universe (and therefore
    // the matrix) instead of escaping it.
    for entry in entries {
        let fixtures: Vec<(&str, &SbomFixture)> = match &entry.coverage {
            RuleCoverage::Tested {
                firing,
                silent,
                extra_silent,
                ..
            } => firing
                .iter()
                .map(|c| (c.label, &c.fixture))
                .chain(std::iter::once(("silent", silent.as_ref())))
                .chain(extra_silent.iter().map(|c| (c.label, &c.fixture)))
                .collect(),
            RuleCoverage::Passing {
                passing,
                silent,
                extra_silent,
            } => passing
                .iter()
                .map(|c| (c.label, &c.fixture))
                .chain(std::iter::once(("silent", silent.as_ref())))
                .chain(extra_silent.iter().map(|c| (c.label, &c.fixture)))
                .collect(),
            RuleCoverage::Skipped { .. } => continue,
        };
        for (label, fixture) in fixtures {
            let result = check(level, fixture);
            // An Info violation is a reviewed gap or advice; an affirmation
            // would be a passed check instead.
            for v in &result.violations {
                assert!(
                    v.severity != ViolationSeverity::Info
                        || info_classification::info_finding_reason(v.rule_id).is_some(),
                    "[{level:?}] fixture for {id} ({label}) reported {rule} at Info, which \
                     tests/common/info_classification.rs does not classify: list it with the \
                     reason it stays a violation, or make it a pass-only rule",
                    id = entry.id,
                    rule = v.rule_id,
                );
            }
            let emitted = result
                .violations
                .iter()
                .map(|v| (v.rule_id, v.sarif_rule_id()))
                .chain(result.passed.iter().map(|p| (p.rule_id, p.sarif_rule_id())));
            for (rule, sarif) in emitted {
                assert!(
                    universe_set.contains(sarif),
                    "[{level:?}] fixture for {id} ({label}) emitted rule {rule} \
                     (sarif {sarif}) outside the declared rule universe {universe_set:?} — \
                     new check site? extend the universe and the matrix",
                    id = entry.id,
                );
                let meta = rule_meta(rule).unwrap_or_else(|| {
                    panic!(
                        "[{level:?}] fixture for {id} ({label}) emitted unregistered rule {rule}",
                        id = entry.id,
                    )
                });
                assert!(
                    meta.sarif_id == rule || keys.contains(rule),
                    "[{level:?}] fixture for {id} ({label}) emitted alias key {rule} \
                     (sarif {sarif}) with no per-key row — add RuleEntry::key_tested \
                     (or key_passing, or key_skipped with a reason) for it",
                    id = entry.id,
                    sarif = meta.sarif_id,
                );
            }
        }
    }
}

/// The silent cases of a row: none may surface the row's rule, as a
/// violation or as a passed check.
fn assert_silent(
    level: ComplianceLevel,
    entry: &RuleEntry,
    silent: &SbomFixture,
    extra_silent: &[SilentCase],
) {
    let id = entry.id;
    let silent_cases = std::iter::once(("silent", silent))
        .chain(extra_silent.iter().map(|c| (c.label, &c.fixture)));
    for (label, fixture) in silent_cases {
        let result = check(level, fixture);
        assert!(
            result.violations.iter().all(|v| !entry.matches(v))
                && result.passed.iter().all(|p| !entry.matches_pass(p)),
            "[{level:?}] {id} ({label}): the silent fixture must not surface this rule; \
             emitted:\n{violations}",
            violations = render_violations(&result)
        );
    }
}

/// A pass-only row: the rule is a registered pass-only rule declared at the
/// `Info` default (see [`run_matrix`]), every passing fixture reports it
/// among its passed checks and never as a violation, and the silent
/// fixtures surface it nowhere.
fn check_passing_row(
    level: ComplianceLevel,
    entry: &RuleEntry,
    passing: &[PassingCase],
    silent: &SbomFixture,
    extra_silent: &[SilentCase],
) {
    let id = entry.id;
    let meta = rule_meta(id)
        .unwrap_or_else(|| panic!("[{level:?}] {id} does not resolve in the rule registry"));
    assert_eq!(
        rule_kind(id),
        Some(RuleKind::Pass),
        "[{level:?}] {id} has a passing row but is no pass-only rule (PASS_RULE_IDS)"
    );
    assert_eq!(
        meta.default_severity,
        ViolationSeverity::Info,
        "[{level:?}] {id}: a pass-only rule keeps the Info registry default, which the \
         SARIF catalogue declares as `note`"
    );
    assert!(!passing.is_empty(), "[{level:?}] {id} has no passing case");
    for case in passing {
        let result = check(level, &case.fixture);
        assert!(
            result.passed.iter().any(|p| entry.matches_pass(p)),
            "[{level:?}] {id} ({label}): the passing fixture must pass this check; \
             emitted:\n{violations}",
            label = case.label,
            violations = render_violations(&result)
        );
        assert!(
            result.violations.iter().all(|v| !entry.matches(v)),
            "[{level:?}] {id} ({label}): a pass-only rule must never report a violation; \
             emitted:\n{violations}",
            label = case.label,
            violations = render_violations(&result)
        );
    }
    assert_silent(level, entry, silent, extra_silent);
}
