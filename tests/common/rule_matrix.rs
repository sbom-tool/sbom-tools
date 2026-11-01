//! Registry-driven per-rule compliance test harness (audit P3).
//!
//! Provides four things to the `tests/rule_matrix_*.rs` integration tests:
//!
//! 1. **A minimal fixture DSL** ([`SbomFixture`] / [`ComponentFixture`] /
//!    [`CryptoAssetFixture`]) that renders a small SBOM and feeds it through
//!    the *real* parser (`parse_sbom_str`), so every matrix case exercises
//!    the same normalization path a production `validate` run does — not a
//!    hand-built `NormalizedSbom` that may drift from what parsers actually
//!    produce. A fixture can also carry a CRA sidecar, attached to the
//!    checker like `--cra-sidecar`.
//!
//! 2. **A format axis** ([`Encoding`], tests/common/rule_matrix_encodings.rs):
//!    one fixture renders as CycloneDX JSON, CycloneDX XML, SPDX 2.3 JSON and
//!    SPDX 3.0.1 JSON-LD, each field written where its format keeps it and
//!    the parsers read it. Every matrix case runs in all four encodings and
//!    must reach the same outcome in each — the same rule at the same
//!    severity, silence, or a pass — unless its entry declares otherwise
//!    with a reason: [`RuleEntry::only`] or [`RuleEntry::case_only`] when an
//!    encoding cannot carry what the case is about (or a named bug blocks
//!    it), [`RuleEntry::case_differs`] when a format legitimately reaches a
//!    different outcome (a check evidence-gated to SPDX, say), which the
//!    runner then asserts. An omission must be load-bearing: a case that
//!    renders without dropping a field and holds in an omitted encoding
//!    fails as a stale omission.
//!
//! 3. **A table-driven matrix runner** ([`run_matrix`]): every SARIF rule id
//!    in a standard's rule universe gets at least one *firing* case (a
//!    minimal SBOM that must surface the rule, with the expected severity)
//!    and one *silent* case (a minimal SBOM that must not surface it), or an
//!    explicit skip-with-reason entry. A pass-only rule (`RuleKind::Pass`,
//!    such as SBOM-PQC-009) gets *passing* cases instead of firing ones: the
//!    rule must appear among the result's passed checks, never among its
//!    violations. No silent omissions: the runner fails if the entry table
//!    and the declared universe differ. Every check is its own SARIF rule, so
//!    a row matches one check.
//!
//! 4. **A universe sweep**: every violation and every passed check emitted
//!    by every fixture in a matrix, in every encoding it runs in, must map
//!    (via its registry SARIF identity) into the standard's declared rule
//!    universe — a new check site that emits a new rule id forces the matrix
//!    to be extended instead of silently escaping it. The universe must be
//!    the level's rule list (`rules_for_level`), so the matrix proves that
//!    list: every listed rule fires in a case (or is skipped with a reason),
//!    and no case emits a rule outside it.
//!
//! 5. **An every-level sweep**: each fixture, in every encoding it runs in,
//!    is also checked at every other compliance level, and what each level
//!    reports must lie in that level's rule list. Every level's list is thus
//!    held against the fixtures of every matrix, not only its own.

// Each per-standard matrix binary uses a subset of the DSL (mirrors the
// existing tests/common/ffi_helpers.rs posture).
#![allow(dead_code)]

#[path = "clock.rs"]
pub mod clock;

#[path = "info_classification.rs"]
pub mod info_classification;

#[path = "rule_matrix_encodings.rs"]
mod encodings;

pub use encodings::{Encoding, Rendered};

use sbom_tools::model::{CraSidecarMetadata, EolInfo, EolStatus, NormalizedSbom};
use sbom_tools::parsers::{FormatDetector, parse_sbom_str};
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, PassedCheck, RuleKind, Violation, ViolationSeverity,
    rule_kind, rule_meta, rules_for_level,
};
use std::collections::{BTreeMap, BTreeSet};

/// Filler SHA-256 digest (64 hex chars) for conforming components.
pub const SHA256_FILLER: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Filler SHA-512 digest (128 hex chars) for the BSI TR-03183-2 hash field.
pub const SHA512_FILLER: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// Filler MD5 digest (32 hex chars) for weak-hash cases.
pub const MD5_FILLER: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// SHA-256 values no hash rule counts, as `(case label, algorithm, value)`:
/// an empty value, one that is not hexadecimal (a `sha256:` prefix on the
/// filler), and one of the wrong length (an MD5-sized value). Every hash
/// rule counts only plausible digests.
pub const IMPLAUSIBLE_SHA256_DIGESTS: [(&str, &str, &str); 3] = [
    ("empty SHA-256 digest", "SHA-256", ""),
    (
        "SHA-256 digest that is not hexadecimal",
        "SHA-256",
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "SHA-256 digest of the wrong length",
        "SHA-256",
        "d41d8cd98f00b204e9800998ecf8427e",
    ),
];

/// SHA-512 values no hash rule counts, as for
/// [`IMPLAUSIBLE_SHA256_DIGESTS`]; the wrong-length one is SHA-256-sized.
pub const IMPLAUSIBLE_SHA512_DIGESTS: [(&str, &str, &str); 3] = [
    ("empty SHA-512 digest", "SHA-512", ""),
    (
        "SHA-512 digest that is not hexadecimal",
        "SHA-512",
        "not-a-digest-cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
    ),
    (
        "SHA-512 digest of the wrong length",
        "SHA-512",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
];

// ── Encoding omissions and differences shared by several matrices ─────────

/// A case about a CycloneDX specVersion runs in CycloneDX only.
pub const CYCLONEDX_VERSION_CASE: &str = "the case is about a CycloneDX specVersion, which SPDX \
     documents do not carry: the SPDX encodings write their own version";
/// A case about an SPDX version runs in SPDX only.
pub const SPDX_VERSION_CASE: &str =
    "the case is about an SPDX version, which CycloneDX documents do not carry";
/// A CBOM row runs in CycloneDX only.
pub const CBOM_IS_CYCLONEDX: &str = "SPDX 2.3 and SPDX 3.0 have no cryptographic-asset model: a \
     CBOM is CycloneDX 1.6+ only";
/// An AI-profile row runs in every encoding but SPDX 2.3.
pub const SPDX23_HAS_NO_AI_PROFILE: &str = "SPDX 2.3 has no AI or dataset profile (no model \
     type, model card or dataset evidence), so no SPDX 2.3 document is an AI-BOM";
/// A case about embedded vulnerability data cannot be written in SPDX 2.3.
pub const SPDX23_HAS_NO_VULNERABILITIES: &str = "SPDX 2.3 documents carry no vulnerability data";
/// SPDX 2.3 cannot declare completeness.
pub const SPDX23_HAS_NO_COMPLETENESS: &str = "SPDX 2.3 has no completeness declaration, so no \
     SPDX 2.3 document declares its inventory or dependency enumeration complete";
/// A case about the hash of a referenced document runs in CycloneDX only.
pub const SPDX_REFERENCES_CARRY_NO_HASH: &str = "SPDX external references carry no hash of the \
     referenced document";
/// The SPDX 3 parser reads no agent email.
pub const SPDX3_AGENT_EMAILS_NOT_READ: &str = "open gap: the SPDX 3 parser reads no agent email \
     (the Person or Organization externalIdentifier of type email), as the registry advice \
     says, so no SPDX 3 creator carries one";
/// The SPDX 3 parser does not read `validUntilTime`.
pub const SPDX3_VALID_UNTIL_NOT_READ: &str = "open gap: the SPDX 3 parser does not read the \
     primary package's validUntilTime, as the registry advice says, so no SPDX 3 document \
     states an end of support";
/// The SPDX 3 parser does not read `software_sbomType`.
pub const SPDX3_SBOM_TYPE_NOT_READ: &str = "open gap: the SPDX 3 parser does not read \
     software_sbomType, as the registry advice says, so no SPDX 3 document declares a \
     lifecycle phase";

/// One component of a [`SbomFixture`]: a CycloneDX `components[]` entry
/// (or `metadata.component` for the primary), an SPDX package.
#[derive(Debug, Clone)]
pub struct ComponentFixture {
    /// CycloneDX `bom-ref`; the SPDX element id derives from it. Kept
    /// distinct from `name` so the generic "may be missing bom-ref" Info
    /// check stays silent unless a case deliberately collapses the two —
    /// which every encoding then writes as a component without an
    /// identifier of its own.
    pub bom_ref: String,
    /// CycloneDX component `type` (`library` unless a case changes it).
    pub component_type: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// CycloneDX `cpe` (an SPDX `cpe23Type` reference / `cpe23` external
    /// identifier).
    pub cpe: Option<String>,
    /// `supplier.name`.
    pub supplier: Option<String>,
    /// `manufacturer.name` (CycloneDX 1.6+; SPDX has no manufacturer
    /// field).
    pub manufacturer: Option<String>,
    /// `description`.
    pub description: Option<String>,
    /// `copyright` (SPDX `copyrightText`).
    pub copyright: Option<String>,
    /// `(alg, content)` pairs, e.g. `("SHA-256", SHA256_FILLER)`.
    pub hashes: Vec<(String, String)>,
    /// `(type, url)` external references, e.g. `("vcs", "https://…")`.
    pub external_refs: Vec<(String, String)>,
    /// External references that carry `hashes[]`, rendered after
    /// [`Self::external_refs`]: `(type, url, (alg, content) pairs)`.
    pub hashed_external_refs: Vec<(String, String, Vec<(String, String)>)>,
    /// SPDX license ids rendered as `{"license": {"id": …}}` entries (the
    /// SPDX declared licence).
    pub licenses: Vec<String>,
    /// The concluded licence (SPDX `licenseConcluded` /
    /// `hasConcludedLicense`).
    pub concluded_license: Option<String>,
    /// End of support, `YYYY-MM-DD`: the CycloneDX `endOfSupport` property
    /// the parser lifts from the primary component, SPDX 2.3
    /// `validUntilDate`, SPDX 3 `validUntilTime`.
    pub support_end: Option<String>,
    /// Other `(name, value)` CycloneDX properties.
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
            cpe: None,
            supplier: Some("Acme Components Ltd".to_string()),
            manufacturer: None,
            description: None,
            copyright: None,
            hashes: vec![("SHA-256".to_string(), SHA256_FILLER.to_string())],
            external_refs: Vec::new(),
            hashed_external_refs: Vec::new(),
            licenses: Vec::new(),
            concluded_license: None,
            support_end: None,
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
/// `bom_ref`. No SPDX version can carry one.
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
}

/// The VEX analysis of an embedded vulnerability: CycloneDX
/// `analysis.state`, `analysis.justification`, `analysis.response[]` and
/// `analysis.detail`, and the `recommendation` and `workaround` texts.
#[derive(Debug, Clone, Default)]
pub struct VulnAnalysisFixture {
    /// `analysis.state` (e.g. `exploitable`).
    pub state: Option<String>,
    /// `analysis.justification`, a CycloneDX impactAnalysisJustification
    /// (e.g. `code_not_reachable`).
    pub justification: Option<String>,
    /// `analysis.response[]` (e.g. `update`, `workaround_available`).
    pub responses: Vec<String>,
    /// `analysis.detail`, the free-text description of the impact.
    pub detail: Option<String>,
    /// `recommendation`.
    pub recommendation: Option<String>,
    /// `workaround`.
    pub workaround: Option<String>,
}

/// A minimal SBOM, rendered in any [`Encoding`] and parsed through the real
/// parser. All fields are public so a test can clone a conforming baseline
/// and break exactly one aspect per case. `SbomFixture::default()` is an
/// empty CycloneDX 1.6 document; baselines spell out the fields they rely
/// on and take the rest from it (`..SbomFixture::default()`).
#[derive(Debug, Clone)]
pub struct SbomFixture {
    /// CycloneDX `specVersion`. The SPDX encodings write their own version
    /// ([`Self::spdx_version`]); a CycloneDX version outside 1.4–1.7 has no
    /// SPDX counterpart.
    pub spec_version: String,
    /// The SPDX version the SPDX encodings write (`SPDX-<v>` in SPDX 2.3,
    /// `creationInfo.specVersion` in SPDX 3); `None` → 2.3 and 3.0.1.
    pub spdx_version: Option<String>,
    /// Top-level `version`, the BOM revision (`None` omits it; SPDX has no
    /// revision counter).
    pub doc_version: Option<u32>,
    /// RFC 3339 `metadata.timestamp`; `None` → the parser stores the
    /// UNIX-epoch "unknown" sentinel (`has_known_timestamp() == false`).
    pub timestamp: Option<String>,
    /// `metadata.lifecycles[]` phases (or lifecycle names), SPDX 3
    /// `software_sbomType`.
    pub lifecycles: Vec<String>,
    /// Top-level `serialNumber` (SPDX 2.3 `documentNamespace`, the SPDX 3
    /// document's `spdxId`).
    pub serial_number: Option<String>,
    /// `metadata.tools` entries `(name, version)` → `CreatorType::Tool`.
    pub tools: Vec<(String, String)>,
    /// `metadata.authors` entries `(name, email)` → `CreatorType::Person`.
    pub authors: Vec<(String, Option<String>)>,
    /// `metadata.manufacturer` `(name, contact email)` →
    /// `CreatorType::Organization`.
    pub manufacturer: Option<(String, Option<String>)>,
    /// `metadata.supplier.name`, the supplier of the described product
    /// (SPDX keeps the supplier on the described package instead).
    pub supplier: Option<String>,
    /// `metadata.component` → `document.name` + primary component (joins
    /// `sbom.components` like any other component).
    pub primary: Option<ComponentFixture>,
    pub components: Vec<ComponentFixture>,
    /// bom-refs of listed components the document also describes, beside
    /// the primary: SPDX 2.3 `DESCRIBES` relationships and SPDX 3 Sbom
    /// `rootElement`s (an SPDX document can describe several sibling
    /// products; a CycloneDX document describes one).
    pub described: Vec<String>,
    /// Cryptographic assets, rendered into `components[]` after
    /// [`Self::components`].
    pub crypto_assets: Vec<CryptoAssetFixture>,
    /// `dependencies[]` entries: `(ref, dependsOn refs)`.
    pub dependencies: Vec<(String, Vec<String>)>,
    /// Dynamic links `(from ref, to ref)`: SPDX 2.3 `DYNAMIC_LINK`, SPDX 3
    /// `hasDynamicLink` relationships (CycloneDX dependencies have no link
    /// type).
    pub dynamic_links: Vec<(String, String)>,
    /// Document `vulnerabilities[]`: `(id, rating severity, affected
    /// bom-ref)`. An empty severity renders no `ratings` at all (an unrated
    /// vulnerability).
    pub vulnerabilities: Vec<(String, String, String)>,
    /// The analysis of the embedded vulnerability with the given id.
    pub vulnerability_analyses: Vec<(String, VulnAnalysisFixture)>,
    /// `compositions[0].aggregate` (e.g. `complete`, `incomplete`); SPDX 3
    /// relationship `completeness`.
    pub completeness: Option<String>,
    /// Top-level JSF `signature` as `(algorithm, value)` (an enveloped
    /// XML-DSig signature in XML, a `verifiedUsing` signature on the SPDX 3
    /// document).
    pub signature: Option<(String, String)>,
    /// SPDX 3 profiles the document uses but leaves out of its
    /// `profileConformance` (the SPDX 3 renderer declares every profile its
    /// elements use).
    pub undeclared_spdx3_profiles: Vec<String>,
    /// CRA sidecar metadata, attached to the checker by [`check`] the way
    /// `validate --cra-sidecar` attaches it.
    pub sidecar: Option<CraSidecarMetadata>,
}

impl Default for SbomFixture {
    fn default() -> Self {
        Self {
            spec_version: "1.6".to_string(),
            spdx_version: None,
            doc_version: Some(1),
            timestamp: None,
            lifecycles: Vec::new(),
            serial_number: None,
            tools: Vec::new(),
            authors: Vec::new(),
            manufacturer: None,
            supplier: None,
            primary: None,
            components: Vec::new(),
            described: Vec::new(),
            crypto_assets: Vec::new(),
            dependencies: Vec::new(),
            dynamic_links: Vec::new(),
            vulnerabilities: Vec::new(),
            vulnerability_analyses: Vec::new(),
            completeness: None,
            signature: None,
            undeclared_spdx3_profiles: Vec::new(),
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

    /// Parse the CycloneDX JSON rendering through the real parser (see
    /// [`Self::parse_in`]).
    pub fn parse(&self) -> NormalizedSbom {
        self.parse_in(Encoding::CycloneDxJson)
    }

    /// Render the fixture in `encoding` and parse it through the real
    /// parser, which must be the one `encoding` names, then attach the EOL
    /// status of every component that declares one (what EOL enrichment
    /// would add after parsing).
    pub fn parse_in(&self, encoding: Encoding) -> NormalizedSbom {
        self.parse_rendered(&self.render(encoding))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn parse_rendered(&self, rendered: &Rendered) -> Result<NormalizedSbom, String> {
        let encoding = rendered.encoding;
        let detection = FormatDetector::new().detect_from_content(&rendered.text);
        let (parser, variant) = encoding.expected_detection();
        if detection.parser != Some(parser) || detection.variant.as_deref() != Some(variant) {
            return Err(format!(
                "the {} rendering was detected as {:?} {:?}, not {parser:?} {variant:?}:\n{}",
                encoding.name(),
                detection.parser,
                detection.variant,
                rendered.text
            ));
        }
        let mut sbom = parse_sbom_str(&rendered.text).map_err(|e| {
            format!(
                "the {} rendering must parse: {e}\n{}",
                encoding.name(),
                rendered.text
            )
        })?;
        for fixture in self.all_components() {
            let Some(status) = fixture.eol else {
                continue;
            };
            let id = self.element_id(encoding, &fixture.bom_ref);
            let comp = sbom
                .components
                .values_mut()
                .find(|c| c.identifiers.format_id == id)
                .ok_or_else(|| {
                    format!("the parsed {} SBOM lost component {id:?}", encoding.name())
                })?;
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
        Ok(sbom)
    }
}

/// Run one compliance standard over the CycloneDX JSON rendering of a
/// fixture (see [`check_in`]).
pub fn check(level: ComplianceLevel, fixture: &SbomFixture) -> ComplianceResult {
    check_in(level, fixture, Encoding::CycloneDxJson)
}

/// Run one compliance standard over a fixture rendered in `encoding` (real
/// parser → real checker), at the pinned test clock, with the fixture's CRA
/// sidecar attached.
pub fn check_in(
    level: ComplianceLevel,
    fixture: &SbomFixture,
    encoding: Encoding,
) -> ComplianceResult {
    check_sbom(level, fixture, &fixture.parse_in(encoding))
}

fn check_sbom(
    level: ComplianceLevel,
    fixture: &SbomFixture,
    sbom: &NormalizedSbom,
) -> ComplianceResult {
    let mut checker = clock::checker(level);
    if let Some(sidecar) = &fixture.sidecar {
        checker = checker.with_sidecar(sidecar.clone());
    }
    checker.check(sbom)
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
/// matrix renders SPDX as JSON and JSON-LD; this document covers the
/// tag-value encoding of the SPDX-only version check.
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
/// `level` once, as a Warning, on an SPDX tag-value document claiming
/// version 4.0 (neither 2.x nor 3.x), and stays silent on SPDX 2.3. Both
/// documents go through the real parser and the checker at the pinned
/// clock.
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

/// Assert a fully-conforming fixture yields a clean, compliant verdict in
/// CycloneDX JSON.
pub fn assert_no_violations(level: ComplianceLevel, fixture: &SbomFixture) {
    assert_no_violations_in(level, fixture, &[Encoding::CycloneDxJson]);
}

/// Assert a fully-conforming fixture yields a clean, compliant verdict in
/// every encoding of `encodings`.
pub fn assert_no_violations_in(
    level: ComplianceLevel,
    fixture: &SbomFixture,
    encodings: &[Encoding],
) {
    for &encoding in encodings {
        let result = check_in(level, fixture, encoding);
        assert!(
            result.violations.is_empty() && result.is_compliant,
            "[{level:?}] conforming fixture must pass with zero violations in {}; got \
             is_compliant={compliant}:\n{violations}",
            encoding.name(),
            compliant = result.is_compliant,
            violations = render_violations(&result)
        );
    }
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

/// What a case must do in an encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Report the row's rule as a violation at this severity.
    Fires(ViolationSeverity),
    /// Surface the row's rule nowhere: no violation, no passed check.
    Silent,
    /// Report the row's rule among the passed checks, never as a violation.
    Passes,
}

/// A case-level departure from running in every encoding of the entry with
/// the case's own outcome.
struct Departure {
    label: &'static str,
    encodings: Vec<Encoding>,
    change: Change,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum Change {
    /// The case does not run in these encodings.
    Omit,
    /// The case reaches this outcome in these encodings.
    Expect(Outcome),
}

/// One row of the per-standard matrix.
pub struct RuleEntry {
    /// The SARIF rule id (`Violation::sarif_rule_id`) the row covers. Every
    /// check is its own SARIF rule, so this names exactly one check.
    pub id: &'static str,
    pub coverage: RuleCoverage,
    /// The encodings the entry runs in when [`Self::only`] narrows them,
    /// with the reason; all four otherwise.
    scope: Option<(Vec<Encoding>, &'static str)>,
    /// Per-case omissions and declared differences.
    departures: Vec<Departure>,
}

/// One case of a row, with the outcome it must reach wherever it runs
/// unchanged.
struct Case<'a> {
    label: &'static str,
    outcome: Outcome,
    fixture: &'a SbomFixture,
}

/// How a case runs in one encoding.
enum Plan {
    /// Run it; the outcome to assert, and the reason when a declared
    /// difference replaces the case's own outcome.
    Run(Outcome, Option<&'static str>),
    /// Leave it out, for this reason.
    Omit(&'static str),
}

impl RuleEntry {
    fn new(id: &'static str, coverage: RuleCoverage) -> Self {
        Self {
            id,
            coverage,
            scope: None,
            departures: Vec::new(),
        }
    }

    fn tested_case(
        id: &'static str,
        severity: ViolationSeverity,
        departs_from_registry_default: bool,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::new(
            id,
            RuleCoverage::Tested {
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
        )
    }

    /// Rule with a firing case at the registry's default severity plus a
    /// silent case.
    pub fn tested(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(sarif_id, severity, false, firing, silent)
    }

    /// Rule whose main firing case intentionally departs from the registry's
    /// documented default severity (push-site escalation/relaxation).
    pub fn tested_departing(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self::tested_case(sarif_id, severity, true, firing, silent)
    }

    fn passing_case(id: &'static str, passing: SbomFixture, silent: SbomFixture) -> Self {
        Self::new(
            id,
            RuleCoverage::Passing {
                passing: vec![PassingCase {
                    label: "passing",
                    fixture: passing,
                }],
                silent: Box::new(silent),
                extra_silent: Vec::new(),
            },
        )
    }

    /// Pass-only rule (`RuleKind::Pass`): a passing case, whose SBOM passes
    /// the check, plus a silent case.
    pub fn passing(sarif_id: &'static str, passing: SbomFixture, silent: SbomFixture) -> Self {
        Self::passing_case(sarif_id, passing, silent)
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

    /// One firing case at `severity` per digest no hash rule counts (see
    /// [`IMPLAUSIBLE_SHA256_DIGESTS`]): `with_digest(algorithm, value)`
    /// builds the case's fixture. A severity other than the registry's
    /// default is a declared departure.
    #[must_use]
    pub fn with_implausible_digests(
        mut self,
        severity: ViolationSeverity,
        digests: &[(&'static str, &'static str, &'static str)],
        with_digest: impl Fn(&str, &str) -> SbomFixture,
    ) -> Self {
        let departs = rule_meta(self.id).is_some_and(|m| m.default_severity != severity);
        for (label, algorithm, value) in digests {
            self.push_firing(FiringCase {
                label,
                severity,
                departs_from_registry_default: departs,
                fixture: with_digest(algorithm, value),
            });
        }
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

    /// Run the whole entry only in `encodings`: the others cannot carry what
    /// the row is about (or a bug blocks it), which `reason` names.
    #[must_use]
    pub fn only(mut self, encodings: &[Encoding], reason: &'static str) -> Self {
        self.assert_not_skipped("only");
        assert!(
            self.scope.is_none(),
            "{}: declare the encodings of an entry with one only()",
            self.id
        );
        self.scope = Some((encodings.to_vec(), reason));
        self
    }

    /// Run the case `label` only in `encodings` (of those the entry runs
    /// in): the others cannot carry what the case is about, or a bug blocks
    /// it, which `reason` names.
    #[must_use]
    pub fn case_only(
        mut self,
        label: &'static str,
        encodings: &[Encoding],
        reason: &'static str,
    ) -> Self {
        self.assert_not_skipped("case_only");
        let omitted = Encoding::ALL
            .iter()
            .copied()
            .filter(|e| !encodings.contains(e))
            .collect();
        self.departures.push(Departure {
            label,
            encodings: omitted,
            change: Change::Omit,
            reason,
        });
        self
    }

    /// In `encodings`, the case `label` legitimately reaches `outcome`
    /// instead of its own (a check evidence-gated to one format, say), for
    /// the format difference `reason` names. The runner asserts `outcome`
    /// there, and fails when the case's own outcome holds as well.
    #[must_use]
    pub fn case_differs(
        mut self,
        label: &'static str,
        encodings: &[Encoding],
        outcome: Outcome,
        reason: &'static str,
    ) -> Self {
        self.assert_not_skipped("case_differs");
        self.departures.push(Departure {
            label,
            encodings: encodings.to_vec(),
            change: Change::Expect(outcome),
            reason,
        });
        self
    }

    fn assert_not_skipped(&self, what: &str) {
        assert!(
            !matches!(self.coverage, RuleCoverage::Skipped { .. }),
            "{what}() on skipped rule {}: a skipped row runs in no encoding",
            self.id
        );
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
        Self::new(sarif_id, RuleCoverage::Skipped { reason })
    }

    /// Whether `v` carries this row's identity.
    fn matches(&self, v: &Violation) -> bool {
        v.sarif_rule_id() == self.id
    }

    /// Whether the passed check `p` carries this row's identity.
    fn matches_pass(&self, p: &PassedCheck) -> bool {
        p.sarif_rule_id() == self.id
    }

    /// The row's cases with their own outcomes: firing, then silent; or
    /// passing, then silent.
    fn cases(&self) -> Vec<Case<'_>> {
        fn silent_cases<'a>(silent: &'a SbomFixture, extra: &'a [SilentCase]) -> Vec<Case<'a>> {
            let main = Case {
                label: "silent",
                outcome: Outcome::Silent,
                fixture: silent,
            };
            std::iter::once(main)
                .chain(extra.iter().map(|c| Case {
                    label: c.label,
                    outcome: Outcome::Silent,
                    fixture: &c.fixture,
                }))
                .collect()
        }
        match &self.coverage {
            RuleCoverage::Tested {
                firing,
                silent,
                extra_silent,
                ..
            } => firing
                .iter()
                .map(|c| Case {
                    label: c.label,
                    outcome: Outcome::Fires(c.severity),
                    fixture: &c.fixture,
                })
                .chain(silent_cases(silent, extra_silent))
                .collect(),
            RuleCoverage::Passing {
                passing,
                silent,
                extra_silent,
            } => passing
                .iter()
                .map(|c| Case {
                    label: c.label,
                    outcome: Outcome::Passes,
                    fixture: &c.fixture,
                })
                .chain(silent_cases(silent, extra_silent))
                .collect(),
            RuleCoverage::Skipped { .. } => Vec::new(),
        }
    }

    /// The encodings the entry runs in.
    fn encodings(&self) -> Vec<Encoding> {
        self.scope.as_ref().map_or_else(
            || Encoding::ALL.to_vec(),
            |(encodings, _)| encodings.clone(),
        )
    }

    /// How `case` runs in `encoding`.
    fn plan(&self, case: &Case<'_>, encoding: Encoding) -> Plan {
        if let Some((encodings, reason)) = &self.scope
            && !encodings.contains(&encoding)
        {
            return Plan::Omit(reason);
        }
        for d in &self.departures {
            if d.label == case.label && d.encodings.contains(&encoding) {
                return match d.change {
                    Change::Omit => Plan::Omit(d.reason),
                    Change::Expect(outcome) => Plan::Run(outcome, Some(d.reason)),
                };
            }
        }
        Plan::Run(case.outcome, None)
    }

    /// Whether `result` reaches `outcome` for this row, or why not.
    fn reaches(&self, result: &ComplianceResult, outcome: Outcome) -> Result<(), &'static str> {
        let violations: Vec<&Violation> = result
            .violations
            .iter()
            .filter(|v| self.matches(v))
            .collect();
        let passed = result.passed.iter().any(|p| self.matches_pass(p));
        match outcome {
            Outcome::Fires(severity) => {
                if violations.is_empty() {
                    Err("the violating fixture must fire this rule")
                } else if !violations.iter().any(|v| v.severity == severity) {
                    Err("the rule fired, but not at the expected severity")
                } else {
                    Ok(())
                }
            }
            Outcome::Silent if !violations.is_empty() || passed => {
                Err("the silent fixture must not surface this rule")
            }
            Outcome::Silent => Ok(()),
            Outcome::Passes if !passed => Err("the passing fixture must pass this check"),
            Outcome::Passes if !violations.is_empty() => {
                Err("a pass-only rule must never report a violation")
            }
            Outcome::Passes => Ok(()),
        }
    }

    /// Hold the entry's encodings and departures to their rules.
    fn validate_encodings(&self, level: ComplianceLevel) {
        let id = self.id;
        if let Some((encodings, reason)) = &self.scope {
            let unique: BTreeSet<_> = encodings.iter().collect();
            assert!(
                !encodings.is_empty() && unique.len() == encodings.len(),
                "[{level:?}] {id}: only() names each encoding at most once, and at least one"
            );
            assert!(
                encodings.len() < Encoding::ALL.len(),
                "[{level:?}] {id}: only() with every encoding narrows nothing; drop it"
            );
            assert!(
                !reason.trim().is_empty(),
                "[{level:?}] {id}: only() needs a reason"
            );
        }
        let cases = self.cases();
        let mut labels = BTreeSet::new();
        for case in &cases {
            assert!(
                labels.insert(case.label),
                "[{level:?}] {id}: two cases share the label {:?}",
                case.label
            );
        }
        let entry_encodings = self.encodings();
        let mut addressed = BTreeSet::new();
        for d in &self.departures {
            let case = cases
                .iter()
                .find(|c| c.label == d.label)
                .unwrap_or_else(|| panic!("[{level:?}] {id}: no case is labelled {:?}", d.label));
            assert!(
                !d.reason.trim().is_empty(),
                "[{level:?}] {id} ({}): a departure needs a reason",
                d.label
            );
            assert!(
                !d.encodings.is_empty(),
                "[{level:?}] {id} ({}): a departure names at least one encoding",
                d.label
            );
            for encoding in &d.encodings {
                assert!(
                    entry_encodings.contains(encoding) || matches!(d.change, Change::Omit),
                    "[{level:?}] {id} ({}): the entry does not run in {}",
                    d.label,
                    encoding.name()
                );
                assert!(
                    addressed.insert((d.label, *encoding)),
                    "[{level:?}] {id} ({}): {} is addressed by two departures",
                    d.label,
                    encoding.name()
                );
            }
            match d.change {
                Change::Omit => assert!(
                    entry_encodings.iter().any(|e| !d.encodings.contains(e)),
                    "[{level:?}] {id} ({}): case_only() leaves the case no encoding to run in",
                    d.label
                ),
                Change::Expect(outcome) => {
                    assert_ne!(
                        outcome, case.outcome,
                        "[{level:?}] {id} ({}): case_differs() repeats the case's own outcome",
                        d.label
                    );
                    let pass_row = matches!(self.coverage, RuleCoverage::Passing { .. });
                    assert!(
                        pass_row || outcome != Outcome::Passes,
                        "[{level:?}] {id} ({}): a finding rule never passes",
                        d.label
                    );
                    assert!(
                        !pass_row || !matches!(outcome, Outcome::Fires(_)),
                        "[{level:?}] {id} ({}): a pass-only rule never fires",
                        d.label
                    );
                }
            }
        }
    }
}

/// Run a per-standard rule matrix:
///
/// 0. membership — `universe` must be the level's rule list
///    (`rules_for_level`), which the steps below prove;
/// 1. exhaustiveness — the rows must cover `universe` exactly (every rule id
///    tested or explicitly skipped, no duplicates, no strays);
/// 2. per rule and per encoding — each firing fixture surfaces the row's id
///    at the expected severity (with registry-default consistency
///    enforced), each passing fixture of a pass-only row reports the row's
///    id among its passed checks and never as a violation, and each silent
///    fixture stays silent for that id (no violation, no pass), in every
///    encoding the row runs the case in; a declared difference replaces the
///    outcome in its encodings, and an omission is held to being
///    load-bearing;
/// 3. sweep — every violation and every passed check any fixture emits, in
///    any encoding, maps into `universe`, and every Info violation is a rule
///    classified in tests/common/info_classification.rs;
/// 4. every-level sweep — every other level, run over the same parsed
///    fixture, reports only rules of its own list.
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
    // The matrix proves the level's rule list (`rules_for_level`, the
    // standard membership `sbom-tools rules` and SARIF rules[] show), so
    // it must cover that list exactly.
    let listed: BTreeSet<&str> = rules_for_level(level).iter().copied().collect();
    assert_eq!(
        universe_set, listed,
        "[{level:?}] the matrix universe must be the level's rule list \
         (left = universe, right = rules_for_level)"
    );

    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        assert!(
            covered.insert(entry.id),
            "[{level:?}] duplicate matrix entry for {}",
            entry.id
        );
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
        entry.validate_encodings(level);
    }
    assert_eq!(
        covered, universe_set,
        "[{level:?}] the matrix must cover the standard's rule universe \
         exactly: every rule id is tested or explicitly skipped with a reason \
         (left = matrix entries, right = universe)"
    );

    // Every case in every encoding: the failures are collected, so one run
    // shows each mismatch. A rule outside another level's list is reported
    // once per (level, rule), naming the first fixture that showed it.
    let mut failures: Vec<String> = Vec::new();
    let mut strays: BTreeMap<String, String> = BTreeMap::new();
    for entry in entries {
        match &entry.coverage {
            RuleCoverage::Tested { firing, .. } => check_finding_row(level, entry, firing),
            RuleCoverage::Passing { passing, .. } => check_passing_row(level, entry, passing),
            // Skip-with-reason rows carry their justification inline.
            RuleCoverage::Skipped { .. } => continue,
        }
        for case in entry.cases() {
            for &encoding in Encoding::ALL {
                match entry.plan(&case, encoding) {
                    Plan::Run(outcome, difference) => run_case(
                        level,
                        &universe_set,
                        entry,
                        &case,
                        encoding,
                        outcome,
                        difference,
                        &mut failures,
                        &mut strays,
                    ),
                    Plan::Omit(reason) => check_omission_load_bearing(
                        level,
                        entry,
                        &case,
                        encoding,
                        reason,
                        &mut failures,
                    ),
                }
            }
        }
    }
    failures.extend(strays.into_values());
    assert!(
        failures.is_empty(),
        "[{level:?}] {count} matrix failure(s):\n\n{all}",
        count = failures.len(),
        all = failures.join("\n\n")
    );
}

/// The registry side of a finding row: the rule resolves, is a finding rule,
/// and some firing case fires at the default severity the SARIF catalogue
/// advertises, every other one departing from it explicitly.
fn check_finding_row(level: ComplianceLevel, entry: &RuleEntry, firing: &[FiringCase]) {
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
    }
}

/// The registry side of a pass-only row: the rule is a registered pass-only
/// rule declared at the `Info` default (see [`run_matrix`]), with a passing
/// case.
fn check_passing_row(level: ComplianceLevel, entry: &RuleEntry, passing: &[PassingCase]) {
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
}

/// Run one case in one encoding: check its outcome, then sweep everything
/// the result reports into the universe and the Info classification, and
/// what every other level reports for the same SBOM into that level's list.
#[allow(clippy::too_many_arguments)]
fn run_case(
    level: ComplianceLevel,
    universe: &BTreeSet<&str>,
    entry: &RuleEntry,
    case: &Case<'_>,
    encoding: Encoding,
    outcome: Outcome,
    difference: Option<&'static str>,
    failures: &mut Vec<String>,
    strays: &mut BTreeMap<String, String>,
) {
    let id = entry.id;
    let label = case.label;
    let enc = encoding.name();
    let rendered = case.fixture.render(encoding);
    let sbom = match case.fixture.parse_rendered(&rendered) {
        Ok(sbom) => sbom,
        Err(e) => {
            failures.push(format!("[{level:?}] {id} ({label}) in {enc}: {e}"));
            return;
        }
    };
    let result = check_sbom(level, case.fixture, &sbom);
    let dropped = if rendered.dropped.is_empty() {
        String::new()
    } else {
        format!("\n  {enc} has no counterpart for: {:?}", rendered.dropped)
    };
    if let Err(why) = entry.reaches(&result, outcome) {
        let declared = difference.map_or_else(String::new, |reason| {
            format!(" (declared difference: {reason})")
        });
        failures.push(format!(
            "[{level:?}] {id} ({label}) in {enc}: {why}; expected {outcome:?}{declared}\
             {dropped}; emitted:\n{violations}",
            violations = render_violations(&result)
        ));
    } else if let Some(reason) = difference
        && entry.reaches(&result, case.outcome).is_ok()
    {
        failures.push(format!(
            "[{level:?}] {id} ({label}) in {enc}: the case also reaches its own outcome \
             {own:?}, so the declared difference ({reason}) is stale; drop it",
            own = case.outcome,
        ));
    }
    sweep(level, universe, entry, label, encoding, &result, failures);
    for &other in ComplianceLevel::all() {
        if other != level {
            let other_result = check_sbom(other, case.fixture, &sbom);
            level_sweep(other, level, entry, label, encoding, &other_result, strays);
        }
    }
}

/// Every-level sweep: what `checked` reports for a fixture of the `level`
/// matrix must lie in `checked`'s rule list (`rules_for_level`).
fn level_sweep(
    checked: ComplianceLevel,
    level: ComplianceLevel,
    entry: &RuleEntry,
    label: &str,
    encoding: Encoding,
    result: &ComplianceResult,
    strays: &mut BTreeMap<String, String>,
) {
    let listed = rules_for_level(checked);
    let emitted = result
        .violations
        .iter()
        .map(|v| (v.rule_id, v.sarif_rule_id()))
        .chain(result.passed.iter().map(|p| (p.rule_id, p.sarif_rule_id())));
    for (rule, sarif) in emitted {
        if !listed.contains(&sarif) {
            strays
                .entry(format!("{checked:?} {sarif}"))
                .or_insert_with(|| {
                    format!(
                        "[{checked:?}] reported {rule} (sarif {sarif}) for the fixture of {id} \
                         ({label}) in the {level:?} matrix, in {enc}; the rule is not in \
                         rules_for_level({checked:?}) — add it to that level's rule list in \
                         src/quality/compliance/registry.rs",
                        id = entry.id,
                        enc = encoding.name(),
                    )
                });
        }
    }
}

/// An omission must be load-bearing: a case that renders in the omitted
/// encoding without dropping a field, and reaches its own outcome there,
/// needs no omission.
fn check_omission_load_bearing(
    level: ComplianceLevel,
    entry: &RuleEntry,
    case: &Case<'_>,
    encoding: Encoding,
    reason: &'static str,
    failures: &mut Vec<String>,
) {
    let rendered = case.fixture.render(encoding);
    if !rendered.dropped.is_empty() {
        return;
    }
    let Ok(sbom) = case.fixture.parse_rendered(&rendered) else {
        return;
    };
    let result = check_sbom(level, case.fixture, &sbom);
    if entry.reaches(&result, case.outcome).is_ok() {
        failures.push(format!(
            "[{level:?}] {id} ({label}): the case renders in {enc} with nothing dropped and \
             reaches {outcome:?} there, so its omission ({reason}) is stale; run it in {enc}",
            id = entry.id,
            label = case.label,
            enc = encoding.name(),
            outcome = case.outcome,
        ));
    }
}

/// Universe sweep: no fixture in this matrix may emit a rule outside the
/// declared universe, or an unregistered rule, in any encoding. A new check
/// site for this standard must extend the universe (and therefore the
/// matrix) instead of escaping it. An Info violation is a reviewed gap or
/// advice; an affirmation would be a passed check instead.
fn sweep(
    level: ComplianceLevel,
    universe: &BTreeSet<&str>,
    entry: &RuleEntry,
    label: &str,
    encoding: Encoding,
    result: &ComplianceResult,
    failures: &mut Vec<String>,
) {
    let id = entry.id;
    let enc = encoding.name();
    for v in &result.violations {
        if v.severity == ViolationSeverity::Info
            && info_classification::info_finding_reason(v.rule_id).is_none()
        {
            failures.push(format!(
                "[{level:?}] fixture for {id} ({label}) in {enc} reported {rule} at Info, which \
                 tests/common/info_classification.rs does not classify: list it with the \
                 reason it stays a violation, or make it a pass-only rule",
                rule = v.rule_id,
            ));
        }
    }
    let emitted = result
        .violations
        .iter()
        .map(|v| (v.rule_id, v.sarif_rule_id()))
        .chain(result.passed.iter().map(|p| (p.rule_id, p.sarif_rule_id())));
    for (rule, sarif) in emitted {
        if !universe.contains(sarif) {
            failures.push(format!(
                "[{level:?}] fixture for {id} ({label}) in {enc} emitted rule {rule} \
                 (sarif {sarif}) outside the declared rule universe {universe:?} — \
                 new check site? extend the universe and the matrix",
            ));
        }
        if rule_meta(rule).is_none() {
            failures.push(format!(
                "[{level:?}] fixture for {id} ({label}) in {enc} emitted unregistered rule \
                 {rule}",
            ));
        }
    }
}
