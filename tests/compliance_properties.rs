//! Properties of the compliance engine over generated SBOMs.
//!
//! The snapshot harness pins the verdicts of the fixtures someone wrote
//! down; these properties check every level on SBOMs nobody wrote down.
//!
//! Each case is a [`NormalizedSbom`] built through the public model API from
//! a generated [`SbomSpec`], not a CycloneDX or SPDX document run through a
//! parser. The model reaches more of the engine: a spec sets every field the
//! checks read, in combinations no single format expresses (an SPDX document
//! with a CycloneDX `metadata.supplier`, a timestamp that did not parse,
//! dependency edges to components that are not there, crypto assets in any
//! format), and no parser normalizes a malformed value away before a check
//! sees it. The parsers' road into the engine is fuzzed by
//! `fuzz/fuzz_targets/fuzz_compliance.rs`, and the CLI's own text renderers
//! get the generated SBOMs as CycloneDX (see
//! `cli_text_and_summary_render_every_generated_sbom`).
//!
//! Every run is pinned to one instant. The RNG seed is fixed, so CI checks
//! the same cases every time; `PROPTEST_CASES` sets how many (64 by
//! default), and no failure is persisted to `proptest-regressions/`.

#[path = "common/json_schema.rs"]
mod json_schema;

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use sbom_tools::model::{
    AlgorithmProperties, CanonicalId, CertificateProperties, CipherSuite, Component, ComponentType,
    Contact, CraProductClass, Creator, CreatorType, CryptoAssetType, CryptoMaterialType,
    CryptoPrimitive, CryptoProperties, DatasetInfo, DependencyEdge, DependencyScope,
    DependencyType, DocumentMetadata, ExternalRefType, ExternalReference, Hash, HashAlgorithm,
    LicenseExpression, MlModelInfo, NormalizedSbom, Organization, ProtocolProperties, ProtocolType,
    RelatedCryptoMaterialProperties, SbomFormat, Severity, SignatureInfo, VulnerabilityRef,
    VulnerabilitySource,
};
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, ComplianceRunConfig, FindingIdentity, PqcMode, RuleKind,
    RuleSetting, RuleSettings, SettingSource, StandardSelector, ViolationSeverity, all_rule_ids,
    compliance_score, finding_subject, parse_as_of, rule_kind, rules_for_level, standard_key,
};
use sbom_tools::reports::{
    AssessedSbom, HtmlReporter, MarkdownReporter, ReportConfig, ReportGenerator, SarifArtifact,
    SarifArtifactLocation, SarifOptions, generate_compliance_json, generate_compliance_json_at,
    generate_compliance_sarif_with, generate_multi_compliance_sarif_with, oscal,
};
use serde_json::Value;

/// The instant every run judges (the shared test clock, tests/common/clock.rs).
const AS_OF: &str = "2026-10-12T00:00:00Z";

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/compliance/v2.schema.json"
);

fn as_of() -> DateTime<Utc> {
    parse_as_of(AS_OF).expect("valid instant")
}

/// 64 cases a property, or `PROPTEST_CASES`; a fixed seed; no persisted
/// failures.
fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        rng_seed: RngSeed::Fixed(0x5b0_7001_c0de),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ============================================================================
// What a generated SBOM is made of
//
// Every strategy is a `BoxedStrategy`, and composite strategies are boxed
// where they are combined (tuples, `prop_oneof!`): nested strategy types
// otherwise make symbol names of over 100,000 characters, which the MSVC
// linker cannot write to a PDB (LNK4319). Boxing changes no generated case.
// ============================================================================

/// A field as an SBOM gives it: absent, explicitly or vaguely unknown, or a
/// real value.
#[derive(Debug, Clone)]
enum Field {
    Absent,
    Unknown(&'static str),
    Known(String),
}

impl Field {
    fn text(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Unknown(text) => Some((*text).to_string()),
            Self::Known(text) => Some(text.clone()),
        }
    }

    const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// The sentinels and placeholders generators write for a value they do not
/// have (see src/model/known.rs), and blanks.
const UNKNOWNS: &[&str] = &[
    "NOASSERTION",
    "NONE",
    "unknown",
    "UNKNOWN",
    "",
    "  ",
    "TBD",
    "n/a",
    "-",
];

/// Text that renderers must clean or escape: markup, table and list
/// syntax, line breaks, CI workflow commands, bidi and control characters.
const ODD_TEXT: &[&str] = &[
    "<script>alert(1)</script>",
    "pipe|name",
    "line\nbreak",
    "::error ::injected",
    "ünïcødé ✓",
    "rtl\u{202e}txt",
    "tab\tand\rreturn",
    "back`tick*_[x](y)",
    "\u{1b}[31mred",
];

fn field(known: BoxedStrategy<String>) -> BoxedStrategy<Field> {
    prop_oneof![
        2 => Just(Field::Absent),
        1 => prop::sample::select(UNKNOWNS).prop_map(Field::Unknown),
        3 => known.prop_map(Field::Known),
    ]
    .boxed()
}

fn known_name() -> BoxedStrategy<String> {
    prop_oneof![
        5 => "[a-z][a-z0-9_.-]{0,12}",
        1 => prop::sample::select(ODD_TEXT).prop_map(str::to_string),
    ]
    .boxed()
}

fn known_version() -> BoxedStrategy<String> {
    prop_oneof![
        5 => "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
        1 => prop::sample::select(&["v2", "2024-01-01", "1.0.0-rc.1+build.5", "r1234"][..])
            .prop_map(str::to_string),
    ]
    .boxed()
}

/// A supplier, manufacturer or document supplier.
#[derive(Debug, Clone)]
struct OrgSpec {
    name: Field,
    url: bool,
    email: bool,
}

fn org() -> BoxedStrategy<OrgSpec> {
    (field(known_name()), any::<bool>(), any::<bool>())
        .prop_map(|(name, url, email)| OrgSpec { name, url, email })
        .boxed()
}

impl OrgSpec {
    fn build(&self) -> Option<Organization> {
        let mut org = Organization::new(self.name.text()?);
        if self.url {
            org.urls.push("https://acme-corp.eu".to_string());
        }
        if self.email {
            org.contacts.push(Contact {
                name: None,
                email: Some("security@acme-corp.eu".to_string()),
                phone: None,
            });
        }
        Some(org)
    }
}

/// A purl or a CPE: absent, a placeholder (which `Component::set_purl` and
/// `Component::add_cpe` drop, as they do for the parsers), well-formed for
/// the component, or malformed.
#[derive(Debug, Clone)]
enum IdSpec {
    Absent,
    Placeholder(&'static str),
    Valid,
    Malformed(&'static str),
}

fn purl() -> BoxedStrategy<IdSpec> {
    prop_oneof![
        3 => Just(IdSpec::Absent),
        1 => prop::sample::select(&["NOASSERTION", "", "unknown"][..]).prop_map(IdSpec::Placeholder),
        4 => Just(IdSpec::Valid),
        1 => prop::sample::select(
            &["pkg:", "pkg:npm", "pkg:/@", "pkg:npm/%zz@1", "pkg:cargo/a b@1", "pkg:npm/x@"][..]
        )
        .prop_map(IdSpec::Malformed),
    ].boxed()
}

fn cpe() -> BoxedStrategy<IdSpec> {
    prop_oneof![
        6 => Just(IdSpec::Absent),
        1 => Just(IdSpec::Placeholder("NOASSERTION")),
        2 => Just(IdSpec::Valid),
        1 => prop::sample::select(&["cpe:2.3:a", "cpe:/", "cpe:2.3:a:acme"][..])
            .prop_map(IdSpec::Malformed),
    ]
    .boxed()
}

/// The ecosystems a valid purl names.
const PURL_TYPES: &[&str] = &[
    "cargo",
    "npm",
    "pypi",
    "generic",
    "deb/debian",
    "maven/org.acme",
];

/// How a digest is written.
#[derive(Debug, Clone, Copy)]
enum Digest {
    /// Hex of the algorithm's length.
    Good,
    /// Half the length.
    Short,
    /// The right length, but not hex.
    NotHex,
    /// All zeros, the right length.
    Zero,
    Empty,
}

#[derive(Debug, Clone)]
struct HashSpec {
    algorithm: HashAlgorithm,
    digest: Digest,
}

/// The algorithms, strong and weak, with their digest length in hex.
fn hash_algorithms() -> Vec<(HashAlgorithm, usize)> {
    vec![
        (HashAlgorithm::Md5, 32),
        (HashAlgorithm::Sha1, 40),
        (HashAlgorithm::Sha256, 64),
        (HashAlgorithm::Sha384, 96),
        (HashAlgorithm::Sha512, 128),
        (HashAlgorithm::Sha3_256, 64),
        (HashAlgorithm::Sha3_512, 128),
        (HashAlgorithm::Blake2b256, 64),
        (HashAlgorithm::Blake3, 64),
        (HashAlgorithm::Streebog256, 64),
        (HashAlgorithm::Other("CRC32".to_string()), 8),
    ]
}

fn hash() -> BoxedStrategy<HashSpec> {
    (
        prop::sample::select(hash_algorithms()),
        prop_oneof![
            6 => Just(Digest::Good),
            1 => Just(Digest::Short),
            1 => Just(Digest::NotHex),
            1 => Just(Digest::Zero),
            1 => Just(Digest::Empty),
        ],
    )
        .prop_map(|((algorithm, _), digest)| HashSpec { algorithm, digest })
        .boxed()
}

impl HashSpec {
    /// The hash, its digest derived from `seed` so components differ.
    fn build(&self, seed: usize) -> Hash {
        let len = hash_algorithms()
            .into_iter()
            .find(|(algorithm, _)| *algorithm == self.algorithm)
            .map_or(64, |(_, len)| len);
        let good: String = format!(
            "{:016x}",
            (seed as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        )
        .repeat(len / 16 + 1)
        .chars()
        .take(len)
        .collect();
        let value = match self.digest {
            Digest::Good => good,
            Digest::Short => good[..len / 2].to_string(),
            Digest::NotHex => "z".repeat(len),
            Digest::Zero => "0".repeat(len),
            Digest::Empty => String::new(),
        };
        Hash::new(self.algorithm.clone(), value)
    }
}

/// Declared and concluded licenses: SPDX ids and expressions, a
/// `LicenseRef`, sentinels, free text and a broken expression.
const LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "GPL-3.0-only",
    "MIT OR Apache-2.0",
    "LicenseRef-acme",
    "NOASSERTION",
    "NONE",
    "Proprietary",
    "MIT AND (",
    "",
];

#[derive(Debug, Clone)]
struct LicenseSpec {
    declared: Vec<&'static str>,
    concluded: Option<&'static str>,
}

fn licenses() -> BoxedStrategy<LicenseSpec> {
    (
        prop::collection::vec(prop::sample::select(LICENSES), 0..3),
        prop::option::weighted(0.3, prop::sample::select(LICENSES)),
    )
        .prop_map(|(declared, concluded)| LicenseSpec {
            declared,
            concluded,
        })
        .boxed()
}

/// A cryptographic asset (CycloneDX `cryptoProperties`).
#[derive(Debug, Clone)]
enum CryptoSpec {
    Algorithm {
        family: &'static str,
        parameter: Option<&'static str>,
        quantum_level: Option<u8>,
        classical_level: Option<u32>,
    },
    Certificate {
        expires_in_days: Option<i64>,
        signature_algorithm: Option<&'static str>,
    },
    Material {
        size: Option<u32>,
        algorithm: Option<&'static str>,
    },
    Protocol {
        protocol: u8,
        version: Option<&'static str>,
        suites: Vec<&'static str>,
    },
    Other,
}

/// Algorithm families, quantum-safe and not, with their primitive.
const ALGORITHMS: &[&str] = &[
    "RSA", "ECDSA", "EdDSA", "AES", "3DES", "ML-KEM", "ML-DSA", "SLH-DSA", "SHA-256", "SHA-384",
    "MD5", "SHA-1", "X25519", "HMAC", "ChaCha20", "mystery",
];

fn primitive(family: &str) -> CryptoPrimitive {
    match family {
        "RSA" => CryptoPrimitive::Pke,
        "ECDSA" | "EdDSA" | "ML-DSA" | "SLH-DSA" => CryptoPrimitive::Signature,
        "AES" | "3DES" => CryptoPrimitive::BlockCipher,
        "ML-KEM" => CryptoPrimitive::Kem,
        "SHA-256" | "SHA-384" | "MD5" | "SHA-1" => CryptoPrimitive::Hash,
        "X25519" => CryptoPrimitive::KeyAgree,
        "HMAC" => CryptoPrimitive::Mac,
        "ChaCha20" => CryptoPrimitive::StreamCipher,
        _ => CryptoPrimitive::Unknown,
    }
}

/// `bom-ref`s a crypto asset names another by: the generated components'
/// format ids, and one that names nothing.
const CRYPTO_REFS: &[&str] = &["ref-0", "ref-1", "ref-2", "missing-ref"];

const CIPHER_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "not-a-suite",
];

fn crypto() -> BoxedStrategy<CryptoSpec> {
    prop_oneof![
        4 => (
            prop::sample::select(ALGORITHMS),
            prop::option::of(prop::sample::select(&["128", "256", "2048", "768", "1024", "87", "P-256"][..])),
            prop::option::of(0u8..=6),
            prop::option::of(prop::sample::select(&[0u32, 80, 112, 128, 256][..])),
        )
            .prop_map(|(family, parameter, quantum_level, classical_level)| CryptoSpec::Algorithm {
                family,
                parameter,
                quantum_level,
                classical_level,
            })
            .boxed(),
        1 => (
            prop::option::of(-400i64..4000),
            prop::option::of(prop::sample::select(CRYPTO_REFS)),
        )
            .prop_map(|(expires_in_days, signature_algorithm)| CryptoSpec::Certificate {
                expires_in_days,
                signature_algorithm,
            })
            .boxed(),
        1 => (
            prop::option::of(prop::sample::select(&[0u32, 128, 256, 1024, 2048, 4096][..])),
            prop::option::of(prop::sample::select(CRYPTO_REFS)),
        )
            .prop_map(|(size, algorithm)| CryptoSpec::Material { size, algorithm })
            .boxed(),
        2 => (
            0u8..4,
            prop::option::of(prop::sample::select(&["1.0", "1.2", "1.3", "2"][..])),
            prop::collection::vec(prop::sample::select(CIPHER_SUITES), 0..3),
        )
            .prop_map(|(protocol, version, suites)| CryptoSpec::Protocol {
                protocol,
                version,
                suites,
            })
            .boxed(),
        1 => Just(CryptoSpec::Other).boxed(),
    ].boxed()
}

impl CryptoSpec {
    fn build(&self) -> CryptoProperties {
        match self {
            Self::Algorithm {
                family,
                parameter,
                quantum_level,
                classical_level,
            } => {
                let mut algorithm = AlgorithmProperties::new(primitive(family));
                algorithm.algorithm_family = Some((*family).to_string());
                algorithm.parameter_set_identifier = parameter.map(str::to_string);
                algorithm.nist_quantum_security_level = *quantum_level;
                algorithm.classical_security_level = *classical_level;
                CryptoProperties::new(CryptoAssetType::Algorithm)
                    .with_algorithm_properties(algorithm)
            }
            Self::Certificate {
                expires_in_days,
                signature_algorithm,
            } => {
                let mut certificate = CertificateProperties::new();
                certificate.subject_name = Some("CN=acme".to_string());
                certificate.not_valid_after =
                    expires_in_days.map(|days| as_of() + Duration::days(days));
                certificate.signature_algorithm_ref = signature_algorithm.map(str::to_string);
                CryptoProperties::new(CryptoAssetType::Certificate)
                    .with_certificate_properties(certificate)
            }
            Self::Material { size, algorithm } => {
                let mut material =
                    RelatedCryptoMaterialProperties::new(CryptoMaterialType::PublicKey);
                material.size = *size;
                material.algorithm_ref = algorithm.map(str::to_string);
                CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
                    .with_related_crypto_material_properties(material)
            }
            Self::Protocol {
                protocol,
                version,
                suites,
            } => {
                let protocol_type = match protocol {
                    0 => ProtocolType::Tls,
                    1 => ProtocolType::Ssh,
                    2 => ProtocolType::Ipsec,
                    _ => ProtocolType::Ikev2,
                };
                let mut properties = ProtocolProperties::new(protocol_type);
                properties.version = version.map(str::to_string);
                properties.cipher_suites = suites
                    .iter()
                    .map(|name| CipherSuite {
                        name: Some((*name).to_string()),
                        ..CipherSuite::default()
                    })
                    .collect();
                CryptoProperties::new(CryptoAssetType::Protocol)
                    .with_protocol_properties(properties)
            }
            Self::Other => CryptoProperties::new(CryptoAssetType::Other("custom".to_string())),
        }
    }
}

/// Every component type; cryptographic assets are weighted up so the crypto
/// standards have assets to judge.
fn component_type() -> BoxedStrategy<ComponentType> {
    prop_oneof![
        6 => Just(ComponentType::Library),
        2 => Just(ComponentType::Application),
        1 => Just(ComponentType::Framework),
        1 => Just(ComponentType::Container),
        1 => Just(ComponentType::OperatingSystem),
        1 => Just(ComponentType::Device),
        1 => Just(ComponentType::Firmware),
        1 => Just(ComponentType::File),
        1 => Just(ComponentType::Data),
        2 => Just(ComponentType::MachineLearningModel),
        1 => Just(ComponentType::Platform),
        1 => Just(ComponentType::DeviceDriver),
        4 => Just(ComponentType::Cryptographic),
        1 => Just(ComponentType::Service),
        1 => Just(ComponentType::Other("custom".to_string())),
    ]
    .boxed()
}

#[derive(Debug, Clone)]
struct VulnSpec {
    id: &'static str,
    severity: Option<Severity>,
}

fn vulnerability() -> BoxedStrategy<VulnSpec> {
    (
        prop::sample::select(&["CVE-2024-3094", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"][..]),
        prop::option::of(prop::sample::select(vec![
            Severity::Critical,
            Severity::High,
            Severity::Low,
            Severity::Unknown,
        ])),
    )
        .prop_map(|(id, severity)| VulnSpec { id, severity })
        .boxed()
}

/// External references: the kinds the CRA, AI and EUCC checks read, with
/// working, template and placeholder locators.
fn external_ref() -> BoxedStrategy<ExternalReference> {
    (
        prop::sample::select(vec![
            ExternalRefType::SecurityContact,
            ExternalRefType::Advisories,
            ExternalRefType::Support,
            ExternalRefType::Website,
            ExternalRefType::Vcs,
            ExternalRefType::Documentation,
            ExternalRefType::ModelCard,
            ExternalRefType::Certification,
            ExternalRefType::RiskAssessment,
            ExternalRefType::VulnerabilityAssertion,
        ]),
        prop::sample::select(
            &[
                "https://acme-corp.eu/security",
                "mailto:psirt@acme-corp.eu",
                "https://example.com/template",
                "NOASSERTION",
                "",
            ][..],
        ),
    )
        .prop_map(|(ref_type, url)| ExternalReference {
            ref_type,
            url: url.to_string(),
            comment: None,
            hashes: Vec::new(),
        })
        .boxed()
}

/// One component entry.
#[derive(Debug, Clone)]
struct ComponentSpec {
    name: Field,
    version: Field,
    component_type: ComponentType,
    supplier: Option<OrgSpec>,
    author: Field,
    manufacturer: Option<OrgSpec>,
    licenses: LicenseSpec,
    purl: IdSpec,
    purl_type: &'static str,
    cpe: IdSpec,
    hashes: Vec<HashSpec>,
    scope: Option<DependencyScope>,
    copyright: Field,
    vulnerabilities: Vec<VulnSpec>,
    external_refs: Vec<ExternalReference>,
    crypto: Option<CryptoSpec>,
    ai: bool,
}

fn component() -> BoxedStrategy<ComponentSpec> {
    let identity = (
        field(known_name()),
        field(known_version()),
        component_type(),
        prop::option::weighted(0.6, org()),
        field(known_name()),
        prop::option::weighted(0.2, org()),
    )
        .boxed();
    let package = (
        licenses(),
        purl(),
        prop::sample::select(PURL_TYPES),
        cpe(),
        prop::collection::vec(hash(), 0..3),
        prop::option::weighted(
            0.3,
            prop::sample::select(vec![
                DependencyScope::Required,
                DependencyScope::Optional,
                DependencyScope::Excluded,
            ]),
        ),
        field(known_name()),
    )
        .boxed();
    let extra = (
        prop::collection::vec(vulnerability(), 0..3),
        prop::collection::vec(external_ref(), 0..2),
        prop::option::weighted(0.85, crypto()),
        any::<bool>(),
    )
        .boxed();
    (identity, package, extra)
        .prop_map(
            |(
                (name, version, component_type, supplier, author, manufacturer),
                (licenses, purl, purl_type, cpe, hashes, scope, copyright),
                (vulnerabilities, external_refs, crypto, ai),
            )| {
                // Only a cryptographic asset carries crypto properties.
                let crypto = crypto.filter(|_| component_type == ComponentType::Cryptographic);
                ComponentSpec {
                    name,
                    version,
                    component_type,
                    supplier: supplier.filter(|org| !org.name.is_absent()),
                    author,
                    manufacturer: manufacturer.filter(|org| !org.name.is_absent()),
                    licenses,
                    purl,
                    purl_type,
                    cpe,
                    hashes,
                    scope,
                    copyright,
                    vulnerabilities,
                    external_refs,
                    crypto,
                    ai,
                }
            },
        )
        .boxed()
}

impl ComponentSpec {
    /// The component of the `index`th entry; its format id is `ref-<index>`.
    fn build(&self, index: usize) -> Component {
        self.build_as(index, format!("ref-{index}"))
    }

    /// The component of the `index`th spec, listed under `format_id`.
    fn build_as(&self, index: usize, format_id: String) -> Component {
        let name = self.name.text().unwrap_or_default();
        let mut component = Component::new(name, format_id);
        if let Some(version) = self.version.text() {
            component = component.with_version(version);
        }
        component.component_type = self.component_type.clone();
        component.supplier = self.supplier.as_ref().and_then(OrgSpec::build);
        component.author = self.author.text();
        component.manufacturer = self.manufacturer.as_ref().and_then(OrgSpec::build);
        for license in &self.licenses.declared {
            component
                .licenses
                .add_declared(LicenseExpression::new((*license).to_string()));
        }
        component.licenses.concluded = self
            .licenses
            .concluded
            .map(|license| LicenseExpression::new(license.to_string()));
        // A valid purl names the component's version when it has a known
        // one, as generators write it.
        let version = match &self.version {
            Field::Known(version) => Some(version.clone()),
            _ => None,
        };
        match &self.purl {
            IdSpec::Absent => {}
            IdSpec::Placeholder(text) | IdSpec::Malformed(text) => {
                component.set_purl((*text).to_string());
            }
            IdSpec::Valid => component.set_purl(match &version {
                Some(version) => format!("pkg:{}/comp{index}@{version}", self.purl_type),
                None => format!("pkg:{}/comp{index}", self.purl_type),
            }),
        }
        match &self.cpe {
            IdSpec::Absent => {}
            IdSpec::Placeholder(text) | IdSpec::Malformed(text) => {
                component.add_cpe((*text).to_string());
            }
            IdSpec::Valid => component.add_cpe(format!(
                "cpe:2.3:a:acme:comp{index}:{}:*:*:*:*:*:*:*",
                version.as_deref().unwrap_or("*")
            )),
        }
        component.hashes = self.hashes.iter().map(|hash| hash.build(index)).collect();
        component.scope = self.scope.clone();
        component.copyright = self.copyright.text();
        component.vulnerabilities = self
            .vulnerabilities
            .iter()
            .map(|vuln| {
                let mut reference =
                    VulnerabilityRef::new(vuln.id.to_string(), VulnerabilitySource::Cve);
                reference.severity = vuln.severity.clone();
                reference
            })
            .collect();
        component.external_refs = self.external_refs.clone();
        component.crypto_properties = self.crypto.as_ref().map(CryptoSpec::build);
        if self.ai {
            match self.component_type {
                ComponentType::MachineLearningModel => {
                    let mut model = MlModelInfo::default();
                    model.architecture_family = Some("transformer".to_string());
                    model.task = Some("nlp".to_string());
                    model.limitations = Some("English text only".to_string());
                    component = component.with_ml_model(model);
                }
                ComponentType::Data => {
                    let mut dataset = DatasetInfo::default();
                    dataset.dataset_type = Some("training".to_string());
                    dataset.intended_use = Some("fine-tuning".to_string());
                    component = component.with_dataset(dataset);
                }
                _ => {}
            }
        }
        component.calculate_content_hash();
        component
    }
}

/// The document's creation timestamp.
#[derive(Debug, Clone, Copy)]
enum Created {
    /// This many days before the run's instant.
    Past(i64),
    /// This many days after it.
    Future(i64),
    /// A value that did not parse (`created_unparsed`; `created` holds the
    /// epoch sentinel).
    Unparsed(&'static str),
    /// No timestamp (the epoch sentinel).
    Absent,
}

fn created() -> BoxedStrategy<Created> {
    prop_oneof![
        5 => (0i64..2000).prop_map(Created::Past),
        1 => (1i64..400).prop_map(Created::Future),
        1 => prop::sample::select(&["not-a-date", "2026-13-45", "yesterday"][..]).prop_map(Created::Unparsed),
        1 => Just(Created::Absent),
    ].boxed()
}

#[derive(Debug, Clone)]
struct CreatorSpec {
    creator_type: CreatorType,
    name: Field,
    email: bool,
}

fn creator() -> BoxedStrategy<CreatorSpec> {
    (
        prop::sample::select(vec![
            CreatorType::Person,
            CreatorType::Organization,
            CreatorType::Tool,
        ]),
        field(
            prop_oneof![
                known_name(),
                Just("syft 1.4.2".to_string()),
                Just("Acme Corp".to_string()),
            ]
            .boxed(),
        ),
        any::<bool>(),
    )
        .prop_map(|(creator_type, name, email)| CreatorSpec {
            creator_type,
            name,
            email,
        })
        .boxed()
}

/// Document-level metadata.
#[derive(Debug, Clone)]
struct DocSpec {
    format: SbomFormat,
    spec_version: &'static str,
    created: Created,
    creators: Vec<CreatorSpec>,
    supplier: Option<OrgSpec>,
    name: Field,
    serial_number: bool,
    security_contact: Field,
    disclosure_url: Field,
    support_end_in_days: Option<i64>,
    signature: Option<bool>,
    doc_version: Option<u32>,
}

fn document() -> BoxedStrategy<DocSpec> {
    let format = prop_oneof![
        (
            Just(SbomFormat::CycloneDx),
            prop::sample::select(&["1.3", "1.4", "1.5", "1.6", "1.7", ""][..]),
        ),
        (
            Just(SbomFormat::Spdx),
            prop::sample::select(&["SPDX-2.2", "SPDX-2.3", "3.0.1", "garbage"][..]),
        ),
    ]
    .boxed();
    let contact = || {
        field(
            prop::sample::select(
                &[
                    "https://acme-corp.eu/security",
                    "mailto:psirt@acme-corp.eu",
                    "security@example.com",
                ][..],
            )
            .prop_map(str::to_string)
            .boxed(),
        )
    };
    (
        (
            format,
            created(),
            prop::collection::vec(creator(), 0..3),
            prop::option::weighted(0.4, org()),
            field(known_name()),
            any::<bool>(),
        )
            .boxed(),
        (
            contact(),
            contact(),
            prop::option::weighted(0.3, -200i64..4000),
            prop::option::weighted(0.2, any::<bool>()),
            prop::option::of(0u32..4),
        )
            .boxed(),
    )
        .prop_map(
            |(
                ((format, spec_version), created, creators, supplier, name, serial_number),
                (security_contact, disclosure_url, support_end_in_days, signature, doc_version),
            )| DocSpec {
                format,
                spec_version,
                created,
                creators,
                supplier: supplier.filter(|org| !org.name.is_absent()),
                name,
                serial_number,
                security_contact,
                disclosure_url,
                support_end_in_days,
                signature,
                doc_version,
            },
        )
        .boxed()
}

impl DocSpec {
    fn build(&self) -> DocumentMetadata {
        DocumentMetadata {
            format: self.format.clone(),
            format_version: self.spec_version.to_string(),
            spec_version: self.spec_version.to_string(),
            created: match self.created {
                Created::Past(days) => as_of() - Duration::days(days),
                Created::Future(days) => as_of() + Duration::days(days),
                Created::Unparsed(_) | Created::Absent => DateTime::UNIX_EPOCH,
            },
            created_unparsed: match self.created {
                Created::Unparsed(text) => Some(text.to_string()),
                _ => None,
            },
            creators: self
                .creators
                .iter()
                .filter_map(|creator| {
                    Some(Creator {
                        creator_type: creator.creator_type.clone(),
                        name: creator.name.text()?,
                        email: creator.email.then(|| "sbom@acme-corp.eu".to_string()),
                    })
                })
                .collect(),
            supplier: self.supplier.as_ref().and_then(OrgSpec::build),
            name: self.name.text(),
            serial_number: self
                .serial_number
                .then(|| "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
            security_contact: self.security_contact.text(),
            vulnerability_disclosure_url: self.disclosure_url.text(),
            support_end_date: self
                .support_end_in_days
                .map(|days| as_of() + Duration::days(days)),
            signature: self.signature.map(|has_value| SignatureInfo {
                algorithm: "ES256".to_string(),
                has_value,
            }),
            doc_version: self.doc_version,
            ..DocumentMetadata::default()
        }
    }
}

/// One end of a dependency edge.
#[derive(Debug, Clone, Copy)]
enum End {
    /// The component of this entry (modulo the number of entries).
    Entry(usize),
    /// A reference no component holds.
    Dangling(usize),
}

#[derive(Debug, Clone)]
struct EdgeSpec {
    from: End,
    to: End,
    relationship: DependencyType,
}

fn end() -> BoxedStrategy<End> {
    prop_oneof![
        8 => (0usize..16).prop_map(End::Entry),
        1 => (0usize..2).prop_map(End::Dangling),
    ]
    .boxed()
}

fn edge() -> BoxedStrategy<EdgeSpec> {
    (
        end(),
        end(),
        prop::sample::select(vec![
            DependencyType::DependsOn,
            DependencyType::DevDependsOn,
            DependencyType::OptionalDependsOn,
            DependencyType::Contains,
            DependencyType::Describes,
        ]),
    )
        .prop_map(|(from, to, relationship)| EdgeSpec {
            from,
            to,
            relationship,
        })
        .boxed()
}

/// A whole SBOM: its document, its component entries (some listed twice),
/// its primary component and its dependency edges, which can form cycles,
/// loop on one component, or name components that are not there.
#[derive(Debug, Clone)]
struct SbomSpec {
    document: DocSpec,
    components: Vec<ComponentSpec>,
    /// Entries listed a second time, by index (modulo the number of
    /// entries), under the same format id or another one: the duplicates
    /// the model merges into one component when an identifier ties them.
    repeats: Vec<(usize, bool)>,
    primary: Option<usize>,
    edges: Vec<EdgeSpec>,
}

/// An SBOM of any shape, or one that is mostly well formed, so verdicts on
/// both sides of every gate are common.
fn sbom_spec() -> BoxedStrategy<SbomSpec> {
    prop_oneof![
        3 => any_sbom_spec(),
        2 => good_sbom_spec(),
    ]
    .boxed()
}

fn any_sbom_spec() -> BoxedStrategy<SbomSpec> {
    (
        document(),
        prop::collection::vec(component(), 0..10),
        prop::collection::vec((0usize..16, any::<bool>()), 0..3),
        prop::option::weighted(0.7, 0usize..16),
        prop::collection::vec(edge(), 0..14),
    )
        .prop_map(|(document, components, repeats, primary, edges)| SbomSpec {
            document,
            components,
            repeats,
            primary,
            edges,
        })
        .boxed()
}

/// A mostly well-formed SBOM: a complete document (now and then any
/// document), components that give every package field (now and then any
/// component), the first one the primary, which depends on all the others,
/// and a few edges of any kind.
fn good_sbom_spec() -> BoxedStrategy<SbomSpec> {
    (
        prop_oneof![3 => good_document(), 1 => document()].boxed(),
        prop::collection::vec(
            prop_oneof![5 => good_component(), 1 => component()].boxed(),
            1..8,
        ),
        prop::collection::vec(edge(), 0..3),
    )
        .prop_map(|(document, components, extra_edges)| {
            let mut edges: Vec<EdgeSpec> = (1..components.len())
                .map(|to| EdgeSpec {
                    from: End::Entry(0),
                    to: End::Entry(to),
                    relationship: DependencyType::DependsOn,
                })
                .collect();
            edges.extend(extra_edges);
            SbomSpec {
                document,
                components,
                repeats: Vec::new(),
                primary: Some(0),
                edges,
            }
        })
        .boxed()
}

/// A component that gives every package field a strong value: a name, a
/// version, a supplier with a URL and an email, an SPDX license, a purl and
/// SHA-256 and SHA-512 digests. It is a library or an application, or a
/// cryptographic asset with its properties. Now and then one of the fields
/// [`Evidence`] fills is left out.
fn good_component() -> BoxedStrategy<ComponentSpec> {
    (
        "[a-z][a-z0-9-]{2,10}",
        "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
        prop_oneof![
            4 => Just(ComponentType::Library),
            1 => Just(ComponentType::Application),
            1 => Just(ComponentType::Cryptographic),
        ],
        prop::sample::select(&["MIT", "Apache-2.0"][..]),
        prop::sample::select(PURL_TYPES),
        crypto(),
        prop::option::weighted(0.4, evidence()),
    )
        .prop_map(
            |(name, version, component_type, license, purl_type, crypto, gap)| {
                let mut component =
                    good_component_of(name, version, component_type, license, purl_type, crypto);
                if let Some(gap) = gap {
                    component.clear(gap);
                }
                component
            },
        )
        .boxed()
}

fn good_component_of(
    name: String,
    version: String,
    component_type: ComponentType,
    license: &'static str,
    purl_type: &'static str,
    crypto: CryptoSpec,
) -> ComponentSpec {
    ComponentSpec {
        name: Field::Known(name),
        version: Field::Known(version),
        crypto: (component_type == ComponentType::Cryptographic).then_some(crypto),
        component_type,
        supplier: Some(OrgSpec {
            name: Field::Known("Acme Corp".to_string()),
            url: true,
            email: true,
        }),
        author: Field::Known("Jane Doe".to_string()),
        manufacturer: None,
        licenses: LicenseSpec {
            declared: vec![license],
            concluded: None,
        },
        purl: IdSpec::Valid,
        purl_type,
        cpe: IdSpec::Absent,
        hashes: vec![
            HashSpec {
                algorithm: HashAlgorithm::Sha256,
                digest: Digest::Good,
            },
            HashSpec {
                algorithm: HashAlgorithm::Sha512,
                digest: Digest::Good,
            },
        ],
        scope: None,
        copyright: Field::Known("Copyright 2026 Acme Corp".to_string()),
        vulnerabilities: Vec::new(),
        external_refs: Vec::new(),
        ai: false,
    }
}

impl ComponentSpec {
    /// Leave out the field `evidence` fills.
    fn clear(&mut self, evidence: Evidence) {
        match evidence {
            Evidence::Supplier => self.supplier = None,
            Evidence::Version => self.version = Field::Absent,
            Evidence::Purl => self.purl = IdSpec::Absent,
            Evidence::Sha256 | Evidence::Sha512 => self.hashes.clear(),
            Evidence::License => {
                self.licenses.declared.clear();
                self.licenses.concluded = None;
            }
        }
    }
}

/// A document that gives every document field a strong value, in a
/// current CycloneDX or SPDX version.
fn good_document() -> BoxedStrategy<DocSpec> {
    (
        prop_oneof![
            (
                Just(SbomFormat::CycloneDx),
                prop::sample::select(&["1.6", "1.7"][..])
            ),
            (
                Just(SbomFormat::Spdx),
                prop::sample::select(&["SPDX-2.3", "3.0.1"][..])
            ),
        ],
        0i64..30,
    )
        .prop_map(|((format, spec_version), age)| DocSpec {
            format,
            spec_version,
            created: Created::Past(age),
            creators: vec![
                CreatorSpec {
                    creator_type: CreatorType::Organization,
                    name: Field::Known("Acme Corp".to_string()),
                    email: true,
                },
                CreatorSpec {
                    creator_type: CreatorType::Tool,
                    name: Field::Known("syft 1.4.2".to_string()),
                    email: false,
                },
            ],
            supplier: Some(OrgSpec {
                name: Field::Known("Acme Corp".to_string()),
                url: true,
                email: true,
            }),
            name: Field::Known("acme-product".to_string()),
            serial_number: true,
            security_contact: Field::Known("mailto:psirt@acme-corp.eu".to_string()),
            disclosure_url: Field::Known("https://acme-corp.eu/security".to_string()),
            support_end_in_days: Some(1500),
            signature: Some(true),
            doc_version: Some(1),
        })
        .boxed()
}

impl SbomSpec {
    /// The entries in document order: each component once, then the
    /// repeats. An entry is its spec's index, and whether it is listed under
    /// another format id (`ref-<index>-again`).
    fn entries(&self) -> Vec<(usize, bool)> {
        let n = self.components.len();
        let mut entries: Vec<(usize, bool)> = (0..n).map(|index| (index, false)).collect();
        if n > 0 {
            entries.extend(
                self.repeats
                    .iter()
                    .map(|(repeat, again)| (repeat % n, *again)),
            );
        }
        entries
    }

    fn build(&self) -> NormalizedSbom {
        self.build_in_order(&self.entries(), &(0..self.edges.len()).collect::<Vec<_>>())
            .sbom
    }

    /// The SBOM with its entries listed in `entries` order (see
    /// [`Self::entries`]) and its edges in `edges` order (indices).
    fn build_in_order(&self, entries: &[(usize, bool)], edges: &[usize]) -> Built {
        let mut sbom = NormalizedSbom::new(self.document.build());
        let mut ids: BTreeMap<usize, CanonicalId> = BTreeMap::new();
        let mut sources: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for &(index, again) in entries {
            let format_id = if again {
                format!("ref-{index}-again")
            } else {
                format!("ref-{index}")
            };
            let mut component = self.components[index].build_as(index, format_id);
            // As the parsers do: a different component under a taken id gets
            // one of its own, a true duplicate is merged.
            let id = sbom.claim_canonical_id(&mut component);
            sbom.add_component(component);
            sources
                .entry(id.value().to_string())
                .or_default()
                .insert(index);
            ids.entry(index).or_insert(id);
        }
        let n = self.components.len();
        let resolve = |end: End| match end {
            End::Entry(index) if n > 0 => ids[&(index % n)].clone(),
            End::Entry(index) | End::Dangling(index) => {
                CanonicalId::from_format_id(&format!("ghost-{index}"))
            }
        };
        for &index in edges {
            let edge = &self.edges[index];
            sbom.add_edge(DependencyEdge::new(
                resolve(edge.from),
                resolve(edge.to),
                edge.relationship.clone(),
            ));
        }
        if let Some(primary) = self.primary
            && n > 0
        {
            sbom.set_primary_component(ids[&(primary % n)].clone());
        }
        sbom.calculate_content_hash();
        Built { sbom, sources }
    }

    /// Whether the component of entry `index` takes its canonical id with
    /// the component of another entry.
    fn shares_id(&self, index: usize) -> bool {
        let id = self.components[index].build(index).canonical_id;
        (0..self.components.len())
            .any(|other| other != index && self.components[other].build(other).canonical_id == id)
    }

    /// Whether, among the entries of different specs that take one
    /// canonical id (they carry the same malformed purl or CPE), one agrees
    /// with two that do not agree with each other
    /// ([`Component::is_same_component`]): an entry whose name or version is
    /// not known agrees with any. It then merges into whichever of the two
    /// comes first: in `a, NOASSERTION, b` its fields go to `a`, in
    /// `NOASSERTION, b, a` to `b`, and the findings and counts follow.
    /// Left as it is (which of the two the entry belongs to has no
    /// order-free answer), and excluded where it matters.
    ///
    /// Every other sharing is order-free and not excluded: a different
    /// component under a taken id is re-keyed, and a later entry of a
    /// re-keyed component finds it, under any format id.
    fn has_ambiguous_merges(&self) -> bool {
        let mut groups: BTreeMap<String, Vec<Component>> = BTreeMap::new();
        for index in 0..self.components.len() {
            let component = self.components[index].build(index);
            groups
                .entry(component.canonical_id.value().to_string())
                .or_default()
                .push(component);
        }
        groups.values().any(|group| {
            group.iter().enumerate().any(|(i, entry)| {
                let agreeing: Vec<&Component> = group
                    .iter()
                    .enumerate()
                    .filter(|(j, other)| *j != i && entry.is_same_component(other))
                    .map(|(_, other)| other)
                    .collect();
                agreeing.iter().enumerate().any(|(k, first)| {
                    agreeing[k + 1..]
                        .iter()
                        .any(|second| !first.is_same_component(second))
                })
            })
        })
    }
}

/// A well-formed, strong value for a field a component leaves absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// A supplier name.
    Supplier,
    /// A version (a valid purl or CPE of the component then names it too,
    /// as generators write them).
    Version,
    /// A valid purl.
    Purl,
    /// A SHA-256 digest of the right length.
    Sha256,
    /// A SHA-512 digest of the right length.
    Sha512,
    /// An SPDX license id.
    License,
}

fn evidence() -> BoxedStrategy<Evidence> {
    prop::sample::select(Evidence::ALL).boxed()
}

impl Evidence {
    const ALL: &[Self] = &[
        Self::Supplier,
        Self::Version,
        Self::Purl,
        Self::Sha256,
        Self::Sha512,
        Self::License,
    ];

    /// Whether filling this value in may legitimately add an error of
    /// `rule_id`: the value brings the component into the scope of a rule
    /// it was outside of, by design.
    ///
    /// - BSI TR-03183-2 names SHA-512 for the component hash. A component
    ///   without a hash is a Warning there (`SBOM-BSI-TR-03183-2-5-4-MISSING`,
    ///   since §3.2.1 lets an SBOM omit a value that cannot exist), and one
    ///   whose hashes include no SHA-512 an Error (`SBOM-BSI-TR-03183-2-5-4`),
    ///   so a SHA-256 alone turns the warning into an error.
    /// - The CRA vendor-hash rule (`SBOM-CRA-PRE-7-RQ-07-RE`) judges the
    ///   vendor-supplied components: those with a known producer and an
    ///   identifier. A supplier or a purl given to a hashless component can
    ///   make it one, and lower the coverage below the threshold.
    fn may_add(self, rule_id: &str) -> bool {
        match self {
            Self::Sha256 => rule_id == "SBOM-BSI-TR-03183-2-5-4",
            Self::Supplier | Self::Purl => rule_id == "SBOM-CRA-PRE-7-RQ-07-RE",
            _ => false,
        }
    }

    /// The errors of `result` that filling this value in must not add to.
    fn errors(self, result: &ComplianceResult) -> usize {
        result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error && !self.may_add(v.rule_id))
            .count()
    }
}

impl SbomSpec {
    /// The SBOM with `evidence` filled into the component of entry `index`
    /// (each of its entries, when it is listed twice), or `None` when that
    /// field is not absent there.
    fn fill(&self, index: usize, evidence: Evidence) -> Option<Self> {
        let mut spec = self.clone();
        let component = &mut spec.components[index];
        match evidence {
            Evidence::Supplier if component.supplier.is_none() => {
                component.supplier = Some(OrgSpec {
                    name: Field::Known("Acme Corp".to_string()),
                    url: false,
                    email: false,
                });
            }
            Evidence::Version if component.version.is_absent() => {
                component.version = Field::Known("1.2.3".to_string());
            }
            Evidence::Purl if matches!(component.purl, IdSpec::Absent) => {
                component.purl = IdSpec::Valid;
            }
            Evidence::Sha256 | Evidence::Sha512 if component.hashes.is_empty() => {
                let algorithm = if matches!(evidence, Evidence::Sha256) {
                    HashAlgorithm::Sha256
                } else {
                    HashAlgorithm::Sha512
                };
                component.hashes = vec![HashSpec {
                    algorithm,
                    digest: Digest::Good,
                }];
            }
            Evidence::License
                if component.licenses.declared.is_empty()
                    && component.licenses.concluded.is_none() =>
            {
                component.licenses.declared = vec!["MIT"];
            }
            _ => return None,
        }
        Some(spec)
    }
}

/// A built SBOM, and for each of its components the entries (by index)
/// it was built from.
struct Built {
    sbom: NormalizedSbom,
    sources: BTreeMap<String, BTreeSet<usize>>,
}

// ============================================================================
// The runs
// ============================================================================

/// The inputs of a run besides the SBOM.
#[derive(Debug, Clone)]
struct RunSpec {
    pqc_mode: PqcMode,
    include_excluded_scope: bool,
    product_class: Option<CraProductClass>,
}

fn run_spec() -> BoxedStrategy<RunSpec> {
    (
        prop::sample::select(vec![PqcMode::Readiness, PqcMode::Deadline]),
        any::<bool>(),
        prop::option::weighted(
            0.3,
            prop::sample::select(vec![
                CraProductClass::Default,
                CraProductClass::ImportantClass1,
                CraProductClass::ImportantClass2,
                CraProductClass::Critical,
            ]),
        ),
    )
        .prop_map(
            |(pqc_mode, include_excluded_scope, product_class)| RunSpec {
                pqc_mode,
                include_excluded_scope,
                product_class,
            },
        )
        .boxed()
}

impl RunSpec {
    fn config(&self) -> ComplianceRunConfig {
        let mut run = ComplianceRunConfig::new()
            .with_as_of(as_of())
            .with_pqc_mode(self.pqc_mode)
            .with_include_excluded_scope(self.include_excluded_scope);
        if let Some(class) = self.product_class {
            run = run.with_product_class(class);
        }
        run
    }
}

fn levels() -> &'static [ComplianceLevel] {
    ComplianceLevel::all()
}

/// The v2 envelope of `results` about `sbom`, judged at the run's instant.
fn envelope(results: &[ComplianceResult], sbom: &NormalizedSbom) -> String {
    let input = sbom_bytes(sbom);
    let assessed = AssessedSbom::new(sbom, &input);
    generate_compliance_json_at(results, &assessed, as_of()).expect("envelope renders")
}

/// Stand-in bytes for the SBOM's file: the subject's digest is computed
/// over them.
fn sbom_bytes(sbom: &NormalizedSbom) -> Vec<u8> {
    format!("{}:{}", sbom.document.format, sbom.content_hash).into_bytes()
}

/// A finding without its message and its place in the report: the rule,
/// the severity and the subject. A component subject is named by the spec
/// entries the component was built from, not by its canonical id: of two
/// components that take one id the later one is re-keyed (see
/// `NormalizedSbom::claim_canonical_id`), so which one keeps it follows
/// their order.
type FindingShape = (&'static str, ViolationSeverity, String);

fn finding_shapes(result: &ComplianceResult, built: &Built) -> Vec<FindingShape> {
    let mut shapes: Vec<FindingShape> = result
        .violations
        .iter()
        .map(|v| (v.rule_id, v.severity, built.subject(v)))
        .collect();
    shapes.sort_by(|a, b| (a.0, severity_rank(a.1), &a.2).cmp(&(b.0, severity_rank(b.1), &b.2)));
    shapes
}

/// The passed checks of `result` as (rule, subject), sorted.
fn passed_shapes(result: &ComplianceResult, built: &Built) -> Vec<(&'static str, String)> {
    let mut shapes: Vec<_> = result
        .passed
        .iter()
        .map(|p| (p.rule_id, built.subject(p)))
        .collect();
    shapes.sort();
    shapes
}

impl Built {
    /// What `finding` is about: the entries its component was built from,
    /// or the document.
    fn subject<F: FindingIdentity>(&self, finding: &F) -> String {
        let subject = finding_subject(finding);
        self.sources.get(subject.as_ref()).map_or_else(
            || subject.clone().into_owned(),
            |entries| format!("entries {entries:?}"),
        )
    }
}

const fn severity_rank(severity: ViolationSeverity) -> u8 {
    match severity {
        ViolationSeverity::Error => 2,
        ViolationSeverity::Warning => 1,
        _ => 0,
    }
}

/// Everything about a result that must not depend on the order of the
/// SBOM's entries.
fn verdict(result: &ComplianceResult) -> (bool, bool, usize, usize, usize, Option<u8>, usize) {
    (
        result.is_compliant,
        result.is_applicable(),
        result.error_count,
        result.warning_count,
        result.info_count,
        result.score(),
        result.passed.len(),
    )
}

/// A permutation of `0..len` from `seed` (Fisher-Yates over a SplitMix64
/// stream), so a case shrinks to a smaller SBOM, not to another order.
fn permutation(len: usize, seed: u64) -> Vec<usize> {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let mut order: Vec<usize> = (0..len).collect();
    for i in (1..len).rev() {
        let j = usize::try_from(next() % (i as u64 + 1)).expect("index fits");
        order.swap(i, j);
    }
    order
}

// ============================================================================
// Properties
// ============================================================================

proptest! {
    #![proptest_config(config())]

    /// The verdict contract (docs/compliance-output.md, "Results" and
    /// "Score"): `compliant` is exactly "no violation of Error severity",
    /// each count counts the violations of its severity, and a standard that
    /// did not apply reports nothing, stays `compliant` and has no score.
    /// An applicable result scores 50–100 when compliant and 0–49 when not,
    /// by the documented formula over the checks its errors and warnings
    /// failed. Every violation is of a rule the level reports, and a rule
    /// the settings turn off reports none.
    #[test]
    fn verdict_is_no_error_finding(
        spec in sbom_spec(),
        run in run_spec(),
        settings in prop::collection::vec((any::<prop::sample::Index>(), 0u8..4), 0..4),
    ) {
        let sbom = spec.build();
        let rule_ids: Vec<&'static str> = all_rule_ids()
            .iter()
            .copied()
            .filter(|id| rule_kind(id) != Some(RuleKind::Pass))
            .collect();
        let mut rule_settings = RuleSettings::new();
        for (index, setting) in &settings {
            let setting = match setting {
                0 => RuleSetting::Off,
                1 => RuleSetting::Info,
                2 => RuleSetting::Warning,
                _ => RuleSetting::Error,
            };
            let rule_id: &&str = index.get(&rule_ids);
            rule_settings
                .set(rule_id, setting, SettingSource::Cli)
                .expect("a registered rule");
        }
        let config = run.config().with_rule_settings(rule_settings.clone());
        let results = config.check_levels(levels(), &sbom);

        for result in &results {
            let level = result.level;
            let count = |severity| result.violations.iter().filter(|v| v.severity == severity).count();
            prop_assert_eq!(result.error_count, count(ViolationSeverity::Error), "{:?} error count", level);
            prop_assert_eq!(result.warning_count, count(ViolationSeverity::Warning), "{:?} warning count", level);
            prop_assert_eq!(result.info_count, count(ViolationSeverity::Info), "{:?} info count", level);
            prop_assert_eq!(result.is_compliant, result.error_count == 0, "{:?} verdict", level);
            prop_assert!(result.elements_checked >= 1, "{:?} checks the document", level);

            for v in &result.violations {
                prop_assert!(
                    rules_for_level(level).contains(&v.rule_id),
                    "{:?} reported {}, not one of its rules", level, v.rule_id
                );
                prop_assert!(
                    !matches!(rule_settings.get(v.rule_id), Some((RuleSetting::Off, _))),
                    "{:?} reported {}, which the settings turn off", level, v.rule_id
                );
            }

            if result.is_applicable() {
                let (mut errors, mut warnings) = (0, 0);
                for v in &result.violations {
                    match v.severity {
                        ViolationSeverity::Error => errors += v.failed_checks(),
                        ViolationSeverity::Warning => warnings += v.failed_checks(),
                        _ => {}
                    }
                }
                let score = result.score().expect("an applicable result has a score");
                prop_assert_eq!(score, compliance_score(errors, warnings, result.elements_checked), "{:?} score", level);
                prop_assert_eq!(score >= 50, result.is_compliant, "{:?} score band", level);
            } else {
                prop_assert!(result.is_compliant, "{:?}: N/A stays compliant", level);
                prop_assert!(result.score().is_none(), "{:?}: N/A has no score", level);
                prop_assert!(result.violations.is_empty(), "{:?}: N/A reports no violation", level);
                prop_assert!(result.passed.is_empty(), "{:?}: N/A passes no check", level);
                prop_assert!(result.evaluated.is_empty(), "{:?}: N/A lists no check not evaluated", level);
            }

            // Components left out for their excluded scope: none when the
            // run judges them, or the level has no package rules.
            if run.include_excluded_scope || !ComplianceRunConfig::excluded_scope_applies(level) {
                prop_assert_eq!(result.excluded_components, 0, "{:?} excluded components", level);
            }
            // The CRA Annex VIII summary: CRA Phase 1 and 2 with a class.
            prop_assert_eq!(
                result.conformity_summary.is_some(),
                level.cra_phase().is_some() && run.product_class.is_some(),
                "{:?} conformity summary", level
            );
        }

        // The same contract in the envelope `validate -o json` prints.
        let envelope: Value = serde_json::from_str(&envelope(&results, &sbom)).expect("JSON");
        let entries = envelope["results"].as_array().expect("results");
        prop_assert_eq!(entries.len(), results.len());
        for (entry, result) in entries.iter().zip(&results) {
            let standard = standard_key(result.level);
            prop_assert_eq!(entry["standard"].as_str(), Some(standard));
            let violations = entry["violations"].as_array().expect("violations");
            let errors = violations.iter().filter(|v| v["severity"] == "Error").count();
            prop_assert_eq!(entry["compliant"].as_bool(), Some(errors == 0), "{} compliant", standard);
            prop_assert_eq!(entry["counts"]["error"].as_u64(), Some(errors as u64), "{} counts.error", standard);
            let applicable = entry["applicable"].as_bool().expect("applicable");
            prop_assert_eq!(entry["score"].is_null(), !applicable, "{} score", standard);
            prop_assert_eq!(entry.get("score_basis").is_some(), applicable, "{} score_basis", standard);
            prop_assert_eq!(entry.get("not_applicable_reason").is_some(), !applicable, "{} reason", standard);
            if let Some(score) = entry["score"].as_u64() {
                prop_assert_eq!(score >= 50, errors == 0, "{} score band", standard);
            }
        }
    }

    /// Order independence: listing the components and the dependency edges
    /// in another order changes no verdict, count or score, and leaves the
    /// set of findings (rule, severity, subject) as it was.
    #[test]
    fn verdicts_do_not_depend_on_entry_order(
        spec in sbom_spec(),
        run in run_spec(),
        seed in any::<u64>(),
    ) {
        let entries = spec.entries();
        let shuffled_entries: Vec<(usize, bool)> = permutation(entries.len(), seed)
            .into_iter()
            .map(|i| entries[i])
            .collect();
        let shuffled_edges = permutation(spec.edges.len(), seed.rotate_left(17));
        // Excluded: entries whose merging follows their order (see
        // `SbomSpec::has_ambiguous_merges`).
        prop_assume!(!spec.has_ambiguous_merges());
        let original = spec.build_in_order(&entries, &(0..spec.edges.len()).collect::<Vec<_>>());
        let shuffled = spec.build_in_order(&shuffled_entries, &shuffled_edges);

        let config = run.config();
        let before = config.check_levels(levels(), &original.sbom);
        let after = config.check_levels(levels(), &shuffled.sbom);
        for (a, b) in before.iter().zip(&after) {
            prop_assert_eq!(verdict(a), verdict(b), "{:?} verdict", a.level);
            prop_assert_eq!(
                finding_shapes(a, &original),
                finding_shapes(b, &shuffled),
                "{:?} findings", a.level
            );
            prop_assert_eq!(
                passed_shapes(a, &original),
                passed_shapes(b, &shuffled),
                "{:?} passed checks", a.level
            );
        }
    }

    /// Determinism: checking the same SBOM twice, and checking every level
    /// in parallel (`check_levels`) or one at a time, prints the same bytes.
    #[test]
    fn checks_are_deterministic(spec in sbom_spec(), run in run_spec()) {
        let sbom = spec.build();
        let config = run.config();
        let parallel = config.check_levels(levels(), &sbom);
        let again = config.check_levels(levels(), &sbom);
        let one_by_one: Vec<ComplianceResult> = levels()
            .iter()
            .map(|level| config.check(*level, &sbom))
            .collect();
        let json = envelope(&parallel, &sbom);
        prop_assert_eq!(&json, &envelope(&again, &sbom), "checked twice");
        prop_assert_eq!(&json, &envelope(&one_by_one, &sbom), "parallel vs one by one");

        // SARIF and OSCAL derive their identifiers from the same results.
        let input = sbom_bytes(&sbom);
        let assessed = AssessedSbom::new(&sbom, &input);
        let sarif = |results: &[ComplianceResult]| {
            generate_multi_compliance_sarif_with(
                results,
                &SarifOptions::new().with_passes(true).with_subject(&assessed, as_of()),
            )
            .expect("SARIF")
        };
        let oscal = |results: &[ComplianceResult]| {
            oscal::generate_assessment_results_at(results, &assessed, as_of()).expect("OSCAL")
        };
        prop_assert_eq!(sarif(&parallel), sarif(&one_by_one), "SARIF, parallel vs one by one");
        prop_assert_eq!(oscal(&parallel), oscal(&one_by_one), "OSCAL, parallel vs one by one");
    }

    /// Monotonic evidence: filling one absent field of one component with a
    /// well-formed, strong value never adds an error to any level.
    #[test]
    fn filling_an_absent_field_never_adds_an_error(
        spec in sbom_spec(),
        run in run_spec(),
        pick in any::<prop::sample::Index>(),
        evidence in evidence(),
    ) {
        // The picked entry and evidence, or the next ones where the field
        // is absent.
        let n = spec.components.len();
        let start = if n == 0 { 0 } else { pick.index(n) };
        let kinds = Evidence::ALL.len();
        let first = Evidence::ALL.iter().position(|e| *e == evidence).expect("listed");
        let fill = (0..n * kinds).find_map(|step| {
            let index = (start + step / kinds) % n;
            let evidence = Evidence::ALL[(first + step) % kinds];
            spec.fill(index, evidence).map(|filled| (index, evidence, filled))
        });
        prop_assume!(fill.is_some());
        let (index, evidence, filled) = fill.expect("assumed");
        // Excluded: a component that takes one canonical id with another
        // (both carry one malformed purl or CPE). A purl, or a version that
        // its valid purl or CPE then names, gives it an id of its own, and
        // one merged entry can become two components.
        prop_assume!(!spec.shares_id(index) && !filled.shares_id(index));

        let config = run.config();
        let before = config.check_levels(levels(), &spec.build());
        let after = config.check_levels(levels(), &filled.build());
        for (a, b) in before.iter().zip(&after) {
            prop_assert!(
                evidence.errors(b) <= evidence.errors(a),
                "{:?}: {:?} on entry {} raised the errors from {} to {}:\n{:#?}",
                a.level, evidence, index, evidence.errors(a), evidence.errors(b),
                b.violations
                    .iter()
                    .filter(|v| v.severity == ViolationSeverity::Error)
                    .map(|v| (v.rule_id, &v.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// The CRA phases nest: every error CRA Phase 1 (`cra-phase1`) reports
    /// on an SBOM, Phase 2 (`cra`) reports as an error too, on the same
    /// subject. The registry lists Phase 2's rules as "Phase 1's, plus the
    /// full-application checks", and the checks they share only ever make
    /// Phase 2 the stricter.
    #[test]
    fn cra_phase1_errors_are_phase2_errors(spec in sbom_spec(), run in run_spec()) {
        let sbom = spec.build();
        let config = run.config();
        let errors = |level| {
            config
                .check(level, &sbom)
                .violations
                .iter()
                .filter(|v| v.severity == ViolationSeverity::Error)
                .map(|v| (v.rule_id, finding_subject(v).into_owned()))
                .collect::<BTreeSet<_>>()
        };
        let phase1 = errors(ComplianceLevel::CraPhase1);
        let phase2 = errors(ComplianceLevel::CraPhase2);
        let missing: Vec<_> = phase1.difference(&phase2).collect();
        prop_assert!(missing.is_empty(), "Phase 1 errors Phase 2 does not report: {:?}", missing);
    }

    /// Every writer `validate` and `view` use finishes on every generated
    /// SBOM, and the v2 envelope matches its published schema and the
    /// strict copy that rejects undeclared fields.
    #[test]
    fn every_writer_renders_and_the_envelope_matches_its_schema(
        spec in sbom_spec(),
        run in run_spec(),
    ) {
        let sbom = spec.build();
        let results = run.config().check_levels(levels(), &sbom);
        let input = sbom_bytes(&sbom);
        let assessed = AssessedSbom::new(&sbom, &input);

        let schema: Value = serde_json::from_str(
            &std::fs::read_to_string(SCHEMA_PATH).expect("schema readable"),
        )
        .expect("schema is JSON");
        let strict = json_schema::strict_copy(&schema);
        for document in [
            generate_compliance_json_at(&results, &assessed, as_of()).expect("envelope"),
            generate_compliance_json(&results).expect("envelope without subject"),
        ] {
            let document: Value = serde_json::from_str(&document).expect("envelope is JSON");
            if let Err(errors) = json_schema::validate(&schema, &document) {
                prop_assert!(false, "envelope fails the schema: {:#?}", errors);
            }
            if let Err(errors) = json_schema::validate(&strict, &document) {
                prop_assert!(false, "envelope fails the strict schema: {:#?}", errors);
            }
        }

        // `--json-schema v1`: the results without their passed checks.
        let v1: Vec<ComplianceResult> = results
            .iter()
            .map(|result| {
                let mut v1 = result.clone();
                v1.passed.clear();
                v1
            })
            .collect();
        serde_json::to_string_pretty(&v1).expect("v1 layout");

        let content = String::from_utf8(input.clone()).expect("UTF-8");
        let artifact = SarifArtifact::new(SarifArtifactLocation::relative("sbom.json"), &sbom, &content);
        for options in [
            SarifOptions::new()
                .with_passes(true)
                .with_artifact(artifact)
                .with_subject(&assessed, as_of()),
            SarifOptions::new().with_max_results(3),
        ] {
            for result in &results {
                let sarif = generate_compliance_sarif_with(result, &options).expect("SARIF");
                serde_json::from_str::<Value>(&sarif).expect("SARIF is JSON");
            }
            let sarif = generate_multi_compliance_sarif_with(&results, &options).expect("SARIF");
            serde_json::from_str::<Value>(&sarif).expect("SARIF is JSON");
        }
        let oscal = oscal::generate_assessment_results_at(&results, &assessed, as_of()).expect("OSCAL");
        serde_json::from_str::<Value>(&oscal).expect("OSCAL is JSON");

        let cra = results
            .iter()
            .find(|result| result.level == ComplianceLevel::CraPhase2)
            .expect("CRA Phase 2 is a level");
        let report = ReportConfig {
            view_cra_compliance: Some(cra.clone()),
            ..ReportConfig::default()
        };
        MarkdownReporter::new().generate_view_report(&sbom, &report).expect("Markdown");
        HtmlReporter::new().generate_view_report(&sbom, &report).expect("HTML");
    }
}

// ============================================================================
// The CLI's text renderers
// ============================================================================

proptest! {
    // Each case starts the binary twice, so a quarter of the cases.
    #![proptest_config(ProptestConfig { cases: config().cases.div_ceil(4), ..config() })]

    /// `validate` renders its text report and its `--summary` for every
    /// standard on the generated SBOMs, written as CycloneDX. Those
    /// renderers are private to the CLI, so the binary runs them: it exits
    /// 0 or 1 (the verdict), never 3 (an error) or by a panic.
    #[test]
    fn cli_text_and_summary_render_every_generated_sbom(spec in sbom_spec()) {
        let sbom = spec.build();
        let (document, _) = sbom_tools::serialization::emit_cyclonedx(&sbom).expect("emits");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sbom.cdx.json");
        std::fs::write(&path, document).expect("written");
        let standards = StandardSelector::valid_values().replace(", ", ",");
        for summary in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
            command
                .args(["validate", "--standard", &standards, "--as-of", AS_OF])
                .arg(&path);
            if summary {
                command.arg("--summary");
            }
            let output = command.output().expect("binary runs");
            prop_assert!(
                matches!(output.status.code(), Some(0 | 1)),
                "validate{} exited {:?}: {}",
                if summary { " --summary" } else { "" },
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
