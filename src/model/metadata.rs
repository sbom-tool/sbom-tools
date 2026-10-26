//! Metadata structures for SBOM documents and components.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SBOM format type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CycloneDx => write!(f, "CycloneDX"),
            Self::Spdx => write!(f, "SPDX"),
        }
    }
}

/// Document-level metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// SBOM format type
    pub format: SbomFormat,
    /// Format version (e.g., "1.5" for `CycloneDX`)
    pub format_version: String,
    /// Specification version
    pub spec_version: String,
    /// Serial number or document namespace
    pub serial_number: Option<String>,
    /// Document revision counter (CycloneDX top-level `version`, bumped on
    /// each BOM revision of the same `serialNumber`). `None` for formats
    /// without a revision counter (SPDX) and for documents that omit it.
    /// Additive: skipped in JSON when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_version: Option<u32>,
    /// Creation timestamp
    pub created: DateTime<Utc>,
    /// Creators/authors
    pub creators: Vec<Creator>,
    /// Document name
    pub name: Option<String>,
    /// Security contact for vulnerability disclosure (CRA requirement)
    pub security_contact: Option<String>,
    /// URL for vulnerability disclosure policy/portal
    pub vulnerability_disclosure_url: Option<String>,
    /// Support/end-of-life date for security updates
    pub support_end_date: Option<DateTime<Utc>>,
    /// SBOM lifecycle phase (e.g., "build", "pre-build", "operations")
    pub lifecycle_phase: Option<String>,
    /// Self-declared completeness level (from CycloneDX compositions)
    pub completeness_declaration: CompletenessDeclaration,
    /// Digital signature information (from CycloneDX signature field)
    pub signature: Option<SignatureInfo>,
    /// Distribution classification (e.g., TLP: CLEAR, GREEN, AMBER, RED)
    pub distribution_classification: Option<String>,
    /// Number of data provenance citations (CycloneDX 1.7+)
    pub citations_count: usize,
}

/// Self-declared completeness level of the SBOM
///
/// Derived from CycloneDX compositions aggregate field, which declares
/// whether the SBOM inventory is complete, incomplete, or unknown.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CompletenessDeclaration {
    /// SBOM author declares the inventory is complete
    Complete,
    /// SBOM author declares the inventory includes only first-party components
    IncompleteFirstPartyOnly,
    /// SBOM author declares the inventory includes only third-party components
    IncompleteThirdPartyOnly,
    /// SBOM author declares the inventory is incomplete
    Incomplete,
    /// No completeness declaration or explicitly unknown
    #[default]
    Unknown,
    /// Completeness was declared but with an unrecognized value
    NotSpecified,
}

impl std::fmt::Display for CompletenessDeclaration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete => write!(f, "complete"),
            Self::IncompleteFirstPartyOnly => write!(f, "incomplete (first-party only)"),
            Self::IncompleteThirdPartyOnly => write!(f, "incomplete (third-party only)"),
            Self::Incomplete => write!(f, "incomplete"),
            Self::Unknown => write!(f, "unknown"),
            Self::NotSpecified => write!(f, "not specified"),
        }
    }
}

/// Digital signature information for the SBOM document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Signature algorithm (e.g., "ES256", "RS256", "Ed25519")
    pub algorithm: String,
    /// Whether the signature appears structurally valid (has algorithm + value)
    pub has_value: bool,
}

/// A format spec version (CycloneDX `specVersion`, SPDX `spdxVersion`)
/// parsed into numbers, so versions compare numerically: "1.10" is newer
/// than "1.7", where string-prefix tests read it as "1.1".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpecVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SpecVersion {
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse "1.6", "3.0.1", "SPDX-2.3" or "v1.6". Missing trailing
    /// segments count as zero; an empty or non-numeric value, or one with
    /// more than three segments, yields `None` so callers can skip a version
    /// gate instead of false-failing a document that declares no version.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let v = value.trim();
        let v = v.strip_prefix("SPDX-").unwrap_or(v);
        let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
        let mut parts = v.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = match parts.next() {
            Some(s) => s.parse().ok()?,
            None => 0,
        };
        let patch = match parts.next() {
            Some(s) => s.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(major, minor, patch))
    }
}

impl std::fmt::Display for SpecVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl DocumentMetadata {
    /// The spec version as numbers, or `None` when it is empty or cannot be
    /// parsed. Every format-version gate compares this value; see
    /// [`SpecVersion`].
    #[must_use]
    pub fn spec_version_parsed(&self) -> Option<SpecVersion> {
        SpecVersion::parse(&self.spec_version)
    }

    /// Whether the document carries a real creation timestamp.
    ///
    /// Parsers substitute [`DateTime::UNIX_EPOCH`] when the source document
    /// has no (or an unparseable) timestamp, so the content hash stays
    /// deterministic. Consumers that compute an AGE or gate on freshness
    /// must use this to distinguish "no timestamp" from a document that
    /// genuinely claims 1970 — otherwise a missing timestamp reads as a
    /// ~55-year-old SBOM.
    #[must_use]
    pub fn has_known_timestamp(&self) -> bool {
        self.created.timestamp() > 0
    }
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            format: SbomFormat::CycloneDx,
            format_version: String::new(),
            spec_version: String::new(),
            serial_number: None,
            doc_version: None,
            created: Utc::now(),
            creators: Vec::new(),
            name: None,
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
            lifecycle_phase: None,
            completeness_declaration: CompletenessDeclaration::default(),
            signature: None,
            distribution_classification: None,
            citations_count: 0,
        }
    }
}

/// Creator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creator {
    /// Creator type
    pub creator_type: CreatorType,
    /// Creator name or identifier
    pub name: String,
    /// Optional email
    pub email: Option<String>,
}

/// Type of creator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreatorType {
    Person,
    Organization,
    Tool,
}

/// Organization/supplier information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// Organization name
    pub name: String,
    /// Contact URLs
    pub urls: Vec<String>,
    /// Contact emails
    pub contacts: Vec<Contact>,
}

impl Organization {
    /// Create a new organization with just a name
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self {
            name,
            urls: Vec::new(),
            contacts: Vec::new(),
        }
    }
}

/// Contact information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Contact name
    pub name: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Phone number
    pub phone: Option<String>,
}

/// Component type classification
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ComponentType {
    Application,
    Framework,
    #[default]
    Library,
    Container,
    OperatingSystem,
    Device,
    Firmware,
    File,
    Data,
    MachineLearningModel,
    Platform,
    DeviceDriver,
    Cryptographic,
    /// A CycloneDX service (SaaSBOM): an endpoint the product calls, not a
    /// package it ships.
    Service,
    Other(String),
}

impl ComponentType {
    /// Whether package-level SBOM elements (version, supplier, license,
    /// unique identifier, hash, dependency-graph membership) apply. File /
    /// snippet entries are name+hash inventory records, CycloneDX
    /// `cryptographic-asset`s describe algorithms, keys, certificates and
    /// protocols, and CycloneDX services are endpoints whose schema carries
    /// no purl or hashes — none is a package, so standards scope those
    /// elements away from them. A crypto *library* (e.g. OpenSSL typed
    /// `library`) is still a package, and so is an SPDX package whose
    /// purpose is SOURCE, ARCHIVE or FILE.
    #[must_use]
    pub const fn is_package_scoped(&self) -> bool {
        !matches!(self, Self::File | Self::Cryptographic | Self::Service)
    }
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application => write!(f, "application"),
            Self::Framework => write!(f, "framework"),
            Self::Library => write!(f, "library"),
            Self::Container => write!(f, "container"),
            Self::OperatingSystem => write!(f, "operating-system"),
            Self::Device => write!(f, "device"),
            Self::Firmware => write!(f, "firmware"),
            Self::File => write!(f, "file"),
            Self::Data => write!(f, "data"),
            Self::MachineLearningModel => write!(f, "machine-learning-model"),
            Self::Platform => write!(f, "platform"),
            Self::DeviceDriver => write!(f, "device-driver"),
            Self::Cryptographic => write!(f, "cryptographic"),
            Self::Service => write!(f, "service"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Where a hash came from — determines whether integrity verification trusts
/// it as an EXPECTED baseline. Runtime-only, never serialized: a hash parsed
/// from an SBOM is author-attested (`Authored`); one this tool added during
/// enrichment (fetched from a registry / served from cache) is `Enriched` and
/// must NOT be used as the baseline to verify local files against — that
/// would be circular (the tool checks a file against a hash it fetched from
/// the same source that could host the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashProvenance {
    /// Present in the parsed SBOM — author-attested, trusted as a baseline.
    #[default]
    Authored,
    /// Added by this tool's enrichment — informational, not a verify baseline.
    Enriched,
}

/// Cryptographic hash.
///
/// `PartialEq`/`Eq`/`Hash` intentionally ignore [`provenance`](Self::provenance)
/// so dedup, content-hashing, and diff identity depend only on the
/// algorithm+value (provenance is a runtime trust marker, not part of the
/// hash's identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Hash value (hex encoded)
    pub value: String,
    /// Trust provenance (runtime only — never serialized).
    #[serde(skip)]
    pub provenance: HashProvenance,
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}

impl Eq for Hash {}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.value.hash(state);
    }
}

impl Hash {
    /// Create an author-attested hash (parsed from an SBOM).
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm, value: String) -> Self {
        Self {
            algorithm,
            value,
            provenance: HashProvenance::Authored,
        }
    }

    /// Create an enrichment-sourced hash (fetched from a registry / cache).
    /// Not trusted as an integrity baseline by `verify`.
    #[must_use]
    pub const fn enriched(algorithm: HashAlgorithm, value: String) -> Self {
        Self {
            algorithm,
            value,
            provenance: HashProvenance::Enriched,
        }
    }
}

/// Hash algorithm types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b256,
    Blake2b384,
    Blake2b512,
    Blake3,
    Streebog256,
    Streebog512,
    Other(String),
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Md5 => write!(f, "MD5"),
            Self::Sha1 => write!(f, "SHA-1"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Sha3_256 => write!(f, "SHA3-256"),
            Self::Sha3_384 => write!(f, "SHA3-384"),
            Self::Sha3_512 => write!(f, "SHA3-512"),
            Self::Blake2b256 => write!(f, "BLAKE2b-256"),
            Self::Blake2b384 => write!(f, "BLAKE2b-384"),
            Self::Blake2b512 => write!(f, "BLAKE2b-512"),
            Self::Blake3 => write!(f, "BLAKE3"),
            Self::Streebog256 => write!(f, "Streebog-256"),
            Self::Streebog512 => write!(f, "Streebog-512"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// External reference
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalReference {
    /// Reference type
    pub ref_type: ExternalRefType,
    /// URL or locator
    pub url: String,
    /// Comment or description
    pub comment: Option<String>,
    /// Hash of the referenced content
    pub hashes: Vec<Hash>,
}

/// External reference types.
///
/// The variants follow the CycloneDX `externalReference.type` vocabulary,
/// and each displays as its CycloneDX value (`Certification` as
/// `certification-report`, `SourceDistribution` as `distribution`, …), which
/// is what the CycloneDX writer emits. Parsers map the other formats'
/// equivalents onto the same variants; a type without one is kept verbatim
/// in `Other`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalRefType {
    Vcs,
    IssueTracker,
    Website,
    Advisories,
    Bom,
    MailingList,
    Social,
    Chat,
    Documentation,
    Support,
    /// CycloneDX `distribution`: a direct or repository download location
    /// (the SPDX parsers store a package's download location here).
    SourceDistribution,
    /// CycloneDX `distribution-intake`: where the component was published.
    BinaryDistribution,
    License,
    BuildMeta,
    BuildSystem,
    ReleaseNotes,
    SecurityContact,
    ModelCard,
    Log,
    Configuration,
    Evidence,
    Formulation,
    Attestation,
    ThreatModel,
    AdversaryModel,
    RiskAssessment,
    VulnerabilityAssertion,
    ExploitabilityStatement,
    Pentest,
    StaticAnalysis,
    DynamicAnalysis,
    RuntimeAnalysis,
    ComponentAnalysis,
    Maturity,
    Certification,
    QualityMetrics,
    /// CycloneDX `codified-infrastructure` (infrastructure as code).
    Codified,
    Citation,
    Patent,
    PatentAssertion,
    PatentFamily,
    Other(String),
}

impl std::fmt::Display for ExternalRefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vcs => write!(f, "vcs"),
            Self::IssueTracker => write!(f, "issue-tracker"),
            Self::Website => write!(f, "website"),
            Self::Advisories => write!(f, "advisories"),
            Self::Bom => write!(f, "bom"),
            Self::MailingList => write!(f, "mailing-list"),
            Self::Social => write!(f, "social"),
            Self::Chat => write!(f, "chat"),
            Self::Documentation => write!(f, "documentation"),
            Self::Support => write!(f, "support"),
            Self::SourceDistribution => write!(f, "distribution"),
            Self::BinaryDistribution => write!(f, "distribution-intake"),
            Self::License => write!(f, "license"),
            Self::BuildMeta => write!(f, "build-meta"),
            Self::BuildSystem => write!(f, "build-system"),
            Self::ReleaseNotes => write!(f, "release-notes"),
            Self::SecurityContact => write!(f, "security-contact"),
            Self::ModelCard => write!(f, "model-card"),
            Self::Log => write!(f, "log"),
            Self::Configuration => write!(f, "configuration"),
            Self::Evidence => write!(f, "evidence"),
            Self::Formulation => write!(f, "formulation"),
            Self::Attestation => write!(f, "attestation"),
            Self::ThreatModel => write!(f, "threat-model"),
            Self::AdversaryModel => write!(f, "adversary-model"),
            Self::RiskAssessment => write!(f, "risk-assessment"),
            Self::VulnerabilityAssertion => write!(f, "vulnerability-assertion"),
            Self::ExploitabilityStatement => write!(f, "exploitability-statement"),
            Self::Pentest => write!(f, "pentest-report"),
            Self::StaticAnalysis => write!(f, "static-analysis-report"),
            Self::DynamicAnalysis => write!(f, "dynamic-analysis-report"),
            Self::RuntimeAnalysis => write!(f, "runtime-analysis-report"),
            Self::ComponentAnalysis => write!(f, "component-analysis-report"),
            Self::Maturity => write!(f, "maturity-report"),
            Self::Certification => write!(f, "certification-report"),
            Self::QualityMetrics => write!(f, "quality-metrics"),
            Self::Codified => write!(f, "codified-infrastructure"),
            Self::Citation => write!(f, "citation"),
            Self::Patent => write!(f, "patent"),
            Self::PatentAssertion => write!(f, "patent-assertion"),
            Self::PatentFamily => write!(f, "patent-family"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Dependency relationship type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DependencyType {
    /// Direct dependency
    DependsOn,
    /// Optional dependency
    OptionalDependsOn,
    /// Development dependency
    DevDependsOn,
    /// Build dependency
    BuildDependsOn,
    /// Test dependency
    TestDependsOn,
    /// Runtime dependency
    RuntimeDependsOn,
    /// Provided dependency (e.g., Java provided scope)
    ProvidedDependsOn,
    /// Describes relationship (SPDX)
    Describes,
    /// Generates relationship
    Generates,
    /// Contains relationship
    Contains,
    /// Ancestor of
    AncestorOf,
    /// Variant of
    VariantOf,
    /// Distribution artifact
    DistributionArtifact,
    /// Patch for
    PatchFor,
    /// Copy of
    CopyOf,
    /// File added
    FileAdded,
    /// File deleted
    FileDeleted,
    /// File modified
    FileModified,
    /// Dynamic link
    DynamicLink,
    /// Static link
    StaticLink,
    /// Provides (CycloneDX 1.7: library provides/implements a crypto asset)
    Provides,
    /// Other relationship
    Other(String),
}

impl std::fmt::Display for DependencyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DependsOn => write!(f, "depends-on"),
            Self::OptionalDependsOn => write!(f, "optional-depends-on"),
            Self::DevDependsOn => write!(f, "dev-depends-on"),
            Self::BuildDependsOn => write!(f, "build-depends-on"),
            Self::TestDependsOn => write!(f, "test-depends-on"),
            Self::RuntimeDependsOn => write!(f, "runtime-depends-on"),
            Self::ProvidedDependsOn => write!(f, "provided-depends-on"),
            Self::Describes => write!(f, "describes"),
            Self::Generates => write!(f, "generates"),
            Self::Contains => write!(f, "contains"),
            Self::AncestorOf => write!(f, "ancestor-of"),
            Self::VariantOf => write!(f, "variant-of"),
            Self::DistributionArtifact => write!(f, "distribution-artifact"),
            Self::PatchFor => write!(f, "patch-for"),
            Self::CopyOf => write!(f, "copy-of"),
            Self::FileAdded => write!(f, "file-added"),
            Self::FileDeleted => write!(f, "file-deleted"),
            Self::FileModified => write!(f, "file-modified"),
            Self::DynamicLink => write!(f, "dynamic-link"),
            Self::StaticLink => write!(f, "static-link"),
            Self::Provides => write!(f, "provides"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Dependency scope
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyScope {
    #[default]
    Required,
    Optional,
    Excluded,
}

impl std::fmt::Display for DependencyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required => write!(f, "required"),
            Self::Optional => write!(f, "optional"),
            Self::Excluded => write!(f, "excluded"),
        }
    }
}

/// Format-specific extensions that don't map to the canonical model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FormatExtensions {
    /// CycloneDX-specific extensions
    pub cyclonedx: Option<serde_json::Value>,
    /// SPDX-specific extensions
    pub spdx: Option<serde_json::Value>,
    /// CycloneDX 1.6 Attestations (CDXA): normalized `declarations` plus
    /// `definitions.standards`. Populated only by the CycloneDX JSON parser
    /// for `specVersion >= 1.6` documents that carry these sections; `None`
    /// otherwise (SPDX, older CycloneDX, XML input). Additive: skipped in
    /// serialized output when absent, so documents without declarations
    /// serialize byte-identically to previous releases. Prefer the
    /// [`crate::model::NormalizedSbom::declarations`] accessor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declarations: Option<crate::model::AttestationDeclarations>,
}

/// Component-level extensions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentExtensions {
    /// Properties from `CycloneDX`
    pub properties: Vec<Property>,
    /// Annotations from SPDX
    pub annotations: Vec<Annotation>,
    /// Raw extension data.
    ///
    /// Occupied by the SPDX-3 AI-profile bridge (`parsers::spdx3`), which mirrors
    /// non-typed AI signals here in CycloneDX `mlModel.modelCard` layout so the
    /// AI-readiness scorer can read them. Do NOT repurpose this for round-trip
    /// preservation — use [`source_json`](Self::source_json) instead.
    pub raw: Option<serde_json::Value>,
    /// Verbatim source JSON object for this component, captured for cross-format
    /// conversion fidelity.
    ///
    /// Opt-in and convert-only: populated solely when the `convert`/`--preserve`
    /// path is active (see [`crate::serialization::emit`]), keeping it out of the
    /// normal parse hot path so memory stays bounded. Boxed to keep
    /// [`ComponentExtensions`] small when the slot is empty (the common case),
    /// and skipped on serialization when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_json: Option<Box<serde_json::Value>>,
}

/// Key-value property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// Annotation/comment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub annotator: String,
    pub annotation_date: DateTime<Utc>,
    pub annotation_type: String,
    pub comment: String,
}

/// Machine learning model metadata (CycloneDX 1.5+)
///
/// Structured information about trained ML models, including architecture,
/// approach, quantization, and environmental impact.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MlModelInfo {
    /// ML approach type: "supervised", "unsupervised", "reinforcement-learning", "semi-supervised"
    pub approach: Option<String>,
    /// Architecture family: "transformer", "cnn", "rnn", "llm", "gan", etc.
    pub architecture_family: Option<String>,
    /// Architecture name: "bert", "gpt", "resnet", etc.
    pub architecture_name: Option<String>,
    /// ML task: "nlp", "computer-vision", "audio", "tabular", etc.
    pub task: Option<String>,
    /// Quantization mode: "int4", "int8", "fp16", "bf16", "fp32", "mixed", etc.
    pub quantization: Option<String>,
    /// Limitations or known constraints of the model
    pub limitations: Option<String>,
    /// Training datasets used for this model
    pub training_datasets: Vec<DatasetRef>,
    /// Energy consumed during training in kWh (approximate)
    pub energy_kwh_training: Option<f64>,
    /// URL to detailed model card (from ExternalRefType::ModelCard)
    pub model_card_url: Option<String>,
    /// Fairness assessments (CycloneDX 1.5+ `considerations.fairnessAssessments`).
    /// SPDX 3.0 has no direct analogue; the nearest AI-profile signals are
    /// normalized into this shape so cross-format scoring is symmetric.
    pub fairness: Vec<FairnessAssessment>,
    /// Ethical considerations. CycloneDX emits structured objects
    /// (`considerations.ethicalConsiderations[]`); SPDX emits free strings.
    /// Both are normalized into this single shape.
    pub ethical_considerations: Vec<EthicalConsideration>,
    /// Intended use-cases (CycloneDX `considerations.useCases`, SPDX `ai_domain` /
    /// `ai_informationAboutApplication`).
    pub use_cases: Vec<String>,
    /// Quantitative performance metrics (CycloneDX
    /// `modelCard.quantitativeAnalysis.performanceMetrics`, SPDX `ai_metric`).
    pub performance_metrics: Vec<MetricEntry>,
    /// Data-preprocessing steps applied to the model's inputs (SPDX 3.0 AI
    /// profile `ai_modelDataPreprocessing`). Surfaced for the BSI/G7
    /// SBOM-for-AI "Models" cluster; CycloneDX has no direct analogue.
    pub data_preprocessing: Vec<String>,
}

/// A fairness assessment for an ML model (CycloneDX 1.5+
/// `considerations.fairnessAssessments[]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FairnessAssessment {
    /// The group(s) potentially at risk for the identified fairness concern.
    pub group_at_risk: Option<String>,
    /// Expected benefits to the group at risk.
    pub benefits: Option<String>,
    /// Potential harms to the group at risk.
    pub harms: Option<String>,
    /// Strategy used to mitigate the identified harms.
    pub mitigation_strategy: Option<String>,
}

/// An ethical consideration for an ML model. Normalized from CycloneDX structured
/// objects (`{ name, mitigationStrategy }`) and SPDX free-text strings alike.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EthicalConsideration {
    /// Name / description of the ethical risk.
    pub name: Option<String>,
    /// Strategy used to mitigate the ethical risk (CycloneDX only).
    pub mitigation_strategy: Option<String>,
}

/// A single quantitative performance metric (CycloneDX
/// `quantitativeAnalysis.performanceMetrics[]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MetricEntry {
    /// Metric type (e.g. "accuracy", "F1", "precision").
    pub metric_type: Option<String>,
    /// Metric value, retained verbatim (string form is spec-conformant and
    /// preserves precision / non-numeric values such as confidence intervals).
    pub value: Option<String>,
    /// Data slice the metric was computed over (CycloneDX `slice`).
    pub slice: Option<String>,
}

/// Reference to a dataset used for training or evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DatasetRef {
    /// BOM-ref / BOM-Link to a dataset component (CycloneDX `modelParameters.datasets` `{ref}` form)
    pub reference: Option<String>,
    /// Dataset name (from an inline `componentData` dataset)
    pub name: Option<String>,
    /// Package URL (PURL). Not part of the CycloneDX spec for datasets; retained for
    /// non-spec emitters and is `None` for spec-conformant input.
    pub purl: Option<String>,
}

/// Dataset component metadata (CycloneDX 1.5+ data type)
///
/// Structured information about datasets, including type, sensitivity,
/// governance, and content properties.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DatasetInfo {
    /// Dataset type: "training", "testing", "validation", "evaluation"
    pub dataset_type: Option<String>,
    /// Sensitivity classifications: "sensitive", "confidential", "pii", etc.
    pub sensitivity_classifications: Vec<String>,
    /// Data governance owners/custodians
    pub governance_owners: Vec<String>,
    /// Intended use of the dataset (SPDX 3.0 Dataset profile
    /// `dataset_intendedUse`). Part of the BSI/G7 SBOM-for-AI "Datasets"
    /// cluster provenance / intended-use element.
    pub intended_use: Option<String>,
    /// Confidentiality level of the dataset (SPDX 3.0 Dataset profile
    /// `dataset_confidentialityLevel`). Distinct from the sensitivity
    /// classifications above, which already fold this in for AI-Act scoring;
    /// retained verbatim here for the BSI sensitivity-classification element.
    pub confidentiality_level: Option<String>,
    /// Data-preprocessing steps applied to the dataset (SPDX 3.0 Dataset
    /// profile `dataset_dataPreprocessing`). Surfaced for the BSI/G7
    /// SBOM-for-AI "Datasets" cluster provenance element.
    pub preprocessing: Vec<String>,
    /// Anonymization methods applied to the dataset (SPDX 3.0 Dataset profile
    /// `dataset_anonymizationMethodUsed`). Surfaced for the BSI/G7
    /// SBOM-for-AI "Datasets" cluster provenance element.
    pub anonymization: Vec<String>,
}

#[cfg(test)]
mod spec_version_tests {
    use super::SpecVersion;

    #[test]
    fn parses_common_spellings() {
        assert_eq!(SpecVersion::parse("1.6"), Some(SpecVersion::new(1, 6, 0)));
        assert_eq!(SpecVersion::parse("3.0.1"), Some(SpecVersion::new(3, 0, 1)));
        assert_eq!(
            SpecVersion::parse("SPDX-2.3"),
            Some(SpecVersion::new(2, 3, 0))
        );
        assert_eq!(
            SpecVersion::parse(" v1.7 "),
            Some(SpecVersion::new(1, 7, 0))
        );
        assert_eq!(SpecVersion::parse("2"), Some(SpecVersion::new(2, 0, 0)));
        for bad in ["", "   ", "abc", "1.x", "1.2.3.4", "1..2"] {
            assert_eq!(SpecVersion::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn compares_numerically_not_by_prefix() {
        // String prefixes read "1.10" as "1.1"; numerically it is newer.
        let v110 = SpecVersion::parse("1.10").expect("parses");
        assert!(v110 > SpecVersion::new(1, 7, 0));
        assert!(SpecVersion::new(1, 0, 0) < SpecVersion::new(1, 4, 0));
        assert!(SpecVersion::new(2, 0, 0) > SpecVersion::new(1, 7, 0));
        assert!(SpecVersion::new(3, 0, 1) > SpecVersion::new(3, 0, 0));
    }
}
