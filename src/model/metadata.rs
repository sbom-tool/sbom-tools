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
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            format: SbomFormat::CycloneDx,
            format_version: String::new(),
            spec_version: String::new(),
            serial_number: None,
            created: Utc::now(),
            creators: Vec::new(),
            name: None,
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
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
    Other(String),
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
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Cryptographic hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash {
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Hash value (hex encoded)
    pub value: String,
}

impl Hash {
    /// Create a new hash
    #[must_use] 
    pub const fn new(algorithm: HashAlgorithm, value: String) -> Self {
        Self { algorithm, value }
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
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// External reference types
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
    SourceDistribution,
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
    Codified,
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
            Self::Codified => write!(f, "codified"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Dependency relationship type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Format-specific extensions that don't map to the canonical model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FormatExtensions {
    /// CycloneDX-specific extensions
    pub cyclonedx: Option<serde_json::Value>,
    /// SPDX-specific extensions
    pub spdx: Option<serde_json::Value>,
}

/// Component-level extensions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentExtensions {
    /// Properties from `CycloneDX`
    pub properties: Vec<Property>,
    /// Annotations from SPDX
    pub annotations: Vec<Annotation>,
    /// Raw extension data
    pub raw: Option<serde_json::Value>,
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
