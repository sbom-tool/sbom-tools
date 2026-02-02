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
            SbomFormat::CycloneDx => write!(f, "CycloneDX"),
            SbomFormat::Spdx => write!(f, "SPDX"),
        }
    }
}

/// Document-level metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// SBOM format type
    pub format: SbomFormat,
    /// Format version (e.g., "1.5" for CycloneDX)
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
    pub fn new(name: String) -> Self {
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
            ComponentType::Application => write!(f, "application"),
            ComponentType::Framework => write!(f, "framework"),
            ComponentType::Library => write!(f, "library"),
            ComponentType::Container => write!(f, "container"),
            ComponentType::OperatingSystem => write!(f, "operating-system"),
            ComponentType::Device => write!(f, "device"),
            ComponentType::Firmware => write!(f, "firmware"),
            ComponentType::File => write!(f, "file"),
            ComponentType::Data => write!(f, "data"),
            ComponentType::MachineLearningModel => write!(f, "machine-learning-model"),
            ComponentType::Platform => write!(f, "platform"),
            ComponentType::DeviceDriver => write!(f, "device-driver"),
            ComponentType::Cryptographic => write!(f, "cryptographic"),
            ComponentType::Other(s) => write!(f, "{}", s),
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
    pub fn new(algorithm: HashAlgorithm, value: String) -> Self {
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
            HashAlgorithm::Md5 => write!(f, "MD5"),
            HashAlgorithm::Sha1 => write!(f, "SHA-1"),
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Sha384 => write!(f, "SHA-384"),
            HashAlgorithm::Sha512 => write!(f, "SHA-512"),
            HashAlgorithm::Sha3_256 => write!(f, "SHA3-256"),
            HashAlgorithm::Sha3_384 => write!(f, "SHA3-384"),
            HashAlgorithm::Sha3_512 => write!(f, "SHA3-512"),
            HashAlgorithm::Blake2b256 => write!(f, "BLAKE2b-256"),
            HashAlgorithm::Blake2b384 => write!(f, "BLAKE2b-384"),
            HashAlgorithm::Blake2b512 => write!(f, "BLAKE2b-512"),
            HashAlgorithm::Blake3 => write!(f, "BLAKE3"),
            HashAlgorithm::Other(s) => write!(f, "{}", s),
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
            ExternalRefType::Vcs => write!(f, "vcs"),
            ExternalRefType::IssueTracker => write!(f, "issue-tracker"),
            ExternalRefType::Website => write!(f, "website"),
            ExternalRefType::Advisories => write!(f, "advisories"),
            ExternalRefType::Bom => write!(f, "bom"),
            ExternalRefType::MailingList => write!(f, "mailing-list"),
            ExternalRefType::Social => write!(f, "social"),
            ExternalRefType::Chat => write!(f, "chat"),
            ExternalRefType::Documentation => write!(f, "documentation"),
            ExternalRefType::Support => write!(f, "support"),
            ExternalRefType::SourceDistribution => write!(f, "distribution"),
            ExternalRefType::BinaryDistribution => write!(f, "distribution-intake"),
            ExternalRefType::License => write!(f, "license"),
            ExternalRefType::BuildMeta => write!(f, "build-meta"),
            ExternalRefType::BuildSystem => write!(f, "build-system"),
            ExternalRefType::ReleaseNotes => write!(f, "release-notes"),
            ExternalRefType::SecurityContact => write!(f, "security-contact"),
            ExternalRefType::ModelCard => write!(f, "model-card"),
            ExternalRefType::Log => write!(f, "log"),
            ExternalRefType::Configuration => write!(f, "configuration"),
            ExternalRefType::Evidence => write!(f, "evidence"),
            ExternalRefType::Formulation => write!(f, "formulation"),
            ExternalRefType::Attestation => write!(f, "attestation"),
            ExternalRefType::ThreatModel => write!(f, "threat-model"),
            ExternalRefType::AdversaryModel => write!(f, "adversary-model"),
            ExternalRefType::RiskAssessment => write!(f, "risk-assessment"),
            ExternalRefType::VulnerabilityAssertion => write!(f, "vulnerability-assertion"),
            ExternalRefType::ExploitabilityStatement => write!(f, "exploitability-statement"),
            ExternalRefType::Pentest => write!(f, "pentest-report"),
            ExternalRefType::StaticAnalysis => write!(f, "static-analysis-report"),
            ExternalRefType::DynamicAnalysis => write!(f, "dynamic-analysis-report"),
            ExternalRefType::RuntimeAnalysis => write!(f, "runtime-analysis-report"),
            ExternalRefType::ComponentAnalysis => write!(f, "component-analysis-report"),
            ExternalRefType::Maturity => write!(f, "maturity-report"),
            ExternalRefType::Certification => write!(f, "certification-report"),
            ExternalRefType::QualityMetrics => write!(f, "quality-metrics"),
            ExternalRefType::Codified => write!(f, "codified"),
            ExternalRefType::Other(s) => write!(f, "{}", s),
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
            DependencyType::DependsOn => write!(f, "depends-on"),
            DependencyType::OptionalDependsOn => write!(f, "optional-depends-on"),
            DependencyType::DevDependsOn => write!(f, "dev-depends-on"),
            DependencyType::BuildDependsOn => write!(f, "build-depends-on"),
            DependencyType::TestDependsOn => write!(f, "test-depends-on"),
            DependencyType::RuntimeDependsOn => write!(f, "runtime-depends-on"),
            DependencyType::ProvidedDependsOn => write!(f, "provided-depends-on"),
            DependencyType::Describes => write!(f, "describes"),
            DependencyType::Generates => write!(f, "generates"),
            DependencyType::Contains => write!(f, "contains"),
            DependencyType::AncestorOf => write!(f, "ancestor-of"),
            DependencyType::VariantOf => write!(f, "variant-of"),
            DependencyType::DistributionArtifact => write!(f, "distribution-artifact"),
            DependencyType::PatchFor => write!(f, "patch-for"),
            DependencyType::CopyOf => write!(f, "copy-of"),
            DependencyType::FileAdded => write!(f, "file-added"),
            DependencyType::FileDeleted => write!(f, "file-deleted"),
            DependencyType::FileModified => write!(f, "file-modified"),
            DependencyType::DynamicLink => write!(f, "dynamic-link"),
            DependencyType::StaticLink => write!(f, "static-link"),
            DependencyType::Other(s) => write!(f, "{}", s),
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
    /// Properties from CycloneDX
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
