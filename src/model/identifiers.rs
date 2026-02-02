//! Canonical identifiers for SBOM components.
//!
//! This module provides stable, comparable identifiers for components across
//! different SBOM formats. The identification strategy uses a tiered fallback:
//!
//! 1. **PURL** (Package URL) - Most reliable, globally unique
//! 2. **CPE** (Common Platform Enumeration) - Industry standard for vulnerability matching
//! 3. **SWID** (Software Identification) - ISO standard tag
//! 4. **Synthetic** - Generated from group:name@version (stable across regenerations)
//! 5. **FormatSpecific** - Original format ID (least stable, may be UUIDs)

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Canonical identifier for a component.
///
/// This provides a stable, comparable identifier across different SBOM formats.
/// The identifier is derived from the PURL when available, falling back through
/// a tiered strategy to ensure stability.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct CanonicalId {
    /// The normalized identifier string
    value: String,
    /// Source of the identifier
    source: IdSource,
    /// Whether this ID is considered stable across SBOM regenerations
    #[serde(default)]
    stable: bool,
}

/// Source of the canonical identifier, ordered by reliability
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdSource {
    /// Derived from Package URL (most reliable)
    Purl,
    /// Derived from CPE
    Cpe,
    /// Derived from SWID tag
    Swid,
    /// Derived from name and version (stable)
    NameVersion,
    /// Synthetically generated from group:name@version
    Synthetic,
    /// Format-specific identifier (least stable - may be UUID)
    FormatSpecific,
}

impl IdSource {
    /// Returns true if this source produces stable identifiers
    pub fn is_stable(&self) -> bool {
        matches!(
            self,
            IdSource::Purl
                | IdSource::Cpe
                | IdSource::Swid
                | IdSource::NameVersion
                | IdSource::Synthetic
        )
    }

    /// Returns the reliability rank (lower is better)
    pub fn reliability_rank(&self) -> u8 {
        match self {
            IdSource::Purl => 0,
            IdSource::Cpe => 1,
            IdSource::Swid => 2,
            IdSource::NameVersion => 3,
            IdSource::Synthetic => 4,
            IdSource::FormatSpecific => 5,
        }
    }
}

impl CanonicalId {
    /// Create a new canonical ID from a PURL
    pub fn from_purl(purl: &str) -> Self {
        Self {
            value: Self::normalize_purl(purl),
            source: IdSource::Purl,
            stable: true,
        }
    }

    /// Create a new canonical ID from name and version
    pub fn from_name_version(name: &str, version: Option<&str>) -> Self {
        let value = match version {
            Some(v) => format!("{}@{}", name.to_lowercase(), v),
            None => name.to_lowercase(),
        };
        Self {
            value,
            source: IdSource::NameVersion,
            stable: true,
        }
    }

    /// Create a synthetic canonical ID from group, name, and version
    ///
    /// This provides a stable identifier when primary identifiers (PURL, CPE, SWID)
    /// are not available. The format is: `group:name@version` or `name@version`.
    pub fn synthetic(group: Option<&str>, name: &str, version: Option<&str>) -> Self {
        let value = match (group, version) {
            (Some(g), Some(v)) => format!("{}:{}@{}", g.to_lowercase(), name.to_lowercase(), v),
            (Some(g), None) => format!("{}:{}", g.to_lowercase(), name.to_lowercase()),
            (None, Some(v)) => format!("{}@{}", name.to_lowercase(), v),
            (None, None) => name.to_lowercase(),
        };
        Self {
            value,
            source: IdSource::Synthetic,
            stable: true,
        }
    }

    /// Create a new canonical ID from a format-specific identifier
    ///
    /// **Warning**: Format-specific IDs (like bom-ref UUIDs) are often unstable
    /// across SBOM regenerations. Use `synthetic()` or other methods when possible.
    pub fn from_format_id(id: &str) -> Self {
        // Check if this looks like a UUID (unstable)
        let looks_like_uuid = id.len() == 36
            && id.chars().filter(|c| *c == '-').count() == 4
            && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-');

        Self {
            value: id.to_string(),
            source: IdSource::FormatSpecific,
            stable: !looks_like_uuid,
        }
    }

    /// Create from CPE
    pub fn from_cpe(cpe: &str) -> Self {
        Self {
            value: cpe.to_lowercase(),
            source: IdSource::Cpe,
            stable: true,
        }
    }

    /// Create from SWID tag
    pub fn from_swid(swid: &str) -> Self {
        Self {
            value: swid.to_string(),
            source: IdSource::Swid,
            stable: true,
        }
    }

    /// Get the canonical ID value
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Get the source of this identifier
    pub fn source(&self) -> &IdSource {
        &self.source
    }

    /// Returns true if this identifier is stable across SBOM regenerations
    pub fn is_stable(&self) -> bool {
        self.stable
    }

    /// Normalize a PURL string for comparison
    fn normalize_purl(purl: &str) -> String {
        // Basic normalization - a full implementation would use the packageurl crate
        let mut normalized = purl.to_lowercase();

        // Handle common ecosystem-specific normalizations
        if normalized.starts_with("pkg:pypi/") {
            // PyPI: normalize underscores, hyphens, and dots to hyphens
            normalized = normalized.replace(['_', '.'], "-");
        } else if normalized.starts_with("pkg:npm/") {
            // NPM: decode URL-encoded scope
            normalized = normalized.replace("%40", "@");
        }

        normalized
    }
}

impl PartialEq for CanonicalId {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Hash for CanonicalId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl fmt::Display for CanonicalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Component identifiers from various sources
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentIdentifiers {
    /// Package URL (preferred identifier)
    pub purl: Option<String>,
    /// Common Platform Enumeration identifiers
    pub cpe: Vec<String>,
    /// Software Identification tag
    pub swid: Option<String>,
    /// Original format-specific identifier
    pub format_id: String,
    /// Known aliases for this component
    pub aliases: Vec<String>,
}

/// Result of canonical ID generation, including stability information
#[derive(Debug, Clone)]
pub struct CanonicalIdResult {
    /// The canonical ID
    pub id: CanonicalId,
    /// Warning message if fallback was used
    pub warning: Option<String>,
}

impl ComponentIdentifiers {
    /// Create a new empty set of identifiers
    pub fn new(format_id: String) -> Self {
        Self {
            format_id,
            ..Default::default()
        }
    }

    /// Get the best available canonical ID (without component context)
    ///
    /// For better stability, prefer `canonical_id_with_context()` which can
    /// generate synthetic IDs from component metadata.
    pub fn canonical_id(&self) -> CanonicalId {
        // Tiered fallback: PURL → CPE → SWID → format_id
        if let Some(purl) = &self.purl {
            CanonicalId::from_purl(purl)
        } else if let Some(cpe) = self.cpe.first() {
            CanonicalId::from_cpe(cpe)
        } else if let Some(swid) = &self.swid {
            CanonicalId::from_swid(swid)
        } else {
            CanonicalId::from_format_id(&self.format_id)
        }
    }

    /// Get the best available canonical ID with component context for stable fallback
    ///
    /// This method uses a tiered fallback strategy:
    /// 1. PURL (most reliable)
    /// 2. CPE
    /// 3. SWID
    /// 4. Synthetic (group:name@version) - stable across regenerations
    /// 5. Format-specific ID (least stable)
    ///
    /// Returns both the ID and any warnings about stability.
    pub fn canonical_id_with_context(
        &self,
        name: &str,
        version: Option<&str>,
        group: Option<&str>,
    ) -> CanonicalIdResult {
        // Tier 1: PURL (best)
        if let Some(purl) = &self.purl {
            return CanonicalIdResult {
                id: CanonicalId::from_purl(purl),
                warning: None,
            };
        }

        // Tier 2: CPE
        if let Some(cpe) = self.cpe.first() {
            return CanonicalIdResult {
                id: CanonicalId::from_cpe(cpe),
                warning: None,
            };
        }

        // Tier 3: SWID
        if let Some(swid) = &self.swid {
            return CanonicalIdResult {
                id: CanonicalId::from_swid(swid),
                warning: None,
            };
        }

        // Tier 4: Synthetic from name/version/group (stable)
        // Only use if we have at least a name
        if !name.is_empty() {
            return CanonicalIdResult {
                id: CanonicalId::synthetic(group, name, version),
                warning: Some(format!(
                    "Component '{}' lacks PURL/CPE/SWID identifiers; using synthetic ID. \
                     Consider enriching SBOM with package URLs for accurate diffing.",
                    name
                )),
            };
        }

        // Tier 5: Format-specific (least stable - may be UUID)
        let id = CanonicalId::from_format_id(&self.format_id);
        let warning = if !id.is_stable() {
            Some(format!(
                "Component uses unstable format-specific ID '{}'. \
                 This may cause inaccurate diff results across SBOM regenerations.",
                self.format_id
            ))
        } else {
            Some(format!(
                "Component uses format-specific ID '{}' without standard identifiers.",
                self.format_id
            ))
        };

        CanonicalIdResult { id, warning }
    }

    /// Check if this component has any stable identifiers
    pub fn has_stable_id(&self) -> bool {
        self.purl.is_some() || !self.cpe.is_empty() || self.swid.is_some()
    }

    /// Get the reliability level of available identifiers
    pub fn id_reliability(&self) -> IdReliability {
        if self.purl.is_some() {
            IdReliability::High
        } else if !self.cpe.is_empty() || self.swid.is_some() {
            IdReliability::Medium
        } else {
            IdReliability::Low
        }
    }
}

/// Reliability level of component identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdReliability {
    /// High reliability (PURL available)
    High,
    /// Medium reliability (CPE or SWID available)
    Medium,
    /// Low reliability (synthetic or format-specific only)
    Low,
}

impl fmt::Display for IdReliability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdReliability::High => write!(f, "high"),
            IdReliability::Medium => write!(f, "medium"),
            IdReliability::Low => write!(f, "low"),
        }
    }
}

/// Ecosystem/package manager type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    PyPi,
    Cargo,
    Maven,
    Golang,
    Nuget,
    RubyGems,
    Composer,
    CocoaPods,
    Swift,
    Hex,
    Pub,
    Hackage,
    Cpan,
    Cran,
    Conda,
    Conan,
    Deb,
    Rpm,
    Apk,
    Generic,
    Unknown(String),
}

impl Ecosystem {
    /// Parse ecosystem from PURL type
    pub fn from_purl_type(purl_type: &str) -> Self {
        match purl_type.to_lowercase().as_str() {
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPi,
            "cargo" => Ecosystem::Cargo,
            "maven" => Ecosystem::Maven,
            "golang" | "go" => Ecosystem::Golang,
            "nuget" => Ecosystem::Nuget,
            "gem" => Ecosystem::RubyGems,
            "composer" => Ecosystem::Composer,
            "cocoapods" => Ecosystem::CocoaPods,
            "swift" => Ecosystem::Swift,
            "hex" => Ecosystem::Hex,
            "pub" => Ecosystem::Pub,
            "hackage" => Ecosystem::Hackage,
            "cpan" => Ecosystem::Cpan,
            "cran" => Ecosystem::Cran,
            "conda" => Ecosystem::Conda,
            "conan" => Ecosystem::Conan,
            "deb" => Ecosystem::Deb,
            "rpm" => Ecosystem::Rpm,
            "apk" => Ecosystem::Apk,
            "generic" => Ecosystem::Generic,
            other => Ecosystem::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::PyPi => write!(f, "pypi"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::Maven => write!(f, "maven"),
            Ecosystem::Golang => write!(f, "golang"),
            Ecosystem::Nuget => write!(f, "nuget"),
            Ecosystem::RubyGems => write!(f, "gem"),
            Ecosystem::Composer => write!(f, "composer"),
            Ecosystem::CocoaPods => write!(f, "cocoapods"),
            Ecosystem::Swift => write!(f, "swift"),
            Ecosystem::Hex => write!(f, "hex"),
            Ecosystem::Pub => write!(f, "pub"),
            Ecosystem::Hackage => write!(f, "hackage"),
            Ecosystem::Cpan => write!(f, "cpan"),
            Ecosystem::Cran => write!(f, "cran"),
            Ecosystem::Conda => write!(f, "conda"),
            Ecosystem::Conan => write!(f, "conan"),
            Ecosystem::Deb => write!(f, "deb"),
            Ecosystem::Rpm => write!(f, "rpm"),
            Ecosystem::Apk => write!(f, "apk"),
            Ecosystem::Generic => write!(f, "generic"),
            Ecosystem::Unknown(s) => write!(f, "{}", s),
        }
    }
}

// ============================================================================
// ComponentRef: Lightweight reference combining ID and display name
// ============================================================================

/// A lightweight reference to a component, combining its stable ID with
/// a human-readable display name.
///
/// This type is used throughout the diff system and TUI to:
/// - Navigate and link by ID (stable, unique)
/// - Display by name (human-readable)
///
/// # Example
/// ```ignore
/// let comp_ref = ComponentRef::new(component.canonical_id.clone(), &component.name);
/// println!("Component: {} (ID: {})", comp_ref.name(), comp_ref.id());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComponentRef {
    /// The stable canonical ID for linking and navigation
    id: CanonicalId,
    /// Human-readable name for display
    name: String,
    /// Optional version for display context
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

impl ComponentRef {
    /// Create a new component reference
    pub fn new(id: CanonicalId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            version: None,
        }
    }

    /// Create a component reference with version
    pub fn with_version(id: CanonicalId, name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            id,
            name: name.into(),
            version,
        }
    }

    /// Create from a Component
    pub fn from_component(component: &super::Component) -> Self {
        Self {
            id: component.canonical_id.clone(),
            name: component.name.clone(),
            version: component.version.clone(),
        }
    }

    /// Get the canonical ID
    pub fn id(&self) -> &CanonicalId {
        &self.id
    }

    /// Get the ID as a string
    pub fn id_str(&self) -> &str {
        self.id.value()
    }

    /// Get the display name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the version if available
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Get display string with version if available
    pub fn display_with_version(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }

    /// Check if this ref matches a given ID
    pub fn matches_id(&self, id: &CanonicalId) -> bool {
        &self.id == id
    }

    /// Check if this ref matches a given ID string
    pub fn matches_id_str(&self, id_str: &str) -> bool {
        self.id.value() == id_str
    }
}

impl fmt::Display for ComponentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&super::Component> for ComponentRef {
    fn from(component: &super::Component) -> Self {
        Self::from_component(component)
    }
}

/// A reference to a vulnerability with its associated component
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VulnerabilityRef2 {
    /// Vulnerability ID (e.g., CVE-2021-44228)
    pub vuln_id: String,
    /// Reference to the affected component
    pub component: ComponentRef,
}

impl VulnerabilityRef2 {
    /// Create a new vulnerability reference
    pub fn new(vuln_id: impl Into<String>, component: ComponentRef) -> Self {
        Self {
            vuln_id: vuln_id.into(),
            component,
        }
    }

    /// Get the component's canonical ID
    pub fn component_id(&self) -> &CanonicalId {
        self.component.id()
    }

    /// Get the component name for display
    pub fn component_name(&self) -> &str {
        self.component.name()
    }
}
