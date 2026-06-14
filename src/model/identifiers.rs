//! Canonical identifiers for SBOM components.
//!
//! This module provides stable, comparable identifiers for components across
//! different SBOM formats. The identification strategy uses a tiered fallback:
//!
//! 1. **PURL** (Package URL) - Most reliable, globally unique
//! 2. **CPE** (Common Platform Enumeration) - Industry standard for vulnerability matching
//! 3. **SWHID** (Software Heritage persistent ID) - Content-addressed, ISO/IEC 18670
//! 4. **SWID** (Software Identification) - ISO standard tag
//! 5. **Synthetic** - Generated from group:name@version (stable across regenerations)
//! 6. **`FormatSpecific`** - Original format ID (least stable, may be UUIDs)
//!
//! SWHID is one of the three identifier types named by CRA prEN 40000-1-3
//! `[PRE-7-RQ-07]` (alongside PURL and CPE).

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
#[non_exhaustive]
pub enum IdSource {
    /// Derived from Package URL (most reliable)
    Purl,
    /// Derived from CPE
    Cpe,
    /// Derived from Software Heritage persistent identifier (content-addressed)
    Swhid,
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
    #[must_use]
    pub const fn is_stable(&self) -> bool {
        matches!(
            self,
            Self::Purl | Self::Cpe | Self::Swhid | Self::Swid | Self::NameVersion | Self::Synthetic
        )
    }

    /// Returns the reliability rank (lower is better)
    #[must_use]
    pub const fn reliability_rank(&self) -> u8 {
        match self {
            Self::Purl => 0,
            Self::Cpe => 1,
            Self::Swhid => 2,
            Self::Swid => 3,
            Self::NameVersion => 4,
            Self::Synthetic => 5,
            Self::FormatSpecific => 6,
        }
    }
}

impl CanonicalId {
    /// Create a new canonical ID from a PURL
    #[must_use]
    pub fn from_purl(purl: &str) -> Self {
        Self {
            value: Self::normalize_purl(purl),
            source: IdSource::Purl,
            stable: true,
        }
    }

    /// Create a new canonical ID from name and version
    #[must_use]
    pub fn from_name_version(name: &str, version: Option<&str>) -> Self {
        let value = version.map_or_else(
            || name.to_lowercase(),
            |v| format!("{}@{}", name.to_lowercase(), v),
        );
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn from_cpe(cpe: &str) -> Self {
        Self {
            value: cpe.to_lowercase(),
            source: IdSource::Cpe,
            stable: true,
        }
    }

    /// Create from SWID tag
    #[must_use]
    pub fn from_swid(swid: &str) -> Self {
        Self {
            value: swid.to_string(),
            source: IdSource::Swid,
            stable: true,
        }
    }

    /// Create from a Software Heritage persistent identifier (SWHID).
    ///
    /// SWHIDs are content-addressed identifiers of the form
    /// `swh:1:<kind>:<sha1-hex>[;<qualifier>=<value>...]`.
    /// Named explicitly by CRA prEN 40000-1-3 `[PRE-7-RQ-07]` alongside PURL/CPE.
    ///
    /// Falls back to a `FormatSpecific` identifier (marked unstable) if the
    /// input does not look like a valid SWHID.
    #[must_use]
    pub fn from_swhid(swhid: &str) -> Self {
        match SwhidObject::parse(swhid) {
            Ok(obj) => Self {
                // Display reconstitutes the canonical lowercase form with qualifiers
                value: obj.to_string(),
                source: IdSource::Swhid,
                stable: true,
            },
            Err(_) => Self {
                value: swhid.to_string(),
                source: IdSource::FormatSpecific,
                stable: false,
            },
        }
    }

    /// Create from a structured `SwhidObject` (preferred internal path).
    #[must_use]
    pub fn from_swhid_object(obj: &SwhidObject) -> Self {
        Self {
            value: obj.to_string(),
            source: IdSource::Swhid,
            stable: true,
        }
    }

    /// Get the canonical ID value
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Get the source of this identifier
    #[must_use]
    pub const fn source(&self) -> &IdSource {
        &self.source
    }

    /// Returns true if this identifier is stable across SBOM regenerations
    #[must_use]
    pub const fn is_stable(&self) -> bool {
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

/// Software Heritage persistent identifier kind.
///
/// Per the SWHID spec (<https://www.swhid.org/>), every SWHID identifies one of
/// five object kinds in the Software Heritage archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwhidKind {
    /// File content (blob)
    Cnt,
    /// Directory (tree)
    Dir,
    /// Revision (commit)
    Rev,
    /// Release (tag)
    Rel,
    /// Snapshot (repository state)
    Snp,
}

impl SwhidKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cnt => "cnt",
            Self::Dir => "dir",
            Self::Rev => "rev",
            Self::Rel => "rel",
            Self::Snp => "snp",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cnt" => Some(Self::Cnt),
            "dir" => Some(Self::Dir),
            "rev" => Some(Self::Rev),
            "rel" => Some(Self::Rel),
            "snp" => Some(Self::Snp),
            _ => None,
        }
    }
}

impl fmt::Display for SwhidKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured Software Heritage persistent identifier.
///
/// Format: `swh:1:<kind>:<sha1-hex-40>[;<qualifier>=<value>...]`. Recognised
/// by CRA prEN 40000-1-3 `[PRE-7-RQ-07]` as one of the three named identifier
/// types (alongside PURL and CPE).
///
/// Serialised as a plain string in JSON to match CycloneDX/SPDX wire formats
/// (`["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", ...]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SwhidObject {
    /// Object kind (cnt/dir/rev/rel/snp)
    pub kind: SwhidKind,
    /// 20-byte SHA-1 of the canonical object representation
    pub hash: [u8; 20],
    /// Optional contextual qualifiers (origin, visit, anchor, path, lines)
    pub qualifiers: Vec<(String, String)>,
}

/// Errors returned when parsing a SWHID string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwhidParseError {
    /// String didn't have the four-part `swh:1:<kind>:<hash>` shape
    BadShape,
    /// Prefix wasn't `swh:1:`
    BadPrefix,
    /// Kind wasn't one of cnt/dir/rev/rel/snp
    BadKind,
    /// Hash wasn't 40 hex characters
    BadHash,
    /// Qualifier didn't have the `key=value` shape
    BadQualifier,
}

impl fmt::Display for SwhidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadShape => f.write_str("SWHID does not have shape swh:1:<kind>:<hash>"),
            Self::BadPrefix => f.write_str("SWHID prefix is not 'swh:1:'"),
            Self::BadKind => f.write_str("SWHID kind must be one of cnt/dir/rev/rel/snp"),
            Self::BadHash => f.write_str("SWHID hash must be 40 hexadecimal characters"),
            Self::BadQualifier => f.write_str("SWHID qualifier missing '=' separator"),
        }
    }
}

impl std::error::Error for SwhidParseError {}

impl SwhidObject {
    /// Parse a SWHID string into structured form.
    ///
    /// Validation is case-insensitive on the prefix, kind, and hash; the
    /// canonical form (returned by `Display`) is lowercase. Qualifier values
    /// are preserved verbatim — the SWHID spec does not mandate a case
    /// convention for qualifier values (e.g., URLs in `origin=`).
    pub fn parse(s: &str) -> Result<Self, SwhidParseError> {
        let (core, qualifier_str) = s.split_once(';').unwrap_or((s, ""));
        let parts: Vec<&str> = core.split(':').collect();
        if parts.len() != 4 {
            return Err(SwhidParseError::BadShape);
        }
        if !parts[0].eq_ignore_ascii_case("swh") || parts[1] != "1" {
            return Err(SwhidParseError::BadPrefix);
        }
        let kind = SwhidKind::parse(parts[2]).ok_or(SwhidParseError::BadKind)?;

        if parts[3].len() != 40 || !parts[3].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SwhidParseError::BadHash);
        }
        let mut hash = [0u8; 20];
        let bytes = parts[3].as_bytes();
        for (i, byte) in hash.iter_mut().enumerate() {
            let high = hex_digit(bytes[i * 2]).ok_or(SwhidParseError::BadHash)?;
            let low = hex_digit(bytes[i * 2 + 1]).ok_or(SwhidParseError::BadHash)?;
            *byte = (high << 4) | low;
        }

        let mut qualifiers = Vec::new();
        if !qualifier_str.is_empty() {
            for q in qualifier_str.split(';') {
                if q.is_empty() {
                    continue;
                }
                let (k, v) = q.split_once('=').ok_or(SwhidParseError::BadQualifier)?;
                qualifiers.push((k.to_string(), v.to_string()));
            }
        }

        Ok(Self {
            kind,
            hash,
            qualifiers,
        })
    }

    /// Canonical lowercase hex representation of the SHA-1 hash.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.hash {
            s.push(hex_char(b >> 4));
            s.push(hex_char(b & 0xf));
        }
        s
    }
}

const fn hex_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

const fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for SwhidObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "swh:1:{}:{}", self.kind, self.hash_hex())?;
        for (k, v) in &self.qualifiers {
            write!(f, ";{k}={v}")?;
        }
        Ok(())
    }
}

// Keep the wire format as a plain string so CycloneDX/SPDX I/O stays unchanged.
impl Serialize for SwhidObject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SwhidObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validate a SWHID string (convenience predicate over `SwhidObject::parse`).
#[must_use]
pub fn is_valid_swhid(s: &str) -> bool {
    SwhidObject::parse(s).is_ok()
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
    /// Software Heritage persistent identifiers (SWHIDs).
    ///
    /// Multiple values supported because a component may be expressible by
    /// several SWHID kinds (e.g., one `cnt` per archive entry plus a `dir`
    /// for the unpacked tree). CRA prEN 40000-1-3 `[PRE-7-RQ-07]` accepts
    /// SWHIDs as one of three named identifier types.
    ///
    /// Stored as structured `SwhidObject` for downstream consumers; on the
    /// wire (JSON), each element serialises as a plain string to match the
    /// CycloneDX / SPDX 3.0 `swhid` array shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swhid: Vec<SwhidObject>,
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
    #[must_use]
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
    #[must_use]
    pub fn canonical_id(&self) -> CanonicalId {
        // Tiered fallback: PURL → CPE → SWHID → SWID → format_id
        if let Some(purl) = &self.purl {
            return CanonicalId::from_purl(purl);
        }
        if let Some(cpe) = self.cpe.first() {
            return CanonicalId::from_cpe(cpe);
        }
        if let Some(swhid) = self.swhid.first() {
            return CanonicalId::from_swhid_object(swhid);
        }
        if let Some(swid) = &self.swid {
            return CanonicalId::from_swid(swid);
        }
        CanonicalId::from_format_id(&self.format_id)
    }

    /// Get the best available canonical ID with component context for stable fallback
    ///
    /// This method uses a tiered fallback strategy:
    /// 1. PURL (most reliable)
    /// 2. CPE
    /// 3. SWHID (content-addressed, CRA prEN 40000-1-3 named)
    /// 4. SWID
    /// 5. Synthetic (group:name@version) - stable across regenerations
    /// 6. Format-specific ID (least stable)
    ///
    /// Returns both the ID and any warnings about stability.
    #[must_use]
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

        // Tier 3: SWHID (content-addressed)
        if let Some(swhid) = self.swhid.first() {
            return CanonicalIdResult {
                id: CanonicalId::from_swhid_object(swhid),
                warning: None,
            };
        }

        // Tier 4: SWID
        if let Some(swid) = &self.swid {
            return CanonicalIdResult {
                id: CanonicalId::from_swid(swid),
                warning: None,
            };
        }

        // Tier 5: Synthetic from name/version/group (stable)
        // Only use if we have at least a name
        if !name.is_empty() {
            return CanonicalIdResult {
                id: CanonicalId::synthetic(group, name, version),
                warning: Some(format!(
                    "Component '{name}' lacks PURL/CPE/SWHID/SWID identifiers; using synthetic ID. \
                     Consider enriching SBOM with package URLs for accurate diffing."
                )),
            };
        }

        // Tier 6: Format-specific (least stable - may be UUID)
        let id = CanonicalId::from_format_id(&self.format_id);
        let warning = if id.is_stable() {
            Some(format!(
                "Component uses format-specific ID '{}' without standard identifiers.",
                self.format_id
            ))
        } else {
            Some(format!(
                "Component uses unstable format-specific ID '{}'. \
                 This may cause inaccurate diff results across SBOM regenerations.",
                self.format_id
            ))
        };

        CanonicalIdResult { id, warning }
    }

    /// Check if this component has any stable identifiers
    #[must_use]
    pub fn has_stable_id(&self) -> bool {
        self.purl.is_some() || !self.cpe.is_empty() || !self.swhid.is_empty() || self.swid.is_some()
    }

    /// Get the reliability level of available identifiers
    #[must_use]
    pub fn id_reliability(&self) -> IdReliability {
        if self.purl.is_some() {
            IdReliability::High
        } else if !self.cpe.is_empty() || !self.swhid.is_empty() || self.swid.is_some() {
            IdReliability::Medium
        } else {
            IdReliability::Low
        }
    }

    /// Returns true if this component has any of the CRA-named identifier
    /// types (PURL, CPE, SWHID, or SWID), satisfying CRA Annex I Part II
    /// identifier-traceability and prEN 40000-1-3 `[PRE-7-RQ-07]`.
    #[must_use]
    pub fn has_cra_identifier(&self) -> bool {
        self.purl.is_some() || !self.cpe.is_empty() || !self.swhid.is_empty() || self.swid.is_some()
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
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Ecosystem/package manager type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// HuggingFace Hub ML model (`pkg:huggingface/...`). Not a classical
    /// package ecosystem; surfaced so ML components are routed through the
    /// vulnerability/exploitability enrichment stack rather than silently
    /// treated as `Unknown`.
    HuggingFace,
    Generic,
    Unknown(String),
}

impl Ecosystem {
    /// Parse ecosystem from PURL type
    #[must_use]
    pub fn from_purl_type(purl_type: &str) -> Self {
        match purl_type.to_lowercase().as_str() {
            "npm" => Self::Npm,
            "pypi" => Self::PyPi,
            "cargo" => Self::Cargo,
            "maven" => Self::Maven,
            "golang" | "go" => Self::Golang,
            "nuget" => Self::Nuget,
            "gem" => Self::RubyGems,
            "composer" => Self::Composer,
            "cocoapods" => Self::CocoaPods,
            "swift" => Self::Swift,
            "hex" => Self::Hex,
            "pub" => Self::Pub,
            "hackage" => Self::Hackage,
            "cpan" => Self::Cpan,
            "cran" => Self::Cran,
            "conda" => Self::Conda,
            "conan" => Self::Conan,
            "deb" => Self::Deb,
            "rpm" => Self::Rpm,
            "apk" => Self::Apk,
            "huggingface" => Self::HuggingFace,
            "generic" => Self::Generic,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPi => write!(f, "pypi"),
            Self::Cargo => write!(f, "cargo"),
            Self::Maven => write!(f, "maven"),
            Self::Golang => write!(f, "golang"),
            Self::Nuget => write!(f, "nuget"),
            Self::RubyGems => write!(f, "gem"),
            Self::Composer => write!(f, "composer"),
            Self::CocoaPods => write!(f, "cocoapods"),
            Self::Swift => write!(f, "swift"),
            Self::Hex => write!(f, "hex"),
            Self::Pub => write!(f, "pub"),
            Self::Hackage => write!(f, "hackage"),
            Self::Cpan => write!(f, "cpan"),
            Self::Cran => write!(f, "cran"),
            Self::Conda => write!(f, "conda"),
            Self::Conan => write!(f, "conan"),
            Self::Deb => write!(f, "deb"),
            Self::Rpm => write!(f, "rpm"),
            Self::Apk => write!(f, "apk"),
            Self::HuggingFace => write!(f, "huggingface"),
            Self::Generic => write!(f, "generic"),
            Self::Unknown(s) => write!(f, "{s}"),
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
    #[must_use]
    pub fn from_component(component: &super::Component) -> Self {
        Self {
            id: component.canonical_id.clone(),
            name: component.name.clone(),
            version: component.version.clone(),
        }
    }

    /// Get the canonical ID
    #[must_use]
    pub const fn id(&self) -> &CanonicalId {
        &self.id
    }

    /// Get the ID as a string
    #[must_use]
    pub fn id_str(&self) -> &str {
        self.id.value()
    }

    /// Get the display name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the version if available
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Get display string with version if available
    #[must_use]
    pub fn display_with_version(&self) -> String {
        self.version
            .as_ref()
            .map_or_else(|| self.name.clone(), |v| format!("{}@{}", self.name, v))
    }

    /// Check if this ref matches a given ID
    #[must_use]
    pub fn matches_id(&self, id: &CanonicalId) -> bool {
        &self.id == id
    }

    /// Check if this ref matches a given ID string
    #[must_use]
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
    #[must_use]
    pub const fn component_id(&self) -> &CanonicalId {
        self.component.id()
    }

    /// Get the component name for display
    #[must_use]
    pub fn component_name(&self) -> &str {
        self.component.name()
    }
}

#[cfg(test)]
mod swhid_tests {
    use super::*;

    #[test]
    fn valid_swhid_content() {
        assert!(is_valid_swhid(
            "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
        ));
    }

    #[test]
    fn valid_swhid_all_kinds() {
        for kind in ["cnt", "dir", "rev", "rel", "snp"] {
            let s = format!("swh:1:{kind}:94a9ed024d3859793618152ea559a168bbcbb5e2");
            assert!(is_valid_swhid(&s), "kind {kind} should be valid");
        }
    }

    #[test]
    fn valid_swhid_with_qualifier() {
        let swhid =
            "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d;origin=https://github.com/x/y";
        assert!(is_valid_swhid(swhid));
    }

    #[test]
    fn invalid_swhid_wrong_prefix() {
        assert!(!is_valid_swhid(
            "swhid:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
        ));
    }

    #[test]
    fn invalid_swhid_unknown_kind() {
        assert!(!is_valid_swhid(
            "swh:1:foo:94a9ed024d3859793618152ea559a168bbcbb5e2"
        ));
    }

    #[test]
    fn invalid_swhid_short_hash() {
        assert!(!is_valid_swhid("swh:1:cnt:94a9ed024d"));
    }

    #[test]
    fn invalid_swhid_non_hex() {
        assert!(!is_valid_swhid(
            "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbZZZZ"
        ));
    }

    #[test]
    fn invalid_swhid_falls_back_to_format_specific() {
        let id = CanonicalId::from_swhid("swh:1:foo:bad");
        assert_eq!(id.source(), &IdSource::FormatSpecific);
        assert!(!id.is_stable());
    }

    #[test]
    fn valid_swhid_construction_and_round_trip() {
        let raw = "swh:1:cnt:94A9ED024D3859793618152EA559A168BBCBB5E2";
        let id = CanonicalId::from_swhid(raw);
        assert_eq!(id.source(), &IdSource::Swhid);
        assert!(id.is_stable());
        assert_eq!(
            id.value(),
            "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
        );
    }

    #[test]
    fn swhid_qualifier_preserved_after_normalization() {
        let raw = "swh:1:REV:309CF2674EE7A0749978CF8265AB91A60AEA0F7D;origin=Https://X.Y";
        let id = CanonicalId::from_swhid(raw);
        assert_eq!(
            id.value(),
            "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d;origin=Https://X.Y"
        );
    }

    #[test]
    fn component_identifiers_canonical_id_prefers_purl() {
        let mut ids = ComponentIdentifiers::new("synthetic-1".to_string());
        ids.purl = Some("pkg:cargo/serde@1.0.0".to_string());
        ids.swhid.push(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap(),
        );
        assert_eq!(ids.canonical_id().source(), &IdSource::Purl);
    }

    #[test]
    fn component_identifiers_canonical_id_uses_swhid_when_purl_absent() {
        let mut ids = ComponentIdentifiers::new("synthetic-1".to_string());
        ids.swhid.push(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap(),
        );
        let id = ids.canonical_id();
        assert_eq!(id.source(), &IdSource::Swhid);
    }

    #[test]
    fn has_cra_identifier_recognizes_swhid_only() {
        let mut ids = ComponentIdentifiers::new("synthetic-1".to_string());
        assert!(!ids.has_cra_identifier());
        ids.swhid.push(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap(),
        );
        assert!(ids.has_cra_identifier());
    }

    #[test]
    fn swhid_object_round_trip_via_display() {
        let raw = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2";
        let obj = SwhidObject::parse(raw).unwrap();
        assert_eq!(obj.kind, SwhidKind::Cnt);
        assert_eq!(obj.qualifiers.len(), 0);
        assert_eq!(obj.to_string(), raw);
    }

    #[test]
    fn swhid_object_preserves_qualifiers_in_order() {
        let raw = "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d;origin=https://github.com/x/y;path=/src";
        let obj = SwhidObject::parse(raw).unwrap();
        assert_eq!(obj.kind, SwhidKind::Rev);
        assert_eq!(obj.qualifiers.len(), 2);
        assert_eq!(
            obj.qualifiers[0],
            ("origin".to_string(), "https://github.com/x/y".to_string())
        );
        assert_eq!(obj.qualifiers[1], ("path".to_string(), "/src".to_string()));
        assert_eq!(obj.to_string(), raw);
    }

    #[test]
    fn swhid_object_lowercases_uppercase_input() {
        let raw = "SWH:1:CNT:94A9ED024D3859793618152EA559A168BBCBB5E2";
        let obj = SwhidObject::parse(raw).unwrap();
        assert_eq!(
            obj.to_string(),
            "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
        );
    }

    #[test]
    fn swhid_object_serde_round_trip_as_string() {
        let obj = SwhidObject::parse("swh:1:dir:309cf2674ee7a0749978cf8265ab91a60aea0f7d").unwrap();
        let json = serde_json::to_string(&obj).unwrap();
        assert_eq!(
            json,
            "\"swh:1:dir:309cf2674ee7a0749978cf8265ab91a60aea0f7d\""
        );
        let back: SwhidObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn swhid_object_parse_errors() {
        assert_eq!(
            SwhidObject::parse("not-a-swhid").unwrap_err(),
            SwhidParseError::BadShape
        );
        assert_eq!(
            SwhidObject::parse("swh:2:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap_err(),
            SwhidParseError::BadPrefix
        );
        assert_eq!(
            SwhidObject::parse("swh:1:foo:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap_err(),
            SwhidParseError::BadKind
        );
        assert_eq!(
            SwhidObject::parse("swh:1:cnt:not-hex").unwrap_err(),
            SwhidParseError::BadHash
        );
        assert_eq!(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2;malformed",)
                .unwrap_err(),
            SwhidParseError::BadQualifier
        );
    }

    #[test]
    fn swhid_object_serializes_within_component_identifiers_as_array_of_strings() {
        let mut ids = ComponentIdentifiers::new("synthetic-1".to_string());
        ids.swhid.push(
            SwhidObject::parse("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2").unwrap(),
        );
        ids.swhid.push(
            SwhidObject::parse("swh:1:dir:309cf2674ee7a0749978cf8265ab91a60aea0f7d").unwrap(),
        );
        let json = serde_json::to_value(&ids).unwrap();
        let arr = json
            .get("swhid")
            .and_then(|v| v.as_array())
            .expect("swhid serialises as array");
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(serde_json::Value::is_string));
        // Round-trip via deserialize keeps structure intact
        let parsed: ComponentIdentifiers = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.swhid.len(), 2);
        assert_eq!(parsed.swhid[0].kind, SwhidKind::Cnt);
        assert_eq!(parsed.swhid[1].kind, SwhidKind::Dir);
    }
}
