//! Core SBOM and Component data structures.

use super::{
    CanonicalId, ComponentExtensions, ComponentIdentifiers, ComponentType, DependencyScope,
    DependencyType, DocumentMetadata, Ecosystem, ExternalReference, FormatExtensions, Hash,
    LicenseInfo, Organization, VexStatus, VulnerabilityRef,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

/// Normalized SBOM document - the canonical intermediate representation.
///
/// This structure represents an SBOM in a format-agnostic way, allowing
/// comparison between `CycloneDX` and SPDX documents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSbom {
    /// Document-level metadata
    pub document: DocumentMetadata,
    /// Components indexed by canonical ID
    pub components: IndexMap<CanonicalId, Component>,
    /// Dependency edges
    pub edges: Vec<DependencyEdge>,
    /// Format-specific extensions
    pub extensions: FormatExtensions,
    /// Content hash for quick equality checks
    pub content_hash: u64,
    /// Primary/root product component (`CycloneDX` metadata.component or SPDX documentDescribes)
    /// This identifies the main product that this SBOM describes, important for CRA compliance.
    pub primary_component_id: Option<CanonicalId>,
    /// Number of canonical ID collisions encountered during parsing
    #[serde(skip)]
    pub collision_count: usize,
}

impl NormalizedSbom {
    /// Create a new empty normalized SBOM
    #[must_use]
    pub fn new(document: DocumentMetadata) -> Self {
        Self {
            document,
            components: IndexMap::new(),
            edges: Vec::new(),
            extensions: FormatExtensions::default(),
            content_hash: 0,
            primary_component_id: None,
            collision_count: 0,
        }
    }

    /// Add a component to the SBOM.
    ///
    /// Returns `true` if a collision occurred (a component with the same canonical ID
    /// was already present and has been overwritten). Collisions are logged as warnings.
    pub fn add_component(&mut self, component: Component) -> bool {
        let id = component.canonical_id.clone();
        if let Some(existing) = self.components.get(&id) {
            // Count genuinely different components that collide on canonical ID
            if existing.identifiers.format_id != component.identifiers.format_id
                || existing.name != component.name
            {
                self.collision_count += 1;
            }
            self.components.insert(id, component);
            true
        } else {
            self.components.insert(id, component);
            false
        }
    }

    /// Log a single summary line if any canonical ID collisions occurred during parsing.
    pub fn log_collision_summary(&self) {
        if self.collision_count > 0 {
            tracing::info!(
                collision_count = self.collision_count,
                "Canonical ID collisions: {} distinct components resolved to the same ID \
                 and were overwritten. Consider adding PURL identifiers to disambiguate.",
                self.collision_count
            );
        }
    }

    /// Add a dependency edge
    pub fn add_edge(&mut self, edge: DependencyEdge) {
        self.edges.push(edge);
    }

    /// Get a component by canonical ID
    #[must_use]
    pub fn get_component(&self, id: &CanonicalId) -> Option<&Component> {
        self.components.get(id)
    }

    /// Get dependencies of a component
    #[must_use]
    pub fn get_dependencies(&self, id: &CanonicalId) -> Vec<&DependencyEdge> {
        self.edges.iter().filter(|e| &e.from == id).collect()
    }

    /// Get dependents of a component
    #[must_use]
    pub fn get_dependents(&self, id: &CanonicalId) -> Vec<&DependencyEdge> {
        self.edges.iter().filter(|e| &e.to == id).collect()
    }

    /// Calculate and update the content hash
    pub fn calculate_content_hash(&mut self) {
        let mut hasher_input = Vec::new();

        // Hash document metadata
        if let Ok(meta_json) = serde_json::to_vec(&self.document) {
            hasher_input.extend(meta_json);
        }

        // Hash all components (sorted for determinism)
        let mut component_ids: Vec<_> = self.components.keys().collect();
        component_ids.sort_by(|a, b| a.value().cmp(b.value()));

        for id in component_ids {
            if let Some(comp) = self.components.get(id) {
                hasher_input.extend(comp.content_hash.to_le_bytes());
            }
        }

        // Hash edges
        for edge in &self.edges {
            hasher_input.extend(edge.from.value().as_bytes());
            hasher_input.extend(edge.to.value().as_bytes());
        }

        self.content_hash = xxh3_64(&hasher_input);
    }

    /// Get total component count
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get the primary/root product component if set
    #[must_use]
    pub fn primary_component(&self) -> Option<&Component> {
        self.primary_component_id
            .as_ref()
            .and_then(|id| self.components.get(id))
    }

    /// Set the primary component by its canonical ID
    pub fn set_primary_component(&mut self, id: CanonicalId) {
        self.primary_component_id = Some(id);
    }

    /// Get all unique ecosystems in the SBOM
    pub fn ecosystems(&self) -> Vec<&Ecosystem> {
        let mut ecosystems: Vec<_> = self
            .components
            .values()
            .filter_map(|c| c.ecosystem.as_ref())
            .collect();
        ecosystems.sort_by_key(std::string::ToString::to_string);
        ecosystems.dedup();
        ecosystems
    }

    /// Get all vulnerabilities across all components
    #[must_use]
    pub fn all_vulnerabilities(&self) -> Vec<(&Component, &VulnerabilityRef)> {
        self.components
            .values()
            .flat_map(|c| c.vulnerabilities.iter().map(move |v| (c, v)))
            .collect()
    }

    /// Count vulnerabilities by severity
    #[must_use]
    pub fn vulnerability_counts(&self) -> VulnerabilityCounts {
        let mut counts = VulnerabilityCounts::default();
        for (_, vuln) in self.all_vulnerabilities() {
            match vuln.severity {
                Some(super::Severity::Critical) => counts.critical += 1,
                Some(super::Severity::High) => counts.high += 1,
                Some(super::Severity::Medium) => counts.medium += 1,
                Some(super::Severity::Low) => counts.low += 1,
                _ => counts.unknown += 1,
            }
        }
        counts
    }

    /// Build an index for this SBOM.
    ///
    /// The index provides O(1) lookups for dependencies, dependents,
    /// and name-based searches. Build once and reuse for multiple operations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sbom = parse_sbom(&path)?;
    /// let index = sbom.build_index();
    ///
    /// // Fast dependency lookup
    /// let deps = index.dependencies_of(&component_id, &sbom.edges);
    /// ```
    pub fn build_index(&self) -> super::NormalizedSbomIndex {
        super::NormalizedSbomIndex::build(self)
    }

    /// Get dependencies using an index (O(k) instead of O(edges)).
    ///
    /// Use this when you have a prebuilt index for repeated lookups.
    #[must_use]
    pub fn get_dependencies_indexed<'a>(
        &'a self,
        id: &CanonicalId,
        index: &super::NormalizedSbomIndex,
    ) -> Vec<&'a DependencyEdge> {
        index.dependencies_of(id, &self.edges)
    }

    /// Get dependents using an index (O(k) instead of O(edges)).
    ///
    /// Use this when you have a prebuilt index for repeated lookups.
    #[must_use]
    pub fn get_dependents_indexed<'a>(
        &'a self,
        id: &CanonicalId,
        index: &super::NormalizedSbomIndex,
    ) -> Vec<&'a DependencyEdge> {
        index.dependents_of(id, &self.edges)
    }

    /// Find components by name (case-insensitive) using an index.
    ///
    /// Returns components whose lowercased name exactly matches the query.
    #[must_use]
    pub fn find_by_name_indexed(
        &self,
        name: &str,
        index: &super::NormalizedSbomIndex,
    ) -> Vec<&Component> {
        let name_lower = name.to_lowercase();
        index
            .find_by_name_lower(&name_lower)
            .iter()
            .filter_map(|id| self.components.get(id))
            .collect()
    }

    /// Search components by name (case-insensitive substring) using an index.
    ///
    /// Returns components whose name contains the query substring.
    #[must_use]
    pub fn search_by_name_indexed(
        &self,
        query: &str,
        index: &super::NormalizedSbomIndex,
    ) -> Vec<&Component> {
        let query_lower = query.to_lowercase();
        index
            .search_by_name(&query_lower)
            .iter()
            .filter_map(|id| self.components.get(id))
            .collect()
    }

    /// Apply CRA sidecar metadata to supplement SBOM fields.
    ///
    /// Sidecar values only override SBOM fields if the SBOM field is None/empty.
    /// This ensures SBOM data takes precedence when available.
    pub fn apply_cra_sidecar(&mut self, sidecar: &super::CraSidecarMetadata) {
        // Only apply if SBOM doesn't already have the value
        if self.document.security_contact.is_none() {
            self.document
                .security_contact
                .clone_from(&sidecar.security_contact);
        }

        if self.document.vulnerability_disclosure_url.is_none() {
            self.document
                .vulnerability_disclosure_url
                .clone_from(&sidecar.vulnerability_disclosure_url);
        }

        if self.document.support_end_date.is_none() {
            self.document.support_end_date = sidecar.support_end_date;
        }

        if self.document.name.is_none() {
            self.document.name.clone_from(&sidecar.product_name);
        }

        // Add manufacturer as creator if not present
        if let Some(manufacturer) = &sidecar.manufacturer_name {
            let has_org = self
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == super::CreatorType::Organization);

            if !has_org {
                self.document.creators.push(super::Creator {
                    creator_type: super::CreatorType::Organization,
                    name: manufacturer.clone(),
                    email: sidecar.manufacturer_email.clone(),
                });
            }
        }
    }
}

impl Default for NormalizedSbom {
    fn default() -> Self {
        Self::new(DocumentMetadata::default())
    }
}

/// Vulnerability counts by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl VulnerabilityCounts {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unknown
    }
}

/// Staleness level classification for dependencies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StalenessLevel {
    /// Updated within 6 months
    Fresh,
    /// 6-12 months since last update
    Aging,
    /// 1-2 years since last update
    Stale,
    /// More than 2 years since last update
    Abandoned,
    /// Explicitly marked as deprecated
    Deprecated,
    /// Repository/package archived
    Archived,
}

impl StalenessLevel {
    /// Create from age in days
    #[must_use]
    pub const fn from_days(days: u32) -> Self {
        match days {
            0..=182 => Self::Fresh,   // ~6 months
            183..=365 => Self::Aging, // 6-12 months
            366..=730 => Self::Stale, // 1-2 years
            _ => Self::Abandoned,     // >2 years
        }
    }

    /// Get display label
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Fresh => "Fresh",
            Self::Aging => "Aging",
            Self::Stale => "Stale",
            Self::Abandoned => "Abandoned",
            Self::Deprecated => "Deprecated",
            Self::Archived => "Archived",
        }
    }

    /// Get icon for TUI display
    #[must_use]
    pub const fn icon(&self) -> &'static str {
        match self {
            Self::Fresh => "✓",
            Self::Aging => "⏳",
            Self::Stale => "⚠",
            Self::Abandoned => "⛔",
            Self::Deprecated => "⊘",
            Self::Archived => "📦",
        }
    }

    /// Get severity weight (higher = worse)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Fresh => 0,
            Self::Aging => 1,
            Self::Stale => 2,
            Self::Abandoned => 3,
            Self::Deprecated | Self::Archived => 4,
        }
    }
}

impl std::fmt::Display for StalenessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Staleness information for a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalenessInfo {
    /// Staleness classification
    pub level: StalenessLevel,
    /// Last publish/release date
    pub last_published: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether explicitly deprecated by maintainer
    pub is_deprecated: bool,
    /// Whether repository/package is archived
    pub is_archived: bool,
    /// Deprecation message if available
    pub deprecation_message: Option<String>,
    /// Days since last update
    pub days_since_update: Option<u32>,
    /// Latest available version (if different from current)
    pub latest_version: Option<String>,
}

impl StalenessInfo {
    /// Create new staleness info
    #[must_use]
    pub const fn new(level: StalenessLevel) -> Self {
        Self {
            level,
            last_published: None,
            is_deprecated: false,
            is_archived: false,
            deprecation_message: None,
            days_since_update: None,
            latest_version: None,
        }
    }

    /// Create from last published date
    #[must_use]
    pub fn from_date(last_published: chrono::DateTime<chrono::Utc>) -> Self {
        let days = (chrono::Utc::now() - last_published).num_days() as u32;
        let level = StalenessLevel::from_days(days);
        Self {
            level,
            last_published: Some(last_published),
            is_deprecated: false,
            is_archived: false,
            deprecation_message: None,
            days_since_update: Some(days),
            latest_version: None,
        }
    }

    /// Check if component needs attention (stale or worse)
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.level.severity() >= 2
    }
}

/// End-of-life status classification for components
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EolStatus {
    /// Actively receiving updates
    Supported,
    /// Active support ended, security patches continue (LTS phase)
    SecurityOnly,
    /// Within 6 months of EOL date
    ApproachingEol,
    /// Past EOL, no more updates
    EndOfLife,
    /// Product found but cycle not matched
    Unknown,
}

impl EolStatus {
    /// Get display label
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Supported => "Supported",
            Self::SecurityOnly => "Security Only",
            Self::ApproachingEol => "Approaching EOL",
            Self::EndOfLife => "End of Life",
            Self::Unknown => "Unknown",
        }
    }

    /// Get icon for TUI display
    #[must_use]
    pub const fn icon(&self) -> &'static str {
        match self {
            Self::Supported => "✓",
            Self::SecurityOnly => "🔒",
            Self::ApproachingEol => "⚠",
            Self::EndOfLife => "⛔",
            Self::Unknown => "?",
        }
    }

    /// Get severity weight (higher = worse)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Supported => 0,
            Self::SecurityOnly => 1,
            Self::ApproachingEol => 2,
            Self::EndOfLife => 3,
            Self::Unknown => 0,
        }
    }
}

impl std::fmt::Display for EolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// End-of-life information for a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EolInfo {
    /// EOL status classification
    pub status: EolStatus,
    /// Matched endoflife.date product slug
    pub product: String,
    /// Matched release cycle (e.g., "3.11")
    pub cycle: String,
    /// EOL date if known
    pub eol_date: Option<chrono::NaiveDate>,
    /// Active support end date
    pub support_end_date: Option<chrono::NaiveDate>,
    /// Whether this is an LTS release
    pub is_lts: bool,
    /// Latest patch version in this cycle
    pub latest_in_cycle: Option<String>,
    /// Latest release date in this cycle
    pub latest_release_date: Option<chrono::NaiveDate>,
    /// Days until EOL (negative = past EOL)
    pub days_until_eol: Option<i64>,
}

impl EolInfo {
    /// Check if the component needs attention (approaching or past EOL)
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.status.severity() >= 2
    }
}

/// Component in the normalized SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Canonical identifier
    pub canonical_id: CanonicalId,
    /// Various identifiers (PURL, CPE, etc.)
    pub identifiers: ComponentIdentifiers,
    /// Component name
    pub name: String,
    /// Version string
    pub version: Option<String>,
    /// Parsed semantic version (if valid)
    pub semver: Option<semver::Version>,
    /// Component type
    pub component_type: ComponentType,
    /// Package ecosystem
    pub ecosystem: Option<Ecosystem>,
    /// License information
    pub licenses: LicenseInfo,
    /// Supplier/vendor information
    pub supplier: Option<Organization>,
    /// Cryptographic hashes
    pub hashes: Vec<Hash>,
    /// External references
    pub external_refs: Vec<ExternalReference>,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityRef>,
    /// VEX status
    pub vex_status: Option<VexStatus>,
    /// Content hash for quick comparison
    pub content_hash: u64,
    /// Format-specific extensions
    pub extensions: ComponentExtensions,
    /// Description
    pub description: Option<String>,
    /// Copyright text
    pub copyright: Option<String>,
    /// Author information
    pub author: Option<String>,
    /// Group/namespace (e.g., Maven groupId)
    pub group: Option<String>,
    /// Staleness information (populated by enrichment)
    pub staleness: Option<StalenessInfo>,
    /// End-of-life information (populated by enrichment)
    pub eol: Option<EolInfo>,
}

impl Component {
    /// Create a new component with minimal required fields
    #[must_use]
    pub fn new(name: String, format_id: String) -> Self {
        let identifiers = ComponentIdentifiers::new(format_id);
        let canonical_id = identifiers.canonical_id();

        Self {
            canonical_id,
            identifiers,
            name,
            version: None,
            semver: None,
            component_type: ComponentType::Library,
            ecosystem: None,
            licenses: LicenseInfo::default(),
            supplier: None,
            hashes: Vec::new(),
            external_refs: Vec::new(),
            vulnerabilities: Vec::new(),
            vex_status: None,
            content_hash: 0,
            extensions: ComponentExtensions::default(),
            description: None,
            copyright: None,
            author: None,
            group: None,
            staleness: None,
            eol: None,
        }
    }

    /// Set the PURL and update canonical ID
    #[must_use]
    pub fn with_purl(mut self, purl: String) -> Self {
        self.identifiers.purl = Some(purl);
        self.canonical_id = self.identifiers.canonical_id();

        // Try to extract ecosystem from PURL
        if let Some(purl_str) = &self.identifiers.purl
            && let Some(purl_type) = purl_str
                .strip_prefix("pkg:")
                .and_then(|s| s.split('/').next())
        {
            self.ecosystem = Some(Ecosystem::from_purl_type(purl_type));
        }

        self
    }

    /// Set the version and try to parse as semver
    #[must_use]
    pub fn with_version(mut self, version: String) -> Self {
        self.semver = semver::Version::parse(&version).ok();
        self.version = Some(version);
        self
    }

    /// Calculate and update content hash
    pub fn calculate_content_hash(&mut self) {
        let mut hasher_input = Vec::new();

        hasher_input.extend(self.name.as_bytes());
        if let Some(v) = &self.version {
            hasher_input.extend(v.as_bytes());
        }
        if let Some(purl) = &self.identifiers.purl {
            hasher_input.extend(purl.as_bytes());
        }
        for license in &self.licenses.declared {
            hasher_input.extend(license.expression.as_bytes());
        }
        if let Some(supplier) = &self.supplier {
            hasher_input.extend(supplier.name.as_bytes());
        }
        for hash in &self.hashes {
            hasher_input.extend(hash.value.as_bytes());
        }
        for vuln in &self.vulnerabilities {
            hasher_input.extend(vuln.id.as_bytes());
        }

        self.content_hash = xxh3_64(&hasher_input);
    }

    /// Check if this is an OSS (open source) component
    #[must_use]
    pub fn is_oss(&self) -> bool {
        // Check if any declared license is OSS
        self.licenses.declared.iter().any(|l| l.is_valid_spdx) || self.identifiers.purl.is_some()
    }

    /// Get display name with version
    #[must_use]
    pub fn display_name(&self) -> String {
        self.version
            .as_ref()
            .map_or_else(|| self.name.clone(), |v| format!("{}@{}", self.name, v))
    }
}

/// Dependency edge between components
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Source component
    pub from: CanonicalId,
    /// Target component
    pub to: CanonicalId,
    /// Relationship type
    pub relationship: DependencyType,
    /// Dependency scope
    pub scope: Option<DependencyScope>,
}

impl DependencyEdge {
    /// Create a new dependency edge
    #[must_use]
    pub const fn new(from: CanonicalId, to: CanonicalId, relationship: DependencyType) -> Self {
        Self {
            from,
            to,
            relationship,
            scope: None,
        }
    }

    /// Check if this is a direct dependency
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(
            self.relationship,
            DependencyType::DependsOn
                | DependencyType::DevDependsOn
                | DependencyType::BuildDependsOn
                | DependencyType::TestDependsOn
                | DependencyType::RuntimeDependsOn
        )
    }
}
