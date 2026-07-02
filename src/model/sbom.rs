//! Core SBOM and Component data structures.

use super::{
    CanonicalId, ComponentExtensions, ComponentIdentifiers, ComponentType, CryptoProperties,
    DependencyScope, DependencyType, DocumentMetadata, Ecosystem, ExternalReference,
    FormatExtensions, Hash, LicenseInfo, Organization, VexStatus, VulnerabilityRef,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

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

    /// Return the canonical IDs of *direct* dependencies (1 hop from the
    /// primary component along the dependency graph).
    ///
    /// When no `primary_component_id` is set, all components reachable from
    /// any node with no incoming edges are treated as direct (best-effort
    /// approximation for SBOMs that don't declare a root).
    ///
    /// Used by CRA prEN 40000-1-3 `[PRE-7-RQ-03]` enforcement, which makes
    /// direct dependencies *mandatory* and transitive *recommended*.
    #[must_use]
    pub fn direct_dependency_ids(&self) -> std::collections::HashSet<CanonicalId> {
        use std::collections::HashSet;
        if let Some(root) = &self.primary_component_id {
            return self
                .edges
                .iter()
                .filter(|e| &e.from == root)
                .map(|e| e.to.clone())
                .collect();
        }
        // Fallback: find roots = nodes with no incoming edges, then take their direct children.
        let incoming: HashSet<&CanonicalId> = self.edges.iter().map(|e| &e.to).collect();
        let roots: HashSet<&CanonicalId> = self
            .components
            .keys()
            .filter(|id| !incoming.contains(id))
            .collect();
        self.edges
            .iter()
            .filter(|e| roots.contains(&e.from))
            .map(|e| e.to.clone())
            .collect()
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

        // Hash edges (sorted for determinism, including relationship and scope)
        let mut edge_keys: Vec<_> = self
            .edges
            .iter()
            .map(|edge| {
                (
                    edge.from.value(),
                    edge.to.value(),
                    edge.relationship.to_string(),
                    edge.scope
                        .as_ref()
                        .map_or(String::new(), std::string::ToString::to_string),
                )
            })
            .collect();
        edge_keys.sort();
        for (from, to, relationship, scope) in &edge_keys {
            hasher_input.extend(from.as_bytes());
            hasher_input.extend(to.as_bytes());
            hasher_input.extend(relationship.as_bytes());
            hasher_input.extend(scope.as_bytes());
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
        let days = (chrono::Utc::now() - last_published).num_days().max(0) as u32;
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
    /// Whether this component is external (expected from environment, not bundled)
    pub is_external: bool,
    /// Package URL Version Range (vers) syntax, only valid when is_external is true
    pub version_range: Option<String>,
    /// Staleness information (populated by enrichment)
    pub staleness: Option<StalenessInfo>,
    /// End-of-life information (populated by enrichment)
    pub eol: Option<EolInfo>,
    /// ML model metadata (populated for MachineLearningModel components)
    pub ml_model: Option<crate::model::MlModelInfo>,
    /// Dataset metadata (populated for Data components)
    pub dataset: Option<crate::model::DatasetInfo>,
    /// Cryptographic properties (CycloneDX 1.6+ cryptoProperties)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
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
            is_external: false,
            version_range: None,
            staleness: None,
            eol: None,
            ml_model: None,
            dataset: None,
            crypto_properties: None,
        }
    }

    /// Set the PURL and update canonical ID
    #[must_use]
    pub fn with_purl(mut self, purl: String) -> Self {
        self.set_purl(purl);
        self
    }

    /// Set the PURL in place, refreshing the canonical ID and deriving the
    /// ecosystem from the PURL type. Mirrors [`Self::with_purl`] for callers
    /// holding a `&mut Component` (e.g. enrichment that synthesizes a PURL).
    pub fn set_purl(&mut self, purl: String) {
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
    }

    /// Set the version and try to parse as semver
    #[must_use]
    pub fn with_version(mut self, version: String) -> Self {
        self.semver = semver::Version::parse(&version).ok();
        self.version = Some(version);
        self
    }

    /// Add a Software Heritage persistent identifier (SWHID) from a string.
    ///
    /// Invalid SWHIDs are silently dropped (matches the parser-tolerant
    /// behaviour of `CanonicalId::from_swhid`). Use `with_swhid_object` when
    /// you already have a `SwhidObject` in hand.
    ///
    /// Recognised by CRA prEN 40000-1-3 `[PRE-7-RQ-07]` as one of the three
    /// named identifier types (alongside PURL and CPE). Multiple SWHIDs can
    /// be attached to a single component (e.g., a `dir` SWHID for the
    /// unpacked tree plus `cnt` SWHIDs for individual files).
    #[must_use]
    pub fn with_swhid(mut self, swhid: String) -> Self {
        if let Ok(obj) = crate::model::SwhidObject::parse(&swhid) {
            self.identifiers.swhid.push(obj);
            self.canonical_id = self.identifiers.canonical_id();
        }
        self
    }

    /// Add a structured `SwhidObject` SWHID.
    #[must_use]
    pub fn with_swhid_object(mut self, swhid: crate::model::SwhidObject) -> Self {
        self.identifiers.swhid.push(swhid);
        self.canonical_id = self.identifiers.canonical_id();
        self
    }

    /// Attach ML model metadata (CycloneDX modelCard)
    #[must_use]
    pub fn with_ml_model(mut self, ml_model: crate::model::MlModelInfo) -> Self {
        self.ml_model = Some(ml_model);
        self
    }

    /// Attach dataset metadata (CycloneDX ML BOM dataset component)
    #[must_use]
    pub fn with_dataset(mut self, dataset: crate::model::DatasetInfo) -> Self {
        self.dataset = Some(dataset);
        self
    }

    fn extend_with_optional_str(hasher_input: &mut Vec<u8>, value: &Option<String>) {
        if let Some(value) = value {
            hasher_input.extend(value.as_bytes());
        }
    }

    fn extend_with_string_list(hasher_input: &mut Vec<u8>, values: &[String]) {
        for value in values {
            hasher_input.extend(value.as_bytes());
        }
    }

    fn extend_with_optional_f64(hasher_input: &mut Vec<u8>, value: Option<f64>) {
        if let Some(value) = value {
            let normalized = if value == 0.0 {
                0.0
            } else if value.is_nan() {
                f64::from_bits(CANONICAL_NAN_BITS)
            } else {
                value
            };
            hasher_input.extend(normalized.to_bits().to_le_bytes());
        }
    }

    fn extend_with_ml_model(
        hasher_input: &mut Vec<u8>,
        ml_model: &Option<crate::model::MlModelInfo>,
    ) {
        if let Some(ml_model) = ml_model {
            Self::extend_with_optional_str(hasher_input, &ml_model.approach);
            Self::extend_with_optional_str(hasher_input, &ml_model.architecture_family);
            Self::extend_with_optional_str(hasher_input, &ml_model.architecture_name);
            Self::extend_with_optional_str(hasher_input, &ml_model.task);
            Self::extend_with_optional_str(hasher_input, &ml_model.quantization);
            Self::extend_with_optional_str(hasher_input, &ml_model.limitations);
            Self::extend_with_optional_str(hasher_input, &ml_model.model_card_url);
            Self::extend_with_optional_f64(hasher_input, ml_model.energy_kwh_training);

            for dataset in &ml_model.training_datasets {
                Self::extend_with_optional_str(hasher_input, &dataset.reference);
                Self::extend_with_optional_str(hasher_input, &dataset.name);
                Self::extend_with_optional_str(hasher_input, &dataset.purl);
            }
            for metric in &ml_model.performance_metrics {
                Self::extend_with_optional_str(hasher_input, &metric.metric_type);
                Self::extend_with_optional_str(hasher_input, &metric.value);
                Self::extend_with_optional_str(hasher_input, &metric.slice);
            }
        }
    }

    fn extend_with_dataset(
        hasher_input: &mut Vec<u8>,
        dataset: &Option<crate::model::DatasetInfo>,
    ) {
        if let Some(dataset) = dataset {
            Self::extend_with_optional_str(hasher_input, &dataset.dataset_type);
            Self::extend_with_string_list(hasher_input, &dataset.sensitivity_classifications);
            Self::extend_with_string_list(hasher_input, &dataset.governance_owners);
        }
    }
    /// Calculate and update content hash
    pub fn calculate_content_hash(&mut self) {
        let mut hasher_input = Vec::new();

        hasher_input.extend(self.name.as_bytes());
        Self::extend_with_optional_str(&mut hasher_input, &self.version);
        Self::extend_with_optional_str(&mut hasher_input, &self.identifiers.purl);
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
        if self.is_external {
            hasher_input.push(b'E');
        }
        if let Some(vr) = &self.version_range {
            hasher_input.extend(vr.as_bytes());
        }
        Self::extend_with_ml_model(&mut hasher_input, &self.ml_model);
        Self::extend_with_dataset(&mut hasher_input, &self.dataset);

        // Crypto properties: include fields that affect security semantics
        if let Some(cp) = &self.crypto_properties {
            hasher_input.extend(cp.asset_type.to_string().as_bytes());
            if let Some(oid) = &cp.oid {
                hasher_input.extend(oid.as_bytes());
            }
            if let Some(algo) = &cp.algorithm_properties {
                if let Some(family) = &algo.algorithm_family {
                    hasher_input.extend(family.as_bytes());
                }
                if let Some(level) = algo.nist_quantum_security_level {
                    hasher_input.push(level);
                }
            }
            if let Some(mat) = &cp.related_crypto_material_properties
                && let Some(state) = &mat.state
            {
                hasher_input.extend(state.to_string().as_bytes());
            }
            if let Some(cert) = &cp.certificate_properties
                && let Some(expiry) = &cert.not_valid_after
            {
                hasher_input.extend(expiry.to_rfc3339().as_bytes());
            }
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

    /// Set the dependency scope
    #[must_use]
    pub const fn with_scope(mut self, scope: DependencyScope) -> Self {
        self.scope = Some(scope);
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MlModelInfo;

    #[test]
    fn test_content_hash_normalizes_ml_energy_zero_and_nan() {
        let mut positive_zero = Component::new("model".to_string(), "model@1".to_string());
        positive_zero.ml_model = Some(MlModelInfo {
            energy_kwh_training: Some(0.0),
            ..MlModelInfo::default()
        });
        positive_zero.calculate_content_hash();

        let mut negative_zero = Component::new("model".to_string(), "model@1".to_string());
        negative_zero.ml_model = Some(MlModelInfo {
            energy_kwh_training: Some(-0.0),
            ..MlModelInfo::default()
        });
        negative_zero.calculate_content_hash();

        let mut nan_a = Component::new("model".to_string(), "model@1".to_string());
        nan_a.ml_model = Some(MlModelInfo {
            energy_kwh_training: Some(f64::NAN),
            ..MlModelInfo::default()
        });
        nan_a.calculate_content_hash();

        let mut nan_b = Component::new("model".to_string(), "model@1".to_string());
        nan_b.ml_model = Some(MlModelInfo {
            energy_kwh_training: Some(f64::from_bits(CANONICAL_NAN_BITS + 1)),
            ..MlModelInfo::default()
        });
        nan_b.calculate_content_hash();

        assert_eq!(positive_zero.content_hash, negative_zero.content_hash);
        assert_eq!(nan_a.content_hash, nan_b.content_hash);
    }
}
