//! Core SBOM and Component data structures.

use super::{
    CanonicalId, ComponentExtensions, ComponentIdentifiers, ComponentType, CryptoProperties,
    DependencyScope, DependencyType, DocumentMetadata, DuplicateComponent, Ecosystem,
    ExternalReference, FormatExtensions, Hash, LicenseInfo, Organization, VexStatus,
    VulnerabilityRef,
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
    /// The other components the document describes, besides the primary:
    /// an SPDX document can describe several sibling products (SPDX 2
    /// `documentDescribes` and `DESCRIBES` targets, SPDX 3 `rootElement`s).
    /// A CycloneDX document describes one, `metadata.component`, the
    /// primary. In document order, each once; see
    /// [`Self::described_components`]. Additive: skipped in JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub described_root_ids: Vec<CanonicalId>,
    /// The components the document lists more than once, keyed by canonical
    /// id, in the order of their first repeat: how many entries each had,
    /// their format ids and the fields they disagree on. Each component's
    /// entries were merged into one (see [`Self::add_component`]).
    /// Additive: serialized as a list of records, and skipped when empty.
    #[serde(
        default,
        skip_serializing_if = "IndexMap::is_empty",
        with = "super::merge::duplicate_list"
    )]
    pub duplicate_components: IndexMap<CanonicalId, DuplicateComponent>,
    /// Number of canonical ID collisions encountered during parsing: the
    /// entries merged into a component listed before them (see
    /// [`Self::duplicate_components`]), plus the components another of a
    /// different name or version replaced.
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
            described_root_ids: Vec::new(),
            duplicate_components: IndexMap::new(),
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
    /// A component whose canonical id is new is inserted, and `false` is
    /// returned. One whose id a component of the same name and version
    /// already holds is another entry of that component (the document lists
    /// it twice; a name or version that is absent or not known, such as
    /// `NOASSERTION`, agrees with any, see [`Component::is_same_component`]):
    /// the two are merged ([`Component::merge_duplicate`]), so the result
    /// does not depend on which entry came first, no entry's data is lost,
    /// and a known value always wins over a placeholder. The duplicate is
    /// recorded in [`Self::duplicate_components`] and counted in
    /// [`Self::collision_count`], and `true` is returned.
    ///
    /// A component of a different known name or version under a taken id
    /// replaces the one there (counted, and `true`). Parsers never pass one:
    /// [`Self::claim_canonical_id`] gives it an id of its own first.
    pub fn add_component(&mut self, component: Component) -> bool {
        let id = component.canonical_id.clone();
        let Some(existing) = self.components.get_mut(&id) else {
            self.components.insert(id, component);
            return false;
        };
        self.collision_count += 1;
        if !existing.is_same_component(&component) {
            *existing = component;
            return true;
        }
        let first_format_id = existing.identifiers.format_id.clone();
        let format_id = component.identifiers.format_id.clone();
        let conflicts = existing.merge_duplicate(component);
        self.duplicate_components
            .entry(id.clone())
            .or_insert_with(|| DuplicateComponent::first_entry(id, first_format_id))
            .count_entry(format_id, conflicts);
        true
    }

    /// Settle the canonical ID `component` will be inserted under.
    ///
    /// Parsers call this before recording the ID in their reference maps.
    /// When another component already holds the same canonical ID but has a
    /// different known name or version, the two are distinct components that
    /// share an identifier (two versions under one version-less purl, say).
    /// Inserting would overwrite — silently dropping a component from every
    /// count and check — so `component` is re-keyed to an ID that appends its
    /// format ID (bom-ref or SPDXID), and the clash is logged. A true
    /// duplicate (the same name and version, where a name or version that is
    /// absent or not known agrees with any; see
    /// [`Component::is_same_component`]) keeps the shared ID, and
    /// [`Self::add_component`] merges the two entries. Returns the ID to
    /// register.
    pub fn claim_canonical_id(&self, component: &mut Component) -> CanonicalId {
        let distinct = self
            .components
            .get(&component.canonical_id)
            .is_some_and(|existing| !existing.is_same_component(component));
        if distinct {
            let base = format!(
                "{}#{}",
                component.canonical_id.value(),
                component.identifiers.format_id
            );
            let mut candidate = CanonicalId::from_format_id(&base);
            let mut n = 2;
            while self.components.contains_key(&candidate) {
                candidate = CanonicalId::from_format_id(&format!("{base}#{n}"));
                n += 1;
            }
            tracing::warn!(
                shared_id = %component.canonical_id,
                component = %component.name,
                kept_as = %candidate,
                "distinct components share a canonical ID; keeping both"
            );
            component.canonical_id = candidate;
        }
        component.canonical_id.clone()
    }

    /// Log a single summary line if any canonical ID collisions occurred during parsing.
    pub fn log_collision_summary(&self) {
        if self.collision_count > 0 {
            tracing::info!(
                collision_count = self.collision_count,
                duplicated_components = self.duplicate_components.len(),
                "Canonical ID collisions: {} entries repeat a component listed before them \
                 ({} components listed more than once); each component's entries were merged.",
                self.collision_count,
                self.duplicate_components.len()
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

        // CDXA declarations (CycloneDX 1.6+): folded in only when present so
        // documents without declarations hash identically to previous
        // releases, while attestation-evidence changes stay visible to the
        // diff's identical-SBOM short-circuit and the incremental cache key.
        // Tagged + length-prefixed so the block cannot collide with the edge
        // bytes above.
        if let Some(declarations) = &self.extensions.declarations
            && let Ok(json) = serde_json::to_vec(declarations)
        {
            hasher_input.extend(b"cdxa-declarations");
            hasher_input.extend((json.len() as u64).to_le_bytes());
            hasher_input.extend(json);
        }

        self.content_hash = xxh3_64(&hasher_input);
    }

    /// Get total component count
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// CycloneDX 1.6 CDXA declarations parsed from the document, if any.
    ///
    /// Stored under [`FormatExtensions::declarations`]; `None` for SPDX,
    /// pre-1.6 CycloneDX, XML input, and 1.6+ documents without the
    /// `declarations`/`definitions.standards` sections. Signature objects in
    /// the returned model record PRESENCE only — no cryptographic
    /// verification is performed (see [`super::AttestationDeclarations`]).
    #[must_use]
    pub fn declarations(&self) -> Option<&super::AttestationDeclarations> {
        self.extensions.declarations.as_ref()
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

    /// Record another component the document describes (see
    /// [`Self::described_root_ids`]). The primary component and an id
    /// already recorded are skipped, so parsers can pass every described
    /// id once the primary is set.
    pub fn add_described_root(&mut self, id: CanonicalId) {
        if self.primary_component_id.as_ref() != Some(&id) && !self.described_root_ids.contains(&id)
        {
            self.described_root_ids.push(id);
        }
    }

    /// The components the document describes: the primary component, then
    /// the other described roots, each once. Empty when the document names
    /// no product (or the ids resolve to no component). Compliance checks
    /// read manufacturer evidence, such as a security contact or a
    /// certificate reference, from these components only.
    #[must_use]
    pub fn described_components(&self) -> Vec<&Component> {
        let mut seen = std::collections::HashSet::new();
        self.primary_component_id
            .iter()
            .chain(&self.described_root_ids)
            .filter(|id| seen.insert(*id))
            .filter_map(|id| self.components.get(id))
            .collect()
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
#[non_exhaustive]
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
    /// Author information (CycloneDX `author`, or the names of the 1.6+
    /// `authors` that deprecate it)
    pub author: Option<String>,
    /// Organization that created the component (CycloneDX 1.6+
    /// `manufacturer`), as distinct from the supplier that distributes it
    #[serde(default)]
    pub manufacturer: Option<Organization>,
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
    /// Whether the product needs the component at runtime: the CycloneDX
    /// component `scope` (`required`, `optional`, `excluded`). SPDX states
    /// it on the relationships instead, so an SPDX component is `Excluded`
    /// when only development, build or test relationships bring it in
    /// (SPDX 2.3 `DEV_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`,
    /// `TEST_DEPENDENCY_OF` and the `*_TOOL_OF` types; SPDX 3.0
    /// `LifecycleScopedRelationship`s of scope `design`, `development`,
    /// `build` or `test`), directly or through other such components. `None`
    /// when the SBOM does not say. Compliance package rules leave `Excluded`
    /// components out unless the run includes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<DependencyScope>,
}

impl Component {
    /// Whether any producer attribution is present: a supplier, an author,
    /// or a manufacturer.
    ///
    /// This is a raw presence test: a `NOASSERTION` or placeholder name
    /// counts. Compliance checks use the sentinel-aware `has_known_producer`
    /// instead.
    #[must_use]
    pub const fn has_producer(&self) -> bool {
        self.supplier.is_some() || self.author.is_some() || self.manufacturer.is_some()
    }

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
            manufacturer: None,
            group: None,
            is_external: false,
            version_range: None,
            staleness: None,
            eol: None,
            ml_model: None,
            dataset: None,
            crypto_properties: None,
            scope: None,
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
    ///
    /// A value that is not a usable purl ([`is_usable_purl`]: empty, a
    /// placeholder such as `NOASSERTION`, or missing the `pkg:` scheme) is
    /// ignored, so it can neither pass an identifier rule nor merge distinct
    /// components onto one canonical ID. Surrounding whitespace is trimmed.
    ///
    /// [`is_usable_purl`]: crate::model::is_usable_purl
    pub fn set_purl(&mut self, purl: String) {
        if !crate::model::is_usable_purl(&purl) {
            tracing::debug!(
                component = %self.name,
                purl = %purl,
                "ignoring unusable purl"
            );
            return;
        }
        let trimmed = purl.trim();
        let purl = if trimmed.len() == purl.len() {
            purl
        } else {
            trimmed.to_string()
        };
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

    /// Add a CPE identifier and refresh the canonical ID.
    ///
    /// Values that are not usable CPEs ([`is_usable_cpe`]: empty, a
    /// placeholder, or not a `cpe:2.3:` / `cpe:/` string) are ignored, for
    /// the same reasons as in [`Self::set_purl`].
    ///
    /// [`is_usable_cpe`]: crate::model::is_usable_cpe
    pub fn add_cpe(&mut self, cpe: String) {
        if !crate::model::is_usable_cpe(&cpe) {
            tracing::debug!(component = %self.name, cpe = %cpe, "ignoring unusable CPE");
            return;
        }
        self.identifiers.cpe.push(cpe.trim().to_string());
        self.canonical_id = self.identifiers.canonical_id();
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

    /// Append a tagged, length-prefixed value. Tags and length prefixes make
    /// field boundaries unambiguous: raw concatenation let a dropped declared
    /// license "MIT" plus a gained supplier named "MIT" produce the identical
    /// byte stream — and therefore an identical content hash — silently
    /// suppressing both changes from the diff.
    fn extend_tagged(hasher_input: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        hasher_input.push(tag);
        hasher_input.extend((bytes.len() as u64).to_le_bytes());
        hasher_input.extend(bytes);
    }

    fn extend_with_optional_str(hasher_input: &mut Vec<u8>, value: &Option<String>) {
        match value {
            Some(value) => {
                hasher_input.push(1);
                hasher_input.extend((value.len() as u64).to_le_bytes());
                hasher_input.extend(value.as_bytes());
            }
            None => hasher_input.push(0),
        }
    }

    fn extend_with_string_list(hasher_input: &mut Vec<u8>, values: &[String]) {
        hasher_input.extend((values.len() as u64).to_le_bytes());
        for value in values {
            hasher_input.extend((value.len() as u64).to_le_bytes());
            hasher_input.extend(value.as_bytes());
        }
    }

    fn extend_with_optional_f64(hasher_input: &mut Vec<u8>, value: Option<f64>) {
        match value {
            Some(value) => {
                let normalized = if value == 0.0 {
                    0.0
                } else if value.is_nan() {
                    f64::from_bits(CANONICAL_NAN_BITS)
                } else {
                    value
                };
                hasher_input.push(1);
                hasher_input.extend(normalized.to_bits().to_le_bytes());
            }
            None => hasher_input.push(0),
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

            // Count-prefix each list: entries of both lists are three
            // optional strings, so without framing a training dataset and a
            // performance metric with the same payload are byte-identical
            // and the two lists collide.
            hasher_input.extend((ml_model.training_datasets.len() as u64).to_le_bytes());
            for dataset in &ml_model.training_datasets {
                Self::extend_with_optional_str(hasher_input, &dataset.reference);
                Self::extend_with_optional_str(hasher_input, &dataset.name);
                Self::extend_with_optional_str(hasher_input, &dataset.purl);
            }
            hasher_input.extend((ml_model.performance_metrics.len() as u64).to_le_bytes());
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
    /// Calculate and update content hash.
    ///
    /// Every field is tagged and length-prefixed (see `extend_tagged`) so a
    /// value moving between fields always changes the hash. Coverage matters:
    /// the diff's modified-component gate and the incremental cache key both
    /// trust this hash, so any semantic field left out produces silently
    /// empty or stale diffs (vulnerability severity and VEX status were
    /// previously invisible here).
    pub fn calculate_content_hash(&mut self) {
        let mut hasher_input = Vec::new();

        Self::extend_tagged(&mut hasher_input, 1, self.name.as_bytes());
        hasher_input.push(2);
        Self::extend_with_optional_str(&mut hasher_input, &self.version);
        hasher_input.push(3);
        Self::extend_with_optional_str(&mut hasher_input, &self.identifiers.purl);
        if let Some(ecosystem) = &self.ecosystem {
            Self::extend_tagged(&mut hasher_input, 4, ecosystem.to_string().as_bytes());
        }
        if let Some(group) = &self.group {
            // Group/namespace is a fuzzy-matcher scoring input; leaving it
            // out lets a group-only change slip past the identical-SBOM
            // short-circuit and the incremental cache key.
            Self::extend_tagged(&mut hasher_input, 15, group.as_bytes());
        }
        for license in &self.licenses.declared {
            Self::extend_tagged(&mut hasher_input, 5, license.expression.as_bytes());
        }
        if let Some(supplier) = &self.supplier {
            Self::extend_tagged(&mut hasher_input, 6, supplier.name.as_bytes());
        }
        for hash in &self.hashes {
            Self::extend_tagged(&mut hasher_input, 7, hash.value.as_bytes());
        }
        for vuln in &self.vulnerabilities {
            // Cover every VulnerabilityRef field that VulnerabilityDetail
            // serializes: a field change invisible here short-circuits
            // DiffEngine::diff as "identical" and collides incremental cache
            // keys, serving stale details.
            let mut vuln_buf = Vec::new();
            vuln_buf.extend((vuln.id.len() as u64).to_le_bytes());
            vuln_buf.extend(vuln.id.as_bytes());
            Self::extend_with_optional_str(
                &mut vuln_buf,
                &vuln.severity.as_ref().map(std::string::ToString::to_string),
            );
            Self::extend_with_optional_str(
                &mut vuln_buf,
                &vuln.vex_status.as_ref().map(|v| format!("{v:?}")),
            );
            vuln_buf.push(u8::from(vuln.is_kev));
            Self::extend_with_optional_f64(&mut vuln_buf, vuln.epss_score);
            Self::extend_with_optional_f64(&mut vuln_buf, vuln.max_cvss_score().map(f64::from));
            Self::extend_with_optional_str(&mut vuln_buf, &Some(vuln.source.to_string()));
            Self::extend_with_string_list(&mut vuln_buf, &vuln.cwes);
            Self::extend_with_optional_str(&mut vuln_buf, &vuln.description);
            Self::extend_with_optional_str(
                &mut vuln_buf,
                &vuln.published.as_ref().map(|d| d.to_rfc3339()),
            );
            Self::extend_with_optional_str(
                &mut vuln_buf,
                &vuln.kev_info.as_ref().map(|k| k.due_date.to_rfc3339()),
            );
            Self::extend_with_optional_str(
                &mut vuln_buf,
                &vuln.remediation.as_ref().map(|r| {
                    format!(
                        "{}:{}",
                        r.remediation_type,
                        r.description.as_deref().unwrap_or("")
                    )
                }),
            );
            Self::extend_tagged(&mut hasher_input, 8, &vuln_buf);
        }
        if let Some(vex) = &self.vex_status {
            Self::extend_tagged(&mut hasher_input, 9, format!("{vex:?}").as_bytes());
        }
        if self.is_external {
            hasher_input.push(10);
        }
        if let Some(vr) = &self.version_range {
            Self::extend_tagged(&mut hasher_input, 11, vr.as_bytes());
        }
        let mut ml_buf = Vec::new();
        Self::extend_with_ml_model(&mut ml_buf, &self.ml_model);
        if !ml_buf.is_empty() {
            Self::extend_tagged(&mut hasher_input, 12, &ml_buf);
        }
        let mut dataset_buf = Vec::new();
        Self::extend_with_dataset(&mut dataset_buf, &self.dataset);
        if !dataset_buf.is_empty() {
            Self::extend_tagged(&mut hasher_input, 13, &dataset_buf);
        }

        // Crypto properties: include fields that affect security semantics
        if let Some(cp) = &self.crypto_properties {
            let mut crypto_buf = Vec::new();
            Self::extend_with_optional_str(&mut crypto_buf, &Some(cp.asset_type.to_string()));
            Self::extend_with_optional_str(&mut crypto_buf, &cp.oid);
            let (family, level, classical) =
                cp.algorithm_properties
                    .as_ref()
                    .map_or((None, None, None), |a| {
                        (
                            a.algorithm_family.clone(),
                            a.nist_quantum_security_level,
                            a.classical_security_level,
                        )
                    });
            Self::extend_with_optional_str(&mut crypto_buf, &family);
            match level {
                Some(level) => {
                    crypto_buf.push(1);
                    crypto_buf.push(level);
                }
                None => crypto_buf.push(0),
            }
            // classical_security_level drives the crypto-downgrade detector;
            // protocol version drives TLS-version change reporting — both
            // must be hash-visible or those diffs are gated away.
            match classical {
                Some(bits) => {
                    crypto_buf.push(1);
                    crypto_buf.extend(bits.to_le_bytes());
                }
                None => crypto_buf.push(0),
            }
            Self::extend_with_optional_str(
                &mut crypto_buf,
                &cp.protocol_properties
                    .as_ref()
                    .and_then(|p| p.version.clone()),
            );
            Self::extend_with_optional_str(
                &mut crypto_buf,
                &cp.related_crypto_material_properties
                    .as_ref()
                    .and_then(|m| m.state.as_ref().map(std::string::ToString::to_string)),
            );
            Self::extend_with_optional_str(
                &mut crypto_buf,
                &cp.certificate_properties
                    .as_ref()
                    .and_then(|c| c.not_valid_after.as_ref().map(|e| e.to_rfc3339())),
            );
            Self::extend_tagged(&mut hasher_input, 14, &crypto_buf);
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

    #[test]
    fn unusable_purls_and_cpes_are_not_identifiers() {
        let mut comp = Component::new("beta".to_string(), "comp-beta".to_string());
        comp = comp.with_purl(String::new());
        comp = comp.with_purl("NOASSERTION".to_string());
        comp.add_cpe("NOASSERTION".to_string());
        assert!(comp.identifiers.purl.is_none());
        assert!(comp.identifiers.cpe.is_empty());
        assert_eq!(comp.canonical_id.value(), "comp-beta");
    }

    #[test]
    fn add_cpe_refreshes_the_canonical_id() {
        let mut comp = Component::new("openssl".to_string(), "comp-openssl".to_string());
        comp.add_cpe("cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*".to_string());
        assert_eq!(comp.identifiers.cpe.len(), 1);
        assert_ne!(comp.canonical_id.value(), "comp-openssl");
    }

    #[test]
    fn claim_canonical_id_keeps_distinct_components_apart() {
        let mut sbom = NormalizedSbom::default();
        // Two versions under one version-less purl.
        let mut v1 = Component::new("beta".to_string(), "beta-1".to_string())
            .with_version("1.0.0".to_string())
            .with_purl("pkg:npm/beta".to_string());
        let mut v2 = Component::new("beta".to_string(), "beta-2".to_string())
            .with_version("2.0.0".to_string())
            .with_purl("pkg:npm/beta".to_string());
        let id1 = sbom.claim_canonical_id(&mut v1);
        sbom.add_component(v1);
        let id2 = sbom.claim_canonical_id(&mut v2);
        sbom.add_component(v2);
        assert_ne!(id1, id2);
        assert_eq!(sbom.components.len(), 2, "both versions must survive");

        // A true duplicate (same name and version) still merges.
        let mut dup = Component::new("beta".to_string(), "beta-1-again".to_string())
            .with_version("1.0.0".to_string())
            .with_purl("pkg:npm/beta".to_string());
        assert_eq!(sbom.claim_canonical_id(&mut dup), id1);
    }
}
