//! Component index for efficient matching.
//!
//! This module provides indexing structures to reduce O(n²) fuzzy comparisons
//! by pre-normalizing and bucketing components for efficient candidate lookup.

use crate::model::{CanonicalId, Component, NormalizedSbom};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Pre-computed normalized data for a component.
#[derive(Debug, Clone)]
pub struct NormalizedEntry {
    /// Normalized PURL (if available)
    pub normalized_purl: Option<String>,
    /// Normalized component name (lowercase, separators normalized)
    pub normalized_name: String,
    /// Length of the normalized name (for length-based filtering)
    pub name_length: usize,
    /// Ecosystem extracted from PURL or inferred
    pub ecosystem: Option<String>,
    /// First 3 characters of normalized name (for prefix bucketing)
    pub prefix: String,
    /// Trigrams (3-character substrings) for fuzzy matching
    pub trigrams: Vec<String>,
}

/// Index for efficient component candidate lookup.
///
/// Reduces the O(n·m) comparison to O(n·k) where k << m by:
/// 1. Grouping components by ecosystem
/// 2. Bucketing by name prefix
/// 3. Bucketing by trigrams (3-char substrings) for fuzzy matching
/// 4. Pre-normalizing names for fast comparison
///
/// Uses `Arc<CanonicalId>` internally for efficient cloning during index building.
pub struct ComponentIndex {
    /// Ecosystem -> list of component IDs in that ecosystem
    by_ecosystem: HashMap<String, Vec<Arc<CanonicalId>>>,
    /// Normalized name prefix (first 3 chars) -> component IDs
    by_prefix: HashMap<String, Vec<Arc<CanonicalId>>>,
    /// Trigram -> list of component IDs containing that trigram
    by_trigram: HashMap<String, Vec<Arc<CanonicalId>>>,
    /// Pre-computed normalized data for each component
    entries: HashMap<Arc<CanonicalId>, NormalizedEntry>,
    /// All component IDs (for fallback)
    all_ids: Vec<Arc<CanonicalId>>,
}

impl ComponentIndex {
    /// Build an index from an SBOM.
    ///
    /// Uses `Arc<CanonicalId>` internally to avoid expensive cloning of IDs
    /// across multiple index structures.
    pub fn build(sbom: &NormalizedSbom) -> Self {
        let mut by_ecosystem: HashMap<String, Vec<Arc<CanonicalId>>> = HashMap::new();
        let mut by_prefix: HashMap<String, Vec<Arc<CanonicalId>>> = HashMap::new();
        let mut by_trigram: HashMap<String, Vec<Arc<CanonicalId>>> = HashMap::new();
        let mut entries: HashMap<Arc<CanonicalId>, NormalizedEntry> = HashMap::new();
        let mut all_ids: Vec<Arc<CanonicalId>> = Vec::new();

        for (id, comp) in &sbom.components {
            let entry = Self::normalize_component(comp);
            // Wrap ID in Arc once - all subsequent "clones" are cheap reference count increments
            let arc_id = Arc::new(id.clone());

            // Index by ecosystem
            if let Some(ref eco) = entry.ecosystem {
                by_ecosystem
                    .entry(eco.clone())
                    .or_default()
                    .push(Arc::clone(&arc_id));
            }

            // Index by name prefix
            if !entry.prefix.is_empty() {
                by_prefix
                    .entry(entry.prefix.clone())
                    .or_default()
                    .push(Arc::clone(&arc_id));
            }

            // Index by trigrams
            for trigram in &entry.trigrams {
                by_trigram
                    .entry(trigram.clone())
                    .or_default()
                    .push(Arc::clone(&arc_id));
            }

            entries.insert(Arc::clone(&arc_id), entry);
            all_ids.push(arc_id);
        }

        Self {
            by_ecosystem,
            by_prefix,
            by_trigram,
            entries,
            all_ids,
        }
    }

    /// Normalize a component for indexing.
    pub fn normalize_component(comp: &Component) -> NormalizedEntry {
        // Extract ecosystem from PURL
        let (ecosystem, normalized_purl) = comp.identifiers.purl.as_ref().map_or_else(
            || {
                // Try to infer ecosystem from component type or other fields
                // Convert Ecosystem enum to String for consistent comparison
                (comp.ecosystem.as_ref().map(std::string::ToString::to_string), None)
            },
            |purl| {
                let eco = Self::extract_ecosystem(purl);
                let normalized = Self::normalize_purl(purl);
                (eco, Some(normalized))
            },
        );

        // Normalize name
        let normalized_name = Self::normalize_name(&comp.name, ecosystem.as_deref());
        let name_length = normalized_name.len();
        let prefix = normalized_name.chars().take(3).collect::<String>();
        let trigrams = Self::compute_trigrams(&normalized_name);

        NormalizedEntry {
            normalized_purl,
            normalized_name,
            name_length,
            ecosystem,
            prefix,
            trigrams,
        }
    }

    /// Compute trigrams (3-character substrings) for a normalized name.
    ///
    /// Trigrams enable finding matches where only the middle or end differs,
    /// which prefix-based indexing would miss.
    fn compute_trigrams(name: &str) -> Vec<String> {
        if name.len() < 3 {
            // For very short names, use the name itself as a "trigram"
            return if name.is_empty() {
                vec![]
            } else {
                vec![name.to_string()]
            };
        }

        // Fast path: ASCII-only names (common for package names)
        // Avoids intermediate Vec<char> allocation
        if name.is_ascii() {
            return name
                .as_bytes()
                .windows(3)
                .map(|w| {
                    // SAFETY: name.is_ascii() was checked above, so all bytes are valid
                    // single-byte UTF-8 characters. Any 3-byte window is valid UTF-8.
                    unsafe { std::str::from_utf8_unchecked(w) }.to_string()
                })
                .collect();
        }

        // Slow path: Unicode names - need to collect chars first for windows()
        let chars: Vec<char> = name.chars().collect();
        if chars.len() < 3 {
            return vec![name.to_string()];
        }

        chars
            .windows(3)
            .map(|w| w.iter().collect::<String>())
            .collect()
    }

    /// Extract ecosystem from a PURL.
    fn extract_ecosystem(purl: &str) -> Option<String> {
        // PURL format: pkg:ecosystem/namespace/name@version
        if let Some(rest) = purl.strip_prefix("pkg:") {
            if let Some(slash_pos) = rest.find('/') {
                return Some(rest[..slash_pos].to_lowercase());
            }
        }
        None
    }

    /// Normalize a PURL for comparison.
    fn normalize_purl(purl: &str) -> String {
        // Basic normalization: lowercase and strip version qualifiers
        let purl_lower = purl.to_lowercase();
        // Remove version part for comparison if present
        if let Some(at_pos) = purl_lower.rfind('@') {
            purl_lower[..at_pos].to_string()
        } else {
            purl_lower
        }
    }

    /// Normalize a component name for comparison.
    ///
    /// Applies ecosystem-specific normalization rules:
    /// - PyPI: underscores, hyphens, dots are all equivalent (converted to hyphen)
    /// - Cargo: hyphens and underscores are equivalent (converted to underscore)
    /// - npm: lowercase only, preserves scope
    /// - Default: lowercase with underscore to hyphen conversion
    ///
    /// This is also used by LSH for consistent shingle computation.
    pub fn normalize_name(name: &str, ecosystem: Option<&str>) -> String {
        let mut normalized = name.to_lowercase();

        // Apply ecosystem-specific normalization
        match ecosystem {
            Some("pypi") => {
                // Python: underscores, hyphens, dots are equivalent
                normalized = normalized.replace(['_', '.'], "-");
            }
            Some("cargo") => {
                // Rust: hyphens and underscores are equivalent
                normalized = normalized.replace('-', "_");
            }
            Some("npm") => {
                // npm: already lowercase, preserve scope
                // Nothing special needed
            }
            _ => {
                // Default: just lowercase, normalize common separators
                normalized = normalized.replace('_', "-");
            }
        }

        // Collapse multiple separators
        while normalized.contains("--") {
            normalized = normalized.replace("--", "-");
        }

        normalized
    }

    /// Get normalized entry for a component.
    pub fn get_entry(&self, id: &CanonicalId) -> Option<&NormalizedEntry> {
        // Arc<T>: Borrow<T> allows HashMap lookup with &CanonicalId
        self.entries.get(id)
    }

    /// Get components by ecosystem.
    ///
    /// Returns cloned CanonicalIds for API stability. The internal storage uses Arc
    /// to avoid expensive cloning during index building.
    pub fn get_by_ecosystem(&self, ecosystem: &str) -> Option<Vec<CanonicalId>> {
        self.by_ecosystem
            .get(ecosystem)
            .map(|v| v.iter().map(|arc| (**arc).clone()).collect())
    }

    /// Find candidate matches for a component.
    ///
    /// Returns a list of component IDs that are likely matches, ordered by likelihood.
    /// Uses ecosystem and prefix-based filtering to reduce candidates.
    ///
    /// Returns cloned CanonicalIds for API stability. The internal storage uses Arc
    /// to avoid expensive cloning during index building.
    pub fn find_candidates(
        &self,
        source_id: &CanonicalId,
        source_entry: &NormalizedEntry,
        max_candidates: usize,
        max_length_diff: usize,
    ) -> Vec<CanonicalId> {
        let mut candidates: Vec<Arc<CanonicalId>> = Vec::new();
        let mut seen: HashSet<Arc<CanonicalId>> = HashSet::new();

        // Priority 1: Same ecosystem candidates
        if let Some(ref eco) = source_entry.ecosystem {
            if let Some(ids) = self.by_ecosystem.get(eco) {
                for id in ids {
                    if id.as_ref() != source_id && !seen.contains(id) {
                        // Apply length filter
                        if let Some(entry) = self.entries.get(id.as_ref()) {
                            let len_diff = (source_entry.name_length as i32
                                - entry.name_length as i32)
                                .unsigned_abs() as usize;
                            if len_diff <= max_length_diff {
                                candidates.push(Arc::clone(id));
                                seen.insert(Arc::clone(id));
                            }
                        }
                    }
                }
            }
        }

        // Priority 2: Same prefix candidates (cross-ecosystem fallback)
        if candidates.len() < max_candidates && !source_entry.prefix.is_empty() {
            if let Some(ids) = self.by_prefix.get(&source_entry.prefix) {
                for id in ids {
                    if id.as_ref() != source_id && !seen.contains(id) {
                        if let Some(entry) = self.entries.get(id.as_ref()) {
                            let len_diff = (source_entry.name_length as i32
                                - entry.name_length as i32)
                                .unsigned_abs() as usize;
                            if len_diff <= max_length_diff {
                                candidates.push(Arc::clone(id));
                                seen.insert(Arc::clone(id));
                            }
                        }
                    }
                    if candidates.len() >= max_candidates {
                        break;
                    }
                }
            }
        }

        // Priority 3: Similar prefixes (1-char difference in prefix)
        if candidates.len() < max_candidates && source_entry.prefix.len() >= 2 {
            let prefix_2 = &source_entry.prefix[..2.min(source_entry.prefix.len())];
            for (prefix, ids) in &self.by_prefix {
                if prefix.starts_with(prefix_2) && prefix != &source_entry.prefix {
                    for id in ids {
                        if id.as_ref() != source_id && !seen.contains(id) {
                            if let Some(entry) = self.entries.get(id.as_ref()) {
                                let len_diff = (source_entry.name_length as i32
                                    - entry.name_length as i32)
                                    .unsigned_abs()
                                    as usize;
                                if len_diff <= max_length_diff {
                                    candidates.push(Arc::clone(id));
                                    seen.insert(Arc::clone(id));
                                }
                            }
                        }
                        if candidates.len() >= max_candidates {
                            break;
                        }
                    }
                }
                if candidates.len() >= max_candidates {
                    break;
                }
            }
        }

        // Priority 4: Trigram-based matching (catches middle/end differences)
        // Find components that share multiple trigrams with the source
        if candidates.len() < max_candidates && !source_entry.trigrams.is_empty() {
            // Count trigram overlap for each candidate
            let mut trigram_scores: HashMap<Arc<CanonicalId>, usize> = HashMap::new();

            for trigram in &source_entry.trigrams {
                if let Some(ids) = self.by_trigram.get(trigram) {
                    for id in ids {
                        if id.as_ref() != source_id && !seen.contains(id) {
                            *trigram_scores.entry(Arc::clone(id)).or_default() += 1;
                        }
                    }
                }
            }

            // Require at least 2 shared trigrams (or 1 for very short names)
            let min_shared = if source_entry.trigrams.len() <= 2 {
                1
            } else {
                2
            };

            // Sort by trigram overlap count (descending)
            let mut scored: Vec<_> = trigram_scores
                .into_iter()
                .filter(|(_, count)| *count >= min_shared)
                .collect();
            scored.sort_by(|a, b| b.1.cmp(&a.1));

            for (id, _score) in scored {
                if candidates.len() >= max_candidates {
                    break;
                }
                if let Some(entry) = self.entries.get(id.as_ref()) {
                    let len_diff = (source_entry.name_length as i32 - entry.name_length as i32)
                        .unsigned_abs() as usize;
                    if len_diff <= max_length_diff {
                        candidates.push(Arc::clone(&id));
                        seen.insert(id);
                    }
                }
            }
        }

        // Truncate to max_candidates and convert to owned CanonicalIds
        candidates.truncate(max_candidates);
        candidates.into_iter().map(|arc| (*arc).clone()).collect()
    }

    /// Get all component IDs (for fallback full scan).
    ///
    /// Returns cloned CanonicalIds for API stability.
    pub fn all_ids(&self) -> Vec<CanonicalId> {
        self.all_ids.iter().map(|arc| (**arc).clone()).collect()
    }

    /// Get the number of indexed components.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find candidates for multiple source components in parallel.
    ///
    /// This is significantly faster than calling `find_candidates` sequentially
    /// for large SBOMs (1000+ components). Uses rayon for parallel iteration.
    ///
    /// Returns a vector of (source_id, candidates) pairs in the same order as input.
    pub fn find_candidates_parallel<'a>(
        &self,
        sources: &[(&'a CanonicalId, &NormalizedEntry)],
        max_candidates: usize,
        max_length_diff: usize,
    ) -> Vec<(&'a CanonicalId, Vec<CanonicalId>)> {
        sources
            .par_iter()
            .map(|(source_id, source_entry)| {
                let candidates =
                    self.find_candidates(source_id, source_entry, max_candidates, max_length_diff);
                (*source_id, candidates)
            })
            .collect()
    }

    /// Find candidates for all components in another index in parallel.
    ///
    /// Useful for diffing two SBOMs: build an index from the new SBOM,
    /// then find candidates for all components from the old SBOM.
    pub fn find_all_candidates_from(
        &self,
        other: &Self,
        max_candidates: usize,
        max_length_diff: usize,
    ) -> Vec<(CanonicalId, Vec<CanonicalId>)> {
        let sources: Vec<_> = other
            .entries
            .iter()
            .collect();

        sources
            .par_iter()
            .map(|(source_id, source_entry)| {
                let candidates =
                    self.find_candidates(source_id, source_entry, max_candidates, max_length_diff);
                // Clone the inner CanonicalId from the Arc
                ((*source_id).as_ref().clone(), candidates)
            })
            .collect::<Vec<_>>()
    }

    /// Get statistics about the index.
    pub fn stats(&self) -> IndexStats {
        let ecosystems = self.by_ecosystem.len();
        let prefixes = self.by_prefix.len();
        let trigrams = self.by_trigram.len();
        let avg_per_ecosystem = if ecosystems > 0 {
            self.by_ecosystem.values().map(std::vec::Vec::len).sum::<usize>() / ecosystems
        } else {
            0
        };
        let avg_per_prefix = if prefixes > 0 {
            self.by_prefix.values().map(std::vec::Vec::len).sum::<usize>() / prefixes
        } else {
            0
        };
        let avg_per_trigram = if trigrams > 0 {
            self.by_trigram.values().map(std::vec::Vec::len).sum::<usize>() / trigrams
        } else {
            0
        };

        IndexStats {
            total_components: self.entries.len(),
            ecosystems,
            prefixes,
            trigrams,
            avg_per_ecosystem,
            avg_per_prefix,
            avg_per_trigram,
        }
    }

    /// Compute trigram similarity between two entries (Jaccard coefficient).
    ///
    /// Returns a value between 0.0 and 1.0 where 1.0 means identical trigram sets.
    pub fn trigram_similarity(entry_a: &NormalizedEntry, entry_b: &NormalizedEntry) -> f64 {
        if entry_a.trigrams.is_empty() || entry_b.trigrams.is_empty() {
            return 0.0;
        }

        let set_a: HashSet<_> = entry_a.trigrams.iter().collect();
        let set_b: HashSet<_> = entry_b.trigrams.iter().collect();

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
}

/// Statistics about the component index.
#[derive(Debug, Clone)]
pub struct IndexStats {
    /// Total number of indexed components
    pub total_components: usize,
    /// Number of unique ecosystems
    pub ecosystems: usize,
    /// Number of unique prefixes
    pub prefixes: usize,
    /// Number of unique trigrams
    pub trigrams: usize,
    /// Average components per ecosystem
    pub avg_per_ecosystem: usize,
    /// Average components per prefix
    pub avg_per_prefix: usize,
    /// Average components per trigram
    pub avg_per_trigram: usize,
}

/// Batch candidate generator that combines multiple indexing strategies.
///
/// For best recall, combines:
/// 1. ComponentIndex (ecosystem, prefix, trigram-based)
/// 2. LSH index (for large SBOMs, catches approximate matches)
/// 3. Cross-ecosystem mappings (optional)
///
/// The candidates from each source are deduplicated and merged.
pub struct BatchCandidateGenerator {
    /// Primary component index
    component_index: ComponentIndex,
    /// Optional LSH index for large SBOMs
    lsh_index: Option<super::lsh::LshIndex>,
    /// Optional cross-ecosystem database
    cross_ecosystem_db: Option<super::cross_ecosystem::CrossEcosystemDb>,
    /// Configuration
    config: BatchCandidateConfig,
}

/// Configuration for batch candidate generation.
#[derive(Debug, Clone)]
pub struct BatchCandidateConfig {
    /// Maximum candidates per source component
    pub max_candidates: usize,
    /// Maximum name length difference
    pub max_length_diff: usize,
    /// Minimum SBOM size to enable LSH (smaller SBOMs don't benefit)
    pub lsh_threshold: usize,
    /// Enable cross-ecosystem matching
    pub enable_cross_ecosystem: bool,
}

impl Default for BatchCandidateConfig {
    fn default() -> Self {
        Self {
            max_candidates: 100,
            max_length_diff: 5,
            lsh_threshold: 500, // Only use LSH for SBOMs with 500+ components
            enable_cross_ecosystem: true,
        }
    }
}

/// Result of batch candidate generation.
#[derive(Debug)]
pub struct BatchCandidateResult {
    /// Source component ID
    pub source_id: CanonicalId,
    /// Candidates from component index
    pub index_candidates: Vec<CanonicalId>,
    /// Additional candidates from LSH (not in index_candidates)
    pub lsh_candidates: Vec<CanonicalId>,
    /// Cross-ecosystem candidates (if different ecosystems)
    pub cross_ecosystem_candidates: Vec<CanonicalId>,
    /// Total unique candidates
    pub total_unique: usize,
}

impl BatchCandidateGenerator {
    /// Create a new batch candidate generator from an SBOM.
    pub fn build(sbom: &NormalizedSbom, config: BatchCandidateConfig) -> Self {
        let component_index = ComponentIndex::build(sbom);

        // Only build LSH index for large SBOMs
        let lsh_index = if sbom.component_count() >= config.lsh_threshold {
            Some(super::lsh::LshIndex::build(
                sbom,
                super::lsh::LshConfig::default(),
            ))
        } else {
            None
        };

        // Optionally load cross-ecosystem database
        let cross_ecosystem_db = if config.enable_cross_ecosystem {
            Some(super::cross_ecosystem::CrossEcosystemDb::with_builtin_mappings())
        } else {
            None
        };

        Self {
            component_index,
            lsh_index,
            cross_ecosystem_db,
            config,
        }
    }

    /// Generate candidates for a single component.
    pub fn find_candidates(
        &self,
        source_id: &CanonicalId,
        source_component: &Component,
    ) -> BatchCandidateResult {
        let mut seen: HashSet<CanonicalId> = HashSet::new();

        // Get normalized entry for the source
        let source_entry = self.component_index.get_entry(source_id).map_or_else(
            || {
                // Build entry on the fly if not in our index (source from different SBOM)
                ComponentIndex::normalize_component(source_component)
            },
            NormalizedEntry::clone,
        );

        // 1. Component index candidates
        let index_candidates = self.component_index.find_candidates(
            source_id,
            &source_entry,
            self.config.max_candidates,
            self.config.max_length_diff,
        );
        for id in &index_candidates {
            seen.insert(id.clone());
        }

        // 2. LSH candidates (additional ones not found by component index)
        let lsh_candidates: Vec<CanonicalId> = self.lsh_index.as_ref().map_or_else(
            Vec::new,
            |lsh| {
                let candidates: Vec<_> = lsh
                    .find_candidates(source_component)
                    .into_iter()
                    .filter(|id| id != source_id && !seen.contains(id))
                    .take(self.config.max_candidates / 2) // Limit LSH additions
                    .collect();
                for id in &candidates {
                    seen.insert(id.clone());
                }
                candidates
            },
        );

        // 3. Cross-ecosystem candidates
        let cross_ecosystem_candidates: Vec<CanonicalId> =
            if let (Some(db), Some(eco)) =
                (&self.cross_ecosystem_db, &source_component.ecosystem)
            {
                let candidates: Vec<_> = db
                    .find_equivalents(eco, &source_component.name)
                    .into_iter()
                    .flat_map(|m| {
                        // Look up components with these names in our index
                        let target_eco_str = m.target_ecosystem.to_string().to_lowercase();
                        self.component_index
                            .get_by_ecosystem(&target_eco_str)
                            .unwrap_or_default()
                    })
                    .filter(|id| id != source_id && !seen.contains(id))
                    .take(self.config.max_candidates / 4) // Limit cross-ecosystem
                    .collect();
                for id in &candidates {
                    seen.insert(id.clone());
                }
                candidates
            } else {
                Vec::new()
            };

        let total_unique = seen.len();

        BatchCandidateResult {
            source_id: source_id.clone(),
            index_candidates,
            lsh_candidates,
            cross_ecosystem_candidates,
            total_unique,
        }
    }

    /// Generate candidates for multiple components in parallel.
    pub fn find_candidates_batch(
        &self,
        sources: &[(&CanonicalId, &Component)],
    ) -> Vec<BatchCandidateResult> {
        sources
            .par_iter()
            .map(|(id, comp)| self.find_candidates(id, comp))
            .collect()
    }

    /// Get all unique candidates (deduplicated across all strategies).
    pub fn all_candidates(
        &self,
        source_id: &CanonicalId,
        source_component: &Component,
    ) -> Vec<CanonicalId> {
        let result = self.find_candidates(source_id, source_component);
        let mut all: Vec<_> = result.index_candidates;
        all.extend(result.lsh_candidates);
        all.extend(result.cross_ecosystem_candidates);
        all
    }

    /// Get the underlying component index.
    pub fn component_index(&self) -> &ComponentIndex {
        &self.component_index
    }

    /// Check if LSH is enabled.
    pub fn has_lsh(&self) -> bool {
        self.lsh_index.is_some()
    }

    /// Check if cross-ecosystem matching is enabled.
    pub fn has_cross_ecosystem(&self) -> bool {
        self.cross_ecosystem_db.is_some()
    }

    /// Get statistics about the generator.
    pub fn stats(&self) -> BatchCandidateStats {
        BatchCandidateStats {
            index_stats: self.component_index.stats(),
            lsh_enabled: self.lsh_index.is_some(),
            lsh_stats: self.lsh_index.as_ref().map(super::lsh::LshIndex::stats),
            cross_ecosystem_enabled: self.cross_ecosystem_db.is_some(),
        }
    }
}

/// Statistics about the batch candidate generator.
#[derive(Debug)]
pub struct BatchCandidateStats {
    /// Component index statistics
    pub index_stats: IndexStats,
    /// Whether LSH is enabled
    pub lsh_enabled: bool,
    /// LSH statistics (if enabled)
    pub lsh_stats: Option<super::lsh::LshIndexStats>,
    /// Whether cross-ecosystem matching is enabled
    pub cross_ecosystem_enabled: bool,
}

/// A lazily-built component index that only constructs the index on first use.
///
/// This is useful when the index might not be needed (e.g., when doing simple
/// exact-match only comparisons), or when construction should be deferred.
pub struct LazyComponentIndex {
    /// The SBOM to index (stored for deferred building)
    sbom: Option<std::sync::Arc<NormalizedSbom>>,
    /// The built index (populated on first access)
    index: std::sync::OnceLock<ComponentIndex>,
}

impl LazyComponentIndex {
    /// Create a new lazy index that will build from the given SBOM on first access.
    pub fn new(sbom: std::sync::Arc<NormalizedSbom>) -> Self {
        Self {
            sbom: Some(sbom),
            index: std::sync::OnceLock::new(),
        }
    }

    /// Create a lazy index from an already-built ComponentIndex.
    pub fn from_index(index: ComponentIndex) -> Self {
        let lazy = Self {
            sbom: None,
            index: std::sync::OnceLock::new(),
        };
        let _ = lazy.index.set(index);
        lazy
    }

    /// Get the index, building it if necessary.
    ///
    /// This is safe to call from multiple threads - the index will only
    /// be built once.
    pub fn get(&self) -> &ComponentIndex {
        self.index.get_or_init(|| {
            self.sbom.as_ref().map_or_else(
                || {
                    // Empty index as fallback (shouldn't happen in normal use)
                    ComponentIndex::build(&NormalizedSbom::default())
                },
                |sbom| ComponentIndex::build(sbom),
            )
        })
    }

    /// Check if the index has been built yet.
    pub fn is_built(&self) -> bool {
        self.index.get().is_some()
    }

    /// Get the index if already built, without triggering a build.
    pub fn try_get(&self) -> Option<&ComponentIndex> {
        self.index.get()
    }
}

impl std::ops::Deref for LazyComponentIndex {
    type Target = ComponentIndex;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DocumentMetadata, Ecosystem};

    fn make_component(name: &str, purl: Option<&str>) -> Component {
        let mut comp = Component::new(name.to_string(), format!("test-{}", name));
        comp.version = Some("1.0.0".to_string());
        comp.identifiers.purl = purl.map(|s| s.to_string());
        // Convert extracted ecosystem string to Ecosystem enum
        comp.ecosystem = purl
            .and_then(|p| ComponentIndex::extract_ecosystem(p))
            .map(|eco_str| Ecosystem::from_purl_type(&eco_str));
        comp
    }

    #[test]
    fn test_extract_ecosystem() {
        assert_eq!(
            ComponentIndex::extract_ecosystem("pkg:pypi/requests@2.28.0"),
            Some("pypi".to_string())
        );
        assert_eq!(
            ComponentIndex::extract_ecosystem("pkg:npm/@angular/core@14.0.0"),
            Some("npm".to_string())
        );
        assert_eq!(
            ComponentIndex::extract_ecosystem("pkg:cargo/serde@1.0.0"),
            Some("cargo".to_string())
        );
    }

    #[test]
    fn test_normalize_name_pypi() {
        assert_eq!(
            ComponentIndex::normalize_name("Python_Dateutil", Some("pypi")),
            "python-dateutil"
        );
        assert_eq!(
            ComponentIndex::normalize_name("Some.Package", Some("pypi")),
            "some-package"
        );
    }

    #[test]
    fn test_normalize_name_cargo() {
        assert_eq!(
            ComponentIndex::normalize_name("serde-json", Some("cargo")),
            "serde_json"
        );
    }

    #[test]
    fn test_build_index() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        let comp1 = make_component("requests", Some("pkg:pypi/requests@2.28.0"));
        let comp2 = make_component("urllib3", Some("pkg:pypi/urllib3@1.26.0"));
        let comp3 = make_component("serde", Some("pkg:cargo/serde@1.0.0"));

        sbom.add_component(comp1);
        sbom.add_component(comp2);
        sbom.add_component(comp3);

        let index = ComponentIndex::build(&sbom);

        assert_eq!(index.len(), 3);
        assert_eq!(index.by_ecosystem.get("pypi").map(|v| v.len()), Some(2));
        assert_eq!(index.by_ecosystem.get("cargo").map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_find_candidates_same_ecosystem() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        let comp1 = make_component("requests", Some("pkg:pypi/requests@2.28.0"));
        let comp2 = make_component("urllib3", Some("pkg:pypi/urllib3@1.26.0"));
        let comp3 = make_component("flask", Some("pkg:pypi/flask@2.0.0"));
        let comp4 = make_component("serde", Some("pkg:cargo/serde@1.0.0"));

        sbom.add_component(comp1.clone());
        sbom.add_component(comp2);
        sbom.add_component(comp3);
        sbom.add_component(comp4);

        let index = ComponentIndex::build(&sbom);

        // Get the ID for requests
        let requests_id = sbom
            .components
            .keys()
            .find(|id| {
                sbom.components
                    .get(*id)
                    .map(|c| c.name == "requests")
                    .unwrap_or(false)
            })
            .unwrap();

        let entry = index.get_entry(requests_id).unwrap();
        let candidates = index.find_candidates(requests_id, entry, 10, 5);

        // Should find pypi packages, not cargo packages
        assert!(candidates.len() >= 2);
        for cand_id in &candidates {
            let cand_entry = index.get_entry(cand_id).unwrap();
            assert_eq!(cand_entry.ecosystem, Some("pypi".to_string()));
        }
    }

    #[test]
    fn test_compute_trigrams() {
        // Normal case
        let trigrams = ComponentIndex::compute_trigrams("lodash");
        assert_eq!(trigrams, vec!["lod", "oda", "das", "ash"]);

        // Short name (< 3 chars)
        let trigrams = ComponentIndex::compute_trigrams("ab");
        assert_eq!(trigrams, vec!["ab"]);

        // Empty name
        let trigrams = ComponentIndex::compute_trigrams("");
        assert!(trigrams.is_empty());

        // Exactly 3 chars
        let trigrams = ComponentIndex::compute_trigrams("abc");
        assert_eq!(trigrams, vec!["abc"]);
    }

    #[test]
    fn test_trigram_similarity() {
        let entry_a = NormalizedEntry {
            normalized_purl: None,
            normalized_name: "lodash".to_string(),
            name_length: 6,
            ecosystem: None,
            prefix: "lod".to_string(),
            trigrams: vec![
                "lod".to_string(),
                "oda".to_string(),
                "das".to_string(),
                "ash".to_string(),
            ],
        };

        let entry_b = NormalizedEntry {
            normalized_purl: None,
            normalized_name: "lodash-es".to_string(),
            name_length: 9,
            ecosystem: None,
            prefix: "lod".to_string(),
            trigrams: vec![
                "lod".to_string(),
                "oda".to_string(),
                "das".to_string(),
                "ash".to_string(),
                "sh-".to_string(),
                "h-e".to_string(),
                "-es".to_string(),
            ],
        };

        let similarity = ComponentIndex::trigram_similarity(&entry_a, &entry_b);
        // lodash has 4 trigrams, lodash-es has 7, they share 4
        // Jaccard = 4 / 7 ≈ 0.57
        assert!(
            similarity > 0.5 && similarity < 0.6,
            "Expected ~0.57, got {}",
            similarity
        );

        // Identical entries should have similarity 1.0
        let same_similarity = ComponentIndex::trigram_similarity(&entry_a, &entry_a);
        assert!((same_similarity - 1.0).abs() < f64::EPSILON);

        // Completely different entries should have low similarity
        let entry_c = NormalizedEntry {
            normalized_purl: None,
            normalized_name: "react".to_string(),
            name_length: 5,
            ecosystem: None,
            prefix: "rea".to_string(),
            trigrams: vec!["rea".to_string(), "eac".to_string(), "act".to_string()],
        };

        let diff_similarity = ComponentIndex::trigram_similarity(&entry_a, &entry_c);
        assert!(
            diff_similarity < 0.1,
            "Expected low similarity, got {}",
            diff_similarity
        );
    }

    #[test]
    fn test_trigram_index_find_similar_suffix() {
        // Test that trigram indexing can find packages with different prefixes but similar content
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        // These packages share trigrams in the middle/end
        let comp1 = make_component("react-dom", Some("pkg:npm/react-dom@18.0.0"));
        let comp2 = make_component("preact-dom", Some("pkg:npm/preact-dom@10.0.0")); // shares "act", "-do", "dom"
        let comp3 = make_component("angular", Some("pkg:npm/angular@15.0.0")); // completely different

        sbom.add_component(comp1.clone());
        sbom.add_component(comp2);
        sbom.add_component(comp3);

        let index = ComponentIndex::build(&sbom);

        // Find ID for react-dom
        let react_id = sbom
            .components
            .keys()
            .find(|id| {
                sbom.components
                    .get(*id)
                    .map(|c| c.name == "react-dom")
                    .unwrap_or(false)
            })
            .unwrap();

        let entry = index.get_entry(react_id).unwrap();

        // Should find preact-dom via trigram matching even though prefix differs
        let candidates = index.find_candidates(react_id, entry, 10, 5);

        let preact_found = candidates.iter().any(|id| {
            index
                .get_entry(id)
                .map(|e| e.normalized_name.contains("preact"))
                .unwrap_or(false)
        });

        assert!(preact_found, "Should find preact-dom via trigram matching");
    }
}
