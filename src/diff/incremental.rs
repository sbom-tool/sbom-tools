//! Incremental diffing with result caching.
//!
//! This module provides caching and incremental computation for SBOM diffs,
//! dramatically improving performance when comparing related SBOMs (e.g.,
//! successive builds where only a few components change).
//!
//! # How It Works
//!
//! 1. **Content Hashing**: Each SBOM section (components, dependencies, licenses,
//!    vulnerabilities) has a separate content hash.
//! 2. **Change Detection**: Before recomputing, we check if each section changed.
//! 3. **Partial Recomputation**: Only sections that changed are recomputed.
//! 4. **Result Caching**: Full results are cached for exact SBOM pair matches.
//!
//! # Performance Gains
//!
//! - Exact cache hit: O(1) lookup
//! - Partial change: Only recompute changed sections (typically 10-50% of work)
//! - Cold start: Same as regular diff

use crate::diff::{DiffEngine, DiffResult};
use crate::error::SbomDiffError;
use crate::model::NormalizedSbom;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Cache Key Types
// ============================================================================

/// Key for full diff cache lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiffCacheKey {
    /// Hash of the old SBOM
    pub old_hash: u64,
    /// Hash of the new SBOM
    pub new_hash: u64,
}

impl DiffCacheKey {
    /// Create a cache key from two SBOMs.
    #[must_use]
    pub const fn from_sboms(old: &NormalizedSbom, new: &NormalizedSbom) -> Self {
        Self {
            old_hash: old.content_hash,
            new_hash: new.content_hash,
        }
    }
}

/// Section-level hashes for incremental change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHashes {
    /// Hash of all components
    pub components: u64,
    /// Hash of all dependency edges
    pub dependencies: u64,
    /// Hash of all licenses
    pub licenses: u64,
    /// Hash of all vulnerabilities
    pub vulnerabilities: u64,
}

impl SectionHashes {
    /// Compute section hashes for an SBOM.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        use std::collections::hash_map::DefaultHasher;

        // Component hash
        let mut hasher = DefaultHasher::new();
        for (id, comp) in &sbom.components {
            id.hash(&mut hasher);
            comp.name.hash(&mut hasher);
            comp.version.hash(&mut hasher);
            comp.content_hash.hash(&mut hasher);
        }
        let components = hasher.finish();

        // Dependencies hash
        let mut hasher = DefaultHasher::new();
        for edge in &sbom.edges {
            edge.from.hash(&mut hasher);
            edge.to.hash(&mut hasher);
            edge.relationship.to_string().hash(&mut hasher);
        }
        let dependencies = hasher.finish();

        // Licenses hash
        let mut hasher = DefaultHasher::new();
        for (_, comp) in &sbom.components {
            for lic in &comp.licenses.declared {
                lic.expression.hash(&mut hasher);
            }
        }
        let licenses = hasher.finish();

        // Vulnerabilities hash
        let mut hasher = DefaultHasher::new();
        for (_, comp) in &sbom.components {
            for vuln in &comp.vulnerabilities {
                vuln.id.hash(&mut hasher);
            }
        }
        let vulnerabilities = hasher.finish();

        Self {
            components,
            dependencies,
            licenses,
            vulnerabilities,
        }
    }

    /// Check which sections differ between two hash sets.
    #[must_use]
    pub const fn changed_sections(&self, other: &Self) -> ChangedSections {
        ChangedSections {
            components: self.components != other.components,
            dependencies: self.dependencies != other.dependencies,
            licenses: self.licenses != other.licenses,
            vulnerabilities: self.vulnerabilities != other.vulnerabilities,
        }
    }
}

/// Indicates which sections changed between two SBOMs.
#[derive(Debug, Clone, Default)]
pub struct ChangedSections {
    pub components: bool,
    pub dependencies: bool,
    pub licenses: bool,
    pub vulnerabilities: bool,
}

impl ChangedSections {
    /// Create a `ChangedSections` with all sections marked as changed.
    #[must_use]
    pub const fn all_changed() -> Self {
        Self {
            components: true,
            dependencies: true,
            licenses: true,
            vulnerabilities: true,
        }
    }

    /// Check if any section changed.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.components || self.dependencies || self.licenses || self.vulnerabilities
    }

    /// Check if all sections changed.
    #[must_use]
    pub const fn all(&self) -> bool {
        self.components && self.dependencies && self.licenses && self.vulnerabilities
    }

    /// Count how many sections changed.
    #[must_use]
    pub fn count(&self) -> usize {
        [
            self.components,
            self.dependencies,
            self.licenses,
            self.vulnerabilities,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }
}

// ============================================================================
// Cached Entry
// ============================================================================

/// A cached diff result with metadata.
#[derive(Debug, Clone)]
pub struct CachedDiffResult {
    /// The diff result
    pub result: Arc<DiffResult>,
    /// When this was computed
    pub computed_at: Instant,
    /// Section hashes from old SBOM
    pub old_hashes: SectionHashes,
    /// Section hashes from new SBOM
    pub new_hashes: SectionHashes,
    /// Number of times this cache entry was hit
    pub hit_count: u64,
}

impl CachedDiffResult {
    /// Create a new cached result.
    #[must_use]
    pub fn new(result: DiffResult, old_hashes: SectionHashes, new_hashes: SectionHashes) -> Self {
        Self {
            result: Arc::new(result),
            computed_at: Instant::now(),
            old_hashes,
            new_hashes,
            hit_count: 0,
        }
    }

    /// Check if this entry is still valid (not expired).
    #[must_use]
    pub fn is_valid(&self, ttl: Duration) -> bool {
        self.computed_at.elapsed() < ttl
    }

    /// Get age of this cache entry.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.computed_at.elapsed()
    }
}

// ============================================================================
// Diff Cache
// ============================================================================

/// Configuration for the diff cache.
#[derive(Debug, Clone)]
pub struct DiffCacheConfig {
    /// Maximum number of entries to cache
    pub max_entries: usize,
    /// Time-to-live for cache entries
    pub ttl: Duration,
    /// Enable incremental computation for partial changes
    pub enable_incremental: bool,
}

impl Default for DiffCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            ttl: Duration::from_secs(3600), // 1 hour
            enable_incremental: true,
        }
    }
}

/// Thread-safe cache for diff results.
///
/// Supports both full result caching and incremental computation
/// when only some sections change.
pub struct DiffCache {
    /// Full result cache (keyed by SBOM pair hashes)
    cache: RwLock<HashMap<DiffCacheKey, CachedDiffResult>>,
    /// Configuration
    config: DiffCacheConfig,
    /// Statistics
    stats: RwLock<CacheStats>,
}

/// Statistics for cache performance.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total cache lookups
    pub lookups: u64,
    /// Exact cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Incremental computations (partial cache hit)
    pub incremental_hits: u64,
    /// Entries evicted
    pub evictions: u64,
    /// Total computation time saved (estimated)
    pub time_saved_ms: u64,
}

impl CacheStats {
    /// Get the cache hit rate.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            (self.hits + self.incremental_hits) as f64 / self.lookups as f64
        }
    }
}

impl DiffCache {
    /// Create a new diff cache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DiffCacheConfig::default())
    }

    /// Create a new diff cache with custom configuration.
    #[must_use]
    pub fn with_config(config: DiffCacheConfig) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            config,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Look up a cached result.
    ///
    /// Returns `Some` if an exact match is found and still valid.
    pub fn get(&self, key: &DiffCacheKey) -> Option<Arc<DiffResult>> {
        let result = {
            let mut cache = self.cache.write().expect("cache lock poisoned");
            cache.get_mut(key).and_then(|entry| {
                entry.is_valid(self.config.ttl).then(|| {
                    entry.hit_count += 1;
                    Arc::clone(&entry.result)
                })
            })
        };

        let mut stats = self.stats.write().expect("stats lock poisoned");
        stats.lookups += 1;
        if let Some(ref result) = result {
            stats.hits += 1;
            stats.time_saved_ms += Self::estimate_computation_time(result);
        } else {
            stats.misses += 1;
        }
        result
    }

    /// Store a result in the cache.
    pub fn put(
        &self,
        key: DiffCacheKey,
        result: DiffResult,
        old_hashes: SectionHashes,
        new_hashes: SectionHashes,
    ) {
        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Evict oldest entries if at capacity
        while cache.len() >= self.config.max_entries {
            if let Some(oldest_key) = Self::find_oldest_entry(&cache) {
                cache.remove(&oldest_key);
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.evictions += 1;
            } else {
                break;
            }
        }

        cache.insert(key, CachedDiffResult::new(result, old_hashes, new_hashes));
    }

    /// Find the oldest cache entry.
    fn find_oldest_entry(cache: &HashMap<DiffCacheKey, CachedDiffResult>) -> Option<DiffCacheKey> {
        cache
            .iter()
            .max_by_key(|(_, entry)| entry.age())
            .map(|(key, _)| key.clone())
    }

    /// Estimate computation time based on result size.
    fn estimate_computation_time(result: &DiffResult) -> u64 {
        // Rough estimate: 1ms per 10 components
        let component_count = result.components.added.len()
            + result.components.removed.len()
            + result.components.modified.len();
        (component_count / 10).max(1) as u64
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        self.stats.read().expect("stats lock poisoned").clone()
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.clear();
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.read().expect("cache lock poisoned").len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().expect("cache lock poisoned").is_empty()
    }
}

impl Default for DiffCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Incremental Diff Engine
// ============================================================================

/// Metadata about the last diffed pair, used for incremental updates.
struct LastDiffMeta {
    /// Cache key of the last diffed pair
    key: DiffCacheKey,
    /// Section hashes from the last pair's old SBOM
    old_hashes: SectionHashes,
    /// Section hashes from the last pair's new SBOM
    new_hashes: SectionHashes,
}

/// A diff engine wrapper that supports incremental computation and caching.
///
/// Wraps the standard `DiffEngine` and adds:
/// - Result caching for repeated comparisons
/// - Section-level change detection
/// - Incremental recomputation for partial changes
pub struct IncrementalDiffEngine {
    /// The underlying diff engine
    engine: DiffEngine,
    /// Result cache
    cache: DiffCache,
    /// Track previous computation for incremental updates
    last_diff: RwLock<Option<LastDiffMeta>>,
}

impl IncrementalDiffEngine {
    /// Create a new incremental diff engine.
    #[must_use]
    pub fn new(engine: DiffEngine) -> Self {
        Self {
            engine,
            cache: DiffCache::new(),
            last_diff: RwLock::new(None),
        }
    }

    /// Create with custom cache configuration.
    #[must_use]
    pub fn with_cache_config(engine: DiffEngine, config: DiffCacheConfig) -> Self {
        Self {
            engine,
            cache: DiffCache::with_config(config),
            last_diff: RwLock::new(None),
        }
    }

    /// Perform a diff, using cache when possible.
    ///
    /// Returns the diff result and metadata about cache usage.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying diff computation fails.
    pub fn diff(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
    ) -> Result<IncrementalDiffResult, SbomDiffError> {
        let start = Instant::now();
        let cache_key = DiffCacheKey::from_sboms(old, new);

        // Check for exact cache hit
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(IncrementalDiffResult {
                result: (*cached).clone(),
                cache_hit: CacheHitType::Full,
                sections_recomputed: ChangedSections::default(),
                computation_time: start.elapsed(),
            });
        }

        // Compute section hashes
        let old_hashes = SectionHashes::from_sbom(old);
        let new_hashes = SectionHashes::from_sbom(new);

        // Check for incremental opportunity against the last diffed pair
        let (changed, prev_key) = {
            let last = self.last_diff.read().expect("last_diff lock poisoned");
            match &*last {
                Some(meta) => {
                    let old_changed = old_hashes != meta.old_hashes;
                    let new_changed = new_hashes != meta.new_hashes;

                    if !old_changed && !new_changed {
                        // Nothing changed, but we don't have the result cached
                        // This shouldn't normally happen, but fall through to full compute
                        (None, None)
                    } else {
                        (
                            Some(
                                meta.old_hashes
                                    .changed_sections(&old_hashes)
                                    .or(&meta.new_hashes.changed_sections(&new_hashes)),
                            ),
                            Some(meta.key.clone()),
                        )
                    }
                }
                None => (None, None),
            }
        };

        // Section-selective or full computation
        let (result, cache_hit, sections_recomputed) = if let Some(ref changed) = changed
            && let Some(ref prev_key) = prev_key
            && !changed.all()
            && changed.any()
        {
            // Change detection is relative to the last diffed pair, so only
            // that exact pair's cached result is a valid splice base
            if let Some(prev_result) = self.find_previous_result(prev_key) {
                match self.engine.diff_sections(old, new, changed, &prev_result) {
                    Ok(result) => (result, CacheHitType::Partial, changed.clone()),
                    Err(_) => {
                        // Fall back to full computation on diff_sections errors
                        let result = self.engine.diff(old, new)?;
                        (result, CacheHitType::Miss, ChangedSections::all_changed())
                    }
                }
            } else {
                // Last pair's entry was evicted or expired — full computation
                let result = self.engine.diff(old, new)?;
                (result, CacheHitType::Miss, ChangedSections::all_changed())
            }
        } else {
            // Either no change detection possible, or all sections changed — full computation
            let result = self.engine.diff(old, new)?;
            let sections = changed.unwrap_or_else(ChangedSections::all_changed);
            (result, CacheHitType::Miss, sections)
        };

        // Track incremental hits in cache stats
        if cache_hit == CacheHitType::Partial
            && let Ok(mut stats) = self.cache.stats.write()
        {
            stats.incremental_hits += 1;
        }

        // Cache the result
        self.cache.put(
            cache_key.clone(),
            result.clone(),
            old_hashes.clone(),
            new_hashes.clone(),
        );

        // Update last diff metadata
        *self.last_diff.write().expect("last_diff lock poisoned") = Some(LastDiffMeta {
            key: cache_key,
            old_hashes,
            new_hashes,
        });

        Ok(IncrementalDiffResult {
            result,
            cache_hit,
            sections_recomputed,
            computation_time: start.elapsed(),
        })
    }

    /// Find the last diffed pair's cached result to use as a base for
    /// incremental recomputation.
    ///
    /// Section change detection is computed against the last diffed pair, so
    /// only that exact pair's cached entry is a valid splice base.
    fn find_previous_result(&self, key: &DiffCacheKey) -> Option<Arc<DiffResult>> {
        let cache = self.cache.cache.read().ok()?;
        cache
            .get(key)
            .filter(|e| e.is_valid(self.cache.config.ttl))
            .map(|e| Arc::clone(&e.result))
    }

    /// Get the underlying engine.
    pub const fn engine(&self) -> &DiffEngine {
        &self.engine
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl ChangedSections {
    /// Combine two `ChangedSections` with OR logic.
    const fn or(&self, other: &Self) -> Self {
        Self {
            components: self.components || other.components,
            dependencies: self.dependencies || other.dependencies,
            licenses: self.licenses || other.licenses,
            vulnerabilities: self.vulnerabilities || other.vulnerabilities,
        }
    }
}

/// Type of cache hit achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHitType {
    /// Full result was in cache
    Full,
    /// Partial cache hit, some sections reused
    Partial,
    /// No cache hit, full computation required
    Miss,
}

/// Result of an incremental diff operation.
#[derive(Debug)]
pub struct IncrementalDiffResult {
    /// The diff result
    pub result: DiffResult,
    /// Type of cache hit
    pub cache_hit: CacheHitType,
    /// Which sections were recomputed (false = reused from cache)
    pub sections_recomputed: ChangedSections,
    /// Time taken for this operation
    pub computation_time: Duration,
}

impl IncrementalDiffResult {
    /// Get the diff result.
    pub fn into_result(self) -> DiffResult {
        self.result
    }

    /// Check if this was a cache hit.
    #[must_use]
    pub fn was_cached(&self) -> bool {
        self.cache_hit == CacheHitType::Full
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DocumentMetadata;

    fn make_sbom(name: &str, components: &[&str]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for comp_name in components {
            let comp = crate::model::Component::new(
                comp_name.to_string(),
                format!("{}-{}", name, comp_name),
            );
            sbom.add_component(comp);
        }
        // Ensure unique content hash
        sbom.content_hash = {
            use std::collections::hash_map::DefaultHasher;
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            for c in components {
                c.hash(&mut hasher);
            }
            hasher.finish()
        };
        sbom
    }

    #[test]
    fn test_section_hashes() {
        let sbom1 = make_sbom("test1", &["a", "b", "c"]);
        let sbom2 = make_sbom("test2", &["a", "b", "c"]);
        let sbom3 = make_sbom("test3", &["a", "b", "d"]);

        let hash1 = SectionHashes::from_sbom(&sbom1);
        let hash2 = SectionHashes::from_sbom(&sbom2);
        let hash3 = SectionHashes::from_sbom(&sbom3);

        // Different SBOMs with same components should have different component hashes
        // (because canonical IDs differ)
        assert_ne!(hash1.components, hash2.components);

        // Different components should definitely differ
        assert_ne!(hash1.components, hash3.components);
    }

    #[test]
    fn test_changed_sections() {
        let hash1 = SectionHashes {
            components: 100,
            dependencies: 200,
            licenses: 300,
            vulnerabilities: 400,
        };

        let hash2 = SectionHashes {
            components: 100,
            dependencies: 200,
            licenses: 999, // Changed
            vulnerabilities: 400,
        };

        let changed = hash1.changed_sections(&hash2);
        assert!(!changed.components);
        assert!(!changed.dependencies);
        assert!(changed.licenses);
        assert!(!changed.vulnerabilities);
        assert_eq!(changed.count(), 1);
    }

    #[test]
    fn test_diff_cache_basic() {
        let cache = DiffCache::new();
        let key = DiffCacheKey {
            old_hash: 123,
            new_hash: 456,
        };

        // Initially empty
        assert!(cache.get(&key).is_none());
        assert!(cache.is_empty());

        // Add a result
        let result = DiffResult::new();
        let hashes = SectionHashes {
            components: 0,
            dependencies: 0,
            licenses: 0,
            vulnerabilities: 0,
        };
        cache.put(key.clone(), result, hashes.clone(), hashes.clone());

        // Should be retrievable
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.len(), 1);

        // Stats should show 1 hit, 1 miss
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_diff_cache_eviction() {
        let config = DiffCacheConfig {
            max_entries: 3,
            ttl: Duration::from_secs(3600),
            enable_incremental: true,
        };
        let cache = DiffCache::with_config(config);

        let hashes = SectionHashes {
            components: 0,
            dependencies: 0,
            licenses: 0,
            vulnerabilities: 0,
        };

        // Add 5 entries, should only keep 3
        for i in 0..5 {
            let key = DiffCacheKey {
                old_hash: i,
                new_hash: i + 100,
            };
            cache.put(key, DiffResult::new(), hashes.clone(), hashes.clone());
        }

        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_cache_hit_type() {
        assert_eq!(CacheHitType::Full, CacheHitType::Full);
        assert_ne!(CacheHitType::Full, CacheHitType::Miss);
    }

    #[test]
    fn test_incremental_diff_engine() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        // First diff should be a miss
        let result1 = incremental.diff(&old, &new).expect("diff should succeed");
        assert_eq!(result1.cache_hit, CacheHitType::Miss);

        // Same diff should be a hit
        let result2 = incremental.diff(&old, &new).expect("diff should succeed");
        assert_eq!(result2.cache_hit, CacheHitType::Full);

        // Stats should reflect this
        let stats = incremental.cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_changed_sections_all_changed() {
        let all = ChangedSections::all_changed();
        assert!(all.components);
        assert!(all.dependencies);
        assert!(all.licenses);
        assert!(all.vulnerabilities);
        assert!(all.all());
        assert!(all.any());
        assert_eq!(all.count(), 4);
    }

    #[test]
    fn test_changed_sections_or_combine() {
        let a = ChangedSections {
            components: true,
            dependencies: false,
            licenses: false,
            vulnerabilities: false,
        };
        let b = ChangedSections {
            components: false,
            dependencies: false,
            licenses: true,
            vulnerabilities: false,
        };
        let combined = a.or(&b);
        assert!(combined.components);
        assert!(!combined.dependencies);
        assert!(combined.licenses);
        assert!(!combined.vulnerabilities);
        assert_eq!(combined.count(), 2);
    }

    #[test]
    fn test_diff_sections_selective_recomputation() {
        // Test that diff_sections on DiffEngine produces a valid result
        // when only a subset of sections are marked as changed
        let engine = DiffEngine::new();
        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        // Full diff first to get a baseline
        let full_result = engine.diff(&old, &new).expect("diff should succeed");

        // Now do a section-selective diff recomputing only components
        let sections = ChangedSections {
            components: true,
            dependencies: false,
            licenses: false,
            vulnerabilities: false,
        };
        let selective_result = engine
            .diff_sections(&old, &new, &sections, &full_result)
            .expect("diff_sections should succeed");

        // Components should be freshly computed — same as full diff
        assert_eq!(
            selective_result.components.added.len(),
            full_result.components.added.len()
        );
        assert_eq!(
            selective_result.components.removed.len(),
            full_result.components.removed.len()
        );
        assert_eq!(
            selective_result.components.modified.len(),
            full_result.components.modified.len()
        );

        // Dependencies were not recomputed — should be preserved from cached
        assert_eq!(
            selective_result.dependencies.added.len(),
            full_result.dependencies.added.len()
        );
        assert_eq!(
            selective_result.dependencies.removed.len(),
            full_result.dependencies.removed.len()
        );
    }

    #[test]
    fn test_diff_sections_all_changed_matches_full_diff() {
        // When all sections are marked as changed, diff_sections should produce
        // the same result as a full diff
        let engine = DiffEngine::new();
        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        let full_result = engine.diff(&old, &new).expect("diff should succeed");
        let sections = ChangedSections::all_changed();
        let selective_result = engine
            .diff_sections(&old, &new, &sections, &DiffResult::new())
            .expect("diff_sections should succeed");

        assert_eq!(
            selective_result.components.added.len(),
            full_result.components.added.len()
        );
        assert_eq!(
            selective_result.components.removed.len(),
            full_result.components.removed.len()
        );
        assert_eq!(
            selective_result.vulnerabilities.introduced.len(),
            full_result.vulnerabilities.introduced.len()
        );
    }

    #[test]
    fn test_incremental_partial_change_detection() {
        // Simulate the incremental path: diff two SBOMs, then diff again
        // with a slightly different new SBOM that shares the same old SBOM.
        // This tests that the engine detects partial changes and attempts
        // section-selective diff.
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b", "c"]);
        let new1 = make_sbom("new1", &["a", "b", "d"]);

        // First diff populates the last-diff metadata
        let result1 = incremental.diff(&old, &new1).expect("diff should succeed");
        assert_eq!(result1.cache_hit, CacheHitType::Miss);

        // Second diff with different SBOMs (different content hashes = no exact cache hit)
        // but the last-diff metadata is now set, so change detection runs
        let new2 = make_sbom("new2", &["a", "b", "e"]);
        let result2 = incremental.diff(&old, &new2).expect("diff should succeed");

        // This should either be a Partial hit (if section-selective kicked in)
        // or a Miss (if all sections changed). Either way, it should produce a valid result.
        assert!(
            result2.cache_hit == CacheHitType::Partial || result2.cache_hit == CacheHitType::Miss
        );
        // The result should have been computed successfully regardless
        assert!(result2.sections_recomputed.any());
    }

    #[test]
    fn test_find_previous_result_empty_cache() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);
        let key = DiffCacheKey {
            old_hash: 1,
            new_hash: 2,
        };
        // With an empty cache, find_previous_result should return None
        assert!(incremental.find_previous_result(&key).is_none());
    }

    #[test]
    fn test_find_previous_result_after_diff() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b"]);
        let new = make_sbom("new", &["a", "c"]);

        // Populate the cache
        let _ = incremental.diff(&old, &new).expect("diff should succeed");

        // The diffed pair's key should be retrievable; an unrelated key should not
        let key = DiffCacheKey::from_sboms(&old, &new);
        assert!(incremental.find_previous_result(&key).is_some());
        let other_key = DiffCacheKey {
            old_hash: key.old_hash.wrapping_add(1),
            new_hash: key.new_hash,
        };
        assert!(incremental.find_previous_result(&other_key).is_none());
    }

    fn assert_sections_match(actual: &DiffResult, expected: &DiffResult) {
        assert_eq!(
            actual.components.added.len(),
            expected.components.added.len()
        );
        assert_eq!(
            actual.components.removed.len(),
            expected.components.removed.len()
        );
        assert_eq!(
            actual.components.modified.len(),
            expected.components.modified.len()
        );
        assert_eq!(
            actual.licenses.new_licenses.len(),
            expected.licenses.new_licenses.len()
        );
        assert_eq!(
            actual.licenses.removed_licenses.len(),
            expected.licenses.removed_licenses.len()
        );
        assert_eq!(
            actual.vulnerabilities.introduced.len(),
            expected.vulnerabilities.introduced.len()
        );
        assert_eq!(
            actual.vulnerabilities.resolved.len(),
            expected.vulnerabilities.resolved.len()
        );
        assert_eq!(
            actual.dependencies.added.len(),
            expected.dependencies.added.len()
        );
        assert_eq!(
            actual.dependencies.removed.len(),
            expected.dependencies.removed.len()
        );
    }

    #[test]
    fn test_no_cross_pair_section_splice() {
        // Note: DiffEngine::diff has no constructible Err path today, so the
        // Result-propagation change is covered at the type level only.
        let incremental = IncrementalDiffEngine::new(DiffEngine::new());

        let a_old = make_sbom("a-old", &["a", "b", "c"]);
        let a_new = make_sbom("a-new", &["a", "b", "d"]);
        let b_old = make_sbom("b-old", &["x", "y"]);
        let b_new = make_sbom("b-new", &["x", "z", "w"]);

        // Pair A first, then pair B through the same engine
        let _ = incremental
            .diff(&a_old, &a_new)
            .expect("diff should succeed");
        let b_result = incremental
            .diff(&b_old, &b_new)
            .expect("diff should succeed");

        // Every section of B's result must match a from-scratch full diff —
        // no sections spliced in from pair A's cached result
        let fresh = DiffEngine::new()
            .diff(&b_old, &b_new)
            .expect("diff should succeed");
        assert_sections_match(&b_result.result, &fresh);
    }

    #[test]
    fn test_partial_splice_uses_last_pair_base() {
        let incremental = IncrementalDiffEngine::new(DiffEngine::new());

        let s0 = make_sbom("s0", &["a", "b", "c"]);
        let s1 = make_sbom("s1", &["a", "b", "d"]);
        let s2 = make_sbom("s2", &["a", "b", "e"]);

        // s0->s1 first so that s0->s2 only differs in the components section
        let _ = incremental.diff(&s0, &s1).expect("diff should succeed");
        let result = incremental.diff(&s0, &s2).expect("diff should succeed");
        assert_eq!(result.cache_hit, CacheHitType::Partial);

        // The spliced result must match a from-scratch full diff of s0->s2
        let fresh = DiffEngine::new()
            .diff(&s0, &s2)
            .expect("diff should succeed");
        assert_sections_match(&result.result, &fresh);
    }
}
