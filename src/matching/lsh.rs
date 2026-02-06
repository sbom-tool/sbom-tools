//! Locality-Sensitive Hashing (LSH) for approximate nearest neighbor search.
//!
//! This module provides MinHash LSH for efficient similarity search on large SBOMs
//! (10,000+ components). It trades some accuracy for dramatic speed improvements
//! by using hash-based approximate matching.
//!
//! # How it works
//!
//! 1. Each component name is converted to a set of character shingles (n-grams)
//! 2. MinHash signatures are computed for each shingle set
//! 3. Signatures are divided into bands and hashed into buckets
//! 4. Components in the same bucket are candidate matches
//!
//! # Performance
//!
//! - Build time: O(n × k) where k = signature size
//! - Query time: O(1) average for bucket lookup + O(m) for candidates
//! - Space: O(n × k) for signatures

use super::index::ComponentIndex;
use crate::model::{CanonicalId, Component, NormalizedSbom};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

/// Configuration for LSH index.
#[derive(Debug, Clone)]
pub struct LshConfig {
    /// Number of hash functions in the MinHash signature
    pub num_hashes: usize,
    /// Number of bands to divide the signature into
    pub num_bands: usize,
    /// Size of character shingles (n-grams)
    pub shingle_size: usize,
    /// Minimum Jaccard similarity threshold this config is tuned for
    pub target_threshold: f64,
    /// Include ecosystem as a token in shingles (improves grouping by ecosystem)
    pub include_ecosystem_token: bool,
    /// Include group/namespace as a token in shingles (useful for Maven, npm scopes)
    pub include_group_token: bool,
}

impl LshConfig {
    /// Create a config tuned for the given similarity threshold.
    ///
    /// The number of bands and rows are chosen to maximize the probability
    /// of finding pairs with similarity >= threshold while minimizing false positives.
    pub fn for_threshold(threshold: f64) -> Self {
        // For threshold t, optimal parameters satisfy: t ≈ (1/b)^(1/r)
        // where b = bands, r = rows per band, and b × r = num_hashes
        //
        // Common configurations:
        // - t=0.5: b=20, r=5 (100 hashes)
        // - t=0.8: b=50, r=2 (100 hashes)
        // - t=0.9: b=90, r=1 (90 hashes) - but this is just exact bucketing

        let (num_bands, rows_per_band) = if threshold >= 0.9 {
            (50, 2) // 100 hashes, catches ~90%+ similar
        } else if threshold >= 0.8 {
            (25, 4) // 100 hashes, catches ~80%+ similar
        } else if threshold >= 0.7 {
            (20, 5) // 100 hashes, catches ~70%+ similar
        } else if threshold >= 0.5 {
            (10, 10) // 100 hashes, catches ~50%+ similar
        } else {
            (5, 20) // 100 hashes, very permissive
        };

        Self {
            num_hashes: num_bands * rows_per_band,
            num_bands,
            shingle_size: 3, // Trigrams work well for package names
            target_threshold: threshold,
            include_ecosystem_token: true,  // Helps group by ecosystem
            include_group_token: false,     // Optional, disabled by default
        }
    }

    /// Default config for balanced matching (~0.8 threshold).
    pub fn default_balanced() -> Self {
        Self::for_threshold(0.8)
    }

    /// Config for strict matching (~0.9 threshold).
    pub fn strict() -> Self {
        Self::for_threshold(0.9)
    }

    /// Config for permissive matching (~0.5 threshold).
    pub fn permissive() -> Self {
        Self::for_threshold(0.5)
    }

    /// Get rows per band (signature elements per band).
    pub fn rows_per_band(&self) -> usize {
        self.num_hashes / self.num_bands
    }
}

impl Default for LshConfig {
    fn default() -> Self {
        Self::default_balanced()
    }
}

/// MinHash signature for a component.
#[derive(Debug, Clone)]
pub struct MinHashSignature {
    /// The hash values (one per hash function)
    pub values: Vec<u64>,
}

impl MinHashSignature {
    /// Compute the estimated Jaccard similarity between two signatures.
    pub fn estimated_similarity(&self, other: &Self) -> f64 {
        if self.values.len() != other.values.len() {
            return 0.0;
        }

        let matching = self
            .values
            .iter()
            .zip(other.values.iter())
            .filter(|(a, b)| a == b)
            .count();

        matching as f64 / self.values.len() as f64
    }
}

/// LSH index for efficient approximate nearest neighbor search.
pub struct LshIndex {
    /// Configuration
    config: LshConfig,
    /// MinHash signatures for each component
    signatures: HashMap<CanonicalId, MinHashSignature>,
    /// Band buckets: band_index -> bucket_hash -> component IDs
    buckets: Vec<HashMap<u64, Vec<CanonicalId>>>,
    /// Hash coefficients for MinHash (a, b pairs for h(x) = (ax + b) mod p)
    hash_coeffs: Vec<(u64, u64)>,
    /// Large prime for hashing
    prime: u64,
}

impl LshIndex {
    /// Create a new LSH index with the given configuration.
    pub fn new(config: LshConfig) -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::BuildHasher;

        // Generate random hash coefficients
        let mut hash_coeffs = Vec::with_capacity(config.num_hashes);
        let random_state = RandomState::new();

        for i in 0..config.num_hashes {
            let a = random_state.hash_one(i as u64 * 31337) | 1; // Ensure odd (coprime with 2^64)

            let b = random_state.hash_one(i as u64 * 7919 + 12345);

            hash_coeffs.push((a, b));
        }

        // Initialize empty buckets for each band
        let buckets = (0..config.num_bands)
            .map(|_| HashMap::with_capacity(64))
            .collect();

        Self {
            config,
            signatures: HashMap::with_capacity(256),
            buckets,
            hash_coeffs,
            prime: 0xFFFFFFFFFFFFFFC5, // Large prime close to 2^64
        }
    }

    /// Build an LSH index from an SBOM.
    pub fn build(sbom: &NormalizedSbom, config: LshConfig) -> Self {
        let mut index = Self::new(config);

        for (id, comp) in &sbom.components {
            index.insert(id.clone(), comp);
        }

        index
    }

    /// Insert a component into the index.
    pub fn insert(&mut self, id: CanonicalId, component: &Component) {
        // Compute shingles from the component (uses ecosystem-aware normalization)
        let shingles = self.compute_shingles(component);

        // Compute MinHash signature
        let signature = self.compute_minhash(&shingles);

        // Insert into band buckets
        self.insert_into_buckets(&id, &signature);

        // Store signature
        self.signatures.insert(id, signature);
    }

    /// Find candidate matches for a component.
    ///
    /// Returns component IDs that are likely similar based on LSH buckets.
    /// These candidates should be verified with exact similarity computation.
    pub fn find_candidates(&self, component: &Component) -> Vec<CanonicalId> {
        let shingles = self.compute_shingles(component);
        let signature = self.compute_minhash(&shingles);

        self.find_candidates_by_signature(&signature)
    }

    /// Find candidates using a pre-computed signature.
    pub fn find_candidates_by_signature(&self, signature: &MinHashSignature) -> Vec<CanonicalId> {
        let mut candidates = HashSet::new();
        let rows_per_band = self.config.rows_per_band();

        for (band_idx, bucket_map) in self.buckets.iter().enumerate() {
            let band_hash = self.hash_band(signature, band_idx, rows_per_band);

            if let Some(ids) = bucket_map.get(&band_hash) {
                for id in ids {
                    candidates.insert(id.clone());
                }
            }
        }

        candidates.into_iter().collect()
    }

    /// Find candidates for a component from another index.
    ///
    /// Useful for diffing: build index from new SBOM, query with old SBOM components.
    pub fn find_candidates_for_id(&self, id: &CanonicalId) -> Vec<CanonicalId> {
        if let Some(signature) = self.signatures.get(id) {
            self.find_candidates_by_signature(signature)
        } else {
            Vec::new()
        }
    }

    /// Get the MinHash signature for a component.
    pub fn get_signature(&self, id: &CanonicalId) -> Option<&MinHashSignature> {
        self.signatures.get(id)
    }

    /// Estimate similarity between two components in the index.
    pub fn estimate_similarity(&self, id_a: &CanonicalId, id_b: &CanonicalId) -> Option<f64> {
        let sig_a = self.signatures.get(id_a)?;
        let sig_b = self.signatures.get(id_b)?;
        Some(sig_a.estimated_similarity(sig_b))
    }

    /// Get statistics about the index.
    pub fn stats(&self) -> LshIndexStats {
        let total_components = self.signatures.len();
        let total_buckets: usize = self.buckets.iter().map(std::collections::HashMap::len).sum();
        let max_bucket_size = self
            .buckets
            .iter()
            .flat_map(|b| b.values())
            .map(std::vec::Vec::len)
            .max()
            .unwrap_or(0);
        let avg_bucket_size = if total_buckets > 0 {
            self.buckets
                .iter()
                .flat_map(|b| b.values())
                .map(std::vec::Vec::len)
                .sum::<usize>() as f64
                / total_buckets as f64
        } else {
            0.0
        };

        LshIndexStats {
            total_components,
            num_bands: self.config.num_bands,
            num_hashes: self.config.num_hashes,
            total_buckets,
            max_bucket_size,
            avg_bucket_size,
        }
    }

    /// Compute character shingles (n-grams) from a component.
    ///
    /// Uses ecosystem-aware normalization from ComponentIndex for consistent
    /// shingling across PyPI, Cargo, npm, etc. Also adds optional ecosystem
    /// and group tokens to improve candidate grouping.
    fn compute_shingles(&self, component: &Component) -> HashSet<u64> {
        // Get ecosystem for normalization
        let ecosystem = component.ecosystem.as_ref().map(std::string::ToString::to_string);
        let ecosystem_str = ecosystem.as_deref();

        // Use ComponentIndex's normalization for consistency
        let normalized = ComponentIndex::normalize_name(&component.name, ecosystem_str);
        let chars: Vec<char> = normalized.chars().collect();

        // Estimate capacity: roughly (len - shingle_size + 1) shingles + 2 tokens
        let estimated_shingles = chars.len().saturating_sub(self.config.shingle_size) + 3;
        let mut shingles = HashSet::with_capacity(estimated_shingles);

        // Compute name shingles
        if chars.len() < self.config.shingle_size {
            // For very short names, use the whole name as a shingle
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            normalized.hash(&mut hasher);
            shingles.insert(hasher.finish());
        } else {
            // Hash character windows directly without allocating intermediate strings
            for window in chars.windows(self.config.shingle_size) {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                window.hash(&mut hasher);
                shingles.insert(hasher.finish());
            }
        }

        // Add ecosystem token (helps group components by ecosystem)
        if self.config.include_ecosystem_token {
            if let Some(ref eco) = ecosystem {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                "__eco:".hash(&mut hasher);
                eco.to_lowercase().hash(&mut hasher);
                shingles.insert(hasher.finish());
            }
        }

        // Add group/namespace token (useful for Maven group IDs, npm scopes)
        if self.config.include_group_token {
            if let Some(ref group) = component.group {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                "__grp:".hash(&mut hasher);
                group.to_lowercase().hash(&mut hasher);
                shingles.insert(hasher.finish());
            }
        }

        shingles
    }

    /// Compute MinHash signature from shingles.
    fn compute_minhash(&self, shingles: &HashSet<u64>) -> MinHashSignature {
        let mut min_hashes = vec![u64::MAX; self.config.num_hashes];

        for &shingle in shingles {
            for (i, &(a, b)) in self.hash_coeffs.iter().enumerate() {
                // h_i(x) = (a*x + b) mod prime
                let hash = a.wrapping_mul(shingle).wrapping_add(b) % self.prime;
                if hash < min_hashes[i] {
                    min_hashes[i] = hash;
                }
            }
        }

        MinHashSignature { values: min_hashes }
    }

    /// Insert a signature into band buckets.
    fn insert_into_buckets(&mut self, id: &CanonicalId, signature: &MinHashSignature) {
        let rows_per_band = self.config.rows_per_band();

        // Pre-compute all band hashes to avoid borrow conflicts
        let band_hashes: Vec<u64> = (0..self.config.num_bands)
            .map(|band_idx| self.hash_band(signature, band_idx, rows_per_band))
            .collect();

        for (band_idx, bucket_map) in self.buckets.iter_mut().enumerate() {
            bucket_map
                .entry(band_hashes[band_idx])
                .or_default()
                .push(id.clone());
        }
    }

    /// Hash a band of the signature.
    fn hash_band(
        &self,
        signature: &MinHashSignature,
        band_idx: usize,
        rows_per_band: usize,
    ) -> u64 {
        let start = band_idx * rows_per_band;
        let end = (start + rows_per_band).min(signature.values.len());

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for &value in &signature.values[start..end] {
            value.hash(&mut hasher);
        }
        hasher.finish()
    }
}

/// Statistics about an LSH index.
#[derive(Debug, Clone)]
pub struct LshIndexStats {
    /// Total number of indexed components
    pub total_components: usize,
    /// Number of bands
    pub num_bands: usize,
    /// Total number of hash functions
    pub num_hashes: usize,
    /// Total number of non-empty buckets
    pub total_buckets: usize,
    /// Maximum components in a single bucket
    pub max_bucket_size: usize,
    /// Average components per bucket
    pub avg_bucket_size: f64,
}

impl std::fmt::Display for LshIndexStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LSH Index: {} components, {} bands × {} hashes, {} buckets (max: {}, avg: {:.1})",
            self.total_components,
            self.num_bands,
            self.num_hashes / self.num_bands,
            self.total_buckets,
            self.max_bucket_size,
            self.avg_bucket_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DocumentMetadata;

    fn make_component(name: &str) -> Component {
        Component::new(name.to_string(), format!("id-{}", name))
    }

    #[test]
    fn test_lsh_config_for_threshold() {
        let config = LshConfig::for_threshold(0.8);
        assert_eq!(config.num_hashes, 100);
        assert!(config.num_bands > 0);
        assert_eq!(config.num_hashes, config.num_bands * config.rows_per_band());
    }

    #[test]
    fn test_minhash_signature_similarity() {
        let sig_a = MinHashSignature {
            values: vec![1, 2, 3, 4, 5],
        };
        let sig_b = MinHashSignature {
            values: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(sig_a.estimated_similarity(&sig_b), 1.0);

        let sig_c = MinHashSignature {
            values: vec![1, 2, 3, 6, 7],
        };
        assert!((sig_a.estimated_similarity(&sig_c) - 0.6).abs() < 0.01);
    }

    #[test]
    fn test_lsh_index_build() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(make_component("lodash"));
        sbom.add_component(make_component("lodash-es"));
        sbom.add_component(make_component("underscore"));
        sbom.add_component(make_component("react"));

        let index = LshIndex::build(&sbom, LshConfig::default_balanced());
        let stats = index.stats();

        assert_eq!(stats.total_components, 4);
        assert!(stats.total_buckets > 0);
    }

    #[test]
    fn test_lsh_finds_similar_names() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(make_component("lodash"));
        sbom.add_component(make_component("lodash-es"));
        sbom.add_component(make_component("lodash-fp"));
        sbom.add_component(make_component("react"));
        sbom.add_component(make_component("angular"));

        let index = LshIndex::build(&sbom, LshConfig::for_threshold(0.5));

        // Query for similar to "lodash"
        let query = make_component("lodash");
        let candidates = index.find_candidates(&query);

        // Should find lodash variants as candidates
        // Note: LSH is probabilistic, so we check for likely outcomes
        assert!(
            !candidates.is_empty(),
            "Should find at least some candidates"
        );
    }

    #[test]
    fn test_lsh_signature_estimation() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());

        let comp1 = make_component("lodash");
        let comp2 = make_component("lodash-es");
        let comp3 = make_component("completely-different-name");

        let id1 = comp1.canonical_id.clone();
        let id2 = comp2.canonical_id.clone();
        let id3 = comp3.canonical_id.clone();

        sbom.add_component(comp1);
        sbom.add_component(comp2);
        sbom.add_component(comp3);

        let index = LshIndex::build(&sbom, LshConfig::default_balanced());

        // Similar names should have higher estimated similarity
        let sim_12 = index.estimate_similarity(&id1, &id2).unwrap();
        let sim_13 = index.estimate_similarity(&id1, &id3).unwrap();

        assert!(
            sim_12 > sim_13,
            "lodash vs lodash-es ({:.2}) should be more similar than lodash vs completely-different ({:.2})",
            sim_12, sim_13
        );
    }

    #[test]
    fn test_lsh_index_stats() {
        let config = LshConfig::for_threshold(0.8);
        let index = LshIndex::new(config);

        let stats = index.stats();
        assert_eq!(stats.total_components, 0);
        assert_eq!(stats.num_bands, 25);
        assert_eq!(stats.num_hashes, 100);
    }
}
