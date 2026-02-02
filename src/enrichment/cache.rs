//! File-based cache for vulnerability data.

use crate::error::Result;
use crate::model::VulnerabilityRef;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Cache key for vulnerability lookups.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// Package URL (preferred)
    pub purl: Option<String>,
    /// Component name
    pub name: String,
    /// Ecosystem (npm, pypi, etc.)
    pub ecosystem: Option<String>,
    /// Version
    pub version: Option<String>,
}

impl CacheKey {
    /// Create a cache key from component data.
    pub fn new(
        purl: Option<String>,
        name: String,
        ecosystem: Option<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            purl,
            name,
            ecosystem,
            version,
        }
    }

    /// Convert to a filesystem-safe filename using SHA256 hash.
    pub fn to_filename(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "purl:{:?}|name:{}|eco:{:?}|ver:{:?}",
            self.purl, self.name, self.ecosystem, self.version
        ));
        let hash = hasher.finalize();
        format!("{:x}.json", hash)
    }

    /// Check if this key can be used for an OSV query.
    pub fn is_queryable(&self) -> bool {
        // Need either a PURL or name + ecosystem + version
        self.purl.is_some() || (self.ecosystem.is_some() && self.version.is_some())
    }
}

/// File-based cache with TTL support.
pub struct FileCache {
    /// Cache directory
    cache_dir: PathBuf,
    /// Time-to-live for cached entries
    ttl: Duration,
}

impl FileCache {
    /// Create a new file cache.
    pub fn new(cache_dir: PathBuf, ttl: Duration) -> Result<Self> {
        // Ensure cache directory exists
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }
        Ok(Self { cache_dir, ttl })
    }

    /// Get cached vulnerabilities for a key.
    ///
    /// Returns None if not cached or cache is expired.
    pub fn get(&self, key: &CacheKey) -> Option<Vec<VulnerabilityRef>> {
        let path = self.cache_dir.join(key.to_filename());

        // Check if file exists
        let metadata = fs::metadata(&path).ok()?;

        // Check TTL
        let modified = metadata.modified().ok()?;
        let age = modified.elapsed().ok()?;
        if age > self.ttl {
            // Cache expired, remove it
            let _ = fs::remove_file(&path);
            return None;
        }

        // Read and parse
        let data = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Store vulnerabilities in the cache.
    pub fn set(&self, key: &CacheKey, vulns: &[VulnerabilityRef]) -> Result<()> {
        let path = self.cache_dir.join(key.to_filename());
        let data = serde_json::to_string(vulns)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Remove a cached entry.
    pub fn remove(&self, key: &CacheKey) -> Result<()> {
        let path = self.cache_dir.join(key.to_filename());
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Clear all cached entries.
    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let mut stats = CacheStats::default();

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
                {
                    stats.total_entries += 1;
                    if let Ok(metadata) = entry.metadata() {
                        stats.total_size += metadata.len();

                        // Check if expired
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(age) = modified.elapsed() {
                                if age > self.ttl {
                                    stats.expired_entries += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        stats
    }
}

/// Cache statistics.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Total number of cached entries
    pub total_entries: usize,
    /// Number of expired entries
    pub expired_entries: usize,
    /// Total size in bytes
    pub total_size: u64,
}
