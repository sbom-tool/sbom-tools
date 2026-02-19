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
    #[must_use]
    pub const fn new(
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
    #[must_use]
    pub fn to_filename(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "purl:{:?}|name:{}|eco:{:?}|ver:{:?}",
            self.purl, self.name, self.ecosystem, self.version
        ));
        let hash = hasher.finalize();
        format!("{hash:x}.json")
    }

    /// Check if this key can be used for an OSV query.
    #[must_use]
    pub const fn is_queryable(&self) -> bool {
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
    #[must_use]
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
                if entry.path().extension().is_some_and(|e| e == "json") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }

    /// Get cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let mut stats = CacheStats::default();

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().is_some_and(|e| e == "json") {
                    stats.total_entries += 1;
                    if let Ok(metadata) = entry.metadata() {
                        stats.total_size += metadata.len();

                        // Check if expired
                        if let Ok(modified) = metadata.modified()
                            && let Ok(age) = modified.elapsed()
                            && age > self.ttl
                        {
                            stats.expired_entries += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(purl: Option<&str>, name: &str, eco: Option<&str>, ver: Option<&str>) -> CacheKey {
        CacheKey::new(
            purl.map(String::from),
            name.to_string(),
            eco.map(String::from),
            ver.map(String::from),
        )
    }

    #[test]
    fn test_cache_key_filename_deterministic() {
        let key = make_key(Some("pkg:npm/foo@1.0"), "foo", Some("npm"), Some("1.0"));
        let f1 = key.to_filename();
        let f2 = key.to_filename();
        assert_eq!(f1, f2);
        assert!(f1.ends_with(".json"));
    }

    #[test]
    fn test_cache_key_filename_different() {
        let k1 = make_key(Some("pkg:npm/foo@1.0"), "foo", Some("npm"), Some("1.0"));
        let k2 = make_key(Some("pkg:npm/bar@1.0"), "bar", Some("npm"), Some("1.0"));
        assert_ne!(k1.to_filename(), k2.to_filename());
    }

    #[test]
    fn test_cache_key_is_queryable_purl() {
        let key = make_key(Some("pkg:npm/foo@1.0"), "foo", None, None);
        assert!(key.is_queryable());
    }

    #[test]
    fn test_cache_key_is_queryable_eco_ver() {
        let key = make_key(None, "foo", Some("npm"), Some("1.0"));
        assert!(key.is_queryable());
    }

    #[test]
    fn test_cache_key_is_queryable_name_only() {
        let key = make_key(None, "foo", None, None);
        assert!(!key.is_queryable());
    }

    #[test]
    fn test_file_cache_new_creates_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("vuln_cache");
        assert!(!cache_dir.exists());
        let _cache = FileCache::new(cache_dir.clone(), Duration::from_secs(3600)).unwrap();
        assert!(cache_dir.exists());
    }

    #[test]
    fn test_file_cache_set_get_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        let key = make_key(Some("pkg:npm/foo@1.0"), "foo", Some("npm"), Some("1.0"));

        let vulns = vec![VulnerabilityRef::new(
            "CVE-2024-0001".to_string(),
            crate::model::VulnerabilitySource::Osv,
        )];

        cache.set(&key, &vulns).unwrap();
        let result = cache.get(&key);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].id, "CVE-2024-0001");
    }

    #[test]
    fn test_file_cache_get_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        let key = make_key(Some("pkg:npm/nope@1.0"), "nope", Some("npm"), Some("1.0"));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_file_cache_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        let key = make_key(Some("pkg:npm/rm@1.0"), "rm", Some("npm"), Some("1.0"));

        cache.set(&key, &[]).unwrap();
        assert!(cache.get(&key).is_some());
        cache.remove(&key).unwrap();
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_file_cache_clear() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();

        for i in 0..3 {
            let key = make_key(None, &format!("pkg{i}"), Some("npm"), Some("1.0"));
            cache.set(&key, &[]).unwrap();
        }

        assert_eq!(cache.stats().total_entries, 3);
        cache.clear().unwrap();
        assert_eq!(cache.stats().total_entries, 0);
    }

    #[test]
    fn test_file_cache_stats_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();

        for i in 0..3 {
            let key = make_key(None, &format!("stats{i}"), Some("npm"), Some("1.0"));
            cache.set(&key, &[]).unwrap();
        }

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.expired_entries, 0);
    }
}
