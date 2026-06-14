//! File-based cache for vulnerability data.
//!
//! [`FileCache`] is the vulnerability-specific view over the shared
//! [`JsonCache`](super::source::JsonCache): it stores `Vec<VulnerabilityRef>`
//! payloads and inherits the shared cache's atomic writes, TTL eviction, and
//! schema-versioned envelope.

use super::source::{CacheStats, JsonCache};
use crate::error::Result;
use crate::model::VulnerabilityRef;
use std::path::PathBuf;
use std::time::Duration;

pub use super::source::CacheKey;

/// File-based cache of `Vec<VulnerabilityRef>` with TTL support.
pub struct FileCache {
    inner: JsonCache<Vec<VulnerabilityRef>>,
}

impl FileCache {
    /// Create a new file cache.
    pub fn new(cache_dir: PathBuf, ttl: Duration) -> Result<Self> {
        Ok(Self {
            inner: JsonCache::new(cache_dir, ttl)?,
        })
    }

    /// Get cached vulnerabilities for a key.
    ///
    /// Returns None if not cached or cache is expired.
    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<Vec<VulnerabilityRef>> {
        self.inner.get(key)
    }

    /// Store vulnerabilities in the cache.
    pub fn set(&self, key: &CacheKey, vulns: &[VulnerabilityRef]) -> Result<()> {
        self.inner.set(key, vulns)
    }

    /// Remove a cached entry.
    pub fn remove(&self, key: &CacheKey) -> Result<()> {
        self.inner.remove(key)
    }

    /// Clear all cached entries.
    pub fn clear(&self) -> Result<()> {
        self.inner.clear()
    }

    /// Get cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.inner.stats()
    }
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
