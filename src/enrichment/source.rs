//! Shared enrichment infrastructure: cache directory, HTTP client, retry
//! policy, and a generic versioned file cache.
//!
//! Every enrichment source (OSV, KEV, EOL, staleness) used to carry its own
//! copy of the platform cache-directory shim and an ad-hoc, non-atomic
//! mtime-TTL JSON file cache. This module centralizes that plumbing:
//!
//! - [`cache_dir`] / [`namespaced_cache_dir`] — one platform-aware helper.
//! - [`http_client`] — one [`reqwest::blocking::Client`] builder with a
//!   consistent `CARGO_PKG_NAME/CARGO_PKG_VERSION` User-Agent.
//! - [`get_with_retry`] — a shared retry policy honoring `429`/`Retry-After`
//!   with bounded exponential backoff.
//! - [`JsonCache`] — a generic file cache with **atomic** writes
//!   (temp-file + rename) and a `schema_version` envelope so that a version
//!   bump transparently invalidates stale entries.

use crate::error::Result;
use crate::model::Component;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Process-global offline switch.
///
/// In air-gapped (CRA / FDA / defense) deployments the tool must serve
/// enrichment data purely from cache and never attempt a network call. This is
/// a process-wide flag rather than per-config because the HTTP choke point
/// ([`http_client`]) and the cache ([`JsonCache`]) are reached through many
/// independently-constructed source configs; threading a bool through every one
/// would be invasive and easy to miss. It is set once, early, from the global
/// `--offline` flag / `SBOM_TOOLS_OFFLINE` env.
static OFFLINE: AtomicBool = AtomicBool::new(false);

/// Enable or disable offline mode for the whole process.
pub fn set_offline(offline: bool) {
    OFFLINE.store(offline, Ordering::Relaxed);
}

/// Whether the process is running in offline mode.
#[must_use]
pub fn is_offline() -> bool {
    OFFLINE.load(Ordering::Relaxed)
}

/// Schema version embedded in every cache envelope.
///
/// Bumping this value invalidates all previously written cache entries: any
/// envelope whose `schema_version` does not match is treated as a miss (and
/// removed) so a changed payload shape can never be deserialized as the old
/// one.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Cache directory
// ============================================================================

/// Platform-specific base cache directory.
///
/// - macOS: `$HOME/Library/Caches`
/// - Linux: `$XDG_CACHE_HOME` or `$HOME/.cache`
/// - Windows: `%LOCALAPPDATA%`
/// - other: `$HOME/.cache`
///
/// Returns `None` when the relevant environment variables are unset.
#[must_use]
pub fn cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Caches"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CACHE_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".cache"))
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache"))
    }
}

/// Root cache directory for all enrichment sources, i.e. `…/sbom-tools`.
///
/// This is the parent of every per-source namespace directory; the `cache`
/// subcommand uses it to enumerate, size, export, and import the cache as a
/// whole. Falls back to a `.cache`-relative path when no platform cache
/// directory is available, matching [`namespaced_cache_dir`].
#[must_use]
pub fn root_cache_dir() -> PathBuf {
    cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("sbom-tools")
}

/// Cache directory for an enrichment source, e.g. `…/sbom-tools/osv`.
///
/// Falls back to a `.cache`-relative path only when no platform cache
/// directory is available, matching the previous per-source behavior.
#[must_use]
pub fn namespaced_cache_dir(namespace: &str) -> PathBuf {
    root_cache_dir().join(namespace)
}

// ============================================================================
// HTTP client + retry policy
// ============================================================================

/// Build the shared blocking HTTP client used by all enrichment sources.
///
/// All sources share the same `CARGO_PKG_NAME/CARGO_PKG_VERSION` User-Agent so
/// upstream registries see a single, identifiable client.
/// Refuse a network operation when the process is in offline mode.
///
/// Building a [`reqwest`] client makes no network call, so [`http_client`] is
/// not gated; the guard is applied at the request-dispatch layer
/// ([`get_with_retry`] and each source's direct `.send()`) so that a warm cache
/// is still served before any refusal. `what` describes the resource the caller
/// was about to fetch, for a clear "offline: not in cache (<what>)" error.
pub fn offline_guard(what: &str) -> Result<()> {
    if is_offline() {
        return Err(crate::error::SbomDiffError::enrichment(
            "offline mode",
            crate::error::EnrichmentErrorKind::Offline(what.to_string()),
        ));
    }
    Ok(())
}

#[cfg(feature = "enrichment")]
pub fn http_client(timeout: Duration) -> reqwest::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
}

/// Maximum backoff applied between retries, regardless of attempt count or a
/// server-provided `Retry-After`.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Upper bound on a single enrichment response body, in bytes.
///
/// Enrichment responses are read fully into memory (the EPSS CSV into a
/// `HashMap`, the KEV/HuggingFace JSON into structs). Without a cap a malicious
/// or MITM'd endpoint advertising (or streaming) a huge body could OOM the
/// process. The largest legitimate payload is the full daily EPSS dataset
/// (~10-20 MB uncompressed); 256 MiB is a generous-but-finite ceiling that no
/// real source approaches.
pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// Read a response body into memory, refusing bodies larger than
/// [`MAX_RESPONSE_BYTES`].
///
/// The cap is enforced twice: first against a declared `Content-Length` (a cheap
/// up-front reject), then against the actually-buffered length (a defense against
/// a lying or absent header). The returned bytes are guaranteed `<= MAX`.
#[cfg(feature = "enrichment")]
pub fn read_bounded(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    read_bounded_with_max(response, MAX_RESPONSE_BYTES)
}

/// [`read_bounded`] with an explicit cap.
///
/// Split out so the cap behavior can be exercised against a real (small)
/// response without having to transmit a 256 MiB body in tests.
#[cfg(feature = "enrichment")]
pub(crate) fn read_bounded_with_max(
    response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    if let Some(len) = response.content_length()
        && len > max_bytes
    {
        return Err(oversized_error(len, max_bytes));
    }

    let bytes = response
        .bytes()
        .map_err(|e| network_error("reading response body", &e))?;

    if bytes.len() as u64 > max_bytes {
        return Err(oversized_error(bytes.len() as u64, max_bytes));
    }

    Ok(bytes.to_vec())
}

/// Build the "response too large" enrichment error.
#[cfg(feature = "enrichment")]
fn oversized_error(len: u64, max_bytes: u64) -> crate::error::SbomDiffError {
    crate::error::SbomDiffError::enrichment(
        "response too large",
        crate::error::EnrichmentErrorKind::NetworkError(format!(
            "response body of {len} bytes exceeds the {max_bytes}-byte limit"
        )),
    )
}

/// Compute the backoff delay before retry `attempt` (1-based).
///
/// Honors a server-provided `Retry-After` (seconds) when present, otherwise
/// applies bounded exponential backoff (1s, 2s, 4s, …) capped at
/// [`MAX_BACKOFF`].
#[must_use]
pub fn backoff_delay(attempt: u32, retry_after: Option<Duration>) -> Duration {
    if let Some(after) = retry_after {
        return after.min(MAX_BACKOFF);
    }
    let secs = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

/// Parse a `Retry-After` header value expressed as a number of seconds.
///
/// The HTTP-date form of `Retry-After` is not supported (registries used here
/// only emit the delta-seconds form); unparseable values yield `None`.
#[cfg(feature = "enrichment")]
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Perform a `GET` with the shared retry policy.
///
/// Retries on transport errors and on `429`/`5xx` responses up to
/// `max_retries` times, honoring `Retry-After` on `429`. Non-retryable
/// responses (including `4xx` other than `429`) are returned to the caller on
/// the first attempt for status inspection.
///
/// In offline mode the request is refused up front with an
/// [`EnrichmentErrorKind::Offline`](crate::error::EnrichmentErrorKind::Offline)
/// error before any socket is opened.
#[cfg(feature = "enrichment")]
pub fn get_with_retry(
    client: &reqwest::blocking::Client,
    url: &str,
    max_retries: u8,
) -> Result<reqwest::blocking::Response> {
    offline_guard(url)?;

    for attempt in 0..=u32::from(max_retries) {
        if attempt > 0 {
            tracing::debug!("retry attempt {attempt} for {url}");
        }

        match client.get(url).send() {
            Ok(response) => {
                let status = response.status();
                let retryable =
                    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
                if retryable && attempt < u32::from(max_retries) {
                    let retry_after = if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        parse_retry_after(response.headers())
                    } else {
                        None
                    };
                    std::thread::sleep(backoff_delay(attempt + 1, retry_after));
                    continue;
                }
                return Ok(response);
            }
            Err(e) => {
                if attempt < u32::from(max_retries) {
                    std::thread::sleep(backoff_delay(attempt + 1, None));
                    continue;
                }
                return Err(network_error("request failed", &e));
            }
        }
    }

    // Unreachable in practice: the loop always returns on the final attempt.
    Err(network_error_msg("retry loop returned no response"))
}

/// Wrap a [`reqwest::Error`] in our enrichment network-error variant.
#[cfg(feature = "enrichment")]
fn network_error(context: &str, err: &reqwest::Error) -> crate::error::SbomDiffError {
    crate::error::SbomDiffError::enrichment(
        context,
        crate::error::EnrichmentErrorKind::NetworkError(err.to_string()),
    )
}

/// Build a network-error variant from a bare message.
#[cfg(feature = "enrichment")]
fn network_error_msg(msg: &str) -> crate::error::SbomDiffError {
    crate::error::SbomDiffError::enrichment(
        "network",
        crate::error::EnrichmentErrorKind::NetworkError(msg.to_string()),
    )
}

// ============================================================================
// Cache key
// ============================================================================

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
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("{hex}.json")
    }

    /// Check if this key can be used for an OSV query.
    #[must_use]
    pub const fn is_queryable(&self) -> bool {
        // Need either a PURL or name + ecosystem + version
        self.purl.is_some() || (self.ecosystem.is_some() && self.version.is_some())
    }
}

// ============================================================================
// Generic versioned file cache
// ============================================================================

/// Envelope wrapping every cached payload with a schema version.
///
/// The version is checked on read; a mismatch is treated as a miss so a
/// changed payload shape can never be deserialized as the old one.
#[derive(Debug, Serialize, serde::Deserialize)]
struct CacheEnvelope<T> {
    /// Schema version of the embedded payload.
    schema_version: u32,
    /// The cached value.
    payload: T,
}

/// A generic file-based cache with atomic writes, TTL, and schema versioning.
///
/// Each entry is a JSON file under `cache_dir` whose name derives from the
/// entry key. Writes go to a temporary sibling file that is then renamed over
/// the target, so a reader never observes a torn write. Reads enforce both the
/// configured TTL (via file mtime) and the [`CACHE_SCHEMA_VERSION`] envelope.
pub struct JsonCache<T> {
    cache_dir: PathBuf,
    ttl: Duration,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> JsonCache<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create a cache rooted at `cache_dir`, creating the directory if needed.
    pub fn new(cache_dir: PathBuf, ttl: Duration) -> Result<Self> {
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }
        Ok(Self {
            cache_dir,
            ttl,
            _marker: std::marker::PhantomData,
        })
    }

    /// Path for a named entry (the name must already be filesystem-safe).
    #[must_use]
    pub fn path_for(&self, file_name: &str) -> PathBuf {
        self.cache_dir.join(file_name)
    }

    /// Cache directory root.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Read a cached value by file name.
    ///
    /// Returns `None` (evicting the file) when the entry is missing, older
    /// than the TTL, has a mismatched schema version, or fails to parse.
    ///
    /// One exception: in process-wide [offline](is_offline) mode a TTL-expired
    /// entry is **served** (and *not* evicted) so an air-gapped run can fall
    /// back to whatever data is on disk. A staleness warning is logged. The
    /// online path is unchanged — expired entries are still evicted on read.
    #[must_use]
    pub fn get_named(&self, file_name: &str) -> Option<T> {
        let (value, stale_by) = self.get_named_allow_stale(file_name)?;
        if let Some(age) = stale_by {
            tracing::warn!(
                "serving stale cache entry {file_name}: {} day(s) past its TTL (offline mode)",
                age.as_secs() / 86_400
            );
        }
        Some(value)
    }

    /// Read a cached value, tolerating TTL expiry when offline.
    ///
    /// Returns the payload together with a staleness signal: `Some(age)` is the
    /// amount the entry is *past* its TTL when it was served despite being
    /// expired (only possible in offline mode), or `None` when the entry was
    /// still fresh.
    ///
    /// Unlike [`get_named`](Self::get_named), this never logs; it is the
    /// building block callers use when they want to surface the staleness
    /// (e.g. as CRA evidence) rather than only warn.
    #[must_use]
    pub fn get_named_allow_stale(&self, file_name: &str) -> Option<(T, Option<Duration>)> {
        let path = self.path_for(file_name);

        let metadata = fs::metadata(&path).ok()?;
        let modified = metadata.modified().ok()?;
        let age = modified.elapsed().ok()?;
        let mut stale_by = None;
        if age > self.ttl {
            // Online: an expired entry is a miss and is evicted on read (the
            // E1 cache tests assert this). Offline: keep it and serve it so an
            // air-gapped run has a stale-if-offline fallback.
            if is_offline() {
                stale_by = Some(age - self.ttl);
            } else {
                let _ = fs::remove_file(&path);
                return None;
            }
        }

        let data = fs::read_to_string(&path).ok()?;
        let envelope: CacheEnvelope<T> = serde_json::from_str(&data).ok()?;
        if envelope.schema_version != CACHE_SCHEMA_VERSION {
            // A schema mismatch is a hard miss in every mode: the payload shape
            // changed and must never be deserialized as the old one.
            let _ = fs::remove_file(&path);
            return None;
        }
        Some((envelope.payload, stale_by))
    }

    /// Atomically write a value under `file_name`.
    pub fn set_named<V: Serialize + ?Sized>(&self, file_name: &str, value: &V) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir)?;
        }
        let envelope = CacheEnvelope {
            schema_version: CACHE_SCHEMA_VERSION,
            payload: value,
        };
        let data = serde_json::to_string(&envelope)?;
        write_atomic(&self.path_for(file_name), data.as_bytes())?;
        Ok(())
    }

    /// Read a cached value by [`CacheKey`].
    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<T> {
        self.get_named(&key.to_filename())
    }

    /// Atomically write a value keyed by [`CacheKey`].
    pub fn set<V: Serialize + ?Sized>(&self, key: &CacheKey, value: &V) -> Result<()> {
        self.set_named(&key.to_filename(), value)
    }

    /// Remove a cached entry by [`CacheKey`].
    pub fn remove(&self, key: &CacheKey) -> Result<()> {
        let path = self.path_for(&key.to_filename());
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Remove every JSON entry from the cache directory.
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

    /// Aggregate statistics over the cache directory.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let mut stats = CacheStats::default();

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().is_some_and(|e| e == "json") {
                    stats.total_entries += 1;
                    if let Ok(metadata) = entry.metadata() {
                        stats.total_size += metadata.len();
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

/// Write `bytes` to `path` atomically via a temp file + rename.
///
/// The temp file lives in the same directory as the target so the final
/// `rename` is a same-filesystem operation and therefore atomic.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map_or_else(|| "cache".to_string(), |n| n.to_string_lossy().into_owned());
    let tmp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));

    fs::write(&tmp, bytes)?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e.into())
        }
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

// ============================================================================
// EnrichmentSource trait
// ============================================================================

/// A source of external data that enriches SBOM components.
///
/// This models the shape shared by the OSV, KEV, EOL, and staleness enrichers:
/// each has a stable name, a cache namespace and TTL, and an operation that
/// applies fetched data to a slice of [`Component`]s in place, returning a
/// source-specific statistics value.
///
/// It is a thin description layer over the existing enrichers — implementing it
/// does not change what any source fetches or how results are mapped.
pub trait EnrichmentSource {
    /// Per-source statistics returned by [`enrich`](EnrichmentSource::enrich).
    type Stats;

    /// Stable, human-readable source name (e.g. `"OSV"`, `"KEV"`).
    fn name(&self) -> &'static str;

    /// Cache namespace (the directory under `…/sbom-tools/`).
    fn cache_namespace(&self) -> &'static str;

    /// Time-to-live for this source's cache entries.
    fn cache_ttl(&self) -> Duration;

    /// Apply this source's data to the given components in place.
    fn enrich(&mut self, components: &mut [Component]) -> Result<Self::Stats>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Payload {
        value: u32,
        label: String,
    }

    fn sample() -> Payload {
        Payload {
            value: 7,
            label: "hello".to_string(),
        }
    }

    #[test]
    fn namespaced_cache_dir_includes_namespace() {
        let dir = namespaced_cache_dir("osv");
        let s = dir.to_string_lossy();
        assert!(s.contains("sbom-tools"));
        assert!(s.ends_with("osv"));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_delay(1, None), Duration::from_secs(1));
        assert_eq!(backoff_delay(2, None), Duration::from_secs(2));
        assert_eq!(backoff_delay(3, None), Duration::from_secs(4));
        // Capped at MAX_BACKOFF regardless of attempt.
        assert_eq!(backoff_delay(20, None), MAX_BACKOFF);
    }

    #[test]
    fn backoff_honors_retry_after_but_caps_it() {
        assert_eq!(
            backoff_delay(1, Some(Duration::from_secs(3))),
            Duration::from_secs(3)
        );
        assert_eq!(
            backoff_delay(1, Some(Duration::from_secs(120))),
            MAX_BACKOFF
        );
    }

    #[test]
    fn cache_roundtrip_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let cache: JsonCache<Payload> =
                JsonCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
            cache.set_named("entry", &sample()).unwrap();
        }
        // A freshly constructed cache reads the persisted, atomically written file.
        let cache: JsonCache<Payload> =
            JsonCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        assert_eq!(cache.get_named("entry"), Some(sample()));
    }

    #[test]
    fn atomic_write_leaves_no_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cache: JsonCache<Payload> =
            JsonCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        cache.set_named("entry", &sample()).unwrap();

        let tmp_files: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "temp file should be renamed away");
    }

    #[test]
    fn schema_version_mismatch_invalidates_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache: JsonCache<Payload> =
            JsonCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();

        // Hand-write an envelope with a different schema version.
        let stale = format!(
            "{{\"schema_version\":{},\"payload\":{{\"value\":1,\"label\":\"x\"}}}}",
            CACHE_SCHEMA_VERSION + 1
        );
        let path = cache.path_for("entry");
        fs::write(&path, stale).unwrap();

        assert!(
            cache.get_named("entry").is_none(),
            "mismatched schema version must be a miss"
        );
        assert!(!path.exists(), "stale entry should be evicted");
    }

    #[test]
    fn ttl_expiry_evicts_entry() {
        let tmp = tempfile::tempdir().unwrap();
        // TTL margin must comfortably exceed the set+get round-trip (atomic
        // write + read + deserialize), which can spike on a loaded CI runner.
        let cache: JsonCache<Payload> =
            JsonCache::new(tmp.path().to_path_buf(), Duration::from_millis(200)).unwrap();
        cache.set_named("entry", &sample()).unwrap();
        assert!(cache.get_named("entry").is_some());

        std::thread::sleep(Duration::from_millis(400));
        assert!(
            cache.get_named("entry").is_none(),
            "entry past TTL must be a miss"
        );
        assert!(
            !cache.path_for("entry").exists(),
            "expired entry should be evicted"
        );
    }

    #[cfg(feature = "enrichment")]
    #[test]
    fn read_bounded_rejects_oversized_body() {
        use httpmock::prelude::*;

        let server = MockServer::start();
        // A body that comfortably exceeds the tiny test cap below.
        let body = "x".repeat(1024);
        let mock = server.mock(|when, then| {
            when.method(GET).path("/big");
            then.status(200).body(&body);
        });

        let client = http_client(Duration::from_secs(5)).unwrap();
        let resp = get_with_retry(&client, &format!("{}/big", server.base_url()), 0).unwrap();
        mock.assert();

        let err =
            read_bounded_with_max(resp, 16).expect_err("a body over the cap must be rejected");
        // The user-facing message names the size-cap; the byte-precise detail
        // ("exceeds the N-byte limit") is carried on the error's source chain.
        assert!(
            err.to_string().contains("too large"),
            "error must explain the size-cap rejection, got: {err}"
        );
        let detail = std::error::Error::source(&err)
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(
            detail.contains("exceeds"),
            "source must carry the byte-precise detail, got: {detail}"
        );
    }

    #[cfg(feature = "enrichment")]
    #[test]
    fn read_bounded_accepts_body_within_cap() {
        use httpmock::prelude::*;

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/ok");
            then.status(200).body("hello");
        });

        let client = http_client(Duration::from_secs(5)).unwrap();
        let resp = get_with_retry(&client, &format!("{}/ok", server.base_url()), 0).unwrap();
        mock.assert();

        let bytes = read_bounded_with_max(resp, MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn clear_and_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let cache: JsonCache<Payload> =
            JsonCache::new(tmp.path().to_path_buf(), Duration::from_secs(3600)).unwrap();
        // `stats`/`clear` operate on `.json` entries, matching how all real
        // callers name their files (CacheKey::to_filename, cache_filename, …).
        cache.set_named("a.json", &sample()).unwrap();
        cache.set_named("b.json", &sample()).unwrap();
        assert_eq!(cache.stats().total_entries, 2);
        cache.clear().unwrap();
        assert_eq!(cache.stats().total_entries, 0);
    }
}
