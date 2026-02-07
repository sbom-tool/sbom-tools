//! Enrichment statistics and error types.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Statistics from an enrichment operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EnrichmentStats {
    /// Number of components that were queried
    pub components_queried: usize,
    /// Number of components that had vulnerabilities found
    pub components_with_vulns: usize,
    /// Total number of vulnerabilities found
    pub total_vulns_found: usize,
    /// Number of cache hits (avoided API calls)
    pub cache_hits: usize,
    /// Number of API calls made
    pub api_calls: usize,
    /// Number of components that couldn't be queried (missing identifiers)
    pub components_skipped: usize,
    /// Duration of the enrichment operation
    #[serde(with = "duration_serde")]
    pub duration: Duration,
    /// Errors encountered during enrichment
    pub errors: Vec<EnrichmentError>,
}

impl EnrichmentStats {
    /// Create new empty stats
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create empty stats (alias for default, for clarity in null object pattern)
    #[must_use] 
    pub fn empty() -> Self {
        Self::default()
    }

    /// Total number of components checked (queried + skipped)
    #[must_use] 
    pub const fn components_checked(&self) -> usize {
        self.components_queried + self.components_skipped
    }

    /// Log a summary of the enrichment operation
    pub fn log_summary(&self) {
        tracing::info!(
            "Enrichment complete: {} components queried, {} with vulns ({} total), \
             {} cache hits, {} API calls, {} skipped in {:?}",
            self.components_queried,
            self.components_with_vulns,
            self.total_vulns_found,
            self.cache_hits,
            self.api_calls,
            self.components_skipped,
            self.duration
        );

        for err in &self.errors {
            tracing::warn!("Enrichment error: {}", err);
        }
    }

    /// Check if there were any errors
    #[must_use] 
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Merge stats from another enrichment operation
    pub fn merge(&mut self, other: &Self) {
        self.components_queried += other.components_queried;
        self.components_with_vulns += other.components_with_vulns;
        self.total_vulns_found += other.total_vulns_found;
        self.cache_hits += other.cache_hits;
        self.api_calls += other.api_calls;
        self.components_skipped += other.components_skipped;
        self.duration += other.duration;
        self.errors.extend(other.errors.iter().cloned());
    }
}

/// Errors that can occur during enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrichmentError {
    /// API request failed
    ApiError(String),
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Cache read/write error
    CacheError(String),
    /// Response parsing error
    ParseError(String),
    /// Network timeout
    Timeout,
    /// Component missing required identifiers
    MissingIdentifiers(String),
}

impl fmt::Display for EnrichmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiError(msg) => write!(f, "API error: {msg}"),
            Self::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            Self::CacheError(msg) => write!(f, "Cache error: {msg}"),
            Self::ParseError(msg) => write!(f, "Parse error: {msg}"),
            Self::Timeout => write!(f, "Request timeout"),
            Self::MissingIdentifiers(name) => {
                write!(f, "Component '{name}' missing identifiers for query")
            }
        }
    }
}

impl std::error::Error for EnrichmentError {}

/// Serde support for Duration
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
