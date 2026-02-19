//! Watch configuration and duration parsing.

use super::WatchError;
use crate::config::{EnrichmentConfig, OutputConfig};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the watch command.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directories to monitor for SBOM files
    pub watch_dirs: Vec<PathBuf>,
    /// Polling interval for file changes
    pub poll_interval: Duration,
    /// Interval between enrichment refresh cycles
    pub enrich_interval: Duration,
    /// Debounce duration — wait this long after detecting a change before
    /// processing, to coalesce rapid successive writes (default: 2s).
    pub debounce: Duration,
    /// Output configuration
    pub output: OutputConfig,
    /// Enrichment configuration
    pub enrichment: EnrichmentConfig,
    /// Optional webhook URL for alerts
    pub webhook_url: Option<String>,
    /// Exit after first detected change (CI mode)
    pub exit_on_change: bool,
    /// Maximum number of diff snapshots to retain per SBOM
    pub max_snapshots: usize,
    /// Suppress non-essential output
    pub quiet: bool,
    /// Dry-run mode: do initial scan only, then exit
    pub dry_run: bool,
}

/// Parse a human-readable duration string into a [`Duration`].
///
/// Supported suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes),
/// `h` (hours), `d` (days).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
/// ```
pub fn parse_duration(s: &str) -> Result<Duration, WatchError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(WatchError::InvalidInterval(s.to_string()));
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, "ms")
    } else if s.ends_with('s') || s.ends_with('m') || s.ends_with('h') || s.ends_with('d') {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        return Err(WatchError::InvalidInterval(s.to_string()));
    };

    let value: u64 = num_str
        .parse()
        .map_err(|_| WatchError::InvalidInterval(s.to_string()))?;

    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 3600)),
        "d" => Ok(Duration::from_secs(value * 86400)),
        _ => Err(WatchError::InvalidInterval(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  10s  ").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_invalid_unit() {
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn test_parse_duration_invalid_number() {
        assert!(parse_duration("abcs").is_err());
    }

    #[test]
    fn test_parse_duration_empty() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_duration_no_unit() {
        assert!(parse_duration("100").is_err());
    }
}
