//! Pipeline orchestration for SBOM operations.
//!
//! This module provides shared orchestration logic for parse → enrich → diff → report
//! workflows, reducing duplication across CLI command handlers.

mod diff_stage;
mod output;
mod parse;
mod report_stage;

pub use diff_stage::compute_diff;
pub use output::{auto_detect_format, should_use_color, write_output, OutputTarget};
pub use parse::{parse_sbom_with_context, ParsedSbom};
pub use report_stage::output_report;

#[cfg(feature = "enrichment")]
pub use parse::{build_enrichment_config, enrich_eol, enrich_sbom, enrich_vex};

/// Structured pipeline error types for better diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Failed to read or parse an SBOM file
    #[error("Parse failed for {path}: {source}")]
    ParseFailed {
        path: String,
        source: anyhow::Error,
    },

    /// Enrichment failed (non-fatal by default)
    #[error("Enrichment failed: {reason}")]
    EnrichmentFailed { reason: String },

    /// Diff computation failed
    #[error("Diff failed: {source}")]
    DiffFailed {
        #[source]
        source: anyhow::Error,
    },

    /// Report generation or output failed
    #[error("Report failed: {source}")]
    ReportFailed {
        #[source]
        source: anyhow::Error,
    },
}

/// Exit codes for CI/CD integration
pub mod exit_codes {
    /// Success - no changes detected (or --no-fail-on-change)
    pub const SUCCESS: i32 = 0;
    /// Changes were detected
    pub const CHANGES_DETECTED: i32 = 1;
    /// Vulnerabilities were introduced
    pub const VULNS_INTRODUCED: i32 = 2;
    /// An error occurred
    pub const ERROR: i32 = 3;
}

/// Platform-specific cache directory utilities
pub mod dirs {
    use std::path::PathBuf;

    /// Get the platform-specific cache directory
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

    /// Get the default OSV cache directory
    #[must_use]
    pub fn osv_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("osv")
    }

    /// Get the default EOL cache directory
    #[must_use]
    pub fn eol_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("eol")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes_values() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::CHANGES_DETECTED, 1);
        assert_eq!(exit_codes::VULNS_INTRODUCED, 2);
        assert_eq!(exit_codes::ERROR, 3);
    }

    #[test]
    fn test_cache_dir_returns_some() {
        // Should return Some on most platforms when HOME is set
        // This test verifies the function doesn't panic
        let _ = dirs::cache_dir();
    }

    #[test]
    fn test_osv_cache_dir_path() {
        let path = dirs::osv_cache_dir();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("osv"));
    }
}
