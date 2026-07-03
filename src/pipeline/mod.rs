//! Pipeline orchestration for SBOM operations.
//!
//! This module provides shared orchestration logic for parse → enrich → diff → report
//! workflows, reducing duplication across CLI command handlers.

mod diff_stage;
pub mod enrich;
mod output;
mod parse;
mod report_stage;

pub use diff_stage::{apply_post_diff_filters, compute_diff, graph_diff_config_from};
pub use enrich::{AggregatedEnrichmentStats, enrich_sbom_full, enrich_sboms};
pub use output::{OutputTarget, auto_detect_format, should_use_color, write_output};
pub use parse::{ParsedSbom, STDIN_PATH, is_stdin_path, parse_sbom_with_context, read_input};
pub use report_stage::output_report;

#[cfg(feature = "enrichment")]
pub use parse::{
    build_enrichment_config, enrich_eol, enrich_epss, enrich_huggingface, enrich_kev, enrich_sbom,
    enrich_staleness, enrich_vex,
};

/// Structured pipeline error types for better diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Failed to read or parse an SBOM file
    #[error("Parse failed for {path}: {source}")]
    ParseFailed { path: String, source: anyhow::Error },

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
    /// Introduced vulnerabilities lack VEX statements (--fail-on-vex-gap)
    pub const VEX_GAPS_FOUND: i32 = 4;
    /// License policy violations found
    pub const LICENSE_VIOLATIONS: i32 = 5;
    /// Introduced vulnerabilities are in CISA's KEV catalog (--fail-on-kev)
    pub const KEV_INTRODUCED: i32 = 6;
    /// A supported ML performance metric regressed (--fail-on-ml-regression)
    pub const ML_REGRESSION: i32 = 7;

    // --- Per-command meanings (aliases preserving the numeric values above) ---

    /// `validate`: compliance errors found (non-compliant SBOM). Same value as
    /// [`CHANGES_DETECTED`].
    pub const COMPLIANCE_ERRORS: i32 = CHANGES_DETECTED;
    /// `validate --fail-on-warning`: compliance warnings found. Same value as
    /// [`VULNS_INTRODUCED`].
    pub const COMPLIANCE_WARNINGS: i32 = VULNS_INTRODUCED;
    /// `quality --min-score`: overall score below the requested threshold. Same
    /// value as [`CHANGES_DETECTED`].
    pub const QUALITY_BELOW_THRESHOLD: i32 = CHANGES_DETECTED;
    /// `query`: no components matched the filter. Same value as
    /// [`CHANGES_DETECTED`].
    pub const NO_MATCHES: i32 = CHANGES_DETECTED;
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

    /// Get the default CISA KEV cache directory
    #[must_use]
    pub fn kev_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("kev")
    }

    /// Get the default FIRST EPSS cache directory
    #[must_use]
    pub fn epss_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("epss")
    }

    /// Get the default staleness (registry) cache directory
    #[must_use]
    pub fn staleness_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("staleness")
    }

    /// Get the default HuggingFace Hub cache directory
    #[must_use]
    pub fn huggingface_cache_dir() -> PathBuf {
        cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("sbom-tools")
            .join("huggingface")
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
        assert_eq!(exit_codes::VEX_GAPS_FOUND, 4);
        assert_eq!(exit_codes::LICENSE_VIOLATIONS, 5);
        assert_eq!(exit_codes::KEV_INTRODUCED, 6);
    }

    #[test]
    fn test_per_command_exit_code_aliases_preserve_values() {
        // Per-command aliases must not introduce new numeric exit codes.
        assert_eq!(exit_codes::COMPLIANCE_ERRORS, exit_codes::CHANGES_DETECTED);
        assert_eq!(
            exit_codes::COMPLIANCE_WARNINGS,
            exit_codes::VULNS_INTRODUCED
        );
        assert_eq!(
            exit_codes::QUALITY_BELOW_THRESHOLD,
            exit_codes::CHANGES_DETECTED
        );
        assert_eq!(exit_codes::NO_MATCHES, exit_codes::CHANGES_DETECTED);
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
