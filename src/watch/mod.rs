//! Continuous monitoring / watch mode for SBOMs.
//!
//! Polls directories for SBOM file changes and optionally re-enriches
//! with vulnerability/EOL data on a configurable interval, firing alerts
//! through pluggable sinks (stdout, NDJSON, webhook).

pub(crate) mod alerts;
pub(crate) mod config;
pub(crate) mod loop_impl;
pub(crate) mod monitor;
pub(crate) mod state;

pub use config::{WatchConfig, parse_duration};
pub use loop_impl::run_watch_loop;

/// Errors specific to the watch subsystem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WatchError {
    #[error("invalid interval '{0}': expected format like 30s, 5m, 1h")]
    InvalidInterval(String),

    #[error("no SBOM files found in watched directories")]
    NoFilesFound,

    #[error("watch directory does not exist: {}", .0.display())]
    DirNotFound(std::path::PathBuf),

    #[error("webhook delivery failed: {0}")]
    WebhookFailed(String),
}
