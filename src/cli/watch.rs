//! CLI handler for the `watch` subcommand.

use crate::config::WatchConfig;
use crate::watch::WatchError;
use anyhow::Result;

/// Run the watch command with the given configuration.
pub fn run_watch(config: WatchConfig) -> Result<()> {
    // Validate that all watch directories exist
    for dir in &config.watch_dirs {
        if !dir.is_dir() {
            return Err(WatchError::DirNotFound(dir.clone()).into());
        }
    }

    crate::watch::run_watch_loop(&config)
}
