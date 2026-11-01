//! CLI handler for the `merge` command.
//!
//! Merges two SBOMs into one, deduplicating components.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::pipeline::{exit_codes, read_input};
use crate::reports::escape::sanitize_path;
use crate::serialization::{MergeConfig, merge_sbom_json};

/// Run the merge command.
pub fn run_merge(
    primary: &Path,
    secondary: &Path,
    output_file: Option<&PathBuf>,
    config: MergeConfig,
    quiet: bool,
) -> Result<i32> {
    // Shared '-'-aware input path (same as view/validate): either input may
    // be piped via stdin (only one of the two can actually be '-').
    let primary_json = read_input(primary)?;
    let secondary_json = read_input(secondary)?;
    let merged = merge_sbom_json(&primary_json, &secondary_json, &config)?;

    match output_file {
        Some(path) => {
            std::fs::write(path, &merged)?;
            if !quiet {
                eprintln!("Merged SBOM written to {}", sanitize_path(path));
            }
        }
        None => {
            println!("{merged}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
