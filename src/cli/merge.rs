//! CLI handler for the `merge` command.
//!
//! Merges two SBOMs into one, deduplicating components.

use std::path::PathBuf;

use anyhow::Result;

use crate::pipeline::exit_codes;
use crate::serialization::{MergeConfig, merge_sbom_json};

/// Run the merge command.
pub fn run_merge(
    primary: &PathBuf,
    secondary: &PathBuf,
    output_file: Option<&PathBuf>,
    config: MergeConfig,
    quiet: bool,
) -> Result<i32> {
    let primary_json = std::fs::read_to_string(primary)?;
    let secondary_json = std::fs::read_to_string(secondary)?;
    let merged = merge_sbom_json(&primary_json, &secondary_json, &config)?;

    match output_file {
        Some(path) => {
            std::fs::write(path, &merged)?;
            if !quiet {
                eprintln!("Merged SBOM written to {}", path.display());
            }
        }
        None => {
            println!("{merged}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
