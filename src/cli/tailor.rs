//! CLI handler for the `tailor` command.
//!
//! Filters an SBOM by removing components that don't match criteria.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::parsers::parse_sbom_str;
use crate::pipeline::{exit_codes, read_input};
use crate::reports::escape::sanitize_path;
use crate::serialization::{TailorConfig, tailor_sbom_json};

/// Run the tailor command.
pub fn run_tailor(
    file: &Path,
    output_file: Option<&PathBuf>,
    config: TailorConfig,
    quiet: bool,
) -> Result<i32> {
    // Shared '-'-aware input path (same as view/validate): supports piping an
    // SBOM via stdin and gives contextful errors instead of a raw ENOENT.
    let raw_json = read_input(file)?;
    let sbom = parse_sbom_str(&raw_json)?;
    let tailored = tailor_sbom_json(&raw_json, &sbom, &config)?;

    match output_file {
        Some(path) => {
            std::fs::write(path, &tailored)?;
            if !quiet {
                eprintln!("Tailored SBOM written to {}", sanitize_path(path));
            }
        }
        None => {
            println!("{tailored}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
