//! CLI handler for the `tailor` command.
//!
//! Filters an SBOM by removing components that don't match criteria.

use std::path::PathBuf;

use anyhow::Result;

use crate::parsers::parse_sbom;
use crate::pipeline::exit_codes;
use crate::serialization::{TailorConfig, tailor_sbom_json};

/// Run the tailor command.
pub fn run_tailor(
    file: &PathBuf,
    output_file: Option<&PathBuf>,
    config: TailorConfig,
    quiet: bool,
) -> Result<i32> {
    let raw_json = std::fs::read_to_string(file)?;
    let sbom = parse_sbom(file)?;
    let tailored = tailor_sbom_json(&raw_json, &sbom, &config)?;

    match output_file {
        Some(path) => {
            std::fs::write(path, &tailored)?;
            if !quiet {
                eprintln!("Tailored SBOM written to {}", path.display());
            }
        }
        None => {
            println!("{tailored}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
