//! CLI handler for the `enrich` command.
//!
//! Enriches an SBOM with vulnerability and EOL data, writing the result
//! back in the original format.

use std::path::PathBuf;

use anyhow::Result;

use crate::pipeline::exit_codes;

/// Run the enrich command.
///
/// Parses, enriches, and serializes the SBOM back to its original format.
#[cfg(feature = "enrichment")]
pub fn run_enrich(
    file: &PathBuf,
    output_file: Option<&PathBuf>,
    enrichment: crate::config::EnrichmentConfig,
    quiet: bool,
) -> Result<i32> {
    use crate::parsers::parse_sbom;
    use crate::serialization::enrich_sbom_json;

    let raw_json = std::fs::read_to_string(file)?;
    let mut sbom = parse_sbom(file)?;

    // Route through the unified orchestrator so every advertised source
    // (OSV / KEV / EPSS / EOL / staleness / HuggingFace / VEX) and the config
    // file's `enrichment:` block are honored. Hand-rolling individual sources
    // here silently dropped --kev/--epss/--enrich-staleness/--huggingface.
    let stats = crate::pipeline::enrich_sbom_full(&mut sbom, &enrichment, quiet);
    if !quiet {
        for warning in &stats.warnings {
            eprintln!("Warning: {warning}");
        }
    }

    let enriched_json = enrich_sbom_json(&raw_json, &sbom)?;

    match output_file {
        Some(path) => {
            std::fs::write(path, &enriched_json)?;
            if !quiet {
                eprintln!("Enriched SBOM written to {}", path.display());
            }
        }
        None => {
            println!("{enriched_json}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
