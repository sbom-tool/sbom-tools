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

    // Enrich with OSV vulnerability data
    if enrichment.enabled {
        let osv_config = crate::pipeline::build_enrichment_config(&enrichment);
        if crate::pipeline::enrich_sbom(&mut sbom, &osv_config, quiet).is_none() && !quiet {
            eprintln!("Warning: OSV vulnerability enrichment failed");
        }
    }

    // Enrich with EOL data
    if enrichment.enable_eol {
        let eol_config = crate::enrichment::EolClientConfig {
            cache_dir: enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
            cache_ttl: std::time::Duration::from_secs(enrichment.cache_ttl_hours * 3600),
            bypass_cache: enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(enrichment.timeout_secs),
            ..Default::default()
        };
        if crate::pipeline::enrich_eol(&mut sbom, &eol_config, quiet).is_none() && !quiet {
            eprintln!("Warning: EOL enrichment failed");
        }
    }

    // Apply VEX overlays
    if !enrichment.vex_paths.is_empty() {
        crate::pipeline::enrich_vex(&mut sbom, &enrichment.vex_paths, quiet);
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
