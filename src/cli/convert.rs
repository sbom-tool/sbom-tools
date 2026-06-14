//! CLI handler for the `convert` command.
//!
//! Cross-format SBOM conversion: parses any supported input format and emits a
//! single target format from the canonical model. A fidelity report is written
//! to stderr describing synthesized and dropped fields (honest about lossiness).

use std::path::PathBuf;

use anyhow::Result;

use crate::parsers::parse_sbom;
use crate::pipeline::exit_codes;
use crate::serialization::emit::{self, EmitError, EmitTarget};

/// Run the convert command.
///
/// `target` is the raw `--to` value (e.g. "cyclonedx"). When `preserve` is set,
/// each component's verbatim source JSON is captured before emission so
/// format-specific blocks the canonical model can't fully reconstruct
/// (`cryptoProperties`, `evidence`) are spliced back where present.
pub fn run_convert(
    file: &PathBuf,
    target: &str,
    output_file: Option<&PathBuf>,
    preserve: bool,
    quiet: bool,
) -> Result<i32> {
    let Some(emit_target) = EmitTarget::parse(target) else {
        eprintln!("error: unknown conversion target '{target}'. Supported: cyclonedx, spdx.");
        return Ok(exit_codes::ERROR);
    };

    let raw_json = std::fs::read_to_string(file)?;
    let mut sbom = parse_sbom(file)?;

    if preserve {
        emit::preserve_source_json(&raw_json, &mut sbom);
    }

    let (output, report) = match emit::emit(&sbom, emit_target) {
        Ok(result) => result,
        Err(EmitError::Unsupported(fmt)) => {
            eprintln!("error: emitting to {fmt} is not yet implemented.");
            return Ok(exit_codes::ERROR);
        }
        Err(e) => return Err(e.into()),
    };

    // Fidelity report always goes to stderr so it never pollutes piped output.
    if !quiet {
        eprint!("{}", report.render());
        if report.is_lossy() {
            eprintln!(
                "  Note: conversion is lossy ({} field type(s) dropped). Re-run with --preserve to retain format-specific blocks where possible.",
                report.dropped_count()
            );
        }
    }

    match output_file {
        Some(path) => {
            std::fs::write(path, &output)?;
            if !quiet {
                eprintln!("Converted SBOM written to {}", path.display());
            }
        }
        None => {
            println!("{output}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
