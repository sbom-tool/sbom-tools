//! CLI handler for the `convert` command.
//!
//! Cross-format SBOM conversion: parses any supported input format and emits a
//! single target format from the canonical model. A fidelity report is written
//! to stderr describing synthesized and dropped fields (honest about lossiness).

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::parsers::parse_sbom_str;
use crate::pipeline::{exit_codes, read_input};
use crate::reports::escape::sanitize_path;
use crate::serialization::emit::{self, EmitError, EmitTarget};

/// Run the convert command.
///
/// `target` is the raw `--to` value (e.g. "cyclonedx"). When `preserve` is set,
/// each component's verbatim source JSON is captured before emission so
/// format-specific blocks the canonical model can't fully reconstruct
/// (`cryptoProperties`, `evidence`) are spliced back where present.
pub fn run_convert(
    file: &Path,
    target: &str,
    output_file: Option<&PathBuf>,
    preserve: bool,
    quiet: bool,
) -> Result<i32> {
    let Some(emit_target) = EmitTarget::parse(target) else {
        eprintln!(
            "error: unknown conversion target '{target}'. Supported: cyclonedx, spdx, normalized."
        );
        return Ok(exit_codes::ERROR);
    };

    // Shared '-'-aware input path (same as view/validate): supports piping an
    // SBOM via stdin and gives contextful errors instead of a raw ENOENT.
    let raw_json = read_input(file)?;
    let mut sbom = parse_sbom_str(&raw_json)?;

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
    // The normalized payload is the canonical model itself, so there is nothing
    // to report.
    if !quiet && emit_target != EmitTarget::Normalized {
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
                eprintln!("Converted SBOM written to {}", sanitize_path(path));
            }
        }
        None => {
            println!("{output}");
        }
    }

    Ok(exit_codes::SUCCESS)
}
