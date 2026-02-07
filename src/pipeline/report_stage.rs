//! Report output stage.
//!
//! Handles generating and writing diff reports, including streaming mode
//! for large SBOMs.

use crate::config::DiffConfig;
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::reports::{
    create_reporter_with_options, ReportConfig, ReportFormat, StreamingJsonReporter,
    WriterReporter,
};
use anyhow::Result;
use std::fs::File;
use std::io::BufWriter;

use super::{auto_detect_format, should_use_color, write_output, OutputTarget};

/// Output a diff report to the configured destination.
///
/// Handles format auto-detection, CRA compliance pre-computation,
/// streaming mode for large SBOMs, and writing to file or stdout.
pub fn output_report(
    config: &DiffConfig,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
) -> Result<()> {
    let output_target = OutputTarget::from_option(config.output.file.clone());
    let effective_output = auto_detect_format(config.output.format, &output_target);

    // Pre-compute CRA compliance once, pass to reporters to avoid redundant checks
    let cra_checker =
        crate::quality::ComplianceChecker::new(crate::quality::ComplianceLevel::CraPhase2);
    let old_cra = cra_checker.check(old_sbom);
    let new_cra = cra_checker.check(new_sbom);

    let report_config = ReportConfig {
        report_types: vec![config.output.report_types],
        include_unchanged: config.matching.include_unchanged,
        only_changes: config.filtering.only_changes,
        min_severity: config
            .filtering
            .min_severity
            .as_ref()
            .and_then(|s| crate::reports::MinSeverity::parse(s)),
        metadata: crate::reports::ReportMetadata {
            old_sbom_path: Some(config.paths.old.to_string_lossy().to_string()),
            new_sbom_path: Some(config.paths.new.to_string_lossy().to_string()),
            ..Default::default()
        },
        old_cra_compliance: Some(old_cra),
        new_cra_compliance: Some(new_cra),
        ..Default::default()
    };

    // Check if we should use streaming mode for JSON output
    let use_streaming = should_use_streaming(config) && effective_output == ReportFormat::Json;

    if use_streaming {
        if !config.behavior.quiet {
            tracing::info!("Using streaming mode for large SBOM report generation");
        }
        return output_streaming(config, result, old_sbom, new_sbom, &report_config);
    }

    let use_color = should_use_color(config.output.no_color);
    let reporter = create_reporter_with_options(effective_output, use_color);
    let report = reporter.generate_diff_report(result, old_sbom, new_sbom, &report_config)?;

    write_output(&report, &output_target, config.behavior.quiet)
}

/// Check if streaming mode should be used based on file sizes and config.
fn should_use_streaming(config: &DiffConfig) -> bool {
    let streaming_config = &config.output.streaming;

    let old_size = std::fs::metadata(&config.paths.old)
        .map(|m| m.len())
        .ok();

    let new_size = std::fs::metadata(&config.paths.new)
        .map(|m| m.len())
        .ok();

    let old_should_stream = streaming_config.should_stream(old_size, false);
    let new_should_stream = streaming_config.should_stream(new_size, false);

    old_should_stream || new_should_stream
}

/// Output diff report using streaming mode (writes directly without buffering).
fn output_streaming(
    config: &DiffConfig,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    report_config: &ReportConfig,
) -> Result<()> {
    let streaming_reporter = StreamingJsonReporter::new();

    if let Some(path) = &config.output.file {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        streaming_reporter.write_diff_to(
            result,
            old_sbom,
            new_sbom,
            report_config,
            &mut writer,
        )?;
        if !config.behavior.quiet {
            tracing::info!("Streaming report written to {:?}", path);
        }
    } else {
        let stdout = std::io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        streaming_reporter.write_diff_to(
            result,
            old_sbom,
            new_sbom,
            report_config,
            &mut writer,
        )?;
    }

    Ok(())
}
