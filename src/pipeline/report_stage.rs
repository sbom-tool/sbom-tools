//! Report output stage.
//!
//! Handles generating and writing diff reports, including streaming mode
//! for large SBOMs.

use crate::config::DiffConfig;
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::reports::{
    ReportConfig, ReportFormat, StreamingJsonReporter, WriterReporter, create_reporter_with_options,
};
use anyhow::Result;
use std::fs::File;
use std::io::BufWriter;

use super::{OutputTarget, auto_detect_format, should_use_color, write_output};

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

    // Check if we should use streaming mode for JSON output. Decided up front so
    // the compliance gate below can also skip the streaming JSON path, whose
    // reporter does not emit CRA compliance.
    let use_streaming = should_use_streaming(config) && effective_output == ReportFormat::Json;

    // Pre-compute CRA (Phase 2) compliance once and pass it to the reporter so it
    // doesn't recompute per SBOM — but ONLY for formats that actually render it.
    // Compliance-free formats (summary/table/csv/side-by-side/ndjson, and the
    // streaming JSON path) never read these fields, so running the checker for
    // them is wasted O(V+E) work on both SBOMs. Consuming reporters fall back to
    // computing it themselves when the field is `None`, so leaving it unset for
    // non-consuming formats is output-identical.
    let (old_cra, new_cra) = if !use_streaming && format_uses_compliance(effective_output) {
        let cra_checker =
            crate::quality::ComplianceChecker::new(crate::quality::ComplianceLevel::CraPhase2);
        (
            Some(cra_checker.check(old_sbom)),
            Some(cra_checker.check(new_sbom)),
        )
    } else {
        (None, None)
    };

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
        old_cra_compliance: old_cra,
        new_cra_compliance: new_cra,
        ..Default::default()
    };

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

/// Whether a report format renders the pre-computed CRA compliance results.
///
/// Only Markdown, HTML, non-streaming JSON, and SARIF read
/// `ReportConfig::{old,new}_cra_compliance`; every other format
/// (summary/table/csv/side-by-side/ndjson/streaming-JSON, plus TUI/auto which
/// don't reach this stage) ignores them, so pre-computing compliance for those
/// is wasted work. Consuming reporters fall back to computing compliance
/// themselves when the field is unset, so this gate only changes *where* the
/// work happens for consumers (here vs. in the reporter) — never the output.
const fn format_uses_compliance(format: ReportFormat) -> bool {
    matches!(
        format,
        ReportFormat::Markdown | ReportFormat::Html | ReportFormat::Json | ReportFormat::Sarif
    )
}

/// Check if streaming mode should be used based on file sizes and config.
fn should_use_streaming(config: &DiffConfig) -> bool {
    let streaming_config = &config.output.streaming;

    let old_size = std::fs::metadata(&config.paths.old).map(|m| m.len()).ok();

    let new_size = std::fs::metadata(&config.paths.new).map(|m| m.len()).ok();

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
        streaming_reporter.write_diff_to(result, old_sbom, new_sbom, report_config, &mut writer)?;
        if !config.behavior.quiet {
            tracing::info!("Streaming report written to {:?}", path);
        }
    } else {
        let stdout = std::io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        streaming_reporter.write_diff_to(result, old_sbom, new_sbom, report_config, &mut writer)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_consuming_formats_are_gated() {
        // Exactly the formats whose reporters read the cra_compliance fields.
        assert!(format_uses_compliance(ReportFormat::Markdown));
        assert!(format_uses_compliance(ReportFormat::Html));
        assert!(format_uses_compliance(ReportFormat::Json));
        assert!(format_uses_compliance(ReportFormat::Sarif));
        // Everything else ignores compliance, so pre-computing it is wasted work.
        assert!(!format_uses_compliance(ReportFormat::Summary));
        assert!(!format_uses_compliance(ReportFormat::Table));
        assert!(!format_uses_compliance(ReportFormat::Csv));
        assert!(!format_uses_compliance(ReportFormat::SideBySide));
        assert!(!format_uses_compliance(ReportFormat::Ndjson));
    }

    /// A compliance-free format must render identically whether or not the
    /// pre-computed compliance results are supplied — proving that gating the
    /// `ComplianceChecker` off for such formats is output-preserving.
    #[test]
    fn compliance_free_format_output_is_independent_of_compliance() {
        use crate::quality::{ComplianceChecker, ComplianceLevel};

        let result = DiffResult::default();
        let old_sbom = NormalizedSbom::default();
        let new_sbom = NormalizedSbom::default();

        let make_config = |with_compliance: bool| {
            let (old_cra, new_cra) = if with_compliance {
                let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
                (
                    Some(checker.check(&old_sbom)),
                    Some(checker.check(&new_sbom)),
                )
            } else {
                (None, None)
            };
            ReportConfig {
                old_cra_compliance: old_cra,
                new_cra_compliance: new_cra,
                ..Default::default()
            }
        };

        // Summary is a non-consumer: gated path (None) vs eager path (Some).
        let reporter = create_reporter_with_options(ReportFormat::Summary, false);
        let gated = reporter
            .generate_diff_report(&result, &old_sbom, &new_sbom, &make_config(false))
            .expect("gated summary report");
        let eager = reporter
            .generate_diff_report(&result, &old_sbom, &new_sbom, &make_config(true))
            .expect("eager summary report");
        assert_eq!(gated, eager, "summary output must not depend on compliance");
    }
}
