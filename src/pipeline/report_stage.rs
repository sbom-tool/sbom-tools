//! Report output stage.
//!
//! Handles generating and writing diff reports, including streaming mode
//! for large SBOMs.

use crate::config::DiffConfig;
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::quality::{ComplianceLevel, ComplianceRunConfig};
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
    output_report_with_sarif(config, result, old_sbom, new_sbom, None)
}

/// [`output_report`] with the new SBOM file `-o sarif` results point into
/// (a diff reports into the new SBOM only). Without it, SARIF results carry
/// no physical location.
pub fn output_report_with_sarif(
    config: &DiffConfig,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    sarif: Option<crate::reports::SarifArtifact>,
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
    //
    // Each side is judged with the run's shared inputs plus its own CRA
    // sidecar (auto-discovered next to that SBOM), matching the TUI path in
    // `cli/diff.rs`, so `diff -o json|md|html|sarif` renders the same
    // verdicts as the interactive TUI. SARIF reports into the new SBOM only,
    // so it needs no old-side compliance.
    let (old_cra, new_cra) = if !use_streaming && format_uses_compliance(effective_output) {
        let old_cra = if effective_output == ReportFormat::Sarif {
            None
        } else {
            Some(
                side_compliance(&config.compliance, &config.paths.old)?
                    .check(ComplianceLevel::CraPhase2, old_sbom),
            )
        };
        (
            old_cra,
            Some(
                side_compliance(&config.compliance, &config.paths.new)?
                    .check(ComplianceLevel::CraPhase2, new_sbom),
            ),
        )
    } else {
        (None, None)
    };

    let mut report_config = ReportConfig {
        report_types: vec![config.output.report_types],
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
        sarif: config.output.sarif_options(),
        ..Default::default()
    };
    if let Some(new_artifact) = sarif {
        report_config.sarif = report_config.sarif.with_artifact(new_artifact);
    }

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

/// Auto-discover the CRA sidecar adjacent to an SBOM path.
///
/// Looks for `<sbom>.cra.{json,yaml,yml}` (and the `-cra.*` / inner-stem
/// variants handled by [`CraSidecarMetadata::discover_for_sbom`]) next to the
/// SBOM. Stdin (`-`) has no adjacent file, so it never resolves a sidecar.
/// A discovered-but-invalid sidecar is a hard error, matching the explicit
/// `--cra-sidecar` contract — the trust decision must not depend on how the
/// file was found.
///
/// The `diff` command takes two SBOMs, so it has no `--cra-sidecar` flag:
/// auto-discovery is the only sidecar channel for diffs, and the sidecar's
/// own `productClass` wins over `--cra-product-class`. Shared by the diff TUI
/// path (`cli/diff.rs`) and this report stage through [`side_compliance`],
/// so both resolve sidecars identically.
///
/// [`CraSidecarMetadata::discover_for_sbom`]: crate::model::CraSidecarMetadata::discover_for_sbom
pub fn discover_cra_sidecar(
    sbom_path: &std::path::Path,
) -> Result<Option<crate::model::CraSidecarMetadata>> {
    if super::is_stdin_path(sbom_path) {
        Ok(None)
    } else {
        crate::model::CraSidecarMetadata::discover_for_sbom(sbom_path)
            .map_err(|e| anyhow::anyhow!("Failed to load auto-discovered CRA sidecar: {e}"))
    }
}

/// The compliance run of one side of a diff: `shared` (the inputs both sides
/// share, [`DiffConfig::compliance`]) plus the CRA sidecar found next to
/// `sbom_path`. Sidecar resolution is per-SBOM: each side of the diff is
/// judged against the metadata shipped next to it, so a product-class or
/// contact change between releases (old sidecar vs new sidecar) shows up in
/// the diff instead of being masked by one side's evidence. A sidecar
/// `productClass` that differs from `--cra-product-class` wins, with a
/// warning on stderr that names the SBOM.
pub(crate) fn side_compliance(
    shared: &ComplianceRunConfig,
    sbom_path: &std::path::Path,
) -> Result<ComplianceRunConfig> {
    let mut config = shared.clone();
    if let Some(sidecar) = discover_cra_sidecar(sbom_path)? {
        config = config.with_sidecar(sidecar);
    }
    config.warn_on_product_class_conflict(sbom_path);
    Ok(config)
}

/// Whether a report format renders the pre-computed CRA compliance results.
///
/// Only Markdown, HTML, non-streaming JSON, and SARIF read
/// `ReportConfig::{old,new}_cra_compliance` (SARIF only the new side); every other format
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

        // The shared test clock (tests/common/clock.rs).
        let as_of = chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc);
        let make_config = |with_compliance: bool| {
            let (old_cra, new_cra) = if with_compliance {
                let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2).with_as_of(as_of);
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
