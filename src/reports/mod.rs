//! Report generation for diff results.
//!
//! This module provides multiple output formats for SBOM diff results:
//! - JSON: Structured data for programmatic integration
//! - SARIF: CI/CD security dashboard integration
//! - Markdown: Human-readable documentation
//! - HTML: Interactive stakeholder reports
//! - Side-by-side: Terminal diff output like difftastic
//! - Summary: Compact shell-friendly output
//! - Table: Aligned tabular terminal output
//!
//! # Security
//!
//! The `escape` module provides utilities for safe output generation.
//! All user-controllable data (component names, versions, etc.) should
//! be escaped before embedding in HTML or Markdown reports.

pub mod analyst;
mod csv;
pub mod escape;
mod html;
mod json;
mod markdown;
mod sarif;
mod sidebyside;
pub mod streaming;
mod summary;
mod types;

pub use csv::CsvReporter;
pub use html::HtmlReporter;
pub use json::JsonReporter;
pub use markdown::MarkdownReporter;
pub use sarif::SarifReporter;
pub use sarif::{generate_compliance_sarif, generate_multi_compliance_sarif};
pub use sidebyside::SideBySideReporter;
pub use streaming::{NdjsonReporter, NdjsonWriter, StreamingJsonReporter, StreamingJsonWriter};
pub use summary::{SummaryReporter, TableReporter};
pub use types::{MinSeverity, ReportConfig, ReportFormat, ReportMetadata, ReportType};

// Re-export traits
// Note: StreamingReporter is implemented as a blanket impl for ReportGenerator

use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use std::io::Write;
use thiserror::Error;

/// Errors that can occur during report generation
#[derive(Error, Debug)]
pub enum ReportError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Template error: {0}")]
    TemplateError(String),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Format error: {0}")]
    FormatError(#[from] std::fmt::Error),
}

/// Trait for report generators
pub trait ReportGenerator {
    /// Generate a report from diff results
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError>;

    /// Generate a report for a single SBOM (view mode)
    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError>;

    /// Write report to a writer
    fn write_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut dyn Write,
    ) -> Result<(), ReportError> {
        let report = self.generate_diff_report(result, old_sbom, new_sbom, config)?;
        writer.write_all(report.as_bytes())?;
        Ok(())
    }

    /// Get the format this generator produces
    fn format(&self) -> ReportFormat;
}

/// Trait for writing reports directly to a [`Write`] sink.
///
/// Every `ReportGenerator` automatically implements this trait via a blanket
/// impl that generates the full report string and writes it. Reporters that
/// can write **incrementally** (e.g., [`StreamingJsonReporter`],
/// [`NdjsonReporter`]) override this with truly streaming implementations
/// that avoid buffering the entire output in memory.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::reports::{WriterReporter, JsonReporter, ReportConfig};
/// use std::io::BufWriter;
/// use std::fs::File;
///
/// let reporter = JsonReporter::new();
/// let file = File::create("report.json")?;
/// let mut writer = BufWriter::new(file);
///
/// reporter.write_diff_to(&result, &old, &new, &config, &mut writer)?;
/// ```
pub trait WriterReporter {
    /// Write a diff report to a writer.
    ///
    /// Implementations may buffer the full report or write incrementally
    /// depending on the reporter type.
    fn write_diff_to<W: Write>(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError>;

    /// Write a view report to a writer.
    fn write_view_to<W: Write>(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError>;

    /// Get the format this reporter produces
    fn format(&self) -> ReportFormat;
}

/// Backwards-compatible alias for `WriterReporter`.
#[deprecated(since = "0.2.0", note = "Renamed to WriterReporter for clarity")]
pub trait StreamingReporter: WriterReporter {}

/// Blanket implementation of `WriterReporter` for any `ReportGenerator`.
///
/// Generates the full report in memory, then writes it. This is **not**
/// streaming — it buffers the entire output. Reporters that need true
/// incremental output (e.g., for very large SBOMs) should implement
/// `WriterReporter` directly.
impl<T: ReportGenerator> WriterReporter for T {
    fn write_diff_to<W: Write>(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        let report = self.generate_diff_report(result, old_sbom, new_sbom, config)?;
        writer.write_all(report.as_bytes())?;
        Ok(())
    }

    fn write_view_to<W: Write>(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        let report = self.generate_view_report(sbom, config)?;
        writer.write_all(report.as_bytes())?;
        Ok(())
    }

    fn format(&self) -> ReportFormat {
        ReportGenerator::format(self)
    }
}

#[allow(deprecated)]
impl<T: WriterReporter> StreamingReporter for T {}

/// Create a report generator for the given format
#[must_use]
pub fn create_reporter(format: ReportFormat) -> Box<dyn ReportGenerator> {
    create_reporter_with_options(format, true)
}

/// Create a report generator with color control
#[must_use]
pub fn create_reporter_with_options(
    format: ReportFormat,
    use_color: bool,
) -> Box<dyn ReportGenerator> {
    match format {
        ReportFormat::Auto | ReportFormat::Summary => {
            if use_color {
                Box::new(SummaryReporter::new())
            } else {
                Box::new(SummaryReporter::new().no_color())
            }
        }
        ReportFormat::Json | ReportFormat::Tui => Box::new(JsonReporter::new()), // TUI uses JSON internally
        ReportFormat::Sarif => Box::new(SarifReporter::new()),
        ReportFormat::Markdown => Box::new(MarkdownReporter::new()),
        ReportFormat::Html => Box::new(HtmlReporter::new()),
        ReportFormat::SideBySide => Box::new(SideBySideReporter::new()),
        ReportFormat::Table => {
            if use_color {
                Box::new(TableReporter::new())
            } else {
                Box::new(TableReporter::new().no_color())
            }
        }
        ReportFormat::Csv => Box::new(CsvReporter::new()),
    }
}
