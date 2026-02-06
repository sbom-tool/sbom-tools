//! Streaming report generators for memory-efficient output.
//!
//! This module provides report generators that write directly to output
//! without buffering the entire report in memory. This is essential for
//! large SBOMs with thousands of components.
//!
//! # Supported Formats
//!
//! - **JSON Streaming**: Writes JSON incrementally with periodic flushing
//! - **NDJSON**: Newline-delimited JSON for easy processing of large datasets
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::reports::streaming::{StreamingJsonWriter, NdjsonWriter};
//! use std::io::BufWriter;
//! use std::fs::File;
//!
//! // Stream JSON to a file
//! let file = File::create("report.json")?;
//! let mut writer = BufWriter::new(file);
//! let json_writer = StreamingJsonWriter::new(&mut writer, true);
//! json_writer.write_diff_report(&result, &old, &new, &config)?;
//!
//! // Stream NDJSON (one JSON object per line)
//! let file = File::create("components.ndjson")?;
//! let mut writer = BufWriter::new(file);
//! let ndjson = NdjsonWriter::new(&mut writer);
//! ndjson.write_components(&result.components)?;
//! ```

use super::{ReportConfig, ReportError, ReportFormat, ReportType, WriterReporter};
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use chrono::Utc;
use serde::Serialize;
use std::io::Write;

// ============================================================================
// Streaming JSON Writer
// ============================================================================

/// A streaming JSON report writer that writes incrementally.
///
/// Unlike the standard `JsonReporter`, this writer streams data directly
/// to the output without building the entire JSON document in memory.
pub struct StreamingJsonWriter<'w, W: Write> {
    writer: &'w mut W,
    pretty: bool,
    indent_level: usize,
    flush_interval: usize,
    items_written: usize,
}

impl<'w, W: Write> StreamingJsonWriter<'w, W> {
    /// Create a new streaming JSON writer.
    pub fn new(writer: &'w mut W, pretty: bool) -> Self {
        Self {
            writer,
            pretty,
            indent_level: 0,
            flush_interval: 100, // Flush every 100 items
            items_written: 0,
        }
    }

    /// Set the flush interval (number of items between flushes).
    pub fn with_flush_interval(mut self, interval: usize) -> Self {
        self.flush_interval = interval.max(1);
        self
    }

    /// Write the opening brace and increase indent.
    fn write_object_start(&mut self) -> Result<(), ReportError> {
        self.write_raw("{")?;
        self.indent_level += 1;
        Ok(())
    }

    /// Write the closing brace and decrease indent.
    fn write_object_end(&mut self) -> Result<(), ReportError> {
        self.indent_level = self.indent_level.saturating_sub(1);
        self.write_newline()?;
        self.write_indent()?;
        self.write_raw("}")?;
        Ok(())
    }

    /// Write the opening bracket and increase indent.
    fn write_array_start(&mut self) -> Result<(), ReportError> {
        self.write_raw("[")?;
        self.indent_level += 1;
        Ok(())
    }

    /// Write the closing bracket and decrease indent.
    fn write_array_end(&mut self) -> Result<(), ReportError> {
        self.indent_level = self.indent_level.saturating_sub(1);
        self.write_newline()?;
        self.write_indent()?;
        self.write_raw("]")?;
        Ok(())
    }

    /// Write a key-value pair.
    fn write_key_value<V: Serialize>(
        &mut self,
        key: &str,
        value: &V,
        trailing_comma: bool,
    ) -> Result<(), ReportError> {
        self.write_newline()?;
        self.write_indent()?;
        self.write_raw(&format!("\"{key}\":"))?;
        if self.pretty {
            self.write_raw(" ")?;
        }

        let json = if self.pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        }
        .map_err(|e| ReportError::SerializationError(e.to_string()))?;

        // For pretty printing, re-indent multi-line values
        if self.pretty && json.contains('\n') {
            let indented = self.indent_multiline(&json);
            self.write_raw(&indented)?;
        } else {
            self.write_raw(&json)?;
        }

        if trailing_comma {
            self.write_raw(",")?;
        }

        Ok(())
    }

    /// Write a key and start an array for it.
    fn write_key_array_start(&mut self, key: &str) -> Result<(), ReportError> {
        self.write_newline()?;
        self.write_indent()?;
        self.write_raw(&format!("\"{key}\":"))?;
        if self.pretty {
            self.write_raw(" ")?;
        }
        self.write_array_start()?;
        Ok(())
    }

    /// Write a single array item.
    fn write_array_item<V: Serialize>(
        &mut self,
        value: &V,
        trailing_comma: bool,
    ) -> Result<(), ReportError> {
        self.write_newline()?;
        self.write_indent()?;

        let json = if self.pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        }
        .map_err(|e| ReportError::SerializationError(e.to_string()))?;

        if self.pretty && json.contains('\n') {
            let indented = self.indent_multiline(&json);
            self.write_raw(&indented)?;
        } else {
            self.write_raw(&json)?;
        }

        if trailing_comma {
            self.write_raw(",")?;
        }

        self.items_written += 1;
        if self.items_written % self.flush_interval == 0 {
            self.writer.flush()?;
        }

        Ok(())
    }

    /// Write raw bytes.
    fn write_raw(&mut self, s: &str) -> Result<(), ReportError> {
        self.writer.write_all(s.as_bytes())?;
        Ok(())
    }

    /// Write a newline if pretty printing.
    fn write_newline(&mut self) -> Result<(), ReportError> {
        if self.pretty {
            self.write_raw("\n")?;
        }
        Ok(())
    }

    /// Write indentation if pretty printing.
    fn write_indent(&mut self) -> Result<(), ReportError> {
        if self.pretty {
            let indent = "  ".repeat(self.indent_level);
            self.write_raw(&indent)?;
        }
        Ok(())
    }

    /// Re-indent a multi-line JSON string.
    fn indent_multiline(&self, json: &str) -> String {
        let base_indent = "  ".repeat(self.indent_level);
        let lines: Vec<&str> = json.lines().collect();
        if lines.len() <= 1 {
            return json.to_string();
        }

        let mut result = String::new();
        result.push_str(lines[0]);
        for line in &lines[1..] {
            result.push('\n');
            result.push_str(&base_indent);
            result.push_str(line);
        }
        result
    }

    /// Write a complete diff report.
    pub fn write_diff_report(
        mut self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<(), ReportError> {
        self.write_object_start()?;

        // Write metadata
        let metadata = StreamingMetadata {
            tool: ToolInfo {
                name: "sbom-tools".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            generated_at: Utc::now().to_rfc3339(),
            old_sbom: SbomInfo {
                format: old_sbom.document.format.to_string(),
                file_path: config.metadata.old_sbom_path.clone(),
                component_count: old_sbom.component_count(),
            },
            new_sbom: Some(SbomInfo {
                format: new_sbom.document.format.to_string(),
                file_path: config.metadata.new_sbom_path.clone(),
                component_count: new_sbom.component_count(),
            }),
        };
        self.write_key_value("metadata", &metadata, true)?;

        // Write summary
        let summary = StreamingSummary {
            total_changes: result.summary.total_changes,
            components_added: result.summary.components_added,
            components_removed: result.summary.components_removed,
            components_modified: result.summary.components_modified,
            vulnerabilities_introduced: result.summary.vulnerabilities_introduced,
            vulnerabilities_resolved: result.summary.vulnerabilities_resolved,
            semantic_score: result.semantic_score,
        };
        self.write_key_value("summary", &summary, true)?;

        // Write components (streamed)
        if config.includes(ReportType::Components) {
            self.write_key_array_start("components_added")?;
            let added_len = result.components.added.len();
            for (i, comp) in result.components.added.iter().enumerate() {
                self.write_array_item(comp, i + 1 < added_len)?;
            }
            self.write_array_end()?;
            self.write_raw(",")?;

            self.write_key_array_start("components_removed")?;
            let removed_len = result.components.removed.len();
            for (i, comp) in result.components.removed.iter().enumerate() {
                self.write_array_item(comp, i + 1 < removed_len)?;
            }
            self.write_array_end()?;
            self.write_raw(",")?;

            self.write_key_array_start("components_modified")?;
            let modified_len = result.components.modified.len();
            for (i, comp) in result.components.modified.iter().enumerate() {
                self.write_array_item(comp, i + 1 < modified_len)?;
            }
            self.write_array_end()?;

            // Check if more sections follow
            let has_more = config.includes(ReportType::Vulnerabilities)
                || config.includes(ReportType::Dependencies)
                || config.includes(ReportType::Licenses);
            if has_more {
                self.write_raw(",")?;
            }
        }

        // Write vulnerabilities (streamed)
        if config.includes(ReportType::Vulnerabilities) {
            self.write_key_array_start("vulnerabilities_introduced")?;
            let introduced_len = result.vulnerabilities.introduced.len();
            for (i, vuln) in result.vulnerabilities.introduced.iter().enumerate() {
                self.write_array_item(vuln, i + 1 < introduced_len)?;
            }
            self.write_array_end()?;
            self.write_raw(",")?;

            self.write_key_array_start("vulnerabilities_resolved")?;
            let resolved_len = result.vulnerabilities.resolved.len();
            for (i, vuln) in result.vulnerabilities.resolved.iter().enumerate() {
                self.write_array_item(vuln, i + 1 < resolved_len)?;
            }
            self.write_array_end()?;

            let has_more =
                config.includes(ReportType::Dependencies) || config.includes(ReportType::Licenses);
            if has_more {
                self.write_raw(",")?;
            }
        }

        // Write dependencies (streamed)
        if config.includes(ReportType::Dependencies) {
            self.write_key_array_start("dependencies_added")?;
            let added_len = result.dependencies.added.len();
            for (i, dep) in result.dependencies.added.iter().enumerate() {
                self.write_array_item(dep, i + 1 < added_len)?;
            }
            self.write_array_end()?;
            self.write_raw(",")?;

            self.write_key_array_start("dependencies_removed")?;
            let removed_len = result.dependencies.removed.len();
            for (i, dep) in result.dependencies.removed.iter().enumerate() {
                self.write_array_item(dep, i + 1 < removed_len)?;
            }
            self.write_array_end()?;

            if config.includes(ReportType::Licenses) {
                self.write_raw(",")?;
            }
        }

        // Write licenses (streamed)
        if config.includes(ReportType::Licenses) {
            self.write_key_array_start("licenses_new")?;
            let new_len = result.licenses.new_licenses.len();
            for (i, lic) in result.licenses.new_licenses.iter().enumerate() {
                self.write_array_item(lic, i + 1 < new_len)?;
            }
            self.write_array_end()?;
            self.write_raw(",")?;

            self.write_key_array_start("licenses_removed")?;
            let removed_len = result.licenses.removed_licenses.len();
            for (i, lic) in result.licenses.removed_licenses.iter().enumerate() {
                self.write_array_item(lic, i + 1 < removed_len)?;
            }
            self.write_array_end()?;
        }

        self.write_object_end()?;
        self.write_newline()?;
        self.writer.flush()?;

        Ok(())
    }
}

// ============================================================================
// NDJSON Writer (Newline-Delimited JSON)
// ============================================================================

/// Writer for Newline-Delimited JSON (NDJSON) format.
///
/// NDJSON is ideal for streaming large datasets where each line is a
/// complete JSON object. This allows easy processing with tools like
/// `jq`, `grep`, or streaming parsers.
pub struct NdjsonWriter<'w, W: Write> {
    writer: &'w mut W,
    flush_interval: usize,
    items_written: usize,
}

impl<'w, W: Write> NdjsonWriter<'w, W> {
    /// Create a new NDJSON writer.
    pub fn new(writer: &'w mut W) -> Self {
        Self {
            writer,
            flush_interval: 100,
            items_written: 0,
        }
    }

    /// Set the flush interval.
    pub fn with_flush_interval(mut self, interval: usize) -> Self {
        self.flush_interval = interval.max(1);
        self
    }

    /// Write a single item as a JSON line.
    pub fn write_item<T: Serialize>(&mut self, item: &T) -> Result<(), ReportError> {
        let json = serde_json::to_string(item)
            .map_err(|e| ReportError::SerializationError(e.to_string()))?;
        self.writer.write_all(json.as_bytes())?;
        self.writer.write_all(b"\n")?;

        self.items_written += 1;
        if self.items_written % self.flush_interval == 0 {
            self.writer.flush()?;
        }

        Ok(())
    }

    /// Write a tagged item (with a type field).
    pub fn write_tagged<T: Serialize>(&mut self, tag: &str, item: &T) -> Result<(), ReportError> {
        #[derive(Serialize)]
        struct Tagged<'a, T> {
            #[serde(rename = "type")]
            type_: &'a str,
            data: &'a T,
        }

        let tagged = Tagged {
            type_: tag,
            data: item,
        };
        self.write_item(&tagged)
    }

    /// Write all components from a diff result.
    pub fn write_diff_components(&mut self, result: &DiffResult) -> Result<(), ReportError> {
        for comp in &result.components.added {
            self.write_tagged("component_added", comp)?;
        }
        for comp in &result.components.removed {
            self.write_tagged("component_removed", comp)?;
        }
        for comp in &result.components.modified {
            self.write_tagged("component_modified", comp)?;
        }
        self.writer.flush()?;
        Ok(())
    }

    /// Write all vulnerabilities from a diff result.
    pub fn write_diff_vulnerabilities(&mut self, result: &DiffResult) -> Result<(), ReportError> {
        for vuln in &result.vulnerabilities.introduced {
            self.write_tagged("vulnerability_introduced", vuln)?;
        }
        for vuln in &result.vulnerabilities.resolved {
            self.write_tagged("vulnerability_resolved", vuln)?;
        }
        for vuln in &result.vulnerabilities.persistent {
            self.write_tagged("vulnerability_persistent", vuln)?;
        }
        self.writer.flush()?;
        Ok(())
    }

    /// Write a complete diff report in NDJSON format.
    ///
    /// The first line is metadata, then components, then vulnerabilities.
    pub fn write_diff_report(
        &mut self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<(), ReportError> {
        // Write metadata as first line
        let metadata = NdjsonMetadata {
            type_: "metadata",
            tool: "sbom-tools",
            version: env!("CARGO_PKG_VERSION"),
            generated_at: Utc::now().to_rfc3339(),
            old_sbom_format: old_sbom.document.format.to_string(),
            new_sbom_format: new_sbom.document.format.to_string(),
            old_component_count: old_sbom.component_count(),
            new_component_count: new_sbom.component_count(),
        };
        self.write_item(&metadata)?;

        // Write summary
        let summary = NdjsonSummary {
            type_: "summary",
            total_changes: result.summary.total_changes,
            components_added: result.summary.components_added,
            components_removed: result.summary.components_removed,
            components_modified: result.summary.components_modified,
            vulnerabilities_introduced: result.summary.vulnerabilities_introduced,
            vulnerabilities_resolved: result.summary.vulnerabilities_resolved,
            semantic_score: result.semantic_score,
        };
        self.write_item(&summary)?;

        // Write components
        if config.includes(ReportType::Components) {
            self.write_diff_components(result)?;
        }

        // Write vulnerabilities
        if config.includes(ReportType::Vulnerabilities) {
            self.write_diff_vulnerabilities(result)?;
        }

        // Write dependencies
        if config.includes(ReportType::Dependencies) {
            for dep in &result.dependencies.added {
                self.write_tagged("dependency_added", dep)?;
            }
            for dep in &result.dependencies.removed {
                self.write_tagged("dependency_removed", dep)?;
            }
        }

        // Write licenses
        if config.includes(ReportType::Licenses) {
            for lic in &result.licenses.new_licenses {
                self.write_tagged("license_new", lic)?;
            }
            for lic in &result.licenses.removed_licenses {
                self.write_tagged("license_removed", lic)?;
            }
        }

        self.writer.flush()?;
        Ok(())
    }

    /// Get the number of items written.
    pub fn items_written(&self) -> usize {
        self.items_written
    }
}

// ============================================================================
// Streaming Reporter Implementation
// ============================================================================

/// A streaming JSON reporter that writes incrementally to a `Write` sink.
///
/// This wraps `StreamingJsonWriter` to provide the `WriterReporter` trait
/// with true incremental output (no full-report buffering).
#[derive(Default)]
pub struct StreamingJsonReporter {
    pretty: bool,
}

impl StreamingJsonReporter {
    /// Create a new streaming JSON reporter.
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// Create a compact (non-pretty) streaming JSON reporter.
    pub fn compact() -> Self {
        Self { pretty: false }
    }
}

impl WriterReporter for StreamingJsonReporter {
    fn write_diff_to<W: Write>(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        let streaming = StreamingJsonWriter::new(writer, self.pretty);
        streaming.write_diff_report(result, old_sbom, new_sbom, config)
    }

    fn write_view_to<W: Write>(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        // For view reports, use the regular JSON reporter
        // (typically smaller, streaming less beneficial)
        use super::JsonReporter;
        use super::ReportGenerator;

        let reporter = JsonReporter::new().pretty(self.pretty);
        let report = reporter.generate_view_report(sbom, config)?;
        writer.write_all(report.as_bytes())?;
        Ok(())
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }
}

/// A streaming NDJSON reporter.
#[derive(Default)]
pub struct NdjsonReporter;

impl NdjsonReporter {
    /// Create a new NDJSON reporter.
    pub fn new() -> Self {
        Self
    }
}

impl WriterReporter for NdjsonReporter {
    fn write_diff_to<W: Write>(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        let mut ndjson = NdjsonWriter::new(writer);
        ndjson.write_diff_report(result, old_sbom, new_sbom, config)
    }

    fn write_view_to<W: Write>(
        &self,
        sbom: &NormalizedSbom,
        _config: &ReportConfig,
        writer: &mut W,
    ) -> Result<(), ReportError> {
        let mut ndjson = NdjsonWriter::new(writer);

        // Write metadata
        #[derive(Serialize)]
        struct ViewMetadata<'a> {
            #[serde(rename = "type")]
            type_: &'a str,
            format: String,
            component_count: usize,
        }

        let metadata = ViewMetadata {
            type_: "metadata",
            format: sbom.document.format.to_string(),
            component_count: sbom.component_count(),
        };
        ndjson.write_item(&metadata)?;

        // Write each component
        for (_, comp) in &sbom.components {
            #[derive(Serialize)]
            struct ComponentLine<'a> {
                #[serde(rename = "type")]
                type_: &'a str,
                name: &'a str,
                version: Option<&'a str>,
                ecosystem: Option<String>,
            }

            let line = ComponentLine {
                type_: "component",
                name: &comp.name,
                version: comp.version.as_deref(),
                ecosystem: comp.ecosystem.as_ref().map(std::string::ToString::to_string),
            };
            ndjson.write_item(&line)?;
        }

        Ok(())
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Json // NDJSON is a variant of JSON
    }
}

// ============================================================================
// Helper Types
// ============================================================================

#[derive(Serialize)]
struct ToolInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct SbomInfo {
    format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    component_count: usize,
}

#[derive(Serialize)]
struct StreamingMetadata {
    tool: ToolInfo,
    generated_at: String,
    old_sbom: SbomInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_sbom: Option<SbomInfo>,
}

#[derive(Serialize)]
struct StreamingSummary {
    total_changes: usize,
    components_added: usize,
    components_removed: usize,
    components_modified: usize,
    vulnerabilities_introduced: usize,
    vulnerabilities_resolved: usize,
    semantic_score: f64,
}

#[derive(Serialize)]
struct NdjsonMetadata<'a> {
    #[serde(rename = "type")]
    type_: &'a str,
    tool: &'a str,
    version: &'a str,
    generated_at: String,
    old_sbom_format: String,
    new_sbom_format: String,
    old_component_count: usize,
    new_component_count: usize,
}

#[derive(Serialize)]
struct NdjsonSummary<'a> {
    #[serde(rename = "type")]
    type_: &'a str,
    total_changes: usize,
    components_added: usize,
    components_removed: usize,
    components_modified: usize,
    vulnerabilities_introduced: usize,
    vulnerabilities_resolved: usize,
    semantic_score: f64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndjson_writer_item() {
        let mut buffer = Vec::new();
        let mut writer = NdjsonWriter::new(&mut buffer);

        #[derive(Serialize)]
        struct TestItem {
            name: String,
            value: i32,
        }

        let item = TestItem {
            name: "test".to_string(),
            value: 42,
        };
        writer.write_item(&item).unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("\"name\":\"test\""));
        assert!(output.contains("\"value\":42"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn test_ndjson_writer_tagged() {
        let mut buffer = Vec::new();
        let mut writer = NdjsonWriter::new(&mut buffer);

        writer.write_tagged("test_type", &42).unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("\"type\":\"test_type\""));
        assert!(output.contains("\"data\":42"));
    }

    #[test]
    fn test_streaming_json_reporter_implements_writer_reporter() {
        let reporter = StreamingJsonReporter::new();
        // Verify it implements WriterReporter (compile-time check via trait method)
        assert_eq!(WriterReporter::format(&reporter), ReportFormat::Json);
    }

    #[test]
    fn test_ndjson_reporter_implements_writer_reporter() {
        let reporter = NdjsonReporter::new();
        assert_eq!(WriterReporter::format(&reporter), ReportFormat::Json);
    }

    #[test]
    fn test_ndjson_writer_items_counted() {
        let mut buffer = Vec::new();
        let mut writer = NdjsonWriter::new(&mut buffer);

        writer.write_item(&1).unwrap();
        writer.write_item(&2).unwrap();
        writer.write_item(&3).unwrap();

        assert_eq!(writer.items_written(), 3);
    }
}
