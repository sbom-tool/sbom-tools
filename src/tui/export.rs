//! TUI export functionality.
//!
//! Provides export capabilities for diff and view modes using the reports module.

use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::reports::{ReportConfig, ReportFormat, ReportType, create_reporter};
use crate::tui::ViewTab;
use crate::tui::app::TabKind;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Export format selection for TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Markdown,
    Html,
    Sarif,
    Csv,
}

impl ExportFormat {
    /// Get file extension for this format
    pub(crate) const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Sarif => "sarif.json",
            Self::Csv => "csv",
        }
    }

    /// Convert to report format
    const fn to_report_format(self) -> ReportFormat {
        match self {
            Self::Json => ReportFormat::Json,
            Self::Markdown => ReportFormat::Markdown,
            Self::Html => ReportFormat::Html,
            Self::Sarif => ReportFormat::Sarif,
            Self::Csv => ReportFormat::Csv,
        }
    }
}

/// Result of an export operation
#[derive(Debug)]
pub struct ExportResult {
    pub path: PathBuf,
    pub success: bool,
    pub message: String,
}

/// Map a diff-mode tab to its corresponding `ReportType`.
///
/// Tabs that represent the full report (Summary, Quality, Compliance, etc.)
/// map to `ReportType::All`.
#[must_use]
pub const fn tab_to_report_type(tab: TabKind) -> ReportType {
    match tab {
        TabKind::Components => ReportType::Components,
        TabKind::Dependencies => ReportType::Dependencies,
        TabKind::Licenses => ReportType::Licenses,
        TabKind::Vulnerabilities => ReportType::Vulnerabilities,
        TabKind::Summary
        | TabKind::Quality
        | TabKind::Compliance
        | TabKind::SideBySide
        | TabKind::GraphChanges
        | TabKind::Source => ReportType::All,
    }
}

/// Map a view-mode tab to its corresponding `ReportType`.
#[must_use]
pub const fn view_tab_to_report_type(tab: ViewTab) -> ReportType {
    match tab {
        ViewTab::Tree => ReportType::Components,
        ViewTab::Vulnerabilities => ReportType::Vulnerabilities,
        ViewTab::Licenses => ReportType::Licenses,
        ViewTab::Dependencies => ReportType::Dependencies,
        ViewTab::Overview
        | ViewTab::Quality
        | ViewTab::Compliance
        | ViewTab::Source
        | ViewTab::Crypto
        | ViewTab::Algorithms
        | ViewTab::Certificates
        | ViewTab::Keys
        | ViewTab::Protocols
        | ViewTab::PqcCompliance
        | ViewTab::Models
        | ViewTab::Datasets
        | ViewTab::AiReadiness => ReportType::All,
    }
}

/// Get the export scope label for a diff-mode tab.
#[must_use]
pub const fn tab_export_scope(tab: TabKind) -> &'static str {
    match tab {
        TabKind::Components => "Components",
        TabKind::Dependencies => "Dependencies",
        TabKind::Licenses => "Licenses",
        TabKind::Vulnerabilities => "Vulnerabilities",
        _ => "Report",
    }
}

/// Get the export scope label for a view-mode tab.
#[must_use]
pub const fn view_tab_export_scope(tab: ViewTab) -> &'static str {
    match tab {
        ViewTab::Tree => "Components",
        ViewTab::Vulnerabilities => "Vulnerabilities",
        ViewTab::Licenses => "Licenses",
        ViewTab::Dependencies => "Dependencies",
        _ => "Report",
    }
}

/// Expand a filename template with placeholders.
///
/// Supported placeholders:
/// - `{date}` → YYYY-MM-DD
/// - `{time}` → HHMMSS
/// - `{format}` → json, md, html, etc.
/// - `{command}` → diff, view, compliance, matrix
fn expand_template(template: &str, command: &str, format: &ExportFormat) -> String {
    let now = chrono::Local::now();
    template
        .replace("{date}", &now.format("%Y-%m-%d").to_string())
        .replace("{time}", &now.format("%H%M%S").to_string())
        .replace("{format}", format.extension())
        .replace("{command}", command)
}

/// Build an export filename from an optional template, falling back to timestamp.
fn build_export_filename(
    template: Option<&str>,
    command: &str,
    format: &ExportFormat,
    output_dir: Option<&str>,
) -> PathBuf {
    let filename = if let Some(tmpl) = template {
        let expanded = expand_template(tmpl, command, format);
        // Append extension if the template doesn't already have one
        if std::path::Path::new(&expanded).extension().is_some() {
            expanded
        } else {
            format!("{expanded}.{}", format.extension())
        }
    } else {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        format!("sbom_{command}_{timestamp}.{}", format.extension())
    };
    output_dir.map_or_else(
        || PathBuf::from(&filename),
        |dir| PathBuf::from(dir).join(&filename),
    )
}

/// Export diff results to a file
pub fn export_diff(
    format: ExportFormat,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    output_dir: Option<&str>,
    config: &ReportConfig,
    template: Option<&str>,
) -> ExportResult {
    let path = build_export_filename(template, "diff", &format, output_dir);
    export_with_reporter(
        format.to_report_format(),
        result,
        old_sbom,
        new_sbom,
        &path,
        config,
    )
}

/// Export single SBOM to a file (view mode)
pub fn export_view(
    format: ExportFormat,
    sbom: &NormalizedSbom,
    output_dir: Option<&str>,
    config: &ReportConfig,
    template: Option<&str>,
) -> ExportResult {
    let path = build_export_filename(template, "view", &format, output_dir);
    export_view_with_reporter(format.to_report_format(), sbom, &path, config)
}

fn export_with_reporter(
    report_format: ReportFormat,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    path: &Path,
    config: &ReportConfig,
) -> ExportResult {
    let reporter = create_reporter(report_format);

    match reporter.generate_diff_report(result, old_sbom, new_sbom, config) {
        Ok(content) => match write_to_file(path, &content) {
            Ok(actual_path) => ExportResult {
                message: format!("Exported to {}", display_path(&actual_path)),
                path: actual_path,
                success: true,
            },
            Err(e) => ExportResult {
                path: path.to_path_buf(),
                success: false,
                message: format!("Failed to write file: {e}"),
            },
        },
        Err(e) => ExportResult {
            path: path.to_path_buf(),
            success: false,
            message: format!("Failed to generate report: {e}"),
        },
    }
}

fn export_view_with_reporter(
    report_format: ReportFormat,
    sbom: &NormalizedSbom,
    path: &Path,
    config: &ReportConfig,
) -> ExportResult {
    let reporter = create_reporter(report_format);

    match reporter.generate_view_report(sbom, config) {
        Ok(content) => match write_to_file(path, &content) {
            Ok(actual_path) => ExportResult {
                message: format!("Exported to {}", display_path(&actual_path)),
                path: actual_path,
                success: true,
            },
            Err(e) => ExportResult {
                path: path.to_path_buf(),
                success: false,
                message: format!("Failed to write file: {e}"),
            },
        },
        Err(e) => ExportResult {
            path: path.to_path_buf(),
            success: false,
            message: format!("Failed to generate report: {e}"),
        },
    }
}

/// Export compliance results to a file.
///
/// All five export formats are supported: JSON, SARIF, Markdown, HTML, CSV.
pub fn export_compliance(
    format: ExportFormat,
    results: &[crate::quality::ComplianceResult],
    selected_standard: usize,
    output_dir: Option<&str>,
    template: Option<&str>,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let result = results.get(selected_standard);

    let (ext, content) = match format {
        ExportFormat::Json => {
            let json = compliance_to_json(results, selected_standard);
            ("json", json)
        }
        ExportFormat::Sarif => {
            let sarif = compliance_to_sarif(result);
            ("sarif.json", sarif)
        }
        ExportFormat::Markdown => {
            let md = compliance_to_markdown(results, selected_standard);
            ("md", md)
        }
        ExportFormat::Html => {
            let html = compliance_to_html(results, selected_standard);
            ("html", html)
        }
        ExportFormat::Csv => {
            let csv = compliance_to_csv(results, selected_standard);
            ("csv", csv)
        }
    };

    let path = if let Some(tmpl) = template {
        let expanded = expand_template(tmpl, "compliance", &format);
        let expanded = if std::path::Path::new(&expanded).extension().is_some() {
            expanded
        } else {
            format!("{expanded}.{ext}")
        };
        output_dir.map_or_else(
            || PathBuf::from(&expanded),
            |dir| PathBuf::from(dir).join(&expanded),
        )
    } else {
        let level_name = result.map_or_else(
            || "all".to_string(),
            |r| r.level.name().to_lowercase().replace(' ', "_"),
        );
        let filename = format!("compliance_{level_name}_{timestamp}.{ext}");
        output_dir.map_or_else(
            || PathBuf::from(&filename),
            |dir| PathBuf::from(dir).join(&filename),
        )
    };

    match write_to_file(&path, &content) {
        Ok(actual_path) => ExportResult {
            message: format!("Compliance exported to {}", display_path(&actual_path)),
            path: actual_path,
            success: true,
        },
        Err(e) => ExportResult {
            path,
            success: false,
            message: format!("Failed to write: {e}"),
        },
    }
}

/// Serialize the canonical serde [`crate::quality::ComplianceResult`] —
/// the exact same shape `validate -o json` emits (single result → object,
/// all standards → array). No hand-rolled mirror: field additions to the
/// result contract (applicability, conformity summary, standard refs)
/// flow through automatically.
fn compliance_to_json(results: &[crate::quality::ComplianceResult], selected: usize) -> String {
    results.get(selected).map_or_else(
        || serde_json::to_string_pretty(results).unwrap_or_default(),
        |r| serde_json::to_string_pretty(r).unwrap_or_default(),
    )
}

/// Canonical status label for a compliance result. N/A results must never
/// render as a pass (`is_compliant` stays `true` for them by contract).
fn compliance_status_label(r: &crate::quality::ComplianceResult) -> &'static str {
    if !r.is_applicable() {
        "NOT APPLICABLE"
    } else if r.is_compliant {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    }
}

/// Shared badge score via [`crate::quality::ComplianceResult::score`];
/// "N/A" when the standard did not evaluate the SBOM.
fn compliance_score_label(r: &crate::quality::ComplianceResult) -> String {
    r.score()
        .map_or_else(|| "N/A".to_string(), |s| format!("{s}%"))
}

/// ` | Passed: N` for the summary line of a result that passed checks, empty
/// otherwise. Passed checks are counted, never listed among the violations.
fn passed_suffix(r: &crate::quality::ComplianceResult) -> String {
    if r.passed.is_empty() {
        String::new()
    } else {
        format!(" | Passed: {}", r.passed.len())
    }
}

/// Human-readable reason when a standard did not evaluate the SBOM.
fn not_applicable_reason(r: &crate::quality::ComplianceResult) -> Option<&str> {
    match &r.applicability {
        crate::quality::Applicability::NotApplicable(reason) => Some(reason),
        crate::quality::Applicability::Applicable => None,
    }
}

/// Delegate to the proper SARIF generator in `reports::sarif`.
fn compliance_to_sarif(result: Option<&crate::quality::ComplianceResult>) -> String {
    let Some(result) = result else {
        return r#"{"error": "no compliance result selected"}"#.to_string();
    };

    crate::reports::generate_compliance_sarif(result)
        .unwrap_or_else(|e| format!(r#"{{"error": "{e}"}}"#))
}

/// Escape `|` in markdown table cell content so untrusted SBOM values
/// (component names in `element`, requirement text) cannot shift every
/// subsequent column of the row. The sibling HTML/CSV exports already
/// escape via `escape_html`/`csv_escape`.
fn md_escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn compliance_to_markdown(results: &[crate::quality::ComplianceResult], selected: usize) -> String {
    let mut md = String::new();

    let items: Vec<&crate::quality::ComplianceResult> = results
        .get(selected)
        .map_or_else(|| results.iter().collect(), |r| vec![r]);

    for r in items {
        md.push_str(&format!(
            "# {} - {}\n\n",
            r.level.name(),
            compliance_status_label(r)
        ));
        if let Some(reason) = not_applicable_reason(r) {
            md.push_str(&format!("Not applicable: {reason}\n\n"));
            continue;
        }
        md.push_str(&format!("Score: {}\n\n", compliance_score_label(r)));
        md.push_str(&format!(
            "Errors: {} | Warnings: {} | Info: {}{}\n\n",
            r.error_count,
            r.warning_count,
            r.info_count,
            passed_suffix(r)
        ));

        if r.violations.is_empty() {
            md.push_str("No violations found.\n\n");
            continue;
        }

        md.push_str("| Severity | Rule ID | Category | Requirement | Element | Remediation |\n");
        md.push_str("|----------|---------|----------|-------------|---------|-------------|\n");
        for v in &r.violations {
            let element = v.element.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                v.severity.name(),
                v.rule_id,
                v.category.name(),
                md_escape_cell(&v.requirement),
                md_escape_cell(element),
                md_escape_cell(&v.remediation_guidance()),
            ));
        }
        md.push('\n');
    }

    md
}

fn compliance_to_csv(results: &[crate::quality::ComplianceResult], selected: usize) -> String {
    let mut lines = vec![
        "Standard,Status,Severity,RuleId,Category,Requirement,Element,Message,Remediation"
            .to_string(),
    ];

    let items: Vec<&crate::quality::ComplianceResult> = results
        .get(selected)
        .map_or_else(|| results.iter().collect(), |r| vec![r]);

    for r in &items {
        let std_name = r.level.name();
        let status = compliance_status_label(r);
        if !r.is_applicable() {
            // One status row: an unevaluated standard has no actionable
            // violations; the row carries the reason it did not apply.
            let reason = not_applicable_reason(r).unwrap_or("");
            lines.push(format!(
                "\"{std_name}\",\"{status}\",\"\",\"\",\"\",\"\",\"\",\"{}\",\"\"",
                csv_escape(reason),
            ));
            continue;
        }
        for v in &r.violations {
            let element = v.element.as_deref().unwrap_or("");
            lines.push(format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                std_name,
                status,
                v.severity.name(),
                v.rule_id,
                csv_escape(v.category.name()),
                csv_escape(&v.requirement),
                csv_escape(element),
                csv_escape(&v.message),
                csv_escape(&v.remediation_guidance()),
            ));
        }
    }

    lines.join("\n")
}

fn compliance_to_html(results: &[crate::quality::ComplianceResult], selected: usize) -> String {
    use crate::reports::escape::escape_html;

    let items: Vec<&crate::quality::ComplianceResult> = results
        .get(selected)
        .map_or_else(|| results.iter().collect(), |r| vec![r]);

    let mut html = String::from(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SBOM Compliance Report</title>
<style>
body { font-family: system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 2rem; }
h1, h2 { color: #89b4fa; }
table { border-collapse: collapse; margin: 1rem 0; width: 100%; }
th, td { padding: 8px 12px; border: 1px solid #45475a; text-align: left; }
th { background: #313244; color: #89b4fa; font-weight: 600; }
.error { color: #f38ba8; }
.warning { color: #f9e2af; }
.info { color: #89b4fa; }
.pass { color: #a6e3a1; font-weight: bold; }
.fail { color: #f38ba8; font-weight: bold; }
.na { color: #a6adc8; font-weight: bold; }
.summary { margin: 1rem 0; color: #a6adc8; }
</style></head><body>
<h1>SBOM Compliance Report</h1>
<p class="summary">Generated by sbom-tools</p>
"#,
    );

    for r in &items {
        let status_class = if !r.is_applicable() {
            "na"
        } else if r.is_compliant {
            "pass"
        } else {
            "fail"
        };
        let status_label = compliance_status_label(r);
        html.push_str(&format!(
            "<h2>{} - <span class=\"{status_class}\">{status_label}</span></h2>\n",
            escape_html(r.level.name()),
        ));
        if let Some(reason) = not_applicable_reason(r) {
            html.push_str(&format!("<p>Not applicable: {}</p>\n", escape_html(reason)));
            continue;
        }
        html.push_str(&format!(
            "<p>Score: {} | Errors: {} | Warnings: {} | Info: {}{}</p>\n",
            compliance_score_label(r),
            r.error_count,
            r.warning_count,
            r.info_count,
            passed_suffix(r)
        ));

        if r.violations.is_empty() {
            html.push_str("<p>No violations found.</p>\n");
            continue;
        }

        html.push_str("<table><tr><th>Severity</th><th>Rule ID</th><th>Category</th><th>Requirement</th><th>Element</th><th>Message</th><th>Remediation</th></tr>\n");
        for v in &r.violations {
            let sev_class = match v.severity {
                crate::quality::ViolationSeverity::Error => "error",
                crate::quality::ViolationSeverity::Warning => "warning",
                crate::quality::ViolationSeverity::Info => "info",
            };
            let element = v.element.as_deref().unwrap_or("-");
            html.push_str(&format!(
                "<tr><td class=\"{sev_class}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                v.severity.name(),
                escape_html(v.rule_id),
                escape_html(v.category.name()),
                escape_html(&v.requirement),
                escape_html(element),
                escape_html(&v.message),
                escape_html(&v.remediation_guidance()),
            ));
        }
        html.push_str("</table>\n");
    }

    html.push_str("</body></html>");
    html
}

/// Export raw source content to a file.
///
/// Detects XML vs JSON from content prefix and writes to `sbom-source-{label}.{ext}`.
pub fn export_source_content(content: &str, label: &str) -> ExportResult {
    let ext = if content.trim_start().starts_with('<') {
        "xml"
    } else {
        "json"
    };
    let filename = format!("sbom-source-{label}.{ext}");
    let path = PathBuf::from(&filename);

    match write_to_file(&path, content) {
        Ok(actual_path) => ExportResult {
            message: format!("Source exported to {}", display_path(&actual_path)),
            path: actual_path,
            success: true,
        },
        Err(e) => ExportResult {
            path,
            success: false,
            message: format!("Failed to write: {e}"),
        },
    }
}

/// Escape a value for CSV: double any embedded quotes.
fn csv_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}

/// Export multi-diff (1:N baseline comparison) results to a file.
///
/// JSON only: the result is the canonical serde `MultiDiffResult`.
pub fn export_multi_diff(
    format: ExportFormat,
    result: &crate::diff::MultiDiffResult,
    template: Option<&str>,
) -> ExportResult {
    export_serde_json_only(format, result, "multi_diff", template)
}

/// Export timeline analysis results to a file.
///
/// JSON only: the result is the canonical serde `TimelineResult`.
pub fn export_timeline(
    format: ExportFormat,
    result: &crate::diff::TimelineResult,
    template: Option<&str>,
) -> ExportResult {
    export_serde_json_only(format, result, "timeline", template)
}

/// Shared JSON-only exporter for the multi-comparison result structs.
fn export_serde_json_only<T: serde::Serialize>(
    format: ExportFormat,
    result: &T,
    command: &str,
    template: Option<&str>,
) -> ExportResult {
    let path = build_export_filename(template, command, &format, None);
    if format != ExportFormat::Json {
        return ExportResult {
            path,
            success: false,
            message: format!("{command} export supports JSON only — press j"),
        };
    }
    let content = serde_json::to_string_pretty(result).unwrap_or_default();
    match write_to_file(&path, &content) {
        Ok(actual_path) => ExportResult {
            message: format!("Exported to {}", display_path(&actual_path)),
            path: actual_path,
            success: true,
        },
        Err(e) => ExportResult {
            path,
            success: false,
            message: format!("Failed to write: {e}"),
        },
    }
}

/// Export matrix results to a file (JSON, CSV, or HTML)
pub fn export_matrix(
    format: ExportFormat,
    result: &crate::diff::MatrixResult,
    template: Option<&str>,
) -> ExportResult {
    let path = build_export_filename(template, "matrix", &format, None);

    let content = match format {
        ExportFormat::Json => matrix_to_json(result),
        ExportFormat::Csv => matrix_to_csv(result),
        ExportFormat::Html => matrix_to_html(result),
        _ => {
            return ExportResult {
                path,
                success: false,
                message: "Matrix export supports JSON, CSV, and HTML".to_string(),
            };
        }
    };

    match write_to_file(&path, &content) {
        Ok(actual_path) => ExportResult {
            message: format!("Matrix exported to {}", display_path(&actual_path)),
            path: actual_path,
            success: true,
        },
        Err(e) => ExportResult {
            path,
            success: false,
            message: format!("Failed to write: {e}"),
        },
    }
}

fn matrix_to_json(result: &crate::diff::MatrixResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_default()
}

fn matrix_to_csv(result: &crate::diff::MatrixResult) -> String {
    let n = result.sboms.len();
    let mut lines = Vec::with_capacity(n + 1);

    // Header row: empty cell + SBOM names
    let mut header = String::from("\"\"");
    for sbom in &result.sboms {
        header.push_str(&format!(",\"{}\"", sbom.name.replace('"', "\"\"")));
    }
    lines.push(header);

    // Data rows: SBOM name + similarity scores
    for i in 0..n {
        let mut row = format!("\"{}\"", result.sboms[i].name.replace('"', "\"\""));
        for j in 0..n {
            if i == j {
                row.push_str(",1.000");
            } else {
                let score = result.get_similarity(i, j);
                row.push_str(&format!(",{score:.3}"));
            }
        }
        lines.push(row);
    }

    lines.join("\n")
}

fn matrix_to_html(result: &crate::diff::MatrixResult) -> String {
    use crate::reports::escape::escape_html;

    let n = result.sboms.len();
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SBOM Similarity Matrix</title>
<style>
body { font-family: system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 2rem; }
h1 { color: #89b4fa; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { padding: 8px 12px; border: 1px solid #45475a; text-align: center; }
th { background: #313244; color: #89b4fa; font-weight: 600; }
.high { background: #a6e3a1; color: #1e1e2e; }
.medium { background: #f9e2af; color: #1e1e2e; }
.low { background: #f38ba8; color: #1e1e2e; }
.self { background: #585b70; color: #a6adc8; }
.info { margin: 1rem 0; color: #a6adc8; }
</style></head><body>
<h1>SBOM Similarity Matrix</h1>
<p class="info">Generated by sbom-tools</p>
<table><tr><th></th>"#,
    );

    // Header row
    for sbom in &result.sboms {
        html.push_str(&format!("<th>{}</th>", escape_html(&sbom.name)));
    }
    html.push_str("</tr>");

    // Data rows
    for i in 0..n {
        html.push_str(&format!(
            "<tr><th>{}</th>",
            escape_html(&result.sboms[i].name)
        ));
        for j in 0..n {
            if i == j {
                html.push_str("<td class=\"self\">-</td>");
            } else {
                let score = result.get_similarity(i, j);
                let class = if score >= 0.8 {
                    "high"
                } else if score >= 0.5 {
                    "medium"
                } else {
                    "low"
                };
                html.push_str(&format!("<td class=\"{class}\">{score:.1}%</td>"));
            }
        }
        html.push_str("</tr>");
    }

    html.push_str("</table>");

    // Clustering info
    if let Some(ref clustering) = result.clustering {
        html.push_str("<h2>Clusters</h2><ul>");
        for (idx, cluster) in clustering.clusters.iter().enumerate() {
            let names: Vec<&str> = cluster
                .members
                .iter()
                .filter_map(|&i| result.sboms.get(i).map(|s| s.name.as_str()))
                .collect();
            html.push_str(&format!(
                "<li>Cluster {} (avg similarity: {:.1}%): {}</li>",
                idx + 1,
                cluster.internal_similarity * 100.0,
                names.join(", ")
            ));
        }
        html.push_str("</ul>");
    }

    html.push_str("</body></html>");
    html
}

/// Write content to a file, auto-renaming if the path already exists.
///
/// Returns the actual path written to (which may differ from `path` if
/// the original was renamed to avoid overwriting).
fn write_to_file(path: &Path, content: &str) -> std::io::Result<PathBuf> {
    let actual_path = find_available_path(path);
    // Create the parent directory so exports can target a new subdirectory.
    if let Some(parent) = actual_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(&actual_path)?;
    file.write_all(content.as_bytes())?;
    Ok(actual_path)
}

/// Find an available path by appending `_2`, `_3`, etc. if the path already exists.
fn find_available_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("export");
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let parent = path.parent();

    // Handle double extensions like .sarif.json
    let (base_stem, full_ext) = if stem.ends_with(".sarif") && extension == "json" {
        (stem.strip_suffix(".sarif").unwrap_or(stem), "sarif.json")
    } else {
        (stem, extension)
    };

    for i in 2..=99 {
        let new_name = if full_ext.is_empty() {
            format!("{base_stem}_{i}")
        } else {
            format!("{base_stem}_{i}.{full_ext}")
        };
        let new_path = parent.map_or_else(|| PathBuf::from(&new_name), |p| p.join(&new_name));
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback: just return the original path (will overwrite)
    path.to_path_buf()
}

/// Resolve a path to an absolute path for display in status messages.
fn display_path(path: &PathBuf) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    }
}

#[cfg(test)]
mod compliance_export_tests {
    use super::{
        compliance_to_csv, compliance_to_html, compliance_to_json, compliance_to_markdown,
    };
    use crate::quality::{
        Applicability, ComplianceLevel, ComplianceResult, Violation, ViolationCategory,
        ViolationSeverity,
    };

    const RULE_ID: &str = "SBOM-BSI-TR-03183-2-VERSION";
    /// Why the fixture's readiness standard did not apply.
    const NA_REASON: &str = "SBOM contains no ML components";

    fn violation(rule_id: &'static str, severity: ViolationSeverity) -> Violation {
        Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: "test finding message".to_string(),
            element: Some("comp-a".to_string()),
            requirement: "Test requirement".to_string(),
            rule_id,
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
        }
    }

    /// One applicable NON-COMPLIANT result + one N/A readiness result.
    fn fixture() -> Vec<ComplianceResult> {
        let applicable = ComplianceResult::new(
            ComplianceLevel::BsiTr03183_2,
            vec![violation(RULE_ID, ViolationSeverity::Error)],
        );
        let not_applicable = ComplianceResult::not_applicable(ComplianceLevel::EuAiAct, NA_REASON);
        assert!(!not_applicable.is_applicable(), "fixture must be N/A");
        vec![applicable, not_applicable]
    }

    #[test]
    fn json_export_roundtrips_canonical_serde_result() {
        let results = fixture();
        let json = compliance_to_json(&results, 0);

        // Must parse back through the canonical serde contract — same shape
        // as `validate -o json` — not a hand-rolled mirror.
        let parsed: ComplianceResult =
            serde_json::from_str(&json).expect("canonical ComplianceResult JSON");
        assert_eq!(parsed.level, ComplianceLevel::BsiTr03183_2);
        assert!(!parsed.is_compliant);
        assert_eq!(parsed.error_count, 1);
        assert_eq!(parsed.violations.len(), 1);
        assert_eq!(parsed.violations[0].severity, ViolationSeverity::Error);

        // Severity must be the serde form ("Error"), not a Debug artifact
        // of a hand-rolled object.
        assert!(json.contains("\"severity\": \"Error\""));
    }

    #[test]
    fn json_export_all_standards_is_canonical_serde_array() {
        let results = fixture();
        // Out-of-range selection = "all standards" → serde array, matching
        // the multi-standard `validate -o json` shape.
        let json = compliance_to_json(&results, results.len());
        let parsed: Vec<ComplianceResult> =
            serde_json::from_str(&json).expect("canonical ComplianceResult array");
        assert_eq!(parsed.len(), 2);
        assert!(matches!(
            parsed[1].applicability,
            Applicability::NotApplicable(_)
        ));
    }

    #[test]
    fn markdown_includes_rule_id_shared_score_and_severity_label() {
        let results = fixture();
        let md = compliance_to_markdown(&results, 0);

        assert!(md.contains(RULE_ID), "markdown must carry stable rule ids");
        assert!(md.contains("NON-COMPLIANT"));
        assert!(md.contains("| Error |"), "severity via canonical label");
        // Shared ComplianceResult::score(): 1 error → 100/(1+1) = 50.
        let expected = format!("Score: {}%", results[0].score().expect("applicable score"));
        assert!(md.contains(&expected), "score must come from score()");
    }

    #[test]
    fn markdown_escapes_pipes_in_table_cells() {
        // Component names are untrusted SBOM input and may legally contain
        // '|' (CycloneDX name fields); unescaped they shift every following
        // column of the table row.
        let mut v = violation(RULE_ID, ViolationSeverity::Error);
        v.element = Some("lib|4.x".to_string());
        v.requirement = "Field a | field b".to_string();
        let results = vec![ComplianceResult::new(
            ComplianceLevel::BsiTr03183_2,
            vec![v],
        )];

        let md = compliance_to_markdown(&results, 0);

        assert!(
            md.contains("lib\\|4.x"),
            "element cell must escape '|': {md}"
        );
        assert!(
            md.contains("Field a \\| field b"),
            "requirement cell must escape '|': {md}"
        );
        assert!(
            !md.contains("| lib|4.x |"),
            "raw pipe must not survive inside a cell: {md}"
        );
    }

    /// Passed checks are counted on the summary line and listed nowhere.
    #[test]
    fn exports_count_passed_checks_and_list_none() {
        let pass = crate::quality::PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm".to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Vec::new(),
        };
        let results = vec![
            ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new()).with_passed(vec![pass]),
        ];
        let md = compliance_to_markdown(&results, 0);
        assert!(
            md.contains("Errors: 0 | Warnings: 0 | Info: 0 | Passed: 1"),
            "{md}"
        );
        assert!(!md.contains("NIST-approved"), "no pass is listed: {md}");
        let html = compliance_to_html(&results, 0);
        assert!(html.contains("| Info: 0 | Passed: 1</p>"), "{html}");
        assert!(!html.contains("NIST-approved"), "{html}");
        let csv = compliance_to_csv(&results, 0);
        assert!(!csv.contains("SBOM-PQC-009"), "{csv}");

        // A result that passed nothing keeps its summary line.
        let md = compliance_to_markdown(&fixture(), 0);
        assert!(!md.contains("Passed"), "{md}");
    }

    #[test]
    fn markdown_renders_not_applicable_instead_of_compliant() {
        let results = fixture();
        let md = compliance_to_markdown(&results, 1);

        assert!(md.contains("NOT APPLICABLE"));
        // "NOT APPLICABLE" carries no COMPLIANT substring, so the whole
        // document must be free of both COMPLIANT and NON-COMPLIANT.
        assert!(
            !md.contains("COMPLIANT"),
            "an unevaluated standard must not render as a pass: {md}"
        );
        assert!(md.contains(NA_REASON), "reason surfaced");
    }

    #[test]
    fn csv_includes_rule_id_and_not_applicable_status() {
        let results = fixture();

        let selected = compliance_to_csv(&results, 0);
        let mut lines = selected.lines();
        assert_eq!(
            lines.next(),
            Some(
                "Standard,Status,Severity,RuleId,Category,Requirement,Element,Message,Remediation"
            )
        );
        let row = lines.next().expect("one violation row");
        assert!(row.contains(&format!("\"{RULE_ID}\"")));
        assert!(row.contains("\"NON-COMPLIANT\""));
        assert!(row.contains("\"Error\""));

        let all = compliance_to_csv(&results, results.len());
        assert!(all.contains("\"NOT APPLICABLE\""));
        assert!(
            !all.contains("\"COMPLIANT\""),
            "N/A standard must not emit a COMPLIANT row: {all}"
        );
    }

    #[test]
    fn html_includes_rule_id_and_not_applicable_status() {
        let results = fixture();

        let selected = compliance_to_html(&results, 0);
        assert!(selected.contains(RULE_ID), "html must carry rule ids");
        assert!(selected.contains("NON-COMPLIANT"));
        assert!(selected.contains(">Error<"), "severity via canonical label");
        let expected = format!("Score: {}%", results[0].score().expect("applicable score"));
        assert!(selected.contains(&expected));

        let na = compliance_to_html(&results, 1);
        assert!(na.contains("NOT APPLICABLE"));
        assert!(na.contains("class=\"na\""));
        assert!(
            !na.contains(">COMPLIANT<"),
            "N/A standard must not render as a pass: {na}"
        );
    }
}

#[cfg(test)]
mod write_tests {
    use super::write_to_file;

    #[test]
    fn creates_missing_parent_directories() {
        let base = std::env::temp_dir().join(format!("sbom-tools-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base); // clean slate
        let path = base.join("nested").join("sub").join("report.txt");
        assert!(!path.parent().unwrap().exists());

        let written = write_to_file(&path, "hello").expect("should create parents and write");

        assert!(written.exists());
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "hello");
        let _ = std::fs::remove_dir_all(&base);
    }
}
