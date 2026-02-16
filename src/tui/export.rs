//! TUI export functionality.
//!
//! Provides export capabilities for diff and view modes using the reports module.

use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::reports::{create_reporter, ReportConfig, ReportFormat};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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

/// Export diff results to a file
pub fn export_diff(
    format: ExportFormat,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    output_dir: Option<&str>,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("sbom_tools_{}.{}", timestamp, format.extension());
    let path = output_dir.map_or_else(|| PathBuf::from(&filename), |dir| PathBuf::from(dir).join(&filename));

    export_with_reporter(format.to_report_format(), result, old_sbom, new_sbom, &path)
}

/// Export single SBOM to a file (view mode)
pub fn export_view(
    format: ExportFormat,
    sbom: &NormalizedSbom,
    output_dir: Option<&str>,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("sbom_report_{}.{}", timestamp, format.extension());
    let path = output_dir.map_or_else(|| PathBuf::from(&filename), |dir| PathBuf::from(dir).join(&filename));

    export_view_with_reporter(format.to_report_format(), sbom, &path)
}

fn export_with_reporter(
    report_format: ReportFormat,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    path: &PathBuf,
) -> ExportResult {
    let reporter = create_reporter(report_format);
    let config = ReportConfig::default();

    match reporter.generate_diff_report(result, old_sbom, new_sbom, &config) {
        Ok(content) => match write_to_file(path, &content) {
            Ok(()) => ExportResult {
                path: path.clone(),
                success: true,
                message: format!("Exported to {}", path.display()),
            },
            Err(e) => ExportResult {
                path: path.clone(),
                success: false,
                message: format!("Failed to write file: {e}"),
            },
        },
        Err(e) => ExportResult {
            path: path.clone(),
            success: false,
            message: format!("Failed to generate report: {e}"),
        },
    }
}

fn export_view_with_reporter(
    report_format: ReportFormat,
    sbom: &NormalizedSbom,
    path: &PathBuf,
) -> ExportResult {
    let reporter = create_reporter(report_format);
    let config = ReportConfig::default();

    match reporter.generate_view_report(sbom, &config) {
        Ok(content) => match write_to_file(path, &content) {
            Ok(()) => ExportResult {
                path: path.clone(),
                success: true,
                message: format!("Exported to {}", path.display()),
            },
            Err(e) => ExportResult {
                path: path.clone(),
                success: false,
                message: format!("Failed to write file: {e}"),
            },
        },
        Err(e) => ExportResult {
            path: path.clone(),
            success: false,
            message: format!("Failed to generate report: {e}"),
        },
    }
}


/// Export compliance results to a file (JSON or SARIF)
pub fn export_compliance(
    format: ExportFormat,
    results: &[crate::quality::ComplianceResult],
    selected_standard: usize,
    output_dir: Option<&str>,
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
        _ => {
            return ExportResult {
                path: PathBuf::new(),
                success: false,
                message: "Compliance export supports JSON and SARIF only".to_string(),
            };
        }
    };

    let level_name = result.map_or_else(|| "all".to_string(), |r| r.level.name().to_lowercase().replace(' ', "_"));
    let filename = format!("compliance_{level_name}_{timestamp}.{ext}");
    let path = output_dir.map_or_else(|| PathBuf::from(&filename), |dir| PathBuf::from(dir).join(&filename));

    match write_to_file(&path, &content) {
        Ok(()) => ExportResult {
            path: path.clone(),
            success: true,
            message: format!("Compliance exported to {}", path.display()),
        },
        Err(e) => ExportResult {
            path,
            success: false,
            message: format!("Failed to write: {e}"),
        },
    }
}

fn compliance_to_json(
    results: &[crate::quality::ComplianceResult],
    selected: usize,
) -> String {
    use serde_json::{json, Value};

    let to_value = |r: &crate::quality::ComplianceResult| -> Value {
        let violations: Vec<Value> = r
            .violations
            .iter()
            .map(|v| {
                json!({
                    "severity": format!("{:?}", v.severity),
                    "category": v.category.name(),
                    "message": v.message,
                    "element": v.element,
                    "requirement": v.requirement,
                    "remediation": v.remediation_guidance(),
                })
            })
            .collect();

        json!({
            "standard": r.level.name(),
            "is_compliant": r.is_compliant,
            "error_count": r.error_count,
            "warning_count": r.warning_count,
            "info_count": r.info_count,
            "violations": violations,
        })
    };

    let output = results.get(selected).map_or_else(
        || {
            let all: Vec<Value> = results.iter().map(to_value).collect();
            json!({ "standards": all })
        },
        to_value,
    );

    serde_json::to_string_pretty(&output).unwrap_or_default()
}

fn compliance_to_sarif(
    result: Option<&crate::quality::ComplianceResult>,
) -> String {
    use serde_json::{json, Value};

    let Some(result) = result else {
        return json!({"error": "no compliance result"}).to_string();
    };

    let results: Vec<Value> = result
        .violations
        .iter()
        .map(|v| {
            let level = match v.severity {
                crate::quality::ViolationSeverity::Error => "error",
                crate::quality::ViolationSeverity::Warning => "warning",
                crate::quality::ViolationSeverity::Info => "note",
            };
            json!({
                "ruleId": format!("COMPLIANCE-{}", v.category.name().to_uppercase().replace(' ', "-")),
                "level": level,
                "message": { "text": v.message },
                "properties": {
                    "requirement": v.requirement,
                    "category": v.category.name(),
                    "remediation": v.remediation_guidance(),
                    "element": v.element,
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sbom-tools",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/anthropics/sbom-tools",
                    "rules": [],
                }
            },
            "results": results,
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Export matrix results to a file (JSON, CSV, or HTML)
pub fn export_matrix(
    format: ExportFormat,
    result: &crate::diff::MatrixResult,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("sbom_matrix_{}.{}", timestamp, format.extension());
    let path = PathBuf::from(&filename);

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
        Ok(()) => ExportResult {
            path: path.clone(),
            success: true,
            message: format!("Matrix exported to {}", path.display()),
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

fn write_to_file(path: &PathBuf, content: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

