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
    pub(crate) fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Sarif => "sarif.json",
            Self::Csv => "csv",
        }
    }

    /// Convert to report format (where applicable)
    fn to_report_format(self) -> Option<ReportFormat> {
        match self {
            Self::Json => Some(ReportFormat::Json),
            Self::Markdown => Some(ReportFormat::Markdown),
            Self::Html => Some(ReportFormat::Html),
            Self::Sarif => Some(ReportFormat::Sarif),
            Self::Csv => Some(ReportFormat::Csv),
        }
    }
}

/// Result of an export operation
#[derive(Debug)]
pub(crate) struct ExportResult {
    pub path: PathBuf,
    pub success: bool,
    pub message: String,
}

/// Export diff results to a file
pub(crate) fn export_diff(
    format: ExportFormat,
    result: &DiffResult,
    old_sbom: &NormalizedSbom,
    new_sbom: &NormalizedSbom,
    output_dir: Option<&str>,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("sbom_tools_{}.{}", timestamp, format.extension());
    let path = output_dir.map_or_else(|| PathBuf::from(&filename), |dir| PathBuf::from(dir).join(&filename));

    if let Some(report_format) = format.to_report_format() {
        export_with_reporter(report_format, result, old_sbom, new_sbom, &path)
    } else {
        ExportResult {
            path,
            success: false,
            message: "Unsupported format".to_string(),
        }
    }
}

/// Export single SBOM to a file (view mode)
pub(crate) fn export_view(
    format: ExportFormat,
    sbom: &NormalizedSbom,
    output_dir: Option<&str>,
) -> ExportResult {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("sbom_report_{}.{}", timestamp, format.extension());
    let path = output_dir.map_or_else(|| PathBuf::from(&filename), |dir| PathBuf::from(dir).join(&filename));

    if let Some(report_format) = format.to_report_format() {
        export_view_with_reporter(report_format, sbom, &path)
    } else {
        ExportResult {
            path,
            success: false,
            message: "Unsupported format".to_string(),
        }
    }
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
pub(crate) fn export_compliance(
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

fn write_to_file(path: &PathBuf, content: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

