//! CSV report generator.
//!
//! Generates comma-separated reports for diff and view modes,
//! suitable for spreadsheet import and data analysis pipelines.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;

/// CSV report generator.
pub struct CsvReporter;

impl CsvReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CsvReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for CsvReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        _old_sbom: &NormalizedSbom,
        _new_sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut content = String::new();

        // Components CSV
        content.push_str("# Components\n");
        content.push_str("Change,Name,Old Version,New Version,Ecosystem\n");

        for comp in &result.components.added {
            content.push_str(&format!(
                "Added,\"{}\",\"{}\",\"{}\",\"{}\"\n",
                escape_csv(&comp.name),
                comp.old_version.as_deref().unwrap_or("-"),
                comp.new_version.as_deref().unwrap_or("-"),
                comp.ecosystem.as_deref().unwrap_or("-")
            ));
        }

        for comp in &result.components.removed {
            content.push_str(&format!(
                "Removed,\"{}\",\"{}\",\"{}\",\"{}\"\n",
                escape_csv(&comp.name),
                comp.old_version.as_deref().unwrap_or("-"),
                comp.new_version.as_deref().unwrap_or("-"),
                comp.ecosystem.as_deref().unwrap_or("-")
            ));
        }

        for comp in &result.components.modified {
            content.push_str(&format!(
                "Modified,\"{}\",\"{}\",\"{}\",\"{}\"\n",
                escape_csv(&comp.name),
                comp.old_version.as_deref().unwrap_or("-"),
                comp.new_version.as_deref().unwrap_or("-"),
                comp.ecosystem.as_deref().unwrap_or("-")
            ));
        }

        // Vulnerabilities CSV
        content.push_str("\n# Vulnerabilities\n");
        content.push_str("Status,ID,Severity,Type,SLA,Component,Description\n");

        for vuln in &result.vulnerabilities.introduced {
            write_vuln_line(&mut content, "Introduced", vuln);
        }

        for vuln in &result.vulnerabilities.resolved {
            write_vuln_line(&mut content, "Resolved", vuln);
        }

        for vuln in &result.vulnerabilities.persistent {
            write_vuln_line(&mut content, "Persistent", vuln);
        }

        Ok(content)
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut content = String::new();

        content.push_str("Name,Version,Ecosystem,Type,PURL,Licenses,Vulnerabilities\n");

        for (_, comp) in &sbom.components {
            let licenses = comp
                .licenses
                .declared
                .iter()
                .map(|l| l.expression.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let vuln_count = comp.vulnerabilities.len();

            content.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",{}\n",
                escape_csv(&comp.name),
                comp.version.as_deref().unwrap_or("-"),
                comp.ecosystem
                    .as_ref()
                    .map(|e| format!("{:?}", e))
                    .unwrap_or_else(|| "-".to_string()),
                comp.component_type,
                comp.identifiers.purl.as_deref().unwrap_or("-"),
                escape_csv(&licenses),
                vuln_count
            ));
        }

        Ok(content)
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Csv
    }
}

fn write_vuln_line(content: &mut String, status: &str, vuln: &VulnerabilityDetail) {
    let depth_label = match vuln.component_depth {
        Some(1) => "Direct",
        Some(_) => "Transitive",
        None => "-",
    };
    let sla_display = format_sla_csv(vuln);
    content.push_str(&format!(
        "{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
        status,
        escape_csv(&vuln.id),
        escape_csv(&vuln.severity),
        depth_label,
        sla_display,
        escape_csv(&vuln.component_name),
        vuln.description
            .as_deref()
            .map(escape_csv)
            .unwrap_or_default()
    ));
}

/// Escape a string for CSV embedding: double-quote escaping per RFC 4180,
/// plus newline flattening since fields are already wrapped in double quotes.
fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"").replace('\n', " ")
}

fn format_sla_csv(vuln: &VulnerabilityDetail) -> String {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => format!("{}d late", days),
        SlaStatus::DueSoon(days) => format!("{}d left", days),
        SlaStatus::OnTrack(days) => format!("{}d left", days),
        SlaStatus::NoDueDate => vuln
            .days_since_published
            .map(|d| format!("{}d old", d))
            .unwrap_or_else(|| "-".to_string()),
    }
}
