//! CSV report generator.
//!
//! Generates comma-separated reports for diff and view modes,
//! suitable for spreadsheet import and data analysis pipelines.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use std::fmt::Write;

/// CSV report generator.
pub struct CsvReporter;

impl CsvReporter {
    #[must_use] 
    pub const fn new() -> Self {
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
        // Pre-allocate based on estimated output size
        let estimated_lines = result.components.total()
            + result.vulnerabilities.introduced.len()
            + result.vulnerabilities.resolved.len()
            + result.vulnerabilities.persistent.len()
            + 10; // headers
        let mut content = String::with_capacity(estimated_lines * 100);

        // Components CSV
        content.push_str("# Components\n");
        content.push_str("Change,Name,Old Version,New Version,Ecosystem\n");

        for comp in &result.components.added {
            write_component_line(&mut content, "Added", comp);
        }

        for comp in &result.components.removed {
            write_component_line(&mut content, "Removed", comp);
        }

        for comp in &result.components.modified {
            write_component_line(&mut content, "Modified", comp);
        }

        // Vulnerabilities CSV
        content.push_str("\n# Vulnerabilities\n");
        content.push_str("Status,ID,Severity,Type,SLA,Component,Description,VEX\n");

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
        // Pre-allocate based on component count
        let mut content = String::with_capacity(sbom.components.len() * 150 + 100);

        content.push_str("Name,Version,Ecosystem,Type,PURL,Licenses,Vulnerabilities,EOL Status,EOL Date\n");

        for (_, comp) in &sbom.components {
            let licenses = comp
                .licenses
                .declared
                .iter()
                .map(|l| l.expression.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let vuln_count = comp.vulnerabilities.len();
            let ecosystem = comp
                .ecosystem
                .as_ref()
                .map(|e| format!("{e:?}"));
            let ecosystem = ecosystem.as_deref().unwrap_or("-");

            let eol_status = comp
                .eol
                .as_ref()
                .map_or("-", |e| e.status.label());
            let eol_date = comp
                .eol
                .as_ref()
                .and_then(|e| e.eol_date.map(|d| d.to_string()));
            let eol_date = eol_date.as_deref().unwrap_or("-");

            let _ = writeln!(
                content,
                "\"{}\",\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",{},\"{}\",\"{}\"",
                escape_csv(&comp.name),
                comp.version.as_deref().unwrap_or("-"),
                ecosystem,
                comp.component_type,
                comp.identifiers.purl.as_deref().unwrap_or("-"),
                escape_csv(&licenses),
                vuln_count,
                eol_status,
                eol_date,
            );
        }

        Ok(content)
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Csv
    }
}

/// Write a component line using write! macro to avoid format! allocation.
fn write_component_line(
    content: &mut String,
    change_type: &str,
    comp: &crate::diff::ComponentChange,
) {
    let _ = writeln!(
        content,
        "{},\"{}\",\"{}\",\"{}\",\"{}\"",
        change_type,
        escape_csv(&comp.name),
        comp.old_version.as_deref().unwrap_or("-"),
        comp.new_version.as_deref().unwrap_or("-"),
        comp.ecosystem.as_deref().unwrap_or("-")
    );
}

fn write_vuln_line(content: &mut String, status: &str, vuln: &VulnerabilityDetail) {
    let depth_label = match vuln.component_depth {
        Some(1) => "Direct",
        Some(_) => "Transitive",
        None => "-",
    };
    let sla_display = format_sla_csv(vuln);
    let desc = vuln
        .description
        .as_deref()
        .map(escape_csv)
        .unwrap_or_default();
    let vex_display = match vuln.vex_state.as_ref() {
        Some(crate::model::VexState::NotAffected) => "Not Affected",
        Some(crate::model::VexState::Fixed) => "Fixed",
        Some(crate::model::VexState::Affected) => "Affected",
        Some(crate::model::VexState::UnderInvestigation) => "Under Investigation",
        None => "",
    };

    let _ = writeln!(
        content,
        "{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
        status,
        escape_csv(&vuln.id),
        escape_csv(&vuln.severity),
        depth_label,
        sla_display,
        escape_csv(&vuln.component_name),
        desc,
        vex_display,
    );
}

/// Escape a string for CSV embedding: double-quote escaping per RFC 4180,
/// plus newline flattening since fields are already wrapped in double quotes.
fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"").replace('\n', " ")
}

fn format_sla_csv(vuln: &VulnerabilityDetail) -> String {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => format!("{days}d late"),
        SlaStatus::DueSoon(days) | SlaStatus::OnTrack(days) => format!("{days}d left"),
        SlaStatus::NoDueDate => vuln
            .days_since_published.map_or_else(|| "-".to_string(), |d| format!("{d}d old")),
    }
}
