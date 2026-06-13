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

        content.push_str(
            "Name,Version,Ecosystem,Type,PURL,Licenses,Vulnerabilities,EOL Status,EOL Date,Crypto Asset Type,Algorithm Family,Quantum Level\n",
        );

        for (_, comp) in &sbom.components {
            let licenses = comp
                .licenses
                .declared
                .iter()
                .map(|l| l.expression.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let vuln_count = comp.vulnerabilities.len();
            let ecosystem = comp.ecosystem.as_ref().map(|e| format!("{e:?}"));
            let ecosystem = escape_csv_opt(ecosystem.as_deref());

            let eol_status = comp.eol.as_ref().map_or("-", |e| e.status.label());
            let eol_date = comp
                .eol
                .as_ref()
                .and_then(|e| e.eol_date.map(|d| d.to_string()));
            let eol_date = eol_date.as_deref().unwrap_or("-");

            // Crypto fields
            let crypto_type = comp
                .crypto_properties
                .as_ref()
                .map(|cp| cp.asset_type.to_string())
                .unwrap_or_default();
            let algo_family = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| {
                    cp.algorithm_properties
                        .as_ref()
                        .and_then(|a| a.algorithm_family.as_deref().map(escape_csv))
                })
                .unwrap_or_default();
            let quantum_level = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| {
                    cp.algorithm_properties
                        .as_ref()
                        .and_then(|a| a.nist_quantum_security_level.map(|l| l.to_string()))
                })
                .unwrap_or_default();

            let _ = writeln!(
                content,
                "\"{}\",\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                escape_csv(&comp.name),
                escape_csv_opt(comp.version.as_deref()),
                ecosystem,
                comp.component_type,
                escape_csv_opt(comp.identifiers.purl.as_deref()),
                escape_csv(&licenses),
                vuln_count,
                eol_status,
                eol_date,
                crypto_type,
                algo_family,
                quantum_level,
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
        escape_csv_opt(comp.old_version.as_deref()),
        escape_csv_opt(comp.new_version.as_deref()),
        escape_csv_opt(comp.ecosystem.as_deref())
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
///
/// Values starting with a formula trigger (`=`, `+`, `-`, `@`, tab, CR) are
/// prefixed with a single quote so spreadsheet applications treat them as
/// text rather than executable formulas (OWASP CSV injection guidance).
fn escape_csv(s: &str) -> String {
    let escaped = s.replace('"', "\"\"").replace('\n', " ");
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{escaped}")
    } else {
        escaped
    }
}

/// Escape an optional string for CSV embedding, returning "-" for `None`.
fn escape_csv_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_string(), escape_csv)
}

fn format_sla_csv(vuln: &VulnerabilityDetail) -> String {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => format!("{days}d late"),
        SlaStatus::DueSoon(days) | SlaStatus::OnTrack(days) => format!("{days}d left"),
        SlaStatus::NoDueDate => vuln
            .days_since_published
            .map_or_else(|| "-".to_string(), |d| format!("{d}d old")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_csv_guards_formula_triggers() {
        assert_eq!(escape_csv("=1+2"), "'=1+2");
        assert_eq!(escape_csv("+SUM(A1:A2)"), "'+SUM(A1:A2)");
        assert_eq!(escape_csv("-2+3"), "'-2+3");
        assert_eq!(escape_csv("@cmd"), "'@cmd");
        assert_eq!(escape_csv("\tpayload"), "'\tpayload");
        assert_eq!(escape_csv("\rpayload"), "'\rpayload");
        // Scoped npm names share the '@' trigger; the quote prefix keeps them
        // readable while staying inert in spreadsheets
        assert_eq!(escape_csv("@types/node"), "'@types/node");
    }

    #[test]
    fn escape_csv_guards_formula_after_quote_doubling() {
        assert_eq!(escape_csv("=cmd|'/c calc'!A0"), "'=cmd|'/c calc'!A0");
        assert_eq!(escape_csv("=\"evil\""), "'=\"\"evil\"\"");
    }

    #[test]
    fn escape_csv_leaves_benign_values_alone() {
        assert_eq!(escape_csv("lodash"), "lodash");
        assert_eq!(escape_csv("1.2.3"), "1.2.3");
        assert_eq!(
            escape_csv("pkg:npm/lodash@4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
        assert_eq!(escape_csv("MIT OR Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(escape_csv("name \"quoted\""), "name \"\"quoted\"\"");
        assert_eq!(escape_csv("line1\nline2"), "line1 line2");
        assert_eq!(escape_csv(""), "");
    }

    #[test]
    fn escape_csv_opt_uses_placeholder_for_none() {
        assert_eq!(escape_csv_opt(None), "-");
        assert_eq!(escape_csv_opt(Some("=evil")), "'=evil");
        assert_eq!(escape_csv_opt(Some("1.0.0")), "1.0.0");
    }
}
