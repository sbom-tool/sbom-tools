//! Summary report generator for shell output.
//!
//! Provides a compact, human-readable summary for terminal usage.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator};
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;

/// Apply ANSI color formatting if colored output is enabled.
fn ansi_color(text: &str, color: &str, colored: bool) -> String {
    if colored {
        match color {
            "red" => format!("\x1b[31m{text}\x1b[0m"),
            "green" => format!("\x1b[32m{text}\x1b[0m"),
            "yellow" => format!("\x1b[33m{text}\x1b[0m"),
            "cyan" => format!("\x1b[36m{text}\x1b[0m"),
            "bold" => format!("\x1b[1m{text}\x1b[0m"),
            "dim" => format!("\x1b[2m{text}\x1b[0m"),
            _ => text.to_string(),
        }
    } else {
        text.to_string()
    }
}

/// Summary reporter for shell output
pub struct SummaryReporter {
    /// Use colored output
    colored: bool,
}

impl SummaryReporter {
    /// Create a new summary reporter
    #[must_use] 
    pub const fn new() -> Self {
        Self { colored: true }
    }

    /// Disable colored output
    #[must_use]
    pub const fn no_color(mut self) -> Self {
        self.colored = false;
        self
    }

    fn color(&self, text: &str, color: &str) -> String {
        ansi_color(text, color, self.colored)
    }
}

impl Default for SummaryReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for SummaryReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut lines = Vec::new();

        // Header
        lines.push(self.color("SBOM Diff Summary", "bold"));
        lines.push(self.color("─".repeat(40).as_str(), "dim"));

        // File info
        let old_name = old_sbom.document.name.as_deref().unwrap_or("old");
        let new_name = new_sbom.document.name.as_deref().unwrap_or("new");
        lines.push(format!(
            "{}  {} → {}",
            self.color("Files:", "cyan"),
            old_name,
            new_name
        ));

        // Component counts
        lines.push(format!(
            "{}  {} → {} components",
            self.color("Size:", "cyan"),
            old_sbom.component_count(),
            new_sbom.component_count()
        ));

        lines.push(String::new());

        // Changes
        lines.push(self.color("Changes:", "bold"));

        let added = result.summary.components_added;
        let removed = result.summary.components_removed;
        let modified = result.summary.components_modified;

        if added > 0 {
            lines.push(format!(
                "  {} {} added",
                self.color(&format!("+{added}"), "green"),
                if added == 1 {
                    "component"
                } else {
                    "components"
                }
            ));
        }
        if removed > 0 {
            lines.push(format!(
                "  {} {} removed",
                self.color(&format!("-{removed}"), "red"),
                if removed == 1 {
                    "component"
                } else {
                    "components"
                }
            ));
        }
        if modified > 0 {
            lines.push(format!(
                "  {} {} modified",
                self.color(&format!("~{modified}"), "yellow"),
                if modified == 1 {
                    "component"
                } else {
                    "components"
                }
            ));
        }
        if added == 0 && removed == 0 && modified == 0 {
            lines.push(format!("  {}", self.color("No changes", "dim")));
        }

        // Vulnerabilities
        let vulns_intro = result.summary.vulnerabilities_introduced;
        let vulns_resolved = result.summary.vulnerabilities_resolved;

        if vulns_intro > 0 || vulns_resolved > 0 {
            lines.push(String::new());
            lines.push(self.color("Vulnerabilities:", "bold"));

            if vulns_intro > 0 {
                lines.push(format!(
                    "  {} {} introduced",
                    self.color(&format!("!{vulns_intro}"), "red"),
                    if vulns_intro == 1 {
                        "vulnerability"
                    } else {
                        "vulnerabilities"
                    }
                ));
            }
            if vulns_resolved > 0 {
                lines.push(format!(
                    "  {} {} resolved",
                    self.color(&format!("✓{vulns_resolved}"), "green"),
                    if vulns_resolved == 1 {
                        "vulnerability"
                    } else {
                        "vulnerabilities"
                    }
                ));
            }
        }

        // Score
        lines.push(String::new());
        let score = result.semantic_score;
        let score_color = if score > 90.0 {
            "green"
        } else if score > 70.0 {
            "yellow"
        } else {
            "red"
        };
        lines.push(format!(
            "{}  {}",
            self.color("Similarity:", "cyan"),
            self.color(&format!("{score:.1}%"), score_color)
        ));

        Ok(lines.join("\n"))
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut lines = Vec::new();

        // Header
        lines.push(self.color("SBOM Summary", "bold"));
        lines.push(self.color("─".repeat(40).as_str(), "dim"));

        // Basic info
        if let Some(name) = &sbom.document.name {
            lines.push(format!("{}  {}", self.color("Name:", "cyan"), name));
        }
        lines.push(format!(
            "{}  {}",
            self.color("Format:", "cyan"),
            sbom.document.format
        ));
        lines.push(format!(
            "{}  {}",
            self.color("Components:", "cyan"),
            sbom.component_count()
        ));
        lines.push(format!(
            "{}  {}",
            self.color("Dependencies:", "cyan"),
            sbom.edges.len()
        ));

        // Ecosystems
        let ecosystems: Vec<_> = sbom.ecosystems().iter().map(std::string::ToString::to_string).collect();
        if !ecosystems.is_empty() {
            lines.push(format!(
                "{}  {}",
                self.color("Ecosystems:", "cyan"),
                ecosystems.join(", ")
            ));
        }

        // Vulnerabilities
        let counts = sbom.vulnerability_counts();
        let total_vulns = counts.critical + counts.high + counts.medium + counts.low;
        if total_vulns > 0 {
            lines.push(String::new());
            lines.push(self.color("Vulnerabilities:", "bold"));
            if counts.critical > 0 {
                lines.push(format!(
                    "  {}",
                    self.color(&format!("Critical: {}", counts.critical), "red")
                ));
            }
            if counts.high > 0 {
                lines.push(format!(
                    "  {}",
                    self.color(&format!("High: {}", counts.high), "red")
                ));
            }
            if counts.medium > 0 {
                lines.push(format!(
                    "  {}",
                    self.color(&format!("Medium: {}", counts.medium), "yellow")
                ));
            }
            if counts.low > 0 {
                lines.push(format!(
                    "  {}",
                    self.color(&format!("Low: {}", counts.low), "dim")
                ));
            }
        }

        Ok(lines.join("\n"))
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Summary
    }
}

/// Table reporter for terminal output with aligned columns
pub struct TableReporter {
    /// Use colored output
    colored: bool,
}

impl TableReporter {
    /// Create a new table reporter
    #[must_use] 
    pub const fn new() -> Self {
        Self { colored: true }
    }

    /// Disable colored output
    #[must_use]
    pub const fn no_color(mut self) -> Self {
        self.colored = false;
        self
    }

    fn color(&self, text: &str, color: &str) -> String {
        ansi_color(text, color, self.colored)
    }
}

impl Default for TableReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for TableReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        _old_sbom: &NormalizedSbom,
        _new_sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut lines = Vec::new();

        // Header
        lines.push(format!(
            "{:<12} {:<40} {:<15} {:<15}",
            self.color("STATUS", "bold"),
            self.color("COMPONENT", "bold"),
            self.color("OLD VERSION", "bold"),
            self.color("NEW VERSION", "bold")
        ));
        lines.push("─".repeat(85));

        // Added components
        for comp in &result.components.added {
            let version = comp.new_version.as_deref().unwrap_or("-");
            lines.push(format!(
                "{:<12} {:<40} {:<15} {:<15}",
                self.color("+ Added", "green"),
                truncate(&comp.name, 40),
                "-",
                version
            ));
        }

        // Removed components
        for comp in &result.components.removed {
            let version = comp.old_version.as_deref().unwrap_or("-");
            lines.push(format!(
                "{:<12} {:<40} {:<15} {:<15}",
                self.color("- Removed", "red"),
                truncate(&comp.name, 40),
                version,
                "-"
            ));
        }

        // Modified components
        for comp in &result.components.modified {
            let old_ver = comp.old_version.as_deref().unwrap_or("-");
            let new_ver = comp.new_version.as_deref().unwrap_or("-");
            lines.push(format!(
                "{:<12} {:<40} {:<15} {:<15}",
                self.color("~ Modified", "yellow"),
                truncate(&comp.name, 40),
                old_ver,
                new_ver
            ));
        }

        // Vulnerabilities section
        if !result.vulnerabilities.introduced.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "{:<12} {:<20} {:<10} {:<40}",
                self.color("VULNS", "bold"),
                self.color("ID", "bold"),
                self.color("SEVERITY", "bold"),
                self.color("COMPONENT", "bold")
            ));
            lines.push("─".repeat(85));

            for vuln in &result.vulnerabilities.introduced {
                let severity_colored = match vuln.severity.to_lowercase().as_str() {
                    "critical" | "high" => self.color(&vuln.severity, "red"),
                    "medium" => self.color(&vuln.severity, "yellow"),
                    _ => vuln.severity.clone(),
                };
                lines.push(format!(
                    "{:<12} {:<20} {:<10} {:<40}",
                    self.color("! NEW", "red"),
                    truncate(&vuln.id, 20),
                    severity_colored,
                    truncate(&vuln.component_name, 40)
                ));
            }
        }

        // Summary footer
        lines.push(String::new());
        lines.push(format!(
            "Total: {} added, {} removed, {} modified | Vulns: {} new, {} resolved | Similarity: {:.1}%",
            result.summary.components_added,
            result.summary.components_removed,
            result.summary.components_modified,
            result.summary.vulnerabilities_introduced,
            result.summary.vulnerabilities_resolved,
            result.semantic_score
        ));

        Ok(lines.join("\n"))
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut lines = Vec::new();

        // Header
        lines.push(format!(
            "{:<40} {:<15} {:<20} {:<10}",
            self.color("COMPONENT", "bold"),
            self.color("VERSION", "bold"),
            self.color("LICENSE", "bold"),
            self.color("VULNS", "bold")
        ));
        lines.push("─".repeat(90));

        // Components (limit to 50 for readability)
        let mut components: Vec<_> = sbom.components.values().collect();
        components.sort_by(|a, b| a.name.cmp(&b.name));

        for comp in components.iter().take(50) {
            let version = comp.version.as_deref().unwrap_or("-");
            let license = comp
                .licenses
                .declared
                .first()
                .map_or("-", |l| l.expression.as_str());
            let vulns = comp.vulnerabilities.len();
            let vuln_display = if vulns > 0 {
                self.color(&vulns.to_string(), "red")
            } else {
                "0".to_string()
            };

            lines.push(format!(
                "{:<40} {:<15} {:<20} {:<10}",
                truncate(&comp.name, 40),
                truncate(version, 15),
                truncate(license, 20),
                vuln_display
            ));
        }

        if components.len() > 50 {
            lines.push(self.color(
                &format!("... and {} more components", components.len() - 50),
                "dim",
            ));
        }

        // Summary
        lines.push(String::new());
        let counts = sbom.vulnerability_counts();
        let unknown_str = if counts.unknown > 0 {
            format!(", {} unknown", counts.unknown)
        } else {
            String::new()
        };
        lines.push(format!(
            "Total: {} components, {} dependencies | Vulns: {} critical, {} high, {} medium, {} low{}",
            sbom.component_count(),
            sbom.edges.len(),
            counts.critical,
            counts.high,
            counts.medium,
            counts.low,
            unknown_str
        ));

        Ok(lines.join("\n"))
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Table
    }
}

/// Truncate a string to fit within `max_len` (UTF-8 safe)
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        let end = floor_char_boundary(s, max_len - 3);
        format!("{}...", &s[..end])
    } else {
        let end = floor_char_boundary(s, max_len);
        s[..end].to_string()
    }
}

/// Find the largest byte index <= `index` that is a valid UTF-8 char boundary.
const fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let mut i = index;
        while i > 0 && !s.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
}
