//! Side-by-side diff output similar to difftastic.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator};
use crate::diff::{ChangeType, DiffResult};
use crate::model::NormalizedSbom;
use std::fmt::Write;

/// ANSI color codes
mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const LINE_NUM: &str = "\x1b[38;5;242m"; // Gray for line numbers
}

/// Side-by-side diff reporter
#[allow(dead_code)]
pub struct SideBySideReporter {
    /// Terminal width (auto-detect or default)
    width: usize,
    /// Show line numbers
    show_line_numbers: bool,
    /// Use colors
    use_colors: bool,
}

impl SideBySideReporter {
    /// Create a new side-by-side reporter
    #[must_use] 
    pub fn new() -> Self {
        // Try to detect terminal width, default to 120
        let width = terminal_width().unwrap_or(120);
        Self {
            width,
            show_line_numbers: true,
            use_colors: true,
        }
    }

    /// Set terminal width
    #[must_use]
    pub const fn width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Disable colors
    #[must_use]
    pub const fn no_colors(mut self) -> Self {
        self.use_colors = false;
        self
    }

    const fn col(&self, code: &'static str) -> &'static str {
        if self.use_colors {
            code
        } else {
            ""
        }
    }

    fn format_header(&self, old_name: &str, new_name: &str) -> String {
        let half_width = (self.width - 3) / 2;
        format!(
            "{}{:<half_width$}{} │ {}{:<half_width$}{}\n",
            self.col(colors::BOLD),
            truncate(old_name, half_width),
            self.col(colors::RESET),
            self.col(colors::BOLD),
            truncate(new_name, half_width),
            self.col(colors::RESET),
        )
    }

    fn format_section_header(&self, title: &str) -> String {
        format!(
            "\n{}{}═══ {} {}═══{}\n",
            self.col(colors::CYAN),
            self.col(colors::BOLD),
            title,
            "═".repeat(self.width.saturating_sub(title.len() + 8)),
            self.col(colors::RESET),
        )
    }

    fn format_component_row(
        &self,
        line_num: usize,
        old_text: Option<&str>,
        new_text: Option<&str>,
        change_type: ChangeType,
    ) -> String {
        let half_width = (self.width - 7) / 2; // Account for " │ " and line numbers
        let num_width = 3;

        let (left_num, left_text, right_num, right_text) = match change_type {
            ChangeType::Removed => (
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::RED),
                    line_num,
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::RED),
                    truncate(old_text.unwrap_or(""), half_width),
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::DIM),
                    ".",
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::DIM),
                    "...",
                    self.col(colors::RESET)
                ),
            ),
            ChangeType::Added => (
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::DIM),
                    ".",
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::DIM),
                    "...",
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::GREEN),
                    line_num,
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::GREEN),
                    truncate(new_text.unwrap_or(""), half_width),
                    self.col(colors::RESET)
                ),
            ),
            ChangeType::Modified => (
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::YELLOW),
                    line_num,
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::RED),
                    truncate(old_text.unwrap_or(""), half_width),
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::YELLOW),
                    line_num,
                    self.col(colors::RESET)
                ),
                format!(
                    "{}{}{}",
                    self.col(colors::GREEN),
                    truncate(new_text.unwrap_or(""), half_width),
                    self.col(colors::RESET)
                ),
            ),
            ChangeType::Unchanged => (
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::LINE_NUM),
                    line_num,
                    self.col(colors::RESET)
                ),
                truncate(old_text.unwrap_or(""), half_width),
                format!(
                    "{}{:>num_width$}{}",
                    self.col(colors::LINE_NUM),
                    line_num,
                    self.col(colors::RESET)
                ),
                truncate(new_text.unwrap_or(""), half_width),
            ),
        };

        // Calculate visible width (excluding ANSI codes)
        let left_visible = strip_ansi(&left_text);
        let right_visible = strip_ansi(&right_text);
        let left_padding = half_width.saturating_sub(left_visible.len());
        let right_padding = half_width.saturating_sub(right_visible.len());

        format!(
            "{} {}{} │ {} {}{}\n",
            left_num,
            left_text,
            " ".repeat(left_padding),
            right_num,
            right_text,
            " ".repeat(right_padding),
        )
    }

    fn format_vulnerability_row(
        &self,
        vuln_id: &str,
        severity: &str,
        component: &str,
        is_introduced: bool,
    ) -> String {
        let icon = if is_introduced { "+" } else { "-" };
        let color = if is_introduced {
            colors::RED
        } else {
            colors::GREEN
        };
        let severity_color = match severity.to_lowercase().as_str() {
            "critical" => colors::MAGENTA,
            "high" => colors::RED,
            "medium" => colors::YELLOW,
            "low" => colors::CYAN,
            _ => colors::WHITE,
        };

        format!(
            "  {}{}{} {}{:<16}{} {}{:<10}{} → {}\n",
            self.col(color),
            icon,
            self.col(colors::RESET),
            self.col(colors::BOLD),
            vuln_id,
            self.col(colors::RESET),
            self.col(severity_color),
            severity,
            self.col(colors::RESET),
            component,
        )
    }
}

impl Default for SideBySideReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for SideBySideReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut out = String::new();

        // Header with file names
        let old_name = old_sbom.document.name.as_deref().unwrap_or("Old SBOM");
        let new_name = new_sbom.document.name.as_deref().unwrap_or("New SBOM");

        writeln!(
            out,
            "{}sbom-tools{} --- {}",
            self.col(colors::CYAN),
            self.col(colors::RESET),
            old_sbom.document.format
        )?;

        out.push_str(&self.format_header(old_name, new_name));

        // Separator line
        let half_width = (self.width - 3) / 2;
        writeln!(
            out,
            "{}{}│{}{}",
            self.col(colors::DIM),
            "─".repeat(half_width + 4),
            "─".repeat(half_width + 4),
            self.col(colors::RESET)
        )?;

        // Components section
        out.push_str(&self.format_section_header("Components"));

        let mut line_num = 1;

        // Show removed components
        for comp in &result.components.removed {
            let old_text = format!(
                "{} {}",
                comp.name,
                comp.old_version.as_deref().unwrap_or("")
            );
            out.push_str(&self.format_component_row(
                line_num,
                Some(&old_text),
                None,
                ChangeType::Removed,
            ));
            line_num += 1;
        }

        // Show modified components
        for comp in &result.components.modified {
            let old_text = format!(
                "{} {}",
                comp.name,
                comp.old_version.as_deref().unwrap_or("")
            );
            let new_text = format!(
                "{} {}",
                comp.name,
                comp.new_version.as_deref().unwrap_or("")
            );
            out.push_str(&self.format_component_row(
                line_num,
                Some(&old_text),
                Some(&new_text),
                ChangeType::Modified,
            ));
            line_num += 1;
        }

        // Show added components
        for comp in &result.components.added {
            let new_text = format!(
                "{} {}",
                comp.name,
                comp.new_version.as_deref().unwrap_or("")
            );
            out.push_str(&self.format_component_row(
                line_num,
                None,
                Some(&new_text),
                ChangeType::Added,
            ));
            line_num += 1;
        }

        // Dependencies section (if any changes)
        if !result.dependencies.added.is_empty() || !result.dependencies.removed.is_empty() {
            out.push_str(&self.format_section_header("Dependencies"));

            line_num = 1;
            for dep in &result.dependencies.removed {
                let old_text = format!("{} → {}", short_id(&dep.from), short_id(&dep.to));
                out.push_str(&self.format_component_row(
                    line_num,
                    Some(&old_text),
                    None,
                    ChangeType::Removed,
                ));
                line_num += 1;
            }

            for dep in &result.dependencies.added {
                let new_text = format!("{} → {}", short_id(&dep.from), short_id(&dep.to));
                out.push_str(&self.format_component_row(
                    line_num,
                    None,
                    Some(&new_text),
                    ChangeType::Added,
                ));
                line_num += 1;
            }
        }

        // Vulnerabilities section
        if !result.vulnerabilities.introduced.is_empty()
            || !result.vulnerabilities.resolved.is_empty()
        {
            out.push_str(&self.format_section_header("Vulnerabilities"));

            for vuln in &result.vulnerabilities.resolved {
                out.push_str(&self.format_vulnerability_row(
                    &vuln.id,
                    &vuln.severity,
                    &vuln.component_name,
                    false,
                ));
            }

            for vuln in &result.vulnerabilities.introduced {
                out.push_str(&self.format_vulnerability_row(
                    &vuln.id,
                    &vuln.severity,
                    &vuln.component_name,
                    true,
                ));
            }
        }

        // Summary
        out.push_str(&self.format_section_header("Summary"));
        writeln!(
            out,
            "  {}Components:{} {}+{}{} added, {}-{}{} removed, {}~{}{} modified",
            self.col(colors::BOLD),
            self.col(colors::RESET),
            self.col(colors::GREEN),
            result.summary.components_added,
            self.col(colors::RESET),
            self.col(colors::RED),
            result.summary.components_removed,
            self.col(colors::RESET),
            self.col(colors::YELLOW),
            result.summary.components_modified,
            self.col(colors::RESET),
        )?;

        if result.summary.vulnerabilities_introduced > 0
            || result.summary.vulnerabilities_resolved > 0
        {
            writeln!(
                out,
                "  {}Vulnerabilities:{} {}+{}{} introduced, {}-{}{} resolved",
                self.col(colors::BOLD),
                self.col(colors::RESET),
                self.col(colors::RED),
                result.summary.vulnerabilities_introduced,
                self.col(colors::RESET),
                self.col(colors::GREEN),
                result.summary.vulnerabilities_resolved,
                self.col(colors::RESET),
            )?;
        }

        writeln!(
            out,
            "  {}Semantic Score:{} {}{:.1}{}",
            self.col(colors::BOLD),
            self.col(colors::RESET),
            self.col(colors::CYAN),
            result.semantic_score,
            self.col(colors::RESET),
        )?;

        Ok(out)
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        _config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut out = String::new();

        let name = sbom.document.name.as_deref().unwrap_or("SBOM");

        writeln!(
            out,
            "{}sbom-tools view{} --- {}\n",
            self.col(colors::CYAN),
            self.col(colors::RESET),
            sbom.document.format
        )?;

        writeln!(
            out,
            "{}{}{}\n",
            self.col(colors::BOLD),
            name,
            self.col(colors::RESET),
        )?;

        out.push_str(&self.format_section_header("Components"));

        for (i, (_id, comp)) in sbom.components.iter().enumerate() {
            let vuln_count = comp.vulnerabilities.len();
            let vuln_text = if vuln_count > 0 {
                format!(
                    " {}[{} vulns]{}",
                    self.col(colors::RED),
                    vuln_count,
                    self.col(colors::RESET)
                )
            } else {
                String::new()
            };

            writeln!(
                out,
                "{}{:>3}{} {} {}{}{}{}",
                self.col(colors::LINE_NUM),
                i + 1,
                self.col(colors::RESET),
                comp.name,
                self.col(colors::DIM),
                comp.version.as_deref().unwrap_or(""),
                self.col(colors::RESET),
                vuln_text,
            )?;
        }

        // Vulnerability details
        let vulns = sbom.all_vulnerabilities();
        if !vulns.is_empty() {
            out.push_str(&self.format_section_header("Vulnerabilities"));

            for (comp, vuln) in vulns {
                let severity = vuln
                    .severity
                    .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
                out.push_str(&self.format_vulnerability_row(&vuln.id, &severity, &comp.name, true));
            }
        }

        Ok(out)
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::SideBySide
    }
}

/// Try to get terminal width
const fn terminal_width() -> Option<usize> {
    // Try using terminal_size or just return None
    // For simplicity, we'll return None and use default
    None
}

/// Truncate string to fit width
fn truncate(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        s.to_string()
    } else if max_width > 3 {
        format!("{}...", &s[..max_width - 3])
    } else {
        s[..max_width].to_string()
    }
}

/// Strip ANSI escape codes for width calculation
fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Get short component ID (just name@version from PURL)
fn short_id(id: &str) -> String {
    if id.starts_with("pkg:") {
        // Extract name@version from PURL
        if let Some(rest) = id.strip_prefix("pkg:") {
            if let Some(slash_pos) = rest.find('/') {
                let name_ver = &rest[slash_pos + 1..];
                return name_ver.to_string();
            }
        }
    }
    id.to_string()
}
