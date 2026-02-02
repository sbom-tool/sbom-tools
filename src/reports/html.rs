//! HTML report generator.

use super::escape::{escape_html, escape_html_opt};
use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use std::fmt::Write;

/// A single vulnerability row: (id, severity, cvss_score, component_name, component_version).
type VulnRow<'a> = (&'a str, &'a Option<crate::model::Severity>, Option<f32>, &'a str, Option<&'a str>);

/// HTML report generator
pub struct HtmlReporter {
    /// Include inline CSS
    include_styles: bool,
}

impl HtmlReporter {
    /// Create a new HTML reporter
    pub fn new() -> Self {
        Self {
            include_styles: true,
        }
    }

    fn get_styles(&self) -> &'static str {
        r#"
        <style>
            :root {
                --bg-color: #1e1e2e;
                --text-color: #cdd6f4;
                --accent-color: #89b4fa;
                --success-color: #a6e3a1;
                --warning-color: #f9e2af;
                --error-color: #f38ba8;
                --border-color: #45475a;
                --card-bg: #313244;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background-color: var(--bg-color);
                color: var(--text-color);
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
            }

            h1, h2, h3 {
                color: var(--accent-color);
            }

            .header {
                border-bottom: 2px solid var(--border-color);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }

            .summary-cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }

            .card {
                background-color: var(--card-bg);
                border-radius: 8px;
                padding: 20px;
                border: 1px solid var(--border-color);
            }

            .card-title {
                font-size: 0.9em;
                color: #a6adc8;
                margin-bottom: 10px;
            }

            .card-value {
                font-size: 2em;
                font-weight: bold;
            }

            .card-value.added { color: var(--success-color); }
            .card-value.removed { color: var(--error-color); }
            .card-value.modified { color: var(--warning-color); }
            .card-value.critical { color: var(--error-color); }

            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 30px;
                background-color: var(--card-bg);
                border-radius: 8px;
                overflow: hidden;
            }

            th, td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
            }

            th {
                background-color: #45475a;
                font-weight: 600;
            }

            tr:hover {
                background-color: #3b3d4d;
            }

            .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }

            .badge-added { background-color: rgba(166, 227, 161, 0.2); color: var(--success-color); }
            .badge-removed { background-color: rgba(243, 139, 168, 0.2); color: var(--error-color); }
            .badge-modified { background-color: rgba(249, 226, 175, 0.2); color: var(--warning-color); }
            .badge-critical { background-color: rgba(243, 139, 168, 0.3); color: var(--error-color); }
            .badge-high { background-color: rgba(250, 179, 135, 0.3); color: #fab387; }
            .badge-medium { background-color: rgba(249, 226, 175, 0.3); color: var(--warning-color); }
            .badge-low { background-color: rgba(148, 226, 213, 0.3); color: #94e2d5; }
            .badge-direct { background-color: rgba(46, 160, 67, 0.3); color: #2ea043; }
            .badge-transitive { background-color: rgba(110, 118, 129, 0.3); color: #6e7681; }
            .sla-overdue { background-color: rgba(248, 81, 73, 0.2); color: #f85149; font-weight: bold; }
            .sla-due-soon { background-color: rgba(227, 179, 65, 0.2); color: #e3b341; }
            .sla-on-track { color: #8b949e; }
            .sla-unknown { color: #8b949e; }

            .section {
                margin-bottom: 40px;
            }

            .tabs {
                display: flex;
                border-bottom: 2px solid var(--border-color);
                margin-bottom: 20px;
            }

            .tab {
                padding: 10px 20px;
                cursor: pointer;
                border-bottom: 2px solid transparent;
                margin-bottom: -2px;
            }

            .tab:hover {
                color: var(--accent-color);
            }

            .tab.active {
                border-bottom-color: var(--accent-color);
                color: var(--accent-color);
            }

            .footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid var(--border-color);
                font-size: 0.9em;
                color: #a6adc8;
            }
        </style>
        "#
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for HtmlReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        _old_sbom: &NormalizedSbom,
        _new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut html = String::new();

        let title = config
            .title
            .clone()
            .unwrap_or_else(|| "SBOM Diff Report".to_string());

        // HTML header
        writeln!(html, "<!DOCTYPE html>")?;
        writeln!(html, "<html lang=\"en\">")?;
        writeln!(html, "<head>")?;
        writeln!(html, "    <meta charset=\"UTF-8\">")?;
        writeln!(
            html,
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        )?;
        writeln!(html, "    <title>{}</title>", escape_html(&title))?;
        if self.include_styles {
            writeln!(html, "{}", self.get_styles())?;
        }
        writeln!(html, "</head>")?;
        writeln!(html, "<body>")?;
        writeln!(html, "<div class=\"container\">")?;

        // Header
        writeln!(html, "<div class=\"header\">")?;
        writeln!(html, "    <h1>{}</h1>", escape_html(&title))?;
        writeln!(
            html,
            "    <p>Generated by sbom-tools v{} on {}</p>",
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )?;
        writeln!(html, "</div>")?;

        // Summary cards
        writeln!(html, "<div class=\"summary-cards\">")?;
        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Components Added</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value added\">+{}</div>",
            result.summary.components_added
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Components Removed</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value removed\">-{}</div>",
            result.summary.components_removed
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Components Modified</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value modified\">~{}</div>",
            result.summary.components_modified
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Vulns Introduced</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value critical\">{}</div>",
            result.summary.vulnerabilities_introduced
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Semantic Score</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value\">{:.1}</div>",
            result.semantic_score
        )?;
        writeln!(html, "    </div>")?;
        writeln!(html, "</div>")?;

        // Component changes section
        if config.includes(ReportType::Components) && !result.components.is_empty() {
            writeln!(html, "<div class=\"section\">")?;
            writeln!(html, "    <h2>Component Changes</h2>")?;
            writeln!(html, "    <table>")?;
            writeln!(html, "        <thead>")?;
            writeln!(html, "            <tr>")?;
            writeln!(html, "                <th>Status</th>")?;
            writeln!(html, "                <th>Name</th>")?;
            writeln!(html, "                <th>Old Version</th>")?;
            writeln!(html, "                <th>New Version</th>")?;
            writeln!(html, "                <th>Ecosystem</th>")?;
            writeln!(html, "            </tr>")?;
            writeln!(html, "        </thead>")?;
            writeln!(html, "        <tbody>")?;

            for comp in &result.components.added {
                writeln!(html, "            <tr>")?;
                writeln!(
                    html,
                    "                <td><span class=\"badge badge-added\">Added</span></td>"
                )?;
                writeln!(html, "                <td>{}</td>", escape_html(&comp.name))?;
                writeln!(html, "                <td>-</td>")?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.new_version.as_deref())
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.ecosystem.as_deref())
                )?;
                writeln!(html, "            </tr>")?;
            }

            for comp in &result.components.removed {
                writeln!(html, "            <tr>")?;
                writeln!(
                    html,
                    "                <td><span class=\"badge badge-removed\">Removed</span></td>"
                )?;
                writeln!(html, "                <td>{}</td>", escape_html(&comp.name))?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.old_version.as_deref())
                )?;
                writeln!(html, "                <td>-</td>")?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.ecosystem.as_deref())
                )?;
                writeln!(html, "            </tr>")?;
            }

            for comp in &result.components.modified {
                writeln!(html, "            <tr>")?;
                writeln!(
                    html,
                    "                <td><span class=\"badge badge-modified\">Modified</span></td>"
                )?;
                writeln!(html, "                <td>{}</td>", escape_html(&comp.name))?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.old_version.as_deref())
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.new_version.as_deref())
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.ecosystem.as_deref())
                )?;
                writeln!(html, "            </tr>")?;
            }

            writeln!(html, "        </tbody>")?;
            writeln!(html, "    </table>")?;
            writeln!(html, "</div>")?;
        }

        // Vulnerability changes section
        if config.includes(ReportType::Vulnerabilities)
            && !result.vulnerabilities.introduced.is_empty()
        {
            writeln!(html, "<div class=\"section\">")?;
            writeln!(html, "    <h2>Introduced Vulnerabilities</h2>")?;
            writeln!(html, "    <table>")?;
            writeln!(html, "        <thead>")?;
            writeln!(html, "            <tr>")?;
            writeln!(html, "                <th>ID</th>")?;
            writeln!(html, "                <th>Severity</th>")?;
            writeln!(html, "                <th>CVSS</th>")?;
            writeln!(html, "                <th>SLA</th>")?;
            writeln!(html, "                <th>Type</th>")?;
            writeln!(html, "                <th>Component</th>")?;
            writeln!(html, "                <th>Version</th>")?;
            writeln!(html, "            </tr>")?;
            writeln!(html, "        </thead>")?;
            writeln!(html, "        <tbody>")?;

            for vuln in &result.vulnerabilities.introduced {
                let badge_class = match vuln.severity.to_lowercase().as_str() {
                    "critical" => "badge-critical",
                    "high" => "badge-high",
                    "medium" => "badge-medium",
                    _ => "badge-low",
                };
                let (depth_label, depth_class) = match vuln.component_depth {
                    Some(1) => ("Direct", "badge-direct"),
                    Some(_) => ("Transitive", "badge-transitive"),
                    None => ("-", ""),
                };
                writeln!(html, "            <tr>")?;
                writeln!(html, "                <td>{}</td>", escape_html(&vuln.id))?;
                writeln!(
                    html,
                    "                <td><span class=\"badge {}\">{}</span></td>",
                    badge_class,
                    escape_html(&vuln.severity)
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    vuln.cvss_score
                        .map(|s| format!("{:.1}", s))
                        .unwrap_or_else(|| "-".to_string())
                )?;
                // SLA cell
                let (sla_text, sla_class) = format_sla_html(vuln);
                if sla_class.is_empty() {
                    writeln!(html, "                <td>{}</td>", sla_text)?;
                } else {
                    writeln!(
                        html,
                        "                <td><span class=\"{}\">{}</span></td>",
                        sla_class, sla_text
                    )?;
                }
                if depth_class.is_empty() {
                    writeln!(html, "                <td>{}</td>", depth_label)?;
                } else {
                    writeln!(
                        html,
                        "                <td><span class=\"badge {}\">{}</span></td>",
                        depth_class, depth_label
                    )?;
                }
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html(&vuln.component_name)
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(vuln.version.as_deref())
                )?;
                writeln!(html, "            </tr>")?;
            }

            writeln!(html, "        </tbody>")?;
            writeln!(html, "    </table>")?;
            writeln!(html, "</div>")?;
        }

        // Footer
        writeln!(html, "<div class=\"footer\">")?;
        writeln!(html, "    <p>Generated by <a href=\"https://github.com/binarly-io/sbom-tools\">sbom-tools</a></p>")?;
        writeln!(html, "</div>")?;

        writeln!(html, "</div>")?;
        writeln!(html, "</body>")?;
        writeln!(html, "</html>")?;

        Ok(html)
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        use std::collections::HashSet;

        let mut html = String::new();

        let title = config
            .title
            .clone()
            .unwrap_or_else(|| "SBOM Report".to_string());

        // Compute statistics
        let total_components = sbom.component_count();
        let vulnerable_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| !c.vulnerabilities.is_empty())
            .collect();
        let vuln_component_count = vulnerable_components.len();
        let total_vulns: usize = sbom
            .components
            .values()
            .map(|c| c.vulnerabilities.len())
            .sum();
        let ecosystems: HashSet<_> = sbom
            .components
            .values()
            .filter_map(|c| c.ecosystem.as_ref())
            .collect();
        let licenses: HashSet<String> = sbom
            .components
            .values()
            .flat_map(|c| c.licenses.declared.iter().map(|l| l.expression.clone()))
            .collect();

        // HTML header
        writeln!(html, "<!DOCTYPE html>")?;
        writeln!(html, "<html lang=\"en\">")?;
        writeln!(html, "<head>")?;
        writeln!(html, "    <meta charset=\"UTF-8\">")?;
        writeln!(
            html,
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        )?;
        writeln!(html, "    <title>{}</title>", escape_html(&title))?;
        if self.include_styles {
            writeln!(html, "{}", self.get_styles())?;
        }
        writeln!(html, "</head>")?;
        writeln!(html, "<body>")?;
        writeln!(html, "<div class=\"container\">")?;

        // Header
        writeln!(html, "<div class=\"header\">")?;
        writeln!(html, "    <h1>{}</h1>", escape_html(&title))?;
        if let Some(ref name) = sbom.document.name {
            writeln!(html, "    <p>Document: {}</p>", escape_html(name))?;
        }
        writeln!(
            html,
            "    <p>Generated by sbom-tools v{} on {}</p>",
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )?;
        writeln!(html, "</div>")?;

        // Summary cards
        writeln!(html, "<div class=\"summary-cards\">")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Total Components</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value\">{}</div>",
            total_components
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Vulnerable Components</div>"
        )?;
        let vuln_class = if vuln_component_count > 0 {
            "critical"
        } else {
            ""
        };
        writeln!(
            html,
            "        <div class=\"card-value {}\">{}</div>",
            vuln_class, vuln_component_count
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Total Vulnerabilities</div>"
        )?;
        let total_vuln_class = if total_vulns > 0 { "critical" } else { "" };
        writeln!(
            html,
            "        <div class=\"card-value {}\">{}</div>",
            total_vuln_class, total_vulns
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(html, "        <div class=\"card-title\">Ecosystems</div>")?;
        writeln!(
            html,
            "        <div class=\"card-value\">{}</div>",
            ecosystems.len()
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "    <div class=\"card\">")?;
        writeln!(
            html,
            "        <div class=\"card-title\">Unique Licenses</div>"
        )?;
        writeln!(
            html,
            "        <div class=\"card-value\">{}</div>",
            licenses.len()
        )?;
        writeln!(html, "    </div>")?;

        writeln!(html, "</div>")?;

        // Components table
        if config.includes(ReportType::Components) && total_components > 0 {
            writeln!(html, "<div class=\"section\">")?;
            writeln!(html, "    <h2>Components</h2>")?;
            writeln!(html, "    <table>")?;
            writeln!(html, "        <thead>")?;
            writeln!(html, "            <tr>")?;
            writeln!(html, "                <th>Name</th>")?;
            writeln!(html, "                <th>Version</th>")?;
            writeln!(html, "                <th>Ecosystem</th>")?;
            writeln!(html, "                <th>License</th>")?;
            writeln!(html, "                <th>Vulnerabilities</th>")?;
            writeln!(html, "            </tr>")?;
            writeln!(html, "        </thead>")?;
            writeln!(html, "        <tbody>")?;

            // Sort components by name for consistent output
            let mut components: Vec<_> = sbom.components.values().collect();
            components.sort_by(|a, b| a.name.cmp(&b.name));

            for comp in components {
                let license_str = comp
                    .licenses
                    .declared
                    .first()
                    .map(|l| l.expression.as_str())
                    .unwrap_or("-");
                let vuln_count = comp.vulnerabilities.len();
                let vuln_badge = if vuln_count > 0 {
                    format!(
                        "<span class=\"badge badge-critical\">{}</span>",
                        vuln_count
                    )
                } else {
                    "0".to_string()
                };

                writeln!(html, "            <tr>")?;
                writeln!(html, "                <td>{}</td>", escape_html(&comp.name))?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(comp.version.as_deref())
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    comp.ecosystem
                        .as_ref()
                        .map(|e| escape_html(&format!("{:?}", e)))
                        .unwrap_or_else(|| "-".to_string())
                )?;
                writeln!(html, "                <td>{}</td>", escape_html(license_str))?;
                writeln!(html, "                <td>{}</td>", vuln_badge)?;
                writeln!(html, "            </tr>")?;
            }

            writeln!(html, "        </tbody>")?;
            writeln!(html, "    </table>")?;
            writeln!(html, "</div>")?;
        }

        // Vulnerabilities table
        if config.includes(ReportType::Vulnerabilities) && total_vulns > 0 {
            writeln!(html, "<div class=\"section\">")?;
            writeln!(html, "    <h2>Vulnerabilities</h2>")?;
            writeln!(html, "    <table>")?;
            writeln!(html, "        <thead>")?;
            writeln!(html, "            <tr>")?;
            writeln!(html, "                <th>ID</th>")?;
            writeln!(html, "                <th>Severity</th>")?;
            writeln!(html, "                <th>CVSS</th>")?;
            writeln!(html, "                <th>Component</th>")?;
            writeln!(html, "                <th>Version</th>")?;
            writeln!(html, "            </tr>")?;
            writeln!(html, "        </thead>")?;
            writeln!(html, "        <tbody>")?;

            // Collect all vulnerabilities with their component info
            let mut all_vulns: Vec<VulnRow<'_>> = sbom
                .components
                .values()
                .flat_map(|comp| {
                    comp.vulnerabilities.iter().map(move |v| {
                        (
                            v.id.as_str(),
                            &v.severity,
                            v.cvss.first().map(|c| c.base_score),
                            comp.name.as_str(),
                            comp.version.as_deref(),
                        )
                    })
                })
                .collect();

            // Sort by severity (critical first)
            all_vulns.sort_by(|a, b| {
                let sev_order = |s: &Option<crate::model::Severity>| match s {
                    Some(crate::model::Severity::Critical) => 0,
                    Some(crate::model::Severity::High) => 1,
                    Some(crate::model::Severity::Medium) => 2,
                    Some(crate::model::Severity::Low) => 3,
                    Some(crate::model::Severity::Info) => 4,
                    _ => 5,
                };
                sev_order(a.1).cmp(&sev_order(b.1))
            });

            for (id, severity, cvss, comp_name, version) in all_vulns {
                let (badge_class, sev_str) = match severity {
                    Some(crate::model::Severity::Critical) => ("badge-critical", "Critical"),
                    Some(crate::model::Severity::High) => ("badge-high", "High"),
                    Some(crate::model::Severity::Medium) => ("badge-medium", "Medium"),
                    Some(crate::model::Severity::Low) => ("badge-low", "Low"),
                    Some(crate::model::Severity::Info) => ("badge-low", "Info"),
                    _ => ("badge-low", "Unknown"),
                };

                writeln!(html, "            <tr>")?;
                writeln!(html, "                <td>{}</td>", escape_html(id))?;
                writeln!(
                    html,
                    "                <td><span class=\"badge {}\">{}</span></td>",
                    badge_class, sev_str
                )?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    cvss.map(|s| format!("{:.1}", s))
                        .unwrap_or_else(|| "-".to_string())
                )?;
                writeln!(html, "                <td>{}</td>", escape_html(comp_name))?;
                writeln!(
                    html,
                    "                <td>{}</td>",
                    escape_html_opt(version)
                )?;
                writeln!(html, "            </tr>")?;
            }

            writeln!(html, "        </tbody>")?;
            writeln!(html, "    </table>")?;
            writeln!(html, "</div>")?;
        }

        // Footer
        writeln!(html, "<div class=\"footer\">")?;
        writeln!(html, "    <p>Generated by <a href=\"https://github.com/binarly-io/sbom-tools\">sbom-tools</a></p>")?;
        writeln!(html, "</div>")?;

        writeln!(html, "</div>")?;
        writeln!(html, "</body>")?;
        writeln!(html, "</html>")?;

        Ok(html)
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Html
    }
}

/// Format SLA status for HTML display
fn format_sla_html(vuln: &VulnerabilityDetail) -> (String, &'static str) {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => (format!("{}d late", days), "sla-overdue"),
        SlaStatus::DueSoon(days) => (format!("{}d left", days), "sla-due-soon"),
        SlaStatus::OnTrack(days) => (format!("{}d left", days), "sla-on-track"),
        SlaStatus::NoDueDate => {
            let text = vuln
                .days_since_published
                .map(|d| format!("{}d old", d))
                .unwrap_or_else(|| "-".to_string());
            (text, "sla-unknown")
        }
    }
}
