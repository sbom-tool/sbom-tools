//! Summary view with visual gauges and charts.

use crate::tui::app::{App, AppMode};
use crate::tui::theme::colors;
use crate::quality::ComplianceResult;
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Gauge, Paragraph},
};

pub(crate) fn render_summary(frame: &mut Frame, area: Rect, app: &App) {
    match app.mode {
        AppMode::Diff => render_diff_summary(frame, area, app),
        AppMode::View => render_view_summary(frame, area, app),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_summary(frame: &mut Frame, area: Rect, app: &App) {
    let Some(result) = app.data.diff_result.as_ref() else {
        return;
    };
    let old_count = app
        .data.old_sbom
        .as_ref()
        .map(crate::model::NormalizedSbom::component_count)
        .unwrap_or(0);
    let new_count = app
        .data.new_sbom
        .as_ref()
        .map(crate::model::NormalizedSbom::component_count)
        .unwrap_or(0);

    // Main layout: top row (score + stats), compliance, middle row (charts), bottom row (top changes)
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Semantic score gauge
            Constraint::Length(8),  // Stats cards
            Constraint::Length(5),  // Policy compliance
            Constraint::Length(10), // Bar charts
            Constraint::Min(6),     // Top changes
        ])
        .split(area);

    // Semantic Score Gauge
    render_semantic_score_gauge(frame, main_chunks[0], result.semantic_score);

    // Stats cards row
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(main_chunks[1]);

    render_components_card(frame, stats_chunks[0], result, old_count, new_count);
    render_dependencies_card(frame, stats_chunks[1], result);
    render_vulnerabilities_card(frame, stats_chunks[2], result);
    render_cra_card(frame, stats_chunks[3], app);

    // Policy compliance section
    render_policy_compliance(frame, main_chunks[2], app);

    // Bar charts row
    let chart_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[3]);

    render_change_distribution_chart(frame, chart_chunks[0], result);
    render_severity_chart(frame, chart_chunks[1], result);

    // Top changes section
    render_top_changes(frame, main_chunks[4], app);
}

fn render_semantic_score_gauge(frame: &mut Frame, area: Rect, score: f64) {
    let scheme = colors();
    let score_percent = score.clamp(0.0, 100.0) as u16;

    let (gauge_color, label_text) = match score_percent {
        0..=25 => (scheme.success, "Minimal Changes"),
        26..=50 => (scheme.primary, "Moderate Changes"),
        51..=75 => (scheme.warning, "Significant Changes"),
        _ => (scheme.error, "Major Changes"),
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Semantic Score ")
                .title_style(Style::default().bold().fg(scheme.text))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(scheme.muted))
        .percent(score_percent)
        .label(format!("{score:.1} - {label_text}"));

    frame.render_widget(gauge, area);
}

fn render_components_card(
    frame: &mut Frame,
    area: Rect,
    result: &crate::diff::DiffResult,
    old_count: usize,
    new_count: usize,
) {
    let scheme = colors();
    let added = result.summary.components_added;
    let removed = result.summary.components_removed;
    let modified = result.summary.components_modified;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED    ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED  ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(vec![
            Span::styled(
                " ~ MODIFIED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {modified}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Total: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{old_count} → {new_count}")),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Components ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(paragraph, area);
}

fn render_dependencies_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let added = result.summary.dependencies_added;
    let removed = result.summary.dependencies_removed;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Net change: ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{:+}", added as i32 - removed as i32),
                if added >= removed {
                    Style::default().fg(scheme.added)
                } else {
                    Style::default().fg(scheme.removed)
                },
            ),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Dependencies ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.critical)),
    );

    frame.render_widget(paragraph, area);
}

fn render_cra_card(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();
    let (old_status, old_style, old_counts) = format_compliance_line(app.data.old_cra_compliance.as_ref(), &scheme);
    let (new_status, new_style, new_counts) = format_compliance_line(app.data.new_cra_compliance.as_ref(), &scheme);

    let text = vec![
        Line::from(vec![
            Span::styled("Old: ", Style::default().fg(scheme.muted)),
            Span::styled(old_status, old_style),
            Span::styled(format!(" {old_counts}"), Style::default().fg(scheme.muted)),
        ]),
        Line::from(vec![
            Span::styled("New: ", Style::default().fg(scheme.muted)),
            Span::styled(new_status, new_style),
            Span::styled(format!(" {new_counts}"), Style::default().fg(scheme.muted)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("CRA readiness checks", Style::default().fg(scheme.muted)),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" CRA Readiness ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(paragraph, area);
}

fn render_policy_compliance(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();
    let compliance = &app.compliance_state;

    let mut spans = vec![
        Span::styled("Policy: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {} ", compliance.policy_preset.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  "),
    ];

    if let Some(ref result) = compliance.result {
        // Show compliance status
        let (status, status_style) = if result.passes {
            (
                " PASS ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.success)
                    .bold(),
            )
        } else {
            (
                " FAIL ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.error)
                    .bold(),
            )
        };

        spans.push(Span::styled(status, status_style));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("Score: {}", result.score),
            Style::default().fg(if result.score >= 80 {
                scheme.success
            } else if result.score >= 50 {
                scheme.warning
            } else {
                scheme.error
            }),
        ));
        spans.push(Span::raw("  "));

        // Show violation counts by severity
        let critical = result.count_by_severity(crate::tui::security::PolicySeverity::Critical);
        let high = result.count_by_severity(crate::tui::security::PolicySeverity::High);
        let medium = result.count_by_severity(crate::tui::security::PolicySeverity::Medium);
        let low = result.count_by_severity(crate::tui::security::PolicySeverity::Low);

        if critical > 0 {
            spans.push(Span::styled(
                format!("●{critical} "),
                Style::default().fg(scheme.critical).bold(),
            ));
        }
        if high > 0 {
            spans.push(Span::styled(
                format!("●{high} "),
                Style::default().fg(scheme.high),
            ));
        }
        if medium > 0 {
            spans.push(Span::styled(
                format!("●{medium} "),
                Style::default().fg(scheme.medium),
            ));
        }
        if low > 0 {
            spans.push(Span::styled(
                format!("○{low} "),
                Style::default().fg(scheme.low),
            ));
        }

        // Show top violation if any
        if let Some(violation) = result.violations.first() {
            spans.push(Span::styled("│ ", Style::default().fg(scheme.border)));
            spans.push(Span::styled(
                truncate(&violation.description, 50),
                Style::default().fg(scheme.text_muted).italic(),
            ));
        }
    } else {
        // Not checked yet
        spans.push(Span::styled(
            "Not checked",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::raw("  "));
        spans.push(Span::styled("[P]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " to check  ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled("[p]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " cycle policy",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .title(" Security Policy ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if compliance.passes() {
                scheme.success
            } else if compliance.checked {
                scheme.error
            } else {
                scheme.border
            })),
    );

    frame.render_widget(paragraph, area);
}

fn format_compliance_line(
    result: Option<&ComplianceResult>,
    scheme: &crate::tui::theme::ColorScheme,
) -> (String, Style, String) {
    match result {
        Some(r) => {
            let status = if r.is_compliant { "OK" } else { "FAIL" };
            let style = if r.is_compliant {
                Style::default().fg(scheme.success).bold()
            } else {
                Style::default().fg(scheme.error).bold()
            };
            let counts = format!("E{} W{} I{}", r.error_count, r.warning_count, r.info_count);
            (status.to_string(), style, counts)
        }
        None => (
            "N/A".to_string(),
            Style::default().fg(scheme.muted),
            String::new(),
        ),
    }
}

fn render_vulnerabilities_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let introduced = result.summary.vulnerabilities_introduced;
    let resolved = result.summary.vulnerabilities_resolved;
    let persistent = result.summary.vulnerabilities_persistent;

    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0);
    let high = *severity_counts.get("High").unwrap_or(&0);

    let text = vec![
        Line::from(vec![
            Span::styled(
                " ▲ NEW     ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {introduced}")),
        ]),
        Line::from(vec![
            Span::styled(
                " ▼ FIXED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {resolved}")),
        ]),
        Line::from(vec![
            Span::styled(
                " ● PERSIST ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {persistent}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Critical: ", Style::default().fg(scheme.critical).bold()),
            Span::raw(format!("{critical}  ")),
            Span::styled("High: ", Style::default().fg(scheme.high)),
            Span::raw(format!("{high}")),
        ]),
    ];

    let border_color = if critical > 0 {
        scheme.critical
    } else if introduced > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Vulnerabilities ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    frame.render_widget(paragraph, area);
}

fn render_change_distribution_chart(
    frame: &mut Frame,
    area: Rect,
    result: &crate::diff::DiffResult,
) {
    let scheme = colors();
    let added = result.summary.components_added as u64;
    let removed = result.summary.components_removed as u64;
    let modified = result.summary.components_modified as u64;

    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" Change Distribution ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .bar_width(8)
        .bar_gap(2)
        .group_gap(3)
        .bar_style(Style::default().fg(scheme.primary))
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text))
        .data(
            BarGroup::default().bars(&[
                Bar::default()
                    .value(added)
                    .label(Line::from("Added"))
                    .style(Style::default().fg(scheme.added)),
                Bar::default()
                    .value(removed)
                    .label(Line::from("Removed"))
                    .style(Style::default().fg(scheme.removed)),
                Bar::default()
                    .value(modified)
                    .label(Line::from("Modified"))
                    .style(Style::default().fg(scheme.modified)),
            ]),
        );

    frame.render_widget(bar_chart, area);
}

fn render_severity_chart(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0) as u64;
    let high = *severity_counts.get("High").unwrap_or(&0) as u64;
    let medium = *severity_counts.get("Medium").unwrap_or(&0) as u64;
    let low = *severity_counts.get("Low").unwrap_or(&0) as u64;

    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" New Vulnerabilities by Severity ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .bar_width(6)
        .bar_gap(1)
        .bar_style(Style::default().fg(scheme.error))
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text))
        .data(
            BarGroup::default().bars(&[
                Bar::default()
                    .value(critical)
                    .label(Line::from("Crit"))
                    .style(Style::default().fg(scheme.critical)),
                Bar::default()
                    .value(high)
                    .label(Line::from("High"))
                    .style(Style::default().fg(scheme.high)),
                Bar::default()
                    .value(medium)
                    .label(Line::from("Med"))
                    .style(Style::default().fg(scheme.medium)),
                Bar::default()
                    .value(low)
                    .label(Line::from("Low"))
                    .style(Style::default().fg(scheme.low)),
            ]),
        );

    frame.render_widget(bar_chart, area);
}

fn render_top_changes(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();
    let Some(result) = app.data.diff_result.as_ref() else {
        return;
    };
    let mut lines = vec![];

    // Critical vulnerabilities first
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .take(2)
    {
        lines.push(Line::from(vec![
            Span::styled(
                " ⚠ CRITICAL ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.critical)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(&vuln.id, Style::default().fg(scheme.critical).bold()),
            Span::styled(" in ", Style::default().fg(scheme.muted)),
            Span::raw(&vuln.component_name),
            Span::styled(
                vuln.description
                    .as_ref()
                    .map(|d| format!(" - {}", truncate(d, 40)))
                    .unwrap_or_default(),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    // Added components with vulnerabilities
    for comp in result.components.added.iter().take(2) {
        let has_vuln = result
            .vulnerabilities
            .introduced
            .iter()
            .any(|v| v.component_id == comp.id);  // ID-based lookup
        let icon = if has_vuln { "⚠" } else { "+" };
        let style = if has_vuln {
            Style::default().fg(scheme.error)
        } else {
            Style::default().fg(scheme.added)
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {icon} "), style.bold()),
            Span::styled(&comp.name, style),
            Span::styled(
                format!(" {}", comp.new_version.as_deref().unwrap_or("")),
                Style::default().fg(scheme.muted),
            ),
            if has_vuln {
                Span::styled(" (has vulnerabilities)", Style::default().fg(scheme.error))
            } else {
                Span::raw("")
            },
        ]));
    }

    // Removed components
    for comp in result.components.removed.iter().take(2) {
        lines.push(Line::from(vec![
            Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
            Span::styled(&comp.name, Style::default().fg(scheme.removed)),
            Span::styled(
                format!(" {}", comp.old_version.as_deref().unwrap_or("")),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    // Version changes (potential downgrades)
    for comp in result.components.modified.iter().take(2) {
        let is_downgrade =
            is_version_downgrade(comp.old_version.as_deref(), comp.new_version.as_deref());

        lines.push(Line::from(vec![
            Span::styled(" ~ ", Style::default().fg(scheme.modified).bold()),
            Span::styled(&comp.name, Style::default().fg(scheme.modified)),
            Span::raw(" "),
            Span::styled(
                comp.old_version.as_deref().unwrap_or("?"),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(" → ", Style::default().fg(scheme.muted)),
            Span::styled(
                comp.new_version.as_deref().unwrap_or("?"),
                Style::default().fg(scheme.added),
            ),
            if is_downgrade {
                Span::styled(" ⚠ downgrade", Style::default().fg(scheme.error).bold())
            } else {
                Span::raw("")
            },
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::styled(
            "No significant changes to highlight",
            Style::default().fg(scheme.muted),
        ));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Top Changes ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.border)),
    );

    frame.render_widget(paragraph, area);
}

fn render_view_summary(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();

    if let Some(sbom) = &app.data.sbom {
        let vuln_counts = sbom.vulnerability_counts();
        let total_vulns =
            vuln_counts.critical + vuln_counts.high + vuln_counts.medium + vuln_counts.low;

        // Main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),  // Overview stats
                Constraint::Length(5),  // Policy compliance
                Constraint::Length(10), // Charts
                Constraint::Min(5),     // Component preview
            ])
            .split(area);

        // Overview stats
        let stats_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(34),
                Constraint::Percentage(33),
            ])
            .split(chunks[0]);

        // Components overview
        let comp_text = vec![
            Line::from(vec![
                Span::styled("Total: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    sbom.component_count().to_string(),
                    Style::default().fg(scheme.primary).bold(),
                ),
            ]),
            Line::from(vec![
                Span::styled("Dependencies: ", Style::default().fg(scheme.muted)),
                Span::raw(sbom.edges.len().to_string()),
            ]),
        ];

        let comp_block = Paragraph::new(comp_text).block(
            Block::default()
                .title(" Components ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.secondary)),
        );
        frame.render_widget(comp_block, stats_chunks[0]);

        // Vulnerability overview with severity gauge
        let vuln_text = vec![
            Line::from(vec![
                Span::styled("Total: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    total_vulns.to_string(),
                    if vuln_counts.critical > 0 {
                        Style::default().fg(scheme.critical).bold()
                    } else {
                        Style::default().fg(scheme.warning)
                    },
                ),
            ]),
            Line::from(vec![
                Span::styled("● ", Style::default().fg(scheme.critical)),
                Span::raw(format!("Critical: {} ", vuln_counts.critical)),
                Span::styled("● ", Style::default().fg(scheme.high)),
                Span::raw(format!("High: {}", vuln_counts.high)),
            ]),
            Line::from(vec![
                Span::styled("● ", Style::default().fg(scheme.medium)),
                Span::raw(format!("Medium: {} ", vuln_counts.medium)),
                Span::styled("● ", Style::default().fg(scheme.low)),
                Span::raw(format!("Low: {}", vuln_counts.low)),
            ]),
        ];

        let vuln_block = Paragraph::new(vuln_text).block(
            Block::default()
                .title(" Vulnerabilities ")
                .borders(Borders::ALL)
                .border_style(if vuln_counts.critical > 0 {
                    Style::default().fg(scheme.critical)
                } else {
                    Style::default().fg(scheme.warning)
                }),
        );
        frame.render_widget(vuln_block, stats_chunks[1]);

        // Ecosystem breakdown
        let mut ecosystem_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for comp in sbom.components.values() {
            let ecosystem = comp
                .ecosystem
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string());
            *ecosystem_counts.entry(ecosystem).or_insert(0) += 1;
        }

        let mut ecosystems: Vec<_> = ecosystem_counts.into_iter().collect();
        ecosystems.sort_by(|a, b| b.1.cmp(&a.1));

        let eco_lines: Vec<Line> = ecosystems
            .iter()
            .take(4)
            .map(|(name, count)| {
                Line::from(vec![
                    Span::styled(format!("{name}: "), Style::default().fg(scheme.primary)),
                    Span::raw(count.to_string()),
                ])
            })
            .collect();

        let eco_block = Paragraph::new(eco_lines).block(
            Block::default()
                .title(" Ecosystems ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        );
        frame.render_widget(eco_block, stats_chunks[2]);

        // Policy compliance section
        render_policy_compliance(frame, chunks[1], app);

        // Severity bar chart
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[2]);

        let severity_chart = BarChart::default()
            .block(
                Block::default()
                    .title(" Vulnerability Severity Distribution ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(scheme.border)),
            )
            .bar_width(8)
            .bar_gap(2)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .value(vuln_counts.critical as u64)
                        .label(Line::from("Critical"))
                        .style(Style::default().fg(scheme.critical)),
                    Bar::default()
                        .value(vuln_counts.high as u64)
                        .label(Line::from("High"))
                        .style(Style::default().fg(scheme.high)),
                    Bar::default()
                        .value(vuln_counts.medium as u64)
                        .label(Line::from("Medium"))
                        .style(Style::default().fg(scheme.medium)),
                    Bar::default()
                        .value(vuln_counts.low as u64)
                        .label(Line::from("Low"))
                        .style(Style::default().fg(scheme.low)),
                ]),
            );

        frame.render_widget(severity_chart, chart_chunks[0]);

        // Ecosystem distribution chart
        let palette = scheme.chart_palette();
        let eco_data: Vec<Bar> = ecosystems
            .iter()
            .take(5)
            .enumerate()
            .map(|(i, (name, count))| {
                Bar::default()
                    .value(*count as u64)
                    .label(Line::from(truncate(name, 8).to_string()))
                    .style(Style::default().fg(palette[i % palette.len()]))
            })
            .collect();

        let eco_chart = BarChart::default()
            .block(
                Block::default()
                    .title(" Ecosystem Distribution ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(scheme.border)),
            )
            .bar_width(7)
            .bar_gap(1)
            .data(BarGroup::default().bars(&eco_data));

        frame.render_widget(eco_chart, chart_chunks[1]);

        // Top vulnerable components
        let vulns = sbom.all_vulnerabilities();
        let mut vuln_lines: Vec<Line> = vec![];

        for (comp, vuln) in vulns.iter().take(5) {
            let severity = vuln
                .severity
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| "Unknown".to_string());
            let severity_color = scheme.severity_color(&severity);
            let severity_style = match severity.to_lowercase().as_str() {
                "critical" | "high" => Style::default().fg(severity_color).bold(),
                _ => Style::default().fg(severity_color),
            };

            vuln_lines.push(Line::from(vec![
                Span::styled(format!("[{severity}] "), severity_style),
                Span::styled(&vuln.id, Style::default().bold()),
                Span::styled(" in ", Style::default().fg(scheme.muted)),
                Span::raw(&comp.name),
            ]));
        }

        if vuln_lines.is_empty() {
            vuln_lines.push(Line::styled(
                "No vulnerabilities detected",
                Style::default().fg(scheme.success),
            ));
        }

        let vuln_preview = Paragraph::new(vuln_lines).block(
            Block::default()
                .title(" Top Vulnerabilities ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        );

        frame.render_widget(vuln_preview, chunks[3]);
    }
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len.saturating_sub(3)]
    }
}

fn is_version_downgrade(old: Option<&str>, new: Option<&str>) -> bool {
    match (old, new) {
        (Some(o), Some(n)) => {
            if let (Ok(old_ver), Ok(new_ver)) =
                (semver::Version::parse(o), semver::Version::parse(n))
            {
                new_ver < old_ver
            } else {
                false
            }
        }
        _ => false,
    }
}
