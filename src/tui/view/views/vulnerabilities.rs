//! Vulnerability explorer view for ViewApp.

use crate::tui::theme::colors;
use crate::tui::view::app::{ViewApp, VulnGroupBy};
use crate::tui::widgets::{truncate_str, SeverityBadge};
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
};

pub fn render_vulnerabilities(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Stats/histogram
            Constraint::Length(2), // Filter bar
            Constraint::Min(10),   // Vulnerability table
        ])
        .split(area);

    render_stats(frame, chunks[0], app);
    render_filter_bar(frame, chunks[1], app);
    render_vuln_table(frame, chunks[2], app);
}

fn render_stats(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let stats = &app.stats;
    let total = stats.vuln_count.max(1);

    // Create a severity histogram - include Unknown if there are any
    let has_unknown = stats.unknown_count > 0;

    let chunks = if has_unknown {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ])
            .split(area)
    };

    let scheme = colors();
    // Severity cards
    render_severity_card(
        frame,
        chunks[0],
        "CRITICAL",
        stats.critical_count,
        total,
        scheme.critical,
    );
    render_severity_card(
        frame,
        chunks[1],
        "HIGH",
        stats.high_count,
        total,
        scheme.high,
    );
    render_severity_card(
        frame,
        chunks[2],
        "MEDIUM",
        stats.medium_count,
        total,
        scheme.medium,
    );
    render_severity_card(frame, chunks[3], "LOW", stats.low_count, total, scheme.low);

    if has_unknown {
        render_severity_card(
            frame,
            chunks[4],
            "UNKNOWN",
            stats.unknown_count,
            total,
            scheme.muted,
        );
    }
}

fn render_severity_card(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    count: usize,
    total: usize,
    color: Color,
) {
    let scheme = colors();
    let _pct = if total > 0 {
        (count as f64 / total as f64 * 100.0) as u16
    } else {
        0
    };

    let bar_width = (area.width.saturating_sub(4)) as usize;
    let filled = if total > 0 {
        (count * bar_width / total).max(if count > 0 { 1 } else { 0 })
    } else {
        0
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            format!(" {} ", label),
            Style::default()
                .fg(scheme.severity_badge_fg(label))
                .bg(color)
                .bold(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            count.to_string(),
            Style::default()
                .fg(color)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
        ]),
    ];

    let card = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(card, area);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let filter_label = match &app.vuln_state.filter_severity {
        Some(s) => s.to_uppercase(),
        None => "All".to_string(),
    };

    let group_label = match app.vuln_state.group_by {
        VulnGroupBy::Severity => "Severity",
        VulnGroupBy::Component => "Component",
        VulnGroupBy::Flat => "Flat",
    };

    let spans = vec![
        Span::styled("Filter: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {} ", filter_label),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Group: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {} ", group_label),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[f]", Style::default().fg(scheme.accent)),
        Span::raw(" filter  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" group  "),
        Span::styled("[Enter]", Style::default().fg(scheme.accent)),
        Span::raw(" jump to component"),
    ];

    let para = Paragraph::new(Line::from(spans));
    frame.render_widget(para, area);
}

fn render_vuln_table(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    // Build vulnerability list
    let mut vulns: Vec<VulnRow> = Vec::new();
    let mut total_unfiltered = 0;

    for (comp_id, comp) in &app.sbom.components {
        for vuln in &comp.vulnerabilities {
            total_unfiltered += 1;
            let sev = vuln
                .severity
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            // Apply filter
            if let Some(ref filter) = app.vuln_state.filter_severity {
                if sev.to_lowercase() != *filter {
                    continue;
                }
            }

            vulns.push(VulnRow {
                vuln_id: vuln.id.clone(),
                severity: sev,
                cvss: vuln.max_cvss_score().map(|v| v as f64),
                component_name: comp.name.clone(),
                component_id: comp_id.value().to_string(),
                description: vuln.description.clone(),
            });
        }
    }

    // Handle empty states
    if vulns.is_empty() {
        if total_unfiltered == 0 {
            crate::tui::widgets::render_empty_state_enhanced(
                frame,
                area,
                "✓",
                "No vulnerabilities detected",
                Some("Great news! No known vulnerabilities were found"),
                None,
            );
        } else {
            let filter_label = app
                .vuln_state
                .filter_severity
                .as_ref()
                .map(|s| s.to_uppercase())
                .unwrap_or_else(|| "current".to_string());
            crate::tui::widgets::render_no_results_state(
                frame,
                area,
                "Severity Filter",
                &filter_label,
            );
        }
        app.vuln_state.total = 0;
        return;
    }

    // Sort by severity then CVSS
    vulns.sort_by(|a, b| {
        let sev_order = |s: &str| match s.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let ord = sev_order(&b.severity).cmp(&sev_order(&a.severity));
        if ord == std::cmp::Ordering::Equal {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        } else {
            ord
        }
    });

    // Update total and clamp selection to valid bounds
    app.vuln_state.total = vulns.len();
    app.vuln_state.clamp_selection();

    // Build table rows - don't apply selection styling here, let the table handle it
    let rows: Vec<Row> = vulns
        .iter()
        .map(|v| {
            let sev_color = SeverityBadge::fg_color(&v.severity);

            Row::new(vec![
                Cell::from(Span::styled(
                    format!(" {} ", SeverityBadge::indicator(&v.severity)),
                    Style::default()
                        .fg(scheme.severity_badge_fg(&v.severity))
                        .bg(sev_color)
                        .bold(),
                )),
                Cell::from(Span::styled(
                    &v.vuln_id,
                    Style::default().fg(sev_color).bold(),
                )),
                Cell::from(
                    v.cvss
                        .map(|c| format!("{:.1}", c))
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(Span::styled(
                    truncate_str(&v.component_name, 25),
                    Style::default().fg(scheme.primary),
                )),
                Cell::from(Span::styled(
                    v.description
                        .as_ref()
                        .map(|d| truncate_str(d, 40))
                        .unwrap_or_else(|| "-".to_string()),
                    Style::default().fg(scheme.muted),
                )),
            ])
        })
        .collect();

    let header = Row::new(vec!["Sev", "CVE ID", "CVSS", "Component", "Description"])
        .style(Style::default().fg(scheme.accent).bold())
        .height(1);

    let widths = [
        Constraint::Length(5),
        Constraint::Length(18),
        Constraint::Length(6),
        Constraint::Length(25),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Vulnerabilities ({}) ", vulns.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.high)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    // Use scroll_offset to maintain scroll position
    let mut state = TableState::default()
        .with_offset(app.vuln_state.scroll_offset)
        .with_selected(if vulns.is_empty() {
            None
        } else {
            Some(app.vuln_state.selected)
        });

    frame.render_stateful_widget(table, area, &mut state);

    // Save the scroll offset for next frame
    app.vuln_state.scroll_offset = state.offset();

    // Render scrollbar if needed
    let visible_height = area.height.saturating_sub(3) as usize;
    if vulns.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.high))
            .track_style(Style::default().fg(scheme.muted));

        let mut scrollbar_state =
            ScrollbarState::new(vulns.len()).position(app.vuln_state.selected);

        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

#[allow(dead_code)]
struct VulnRow {
    vuln_id: String,
    severity: String,
    cvss: Option<f64>,
    component_name: String,
    component_id: String,
    description: Option<String>,
}
