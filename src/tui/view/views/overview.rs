//! Overview tab for ViewApp - high-level SBOM statistics.

use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use crate::tui::widgets::{format_count, SeverityBar};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

pub fn render_overview(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    // Split into left (stats) and right (details) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_stats_panel(frame, chunks[0], app);
    render_details_panel(frame, chunks[1], app);
}

fn render_stats_panel(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Summary cards
            Constraint::Length(8), // Vulnerability breakdown
            Constraint::Min(6),    // Ecosystem distribution
        ])
        .split(area);

    // Summary cards
    render_summary_cards(frame, chunks[0], app);

    // Vulnerability breakdown
    render_vuln_breakdown(frame, chunks[1], app);

    // Ecosystem distribution
    render_ecosystem_dist(frame, chunks[2], app);
}

fn render_summary_cards(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let stats = &app.stats;

    let card_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    // Components card
    let comp_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format_count(stats.component_count),
            Style::default()
                .fg(scheme.primary)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Components", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("{} ecosystems", stats.ecosystem_counts.len()),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let comp_para = Paragraph::new(comp_content)
        .block(
            Block::default()
                .title(" Components ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(comp_para, card_chunks[0]);

    // Vulnerabilities card
    let vuln_color = if stats.critical_count > 0 {
        scheme.critical
    } else if stats.high_count > 0 {
        scheme.high
    } else if stats.vuln_count > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    let vuln_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format_count(stats.vuln_count),
            Style::default()
                .fg(vuln_color)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Vulnerabilities", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "{}C {}H {}M {}L",
                stats.critical_count, stats.high_count, stats.medium_count, stats.low_count
            ),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let vuln_para = Paragraph::new(vuln_content)
        .block(
            Block::default()
                .title(" Vulnerabilities ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(vuln_color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(vuln_para, card_chunks[1]);

    // Licenses card
    let lic_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            stats.license_count.to_string(),
            Style::default()
                .fg(scheme.success)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Unique Licenses", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "{} unknown",
                stats.license_counts.get("Unknown").unwrap_or(&0)
            ),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let lic_para = Paragraph::new(lic_content)
        .block(
            Block::default()
                .title(" Licenses ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(lic_para, card_chunks[2]);
}

fn render_vuln_breakdown(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let stats = &app.stats;
    let total = stats.vuln_count.max(1);

    let mut lines = vec![Line::from("")];

    // Severity bar
    let _bar = SeverityBar::new(
        stats.critical_count,
        stats.high_count,
        stats.medium_count,
        stats.low_count,
    );

    // Add percentage breakdown
    let add_severity_line = |lines: &mut Vec<Line>, label: &str, count: usize, color: Color| {
        let pct = (count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 20;
        let filled = (count * bar_width / total.max(1)).max(if count > 0 { 1 } else { 0 });
        let scheme = colors();

        lines.push(Line::from(vec![
            Span::styled(format!("{:>10} ", label), Style::default().fg(color).bold()),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {:>5} ({:>2}%)", count, pct),
                Style::default().fg(scheme.text),
            ),
        ]));
    };

    add_severity_line(
        &mut lines,
        "Critical",
        stats.critical_count,
        scheme.critical,
    );
    add_severity_line(&mut lines, "High", stats.high_count, scheme.high);
    add_severity_line(&mut lines, "Medium", stats.medium_count, scheme.medium);
    add_severity_line(&mut lines, "Low", stats.low_count, scheme.low);

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Vulnerability Severity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(para, area);
}

fn render_ecosystem_dist(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let stats = &app.stats;

    // Sort ecosystems by count
    let mut ecosystems: Vec<_> = stats.ecosystem_counts.iter().collect();
    ecosystems.sort_by(|a, b| b.1.cmp(a.1));

    let total = stats.component_count.max(1);

    let mut lines = vec![];

    let palette = scheme.chart_palette();

    for (i, (eco, count)) in ecosystems.iter().take(6).enumerate() {
        let pct = (**count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 25;
        let filled = (**count * bar_width / total).max(if **count > 0 { 1 } else { 0 });
        let color = palette[i % palette.len()];

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", if eco.len() > 12 { &eco[..12] } else { eco }),
                Style::default().fg(color).bold(),
            ),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {:>5} ({:>2}%)", count, pct),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    if ecosystems.len() > 6 {
        let remaining: usize = ecosystems.iter().skip(6).map(|(_, c)| *c).sum();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", "Other"),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!("{} more", remaining),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Ecosystem Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );

    frame.render_widget(para, area);
}

fn render_details_panel(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Document info
            Constraint::Min(6),     // Top components with vulns
        ])
        .split(area);

    // Document info
    render_document_info(frame, chunks[0], app);

    // Top vulnerable components
    render_top_vulnerable(frame, chunks[1], app);
}

fn render_document_info(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let doc = &app.sbom.document;

    let mut lines = vec![];

    if let Some(name) = &doc.name {
        lines.push(Line::from(vec![
            Span::styled("Name: ", Style::default().fg(scheme.muted)),
            Span::styled(name, Style::default().fg(scheme.text).bold()),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Format: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!("{} {}", doc.format, doc.format_version),
            Style::default().fg(scheme.primary),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("Created: ", Style::default().fg(scheme.muted)),
        Span::raw(doc.created.format("%Y-%m-%d %H:%M:%S").to_string()),
    ]));

    // Get creators (people and orgs)
    let authors: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| {
            matches!(
                c.creator_type,
                crate::model::CreatorType::Person | crate::model::CreatorType::Organization
            )
        })
        .map(|c| c.name.clone())
        .collect();
    if !authors.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Creators: ", Style::default().fg(scheme.muted)),
            Span::raw(authors.join(", ")),
        ]));
    }

    // Get tools
    let tools: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
        .map(|c| c.name.clone())
        .collect();
    if !tools.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tools: ", Style::default().fg(scheme.muted)),
            Span::raw(tools.join(", ")),
        ]));
    }

    if let Some(serial) = &doc.serial_number {
        lines.push(Line::from(vec![
            Span::styled("Serial: ", Style::default().fg(scheme.muted)),
            Span::raw(if serial.len() > 40 {
                format!("{}...", &serial[..40])
            } else {
                serial.clone()
            }),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Document Info ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(para, area);
}

fn render_top_vulnerable(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();

    // Get components sorted by vulnerability count
    let mut vuln_comps: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| !c.vulnerabilities.is_empty())
        .map(|c| (c.name.clone(), c.vulnerabilities.len(), c.max_severity()))
        .collect();

    vuln_comps.sort_by(|a, b| b.1.cmp(&a.1));

    let rows: Vec<Row> = vuln_comps
        .iter()
        .take(8)
        .map(|(name, count, max_sev)| {
            let sev_str = max_sev.as_deref().unwrap_or("Unknown");
            let sev_color = scheme.severity_color(sev_str);

            Row::new(vec![
                if name.len() > 25 {
                    format!("{}...", &name[..22])
                } else {
                    name.clone()
                },
                count.to_string(),
                sev_str.to_string(),
            ])
            .style(Style::default().fg(sev_color))
        })
        .collect();

    let header = Row::new(vec!["Component", "CVEs", "Max Severity"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(
                " Top Vulnerable Components ({}) ",
                vuln_comps.len()
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(table, area);
}

/// Extension trait for Component to get max severity.
trait ComponentExt {
    fn max_severity(&self) -> Option<String>;
}

impl ComponentExt for crate::model::Component {
    fn max_severity(&self) -> Option<String> {
        self.vulnerabilities
            .iter()
            .filter_map(|v| v.severity.as_ref())
            .max_by(|a, b| {
                let order = |s: &crate::model::Severity| match s.to_string().to_lowercase().as_str()
                {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    "low" => 1,
                    _ => 0,
                };
                order(a).cmp(&order(b))
            })
            .map(|s| s.to_string())
    }
}
