//! Compliance tab view for diff mode.
//!
//! Shows side-by-side compliance results for old and new SBOMs across all
//! compliance standards, with violation diff (new/resolved/persistent).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Tabs},
    Frame,
};

use crate::quality::{ComplianceLevel, ComplianceResult, ViolationSeverity};
use crate::tui::app::App;
use crate::tui::app_states::DiffComplianceViewMode;
use crate::tui::shared::compliance as shared_compliance;
use crate::tui::theme::colors;

/// Get the count of violations shown in the current view mode (for navigation bounds).
pub fn diff_compliance_violation_count(app: &App) -> usize {
    let idx = app.tabs.diff_compliance.selected_standard;
    let Some(old_results) = app.data.old_compliance_results.as_ref() else {
        return 0;
    };
    let Some(new_results) = app.data.new_compliance_results.as_ref() else {
        return 0;
    };
    if idx >= old_results.len() || idx >= new_results.len() {
        return 0;
    }
    let old = &old_results[idx];
    let new = &new_results[idx];

    match app.tabs.diff_compliance.view_mode {
        DiffComplianceViewMode::Overview => 0,
        DiffComplianceViewMode::NewViolations => compute_new_violations(old, new).len(),
        DiffComplianceViewMode::ResolvedViolations => compute_resolved_violations(old, new).len(),
        DiffComplianceViewMode::OldViolations => old.violations.len(),
        DiffComplianceViewMode::NewSbomViolations => new.violations.len(),
    }
}

/// Main render function for the diff compliance tab.
pub fn render_diff_compliance(frame: &mut Frame, area: Rect, app: &mut App) {
    app.ensure_compliance_results();

    let old_empty = app.data.old_compliance_results.as_ref().is_none_or(std::vec::Vec::is_empty);
    let new_empty = app.data.new_compliance_results.as_ref().is_none_or(std::vec::Vec::is_empty);
    if old_empty || new_empty {
        let msg = Paragraph::new("No compliance data available")
            .block(Block::default().borders(Borders::ALL).title(" Compliance "));
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Standard selector
            Constraint::Length(7),  // Side-by-side summary
            Constraint::Min(10),   // Violations / overview
            Constraint::Length(2), // Help bar
        ])
        .split(area);

    render_standard_selector(frame, chunks[0], app);
    render_sidebyside_summary(frame, chunks[1], app);
    render_violations_panel(frame, chunks[2], app);
    render_help_bar(frame, chunks[3], app);

    // Render detail overlay if active
    if app.tabs.diff_compliance.show_detail {
        if let Some(violation) = get_selected_diff_violation(app) {
            shared_compliance::render_violation_detail_overlay(frame, area, violation);
        }
    }
}

fn render_standard_selector(frame: &mut Frame, area: Rect, app: &App) {
    let levels = ComplianceLevel::all();
    let selected = app.tabs.diff_compliance.selected_standard;
    let Some(old_results) = app.data.old_compliance_results.as_ref() else {
        return;
    };
    let Some(new_results) = app.data.new_compliance_results.as_ref() else {
        return;
    };

    let titles: Vec<Line> = levels
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let old_ok = old_results
                .get(i)
                .is_some_and(|r| r.is_compliant);
            let new_ok = new_results
                .get(i)
                .is_some_and(|r| r.is_compliant);

            let indicator = match (old_ok, new_ok) {
                (true, true) => ("✓", colors().success),
                (false, true) => ("↑", colors().success),
                (true, false) => ("↓", colors().error),
                (false, false) => ("✗", colors().error),
            };

            let style = if i == selected {
                Style::default()
                    .fg(colors().accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(colors().text_muted)
            };

            Line::from(vec![
                Span::styled(format!("{} ", indicator.0), Style::default().fg(indicator.1)),
                Span::styled(level.name(), style),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors().border))
                .title(Span::styled(
                    " Compliance Standards (←/→) ",
                    Style::default().fg(colors().text_muted),
                )),
        )
        .select(selected)
        .divider(Span::styled(" │ ", Style::default().fg(colors().muted)));

    frame.render_widget(tabs, area);
}

fn render_sidebyside_summary(frame: &mut Frame, area: Rect, app: &App) {
    let idx = app.tabs.diff_compliance.selected_standard;
    let old = app.data.old_compliance_results.as_ref().and_then(|r| r.get(idx));
    let new = app.data.new_compliance_results.as_ref().and_then(|r| r.get(idx));

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Old SBOM panel
    if let Some(result) = old {
        render_compliance_gauge(frame, halves[0], result, "Old SBOM");
    }
    // New SBOM panel
    if let Some(result) = new {
        render_compliance_gauge(frame, halves[1], result, "New SBOM");
    }
}

fn render_compliance_gauge(frame: &mut Frame, area: Rect, result: &ComplianceResult, label: &str) {
    let actionable = result.error_count + result.warning_count;
    let pct = if actionable == 0 {
        100
    } else {
        let error_w = result.error_count * 3;
        let warning_w = result.warning_count;
        let max_w = actionable * 3;
        ((max_w.saturating_sub(error_w + warning_w)) * 100 / max_w) as u16
    };

    let status_color = if result.is_compliant && result.warning_count == 0 {
        colors().success
    } else if result.is_compliant {
        colors().warning
    } else {
        colors().error
    };

    let status_text = if result.is_compliant {
        "PASS"
    } else {
        "FAIL"
    };

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3)])
        .split(area);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(status_color))
                .title(Span::styled(
                    format!(" {label} [{status_text}] "),
                    Style::default().fg(status_color),
                )),
        )
        .gauge_style(Style::default().fg(status_color))
        .percent(pct)
        .label(format!("{pct}%"));
    frame.render_widget(gauge, inner[0]);

    let counts = Line::from(vec![
        Span::styled(
            format!(" E:{} ", result.error_count),
            Style::default().fg(colors().error),
        ),
        Span::styled(
            format!("W:{} ", result.warning_count),
            Style::default().fg(colors().warning),
        ),
        Span::styled(
            format!("I:{}", result.info_count),
            Style::default().fg(colors().info),
        ),
    ]);
    let counts_para = Paragraph::new(counts);
    frame.render_widget(counts_para, inner[1]);
}

fn render_violations_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    let idx = app.tabs.diff_compliance.selected_standard;
    let Some(old) = app.data.old_compliance_results.as_ref().and_then(|r| r.get(idx)) else {
        return;
    };
    let Some(new) = app.data.new_compliance_results.as_ref().and_then(|r| r.get(idx)) else {
        return;
    };

    let mode = app.tabs.diff_compliance.view_mode;
    let selected = app.tabs.diff_compliance.selected_violation;

    // Compute viewport height for scroll adjustment (borders=2, header=1, header margin=1)
    let viewport_height = area.height.saturating_sub(4) as usize;
    app.tabs.diff_compliance.adjust_scroll(viewport_height);
    let scroll_offset = app.tabs.diff_compliance.scroll_offset;

    match mode {
        DiffComplianceViewMode::Overview => {
            render_overview(frame, area, old, new);
        }
        DiffComplianceViewMode::NewViolations => {
            let violations = compute_new_violations(old, new);
            render_violation_table(frame, area, &violations, selected, scroll_offset, "New Violations (introduced)", colors().error);
        }
        DiffComplianceViewMode::ResolvedViolations => {
            let violations = compute_resolved_violations(old, new);
            render_violation_table(frame, area, &violations, selected, scroll_offset, "Resolved Violations (fixed)", colors().success);
        }
        DiffComplianceViewMode::OldViolations => {
            let violations: Vec<_> = old.violations.iter().map(ViolationEntry::from_violation).collect();
            render_violation_table(frame, area, &violations, selected, scroll_offset, "Old SBOM — All Violations", colors().text_muted);
        }
        DiffComplianceViewMode::NewSbomViolations => {
            let violations: Vec<_> = new.violations.iter().map(ViolationEntry::from_violation).collect();
            render_violation_table(frame, area, &violations, selected, scroll_offset, "New SBOM — All Violations", colors().text_muted);
        }
    }
}

fn render_overview(frame: &mut Frame, area: Rect, old: &ComplianceResult, new: &ComplianceResult) {
    let new_violations = compute_new_violations(old, new);
    let resolved_violations = compute_resolved_violations(old, new);

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Violation Diff:  ", Style::default().fg(colors().text).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
    ];

    // New violations
    let new_color = if new_violations.is_empty() {
        colors().success
    } else {
        colors().error
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            format!("  + {} new violation(s) introduced  ", new_violations.len()),
            Style::default().fg(new_color).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Resolved violations
    let resolved_color = if resolved_violations.is_empty() {
        colors().text_muted
    } else {
        colors().success
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            format!("  - {} violation(s) resolved  ", resolved_violations.len()),
            Style::default().fg(resolved_color).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Persistent
    let persistent = new.violations.len().saturating_sub(new_violations.len());
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            format!("  = {persistent} violation(s) persistent  "),
            Style::default().fg(colors().text_muted),
        ),
    ]));

    lines.push(Line::from(""));

    // Delta summary
    let old_errors = old.error_count;
    let new_errors = new.error_count;
    let error_delta = new_errors as i64 - old_errors as i64;
    let delta_str = if error_delta > 0 {
        format!("+{error_delta}")
    } else {
        format!("{error_delta}")
    };
    let delta_color = match error_delta.cmp(&0) {
        std::cmp::Ordering::Greater => colors().error,
        std::cmp::Ordering::Less => colors().success,
        std::cmp::Ordering::Equal => colors().text_muted,
    };

    lines.push(Line::from(vec![
        Span::raw("    Error count:  "),
        Span::styled(format!("{old_errors}"), Style::default().fg(colors().text_muted)),
        Span::raw(" → "),
        Span::styled(format!("{new_errors}"), Style::default().fg(colors().text)),
        Span::raw("  ("),
        Span::styled(delta_str, Style::default().fg(delta_color)),
        Span::raw(")"),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "    Press Tab to cycle through: Overview → New → Resolved → Old → New SBOM",
            Style::default().fg(colors().text_muted),
        ),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colors().border))
        .title(Span::styled(
            " Compliance Diff Overview ",
            Style::default().fg(colors().accent),
        ));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

struct ViolationEntry {
    severity: String,
    severity_color: ratatui::style::Color,
    category: String,
    message: String,
    element: String,
}

impl ViolationEntry {
    fn from_violation(v: &crate::quality::Violation) -> Self {
        let (severity, severity_color) = match v.severity {
            ViolationSeverity::Error => ("ERROR", colors().error),
            ViolationSeverity::Warning => ("WARN", colors().warning),
            ViolationSeverity::Info => ("INFO", colors().info),
        };
        Self {
            severity: severity.to_string(),
            severity_color,
            category: v.category.name().to_string(),
            message: v.message.clone(),
            element: v.element.clone().unwrap_or_default(),
        }
    }
}

fn render_violation_table(
    frame: &mut Frame,
    area: Rect,
    violations: &[ViolationEntry],
    selected: usize,
    scroll_offset: usize,
    title: &str,
    title_color: ratatui::style::Color,
) {
    if violations.is_empty() {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No violations in this category",
                Style::default().fg(colors().success),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" {title} (0) "),
                    Style::default().fg(title_color),
                )),
        );
        frame.render_widget(msg, area);
        return;
    }

    let viewport_height = area.height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(violations.len());

    let header = Row::new(vec![
        Cell::from("Severity").style(Style::default().fg(colors().text).add_modifier(Modifier::BOLD)),
        Cell::from("Category").style(Style::default().fg(colors().text).add_modifier(Modifier::BOLD)),
        Cell::from("Issue").style(Style::default().fg(colors().text).add_modifier(Modifier::BOLD)),
        Cell::from("Element").style(Style::default().fg(colors().text).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = violations
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_end - scroll_offset)
        .map(|(i, v)| {
            let style = if i == selected {
                Style::default().bg(colors().selection)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(v.severity.as_str()).style(Style::default().fg(v.severity_color)),
                Cell::from(v.category.as_str()),
                Cell::from(v.message.as_str()),
                Cell::from(v.element.as_str()).style(Style::default().fg(colors().text_muted)),
            ])
            .style(style)
        })
        .collect();

    // Show scroll position in title when scrolled
    let title_text = if scroll_offset > 0 || visible_end < violations.len() {
        format!(
            " {} ({}) [{}-{}/{}] — j/k to navigate ",
            title,
            violations.len(),
            scroll_offset + 1,
            visible_end,
            violations.len(),
        )
    } else {
        format!(" {} ({}) — j/k to navigate ", title, violations.len())
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Min(30),
            Constraint::Length(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().border))
            .title(Span::styled(title_text, Style::default().fg(title_color))),
    );

    frame.render_widget(table, area);
}

fn render_help_bar(frame: &mut Frame, area: Rect, app: &App) {
    let mode_name = match app.tabs.diff_compliance.view_mode {
        DiffComplianceViewMode::Overview => "Overview",
        DiffComplianceViewMode::NewViolations => "New",
        DiffComplianceViewMode::ResolvedViolations => "Resolved",
        DiffComplianceViewMode::OldViolations => "Old SBOM",
        DiffComplianceViewMode::NewSbomViolations => "New SBOM",
    };

    let help = Line::from(vec![
        Span::styled("←/→", Style::default().fg(colors().accent)),
        Span::styled(" switch standard  ", Style::default().fg(colors().text_muted)),
        Span::styled("Tab", Style::default().fg(colors().accent)),
        Span::styled(
            format!(" cycle view [{mode_name}]  "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("j/k", Style::default().fg(colors().accent)),
        Span::styled(" navigate  ", Style::default().fg(colors().text_muted)),
        Span::styled("E", Style::default().fg(colors().accent)),
        Span::styled(" export  ", Style::default().fg(colors().text_muted)),
        Span::styled("?", Style::default().fg(colors().accent)),
        Span::styled(" help", Style::default().fg(colors().text_muted)),
    ]);

    let bar = Paragraph::new(help).style(Style::default());
    frame.render_widget(bar, area);
}

/// Compute violations present in new but not in old (by message matching).
fn compute_new_violations(
    old: &ComplianceResult,
    new: &ComplianceResult,
) -> Vec<ViolationEntry> {
    let old_messages: std::collections::HashSet<&str> =
        old.violations.iter().map(|v| v.message.as_str()).collect();

    new.violations
        .iter()
        .filter(|v| !old_messages.contains(v.message.as_str()))
        .map(ViolationEntry::from_violation)
        .collect()
}

/// Compute violations present in old but not in new (resolved).
fn compute_resolved_violations(
    old: &ComplianceResult,
    new: &ComplianceResult,
) -> Vec<ViolationEntry> {
    let new_messages: std::collections::HashSet<&str> =
        new.violations.iter().map(|v| v.message.as_str()).collect();

    old.violations
        .iter()
        .filter(|v| !new_messages.contains(v.message.as_str()))
        .map(ViolationEntry::from_violation)
        .collect()
}

/// Get the actual Violation reference for the currently selected entry in diff mode.
fn get_selected_diff_violation(app: &App) -> Option<&crate::quality::Violation> {
    let idx = app.tabs.diff_compliance.selected_standard;
    let old = app.data.old_compliance_results.as_ref()?.get(idx)?;
    let new = app.data.new_compliance_results.as_ref()?.get(idx)?;
    let selected = app.tabs.diff_compliance.selected_violation;

    match app.tabs.diff_compliance.view_mode {
        DiffComplianceViewMode::Overview => None,
        DiffComplianceViewMode::NewViolations => {
            let old_messages: std::collections::HashSet<&str> =
                old.violations.iter().map(|v| v.message.as_str()).collect();
            new.violations
                .iter()
                .filter(|v| !old_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::ResolvedViolations => {
            let new_messages: std::collections::HashSet<&str> =
                new.violations.iter().map(|v| v.message.as_str()).collect();
            old.violations
                .iter()
                .filter(|v| !new_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::OldViolations => old.violations.get(selected),
        DiffComplianceViewMode::NewSbomViolations => new.violations.get(selected),
    }
}

