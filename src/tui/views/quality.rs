//! Quality score view for the TUI with enhanced explainability.
//!
//! Diff-specific rendering lives here; shared rendering functions are
//! delegated to `crate::tui::shared::quality`.

use crate::quality::QualityReport;
use crate::tui::app::{App, AppMode, QualityViewMode};
use crate::tui::shared::quality as shared;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
};

pub fn render_quality(frame: &mut Frame, area: Rect, app: &App) {
    match app.mode {
        AppMode::Diff => render_diff_quality(frame, area, app),
        AppMode::View => render_view_quality(frame, area, app),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_quality(frame: &mut Frame, area: Rect, app: &App) {
    let old_report = app.data.old_quality.as_ref();
    let new_report = app.data.new_quality.as_ref();

    if old_report.is_none() && new_report.is_none() {
        render_no_quality_data(frame, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(14),
            Constraint::Min(8),
        ])
        .split(area);

    render_score_comparison(frame, chunks[0], old_report, new_report);
    render_metrics_comparison(frame, chunks[1], old_report, new_report);
    render_combined_recommendations(frame, chunks[2], old_report, new_report, app);
}

fn render_view_quality(frame: &mut Frame, area: Rect, app: &App) {
    let Some(report) = &app.data.quality_report else {
        render_no_quality_data(frame, area);
        return;
    };

    match app.tabs.quality.view_mode {
        QualityViewMode::Summary => shared::render_quality_summary(frame, area, report, 0),
        QualityViewMode::Breakdown => shared::render_score_breakdown(frame, area, report),
        QualityViewMode::Metrics => shared::render_quality_metrics(frame, area, report),
        QualityViewMode::Recommendations => shared::render_quality_recommendations(
            frame,
            area,
            report,
            app.tabs.quality.selected_recommendation,
            app.tabs.quality.scroll_offset,
        ),
    }
}

fn render_no_quality_data(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "📊",
        "Quality analysis unavailable",
        Some("Quality scoring requires a valid SBOM to analyze"),
        Some("Ensure the SBOM was successfully parsed"),
    );
}

// ---------------------------------------------------------------------------
// Diff-specific rendering
// ---------------------------------------------------------------------------

fn render_score_comparison(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(report) = old_report {
        shared::render_score_gauge(frame, chunks[0], report, "Old SBOM Quality");
    } else {
        render_empty_gauge(frame, chunks[0], "Old SBOM Quality");
    }

    if let Some(report) = new_report {
        shared::render_score_gauge(frame, chunks[1], report, "New SBOM Quality");
    } else {
        render_empty_gauge(frame, chunks[1], "New SBOM Quality");
    }
}

fn render_empty_gauge(frame: &mut Frame, area: Rect, title: &str) {
    let scheme = colors();
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" {title} "))
                .title_style(Style::default().fg(scheme.muted))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.muted)),
        )
        .gauge_style(Style::default().fg(scheme.muted))
        .percent(0)
        .label("N/A");
    frame.render_widget(gauge, area);
}

fn render_metrics_comparison(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(report) = old_report {
        render_metrics_panel_with_explanation(frame, chunks[0], report, "Old");
    } else {
        render_empty_metrics(frame, chunks[0], "Old");
    }

    if let Some(report) = new_report {
        render_metrics_panel_with_explanation(frame, chunks[1], report, "New");
    } else {
        render_empty_metrics(frame, chunks[1], "New");
    }
}

fn render_metrics_panel_with_explanation(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    label: &str,
) {
    let scheme = colors();
    let weights = shared::get_profile_weights(report.profile);

    let rows = vec![
        ratatui::widgets::Row::new(vec![
            "Completeness".to_string(),
            format!("{:.0}%", report.completeness_score),
            format!("×{:.0}%", weights.0 * 100.0),
            shared::explain_completeness_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Identifiers".to_string(),
            format!("{:.0}%", report.identifier_score),
            format!("×{:.0}%", weights.1 * 100.0),
            shared::explain_identifier_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Licenses".to_string(),
            format!("{:.0}%", report.license_score),
            format!("×{:.0}%", weights.2 * 100.0),
            shared::explain_license_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Vulnerabilities".to_string(),
            match report.vulnerability_score {
                Some(score) => format!("{score:.0}%"),
                None => "N/A".to_string(),
            },
            format!(
                "×{:.0}%",
                if report.vulnerability_score.is_some() {
                    weights.3 * 100.0
                } else {
                    0.0
                }
            ),
            shared::explain_vulnerability_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Dependencies".to_string(),
            format!("{:.0}%", report.dependency_score),
            format!("×{:.0}%", weights.4 * 100.0),
            shared::explain_dependency_score(report),
        ]),
    ];

    let widths = [
        Constraint::Length(14),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Min(15),
    ];

    let table = ratatui::widgets::Table::new(rows, widths)
        .block(
            Block::default()
                .title(format!(" {label} - Score Factors "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.info)),
        )
        .header(
            ratatui::widgets::Row::new(vec!["Category", "Score", "Weight", "Reason"])
                .style(Style::default().fg(scheme.primary).bold())
                .bottom_margin(1),
        );
    frame.render_widget(table, area);
}

fn render_empty_metrics(frame: &mut Frame, area: Rect, label: &str) {
    crate::tui::widgets::render_empty_state_enhanced(
        frame,
        area,
        "📊",
        &format!("No {} metrics available", label.to_lowercase()),
        Some("Quality analysis could not be performed for this SBOM"),
        Some("SBOM may lack the required metadata for scoring"),
    );
}

fn render_combined_recommendations(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
    app: &App,
) {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];

    if let (Some(old), Some(new)) = (old_report, new_report) {
        let score_diff = new.overall_score as i32 - old.overall_score as i32;
        let (icon, color, text) = if score_diff > 5 {
            (
                "↑",
                scheme.added,
                format!("Quality improved by {score_diff} points"),
            )
        } else if score_diff < -5 {
            (
                "↓",
                scheme.removed,
                format!("Quality decreased by {} points", score_diff.abs()),
            )
        } else {
            ("→", scheme.warning, "Quality score unchanged".to_string())
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {icon} "), Style::default().fg(color).bold()),
            Span::styled(text, Style::default().fg(color)),
        ]));

        // Add specific change reasons
        lines.push(Line::from(""));
        add_change_reasons(&mut lines, old, new);
    }

    if let Some(report) = new_report {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            " Top Actions to Improve Score:",
            Style::default().fg(scheme.primary).bold(),
        ));

        for (i, rec) in report.recommendations.iter().take(4).enumerate() {
            let is_selected = i == app.tabs.quality.selected_recommendation;
            let prefix = if is_selected { "▶ " } else { "  " };
            let style = if is_selected {
                Style::default().fg(scheme.text).bold()
            } else {
                Style::default().fg(scheme.text)
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(scheme.primary)),
                Span::styled(
                    format!("[P{}] ", rec.priority),
                    shared::priority_style(rec.priority),
                ),
                Span::styled(&rec.message, style),
                Span::styled(
                    format!(" (+{:.0}pts)", rec.impact),
                    Style::default().fg(scheme.success),
                ),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Quality Analysis ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.error)),
        )
        .scroll((app.tabs.quality.scroll_offset as u16, 0));
    frame.render_widget(paragraph, area);
}

fn add_change_reasons(lines: &mut Vec<Line>, old: &QualityReport, new: &QualityReport) {
    let scheme = colors();
    let changes = vec![
        (
            "Completeness",
            old.completeness_score,
            new.completeness_score,
        ),
        ("Identifiers", old.identifier_score, new.identifier_score),
        ("Licenses", old.license_score, new.license_score),
        ("Dependencies", old.dependency_score, new.dependency_score),
    ];

    for (name, old_score, new_score) in changes {
        let diff = new_score - old_score;
        if diff.abs() > 5.0 {
            let (icon, color) = if diff > 0.0 {
                ("↑", scheme.added)
            } else {
                ("↓", scheme.removed)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("   {icon} "), Style::default().fg(color)),
                Span::styled(format!("{name}: "), Style::default().fg(scheme.text)),
                Span::styled(
                    format!("{old_score:.0}% → {new_score:.0}%"),
                    Style::default().fg(color),
                ),
            ]));
        }
    }
}
