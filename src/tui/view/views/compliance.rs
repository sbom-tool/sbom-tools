//! Compliance tab for `ViewApp` - SBOM compliance validation against standards.

use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity};
use crate::tui::shared::compliance as shared_compliance;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Tabs},
};

pub fn render_compliance(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    app.ensure_compliance_results();

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Standard selector tabs
            Constraint::Length(5), // Summary gauge
            Constraint::Min(10),   // Violations list
            Constraint::Length(3), // Help bar
        ])
        .split(area);

    // Adjust scroll before borrowing results (avoids borrow conflict)
    let violations_viewport = chunks[2].height.saturating_sub(4) as usize;
    app.compliance_state.adjust_scroll(violations_viewport);

    // Snapshot scroll state before immutable borrows
    let selected_standard = app.compliance_state.selected_standard;
    let selected_violation = app.compliance_state.selected_violation;
    let scroll_offset = app.compliance_state.scroll_offset;
    let show_detail = app.compliance_state.show_detail;

    // Render standard selector
    render_standard_selector(frame, chunks[0], app);

    // Get compliance result for selected standard
    let Some(results) = app.compliance_results.as_ref() else {
        return;
    };
    let result = &results[selected_standard];

    // Render summary gauge
    render_compliance_summary(frame, chunks[1], result);

    // Render violations with scroll + filter
    let severity_filter = app.compliance_state.severity_filter;
    render_violations(frame, chunks[2], result, selected_violation, scroll_offset, severity_filter);

    // Render help bar
    render_help_bar(frame, chunks[3], severity_filter);

    // Render detail overlay if active
    if show_detail
        && let Some(violation) = app
            .compliance_results.as_ref()
            .and_then(|rs| rs.get(selected_standard))
            .and_then(|r| r.violations.get(selected_violation))
        {
            shared_compliance::render_violation_detail_overlay(frame, area, violation);
        }
}

fn render_standard_selector(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let Some(compliance_results) = app.compliance_results.as_ref() else {
        return;
    };

    let standards: Vec<Line> = ComplianceLevel::all()
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let is_selected = i == app.compliance_state.selected_standard;
            let result = &compliance_results[i];

            // Status indicator
            let status = if result.is_compliant {
                if result.warning_count > 0 {
                    ("⚠", scheme.warning)
                } else {
                    ("✓", scheme.success)
                }
            } else {
                ("✗", scheme.error)
            };

            let style = if is_selected {
                Style::default().fg(scheme.text).bold().bg(scheme.selection)
            } else {
                Style::default().fg(scheme.muted)
            };

            Line::from(vec![
                Span::styled(format!(" {} ", status.0), Style::default().fg(status.1)),
                Span::styled(level.name(), style),
                Span::styled(" ", style),
            ])
        })
        .collect();

    let tabs = Tabs::new(standards)
        .block(
            Block::default()
                .title(" Compliance Standards (←/→ to switch) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .highlight_style(Style::default().fg(scheme.text).bold())
        .select(app.compliance_state.selected_standard);

    frame.render_widget(tabs, area);
}

fn render_compliance_summary(frame: &mut Frame, area: Rect, result: &ComplianceResult) {
    let scheme = colors();

    // Calculate compliance percentage based on errors and warnings only.
    // Info messages are recommendations and should not affect the score.
    let actionable = result.error_count + result.warning_count;
    let compliance_pct = if actionable == 0 {
        100
    } else {
        // Errors weigh 3x, warnings weigh 1x
        let error_weight = result.error_count * 3;
        let warning_weight = result.warning_count;
        let max_weight = actionable * 3; // worst case: all actionable items are errors
        ((max_weight.saturating_sub(error_weight + warning_weight)) * 100 / max_weight) as u16
    };

    let (gauge_color, status_text) = if result.is_compliant {
        if result.warning_count == 0 && result.info_count == 0 {
            (scheme.success, "COMPLIANT - All checks passed")
        } else if result.warning_count == 0 {
            (scheme.success, "COMPLIANT - With recommendations")
        } else {
            (scheme.warning, "COMPLIANT - With warnings")
        }
    } else {
        (scheme.error, "NON-COMPLIANT - Errors must be fixed")
    };

    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Gauge
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" {} ", result.level.name()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(gauge_color)),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(scheme.muted))
        .percent(compliance_pct.min(100))
        .label(status_text);

    frame.render_widget(gauge, h_chunks[0]);

    // Issue counts
    let counts = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Errors: ", Style::default().fg(scheme.muted)),
            Span::styled(
                result.error_count.to_string(),
                if result.error_count > 0 {
                    Style::default().fg(scheme.error).bold()
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled("  Warnings: ", Style::default().fg(scheme.muted)),
            Span::styled(
                result.warning_count.to_string(),
                if result.warning_count > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled("  Info: ", Style::default().fg(scheme.muted)),
            Span::styled(
                result.info_count.to_string(),
                Style::default().fg(scheme.info),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total issues: ", Style::default().fg(scheme.muted)),
            Span::styled(
                result.violations.len().to_string(),
                Style::default().fg(scheme.text),
            ),
        ]),
    ])
    .block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.muted)),
    );

    frame.render_widget(counts, h_chunks[1]);
}

fn render_violations(
    frame: &mut Frame,
    area: Rect,
    result: &ComplianceResult,
    selected_violation: usize,
    scroll_offset: usize,
    severity_filter: SeverityFilter,
) {
    let scheme = colors();

    if result.violations.is_empty() {
        let message = Paragraph::new(vec![
            Line::from(""),
            Line::styled(
                "  ✓ All compliance checks passed!",
                Style::default().fg(scheme.success).bold(),
            ),
            Line::from(""),
            Line::styled(
                format!("  This SBOM meets {} requirements.", result.level.name()),
                Style::default().fg(scheme.text),
            ),
            Line::from(""),
            Line::styled(
                format!("  {}", result.level.description()),
                Style::default().fg(scheme.muted),
            ),
        ])
        .block(
            Block::default()
                .title(" Compliance Status ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        );
        frame.render_widget(message, area);
        return;
    }

    // Apply severity filter
    let filtered: Vec<(usize, &crate::quality::Violation)> = result
        .violations
        .iter()
        .enumerate()
        .filter(|(_, v)| severity_filter.matches(v.severity))
        .collect();

    // Viewport scrolling: compute visible range
    let viewport_height = area.height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(filtered.len());

    // Create table rows from visible filtered violations
    let rows: Vec<Row> = filtered
        .iter()
        .skip(scroll_offset)
        .take(visible_end - scroll_offset)
        .map(|&(i, violation)| {
            let is_selected = i == selected_violation;

            let severity_style = match violation.severity {
                ViolationSeverity::Error => Style::default().fg(scheme.error).bold(),
                ViolationSeverity::Warning => Style::default().fg(scheme.warning),
                ViolationSeverity::Info => Style::default().fg(scheme.info),
            };

            let severity_text = match violation.severity {
                ViolationSeverity::Error => "ERROR",
                ViolationSeverity::Warning => "WARN",
                ViolationSeverity::Info => "INFO",
            };

            let row_style = if is_selected {
                Style::default().bg(scheme.selection)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(severity_text).style(severity_style),
                Cell::from(violation.category.name()),
                Cell::from(violation.message.clone()),
                Cell::from(violation.element.clone().unwrap_or_default())
                    .style(Style::default().fg(scheme.muted)),
            ])
            .style(row_style)
        })
        .collect();

    let header = Row::new(vec!["Severity", "Category", "Issue", "Element"])
        .style(Style::default().fg(scheme.primary).bold())
        .bottom_margin(1);

    let widths = [
        Constraint::Length(8),
        Constraint::Length(20),
        Constraint::Min(30),
        Constraint::Length(20),
    ];

    // Show scroll position in title when scrolled, and filter info
    let filter_label = if severity_filter == SeverityFilter::All {
        String::new()
    } else {
        format!(" [Filter: {}]", severity_filter.label())
    };
    let title = if scroll_offset > 0 || visible_end < filtered.len() {
        format!(
            " Violations ({}/{}) [{}-{}/{}]{} - j/k to navigate ",
            filtered.len(),
            result.violations.len(),
            scroll_offset + 1,
            visible_end,
            filtered.len(),
            filter_label,
        )
    } else {
        format!(
            " Violations ({}){} - j/k to navigate ",
            filtered.len(),
            filter_label,
        )
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if result.is_compliant {
                    scheme.warning
                } else {
                    scheme.error
                })),
        )
        .row_highlight_style(Style::default().bg(scheme.selection));

    frame.render_widget(table, area);
}

fn render_help_bar(frame: &mut Frame, area: Rect, severity_filter: SeverityFilter) {
    let scheme = colors();

    let help = Line::from(vec![
        Span::styled("←/→", Style::default().fg(scheme.primary)),
        Span::styled(" standard  ", Style::default().fg(scheme.muted)),
        Span::styled("j/k", Style::default().fg(scheme.primary)),
        Span::styled(" navigate  ", Style::default().fg(scheme.muted)),
        Span::styled("Enter", Style::default().fg(scheme.primary)),
        Span::styled(" details  ", Style::default().fg(scheme.muted)),
        Span::styled("f", Style::default().fg(scheme.primary)),
        Span::styled(
            format!(" filter [{}]  ", severity_filter.label()),
            Style::default().fg(scheme.muted),
        ),
        Span::styled("E", Style::default().fg(scheme.primary)),
        Span::styled(" export  ", Style::default().fg(scheme.muted)),
        Span::styled("?", Style::default().fg(scheme.primary)),
        Span::styled(" help", Style::default().fg(scheme.muted)),
    ]);

    let paragraph = Paragraph::new(help).block(Block::default().borders(Borders::ALL));

    frame.render_widget(paragraph, area);
}

/// Severity filter for violation display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityFilter {
    /// Show all violations
    #[default]
    All,
    /// Show only errors
    ErrorsOnly,
    /// Show errors and warnings
    WarningsAndAbove,
}

impl SeverityFilter {
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::ErrorsOnly,
            Self::ErrorsOnly => Self::WarningsAndAbove,
            Self::WarningsAndAbove => Self::All,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::ErrorsOnly => "Errors",
            Self::WarningsAndAbove => "Warn+",
        }
    }

    pub const fn matches(self, severity: ViolationSeverity) -> bool {
        match self {
            Self::All => true,
            Self::ErrorsOnly => matches!(severity, ViolationSeverity::Error),
            Self::WarningsAndAbove => matches!(
                severity,
                ViolationSeverity::Error | ViolationSeverity::Warning
            ),
        }
    }
}

/// Compliance view state for multi-standard comparison (view mode)
#[derive(Debug, Clone)]
pub struct StandardComplianceState {
    /// Currently selected compliance standard
    pub selected_standard: usize,
    /// Currently selected violation in the list
    pub selected_violation: usize,
    /// Scroll offset for violations
    pub scroll_offset: usize,
    /// Whether the detail overlay is shown for the selected violation
    pub show_detail: bool,
    /// Severity filter for displayed violations
    pub severity_filter: SeverityFilter,
}

impl Default for StandardComplianceState {
    fn default() -> Self {
        Self {
            selected_standard: 2, // Default to NTIA
            selected_violation: 0,
            scroll_offset: 0,
            show_detail: false,
            severity_filter: SeverityFilter::All,
        }
    }
}

impl StandardComplianceState {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn next_standard(&mut self) {
        let max = ComplianceLevel::all().len();
        self.selected_standard = (self.selected_standard + 1) % max;
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub const fn prev_standard(&mut self) {
        let max = ComplianceLevel::all().len();
        self.selected_standard = if self.selected_standard == 0 {
            max - 1
        } else {
            self.selected_standard - 1
        };
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub fn select_next(&mut self, max_violations: usize) {
        if max_violations > 0 {
            self.selected_violation = (self.selected_violation + 1).min(max_violations - 1);
        }
    }

    pub const fn select_prev(&mut self) {
        self.selected_violation = self.selected_violation.saturating_sub(1);
    }

    /// Adjust `scroll_offset` to keep the selected violation visible within the viewport.
    pub const fn adjust_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        if self.selected_violation < self.scroll_offset {
            self.scroll_offset = self.selected_violation;
        } else if self.selected_violation >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_violation + 1 - viewport_height;
        }
    }
}

/// Compute compliance results for all standards
#[must_use] 
pub fn compute_compliance_results(sbom: &crate::model::NormalizedSbom) -> Vec<ComplianceResult> {
    ComplianceLevel::all()
        .iter()
        .map(|level| {
            let checker = ComplianceChecker::new(*level);
            checker.check(sbom)
        })
        .collect()
}
