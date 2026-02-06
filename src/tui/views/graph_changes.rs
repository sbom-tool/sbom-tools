//! Graph changes view showing structural dependency changes.

use crate::diff::{
    DependencyChangeType, DependencyGraphChange, GraphChangeImpact, GraphChangeSummary,
};
use crate::tui::app::App;
use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState, Wrap,
    },
};

pub(crate) fn render_graph_changes(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some(result) = &app.data.diff_result else {
        render_no_data(frame, area);
        return;
    };

    if result.graph_changes.is_empty() {
        render_no_changes(frame, area);
        return;
    }

    // Clone necessary data to avoid borrow issues
    let changes: Vec<DependencyGraphChange> = result.graph_changes.clone();
    let summary = result.graph_summary.clone();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Summary stats
            Constraint::Length(2), // Context bar
            Constraint::Min(8),    // Changes table
        ])
        .split(area);

    // Summary stats
    if let Some(ref sum) = summary {
        render_summary(frame, chunks[0], sum);
    }

    // Update total
    app.tabs.graph_changes.set_total(changes.len());

    // Context bar with selection info
    render_context_bar(frame, chunks[1], app);

    // Changes table
    render_changes_table(frame, chunks[2], &changes, app);
}

fn render_no_data(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "📊",
        "No graph changes available",
        Some("Graph diff analysis not included in this comparison"),
        Some("Run with --graph-diff flag to enable structural analysis"),
    );
}

fn render_no_changes(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "✓",
        "No structural changes detected",
        Some("The dependency graph structure is identical between both SBOMs"),
        None,
    );
}

fn render_summary(frame: &mut Frame, area: Rect, summary: &GraphChangeSummary) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colors().border))
        .title(" Summary ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build summary lines
    let lines = vec![
        Line::from(vec![
            Span::styled("Total Changes: ", Style::default().fg(colors().text_muted)),
            Span::styled(
                format!("{}", summary.total_changes),
                Style::default().fg(colors().accent).bold(),
            ),
            Span::raw("  │  "),
            Span::styled("+ ", Style::default().fg(colors().added).bold()),
            Span::styled(
                format!("{} added  ", summary.dependencies_added),
                Style::default().fg(colors().text),
            ),
            Span::styled("- ", Style::default().fg(colors().removed).bold()),
            Span::styled(
                format!("{} removed  ", summary.dependencies_removed),
                Style::default().fg(colors().text),
            ),
            Span::styled("↔ ", Style::default().fg(colors().modified).bold()),
            Span::styled(
                format!("{} reparented  ", summary.reparented),
                Style::default().fg(colors().text),
            ),
            Span::styled("↕ ", Style::default().fg(colors().info).bold()),
            Span::styled(
                format!("{} depth changed", summary.depth_changed),
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("By Impact: ", Style::default().fg(colors().text_muted)),
            impact_badge(GraphChangeImpact::Critical, summary.by_impact.critical),
            Span::raw("  "),
            impact_badge(GraphChangeImpact::High, summary.by_impact.high),
            Span::raw("  "),
            impact_badge(GraphChangeImpact::Medium, summary.by_impact.medium),
            Span::raw("  "),
            impact_badge(GraphChangeImpact::Low, summary.by_impact.low),
        ]),
    ];

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

fn impact_badge(impact: GraphChangeImpact, count: usize) -> Span<'static> {
    if count == 0 {
        return Span::styled(
            format!("{}: {}", impact.as_str().to_uppercase(), count),
            Style::default().fg(colors().text_muted),
        );
    }

    let scheme = colors();
    let (fg, bg) = match impact {
        GraphChangeImpact::Critical => (scheme.badge_fg_light, scheme.critical),
        GraphChangeImpact::High => (scheme.badge_fg_light, scheme.high),
        GraphChangeImpact::Medium => (scheme.badge_fg_dark, scheme.medium),
        GraphChangeImpact::Low => (scheme.badge_fg_dark, scheme.low),
    };

    Span::styled(
        format!(" {} {} ", impact.as_str().to_uppercase(), count),
        Style::default().fg(fg).bg(bg).bold(),
    )
}

fn render_context_bar(frame: &mut Frame, area: Rect, app: &App) {
    let selected = app.tabs.graph_changes.selected;
    let total = app.tabs.graph_changes.total;

    let context_line = Line::from(vec![
        Span::styled("Row ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{}/{}", if total > 0 { selected + 1 } else { 0 }, total),
            Style::default().fg(colors().accent).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(colors().border)),
        Span::styled("[↑↓/jk]", Style::default().fg(colors().accent)),
        Span::styled(" select ", Style::default().fg(colors().text_muted)),
        Span::styled("[PgUp/Dn]", Style::default().fg(colors().accent)),
        Span::styled(" page ", Style::default().fg(colors().text_muted)),
        Span::styled("[Home/End]", Style::default().fg(colors().accent)),
        Span::styled(" first/last ", Style::default().fg(colors().text_muted)),
        Span::styled("[G]", Style::default().fg(colors().accent)),
        Span::styled(" go to end", Style::default().fg(colors().text_muted)),
    ]);

    let paragraph = Paragraph::new(context_line).style(Style::default().fg(colors().text));

    frame.render_widget(paragraph, area);
}

fn render_changes_table(
    frame: &mut Frame,
    area: Rect,
    changes: &[DependencyGraphChange],
    app: &mut App,
) {
    // Split for scrollbar
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    let table_area = chunks[0];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colors().border))
        .title(" Changes ")
        .title_style(Style::default().fg(colors().accent).bold());

    let inner = block.inner(table_area);
    frame.render_widget(block, table_area);

    // Header
    let header = Row::new(vec![
        Cell::from("Impact").style(Style::default().fg(colors().text_muted).bold()),
        Cell::from("Type").style(Style::default().fg(colors().text_muted).bold()),
        Cell::from("Component").style(Style::default().fg(colors().text_muted).bold()),
        Cell::from("Details").style(Style::default().fg(colors().text_muted).bold()),
    ])
    .height(1);

    // Build rows
    let rows: Vec<Row> = changes
        .iter()
        .map(|change| {
            let impact_cell = impact_cell(change.impact);
            let type_cell = change_type_cell(&change.change);
            let component_cell = Cell::from(truncate(&change.component_name, 30))
                .style(Style::default().fg(colors().text));
            let details_cell = details_cell(&change.change);

            Row::new(vec![impact_cell, type_cell, component_cell, details_cell])
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(30),
        Constraint::Min(30),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().bg(colors().selection));

    // Create table state with selection
    let mut table_state = TableState::default();
    if !changes.is_empty() {
        table_state.select(Some(app.tabs.graph_changes.selected));
    }

    frame.render_stateful_widget(table, inner, &mut table_state);

    // Scrollbar
    let mut scrollbar_state = ScrollbarState::default()
        .content_length(changes.len())
        .position(app.tabs.graph_changes.selected);

    frame.render_stateful_widget(
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(colors().accent))
            .track_style(Style::default().fg(colors().border)),
        chunks[1],
        &mut scrollbar_state,
    );
}

fn impact_cell(impact: GraphChangeImpact) -> Cell<'static> {
    let scheme = colors();
    let (text, style) = match impact {
        GraphChangeImpact::Critical => ("CRITICAL", Style::default().fg(scheme.critical).bold()),
        GraphChangeImpact::High => ("HIGH", Style::default().fg(scheme.high).bold()),
        GraphChangeImpact::Medium => ("MEDIUM", Style::default().fg(scheme.medium)),
        GraphChangeImpact::Low => ("LOW", Style::default().fg(scheme.low)),
    };
    Cell::from(text).style(style)
}

fn change_type_cell(change: &DependencyChangeType) -> Cell<'static> {
    let (text, style) = match change {
        DependencyChangeType::DependencyAdded { .. } => {
            ("+ Added", Style::default().fg(colors().added))
        }
        DependencyChangeType::DependencyRemoved { .. } => {
            ("- Removed", Style::default().fg(colors().removed))
        }
        DependencyChangeType::Reparented { .. } => {
            ("↔ Reparent", Style::default().fg(colors().modified))
        }
        DependencyChangeType::DepthChanged { .. } => {
            ("↕ Depth", Style::default().fg(colors().info))
        }
    };
    Cell::from(text).style(style)
}

fn details_cell(change: &DependencyChangeType) -> Cell<'static> {
    let text = match change {
        DependencyChangeType::DependencyAdded {
            dependency_name, ..
        } => {
            format!("Added dependency: {}", truncate(dependency_name, 40))
        }
        DependencyChangeType::DependencyRemoved {
            dependency_name, ..
        } => {
            format!("Removed dependency: {}", truncate(dependency_name, 40))
        }
        DependencyChangeType::Reparented {
            old_parent_name,
            new_parent_name,
            ..
        } => {
            format!(
                "{} → {}",
                truncate(old_parent_name, 20),
                truncate(new_parent_name, 20)
            )
        }
        DependencyChangeType::DepthChanged {
            old_depth,
            new_depth,
        } => {
            let direction = if *new_depth < *old_depth {
                "↑ promoted"
            } else {
                "↓ demoted"
            };
            format!("Depth {old_depth} → {new_depth} ({direction})")
        }
    };
    Cell::from(text).style(Style::default().fg(colors().text))
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", s.chars().take(max_len - 3).collect::<String>())
    } else {
        s.chars().take(max_len).collect()
    }
}
