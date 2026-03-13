//! Graph changes view showing structural dependency changes.

use crate::diff::{
    DependencyChangeType, DependencyGraphChange, GraphChangeImpact, GraphChangeSummary,
};
use crate::tui::app_states::GraphChangesState;
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

pub fn render_graph_changes(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result else {
        render_no_data(frame, area);
        return;
    };

    if result.graph_changes.is_empty() {
        render_no_changes(frame, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Summary stats
            Constraint::Length(2), // Context bar
            Constraint::Min(8),    // Changes table + detail
        ])
        .split(area);

    // Summary stats
    if let Some(ref sum) = result.graph_summary {
        render_summary(frame, chunks[0], sum);
    }

    // Context bar with selection info
    render_context_bar(frame, chunks[1], ctx.graph_changes);

    // Master-detail layout for changes table + detail panel
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(widgets::MASTER_DETAIL_SPLIT)
        .split(chunks[2]);

    // Changes table (master)
    render_changes_table(
        frame,
        content_chunks[0],
        &result.graph_changes,
        ctx.graph_changes,
    );

    // Detail panel
    render_change_detail(
        frame,
        content_chunks[1],
        &result.graph_changes,
        ctx.graph_changes,
    );
}

fn render_no_data(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "\u{1f4ca}",
        "No graph changes available",
        Some("Graph diff analysis not included in this comparison"),
        Some("Run with --graph-diff flag to enable structural analysis"),
    );
}

fn render_no_changes(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "\u{2713}",
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
            Span::raw("  \u{2502}  "),
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
            Span::styled("~ ", Style::default().fg(colors().modified).bold()),
            Span::styled(
                format!("{} rel changed  ", summary.relationship_changed),
                Style::default().fg(colors().text),
            ),
            Span::styled("\u{2194} ", Style::default().fg(colors().modified).bold()),
            Span::styled(
                format!("{} reparented  ", summary.reparented),
                Style::default().fg(colors().text),
            ),
            Span::styled("\u{2195} ", Style::default().fg(colors().info).bold()),
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

fn render_context_bar(frame: &mut Frame, area: Rect, state: &GraphChangesState) {
    let selected = state.selected;
    let total = state.total;

    let context_line = Line::from(vec![
        Span::styled("Row ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{}/{}", if total > 0 { selected + 1 } else { 0 }, total),
            Style::default().fg(colors().accent).bold(),
        ),
        Span::styled(" \u{2502} ", Style::default().fg(colors().border)),
        Span::styled(
            "[\u{2191}\u{2193}/jk]",
            Style::default().fg(colors().accent),
        ),
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
    state: &GraphChangesState,
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
        table_state.select(Some(state.selected));
    }

    frame.render_stateful_widget(table, inner, &mut table_state);

    // Scrollbar
    widgets::render_scrollbar(frame, chunks[1], changes.len(), state.selected);
}

fn render_change_detail(
    frame: &mut Frame,
    area: Rect,
    changes: &[DependencyGraphChange],
    state: &GraphChangesState,
) {
    let scheme = colors();

    let Some(change) = changes.get(state.selected) else {
        crate::tui::shared::components::render_empty_detail_panel(
            frame,
            area,
            " Change Details ",
            "🔀",
            "Select a change to view details",
            &[("[↑↓]", " navigate")],
            false,
        );
        return;
    };

    let mut lines = vec![];

    // Change type badge
    let (type_label, type_color) = match &change.change {
        DependencyChangeType::DependencyAdded { .. } => ("+ ADDED", scheme.added),
        DependencyChangeType::DependencyRemoved { .. } => ("- REMOVED", scheme.removed),
        DependencyChangeType::RelationshipChanged { .. } => ("~ RELATION", scheme.modified),
        DependencyChangeType::Reparented { .. } => ("↔ REPARENT", scheme.modified),
        DependencyChangeType::DepthChanged { .. } => ("↕ DEPTH", scheme.info),
    };
    lines.push(Line::from(vec![Span::styled(
        format!(" {type_label} "),
        Style::default()
            .fg(scheme.badge_fg_dark)
            .bg(type_color)
            .bold(),
    )]));
    lines.push(Line::from(""));

    // Impact level
    let (impact_label, impact_color) = match change.impact {
        GraphChangeImpact::Critical => ("Critical", scheme.critical),
        GraphChangeImpact::High => ("High", scheme.high),
        GraphChangeImpact::Medium => ("Medium", scheme.medium),
        GraphChangeImpact::Low => ("Low", scheme.low),
    };
    lines.push(Line::from(vec![
        Span::styled("Impact: ", Style::default().fg(scheme.text_muted)),
        Span::styled(impact_label, Style::default().fg(impact_color).bold()),
    ]));
    lines.push(Line::from(""));

    // Component name
    lines.push(Line::from(vec![
        Span::styled("Component: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            &change.component_name,
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    // Change-specific details
    lines.push(Line::from(""));
    match &change.change {
        DependencyChangeType::DependencyAdded {
            dependency_name, ..
        } => {
            lines.push(Line::from(vec![
                Span::styled("Dependency: ", Style::default().fg(scheme.text_muted)),
                Span::styled(dependency_name, Style::default().fg(scheme.added)),
            ]));
        }
        DependencyChangeType::DependencyRemoved {
            dependency_name, ..
        } => {
            lines.push(Line::from(vec![
                Span::styled("Dependency: ", Style::default().fg(scheme.text_muted)),
                Span::styled(dependency_name, Style::default().fg(scheme.removed)),
            ]));
        }
        DependencyChangeType::RelationshipChanged {
            dependency_name,
            old_relationship,
            new_relationship,
            ..
        } => {
            lines.push(Line::from(vec![
                Span::styled("Dependency: ", Style::default().fg(scheme.text_muted)),
                Span::styled(dependency_name, Style::default().fg(scheme.text)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Old: ", Style::default().fg(scheme.text_muted)),
                Span::styled(old_relationship, Style::default().fg(scheme.removed)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("New: ", Style::default().fg(scheme.text_muted)),
                Span::styled(new_relationship, Style::default().fg(scheme.added)),
            ]));
        }
        DependencyChangeType::Reparented {
            old_parent_name,
            new_parent_name,
            ..
        } => {
            lines.push(Line::from(vec![
                Span::styled("Old parent: ", Style::default().fg(scheme.text_muted)),
                Span::styled(old_parent_name, Style::default().fg(scheme.removed)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("New parent: ", Style::default().fg(scheme.text_muted)),
                Span::styled(new_parent_name, Style::default().fg(scheme.added)),
            ]));
        }
        DependencyChangeType::DepthChanged {
            old_depth,
            new_depth,
        } => {
            let fmt = |d: u32| -> String {
                if d == u32::MAX {
                    "unreachable".to_string()
                } else {
                    d.to_string()
                }
            };
            lines.push(Line::from(vec![
                Span::styled("Old depth: ", Style::default().fg(scheme.text_muted)),
                Span::styled(fmt(*old_depth), Style::default().fg(scheme.removed)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("New depth: ", Style::default().fg(scheme.text_muted)),
                Span::styled(fmt(*new_depth), Style::default().fg(scheme.added)),
            ]));
            let direction = if *new_depth == u32::MAX {
                "Component became unreachable"
            } else if *old_depth == u32::MAX {
                "Component became reachable"
            } else if *new_depth < *old_depth {
                "Promoted (closer to root)"
            } else {
                "Demoted (further from root)"
            };
            lines.push(Line::from(vec![Span::styled(
                direction,
                Style::default().fg(scheme.text).italic(),
            )]));
        }
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Change Details ")
                .title_style(Style::default().fg(scheme.border_focused).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(detail, area);
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
        DependencyChangeType::RelationshipChanged { .. } => {
            ("~ Relation", Style::default().fg(colors().modified))
        }
        DependencyChangeType::Reparented { .. } => {
            ("\u{2194} Reparent", Style::default().fg(colors().modified))
        }
        DependencyChangeType::DepthChanged { .. } => {
            ("\u{2195} Depth", Style::default().fg(colors().info))
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
        DependencyChangeType::RelationshipChanged {
            dependency_name,
            old_relationship,
            new_relationship,
            ..
        } => {
            format!(
                "{}: {} \u{2192} {}",
                truncate(dependency_name, 20),
                truncate(old_relationship, 15),
                truncate(new_relationship, 15)
            )
        }
        DependencyChangeType::Reparented {
            old_parent_name,
            new_parent_name,
            ..
        } => {
            format!(
                "{} \u{2192} {}",
                truncate(old_parent_name, 20),
                truncate(new_parent_name, 20)
            )
        }
        DependencyChangeType::DepthChanged {
            old_depth,
            new_depth,
        } => {
            let fmt_depth = |d: u32| -> String {
                if d == u32::MAX {
                    "unreachable".to_string()
                } else {
                    d.to_string()
                }
            };
            let direction = if *new_depth == u32::MAX {
                "\u{2192} unreachable"
            } else if *old_depth == u32::MAX {
                "\u{2190} became reachable"
            } else if *new_depth < *old_depth {
                "\u{2191} promoted"
            } else {
                "\u{2193} demoted"
            };
            format!(
                "Depth {} \u{2192} {} ({direction})",
                fmt_depth(*old_depth),
                fmt_depth(*new_depth)
            )
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
