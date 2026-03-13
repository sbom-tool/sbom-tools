//! Components view with master-detail layout.

use crate::diff::ComponentChange;
use crate::tui::app::{AppMode, ComponentFilter};
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

/// Pre-built component list to avoid rebuilding on each render call.
/// Built once per frame in `render_components` and passed to sub-functions.
pub enum ComponentListData<'a> {
    Diff(Vec<&'a ComponentChange>),
    Empty,
}

pub fn render_components(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(widgets::FILTER_BAR_HEIGHT),
            Constraint::Min(10),
        ])
        .split(area);

    // Render filter bar with badges
    render_filter_bar(frame, chunks[0], ctx);

    // Totals and clamp_selection are done in prepare_render().
    // Compute total_unfiltered for empty-state display only.
    let total_unfiltered = match ctx.mode {
        AppMode::Diff => ctx.diff_result.map_or(0, |r| r.components.total()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
    };

    // Build the list data once for rendering
    let component_data = match ctx.mode {
        AppMode::Diff => ComponentListData::Diff(ctx.diff_component_items()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => ComponentListData::Empty,
    };

    // Master-detail layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(widgets::MASTER_DETAIL_SPLIT)
        .split(chunks[1]);

    // Render component table (master)
    render_component_table(
        frame,
        content_chunks[0],
        ctx,
        &component_data,
        total_unfiltered,
    );
    // Render detail panel
    render_detail_panel(frame, content_chunks[1], ctx, &component_data);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    use crate::tui::viewmodel::security_filter::QuickFilter;

    let filter = ctx.components.filter;
    let sort = &ctx.components.sort_by;
    let multi_select = ctx.components.multi_select_mode;
    let selection_count = ctx.components.selection_count();

    let mut filter_spans = vec![
        Span::styled("Filter: ", Style::default().fg(colors().text_muted)),
        status_badge(filter.label(), filter_color(filter)),
        Span::raw("  "),
        Span::styled("Sort: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{sort:?}"),
            Style::default().fg(colors().accent).bold(),
        ),
    ];

    // Show multi-selection mode indicator
    if multi_select {
        filter_spans.push(Span::raw("  "));
        filter_spans.push(Span::styled(
            format!(" ✓ SELECT: {selection_count} "),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(colors().secondary)
                .bold(),
        ));
    }

    // Show quick filter chips
    let security_filter = &ctx.components.security_filter;
    if security_filter.has_active_filters() {
        filter_spans.push(Span::raw("  "));
        filter_spans.push(Span::styled("│", Style::default().fg(colors().border)));
        filter_spans.push(Span::raw(" "));

        for quick_filter in QuickFilter::all() {
            if quick_filter.is_active(&security_filter.criteria) {
                let label = quick_filter.label();
                filter_spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(colors().accent)
                        .bold(),
                ));
                filter_spans.push(Span::raw(" "));
            }
        }
    }

    filter_spans.extend(vec![
        Span::raw("  │  "),
        Span::styled("[f]", Style::default().fg(colors().accent)),
        Span::styled(" filter  ", Style::default().fg(colors().text_muted)),
        Span::styled("[s]", Style::default().fg(colors().accent)),
        Span::styled(" sort  ", Style::default().fg(colors().text_muted)),
        Span::styled("[", Style::default().fg(colors().accent)),
    ]);
    for (i, qf) in QuickFilter::all().iter().enumerate() {
        if i > 0 {
            filter_spans.push(Span::styled("/", Style::default().fg(colors().border)));
        }
        filter_spans.push(Span::styled(
            qf.shortcut().to_string(),
            Style::default().fg(colors().accent),
        ));
    }
    filter_spans.extend(vec![
        Span::styled("]", Style::default().fg(colors().accent)),
        Span::styled(" quick  ", Style::default().fg(colors().text_muted)),
        Span::styled("[v]", Style::default().fg(colors().accent)),
        Span::styled(
            if multi_select {
                " exit select"
            } else {
                " multi-select"
            },
            Style::default().fg(colors().text_muted),
        ),
    ]);

    let paragraph = Paragraph::new(Line::from(filter_spans))
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors().border)),
        )
        .style(Style::default());

    frame.render_widget(paragraph, area);
}

fn filter_color(filter: ComponentFilter) -> Color {
    match filter {
        ComponentFilter::All => colors().primary,
        ComponentFilter::Added => colors().added,
        ComponentFilter::Removed => colors().removed,
        ComponentFilter::Modified => colors().modified,
        ComponentFilter::EolOnly => colors().critical,
        ComponentFilter::EolRisk => colors().high,
    }
}

fn status_badge(text: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {text} "),
        Style::default().fg(colors().badge_fg_dark).bg(color).bold(),
    )
}

fn render_component_table(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    component_data: &ComponentListData,
    total_unfiltered: usize,
) {
    let is_diff = matches!(component_data, ComponentListData::Diff(_));
    let header_cells: Vec<Cell> = if is_diff {
        [
            "",
            "Name",
            "Old Version",
            "New Version",
            "Ecosystem",
            "Changes",
        ]
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().fg(colors().accent).bold()))
        .collect()
    } else {
        ["", "Name", "Version", "", "Ecosystem", "Staleness", "EOL"]
            .into_iter()
            .map(|h| Cell::from(h).style(Style::default().fg(colors().accent).bold()))
            .collect()
    };
    let header = Row::new(header_cells).height(1);

    // Use pre-built component list (state already updated in prepare_render)
    let rows: Vec<Row> = match component_data {
        ComponentListData::Diff(components) => get_diff_rows(ctx, components),
        ComponentListData::Empty => vec![],
    };

    // Check for empty states
    if rows.is_empty() {
        if total_unfiltered == 0 {
            // No components at all
            widgets::render_empty_state_enhanced(
                frame,
                area,
                "📦",
                "No components found",
                Some("The SBOM contains no component entries"),
                None,
            );
        } else {
            // Filter is hiding everything
            widgets::render_no_results_state(frame, area, "Filter", ctx.components.filter.label());
        }
        return;
    }

    let widths: Vec<Constraint> = if is_diff {
        vec![
            Constraint::Length(12),
            Constraint::Min(16),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(7),
        ]
    } else {
        vec![
            Constraint::Length(12),
            Constraint::Min(14),
            Constraint::Length(10),
            Constraint::Length(0),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(12),
        ]
    };

    let selected_idx = ctx.components.selected;
    let scheme = colors();
    let table_focused = !ctx.components.focus_detail;
    let table_border_color = if table_focused {
        scheme.border_focused
    } else {
        scheme.border
    };
    let table_title_style = if table_focused {
        Style::default().fg(scheme.border_focused).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let table = Table::new(rows.clone(), widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Components ({}) ", rows.len()))
                .title_style(table_title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(table_border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(colors().selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = TableState::default()
        .with_offset(ctx.components.scroll_offset)
        .with_selected(Some(selected_idx));

    frame.render_stateful_widget(table, area, &mut state);

    // Render scrollbar
    let scroll_offset = state.offset();
    if rows.len() > area.height.saturating_sub(3) as usize {
        widgets::render_scrollbar(
            frame,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            rows.len(),
            scroll_offset,
        );
    }
}

fn render_detail_panel(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    component_data: &ComponentListData,
) {
    match component_data {
        ComponentListData::Diff(components) => render_diff_detail(frame, area, ctx, components),
        ComponentListData::Empty => {}
    }
}

fn render_diff_detail(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    components: &[&ComponentChange],
) {
    let selected = ctx.components.selected;

    if let Some(comp) = components.get(selected) {
        let change_type = &comp.change_type;
        let (status_text, status_color, status_symbol) = match change_type {
            crate::diff::ChangeType::Added => ("ADDED", colors().added, "+"),
            crate::diff::ChangeType::Removed => ("REMOVED", colors().removed, "-"),
            crate::diff::ChangeType::Modified => ("MODIFIED", colors().modified, "~"),
            crate::diff::ChangeType::Unchanged => ("UNCHANGED", colors().muted, "="),
        };

        let mut lines = vec![
            // Status badge with symbol for accessibility
            Line::from(vec![
                Span::styled(
                    format!(" {status_symbol} {status_text} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(status_color)
                        .bold(),
                ),
                Span::styled(
                    format!("  Change Weight: {}", comp.cost),
                    Style::default().fg(colors().text_muted),
                ),
            ]),
            Line::from(""),
            // Component name
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(colors().text_muted)),
                Span::styled(&comp.name, Style::default().fg(colors().text).bold()),
            ]),
            // ID (canonical)
            Line::from(vec![
                Span::styled("ID: ", Style::default().fg(colors().text_muted)),
                Span::styled(&comp.id, Style::default().fg(colors().text)),
            ]),
        ];

        // Version info with visual diff
        match (&comp.old_version, &comp.new_version) {
            (Some(old), Some(new)) if old != new => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(old, Style::default().fg(colors().removed)),
                    Span::styled(" → ", Style::default().fg(colors().text_muted)),
                    Span::styled(new, Style::default().fg(colors().added)),
                ]));
            }
            (Some(old), None) => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(old, Style::default().fg(colors().removed)),
                    Span::styled(" (removed)", Style::default().fg(colors().text_muted)),
                ]));
            }
            (None, Some(new)) => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(new, Style::default().fg(colors().added)),
                    Span::styled(" (new)", Style::default().fg(colors().text_muted)),
                ]));
            }
            (Some(ver), Some(_)) => {
                // Same version in both
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(ver, Style::default().fg(colors().text)),
                ]));
            }
            _ => {}
        }

        // Downgrade attack detection
        if let (Some(old_ver), Some(new_ver)) = (&comp.old_version, &comp.new_version) {
            use crate::tui::security::{
                VersionChange, analyze_downgrade, detect_version_downgrade,
            };
            let version_change = detect_version_downgrade(old_ver, new_ver);
            if version_change == VersionChange::Downgrade {
                let downgrade_severity = analyze_downgrade(old_ver, new_ver);
                let (warning_text, warning_color) = match downgrade_severity {
                    Some(crate::tui::security::DowngradeSeverity::Major) => (
                        "⚠ MAJOR DOWNGRADE - Supply chain attack risk!",
                        colors().critical,
                    ),
                    Some(crate::tui::security::DowngradeSeverity::Suspicious) => (
                        "⚠ SUSPICIOUS - Security patch may be removed!",
                        colors().critical,
                    ),
                    Some(crate::tui::security::DowngradeSeverity::Minor) => {
                        ("⚠ Version Downgrade Detected", colors().warning)
                    }
                    None => ("⚠ Downgrade", colors().warning),
                };
                lines.push(Line::from(vec![Span::styled(
                    format!(" {warning_text} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(warning_color)
                        .bold(),
                )]));
            }
        }

        // Ecosystem
        if let Some(eco) = &comp.ecosystem {
            lines.push(Line::from(vec![
                Span::styled("Ecosystem: ", Style::default().fg(colors().text_muted)),
                Span::styled(eco, Style::default().fg(colors().secondary)),
            ]));
        }

        // Field changes for modified components (skip version-only changes since
        // the version diff is already shown above)
        let non_version_changes: Vec<_> = comp
            .field_changes
            .iter()
            .filter(|c| c.field != "version")
            .collect();
        if !non_version_changes.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled("Changes", Style::default().fg(colors().modified).bold()),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));

            for change in &non_version_changes {
                let old_val = change.old_value.as_deref().unwrap_or("(none)");
                let new_val = change.new_value.as_deref().unwrap_or("(none)");
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(colors().text_muted)),
                    Span::styled(&change.field, Style::default().fg(colors().accent)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("    - ", Style::default().fg(colors().removed)),
                    Span::styled(
                        widgets::truncate_str(old_val, area.width as usize - 8),
                        Style::default().fg(colors().removed),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("    + ", Style::default().fg(colors().added)),
                    Span::styled(
                        widgets::truncate_str(new_val, area.width as usize - 8),
                        Style::default().fg(colors().added),
                    ),
                ]));
            }
        }

        // Related vulnerabilities - look up by ID, not by name
        let related_vulns: Vec<_> = ctx
            .diff_result
            .map(|r| {
                r.vulnerabilities
                    .introduced
                    .iter()
                    .filter(|v| v.component_id == comp.id) // ID-based lookup
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !related_vulns.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled(
                    format!("⚠ Vulnerabilities ({})", related_vulns.len()),
                    Style::default().fg(colors().high).bold(),
                ),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));

            let vuln_entries: Vec<(&str, &str, Option<&str>)> = related_vulns
                .iter()
                .map(|v| (v.severity.as_str(), v.id.as_str(), v.description.as_deref()))
                .collect();
            lines.extend(
                crate::tui::shared::components::render_vulnerability_list_lines(
                    &vuln_entries,
                    5,
                    related_vulns.len(),
                    area.width,
                ),
            );
        }

        // Security Analysis section (Diff mode)
        let reverse_graph = &ctx.dependencies.cached_reverse_graph;
        let (direct_deps, transitive_count) =
            crate::tui::shared::components::compute_blast_radius(&comp.name, reverse_graph);
        let license_text = ctx
            .new_sbom
            .and_then(|sbom| {
                let canonical_id = crate::model::CanonicalId::from_format_id(&comp.id);
                sbom.components.get(&canonical_id)
            })
            .and_then(|c| c.licenses.declared.first())
            .map_or("Unknown", |l| l.expression.as_str());
        lines.extend(
            crate::tui::shared::components::render_security_analysis_lines(
                related_vulns.len(),
                direct_deps,
                transitive_count,
                license_text,
            ),
        );

        // Flagged indicator and analyst notes
        let is_flagged = ctx.security_cache.is_flagged(&comp.name);
        lines.extend(crate::tui::shared::components::render_flagged_lines(
            is_flagged,
            ctx.security_cache.get_note(&comp.name),
            area.width,
            "",
        ));

        lines.extend(crate::tui::shared::components::render_quick_actions_hint(
            !related_vulns.is_empty(),
        ));

        crate::tui::shared::components::render_detail_block(
            frame,
            area,
            lines,
            " Component Details ",
            ctx.components.focus_detail,
        );
    } else {
        render_empty_detail(frame, area, ctx.components.focus_detail);
    }
}

fn render_empty_detail(frame: &mut Frame, area: Rect, focused: bool) {
    crate::tui::shared::components::render_empty_detail_panel(
        frame,
        area,
        " Component Details ",
        "📦",
        "Select a component to view details",
        &[("[↑↓]", " navigate  "), ("[p]", " toggle focus")],
        focused,
    );
}

fn get_diff_rows(ctx: &RenderContext, components: &[&ComponentChange]) -> Vec<Row<'static>> {
    let multi_select = ctx.components.multi_select_mode;

    components
        .iter()
        .enumerate()
        .map(|(idx, comp)| {
            let is_selected = ctx.components.is_selected(idx);
            let checkbox = if multi_select {
                if is_selected { "☑ " } else { "☐ " }
            } else {
                ""
            };

            let scheme = colors();
            let (label, status_bg, status_fg, row_style) = match comp.change_type {
                crate::diff::ChangeType::Added => (
                    " + ADDED    ",
                    scheme.added,
                    scheme.badge_fg_dark,
                    Style::default().fg(scheme.added),
                ),
                crate::diff::ChangeType::Removed => (
                    " - REMOVED  ",
                    scheme.removed,
                    scheme.badge_fg_light,
                    Style::default().fg(scheme.removed),
                ),
                crate::diff::ChangeType::Modified => (
                    " ~ MODIFIED ",
                    scheme.modified,
                    scheme.badge_fg_dark,
                    Style::default().fg(scheme.modified),
                ),
                crate::diff::ChangeType::Unchanged => (
                    " = SAME     ",
                    scheme.muted,
                    scheme.badge_fg_light,
                    Style::default().fg(scheme.text),
                ),
            };

            let row_style = if is_selected {
                row_style.bg(scheme.selection)
            } else {
                row_style
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    format!("{checkbox}{label}"),
                    Style::default().fg(status_fg).bg(status_bg).bold(),
                )),
                Cell::from(comp.name.clone()),
                Cell::from(
                    comp.old_version
                        .clone()
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                ),
                Cell::from(
                    comp.new_version
                        .clone()
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                ),
                Cell::from(comp.ecosystem.clone().unwrap_or_else(|| "-".to_string())),
                Cell::from(if comp.field_changes.is_empty() {
                    "-".to_string()
                } else {
                    comp.field_changes.len().to_string()
                }),
            ])
            .style(row_style)
        })
        .collect()
}
