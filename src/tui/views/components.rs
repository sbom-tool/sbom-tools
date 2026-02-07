//! Components view with master-detail layout.

use crate::diff::ComponentChange;
use crate::model::Component;
use crate::tui::app::{App, AppMode, ComponentFilter};
use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
};

/// Pre-built component list to avoid rebuilding on each render call.
/// Built once per frame in `render_components` and passed to sub-functions.
pub enum ComponentListData<'a> {
    Diff(Vec<&'a ComponentChange>),
    View(Vec<&'a Component>),
    Empty,
}

pub fn render_components(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10)])
        .split(area);

    // Render filter bar with badges
    render_filter_bar(frame, chunks[0], app);

    // Build component list once per frame (performance optimization)
    // Use efficient count methods to update state, then build list only once for rendering
    let total_unfiltered = match app.mode {
        AppMode::Diff => {
            app.tabs.components.total = app.diff_component_count(app.tabs.components.filter);
            app.data.diff_result
                .as_ref()
                .map_or(0, |r| r.components.total())
        }
        AppMode::View => {
            app.tabs.components.total = app.view_component_count();
            app.tabs.components.total // For view mode, total equals visible count
        }
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {
            app.tabs.components.total = 0;
            0
        }
    };
    app.tabs.components.clamp_selection();

    // Build the list data once for rendering (borrows app immutably)
    let component_data = match app.mode {
        AppMode::Diff => {
            ComponentListData::Diff(app.diff_component_items(app.tabs.components.filter))
        }
        AppMode::View => ComponentListData::View(app.view_component_items()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => ComponentListData::Empty,
    };

    // Master-detail layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    // Render component table (master) — pass scroll_offset separately to avoid borrow conflict
    let mut scroll_offset = app.tabs.components.scroll_offset;
    render_component_table(
        frame,
        content_chunks[0],
        app,
        &component_data,
        total_unfiltered,
        &mut scroll_offset,
    );
    // Render detail panel (component_data borrow ends after this call)
    render_detail_panel(frame, content_chunks[1], app, &component_data);

    // Save scroll offset back after component_data borrow is released
    app.tabs.components.scroll_offset = scroll_offset;
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &App) {
    use crate::tui::viewmodel::security_filter::QuickFilter;

    let filter = app.tabs.components.filter;
    let sort = &app.tabs.components.sort_by;
    let multi_select = app.tabs.components.multi_select_mode;
    let selection_count = app.tabs.components.selection_count();

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
    let security_filter = &app.tabs.components.security_filter;
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
    app: &App,
    component_data: &ComponentListData,
    total_unfiltered: usize,
    scroll_offset: &mut usize,
) {
    let is_diff = matches!(component_data, ComponentListData::Diff(_));
    let last_col_header = if is_diff { "Changes" } else { "Staleness" };
    let header_cells = ["", "Name", "Old Version", "New Version", "Ecosystem", last_col_header]
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().fg(colors().accent).bold()));
    let header = Row::new(header_cells).height(1);

    // Use pre-built component list (state already updated in render_components)
    let rows: Vec<Row> = match component_data {
        ComponentListData::Diff(components) => get_diff_rows(app, components),
        ComponentListData::View(components) => get_view_rows(app, components),
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
            widgets::render_no_results_state(
                frame,
                area,
                "Filter",
                app.tabs.components.filter.label(),
            );
        }
        return;
    }

    let last_col_width = if is_diff { Constraint::Length(7) } else { Constraint::Length(9) };
    let widths = [
        Constraint::Length(12),
        Constraint::Min(16),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(7),
        last_col_width,
    ];

    let selected_idx = app.tabs.components.selected;
    let scheme = colors();
    let table_focused = !app.tabs.components.focus_detail;
    let table_border_color = if table_focused {
        scheme.accent
    } else {
        scheme.border
    };
    let table_title_style = if table_focused {
        Style::default().fg(scheme.accent).bold()
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
        .with_offset(*scroll_offset)
        .with_selected(Some(selected_idx));

    frame.render_stateful_widget(table, area, &mut state);

    // Save scroll offset for next frame (stable viewport)
    *scroll_offset = state.offset();

    // Render scrollbar
    if rows.len() > area.height.saturating_sub(3) as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(colors().accent))
            .track_style(Style::default().fg(colors().muted))
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));

        let mut scrollbar_state = ScrollbarState::new(rows.len()).position(*scroll_offset);

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

fn render_detail_panel(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    component_data: &ComponentListData,
) {
    match component_data {
        ComponentListData::Diff(components) => render_diff_detail(frame, area, app, components),
        ComponentListData::View(components) => render_view_detail(frame, area, app, components),
        ComponentListData::Empty => {}
    }
}

fn render_diff_detail(frame: &mut Frame, area: Rect, app: &App, components: &[&ComponentChange]) {
    let selected = app.tabs.components.selected;

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
            use crate::tui::security::{detect_version_downgrade, analyze_downgrade, VersionChange};
            let version_change = detect_version_downgrade(old_ver, new_ver);
            if version_change == VersionChange::Downgrade {
                let downgrade_severity = analyze_downgrade(old_ver, new_ver);
                let (warning_text, warning_color) = match downgrade_severity {
                    Some(crate::tui::security::DowngradeSeverity::Major) => {
                        ("⚠ MAJOR DOWNGRADE - Supply chain attack risk!", colors().critical)
                    }
                    Some(crate::tui::security::DowngradeSeverity::Suspicious) => {
                        ("⚠ SUSPICIOUS - Security patch may be removed!", colors().critical)
                    }
                    Some(crate::tui::security::DowngradeSeverity::Minor) => {
                        ("⚠ Version Downgrade Detected", colors().warning)
                    }
                    None => ("⚠ Downgrade", colors().warning),
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {warning_text} "),
                        Style::default().fg(colors().badge_fg_dark).bg(warning_color).bold(),
                    ),
                ]));
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
        let related_vulns: Vec<_> = app
            .data.diff_result
            .as_ref()
            .map(|r| {
                r.vulnerabilities
                    .introduced
                    .iter()
                    .filter(|v| v.component_id == comp.id)  // ID-based lookup
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
            lines.extend(crate::tui::shared::components::render_vulnerability_list_lines(
                &vuln_entries,
                5,
                related_vulns.len(),
                area.width,
            ));
        }

        // Security Analysis section (Diff mode)
        let reverse_graph = &app.tabs.dependencies.cached_reverse_graph;
        let (direct_deps, transitive_count) =
            crate::tui::shared::components::compute_blast_radius(&comp.name, reverse_graph);
        let license_text = app.data.new_sbom.as_ref()
            .and_then(|sbom| {
                let canonical_id = crate::model::CanonicalId::from_format_id(&comp.id);
                sbom.components.get(&canonical_id)
            })
            .and_then(|c| c.licenses.declared.first())
            .map_or("Unknown", |l| l.expression.as_str());
        lines.extend(crate::tui::shared::components::render_security_analysis_lines(
            related_vulns.len(),
            direct_deps,
            transitive_count,
            license_text,
        ));

        // Flagged indicator and analyst notes
        let is_flagged = app.security_cache.is_flagged(&comp.name);
        lines.extend(crate::tui::shared::components::render_flagged_lines(
            is_flagged,
            app.security_cache.get_note(&comp.name),
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
            app.tabs.components.focus_detail,
        );
    } else {
        render_empty_detail(frame, area, app.tabs.components.focus_detail);
    }
}

fn render_view_detail(frame: &mut Frame, area: Rect, app: &App, components: &[&Component]) {
    let selected = app.tabs.components.selected;

    if let Some(comp) = components.get(selected) {
        let mut lines = vec![
            // Component name
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(colors().text_muted)),
                Span::styled(&comp.name, Style::default().fg(colors().text).bold()),
            ]),
        ];

        // Version
        if let Some(ver) = &comp.version {
            lines.push(Line::from(vec![
                Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                Span::styled(ver, Style::default().fg(colors().secondary)),
            ]));
        }

        // Ecosystem
        if let Some(eco) = &comp.ecosystem {
            lines.push(Line::from(vec![
                Span::styled("Ecosystem: ", Style::default().fg(colors().text_muted)),
                Span::styled(eco.to_string(), Style::default().fg(colors().accent)),
            ]));
        }

        // Component type
        lines.push(Line::from(vec![
            Span::styled("Type: ", Style::default().fg(colors().text_muted)),
            Span::styled(
                format!("{:?}", comp.component_type),
                Style::default().fg(colors().text),
            ),
        ]));

        // PURL if available
        if let Some(purl) = &comp.identifiers.purl {
            lines.push(Line::from(vec![
                Span::styled("PURL: ", Style::default().fg(colors().text_muted)),
                Span::styled(
                    widgets::truncate_str(purl, area.width as usize - 8),
                    Style::default().fg(colors().text),
                ),
            ]));
        }

        // Licenses
        if !comp.licenses.declared.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled(
                    format!("Licenses ({})", comp.licenses.declared.len()),
                    Style::default().fg(colors().permissive).bold(),
                ),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));
            for lic in comp.licenses.declared.iter().take(3) {
                let lic_color = colors().license_color(&lic.expression);
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(colors().text_muted)),
                    Span::styled(&lic.expression, Style::default().fg(lic_color)),
                ]));
            }
            if comp.licenses.declared.len() > 3 {
                lines.push(Line::styled(
                    format!("    ... and {} more", comp.licenses.declared.len() - 3),
                    Style::default().fg(colors().text_muted),
                ));
            }
        }

        // Vulnerabilities
        if !comp.vulnerabilities.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled(
                    format!("⚠ Vulnerabilities ({})", comp.vulnerabilities.len()),
                    Style::default().fg(colors().high).bold(),
                ),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));
            let sev_strings: Vec<String> = comp
                .vulnerabilities
                .iter()
                .map(|v| {
                    v.severity
                        .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string)
                })
                .collect();
            let vuln_entries: Vec<(&str, &str, Option<&str>)> = comp
                .vulnerabilities
                .iter()
                .zip(sev_strings.iter())
                .map(|(v, sev)| (sev.as_str(), v.id.as_str(), None))
                .collect();
            lines.extend(crate::tui::shared::components::render_vulnerability_list_lines(
                &vuln_entries,
                5,
                comp.vulnerabilities.len(),
                area.width,
            ));
        }

        // Hashes
        if !comp.hashes.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled("Hashes", Style::default().fg(colors().text_muted).bold()),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));
            for hash in comp.hashes.iter().take(2) {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:?}: ", hash.algorithm),
                        Style::default().fg(colors().text_muted),
                    ),
                    Span::styled(
                        widgets::truncate_str(&hash.value, 32),
                        Style::default().fg(colors().text),
                    ),
                ]));
            }
        }

        // Security Analysis section
        let reverse_graph = &app.tabs.dependencies.cached_reverse_graph;
        let (direct_deps, transitive_count) =
            crate::tui::shared::components::compute_blast_radius(&comp.name, reverse_graph);
        let license_text = comp.licenses.declared.first()
            .map_or("Unknown", |l| l.expression.as_str());
        lines.extend(crate::tui::shared::components::render_security_analysis_lines(
            comp.vulnerabilities.len(),
            direct_deps,
            transitive_count,
            license_text,
        ));

        // Flagged indicator and analyst notes
        let is_flagged = app.security_cache.is_flagged(&comp.name);
        lines.extend(crate::tui::shared::components::render_flagged_lines(
            is_flagged,
            app.security_cache.get_note(&comp.name),
            area.width,
            " for follow-up",
        ));

        lines.extend(crate::tui::shared::components::render_quick_actions_hint(
            !comp.vulnerabilities.is_empty(),
        ));

        crate::tui::shared::components::render_detail_block(
            frame,
            area,
            lines,
            " Component Details ",
            app.tabs.components.focus_detail,
        );
    } else {
        render_empty_detail(frame, area, app.tabs.components.focus_detail);
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

fn get_diff_rows(app: &App, components: &[&ComponentChange]) -> Vec<Row<'static>> {
    let multi_select = app.tabs.components.multi_select_mode;

    components
        .iter()
        .enumerate()
        .map(|(idx, comp)| {
            let is_selected = app.tabs.components.is_selected(idx);
            let checkbox = if multi_select {
                if is_selected {
                    "☑ "
                } else {
                    "☐ "
                }
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
                Cell::from(comp.old_version.clone().unwrap_or_else(|| "\u{2014}".to_string())),
                Cell::from(comp.new_version.clone().unwrap_or_else(|| "\u{2014}".to_string())),
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

fn get_view_rows(app: &App, components: &[&crate::model::Component]) -> Vec<Row<'static>> {
    let multi_select = app.tabs.components.multi_select_mode;

    components
        .iter()
        .enumerate()
        .map(|(idx, comp)| {
            let is_selected = app.tabs.components.is_selected(idx);
            let checkbox = if multi_select {
                if is_selected {
                    "☑ "
                } else {
                    "☐ "
                }
            } else {
                ""
            };

            let scheme = colors();
            let vuln_indicator = if comp.vulnerabilities.is_empty() {
                Span::styled(
                    format!("{checkbox} ✓ "),
                    Style::default().fg(scheme.success),
                )
            } else {
                Span::styled(
                    format!("{} ⚠ {} ", checkbox, comp.vulnerabilities.len()),
                    Style::default()
                        .fg(scheme.badge_fg_light)
                        .bg(scheme.high)
                        .bold(),
                )
            };

            let row_style = if is_selected {
                Style::default().bg(scheme.selection)
            } else {
                Style::default()
            };

            // Build staleness cell
            let staleness_cell = comp.staleness.as_ref().map_or_else(
                || Cell::from("-"),
                |info| {
                    use crate::model::StalenessLevel;
                    let (label, color) = match info.level {
                        StalenessLevel::Fresh => ("Fresh", scheme.success),
                        StalenessLevel::Aging => ("Aging", scheme.warning),
                        StalenessLevel::Stale => ("Stale", scheme.high),
                        StalenessLevel::Abandoned => ("Abandoned", scheme.critical),
                        StalenessLevel::Deprecated => ("Deprecated", scheme.critical),
                        StalenessLevel::Archived => ("Archived", scheme.error),
                    };
                    Cell::from(Span::styled(
                        format!(" {label} "),
                        Style::default()
                            .fg(if matches!(info.level, StalenessLevel::Fresh | StalenessLevel::Aging) {
                                scheme.badge_fg_dark
                            } else {
                                scheme.badge_fg_light
                            })
                            .bg(color)
                            .bold(),
                    ))
                },
            );

            Row::new(vec![
                Cell::from(vuln_indicator),
                Cell::from(comp.name.clone()),
                Cell::from(comp.version.clone().unwrap_or_else(|| "\u{2014}".to_string())),
                Cell::from("\u{2014}"),
                Cell::from(
                    comp.ecosystem
                        .as_ref().map_or_else(|| "-".to_string(), std::string::ToString::to_string),
                ),
                staleness_cell,
            ])
            .style(row_style)
        })
        .collect()
}

#[allow(dead_code)]
fn severity_style(severity: &str) -> Style {
    Style::default().fg(colors().severity_color(severity))
}
