//! Vulnerability explorer view for `ViewApp`.

use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, ViewApp, VulnGroupBy};
use crate::tui::widgets::{SeverityBadge, truncate_str};
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState, Wrap,
    },
};

pub fn render_vulnerabilities(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Stats/histogram
            Constraint::Length(2), // Filter bar
            Constraint::Min(10),   // Vulnerability table + detail panel
        ])
        .split(area);

    render_stats(frame, chunks[0], app);
    render_filter_bar(frame, chunks[1], app);
    render_vuln_content(frame, chunks[2], app);
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
        (count * bar_width / total).max(usize::from(count > 0))
    } else {
        0
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            format!(" {label} "),
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
    let filter_label = app
        .vuln_state
        .filter_severity
        .as_ref()
        .map_or_else(|| "All".to_string(), |s| s.to_uppercase());

    let group_label = match app.vuln_state.group_by {
        VulnGroupBy::Severity => "Severity",
        VulnGroupBy::Component => "Component",
        VulnGroupBy::Flat => "Flat",
    };

    let dedupe_label = if app.vuln_state.deduplicate {
        "On"
    } else {
        "Off"
    };

    let mut spans = vec![
        Span::styled("Filter: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {filter_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Sort: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {} ", app.vuln_state.sort_by.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Dedupe: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {dedupe_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if app.vuln_state.deduplicate {
                    scheme.success
                } else {
                    scheme.muted
                })
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Group: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {group_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.secondary)
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[f]", Style::default().fg(scheme.accent)),
        Span::raw(" filter  "),
        Span::styled("[s]", Style::default().fg(scheme.accent)),
        Span::raw(" sort  "),
        Span::styled("[d]", Style::default().fg(scheme.accent)),
        Span::raw(" dedupe  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" group  "),
        Span::styled("[/]", Style::default().fg(scheme.accent)),
        Span::raw(" search"),
    ];

    // Show active search query
    if app.vuln_state.search_active {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("/{}", app.vuln_state.search_query),
            Style::default().fg(scheme.accent).bold(),
        ));
        spans.push(Span::styled("█", Style::default().fg(scheme.accent)));
    } else if !app.vuln_state.search_query.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("\"{}\"", app.vuln_state.search_query),
            Style::default().fg(scheme.accent),
        ));
    }

    let para = Paragraph::new(Line::from(spans));
    frame.render_widget(para, area);
}

/// Main content area with table and detail panel
fn render_vuln_content(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    // Use cached data if available, otherwise rebuild
    if !app.vuln_state.is_cache_valid() {
        let cache = build_vuln_cache(app);
        app.vuln_state.set_cache(cache);
    }

    // Clone cache data to avoid borrow conflicts (cache is already computed, clone is cheap for metadata)
    let Some(cache) = app.vuln_state.cached_data.clone() else {
        return;
    };
    let has_any_cvss = cache.has_any_cvss;
    let all_same_component = cache.all_same_component;
    let has_multi_affected = cache.has_multi_affected;
    let total_unfiltered = cache.total_unfiltered;

    // Handle empty states
    if cache.vulns.is_empty() {
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
                .map_or_else(|| "current".to_string(), |s| s.to_uppercase());
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

    // Build display items (flat or grouped)
    let display_items = build_display_items(
        &cache.vulns,
        &app.vuln_state.group_by,
        &app.vuln_state.expanded_groups,
    );

    // Update total and clamp selection based on display items
    app.vuln_state.total = display_items.len();
    app.vuln_state.clamp_selection();

    // Split into table and detail panel
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55), // Table
            Constraint::Percentage(45), // Detail panel
        ])
        .split(area);

    let is_left_focused = app.focus_panel == FocusPanel::Left;

    // Render table
    render_vuln_table_panel(
        frame,
        chunks[0],
        &cache.vulns,
        &display_items,
        app,
        has_any_cvss,
        all_same_component,
        has_multi_affected,
        is_left_focused,
    );

    // Render detail panel - resolve selected vuln from display items
    let selected_vuln = display_items
        .get(app.vuln_state.selected)
        .and_then(|item| match item {
            VulnDisplayItem::Vuln(idx) => cache.vulns.get(*idx),
            VulnDisplayItem::GroupHeader { .. } => None,
        });
    render_vuln_detail_panel(
        frame,
        chunks[1],
        selected_vuln,
        !is_left_focused,
        &mut app.vuln_state.detail_scroll,
    );
}

/// Resolve severity: use explicit severity, fall back to CVSS score, then "Unknown"
fn resolve_severity(vuln: &crate::model::VulnerabilityRef) -> String {
    if let Some(sev) = &vuln.severity {
        let s = sev.to_string();
        if s != "Unknown" {
            return s;
        }
    }
    // Fall back to CVSS-derived severity
    if let Some(score) = vuln.max_cvss_score() {
        return crate::model::Severity::from_cvss(score).to_string();
    }
    "Unknown".to_string()
}

/// Group affected component names by extracted package name for smart display.
/// Returns (`package_display_name`, count) pairs.
fn group_affected_components(
    components: &[String],
    description: Option<&str>,
) -> Vec<(String, usize)> {
    use std::collections::HashMap;
    let mut groups: HashMap<String, usize> = HashMap::new();

    for comp in components {
        let display = extract_component_display_name(comp, description);
        *groups.entry(display).or_insert(0) += 1;
    }

    let mut sorted: Vec<_> = groups.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1)); // Most frequent first
    sorted
}

/// Build the vulnerability cache from SBOM data
pub(crate) fn build_vuln_cache(app: &ViewApp) -> VulnCache {
    use crate::tui::shared::vulnerabilities::severity_rank;
    use crate::tui::view::app::VulnSortBy;
    use std::collections::HashMap;

    let mut vulns: Vec<VulnRow> = Vec::new();
    let mut total_unfiltered = 0;
    let mut has_any_cvss = false;
    let mut all_same_component = true;
    let mut first_component: Option<String> = None;

    let search_query = app.vuln_state.search_query.to_lowercase();
    let has_search = !search_query.is_empty();

    // If deduplicating, collect by CVE ID first
    if app.vuln_state.deduplicate {
        let mut vuln_map: HashMap<String, VulnRow> = HashMap::new();

        for (comp_id, comp) in &app.sbom.components {
            for vuln in &comp.vulnerabilities {
                total_unfiltered += 1;
                let sev = resolve_severity(vuln);

                // Apply severity filter
                if let Some(ref filter) = app.vuln_state.filter_severity
                    && sev.to_lowercase() != *filter
                {
                    continue;
                }

                // Apply search filter
                if has_search {
                    let matches = vuln.id.to_lowercase().contains(&search_query)
                        || comp.name.to_lowercase().contains(&search_query)
                        || vuln
                            .description
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(&search_query));
                    if !matches {
                        continue;
                    }
                }

                let cvss = vuln.max_cvss_score().map(f64::from);
                if cvss.is_some() {
                    has_any_cvss = true;
                }

                vuln_map
                    .entry(vuln.id.clone())
                    .and_modify(|existing| {
                        existing.affected_count += 1;
                        existing.affected_components.push(comp.name.clone());
                        // Keep the highest CVSS score
                        if let Some(new_cvss) = cvss
                            && existing.cvss.is_none_or(|c| new_cvss > c)
                        {
                            existing.cvss = Some(new_cvss);
                        }
                        // Merge affected versions
                        for v in &vuln.affected_versions {
                            if !existing.affected_versions.contains(v) {
                                existing.affected_versions.push(v.clone());
                            }
                        }
                    })
                    .or_insert_with(|| VulnRow {
                        vuln_id: vuln.id.clone(),
                        severity: sev,
                        cvss,
                        component_name: comp.name.clone(),
                        component_id: comp_id.value().to_string(),
                        description: vuln.description.clone(),
                        affected_count: 1,
                        affected_components: vec![comp.name.clone()],
                        cwes: vuln.cwes.clone(),
                        published: vuln.published,
                        affected_versions: vuln.affected_versions.clone(),
                        source: vuln.source.to_string(),
                        is_kev: vuln.is_kev,
                        vex_state: vuln
                            .vex_status
                            .as_ref()
                            .map(|v| v.status.clone())
                            .or_else(|| comp.vex_status.as_ref().map(|v| v.status.clone())),
                        grouped_components: Vec::new(),
                    });
            }
        }

        // Build smart component groupings for each deduped vuln
        vulns = vuln_map
            .into_values()
            .map(|mut v| {
                v.grouped_components =
                    group_affected_components(&v.affected_components, v.description.as_deref());
                v
            })
            .collect();

        // Compute all_same_component for dedup path
        if let Some(first) = vulns.first() {
            let first_name = &first.component_name;
            all_same_component = vulns.iter().all(|v| &v.component_name == first_name);
        }
    } else {
        for (comp_id, comp) in &app.sbom.components {
            for vuln in &comp.vulnerabilities {
                total_unfiltered += 1;
                let sev = resolve_severity(vuln);

                // Apply severity filter
                if let Some(ref filter) = app.vuln_state.filter_severity
                    && sev.to_lowercase() != *filter
                {
                    continue;
                }

                // Apply search filter
                if has_search {
                    let matches = vuln.id.to_lowercase().contains(&search_query)
                        || comp.name.to_lowercase().contains(&search_query)
                        || vuln
                            .description
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(&search_query));
                    if !matches {
                        continue;
                    }
                }

                let cvss = vuln.max_cvss_score().map(f64::from);
                if cvss.is_some() {
                    has_any_cvss = true;
                }

                // Check if all components are the same
                if let Some(ref first) = first_component {
                    if first != &comp.name {
                        all_same_component = false;
                    }
                } else {
                    first_component = Some(comp.name.clone());
                }

                vulns.push(VulnRow {
                    vuln_id: vuln.id.clone(),
                    severity: sev,
                    cvss,
                    component_name: comp.name.clone(),
                    component_id: comp_id.value().to_string(),
                    description: vuln.description.clone(),
                    affected_count: 1,
                    affected_components: vec![comp.name.clone()],
                    cwes: vuln.cwes.clone(),
                    published: vuln.published,
                    affected_versions: vuln.affected_versions.clone(),
                    source: vuln.source.to_string(),
                    is_kev: vuln.is_kev,
                    vex_state: vuln
                        .vex_status
                        .as_ref()
                        .map(|v| v.status.clone())
                        .or_else(|| comp.vex_status.as_ref().map(|v| v.status.clone())),
                    grouped_components: Vec::new(),
                });
            }
        }
    }

    // Sort based on user selection
    match app.vuln_state.sort_by {
        VulnSortBy::Severity => {
            vulns.sort_by(|a, b| {
                let ord = severity_rank(&a.severity).cmp(&severity_rank(&b.severity));
                if ord == std::cmp::Ordering::Equal {
                    b.cvss
                        .partial_cmp(&a.cvss)
                        .unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    ord
                }
            });
        }
        VulnSortBy::Cvss => {
            vulns.sort_by(|a, b| {
                b.cvss
                    .partial_cmp(&a.cvss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        VulnSortBy::CveId => {
            vulns.sort_by(|a, b| a.vuln_id.cmp(&b.vuln_id));
        }
        VulnSortBy::Component => {
            vulns.sort_by(|a, b| a.component_name.cmp(&b.component_name));
        }
    }

    let has_multi_affected = vulns.iter().any(|v| v.affected_count > 1);

    VulnCache {
        vulns,
        has_any_cvss,
        all_same_component,
        has_multi_affected,
        total_unfiltered,
    }
}

#[allow(clippy::too_many_arguments)]
fn render_vuln_table_panel(
    frame: &mut Frame,
    area: Rect,
    vulns: &[VulnRow],
    display_items: &[VulnDisplayItem],
    app: &mut ViewApp,
    has_any_cvss: bool,
    all_same_component: bool,
    has_multi_affected: bool,
    is_focused: bool,
) {
    let scheme = colors();
    let is_dedupe = app.vuln_state.deduplicate;

    // Determine which columns to show
    let show_cvss = has_any_cvss;
    // Show component column when components differ, or when dedup has multi-affected vulns
    let show_component = !all_same_component || (is_dedupe && has_multi_affected);
    // Column label: "Affected" only when there are multi-component vulns
    let component_header = if is_dedupe && has_multi_affected {
        "Affected"
    } else {
        "Component"
    };

    // Build dynamic column widths and headers
    let (widths, headers, num_columns): (Vec<Constraint>, Vec<&str>, usize) =
        if show_cvss && show_component {
            (
                vec![
                    Constraint::Length(3),
                    Constraint::Length(16),
                    Constraint::Length(5),
                    Constraint::Length(28),
                    Constraint::Min(15),
                ],
                vec!["", "CVE ID", "CVSS", component_header, "Description"],
                5,
            )
        } else if show_cvss {
            (
                vec![
                    Constraint::Length(3),
                    Constraint::Length(16),
                    Constraint::Length(5),
                    Constraint::Min(20),
                ],
                vec!["", "CVE ID", "CVSS", "Description"],
                4,
            )
        } else if show_component {
            (
                vec![
                    Constraint::Length(3),
                    Constraint::Length(16),
                    Constraint::Length(28),
                    Constraint::Min(20),
                ],
                vec!["", "CVE ID", component_header, "Description"],
                4,
            )
        } else {
            (
                vec![
                    Constraint::Length(3),
                    Constraint::Length(16),
                    Constraint::Min(30),
                ],
                vec!["", "CVE ID", "Description"],
                3,
            )
        };

    // Calculate available width for description
    let desc_width = area.width.saturating_sub(
        widths
            .iter()
            .filter_map(|c| match c {
                Constraint::Length(l) => Some(*l),
                _ => None,
            })
            .sum::<u16>()
            + 5, // borders and spacing
    ) as usize;

    // VIRTUALIZATION: Only render visible rows for performance
    let visible_height = area.height.saturating_sub(3) as usize;
    let total_items = display_items.len();

    // Ensure scroll offset keeps selection visible
    let selected = app.vuln_state.selected;
    let mut scroll_offset = app.vuln_state.scroll_offset;

    if selected < scroll_offset {
        scroll_offset = selected;
    } else if selected >= scroll_offset + visible_height {
        scroll_offset = selected.saturating_sub(visible_height - 1);
    }
    app.vuln_state.scroll_offset = scroll_offset;

    let buffer = 2;
    let start = scroll_offset.saturating_sub(buffer);
    let end = (scroll_offset + visible_height + buffer).min(total_items);

    // Build rows from display items
    let rows: Vec<Row> = display_items[start..end]
        .iter()
        .map(|item| match item {
            VulnDisplayItem::GroupHeader {
                label,
                count,
                expanded,
            } => {
                let arrow = if *expanded { "▼" } else { "▶" };
                let sev_color = SeverityBadge::fg_color(label);
                let is_severity_group = matches!(
                    app.vuln_state.group_by,
                    crate::tui::view::app::VulnGroupBy::Severity
                );

                let mut cells = vec![
                    Cell::from(Span::styled(
                        arrow,
                        Style::default().fg(scheme.accent).bold(),
                    )),
                    Cell::from(Span::styled(
                        format!("{label} ({count})"),
                        Style::default()
                            .fg(if is_severity_group {
                                sev_color
                            } else {
                                scheme.accent
                            })
                            .bold(),
                    )),
                ];
                // Fill remaining columns with empty cells
                for _ in 2..num_columns {
                    cells.push(Cell::from(""));
                }
                Row::new(cells)
            }
            VulnDisplayItem::Vuln(idx) => {
                let v = &vulns[*idx];
                let sev_color = SeverityBadge::fg_color(&v.severity);

                // Build ID cell with optional KEV + VEX badges
                let mut id_spans: Vec<Span<'static>> = Vec::new();
                if v.is_kev {
                    id_spans.push(Span::styled(
                        "KEV",
                        Style::default()
                            .fg(scheme.kev_badge_fg())
                            .bg(scheme.kev())
                            .bold(),
                    ));
                    id_spans.push(Span::raw(" "));
                }
                id_spans.extend(crate::tui::shared::vulnerabilities::render_vex_badge_spans(
                    v.vex_state.as_ref(),
                    &scheme,
                ));
                id_spans.push(Span::styled(
                    truncate_str(&v.vuln_id, 16),
                    Style::default().fg(sev_color).bold(),
                ));

                let mut cells = vec![
                    Cell::from(Span::styled(
                        SeverityBadge::indicator(&v.severity),
                        Style::default()
                            .fg(scheme.severity_badge_fg(&v.severity))
                            .bg(sev_color)
                            .bold(),
                    )),
                    Cell::from(Line::from(id_spans)),
                ];

                if show_cvss {
                    cells.push(Cell::from(
                        v.cvss
                            .map_or_else(|| "-".to_string(), |c| format!("{c:.1}")),
                    ));
                }

                if show_component {
                    if is_dedupe && v.affected_count > 1 {
                        // Multiple components: show count
                        cells.push(Cell::from(Span::styled(
                            format!("{} comp", v.affected_count),
                            Style::default().fg(scheme.primary),
                        )));
                    } else {
                        // Single component or non-dedup: show name
                        let display_name = extract_component_display_name(
                            &v.component_name,
                            v.description.as_deref(),
                        );
                        cells.push(Cell::from(Span::styled(
                            truncate_str(&display_name, 28),
                            Style::default().fg(scheme.primary),
                        )));
                    }
                }

                cells.push(Cell::from(Span::styled(
                    v.description
                        .as_ref()
                        .map_or_else(|| "-".to_string(), |d| truncate_str(d, desc_width.max(15))),
                    Style::default().fg(scheme.text),
                )));

                Row::new(cells)
            }
        })
        .collect();

    let header = Row::new(headers.clone())
        .style(Style::default().fg(scheme.accent).bold())
        .height(1);

    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let relative_selected = if selected >= start && selected < end {
        Some(selected - start)
    } else {
        None
    };

    // Count actual vulns for the title
    let vuln_count = vulns.len();
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Vulnerabilities ({vuln_count}) "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶");

    let mut state = TableState::default()
        .with_offset(scroll_offset.saturating_sub(start))
        .with_selected(relative_selected);

    frame.render_stateful_widget(table, area, &mut state);

    // Scrollbar
    let visible_height = area.height.saturating_sub(3) as usize;
    if total_items > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.high))
            .track_style(Style::default().fg(scheme.muted));

        let mut scrollbar_state =
            ScrollbarState::new(total_items).position(app.vuln_state.selected);

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

fn render_vuln_detail_panel(
    frame: &mut Frame,
    area: Rect,
    vuln: Option<&VulnRow>,
    is_focused: bool,
    detail_scroll: &mut u16,
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let Some(v) = vuln else {
        *detail_scroll = 0;
        let block = Block::default()
            .title(" Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));
        let para = Paragraph::new("Select a vulnerability to view details")
            .block(block)
            .style(Style::default().fg(scheme.muted));
        frame.render_widget(para, area);
        return;
    };

    let sev_color = SeverityBadge::fg_color(&v.severity);

    // Build detail content
    let mut lines: Vec<Line> = Vec::new();

    // CVE ID with severity badge + KEV + VEX badges
    {
        let mut id_line_spans = vec![
            Span::styled(
                format!(" {} ", SeverityBadge::indicator(&v.severity)),
                Style::default()
                    .fg(scheme.severity_badge_fg(&v.severity))
                    .bg(sev_color)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(&v.vuln_id, Style::default().fg(sev_color).bold()),
        ];
        if v.is_kev {
            id_line_spans.push(Span::raw(" "));
            id_line_spans.push(Span::styled(
                "KEV",
                Style::default()
                    .fg(scheme.kev_badge_fg())
                    .bg(scheme.kev())
                    .bold(),
            ));
        }
        let vex_spans = crate::tui::shared::vulnerabilities::render_vex_badge_spans(
            v.vex_state.as_ref(),
            &scheme,
        );
        if !vex_spans.is_empty() {
            id_line_spans.push(Span::raw(" "));
            id_line_spans.extend(vex_spans);
        }
        lines.push(Line::from(id_line_spans));
    }

    // Severity + CVSS on one line
    let mut sev_spans = vec![
        Span::styled("Severity: ", Style::default().fg(scheme.muted)),
        Span::styled(&v.severity, Style::default().fg(sev_color).bold()),
    ];
    if let Some(cvss) = v.cvss {
        sev_spans.push(Span::styled("  CVSS: ", Style::default().fg(scheme.muted)));
        sev_spans.push(Span::styled(
            format!("{cvss:.1}"),
            Style::default().fg(scheme.text).bold(),
        ));
    }
    lines.push(Line::from(sev_spans));

    // Source + Published date on one line
    let mut meta_spans = vec![
        Span::styled("Source: ", Style::default().fg(scheme.muted)),
        Span::styled(&v.source, Style::default().fg(scheme.primary)),
    ];
    if let Some(pub_date) = v.published {
        let age_days = (chrono::Utc::now() - pub_date).num_days();
        meta_spans.push(Span::styled(
            "  Published: ",
            Style::default().fg(scheme.muted),
        ));
        meta_spans.push(Span::styled(
            format!("{} ({} days ago)", pub_date.format("%Y-%m-%d"), age_days),
            Style::default().fg(scheme.text),
        ));
    }
    lines.push(Line::from(meta_spans));

    // VEX status detail
    if let Some(ref vex_state) = v.vex_state {
        let (vex_label, vex_color) = match vex_state {
            crate::model::VexState::NotAffected => ("Not Affected", scheme.low),
            crate::model::VexState::Fixed => ("Fixed", scheme.low),
            crate::model::VexState::Affected => ("Affected", scheme.critical),
            crate::model::VexState::UnderInvestigation => ("Under Investigation", scheme.medium),
        };
        lines.push(Line::from(vec![
            Span::styled("VEX: ", Style::default().fg(scheme.muted)),
            Span::styled(vex_label, Style::default().fg(vex_color).bold()),
        ]));
    }

    // Affected versions
    if !v.affected_versions.is_empty() {
        let versions_str = v
            .affected_versions
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if v.affected_versions.len() > 3 {
            format!(" +{} more", v.affected_versions.len() - 3)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled("Versions: ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{versions_str}{suffix}"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    lines.push(Line::from(""));

    // Component(s) - use smart grouping when available
    if v.affected_count > 1 {
        lines.push(Line::from(vec![
            Span::styled("Components: ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{} affected", v.affected_count),
                Style::default().fg(scheme.primary),
            ),
        ]));
        // Show smart-grouped components
        if v.grouped_components.is_empty() {
            // Fallback: show raw component names
            for (i, comp) in v.affected_components.iter().take(5).enumerate() {
                let display = extract_component_display_name(comp, v.description.as_deref());
                lines.push(Line::from(Span::styled(
                    format!("  {}. {}", i + 1, display),
                    Style::default().fg(scheme.text),
                )));
            }
            if v.affected_count > 5 {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", v.affected_count - 5),
                    Style::default().fg(scheme.muted),
                )));
            }
        } else {
            for (name, count) in v.grouped_components.iter().take(6) {
                if *count > 1 {
                    lines.push(Line::from(Span::styled(
                        format!("  {name} (x{count})"),
                        Style::default().fg(scheme.text),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("  {name}"),
                        Style::default().fg(scheme.text),
                    )));
                }
            }
            let total_shown: usize = v.grouped_components.iter().take(6).map(|(_, c)| c).sum();
            if total_shown < v.affected_count {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", v.affected_count - total_shown),
                    Style::default().fg(scheme.muted),
                )));
            }
        }
    } else {
        let display = extract_component_display_name(&v.component_name, v.description.as_deref());
        let show_raw = display != v.component_name;
        lines.push(Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.muted)),
            Span::styled(display, Style::default().fg(scheme.primary)),
        ]));
        if show_raw {
            lines.push(Line::from(Span::styled(
                format!("  ({})", truncate_str(&v.component_name, 40)),
                Style::default().fg(scheme.muted).dim(),
            )));
        }
    }

    // CWEs (inline)
    lines.extend(crate::tui::shared::vulnerabilities::render_vuln_cwe_lines(
        &v.cwes, 5,
    ));

    lines.push(Line::from(""));

    // Description
    lines.push(Line::from(Span::styled(
        "Description:",
        Style::default().fg(scheme.muted),
    )));

    if let Some(desc) = &v.description {
        let max_width = area.width.saturating_sub(4) as usize;
        for wrapped_line in crate::tui::shared::vulnerabilities::word_wrap(desc, max_width) {
            lines.push(Line::from(Span::styled(
                format!("  {wrapped_line}"),
                Style::default().fg(scheme.text),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  No description available",
            Style::default().fg(scheme.muted).italic(),
        )));
    }

    // Reference URL hint
    lines.push(Line::from(""));
    if v.vuln_id.starts_with("CVE-") {
        lines.push(Line::from(vec![
            Span::styled("[o]", Style::default().fg(scheme.accent)),
            Span::styled(
                format!(" nvd.nist.gov/vuln/detail/{}", v.vuln_id),
                Style::default().fg(scheme.muted),
            ),
        ]));
    } else if v.vuln_id.starts_with("GHSA-") {
        lines.push(Line::from(vec![
            Span::styled("[o]", Style::default().fg(scheme.accent)),
            Span::styled(
                format!(" github.com/advisories/{}", v.vuln_id),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    // Clamp scroll offset so it doesn't exceed content
    let content_height = area.height.saturating_sub(2); // borders
    let total_lines = lines.len() as u16;
    let max_scroll = total_lines.saturating_sub(content_height);
    if *detail_scroll > max_scroll {
        *detail_scroll = max_scroll;
    }

    let block = Block::default()
        .title(if is_focused {
            " Details [↑↓ scroll] "
        } else {
            " Details "
        })
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((*detail_scroll, 0));

    frame.render_widget(para, area);

    // Scrollbar when content overflows
    if total_lines > content_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));

        let mut scrollbar_state =
            ScrollbarState::new(total_lines as usize).position(*detail_scroll as usize);

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

/// Extract a meaningful display name from a component path and/or description
fn extract_component_display_name(name: &str, description: Option<&str>) -> String {
    // First, check if the component name is already meaningful
    let is_cryptic = is_cryptic_name(name);

    if !is_cryptic {
        // Name looks good, use it (possibly cleaned up)
        return clean_component_name(name);
    }

    // Name is cryptic - try to extract from description
    if let Some(desc) = description
        && let Some(pkg_name) = extract_package_from_description(desc)
    {
        return pkg_name;
    }

    // Fall back to cleaning up the file path
    clean_component_name(name)
}

/// Check if a component name is cryptic (hash-like, numeric, or uninformative)
fn is_cryptic_name(name: &str) -> bool {
    // Get the base name (last component of path)
    let base = name.rsplit('/').next().unwrap_or(name);

    // Remove common extensions
    let clean = base
        .trim_end_matches(".squ")
        .trim_end_matches(".squashfs")
        .trim_end_matches(".img")
        .trim_end_matches(".bin")
        .trim_end_matches(".so")
        .trim_end_matches(".a");

    // Check if it's mostly hex digits and dashes (hash-like)
    if clean
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
        && clean.len() > 8
    {
        return true;
    }

    // Check if it's mostly numeric
    let digit_count = clean.chars().filter(char::is_ascii_digit).count();
    if digit_count > clean.len() / 2 && clean.len() > 6 {
        return true;
    }

    // Check if it starts with ./ which often indicates extracted files
    if name.starts_with("./") {
        // But allow if the filename itself is meaningful
        let has_letters = clean.chars().filter(|c| c.is_alphabetic()).count() > 3;
        if !has_letters {
            return true;
        }
    }

    false
}

/// Clean up a component name (remove path prefixes, extensions)
fn clean_component_name(name: &str) -> String {
    if (name.starts_with("./") || name.starts_with('/') || name.contains('/'))
        && let Some(filename) = name.rsplit('/').next()
    {
        let clean = filename
            .trim_end_matches(".squ")
            .trim_end_matches(".squashfs")
            .trim_end_matches(".img")
            .trim_end_matches(".bin");

        if clean.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return format!("file:{}", truncate_str(clean, 12));
        }
        return clean.to_string();
    }
    name.to_string()
}

/// Extract package name from CVE description
/// CVE descriptions often mention the affected package early in the text
fn extract_package_from_description(description: &str) -> Option<String> {
    // Common patterns in CVE descriptions:
    // "BusyBox through 1.35.0 allows..."
    // "In BusyBox before 1.35.0, ..."
    // "A vulnerability in PCRE allows..."
    // "The libpcre library in PCRE 8.x..."
    // "An issue was discovered in OpenSSL..."
    // "Buffer overflow in zlib before 1.2.12..."

    // List of known package names to look for (common embedded/system packages)
    const KNOWN_PACKAGES: &[&str] = &[
        // Libraries
        "busybox",
        "glibc",
        "musl",
        "uclibc",
        "openssl",
        "libssl",
        "libcrypto",
        "zlib",
        "bzip2",
        "xz",
        "lzma",
        "lz4",
        "zstd",
        "pcre",
        "pcre2",
        "libpcre",
        "libpcre2",
        "curl",
        "libcurl",
        "wget",
        "sqlite",
        "sqlite3",
        "libsqlite",
        "expat",
        "libexpat",
        "libxml2",
        "libxslt",
        "libjpeg",
        "libpng",
        "libtiff",
        "libwebp",
        "giflib",
        "freetype",
        "fontconfig",
        "harfbuzz",
        "openldap",
        "libldap",
        "libssh",
        "libssh2",
        "openssh",
        "gnutls",
        "mbedtls",
        "wolfssl",
        "libressl",
        "dbus",
        "systemd",
        "udev",
        "linux",
        "kernel",
        "linux-kernel",
        "bash",
        "dash",
        "ash",
        "sh",
        "python",
        "perl",
        "ruby",
        "php",
        "lua",
        "nginx",
        "apache",
        "httpd",
        "lighttpd",
        "libuv",
        "libevent",
        "libev",
        "protobuf",
        "grpc",
        "flatbuffers",
        "boost",
        "poco",
        "qt",
        "ncurses",
        "readline",
        "icu",
        "libicu",
        "libidn",
        "libidn2",
        "nettle",
        "libgcrypt",
        "libsodium",
        "nss",
        "nspr",
        "krb5",
        "libkrb5",
        "cyrus-sasl",
        "libsasl",
        "pam",
        "libpam",
        "audit",
        "libaudit",
        "selinux",
        "libselinux",
        "acl",
        "libacl",
        "attr",
        "libattr",
        "cap",
        "libcap",
        "util-linux",
        "coreutils",
        "findutils",
        "binutils",
        "gcc",
        "llvm",
        "clang",
        "dropbear",
        "dnsmasq",
        "hostapd",
        "wpa_supplicant",
        "iptables",
        "nftables",
        "iproute2",
        "tcpdump",
        "libpcap",
        "snmp",
        "net-snmp",
        "ntp",
        "chrony",
        "samba",
        "cifs",
        // Firmware/embedded specific
        "u-boot",
        "grub",
        "barebox",
        "mtd-utils",
        "squashfs",
        "jffs2",
        "ubifs",
        "openwrt",
        "buildroot",
        "yocto",
    ];

    let desc_lower = description.to_lowercase();

    // Strategy 1: Look for known package names at word boundaries
    for &pkg in KNOWN_PACKAGES {
        // Check various patterns where the package might appear
        let patterns = [
            format!("{pkg} "),        // "busybox allows..."
            format!(" {pkg} "),       // "in busybox before..."
            format!("in {pkg}"),      // "vulnerability in busybox"
            format!("{pkg} before"),  // "busybox before 1.35"
            format!("{pkg} through"), // "busybox through 1.35"
            format!("{pkg} prior"),   // "busybox prior to"
            format!("lib{pkg}"),      // "libcurl" when looking for "curl"
        ];

        for pattern in &patterns {
            if desc_lower.contains(pattern) {
                // Return the properly capitalized version
                return Some(capitalize_package_name(pkg));
            }
        }
    }

    // Strategy 2: Look for patterns like "X before/through/prior to VERSION"
    // This catches packages not in our known list
    let version_patterns = [
        " before ",
        " through ",
        " prior to ",
        " up to ",
        " <= ",
        " < ",
    ];

    for pattern in version_patterns {
        if let Some(pos) = desc_lower.find(pattern) {
            // Look backwards from the pattern to find the package name
            let prefix = &description[..pos];
            if let Some(pkg) = extract_word_before(prefix) {
                // Validate it looks like a package name (not "vulnerability", "issue", etc.)
                let pkg_lower = pkg.to_lowercase();
                if !is_noise_word(&pkg_lower) && pkg.len() >= 2 && pkg.len() <= 30 {
                    return Some(pkg.to_string());
                }
            }
        }
    }

    // Strategy 3: Look for "in X," or "in X " early in the description
    if let Some(in_pos) = desc_lower.find(" in ")
        && in_pos < 50
    {
        // Only look near the start
        let after_in = &description[in_pos + 4..];
        if let Some(pkg) = extract_first_word(after_in) {
            let pkg_lower = pkg.to_lowercase();
            if !is_noise_word(&pkg_lower) && pkg.len() >= 2 && pkg.len() <= 30 {
                return Some(pkg.to_string());
            }
        }
    }

    None
}

/// Capitalize package name appropriately
fn capitalize_package_name(name: &str) -> String {
    // Some packages have specific capitalization
    match name {
        "busybox" => "BusyBox".to_string(),
        "openssl" => "OpenSSL".to_string(),
        "libssl" => "libssl".to_string(),
        "libcrypto" => "libcrypto".to_string(),
        "openssh" => "OpenSSH".to_string(),
        "sqlite" | "sqlite3" => "SQLite".to_string(),
        "mysql" => "MySQL".to_string(),
        "postgresql" => "PostgreSQL".to_string(),
        "libxml2" => "libxml2".to_string(),
        "libxslt" => "libxslt".to_string(),
        "libjpeg" => "libjpeg".to_string(),
        "libpng" => "libpng".to_string(),
        "systemd" => "systemd".to_string(),
        "linux" | "kernel" | "linux-kernel" => "Linux kernel".to_string(),
        "glibc" => "glibc".to_string(),
        "musl" => "musl".to_string(),
        "pcre" | "pcre2" => "PCRE".to_string(),
        "libpcre" | "libpcre2" => "libpcre".to_string(),
        "zlib" => "zlib".to_string(),
        "curl" | "libcurl" => "cURL".to_string(),
        "u-boot" => "U-Boot".to_string(),
        _ => {
            // Default: capitalize first letter
            let mut chars = name.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        }
    }
}

/// Extract the word immediately before a position
fn extract_word_before(text: &str) -> Option<&str> {
    let trimmed = text.trim_end();
    let last_space = trimmed.rfind(|c: char| c.is_whitespace() || c == '(' || c == ',')?;
    let word = &trimmed[last_space + 1..];
    if word.is_empty() { None } else { Some(word) }
}

/// Extract the first word from text
fn extract_first_word(text: &str) -> Option<&str> {
    let trimmed = text.trim_start();
    let end = trimmed.find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '.')?;
    let word = &trimmed[..end];
    if word.is_empty() { None } else { Some(word) }
}

/// Check if a word is likely not a package name
fn is_noise_word(word: &str) -> bool {
    const NOISE: &[&str] = &[
        "a",
        "an",
        "the",
        "this",
        "that",
        "these",
        "those",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "must",
        "vulnerability",
        "vulnerabilities",
        "issue",
        "issues",
        "flaw",
        "flaws",
        "bug",
        "bugs",
        "error",
        "errors",
        "problem",
        "problems",
        "attack",
        "attacker",
        "attackers",
        "remote",
        "local",
        "user",
        "users",
        "function",
        "functions",
        "method",
        "methods",
        "file",
        "files",
        "memory",
        "buffer",
        "heap",
        "stack",
        "overflow",
        "underflow",
        "corruption",
        "leak",
        "injection",
        "code",
        "execution",
        "denial",
        "service",
        "access",
        "control",
        "certain",
        "some",
        "all",
        "any",
        "many",
        "multiple",
        "allows",
        "allow",
        "allowed",
        "enabling",
        "enables",
        "enable",
        "causes",
        "cause",
        "caused",
        "leading",
        "leads",
        "lead",
        "via",
        "through",
        "using",
        "when",
        "where",
        "which",
        "what",
        "version",
        "versions",
        "release",
        "releases",
        "component",
        "components",
        "module",
        "modules",
        "package",
        "packages",
        "application",
        "applications",
        "program",
        "programs",
        "software",
        "system",
        "systems",
        "server",
        "servers",
        "client",
        "clients",
        "library",
        "libraries",
        "framework",
        "frameworks",
        "and",
        "or",
        "but",
        "not",
        "with",
        "without",
        "for",
        "from",
        "to",
        "of",
        "on",
        "at",
        "by",
        "as",
        "if",
        "so",
        "than",
        "discovered",
        "found",
        "identified",
        "reported",
        "fixed",
        "cve",
        "nvd",
        "cwe",
    ];
    NOISE.contains(&word)
}

/// Cached vulnerability row data for display
#[derive(Debug, Clone)]
pub struct VulnRow {
    pub vuln_id: String,
    pub severity: String,
    pub cvss: Option<f64>,
    pub component_name: String,
    #[allow(dead_code)]
    pub component_id: String,
    pub description: Option<String>,
    pub affected_count: usize,
    pub affected_components: Vec<String>,
    pub cwes: Vec<String>,
    /// Published date
    pub published: Option<chrono::DateTime<chrono::Utc>>,
    /// Affected version ranges
    pub affected_versions: Vec<String>,
    /// Source database
    pub source: String,
    /// Whether in KEV catalog
    pub is_kev: bool,
    /// VEX state for this vulnerability (per-vuln or component-level)
    pub vex_state: Option<crate::model::VexState>,
    /// Grouped display names for affected components (dedupe smart grouping)
    pub grouped_components: Vec<(String, usize)>,
}

use std::collections::HashSet;
use std::sync::Arc;

/// A display item in the vulnerability list (either a group header or a vuln row).
#[derive(Debug, Clone)]
pub enum VulnDisplayItem {
    GroupHeader {
        label: String,
        count: usize,
        expanded: bool,
    },
    Vuln(usize), // index into VulnCache.vulns
}

/// Build display items from cached vulns based on grouping mode and expansion state.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn build_display_items(
    vulns: &[VulnRow],
    group_by: &VulnGroupBy,
    expanded: &HashSet<String>,
) -> Vec<VulnDisplayItem> {
    if matches!(group_by, VulnGroupBy::Flat) {
        return vulns
            .iter()
            .enumerate()
            .map(|(i, _)| VulnDisplayItem::Vuln(i))
            .collect();
    }

    // Group vulns by the grouping key, preserving insertion order
    let mut groups: indexmap::IndexMap<String, Vec<usize>> = indexmap::IndexMap::new();
    for (i, v) in vulns.iter().enumerate() {
        let key = match group_by {
            VulnGroupBy::Severity => v.severity.clone(),
            VulnGroupBy::Component => {
                if v.affected_count > 1 {
                    // Use smart grouped name if available
                    v.grouped_components
                        .first()
                        .map_or_else(|| v.component_name.clone(), |(name, _)| name.clone())
                } else {
                    extract_component_display_name(&v.component_name, v.description.as_deref())
                }
            }
            VulnGroupBy::Flat => unreachable!(),
        };
        groups.entry(key).or_default().push(i);
    }

    // For severity grouping, sort by severity order
    if matches!(group_by, VulnGroupBy::Severity) {
        use crate::tui::shared::vulnerabilities::severity_rank;
        groups.sort_by(|a, _, b, _| severity_rank(a).cmp(&severity_rank(b)));
    }

    let auto_expand_all = groups.len() == 1;
    let mut items = Vec::new();
    for (label, indices) in &groups {
        let is_expanded = auto_expand_all || expanded.contains(label);
        items.push(VulnDisplayItem::GroupHeader {
            label: label.clone(),
            count: indices.len(),
            expanded: is_expanded,
        });
        if is_expanded {
            for &idx in indices {
                items.push(VulnDisplayItem::Vuln(idx));
            }
        }
    }
    items
}

/// Cached vulnerability list with metadata (wrapped in Arc for cheap cloning)
#[derive(Debug, Clone, Default)]
pub struct VulnCache {
    pub vulns: Vec<VulnRow>,
    pub has_any_cvss: bool,
    pub all_same_component: bool,
    /// Whether any vuln affects multiple components (for column header decision)
    pub has_multi_affected: bool,
    pub total_unfiltered: usize,
}

/// Arc-wrapped cache for zero-cost cloning during render
pub type VulnCacheRef = Arc<VulnCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_from_description_busybox() {
        let desc = "BusyBox through 1.35.0 allows remote attackers to execute arbitrary code";
        assert_eq!(
            extract_package_from_description(desc),
            Some("BusyBox".to_string())
        );
    }

    #[test]
    fn test_extract_package_from_description_in_pattern() {
        let desc = "A vulnerability in OpenSSL allows denial of service";
        assert_eq!(
            extract_package_from_description(desc),
            Some("OpenSSL".to_string())
        );
    }

    #[test]
    fn test_extract_package_from_description_before_pattern() {
        let desc = "zlib before 1.2.12 allows memory corruption";
        assert_eq!(
            extract_package_from_description(desc),
            Some("zlib".to_string())
        );
    }

    #[test]
    fn test_extract_package_from_description_pcre() {
        let desc = "PCRE before 8.45 has a buffer overflow in pcre_compile";
        assert_eq!(
            extract_package_from_description(desc),
            Some("PCRE".to_string())
        );
    }

    #[test]
    fn test_extract_package_from_description_libcurl() {
        let desc = "An issue was discovered in curl before 7.83.1";
        assert_eq!(
            extract_package_from_description(desc),
            Some("cURL".to_string())
        );
    }

    #[test]
    fn test_is_cryptic_name_hash() {
        assert!(is_cryptic_name("./6488064-48136192.squ"));
        assert!(is_cryptic_name("a1b2c3d4e5f6-7890abcd"));
    }

    #[test]
    fn test_is_cryptic_name_numeric() {
        assert!(is_cryptic_name("./12345678.img"));
    }

    #[test]
    fn test_is_cryptic_name_meaningful() {
        assert!(!is_cryptic_name("busybox"));
        assert!(!is_cryptic_name("libssl.so"));
        assert!(!is_cryptic_name("openssl-1.1.1"));
    }

    #[test]
    fn test_extract_component_display_name_with_description() {
        let name = "./6488064-48136192.squ";
        let desc = Some("BusyBox through 1.35.0 allows remote attackers");
        assert_eq!(
            extract_component_display_name(name, desc),
            "BusyBox".to_string()
        );
    }

    #[test]
    fn test_extract_component_display_name_meaningful_name() {
        let name = "openssl-1.1.1";
        let desc = Some("OpenSSL has a vulnerability");
        // Should use the component name since it's meaningful
        assert_eq!(
            extract_component_display_name(name, desc),
            "openssl-1.1.1".to_string()
        );
    }

    #[test]
    fn test_clean_component_name() {
        assert_eq!(clean_component_name("./path/to/busybox.squ"), "busybox");
        // Hash-like names get prefixed with "file:" and truncated
        let result = clean_component_name("./abc123-def456.squashfs");
        assert!(result.starts_with("file:"));
    }
}
