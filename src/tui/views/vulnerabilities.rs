//! Vulnerabilities view with master-detail layout.

use crate::diff::SlaStatus;
use crate::model::{Component, VulnerabilityRef};
use crate::tui::app::{App, AppMode, DiffVulnItem, DiffVulnStatus, VulnFilter, VulnSort};
use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

/// Vulnerability detail tuple: (status, id, severity, cvss, component, description, cwes, source).
type VulnDetail = (String, String, String, Option<f32>, String, Option<String>, Vec<String>, String);

/// Render item for grouped vulnerability display.
enum VulnRenderItem {
    /// A component group header row
    ComponentHeader {
        name: String,
        vuln_count: usize,
        max_severity: String,
        expanded: bool,
    },
    /// A vulnerability row (index into the underlying vuln list)
    VulnRow(usize),
}

/// Pre-built vulnerability list to avoid rebuilding on each render call.
/// Built once per frame in `render_vulnerabilities` and passed to sub-functions.
pub enum VulnListData<'a> {
    Diff(Vec<DiffVulnItem<'a>>),
    View(Vec<(&'a Component, &'a VulnerabilityRef)>),
    Empty,
}

pub fn render_vulnerabilities(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Filter bar + stats
            Constraint::Min(10),   // Main content
        ])
        .split(area);

    // Filter bar with stats
    render_filter_bar(frame, chunks[0], app);

    // Build vulnerability list once per frame (performance optimization)
    // Use efficient count methods where available, then build list only once for rendering
    let total_unfiltered = match app.mode {
        AppMode::Diff => {
            // Use efficient count method (doesn't build/sort full list)
            app.tabs.vulnerabilities.total = app.diff_vulnerability_count();
            app.data.diff_result
                .as_ref()
                .map_or(0, |r| {
                    r.vulnerabilities.introduced.len()
                        + r.vulnerabilities.resolved.len()
                        + r.vulnerabilities.persistent.len()
                })
        }
        AppMode::View => {
            // For view mode, build list to count (filter logic is complex)
            let items = collect_view_vulns(app);
            let total = app
                .data.sbom
                .as_ref()
                .map_or(0, |s| s.all_vulnerabilities().len());
            app.tabs.vulnerabilities.total = items.len();
            total
        }
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {
            app.tabs.vulnerabilities.total = 0;
            0
        }
    };
    app.tabs.vulnerabilities.clamp_selection();

    // When in grouped mode, update total to match visible render items count
    // (must happen before building vuln_data to avoid borrow conflicts)
    if app.tabs.vulnerabilities.group_by_component {
        let grouped_count = count_grouped_items(app);
        app.tabs.vulnerabilities.total = grouped_count;
        app.tabs.vulnerabilities.clamp_selection();
    }

    // Build the list data once for rendering (uses cache when available)
    if app.mode == AppMode::Diff {
        app.ensure_vulnerability_cache();
    }
    let vuln_data = match app.mode {
        AppMode::Diff => VulnListData::Diff(app.diff_vulnerability_items_from_cache()),
        AppMode::View => VulnListData::View(collect_view_vulns(app)),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => VulnListData::Empty,
    };

    // Master-detail layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    // Vulnerability table (master)
    render_vuln_table(frame, content_chunks[0], app, &vuln_data, total_unfiltered);

    // Detail panel
    render_detail_panel(frame, content_chunks[1], app, &vuln_data);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &App) {
    let filter = app.tabs.vulnerabilities.filter;
    let sort = app.tabs.vulnerabilities.sort_by;

    let sort_label = sort.label();

    let mut spans = vec![
        Span::styled("Filter: ", Style::default().fg(colors().text_muted)),
        filter_badge(filter),
        Span::raw("  "),
        Span::styled("[s]", Style::default().fg(colors().accent)),
        Span::styled(" Sort: ", Style::default().fg(colors().text_muted)),
        Span::styled(sort_label, Style::default().fg(colors().accent).bold()),
        Span::raw("  "),
    ];

    // Add stats based on mode
    match app.mode {
        AppMode::Diff => {
            if let Some(result) = &app.data.diff_result {
                spans.extend(vec![
                    Span::styled("│ ", Style::default().fg(colors().border)),
                    Span::styled("+ ", Style::default().fg(colors().removed).bold()),
                    Span::styled(
                        format!("{} introduced  ", result.summary.vulnerabilities_introduced),
                        Style::default().fg(colors().text),
                    ),
                    Span::styled("- ", Style::default().fg(colors().added).bold()),
                    Span::styled(
                        format!("{} resolved  ", result.summary.vulnerabilities_resolved),
                        Style::default().fg(colors().text),
                    ),
                    Span::styled("= ", Style::default().fg(colors().modified).bold()),
                    Span::styled(
                        format!("{} persistent", result.summary.vulnerabilities_persistent),
                        Style::default().fg(colors().text),
                    ),
                ]);

                // Add enrichment stats if available
                #[cfg(feature = "enrichment")]
                if let Some(stats) = app.combined_enrichment_stats() {
                    if stats.total_vulns_found > 0 {
                        spans.extend(vec![
                            Span::styled("  │ ", Style::default().fg(colors().border)),
                            Span::styled("OSV ", Style::default().fg(colors().accent).bold()),
                            Span::styled(
                                format!("+{}", stats.total_vulns_found),
                                Style::default().fg(colors().accent),
                            ),
                        ]);
                    }
                }
            }
        }
        AppMode::View => {
            if let Some(sbom) = &app.data.sbom {
                let counts = sbom.vulnerability_counts();
                let scheme = colors();
                spans.extend(vec![
                    Span::styled("│ ", Style::default().fg(scheme.border)),
                    Span::styled(
                        " C ",
                        Style::default()
                            .fg(scheme.severity_badge_fg("critical"))
                            .bg(scheme.critical)
                            .bold(),
                    ),
                    Span::styled(
                        format!(" {}  ", counts.critical),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(
                        " H ",
                        Style::default()
                            .fg(scheme.severity_badge_fg("high"))
                            .bg(scheme.high)
                            .bold(),
                    ),
                    Span::styled(
                        format!(" {}  ", counts.high),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(
                        " M ",
                        Style::default()
                            .fg(scheme.severity_badge_fg("medium"))
                            .bg(scheme.medium)
                            .bold(),
                    ),
                    Span::styled(
                        format!(" {}  ", counts.medium),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(
                        " L ",
                        Style::default()
                            .fg(scheme.severity_badge_fg("low"))
                            .bg(scheme.low)
                            .bold(),
                    ),
                    Span::styled(format!(" {}", counts.low), Style::default().fg(scheme.text)),
                ]);
            }
        }
        _ => {}
    }

    // Add grouped mode indicator
    let grouped_label = if app.tabs.vulnerabilities.group_by_component {
        "Grouped"
    } else {
        "List"
    };
    spans.extend(vec![
        Span::styled("  │  ", Style::default().fg(colors().border)),
        Span::styled("View: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!(" {grouped_label} "),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(if app.tabs.vulnerabilities.group_by_component {
                    colors().secondary
                } else {
                    colors().primary
                })
                .bold(),
        ),
    ]);

    // Add hints
    spans.extend(vec![
        Span::styled("  │  ", Style::default().fg(colors().border)),
        Span::styled("[f]", Style::default().fg(colors().accent)),
        Span::styled(" filter  ", Style::default().fg(colors().text_muted)),
        Span::styled("[s]", Style::default().fg(colors().accent)),
        Span::styled(" sort  ", Style::default().fg(colors().text_muted)),
        Span::styled("[g]", Style::default().fg(colors().accent)),
        Span::styled(" group", Style::default().fg(colors().text_muted)),
    ]);

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(colors().border)),
    );

    frame.render_widget(paragraph, area);
}

fn filter_badge(filter: VulnFilter) -> Span<'static> {
    let (label, color) = match filter {
        VulnFilter::All => ("All", colors().primary),
        VulnFilter::Introduced => ("Introduced", colors().removed),
        VulnFilter::Resolved => ("Resolved", colors().added),
        VulnFilter::Critical => ("Critical", colors().critical),
        VulnFilter::High => ("High+", colors().high),
        VulnFilter::Kev => ("KEV", colors().kev()),
        VulnFilter::Direct => ("Direct", colors().direct_dep()),
        VulnFilter::Transitive => ("Transitive", colors().transitive_dep()),
        VulnFilter::VexActionable => ("VEX Actionable", colors().primary),
    };

    Span::styled(
        format!(" {label} "),
        Style::default().fg(colors().badge_fg_dark).bg(color).bold(),
    )
}

fn render_vuln_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    vuln_data: &VulnListData,
    total_unfiltered: usize,
) {
    let header = Row::new(vec![
        Cell::from("Status").style(Style::default().fg(colors().accent).bold()),
        Cell::from("ID").style(Style::default().fg(colors().accent).bold()),
        Cell::from("CVSS").style(Style::default().fg(colors().accent).bold()),
        Cell::from("SLA").style(Style::default().fg(colors().accent).bold()),
        Cell::from("Component").style(Style::default().fg(colors().accent).bold()),
    ])
    .height(1);

    // Use pre-built vulnerability list (state already updated in render_vulnerabilities)
    let cached_depths = &app.tabs.dependencies.cached_depths;

    // Build rows (flat or grouped)
    let rows: Vec<Row> = if app.tabs.vulnerabilities.group_by_component {
        build_grouped_rows(app, vuln_data, cached_depths)
    } else {
        match vuln_data {
            VulnListData::Diff(items) => get_diff_vuln_rows(items),
            VulnListData::View(items) => get_view_vuln_rows(items, cached_depths),
            VulnListData::Empty => vec![],
        }
    };

    // Handle empty states
    if rows.is_empty() {
        if total_unfiltered == 0 {
            widgets::render_empty_state_enhanced(
                frame,
                area,
                "✓",
                "No vulnerabilities detected",
                Some("Great news! No known vulnerabilities were found"),
                None,
            );
        } else {
            widgets::render_no_results_state(
                frame,
                area,
                "Filter",
                app.tabs.vulnerabilities.filter.label(),
            );
        }
        return;
    }

    let widths = [
        Constraint::Length(12),
        Constraint::Percentage(25),
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Percentage(30),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Vulnerabilities ")
                .title_style(Style::default().fg(colors().primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().border)),
        )
        .row_highlight_style(Style::default().bg(colors().selection))
        .highlight_symbol("▶ ");

    let mut state = TableState::default();
    state.select(Some(app.tabs.vulnerabilities.selected));

    frame.render_stateful_widget(table, area, &mut state);
}

/// Build the grouped render items list from vulnerability data.
/// Groups vulns by component name, renders headers with expand/collapse.
fn build_grouped_render_items(
    app: &App,
    vuln_data: &VulnListData,
) -> Vec<VulnRenderItem> {
    let mut items = Vec::new();

    match vuln_data {
        VulnListData::Diff(diff_items) => {
            // Group by component name
            let mut groups: indexmap::IndexMap<String, Vec<(usize, &DiffVulnItem)>> =
                indexmap::IndexMap::new();
            for (idx, item) in diff_items.iter().enumerate() {
                groups
                    .entry(item.vuln.component_name.clone())
                    .or_default()
                    .push((idx, item));
            }

            // Sort groups by max severity
            let mut sorted_groups: Vec<_> = groups.into_iter().collect();
            sorted_groups.sort_by(|a, b| {
                let max_sev_a = a.1.iter().map(|(_, it)| severity_rank(&it.vuln.severity)).min().unwrap_or(99);
                let max_sev_b = b.1.iter().map(|(_, it)| severity_rank(&it.vuln.severity)).min().unwrap_or(99);
                max_sev_a.cmp(&max_sev_b)
            });

            for (comp_name, vulns) in sorted_groups {
                let max_sev = vulns
                    .iter()
                    .map(|(_, it)| it.vuln.severity.as_str())
                    .min_by_key(|s| severity_rank(s))
                    .unwrap_or("Unknown")
                    .to_string();
                let expanded = app.tabs.vulnerabilities.is_group_expanded(&comp_name);

                items.push(VulnRenderItem::ComponentHeader {
                    name: comp_name,
                    vuln_count: vulns.len(),
                    max_severity: max_sev,
                    expanded,
                });

                if expanded {
                    for (idx, _) in &vulns {
                        items.push(VulnRenderItem::VulnRow(*idx));
                    }
                }
            }
        }
        VulnListData::View(view_items) => {
            // Group by component name (track index only, look up items later)
            let mut groups: indexmap::IndexMap<String, Vec<usize>> =
                indexmap::IndexMap::new();
            for (idx, item) in view_items.iter().enumerate() {
                groups
                    .entry(item.0.name.clone())
                    .or_default()
                    .push(idx);
            }

            // Sort groups by max severity
            let mut sorted_groups: Vec<_> = groups.into_iter().collect();
            sorted_groups.sort_by(|a, b| {
                let max_sev_a = a.1.iter().filter_map(|&i| view_items.get(i)).map(|it| {
                    severity_rank(&it.1.severity.as_ref().map(std::string::ToString::to_string).unwrap_or_default())
                }).min().unwrap_or(99);
                let max_sev_b = b.1.iter().filter_map(|&i| view_items.get(i)).map(|it| {
                    severity_rank(&it.1.severity.as_ref().map(std::string::ToString::to_string).unwrap_or_default())
                }).min().unwrap_or(99);
                max_sev_a.cmp(&max_sev_b)
            });

            for (comp_name, vuln_indices) in sorted_groups {
                let max_sev = vuln_indices
                    .iter()
                    .filter_map(|&i| view_items.get(i))
                    .map(|it| {
                        it.1.severity
                            .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string)
                    })
                    .min_by_key(|s| severity_rank(s))
                    .unwrap_or_else(|| "Unknown".to_string());
                let expanded = app.tabs.vulnerabilities.is_group_expanded(&comp_name);

                items.push(VulnRenderItem::ComponentHeader {
                    name: comp_name,
                    vuln_count: vuln_indices.len(),
                    max_severity: max_sev,
                    expanded,
                });

                if expanded {
                    for &idx in &vuln_indices {
                        items.push(VulnRenderItem::VulnRow(idx));
                    }
                }
            }
        }
        VulnListData::Empty => {}
    }

    items
}

use crate::tui::shared::vulnerabilities::severity_rank;

/// Build table rows for grouped mode.
fn build_grouped_rows(
    app: &App,
    vuln_data: &VulnListData<'_>,
    cached_depths: &std::collections::HashMap<String, usize>,
) -> Vec<Row<'static>> {
    let render_items = build_grouped_render_items(app, vuln_data);
    let scheme = colors();

    render_items
        .iter()
        .map(|item| match item {
            VulnRenderItem::ComponentHeader {
                name,
                vuln_count,
                max_severity,
                expanded,
            } => {
                let arrow = if *expanded { "▼" } else { "▶" };
                let sev_color = scheme.severity_color(max_severity);
                let bg_tint = scheme.severity_bg_tint(max_severity);

                Row::new(vec![
                    Cell::from(Span::styled(
                        format!(" {} ", max_severity.chars().next().unwrap_or('?')),
                        Style::default()
                            .fg(scheme.severity_badge_fg(max_severity))
                            .bg(sev_color)
                            .bold(),
                    )),
                    Cell::from(Line::from(vec![
                        Span::styled(
                            format!("{arrow} "),
                            Style::default().fg(scheme.accent),
                        ),
                        Span::styled(
                            name.clone(),
                            Style::default().fg(scheme.text).bold(),
                        ),
                    ])),
                    Cell::from(""),
                    Cell::from(Span::styled(
                        format!("{vuln_count} {}", if *vuln_count == 1 { "CVE" } else { "CVEs" }),
                        Style::default().fg(scheme.text_muted),
                    )),
                    Cell::from(""),
                ])
                .style(Style::default().bg(bg_tint))
            }
            VulnRenderItem::VulnRow(idx) => match vuln_data {
                VulnListData::Diff(items) => {
                    items.get(*idx).map_or_else(
                        || Row::new(vec![Cell::from("")]),
                        |row| build_single_diff_row(row, &scheme),
                    )
                }
                VulnListData::View(items) => {
                    items.get(*idx).map_or_else(
                        || Row::new(vec![Cell::from("")]),
                        |item| build_single_view_row(item, cached_depths, &scheme),
                    )
                }
                VulnListData::Empty => Row::new(vec![Cell::from("")]),
            },
        })
        .collect()
}

/// Build a single diff-mode row (extracted for reuse in grouped mode).
fn build_single_diff_row(
    item: &DiffVulnItem<'_>,
    scheme: &crate::tui::theme::ColorScheme,
) -> Row<'static> {
    use crate::tui::shared::vulnerabilities::{render_kev_badge_spans, render_depth_badge_spans};

    let (status_label, status_bg, status_fg, row_style) = match item.status {
        DiffVulnStatus::Introduced => (
            " + NEW ",
            scheme.removed,
            scheme.badge_fg_light,
            Style::default().fg(scheme.text),
        ),
        DiffVulnStatus::Resolved => (
            " - FIXED ",
            scheme.added,
            scheme.badge_fg_dark,
            Style::default().fg(scheme.added),
        ),
        DiffVulnStatus::Persistent => (
            " = PERSIST ",
            scheme.modified,
            scheme.badge_fg_dark,
            Style::default().fg(scheme.text),
        ),
    };

    let vuln = item.vuln;

    // Build ID cell with KEV and DIR/TRN badges
    let mut id_spans: Vec<Span<'_>> = Vec::new();
    id_spans.extend(render_kev_badge_spans(vuln.is_kev, scheme));
    id_spans.extend(render_depth_badge_spans(vuln.component_depth.map(|d| d as usize), scheme));
    id_spans.push(Span::raw(vuln.id.clone()));

    let sla_cell = format_sla_cell(
        vuln.sla_status(),
        vuln.days_since_published,
        scheme,
    );

    let bg_tint = if item.status == DiffVulnStatus::Resolved {
        Color::Reset
    } else {
        scheme.severity_bg_tint(&vuln.severity)
    };

    Row::new(vec![
        Cell::from(Span::styled(
            status_label,
            Style::default().fg(status_fg).bg(status_bg).bold(),
        )),
        Cell::from(Line::from(id_spans)),
        Cell::from(
            vuln.cvss_score.map_or_else(|| "-".to_string(), |s| format!("{s:.1}")),
        ),
        sla_cell,
        Cell::from(widgets::truncate_str(&vuln.component_name, 30)),
    ])
    .style(row_style.bg(bg_tint))
}

/// Build a single view-mode row (extracted for reuse in grouped mode).
fn build_single_view_row(
    item: &(&Component, &VulnerabilityRef),
    cached_depths: &std::collections::HashMap<String, usize>,
    scheme: &crate::tui::theme::ColorScheme,
) -> Row<'static> {
    use crate::tui::shared::vulnerabilities::{render_kev_badge_spans, render_depth_badge_spans};

    let (comp, vuln) = item;
    let severity = vuln
        .severity
        .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
    let sev_color = scheme.severity_color(&severity);

    let mut id_spans: Vec<Span<'_>> = Vec::new();
    id_spans.extend(render_kev_badge_spans(vuln.is_kev, scheme));
    let comp_id = comp.canonical_id.to_string();
    let depth = cached_depths.get(&comp_id).copied();
    id_spans.extend(render_depth_badge_spans(depth, scheme));
    id_spans.push(Span::raw(vuln.id.clone()));

    let sla_cell = format_view_vuln_sla_cell(vuln, &severity, scheme);
    let bg_tint = scheme.severity_bg_tint(&severity);

    Row::new(vec![
        Cell::from(Span::styled(
            format!(" {} ", severity.chars().next().unwrap_or('?')),
            Style::default()
                .fg(scheme.severity_badge_fg(&severity))
                .bg(sev_color)
                .bold(),
        )),
        Cell::from(Line::from(id_spans)),
        Cell::from(
            vuln.max_cvss_score().map_or_else(|| "-".to_string(), |s| format!("{s:.1}")),
        ),
        sla_cell,
        Cell::from(widgets::truncate_str(&comp.name, 30)),
    ])
    .style(Style::default().fg(scheme.text).bg(bg_tint))
}

fn render_detail_panel(frame: &mut Frame, area: Rect, app: &App, vuln_data: &VulnListData) {
    let selected = app.tabs.vulnerabilities.selected;

    // In grouped mode, resolve the selected index through the render items
    let vuln_info = if app.tabs.vulnerabilities.group_by_component {
        let render_items = build_grouped_render_items(app, vuln_data);
        match render_items.get(selected) {
            Some(VulnRenderItem::VulnRow(idx)) => match vuln_data {
                VulnListData::Diff(items) => get_diff_vuln_at(items, *idx),
                VulnListData::View(items) => get_view_vuln_at(items, *idx),
                VulnListData::Empty => None,
            },
            Some(VulnRenderItem::ComponentHeader { name, vuln_count, max_severity, .. }) => {
                // Show a summary for the component group header
                Some((
                    "Component Group".to_string(),
                    name.clone(),
                    max_severity.clone(),
                    None,
                    name.clone(),
                    Some(format!("{vuln_count} vulnerabilities in this component")),
                    Vec::new(),
                    String::new(),
                ))
            }
            None => None,
        }
    } else {
        match vuln_data {
            VulnListData::Diff(items) => get_diff_vuln_at(items, selected),
            VulnListData::View(items) => get_view_vuln_at(items, selected),
            VulnListData::Empty => None,
        }
    };

    if let Some((status, id, severity, cvss, component, description, cwes, source)) = vuln_info {
        let scheme = colors();
        let sev_color = scheme.severity_color(&severity);

        let source_color = crate::tui::shared::vulnerabilities::source_color(&source, &scheme);

        let mut lines = vec![
            // Severity badge
            Line::from(vec![
                Span::styled(
                    format!(" {} ", severity.chars().next().unwrap_or('?')),
                    Style::default()
                        .fg(scheme.severity_badge_fg(&severity))
                        .bg(sev_color)
                        .bold(),
                ),
                Span::styled(
                    format!(" {severity} "),
                    Style::default().fg(sev_color).bold(),
                ),
                cvss.map_or_else(
                    || Span::raw(""),
                    |score| Span::styled(
                        format!("  CVSS: {score:.1}"),
                        Style::default().fg(colors().text),
                    ),
                ),
            ]),
            Line::from(""),
            // Vulnerability ID
            Line::from(vec![
                Span::styled("ID: ", Style::default().fg(colors().text_muted)),
                Span::styled(&id, Style::default().fg(colors().text).bold()),
            ]),
            // Source
            Line::from(vec![
                Span::styled("Source: ", Style::default().fg(colors().text_muted)),
                Span::styled(
                    format!("[{source}]"),
                    Style::default().fg(source_color).bold(),
                ),
            ]),
            // Status
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(colors().text_muted)),
                status_span(&status),
            ]),
            // Component
            Line::from(vec![
                Span::styled("Component: ", Style::default().fg(colors().text_muted)),
                Span::styled(&component, Style::default().fg(colors().secondary)),
            ]),
        ];

        // Description (inline label, no heavy borders)
        if let Some(desc) = description {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Description: ", Style::default().fg(colors().text_muted)),
            ]));
            let max_width = area.width.saturating_sub(4) as usize;
            for wrapped_line in crate::tui::shared::vulnerabilities::word_wrap(&desc, max_width) {
                lines.push(Line::styled(
                    wrapped_line,
                    Style::default().fg(colors().text).italic(),
                ));
            }
        }

        // CWEs (inline label)
        lines.extend(crate::tui::shared::vulnerabilities::render_vuln_cwe_lines(&cwes, 3));

        // Attack Paths (show how to reach this vulnerable component from entry points)
        if matches!(app.mode, AppMode::Diff | AppMode::View) {
            // Use cached forward graph instead of rebuilding every frame
            let forward_graph = &app.tabs.dependencies.cached_forward_graph;
            let reverse_graph = &app.tabs.dependencies.cached_reverse_graph;

            // Find root components (those with no dependencies pointing to them)
            let all_components: Vec<String> = reverse_graph.keys().cloned().collect();
            let roots =
                crate::tui::security::find_root_components(&all_components, reverse_graph);

            // Find attack paths to this vulnerable component
            let attack_paths = crate::tui::security::find_attack_paths(
                &component,
                forward_graph,
                &roots,
                3,  // max 3 paths
                5,  // max depth 5
            );

            if !attack_paths.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("Attack Paths ({}): ", attack_paths.len()),
                        Style::default().fg(colors().high).bold(),
                    ),
                ]));

                for (i, path) in attack_paths.iter().take(3).enumerate() {
                    let risk_color = if path.risk_score >= 70 {
                        colors().critical
                    } else if path.risk_score >= 40 {
                        colors().high
                    } else {
                        colors().medium
                    };

                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {}. ", i + 1),
                            Style::default().fg(colors().text_muted),
                        ),
                        Span::styled(
                            format!("[{}]", path.description()),
                            Style::default().fg(risk_color).bold(),
                        ),
                    ]));

                    // Show path (truncated if too long)
                    let path_str = if path.path.len() <= 3 {
                        path.format()
                    } else {
                        format!(
                            "{} → ... → {}",
                            path.path.first().unwrap_or(&String::new()),
                            path.path.last().unwrap_or(&String::new())
                        )
                    };
                    lines.push(Line::from(vec![
                        Span::styled("     ", Style::default()),
                        Span::styled(
                            widgets::truncate_str(&path_str, area.width as usize - 8),
                            Style::default().fg(colors().text).italic(),
                        ),
                    ]));
                }
            }
        }

        // Quick actions hint
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("[o]", Style::default().fg(colors().accent)),
            Span::styled(" open CVE  ", Style::default().fg(colors().text_muted)),
            Span::styled("[Enter]", Style::default().fg(colors().accent)),
            Span::styled(" go to component", Style::default().fg(colors().text_muted)),
        ]));

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Vulnerability Details ")
                    .title_style(Style::default().fg(colors().primary).bold())
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(colors().primary)),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(detail, area);
    } else {
        render_empty_detail(frame, area);
    }
}

fn status_span(status: &str) -> Span<'static> {
    let (color, symbol) = match status.to_lowercase().as_str() {
        "introduced" => (colors().removed, "+"),
        "resolved" => (colors().added, "-"),
        "persistent" => (colors().modified, "="),
        _ => (colors().text, "•"),
    };

    Span::styled(format!("{symbol} {status}"), Style::default().fg(color))
}

fn render_empty_detail(frame: &mut Frame, area: Rect) {
    crate::tui::shared::components::render_empty_detail_panel(
        frame,
        area,
        " Vulnerability Details ",
        "⚠",
        "Select a vulnerability to view details",
        &[("[↑↓]", " navigate  "), ("[Enter]", " expand")],
        false,
    );
}

// Returns: (status, id, severity, cvss, component, description, cwes, source)
fn get_diff_vuln_at(
    items: &[crate::tui::app::DiffVulnItem<'_>],
    index: usize,
) -> Option<VulnDetail> {
    items.get(index).map(|item| {
        let vuln = item.vuln;
        (
            item.status.label().to_string(),
            vuln.id.clone(),
            vuln.severity.clone(),
            vuln.cvss_score,
            vuln.component_name.clone(),
            vuln.description.clone(),
            vuln.cwes.clone(),
            vuln.source.clone(),
        )
    })
}

fn collect_view_vulns(
    app: &App,
) -> Vec<(&crate::model::Component, &crate::model::VulnerabilityRef)> {
    let Some(sbom) = app.data.sbom.as_ref() else {
        return Vec::new();
    };
    let filter = &app.tabs.vulnerabilities.filter;
    let sort = &app.tabs.vulnerabilities.sort_by;

    // Get cached depths for Direct/Transitive filtering
    let cached_depths = &app.tabs.dependencies.cached_depths;

    let mut vulns: Vec<_> = sbom
        .all_vulnerabilities()
        .into_iter()
        .filter(|(comp, vuln)| {
            match filter {
                VulnFilter::All | VulnFilter::Introduced | VulnFilter::Resolved => true, // Introduced/Resolved are diff-mode only
                VulnFilter::Critical => {
                    vuln.severity.as_ref().map(std::string::ToString::to_string) == Some("Critical".to_string())
                }
                VulnFilter::High => {
                    let sev = vuln.severity.as_ref().map(std::string::ToString::to_string);
                    sev == Some("Critical".to_string()) || sev == Some("High".to_string())
                }
                VulnFilter::Kev => vuln.is_kev,
                VulnFilter::Direct => {
                    // Direct = depth 1 (immediate child of root)
                    let comp_id = comp.canonical_id.to_string();
                    cached_depths.get(&comp_id).copied() == Some(1)
                }
                VulnFilter::Transitive => {
                    // Transitive = depth > 1
                    let comp_id = comp.canonical_id.to_string();
                    cached_depths.get(&comp_id).is_some_and(|&d| d > 1)
                }
                VulnFilter::VexActionable => {
                    // Exclude components with VEX status NotAffected or Fixed
                    !matches!(
                        comp.vex_status.as_ref().map(|v| &v.status),
                        Some(crate::model::VexState::NotAffected | crate::model::VexState::Fixed)
                    )
                }
            }
        })
        .collect();

    match sort {
        VulnSort::Severity => {
            vulns.sort_by(|a, b| {
                let sev_order = |s: &Option<crate::model::Severity>| match s
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .as_deref()
                {
                    Some("Critical") => 0,
                    Some("High") => 1,
                    Some("Medium") => 2,
                    Some("Low") => 3,
                    _ => 4,
                };
                sev_order(&a.1.severity).cmp(&sev_order(&b.1.severity))
            });
        }
        VulnSort::Id => {
            vulns.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        }
        VulnSort::Component => {
            vulns.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        }
        VulnSort::FixUrgency => {
            // Sort by fix urgency (severity × blast radius × CVSS)
            let reverse_graph = &app.tabs.dependencies.cached_reverse_graph;
            vulns.sort_by(|a, b| {
                let urgency_a = calculate_view_vuln_urgency(a, reverse_graph);
                let urgency_b = calculate_view_vuln_urgency(b, reverse_graph);
                urgency_b.cmp(&urgency_a) // Higher urgency first
            });
        }
        VulnSort::CvssScore => {
            // Sort by CVSS score (highest first)
            vulns.sort_by(|a, b| {
                let score_a = a.1.max_cvss_score().unwrap_or(0.0);
                let score_b = b.1.max_cvss_score().unwrap_or(0.0);
                score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        VulnSort::SlaUrgency => {
            // Sort by SLA urgency (most overdue first)
            vulns.sort_by(|a, b| {
                let severity_a = a.1.severity.as_ref().map(std::string::ToString::to_string).unwrap_or_default();
                let severity_b = b.1.severity.as_ref().map(std::string::ToString::to_string).unwrap_or_default();
                let sla_a = calculate_view_vuln_sla_sort_key(a.1, &severity_a);
                let sla_b = calculate_view_vuln_sla_sort_key(b.1, &severity_b);
                sla_a.cmp(&sla_b)
            });
        }
    }

    vulns
}

// Returns: (status, id, severity, cvss, component, description, cwes, source)
fn get_view_vuln_at(
    items: &[(&crate::model::Component, &crate::model::VulnerabilityRef)],
    index: usize,
) -> Option<VulnDetail> {
    items.get(index).map(|(comp, vuln)| {
        let severity = vuln
            .severity
            .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
        (
            "Present".to_string(),
            vuln.id.clone(),
            severity,
            vuln.max_cvss_score(),
            comp.name.clone(),
            vuln.description.clone(),
            vuln.cwes.clone(),
            vuln.source.to_string(),
        )
    })
}

fn get_diff_vuln_rows(items: &[crate::tui::app::DiffVulnItem<'_>]) -> Vec<Row<'static>> {
    let scheme = colors();
    items.iter().map(|item| build_single_diff_row(item, &scheme)).collect()
}

fn get_view_vuln_rows(
    items: &[(&crate::model::Component, &crate::model::VulnerabilityRef)],
    cached_depths: &std::collections::HashMap<String, usize>,
) -> Vec<Row<'static>> {
    let scheme = colors();
    items.iter().map(|item| build_single_view_row(item, cached_depths, &scheme)).collect()
}

/// Format SLA cell for diff mode (using `VulnerabilityDetail`)
fn format_sla_cell(
    sla_status: SlaStatus,
    days_since_published: Option<i64>,
    scheme: &crate::tui::theme::ColorScheme,
) -> Cell<'static> {
    match sla_status {
        SlaStatus::Overdue(days) => Cell::from(Span::styled(
            format!("{days}d late"),
            Style::default().fg(scheme.critical).bold(),
        )),
        SlaStatus::DueSoon(days) => Cell::from(Span::styled(
            format!("{days}d left"),
            Style::default().fg(scheme.high),
        )),
        SlaStatus::OnTrack(days) => Cell::from(Span::styled(
            format!("{days}d left"),
            Style::default().fg(scheme.text_muted),
        )),
        SlaStatus::NoDueDate => {
            days_since_published.map_or_else(
                || Cell::from("-".to_string()),
                |age| Cell::from(Span::styled(
                    format!("{age}d old"),
                    Style::default().fg(scheme.text_muted),
                )),
            )
        }
    }
}

/// Format SLA cell for view mode (using `VulnerabilityRef`)
fn format_view_vuln_sla_cell(
    vuln: &VulnerabilityRef,
    severity: &str,
    scheme: &crate::tui::theme::ColorScheme,
) -> Cell<'static> {
    // Calculate days since published (published is DateTime<Utc>)
    let days_since_published = vuln.published.map(|dt| {
        let today = chrono::Utc::now().date_naive();
        (today - dt.date_naive()).num_days()
    });

    // Get KEV due date info (days_until_due returns i64, wrap in Some)
    let days_until_due = vuln.kev_info.as_ref().map(crate::model::KevInfo::days_until_due);

    // Calculate SLA status
    let sla_status = calculate_sla_status(days_until_due, days_since_published, severity);

    format_sla_cell(sla_status, days_since_published, scheme)
}

/// Calculate SLA status from raw data
fn calculate_sla_status(
    days_until_due: Option<i64>,
    days_since_published: Option<i64>,
    severity: &str,
) -> SlaStatus {
    // KEV due date takes priority
    if let Some(days) = days_until_due {
        if days < 0 {
            return SlaStatus::Overdue(-days);
        } else if days <= 3 {
            return SlaStatus::DueSoon(days);
        }
        return SlaStatus::OnTrack(days);
    }

    // Fall back to severity-based SLA
    if let Some(age_days) = days_since_published {
        let sla_days = match severity.to_lowercase().as_str() {
            "critical" => 1,
            "high" => 7,
            "medium" => 30,
            "low" => 90,
            _ => return SlaStatus::NoDueDate,
        };
        let remaining = sla_days - age_days;
        if remaining < 0 {
            return SlaStatus::Overdue(-remaining);
        } else if remaining <= 3 {
            return SlaStatus::DueSoon(remaining);
        }
        return SlaStatus::OnTrack(remaining);
    }

    SlaStatus::NoDueDate
}

/// Calculate SLA sort key for a vulnerability (lower = more urgent)
fn calculate_view_vuln_sla_sort_key(vuln: &VulnerabilityRef, severity: &str) -> i64 {
    // Calculate days since published (published is DateTime<Utc>)
    let days_since_published = vuln.published.map(|dt| {
        let today = chrono::Utc::now().date_naive();
        (today - dt.date_naive()).num_days()
    });

    // Get KEV due date info
    let days_until_due = vuln.kev_info.as_ref().map(crate::model::KevInfo::days_until_due);

    // Calculate SLA status
    let sla_status = calculate_sla_status(days_until_due, days_since_published, severity);

    match sla_status {
        SlaStatus::Overdue(days) => -(days + crate::tui::constants::SLA_OVERDUE_SORT_OFFSET), // Most urgent (negative, very low)
        SlaStatus::DueSoon(days) | SlaStatus::OnTrack(days) => days,
        SlaStatus::NoDueDate => i64::MAX,
    }
}

/// Calculate fix urgency for a vulnerability in view mode
fn calculate_view_vuln_urgency(
    vuln_data: &(&crate::model::Component, &crate::model::VulnerabilityRef),
    reverse_graph: &std::collections::HashMap<String, Vec<String>>,
) -> u8 {
    use crate::tui::security::{calculate_fix_urgency, severity_to_rank};

    let (comp, vuln) = vuln_data;
    let severity = vuln
        .severity
        .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
    let severity_rank = severity_to_rank(&severity);
    let cvss_score = vuln.max_cvss_score().unwrap_or(0.0);

    // Calculate blast radius for affected component
    let mut blast_radius = 0usize;
    if let Some(direct_deps) = reverse_graph.get(&comp.name) {
        blast_radius = direct_deps.len();
        // Add transitive count (simplified - just use direct for performance)
        for dep in direct_deps {
            if let Some(transitive) = reverse_graph.get(dep) {
                blast_radius += transitive.len();
            }
        }
    }

    calculate_fix_urgency(severity_rank, blast_radius, cvss_score)
}

/// Count the number of visible items in grouped mode without building full `VulnListData`.
/// Each component group adds 1 header + N vulns (if expanded).
fn count_grouped_items(app: &App) -> usize {
    match app.mode {
        AppMode::Diff => {
            let items = app.diff_vulnerability_items_from_cache();
            let mut groups: Vec<(String, usize)> = Vec::new();
            let mut group_map: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for item in &items {
                let name = &item.vuln.component_name;
                if let Some(&group_idx) = group_map.get(name) {
                    groups[group_idx].1 += 1;
                } else {
                    let group_idx = groups.len();
                    group_map.insert(name.clone(), group_idx);
                    groups.push((name.clone(), 1));
                }
            }

            let mut count = 0;
            for (comp_name, vuln_count) in &groups {
                count += 1; // header
                if app.tabs.vulnerabilities.is_group_expanded(comp_name) {
                    count += vuln_count;
                }
            }
            count
        }
        AppMode::View => {
            let vulns = collect_view_vulns(app);
            let mut groups: Vec<(String, usize)> = Vec::new();
            let mut group_map: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for (comp, _) in &vulns {
                let name = &comp.name;
                if let Some(&group_idx) = group_map.get(name) {
                    groups[group_idx].1 += 1;
                } else {
                    let group_idx = groups.len();
                    group_map.insert(name.clone(), group_idx);
                    groups.push((name.clone(), 1));
                }
            }

            let mut count = 0;
            for (comp_name, vuln_count) in &groups {
                count += 1; // header
                if app.tabs.vulnerabilities.is_group_expanded(comp_name) {
                    count += vuln_count;
                }
            }
            count
        }
        _ => 0,
    }
}
