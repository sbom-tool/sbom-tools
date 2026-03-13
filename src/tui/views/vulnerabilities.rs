//! Vulnerabilities view with master-detail layout.

use crate::diff::SlaStatus;
use crate::tui::app::{App, AppMode, DiffVulnItem, DiffVulnStatus, VulnFilter};
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

/// Structured vulnerability detail for the detail panel.
struct VulnDetailInfo {
    status: String,
    id: String,
    severity: String,
    cvss: Option<f32>,
    component: String,
    description: Option<String>,
    cwes: Vec<String>,
    source: String,
    remediation: Option<String>,
    fixed_version: Option<String>,
    is_kev: bool,
    is_ransomware: bool,
    affected_versions: Vec<String>,
    cvss_vector: Option<String>,
    published_age_days: Option<i64>,
    vex_state: Option<crate::model::VexState>,
    vex_justification: Option<crate::model::VexJustification>,
    vex_impact_statement: Option<String>,
}

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
    Empty,
}

pub fn render_vulnerabilities(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(widgets::FILTER_BAR_HEIGHT), // Filter bar + stats
            Constraint::Min(10),                            // Main content
        ])
        .split(area);

    // Filter bar with stats
    render_filter_bar(frame, chunks[0], ctx);

    // Compute total unfiltered count (totals/clamping already done in prepare_render)
    let total_unfiltered = match ctx.mode {
        AppMode::Diff => ctx.diff_result.map_or(0, |r| {
            r.vulnerabilities.introduced.len()
                + r.vulnerabilities.resolved.len()
                + r.vulnerabilities.persistent.len()
        }),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
    };

    // Build the list data once for rendering (cache already warmed in prepare_render)
    let vuln_data = match ctx.mode {
        AppMode::Diff => VulnListData::Diff(ctx.diff_vulnerability_items_from_cache()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => VulnListData::Empty,
    };

    // Pre-compute grouped render items once per frame (used by both table and detail panel)
    let grouped_items = if ctx.vulnerabilities.group_by_component {
        Some(build_grouped_render_items(ctx, &vuln_data))
    } else {
        None
    };

    // Master-detail layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(widgets::MASTER_DETAIL_SPLIT)
        .split(chunks[1]);

    // Vulnerability table (master)
    render_vuln_table(
        frame,
        content_chunks[0],
        ctx,
        &vuln_data,
        total_unfiltered,
        grouped_items.as_deref(),
    );

    // Detail panel
    render_detail_panel(
        frame,
        content_chunks[1],
        ctx,
        &vuln_data,
        grouped_items.as_deref(),
    );
}

/// Resolve the component name of the currently selected vulnerability (for cache keying).
fn render_filter_bar(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let filter = ctx.vulnerabilities.filter;
    let sort = ctx.vulnerabilities.sort_by;

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
    if ctx.mode == AppMode::Diff {
        if let Some(result) = ctx.diff_result {
            let scheme = colors();

            // Compute per-severity deltas
            let count_by_sev = |vulns: &[crate::diff::VulnerabilityDetail]| -> [usize; 4] {
                let mut counts = [0usize; 4]; // [C, H, M, L]
                for v in vulns {
                    match v.severity.to_lowercase().as_str() {
                        "critical" => counts[0] += 1,
                        "high" => counts[1] += 1,
                        "medium" | "moderate" => counts[2] += 1,
                        "low" => counts[3] += 1,
                        _ => {}
                    }
                }
                counts
            };
            let intro = count_by_sev(&result.vulnerabilities.introduced);
            let resolved = count_by_sev(&result.vulnerabilities.resolved);

            spans.push(Span::styled("│ ", Style::default().fg(scheme.border)));

            let sev_labels = [
                ("C", scheme.critical, "critical"),
                ("H", scheme.high, "high"),
                ("M", scheme.medium, "medium"),
                ("L", scheme.low, "low"),
            ];
            for (i, (label, bg, sev_name)) in sev_labels.iter().enumerate() {
                spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default()
                        .fg(scheme.severity_badge_fg(sev_name))
                        .bg(*bg)
                        .bold(),
                ));
                let net: i32 = intro[i] as i32 - resolved[i] as i32;
                let delta_str = if net > 0 {
                    format!("+{net}")
                } else if net < 0 {
                    format!("{net}")
                } else {
                    "0".to_string()
                };
                let delta_color = if net > 0 {
                    scheme.removed // worse
                } else if net < 0 {
                    scheme.added // better
                } else {
                    scheme.text_muted
                };
                spans.push(Span::styled(
                    format!(" {delta_str} "),
                    Style::default().fg(delta_color),
                ));
            }

            // Total summary
            spans.extend(vec![
                Span::styled("│ ", Style::default().fg(scheme.border)),
                Span::styled("+ ", Style::default().fg(scheme.removed).bold()),
                Span::styled(
                    format!("{}  ", result.summary.vulnerabilities_introduced),
                    Style::default().fg(scheme.text),
                ),
                Span::styled("- ", Style::default().fg(scheme.added).bold()),
                Span::styled(
                    format!("{}  ", result.summary.vulnerabilities_resolved),
                    Style::default().fg(scheme.text),
                ),
                Span::styled("= ", Style::default().fg(scheme.modified).bold()),
                Span::styled(
                    format!("{}", result.summary.vulnerabilities_persistent),
                    Style::default().fg(scheme.text),
                ),
            ]);

            // Add enrichment stats if available
            #[cfg(feature = "enrichment")]
            {
                let combined = match (ctx.enrichment_stats_old, ctx.enrichment_stats_new) {
                    (Some(old), Some(new)) => {
                        let mut c = old.clone();
                        c.merge(new);
                        Some(c)
                    }
                    (Some(s), None) | (None, Some(s)) => Some(s.clone()),
                    (None, None) => None,
                };
                if let Some(stats) = combined
                    && stats.total_vulns_found > 0
                {
                    spans.extend(vec![
                        Span::styled("  │ ", Style::default().fg(scheme.border)),
                        Span::styled("OSV ", Style::default().fg(scheme.accent).bold()),
                        Span::styled(
                            format!("+{}", stats.total_vulns_found),
                            Style::default().fg(scheme.accent),
                        ),
                    ]);
                }
            }
        }
    }

    // Add grouped mode indicator
    let grouped_label = if ctx.vulnerabilities.group_by_component {
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
                .bg(if ctx.vulnerabilities.group_by_component {
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
    ctx: &RenderContext,
    vuln_data: &VulnListData,
    total_unfiltered: usize,
    grouped_items: Option<&[VulnRenderItem]>,
) {
    let is_diff = ctx.mode == AppMode::Diff;
    let header_style = Style::default().fg(colors().accent).bold();
    let header = if is_diff {
        Row::new(vec![
            Cell::from("Status").style(header_style),
            Cell::from("Sev").style(header_style),
            Cell::from("ID").style(header_style),
            Cell::from("CVSS").style(header_style),
            Cell::from("SLA").style(header_style),
            Cell::from("Component").style(header_style),
        ])
    } else {
        Row::new(vec![
            Cell::from("Status").style(header_style),
            Cell::from("ID").style(header_style),
            Cell::from("CVSS").style(header_style),
            Cell::from("SLA").style(header_style),
            Cell::from("Component").style(header_style),
        ])
    }
    .height(1);

    // Use pre-built vulnerability list (state already updated in render_vulnerabilities)
    let cached_depths = &ctx.dependencies.cached_depths;

    // Build rows (flat or grouped)
    let rows: Vec<Row> = if let Some(items) = grouped_items {
        build_grouped_rows(ctx, vuln_data, cached_depths, items)
    } else {
        match vuln_data {
            VulnListData::Diff(items) => get_diff_vuln_rows(items),
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
            // Contextual empty state: show unfiltered counts
            let hint = if total_unfiltered > 0 {
                format!(
                    "{total_unfiltered} {} in unfiltered view",
                    if total_unfiltered == 1 {
                        "vulnerability"
                    } else {
                        "vulnerabilities"
                    },
                )
            } else {
                String::new()
            };
            let filter_label = ctx.vulnerabilities.filter.label();
            widgets::render_no_results_state_with_hint(frame, area, "Filter", filter_label, &hint);
        }
        return;
    }

    let table = if is_diff {
        let widths = [
            Constraint::Length(12),
            Constraint::Length(3),
            Constraint::Percentage(25),
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Percentage(30),
        ];
        Table::new(rows, widths)
    } else {
        let widths = [
            Constraint::Length(12),
            Constraint::Percentage(25),
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Percentage(30),
        ];
        Table::new(rows, widths)
    };

    let table = table
        .header(header)
        .block(
            Block::default()
                .title(" Vulnerabilities ")
                .title_style(Style::default().fg(colors().border_focused).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().border_focused)),
        )
        .row_highlight_style(Style::default().bg(colors().selection))
        .highlight_symbol("▶ ");

    let mut state = TableState::default();
    state.select(Some(ctx.vulnerabilities.selected));

    frame.render_stateful_widget(table, area, &mut state);

    // Render scrollbar
    let total_rows = match vuln_data {
        VulnListData::Diff(items) => grouped_items.map_or(items.len(), <[VulnRenderItem]>::len),
        VulnListData::Empty => 0,
    };
    if total_rows > area.height.saturating_sub(3) as usize {
        widgets::render_scrollbar(
            frame,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            total_rows,
            ctx.vulnerabilities.selected,
        );
    }
}

/// Build the grouped render items list from vulnerability data.
/// Groups vulns by component name, renders headers with expand/collapse.
fn build_grouped_render_items(
    ctx: &RenderContext,
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
                let max_sev_a =
                    a.1.iter()
                        .map(|(_, it)| severity_rank(&it.vuln.severity))
                        .min()
                        .unwrap_or(99);
                let max_sev_b =
                    b.1.iter()
                        .map(|(_, it)| severity_rank(&it.vuln.severity))
                        .min()
                        .unwrap_or(99);
                max_sev_a.cmp(&max_sev_b)
            });

            for (comp_name, vulns) in sorted_groups {
                let max_sev = vulns
                    .iter()
                    .map(|(_, it)| it.vuln.severity.as_str())
                    .min_by_key(|s| severity_rank(s))
                    .unwrap_or("Unknown")
                    .to_string();
                let expanded = ctx.vulnerabilities.is_group_expanded(&comp_name);

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
        VulnListData::Empty => {}
    }

    items
}

use crate::tui::shared::vulnerabilities::severity_rank;

/// Build table rows for grouped mode using pre-computed render items.
fn build_grouped_rows(
    ctx: &RenderContext,
    vuln_data: &VulnListData<'_>,
    _cached_depths: &std::collections::HashMap<String, usize>,
    render_items: &[VulnRenderItem],
) -> Vec<Row<'static>> {
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

                let sev_badge = Cell::from(Span::styled(
                    format!(" {} ", max_severity.chars().next().unwrap_or('?')),
                    Style::default()
                        .fg(scheme.severity_badge_fg(max_severity))
                        .bg(sev_color)
                        .bold(),
                ));
                let name_cell = Cell::from(Line::from(vec![
                    Span::styled(format!("{arrow} "), Style::default().fg(scheme.accent)),
                    Span::styled(name.clone(), Style::default().fg(scheme.text).bold()),
                ]));
                let count_cell = Cell::from(Span::styled(
                    format!(
                        "{vuln_count} {}",
                        if *vuln_count == 1 { "CVE" } else { "CVEs" }
                    ),
                    Style::default().fg(scheme.text_muted),
                ));

                // Diff mode has 6 columns (extra Sev column), view mode has 5
                let cells: Vec<Cell<'static>> = if ctx.mode == AppMode::Diff {
                    vec![
                        Cell::from(""),
                        sev_badge,
                        name_cell,
                        Cell::from(""),
                        count_cell,
                        Cell::from(""),
                    ]
                } else {
                    vec![
                        sev_badge,
                        name_cell,
                        Cell::from(""),
                        count_cell,
                        Cell::from(""),
                    ]
                };
                Row::new(cells).style(Style::default().bg(bg_tint))
            }
            VulnRenderItem::VulnRow(idx) => match vuln_data {
                VulnListData::Diff(items) => items.get(*idx).map_or_else(
                    || Row::new(vec![Cell::from("")]),
                    |row| build_single_diff_row(row, &scheme),
                ),
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
    use crate::tui::shared::vulnerabilities::{
        render_depth_badge_spans, render_kev_badge_spans, render_vex_badge_spans,
    };

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

    // Build ID cell with KEV, DIR/TRN, and VEX badges
    let mut id_spans: Vec<Span<'_>> = Vec::new();
    id_spans.extend(render_kev_badge_spans(vuln.is_kev, scheme));
    id_spans.extend(render_depth_badge_spans(
        vuln.component_depth.map(|d| d as usize),
        scheme,
    ));
    id_spans.extend(render_vex_badge_spans(vuln.vex_state.as_ref(), scheme));
    id_spans.push(Span::raw(vuln.id.clone()));

    let sla_cell = format_sla_cell(vuln.sla_status(), vuln.days_since_published, scheme);

    let bg_tint = if item.status == DiffVulnStatus::Resolved {
        Color::Reset
    } else {
        scheme.severity_bg_tint(&vuln.severity)
    };

    use crate::tui::shared::vulnerabilities::cvss_score_color;

    let sev_color = scheme.severity_color(&vuln.severity);
    let cvss_cell = vuln.cvss_score.map_or_else(
        || Cell::from("-".to_string()),
        |s| {
            Cell::from(Span::styled(
                format!("{s:.1}"),
                Style::default().fg(cvss_score_color(s, scheme)).bold(),
            ))
        },
    );

    Row::new(vec![
        Cell::from(Span::styled(
            status_label,
            Style::default().fg(status_fg).bg(status_bg).bold(),
        )),
        Cell::from(Span::styled(
            format!(" {} ", vuln.severity.chars().next().unwrap_or('?')),
            Style::default()
                .fg(scheme.severity_badge_fg(&vuln.severity))
                .bg(sev_color)
                .bold(),
        )),
        Cell::from(Line::from(id_spans)),
        cvss_cell,
        sla_cell,
        Cell::from(widgets::truncate_str(&vuln.component_name, 30)),
    ])
    .style(row_style.bg(bg_tint))
}

fn render_detail_panel(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    vuln_data: &VulnListData,
    grouped_items: Option<&[VulnRenderItem]>,
) {
    let selected = ctx.vulnerabilities.selected;

    // In grouped mode, resolve the selected index through the pre-computed render items
    let vuln_info = if let Some(items) = grouped_items {
        match items.get(selected) {
            Some(VulnRenderItem::VulnRow(idx)) => match vuln_data {
                VulnListData::Diff(items) => get_diff_vuln_at(items, *idx),
                VulnListData::Empty => None,
            },
            Some(VulnRenderItem::ComponentHeader {
                name,
                vuln_count,
                max_severity,
                ..
            }) => {
                // Show a summary for the component group header
                Some(VulnDetailInfo {
                    status: "Component Group".to_string(),
                    id: name.clone(),
                    severity: max_severity.clone(),
                    cvss: None,
                    component: name.clone(),
                    description: Some(format!("{vuln_count} vulnerabilities in this component")),
                    cwes: Vec::new(),
                    source: String::new(),
                    remediation: None,
                    fixed_version: None,
                    is_kev: false,
                    is_ransomware: false,
                    affected_versions: Vec::new(),
                    cvss_vector: None,
                    published_age_days: None,
                    vex_state: None,
                    vex_justification: None,
                    vex_impact_statement: None,
                })
            }
            None => None,
        }
    } else {
        match vuln_data {
            VulnListData::Diff(items) => get_diff_vuln_at(items, selected),
            VulnListData::Empty => None,
        }
    };

    if let Some(info) = vuln_info {
        let scheme = colors();
        let sev_color = scheme.severity_color(&info.severity);
        let source_color = crate::tui::shared::vulnerabilities::source_color(&info.source, &scheme);

        // === Section 1: Risk Summary ===
        let mut badge_spans = vec![
            Span::styled(
                format!(" {} ", info.severity.chars().next().unwrap_or('?')),
                Style::default()
                    .fg(scheme.severity_badge_fg(&info.severity))
                    .bg(sev_color)
                    .bold(),
            ),
            Span::styled(
                format!(" {} ", info.severity),
                Style::default().fg(sev_color).bold(),
            ),
        ];
        if let Some(score) = info.cvss {
            let cvss_color = crate::tui::shared::vulnerabilities::cvss_score_color(score, &scheme);
            badge_spans.push(Span::styled(
                format!(" {score:.1} "),
                Style::default()
                    .fg(scheme.severity_badge_fg(&info.severity))
                    .bg(cvss_color)
                    .bold(),
            ));
        }
        if info.is_kev {
            badge_spans.push(Span::raw(" "));
            badge_spans.push(Span::styled(
                "KEV",
                Style::default()
                    .fg(scheme.kev_badge_fg())
                    .bg(scheme.kev())
                    .bold(),
            ));
        }
        if info.is_ransomware {
            badge_spans.push(Span::raw(" "));
            badge_spans.push(Span::styled(
                "RANSOMWARE",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.critical)
                    .bold(),
            ));
        }
        {
            let vex_badge = crate::tui::shared::vulnerabilities::render_vex_badge_spans(
                info.vex_state.as_ref(),
                &scheme,
            );
            if !vex_badge.is_empty() {
                badge_spans.push(Span::raw(" "));
                badge_spans.extend(vex_badge);
            }
        }

        let mut lines = vec![
            Line::from(badge_spans),
            // ID + Source + Published
            Line::from({
                let mut spans = vec![
                    Span::styled(&info.id, Style::default().fg(scheme.text).bold()),
                    Span::styled(
                        format!(" [{}]", info.source),
                        Style::default().fg(source_color),
                    ),
                ];
                if let Some(age) = info.published_age_days {
                    spans.push(Span::styled(
                        format!("  {age}d ago"),
                        Style::default().fg(scheme.text_muted),
                    ));
                }
                spans
            }),
            // Status + Component
            Line::from(vec![
                status_span(&info.status),
                Span::styled("  ", Style::default()),
                Span::styled(&info.component, Style::default().fg(scheme.secondary)),
            ]),
        ];

        // === Section 2: Remediation (actionable fix) ===
        if info.fixed_version.is_some()
            || info.remediation.is_some()
            || !info.affected_versions.is_empty()
        {
            lines.push(Line::from(""));
            if let Some(ref fix_ver) = info.fixed_version {
                lines.push(Line::from(vec![Span::styled(
                    format!("\u{2b06} Upgrade to {fix_ver}"),
                    Style::default().fg(scheme.accent).bold(),
                )]));
            }
            if let Some(ref rem) = info.remediation {
                lines.push(Line::from(vec![
                    Span::styled("Remediation: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(rem.clone(), Style::default().fg(scheme.text)),
                ]));
            }
            if !info.affected_versions.is_empty() {
                let versions_str = info.affected_versions.join(", ");
                lines.push(Line::from(vec![
                    Span::styled("Affects: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(versions_str, Style::default().fg(scheme.text)),
                ]));
            }
        }

        // === VEX Exploitability Context ===
        if info.vex_state.is_some() {
            lines.push(Line::from(""));
            if let Some(ref state) = info.vex_state {
                let (vex_label, vex_color) = match state {
                    crate::model::VexState::NotAffected => ("Not Affected", scheme.low),
                    crate::model::VexState::Fixed => ("Fixed", scheme.low),
                    crate::model::VexState::Affected => ("Affected", scheme.critical),
                    crate::model::VexState::UnderInvestigation => {
                        ("Under Investigation", scheme.medium)
                    }
                };
                lines.push(Line::from(vec![
                    Span::styled("VEX Status: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(vex_label, Style::default().fg(vex_color).bold()),
                ]));
            }
            if let Some(ref justification) = info.vex_justification {
                lines.push(Line::from(vec![
                    Span::styled("Justification: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        format!("{justification:?}"),
                        Style::default().fg(scheme.text),
                    ),
                ]));
            }
            if let Some(ref impact) = info.vex_impact_statement {
                let max_width = area.width.saturating_sub(4) as usize;
                lines.push(Line::from(Span::styled(
                    "Impact: ",
                    Style::default().fg(scheme.text_muted),
                )));
                for wrapped in crate::tui::shared::vulnerabilities::word_wrap(impact, max_width) {
                    lines.push(Line::from(Span::styled(
                        format!("  {wrapped}"),
                        Style::default().fg(scheme.text),
                    )));
                }
            }
        }

        // === Section 3: Impact (CWEs + CVSS vector) ===
        if !info.cwes.is_empty() || info.cvss_vector.is_some() {
            lines.push(Line::from(""));
        }
        // CWEs with names
        lines.extend(crate::tui::shared::vulnerabilities::render_vuln_cwe_lines(
            &info.cwes, 3,
        ));
        if let Some(ref vector) = info.cvss_vector {
            // Show abbreviated attack vector (e.g., AV:N/AC:L from full CVSS string)
            let brief = vector.split('/').take(2).collect::<Vec<_>>().join("/");
            lines.push(Line::from(vec![
                Span::styled("Vector: ", Style::default().fg(scheme.text_muted)),
                Span::styled(brief, Style::default().fg(scheme.text)),
            ]));
        }

        // === Section 4: Description ===
        if let Some(ref desc) = info.description {
            lines.push(Line::from(""));
            let max_width = area.width.saturating_sub(4) as usize;
            for wrapped_line in crate::tui::shared::vulnerabilities::word_wrap(desc, max_width) {
                lines.push(Line::styled(
                    wrapped_line,
                    Style::default().fg(scheme.text).italic(),
                ));
            }
        }

        // Attack Paths (show how to reach this vulnerable component from entry points)
        // Uses cached paths when the selected component hasn't changed
        if matches!(ctx.mode, AppMode::Diff) {
            let attack_paths = if let Some((ref cached_comp, ref cached_paths)) =
                ctx.vulnerabilities.cached_attack_paths
            {
                if *cached_comp == info.component {
                    cached_paths.clone()
                } else {
                    compute_attack_paths(&info.component, ctx)
                }
            } else {
                compute_attack_paths(&info.component, ctx)
            };

            if !attack_paths.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    format!("Attack Paths ({}): ", attack_paths.len()),
                    Style::default().fg(colors().high).bold(),
                )]));

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

fn get_diff_vuln_at(
    items: &[crate::tui::app::DiffVulnItem<'_>],
    index: usize,
) -> Option<VulnDetailInfo> {
    items.get(index).map(|item| {
        let vuln = item.vuln;
        VulnDetailInfo {
            status: item.status.label().to_string(),
            id: vuln.id.clone(),
            severity: vuln.severity.clone(),
            cvss: vuln.cvss_score,
            component: vuln.component_name.clone(),
            description: vuln.description.clone(),
            cwes: vuln.cwes.clone(),
            source: vuln.source.clone(),
            remediation: vuln.remediation.clone(),
            fixed_version: None,
            is_kev: vuln.is_kev,
            is_ransomware: false, // Not available in diff mode
            affected_versions: Vec::new(),
            cvss_vector: None,
            published_age_days: vuln.days_since_published,
            vex_state: vuln.vex_state.clone(),
            vex_justification: vuln.vex_justification.clone(),
            vex_impact_statement: vuln.vex_impact_statement.clone(),
        }
    })
}

fn get_diff_vuln_rows(items: &[crate::tui::app::DiffVulnItem<'_>]) -> Vec<Row<'static>> {
    let scheme = colors();
    items
        .iter()
        .map(|item| build_single_diff_row(item, &scheme))
        .collect()
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
        SlaStatus::NoDueDate => days_since_published.map_or_else(
            || Cell::from("-".to_string()),
            |age| {
                Cell::from(Span::styled(
                    format!("{age}d old"),
                    Style::default().fg(scheme.text_muted),
                ))
            },
        ),
    }
}

/// Compute attack paths for a component (used by both render and cache).
fn compute_attack_paths(
    component: &str,
    ctx: &RenderContext,
) -> Vec<crate::tui::security::AttackPath> {
    let forward_graph = &ctx.dependencies.cached_forward_graph;
    let reverse_graph = &ctx.dependencies.cached_reverse_graph;
    let all_components: Vec<String> = reverse_graph.keys().cloned().collect();
    let roots = crate::tui::security::find_root_components(&all_components, reverse_graph);
    crate::tui::security::find_attack_paths(component, forward_graph, &roots, 3, 5)
}

/// Count the number of visible items in grouped mode without building full `VulnListData`.
/// Each component group adds 1 header + N vulns (if expanded).
pub(crate) fn count_grouped_items(app: &App) -> usize {
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
                if app.vulnerabilities_state().is_group_expanded(comp_name) {
                    count += vuln_count;
                }
            }
            count
        }
        _ => 0,
    }
}
