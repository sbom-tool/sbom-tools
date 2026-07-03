//! Vulnerability explorer view for `ViewApp`.

use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, ViewApp, VulnGroupBy};
use crate::tui::widgets::{SeverityBadge, extract_display_name, truncate_str};
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
    let scheme = colors();

    // Count how many severity levels have non-zero counts
    let non_zero_severities = [
        stats.critical_count,
        stats.high_count,
        stats.medium_count,
        stats.low_count,
    ]
    .iter()
    .filter(|&&c| c > 0)
    .count();

    // If only one severity (or zero) has data, show compact summary instead of 5 empty cards
    if non_zero_severities <= 1 && stats.unknown_count > 0 {
        render_stats_compact(frame, area, app);
        return;
    }

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

/// Compact stats when all/most vulns are same severity (e.g., all UNKNOWN).
fn render_stats_compact(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let stats = &app.stats;
    let scheme = colors();

    // Determine the dominant severity
    let (dominant_label, dominant_count, dominant_color) = if stats.critical_count > 0 {
        ("Critical", stats.critical_count, scheme.critical)
    } else if stats.high_count > 0 {
        ("High", stats.high_count, scheme.high)
    } else if stats.medium_count > 0 {
        ("Medium", stats.medium_count, scheme.medium)
    } else if stats.low_count > 0 {
        ("Low", stats.low_count, scheme.low)
    } else {
        ("Unknown", stats.unknown_count, scheme.muted)
    };

    // Split into summary (left) and top components (right)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: summary card
    let total_str = crate::tui::widgets::format_count(stats.vuln_count);
    let comp_count = app
        .vuln_state
        .cached_data
        .as_ref()
        .map_or(0, |c| c.affected_component_count);

    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {dominant_label} "),
                Style::default()
                    .fg(scheme.severity_badge_fg(dominant_label))
                    .bg(dominant_color)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(total_str, Style::default().fg(dominant_color).bold()),
            Span::styled(" vulnerabilities", Style::default().fg(scheme.text)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("{comp_count}"),
                Style::default().fg(scheme.primary).bold(),
            ),
            Span::styled(
                " affected components",
                Style::default().fg(scheme.text_muted),
            ),
            if dominant_count < stats.vuln_count {
                Span::styled(
                    format!(
                        "  ({dominant_count} {}, {} other)",
                        dominant_label.to_lowercase(),
                        stats.vuln_count - dominant_count
                    ),
                    Style::default().fg(scheme.text_muted),
                )
            } else {
                Span::styled(
                    format!("  (all {})", dominant_label.to_lowercase()),
                    Style::default().fg(scheme.text_muted),
                )
            },
        ]),
    ];

    let summary = Paragraph::new(summary_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(dominant_color)),
        )
        .alignment(Alignment::Left);
    frame.render_widget(summary, chunks[0]);

    // Right: top affected components bar
    render_top_components_bar(frame, chunks[1], app);
}

/// Show top affected components as a mini bar chart (uses pre-computed data from cache).
fn render_top_components_bar(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let Some(cache) = &app.vuln_state.cached_data else {
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
            area,
        );
        return;
    };

    let max_rows = area.height.saturating_sub(2) as usize;
    let top = cache.top_components.iter().take(max_rows.max(1));
    let max_count = cache.top_components.first().map_or(1, |(_, c)| *c).max(1);

    let bar_width = area.width.saturating_sub(22) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for (name, count) in top {
        let filled = (*count * bar_width / max_count).max(usize::from(*count > 0));
        let display_name = crate::tui::widgets::truncate_str(name, 14);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{display_name:<14}"),
                Style::default().fg(scheme.text),
            ),
            Span::styled(
                format!("{count:>4} "),
                Style::default().fg(scheme.accent).bold(),
            ),
            Span::styled("█".repeat(filled), Style::default().fg(scheme.primary)),
            Span::styled(
                "░".repeat(bar_width.saturating_sub(filled)),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    let chart = Paragraph::new(lines).block(
        Block::default()
            .title(" Top Affected ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.border)),
    );
    frame.render_widget(chart, area);
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
        Span::styled("KEV: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(
                " {} ",
                if app.vuln_state.filter_kev {
                    "On"
                } else {
                    "Off"
                }
            ),
            Style::default()
                .fg(scheme.kev_badge_fg())
                .bg(if app.vuln_state.filter_kev {
                    scheme.kev()
                } else {
                    scheme.muted
                })
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
        Span::styled("[k]", Style::default().fg(scheme.accent)),
        Span::raw(" kev  "),
        Span::styled("[s]", Style::default().fg(scheme.accent)),
        Span::raw(" sort  "),
        Span::styled("[d]", Style::default().fg(scheme.accent)),
        Span::raw(" dedupe  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" group  "),
        Span::styled("[/]", Style::default().fg(scheme.accent)),
        Span::raw(" search  "),
        Span::styled("[E]", Style::default().fg(scheme.accent)),
        Span::raw(" expand  "),
        Span::styled("[C]", Style::default().fg(scheme.accent)),
        Span::raw(" collapse  "),
        Span::styled("[Tab]", Style::default().fg(scheme.accent)),
        Span::raw(" next group"),
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
        } else if app.vuln_state.filter_kev && app.vuln_state.filter_severity.is_none() {
            crate::tui::widgets::render_no_results_state(frame, area, "KEV Filter", "KEV only");
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

    // Use cached display items — only rebuild when cache or expanded_groups change
    if !app.vuln_state.are_display_items_valid() {
        app.vuln_state.rebuild_display_items();
    }

    // Update total and clamp selection based on display items
    app.vuln_state.total = app.vuln_state.cached_display_items.len();
    app.vuln_state.clamp_selection();

    // Extract detail panel data before passing mutable ref to table panel
    // This avoids cloning the entire display_items Vec every frame
    let selected_idx = app.vuln_state.selected;
    let detail_data = extract_detail_data(
        &app.vuln_state.cached_display_items,
        selected_idx,
        &cache.vulns,
        &app.vuln_state.group_by,
    );

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
    render_vuln_table_panel(frame, chunks[0], &cache, app, is_left_focused);

    // Render detail panel using pre-extracted data
    // Component is contextually known in any grouped mode (from group/sub-group headers)
    let component_in_context = !matches!(
        app.vuln_state.group_by,
        crate::tui::view::app::VulnGroupBy::Flat
    );
    match detail_data {
        DetailData::Vuln(vuln_idx) => {
            render_vuln_detail_panel(
                frame,
                chunks[1],
                cache.vulns.get(vuln_idx),
                !is_left_focused,
                &mut app.vuln_state.detail_scroll,
                component_in_context,
            );
        }
        DetailData::Group {
            label,
            count,
            severity_stats,
            indices,
        } => {
            render_group_detail_panel(
                frame,
                chunks[1],
                &label,
                count,
                &severity_stats,
                &cache.vulns,
                &indices,
                !is_left_focused,
                &mut app.vuln_state.detail_scroll,
            );
        }
        DetailData::None => {
            render_vuln_detail_panel(
                frame,
                chunks[1],
                None,
                !is_left_focused,
                &mut app.vuln_state.detail_scroll,
                component_in_context,
            );
        }
    }
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

                // Apply KEV filter — isolate KEV-flagged vulns (mirrors diff-mode)
                if app.vuln_state.filter_kev && !vuln.is_kev {
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
                        existing
                            .affected_component_ids
                            .push(comp_id.value().to_string());
                        // Keep the highest CVSS score
                        if let Some(new_cvss) = cvss
                            && existing.cvss.is_none_or(|c| new_cvss > c)
                        {
                            existing.cvss = Some(new_cvss);
                        }
                        // Keep the highest EPSS score across affected components
                        if let Some(new_epss) = vuln.epss_score
                            && existing.epss_score.is_none_or(|e| new_epss > e)
                        {
                            existing.epss_score = Some(new_epss);
                        }
                        // Merge affected versions
                        for v in &vuln.affected_versions {
                            if !existing.affected_versions.contains(v) {
                                existing.affected_versions.push(v.clone());
                            }
                        }
                    })
                    .or_insert_with(|| {
                        let best_cvss = vuln.cvss.first();
                        VulnRow {
                            vuln_id: vuln.id.clone(),
                            severity: sev,
                            cvss,
                            component_name: comp.name.clone(),
                            component_id: comp_id.value().to_string(),
                            description: vuln.description.clone(),
                            affected_count: 1,
                            affected_component_ids: vec![comp_id.value().to_string()],
                            affected_components: vec![comp.name.clone()],
                            cwes: vuln.cwes.clone(),
                            published: vuln.published,
                            modified: vuln.modified,
                            affected_versions: vuln.affected_versions.clone(),
                            source: vuln.source.to_string(),
                            is_kev: vuln.is_kev,
                            vex_state: vuln
                                .vex_status
                                .as_ref()
                                .map(|v| v.status.clone())
                                .or_else(|| comp.vex_status.as_ref().map(|v| v.status.clone())),
                            grouped_components: Vec::new(),
                            display_name: String::new(),
                            group_key: String::new(),
                            remediation_type: vuln
                                .remediation
                                .as_ref()
                                .map(|r| format!("{:?}", r.remediation_type)),
                            fixed_version: vuln
                                .remediation
                                .as_ref()
                                .and_then(|r| r.fixed_version.clone()),
                            remediation_desc: vuln
                                .remediation
                                .as_ref()
                                .and_then(|r| r.description.clone()),
                            kev_due_date: vuln.kev_info.as_ref().map(|k| k.due_date),
                            kev_ransomware: vuln
                                .kev_info
                                .as_ref()
                                .is_some_and(|k| k.known_ransomware_use),
                            kev_required_action: vuln
                                .kev_info
                                .as_ref()
                                .map(|k| k.required_action.clone()),
                            cvss_version: best_cvss.map(|c| format!("{:?}", c.version)),
                            cvss_vector: best_cvss.and_then(|c| c.vector.clone()),
                            exploitability_score: best_cvss.and_then(|c| c.exploitability_score),
                            impact_score: best_cvss.and_then(|c| c.impact_score),
                            epss_score: vuln.epss_score,
                        }
                    });
            }
        }

        // Build smart component groupings and pre-compute display names for each deduped vuln
        vulns = vuln_map
            .into_values()
            .map(|mut v| {
                v.grouped_components =
                    group_affected_components(&v.affected_components, v.description.as_deref());
                v.display_name =
                    extract_component_display_name(&v.component_name, v.description.as_deref());
                let raw_key = if v.affected_count > 1 {
                    v.grouped_components
                        .first()
                        .map_or_else(|| v.component_name.clone(), |(name, _)| name.clone())
                } else {
                    v.display_name.clone()
                };
                v.group_key = normalize_component_group_key(&raw_key);
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

                // Apply KEV filter — isolate KEV-flagged vulns (mirrors diff-mode)
                if app.vuln_state.filter_kev && !vuln.is_kev {
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

                let best_cvss = vuln.cvss.first();
                vulns.push(VulnRow {
                    vuln_id: vuln.id.clone(),
                    severity: sev,
                    cvss,
                    component_name: comp.name.clone(),
                    component_id: comp_id.value().to_string(),
                    description: vuln.description.clone(),
                    affected_count: 1,
                    affected_component_ids: vec![comp_id.value().to_string()],
                    affected_components: vec![comp.name.clone()],
                    cwes: vuln.cwes.clone(),
                    published: vuln.published,
                    modified: vuln.modified,
                    affected_versions: vuln.affected_versions.clone(),
                    source: vuln.source.to_string(),
                    is_kev: vuln.is_kev,
                    vex_state: vuln
                        .vex_status
                        .as_ref()
                        .map(|v| v.status.clone())
                        .or_else(|| comp.vex_status.as_ref().map(|v| v.status.clone())),
                    grouped_components: Vec::new(),
                    display_name: String::new(),
                    group_key: String::new(),
                    remediation_type: vuln
                        .remediation
                        .as_ref()
                        .map(|r| format!("{:?}", r.remediation_type)),
                    fixed_version: vuln
                        .remediation
                        .as_ref()
                        .and_then(|r| r.fixed_version.clone()),
                    remediation_desc: vuln
                        .remediation
                        .as_ref()
                        .and_then(|r| r.description.clone()),
                    kev_due_date: vuln.kev_info.as_ref().map(|k| k.due_date),
                    kev_ransomware: vuln
                        .kev_info
                        .as_ref()
                        .is_some_and(|k| k.known_ransomware_use),
                    kev_required_action: vuln.kev_info.as_ref().map(|k| k.required_action.clone()),
                    cvss_version: best_cvss.map(|c| format!("{:?}", c.version)),
                    cvss_vector: best_cvss.and_then(|c| c.vector.clone()),
                    exploitability_score: best_cvss.and_then(|c| c.exploitability_score),
                    impact_score: best_cvss.and_then(|c| c.impact_score),
                    epss_score: vuln.epss_score,
                });
            }
        }
    }

    // Pre-compute display names and group keys for the non-dedup path
    if !app.vuln_state.deduplicate {
        for v in &mut vulns {
            v.display_name =
                extract_component_display_name(&v.component_name, v.description.as_deref());
            v.group_key = normalize_component_group_key(&v.display_name);
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

    // Count unique components that have vulns
    let affected_component_count = {
        let mut seen = HashSet::new();
        for v in &vulns {
            seen.insert(&v.component_name);
            for comp in &v.affected_components {
                seen.insert(comp);
            }
        }
        seen.len()
    };

    // Compute all_same_severity
    let all_same_severity = if let Some(first) = vulns.first() {
        let first_sev = &first.severity;
        vulns.iter().all(|v| v.severity == *first_sev)
    } else {
        true
    };

    // Compute common description prefix (shared by >60% of vulns)
    let common_desc_prefix = compute_common_desc_prefix(&vulns);

    // Pre-compute top affected components using pre-computed display_name
    let top_components = {
        let mut comp_counts: indexmap::IndexMap<String, usize> = indexmap::IndexMap::new();
        for v in &vulns {
            *comp_counts.entry(v.display_name.clone()).or_insert(0) += 1;
        }
        let mut sorted: Vec<_> = comp_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
    };

    // Compute aggregate flags for column visibility
    let has_any_kev = vulns.iter().any(|v| v.is_kev);
    let has_any_fix = vulns.iter().any(|v| v.fixed_version.is_some());
    let has_any_date = vulns.iter().any(|v| v.published.is_some());
    let has_any_version = vulns.iter().any(|v| !v.affected_versions.is_empty());

    VulnCache {
        vulns,
        has_any_cvss,
        all_same_component,
        has_multi_affected,
        total_unfiltered,
        affected_component_count,
        all_same_severity,
        common_desc_prefix,
        top_components,
        has_any_kev,
        has_any_fix,
        has_any_date,
        has_any_version,
    }
}

/// Pre-extracted detail panel data to avoid borrow conflicts
enum DetailData {
    Vuln(usize),
    Group {
        label: String,
        count: usize,
        severity_stats: GroupSeverityStats,
        indices: Vec<usize>,
    },
    None,
}

/// Extract detail panel data from display items without holding a borrow on app.
/// This runs once per frame on the selected item only — O(1) for vuln, O(group_size) for headers.
fn extract_detail_data(
    display_items: &[VulnDisplayItem],
    selected: usize,
    vulns: &[VulnRow],
    group_by: &VulnGroupBy,
) -> DetailData {
    match display_items.get(selected) {
        Some(VulnDisplayItem::Vuln { idx, .. }) => DetailData::Vuln(*idx),
        Some(VulnDisplayItem::GroupHeader {
            label,
            count,
            severity_stats,
            ..
        }) => {
            // Collect all vuln indices under this group (may include sub-groups + vulns)
            let group_indices: Vec<usize> = display_items
                .iter()
                .skip(selected + 1)
                .take_while(|item| !matches!(item, VulnDisplayItem::GroupHeader { .. }))
                .filter_map(|item| match item {
                    VulnDisplayItem::Vuln { idx, .. } => Some(*idx),
                    _ => None,
                })
                .collect();
            // If group is collapsed, find indices by scanning vulns
            let indices = if group_indices.is_empty() {
                vulns
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| {
                        let key = match group_by {
                            VulnGroupBy::Severity => &v.severity,
                            VulnGroupBy::Component | VulnGroupBy::Flat => &v.group_key,
                        };
                        key == label
                    })
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>()
            } else {
                group_indices
            };
            DetailData::Group {
                label: label.clone(),
                count: *count,
                severity_stats: severity_stats.clone(),
                indices,
            }
        }
        Some(VulnDisplayItem::SubGroupHeader {
            parent_label,
            label,
            count,
            severity_stats,
            ..
        }) => {
            // Collect vuln indices following this sub-group header
            let group_indices: Vec<usize> = display_items
                .iter()
                .skip(selected + 1)
                .take_while(|item| matches!(item, VulnDisplayItem::Vuln { .. }))
                .filter_map(|item| match item {
                    VulnDisplayItem::Vuln { idx, .. } => Some(*idx),
                    _ => None,
                })
                .collect();
            // If collapsed, find by severity + component match
            let indices = if group_indices.is_empty() {
                vulns
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.severity == *parent_label && v.group_key == *label)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>()
            } else {
                group_indices
            };
            DetailData::Group {
                label: label.clone(),
                count: *count,
                severity_stats: severity_stats.clone(),
                indices,
            }
        }
        None => DetailData::None,
    }
}

/// Find a common description prefix shared by >60% of vulns.
/// E.g., "In the Linux kernel, " appears in thousands of kernel CVEs.
fn compute_common_desc_prefix(vulns: &[VulnRow]) -> Option<String> {
    if vulns.len() < 10 {
        return None; // Not worth computing for small sets
    }

    let descs: Vec<&str> = vulns
        .iter()
        .filter_map(|v| v.description.as_deref())
        .collect();
    if descs.len() < vulns.len() / 2 {
        return None; // Most vulns have no description
    }

    // Try common known prefixes first (much faster than n^2)
    const KNOWN_PREFIXES: &[&str] = &[
        "In the Linux kernel, ",
        "In the Linux kernel,",
        "In BusyBox ",
        "An issue was discovered in ",
        "A vulnerability was found in ",
        "A flaw was found in ",
    ];

    let threshold = descs.len() * 60 / 100;
    for prefix in KNOWN_PREFIXES {
        let count = descs.iter().filter(|d| d.starts_with(prefix)).count();
        if count >= threshold {
            return Some((*prefix).to_string());
        }
    }

    // Try to find common prefix from the first description
    if let Some(first) = descs.first() {
        // Try progressively shorter prefixes up to comma/space boundaries
        for boundary in [", ", ". ", " — ", " - "] {
            if let Some(pos) = first.find(boundary) {
                let candidate = &first[..pos + boundary.len()];
                if candidate.len() >= 10 && candidate.len() <= 60 {
                    let count = descs.iter().filter(|d| d.starts_with(candidate)).count();
                    if count >= threshold {
                        return Some(candidate.to_string());
                    }
                }
            }
        }
    }

    None
}

fn render_vuln_table_panel(
    frame: &mut Frame,
    area: Rect,
    cache: &VulnCache,
    app: &mut ViewApp,
    is_focused: bool,
) {
    let scheme = colors();
    let vulns = &cache.vulns;
    let is_dedupe = app.vuln_state.deduplicate;
    let total_unfiltered = cache.total_unfiltered;
    let common_desc_prefix = cache.common_desc_prefix.as_deref();

    // Determine which columns to show
    let show_cvss = cache.has_any_cvss;
    let show_severity_badge = !cache.all_same_severity;
    let is_grouped = !matches!(
        app.vuln_state.group_by,
        crate::tui::view::app::VulnGroupBy::Flat
    );
    let is_severity_grouped = matches!(
        app.vuln_state.group_by,
        crate::tui::view::app::VulnGroupBy::Severity
    );
    let show_age = cache.has_any_date;
    // Grouped mode: CWE + merged Fix→Version columns replace Description + old Fix + Version
    // Flat mode: Component + Description (original layout)
    let show_component =
        !is_grouped && (!cache.all_same_component || (is_dedupe && cache.has_multi_affected));
    let show_description = !is_grouped;
    let show_cwe = is_grouped;
    // In grouped mode, merge fix indicator with version into one wider column
    let show_fix_version = is_grouped && (cache.has_any_fix || cache.has_any_version);
    // In flat mode, keep separate Fix and Version columns
    let show_fix = !is_grouped && cache.has_any_fix;
    let show_version = !is_grouped && cache.has_any_version;

    // Build dynamic column widths and headers based on visibility flags
    let mut widths: Vec<Constraint> = Vec::new();
    let mut headers: Vec<&str> = Vec::new();

    if show_severity_badge {
        widths.push(Constraint::Length(3));
        headers.push("");
    }
    widths.push(Constraint::Min(20));
    headers.push("Vuln ID");
    if show_cvss {
        widths.push(Constraint::Length(5));
        headers.push("CVSS");
    }
    if show_age {
        widths.push(Constraint::Length(5));
        headers.push("Age");
    }
    if show_fix {
        widths.push(Constraint::Length(3));
        headers.push("Fix");
    }
    if show_fix_version {
        widths.push(Constraint::Length(14));
        headers.push("Fix");
    }
    if show_version {
        widths.push(Constraint::Length(14));
        headers.push("Version");
    }
    if show_component {
        widths.push(Constraint::Length(28));
        headers.push("Component");
    }
    if show_cwe {
        widths.push(Constraint::Min(15));
        headers.push("CWE");
    }
    if show_description {
        widths.push(Constraint::Min(10));
        headers.push("Description");
    }

    let num_columns = widths.len();

    // Calculate available width for description (account for Min constraints too)
    let fixed_width: u16 = widths
        .iter()
        .filter_map(|c| match c {
            Constraint::Length(l) | Constraint::Min(l) => Some(*l),
            _ => None,
        })
        .sum();
    let desc_width = area.width.saturating_sub(fixed_width + 5) as usize;

    // VIRTUALIZATION: Only render visible rows for performance
    let visible_height = area.height.saturating_sub(3) as usize;
    let display_items = &app.vuln_state.cached_display_items;
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

    // Compute max group count and whether severity is mixed (for proportional bars)
    let max_group_count = display_items
        .iter()
        .filter_map(|item| match item {
            VulnDisplayItem::GroupHeader { count, .. } => Some(*count),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    // Only show bar sparks when there's severity variety to color-code
    let has_mixed_severity = display_items.iter().any(|item| {
        matches!(
            item,
            VulnDisplayItem::GroupHeader { severity_stats, .. }
                if [severity_stats.critical, severity_stats.high, severity_stats.medium,
                    severity_stats.low, severity_stats.unknown]
                    .iter().filter(|&&c| c > 0).count() > 1
        )
    });

    // Build rows from display items
    let rows: Vec<Row> = display_items[start..end]
        .iter()
        .map(|item| match item {
            VulnDisplayItem::GroupHeader {
                label,
                count,
                expanded,
                severity_stats,
                tree,
                ..
            } => {
                let arrow = if *expanded { "▼" } else { "▶" };
                let sev_color = SeverityBadge::fg_color(label);

                let mut header_spans: Vec<Span<'static>> = Vec::new();
                // Tree prefix for top-level groups
                if is_grouped {
                    let prefix = if tree.is_last { "└─" } else { "├─" };
                    header_spans.push(Span::styled(
                        prefix.to_string(),
                        Style::default().fg(scheme.border),
                    ));
                }
                header_spans.push(Span::styled(
                    format!("{arrow} "),
                    Style::default().fg(scheme.accent).bold(),
                ));
                header_spans.push(Span::styled(
                    label.clone(),
                    Style::default()
                        .fg(if is_severity_grouped {
                            sev_color
                        } else {
                            scheme.accent
                        })
                        .bold(),
                ));
                header_spans.push(Span::styled(
                    format!(" ({count})"),
                    Style::default().fg(scheme.text_muted),
                ));
                // Proportional bar spark — only when severity varies across groups
                if has_mixed_severity {
                    let bar_color = dominant_severity_color(severity_stats, &scheme);
                    header_spans.extend(format_count_bar_spans(
                        *count,
                        max_group_count,
                        bar_color,
                        8,
                    ));
                }
                if !is_severity_grouped {
                    let sev_spans = format_severity_mini_spans(severity_stats, &scheme);
                    if !sev_spans.is_empty() {
                        header_spans.push(Span::raw("  "));
                        header_spans.extend(sev_spans);
                    }
                }

                let mut cells: Vec<Cell> = Vec::new();
                if show_severity_badge {
                    cells.push(Cell::from(""));
                }
                cells.push(Cell::from(Line::from(header_spans)));
                let first_col = if show_severity_badge { 2 } else { 1 };
                for _ in first_col..num_columns {
                    cells.push(Cell::from(""));
                }
                Row::new(cells)
            }
            VulnDisplayItem::SubGroupHeader {
                label,
                count,
                expanded,
                severity_stats,
                tree,
                ..
            } => {
                let arrow = if *expanded { "▼" } else { "▶" };

                let mut header_spans: Vec<Span<'static>> = Vec::new();
                // Tree prefix for sub-groups: ancestor line + branch
                let ancestor = if tree.parent_is_last { "  " } else { "│ " };
                let branch = if tree.is_last { "└─" } else { "├─" };
                header_spans.push(Span::styled(
                    ancestor.to_string(),
                    Style::default().fg(scheme.border),
                ));
                header_spans.push(Span::styled(
                    branch.to_string(),
                    Style::default().fg(scheme.border),
                ));
                header_spans.push(Span::styled(
                    format!("{arrow} "),
                    Style::default().fg(scheme.accent),
                ));
                header_spans.push(Span::styled(
                    label.clone(),
                    Style::default().fg(scheme.accent).bold(),
                ));
                header_spans.push(Span::styled(
                    format!(" ({count})"),
                    Style::default().fg(scheme.text_muted),
                ));
                if let Some(max_cvss) = severity_stats.max_cvss {
                    header_spans.push(Span::raw("  "));
                    let cvss_color = cvss_score_color(max_cvss, &scheme);
                    header_spans.push(Span::styled(
                        format!("{max_cvss:.1}"),
                        Style::default().fg(cvss_color).bold(),
                    ));
                }

                let mut cells: Vec<Cell> = Vec::new();
                if show_severity_badge {
                    cells.push(Cell::from(""));
                }
                cells.push(Cell::from(Line::from(header_spans)));
                let first_col = if show_severity_badge { 2 } else { 1 };
                for _ in first_col..num_columns {
                    cells.push(Cell::from(""));
                }
                Row::new(cells)
            }
            VulnDisplayItem::Vuln { idx, tree } => {
                let v = &vulns[*idx];
                let sev_color = SeverityBadge::fg_color(&v.severity);

                // Build ID cell with tree prefix + optional KEV + VEX badges
                let mut id_spans: Vec<Span<'static>> = Vec::new();

                // Tree-drawing characters based on depth
                if is_grouped {
                    match tree.depth {
                        1 => {
                            // Direct child of top-level group (component grouping)
                            let ancestor = if tree.parent_is_last { "  " } else { "│ " };
                            let branch = if tree.is_last { "└─" } else { "├─" };
                            id_spans.push(Span::styled(
                                ancestor.to_string(),
                                Style::default().fg(scheme.border),
                            ));
                            id_spans.push(Span::styled(
                                branch.to_string(),
                                Style::default().fg(scheme.border),
                            ));
                        }
                        2 => {
                            // Child of sub-group (severity → component → vuln)
                            // grandparent_is_last = is the severity group last?
                            let grand = if tree.grandparent_is_last {
                                "  "
                            } else {
                                "│ "
                            };
                            // parent_is_last = is the sub-group last within its severity?
                            let parent_cont = if tree.parent_is_last { "  " } else { "│ " };
                            let branch = if tree.is_last { "└─" } else { "├─" };
                            id_spans.push(Span::styled(
                                grand.to_string(),
                                Style::default().fg(scheme.border),
                            ));
                            id_spans.push(Span::styled(
                                parent_cont.to_string(),
                                Style::default().fg(scheme.border),
                            ));
                            id_spans.push(Span::styled(
                                branch.to_string(),
                                Style::default().fg(scheme.border),
                            ));
                        }
                        _ => {}
                    }
                }

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
                // EPSS badge — only for higher-probability vulns to keep the ID column
                // readable; band colors shared with diff-mode + CLI markdown.
                if let Some(epss) = v.epss_score
                    && epss >= 0.1
                {
                    id_spans.push(Span::styled(
                        format!("EPSS {:.0}%", epss * 100.0),
                        Style::default()
                            .fg(scheme.badge_fg_light)
                            .bg(crate::tui::shared::vulnerabilities::epss_band_color(
                                epss, &scheme,
                            ))
                            .bold(),
                    ));
                    id_spans.push(Span::raw(" "));
                }
                id_spans.extend(crate::tui::shared::vulnerabilities::render_vex_badge_spans(
                    v.vex_state.as_ref(),
                    &scheme,
                ));
                id_spans.push(Span::styled(
                    truncate_str(&v.vuln_id, 20),
                    Style::default().fg(sev_color).bold(),
                ));

                let mut cells: Vec<Cell> = Vec::new();

                if show_severity_badge {
                    cells.push(Cell::from(Span::styled(
                        SeverityBadge::indicator(&v.severity),
                        Style::default()
                            .fg(scheme.severity_badge_fg(&v.severity))
                            .bg(sev_color)
                            .bold(),
                    )));
                }
                cells.push(Cell::from(Line::from(id_spans)));

                if show_cvss {
                    // #10: CVSS score with color-coding
                    let cvss_cell = if let Some(score) = v.cvss {
                        let cvss_color = cvss_score_color(score, &scheme);
                        Cell::from(Span::styled(
                            format!("{score:.1}"),
                            Style::default().fg(cvss_color).bold(),
                        ))
                    } else {
                        Cell::from(Span::styled("-", Style::default().fg(scheme.muted)))
                    };
                    cells.push(cvss_cell);
                }

                if show_age {
                    // #3: Compact age column
                    let age_str = format_vuln_age(v.published);
                    let age_color = if let Some(pub_date) = v.published {
                        let days = (chrono::Utc::now() - pub_date).num_days();
                        if days < 30 {
                            scheme.critical
                        }
                        // Recent = urgent
                        else if days < 365 {
                            scheme.text
                        } else {
                            scheme.muted
                        }
                    } else {
                        scheme.muted
                    };
                    cells.push(Cell::from(Span::styled(
                        age_str,
                        Style::default().fg(age_color),
                    )));
                }

                if show_fix {
                    // #6: Fix available indicator
                    let fix_cell = if v.fixed_version.is_some() {
                        Cell::from(Span::styled(
                            "✓",
                            Style::default().fg(scheme.success).bold(),
                        ))
                    } else {
                        Cell::from(Span::styled("·", Style::default().fg(scheme.muted)))
                    };
                    cells.push(fix_cell);
                }

                if show_fix_version {
                    // Merged Fix→Version column for grouped mode
                    let cell = if let Some(ref fix_ver) = v.fixed_version {
                        Cell::from(Span::styled(
                            format!("→{}", truncate_str(fix_ver, 12)),
                            Style::default().fg(scheme.success),
                        ))
                    } else {
                        let ver_str = v.affected_versions.first().map_or("·", |v| v.as_str());
                        Cell::from(Span::styled(
                            truncate_str(ver_str, 14),
                            Style::default().fg(scheme.muted),
                        ))
                    };
                    cells.push(cell);
                }

                if show_version {
                    // Show affected version in flat mode
                    let ver_str = v.affected_versions.first().map_or("-", |v| v.as_str());
                    cells.push(Cell::from(Span::styled(
                        truncate_str(ver_str, 14),
                        Style::default().fg(scheme.text_muted),
                    )));
                }
                if show_component {
                    if is_dedupe && v.affected_count > 1 {
                        cells.push(Cell::from(Span::styled(
                            format!("{} comp", v.affected_count),
                            Style::default().fg(scheme.primary),
                        )));
                    } else {
                        // Use pre-computed display_name (no per-frame string processing)
                        cells.push(Cell::from(Span::styled(
                            truncate_str(&v.display_name, 28),
                            Style::default().fg(scheme.primary),
                        )));
                    }
                }

                if show_cwe {
                    // CWE column for grouped mode
                    let cwe_display = if v.cwes.is_empty() {
                        "-".to_string()
                    } else {
                        let cwe = &v.cwes[0];
                        format!("{} {}", cwe, cwe_short_name(cwe))
                    };
                    cells.push(Cell::from(Span::styled(
                        truncate_str(&cwe_display, desc_width.max(15)),
                        Style::default().fg(scheme.text),
                    )));
                }

                if show_description {
                    // #8: Better description — use CWE name as fallback for generic/missing descriptions
                    let desc_display = {
                        let raw_desc = v.description.as_ref().map(|d| {
                            let stripped = if let Some(prefix) = common_desc_prefix {
                                d.strip_prefix(prefix).unwrap_or(d)
                            } else {
                                d.as_str()
                            };
                            stripped.to_string()
                        });
                        // If description is missing or very short after stripping, use CWE name
                        let use_cwe = raw_desc.as_ref().is_none_or(|d| d.len() < 5);
                        if use_cwe && !v.cwes.is_empty() {
                            let cwe_name = v
                                .cwes
                                .first()
                                .map(|c| format!("{} {}", c, cwe_short_name(c)))
                                .unwrap_or_default();
                            truncate_str(&cwe_name, desc_width.max(15))
                        } else {
                            raw_desc.as_ref().map_or_else(
                                || "-".to_string(),
                                |d| truncate_str(d, desc_width.max(15)),
                            )
                        }
                    };
                    cells.push(Cell::from(Span::styled(
                        desc_display,
                        Style::default().fg(scheme.text),
                    )));
                }

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

    // Phase 2+3: Build informative table title
    let vuln_count = vulns.len();
    let position_str = if total_items > 0 {
        format!("{} of ", selected + 1)
    } else {
        String::new()
    };
    let all_same_severity = cache.all_same_severity;
    // Phase 2: Show severity in title when all same
    let sev_suffix = if all_same_severity {
        vulns
            .first()
            .map_or(String::new(), |v| format!(" {}", v.severity))
    } else {
        String::new()
    };
    // Phase 3: Show dedup reduction
    let dedup_str = if is_dedupe && total_unfiltered > vuln_count {
        format!(
            " [{} → {} unique]",
            crate::tui::widgets::format_count(total_unfiltered),
            crate::tui::widgets::format_count(vuln_count)
        )
    } else {
        String::new()
    };
    let title = format!(" Vulnerabilities ({position_str}{vuln_count}{sev_suffix}){dedup_str} ");
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .fg(scheme.text)
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
            .thumb_style(Style::default().fg(scheme.accent))
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

/// #2: Format severity mini-distribution as colored spans for group headers.
/// Returns spans like: "2 crit" (red) " 5 high" (orange) " 10 unk" (gray).
/// Returns empty when all vulns share the same severity (the count in parens suffices).
fn format_severity_mini_spans<'a>(
    stats: &GroupSeverityStats,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Span<'a>> {
    let items: &[(&str, usize, Color)] = &[
        ("crit", stats.critical, scheme.critical),
        ("high", stats.high, scheme.high),
        ("med", stats.medium, scheme.medium),
        ("low", stats.low, scheme.low),
        ("unk", stats.unknown, scheme.muted),
    ];

    // Count how many distinct severity buckets are non-zero
    let distinct = items.iter().filter(|(_, c, _)| *c > 0).count();
    // If only 1 bucket, the suffix is redundant — the (count) already says it all
    if distinct <= 1 {
        // Still show max CVSS if available
        let mut spans = Vec::new();
        if let Some(cvss) = stats.max_cvss {
            spans.push(Span::styled(
                format!("max:{cvss:.1}"),
                Style::default().fg(cvss_score_color(cvss, scheme)),
            ));
        }
        return spans;
    }

    let mut spans = Vec::new();
    for (suffix, count, color) in items {
        if *count > 0 {
            if !spans.is_empty() {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                format!("{count} {suffix}"),
                Style::default().fg(*color).bold(),
            ));
        }
    }
    if let Some(cvss) = stats.max_cvss {
        if !spans.is_empty() {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            format!("max:{cvss:.1}"),
            Style::default().fg(cvss_score_color(cvss, scheme)),
        ));
    }
    spans
}

/// Return the color of the highest-severity non-zero bucket in the stats.
fn dominant_severity_color(
    stats: &GroupSeverityStats,
    scheme: &crate::tui::theme::ColorScheme,
) -> Color {
    if stats.critical > 0 {
        scheme.critical
    } else if stats.high > 0 {
        scheme.high
    } else if stats.medium > 0 {
        scheme.medium
    } else if stats.low > 0 {
        scheme.low
    } else {
        scheme.muted
    }
}

/// Render a proportional inline bar spark for a group count.
/// The bar is scaled relative to `max_count` with a maximum width of `max_bar_width` chars.
fn format_count_bar_spans<'a>(
    count: usize,
    max_count: usize,
    color: Color,
    max_bar_width: usize,
) -> Vec<Span<'a>> {
    if max_count == 0 {
        return vec![];
    }
    let bar_len = ((count * max_bar_width) / max_count).max(1);
    vec![
        Span::raw(" "),
        Span::styled("█".repeat(bar_len), Style::default().fg(color)),
    ]
}

/// Render detail panel for a group header (when no specific vuln is selected).
#[allow(clippy::too_many_arguments)]
fn render_group_detail_panel(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    count: usize,
    severity_stats: &GroupSeverityStats,
    vulns: &[VulnRow],
    group_vuln_indices: &[usize],
    is_focused: bool,
    detail_scroll: &mut u16,
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let mut lines: Vec<Line> = Vec::new();

    // Group name with count
    lines.push(Line::from(vec![
        Span::styled(label, Style::default().fg(scheme.accent).bold()),
        Span::styled(
            format!("  ({count} vulnerabilities)"),
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Phase 1: Show component names (clean display name) and full paths
    if !group_vuln_indices.is_empty() {
        let mut raw_names: indexmap::IndexMap<&str, usize> = indexmap::IndexMap::new();
        for &idx in group_vuln_indices {
            *raw_names.entry(&vulns[idx].component_name).or_insert(0) += 1;
        }
        // Only show raw names if they differ from the group label (i.e., normalization merged them)
        let interesting_names: Vec<_> = raw_names
            .iter()
            .filter(|(name, _)| **name != label)
            .collect();
        if !interesting_names.is_empty() {
            for (name, _count) in interesting_names.iter().take(4) {
                let display = extract_display_name(name);
                // Show clean display name
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(display, Style::default().fg(scheme.text)),
                ]));
                // Show full path on next line if different from display name
                if extract_display_name(name) != **name {
                    lines.push(Line::from(vec![
                        Span::styled("    ", Style::default()),
                        Span::styled(name.to_string(), Style::default().fg(scheme.muted).italic()),
                    ]));
                }
            }
            if interesting_names.len() > 4 {
                lines.push(Line::styled(
                    format!("  +{} more components", interesting_names.len() - 4),
                    Style::default().fg(scheme.text_muted),
                ));
            }
        }
    }

    // Severity breakdown — only show when 2+ severity levels present
    let distinct_severities = [
        severity_stats.critical,
        severity_stats.high,
        severity_stats.medium,
        severity_stats.low,
        severity_stats.unknown,
    ]
    .iter()
    .filter(|&&c| c > 0)
    .count();

    if distinct_severities > 1 {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Severity Breakdown:",
            Style::default().fg(scheme.muted),
        ));
        let total_in_group = count.max(1);
        let sev_items: Vec<(&str, usize, Color)> = vec![
            ("Critical", severity_stats.critical, scheme.critical),
            ("High", severity_stats.high, scheme.high),
            ("Medium", severity_stats.medium, scheme.medium),
            ("Low", severity_stats.low, scheme.low),
            ("Unknown", severity_stats.unknown, scheme.muted),
        ];
        for (sev_label, sev_count, color) in &sev_items {
            if *sev_count > 0 {
                let bar_width = 20;
                let filled = (*sev_count * bar_width / total_in_group)
                    .max(1)
                    .min(bar_width);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {sev_label:<10}"), Style::default().fg(*color)),
                    Span::styled(
                        format!("{sev_count:>4}  "),
                        Style::default().fg(scheme.text).bold(),
                    ),
                    Span::styled("█".repeat(filled), Style::default().fg(*color)),
                ]));
            }
        }
    }

    // Max CVSS
    if let Some(cvss) = severity_stats.max_cvss {
        lines.push(Line::from(vec![
            Span::styled("  Max CVSS: ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{cvss:.1}"),
                Style::default().fg(cvss_score_color(cvss, &scheme)).bold(),
            ),
        ]));
    }

    // Date range, source breakdown, CWEs
    if !group_vuln_indices.is_empty() {
        // Phase 5: Date range with human-readable age
        let dates: Vec<_> = group_vuln_indices
            .iter()
            .filter_map(|&i| vulns[i].published)
            .collect();
        if dates.len() >= 2 {
            let min_date = dates.iter().min();
            let max_date = dates.iter().max();
            if let (Some(min), Some(max)) = (min_date, max_date) {
                let oldest_age = (chrono::Utc::now() - *min).num_days();
                let newest_age = (chrono::Utc::now() - *max).num_days();
                lines.push(Line::from(vec![
                    Span::styled("  Published: ", Style::default().fg(scheme.muted)),
                    Span::styled(
                        format!("{} — {}", min.format("%Y-%m-%d"), max.format("%Y-%m-%d")),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(
                        format!(
                            " ({} — {})",
                            format_age_human(oldest_age),
                            format_age_human(newest_age)
                        ),
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
            }
        }

        // Source breakdown — only when multiple source types
        let mut source_counts: indexmap::IndexMap<&str, usize> = indexmap::IndexMap::new();
        for &idx in group_vuln_indices {
            *source_counts.entry(&vulns[idx].source).or_insert(0) += 1;
        }
        if source_counts.len() > 1 {
            let source_parts: Vec<String> = source_counts
                .iter()
                .map(|(src, cnt)| format!("{src}: {cnt}"))
                .collect();
            lines.push(Line::from(vec![
                Span::styled("  Sources: ", Style::default().fg(scheme.muted)),
                Span::styled(source_parts.join(", "), Style::default().fg(scheme.text)),
            ]));
        }

        // Top CWEs with names
        let mut cwe_counts: indexmap::IndexMap<&str, usize> = indexmap::IndexMap::new();
        for &idx in group_vuln_indices {
            for cwe in &vulns[idx].cwes {
                *cwe_counts.entry(cwe.as_str()).or_insert(0) += 1;
            }
        }
        if !cwe_counts.is_empty() {
            let mut cwe_sorted: Vec<_> = cwe_counts.into_iter().collect();
            cwe_sorted.sort_by(|a, b| b.1.cmp(&a.1));
            lines.push(Line::from(""));
            lines.push(Line::styled("Top CWEs:", Style::default().fg(scheme.muted)));
            for (cwe, cnt) in cwe_sorted.iter().take(5) {
                let name = cwe_short_name(cwe);
                let mut cwe_spans = vec![
                    Span::styled(format!("  {cwe}"), Style::default().fg(scheme.accent)),
                    Span::styled(format!(" ({cnt})"), Style::default().fg(scheme.text_muted)),
                ];
                if !name.is_empty() {
                    cwe_spans.push(Span::styled(
                        format!(" {name}"),
                        Style::default().fg(scheme.text_muted),
                    ));
                }
                lines.push(Line::from(cwe_spans));
            }
        }
    }

    // Phase 2 + 3 + 4: Full scrollable CVE list with descriptions and KEV/FIX badges
    lines.push(Line::from(""));
    let has_cvss = severity_stats.max_cvss.is_some();
    lines.push(Line::styled(
        format!("CVEs ({count}):"),
        Style::default().fg(scheme.muted),
    ));
    let mut sorted_indices: Vec<usize> = group_vuln_indices.to_vec();
    if has_cvss {
        sorted_indices.sort_by(|a, b| {
            vulns[*b]
                .cvss
                .partial_cmp(&vulns[*a].cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    } else {
        sorted_indices.sort_by(|a, b| vulns[*b].published.cmp(&vulns[*a].published));
    }
    // Phase 2: Render ALL CVEs (no take(5) limit) — scrollable
    for &idx in &sorted_indices {
        let v = &vulns[idx];
        let sev_color = SeverityBadge::fg_color(&v.severity);
        let info_str = if has_cvss {
            v.cvss
                .map_or_else(|| "  -".to_string(), |c| format!("{c:>4.1}"))
        } else {
            v.published
                .map_or_else(|| "    ".to_string(), |d| format!("{}", d.format("%Y")))
        };
        // Phase 4: CVE line with KEV/FIX badges
        let mut cve_spans = vec![
            Span::styled(
                format!(" {} ", SeverityBadge::indicator(&v.severity)),
                Style::default()
                    .fg(scheme.severity_badge_fg(&v.severity))
                    .bg(sev_color)
                    .bold(),
            ),
            Span::styled(format!(" {info_str} "), Style::default().fg(scheme.text)),
            Span::styled(&v.vuln_id, Style::default().fg(sev_color)),
        ];
        if v.is_kev {
            cve_spans.push(Span::raw(" "));
            cve_spans.push(Span::styled(
                "KEV",
                Style::default()
                    .fg(scheme.kev_badge_fg())
                    .bg(scheme.kev())
                    .bold(),
            ));
        }
        if v.fixed_version.is_some() {
            cve_spans.push(Span::raw(" "));
            cve_spans.push(Span::styled(
                "FIX",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.success)
                    .bold(),
            ));
        }
        lines.push(Line::from(cve_spans));

        // Phase 3: One-line description under CVE if available
        if let Some(ref desc) = v.description
            && !desc.is_empty()
        {
            let desc_max = area.width.saturating_sub(8) as usize;
            lines.push(Line::from(vec![
                Span::styled("    ", Style::default()),
                Span::styled(
                    truncate_str(desc, desc_max),
                    Style::default().fg(scheme.text_muted).italic(),
                ),
            ]));
        }
    }

    // Phase 2: Scrollable paragraph with scrollbar
    let block = Block::default()
        .title(" Group Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(area);
    let inner_height = inner.height;
    // Count wrapped rows (the paragraph renders with Wrap) so scroll can reach
    // wrapped overflow and the scrollbar is sized right — logical lines.len()
    // undercounts.
    let content_height = crate::tui::shared::text::wrapped_line_count(&lines, inner.width)
        .min(u16::MAX as usize) as u16;

    // Clamp scroll
    let max_scroll = content_height.saturating_sub(inner_height);
    if *detail_scroll > max_scroll {
        *detail_scroll = max_scroll;
    }

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((*detail_scroll, 0));

    frame.render_widget(para, area);

    // Scrollbar when content overflows
    if content_height > inner_height {
        let inner_area = Block::default().borders(Borders::ALL).inner(area);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));
        let mut scrollbar_state =
            ScrollbarState::new(content_height as usize).position(*detail_scroll as usize);
        frame.render_stateful_widget(scrollbar, inner_area, &mut scrollbar_state);
    }
}

fn render_vuln_detail_panel(
    frame: &mut Frame,
    area: Rect,
    vuln: Option<&VulnRow>,
    is_focused: bool,
    detail_scroll: &mut u16,
    component_in_context: bool,
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
        // EPSS exploit-probability badge (shared band colors with diff-mode + CLI markdown)
        if let Some(epss) = v.epss_score {
            id_line_spans.push(Span::raw(" "));
            id_line_spans.push(Span::styled(
                format!("EPSS {:.0}%", epss * 100.0),
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(crate::tui::shared::vulnerabilities::epss_band_color(
                        epss, &scheme,
                    ))
                    .bold(),
            ));
        }
        // #6: Fix available badge
        if v.fixed_version.is_some() {
            id_line_spans.push(Span::raw(" "));
            id_line_spans.push(Span::styled(
                " FIX ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.success)
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

    // Severity + CVSS on one line with color-coded score (#10)
    let mut sev_spans = vec![
        Span::styled("Severity: ", Style::default().fg(scheme.muted)),
        Span::styled(&v.severity, Style::default().fg(sev_color).bold()),
    ];
    if let Some(cvss) = v.cvss {
        let cvss_color = cvss_score_color(cvss, &scheme);
        sev_spans.push(Span::styled("  CVSS: ", Style::default().fg(scheme.muted)));
        sev_spans.push(Span::styled(
            format!("{cvss:.1}"),
            Style::default().fg(cvss_color).bold(),
        ));
        // #5: CVSS version
        if let Some(ref ver) = v.cvss_version {
            sev_spans.push(Span::styled(
                format!(" ({ver})"),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }
    lines.push(Line::from(sev_spans));

    // #5: CVSS vector breakdown (attack surface visualization)
    if let Some(ref vector) = v.cvss_vector {
        let parsed = parse_cvss_vector(vector);
        if !parsed.is_empty() {
            let mut vector_spans = vec![Span::styled(
                "  Vector: ",
                Style::default().fg(scheme.muted),
            )];
            for (i, (key, val, color)) in parsed.iter().enumerate() {
                if i > 0 {
                    vector_spans.push(Span::styled(" ", Style::default()));
                }
                vector_spans.push(Span::styled(
                    format!("{key}:{val}"),
                    Style::default().fg(*color).bold(),
                ));
            }
            lines.push(Line::from(vector_spans));
        }
    }

    // #7: Exploitability + Impact subscores
    if v.exploitability_score.is_some() || v.impact_score.is_some() {
        let mut score_spans = vec![Span::styled("  ", Style::default())];
        if let Some(exp) = v.exploitability_score {
            score_spans.push(Span::styled("Exploit: ", Style::default().fg(scheme.muted)));
            score_spans.push(Span::styled(
                format!("{exp:.1}"),
                Style::default()
                    .fg(cvss_score_color(f64::from(exp), &scheme))
                    .bold(),
            ));
            score_spans.push(Span::raw("  "));
        }
        if let Some(imp) = v.impact_score {
            score_spans.push(Span::styled("Impact: ", Style::default().fg(scheme.muted)));
            score_spans.push(Span::styled(
                format!("{imp:.1}"),
                Style::default()
                    .fg(cvss_score_color(f64::from(imp), &scheme))
                    .bold(),
            ));
        }
        lines.push(Line::from(score_spans));
    }

    // Source + Published date + Modified date (#9)
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
        let age_color = if age_days < 30 {
            scheme.critical
        } else {
            scheme.text
        };
        meta_spans.push(Span::styled(
            format!("{}", pub_date.format("%Y-%m-%d")),
            Style::default().fg(age_color),
        ));
        meta_spans.push(Span::styled(
            format!(" ({})", format_age_human(age_days)),
            Style::default().fg(scheme.text_muted),
        ));
    }
    lines.push(Line::from(meta_spans));

    // #9: Modified date (if different from published)
    if let Some(mod_date) = v.modified {
        let show_modified = v
            .published
            .is_none_or(|p| (mod_date - p).num_days().abs() > 1);
        if show_modified {
            lines.push(Line::from(vec![
                Span::styled("Modified: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format!("{}", mod_date.format("%Y-%m-%d")),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
    }

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

    // #1: Remediation information
    if v.remediation_type.is_some() || v.fixed_version.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Remediation:",
            Style::default().fg(scheme.success).bold(),
        ));
        if let Some(ref fix_type) = v.remediation_type {
            lines.push(Line::from(vec![
                Span::styled("  Type: ", Style::default().fg(scheme.muted)),
                Span::styled(fix_type, Style::default().fg(scheme.text)),
            ]));
        }
        if let Some(ref fix_ver) = v.fixed_version {
            lines.push(Line::from(vec![
                Span::styled("  Fixed in: ", Style::default().fg(scheme.muted)),
                Span::styled(fix_ver, Style::default().fg(scheme.success).bold()),
            ]));
        }
        if let Some(ref fix_desc) = v.remediation_desc {
            let max_width = area.width.saturating_sub(6) as usize;
            for line in crate::tui::shared::vulnerabilities::word_wrap(fix_desc, max_width) {
                lines.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().fg(scheme.text),
                )));
            }
        }
    }

    // #2: KEV details
    if v.is_kev {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "CISA KEV:",
            Style::default().fg(scheme.kev()).bold(),
        ));
        if let Some(due) = v.kev_due_date {
            let days_until = (due - chrono::Utc::now()).num_days();
            let (due_str, due_color) = if days_until < 0 {
                (
                    format!("{} OVERDUE ({} days)", due.format("%Y-%m-%d"), -days_until),
                    scheme.critical,
                )
            } else if days_until < 14 {
                (
                    format!("{} ({} days left)", due.format("%Y-%m-%d"), days_until),
                    scheme.high,
                )
            } else {
                (
                    format!("{} ({} days left)", due.format("%Y-%m-%d"), days_until),
                    scheme.text,
                )
            };
            lines.push(Line::from(vec![
                Span::styled("  Due: ", Style::default().fg(scheme.muted)),
                Span::styled(due_str, Style::default().fg(due_color).bold()),
            ]));
        }
        if v.kev_ransomware {
            lines.push(Line::from(vec![
                Span::styled("  Ransomware: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    "Known ransomware use",
                    Style::default().fg(scheme.critical).bold(),
                ),
            ]));
        }
        if let Some(ref action) = v.kev_required_action {
            let max_width = area.width.saturating_sub(6) as usize;
            lines.push(Line::from(vec![Span::styled(
                "  Action: ",
                Style::default().fg(scheme.muted),
            )]));
            for line in crate::tui::shared::vulnerabilities::word_wrap(action, max_width) {
                lines.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().fg(scheme.text),
                )));
            }
        }
    }

    lines.push(Line::from(""));

    // Description — show early when component is contextually known (severity grouping)
    if component_in_context {
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
    }

    // CWEs with names
    if !v.cwes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled("CWEs:", Style::default().fg(scheme.muted)));
        for cwe in v.cwes.iter().take(5) {
            let name = cwe_short_name(cwe);
            let mut cwe_spans = vec![Span::styled(
                format!("  {cwe}"),
                Style::default().fg(scheme.accent),
            )];
            if !name.is_empty() {
                cwe_spans.push(Span::styled(
                    format!(" {name}"),
                    Style::default().fg(scheme.text_muted),
                ));
            }
            lines.push(Line::from(cwe_spans));
        }
    }

    // Component(s) — compact when in severity grouping context, full otherwise
    if component_in_context {
        // Compact: just show component name on one line (it's already in the sub-group header)
        let display = extract_component_display_name(&v.component_name, v.description.as_deref());
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.muted)),
            Span::styled(display, Style::default().fg(scheme.primary)),
        ]));
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
                Span::styled("  Version: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format!("{versions_str}{suffix}"),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(""));
        if v.affected_count > 1 {
            lines.push(Line::from(vec![
                Span::styled("Components: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format!("{} affected", v.affected_count),
                    Style::default().fg(scheme.primary),
                ),
            ]));
            if v.grouped_components.is_empty() {
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
            let display =
                extract_component_display_name(&v.component_name, v.description.as_deref());
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

        lines.push(Line::from(""));

        // Description — shown after component when not in severity grouping
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

    // Navigation hints
    let mut nav_spans = vec![
        Span::styled("[i]", Style::default().fg(scheme.accent)),
        Span::styled(" inspect component", Style::default().fg(scheme.muted)),
    ];
    if v.affected_component_ids.len() > 1 {
        nav_spans.push(Span::styled(
            "  [n]/[p]",
            Style::default().fg(scheme.accent),
        ));
        nav_spans.push(Span::styled(
            " cycle components",
            Style::default().fg(scheme.muted),
        ));
    }
    lines.push(Line::from(nav_spans));

    // Clamp scroll offset so it doesn't exceed content. Count *wrapped* rows (the
    // panel renders with Wrap) so wrapped overflow is reachable and the scrollbar is
    // sized correctly — logical lines.len() undercounts wrapped CVE text/URLs.
    let content_height = area.height.saturating_sub(2); // borders
    let inner_width = area.width.saturating_sub(2); // borders
    let total_lines = crate::tui::shared::text::wrapped_line_count(&lines, inner_width)
        .min(u16::MAX as usize) as u16;
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

/// Well-known `.so` library name to friendly package name mapping.
const SO_NAME_MAP: &[(&str, &str)] = &[
    ("libc-", "glibc"),
    ("libc.so", "glibc"),
    ("libcrypto.so", "OpenSSL"),
    ("libssl.so", "OpenSSL"),
    ("libcurl.so", "cURL"),
    ("libexpat.so", "expat"),
    ("libxml2.so", "libxml2"),
    ("libkrb5.so", "Kerberos"),
    ("libsqlite3.so", "SQLite"),
    ("libsqlite.so", "SQLite"),
    ("libz.so", "zlib"),
    ("libpng", "libpng"),
    ("libjpeg", "libjpeg"),
    ("libtiff", "libtiff"),
    ("libpcre", "PCRE"),
    ("libssh", "libssh"),
    ("libgnutls", "GnuTLS"),
    ("libldap", "OpenLDAP"),
    ("libpam", "PAM"),
    ("libaudit", "audit"),
    ("libselinux", "SELinux"),
    ("libsystemd", "systemd"),
    ("libudev", "systemd"),
    ("libdbus", "D-Bus"),
    ("libncurses", "ncurses"),
    ("libreadline", "readline"),
    ("libipmi", "IPMI"),
    ("libstorelib", "storelib"),
    ("libtinfo", "ncurses"),
    ("libbind", "BIND"),
    ("libdns", "BIND"),
    ("libisc", "BIND"),
];

/// Clean up a component name (remove path prefixes, extensions, resolve `.so` names)
fn clean_component_name(name: &str) -> String {
    // Get the filename from path
    let filename = if name.starts_with("./") || name.starts_with('/') || name.contains('/') {
        name.rsplit('/').next().unwrap_or(name)
    } else {
        name
    };

    // Try to resolve .so file names to friendly package names
    if filename.contains(".so") {
        for &(prefix, friendly) in SO_NAME_MAP {
            if filename.starts_with(prefix) {
                // Extract version from .so.X.Y.Z if present
                if let Some(so_pos) = filename.find(".so.") {
                    let ver = &filename[so_pos + 4..];
                    if !ver.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        return format!("{friendly} ({ver})");
                    }
                }
                return friendly.to_string();
            }
        }
        // Generic .so cleanup: strip path, strip .so.* suffix
        let base = filename
            .split(".so")
            .next()
            .unwrap_or(filename)
            .trim_start_matches("lib");
        if !base.is_empty() && base.len() > 1 {
            return base.to_string();
        }
    }

    let clean = filename
        .trim_end_matches(".squ")
        .trim_end_matches(".squashfs")
        .trim_end_matches(".img")
        .trim_end_matches(".bin");

    if clean.chars().all(|c| c.is_ascii_hexdigit() || c == '-') && clean.len() > 8 {
        return format!("file:{}", truncate_str(clean, 12));
    }
    clean.to_string()
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
    /// Primary component ID (first affected; use `affected_component_ids` for all)
    #[allow(dead_code)]
    pub component_id: String,
    pub description: Option<String>,
    pub affected_count: usize,
    /// All affected component IDs (for cross-tab navigation in deduplicated mode)
    pub affected_component_ids: Vec<String>,
    /// Pre-computed display name (avoids re-running extract_component_display_name per frame)
    pub display_name: String,
    /// Pre-computed normalized group key (avoids re-running normalize per frame)
    pub group_key: String,
    pub affected_components: Vec<String>,
    pub cwes: Vec<String>,
    /// Published date
    pub published: Option<chrono::DateTime<chrono::Utc>>,
    /// Last modified date
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
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
    // --- Improvement #1: Remediation info ---
    /// Remediation type (Patch, Upgrade, Workaround, etc.)
    pub remediation_type: Option<String>,
    /// Fixed version if available
    pub fixed_version: Option<String>,
    /// Remediation description
    pub remediation_desc: Option<String>,
    // --- Improvement #2: KEV details ---
    /// KEV due date for remediation
    pub kev_due_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether known to be used in ransomware campaigns
    pub kev_ransomware: bool,
    /// Required action from CISA
    pub kev_required_action: Option<String>,
    // --- Improvement #5: CVSS vector breakdown ---
    /// CVSS version (V2, V3, V31, V4)
    pub cvss_version: Option<String>,
    /// CVSS attack vector string
    pub cvss_vector: Option<String>,
    /// Exploitability sub-score
    pub exploitability_score: Option<f32>,
    /// Impact sub-score
    pub impact_score: Option<f32>,
    /// EPSS exploit-probability score (0.0–1.0), if enriched.
    pub epss_score: Option<f64>,
}

use std::collections::HashSet;
use std::sync::Arc;

/// Severity breakdown for a group header.
#[derive(Debug, Clone, Default)]
pub struct GroupSeverityStats {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub max_cvss: Option<f64>,
}

/// Tree position metadata for rendering tree-drawing characters.
#[derive(Debug, Clone, Default)]
pub struct TreePos {
    /// Depth in the tree (0=top-level group, 1=sub-group or vuln under group, 2=vuln under sub-group)
    pub depth: u8,
    /// Whether this item is the last child in its parent
    pub is_last: bool,
    /// Whether the parent is the last child in its grandparent
    pub parent_is_last: bool,
    /// Whether the grandparent group is last (only relevant for depth=2)
    pub grandparent_is_last: bool,
}

/// A display item in the vulnerability list (either a group header or a vuln row).
#[derive(Debug, Clone)]
pub enum VulnDisplayItem {
    GroupHeader {
        label: String,
        count: usize,
        expanded: bool,
        severity_stats: GroupSeverityStats,
        tree: TreePos,
    },
    /// Component sub-group within a severity group (two-level hierarchy).
    SubGroupHeader {
        parent_label: String,
        label: String,
        count: usize,
        expanded: bool,
        severity_stats: GroupSeverityStats,
        tree: TreePos,
    },
    Vuln {
        idx: usize, // index into VulnCache.vulns
        tree: TreePos,
    },
}

/// Build display items from cached vulns based on grouping mode and expansion state.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn build_display_items(
    vulns: &[VulnRow],
    group_by: &VulnGroupBy,
    expanded: &HashSet<String>,
) -> Vec<VulnDisplayItem> {
    use crate::tui::shared::vulnerabilities::severity_rank;

    if matches!(group_by, VulnGroupBy::Flat) {
        return vulns
            .iter()
            .enumerate()
            .map(|(i, _)| VulnDisplayItem::Vuln {
                idx: i,
                tree: TreePos::default(),
            })
            .collect();
    }

    // Group vulns by the grouping key, preserving insertion order.
    // Uses pre-computed group_key on VulnRow for O(1) lookup (no per-frame string processing).
    let mut groups: indexmap::IndexMap<String, Vec<usize>> = indexmap::IndexMap::new();
    for (i, v) in vulns.iter().enumerate() {
        let key = match group_by {
            VulnGroupBy::Severity => v.severity.clone(),
            VulnGroupBy::Component => v.group_key.clone(),
            VulnGroupBy::Flat => unreachable!(),
        };
        groups.entry(key).or_default().push(i);
    }

    // For severity grouping, sort by severity order
    // #4: For component grouping, sort by vulnerability count descending
    match group_by {
        VulnGroupBy::Severity => {
            groups.sort_by(|a, _, b, _| severity_rank(a).cmp(&severity_rank(b)));
        }
        VulnGroupBy::Component => {
            groups.sort_by(|_, a_indices, _, b_indices| b_indices.len().cmp(&a_indices.len()));
        }
        VulnGroupBy::Flat => {}
    }

    let auto_expand_all = groups.len() == 1;
    let group_count = groups.len();
    let mut items = Vec::new();
    for (group_idx, (label, indices)) in groups.iter().enumerate() {
        let is_expanded = auto_expand_all || expanded.contains(label);
        let is_last_group = group_idx == group_count - 1;

        // Compute severity stats for this group
        let mut severity_stats = GroupSeverityStats::default();
        for &idx in indices {
            let v = &vulns[idx];
            match severity_rank(&v.severity) {
                0 => severity_stats.critical += 1,
                1 => severity_stats.high += 1,
                2 => severity_stats.medium += 1,
                3 => severity_stats.low += 1,
                _ => severity_stats.unknown += 1,
            }
            if let Some(cvss) = v.cvss {
                severity_stats.max_cvss = Some(
                    severity_stats
                        .max_cvss
                        .map_or(cvss, |existing: f64| existing.max(cvss)),
                );
            }
        }

        items.push(VulnDisplayItem::GroupHeader {
            label: label.clone(),
            count: indices.len(),
            expanded: is_expanded,
            severity_stats,
            tree: TreePos {
                depth: 0,
                is_last: is_last_group,
                parent_is_last: false,
                grandparent_is_last: false,
            },
        });
        if is_expanded {
            if matches!(group_by, VulnGroupBy::Severity) {
                // Two-level hierarchy: severity → component sub-groups → CVEs
                let mut sub_groups: indexmap::IndexMap<String, Vec<usize>> =
                    indexmap::IndexMap::new();
                for &idx in indices {
                    let key = vulns[idx].group_key.clone();
                    sub_groups.entry(key).or_default().push(idx);
                }
                sub_groups.sort_by(|_, a, _, b| b.len().cmp(&a.len()));

                let sub_count = sub_groups.len();
                for (sub_idx, (sub_label, sub_indices)) in sub_groups.iter().enumerate() {
                    let sub_key = format!("{label}::{sub_label}");
                    let sub_expanded =
                        auto_expand_all || sub_count == 1 || expanded.contains(&sub_key);
                    let is_last_sub = sub_idx == sub_count - 1;

                    let mut sub_stats = GroupSeverityStats::default();
                    for &idx in sub_indices {
                        let v = &vulns[idx];
                        match severity_rank(&v.severity) {
                            0 => sub_stats.critical += 1,
                            1 => sub_stats.high += 1,
                            2 => sub_stats.medium += 1,
                            3 => sub_stats.low += 1,
                            _ => sub_stats.unknown += 1,
                        }
                        if let Some(cvss) = v.cvss {
                            sub_stats.max_cvss = Some(
                                sub_stats
                                    .max_cvss
                                    .map_or(cvss, |existing: f64| existing.max(cvss)),
                            );
                        }
                    }

                    items.push(VulnDisplayItem::SubGroupHeader {
                        parent_label: label.clone(),
                        label: sub_label.clone(),
                        count: sub_indices.len(),
                        expanded: sub_expanded,
                        severity_stats: sub_stats,
                        tree: TreePos {
                            depth: 1,
                            is_last: is_last_sub,
                            parent_is_last: is_last_group,
                            grandparent_is_last: false,
                        },
                    });
                    if sub_expanded {
                        let vuln_count = sub_indices.len();
                        for (vi, &idx) in sub_indices.iter().enumerate() {
                            items.push(VulnDisplayItem::Vuln {
                                idx,
                                tree: TreePos {
                                    depth: 2,
                                    is_last: vi == vuln_count - 1,
                                    parent_is_last: is_last_sub,
                                    grandparent_is_last: is_last_group,
                                },
                            });
                        }
                    }
                }
            } else {
                // Component grouping: one-level children
                let vuln_count = indices.len();
                for (vi, &idx) in indices.iter().enumerate() {
                    items.push(VulnDisplayItem::Vuln {
                        idx,
                        tree: TreePos {
                            depth: 1,
                            is_last: vi == vuln_count - 1,
                            parent_is_last: is_last_group,
                            grandparent_is_last: false,
                        },
                    });
                }
            }
        }
    }
    items
}

/// #3: Normalize component names for grouping to merge duplicates.
/// Strips version suffixes, normalizes case for known packages, and merges
/// variants like "cURL"/"curl"/"libcurl", "glibc (6)"/"glibc (8)".
fn normalize_component_group_key(name: &str) -> String {
    // Strip trailing version in parentheses: "PCRE (1.2.1)" → "PCRE"
    // But keep parenthesized text that isn't a version: "Linux kernel" stays
    let base = if let Some(paren_start) = name.find(" (") {
        let inside = &name[paren_start + 2..name.len().saturating_sub(1)];
        // If content inside parens looks like a version (starts with digit or is "x.y.z"),
        // strip it; otherwise keep the full name
        if inside.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            name[..paren_start].trim()
        } else {
            name.trim()
        }
    } else {
        name.trim()
    };

    // Normalize known package name variants
    let lower = base.to_lowercase();
    match lower.as_str() {
        "curl" | "libcurl" | "curl (libcurl)" => "cURL".to_string(),
        "glibc" | "libc" | "gnu c library" => "glibc".to_string(),
        "openssl" | "libssl" | "libcrypto" => "OpenSSL".to_string(),
        "pcre" | "libpcre" | "pcre2" | "libpcre2" => "PCRE".to_string(),
        "linux kernel" | "linux" | "kernel" => "Linux kernel".to_string(),
        "bind" | "libbind" | "libdns" | "libisc" => "BIND".to_string(),
        "sqlite" | "sqlite3" | "libsqlite" | "libsqlite3" => "SQLite".to_string(),
        "ncurses" | "libtinfo" | "libncurses" => "ncurses".to_string(),
        "systemd" | "libudev" | "libsystemd" => "systemd".to_string(),
        "dbus" | "libdbus" | "dbus-daemon" => "D-Bus".to_string(),
        "openssh" | "sshd" | "sshd-session" | "ssh" => "OpenSSH".to_string(),
        "busybox" => "BusyBox".to_string(),
        "expat" | "libexpat" => "expat".to_string(),
        "kerberos" | "libkrb5" | "krb5" => "Kerberos".to_string(),
        "zlib" | "libz" => "zlib".to_string(),
        _ => base.to_string(),
    }
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
    /// Number of unique components with vulnerabilities
    pub affected_component_count: usize,
    /// Whether all vulns have the same severity (for adaptive column hiding)
    pub all_same_severity: bool,
    /// Common description prefix shared by >60% of vulns (for stripping in table)
    pub common_desc_prefix: Option<String>,
    /// Pre-computed top affected components: (display_name, count), sorted desc
    pub top_components: Vec<(String, usize)>,
    /// Whether any vuln is in KEV catalog
    #[allow(dead_code)]
    pub has_any_kev: bool,
    /// Whether any vuln has a fix available (for column visibility)
    pub has_any_fix: bool,
    /// Whether any vuln has a published date (for age column)
    pub has_any_date: bool,
    /// Whether any vuln has affected version info (for version column in severity grouping)
    pub has_any_version: bool,
}

/// Arc-wrapped cache for zero-cost cloning during render
pub type VulnCacheRef = Arc<VulnCache>;

// === Helper functions for improvements #3, #5, #8, #10 ===

/// #10: Color-code CVSS scores (red >9, orange >7, yellow >4, green <4)
fn cvss_score_color(score: f64, scheme: &crate::tui::theme::ColorScheme) -> Color {
    if score >= 9.0 {
        scheme.critical
    } else if score >= 7.0 {
        scheme.high
    } else if score >= 4.0 {
        scheme.medium
    } else if score > 0.0 {
        scheme.low
    } else {
        scheme.muted
    }
}

/// #3: Format vulnerability age as compact string (e.g., "3d", "2mo", "1y")
fn format_vuln_age(published: Option<chrono::DateTime<chrono::Utc>>) -> String {
    let Some(pub_date) = published else {
        return "-".to_string();
    };
    let days = (chrono::Utc::now() - pub_date).num_days();
    if days < 0 {
        "new".to_string()
    } else if days == 0 {
        "now".to_string()
    } else if days < 30 {
        format!("{days}d")
    } else if days < 365 {
        format!("{}mo", days / 30)
    } else {
        format!("{}y", days / 365)
    }
}

/// #9: Format days as human-readable age
fn format_age_human(days: i64) -> String {
    if days < 1 {
        "today".to_string()
    } else if days == 1 {
        "yesterday".to_string()
    } else if days < 30 {
        format!("{days} days ago")
    } else if days < 365 {
        let months = days / 30;
        if months == 1 {
            "1 month ago".to_string()
        } else {
            format!("{months} months ago")
        }
    } else {
        let years = days / 365;
        if years == 1 {
            "1 year ago".to_string()
        } else {
            format!("{years} years ago")
        }
    }
}

/// #5: Parse CVSS vector string into colored components
fn parse_cvss_vector(vector: &str) -> Vec<(&str, &str, Color)> {
    let scheme = colors();
    let mut result = Vec::new();

    // Parse CVSS:3.x vectors like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    for part in vector.split('/') {
        let Some((key, val)) = part.split_once(':') else {
            continue;
        };
        // Skip version prefix
        if key == "CVSS" {
            continue;
        }
        let color = match (key, val) {
            // Attack Vector
            ("AV", "N") => scheme.critical, // Network = worst
            ("AV", "A") => scheme.high,     // Adjacent
            ("AV", "L") => scheme.medium,   // Local
            ("AV", "P") => scheme.low,      // Physical
            // Attack Complexity
            ("AC", "L") => scheme.high, // Low complexity = easier
            ("AC", "H") => scheme.low,  // High complexity = harder
            // Privileges Required
            ("PR", "N") => scheme.critical, // None = worst
            ("PR", "L") => scheme.medium,   // Low
            ("PR", "H") => scheme.low,      // High
            // User Interaction
            ("UI", "N") => scheme.high, // None = worse
            ("UI", "R") => scheme.low,  // Required
            // Confidentiality/Integrity/Availability Impact
            (_, "H") => scheme.critical,
            (_, "L") => scheme.medium,
            (_, "N") => scheme.low,
            // Scope
            ("S", "C") => scheme.critical, // Changed = worse
            ("S", "U") => scheme.low,      // Unchanged
            _ => scheme.text,
        };
        result.push((key, val, color));
    }
    result
}

/// #8: Common CWE short names for display in list and detail
fn cwe_short_name(cwe_id: &str) -> &'static str {
    match cwe_id {
        "CWE-20" => "Improper Input Validation",
        "CWE-22" => "Path Traversal",
        "CWE-77" => "Command Injection",
        "CWE-78" => "OS Command Injection",
        "CWE-79" => "Cross-Site Scripting (XSS)",
        "CWE-89" => "SQL Injection",
        "CWE-94" => "Code Injection",
        "CWE-119" => "Buffer Overflow",
        "CWE-120" => "Buffer Copy w/o Bounds Check",
        "CWE-125" => "Out-of-bounds Read",
        "CWE-170" => "Improper Null Termination",
        "CWE-190" => "Integer Overflow",
        "CWE-191" => "Integer Underflow",
        "CWE-200" => "Information Exposure",
        "CWE-252" => "Unchecked Return Value",
        "CWE-269" => "Improper Privilege Management",
        "CWE-276" => "Incorrect Default Permissions",
        "CWE-287" => "Improper Authentication",
        "CWE-295" => "Improper Certificate Validation",
        "CWE-310" => "Cryptographic Issues",
        "CWE-311" => "Missing Encryption",
        "CWE-319" => "Cleartext Transmission",
        "CWE-326" => "Inadequate Encryption Strength",
        "CWE-327" => "Broken Crypto Algorithm",
        "CWE-352" => "Cross-Site Request Forgery",
        "CWE-362" => "Race Condition",
        "CWE-369" => "Divide By Zero",
        "CWE-400" => "Resource Exhaustion",
        "CWE-401" => "Memory Leak",
        "CWE-415" => "Double Free",
        "CWE-416" => "Use After Free",
        "CWE-434" => "Unrestricted File Upload",
        "CWE-476" => "NULL Pointer Dereference",
        "CWE-502" => "Deserialization of Untrusted Data",
        "CWE-521" => "Weak Password Requirements",
        "CWE-532" => "Info Exposure via Log",
        "CWE-601" => "Open Redirect",
        "CWE-611" => "XXE (XML External Entity)",
        "CWE-617" => "Reachable Assertion",
        "CWE-667" => "Improper Locking",
        "CWE-674" => "Uncontrolled Recursion",
        "CWE-704" => "Incorrect Type Conversion",
        "CWE-732" => "Incorrect Permission Assignment",
        "CWE-754" => "Improper Check for Exceptional Condition",
        "CWE-770" => "Allocation w/o Limits",
        "CWE-772" => "Missing Resource Release",
        "CWE-787" => "Out-of-bounds Write",
        "CWE-798" => "Hard-coded Credentials",
        "CWE-835" => "Infinite Loop",
        "CWE-862" => "Missing Authorization",
        "CWE-863" => "Incorrect Authorization",
        "CWE-908" => "Uninitialized Resource",
        "CWE-918" => "Server-Side Request Forgery",
        _ => "",
    }
}

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

    // ---------------------------------------------------------------------
    // EPSS + KEV-filter parity tests
    // ---------------------------------------------------------------------

    use crate::model::{
        CanonicalId, Component, NormalizedSbom, Severity, VulnerabilityRef, VulnerabilitySource,
    };

    /// Build a `ViewApp` over a small SBOM with two components: one carrying a
    /// KEV-flagged vuln (with EPSS), the other a plain vuln (no EPSS).
    fn epss_kev_app() -> ViewApp {
        let mut sbom = NormalizedSbom::default();

        let mut kev_comp = Component::new("kev-lib".to_string(), "kev-ref".to_string())
            .with_version("1.0.0".to_string());
        let mut kev_vuln =
            VulnerabilityRef::new("CVE-2024-0001".to_string(), VulnerabilitySource::Nvd);
        kev_vuln.severity = Some(Severity::Critical);
        kev_vuln.is_kev = true;
        kev_vuln.epss_score = Some(0.73);
        kev_comp.vulnerabilities.push(kev_vuln);
        sbom.components
            .insert(CanonicalId::from_name_version("kev-lib", None), kev_comp);

        let mut plain_comp = Component::new("plain-lib".to_string(), "plain-ref".to_string())
            .with_version("2.0.0".to_string());
        let mut plain_vuln =
            VulnerabilityRef::new("CVE-2024-0002".to_string(), VulnerabilitySource::Nvd);
        plain_vuln.severity = Some(Severity::High);
        plain_comp.vulnerabilities.push(plain_vuln);
        sbom.components.insert(
            CanonicalId::from_name_version("plain-lib", None),
            plain_comp,
        );

        ViewApp::new(sbom, "", crate::model::BomProfile::Sbom)
    }

    #[test]
    fn build_vuln_cache_populates_epss_score() {
        let app = epss_kev_app();
        let cache = build_vuln_cache(&app);
        let kev_row = cache
            .vulns
            .iter()
            .find(|v| v.vuln_id == "CVE-2024-0001")
            .expect("KEV vuln present");
        assert_eq!(kev_row.epss_score, Some(0.73));
        let plain_row = cache
            .vulns
            .iter()
            .find(|v| v.vuln_id == "CVE-2024-0002")
            .expect("plain vuln present");
        assert_eq!(plain_row.epss_score, None);
    }

    #[test]
    fn kev_filter_isolates_kev_vulns() {
        let mut app = epss_kev_app();
        // Without the filter both vulns are present.
        let cache = build_vuln_cache(&app);
        assert_eq!(cache.vulns.len(), 2);
        assert!(cache.has_any_kev);

        // Enabling the KEV-only filter drops the non-KEV vuln.
        app.vuln_state.toggle_kev_filter();
        assert!(app.vuln_state.filter_kev);
        let filtered = build_vuln_cache(&app);
        assert_eq!(filtered.vulns.len(), 1);
        assert_eq!(filtered.vulns[0].vuln_id, "CVE-2024-0001");
        assert!(filtered.vulns[0].is_kev);

        // Toggling off restores the full set.
        app.vuln_state.toggle_kev_filter();
        assert!(!app.vuln_state.filter_kev);
        assert_eq!(build_vuln_cache(&app).vulns.len(), 2);
    }
}
