//! Vulnerability explorer view for ViewApp.

use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, ViewApp, VulnGroupBy};
use crate::tui::widgets::{truncate_str, SeverityBadge};
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
        (count * bar_width / total).max(if count > 0 { 1 } else { 0 })
    } else {
        0
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            format!(" {} ", label),
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
    let filter_label = match &app.vuln_state.filter_severity {
        Some(s) => s.to_uppercase(),
        None => "All".to_string(),
    };

    let _group_label = match app.vuln_state.group_by {
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
            format!(" {} ", filter_label),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Dedupe: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {} ", dedupe_label),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if app.vuln_state.deduplicate {
                    scheme.success
                } else {
                    scheme.muted
                })
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[f]", Style::default().fg(scheme.accent)),
        Span::raw(" filter  "),
        Span::styled("[d]", Style::default().fg(scheme.accent)),
        Span::raw(" dedupe  "),
        Span::styled("[p]", Style::default().fg(scheme.accent)),
        Span::raw(" panel  "),
    ];

    if !app.vuln_state.deduplicate {
        spans.push(Span::styled("[Enter]", Style::default().fg(scheme.accent)));
        spans.push(Span::raw(" jump"));
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
    let cache = app.vuln_state.cached_data.clone().unwrap();
    let has_any_cvss = cache.has_any_cvss;
    let all_same_component = cache.all_same_component;
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
                .map(|s| s.to_uppercase())
                .unwrap_or_else(|| "current".to_string());
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

    // Update total and clamp selection (vulns are pre-sorted in cache)
    app.vuln_state.total = cache.vulns.len();
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
        app,
        has_any_cvss,
        all_same_component,
        is_left_focused,
    );

    // Render detail panel
    let selected_vuln = cache.vulns.get(app.vuln_state.selected);
    render_vuln_detail_panel(frame, chunks[1], selected_vuln, !is_left_focused);
}

/// Build the vulnerability cache from SBOM data
fn build_vuln_cache(app: &ViewApp) -> VulnCache {
    use std::collections::HashMap;

    let mut vulns: Vec<VulnRow> = Vec::new();
    let mut total_unfiltered = 0;
    let mut has_any_cvss = false;
    let mut all_same_component = true;
    let mut first_component: Option<String> = None;

    // If deduplicating, collect by CVE ID first
    if app.vuln_state.deduplicate {
        let mut vuln_map: HashMap<String, VulnRow> = HashMap::new();

        for (comp_id, comp) in &app.sbom.components {
            for vuln in &comp.vulnerabilities {
                total_unfiltered += 1;
                let sev = vuln
                    .severity
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                // Apply filter
                if let Some(ref filter) = app.vuln_state.filter_severity {
                    if sev.to_lowercase() != *filter {
                        continue;
                    }
                }

                let cvss = vuln.max_cvss_score().map(|v| v as f64);
                if cvss.is_some() {
                    has_any_cvss = true;
                }

                vuln_map
                    .entry(vuln.id.clone())
                    .and_modify(|existing| {
                        existing.affected_count += 1;
                        existing.affected_components.push(comp.name.clone());
                        // Keep the highest CVSS score
                        if let Some(new_cvss) = cvss {
                            if existing.cvss.map_or(true, |c| new_cvss > c) {
                                existing.cvss = Some(new_cvss);
                            }
                        }
                    })
                    .or_insert(VulnRow {
                        vuln_id: vuln.id.clone(),
                        severity: sev,
                        cvss,
                        component_name: comp.name.clone(),
                        component_id: comp_id.value().to_string(),
                        description: vuln.description.clone(),
                        affected_count: 1,
                        affected_components: vec![comp.name.clone()],
                        cwes: vuln.cwes.clone(),
                        display_name: None,
                    });
            }
        }

        vulns = vuln_map.into_values().collect();
    } else {
        for (comp_id, comp) in &app.sbom.components {
            for vuln in &comp.vulnerabilities {
                total_unfiltered += 1;
                let sev = vuln
                    .severity
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                // Apply filter
                if let Some(ref filter) = app.vuln_state.filter_severity {
                    if sev.to_lowercase() != *filter {
                        continue;
                    }
                }

                let cvss = vuln.max_cvss_score().map(|v| v as f64);
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
                    display_name: None,
                });
            }
        }
    }

    // Sort by severity then CVSS (done once at cache build time)
    vulns.sort_by(|a, b| {
        let sev_order = |s: &str| match s.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let ord = sev_order(&b.severity).cmp(&sev_order(&a.severity));
        if ord == std::cmp::Ordering::Equal {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        } else {
            ord
        }
    });

    VulnCache {
        vulns,
        has_any_cvss,
        all_same_component,
        total_unfiltered,
    }
}

fn render_vuln_table_panel(
    frame: &mut Frame,
    area: Rect,
    vulns: &[VulnRow],
    app: &mut ViewApp,
    has_any_cvss: bool,
    all_same_component: bool,
    is_focused: bool,
) {
    let scheme = colors();
    let is_dedupe = app.vuln_state.deduplicate;

    // Determine which columns to show
    let show_cvss = has_any_cvss;
    let show_component = !all_same_component || is_dedupe;

    // Build dynamic column widths and headers
    let (widths, headers): (Vec<Constraint>, Vec<&str>) = if show_cvss && show_component {
        (
            vec![
                Constraint::Length(3),
                Constraint::Length(16),
                Constraint::Length(5),
                Constraint::Length(20),
                Constraint::Min(15),
            ],
            if is_dedupe {
                vec!["", "CVE ID", "CVSS", "Affected", "Description"]
            } else {
                vec!["", "CVE ID", "CVSS", "Component", "Description"]
            },
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
        )
    } else if show_component {
        (
            vec![
                Constraint::Length(3),
                Constraint::Length(16),
                Constraint::Length(20),
                Constraint::Min(20),
            ],
            if is_dedupe {
                vec!["", "CVE ID", "Affected", "Description"]
            } else {
                vec!["", "CVE ID", "Component", "Description"]
            },
        )
    } else {
        // No CVSS, all same component - maximize description
        (
            vec![
                Constraint::Length(3),
                Constraint::Length(16),
                Constraint::Min(30),
            ],
            vec!["", "CVE ID", "Description"],
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
    // Calculate visible window (header=1, borders=2, so content height = area.height - 3)
    let visible_height = area.height.saturating_sub(3) as usize;
    let total_items = vulns.len();

    // Ensure scroll offset keeps selection visible
    let selected = app.vuln_state.selected;
    let mut scroll_offset = app.vuln_state.scroll_offset;

    // Adjust scroll to keep selection in view
    if selected < scroll_offset {
        scroll_offset = selected;
    } else if selected >= scroll_offset + visible_height {
        scroll_offset = selected.saturating_sub(visible_height - 1);
    }
    app.vuln_state.scroll_offset = scroll_offset;

    // Calculate the range of items to render (with a small buffer)
    let buffer = 2; // Render a few extra rows for smooth scrolling
    let start = scroll_offset.saturating_sub(buffer);
    let end = (scroll_offset + visible_height + buffer).min(total_items);

    // Build rows only for visible window
    let rows: Vec<Row> = vulns[start..end]
        .iter()
        .map(|v| {
            let sev_color = SeverityBadge::fg_color(&v.severity);

            let mut cells = vec![
                Cell::from(Span::styled(
                    SeverityBadge::indicator(&v.severity),
                    Style::default()
                        .fg(scheme.severity_badge_fg(&v.severity))
                        .bg(sev_color)
                        .bold(),
                )),
                Cell::from(Span::styled(
                    truncate_str(&v.vuln_id, 16),
                    Style::default().fg(sev_color).bold(),
                )),
            ];

            if show_cvss {
                cells.push(Cell::from(
                    v.cvss
                        .map(|c| format!("{:.1}", c))
                        .unwrap_or_else(|| "-".to_string()),
                ));
            }

            if show_component {
                if is_dedupe {
                    cells.push(Cell::from(Span::styled(
                        format!("{} comp", v.affected_count),
                        Style::default().fg(scheme.primary),
                    )));
                } else {
                    // Try to extract meaningful name from path or description
                    let display_name =
                        extract_component_display_name(&v.component_name, v.description.as_deref());
                    cells.push(Cell::from(Span::styled(
                        truncate_str(&display_name, 20),
                        Style::default().fg(scheme.primary),
                    )));
                }
            }

            cells.push(Cell::from(Span::styled(
                v.description
                    .as_ref()
                    .map(|d| truncate_str(d, desc_width.max(15)))
                    .unwrap_or_else(|| "-".to_string()),
                Style::default().fg(scheme.text),
            )));

            Row::new(cells)
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

    // Adjust selected index relative to the visible window
    let relative_selected = if selected >= start && selected < end {
        Some(selected - start)
    } else {
        None
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Vulnerabilities ({}) ", vulns.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶");

    // Use relative offset within the visible window
    let mut state = TableState::default()
        .with_offset(scroll_offset.saturating_sub(start))
        .with_selected(relative_selected);

    frame.render_stateful_widget(table, area, &mut state);

    // Scrollbar
    let visible_height = area.height.saturating_sub(3) as usize;
    if vulns.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.high))
            .track_style(Style::default().fg(scheme.muted));

        let mut scrollbar_state =
            ScrollbarState::new(vulns.len()).position(app.vuln_state.selected);

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
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let Some(v) = vuln else {
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

    // CVE ID with severity badge
    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} ", SeverityBadge::indicator(&v.severity)),
            Style::default()
                .fg(scheme.severity_badge_fg(&v.severity))
                .bg(sev_color)
                .bold(),
        ),
        Span::raw(" "),
        Span::styled(&v.vuln_id, Style::default().fg(sev_color).bold()),
    ]));
    lines.push(Line::from(""));

    // Severity
    lines.push(Line::from(vec![
        Span::styled("Severity: ", Style::default().fg(scheme.muted)),
        Span::styled(&v.severity, Style::default().fg(sev_color).bold()),
    ]));

    // CVSS
    if let Some(cvss) = v.cvss {
        lines.push(Line::from(vec![
            Span::styled("CVSS:     ", Style::default().fg(scheme.muted)),
            Span::styled(format!("{:.1}", cvss), Style::default().fg(scheme.text).bold()),
        ]));
    }

    lines.push(Line::from(""));

    // Component(s)
    lines.push(Line::from(Span::styled(
        "Component:",
        Style::default().fg(scheme.muted),
    )));

    if v.affected_count > 1 {
        lines.push(Line::from(Span::styled(
            format!("  {} components affected", v.affected_count),
            Style::default().fg(scheme.primary),
        )));
        // Show first few
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
        let display = extract_component_display_name(&v.component_name, v.description.as_deref());
        lines.push(Line::from(Span::styled(
            format!("  {}", display),
            Style::default().fg(scheme.primary),
        )));
        // Show full path if different
        if display != v.component_name {
            lines.push(Line::from(Span::styled(
                format!("  ({})", truncate_str(&v.component_name, 40)),
                Style::default().fg(scheme.muted).dim(),
            )));
        }
    }

    lines.push(Line::from(""));

    // CWEs
    if !v.cwes.is_empty() {
        lines.push(Line::from(Span::styled(
            "CWEs:",
            Style::default().fg(scheme.muted),
        )));
        for cwe in v.cwes.iter().take(5) {
            lines.push(Line::from(Span::styled(
                format!("  {}", cwe),
                Style::default().fg(scheme.warning),
            )));
        }
        lines.push(Line::from(""));
    }

    // Description
    lines.push(Line::from(Span::styled(
        "Description:",
        Style::default().fg(scheme.muted),
    )));

    if let Some(desc) = &v.description {
        // Word wrap the description
        let max_width = area.width.saturating_sub(4) as usize;
        for wrapped_line in word_wrap(desc, max_width) {
            lines.push(Line::from(Span::styled(
                format!("  {}", wrapped_line),
                Style::default().fg(scheme.text),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  No description available",
            Style::default().fg(scheme.muted).italic(),
        )));
    }

    let block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
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
    if let Some(desc) = description {
        if let Some(pkg_name) = extract_package_from_description(desc) {
            return pkg_name;
        }
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
    if clean.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_') && clean.len() > 8 {
        return true;
    }

    // Check if it's mostly numeric
    let digit_count = clean.chars().filter(|c| c.is_ascii_digit()).count();
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
    if name.starts_with("./") || name.starts_with("/") || name.contains('/') {
        if let Some(filename) = name.rsplit('/').next() {
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
        "busybox", "glibc", "musl", "uclibc", "openssl", "libssl", "libcrypto",
        "zlib", "bzip2", "xz", "lzma", "lz4", "zstd",
        "pcre", "pcre2", "libpcre", "libpcre2",
        "curl", "libcurl", "wget",
        "sqlite", "sqlite3", "libsqlite",
        "expat", "libexpat", "libxml2", "libxslt",
        "libjpeg", "libpng", "libtiff", "libwebp", "giflib",
        "freetype", "fontconfig", "harfbuzz",
        "openldap", "libldap",
        "libssh", "libssh2", "openssh",
        "gnutls", "mbedtls", "wolfssl", "libressl",
        "dbus", "systemd", "udev",
        "linux", "kernel", "linux-kernel",
        "bash", "dash", "ash", "sh",
        "python", "perl", "ruby", "php", "lua",
        "nginx", "apache", "httpd", "lighttpd",
        "libuv", "libevent", "libev",
        "protobuf", "grpc", "flatbuffers",
        "boost", "poco", "qt",
        "ncurses", "readline",
        "icu", "libicu",
        "libidn", "libidn2",
        "nettle", "libgcrypt", "libsodium",
        "nss", "nspr",
        "krb5", "libkrb5",
        "cyrus-sasl", "libsasl",
        "pam", "libpam",
        "audit", "libaudit",
        "selinux", "libselinux",
        "acl", "libacl", "attr", "libattr",
        "cap", "libcap",
        "util-linux", "coreutils", "findutils",
        "binutils", "gcc", "llvm", "clang",
        "dropbear", "dnsmasq", "hostapd", "wpa_supplicant",
        "iptables", "nftables", "iproute2",
        "tcpdump", "libpcap",
        "snmp", "net-snmp",
        "ntp", "chrony",
        "samba", "cifs",
        // Firmware/embedded specific
        "u-boot", "grub", "barebox",
        "mtd-utils", "squashfs", "jffs2", "ubifs",
        "openwrt", "buildroot", "yocto",
    ];

    let desc_lower = description.to_lowercase();

    // Strategy 1: Look for known package names at word boundaries
    for &pkg in KNOWN_PACKAGES {
        // Check various patterns where the package might appear
        let patterns = [
            format!("{} ", pkg),           // "busybox allows..."
            format!(" {} ", pkg),          // "in busybox before..."
            format!("in {}", pkg),         // "vulnerability in busybox"
            format!("{} before", pkg),     // "busybox before 1.35"
            format!("{} through", pkg),    // "busybox through 1.35"
            format!("{} prior", pkg),      // "busybox prior to"
            format!("lib{}", pkg),         // "libcurl" when looking for "curl"
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
        " before ", " through ", " prior to ", " up to ", " <= ", " < ",
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
    if let Some(in_pos) = desc_lower.find(" in ") {
        if in_pos < 50 {
            // Only look near the start
            let after_in = &description[in_pos + 4..];
            if let Some(pkg) = extract_first_word(after_in) {
                let pkg_lower = pkg.to_lowercase();
                if !is_noise_word(&pkg_lower) && pkg.len() >= 2 && pkg.len() <= 30 {
                    return Some(pkg.to_string());
                }
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
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        }
    }
}

/// Extract the word immediately before a position
fn extract_word_before(text: &str) -> Option<&str> {
    let trimmed = text.trim_end();
    let last_space = trimmed.rfind(|c: char| c.is_whitespace() || c == '(' || c == ',')?;
    let word = &trimmed[last_space + 1..];
    if word.is_empty() {
        None
    } else {
        Some(word)
    }
}

/// Extract the first word from text
fn extract_first_word(text: &str) -> Option<&str> {
    let trimmed = text.trim_start();
    let end = trimmed.find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '.')?;
    let word = &trimmed[..end];
    if word.is_empty() {
        None
    } else {
        Some(word)
    }
}

/// Check if a word is likely not a package name
fn is_noise_word(word: &str) -> bool {
    const NOISE: &[&str] = &[
        "a", "an", "the", "this", "that", "these", "those",
        "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did",
        "will", "would", "could", "should", "may", "might", "must",
        "vulnerability", "vulnerabilities", "issue", "issues", "flaw", "flaws",
        "bug", "bugs", "error", "errors", "problem", "problems",
        "attack", "attacker", "attackers", "remote", "local",
        "user", "users", "function", "functions", "method", "methods",
        "file", "files", "memory", "buffer", "heap", "stack",
        "overflow", "underflow", "corruption", "leak", "injection",
        "code", "execution", "denial", "service", "access", "control",
        "certain", "some", "all", "any", "many", "multiple",
        "allows", "allow", "allowed", "enabling", "enables", "enable",
        "causes", "cause", "caused", "leading", "leads", "lead",
        "via", "through", "using", "when", "where", "which", "what",
        "version", "versions", "release", "releases",
        "component", "components", "module", "modules", "package", "packages",
        "application", "applications", "program", "programs", "software",
        "system", "systems", "server", "servers", "client", "clients",
        "library", "libraries", "framework", "frameworks",
        "and", "or", "but", "not", "with", "without", "for", "from", "to",
        "of", "on", "at", "by", "as", "if", "so", "than",
        "discovered", "found", "identified", "reported", "fixed",
        "cve", "nvd", "cwe",
    ];
    NOISE.contains(&word)
}

/// Simple word wrapping
fn word_wrap(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= max_width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
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
    /// Cached display name (computed lazily from description)
    pub display_name: Option<String>,
}

use std::sync::Arc;

/// Cached vulnerability list with metadata (wrapped in Arc for cheap cloning)
#[derive(Debug, Clone, Default)]
pub struct VulnCache {
    pub vulns: Vec<VulnRow>,
    pub has_any_cvss: bool,
    pub all_same_component: bool,
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
