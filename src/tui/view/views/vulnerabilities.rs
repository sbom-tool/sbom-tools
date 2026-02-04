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
    use std::collections::HashMap;

    // Build vulnerability list first to check if we have any
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
                });
            }
        }
    }

    // Handle empty states
    if vulns.is_empty() {
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

    // Sort by severity then CVSS
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

    // Update total and clamp selection
    app.vuln_state.total = vulns.len();
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
        &vulns,
        app,
        has_any_cvss,
        all_same_component,
        is_left_focused,
    );

    // Render detail panel
    let selected_vuln = vulns.get(app.vuln_state.selected);
    render_vuln_detail_panel(frame, chunks[1], selected_vuln, !is_left_focused);
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

    // Build rows
    let rows: Vec<Row> = vulns
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
                    // Try to extract meaningful name from path
                    let display_name = extract_component_display_name(&v.component_name);
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

    let mut state = TableState::default()
        .with_offset(app.vuln_state.scroll_offset)
        .with_selected(if vulns.is_empty() {
            None
        } else {
            Some(app.vuln_state.selected)
        });

    frame.render_stateful_widget(table, area, &mut state);
    app.vuln_state.scroll_offset = state.offset();

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
            let display = extract_component_display_name(comp);
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
        let display = extract_component_display_name(&v.component_name);
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

/// Extract a meaningful display name from a component path
fn extract_component_display_name(name: &str) -> String {
    // If it looks like a file path, try to extract something meaningful
    if name.starts_with("./") || name.starts_with("/") || name.contains('/') {
        // Get the filename
        if let Some(filename) = name.rsplit('/').next() {
            // Remove common extensions
            let clean = filename
                .trim_end_matches(".squ")
                .trim_end_matches(".squashfs")
                .trim_end_matches(".img")
                .trim_end_matches(".bin");

            // If it's still a hash-like name, try to be more helpful
            if clean.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                return format!("file:{}", truncate_str(clean, 12));
            }
            return clean.to_string();
        }
    }
    name.to_string()
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

struct VulnRow {
    vuln_id: String,
    severity: String,
    cvss: Option<f64>,
    component_name: String,
    #[allow(dead_code)]
    component_id: String,
    description: Option<String>,
    affected_count: usize,
    affected_components: Vec<String>,
    cwes: Vec<String>,
}
