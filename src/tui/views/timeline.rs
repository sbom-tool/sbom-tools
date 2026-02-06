//! Timeline analysis view.
//!
//! Displays SBOM evolution over time with version tracking.

use crate::diff::{TimelineResult, VersionChangeType};
use crate::tui::app::{TimelineComponentFilter, TimelineState};
use crate::tui::theme::colors;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Render the timeline analysis view
pub(crate) fn render_timeline(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let chunks = if state.show_statistics {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(6), // Statistics panel
                Constraint::Length(8), // Timeline bar
                Constraint::Min(12),   // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(8), // Timeline bar
                Constraint::Min(15),   // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(area)
    };

    // Header
    render_header(f, chunks[0], result, state);

    let (bar_chunk, main_chunk, status_chunk) = if state.show_statistics {
        // Render statistics panel
        render_statistics_panel(f, chunks[1], result);
        (chunks[2], chunks[3], chunks[4])
    } else {
        (chunks[1], chunks[2], chunks[3])
    };

    // Timeline visualization
    render_timeline_bar(f, bar_chunk, result, state);

    // Main content - split into versions and component history
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_chunk);

    render_versions_list(f, main_chunks[0], result, state);
    render_component_history(f, main_chunks[1], result, state);

    // Status bar
    render_status_bar(f, status_chunk, result, state);

    // Render overlays
    if state.show_version_diff_modal {
        render_version_diff_modal(f, area, result, state);
    }

    if state.show_component_history {
        render_component_history_modal(f, area, result, state);
    }

    if state.search.active {
        render_search_overlay(f, area, state);
    }

    if state.jump_mode {
        render_jump_overlay(f, area, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let scheme = colors();
    let first = result.sboms.first().map_or("?", |s| s.name.as_str());
    let last = result.sboms.last().map_or("?", |s| s.name.as_str());

    let title = format!(
        " Timeline: {} → {} ({} versions) ",
        first,
        last,
        result.sboms.len()
    );

    let text = vec![Line::from(vec![
        Span::styled(
            title,
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled("Sort: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(
                "{} {}",
                state.sort_by.label(),
                state.sort_direction.indicator()
            ),
            Style::default().fg(scheme.accent),
        ),
        Span::raw(" │ "),
        Span::styled("Filter: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            state.component_filter.label(),
            Style::default().fg(scheme.accent),
        ),
        if state.show_statistics {
            Span::styled(" │ Stats", Style::default().fg(scheme.info))
        } else {
            Span::raw("")
        },
    ])];

    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn render_statistics_panel(f: &mut Frame, area: Rect, result: &TimelineResult) {
    let scheme = colors();

    let total_added: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_added)
        .sum();
    let total_removed: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_removed)
        .sum();
    let total_modified: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_modified)
        .sum();

    let avg_components: usize = if !result.sboms.is_empty() {
        result
            .sboms
            .iter()
            .map(|s| s.component_count)
            .sum::<usize>()
            / result.sboms.len()
    } else {
        0
    };

    // Compliance trend summary: count how many versions pass CRA Phase 2
    let compliance_trend = &result.evolution_summary.compliance_trend;
    let cra_pass_count = compliance_trend
        .iter()
        .filter(|snap| {
            snap.scores
                .iter()
                .any(|s| s.standard.contains("CRA Phase 2") && s.is_compliant)
        })
        .count();
    let compliance_trend_str = if compliance_trend.is_empty() {
        "N/A".to_string()
    } else {
        format!("{}/{} pass CRA", cra_pass_count, compliance_trend.len())
    };
    let compliance_color = if cra_pass_count == compliance_trend.len() && !compliance_trend.is_empty() {
        scheme.success
    } else if cra_pass_count > 0 {
        scheme.warning
    } else {
        scheme.error
    };

    let text = vec![
        Line::from(vec![
            Span::styled("Total Added: ", Style::default().fg(scheme.added)),
            Span::raw(total_added.to_string()),
            Span::raw("  "),
            Span::styled("Total Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(total_removed.to_string()),
            Span::raw("  "),
            Span::styled("Total Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(total_modified.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Avg Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                avg_components.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw("  "),
            Span::styled("Version Changes: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                result.evolution_summary.version_history.len().to_string(),
                Style::default().fg(scheme.accent),
            ),
            Span::raw("  "),
            Span::styled("Compliance: ", Style::default().fg(scheme.text_muted)),
            Span::styled(compliance_trend_str, Style::default().fg(compliance_color)),
        ]),
    ];

    let block = Block::default()
        .title(" Statistics [t: toggle] ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn render_timeline_bar(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let scheme = colors();
    let selected = state.selected_version;

    // Calculate bar width based on zoom level
    let bar_width = 5 + (state.chart_zoom as u16 * 2);

    // Calculate visible range based on scroll
    let visible_count = (area.width.saturating_sub(4)) / (bar_width + 1);
    let start_idx = state
        .chart_scroll
        .min(result.sboms.len().saturating_sub(visible_count as usize));
    let end_idx = (start_idx + visible_count as usize).min(result.sboms.len());

    let bars: Vec<Bar> = result
        .sboms
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(end_idx - start_idx)
        .map(|(i, sbom)| {
            let style = if i == selected {
                Style::default().fg(scheme.accent)
            } else if state.compare_version == Some(i) {
                Style::default().fg(scheme.warning)
            } else {
                Style::default().fg(scheme.primary)
            };

            Bar::default()
                .value(sbom.component_count as u64)
                .label(Line::from(
                    sbom.name
                        .chars()
                        .take(bar_width as usize - 1)
                        .collect::<String>(),
                ))
                .style(style)
        })
        .collect();

    let title = format!(
        " Component Count Evolution ({}-{}/{}) [+/-: zoom, h/l: scroll] ",
        start_idx + 1,
        end_idx,
        result.sboms.len()
    );

    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.info)),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(1)
        .max(
            result
                .sboms
                .iter()
                .map(|s| s.component_count)
                .max()
                .unwrap_or(100) as u64
                + 10,
        );

    f.render_widget(barchart, area);
}

fn render_versions_list(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, TimelinePanel::Versions);
    let selected = state.selected_version;

    let rows: Vec<Row> = result
        .sboms
        .iter()
        .enumerate()
        .map(|(i, sbom)| {
            // Get diff info if available
            let (added, removed) = if i > 0 {
                result
                    .incremental_diffs
                    .get(i - 1)
                    .map_or((0, 0), |d| (d.summary.components_added, d.summary.components_removed))
            } else {
                (sbom.component_count, 0)
            };

            let is_compare_target = state.compare_version == Some(i);
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else if is_compare_target {
                Style::default()
                    .bg(scheme.warning)
                    .add_modifier(Modifier::ITALIC)
            } else {
                Style::default()
            };

            // Highlight search matches
            let name_style = if state.search.matches.contains(&i) {
                style.fg(scheme.accent).add_modifier(Modifier::BOLD)
            } else {
                style
            };

            let change_str = if i == 0 {
                "initial".to_string()
            } else {
                format!("+{added} -{removed}")
            };

            let change_color = if added > removed {
                scheme.added
            } else if removed > added {
                scheme.removed
            } else {
                scheme.text_muted
            };

            // CRA Phase 2 compliance indicator for this version
            let compliance_indicator = result
                .evolution_summary
                .compliance_trend
                .get(i)
                .map_or(("-", scheme.text_muted), |snap| {
                    // Find CRA Phase 2 score
                    let cra = snap.scores.iter().find(|s| s.standard.contains("CRA Phase 2"));
                    match cra {
                        Some(s) if s.is_compliant && s.warning_count == 0 => ("✓", scheme.success),
                        Some(s) if s.is_compliant => ("⚠", scheme.warning),
                        Some(_) => ("✗", scheme.error),
                        None => ("-", scheme.text_muted),
                    }
                });

            Row::new(vec![
                Cell::from(format!("{}.", i + 1)).style(style),
                Cell::from(sbom.name.clone()).style(name_style),
                Cell::from(sbom.component_count.to_string()).style(style),
                Cell::from(change_str).style(style.fg(change_color)),
                Cell::from(compliance_indicator.0)
                    .style(style.fg(compliance_indicator.1)),
            ])
        })
        .collect();

    let header = Row::new(vec!["#", "Version", "Comps", "Changes", "CRA"])
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths = [
        Constraint::Length(4),
        Constraint::Min(10),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(4),
    ];

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };
    let title = " Versions [g: jump, d: diff] ".to_string();

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(table, area);
}

fn render_component_history(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, TimelinePanel::Components);
    let selected = state.selected_component;

    // Get component evolution data with filtering
    let all_evolutions: Vec<_> = result
        .evolution_summary
        .components_added
        .iter()
        .map(|e| (e, false)) // (evolution, is_removed)
        .chain(
            result
                .evolution_summary
                .components_removed
                .iter()
                .map(|e| (e, true)),
        )
        .collect();

    let filtered_evolutions: Vec<_> = all_evolutions
        .iter()
        .filter(|(evo, is_removed)| {
            match state.component_filter {
                TimelineComponentFilter::All => true,
                TimelineComponentFilter::Added => !*is_removed,
                TimelineComponentFilter::Removed => *is_removed,
                TimelineComponentFilter::VersionChanged => {
                    // Check if version changed
                    evo.current_version.as_ref() != Some(&evo.first_seen_version)
                }
                TimelineComponentFilter::Stable => {
                    !*is_removed && evo.current_version.as_ref() == Some(&evo.first_seen_version)
                }
            }
        })
        .collect();

    let rows: Vec<Row> = filtered_evolutions
        .iter()
        .enumerate()
        .take(20)
        .map(|(i, (evo, is_removed))| {
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let status_style = if *is_removed {
                Style::default().fg(scheme.removed)
            } else {
                Style::default().fg(scheme.added)
            };

            let status = if *is_removed { "Removed" } else { "Added" };
            let version_info = if *is_removed {
                format!("{} @ v{}", evo.first_seen_version, evo.first_seen_index + 1)
            } else {
                evo.current_version
                    .clone()
                    .unwrap_or(evo.first_seen_version.clone())
            };

            Row::new(vec![
                Cell::from(evo.name.clone()).style(style),
                Cell::from(version_info).style(style),
                Cell::from(format!("v{}", evo.first_seen_index + 1)).style(style),
                Cell::from(status).style(status_style),
            ])
        })
        .collect();

    let header = Row::new(vec!["Component", "Version", "Since", "Status"])
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
    ];

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };

    let title = format!(
        " Component Evolution ({}/{}) [f: filter, Enter: detail] ",
        filtered_evolutions.len(),
        all_evolutions.len()
    );

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(table, area);
}

fn render_status_bar(f: &mut Frame, area: Rect, result: &TimelineResult, _state: &TimelineState) {
    let scheme = colors();
    let total_added: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_added)
        .sum();
    let total_removed: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_removed)
        .sum();

    let status = Line::from(vec![
        Span::styled("Added: ", Style::default().fg(scheme.text_muted)),
        Span::styled(total_added.to_string(), Style::default().fg(scheme.added)),
        Span::raw("  "),
        Span::styled("Removed: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            total_removed.to_string(),
            Style::default().fg(scheme.removed),
        ),
        Span::raw("  │  "),
        Span::styled("/", Style::default().fg(scheme.primary)),
        Span::raw(": search  "),
        Span::styled("g", Style::default().fg(scheme.primary)),
        Span::raw(": jump  "),
        Span::styled("d", Style::default().fg(scheme.primary)),
        Span::raw(": diff  "),
        Span::styled("t", Style::default().fg(scheme.primary)),
        Span::raw(": stats  "),
        Span::styled("f", Style::default().fg(scheme.primary)),
        Span::raw(": filter"),
    ]);

    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(status).block(block);
    f.render_widget(paragraph, area);
}

/// Render version diff modal
fn render_version_diff_modal(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();

    // Modal area
    let modal_width = area.width * 80 / 100;
    let modal_height = area.height * 70 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let selected = state.selected_version;
    let compare = state.compare_version.unwrap_or(0);

    let sbom_a = result.sboms.get(selected);
    let sbom_b = result.sboms.get(compare);

    let (name_a, name_b) = match (sbom_a, sbom_b) {
        (Some(a), Some(b)) => (a.name.clone(), b.name.clone()),
        _ => return,
    };

    // Get diff between versions if available
    let diff_info = if selected > 0 && compare == selected - 1 {
        result.incremental_diffs.get(compare)
    } else if compare > 0 && selected == compare - 1 {
        result.incremental_diffs.get(selected)
    } else {
        None
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Comparing: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &name_a,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" ↔ "),
            Span::styled(
                &name_b,
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];

    if let (Some(a), Some(b)) = (sbom_a, sbom_b) {
        lines.push(Line::from(vec![
            Span::styled("Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                a.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" vs "),
            Span::styled(
                b.component_count.to_string(),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }

    if let Some(diff) = diff_info {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Changes:",
            Style::default().fg(scheme.text_muted),
        )]));
        lines.push(Line::from(vec![
            Span::styled("  + Added: ", Style::default().fg(scheme.added)),
            Span::raw(diff.summary.components_added.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  - Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(diff.summary.components_removed.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  ~ Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(diff.summary.components_modified.to_string()),
        ]));

        // Show some added components
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Added Components:",
            Style::default().fg(scheme.added),
        )]));
        for comp in diff.components.added.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  + "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Removed Components:",
            Style::default().fg(scheme.removed),
        )]));
        for comp in diff.components.removed.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  - "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
            ]));
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "No direct diff available between these versions.",
            Style::default().fg(scheme.text_muted),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "Select adjacent versions for detailed diff.",
            Style::default().fg(scheme.text_muted),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("←/→", Style::default().fg(scheme.primary)),
        Span::raw(": change compare version  "),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Version Diff: {name_a} ↔ {name_b} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render component history modal
fn render_component_history_modal(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();

    let modal_width = area.width * 75 / 100;
    let modal_height = area.height * 60 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    // Get selected component
    let all_evolutions: Vec<_> = result
        .evolution_summary
        .components_added
        .iter()
        .chain(result.evolution_summary.components_removed.iter())
        .collect();

    let evo = match all_evolutions.get(state.selected_component) {
        Some(e) => *e,
        None => return,
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &evo.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("First Seen: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("v{} ({})", evo.first_seen_index + 1, evo.first_seen_version),
                Style::default().fg(scheme.accent),
            ),
        ]),
    ];

    if let Some(current) = &evo.current_version {
        lines.push(Line::from(vec![
            Span::styled("Current Version: ", Style::default().fg(scheme.text_muted)),
            Span::styled(current, Style::default().fg(scheme.added)),
        ]));
    }

    if let Some(last_seen) = evo.last_seen_index {
        lines.push(Line::from(vec![
            Span::styled("Last Seen: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("v{}", last_seen + 1),
                Style::default().fg(scheme.removed),
            ),
        ]));
    }

    // Show version history if available
    if let Some(history) = result.evolution_summary.version_history.get(&evo.name) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Version History:",
            Style::default().fg(scheme.text_muted),
        )]));

        for point in history.iter().take(10) {
            let change_style = match point.change_type {
                VersionChangeType::Initial => Style::default().fg(scheme.info),
                VersionChangeType::MajorUpgrade => Style::default().fg(scheme.critical),
                VersionChangeType::MinorUpgrade => Style::default().fg(scheme.added),
                VersionChangeType::PatchUpgrade => Style::default().fg(scheme.primary),
                VersionChangeType::Downgrade => Style::default().fg(scheme.removed),
                VersionChangeType::Unchanged => Style::default().fg(scheme.text_muted),
                VersionChangeType::Removed | VersionChangeType::Absent => Style::default().fg(scheme.muted),
            };

            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&point.sbom_name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    point.version.as_deref().unwrap_or("-"),
                    Style::default().fg(scheme.accent),
                ),
                Span::raw(" "),
                Span::styled(point.change_type.symbol(), change_style),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Component: {} ", evo.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, area: Rect, state: &TimelineState) {
    let scheme = colors();

    let search_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, search_area);

    let search_text = Line::from(vec![
        Span::styled("Search: ", Style::default().fg(scheme.text_muted)),
        Span::styled(&state.search.query, Style::default().fg(scheme.text)),
        Span::styled("│", Style::default().fg(scheme.accent)),
        Span::raw("  "),
        Span::styled(
            state.search.match_position(),
            Style::default().fg(scheme.text_muted),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(search_text).block(block);
    f.render_widget(paragraph, search_area);
}

/// Render jump overlay
fn render_jump_overlay(f: &mut Frame, area: Rect, state: &TimelineState) {
    let scheme = colors();

    let jump_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, jump_area);

    let jump_text = Line::from(vec![
        Span::styled("Jump to version: ", Style::default().fg(scheme.text_muted)),
        Span::styled(&state.jump_input, Style::default().fg(scheme.text)),
        Span::styled("│", Style::default().fg(scheme.accent)),
        Span::raw("  "),
        Span::styled(
            format!("(1-{})", state.total_versions),
            Style::default().fg(scheme.text_muted),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.warning))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(jump_text).block(block);
    f.render_widget(paragraph, jump_area);
}

/// Panels in the timeline view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelinePanel {
    Versions,
    Components,
}
