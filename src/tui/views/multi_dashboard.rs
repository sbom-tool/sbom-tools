//! Multi-SBOM comparison dashboard view.
//!
//! Displays 1:N baseline comparison with deviation analysis.

use crate::diff::{MultiDiffResult, SecurityImpact};
use crate::tui::app::{MultiDiffState, MultiViewFilterPreset, MultiViewSortBy, SortDirection};
use crate::tui::theme::colors;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Render the multi-diff dashboard
pub fn render_multi_dashboard(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    state: &MultiDiffState,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(5), // Baseline info
            Constraint::Min(15),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // Header with title and filter/sort info
    render_header(f, chunks[0], result, state);

    // Baseline info panel
    render_baseline_info(f, chunks[1], result);

    // Main content area - split into left (targets) and right (details)
    let main_chunks = if state.show_cross_target {
        // Show cross-target analysis panel instead of normal layout
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(40),
                Constraint::Percentage(35),
            ])
            .split(chunks[2])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(chunks[2])
    };

    render_targets_list(f, main_chunks[0], result, state);

    if state.show_cross_target && main_chunks.len() > 2 {
        render_cross_target_analysis(f, main_chunks[1], result, state);
        render_details_panel(f, main_chunks[2], result, state.selected_target, state);
    } else if main_chunks.len() > 1 {
        render_details_panel(f, main_chunks[1], result, state.selected_target, state);
    }

    // Status bar
    render_status_bar(f, chunks[3], result, state);

    // Render overlays
    if state.show_detail_modal {
        render_detail_modal(f, area, result, state);
    }

    if state.show_variable_drill_down {
        render_variable_drill_down(f, area, result, state);
    }

    if state.search.active {
        render_search_overlay(f, area, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, result: &MultiDiffResult, state: &MultiDiffState) {
    let scheme = colors();
    let title = format!(
        " Multi-SBOM Comparison: {} vs {} targets ",
        result.baseline.name,
        result.comparisons.len()
    );

    // Build header line with filter/sort info
    let text = vec![Line::from(vec![
        Span::styled(
            title,
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled("Filter: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            state.filter_preset.label(),
            Style::default().fg(scheme.accent),
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
        if state.heat_map_mode {
            Span::styled(" │ Heat Map", Style::default().fg(scheme.warning))
        } else {
            Span::raw("")
        },
    ])];

    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn render_baseline_info(f: &mut Frame, area: Rect, result: &MultiDiffResult) {
    let scheme = colors();
    let info = &result.baseline;
    let text = vec![
        Line::from(vec![
            Span::styled("Baseline: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &info.name,
                Style::default()
                    .fg(scheme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Format: ", Style::default().fg(scheme.text_muted)),
            Span::styled(&info.format, Style::default().fg(scheme.accent)),
        ]),
        Line::from(vec![
            Span::styled("Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                info.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw("  "),
            Span::styled("Dependencies: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                info.dependency_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw("  "),
            Span::styled("Max Deviation: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}%", result.summary.max_deviation * 100.0),
                Style::default().fg(if result.summary.max_deviation > 0.3 {
                    scheme.removed
                } else if result.summary.max_deviation > 0.1 {
                    scheme.warning
                } else {
                    scheme.added
                }),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" Baseline ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn render_targets_list(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    state: &MultiDiffState,
) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, MultiDashboardPanel::Targets);
    let selected = state.selected_target;

    // Filter and sort comparisons
    let mut filtered_comparisons: Vec<(usize, &crate::diff::ComparisonResult)> = result
        .comparisons
        .iter()
        .enumerate()
        .filter(|(_, comp)| {
            let deviation = result
                .summary
                .deviation_scores
                .get(&comp.target.name)
                .copied()
                .unwrap_or(0.0);
            let has_changes = comp.diff.summary.total_changes > 0;
            let has_vulns = comp.diff.summary.vulnerabilities_introduced > 0;

            match state.filter_preset {
                MultiViewFilterPreset::All => true,
                MultiViewFilterPreset::HighDeviation => deviation > 0.3,
                MultiViewFilterPreset::ChangesOnly => has_changes,
                MultiViewFilterPreset::WithVulnerabilities => has_vulns,
                MultiViewFilterPreset::AddedOnly => comp.diff.summary.components_added > 0,
                MultiViewFilterPreset::RemovedOnly => comp.diff.summary.components_removed > 0,
            }
        })
        .collect();

    // Sort
    match state.sort_by {
        MultiViewSortBy::Name => {
            filtered_comparisons.sort_by(|a, b| a.1.target.name.cmp(&b.1.target.name));
        }
        MultiViewSortBy::Deviation => {
            filtered_comparisons.sort_by(|a, b| {
                let dev_a = result
                    .summary
                    .deviation_scores
                    .get(&a.1.target.name)
                    .copied()
                    .unwrap_or(0.0);
                let dev_b = result
                    .summary
                    .deviation_scores
                    .get(&b.1.target.name)
                    .copied()
                    .unwrap_or(0.0);
                dev_b
                    .partial_cmp(&dev_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        MultiViewSortBy::Changes => {
            filtered_comparisons.sort_by(|a, b| {
                b.1.diff
                    .summary
                    .total_changes
                    .cmp(&a.1.diff.summary.total_changes)
            });
        }
        MultiViewSortBy::Components => {
            filtered_comparisons
                .sort_by(|a, b| b.1.target.component_count.cmp(&a.1.target.component_count));
        }
        MultiViewSortBy::Vulnerabilities => {
            filtered_comparisons.sort_by(|a, b| {
                b.1.diff
                    .summary
                    .vulnerabilities_introduced
                    .cmp(&a.1.diff.summary.vulnerabilities_introduced)
            });
        }
    }

    // Reverse for ascending order
    if matches!(state.sort_direction, SortDirection::Ascending) {
        filtered_comparisons.reverse();
    }

    let rows: Vec<Row> = filtered_comparisons
        .iter()
        .enumerate()
        .map(|(display_idx, (_, comp))| {
            let deviation = result
                .summary
                .deviation_scores
                .get(&comp.target.name)
                .copied()
                .unwrap_or(0.0);

            let deviation_color = if deviation > 0.3 {
                scheme.removed
            } else if deviation > 0.1 {
                scheme.warning
            } else {
                scheme.added
            };

            let style = if display_idx == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else if state.heat_map_mode {
                // Heat map background color based on deviation
                let bg = if deviation > 0.5 {
                    scheme.error_bg
                } else if deviation > 0.3 {
                    scheme.warning
                } else if deviation > 0.1 {
                    scheme.selection
                } else {
                    scheme.muted
                };
                Style::default().bg(bg)
            } else {
                Style::default()
            };

            // Highlight search matches
            let name_style = if state.search.matches.contains(&display_idx) {
                style.fg(scheme.accent).add_modifier(Modifier::BOLD)
            } else {
                style
            };

            Row::new(vec![
                Cell::from(comp.target.name.clone()).style(name_style),
                Cell::from(comp.target.component_count.to_string()).style(style),
                Cell::from(format!("{:.1}%", deviation * 100.0)).style(style.fg(deviation_color)),
                Cell::from(comp.diff.summary.total_changes.to_string()).style(style),
            ])
        })
        .collect();

    let header = Row::new(vec!["Target", "Components", "Deviation", "Changes"])
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ];

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };
    let title = format!(
        " Targets ({}/{}) ",
        filtered_comparisons.len(),
        result.comparisons.len()
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

fn render_details_panel(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    selected: usize,
    state: &MultiDiffState,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Comparison summary
            Constraint::Percentage(60), // Variable components
        ])
        .split(area);

    if let Some(comp) = result.comparisons.get(selected) {
        render_comparison_details(f, chunks[0], comp, result);
    }

    render_variable_components(f, chunks[1], result, state);
}

fn render_comparison_details(
    f: &mut Frame,
    area: Rect,
    comp: &crate::diff::ComparisonResult,
    result: &MultiDiffResult,
) {
    let scheme = colors();
    let deviation = result
        .summary
        .deviation_scores
        .get(&comp.target.name)
        .copied()
        .unwrap_or(0.0);

    let summary = &comp.diff.summary;
    let text = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &comp.target.name,
                Style::default()
                    .fg(scheme.text)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("+ Added: ", Style::default().fg(scheme.added)),
            Span::raw(summary.components_added.to_string()),
            Span::raw("  "),
            Span::styled("- Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(summary.components_removed.to_string()),
            Span::raw("  "),
            Span::styled("~ Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(summary.components_modified.to_string()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Vulnerabilities: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("+{}", summary.vulnerabilities_introduced),
                Style::default().fg(scheme.removed),
            ),
            Span::raw(" / "),
            Span::styled(
                format!("-{}", summary.vulnerabilities_resolved),
                Style::default().fg(scheme.added),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Semantic Score: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}", comp.diff.semantic_score),
                Style::default().fg(scheme.primary),
            ),
        ]),
    ];

    // Deviation gauge
    let gauge_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(area);

    let block = Block::default()
        .title(format!(" {} Details ", comp.target.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, gauge_area[0]);

    let gauge_color = if deviation > 0.3 {
        scheme.removed
    } else if deviation > 0.1 {
        scheme.warning
    } else {
        scheme.added
    };

    let gauge = Gauge::default()
        .block(Block::default().title(" Deviation ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(gauge_color))
        .percent((deviation * 100.0).min(100.0) as u16)
        .label(format!("{:.1}%", deviation * 100.0));

    f.render_widget(gauge, gauge_area[1]);
}

fn render_variable_components(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    state: &MultiDiffState,
) {
    let scheme = colors();
    let rows: Vec<Row> = result
        .summary
        .variable_components
        .iter()
        .enumerate()
        .take(15) // Limit to first 15
        .map(|(i, vc)| {
            let is_selected = i == state.selected_variable_component;
            let base_style = if is_selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let impact_style = match vc.security_impact {
                SecurityImpact::Critical => {
                    base_style.fg(scheme.critical).add_modifier(Modifier::BOLD)
                }
                SecurityImpact::High => base_style.fg(scheme.high),
                SecurityImpact::Medium => base_style.fg(scheme.medium),
                SecurityImpact::Low => base_style.fg(scheme.low),
            };

            Row::new(vec![
                Cell::from(vc.name.clone()).style(base_style),
                Cell::from(vc.version_spread.baseline.clone().unwrap_or_default())
                    .style(base_style),
                Cell::from(format!(
                    "{} versions",
                    vc.version_spread.unique_versions.len()
                ))
                .style(base_style),
                Cell::from(vc.security_impact.label()).style(impact_style),
            ])
        })
        .collect();

    let header = Row::new(vec!["Component", "Baseline", "Spread", "Impact"])
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(
                " Variable Components ({} total) [v: drill-down] ",
                result.summary.variable_components.len()
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.critical)),
    );

    f.render_widget(table, area);
}

fn render_status_bar(f: &mut Frame, area: Rect, result: &MultiDiffResult, _state: &MultiDiffState) {
    let scheme = colors();
    let universal_count = result.summary.universal_components.len();
    let inconsistent_count = result.summary.inconsistent_components.len();

    let status = Line::from(vec![
        Span::styled("Universal: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            universal_count.to_string(),
            Style::default().fg(scheme.added),
        ),
        Span::raw("  "),
        Span::styled("Variable: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            result.summary.variable_components.len().to_string(),
            Style::default().fg(scheme.warning),
        ),
        Span::raw("  "),
        Span::styled("Inconsistent: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            inconsistent_count.to_string(),
            Style::default().fg(scheme.removed),
        ),
        Span::raw("  │  "),
        Span::styled("/", Style::default().fg(scheme.primary)),
        Span::raw(": search  "),
        Span::styled("f", Style::default().fg(scheme.primary)),
        Span::raw(": filter  "),
        Span::styled("s", Style::default().fg(scheme.primary)),
        Span::raw(": sort  "),
        Span::styled("v", Style::default().fg(scheme.primary)),
        Span::raw(": variable  "),
        Span::styled("h", Style::default().fg(scheme.primary)),
        Span::raw(": heatmap  "),
        Span::styled("x", Style::default().fg(scheme.primary)),
        Span::raw(": cross-target"),
    ]);

    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(status).block(block);
    f.render_widget(paragraph, area);
}

/// Render cross-target analysis panel
fn render_cross_target_analysis(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    _state: &MultiDiffState,
) {
    let scheme = colors();

    // Find components that appear in most targets but with different versions
    let mut cross_target_info: Vec<Line> = vec![
        Line::from(vec![Span::styled(
            "Cross-Target Analysis",
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    // Add inconsistent components summary
    cross_target_info.push(Line::from(vec![
        Span::styled(
            "Inconsistent Components: ",
            Style::default().fg(scheme.text_muted),
        ),
        Span::styled(
            result.summary.inconsistent_components.len().to_string(),
            Style::default().fg(scheme.warning),
        ),
    ]));

    // Show top variable components across targets
    for (i, vc) in result
        .summary
        .variable_components
        .iter()
        .take(8)
        .enumerate()
    {
        let versions_str = vc
            .version_spread
            .unique_versions
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        cross_target_info.push(Line::from(vec![
            Span::styled(
                format!("{}. ", i + 1),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(&vc.name, Style::default().fg(scheme.text)),
            Span::raw(": "),
            Span::styled(versions_str, Style::default().fg(scheme.accent)),
        ]));
    }

    // Add deviation distribution
    cross_target_info.push(Line::from(""));
    cross_target_info.push(Line::from(vec![Span::styled(
        "Deviation Distribution:",
        Style::default().fg(scheme.text_muted),
    )]));

    let high_dev = result
        .comparisons
        .iter()
        .filter(|c| {
            result
                .summary
                .deviation_scores
                .get(&c.target.name)
                .copied()
                .unwrap_or(0.0)
                > 0.3
        })
        .count();
    let med_dev = result
        .comparisons
        .iter()
        .filter(|c| {
            let d = result
                .summary
                .deviation_scores
                .get(&c.target.name)
                .copied()
                .unwrap_or(0.0);
            d > 0.1 && d <= 0.3
        })
        .count();
    let low_dev = result.comparisons.len() - high_dev - med_dev;

    cross_target_info.push(Line::from(vec![
        Span::styled("  High (>30%): ", Style::default().fg(scheme.removed)),
        Span::raw(high_dev.to_string()),
        Span::raw("  "),
        Span::styled("Med (10-30%): ", Style::default().fg(scheme.warning)),
        Span::raw(med_dev.to_string()),
        Span::raw("  "),
        Span::styled("Low (<10%): ", Style::default().fg(scheme.added)),
        Span::raw(low_dev.to_string()),
    ]));

    let block = Block::default()
        .title(" Cross-Target Analysis ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(cross_target_info)
        .block(block)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

/// Render detail modal for selected target
fn render_detail_modal(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    state: &MultiDiffState,
) {
    let scheme = colors();

    // Create modal area (centered, 80% width, 70% height)
    let modal_width = area.width * 80 / 100;
    let modal_height = area.height * 70 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    // Clear the area
    f.render_widget(Clear, modal_area);

    let comp = match result.comparisons.get(state.selected_target) {
        Some(c) => c,
        None => return,
    };

    let deviation = result
        .summary
        .deviation_scores
        .get(&comp.target.name)
        .copied()
        .unwrap_or(0.0);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &comp.target.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Deviation: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}%", deviation * 100.0),
                Style::default().fg(if deviation > 0.3 {
                    scheme.removed
                } else {
                    scheme.added
                }),
            ),
            Span::raw("  "),
            Span::styled("Semantic Score: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}", comp.diff.semantic_score),
                Style::default().fg(scheme.primary),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Component Changes:",
            Style::default().fg(scheme.text_muted),
        )]),
        Line::from(vec![
            Span::styled("  + Added: ", Style::default().fg(scheme.added)),
            Span::raw(comp.diff.summary.components_added.to_string()),
            Span::raw("  "),
            Span::styled("  - Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(comp.diff.summary.components_removed.to_string()),
            Span::raw("  "),
            Span::styled("  ~ Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(comp.diff.summary.components_modified.to_string()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Vulnerabilities:",
            Style::default().fg(scheme.text_muted),
        )]),
        Line::from(vec![
            Span::styled("  Introduced: ", Style::default().fg(scheme.removed)),
            Span::raw(comp.diff.summary.vulnerabilities_introduced.to_string()),
            Span::raw("  "),
            Span::styled("  Resolved: ", Style::default().fg(scheme.added)),
            Span::raw(comp.diff.summary.vulnerabilities_resolved.to_string()),
        ]),
        Line::from(""),
    ];

    // Add top component changes
    lines.push(Line::from(vec![Span::styled(
        "Top Added Components:",
        Style::default().fg(scheme.added),
    )]));
    for comp_change in comp.diff.components.added.iter().take(5) {
        lines.push(Line::from(vec![
            Span::raw("  + "),
            Span::styled(&comp_change.name, Style::default().fg(scheme.text)),
            Span::raw(" "),
            Span::styled(
                comp_change.new_version.as_deref().unwrap_or(""),
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Top Removed Components:",
        Style::default().fg(scheme.removed),
    )]));
    for comp_change in comp.diff.components.removed.iter().take(5) {
        lines.push(Line::from(vec![
            Span::raw("  - "),
            Span::styled(&comp_change.name, Style::default().fg(scheme.text)),
            Span::raw(" "),
            Span::styled(
                comp_change.old_version.as_deref().unwrap_or(""),
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Press ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::styled(" to close", Style::default().fg(scheme.text_muted)),
    ]));

    let block = Block::default()
        .title(format!(" {} Details ", comp.target.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render variable component drill-down modal
fn render_variable_drill_down(
    f: &mut Frame,
    area: Rect,
    result: &MultiDiffResult,
    state: &MultiDiffState,
) {
    let scheme = colors();

    // Create modal area
    let modal_width = area.width * 75 / 100;
    let modal_height = area.height * 60 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let vc = match result
        .summary
        .variable_components
        .get(state.selected_variable_component)
    {
        Some(v) => v,
        None => return,
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &vc.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Security Impact: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                vc.security_impact.label(),
                match vc.security_impact {
                    SecurityImpact::Critical => Style::default().fg(scheme.critical),
                    SecurityImpact::High => Style::default().fg(scheme.high),
                    SecurityImpact::Medium => Style::default().fg(scheme.medium),
                    SecurityImpact::Low => Style::default().fg(scheme.low),
                },
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Baseline Version: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                vc.version_spread.baseline.as_deref().unwrap_or("N/A"),
                Style::default().fg(scheme.primary),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Version Spread:",
            Style::default().fg(scheme.text_muted),
        )]),
    ];

    // Show all unique versions
    for version in &vc.version_spread.unique_versions {
        lines.push(Line::from(vec![
            Span::raw("  • "),
            Span::styled(version, Style::default().fg(scheme.accent)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Targets with this component:",
        Style::default().fg(scheme.text_muted),
    )]));

    // Show which targets have which versions (sample)
    for (_i, comp) in result.comparisons.iter().enumerate().take(10) {
        // Check if this target has the component - use ID-based lookup
        let has_component = comp.diff.components.added.iter().any(|c| c.id == vc.id)
            || comp
                .diff
                .components
                .removed
                .iter()
                .any(|c| c.id == vc.id)
            || comp
                .diff
                .components
                .modified
                .iter()
                .any(|c| c.id == vc.id);

        if has_component {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&comp.target.name, Style::default().fg(scheme.text)),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("j/k", Style::default().fg(scheme.primary)),
        Span::raw(": navigate  "),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Variable Component: {} ", vc.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.warning))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, area: Rect, state: &MultiDiffState) {
    let scheme = colors();

    // Search bar at bottom of screen
    let search_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, search_area);

    let search_text = Line::from(vec![
        Span::styled("Search: ", Style::default().fg(scheme.text_muted)),
        Span::styled(&state.search.query, Style::default().fg(scheme.text)),
        Span::styled("│", Style::default().fg(scheme.accent)), // Cursor
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

/// Panels in the multi-dashboard
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiDashboardPanel {
    Targets,
    Details,
}
