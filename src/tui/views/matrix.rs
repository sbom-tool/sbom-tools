//! Matrix comparison view.
//!
//! Displays N×N SBOM comparison with similarity heatmap.

use crate::diff::MatrixResult;
use crate::tui::app::MatrixState;
use crate::tui::theme::colors;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Render the matrix comparison view
pub fn render_matrix(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(15),   // Main content
            Constraint::Length(8), // Clustering info
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // Header with filter/sort info
    render_header(f, chunks[0], result, state);

    // Main content - matrix and details
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    render_similarity_matrix(f, main_chunks[0], result, state);
    render_pair_details(f, main_chunks[1], result, state);

    // Clustering info
    render_clustering(f, chunks[2], result, state);

    // Status bar
    render_status_bar(f, chunks[3], result, state);

    // Render overlays
    if state.show_pair_diff {
        render_pair_diff_modal(f, area, result, state);
    }

    if state.show_export_options {
        render_export_modal(f, area);
    }

    if state.show_clustering_details {
        render_clustering_detail_modal(f, area, result, state);
    }

    if state.search.active {
        render_search_overlay(f, area, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let title = format!(
        " Matrix: {}×{} SBOMs ({} pairs) ",
        result.sboms.len(),
        result.sboms.len(),
        result.num_pairs()
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
        Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
        Span::styled(state.threshold.label(), Style::default().fg(scheme.accent)),
        if state.focus_mode {
            Span::styled(" │ Focus Mode", Style::default().fg(scheme.warning))
        } else {
            Span::raw("")
        },
        if state.highlight_row_col {
            Span::styled(" │ Highlight", Style::default().fg(scheme.info))
        } else {
            Span::raw("")
        },
    ])];

    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn render_similarity_matrix(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, MatrixPanel::Matrix);
    let selected_row = state.selected_row;
    let selected_col = state.selected_col;

    // Create header row with SBOM names (truncated)
    let mut header_cells = vec![Cell::from("").style(Style::default().fg(scheme.primary))];
    for (j, sbom) in result.sboms.iter().enumerate() {
        let name: String = sbom.name.chars().take(8).collect();

        // Highlight column header if in highlight mode
        let header_style = if state.highlight_row_col && j == selected_col {
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD)
        } else if state.search.matches.contains(&j) {
            Style::default()
                .fg(scheme.warning)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(scheme.primary)
        };

        header_cells.push(Cell::from(name).style(header_style));
    }
    let header = Row::new(header_cells).bottom_margin(1);

    // Create matrix rows with filtering based on threshold and focus mode
    let rows: Vec<Row> = result
        .sboms
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            // In focus mode, only show focused row
            if state.focus_mode {
                if let Some(focus_row) = state.focus_row {
                    return *i == focus_row;
                }
            }
            true
        })
        .map(|(i, row_sbom)| {
            let row_name: String = row_sbom.name.chars().take(8).collect();

            // Highlight row name if in highlight mode
            let row_name_style = if state.highlight_row_col && i == selected_row {
                Style::default()
                    .fg(scheme.accent)
                    .add_modifier(Modifier::BOLD)
            } else if state.search.matches.contains(&i) {
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(scheme.text)
                    .add_modifier(Modifier::BOLD)
            };

            let mut cells = vec![Cell::from(row_name).style(row_name_style)];

            for j in 0..result.sboms.len() {
                // In focus mode with column focus, only show focused column
                if state.focus_mode {
                    if let Some(focus_col) = state.focus_col {
                        if j != focus_col && i != selected_row {
                            // Skip this column in focus mode
                        }
                    }
                }

                let similarity = result.get_similarity(i, j);
                let is_selected = i == selected_row && j == selected_col;
                let is_in_selected_row_or_col =
                    state.highlight_row_col && (i == selected_row || j == selected_col);

                // Check threshold filter
                let passes_threshold = state.passes_threshold(similarity);

                let cell_style = if is_selected {
                    Style::default()
                        .bg(scheme.accent)
                        .fg(scheme.badge_fg_dark)
                        .add_modifier(Modifier::BOLD)
                } else if i == j {
                    // Diagonal
                    Style::default().fg(scheme.muted)
                } else if !passes_threshold && i != j {
                    // Dim cells that don't pass threshold
                    Style::default().fg(scheme.muted)
                } else if is_in_selected_row_or_col {
                    // Highlight row/column
                    let color = similarity_to_color(similarity);
                    Style::default()
                        .fg(color)
                        .add_modifier(Modifier::UNDERLINED)
                } else {
                    // Color based on similarity
                    let color = similarity_to_color(similarity);
                    Style::default().fg(color)
                };

                let cell_text = if i == j {
                    " - ".to_string()
                } else if !passes_threshold && !is_selected && !is_in_selected_row_or_col {
                    "  ·  ".to_string()
                } else {
                    format!("{:.0}%", similarity * 100.0)
                };

                cells.push(Cell::from(cell_text).style(cell_style));
            }

            Row::new(cells)
        })
        .collect();

    // Calculate column widths
    let n = result.sboms.len();
    let name_width = 9;
    let cell_width = 6;
    let mut constraints = vec![Constraint::Length(name_width as u16)];
    for _ in 0..n {
        constraints.push(Constraint::Length(cell_width as u16));
    }

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };
    let title = " Similarity Matrix [z: zoom, r: row, c: col, Enter: diff] ".to_string();

    let table = Table::new(rows, constraints).header(header).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    f.render_widget(table, area);
}

fn render_pair_details(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let row = state.selected_row;
    let col = state.selected_col;

    let (sbom_a, sbom_b) = if row < result.sboms.len() && col < result.sboms.len() {
        (&result.sboms[row], &result.sboms[col])
    } else {
        return;
    };

    let similarity = result.get_similarity(row, col);

    let mut text = vec![
        Line::from(vec![Span::styled(
            "Comparing: ",
            Style::default().fg(scheme.text_muted),
        )]),
        Line::from(vec![
            Span::styled(&sbom_a.name, Style::default().fg(scheme.primary)),
            Span::raw(" ↔ "),
            Span::styled(&sbom_b.name, Style::default().fg(scheme.primary)),
        ]),
        Line::from(""),
    ];

    if row == col {
        text.push(Line::from(vec![Span::styled(
            "(Same SBOM)",
            Style::default().fg(scheme.text_muted),
        )]));
    } else {
        text.extend(vec![
            Line::from(vec![
                Span::styled("Similarity: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.1}%", similarity * 100.0),
                    Style::default()
                        .fg(similarity_to_color(similarity))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(&sbom_a.name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    sbom_a.component_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
                Span::raw(" components"),
            ]),
            Line::from(vec![
                Span::styled(&sbom_b.name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    sbom_b.component_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
                Span::raw(" components"),
            ]),
        ]);

        // Show diff details if available
        if let Some(diff) = result.get_diff(row, col) {
            text.extend(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Changes:",
                    Style::default().fg(scheme.text_muted),
                )]),
                Line::from(vec![
                    Span::styled(" + Added: ", Style::default().fg(scheme.added)),
                    Span::raw(diff.summary.components_added.to_string()),
                ]),
                Line::from(vec![
                    Span::styled(" - Removed: ", Style::default().fg(scheme.removed)),
                    Span::raw(diff.summary.components_removed.to_string()),
                ]),
                Line::from(vec![
                    Span::styled(" ~ Modified: ", Style::default().fg(scheme.accent)),
                    Span::raw(diff.summary.components_modified.to_string()),
                ]),
            ]);
        }

        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("Press ", Style::default().fg(scheme.text_muted)),
            Span::styled("Enter", Style::default().fg(scheme.primary)),
            Span::styled(" for detailed diff", Style::default().fg(scheme.text_muted)),
        ]));
    }

    let block = Block::default()
        .title(" Pair Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn render_clustering(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let text = if let Some(ref clustering) = result.clustering {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Algorithm: ", Style::default().fg(scheme.text_muted)),
                Span::styled(&clustering.algorithm, Style::default().fg(scheme.text)),
                Span::raw("  "),
                Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.0}%", clustering.threshold * 100.0),
                    Style::default().fg(scheme.primary),
                ),
            ]),
            Line::from(""),
        ];

        // Show clusters with selection highlighting
        for (i, cluster) in clustering.clusters.iter().enumerate() {
            let members: Vec<String> = cluster
                .members
                .iter()
                .filter_map(|&idx| result.sboms.get(idx))
                .map(|s| s.name.clone())
                .collect();

            let cluster_label = cluster
                .label
                .clone()
                .unwrap_or(format!("Cluster {}", i + 1));
            let is_selected = i == state.selected_cluster;

            let label_style = if is_selected {
                Style::default()
                    .fg(scheme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(scheme.critical)
                    .add_modifier(Modifier::BOLD)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", cluster_label), label_style),
                Span::styled(members.join(", "), Style::default().fg(scheme.text)),
                Span::raw(" "),
                Span::styled(
                    format!("({:.0}% similarity)", cluster.internal_similarity * 100.0),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }

        // Show outliers
        if !clustering.outliers.is_empty() {
            let outliers: Vec<String> = clustering
                .outliers
                .iter()
                .filter_map(|&idx| result.sboms.get(idx))
                .map(|s| s.name.clone())
                .collect();

            lines.push(Line::from(vec![
                Span::styled("Outliers: ", Style::default().fg(scheme.removed)),
                Span::styled(outliers.join(", "), Style::default().fg(scheme.text)),
            ]));
        }

        lines
    } else {
        vec![Line::from(vec![Span::styled(
            "No clustering computed",
            Style::default().fg(scheme.text_muted),
        )])]
    };

    let block = Block::default()
        .title(format!(
            " Clustering ({} clusters) [C: details] ",
            result
                .clustering
                .as_ref()
                .map(|c| c.clusters.len())
                .unwrap_or(0)
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.critical));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn render_status_bar(f: &mut Frame, area: Rect, result: &MatrixResult, _state: &MatrixState) {
    let scheme = colors();
    // Calculate average similarity
    let total_pairs = result.num_pairs();
    let avg_similarity: f64 = if total_pairs > 0 {
        result.similarity_scores.iter().sum::<f64>() / total_pairs as f64
    } else {
        0.0
    };

    let status = Line::from(vec![
        Span::styled("Pairs: ", Style::default().fg(scheme.text_muted)),
        Span::styled(total_pairs.to_string(), Style::default().fg(scheme.primary)),
        Span::raw("  "),
        Span::styled("Avg: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{:.0}%", avg_similarity * 100.0),
            Style::default().fg(similarity_to_color(avg_similarity)),
        ),
        Span::raw("  │  "),
        Span::styled("/", Style::default().fg(scheme.primary)),
        Span::raw(": search  "),
        Span::styled("t", Style::default().fg(scheme.primary)),
        Span::raw(": threshold  "),
        Span::styled("z", Style::default().fg(scheme.primary)),
        Span::raw(": focus  "),
        Span::styled("H", Style::default().fg(scheme.primary)),
        Span::raw(": highlight  "),
        Span::styled("x", Style::default().fg(scheme.primary)),
        Span::raw(": export"),
    ]);

    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(status).block(block);
    f.render_widget(paragraph, area);
}

/// Render pair diff modal
fn render_pair_diff_modal(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();

    let modal_width = area.width * 80 / 100;
    let modal_height = area.height * 70 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let row = state.selected_row;
    let col = state.selected_col;

    let (sbom_a, sbom_b) = match (result.sboms.get(row), result.sboms.get(col)) {
        (Some(a), Some(b)) => (a, b),
        _ => return,
    };

    let similarity = result.get_similarity(row, col);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Comparing: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &sbom_a.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" ↔ "),
            Span::styled(
                &sbom_b.name,
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Similarity: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}%", similarity * 100.0),
                Style::default()
                    .fg(similarity_to_color(similarity))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(&sbom_a.name, Style::default().fg(scheme.text)),
            Span::raw(": "),
            Span::styled(
                sbom_a.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" components"),
        ]),
        Line::from(vec![
            Span::styled(&sbom_b.name, Style::default().fg(scheme.text)),
            Span::raw(": "),
            Span::styled(
                sbom_b.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" components"),
        ]),
    ];

    if let Some(diff) = result.get_diff(row, col) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Detailed Changes:",
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

        // Show sample components
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Added Components:",
            Style::default().fg(scheme.added),
        )]));
        for comp in diff.components.added.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  + "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
                Span::raw(" "),
                Span::styled(
                    comp.new_version.as_deref().unwrap_or(""),
                    Style::default().fg(scheme.text_muted),
                ),
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
                Span::raw(" "),
                Span::styled(
                    comp.old_version.as_deref().unwrap_or(""),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Diff: {} ↔ {} ", sbom_a.name, sbom_b.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render export modal
fn render_export_modal(f: &mut Frame, area: Rect) {
    let scheme = colors();

    let modal_width = 40;
    let modal_height = 12;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let lines = vec![
        Line::from(vec![Span::styled(
            "Export Matrix As:",
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("c", Style::default().fg(scheme.accent)),
            Span::raw(" - CSV (comma-separated)"),
        ]),
        Line::from(vec![
            Span::styled("j", Style::default().fg(scheme.accent)),
            Span::raw(" - JSON"),
        ]),
        Line::from(vec![
            Span::styled("h", Style::default().fg(scheme.accent)),
            Span::raw(" - HTML (visual heatmap)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Esc", Style::default().fg(scheme.primary)),
            Span::raw(": cancel"),
        ]),
    ];

    let block = Block::default()
        .title(" Export Matrix ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.warning))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, modal_area);
}

/// Render clustering detail modal
fn render_clustering_detail_modal(
    f: &mut Frame,
    area: Rect,
    result: &MatrixResult,
    state: &MatrixState,
) {
    let scheme = colors();

    let modal_width = area.width * 70 / 100;
    let modal_height = area.height * 60 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let mut lines = vec![
        Line::from(vec![Span::styled(
            "Clustering Details",
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    if let Some(ref clustering) = result.clustering {
        lines.push(Line::from(vec![
            Span::styled("Algorithm: ", Style::default().fg(scheme.text_muted)),
            Span::styled(&clustering.algorithm, Style::default().fg(scheme.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", clustering.threshold * 100.0),
                Style::default().fg(scheme.primary),
            ),
        ]));
        lines.push(Line::from(""));

        for (i, cluster) in clustering.clusters.iter().enumerate() {
            let is_selected = i == state.selected_cluster;
            let style = if is_selected {
                Style::default()
                    .fg(scheme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(scheme.text)
            };

            let label = cluster
                .label
                .clone()
                .unwrap_or(format!("Cluster {}", i + 1));
            lines.push(Line::from(vec![Span::styled(format!("{}:", label), style)]));
            lines.push(Line::from(vec![
                Span::styled("  Similarity: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.1}%", cluster.internal_similarity * 100.0),
                    Style::default().fg(similarity_to_color(cluster.internal_similarity)),
                ),
            ]));
            lines.push(Line::from(vec![Span::styled(
                "  Members: ",
                Style::default().fg(scheme.text_muted),
            )]));

            for &member_idx in &cluster.members {
                if let Some(sbom) = result.sboms.get(member_idx) {
                    lines.push(Line::from(vec![
                        Span::raw("    • "),
                        Span::styled(&sbom.name, Style::default().fg(scheme.text)),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }

        if !clustering.outliers.is_empty() {
            lines.push(Line::from(vec![Span::styled(
                "Outliers:",
                Style::default().fg(scheme.removed),
            )]));
            for &outlier_idx in &clustering.outliers {
                if let Some(sbom) = result.sboms.get(outlier_idx) {
                    lines.push(Line::from(vec![
                        Span::raw("  • "),
                        Span::styled(&sbom.name, Style::default().fg(scheme.text)),
                    ]));
                }
            }
        }
    } else {
        lines.push(Line::from(vec![Span::styled(
            "No clustering data available.",
            Style::default().fg(scheme.text_muted),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("j/k", Style::default().fg(scheme.primary)),
        Span::raw(": navigate clusters  "),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(" Clustering Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.critical))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, area: Rect, state: &MatrixState) {
    let scheme = colors();

    let search_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, search_area);

    let search_text = Line::from(vec![
        Span::styled("Search SBOM: ", Style::default().fg(scheme.text_muted)),
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

/// Convert similarity score to color
fn similarity_to_color(similarity: f64) -> Color {
    if similarity >= 0.9 {
        colors().added
    } else if similarity >= 0.7 {
        colors().success
    } else if similarity >= 0.5 {
        colors().accent
    } else if similarity >= 0.3 {
        colors().warning
    } else {
        colors().removed
    }
}

/// Panels in the matrix view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixPanel {
    Matrix,
    Details,
}
