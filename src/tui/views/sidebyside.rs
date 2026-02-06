//! Side-by-side diff view similar to difftastic.
//!
//! This view supports two modes:
//! - Grouped: Changes organized by type (removed, modified, added)
//! - Aligned: Components aligned on same row for direct comparison

use crate::diff::ChangeType;
use crate::tui::app::{AlignmentMode, App, AppMode};
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// An aligned row for side-by-side comparison
#[derive(Debug, Clone)]
pub(crate) struct AlignedRow {
    /// Left side component (old SBOM)
    pub left_name: Option<String>,
    pub left_version: Option<String>,
    /// Right side component (new SBOM)
    pub right_name: Option<String>,
    pub right_version: Option<String>,
    /// Type of change
    pub change_type: ChangeType,
    /// Component ID for detail lookup
    pub component_id: Option<String>,
}

/// Inline diff span for character-level highlighting
#[derive(Debug, Clone)]
pub(crate) struct DiffSpan {
    pub text: String,
    pub style: DiffSpanStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffSpanStyle {
    Unchanged,
    Removed,
    Added,
}

/// Render side-by-side diff view
pub(crate) fn render_sidebyside(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.mode {
        AppMode::Diff => render_diff_sidebyside(frame, area, app),
        AppMode::View => render_view_placeholder(frame, area),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_sidebyside(frame: &mut Frame, area: Rect, app: &mut App) {
    // Handle search input mode
    if app.tabs.side_by_side.search_active {
        render_with_search_input(frame, area, app);
        return;
    }

    // Handle component detail modal
    if app.tabs.side_by_side.show_detail_modal {
        render_with_detail_modal(frame, area, app);
        return;
    }

    // Normal rendering based on alignment mode
    match app.tabs.side_by_side.alignment_mode {
        AlignmentMode::Grouped => render_grouped_mode(frame, area, app),
        AlignmentMode::Aligned => render_aligned_mode(frame, area, app),
    }
}

fn render_grouped_mode(frame: &mut Frame, area: Rect, app: &mut App) {
    // Split into context bar and panels
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Context bar
            Constraint::Min(10),   // Panels
        ])
        .split(area);

    // Render context bar
    render_sidebyside_context_bar(frame, main_chunks[0], app);

    // Split panels area into left, divider, right
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(49),
            Constraint::Length(2),
            Constraint::Percentage(49),
        ])
        .split(main_chunks[1]);

    let left_area = chunks[0];
    let divider_area = chunks[1];
    let right_area = chunks[2];

    // Get SBOM names
    let old_name = app
        .data.old_sbom
        .as_ref()
        .and_then(|s| s.document.name.clone())
        .unwrap_or_else(|| "Old SBOM".to_string());
    let new_name = app
        .data.new_sbom
        .as_ref()
        .and_then(|s| s.document.name.clone())
        .unwrap_or_else(|| "New SBOM".to_string());

    // Track which panel is focused
    let focus_right = app.tabs.side_by_side.focus_right;

    // Render left panel (old)
    let left_lines = render_old_panel(frame, left_area, app, &old_name, !focus_right);

    // Render divider with focus indicator
    render_divider(frame, divider_area, focus_right);

    // Render right panel (new)
    let right_lines = render_new_panel(frame, right_area, app, &new_name, focus_right);

    // Update totals in state
    app.tabs.side_by_side.set_totals(left_lines, right_lines);
}

fn render_aligned_mode(frame: &mut Frame, area: Rect, app: &mut App) {
    let scheme = colors();

    // Split into context bar and main area
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Context bar
            Constraint::Min(10),   // Main content
        ])
        .split(area);

    // Render context bar
    render_sidebyside_context_bar(frame, main_chunks[0], app);

    // Split main area into left, divider, right
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(49),
            Constraint::Length(2),
            Constraint::Percentage(49),
        ])
        .split(main_chunks[1]);

    let left_area = chunks[0];
    let divider_area = chunks[1];
    let right_area = chunks[2];

    // Build aligned rows from diff result
    let rows = build_aligned_rows(app);
    let total_rows = rows.len();

    // Update state with row info
    let change_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.change_type != ChangeType::Unchanged)
        .map(|(i, _)| i)
        .collect();
    app.tabs.side_by_side.set_total_rows(total_rows);
    app.tabs.side_by_side.set_change_indices(change_indices);

    // Calculate visible range based on scroll
    let scroll = app.tabs.side_by_side.left_scroll;
    let visible_height = (left_area.height.saturating_sub(2)) as usize; // Account for borders
    let selected = app.tabs.side_by_side.selected_row;

    // Get search query for highlighting
    let search_query = app.tabs.side_by_side.search_query.clone();

    // Build left and right lines
    let mut left_lines: Vec<Line> = vec![];
    let mut right_lines: Vec<Line> = vec![];

    // Get SBOM names for headers
    let old_name = app
        .data.old_sbom
        .as_ref()
        .and_then(|s| s.document.name.clone())
        .unwrap_or_else(|| "Old SBOM".to_string());
    let new_name = app
        .data.new_sbom
        .as_ref()
        .and_then(|s| s.document.name.clone())
        .unwrap_or_else(|| "New SBOM".to_string());

    for (idx, row) in rows.iter().enumerate().skip(scroll).take(visible_height) {
        let is_selected = idx == selected;
        let is_search_match = search_query
            .as_ref()
            .is_some_and(|q| {
                row.left_name.as_ref().is_some_and(|n| n.contains(q))
                    || row.right_name.as_ref().is_some_and(|n| n.contains(q))
            });

        let (left_line, right_line) =
            render_aligned_row(row, is_selected, is_search_match, &search_query, &scheme);
        left_lines.push(left_line);
        right_lines.push(right_line);
    }

    // Update totals
    app.tabs.side_by_side.set_totals(total_rows, total_rows);

    // Render left panel
    let focus_right = app.tabs.side_by_side.focus_right;
    let left_border_style = if !focus_right {
        Style::default().fg(scheme.removed).bold()
    } else {
        Style::default().fg(scheme.muted)
    };

    let left_panel = Paragraph::new(left_lines).block(
        Block::default()
            .title(format!(" {old_name} (Old) "))
            .title_style(Style::default().fg(scheme.removed).bold())
            .borders(Borders::ALL)
            .border_style(left_border_style),
    );
    frame.render_widget(left_panel, left_area);

    // Render divider
    render_aligned_divider(frame, divider_area, &rows, scroll, visible_height, &scheme);

    // Render right panel
    let right_border_style = if focus_right {
        Style::default().fg(scheme.added).bold()
    } else {
        Style::default().fg(scheme.muted)
    };

    let right_panel = Paragraph::new(right_lines).block(
        Block::default()
            .title(format!(" {new_name} (New) "))
            .title_style(Style::default().fg(scheme.added).bold())
            .borders(Borders::ALL)
            .border_style(right_border_style),
    );
    frame.render_widget(right_panel, right_area);
}

fn build_aligned_rows(app: &App) -> Vec<AlignedRow> {
    let mut rows = Vec::new();
    let filter = &app.tabs.side_by_side.filter;

    if let Some(result) = &app.data.diff_result {
        // Add removed components
        if filter.show_removed {
            for comp in &result.components.removed {
                rows.push(AlignedRow {
                    left_name: Some(comp.name.clone()),
                    left_version: comp.old_version.clone(),
                    right_name: None,
                    right_version: None,
                    change_type: ChangeType::Removed,
                    component_id: Some(comp.id.clone()),  // Use ID, not name
                });
            }
        }

        // Add modified components (aligned on same row)
        if filter.show_modified {
            for comp in &result.components.modified {
                rows.push(AlignedRow {
                    left_name: Some(comp.name.clone()),
                    left_version: comp.old_version.clone(),
                    right_name: Some(comp.name.clone()),
                    right_version: comp.new_version.clone(),
                    change_type: ChangeType::Modified,
                    component_id: Some(comp.id.clone()),  // Use ID, not name
                });
            }
        }

        // Add added components
        if filter.show_added {
            for comp in &result.components.added {
                rows.push(AlignedRow {
                    left_name: None,
                    left_version: None,
                    right_name: Some(comp.name.clone()),
                    right_version: comp.new_version.clone(),
                    change_type: ChangeType::Added,
                    component_id: Some(comp.id.clone()),  // Use ID, not name
                });
            }
        }
    }

    rows
}

fn render_aligned_row<'a>(
    row: &AlignedRow,
    is_selected: bool,
    is_search_match: bool,
    search_query: &Option<String>,
    scheme: &crate::tui::theme::ColorScheme,
) -> (Line<'a>, Line<'a>) {
    let base_style = if is_selected {
        Style::default().bg(scheme.selection_bg)
    } else if is_search_match {
        Style::default().bg(scheme.search_highlight_bg)
    } else {
        Style::default()
    };

    // Left side
    let left_line = match &row.left_name {
        Some(name) => {
            let version = row.left_version.as_deref().unwrap_or("");
            let (name_spans, version_spans) =
                highlight_with_search(name, version, search_query, scheme, row.change_type, false);

            let mut spans = vec![match row.change_type {
                ChangeType::Removed => Span::styled("- ", base_style.fg(scheme.removed).bold()),
                ChangeType::Modified => Span::styled("~ ", base_style.fg(scheme.modified)),
                _ => Span::styled("  ", base_style),
            }];
            spans.extend(name_spans);
            spans.push(Span::styled(" ", base_style));
            spans.extend(version_spans);

            Line::from(spans)
        }
        None => Line::styled(
            "  ...",
            base_style.fg(scheme.muted).add_modifier(Modifier::DIM),
        ),
    };

    // Right side
    let right_line = match &row.right_name {
        Some(name) => {
            let version = row.right_version.as_deref().unwrap_or("");
            let (name_spans, version_spans) =
                highlight_with_search(name, version, search_query, scheme, row.change_type, true);

            let mut spans = vec![match row.change_type {
                ChangeType::Added => Span::styled("+ ", base_style.fg(scheme.added).bold()),
                ChangeType::Modified => Span::styled("~ ", base_style.fg(scheme.modified)),
                _ => Span::styled("  ", base_style),
            }];
            spans.extend(name_spans);
            spans.push(Span::styled(" ", base_style));
            spans.extend(version_spans);

            Line::from(spans)
        }
        None => Line::styled(
            "  ...",
            base_style.fg(scheme.muted).add_modifier(Modifier::DIM),
        ),
    };

    (left_line, right_line)
}

fn highlight_with_search<'a>(
    name: &str,
    version: &str,
    search_query: &Option<String>,
    scheme: &crate::tui::theme::ColorScheme,
    change_type: ChangeType,
    is_right: bool,
) -> (Vec<Span<'a>>, Vec<Span<'a>>) {
    let name_color = match change_type {
        ChangeType::Added => scheme.added,
        ChangeType::Removed => scheme.removed,
        ChangeType::Modified => {
            if is_right {
                scheme.added
            } else {
                scheme.removed
            }
        }
        ChangeType::Unchanged => scheme.text,
    };

    let name_spans = if let Some(query) = search_query {
        if !query.is_empty() {
            highlight_search_matches(name, query, name_color, scheme.search_highlight_bg)
        } else {
            vec![Span::styled(
                name.to_string(),
                Style::default().fg(name_color),
            )]
        }
    } else {
        vec![Span::styled(
            name.to_string(),
            Style::default().fg(name_color),
        )]
    };

    let version_spans = vec![Span::styled(
        version.to_string(),
        Style::default().fg(scheme.muted),
    )];

    (name_spans, version_spans)
}

fn highlight_search_matches<'a>(
    text: &str,
    query: &str,
    base_color: Color,
    highlight_bg: Color,
) -> Vec<Span<'a>> {
    if query.is_empty() {
        return vec![Span::styled(
            text.to_string(),
            Style::default().fg(base_color),
        )];
    }

    let mut spans = Vec::new();
    let text_lower = text.to_lowercase();
    let query_lower = query.to_lowercase();
    let mut last_end = 0;

    for (start, _) in text_lower.match_indices(&query_lower) {
        // Add text before match
        if start > last_end {
            spans.push(Span::styled(
                text[last_end..start].to_string(),
                Style::default().fg(base_color),
            ));
        }
        // Add highlighted match
        let end = start + query.len();
        spans.push(Span::styled(
            text[start..end].to_string(),
            Style::default().fg(base_color).bg(highlight_bg).bold(),
        ));
        last_end = end;
    }

    // Add remaining text
    if last_end < text.len() {
        spans.push(Span::styled(
            text[last_end..].to_string(),
            Style::default().fg(base_color),
        ));
    }

    if spans.is_empty() {
        spans.push(Span::styled(
            text.to_string(),
            Style::default().fg(base_color),
        ));
    }

    spans
}

/// Compute inline diff between two version strings
pub(crate) fn compute_inline_diff(old: &str, new: &str) -> (Vec<DiffSpan>, Vec<DiffSpan>) {
    if old == new {
        return (
            vec![DiffSpan {
                text: old.to_string(),
                style: DiffSpanStyle::Unchanged,
            }],
            vec![DiffSpan {
                text: new.to_string(),
                style: DiffSpanStyle::Unchanged,
            }],
        );
    }

    // Simple character-by-character diff for version strings
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();

    let mut old_spans = Vec::new();
    let mut new_spans = Vec::new();

    // Find common prefix
    let prefix_len = old_chars
        .iter()
        .zip(new_chars.iter())
        .take_while(|(a, b)| a == b)
        .count();

    // Find common suffix (after prefix)
    let old_remaining = &old_chars[prefix_len..];
    let new_remaining = &new_chars[prefix_len..];
    let suffix_len = old_remaining
        .iter()
        .rev()
        .zip(new_remaining.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();

    // Build spans
    if prefix_len > 0 {
        old_spans.push(DiffSpan {
            text: old_chars[..prefix_len].iter().collect(),
            style: DiffSpanStyle::Unchanged,
        });
        new_spans.push(DiffSpan {
            text: new_chars[..prefix_len].iter().collect(),
            style: DiffSpanStyle::Unchanged,
        });
    }

    // Changed middle part
    let old_mid_end = old_chars.len().saturating_sub(suffix_len);
    let new_mid_end = new_chars.len().saturating_sub(suffix_len);

    if prefix_len < old_mid_end {
        old_spans.push(DiffSpan {
            text: old_chars[prefix_len..old_mid_end].iter().collect(),
            style: DiffSpanStyle::Removed,
        });
    }

    if prefix_len < new_mid_end {
        new_spans.push(DiffSpan {
            text: new_chars[prefix_len..new_mid_end].iter().collect(),
            style: DiffSpanStyle::Added,
        });
    }

    // Common suffix
    if suffix_len > 0 {
        old_spans.push(DiffSpan {
            text: old_chars[old_mid_end..].iter().collect(),
            style: DiffSpanStyle::Unchanged,
        });
        new_spans.push(DiffSpan {
            text: new_chars[new_mid_end..].iter().collect(),
            style: DiffSpanStyle::Unchanged,
        });
    }

    (old_spans, new_spans)
}

fn render_aligned_divider(
    frame: &mut Frame,
    area: Rect,
    rows: &[AlignedRow],
    scroll: usize,
    visible_height: usize,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let mut lines: Vec<Line> = Vec::with_capacity(area.height as usize);

    // Top border continuation
    lines.push(Line::styled("┬", Style::default().fg(scheme.muted)));

    for (idx, row) in rows.iter().enumerate().skip(scroll).take(visible_height) {
        let (char, style) = match row.change_type {
            ChangeType::Added => ("►", Style::default().fg(scheme.added)),
            ChangeType::Removed => ("◄", Style::default().fg(scheme.removed)),
            ChangeType::Modified => ("◆", Style::default().fg(scheme.modified)),
            ChangeType::Unchanged => ("│", Style::default().fg(scheme.muted)),
        };

        // Highlight if this is a change we're navigating to
        let _ = idx; // suppress unused warning
        lines.push(Line::styled(char, style));
    }

    // Fill remaining space
    while lines.len() < area.height as usize - 1 {
        lines.push(Line::styled("│", Style::default().fg(scheme.muted)));
    }

    // Bottom border continuation
    lines.push(Line::styled("┴", Style::default().fg(scheme.muted)));

    let divider = Paragraph::new(lines).alignment(Alignment::Center);
    frame.render_widget(divider, area);
}

fn render_sidebyside_context_bar(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();
    let state = &app.tabs.side_by_side;

    let mut spans = vec![
        // Mode indicator
        Span::styled("Mode: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            state.alignment_mode.name(),
            Style::default().fg(scheme.accent).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(scheme.muted)),
    ];

    // Focus indicator
    spans.push(Span::styled(
        "Focus: ",
        Style::default().fg(scheme.text_muted),
    ));
    if !state.focus_right {
        spans.push(Span::styled(
            " ◄ Old ",
            Style::default()
                .fg(scheme.badge_fg_light)
                .bg(scheme.removed)
                .bold(),
        ));
    } else {
        spans.push(Span::styled(" Old ", Style::default().fg(scheme.removed)));
    }
    spans.push(Span::styled("│", Style::default().fg(scheme.muted)));
    if state.focus_right {
        spans.push(Span::styled(
            " New ► ",
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.added)
                .bold(),
        ));
    } else {
        spans.push(Span::styled(" New ", Style::default().fg(scheme.added)));
    }
    spans.push(Span::styled(" │ ", Style::default().fg(scheme.muted)));

    // Sync mode
    spans.push(Span::styled(
        "Sync: ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled(
        state.sync_mode.name(),
        Style::default().fg(scheme.text),
    ));
    spans.push(Span::styled(" │ ", Style::default().fg(scheme.muted)));

    // Filter status
    if state.filter.is_filtered() {
        spans.push(Span::styled(
            "Filter: ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled(
            state.filter.summary(),
            Style::default().fg(scheme.warning),
        ));
        spans.push(Span::styled(" │ ", Style::default().fg(scheme.muted)));
    }

    // Change navigation position
    spans.push(Span::styled(
        "Change: ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled(
        state.change_position(),
        Style::default().fg(scheme.modified),
    ));
    spans.push(Span::styled(" │ ", Style::default().fg(scheme.muted)));

    // Search status
    if state.search_query.is_some() {
        spans.push(Span::styled(
            "Search: ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled(
            state.match_position(),
            Style::default().fg(scheme.accent),
        ));
        spans.push(Span::styled(" │ ", Style::default().fg(scheme.muted)));
    }

    // Key hints
    spans.push(Span::styled("[a]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        "lign ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled("[/]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        "search ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled("[n/N]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        "ext/prev",
        Style::default().fg(scheme.text_muted),
    ));

    let context_line = Line::from(spans);

    let paragraph = Paragraph::new(context_line).style(Style::default().fg(scheme.text_muted));

    frame.render_widget(paragraph, area);
}

fn render_old_panel(frame: &mut Frame, area: Rect, app: &App, name: &str, focused: bool) -> usize {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];
    let filter = &app.tabs.side_by_side.filter;

    if let Some(result) = &app.data.diff_result {
        // Header showing counts
        lines.push(Line::from(vec![
            Span::styled("Removed: ", Style::default().fg(scheme.removed)),
            Span::styled(
                format!("{}", result.summary.components_removed),
                Style::default().fg(scheme.removed).bold(),
            ),
            Span::styled(" │ ", Style::default().fg(scheme.muted)),
            Span::styled("Modified: ", Style::default().fg(scheme.modified)),
            Span::styled(
                format!("{}", result.summary.components_modified),
                Style::default().fg(scheme.modified).bold(),
            ),
        ]));
        lines.push(Line::raw(""));

        // Removed components
        if filter.show_removed && !result.components.removed.is_empty() {
            lines.push(Line::styled(
                "─── Removed ───",
                Style::default().fg(scheme.removed).bold(),
            ));
            for comp in &result.components.removed {
                let version = comp.old_version.as_deref().unwrap_or("");
                lines.push(Line::from(vec![
                    Span::styled("- ", Style::default().fg(scheme.removed).bold()),
                    Span::styled(&comp.name, Style::default().fg(scheme.removed)),
                    Span::styled(format!(" {version}"), Style::default().fg(scheme.muted)),
                ]));
            }
            lines.push(Line::raw(""));
        }

        // Modified components (old versions)
        if filter.show_modified && !result.components.modified.is_empty() {
            lines.push(Line::styled(
                "─── Modified (old) ───",
                Style::default().fg(scheme.modified).bold(),
            ));
            for comp in &result.components.modified {
                let old_version = comp.old_version.as_deref().unwrap_or("");
                let new_version = comp.new_version.as_deref().unwrap_or("");

                // Compute inline diff for versions
                let (old_spans, _) = compute_inline_diff(old_version, new_version);

                let mut line_spans = vec![
                    Span::styled("~ ", Style::default().fg(scheme.modified)),
                    Span::styled(&comp.name, Style::default().fg(scheme.modified)),
                    Span::styled(" ", Style::default()),
                ];

                // Add version with inline diff highlighting
                for span in old_spans {
                    let style = match span.style {
                        DiffSpanStyle::Unchanged => Style::default().fg(scheme.muted),
                        DiffSpanStyle::Removed => Style::default()
                            .fg(scheme.removed)
                            .add_modifier(Modifier::CROSSED_OUT),
                        DiffSpanStyle::Added => Style::default().fg(scheme.added),
                    };
                    line_spans.push(Span::styled(span.text, style));
                }

                lines.push(Line::from(line_spans));
            }
        }

        // Resolved vulnerabilities
        if !result.vulnerabilities.resolved.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "─── Resolved Vulns ───",
                Style::default().fg(scheme.added).bold(),
            ));
            for vuln in result.vulnerabilities.resolved.iter().take(10) {
                let severity_style = Style::default().fg(scheme.severity_color(&vuln.severity));
                lines.push(Line::from(vec![
                    Span::styled("✓ ", Style::default().fg(scheme.added)),
                    Span::styled(&vuln.id, severity_style),
                    Span::styled(
                        format!(" [{}]", vuln.severity),
                        Style::default().fg(scheme.muted),
                    ),
                ]));
            }
        }
    }

    let total_lines = lines.len();
    let scroll = app.tabs.side_by_side.left_scroll;

    // Border style changes based on focus
    let border_style = if focused {
        Style::default().fg(scheme.removed).bold()
    } else {
        Style::default().fg(scheme.muted)
    };

    let title_suffix = if focused { " ◄" } else { "" };

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" {name} (Old){title_suffix} "))
                .title_style(Style::default().fg(scheme.removed).bold())
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .scroll((scroll as u16, 0));

    frame.render_widget(panel, area);

    total_lines
}

fn render_new_panel(frame: &mut Frame, area: Rect, app: &App, name: &str, focused: bool) -> usize {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];
    let filter = &app.tabs.side_by_side.filter;

    if let Some(result) = &app.data.diff_result {
        // Header showing counts
        lines.push(Line::from(vec![
            Span::styled("Added: ", Style::default().fg(scheme.added)),
            Span::styled(
                format!("{}", result.summary.components_added),
                Style::default().fg(scheme.added).bold(),
            ),
            Span::styled(" │ ", Style::default().fg(scheme.muted)),
            Span::styled("Modified: ", Style::default().fg(scheme.modified)),
            Span::styled(
                format!("{}", result.summary.components_modified),
                Style::default().fg(scheme.modified).bold(),
            ),
        ]));
        lines.push(Line::raw(""));

        // Added components
        if filter.show_added && !result.components.added.is_empty() {
            lines.push(Line::styled(
                "─── Added ───",
                Style::default().fg(scheme.added).bold(),
            ));
            for comp in &result.components.added {
                let version = comp.new_version.as_deref().unwrap_or("");
                lines.push(Line::from(vec![
                    Span::styled("+ ", Style::default().fg(scheme.added).bold()),
                    Span::styled(&comp.name, Style::default().fg(scheme.added)),
                    Span::styled(format!(" {version}"), Style::default().fg(scheme.muted)),
                ]));
            }
            lines.push(Line::raw(""));
        }

        // Modified components (new versions)
        if filter.show_modified && !result.components.modified.is_empty() {
            lines.push(Line::styled(
                "─── Modified (new) ───",
                Style::default().fg(scheme.modified).bold(),
            ));
            for comp in &result.components.modified {
                let old_version = comp.old_version.as_deref().unwrap_or("");
                let new_version = comp.new_version.as_deref().unwrap_or("");

                // Compute inline diff for versions
                let (_, new_spans) = compute_inline_diff(old_version, new_version);

                let mut line_spans = vec![
                    Span::styled("~ ", Style::default().fg(scheme.modified)),
                    Span::styled(&comp.name, Style::default().fg(scheme.modified)),
                    Span::styled(" ", Style::default()),
                ];

                // Add version with inline diff highlighting
                for span in new_spans {
                    let style = match span.style {
                        DiffSpanStyle::Unchanged => Style::default().fg(scheme.muted),
                        DiffSpanStyle::Removed => Style::default().fg(scheme.removed),
                        DiffSpanStyle::Added => Style::default()
                            .fg(scheme.added)
                            .add_modifier(Modifier::BOLD),
                    };
                    line_spans.push(Span::styled(span.text, style));
                }

                lines.push(Line::from(line_spans));
            }
        }

        // Introduced vulnerabilities
        if !result.vulnerabilities.introduced.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "─── New Vulns ───",
                Style::default().fg(scheme.removed).bold(),
            ));
            for vuln in result.vulnerabilities.introduced.iter().take(10) {
                let severity_style = Style::default().fg(scheme.severity_color(&vuln.severity));
                lines.push(Line::from(vec![
                    Span::styled("! ", Style::default().fg(scheme.removed).bold()),
                    Span::styled(&vuln.id, severity_style.bold()),
                    Span::styled(
                        format!(" [{}]", vuln.severity),
                        Style::default().fg(scheme.muted),
                    ),
                ]));
            }
        }
    }

    let total_lines = lines.len();
    let scroll = app.tabs.side_by_side.right_scroll;

    // Border style changes based on focus
    let border_style = if focused {
        Style::default().fg(scheme.added).bold()
    } else {
        Style::default().fg(scheme.muted)
    };

    let title_suffix = if focused { " ◄" } else { "" };

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" {name} (New){title_suffix} "))
                .title_style(Style::default().fg(scheme.added).bold())
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .scroll((scroll as u16, 0));

    frame.render_widget(panel, area);

    total_lines
}

fn render_divider(frame: &mut Frame, area: Rect, focus_right: bool) {
    let scheme = colors();
    let height = area.height;
    let mut lines: Vec<Line> = Vec::with_capacity(height as usize);

    for i in 0..height {
        let (char, style) = if i == 0 || i == height - 1 {
            ("│", Style::default().fg(scheme.muted))
        } else if i == height / 2 {
            // Show arrow pointing to focused panel
            if focus_right {
                ("►", Style::default().fg(scheme.added).bold())
            } else {
                ("◄", Style::default().fg(scheme.removed).bold())
            }
        } else {
            ("│", Style::default().fg(scheme.muted))
        };
        lines.push(Line::styled(char, style));
    }

    let divider = Paragraph::new(lines).alignment(Alignment::Center);
    frame.render_widget(divider, area);
}

fn render_with_search_input(frame: &mut Frame, area: Rect, app: &mut App) {
    let scheme = colors();

    // First render the normal view
    match app.tabs.side_by_side.alignment_mode {
        AlignmentMode::Grouped => render_grouped_mode(frame, area, app),
        AlignmentMode::Aligned => render_aligned_mode(frame, area, app),
    }

    // Then render search input overlay at bottom
    let search_area = Rect {
        x: area.x + 2,
        y: area.y + area.height - 3,
        width: area.width.saturating_sub(4).min(60),
        height: 3,
    };

    frame.render_widget(Clear, search_area);

    let query = app.tabs.side_by_side.search_query.as_deref().unwrap_or("");
    let match_info = if !app.tabs.side_by_side.search_matches.is_empty() {
        format!(" ({} matches)", app.tabs.side_by_side.search_matches.len())
    } else if !query.is_empty() {
        " (no matches)".to_string()
    } else {
        String::new()
    };

    let search_text = format!("/{query}{match_info}");
    let search_input = Paragraph::new(search_text)
        .style(Style::default().fg(scheme.text))
        .block(
            Block::default()
                .title(" Search ")
                .title_style(Style::default().fg(scheme.accent).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        );

    frame.render_widget(search_input, search_area);
}

fn render_with_detail_modal(frame: &mut Frame, area: Rect, app: &mut App) {
    let scheme = colors();

    // First render the normal view (dimmed)
    match app.tabs.side_by_side.alignment_mode {
        AlignmentMode::Grouped => render_grouped_mode(frame, area, app),
        AlignmentMode::Aligned => render_aligned_mode(frame, area, app),
    }

    // Calculate modal area (centered, 80% width, 70% height)
    let modal_width = (area.width as f32 * 0.8) as u16;
    let modal_height = (area.height as f32 * 0.7) as u16;
    let modal_x = area.x + (area.width - modal_width) / 2;
    let modal_y = area.y + (area.height - modal_height) / 2;

    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    // Clear area for modal
    frame.render_widget(Clear, modal_area);

    // Get component details
    let mut content_lines: Vec<Line> = vec![];

    // Build aligned rows to find the selected component
    let rows = build_aligned_rows(app);
    if let Some(row) = rows.get(app.tabs.side_by_side.selected_row) {
        // Extract owned data from row
        let component_name = row
            .left_name
            .as_ref()
            .or(row.right_name.as_ref())
            .cloned()
            .unwrap_or_default();
        let old_ver = row
            .left_version
            .clone()
            .unwrap_or_else(|| "(none)".to_string());
        let new_ver = row
            .right_version
            .clone()
            .unwrap_or_else(|| "(none)".to_string());
        let change_type = row.change_type;
        let component_id = row.component_id.clone();

        // Header
        content_lines.push(Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.text_muted)),
            Span::styled(component_name, Style::default().fg(scheme.text).bold()),
        ]));

        content_lines.push(Line::raw(""));

        // Change type
        let change_label = match change_type {
            ChangeType::Added => ("ADDED", scheme.added),
            ChangeType::Removed => ("REMOVED", scheme.removed),
            ChangeType::Modified => ("MODIFIED", scheme.modified),
            ChangeType::Unchanged => ("UNCHANGED", scheme.text_muted),
        };
        content_lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(scheme.text_muted)),
            Span::styled(change_label.0, Style::default().fg(change_label.1).bold()),
        ]));

        content_lines.push(Line::raw(""));

        // Versions side by side
        content_lines.push(Line::styled(
            "─── Version Comparison ───",
            Style::default().fg(scheme.accent),
        ));

        content_lines.push(Line::from(vec![
            Span::styled("Old: ", Style::default().fg(scheme.removed)),
            Span::styled(old_ver.clone(), Style::default().fg(scheme.text)),
        ]));

        content_lines.push(Line::from(vec![
            Span::styled("New: ", Style::default().fg(scheme.added)),
            Span::styled(new_ver.clone(), Style::default().fg(scheme.text)),
        ]));

        // If modified, show inline diff
        if change_type == ChangeType::Modified {
            content_lines.push(Line::raw(""));
            content_lines.push(Line::styled(
                "─── Inline Diff ───",
                Style::default().fg(scheme.accent),
            ));

            let (old_spans, new_spans) = compute_inline_diff(&old_ver, &new_ver);

            let mut old_line = vec![Span::styled("Old: ", Style::default().fg(scheme.removed))];
            for span in old_spans {
                let style = match span.style {
                    DiffSpanStyle::Unchanged => Style::default().fg(scheme.text),
                    DiffSpanStyle::Removed => Style::default()
                        .fg(scheme.removed)
                        .bg(scheme.error_bg)
                        .bold(),
                    DiffSpanStyle::Added => Style::default().fg(scheme.added),
                };
                old_line.push(Span::styled(span.text, style));
            }
            content_lines.push(Line::from(old_line));

            let mut new_line = vec![Span::styled("New: ", Style::default().fg(scheme.added))];
            for span in new_spans {
                let style = match span.style {
                    DiffSpanStyle::Unchanged => Style::default().fg(scheme.text),
                    DiffSpanStyle::Removed => Style::default().fg(scheme.removed),
                    DiffSpanStyle::Added => Style::default()
                        .fg(scheme.added)
                        .bg(scheme.success_bg)
                        .bold(),
                };
                new_line.push(Span::styled(span.text, style));
            }
            content_lines.push(Line::from(new_line));
        }

        // Find related vulnerabilities - lookup by ID
        if let Some(result) = &app.data.diff_result {
            let comp_id = component_id.as_deref().unwrap_or("");
            let related_vulns: Vec<_> = result
                .vulnerabilities
                .introduced
                .iter()
                .chain(result.vulnerabilities.resolved.iter())
                .filter(|v| v.component_id == comp_id)  // ID-based lookup
                .collect();

            if !related_vulns.is_empty() {
                content_lines.push(Line::raw(""));
                content_lines.push(Line::styled(
                    "─── Related Vulnerabilities ───",
                    Style::default().fg(scheme.accent),
                ));

                for vuln in related_vulns.iter().take(5) {
                    let severity_color = scheme.severity_color(&vuln.severity);
                    content_lines.push(Line::from(vec![
                        Span::styled(vuln.id.clone(), Style::default().fg(severity_color).bold()),
                        Span::styled(
                            format!(" [{}]", vuln.severity),
                            Style::default().fg(scheme.text_muted),
                        ),
                    ]));
                }
            }
        }
    }

    // Footer hint
    content_lines.push(Line::raw(""));
    content_lines.push(Line::styled(
        "Press Esc or Enter to close",
        Style::default().fg(scheme.text_muted),
    ));

    let modal = Paragraph::new(content_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Component Details ")
                .title_style(Style::default().fg(scheme.accent).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        );

    frame.render_widget(modal, modal_area);
}

fn render_view_placeholder(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "||",
        "Side-by-side view requires diff mode",
        Some("This view compares two SBOMs side by side"),
        Some("Run: sbom-tools diff <old.json> <new.json> --tui"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_inline_diff_same() {
        let (old, new) = compute_inline_diff("1.2.3", "1.2.3");
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].style, DiffSpanStyle::Unchanged);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].style, DiffSpanStyle::Unchanged);
    }

    #[test]
    fn test_compute_inline_diff_version_change() {
        let (old, new) = compute_inline_diff("1.2.3", "1.2.4");

        // Should have: "1.2." unchanged, "3" removed for old
        // Should have: "1.2." unchanged, "4" added for new
        assert!(old.iter().any(|s| s.style == DiffSpanStyle::Removed));
        assert!(new.iter().any(|s| s.style == DiffSpanStyle::Added));
    }

    #[test]
    fn test_highlight_search_matches() {
        let spans = highlight_search_matches("lodash", "das", Color::White, Color::Yellow);
        assert!(spans.len() >= 2); // Should have at least pre-match and match
    }

    #[test]
    fn test_highlight_search_no_match() {
        let spans = highlight_search_matches("lodash", "xyz", Color::White, Color::Yellow);
        assert_eq!(spans.len(), 1);
    }
}
