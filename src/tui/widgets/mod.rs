//! Custom widgets for the TUI.
//!
//! This module provides reusable widgets for both View and Diff TUI modes.

mod change_badge;
mod severity_badge;
mod sparkline;
mod tree;

pub use change_badge::{ChangeIndicator, ChangeType, ChangeTypeBadge};
pub use severity_badge::{SeverityBadge, SeverityBar};
pub use sparkline::{EcosystemBar, HorizontalBar, MiniSparkline, PercentageRing};
pub use tree::{
    detect_component_type, extract_display_name, get_selected_node, FlattenedItem, Tree, TreeNode,
    TreeState,
};

use crate::tui::theme::{colors, Styles};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Render a detail panel with a title and content lines.
pub fn render_detail_panel(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    border_color: Color,
) {
    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

/// Render an empty state placeholder.
pub fn render_empty_state(
    frame: &mut ratatui::Frame,
    area: Rect,
    message: &str,
    hint: Option<&str>,
) {
    let scheme = colors();
    let mut lines = vec![
        Line::from(""),
        Line::styled(message, Style::default().fg(scheme.text_muted)),
    ];

    if let Some(h) = hint {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            h,
            Style::default().fg(scheme.text_muted).italic(),
        ));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

/// Render a popup overlay.
pub fn render_popup(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    content: Vec<Line<'static>>,
    percent_x: u16,
    percent_y: u16,
    border_color: Color,
) {
    let popup_area = centered_rect(percent_x, percent_y, area);
    frame.render_widget(Clear, popup_area);

    let popup = Paragraph::new(content)
        .block(
            Block::default()
                .title(format!(" {} ", title))
                .title_style(Style::default().fg(border_color).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(popup, popup_area);
}

/// Helper function to create a centered rectangle.
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Truncate a string with ellipsis, using Unicode display width for accuracy.
pub fn truncate_str(s: &str, max_width: usize) -> String {
    use unicode_width::UnicodeWidthChar;
    use unicode_width::UnicodeWidthStr;

    let display_width = UnicodeWidthStr::width(s);
    if display_width <= max_width {
        s.to_string()
    } else if max_width > 3 {
        let mut width = 0;
        let truncated: String = s
            .chars()
            .take_while(|ch| {
                let w = UnicodeWidthChar::width(*ch).unwrap_or(0);
                if width + w > max_width - 3 {
                    return false;
                }
                width += w;
                true
            })
            .collect();
        format!("{}...", truncated)
    } else {
        let mut width = 0;
        s.chars()
            .take_while(|ch| {
                let w = UnicodeWidthChar::width(*ch).unwrap_or(0);
                if width + w > max_width {
                    return false;
                }
                width += w;
                true
            })
            .collect()
    }
}

/// Format a count with appropriate suffix (K, M).
pub fn format_count(count: usize) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

// ============================================================================
// Enhanced State Widgets
// ============================================================================

/// Render a loading state with spinner animation.
pub fn render_loading_state(frame: &mut ratatui::Frame, area: Rect, message: &str, tick: u64) {
    // Spinner animation frames
    let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let frame_idx = (tick / 2) as usize % spinner_frames.len();
    let spinner = spinner_frames[frame_idx];

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(" {} ", spinner),
                Style::default().fg(colors().primary),
            ),
            Span::styled(message, Style::default().fg(colors().text)),
        ]),
        Line::from(""),
        Line::styled(
            "Press [Esc] to cancel",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().border)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

/// Render an error state with error message and optional action hint.
pub fn render_error_state(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    message: &str,
    action_hint: Option<&str>,
) {
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" ✗ ", Style::default().fg(colors().error).bold()),
            Span::styled(title, Style::default().fg(colors().error).bold()),
        ]),
        Line::from(""),
        Line::styled(message, Style::default().fg(colors().text)),
    ];

    if let Some(hint) = action_hint {
        lines.push(Line::from(""));
        lines.push(Line::styled(hint, Style::default().fg(colors().text_muted)));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().error)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

/// Render an enhanced empty state with icon and action hint.
pub fn render_empty_state_enhanced(
    frame: &mut ratatui::Frame,
    area: Rect,
    icon: &str,
    message: &str,
    reason: Option<&str>,
    action_hint: Option<&str>,
) {
    let mut lines = vec![
        Line::from(""),
        Line::styled(icon, Style::default().fg(colors().text_muted)),
        Line::from(""),
        Line::styled(message, Style::default().fg(colors().text)),
    ];

    if let Some(r) = reason {
        lines.push(Line::from(""));
        lines.push(Line::styled(r, Style::default().fg(colors().text_muted)));
    }

    if let Some(hint) = action_hint {
        lines.push(Line::from(""));
        lines.push(Line::styled(hint, Style::default().fg(colors().accent)));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().border)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

/// Render a "no results" state specifically for filtered views.
pub fn render_no_results_state(
    frame: &mut ratatui::Frame,
    area: Rect,
    filter_name: &str,
    filter_value: &str,
) {
    let lines = vec![
        Line::from(""),
        Line::styled("🔍", Style::default().fg(colors().text_muted)),
        Line::from(""),
        Line::styled("No results found", Style::default().fg(colors().text)),
        Line::from(""),
        Line::from(vec![
            Span::styled("Filter: ", Style::default().fg(colors().text_muted)),
            Span::styled(
                format!("{} = {}", filter_name, filter_value),
                Style::default().fg(colors().accent),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "Press [f] to change filter or [Esc] to clear",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().border)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

/// Render a success message (temporary notification).
pub fn render_success_notification(frame: &mut ratatui::Frame, area: Rect, message: &str) {
    let popup_area = centered_rect(50, 20, area);
    frame.render_widget(Clear, popup_area);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(colors().success).bold()),
            Span::styled(message, Style::default().fg(colors().text)),
        ]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().success)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, popup_area);
}

// ============================================================================
// Search Widgets
// ============================================================================

/// Render search results with highlighting.
pub fn render_search_results(
    frame: &mut ratatui::Frame,
    area: Rect,
    query: &str,
    results: &[(String, String, String)], // (type, name, detail)
    selected: usize,
    total_matches: usize,
) {
    let mut lines = vec![];

    // Search header
    lines.push(Line::from(vec![
        Span::styled("/", Style::default().fg(colors().primary)),
        Span::styled(query, Style::default().fg(colors().text)),
        Span::styled(
            format!(" ({}/{})", selected + 1, total_matches),
            Style::default().fg(colors().text_muted),
        ),
    ]));
    lines.push(Line::from(""));

    // Results
    for (i, (typ, name, detail)) in results.iter().enumerate() {
        let is_selected = i == selected;
        let style = if is_selected {
            Styles::selected()
        } else {
            Style::default()
        };

        let type_color = match typ.as_str() {
            "component" => colors().primary,
            "vulnerability" => colors().high,
            "license" => colors().permissive,
            _ => colors().text_muted,
        };

        lines.push(Line::from(vec![
            Span::styled(
                if is_selected { "▶ " } else { "  " },
                Style::default().fg(colors().accent),
            ),
            Span::styled(format!("[{}] ", typ), Style::default().fg(type_color)),
            Span::styled(name.clone(), style.fg(colors().text)),
            Span::styled(
                format!(" - {}", detail),
                Style::default().fg(colors().text_muted),
            ),
        ]));
    }

    if results.is_empty() && !query.is_empty() {
        lines.push(Line::styled(
            "No matches found",
            Style::default().fg(colors().text_muted),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[↑↓]", Style::default().fg(colors().accent)),
        Span::raw(" navigate "),
        Span::styled("[Enter]", Style::default().fg(colors().accent)),
        Span::raw(" select "),
        Span::styled("[Esc]", Style::default().fg(colors().accent)),
        Span::raw(" cancel"),
    ]));

    let popup_area = Rect {
        x: area.x + 2,
        y: area
            .height
            .saturating_sub(results.len() as u16 + 6)
            .max(area.y + 2),
        width: area.width.saturating_sub(4),
        height: (results.len() as u16 + 5).min(area.height / 2),
    };

    frame.render_widget(Clear, popup_area);

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Search Results ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().primary)),
    );

    frame.render_widget(paragraph, popup_area);
}

// ============================================================================
// Mode and Status Indicators
// ============================================================================

/// Render a mode indicator badge for the header.
pub fn render_mode_indicator(mode: &str) -> Span<'static> {
    let (label, color) = match mode.to_lowercase().as_str() {
        "diff" => ("DIFF", colors().modified),
        "view" => ("VIEW", colors().primary),
        "multi-diff" | "multidiff" => ("MULTI", colors().added),
        "timeline" => ("TIME", colors().secondary),
        "matrix" => ("MATRIX", colors().high),
        _ => ("MODE", colors().muted),
    };

    Span::styled(
        format!(" {} ", label),
        Style::default().fg(colors().badge_fg_dark).bg(color).bold(),
    )
}

/// Render a filter indicator showing current filter state.
pub fn render_filter_indicator(
    filter_name: &str,
    current_value: &str,
    all_values: &[&str],
) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(
        format!("{}: ", filter_name),
        Style::default().fg(colors().text_muted),
    )];

    for (i, val) in all_values.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("→", Style::default().fg(colors().text_muted)));
        }
        if *val == current_value {
            spans.push(Span::styled(
                format!(" {} ", val),
                Style::default()
                    .fg(colors().badge_fg_dark)
                    .bg(colors().accent)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", val),
                Style::default().fg(colors().text_muted),
            ));
        }
    }

    spans
}

/// Render a selection counter (for multi-select).
pub fn render_selection_counter(selected: usize, total: usize) -> Span<'static> {
    if selected > 0 {
        Span::styled(
            format!(" {} selected ", selected),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(colors().accent)
                .bold(),
        )
    } else {
        Span::styled(
            format!(" {}/{} ", 0, total),
            Style::default().fg(colors().text_muted),
        )
    }
}

// ============================================================================
// Tab Bar Widget
// ============================================================================

/// Render a horizontal tab bar with selection indicator.
///
/// # Arguments
/// * `tabs` - List of (name, shortcut) tuples for each tab
/// * `selected` - Index of the currently selected tab
/// * `accent_color` - Color for the selected tab
pub fn render_tab_bar(
    frame: &mut ratatui::Frame,
    area: Rect,
    tabs: &[(&str, &str)],
    selected: usize,
    accent_color: Color,
) {
    let mut spans = vec![];

    for (i, (name, shortcut)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(colors().border)));
        }

        let is_selected = i == selected;
        if is_selected {
            // Selected tab with accent background
            spans.push(Span::styled(
                format!("[{}]", shortcut),
                Style::default().fg(accent_color).bold(),
            ));
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default()
                    .fg(colors().badge_fg_dark)
                    .bg(accent_color)
                    .bold(),
            ));
        } else {
            // Unselected tab
            spans.push(Span::styled(
                format!("[{}]", shortcut),
                Style::default().fg(colors().text_muted),
            ));
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default().fg(colors().text_muted),
            ));
        }
    }

    // Add hint at the end
    spans.push(Span::styled("  ", Style::default()));
    spans.push(Span::styled("[Tab]", Style::default().fg(colors().accent)));
    spans.push(Span::styled(
        " cycle",
        Style::default().fg(colors().text_muted),
    ));

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);

    frame.render_widget(paragraph, area);
}

/// Generate tab spans for inline use (without rendering).
pub fn tab_bar_spans(
    tabs: &[(&str, &str)],
    selected: usize,
    accent_color: Color,
) -> Vec<Span<'static>> {
    let mut spans = vec![];

    for (i, (name, shortcut)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(colors().border)));
        }

        let is_selected = i == selected;
        if is_selected {
            spans.push(Span::styled(
                format!("[{}]", shortcut),
                Style::default().fg(accent_color).bold(),
            ));
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default()
                    .fg(colors().badge_fg_dark)
                    .bg(accent_color)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!("[{}]", shortcut),
                Style::default().fg(colors().text_muted),
            ));
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default().fg(colors().text_muted),
            ));
        }
    }

    spans
}

// ============================================================================
// Minimum Size Check
// ============================================================================

/// Minimum terminal size requirements.
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

/// Check if terminal meets minimum size requirements.
pub fn check_terminal_size(width: u16, height: u16) -> Result<(), (u16, u16)> {
    if width < MIN_WIDTH || height < MIN_HEIGHT {
        Err((MIN_WIDTH, MIN_HEIGHT))
    } else {
        Ok(())
    }
}

/// Render a "terminal too small" message.
pub fn render_size_warning(
    frame: &mut ratatui::Frame,
    area: Rect,
    required_width: u16,
    required_height: u16,
) {
    let lines = vec![
        Line::styled(
            "Terminal too small",
            Style::default().fg(colors().warning).bold(),
        ),
        Line::from(""),
        Line::from(vec![
            Span::raw("Current: "),
            Span::styled(
                format!("{}x{}", area.width, area.height),
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::raw("Required: "),
            Span::styled(
                format!("{}x{}", required_width, required_height),
                Style::default().fg(colors().accent),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "Please resize your terminal",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().warning)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}
