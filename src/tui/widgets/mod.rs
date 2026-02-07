//! Custom widgets for the TUI.
//!
//! This module provides reusable widgets for both View and Diff TUI modes.

mod severity_badge;
mod tree;

pub use severity_badge::{SeverityBadge, SeverityBar};
pub use tree::{detect_component_type, Tree, TreeNode, TreeState};

use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};




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
        format!("{truncated}...")
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
                format!("{filter_name} = {filter_value}"),
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
        format!(" {label} "),
        Style::default().fg(colors().badge_fg_dark).bg(color).bold(),
    )
}

/// Minimum terminal size requirements.
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

/// Check if terminal meets minimum size requirements.
pub const fn check_terminal_size(width: u16, height: u16) -> Result<(), (u16, u16)> {
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
                format!("{required_width}x{required_height}"),
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
