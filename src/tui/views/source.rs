//! Source tab rendering for App (diff mode) — side-by-side layout.

use crate::tui::app::App;
use crate::tui::app_states::SourceSide;
use crate::tui::app_states::source::SourceDiffState;
use crate::tui::shared::source::{render_source_panel, render_str};
use crate::tui::theme::colors;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState};
use std::fmt::Write;

/// Render the source tab with side-by-side old/new SBOM panels.
pub fn render_source(frame: &mut Frame, area: Rect, app: &mut App) {
    let source = &mut app.tabs.source;
    let show_detail = source.show_detail;

    // When detail panel is visible: 38% / 38% / 24%
    let main_area = if show_detail {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(38),
                Constraint::Percentage(38),
                Constraint::Percentage(24),
            ])
            .split(area);
        render_detail_panel(frame, chunks[2], source);
        (chunks[0], chunks[1])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        (chunks[0], chunks[1])
    };

    let active = source.active_side;
    let sync_label = if source.is_synced() { " [sync]" } else { "" };

    let (old_a, old_r, old_m) = SourceDiffState::annotation_counts(&source.old_panel);
    let (new_a, new_r, new_m) = SourceDiffState::annotation_counts(&source.new_panel);

    let old_badge = format_change_badge(old_a, old_r, old_m);
    let new_badge = format_change_badge(new_a, new_r, new_m);

    let old_title = format!("Old SBOM{sync_label}{old_badge}");
    let new_title = format!("New SBOM{sync_label}{new_badge}");

    render_source_panel(
        frame,
        main_area.0,
        &mut source.old_panel,
        &old_title,
        active == SourceSide::Old,
    );
    render_source_panel(
        frame,
        main_area.1,
        &mut source.new_panel,
        &new_title,
        active == SourceSide::New,
    );
}

/// Render the detail panel showing info about the selected item.
fn render_detail_panel(frame: &mut Frame, area: Rect, source: &mut SourceDiffState) {
    let scheme = colors();

    let detail_text = source.get_selected_detail().unwrap_or_default();
    let lines: Vec<&str> = detail_text.lines().collect();
    let total_lines = lines.len();

    let block = Block::default()
        .title(" Detail ")
        .title_style(Style::default().fg(scheme.accent).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 2 || inner.height < 1 {
        return;
    }

    let visible_height = inner.height as usize;
    // Clamp scroll
    if source.detail_scroll > total_lines.saturating_sub(visible_height) {
        source.detail_scroll = total_lines.saturating_sub(visible_height);
    }

    for (i, line) in lines
        .iter()
        .skip(source.detail_scroll)
        .take(visible_height)
        .enumerate()
    {
        let y = inner.y + i as u16;
        // Word-wrap: just truncate for now (detail values are typically short)
        render_str(
            frame.buffer_mut(),
            inner.x,
            y,
            line,
            inner.width,
            Style::default().fg(scheme.text),
        );
    }

    // Scrollbar
    if total_lines > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));
        let mut sb_state = ScrollbarState::new(total_lines).position(source.detail_scroll);
        frame.render_stateful_widget(scrollbar, inner, &mut sb_state);
    }
}

/// Format a compact badge string showing change counts.
fn format_change_badge(added: usize, removed: usize, modified: usize) -> String {
    if added == 0 && removed == 0 && modified == 0 {
        return String::new();
    }
    let mut badge = String::new();
    if added > 0 {
        let _ = write!(badge, " +{added}");
    }
    if removed > 0 {
        let _ = write!(badge, " -{removed}");
    }
    if modified > 0 {
        let _ = write!(badge, " ~{modified}");
    }
    badge
}
