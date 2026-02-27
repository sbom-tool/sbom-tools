//! Source tab rendering for App (diff mode) — side-by-side layout.

use crate::tui::app::App;
use crate::tui::app_states::SourceSide;
use crate::tui::app_states::source::SourceDiffState;
use crate::tui::shared::source::render_source_panel;
use ratatui::prelude::*;
use std::fmt::Write;

/// Render the source tab with side-by-side old/new SBOM panels.
pub fn render_source(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let source = &mut app.tabs.source;
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
        chunks[0],
        &mut source.old_panel,
        &old_title,
        active == SourceSide::Old,
    );
    render_source_panel(
        frame,
        chunks[1],
        &mut source.new_panel,
        &new_title,
        active == SourceSide::New,
    );
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
