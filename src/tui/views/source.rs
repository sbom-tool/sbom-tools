//! Source tab rendering for App (diff mode) — side-by-side layout.

use crate::tui::app::App;
use crate::tui::app_states::SourceSide;
use crate::tui::shared::source::render_source_panel;
use ratatui::prelude::*;

/// Render the source tab with side-by-side old/new SBOM panels.
pub(crate) fn render_source(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let source = &mut app.tabs.source;
    let active = source.active_side;

    render_source_panel(
        frame,
        chunks[0],
        &mut source.old_panel,
        "Old SBOM",
        active == SourceSide::Old,
    );
    render_source_panel(
        frame,
        chunks[1],
        &mut source.new_panel,
        "New SBOM",
        active == SourceSide::New,
    );
}
