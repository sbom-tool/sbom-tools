//! Graph changes tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_graph_changes_keys(app: &mut App, key: KeyEvent) -> bool {
    let view = &mut app.graph_changes_view;

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = view.handle_key(key, &mut ctx);
    let consumed = !matches!(result, EventResult::Ignored);

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
    consumed
}
