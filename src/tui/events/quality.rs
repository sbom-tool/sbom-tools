//! Quality tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_quality_keys(app: &mut App, key: KeyEvent) {
    let Some(quality_view) = app.quality_view.as_mut() else {
        return;
    };

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = quality_view.handle_key(key, &mut ctx);

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
}
