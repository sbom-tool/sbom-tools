//! Licenses tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_licenses_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.licenses_view.as_mut() else {
        return;
    };

    // Pre-sync: tabs → view
    view.sync_from(&app.tabs.licenses);

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = view.handle_key(key, &mut ctx);

    // Post-sync: view → tabs
    app.tabs.licenses.group_by = view.group_by();
    app.tabs.licenses.sort_by = view.sort_by();
    app.tabs.licenses.selected = view.selected();
    app.tabs.licenses.focus_left = view.focus_left();
    app.tabs.licenses.show_compatibility = view.show_compatibility();
    app.tabs.licenses.risk_filter = view.risk_filter();
    app.tabs.licenses.selected_new = view.selected_new();
    app.tabs.licenses.selected_removed = view.selected_removed();

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
}
