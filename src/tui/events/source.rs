//! Source tab event handling for App (diff mode).

use crate::tui::app::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent};

/// Handle source-tab-specific key events.
pub fn handle_source_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.source_view.as_mut() else {
        return;
    };

    // Pre-sync: tabs → view
    view.sync_from(&app.tabs.source);

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
    view.sync_to(&mut app.tabs.source);

    match result {
        EventResult::StatusMessage(msg) => {
            app.status_message = Some(msg);
        }
        EventResult::Ignored => {
            // Handle data-dependent keys
            handle_data_dependent_keys(app, key);
        }
        _ => {}
    }
}

/// Handle keys that need access to App data (clipboard, export).
fn handle_data_dependent_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('c') => {
            // Copy JSON path
            let panel = app.tabs.source.active_panel_mut();
            panel.ensure_flat_cache();
            if let Some(item) = panel.cached_flat_items.get(panel.selected) {
                let path = item.node_id.clone();
                if crate::tui::clipboard::copy_to_clipboard(&path) {
                    app.set_status_message(format!("Copied path: {path}"));
                }
            }
        }
        KeyCode::Char('E') => {
            // Export source content
            let panel = app.tabs.source.active_panel_mut();
            let content = panel.get_full_content();
            let label = match app.tabs.source.active_side {
                crate::tui::app_states::SourceSide::Old => "old",
                crate::tui::app_states::SourceSide::New => "new",
            };
            let result = crate::tui::export::export_source_content(&content, label);
            app.set_status_message(result.message);
        }
        _ => {}
    }
}
