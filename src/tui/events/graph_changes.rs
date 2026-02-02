//! Graph changes tab event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_graph_changes_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.tabs.graph_changes.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.graph_changes.select_next(),
        KeyCode::PageUp => app.tabs.graph_changes.page_up(),
        KeyCode::PageDown => app.tabs.graph_changes.page_down(),
        KeyCode::Home => {
            app.tabs.graph_changes.selected = 0;
        }
        KeyCode::End | KeyCode::Char('G') => {
            if app.tabs.graph_changes.total > 0 {
                app.tabs.graph_changes.selected = app.tabs.graph_changes.total - 1;
            }
        }
        _ => {}
    }
}

