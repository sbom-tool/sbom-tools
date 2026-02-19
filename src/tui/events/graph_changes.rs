//! Graph changes tab event handlers.

use crate::tui::App;
use crate::tui::state::ListNavigation;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_graph_changes_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.tabs.graph_changes.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.graph_changes.select_next(),
        KeyCode::PageUp => app.tabs.graph_changes.page_up(),
        KeyCode::PageDown => app.tabs.graph_changes.page_down(),
        KeyCode::Home => app.tabs.graph_changes.go_first(),
        KeyCode::End | KeyCode::Char('G') => app.tabs.graph_changes.go_last(),
        _ => {}
    }
}
