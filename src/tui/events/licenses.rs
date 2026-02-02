//! Licenses tab event handlers.

use crate::tui::{App, AppMode};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_licenses_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('g') => app.tabs.licenses.toggle_group(),
        KeyCode::Char('s') => app.tabs.licenses.toggle_sort(),
        KeyCode::Char('r') => app.tabs.licenses.toggle_risk_filter(),
        KeyCode::Char('c') => app.tabs.licenses.toggle_compatibility(),
        KeyCode::Tab | KeyCode::Char('p') => {
            // Panel toggle only meaningful in Diff mode (new/removed panels)
            if app.mode == AppMode::Diff {
                app.tabs.licenses.toggle_focus();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => app.tabs.licenses.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.licenses.select_next(),
        _ => {}
    }
}

