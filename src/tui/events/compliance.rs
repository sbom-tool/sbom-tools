//! Compliance tab event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_diff_compliance_keys(app: &mut App, key: KeyEvent) {
    // If detail overlay is shown, Esc or Enter closes it
    if app.tabs.diff_compliance.show_detail {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.tabs.diff_compliance.show_detail = false;
            }
            _ => {}
        }
        return;
    }

    let max_violations = crate::tui::views::diff_compliance_violation_count(app);
    match key.code {
        KeyCode::Left | KeyCode::Char('h') => app.tabs.diff_compliance.prev_standard(),
        KeyCode::Right | KeyCode::Char('l') => app.tabs.diff_compliance.next_standard(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.diff_compliance.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.diff_compliance.select_next(max_violations),
        KeyCode::Enter => {
            if max_violations > 0 {
                app.tabs.diff_compliance.show_detail = true;
            }
        }
        KeyCode::Tab => app.tabs.diff_compliance.next_view_mode(),
        KeyCode::Char('E') => app.export_compliance(crate::tui::export::ExportFormat::Json),
        KeyCode::Home => app.tabs.diff_compliance.selected_violation = 0,
        KeyCode::End | KeyCode::Char('G') => {
            if max_violations > 0 {
                app.tabs.diff_compliance.selected_violation = max_violations - 1;
            }
        }
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.tabs.diff_compliance.select_prev();
            }
        }
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.tabs.diff_compliance.select_next(max_violations);
            }
        }
        _ => {}
    }
}

