//! Side-by-side tab event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub(super) fn handle_sidebyside_keys(app: &mut App, key: KeyEvent) {
    // Handle search input mode first
    if app.tabs.side_by_side.search_active {
        handle_sidebyside_search_input(app, key);
        return;
    }

    // Handle detail modal
    if app.tabs.side_by_side.show_detail_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.tabs.side_by_side.close_detail_modal();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        // Toggle focus between left and right panels
        KeyCode::Tab | KeyCode::Char('p') | KeyCode::Left | KeyCode::Right => {
            app.tabs.side_by_side.toggle_focus();
        }
        // Scroll focused panel up/down
        KeyCode::Up | KeyCode::Char('k') => app.tabs.side_by_side.scroll_up(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.side_by_side.scroll_down(),
        // Page up/down
        KeyCode::PageUp => app.tabs.side_by_side.page_up(),
        KeyCode::PageDown => app.tabs.side_by_side.page_down(),
        // Go to top/bottom
        KeyCode::Home | KeyCode::Char('g') => app.tabs.side_by_side.go_to_top(),
        KeyCode::Char('G') => app.tabs.side_by_side.go_to_bottom(),
        // Synchronized scroll (Shift+J/K)
        KeyCode::Char('K') => app.tabs.side_by_side.scroll_both_up(),
        KeyCode::Char('J') => app.tabs.side_by_side.scroll_both_down(),

        // === New Enhanced Features ===

        // Toggle alignment mode (grouped vs aligned)
        KeyCode::Char('a') => {
            app.tabs.side_by_side.toggle_alignment();
            app.set_status_message(format!(
                "Alignment mode: {}",
                app.tabs.side_by_side.alignment_mode.name()
            ));
        }

        // Toggle sync mode
        KeyCode::Char('s') => {
            app.tabs.side_by_side.toggle_sync();
            app.set_status_message(format!(
                "Sync mode: {}",
                app.tabs.side_by_side.sync_mode.name()
            ));
        }

        // Start search
        KeyCode::Char('/') => {
            app.tabs.side_by_side.start_search();
        }

        // Navigate to next/previous change
        KeyCode::Char('n' | ']') => {
            app.tabs.side_by_side.next_change();
            let pos = app.tabs.side_by_side.change_position();
            app.set_status_message(format!("Change {pos}"));
        }
        KeyCode::Char('N' | '[') => {
            app.tabs.side_by_side.prev_change();
            let pos = app.tabs.side_by_side.change_position();
            app.set_status_message(format!("Change {pos}"));
        }

        // Filter toggles
        KeyCode::Char('1') => {
            app.tabs.side_by_side.filter.toggle_added();
            let status = if app.tabs.side_by_side.filter.show_added {
                "Added: shown"
            } else {
                "Added: hidden"
            };
            app.set_status_message(status.to_string());
        }
        KeyCode::Char('2') => {
            app.tabs.side_by_side.filter.toggle_removed();
            let status = if app.tabs.side_by_side.filter.show_removed {
                "Removed: shown"
            } else {
                "Removed: hidden"
            };
            app.set_status_message(status.to_string());
        }
        KeyCode::Char('3') => {
            app.tabs.side_by_side.filter.toggle_modified();
            let status = if app.tabs.side_by_side.filter.show_modified {
                "Modified: shown"
            } else {
                "Modified: hidden"
            };
            app.set_status_message(status.to_string());
        }
        KeyCode::Char('0') => {
            app.tabs.side_by_side.filter.show_all();
            app.set_status_message("Showing all changes".to_string());
        }

        // Open component detail modal
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.tabs.side_by_side.toggle_detail_modal();
        }

        // Copy current row to clipboard (yank)
        KeyCode::Char('y') => {
            // Get the current row info and copy to clipboard
            let info = get_current_row_info(app);
            if let Some(text) = info {
                // Note: clipboard support requires arboard crate
                app.set_status_message(format!(
                    "Copied: {}",
                    text.chars().take(50).collect::<String>()
                ));
            }
        }

        _ => {}
    }
}

pub(super) fn handle_sidebyside_search_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.side_by_side.cancel_search();
        }
        KeyCode::Enter => {
            // Confirm search and stay in results
            app.tabs.side_by_side.confirm_search();
            if !app.tabs.side_by_side.search_matches.is_empty() {
                let pos = app.tabs.side_by_side.match_position();
                app.set_status_message(format!("Match {pos}"));
            }
        }
        KeyCode::Backspace => {
            app.tabs.side_by_side.search_pop();
            // Live update search matches
            update_sidebyside_search_matches(app);
        }
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+N: Next match
            app.tabs.side_by_side.next_match();
        }
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+P: Previous match
            app.tabs.side_by_side.prev_match();
        }
        KeyCode::Down => {
            app.tabs.side_by_side.next_match();
        }
        KeyCode::Up => {
            app.tabs.side_by_side.prev_match();
        }
        KeyCode::Char(c) => {
            app.tabs.side_by_side.search_push(c);
            // Live update search matches
            update_sidebyside_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_sidebyside_search_matches(app: &mut App) {
    let query = app
        .tabs
        .side_by_side
        .search_query
        .clone()
        .unwrap_or_default();

    if query.is_empty() {
        app.tabs.side_by_side.update_search_matches(vec![]);
        return;
    }

    let query_lower = query.to_lowercase();
    let mut matches = Vec::new();

    if let Some(result) = &app.data.diff_result {
        let filter = &app.tabs.side_by_side.filter;
        let mut idx = 0;

        // Check removed components
        if filter.show_removed {
            for comp in &result.components.removed {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }

        // Check modified components
        if filter.show_modified {
            for comp in &result.components.modified {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }

        // Check added components
        if filter.show_added {
            for comp in &result.components.added {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }
    }

    app.tabs.side_by_side.update_search_matches(matches);
}

pub(super) fn get_current_row_info(app: &App) -> Option<String> {
    let result = app.data.diff_result.as_ref()?;
    let filter = &app.tabs.side_by_side.filter;
    let selected = app.tabs.side_by_side.selected_row;

    let mut idx = 0;

    // Check removed components
    if filter.show_removed {
        for comp in &result.components.removed {
            if idx == selected {
                let version = comp.old_version.as_deref().unwrap_or("");
                return Some(format!("- {} {}", comp.name, version));
            }
            idx += 1;
        }
    }

    // Check modified components
    if filter.show_modified {
        for comp in &result.components.modified {
            if idx == selected {
                let old_ver = comp.old_version.as_deref().unwrap_or("");
                let new_ver = comp.new_version.as_deref().unwrap_or("");
                return Some(format!("~ {} {} -> {}", comp.name, old_ver, new_ver));
            }
            idx += 1;
        }
    }

    // Check added components
    if filter.show_added {
        for comp in &result.components.added {
            if idx == selected {
                let version = comp.new_version.as_deref().unwrap_or("");
                return Some(format!("+ {} {}", comp.name, version));
            }
            idx += 1;
        }
    }

    None
}
