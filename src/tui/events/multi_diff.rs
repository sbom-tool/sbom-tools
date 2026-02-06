//! Multi-diff mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_multi_diff_keys(app: &mut App, key: KeyEvent) {
    // Handle search input mode
    if app.tabs.multi_diff.search.active {
        handle_multi_diff_search(app, key);
        return;
    }

    // Handle detail modal
    if app.tabs.multi_diff.show_detail_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.multi_diff.close_detail_modal();
            }
            _ => {}
        }
        return;
    }

    // Handle variable component drill-down
    if app.tabs.multi_diff.show_variable_drill_down {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.multi_diff.close_variable_drill_down();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.tabs.multi_diff.select_prev_variable_component();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.tabs.multi_diff.select_next_variable_component();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::Char('p') => app.tabs.multi_diff.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.multi_diff.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.multi_diff.select_next(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.multi_diff.search.start();
        }

        // Filter and sort
        KeyCode::Char('f') => {
            app.tabs.multi_diff.toggle_filter();
            app.set_status_message(format!(
                "Filter: {}",
                app.tabs.multi_diff.filter_preset.label()
            ));
        }
        KeyCode::Char('s') => {
            app.tabs.multi_diff.toggle_sort();
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.multi_diff.sort_by.label(),
                app.tabs.multi_diff.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.multi_diff.toggle_sort_direction();
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.multi_diff.sort_by.label(),
                app.tabs.multi_diff.sort_direction.indicator()
            ));
        }

        // Detail modal
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.tabs.multi_diff.toggle_detail_modal();
        }

        // Variable components drill-down
        KeyCode::Char('v') => {
            app.tabs.multi_diff.toggle_variable_drill_down();
        }

        // Cross-target analysis
        KeyCode::Char('x') => {
            app.tabs.multi_diff.toggle_cross_target();
            let status = if app.tabs.multi_diff.show_cross_target {
                "Cross-target analysis: enabled"
            } else {
                "Cross-target analysis: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Heat map mode
        KeyCode::Char('h') => {
            app.tabs.multi_diff.toggle_heat_map();
            let status = if app.tabs.multi_diff.heat_map_mode {
                "Heat map mode: enabled"
            } else {
                "Heat map mode: disabled"
            };
            app.set_status_message(status.to_string());
        }

        _ => {}
    }
}

pub(super) fn handle_multi_diff_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.multi_diff.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.multi_diff.search.confirm();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.multi_diff.search.pop();
            update_multi_diff_search_matches(app);
        }
        KeyCode::Down => {
            app.tabs.multi_diff.search.next_match();
        }
        KeyCode::Up => {
            app.tabs.multi_diff.search.prev_match();
        }
        KeyCode::Char(c) => {
            app.tabs.multi_diff.search.push(c);
            update_multi_diff_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_multi_diff_search_matches(app: &mut App) {
    let query = app.tabs.multi_diff.search.query.to_lowercase();
    if query.is_empty() {
        app.tabs.multi_diff.search.update_matches(vec![]);
        return;
    }

    let matches: Vec<usize> = app.data.multi_diff_result.as_ref().map_or_else(
        Vec::new,
        |result| {
            result
                .comparisons
                .iter()
                .enumerate()
                .filter(|(_, comp)| comp.target.name.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect()
        },
    );

    app.tabs.multi_diff.search.update_matches(matches);
}

