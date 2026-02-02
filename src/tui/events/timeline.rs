//! Timeline mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_timeline_keys(app: &mut App, key: KeyEvent) {
    // Handle search input mode
    if app.tabs.timeline.search.active {
        handle_timeline_search(app, key);
        return;
    }

    // Handle jump mode
    if app.tabs.timeline.jump_mode {
        handle_timeline_jump(app, key);
        return;
    }

    // Handle version diff modal
    if app.tabs.timeline.show_version_diff_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.timeline.close_version_diff_modal();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                // Move compare version left
                if let Some(v) = app.tabs.timeline.compare_version {
                    if v > 0 && v - 1 != app.tabs.timeline.selected_version {
                        app.tabs.timeline.set_compare_version(v - 1);
                    }
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                // Move compare version right
                if let Some(v) = app.tabs.timeline.compare_version {
                    if v + 1 < app.tabs.timeline.total_versions
                        && v + 1 != app.tabs.timeline.selected_version
                    {
                        app.tabs.timeline.set_compare_version(v + 1);
                    }
                }
            }
            _ => {}
        }
        return;
    }

    // Handle component history modal
    if app.tabs.timeline.show_component_history {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.timeline.close_component_history();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::Char('p') => app.tabs.timeline.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.timeline.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.timeline.select_next(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.timeline.search.start();
        }

        // Sort and filter
        KeyCode::Char('s') => {
            app.tabs.timeline.toggle_sort();
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.timeline.sort_by.label(),
                app.tabs.timeline.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.timeline.toggle_sort_direction();
        }
        KeyCode::Char('f') => {
            app.tabs.timeline.toggle_component_filter();
            app.set_status_message(format!(
                "Filter: {}",
                app.tabs.timeline.component_filter.label()
            ));
        }

        // Version diff modal
        KeyCode::Char('d') => {
            app.tabs.timeline.toggle_version_diff_modal();
        }

        // Statistics panel
        KeyCode::Char('t') => {
            app.tabs.timeline.toggle_statistics();
            let status = if app.tabs.timeline.show_statistics {
                "Statistics: shown"
            } else {
                "Statistics: hidden"
            };
            app.set_status_message(status.to_string());
        }

        // Component history detail
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.tabs.timeline.toggle_component_history();
        }

        // Jump to version
        KeyCode::Char('g') => {
            app.tabs.timeline.start_jump_mode();
        }

        // Chart zoom
        KeyCode::Char('+') | KeyCode::Char('=') => {
            app.tabs.timeline.zoom_in();
            app.set_status_message(format!("Zoom: {}x", app.tabs.timeline.chart_zoom));
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            app.tabs.timeline.zoom_out();
            app.set_status_message(format!("Zoom: {}x", app.tabs.timeline.chart_zoom));
        }

        // Chart scroll
        KeyCode::Left | KeyCode::Char('h') => {
            app.tabs.timeline.scroll_chart_left();
        }
        KeyCode::Right | KeyCode::Char('l') => {
            app.tabs.timeline.scroll_chart_right();
        }

        _ => {}
    }
}

pub(super) fn handle_timeline_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.timeline.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.timeline.search.confirm();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.timeline.search.pop();
            update_timeline_search_matches(app);
        }
        KeyCode::Down => {
            app.tabs.timeline.search.next_match();
        }
        KeyCode::Up => {
            app.tabs.timeline.search.prev_match();
        }
        KeyCode::Char(c) => {
            app.tabs.timeline.search.push(c);
            update_timeline_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_timeline_search_matches(app: &mut App) {
    let query = app.tabs.timeline.search.query.to_lowercase();
    if query.is_empty() {
        app.tabs.timeline.search.update_matches(vec![]);
        return;
    }

    let matches: Vec<usize> = if let Some(ref result) = app.data.timeline_result {
        result
            .sboms
            .iter()
            .enumerate()
            .filter(|(_, sbom)| sbom.name.to_lowercase().contains(&query))
            .map(|(i, _)| i)
            .collect()
    } else {
        vec![]
    };

    app.tabs.timeline.search.update_matches(matches);
}

pub(super) fn handle_timeline_jump(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.timeline.cancel_jump_mode();
        }
        KeyCode::Enter => {
            app.tabs.timeline.execute_jump();
            app.set_status_message(format!(
                "Jumped to version {}",
                app.tabs.timeline.selected_version + 1
            ));
        }
        KeyCode::Backspace => {
            app.tabs.timeline.jump_pop();
        }
        KeyCode::Char(c) => {
            app.tabs.timeline.jump_push(c);
        }
        _ => {}
    }
}

