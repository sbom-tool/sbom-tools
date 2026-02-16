//! Matrix mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_matrix_keys(app: &mut App, key: KeyEvent) {
    // Handle search input mode
    if app.tabs.matrix.search.active {
        handle_matrix_search(app, key);
        return;
    }

    // Handle pair diff modal
    if app.tabs.matrix.show_pair_diff {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_pair_diff();
            }
            _ => {}
        }
        return;
    }

    // Handle export options
    if app.tabs.matrix.show_export_options {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_export_options();
            }
            KeyCode::Char('c') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Csv);
            }
            KeyCode::Char('j') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Json);
            }
            KeyCode::Char('h') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Html);
            }
            _ => {}
        }
        return;
    }

    // Handle clustering details
    if app.tabs.matrix.show_clustering_details {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_clustering_details();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.tabs.matrix.select_prev_cluster();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.tabs.matrix.select_next_cluster();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::Char('p') => app.tabs.matrix.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.matrix.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.matrix.move_down(),
        KeyCode::Left | KeyCode::Char('h') => app.tabs.matrix.move_left(),
        KeyCode::Right | KeyCode::Char('l') => app.tabs.matrix.move_right(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.matrix.search.start();
        }

        // Sort
        KeyCode::Char('s') => {
            app.tabs.matrix.toggle_sort();
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.matrix.sort_by.label(),
                app.tabs.matrix.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.matrix.toggle_sort_direction();
        }

        // Threshold filter
        KeyCode::Char('t') => {
            app.tabs.matrix.toggle_threshold();
            app.set_status_message(format!("Threshold: {}", app.tabs.matrix.threshold.label()));
        }

        // Focus mode (zoom on row/column)
        KeyCode::Char('z') => {
            app.tabs.matrix.toggle_focus_mode();
            let status = if app.tabs.matrix.focus_mode {
                "Focus mode: enabled"
            } else {
                "Focus mode: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Focus on current row only
        KeyCode::Char('r') => {
            app.tabs.matrix.focus_on_row(app.tabs.matrix.selected_row);
            app.set_status_message(format!(
                "Focused on row {}",
                app.tabs.matrix.selected_row + 1
            ));
        }

        // Focus on current column only
        KeyCode::Char('c') => {
            app.tabs.matrix.focus_on_col(app.tabs.matrix.selected_col);
            app.set_status_message(format!(
                "Focused on column {}",
                app.tabs.matrix.selected_col + 1
            ));
        }

        // Clear focus
        KeyCode::Esc => {
            if app.tabs.matrix.focus_mode {
                app.tabs.matrix.clear_focus();
                app.set_status_message("Focus cleared".to_string());
            }
        }

        // Toggle row/column highlighting
        KeyCode::Char('H') => {
            app.tabs.matrix.toggle_row_col_highlight();
            let status = if app.tabs.matrix.highlight_row_col {
                "Row/column highlight: enabled"
            } else {
                "Row/column highlight: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Launch diff for selected pair
        KeyCode::Enter | KeyCode::Char('d') => {
            if app.tabs.matrix.selected_row == app.tabs.matrix.selected_col {
                app.set_status_message("Cannot diff same SBOM".to_string());
            } else {
                app.tabs.matrix.toggle_pair_diff();
            }
        }

        // Export options
        KeyCode::Char('x') => {
            app.tabs.matrix.toggle_export_options();
        }

        // Clustering details
        KeyCode::Char('C') => {
            app.tabs.matrix.toggle_clustering_details();
        }

        _ => {}
    }
}

pub(super) fn handle_matrix_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.matrix.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.matrix.search.confirm();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.matrix.search.pop();
            update_matrix_search_matches(app);
        }
        KeyCode::Down => {
            app.tabs.matrix.search.next_match();
        }
        KeyCode::Up => {
            app.tabs.matrix.search.prev_match();
        }
        KeyCode::Char(c) => {
            app.tabs.matrix.search.push(c);
            update_matrix_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_matrix_search_matches(app: &mut App) {
    let query = app.tabs.matrix.search.query.to_lowercase();
    if query.is_empty() {
        app.tabs.matrix.search.update_matches(vec![]);
        return;
    }

    let matches: Vec<usize> = app.data.matrix_result.as_ref().map_or_else(
        Vec::new,
        |result| {
            result
                .sboms
                .iter()
                .enumerate()
                .filter(|(_, sbom)| sbom.name.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect()
        },
    );

    app.tabs.matrix.search.update_matches(matches);
}

