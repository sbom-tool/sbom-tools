//! Side-by-side tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_sidebyside_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.sidebyside_view.as_mut() else {
        return;
    };

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = view.handle_key(key, &mut ctx);

    // Update search matches if search is active and text changed
    if app.side_by_side_state().search_active
        && matches!(key.code, KeyCode::Char(_) | KeyCode::Backspace)
    {
        update_sidebyside_search_matches(app);
    }

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

/// Handle keys that need access to App data.
fn handle_data_dependent_keys(app: &mut App, key: KeyEvent) {
    if key.code == KeyCode::Char('y') {
        let info = get_current_row_info(app);
        if let Some(text) = info {
            app.set_status_message(format!(
                "Copied: {}",
                text.chars().take(50).collect::<String>()
            ));
        }
    }
}

pub(super) fn update_sidebyside_search_matches(app: &mut App) {
    let query = app
        .side_by_side_state()
        .search_query
        .clone()
        .unwrap_or_default();

    if query.is_empty() {
        app.side_by_side_state_mut().update_search_matches(vec![]);
        return;
    }

    let query_lower = query.to_lowercase();
    let mut matches = Vec::new();

    if let Some(result) = &app.data.diff_result {
        let filter = &app.side_by_side_state().filter.clone();
        let mut idx = 0;

        if filter.show_removed {
            for comp in &result.components.removed {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }

        if filter.show_modified {
            for comp in &result.components.modified {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }

        if filter.show_added {
            for comp in &result.components.added {
                if comp.name.to_lowercase().contains(&query_lower) {
                    matches.push(idx);
                }
                idx += 1;
            }
        }
    }

    app.side_by_side_state_mut().update_search_matches(matches);
}

pub(super) fn get_current_row_info(app: &App) -> Option<String> {
    let result = app.data.diff_result.as_ref()?;
    let filter = &app.side_by_side_state().filter;
    let selected = app.side_by_side_state().selected_row;

    let mut idx = 0;

    if filter.show_removed {
        for comp in &result.components.removed {
            if idx == selected {
                let version = comp.old_version.as_deref().unwrap_or("");
                return Some(format!("- {} {}", comp.name, version));
            }
            idx += 1;
        }
    }

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
