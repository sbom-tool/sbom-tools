//! Dependencies tab event handlers.

use crate::tui::App;
use crate::tui::state::ListNavigation;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_dependencies_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.dependencies_view.as_mut() else {
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

    // Skip dependency placeholders after navigation
    if matches!(
        key.code,
        KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j')
    ) {
        skip_dependency_placeholders(app, matches!(key.code, KeyCode::Down | KeyCode::Char('j')));
    }

    // Update search matches if search state changed
    if app.dependencies_state().is_searching() {
        update_dependencies_search_matches(app);
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
    if key.code == KeyCode::Char('c') {
        // Navigate to component (cross-tab)
        if let Some(node_id) = app
            .dependencies_state()
            .get_selected_node_id()
            .map(str::to_string)
        {
            app.navigate_dep_to_component(&node_id);
        }
    }
}

/// Update search matches for dependencies view
pub(super) fn update_dependencies_search_matches(app: &mut App) {
    let all_nodes: Vec<(String, String)> = app
        .dependencies_state()
        .visible_nodes
        .iter()
        .filter(|id| !id.starts_with("__"))
        .map(|id| {
            let name = if id.contains(':') {
                id.split(':').next_back().unwrap_or(id).to_string()
            } else {
                id.clone()
            };
            (id.clone(), name)
        })
        .collect();

    app.dependencies_state_mut()
        .update_search_matches(&all_nodes);
}

pub(super) fn skip_dependency_placeholders(app: &mut App, forward: bool) {
    loop {
        let Some(node_id) = app.dependencies_state().get_selected_node_id() else {
            break;
        };
        if !node_id.starts_with("__") {
            break;
        }
        let before = app.dependencies_state().selected;
        if forward {
            app.dependencies_state_mut().select_next();
        } else {
            app.dependencies_state_mut().select_prev();
        }
        if app.dependencies_state().selected == before {
            break;
        }
    }
}
