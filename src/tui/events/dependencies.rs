//! Dependencies tab event handlers.

use crate::tui::state::ListNavigation;
use crate::tui::{App, AppMode};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_dependencies_keys(app: &mut App, key: KeyEvent) {
    // Handle search mode first
    if app.tabs.dependencies.is_searching() {
        match key.code {
            KeyCode::Esc => {
                app.tabs.dependencies.stop_search();
            }
            KeyCode::Enter => {
                // Confirm search and exit search mode
                app.tabs.dependencies.stop_search();
            }
            KeyCode::Backspace => {
                app.tabs.dependencies.search_pop();
                update_dependencies_search_matches(app);
            }
            KeyCode::Char('f') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                // Toggle filter mode
                app.tabs.dependencies.toggle_filter_mode();
            }
            KeyCode::Char('f') => {
                // Toggle filter mode (also works without ctrl)
                app.tabs.dependencies.toggle_filter_mode();
            }
            KeyCode::Char('n') => {
                // Next match
                app.tabs.dependencies.next_match();
            }
            KeyCode::Char('N') => {
                // Previous match
                app.tabs.dependencies.prev_match();
            }
            KeyCode::Char(c) => {
                app.tabs.dependencies.search_push(c);
                update_dependencies_search_matches(app);
            }
            _ => {}
        }
        return;
    }

    // Handle persistent search (when has query but not actively searching)
    if app.tabs.dependencies.has_search_query() {
        match key.code {
            KeyCode::Esc => {
                // Clear search completely
                app.tabs.dependencies.clear_search();
                return;
            }
            KeyCode::Char('n') => {
                // Next match
                app.tabs.dependencies.next_match();
                return;
            }
            KeyCode::Char('N') => {
                // Previous match
                app.tabs.dependencies.prev_match();
                return;
            }
            KeyCode::Char('/') => {
                // Re-enter search mode
                app.tabs.dependencies.search_active = true;
                return;
            }
            _ => {
                // Fall through to normal key handling
            }
        }
    }

    // Handle dependencies help overlay first
    if app.tabs.dependencies.show_deps_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')) {
            app.tabs.dependencies.show_deps_help = false;
        }
        return;
    }

    // Normal key handling
    match key.code {
        KeyCode::Char('/') => {
            // Start search mode
            app.tabs.dependencies.start_search();
        }
        KeyCode::Char('?') => {
            // Toggle dependencies help overlay
            app.tabs.dependencies.toggle_deps_help();
        }
        KeyCode::Char('t') => app.tabs.dependencies.toggle_transitive(),
        KeyCode::Char('h') => {
            // Toggle highlight changes - only meaningful in Diff mode
            if app.mode == AppMode::Diff {
                app.tabs.dependencies.toggle_highlight();
            }
        }
        KeyCode::Char('y') => {
            // Toggle cycle detection display
            app.tabs.dependencies.toggle_cycles();
        }
        KeyCode::Char('s') => {
            // Cycle sort order
            app.tabs.dependencies.toggle_sort();
        }
        KeyCode::Char('e') => {
            // Expand all nodes
            app.tabs.dependencies.expand_all();
        }
        KeyCode::Char('E') => {
            // Collapse all nodes
            app.tabs.dependencies.collapse_all();
        }
        KeyCode::Char('b') => {
            // Toggle breadcrumb display
            app.tabs.dependencies.toggle_breadcrumbs();
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            // Increase depth limit
            app.tabs.dependencies.increase_depth();
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            // Decrease depth limit
            app.tabs.dependencies.decrease_depth();
        }
        KeyCode::Char('>') | KeyCode::Char('.') => {
            // Increase roots limit
            app.tabs.dependencies.increase_roots();
        }
        KeyCode::Char('<') | KeyCode::Char(',') => {
            // Decrease roots limit
            app.tabs.dependencies.decrease_roots();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.tabs.dependencies.select_prev();
            skip_dependency_placeholders(app, false);
            app.tabs.dependencies.update_breadcrumbs();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.tabs.dependencies.select_next();
            skip_dependency_placeholders(app, true);
            app.tabs.dependencies.update_breadcrumbs();
        }
        KeyCode::Enter => {
            // Toggle expand/collapse of tree node
            if let Some(node_id) = app.tabs.dependencies.get_selected_node_id().map(str::to_string) {
                app.tabs.dependencies.toggle_node(&node_id);
            }
        }
        KeyCode::Char('c') => {
            // Navigate to component (go to components tab with this component selected)
            if let Some(node_id) = app.tabs.dependencies.get_selected_node_id().map(str::to_string) {
                // The node_id is often the component name or identifier
                app.navigate_dep_to_component(&node_id);
            }
        }
        KeyCode::Left => {
            // Collapse node
            if let Some(node_id) = app.tabs.dependencies.get_selected_node_id().map(str::to_string) {
                app.tabs.dependencies.collapse(&node_id);
            }
        }
        KeyCode::Right => {
            // Expand node
            if let Some(node_id) = app.tabs.dependencies.get_selected_node_id().map(str::to_string) {
                app.tabs.dependencies.expand(&node_id);
            }
        }
        KeyCode::Home => {
            // Jump to first node
            app.tabs.dependencies.selected = 0;
            app.tabs.dependencies.adjust_scroll_to_selection();
            app.tabs.dependencies.update_breadcrumbs();
        }
        KeyCode::End | KeyCode::Char('G') => {
            // Jump to last node
            if app.tabs.dependencies.total > 0 {
                app.tabs.dependencies.selected = app.tabs.dependencies.total - 1;
                app.tabs.dependencies.adjust_scroll_to_selection();
                app.tabs.dependencies.update_breadcrumbs();
            }
        }
        KeyCode::PageUp => {
            // Jump up by viewport height
            let jump = app.tabs.dependencies.viewport_height.saturating_sub(2);
            app.tabs.dependencies.selected = app.tabs.dependencies.selected.saturating_sub(jump);
            app.tabs.dependencies.adjust_scroll_to_selection();
            app.tabs.dependencies.update_breadcrumbs();
        }
        KeyCode::PageDown => {
            // Jump down by viewport height
            let jump = app.tabs.dependencies.viewport_height.saturating_sub(2);
            let new_sel = app.tabs.dependencies.selected + jump;
            if app.tabs.dependencies.total > 0 {
                app.tabs.dependencies.selected = new_sel.min(app.tabs.dependencies.total - 1);
                app.tabs.dependencies.adjust_scroll_to_selection();
                app.tabs.dependencies.update_breadcrumbs();
            }
        }
        _ => {}
    }
}

/// Update search matches for dependencies view
pub(super) fn update_dependencies_search_matches(app: &mut App) {
    // Collect all node names for search matching
    let all_nodes: Vec<(String, String)> = app
        .tabs.dependencies
        .visible_nodes
        .iter()
        .filter(|id| !id.starts_with("__"))
        .map(|id| {
            // Extract component name from node ID
            let name = if id.contains(':') {
                // For child nodes like "parent:+:child" or "parent:-:child"
                id.split(':').next_back().unwrap_or(id).to_string()
            } else {
                id.clone()
            };
            (id.clone(), name)
        })
        .collect();

    app.tabs.dependencies.update_search_matches(&all_nodes);
}

pub(super) fn skip_dependency_placeholders(app: &mut App, forward: bool) {
    loop {
        let Some(node_id) = app.tabs.dependencies.get_selected_node_id() else {
            break;
        };
        if !node_id.starts_with("__") {
            break;
        }
        if forward {
            let before = app.tabs.dependencies.selected;
            app.tabs.dependencies.select_next();
            if app.tabs.dependencies.selected == before {
                break;
            }
        } else {
            let before = app.tabs.dependencies.selected;
            app.tabs.dependencies.select_prev();
            if app.tabs.dependencies.selected == before {
                break;
            }
        }
    }
}

