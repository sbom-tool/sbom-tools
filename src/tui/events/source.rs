//! Source tab event handling for App (diff mode).

use crate::tui::app::App;
use crate::tui::app_states::SourceViewMode;
use crossterm::event::{KeyCode, KeyEvent};

/// Handle source-tab-specific key events.
pub fn handle_source_keys(app: &mut App, key: KeyEvent) {
    let panel = app.tabs.source.active_panel_mut();

    // Handle active search input first
    if panel.search_active {
        match key.code {
            KeyCode::Esc => {
                panel.stop_search();
                panel.search_query.clear();
                panel.search_matches.clear();
            }
            KeyCode::Enter => {
                panel.stop_search();
            }
            KeyCode::Backspace => {
                panel.search_pop_char();
            }
            KeyCode::Char(c) => {
                panel.search_push_char(c);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('/') => {
            app.tabs.source.active_panel_mut().start_search();
        }
        KeyCode::Char('n') => {
            app.tabs.source.active_panel_mut().next_search_match();
        }
        KeyCode::Char('N') => {
            app.tabs.source.active_panel_mut().prev_search_match();
        }
        KeyCode::Char('v') => {
            app.tabs.source.active_panel_mut().toggle_view_mode();
        }
        KeyCode::Char('w') | KeyCode::Char('\t') => {
            // Tab or 'w' to switch active side
            app.tabs.source.toggle_side();
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            let panel = app.tabs.source.active_panel_mut();
            if panel.view_mode == SourceViewMode::Tree {
                // Get the selected node id from the flattened tree
                if let Some(ref tree) = panel.json_tree {
                    let mut items = Vec::new();
                    crate::tui::shared::source::flatten_json_tree(
                        tree,
                        "",
                        0,
                        &panel.expanded,
                        &mut items,
                        true,
                        &[],
                    );
                    if let Some(item) = items.get(panel.selected) {
                        if item.is_expandable {
                            let node_id = item.node_id.clone();
                            panel.toggle_expand(&node_id);
                        }
                    }
                }
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            let panel = app.tabs.source.active_panel_mut();
            if panel.view_mode == SourceViewMode::Tree {
                // Collapse current node
                if let Some(ref tree) = panel.json_tree {
                    let mut items = Vec::new();
                    crate::tui::shared::source::flatten_json_tree(
                        tree,
                        "",
                        0,
                        &panel.expanded,
                        &mut items,
                        true,
                        &[],
                    );
                    if let Some(item) = items.get(panel.selected) {
                        if item.is_expandable && item.is_expanded {
                            let node_id = item.node_id.clone();
                            panel.toggle_expand(&node_id);
                        }
                    }
                }
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            let panel = app.tabs.source.active_panel_mut();
            if panel.view_mode == SourceViewMode::Tree {
                // Expand current node
                if let Some(ref tree) = panel.json_tree {
                    let mut items = Vec::new();
                    crate::tui::shared::source::flatten_json_tree(
                        tree,
                        "",
                        0,
                        &panel.expanded,
                        &mut items,
                        true,
                        &[],
                    );
                    if let Some(item) = items.get(panel.selected) {
                        if item.is_expandable && !item.is_expanded {
                            let node_id = item.node_id.clone();
                            panel.toggle_expand(&node_id);
                        }
                    }
                }
            }
        }
        KeyCode::Char('H') => {
            app.tabs.source.active_panel_mut().collapse_all();
        }
        KeyCode::Char('L') => {
            app.tabs.source.active_panel_mut().expand_all();
        }
        _ => {}
    }
}
