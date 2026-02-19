//! Source tab event handling for App (diff mode).

use crate::tui::app::App;
use crate::tui::app_states::SourceViewMode;
use crate::tui::app_states::source::SourceDiffState;
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
            app.tabs.source.old_panel.toggle_view_mode();
            app.tabs.source.new_panel.toggle_view_mode();
        }
        KeyCode::Char('w') => {
            app.tabs.source.toggle_side();
        }
        KeyCode::Char('s') => {
            app.tabs.source.toggle_sync();
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            let node_id = get_active_expandable_node(&mut app.tabs.source, None);
            if let Some(id) = node_id {
                app.tabs.source.active_panel_mut().toggle_expand(&id);
                if app.tabs.source.is_synced() {
                    sync_expand_to_inactive(&mut app.tabs.source, &id);
                }
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            // Collapse: only if expanded
            let node_id = get_active_expandable_node(&mut app.tabs.source, Some(true));
            if let Some(id) = node_id {
                app.tabs.source.active_panel_mut().toggle_expand(&id);
                if app.tabs.source.is_synced() {
                    sync_expand_to_inactive(&mut app.tabs.source, &id);
                }
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            // Expand: only if collapsed
            let node_id = get_active_expandable_node(&mut app.tabs.source, Some(false));
            if let Some(id) = node_id {
                app.tabs.source.active_panel_mut().toggle_expand(&id);
                if app.tabs.source.is_synced() {
                    sync_expand_to_inactive(&mut app.tabs.source, &id);
                }
            }
        }
        KeyCode::Char('H') => {
            app.tabs.source.active_panel_mut().collapse_all();
            if app.tabs.source.is_synced() {
                app.tabs.source.inactive_panel_mut().collapse_all();
            }
        }
        KeyCode::Char('L') => {
            app.tabs.source.active_panel_mut().expand_all();
            if app.tabs.source.is_synced() {
                app.tabs.source.inactive_panel_mut().expand_all();
            }
        }
        _ => {}
    }
}

/// Get the node_id of the selected expandable node in the active panel.
///
/// `require_expanded`: `None` = any expandable node, `Some(true)` = must be expanded,
/// `Some(false)` = must be collapsed.
fn get_active_expandable_node(
    source: &mut SourceDiffState,
    require_expanded: Option<bool>,
) -> Option<String> {
    let panel = source.active_panel_mut();
    if panel.view_mode != SourceViewMode::Tree {
        return None;
    }
    panel.ensure_flat_cache();
    let item = panel.cached_flat_items.get(panel.selected)?;
    if !item.is_expandable {
        return None;
    }
    if let Some(must_be_expanded) = require_expanded
        && item.is_expanded != must_be_expanded
    {
        return None;
    }
    Some(item.node_id.clone())
}

/// Apply expand/collapse toggle on the inactive panel for the same node_id (if it exists).
fn sync_expand_to_inactive(source: &mut SourceDiffState, node_id: &str) {
    let inactive = source.inactive_panel_mut();
    if inactive.view_mode != SourceViewMode::Tree || inactive.json_tree.is_none() {
        return;
    }
    // Toggle the same node on the inactive panel (if it exists in its tree)
    inactive.ensure_flat_cache();
    let exists = inactive
        .cached_flat_items
        .iter()
        .any(|item| item.node_id == node_id);
    if exists {
        inactive.toggle_expand(node_id);
    } else {
        // Node path may not be visible yet — check if it exists in the expanded set
        // or try to expand ancestors to reveal it
        if inactive.expanded.contains(node_id) {
            inactive.toggle_expand(node_id);
        }
    }
}
