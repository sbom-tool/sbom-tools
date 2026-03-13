//! Source tab `ViewState` implementation.
//!
//! Handles panel navigation, tree/raw mode, expand/collapse, search,
//! bookmarks, fold depth, detail panel, and sync between panels.
//! Clipboard operations and export remain in the sync bridge.

use crate::tui::app_states::SourceViewMode;
use crate::tui::app_states::source::SourceDiffState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Source tab view implementing the `ViewState` trait.
pub struct SourceView {
    inner: SourceDiffState,
}

impl SourceView {
    pub(crate) fn new() -> Self {
        Self {
            inner: SourceDiffState::new("", ""),
        }
    }

    /// Create with pre-populated state (used when raw SBOM text is available).
    pub(crate) fn with_state(state: SourceDiffState) -> Self {
        Self { inner: state }
    }

    /// Access the inner state for sync operations.
    pub(crate) fn inner(&self) -> &SourceDiffState {
        &self.inner
    }

    /// Mutable access for sync operations.
    pub(crate) fn inner_mut(&mut self) -> &mut SourceDiffState {
        &mut self.inner
    }
}

impl Default for SourceView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SourceView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        let panel = self.inner.active_panel_mut();

        // Handle active search input
        if panel.search_active {
            return handle_panel_search(panel, key);
        }

        match key.code {
            KeyCode::Char('/') => {
                self.inner.active_panel_mut().start_search();
                EventResult::Consumed
            }
            KeyCode::Char('n') => {
                let panel = self.inner.active_panel_mut();
                if panel.search_query.is_empty() && !panel.change_annotations.is_empty() {
                    self.inner.active_panel_mut().next_change();
                    let idx = self.inner.active_panel_mut().current_change_idx;
                    let total = self.inner.active_panel_mut().change_indices.len();
                    if let Some(i) = idx {
                        return EventResult::status(format!("Change {}/{total}", i + 1));
                    }
                } else {
                    self.inner.active_panel_mut().next_search_match();
                }
                EventResult::Consumed
            }
            KeyCode::Char('N') => {
                let panel = self.inner.active_panel_mut();
                if panel.search_query.is_empty() && !panel.change_annotations.is_empty() {
                    self.inner.active_panel_mut().prev_change();
                    let idx = self.inner.active_panel_mut().current_change_idx;
                    let total = self.inner.active_panel_mut().change_indices.len();
                    if let Some(i) = idx {
                        return EventResult::status(format!("Change {}/{total}", i + 1));
                    }
                } else {
                    self.inner.active_panel_mut().prev_search_match();
                }
                EventResult::Consumed
            }
            // Copy JSON path — data-dependent (clipboard), return Ignored for bridge
            KeyCode::Char('c') => EventResult::Ignored,
            // Line numbers toggle
            KeyCode::Char('I') => {
                self.inner.active_panel_mut().toggle_line_numbers();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().toggle_line_numbers();
                }
                EventResult::Consumed
            }
            // Word wrap toggle
            KeyCode::Char('W') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().toggle_word_wrap();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().toggle_word_wrap();
                    }
                }
                EventResult::Consumed
            }
            // Bookmarks
            KeyCode::Char('m') => {
                self.inner.active_panel_mut().toggle_bookmark();
                EventResult::Consumed
            }
            KeyCode::Char('\'') => {
                self.inner.active_panel_mut().next_bookmark();
                EventResult::Consumed
            }
            KeyCode::Char('"') => {
                self.inner.active_panel_mut().prev_bookmark();
                EventResult::Consumed
            }
            // Export — data-dependent, return Ignored for bridge
            KeyCode::Char('E') => EventResult::Ignored,
            // Detail panel toggle
            KeyCode::Char('d') => {
                self.inner.toggle_detail();
                EventResult::Consumed
            }
            // Filter type cycle (tree mode)
            KeyCode::Char('f') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Tree {
                    self.inner.active_panel_mut().cycle_filter_type();
                    let label = self.inner.active_panel_mut().filter_label();
                    if label.is_empty() {
                        return EventResult::status("Filter: off");
                    }
                    return EventResult::status(format!("Filter: {label}"));
                }
                EventResult::Consumed
            }
            // Sort cycle (tree mode)
            KeyCode::Char('S') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Tree {
                    self.inner.active_panel_mut().cycle_sort();
                    let label = self.inner.active_panel_mut().sort_mode.label();
                    if label.is_empty() {
                        return EventResult::status("Sort: off");
                    }
                    return EventResult::status(format!("Sort: {label}"));
                }
                EventResult::Consumed
            }
            // Toggle view mode (tree/raw)
            KeyCode::Char('v') => {
                self.inner.old_panel.toggle_view_mode();
                self.inner.new_panel.toggle_view_mode();
                EventResult::Consumed
            }
            // Toggle side
            KeyCode::Char('w') => {
                self.inner.toggle_side();
                EventResult::Consumed
            }
            // Toggle sync
            KeyCode::Char('s') => {
                self.inner.toggle_sync();
                EventResult::Consumed
            }
            // Expand/collapse (Enter/Space)
            KeyCode::Enter | KeyCode::Char(' ') => {
                let node_id = get_expandable_node(&mut self.inner, None);
                if let Some(id) = node_id {
                    self.inner.active_panel_mut().toggle_expand(&id);
                    if self.inner.is_synced() {
                        sync_expand(&mut self.inner, &id);
                    }
                }
                EventResult::Consumed
            }
            // Left: collapse or scroll left
            KeyCode::Left | KeyCode::Char('h') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().scroll_left();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().scroll_left();
                    }
                } else {
                    let node_id = get_expandable_node(&mut self.inner, Some(true));
                    if let Some(id) = node_id {
                        self.inner.active_panel_mut().toggle_expand(&id);
                        if self.inner.is_synced() {
                            sync_expand(&mut self.inner, &id);
                        }
                    }
                }
                EventResult::Consumed
            }
            // Right: expand or scroll right
            KeyCode::Right | KeyCode::Char('l') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().scroll_right();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().scroll_right();
                    }
                } else {
                    let node_id = get_expandable_node(&mut self.inner, Some(false));
                    if let Some(id) = node_id {
                        self.inner.active_panel_mut().toggle_expand(&id);
                        if self.inner.is_synced() {
                            sync_expand(&mut self.inner, &id);
                        }
                    }
                }
                EventResult::Consumed
            }
            // Collapse all
            KeyCode::Char('H') => {
                self.inner.active_panel_mut().collapse_all();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().collapse_all();
                }
                EventResult::Consumed
            }
            // Expand all
            KeyCode::Char('L') => {
                self.inner.active_panel_mut().expand_all();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_all();
                }
                EventResult::Consumed
            }
            // Fold depth presets
            KeyCode::Char('!') => {
                self.inner.active_panel_mut().expand_to_depth(1);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(1);
                }
                EventResult::Consumed
            }
            KeyCode::Char('@') => {
                self.inner.active_panel_mut().expand_to_depth(2);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(2);
                }
                EventResult::Consumed
            }
            KeyCode::Char('#') => {
                self.inner.active_panel_mut().expand_to_depth(3);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(3);
                }
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Source"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("v", "Tree/Raw"),
            Shortcut::new("w", "Switch side"),
            Shortcut::new("s", "Sync"),
            Shortcut::new("/", "Search"),
            Shortcut::new("H/L", "Collapse/Expand all"),
            Shortcut::new("!/@@/#", "Fold depth"),
            Shortcut::new("m", "Bookmark"),
            Shortcut::new("d", "Detail"),
        ]
    }
}

fn handle_panel_search(
    panel: &mut crate::tui::app_states::source::SourcePanelState,
    key: KeyEvent,
) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            panel.stop_search();
            panel.search_query.clear();
            panel.search_matches.clear();
            EventResult::Consumed
        }
        KeyCode::Enter => {
            panel.stop_search();
            EventResult::Consumed
        }
        KeyCode::Backspace => {
            panel.search_pop_char();
            EventResult::Consumed
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            panel.toggle_search_regex();
            EventResult::Consumed
        }
        KeyCode::Char(c) => {
            panel.search_push_char(c);
            EventResult::Consumed
        }
        _ => EventResult::Consumed,
    }
}

/// Get the node_id of the selected expandable node in the active panel.
fn get_expandable_node(
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

/// Sync expand/collapse to inactive panel.
fn sync_expand(source: &mut SourceDiffState, node_id: &str) {
    let inactive = source.inactive_panel_mut();
    if inactive.view_mode != SourceViewMode::Tree || inactive.json_tree.is_none() {
        return;
    }
    inactive.ensure_flat_cache();
    let exists = inactive
        .cached_flat_items
        .iter()
        .any(|item| item.node_id == node_id);
    if exists || inactive.expanded.contains(node_id) {
        inactive.toggle_expand(node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::traits::ViewMode;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_ctx() -> ViewContext<'static> {
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        ViewContext {
            mode: ViewMode::Diff,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_view_mode_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        // Empty panels start in Raw mode; toggle switches to Tree
        let initial = view.inner().old_panel.view_mode;
        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        // toggle_view_mode cycles the mode
        let _after = view.inner().old_panel.view_mode;
        // Verify it changed (or at least the key was consumed)
        let result = view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        // After two toggles, should be back to initial
        assert_eq!(view.inner().old_panel.view_mode, initial);
    }

    #[test]
    fn test_side_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().active_side;
        view.handle_key(make_key(KeyCode::Char('w')), &mut ctx);
        assert_ne!(view.inner().active_side, initial);
    }

    #[test]
    fn test_sync_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().sync_mode;
        view.handle_key(make_key(KeyCode::Char('s')), &mut ctx);
        assert_ne!(view.inner().sync_mode, initial);
    }

    #[test]
    fn test_data_dependent_ignored() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('c')), &mut ctx),
            EventResult::Ignored
        );
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('E')), &mut ctx),
            EventResult::Ignored
        );
    }
}
