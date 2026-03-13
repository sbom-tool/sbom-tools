//! Dependencies tab `ViewState` implementation.
//!
//! Handles tree navigation, expand/collapse, depth/root limits,
//! sort cycling, and search mode toggling. Data-dependent search
//! matching and cross-tab navigation remain in the sync bridge.

use crate::tui::app_states::dependencies::DependenciesState;
use crate::tui::state::ListNavigation;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Dependencies tab view implementing the `ViewState` trait.
pub struct DependenciesView {
    inner: DependenciesState,
}

impl DependenciesView {
    pub(crate) fn new() -> Self {
        Self {
            inner: DependenciesState::new(),
        }
    }

    /// Access the inner state for sync operations.
    pub(crate) fn inner(&self) -> &DependenciesState {
        &self.inner
    }

    /// Mutable access to the inner state for sync operations.
    pub(crate) fn inner_mut(&mut self) -> &mut DependenciesState {
        &mut self.inner
    }
}

impl Default for DependenciesView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for DependenciesView {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut ViewContext) -> EventResult {
        // Handle search mode
        if self.inner.is_searching() {
            return self.handle_search_key(key);
        }

        // Handle persistent search (has query but not actively searching)
        if self.inner.has_search_query() {
            match key.code {
                KeyCode::Esc => {
                    self.inner.clear_search();
                    return EventResult::Consumed;
                }
                KeyCode::Char('n') => {
                    self.inner.next_match();
                    return EventResult::Consumed;
                }
                KeyCode::Char('N') => {
                    self.inner.prev_match();
                    return EventResult::Consumed;
                }
                KeyCode::Char('/') => {
                    self.inner.search_active = true;
                    return EventResult::Consumed;
                }
                _ => {} // Fall through to normal key handling
            }
        }

        // Handle deps help overlay
        if self.inner.show_deps_help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?' | 'q')) {
                self.inner.show_deps_help = false;
            }
            return EventResult::Consumed;
        }

        // Normal key handling
        match key.code {
            KeyCode::Char('/') => {
                self.inner.start_search();
                EventResult::Consumed
            }
            KeyCode::Char('?') => {
                self.inner.toggle_deps_help();
                EventResult::Consumed
            }
            KeyCode::Char('t') => {
                self.inner.toggle_transitive();
                EventResult::Consumed
            }
            KeyCode::Char('h') => {
                if ctx.mode == ViewMode::Diff {
                    self.inner.toggle_highlight();
                }
                EventResult::Consumed
            }
            KeyCode::Char('y') => {
                self.inner.toggle_cycles();
                EventResult::Consumed
            }
            KeyCode::Char('s') => {
                self.inner.toggle_sort();
                EventResult::Consumed
            }
            KeyCode::Char('e') => {
                self.inner.expand_all();
                EventResult::Consumed
            }
            KeyCode::Char('E') => {
                self.inner.collapse_all();
                EventResult::Consumed
            }
            KeyCode::Char('b') => {
                self.inner.toggle_breadcrumbs();
                EventResult::Consumed
            }
            KeyCode::Char('+' | '=') => {
                self.inner.increase_depth();
                EventResult::Consumed
            }
            KeyCode::Char('-' | '_') => {
                self.inner.decrease_depth();
                EventResult::Consumed
            }
            KeyCode::Char('>' | '.') => {
                self.inner.increase_roots();
                EventResult::Consumed
            }
            KeyCode::Char('<' | ',') => {
                self.inner.decrease_roots();
                EventResult::Consumed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.select_prev();
                self.inner.update_breadcrumbs();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.select_next();
                self.inner.update_breadcrumbs();
                EventResult::Consumed
            }
            KeyCode::Enter => {
                if let Some(node_id) = self.inner.get_selected_node_id().map(str::to_string) {
                    self.inner.toggle_node(&node_id);
                }
                EventResult::Consumed
            }
            // Cross-tab navigation: return Ignored so bridge handles it
            KeyCode::Char('c') => EventResult::Ignored,
            KeyCode::Left => {
                if let Some(node_id) = self.inner.get_selected_node_id().map(str::to_string) {
                    self.inner.collapse(&node_id);
                }
                EventResult::Consumed
            }
            KeyCode::Right => {
                if let Some(node_id) = self.inner.get_selected_node_id().map(str::to_string) {
                    self.inner.expand(&node_id);
                }
                EventResult::Consumed
            }
            KeyCode::Home => {
                self.inner.selected = 0;
                self.inner.adjust_scroll_to_selection();
                self.inner.update_breadcrumbs();
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                if self.inner.total > 0 {
                    self.inner.selected = self.inner.total - 1;
                    self.inner.adjust_scroll_to_selection();
                    self.inner.update_breadcrumbs();
                }
                EventResult::Consumed
            }
            KeyCode::PageUp => {
                let jump = self.inner.viewport_height.saturating_sub(2);
                self.inner.selected = self.inner.selected.saturating_sub(jump);
                self.inner.adjust_scroll_to_selection();
                self.inner.update_breadcrumbs();
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                let jump = self.inner.viewport_height.saturating_sub(2);
                let new_sel = self.inner.selected + jump;
                if self.inner.total > 0 {
                    self.inner.selected = new_sel.min(self.inner.total - 1);
                    self.inner.adjust_scroll_to_selection();
                    self.inner.update_breadcrumbs();
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
        "Dependencies"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("t", "Transitive"),
            Shortcut::new("+/-", "Depth"),
            Shortcut::new(">/<", "Roots"),
            Shortcut::new("e/E", "Expand/Collapse all"),
            Shortcut::new("/", "Search"),
            Shortcut::new("s", "Sort"),
            Shortcut::new("?", "Help"),
        ]
    }
}

impl DependenciesView {
    fn handle_search_key(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Esc => {
                self.inner.stop_search();
                EventResult::Consumed
            }
            KeyCode::Enter => {
                self.inner.stop_search();
                EventResult::Consumed
            }
            KeyCode::Backspace => {
                self.inner.search_pop();
                // Bridge will update search matches
                EventResult::Consumed
            }
            KeyCode::Char('f')
                if key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                self.inner.toggle_filter_mode();
                EventResult::Consumed
            }
            KeyCode::Char('f') => {
                self.inner.toggle_filter_mode();
                EventResult::Consumed
            }
            KeyCode::Char('n') => {
                self.inner.next_match();
                EventResult::Consumed
            }
            KeyCode::Char('N') => {
                self.inner.prev_match();
                EventResult::Consumed
            }
            KeyCode::Char(c) => {
                self.inner.search_push(c);
                // Bridge will update search matches
                EventResult::Consumed
            }
            _ => EventResult::Consumed,
        }
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
    fn test_transitive_toggle() {
        let mut view = DependenciesView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().show_transitive;
        view.handle_key(make_key(KeyCode::Char('t')), &mut ctx);
        assert_ne!(view.inner().show_transitive, initial);
    }

    #[test]
    fn test_depth_controls() {
        let mut view = DependenciesView::new();
        let mut ctx = make_ctx();

        let initial_depth = view.inner().max_depth;
        view.handle_key(make_key(KeyCode::Char('+')), &mut ctx);
        assert!(view.inner().max_depth > initial_depth);

        view.handle_key(make_key(KeyCode::Char('-')), &mut ctx);
        assert_eq!(view.inner().max_depth, initial_depth);
    }

    #[test]
    fn test_search_mode() {
        let mut view = DependenciesView::new();
        let mut ctx = make_ctx();

        assert!(!view.inner().search_active);
        view.handle_key(make_key(KeyCode::Char('/')), &mut ctx);
        assert!(view.inner().search_active);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().search_active);
    }

    #[test]
    fn test_cross_tab_nav_ignored() {
        let mut view = DependenciesView::new();
        let mut ctx = make_ctx();

        // 'c' is cross-tab navigation, should be Ignored for bridge
        let result = view.handle_key(make_key(KeyCode::Char('c')), &mut ctx);
        assert_eq!(result, EventResult::Ignored);
    }
}
