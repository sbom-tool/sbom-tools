//! Side-by-side tab `ViewState` implementation.
//!
//! Handles panel scrolling, alignment mode, sync mode, filter toggles,
//! change/search navigation, and detail modal. Search match computation
//! remains in the sync bridge since it needs `app.data.diff_result`.

use crate::tui::app_states::sidebyside::SideBySideState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Side-by-side tab view implementing the `ViewState` trait.
pub struct SideBySideView {
    inner: SideBySideState,
}

impl SideBySideView {
    pub(crate) fn new() -> Self {
        Self {
            inner: SideBySideState::new(),
        }
    }

    /// Access the inner state for sync operations.
    pub(crate) fn inner(&self) -> &SideBySideState {
        &self.inner
    }

    /// Mutable access for sync operations.
    pub(crate) fn inner_mut(&mut self) -> &mut SideBySideState {
        &mut self.inner
    }

    pub(crate) fn sync_from(&mut self, state: &SideBySideState) {
        self.inner.left_scroll = state.left_scroll;
        self.inner.right_scroll = state.right_scroll;
        self.inner.left_total = state.left_total;
        self.inner.right_total = state.right_total;
        self.inner.focus_right = state.focus_right;
        self.inner.alignment_mode = state.alignment_mode;
        self.inner.sync_mode = state.sync_mode;
        self.inner.filter = state.filter.clone();
        self.inner.selected_row = state.selected_row;
        self.inner.total_rows = state.total_rows;
        self.inner.change_indices.clone_from(&state.change_indices);
        self.inner.current_change_idx = state.current_change_idx;
        self.inner.search_query.clone_from(&state.search_query);
        self.inner.search_matches.clone_from(&state.search_matches);
        self.inner.current_match_idx = state.current_match_idx;
        self.inner.search_active = state.search_active;
        self.inner.show_detail_modal = state.show_detail_modal;
    }

    pub(crate) fn sync_to(&self, state: &mut SideBySideState) {
        state.left_scroll = self.inner.left_scroll;
        state.right_scroll = self.inner.right_scroll;
        state.focus_right = self.inner.focus_right;
        state.alignment_mode = self.inner.alignment_mode;
        state.sync_mode = self.inner.sync_mode;
        state.filter = self.inner.filter.clone();
        state.selected_row = self.inner.selected_row;
        state.change_indices.clone_from(&self.inner.change_indices);
        state.current_change_idx = self.inner.current_change_idx;
        state.search_query.clone_from(&self.inner.search_query);
        state.search_matches.clone_from(&self.inner.search_matches);
        state.current_match_idx = self.inner.current_match_idx;
        state.search_active = self.inner.search_active;
        state.show_detail_modal = self.inner.show_detail_modal;
    }
}

impl Default for SideBySideView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SideBySideView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        // Handle search input mode
        if self.inner.search_active {
            return self.handle_search_key(key);
        }

        // Handle detail modal
        if self.inner.show_detail_modal {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.inner.close_detail_modal();
                    return EventResult::Consumed;
                }
                _ => return EventResult::Consumed,
            }
        }

        match key.code {
            // Toggle focus between panels
            KeyCode::Tab | KeyCode::Char('p') | KeyCode::Left | KeyCode::Right => {
                self.inner.toggle_focus();
                EventResult::Consumed
            }
            // Scroll
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.scroll_up();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.scroll_down();
                EventResult::Consumed
            }
            KeyCode::PageUp => {
                self.inner.page_up();
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                self.inner.page_down();
                EventResult::Consumed
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.inner.go_to_top();
                EventResult::Consumed
            }
            KeyCode::Char('G') => {
                self.inner.go_to_bottom();
                EventResult::Consumed
            }
            // Synchronized scroll
            KeyCode::Char('K') => {
                self.inner.scroll_both_up();
                EventResult::Consumed
            }
            KeyCode::Char('J') => {
                self.inner.scroll_both_down();
                EventResult::Consumed
            }
            // Toggle alignment mode
            KeyCode::Char('a') => {
                self.inner.toggle_alignment();
                EventResult::status(format!(
                    "Alignment mode: {}",
                    self.inner.alignment_mode.name()
                ))
            }
            // Toggle sync mode
            KeyCode::Char('s') => {
                self.inner.toggle_sync();
                EventResult::status(format!("Sync mode: {}", self.inner.sync_mode.name()))
            }
            // Start search
            KeyCode::Char('/') => {
                self.inner.start_search();
                EventResult::Consumed
            }
            // Change navigation
            KeyCode::Char('n' | ']') => {
                self.inner.next_change();
                EventResult::status(format!("Change {}", self.inner.change_position()))
            }
            KeyCode::Char('N' | '[') => {
                self.inner.prev_change();
                EventResult::status(format!("Change {}", self.inner.change_position()))
            }
            // Filter toggles
            KeyCode::Char('1') => {
                self.inner.filter.toggle_added();
                let status = if self.inner.filter.show_added {
                    "Added: shown"
                } else {
                    "Added: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('2') => {
                self.inner.filter.toggle_removed();
                let status = if self.inner.filter.show_removed {
                    "Removed: shown"
                } else {
                    "Removed: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('3') => {
                self.inner.filter.toggle_modified();
                let status = if self.inner.filter.show_modified {
                    "Modified: shown"
                } else {
                    "Modified: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('0') => {
                self.inner.filter.show_all();
                EventResult::status("Showing all changes")
            }
            // Detail modal
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.inner.toggle_detail_modal();
                EventResult::Consumed
            }
            // Yank: data-dependent, return Ignored for bridge
            KeyCode::Char('y') => EventResult::Ignored,
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Side-by-Side"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Scroll"),
            Shortcut::new("J/K", "Sync scroll"),
            Shortcut::new("p/Tab", "Panel focus"),
            Shortcut::new("a", "Alignment"),
            Shortcut::new("s", "Sync mode"),
            Shortcut::new("/", "Search"),
            Shortcut::new("n/N", "Next/Prev change"),
            Shortcut::new("1-3", "Filter toggles"),
            Shortcut::new("Enter", "Detail"),
        ]
    }
}

impl SideBySideView {
    fn handle_search_key(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Esc => {
                self.inner.cancel_search();
                EventResult::Consumed
            }
            KeyCode::Enter => {
                self.inner.confirm_search();
                if !self.inner.search_matches.is_empty() {
                    return EventResult::status(format!("Match {}", self.inner.match_position()));
                }
                EventResult::Consumed
            }
            KeyCode::Backspace => {
                self.inner.search_pop();
                // Bridge will update search matches
                EventResult::Consumed
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.next_match();
                EventResult::Consumed
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.prev_match();
                EventResult::Consumed
            }
            KeyCode::Down => {
                self.inner.next_match();
                EventResult::Consumed
            }
            KeyCode::Up => {
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
    fn test_panel_toggle() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        assert!(!view.inner().focus_right);
        view.handle_key(make_key(KeyCode::Tab), &mut ctx);
        assert!(view.inner().focus_right);
    }

    #[test]
    fn test_alignment_toggle() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        let result = view.handle_key(make_key(KeyCode::Char('a')), &mut ctx);
        assert!(matches!(result, EventResult::StatusMessage(_)));
    }

    #[test]
    fn test_filter_toggles() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        assert!(view.inner().filter.show_added);
        view.handle_key(make_key(KeyCode::Char('1')), &mut ctx);
        assert!(!view.inner().filter.show_added);
    }

    #[test]
    fn test_search_mode() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        view.handle_key(make_key(KeyCode::Char('/')), &mut ctx);
        assert!(view.inner().search_active);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().search_active);
    }

    #[test]
    fn test_detail_modal() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        assert!(!view.inner().show_detail_modal);
        view.handle_key(make_key(KeyCode::Enter), &mut ctx);
        assert!(view.inner().show_detail_modal);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().show_detail_modal);
    }
}
