//! Components tab `ViewState` implementation.
//!
//! Handles filter/sort toggles, multi-select, and security filter toggles.
//! Data-dependent operations (clipboard, browser, flagging) remain in the
//! sync bridge since they need access to `App` data and security cache.

use crate::tui::app_states::components::ComponentsState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Components tab view implementing the `ViewState` trait.
pub struct ComponentsView {
    inner: ComponentsState,
}

impl ComponentsView {
    pub(crate) fn new() -> Self {
        Self {
            inner: ComponentsState::new(0),
        }
    }

    // Accessors for sync bridge
    pub(crate) const fn selected(&self) -> usize {
        self.inner.selected
    }
    pub(crate) const fn filter(&self) -> crate::tui::app_states::ComponentFilter {
        self.inner.filter
    }
    pub(crate) const fn sort_by(&self) -> crate::tui::app_states::ComponentSort {
        self.inner.sort_by
    }
    pub(crate) const fn multi_select_mode(&self) -> bool {
        self.inner.multi_select_mode
    }
    pub(crate) const fn focus_detail(&self) -> bool {
        self.inner.focus_detail
    }
    pub(crate) fn multi_selected(&self) -> &std::collections::HashSet<usize> {
        &self.inner.multi_selected
    }
    pub(crate) const fn scroll_offset(&self) -> usize {
        self.inner.scroll_offset
    }
    pub(crate) fn security_filter(
        &self,
    ) -> &crate::tui::viewmodel::security_filter::SecurityFilterState {
        &self.inner.security_filter
    }

    pub(crate) fn sync_from(&mut self, state: &ComponentsState) {
        self.inner.selected = state.selected;
        self.inner.total = state.total;
        self.inner.filter = state.filter;
        self.inner.sort_by = state.sort_by;
        self.inner.multi_select_mode = state.multi_select_mode;
        self.inner.multi_selected.clone_from(&state.multi_selected);
        self.inner.focus_detail = state.focus_detail;
        self.inner.scroll_offset = state.scroll_offset;
        self.inner.security_filter = state.security_filter.clone();
    }

    pub(crate) fn sync_to(&self, state: &mut ComponentsState) {
        state.selected = self.inner.selected;
        state.filter = self.inner.filter;
        state.sort_by = self.inner.sort_by;
        state.multi_select_mode = self.inner.multi_select_mode;
        state.multi_selected.clone_from(&self.inner.multi_selected);
        state.focus_detail = self.inner.focus_detail;
        state.scroll_offset = self.inner.scroll_offset;
        state.security_filter = self.inner.security_filter.clone();
    }
}

impl Default for ComponentsView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for ComponentsView {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Char('f') => {
                if ctx.mode == ViewMode::View {
                    self.inner.toggle_view_filter();
                } else {
                    self.inner.toggle_filter();
                }
                EventResult::Consumed
            }
            KeyCode::Char('s') => {
                self.inner.toggle_sort();
                EventResult::Consumed
            }
            KeyCode::Char('v') => {
                self.inner.toggle_multi_select_mode();
                EventResult::Consumed
            }
            KeyCode::Char('p') | KeyCode::Tab => {
                self.inner.toggle_focus();
                EventResult::Consumed
            }
            KeyCode::Char(' ') if self.inner.multi_select_mode => {
                self.inner.toggle_current_selection();
                EventResult::Consumed
            }
            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.select_all();
                EventResult::Consumed
            }
            KeyCode::Char('A') => {
                self.inner.select_all();
                EventResult::Consumed
            }
            KeyCode::Esc if self.inner.multi_select_mode => {
                self.inner.toggle_multi_select_mode();
                EventResult::Consumed
            }
            // Security quick filter toggles (1-8)
            KeyCode::Char(c @ '1'..='8') => {
                let idx = (c as u8 - b'1') as usize;
                self.inner.security_filter.toggle_by_index(idx);
                EventResult::status(self.inner.security_filter.summary())
            }
            KeyCode::Char('0') => {
                self.inner.security_filter.clear_all();
                EventResult::status("All filters cleared")
            }
            // Data-dependent actions return Ignored so the bridge handles them
            KeyCode::Char('y' | 'F' | 'o' | 'n') => EventResult::Ignored,
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Components"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("f", "Filter"),
            Shortcut::new("s", "Sort"),
            Shortcut::new("v", "Multi-select"),
            Shortcut::new("1-8", "Quick filters"),
            Shortcut::new("F", "Flag"),
            Shortcut::new("y", "Copy"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_ctx(mode: ViewMode) -> ViewContext<'static> {
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        ViewContext {
            mode,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_filter_toggle() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        let initial = view.filter();
        view.handle_key(make_key(KeyCode::Char('f')), &mut ctx);
        assert_ne!(view.filter(), initial);
    }

    #[test]
    fn test_multi_select() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        assert!(!view.multi_select_mode());
        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert!(view.multi_select_mode());

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.multi_select_mode());
    }

    #[test]
    fn test_data_dependent_keys_ignored() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        // These should return Ignored so the bridge handles them
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('y')), &mut ctx),
            EventResult::Ignored
        );
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('F')), &mut ctx),
            EventResult::Ignored
        );
    }
}
