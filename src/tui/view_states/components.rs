//! Components tab `ViewState` implementation.
//!
//! Handles filter/sort toggles, multi-select, and security filter toggles.
//! Data-dependent operations (clipboard, browser, flagging) remain in the
//! sync bridge since they need access to `App` data and security cache.

use crate::tui::app_states::components::ComponentsState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
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

    /// Access the inner state.
    pub(crate) fn inner(&self) -> &ComponentsState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) fn inner_mut(&mut self) -> &mut ComponentsState {
        &mut self.inner
    }
}

impl Default for ComponentsView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for ComponentsView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Char('f') => {
                self.inner.toggle_filter();
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
    use crate::tui::traits::ViewMode;
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

        let initial = view.inner().filter;
        view.handle_key(make_key(KeyCode::Char('f')), &mut ctx);
        assert_ne!(view.inner().filter, initial);
    }

    #[test]
    fn test_multi_select() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        assert!(!view.inner().multi_select_mode);
        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert!(view.inner().multi_select_mode);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().multi_select_mode);
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
