//! Licenses tab `ViewState` implementation.

use crate::tui::app_states::licenses::LicensesState;
use crate::tui::state::ListNavigation;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Licenses tab view implementing the `ViewState` trait.
///
/// Wraps `LicensesState` for group, sort, risk filter, and panel navigation.
pub struct LicensesView {
    inner: LicensesState,
}

impl LicensesView {
    pub(crate) const fn new() -> Self {
        Self {
            inner: LicensesState::new(),
        }
    }

    /// Access the inner state.
    pub(crate) const fn inner(&self) -> &LicensesState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) fn inner_mut(&mut self) -> &mut LicensesState {
        &mut self.inner
    }
}

impl Default for LicensesView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for LicensesView {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Char('g') => {
                self.inner.toggle_group();
                EventResult::Consumed
            }
            KeyCode::Char('s') => {
                self.inner.toggle_sort();
                EventResult::Consumed
            }
            KeyCode::Char('r') => {
                self.inner.toggle_risk_filter();
                EventResult::Consumed
            }
            KeyCode::Char('c') => {
                self.inner.toggle_compatibility();
                EventResult::Consumed
            }
            KeyCode::Tab | KeyCode::Char('p') => {
                if ctx.mode == ViewMode::Diff {
                    self.inner.toggle_focus();
                }
                EventResult::Consumed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.select_prev();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.select_next();
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Licenses"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("g", "Group by"),
            Shortcut::new("s", "Sort"),
            Shortcut::new("r", "Risk filter"),
            Shortcut::new("c", "Compatibility"),
            Shortcut::new("p", "Panel focus"),
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
    fn test_group_toggle() {
        let mut view = LicensesView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        let initial = view.inner().group_by;
        view.handle_key(make_key(KeyCode::Char('g')), &mut ctx);
        assert_ne!(view.inner().group_by, initial);
    }

    #[test]
    fn test_panel_focus_diff_only() {
        let mut view = LicensesView::new();

        // In diff mode, panel toggle works
        let mut ctx = make_ctx(ViewMode::Diff);
        assert!(view.inner().focus_left);
        view.handle_key(make_key(KeyCode::Char('p')), &mut ctx);
        assert!(!view.inner().focus_left);

        // Reset
        view.handle_key(make_key(KeyCode::Char('p')), &mut ctx);
        assert!(view.inner().focus_left);
    }

    #[test]
    fn test_navigation() {
        let mut view = LicensesView::new();
        view.inner_mut().set_total(5);
        let mut ctx = make_ctx(ViewMode::Diff);

        view.handle_key(make_key(KeyCode::Char('j')), &mut ctx);
        assert_eq!(view.inner().selected, 1);

        view.handle_key(make_key(KeyCode::Char('k')), &mut ctx);
        assert_eq!(view.inner().selected, 0);
    }
}
