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

    // Accessors for sync bridge
    pub(crate) const fn group_by(&self) -> crate::tui::app_states::LicenseGroupBy {
        self.inner.group_by
    }
    pub(crate) const fn sort_by(&self) -> crate::tui::app_states::LicenseSort {
        self.inner.sort_by
    }
    pub(crate) const fn selected(&self) -> usize {
        self.inner.selected
    }
    pub(crate) const fn focus_left(&self) -> bool {
        self.inner.focus_left
    }
    pub(crate) const fn show_compatibility(&self) -> bool {
        self.inner.show_compatibility
    }
    pub(crate) const fn risk_filter(&self) -> Option<crate::tui::app_states::LicenseRiskFilter> {
        self.inner.risk_filter
    }
    pub(crate) const fn selected_new(&self) -> usize {
        self.inner.selected_new
    }
    pub(crate) const fn selected_removed(&self) -> usize {
        self.inner.selected_removed
    }

    pub(crate) fn set_total(&mut self, total: usize) {
        self.inner.set_total(total);
    }

    pub(crate) fn sync_from(&mut self, state: &LicensesState) {
        self.inner.total = state.total;
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

        let initial = view.group_by();
        view.handle_key(make_key(KeyCode::Char('g')), &mut ctx);
        assert_ne!(view.group_by(), initial);
    }

    #[test]
    fn test_panel_focus_diff_only() {
        let mut view = LicensesView::new();

        // In diff mode, panel toggle works
        let mut ctx = make_ctx(ViewMode::Diff);
        assert!(view.focus_left());
        view.handle_key(make_key(KeyCode::Char('p')), &mut ctx);
        assert!(!view.focus_left());

        // Reset
        view.handle_key(make_key(KeyCode::Char('p')), &mut ctx);
        assert!(view.focus_left());
    }

    #[test]
    fn test_navigation() {
        let mut view = LicensesView::new();
        view.set_total(5);
        let mut ctx = make_ctx(ViewMode::View);

        view.handle_key(make_key(KeyCode::Char('j')), &mut ctx);
        assert_eq!(view.selected(), 1);

        view.handle_key(make_key(KeyCode::Char('k')), &mut ctx);
        assert_eq!(view.selected(), 0);
    }
}
