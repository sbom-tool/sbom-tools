//! Graph changes tab `ViewState` implementation.

use crate::tui::app_states::graph_changes::GraphChangesState;
use crate::tui::state::ListNavigation;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Graph changes tab view implementing the `ViewState` trait.
///
/// Wraps `GraphChangesState` and provides event-driven key handling
/// for basic list navigation over graph diff entries.
pub struct GraphChangesView {
    inner: GraphChangesState,
}

impl GraphChangesView {
    pub(crate) const fn new() -> Self {
        Self {
            inner: GraphChangesState::new(),
        }
    }

    /// Access the inner state.
    pub(crate) const fn inner(&self) -> &GraphChangesState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) fn inner_mut(&mut self) -> &mut GraphChangesState {
        &mut self.inner
    }
}

impl Default for GraphChangesView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for GraphChangesView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.select_prev();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.select_next();
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
            KeyCode::Home => {
                self.inner.go_first();
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.inner.go_last();
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Graph Changes"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("g/G", "First/Last"),
            Shortcut::new("PgUp/PgDn", "Page"),
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
    fn test_navigation() {
        let mut view = GraphChangesView::new();
        view.inner_mut().set_total(5);
        let mut ctx = make_ctx();

        assert_eq!(view.inner().selected, 0);

        view.handle_key(make_key(KeyCode::Down), &mut ctx);
        assert_eq!(view.inner().selected, 1);

        view.handle_key(make_key(KeyCode::Char('j')), &mut ctx);
        assert_eq!(view.inner().selected, 2);

        view.handle_key(make_key(KeyCode::Up), &mut ctx);
        assert_eq!(view.inner().selected, 1);

        view.handle_key(make_key(KeyCode::Char('k')), &mut ctx);
        assert_eq!(view.inner().selected, 0);
    }

    #[test]
    fn test_home_end() {
        let mut view = GraphChangesView::new();
        view.inner_mut().set_total(10);
        let mut ctx = make_ctx();

        view.handle_key(make_key(KeyCode::Char('G')), &mut ctx);
        assert_eq!(view.inner().selected, 9);

        view.handle_key(make_key(KeyCode::Home), &mut ctx);
        assert_eq!(view.inner().selected, 0);
    }

    #[test]
    fn test_unhandled_key() {
        let mut view = GraphChangesView::new();
        let mut ctx = make_ctx();

        let result = view.handle_key(make_key(KeyCode::Char('x')), &mut ctx);
        assert_eq!(result, EventResult::Ignored);
    }
}
