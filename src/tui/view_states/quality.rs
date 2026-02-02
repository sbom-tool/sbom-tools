//! Quality tab ViewState implementation.
//!
//! Proof of concept for the ViewState trait: the Quality tab delegates
//! its key handling to this self-contained view state machine.

use crate::tui::app_states::quality::{QualityState, QualityViewMode};
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Quality tab view implementing the `ViewState` trait.
///
/// Wraps `QualityState` and provides event-driven key handling
/// that returns `EventResult` instead of mutating `App` directly.
pub struct QualityView {
    inner: QualityState,
}

impl QualityView {
    pub fn new() -> Self {
        Self {
            inner: QualityState::new(),
        }
    }

    pub fn with_recommendations(total: usize) -> Self {
        Self {
            inner: QualityState::with_recommendations(total),
        }
    }

    pub fn view_mode(&self) -> QualityViewMode {
        self.inner.view_mode
    }

    pub fn selected_recommendation(&self) -> usize {
        self.inner.selected_recommendation
    }

    pub fn set_selected_recommendation(&mut self, idx: usize) {
        self.inner.selected_recommendation = idx;
    }

    pub fn total_recommendations(&self) -> usize {
        self.inner.total_recommendations
    }

    pub fn set_total_recommendations(&mut self, total: usize) {
        self.inner.total_recommendations = total;
    }

    pub fn scroll_offset(&self) -> usize {
        self.inner.scroll_offset
    }
}

impl Default for QualityView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for QualityView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Char('v') => {
                self.inner.toggle_view();
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
            KeyCode::PageUp => {
                for _ in 0..5 {
                    self.inner.scroll_up();
                }
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                for _ in 0..5 {
                    self.inner.scroll_down();
                }
                EventResult::Consumed
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.inner.selected_recommendation = 0;
                self.inner.scroll_offset = 0;
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                if self.inner.total_recommendations > 0 {
                    self.inner.selected_recommendation =
                        self.inner.total_recommendations.saturating_sub(1);
                }
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &str {
        "Quality"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("v", "Toggle view"),
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("g/G", "First/Last"),
            Shortcut::new("PgUp/PgDn", "Scroll"),
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
            mode: ViewMode::View,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_toggle_view() {
        let mut view = QualityView::new();
        let mut ctx = make_ctx();

        assert_eq!(view.view_mode(), QualityViewMode::Summary);

        let result = view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.view_mode(), QualityViewMode::Breakdown);

        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(view.view_mode(), QualityViewMode::Metrics);

        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(view.view_mode(), QualityViewMode::Recommendations);

        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(view.view_mode(), QualityViewMode::Summary);
    }

    #[test]
    fn test_navigation() {
        let mut view = QualityView::with_recommendations(5);
        let mut ctx = make_ctx();

        assert_eq!(view.selected_recommendation(), 0);

        view.handle_key(make_key(KeyCode::Char('j')), &mut ctx);
        assert_eq!(view.selected_recommendation(), 1);

        view.handle_key(make_key(KeyCode::Down), &mut ctx);
        assert_eq!(view.selected_recommendation(), 2);

        view.handle_key(make_key(KeyCode::Char('k')), &mut ctx);
        assert_eq!(view.selected_recommendation(), 1);

        view.handle_key(make_key(KeyCode::Up), &mut ctx);
        assert_eq!(view.selected_recommendation(), 0);

        // Can't go below 0
        view.handle_key(make_key(KeyCode::Up), &mut ctx);
        assert_eq!(view.selected_recommendation(), 0);
    }

    #[test]
    fn test_home_end() {
        let mut view = QualityView::with_recommendations(10);
        let mut ctx = make_ctx();

        // Go to end
        let result = view.handle_key(make_key(KeyCode::Char('G')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected_recommendation(), 9);

        // Go to start
        let result = view.handle_key(make_key(KeyCode::Char('g')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected_recommendation(), 0);
        assert_eq!(view.scroll_offset(), 0);
    }

    #[test]
    fn test_end_with_zero_recommendations() {
        let mut view = QualityView::new(); // 0 recommendations
        let mut ctx = make_ctx();

        let result = view.handle_key(make_key(KeyCode::Char('G')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected_recommendation(), 0); // stays at 0
    }

    #[test]
    fn test_unhandled_key_returns_ignored() {
        let mut view = QualityView::new();
        let mut ctx = make_ctx();

        let result = view.handle_key(make_key(KeyCode::Char('x')), &mut ctx);
        assert_eq!(result, EventResult::Ignored);
    }

    #[test]
    fn test_title_and_shortcuts() {
        let view = QualityView::new();
        assert_eq!(view.title(), "Quality");
        assert!(!view.shortcuts().is_empty());
    }
}
