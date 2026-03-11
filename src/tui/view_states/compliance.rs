//! Compliance tab `ViewState` implementation.

use crate::tui::app_states::compliance::DiffComplianceState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Compliance tab view implementing the `ViewState` trait.
///
/// Wraps `DiffComplianceState` for multi-standard navigation and
/// violation selection. Export and violation count resolution
/// remain in the sync bridge since they need `App` data access.
pub struct ComplianceView {
    inner: DiffComplianceState,
    /// Maximum number of violations in the current view (set by bridge).
    max_violations: usize,
    /// Whether a compliance export was requested (consumed by bridge).
    export_requested: bool,
}

impl ComplianceView {
    pub(crate) fn new() -> Self {
        Self {
            inner: DiffComplianceState::new(),
            max_violations: 0,
            export_requested: false,
        }
    }

    // Accessors for sync bridge
    pub(crate) const fn selected_standard(&self) -> usize {
        self.inner.selected_standard
    }
    pub(crate) const fn selected_violation(&self) -> usize {
        self.inner.selected_violation
    }
    pub(crate) const fn scroll_offset(&self) -> usize {
        self.inner.scroll_offset
    }
    pub(crate) const fn view_mode(&self) -> crate::tui::app_states::DiffComplianceViewMode {
        self.inner.view_mode
    }
    pub(crate) const fn show_detail(&self) -> bool {
        self.inner.show_detail
    }

    pub(crate) fn set_max_violations(&mut self, max: usize) {
        self.max_violations = max;
    }

    pub(crate) fn sync_from(&mut self, state: &DiffComplianceState) {
        self.inner.selected_standard = state.selected_standard;
        self.inner.selected_violation = state.selected_violation;
        self.inner.scroll_offset = state.scroll_offset;
        self.inner.view_mode = state.view_mode;
        self.inner.show_detail = state.show_detail;
    }

    /// Whether a compliance export was requested (set during handle_key, consumed by bridge).
    pub(crate) fn take_export_request(&mut self) -> bool {
        let req = self.export_requested;
        self.export_requested = false;
        req
    }
}

impl Default for ComplianceView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for ComplianceView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        // Detail overlay mode
        if self.inner.show_detail {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.inner.show_detail = false;
                    return EventResult::Consumed;
                }
                _ => return EventResult::Consumed,
            }
        }

        match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                self.inner.prev_standard();
                EventResult::Consumed
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.inner.next_standard();
                EventResult::Consumed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.select_prev();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.select_next(self.max_violations);
                EventResult::Consumed
            }
            KeyCode::Enter => {
                if self.max_violations > 0 {
                    self.inner.show_detail = true;
                }
                EventResult::Consumed
            }
            KeyCode::Tab => {
                self.inner.next_view_mode();
                EventResult::Consumed
            }
            KeyCode::Char('E') => {
                self.export_requested = true;
                EventResult::Consumed
            }
            KeyCode::Home => {
                self.inner.selected_violation = 0;
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                if self.max_violations > 0 {
                    self.inner.selected_violation = self.max_violations - 1;
                }
                EventResult::Consumed
            }
            KeyCode::PageUp => {
                for _ in 0..crate::tui::constants::PAGE_SIZE {
                    self.inner.select_prev();
                }
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                for _ in 0..crate::tui::constants::PAGE_SIZE {
                    self.inner.select_next(self.max_violations);
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
        "Compliance"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("h/l", "Switch standard"),
            Shortcut::new("Tab", "View mode"),
            Shortcut::new("Enter", "Detail"),
            Shortcut::new("E", "Export"),
            Shortcut::new("g/G", "First/Last"),
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
    fn test_standard_navigation() {
        let mut view = ComplianceView::new();
        let mut ctx = make_ctx();
        let initial = view.selected_standard();

        view.handle_key(make_key(KeyCode::Right), &mut ctx);
        assert_ne!(view.selected_standard(), initial);
    }

    #[test]
    fn test_violation_navigation() {
        let mut view = ComplianceView::new();
        view.set_max_violations(5);
        let mut ctx = make_ctx();

        view.handle_key(make_key(KeyCode::Down), &mut ctx);
        assert_eq!(view.selected_violation(), 1);

        view.handle_key(make_key(KeyCode::Up), &mut ctx);
        assert_eq!(view.selected_violation(), 0);
    }

    #[test]
    fn test_detail_toggle() {
        let mut view = ComplianceView::new();
        view.set_max_violations(3);
        let mut ctx = make_ctx();

        assert!(!view.show_detail());
        view.handle_key(make_key(KeyCode::Enter), &mut ctx);
        assert!(view.show_detail());

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.show_detail());
    }

    #[test]
    fn test_export_request() {
        let mut view = ComplianceView::new();
        let mut ctx = make_ctx();

        view.handle_key(make_key(KeyCode::Char('E')), &mut ctx);
        assert!(view.take_export_request());
        assert!(!view.take_export_request()); // consumed
    }
}
