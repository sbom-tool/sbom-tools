//! Vulnerabilities tab `ViewState` implementation.
//!
//! Handles filter/sort toggles and grouped mode toggling.
//! Data-dependent operations (grouped selection resolution, vulnerability
//! cache, navigation to components) remain in the sync bridge.

use crate::tui::app_states::vulnerabilities::VulnerabilitiesState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Vulnerabilities tab view implementing the `ViewState` trait.
pub struct VulnerabilitiesView {
    inner: VulnerabilitiesState,
}

impl VulnerabilitiesView {
    pub(crate) fn new() -> Self {
        Self {
            inner: VulnerabilitiesState::new(0),
        }
    }

    /// Access the inner state.
    pub(crate) fn inner(&self) -> &VulnerabilitiesState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) fn inner_mut(&mut self) -> &mut VulnerabilitiesState {
        &mut self.inner
    }
}

impl Default for VulnerabilitiesView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for VulnerabilitiesView {
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
            KeyCode::Char('g') => {
                self.inner.toggle_grouped_mode();
                let mode = if self.inner.group_by_component {
                    "grouped"
                } else {
                    "list"
                };
                EventResult::status(format!("Vulnerabilities: {mode} view"))
            }
            // E, C, Enter are data-dependent — return Ignored for bridge
            KeyCode::Char('E') if self.inner.group_by_component => EventResult::Ignored,
            KeyCode::Char('C') if self.inner.group_by_component => EventResult::Ignored,
            KeyCode::Enter => EventResult::Ignored,
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Vulnerabilities"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("f", "Filter"),
            Shortcut::new("s", "Sort"),
            Shortcut::new("g", "Group by component"),
            Shortcut::new("E/C", "Expand/Collapse all"),
            Shortcut::new("Enter", "Detail/Toggle group"),
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
    fn test_filter_toggle() {
        let mut view = VulnerabilitiesView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().filter;
        view.handle_key(make_key(KeyCode::Char('f')), &mut ctx);
        assert_ne!(view.inner().filter, initial);
    }

    #[test]
    fn test_grouped_mode() {
        let mut view = VulnerabilitiesView::new();
        let mut ctx = make_ctx();

        assert!(!view.inner().group_by_component);
        let result = view.handle_key(make_key(KeyCode::Char('g')), &mut ctx);
        assert!(view.inner().group_by_component);
        assert!(matches!(result, EventResult::StatusMessage(_)));
    }
}
