//! Summary tab `ViewState` implementation.
//!
//! The Summary tab is display-only with no tab-specific key bindings.
//! All events are passed through to the global handler.

use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyEvent, MouseEvent};

/// Summary tab view implementing the `ViewState` trait.
///
/// The summary tab has no tab-specific interactions — it shows an
/// overview of the SBOM or diff. All key events are ignored so the
/// global handler (tab switching, search, overlays) processes them.
pub struct SummaryView;

impl SummaryView {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl Default for SummaryView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SummaryView {
    fn handle_key(&mut self, _key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Summary"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::traits::ViewMode;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn test_all_keys_ignored() {
        let mut view = SummaryView::new();
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        let mut ctx = ViewContext {
            mode: ViewMode::Diff,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        };

        let result = view.handle_key(
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
            &mut ctx,
        );
        assert_eq!(result, EventResult::Ignored);
    }
}
