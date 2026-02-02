//! Quality tab event handlers.
//!
//! # State synchronization
//!
//! The quality tab state lives in two places during the ViewState migration:
//! - `app.quality_view.inner` — authoritative for event handling
//! - `app.tabs.quality` — read by the rendering code
//!
//! Before each event: `tabs.quality.total_recommendations` is synced into
//! `quality_view.inner` (rendering may update the total).
//! After each event: `quality_view.inner` fields are synced back to
//! `tabs.quality` so the renderer sees the latest state.

use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crate::tui::App;
use crossterm::event::KeyEvent;

pub(super) fn handle_quality_keys(app: &mut App, key: KeyEvent) {
    let quality_view = match app.quality_view.as_mut() {
        Some(v) => v,
        None => return,
    };

    // One-way sync: tabs.quality → quality_view (rendering may have updated total)
    quality_view.set_total_recommendations(app.tabs.quality.total_recommendations);

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        // Dimensions are not used by the current QualityView implementation;
        // pass zeros until terminal size is threaded through the event path.
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = quality_view.handle_key(key, &mut ctx);

    // One-way sync: quality_view → tabs.quality (for rendering)
    app.tabs.quality.view_mode = quality_view.view_mode();
    app.tabs.quality.selected_recommendation = quality_view.selected_recommendation();
    app.tabs.quality.scroll_offset = quality_view.scroll_offset();

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
}
