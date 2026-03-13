//! Compliance tab event handlers.

use crate::tui::App;
use crate::tui::render_context::RenderContext;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_diff_compliance_keys(app: &mut App, key: KeyEvent) {
    // Compute max violations before borrowing view mutably
    let max_violations = {
        let ctx = RenderContext::from_app(app);
        crate::tui::views::diff_compliance_violation_count(&ctx)
    };

    let Some(view) = app.compliance_view.as_mut() else {
        return;
    };

    view.set_max_violations(max_violations);

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = view.handle_key(key, &mut ctx);

    // Handle export request
    if view.take_export_request() {
        app.export_compliance(crate::tui::export::ExportFormat::Json);
    }

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
}
