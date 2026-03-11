//! Compliance tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_diff_compliance_keys(app: &mut App, key: KeyEvent) {
    // Compute max violations before borrowing view mutably
    let max_violations = crate::tui::views::diff_compliance_violation_count(app);

    let Some(view) = app.compliance_view.as_mut() else {
        return;
    };

    // Pre-sync: tabs → view
    view.sync_from(&app.tabs.diff_compliance);
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

    // Post-sync: view → tabs
    app.tabs.diff_compliance.selected_standard = view.selected_standard();
    app.tabs.diff_compliance.selected_violation = view.selected_violation();
    app.tabs.diff_compliance.scroll_offset = view.scroll_offset();
    app.tabs.diff_compliance.view_mode = view.view_mode();
    app.tabs.diff_compliance.show_detail = view.show_detail();

    // Handle export request
    if view.take_export_request() {
        app.export_compliance(crate::tui::export::ExportFormat::Json);
    }

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
}
