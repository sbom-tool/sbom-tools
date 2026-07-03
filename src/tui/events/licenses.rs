//! Licenses tab event handlers.

use crate::tui::App;
use crate::tui::traits::{EventResult, TabTarget, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_licenses_keys(app: &mut App, key: KeyEvent) -> bool {
    let view = &mut app.licenses_view;

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = view.handle_key(key, &mut ctx);

    match result {
        EventResult::Ignored => false,
        EventResult::NavigateTo(TabTarget::Components) => {
            // Enrich the navigation with the selected license name
            let license_name = get_selected_license_name(app);
            let target = if let Some(name) = license_name {
                TabTarget::ComponentByLicense(name)
            } else {
                TabTarget::Components
            };
            app.handle_event_result(EventResult::NavigateTo(target));
            true
        }
        _ => {
            app.handle_event_result(result);
            true
        }
    }
}

/// Get the license name at the currently selected index.
fn get_selected_license_name(app: &App) -> Option<String> {
    let selected = app.licenses_state().selected;
    let result = app.data.diff_result.as_ref()?;
    let licenses: Vec<_> = result
        .licenses
        .new_licenses
        .iter()
        .chain(result.licenses.removed_licenses.iter())
        .collect();
    licenses.get(selected).map(|lic| lic.license.clone())
}
