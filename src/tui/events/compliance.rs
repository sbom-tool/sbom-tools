//! Compliance tab event handlers.

use crate::tui::App;
use crate::tui::render_context::RenderContext;
use crate::tui::traits::{EventResult, TabTarget, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_diff_compliance_keys(app: &mut App, key: KeyEvent) -> bool {
    // Compute max violations before borrowing view mutably
    let max_violations = {
        let ctx = RenderContext::from_app(app);
        crate::tui::views::diff_compliance_violation_count(&ctx)
    };

    // Process the key in a scoped borrow, extracting all side-effect flags
    let (result, wants_export, wants_go_to_component, wants_toggle_group) = {
        let view = &mut app.compliance_view;

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
        let wants_export = view.take_export_request();
        let wants_go_to_component = view.take_go_to_component_request();
        let wants_toggle_group = view.take_toggle_group_entry_request();

        (
            result,
            wants_export,
            wants_go_to_component,
            wants_toggle_group,
        )
    };
    // `view` borrow is now dropped — safe to use `app` freely
    let consumed = !matches!(result, EventResult::Ignored);

    if wants_export {
        app.export_compliance(crate::tui::export::ExportFormat::Json);
    }

    if wants_toggle_group {
        toggle_selected_group(app);
        return true;
    }

    if wants_go_to_component {
        if let Some(component_name) = get_selected_violation_component(app) {
            app.handle_event_result(EventResult::NavigateTo(TabTarget::ComponentByName(
                component_name,
            )));
        } else {
            app.set_status_message("No component associated with this violation");
        }
        return true;
    }

    app.handle_event_result(result);
    consumed
}

/// Toggle the expand/collapse state of the group at the currently selected position.
fn toggle_selected_group(app: &mut App) {
    use crate::tui::views::resolve_selected_group_element;

    let element = {
        let ctx = RenderContext::from_app(app);
        resolve_selected_group_element(&ctx)
    };

    if let Some(element) = element {
        let view = &mut app.compliance_view;
        let state = &mut view.inner_mut().expanded_groups;
        if state.contains(&element) {
            state.remove(&element);
        } else {
            state.insert(element);
        }
    }
}

/// Get the component name from the currently selected compliance violation.
fn get_selected_violation_component(app: &App) -> Option<String> {
    let ctx = RenderContext::from_app(app);
    let idx = ctx.compliance.selected_standard;
    let old = ctx.old_compliance_results?.get(idx)?;
    let new = ctx.new_compliance_results?.get(idx)?;
    let selected = ctx.compliance.selected_violation;

    use crate::tui::app_states::DiffComplianceViewMode;
    let violation = match ctx.compliance.view_mode {
        DiffComplianceViewMode::Overview => None,
        DiffComplianceViewMode::NewViolations => {
            let old_messages: std::collections::HashSet<&str> =
                old.violations.iter().map(|v| v.message.as_str()).collect();
            new.violations
                .iter()
                .filter(|v| !old_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::ResolvedViolations => {
            let new_messages: std::collections::HashSet<&str> =
                new.violations.iter().map(|v| v.message.as_str()).collect();
            old.violations
                .iter()
                .filter(|v| !new_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::OldViolations => old.violations.get(selected),
        DiffComplianceViewMode::NewSbomViolations => new.violations.get(selected),
    };

    violation.and_then(|v| v.element.clone())
}
