//! Components tab event handlers.

use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crate::tui::{App, AppMode};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_components_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.components_view.as_mut() else {
        return;
    };

    // Pre-sync: tabs → view
    view.sync_from(&app.tabs.components);

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
    view.sync_to(&mut app.tabs.components);

    match result {
        EventResult::StatusMessage(msg) => {
            app.status_message = Some(msg);
        }
        EventResult::Ignored => {
            // Handle data-dependent keys that the ViewState can't process
            handle_data_dependent_keys(app, key);
        }
        _ => {}
    }
}

/// Handle keys that need access to App data (clipboard, browser, security cache).
fn handle_data_dependent_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') => {
            if let Some(comp_name) = get_components_tab_selected_name(app) {
                let info = get_components_tab_clipboard_info(app, &comp_name);
                if crate::tui::security::copy_to_clipboard(&info).is_ok() {
                    app.status_message = Some("Copied to clipboard".to_string());
                } else {
                    app.status_message = Some("Failed to copy to clipboard".to_string());
                }
            }
        }
        KeyCode::Char('F') => {
            if let Some(comp_name) = get_components_tab_selected_name(app) {
                let was_flagged = app.security_cache.is_flagged(&comp_name);
                app.security_cache
                    .toggle_flag(&comp_name, "Flagged for review");
                if was_flagged {
                    app.status_message = Some(format!("Unflagged: {comp_name}"));
                } else {
                    app.status_message = Some(format!("Flagged: {comp_name}"));
                }
            }
        }
        KeyCode::Char('o') => {
            if let Some(vuln_id) = get_components_tab_selected_vuln(app) {
                let url = crate::tui::security::cve_url(&vuln_id);
                if crate::tui::security::open_in_browser(&url).is_ok() {
                    app.status_message = Some(format!("Opened: {vuln_id}"));
                } else {
                    app.status_message = Some("Failed to open browser".to_string());
                }
            } else {
                app.status_message = Some("No vulnerability to open".to_string());
            }
        }
        KeyCode::Char('n') => {
            if let Some(comp_name) = get_components_tab_selected_name(app) {
                if app.security_cache.is_flagged(&comp_name) {
                    let preset_notes = [
                        "Needs investigation",
                        "Potential supply chain risk",
                        "Version downgrade detected",
                        "License compliance issue",
                        "Security review required",
                    ];
                    let current_note = app.security_cache.get_note(&comp_name);
                    let next_note = match current_note {
                        None => preset_notes[0],
                        Some(note) => {
                            let idx = preset_notes.iter().position(|&n| n == note);
                            match idx {
                                Some(i) if i + 1 < preset_notes.len() => preset_notes[i + 1],
                                _ => {
                                    app.security_cache.add_note(&comp_name, "");
                                    app.status_message = Some("Note cleared".to_string());
                                    return;
                                }
                            }
                        }
                    };
                    app.security_cache.add_note(&comp_name, next_note);
                    app.status_message = Some(format!("Note: {next_note}"));
                } else {
                    app.status_message = Some("Flag component first with [F]".to_string());
                }
            }
        }
        _ => {}
    }
}

/// Get the name of the currently selected component (for Components tab quick actions)
pub(super) fn get_components_tab_selected_name(app: &App) -> Option<String> {
    let selected = app.tabs.components.selected;
    match app.mode {
        AppMode::Diff => app.data.diff_result.as_ref().and_then(|_| {
            let items = app.diff_component_items(app.tabs.components.filter);
            items.get(selected).map(|c| c.name.clone())
        }),
        AppMode::View => app.data.sbom.as_ref().and_then(|_| {
            let items = app.view_component_items();
            items.get(selected).map(|c| c.name.clone())
        }),
        _ => None,
    }
}

/// Get clipboard-friendly info for the selected component
pub(super) fn get_components_tab_clipboard_info(app: &App, comp_name: &str) -> String {
    let selected = app.tabs.components.selected;
    match app.mode {
        AppMode::Diff => {
            let items = app.diff_component_items(app.tabs.components.filter);
            items.get(selected).map_or_else(
                || comp_name.to_string(),
                |comp| {
                    format!(
                        "Component: {}\nID: {}\nVersion: {}\nEcosystem: {}",
                        comp.name,
                        comp.id,
                        comp.new_version
                            .as_deref()
                            .or(comp.old_version.as_deref())
                            .unwrap_or("unknown"),
                        comp.ecosystem.as_deref().unwrap_or("unknown")
                    )
                },
            )
        }
        AppMode::View => {
            let items = app.view_component_items();
            items.get(selected).map_or_else(
                || comp_name.to_string(),
                |comp| {
                    let vulns: Vec<_> =
                        comp.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
                    format!(
                        "Component: {}\nVersion: {}\nEcosystem: {}\nVulnerabilities: {}",
                        comp.name,
                        comp.version.as_deref().unwrap_or("unknown"),
                        comp.ecosystem.as_ref().map_or_else(
                            || "unknown".to_string(),
                            std::string::ToString::to_string
                        ),
                        if vulns.is_empty() {
                            "None".to_string()
                        } else {
                            vulns.join(", ")
                        }
                    )
                },
            )
        }
        _ => comp_name.to_string(),
    }
}

/// Get the first vulnerability ID for the selected component
pub(super) fn get_components_tab_selected_vuln(app: &App) -> Option<String> {
    let selected = app.tabs.components.selected;
    match app.mode {
        AppMode::Diff => app.data.diff_result.as_ref().and_then(|r| {
            let items = app.diff_component_items(app.tabs.components.filter);
            items.get(selected).and_then(|comp| {
                r.vulnerabilities
                    .introduced
                    .iter()
                    .find(|v| v.component_id == comp.id)
                    .map(|v| v.id.clone())
            })
        }),
        AppMode::View => app.data.sbom.as_ref().and_then(|_| {
            let items = app.view_component_items();
            items
                .get(selected)
                .and_then(|comp| comp.vulnerabilities.first().map(|v| v.id.clone()))
        }),
        _ => None,
    }
}
