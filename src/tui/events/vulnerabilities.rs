//! Vulnerabilities tab event handlers.

use crate::tui::App;
use crate::tui::app::AppMode;
use crate::tui::traits::{EventResult, ViewContext, ViewMode, ViewState};
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_vulnerabilities_keys(app: &mut App, key: KeyEvent) {
    let Some(view) = app.vulnerabilities_view.as_mut() else {
        return;
    };

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
        EventResult::StatusMessage(msg) => {
            app.status_message = Some(msg);
        }
        EventResult::Ignored => {
            // Handle data-dependent keys
            handle_data_dependent_keys(app, key);
        }
        _ => {}
    }
}

/// Handle keys that need access to App data.
fn handle_data_dependent_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('E') => {
            if app.vulnerabilities_state().group_by_component {
                let group_names = collect_all_group_names(app);
                app.vulnerabilities_state_mut()
                    .expand_all_groups(&group_names);
                app.set_status_message("All groups expanded");
            }
        }
        KeyCode::Char('C') => {
            if app.vulnerabilities_state().group_by_component {
                app.vulnerabilities_state_mut().collapse_all_groups();
                app.set_status_message("All groups collapsed");
            }
        }
        KeyCode::Enter => {
            if app.vulnerabilities_state().group_by_component {
                handle_grouped_enter(app);
            } else {
                handle_flat_enter(app);
            }
        }
        _ => {}
    }
}

/// Handle Enter key in flat (non-grouped) mode: navigate to affected component.
fn handle_flat_enter(app: &mut App) {
    let selected = app.vulnerabilities_state().selected;
    let target = {
        app.ensure_vulnerability_cache();
        let items = app.diff_vulnerability_items_from_cache();
        items
            .get(selected)
            .map(|item| (item.vuln.id.clone(), item.vuln.component_name.clone()))
    };

    if let Some((vuln_id, component_name)) = target {
        app.navigate_vuln_to_component(&vuln_id, &component_name);
    }
}

/// Handle Enter key in grouped mode: toggle group or navigate to component.
fn handle_grouped_enter(app: &mut App) {
    let selected = app.vulnerabilities_state().selected;

    let item_info = resolve_grouped_selection(app, selected);

    match item_info {
        GroupedSelection::Header(comp_name) => {
            app.vulnerabilities_state_mut().toggle_group(&comp_name);
        }
        GroupedSelection::Vuln(vuln_id, comp_name) => {
            app.navigate_vuln_to_component(&vuln_id, &comp_name);
        }
        GroupedSelection::None => {}
    }
}

enum GroupedSelection {
    Header(String),
    Vuln(String, String),
    None,
}

/// Resolve what item is at the given index in grouped mode.
fn resolve_grouped_selection(app: &mut App, selected: usize) -> GroupedSelection {
    match app.mode {
        AppMode::Diff => {
            app.ensure_vulnerability_cache();
            let items = app.diff_vulnerability_items_from_cache();

            let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
            let mut group_map: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for (idx, item) in items.iter().enumerate() {
                let name = &item.vuln.component_name;
                if let Some(&group_idx) = group_map.get(name) {
                    groups[group_idx].1.push(idx);
                } else {
                    let group_idx = groups.len();
                    group_map.insert(name.clone(), group_idx);
                    groups.push((name.clone(), vec![idx]));
                }
            }

            groups.sort_by(|a, b| {
                let max_a =
                    a.1.iter()
                        .filter_map(|&i| items.get(i))
                        .map(|it| severity_rank(&it.vuln.severity))
                        .min()
                        .unwrap_or(99);
                let max_b =
                    b.1.iter()
                        .filter_map(|&i| items.get(i))
                        .map(|it| severity_rank(&it.vuln.severity))
                        .min()
                        .unwrap_or(99);
                max_a.cmp(&max_b)
            });

            let mut pos = 0;
            for (comp_name, vuln_indices) in &groups {
                if pos == selected {
                    return GroupedSelection::Header(comp_name.clone());
                }
                pos += 1;

                if app.vulnerabilities_state().is_group_expanded(comp_name) {
                    for &idx in vuln_indices {
                        if pos == selected
                            && let Some(item) = items.get(idx)
                        {
                            return GroupedSelection::Vuln(
                                item.vuln.id.clone(),
                                item.vuln.component_name.clone(),
                            );
                        }
                        pos += 1;
                    }
                }
            }

            GroupedSelection::None
        }
        _ => GroupedSelection::None,
    }
}

/// Collect all unique component names for expand-all.
fn collect_all_group_names(app: &mut App) -> Vec<String> {
    match app.mode {
        AppMode::Diff => {
            app.ensure_vulnerability_cache();
            let items = app.diff_vulnerability_items_from_cache();
            let mut seen = std::collections::HashSet::new();
            let mut names = Vec::new();
            for item in &items {
                if seen.insert(item.vuln.component_name.clone()) {
                    names.push(item.vuln.component_name.clone());
                }
            }
            names
        }
        _ => Vec::new(),
    }
}

use crate::tui::shared::vulnerabilities::severity_rank;
