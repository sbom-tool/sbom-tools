//! Vulnerabilities tab event handlers.

use crate::tui::App;
use crate::tui::app::AppMode;
use crossterm::event::{KeyCode, KeyEvent};

pub(super) fn handle_vulnerabilities_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('f') => app.tabs.vulnerabilities.toggle_filter(),
        KeyCode::Char('s') => app.tabs.vulnerabilities.toggle_sort(),
        KeyCode::Char('g') => {
            // Toggle grouped mode
            app.tabs.vulnerabilities.toggle_grouped_mode();
            let mode = if app.tabs.vulnerabilities.group_by_component {
                "grouped"
            } else {
                "list"
            };
            app.set_status_message(format!("Vulnerabilities: {mode} view"));
        }
        KeyCode::Char('E') => {
            // Expand all groups (in grouped mode)
            if app.tabs.vulnerabilities.group_by_component {
                let group_names = collect_all_group_names(app);
                app.tabs.vulnerabilities.expand_all_groups(&group_names);
                app.set_status_message("All groups expanded");
            }
        }
        KeyCode::Char('C') => {
            // Collapse all groups (in grouped mode)
            if app.tabs.vulnerabilities.group_by_component {
                app.tabs.vulnerabilities.collapse_all_groups();
                app.set_status_message("All groups collapsed");
            }
        }
        KeyCode::Enter => {
            if app.tabs.vulnerabilities.group_by_component {
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
    let selected = app.tabs.vulnerabilities.selected;
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
    let selected = app.tabs.vulnerabilities.selected;

    // Build the same grouped render items to determine what's at the selected index
    let item_info = resolve_grouped_selection(app, selected);

    match item_info {
        GroupedSelection::Header(comp_name) => {
            app.tabs.vulnerabilities.toggle_group(&comp_name);
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

            // Group by component name, same order as render
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

            // Sort groups by max severity
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

            // Walk the grouped items to find what's at `selected`
            let mut pos = 0;
            for (comp_name, vuln_indices) in &groups {
                if pos == selected {
                    return GroupedSelection::Header(comp_name.clone());
                }
                pos += 1;

                if app.tabs.vulnerabilities.is_group_expanded(comp_name) {
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
        AppMode::View => {
            // For view mode, we need sbom data
            let Some(sbom) = app.data.sbom.as_ref() else {
                return GroupedSelection::None;
            };

            let vulns = sbom.all_vulnerabilities();
            let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
            let mut group_map: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for (idx, (comp, _vuln)) in vulns.iter().enumerate() {
                let name = &comp.name;
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
                        .filter_map(|&i| vulns.get(i))
                        .map(|it| {
                            severity_rank(
                                &it.1
                                    .severity
                                    .as_ref()
                                    .map(std::string::ToString::to_string)
                                    .unwrap_or_default(),
                            )
                        })
                        .min()
                        .unwrap_or(99);
                let max_b =
                    b.1.iter()
                        .filter_map(|&i| vulns.get(i))
                        .map(|it| {
                            severity_rank(
                                &it.1
                                    .severity
                                    .as_ref()
                                    .map(std::string::ToString::to_string)
                                    .unwrap_or_default(),
                            )
                        })
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

                if app.tabs.vulnerabilities.is_group_expanded(comp_name) {
                    for &idx in vuln_indices {
                        if pos == selected
                            && let Some((comp, vuln)) = vulns.get(idx)
                        {
                            return GroupedSelection::Vuln(vuln.id.clone(), comp.name.clone());
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
        AppMode::View => app.data.sbom.as_ref().map_or_else(Vec::new, |sbom| {
            let mut seen = std::collections::HashSet::new();
            let mut names = Vec::new();
            for (comp, _) in sbom.all_vulnerabilities() {
                if seen.insert(comp.name.clone()) {
                    names.push(comp.name.clone());
                }
            }
            names
        }),
        _ => Vec::new(),
    }
}

/// Severity rank for sorting (lower = more severe)
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" | "moderate" => 2,
        "low" => 3,
        "info" | "informational" | "none" => 4,
        _ => 5,
    }
}
