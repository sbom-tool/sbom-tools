//! Vulnerabilities tab event handlers.

use crate::tui::App;
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
            app.set_status_message(format!("Vulnerabilities: {} view", mode));
        }
        KeyCode::Char('E') => {
            // Expand all groups (in grouped mode)
            if app.tabs.vulnerabilities.group_by_component {
                // Get all group IDs and expand them
                let groups = crate::diff::changes::group_vulnerabilities(
                    &app.data.diff_result.as_ref().map(|r| r.vulnerabilities.introduced.clone()).unwrap_or_default(),
                    crate::diff::changes::VulnGroupStatus::Introduced,
                );
                let ids: Vec<String> = groups.iter().map(|g| g.component_id.clone()).collect();
                app.tabs.vulnerabilities.expand_all_groups(&ids);
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
            // Navigate to affected component
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
        _ => {}
    }
}

