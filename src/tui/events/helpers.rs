//! Cross-view helper functions.

use crate::tui::{App, AppMode};

pub(super) fn get_selected_component_name(app: &App) -> Option<String> {
    match app.mode {
        AppMode::MultiDiff => {
            // Get selected component from multi-diff view
            if let Some(ref result) = app.data.multi_diff_result {
                let idx = app.tabs.multi_diff.selected_variable_component;
                if idx < result.summary.variable_components.len() {
                    return Some(result.summary.variable_components[idx].name.clone());
                }
            }
            None
        }
        AppMode::Timeline => {
            // Get selected component from timeline view
            if let Some(ref result) = app.data.timeline_result {
                let idx = app.tabs.timeline.selected_component;
                // Check in evolution_summary for component names
                let all_components: Vec<_> = result
                    .evolution_summary
                    .components_added
                    .iter()
                    .chain(result.evolution_summary.components_removed.iter())
                    .collect();
                if idx < all_components.len() {
                    return Some(all_components[idx].name.clone());
                }
            }
            None
        }
        AppMode::Matrix => {
            // Get SBOM name from selected row in matrix
            if let Some(ref result) = app.data.matrix_result {
                let row = app.tabs.matrix.selected_row;
                if row < result.sboms.len() {
                    return Some(result.sboms[row].name.clone());
                }
            }
            None
        }
        AppMode::Diff | AppMode::View => {
            // Get selected component from components tab
            if let Some(ref result) = app.data.diff_result {
                let idx = app.tabs.components.selected;
                let total = result.components.total();
                if idx < total {
                    // Try to get from added, removed, or modified
                    if idx < result.components.added.len() {
                        return Some(result.components.added[idx].name.clone());
                    }
                    let idx = idx - result.components.added.len();
                    if idx < result.components.removed.len() {
                        return Some(result.components.removed[idx].name.clone());
                    }
                    let idx = idx - result.components.removed.len();
                    if idx < result.components.modified.len() {
                        return Some(result.components.modified[idx].name.clone());
                    }
                }
            }
            None
        }
    }
}

