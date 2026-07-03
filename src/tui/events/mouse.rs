//! Mouse event handlers.

use crate::tui::{App, AppMode};
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) {
    // Clear status message on any mouse action
    app.clear_status_message();

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if app.active_tab == crate::tui::TabKind::Source {
                app.source_state_mut().select_prev();
            } else {
                app.select_up();
            }
        }
        MouseEventKind::ScrollDown => {
            if app.active_tab == crate::tui::TabKind::Source {
                app.source_state_mut().select_next();
            } else {
                app.select_down();
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            let x = mouse.column;
            let y = mouse.row;

            // Close overlays on click
            if app.has_overlay() {
                app.close_overlays();
                return;
            }

            // Tab bar is in the first rows. Derive the clicked tab from the real
            // rendered tab set + geometry so every profile/mode tab is reachable
            // (the old fixed-13-col estimate mis-selected once Compliance/Graph/
            // Source were present).
            if y <= 2 {
                let entries = crate::tui::ui::diff_tab_entries(app);
                let labels: Vec<String> = entries
                    .iter()
                    .map(|(_, key, title)| crate::tui::ui::diff_tab_label(key, title))
                    .collect();
                if let Some(idx) = crate::tui::shared::tab_bar_hit(&labels, 0, 3, x) {
                    app.select_tab(entries[idx].0);
                }
                return;
            }

            // Handle click on list items
            // Layout: header (2 rows) + filter bar (3 rows) + content
            // Content area starts around row 5, with 1-row header inside tables
            let content_start_row = 6u16; // After tabs + filter bar + table header

            if y >= content_start_row {
                let clicked_index = (y - content_start_row) as usize;
                handle_list_click(app, clicked_index, x);
            }
        }
        MouseEventKind::Down(MouseButton::Right) => {
            // Right-click closes overlays
            if app.has_overlay() {
                app.close_overlays();
            }
        }
        _ => {}
    }
}

/// Handle a click on a list item
pub(super) fn handle_list_click(app: &mut App, clicked_index: usize, _x: u16) {
    match app.active_tab {
        crate::tui::TabKind::Components => {
            if clicked_index < app.components_state().total {
                app.components_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Vulnerabilities => {
            if clicked_index < app.vulnerabilities_state().total {
                app.vulnerabilities_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Licenses => {
            if clicked_index < app.licenses_state().total {
                app.licenses_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Dependencies => {
            if clicked_index < app.dependencies_state().total {
                app.dependencies_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Quality => {
            // Quality view may have selectable items
            if clicked_index < app.quality_state().total_recommendations {
                app.quality_state_mut().selected_recommendation = clicked_index;
            }
        }
        crate::tui::TabKind::Source => {
            // Determine which panel from x position (50/50 split)
            let panel = app.source_state_mut().active_panel_mut();
            let max = match panel.view_mode {
                crate::tui::app_states::SourceViewMode::Tree => {
                    panel.ensure_flat_cache();
                    panel.cached_flat_items.len()
                }
                crate::tui::app_states::SourceViewMode::Raw => panel.raw_lines.len(),
            };
            let idx = panel.scroll_offset + clicked_index;
            if idx < max {
                panel.selected = idx;
            }
        }
        _ => {}
    }
}

// ============================================================================
// Cross-View Helper Functions
// ============================================================================

/// Switch to a different multi-comparison view
pub(super) fn switch_to_view(app: &mut App, view: crate::tui::app_states::MultiViewType) {
    match view {
        crate::tui::app_states::MultiViewType::MultiDiff => {
            app.mode = AppMode::MultiDiff;
            app.set_status_message("Switched to Multi-Diff Dashboard".to_string());
        }
        crate::tui::app_states::MultiViewType::Timeline => {
            app.mode = AppMode::Timeline;
            app.set_status_message("Switched to Timeline View".to_string());
        }
        crate::tui::app_states::MultiViewType::Matrix => {
            app.mode = AppMode::Matrix;
            app.set_status_message("Switched to Matrix Comparison".to_string());
        }
    }
}
