//! Mouse event handlers.

use crate::tui::{App, AppMode};
use crossterm::event::{MouseEvent, MouseEventKind, MouseButton};

pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) {
    // Clear status message on any mouse action
    app.clear_status_message();

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            app.select_up();
        }
        MouseEventKind::ScrollDown => {
            app.select_down();
        }
        MouseEventKind::Down(MouseButton::Left) => {
            let x = mouse.column;
            let y = mouse.row;

            // Close overlays on click
            if app.has_overlay() {
                app.close_overlays();
                return;
            }

            // Tab bar is typically in the first 2 rows
            if y <= 2 {
                // Estimate tab positions based on typical widths
                let tab_width = 13;
                let tab_index = (x as usize) / tab_width;
                match tab_index {
                    0 => app.select_tab(crate::tui::TabKind::Summary),
                    1 => app.select_tab(crate::tui::TabKind::Components),
                    2 => app.select_tab(crate::tui::TabKind::Dependencies),
                    3 => app.select_tab(crate::tui::TabKind::Licenses),
                    4 => app.select_tab(crate::tui::TabKind::Vulnerabilities),
                    5 => app.select_tab(crate::tui::TabKind::Quality),
                    6 if app.mode == AppMode::Diff => {
                        app.select_tab(crate::tui::TabKind::SideBySide);
                    }
                    _ => {}
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
            if clicked_index < app.tabs.components.total {
                app.tabs.components.selected = clicked_index;
            }
        }
        crate::tui::TabKind::Vulnerabilities => {
            if clicked_index < app.tabs.vulnerabilities.total {
                app.tabs.vulnerabilities.selected = clicked_index;
            }
        }
        crate::tui::TabKind::Licenses => {
            if clicked_index < app.tabs.licenses.total {
                app.tabs.licenses.selected = clicked_index;
            }
        }
        crate::tui::TabKind::Dependencies => {
            if clicked_index < app.tabs.dependencies.total {
                app.tabs.dependencies.selected = clicked_index;
            }
        }
        crate::tui::TabKind::Quality => {
            // Quality view may have selectable items
            if clicked_index < app.tabs.quality.total_recommendations {
                app.tabs.quality.selected_recommendation = clicked_index;
                // Keep quality_view in sync to avoid state divergence
                if let Some(ref mut qv) = app.quality_view {
                    qv.set_selected_recommendation(clicked_index);
                }
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

