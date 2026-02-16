//! Event handling for the TUI.
//!
//! This module provides event handling for the TUI, including:
//! - Key and mouse event polling
//! - Event dispatch to the appropriate handlers
//! - Integration with the `EventResult` type from `traits`

mod components;
mod compliance;
mod dependencies;
mod graph_changes;
mod helpers;
mod licenses;
mod matrix;
pub mod mouse;
mod multi_diff;
mod quality;
mod sidebyside;
mod source;
mod timeline;
mod vulnerabilities;

use crate::config::TuiPreferences;
use crate::tui::toggle_theme;
use crossterm::event::{
    self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers, MouseEvent,
};
use std::time::Duration;

pub use mouse::handle_mouse_event;

/// Application event
#[derive(Debug)]
pub enum Event {
    /// Key press event
    Key(KeyEvent),
    /// Mouse event
    Mouse(MouseEvent),
    /// Terminal tick (for animations)
    Tick,
    /// Resize event
    Resize(u16, u16),
}

/// Event handler
pub struct EventHandler {
    /// Tick rate in milliseconds
    tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler
    pub const fn new(tick_rate: u64) -> Self {
        Self {
            tick_rate: Duration::from_millis(tick_rate),
        }
    }

    /// Poll for the next event
    pub fn next(&self) -> Result<Event, std::io::Error> {
        if event::poll(self.tick_rate)? {
            match event::read()? {
                CrosstermEvent::Key(key) => Ok(Event::Key(key)),
                CrosstermEvent::Mouse(mouse) => Ok(Event::Mouse(mouse)),
                CrosstermEvent::Resize(width, height) => Ok(Event::Resize(width, height)),
                _ => Ok(Event::Tick),
            }
        } else {
            Ok(Event::Tick)
        }
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new(250)
    }
}

/// Handle key events and update app state
pub fn handle_key_event(app: &mut super::App, key: KeyEvent) {
    // Clear any status message on key press
    app.clear_status_message();

    // Handle search mode separately
    if app.overlays.search.active {
        match key.code {
            KeyCode::Esc => app.stop_search(),
            KeyCode::Enter => {
                // Jump to selected search result
                app.jump_to_search_result();
            }
            KeyCode::Backspace => {
                app.search_pop();
                // Live search as user types
                app.execute_search();
            }
            KeyCode::Up => app.overlays.search.select_prev(),
            KeyCode::Down => app.overlays.search.select_next(),
            KeyCode::Char(c) => {
                app.search_push(c);
                // Live search as user types
                app.execute_search();
            }
            _ => {}
        }
        return;
    }

    // Handle threshold tuning overlay
    if app.overlays.threshold_tuning.visible {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.overlays.threshold_tuning.visible = false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.overlays.threshold_tuning.increase();
                app.update_threshold_preview();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.overlays.threshold_tuning.decrease();
                app.update_threshold_preview();
            }
            KeyCode::Right | KeyCode::Char('l') => {
                app.overlays.threshold_tuning.fine_increase();
                app.update_threshold_preview();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                app.overlays.threshold_tuning.fine_decrease();
                app.update_threshold_preview();
            }
            KeyCode::Char('r') => {
                app.overlays.threshold_tuning.reset();
                app.update_threshold_preview();
            }
            KeyCode::Enter => {
                app.apply_threshold();
            }
            _ => {}
        }
        return;
    }

    // Handle overlays (help, export, legend)
    if app.has_overlay() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.close_overlays(),
            KeyCode::Char('?') if app.overlays.show_help => app.toggle_help(),
            KeyCode::Char('e') if app.overlays.show_export => app.toggle_export(),
            KeyCode::Char('l') if app.overlays.show_legend => app.toggle_legend(),
            // Export format selection in export dialog
            KeyCode::Char('j') if app.overlays.show_export => {
                app.close_overlays();
                app.export(super::export::ExportFormat::Json);
            }
            KeyCode::Char('m') if app.overlays.show_export => {
                app.close_overlays();
                app.export(super::export::ExportFormat::Markdown);
            }
            KeyCode::Char('h') if app.overlays.show_export => {
                app.close_overlays();
                app.export(super::export::ExportFormat::Html);
            }
            KeyCode::Char('s') if app.overlays.show_export => {
                app.close_overlays();
                app.export(super::export::ExportFormat::Sarif);
            }
            KeyCode::Char('c') if app.overlays.show_export => {
                app.close_overlays();
                app.export(super::export::ExportFormat::Csv);
            }
            _ => {}
        }
        return;
    }

    // Handle view switcher overlay (for multi-comparison modes)
    if app.overlays.view_switcher.visible {
        match key.code {
            KeyCode::Esc => app.overlays.view_switcher.hide(),
            KeyCode::Up | KeyCode::Char('k') => app.overlays.view_switcher.previous(),
            KeyCode::Down | KeyCode::Char('j') => app.overlays.view_switcher.next(),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(view) = app.overlays.view_switcher.current_view() {
                    app.overlays.view_switcher.hide();
                    mouse::switch_to_view(app, view);
                }
            }
            KeyCode::Char('1') => {
                app.overlays.view_switcher.hide();
                mouse::switch_to_view(app, super::app::MultiViewType::MultiDiff);
            }
            KeyCode::Char('2') => {
                app.overlays.view_switcher.hide();
                mouse::switch_to_view(app, super::app::MultiViewType::Timeline);
            }
            KeyCode::Char('3') => {
                app.overlays.view_switcher.hide();
                mouse::switch_to_view(app, super::app::MultiViewType::Matrix);
            }
            _ => {}
        }
        return;
    }

    // Handle shortcuts overlay
    if app.overlays.shortcuts.visible {
        match key.code {
            KeyCode::Esc | KeyCode::Char('K') | KeyCode::F(1) => app.overlays.shortcuts.hide(),
            _ => {}
        }
        return;
    }

    // Handle component deep dive modal
    if app.overlays.component_deep_dive.visible {
        match key.code {
            KeyCode::Esc => app.overlays.component_deep_dive.close(),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                app.overlays.component_deep_dive.next_section();
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                app.overlays.component_deep_dive.prev_section();
            }
            _ => {}
        }
        return;
    }

    // Global key bindings
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') => app.toggle_help(),
        KeyCode::Char('e') => app.toggle_export(),
        KeyCode::Char('l') => app.toggle_legend(),
        KeyCode::Char('T') => {
            // Toggle theme (dark -> light -> high-contrast) and save preference
            let theme_name = toggle_theme();
            let prefs = TuiPreferences {
                theme: theme_name.to_string(),
            };
            let _ = prefs.save();
        }
        // View switcher (V key in multi-comparison modes)
        KeyCode::Char('V') => {
            if matches!(
                app.mode,
                super::AppMode::MultiDiff | super::AppMode::Timeline | super::AppMode::Matrix
            ) {
                app.overlays.view_switcher.toggle();
            }
        }
        // Match threshold tuning overlay (only in Diff mode)
        KeyCode::Char('M') => {
            if matches!(app.mode, super::AppMode::Diff) {
                app.toggle_threshold_tuning();
            }
        }
        // Keyboard shortcuts overlay
        KeyCode::Char('K') | KeyCode::F(1) => {
            let context = match app.mode {
                super::AppMode::MultiDiff => super::app::ShortcutsContext::MultiDiff,
                super::AppMode::Timeline => super::app::ShortcutsContext::Timeline,
                super::AppMode::Matrix => super::app::ShortcutsContext::Matrix,
                super::AppMode::Diff => super::app::ShortcutsContext::Diff,
                super::AppMode::View => super::app::ShortcutsContext::Global,
            };
            app.overlays.shortcuts.show(context);
        }
        // Component deep dive (D key)
        KeyCode::Char('D') => {
            if let Some(component_name) = helpers::get_selected_component_name(app) {
                app.overlays.component_deep_dive.open(component_name, None);
            }
        }
        // Policy/Compliance check (P key)
        KeyCode::Char('P') => {
            if matches!(app.mode, super::AppMode::Diff | super::AppMode::View) {
                app.run_compliance_check();
            }
        }
        // Cycle policy preset (Shift+P cycles policies)
        KeyCode::Char('p') => {
            if matches!(app.mode, super::AppMode::Diff | super::AppMode::View) {
                app.next_policy();
            }
        }
        KeyCode::Esc => app.close_overlays(),
        KeyCode::Char('b') | KeyCode::Backspace => {
            // Navigate back using breadcrumbs
            if app.has_navigation_history() {
                app.navigate_back();
            }
        }
        KeyCode::Tab => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.prev_tab();
            } else {
                app.next_tab();
            }
        }
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('1') => app.select_tab(super::TabKind::Summary),
        KeyCode::Char('2') => app.select_tab(super::TabKind::Components),
        KeyCode::Char('3') => app.select_tab(super::TabKind::Dependencies),
        KeyCode::Char('4') => app.select_tab(super::TabKind::Licenses),
        KeyCode::Char('5') => app.select_tab(super::TabKind::Vulnerabilities),
        KeyCode::Char('6') => app.select_tab(super::TabKind::Quality),
        KeyCode::Char('7') => {
            // Compliance only in diff mode
            if app.mode == super::AppMode::Diff {
                app.select_tab(super::TabKind::Compliance);
            }
        }
        KeyCode::Char('8') => {
            // Side-by-side only in diff mode
            if app.mode == super::AppMode::Diff {
                app.select_tab(super::TabKind::SideBySide);
            }
        }
        KeyCode::Char('9') => {
            // Graph changes tab when graph diff data is available, otherwise Source
            let has_graph = app
                .data.diff_result
                .as_ref()
                .is_some_and(|r| !r.graph_changes.is_empty());
            if has_graph {
                app.select_tab(super::TabKind::GraphChanges);
            } else if app.mode == super::AppMode::Diff {
                app.select_tab(super::TabKind::Source);
            }
        }
        KeyCode::Char('0') => {
            // Source tab as 10th tab (only when graph changes exist)
            let has_graph = app
                .data.diff_result
                .as_ref()
                .is_some_and(|r| !r.graph_changes.is_empty());
            if has_graph && app.mode == super::AppMode::Diff {
                app.select_tab(super::TabKind::Source);
            }
        }
        // Navigation
        KeyCode::Up | KeyCode::Char('k') => app.select_up(),
        KeyCode::Down | KeyCode::Char('j') => app.select_down(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::Home | KeyCode::Char('g') if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.select_first();
        }
        KeyCode::End | KeyCode::Char('G') => app.select_last(),
        _ => {}
    }

    // Tab-specific key bindings
    match app.active_tab {
        super::TabKind::Components => components::handle_components_keys(app, key),
        super::TabKind::Dependencies => dependencies::handle_dependencies_keys(app, key),
        super::TabKind::Licenses => licenses::handle_licenses_keys(app, key),
        super::TabKind::Vulnerabilities => vulnerabilities::handle_vulnerabilities_keys(app, key),
        super::TabKind::Quality => quality::handle_quality_keys(app, key),
        super::TabKind::Compliance => compliance::handle_diff_compliance_keys(app, key),
        super::TabKind::GraphChanges => graph_changes::handle_graph_changes_keys(app, key),
        super::TabKind::SideBySide => sidebyside::handle_sidebyside_keys(app, key),
        super::TabKind::Source => source::handle_source_keys(app, key),
        super::TabKind::Summary => {}
    }

    // Mode-specific key bindings for multi-diff, timeline, and matrix
    match app.mode {
        super::AppMode::MultiDiff => multi_diff::handle_multi_diff_keys(app, key),
        super::AppMode::Timeline => timeline::handle_timeline_keys(app, key),
        super::AppMode::Matrix => matrix::handle_matrix_keys(app, key),
        _ => {}
    }
}

