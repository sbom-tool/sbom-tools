//! Event handling for the TUI.
//!
//! This module provides event handling for the TUI, including:
//! - Key and mouse event polling
//! - Event dispatch to the appropriate handlers
//! - Integration with the `EventResult` type from `traits`

mod compliance;
mod components;
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

    // Ctrl+C copies the selected item (universal shortcut)
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        handle_yank(app);
        return;
    }

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
            // Ctrl+R toggles between substring and regex search mode
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                use crate::tui::app_states::SearchMode;
                app.overlays.search.mode = match app.overlays.search.mode {
                    SearchMode::Substring => SearchMode::Regex,
                    SearchMode::Regex => SearchMode::Substring,
                };
                // Re-execute search with new mode
                app.execute_search();
                let mode_name = app.overlays.search.mode.label();
                app.set_status_message(format!("Search mode: {mode_name}"));
            }
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
                dispatch_export(app, super::export::ExportFormat::Json);
            }
            KeyCode::Char('m') if app.overlays.show_export => {
                app.close_overlays();
                dispatch_export(app, super::export::ExportFormat::Markdown);
            }
            KeyCode::Char('h') if app.overlays.show_export => {
                app.close_overlays();
                dispatch_export(app, super::export::ExportFormat::Html);
            }
            KeyCode::Char('s') if app.overlays.show_export => {
                app.close_overlays();
                dispatch_export(app, super::export::ExportFormat::Sarif);
            }
            KeyCode::Char('c') if app.overlays.show_export => {
                app.close_overlays();
                dispatch_export(app, super::export::ExportFormat::Csv);
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

    // Tab- and mode-specific handlers get first crack at the key. Whatever they
    // consume never reaches the global fallback below, so a tab-local binding
    // (Components' `1`-`8` quick filters, SideBySide's `/` search, `p` panel
    // focus, …) wins over a colliding global binding instead of both firing.
    let consumed_by_tab = dispatch_tab_key(app, key);
    let consumed_by_mode = dispatch_mode_key(app, key);

    if !consumed_by_tab && !consumed_by_mode {
        handle_global_fallback(app, key);
    }
}

/// Dispatch a key to the active tab's handler.
///
/// Returns `true` if the tab consumed the key, meaning it must not fall through
/// to [`handle_global_fallback`]. Tabs without a dedicated handler
/// (Summary/Overview/Tree) never consume, so global bindings and list
/// navigation still apply on them.
fn dispatch_tab_key(app: &mut super::App, key: KeyEvent) -> bool {
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
        super::TabKind::Summary | super::TabKind::Overview | super::TabKind::Tree => false,
    }
}

/// Dispatch a key to the active multi-comparison mode handler.
///
/// Returns `true` if the mode consumed the key. Single-pair modes (Diff/View)
/// have no mode handler and never consume here.
fn dispatch_mode_key(app: &mut super::App, key: KeyEvent) -> bool {
    match app.mode {
        super::AppMode::MultiDiff => multi_diff::handle_multi_diff_keys(app, key),
        super::AppMode::Timeline => timeline::handle_timeline_keys(app, key),
        super::AppMode::Matrix => matrix::handle_matrix_keys(app, key),
        super::AppMode::Diff | super::AppMode::View => false,
    }
}

/// Global key bindings — the fallback layer.
///
/// Invoked only for keys that no active tab or mode handler consumed, so a
/// tab-local binding always takes precedence over a colliding global one.
fn handle_global_fallback(app: &mut super::App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => {
            // Save last active tab before quitting
            let mut prefs = crate::config::TuiPreferences::load();
            prefs.last_tab = Some(app.active_tab.as_str().to_string());
            let _ = prefs.save();
            app.should_quit = true;
        }
        KeyCode::Char('?') => app.toggle_help(),
        KeyCode::Char('e') => app.toggle_export(),
        KeyCode::Char('l') => app.toggle_legend(),
        KeyCode::Char('T') => {
            // Toggle theme (dark -> light -> high-contrast) and save preference
            let theme_name = toggle_theme();
            let mut prefs = TuiPreferences::load();
            prefs.theme = theme_name.parse().unwrap_or_default();
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
        // Keyboard shortcuts overlay
        KeyCode::Char('K') | KeyCode::F(1) => {
            let context = match app.mode {
                super::AppMode::MultiDiff => super::app::ShortcutsContext::MultiDiff,
                super::AppMode::Timeline => super::app::ShortcutsContext::Timeline,
                super::AppMode::Matrix => super::app::ShortcutsContext::Matrix,
                super::AppMode::Diff => super::app::ShortcutsContext::Diff,
                super::AppMode::View => super::app::ShortcutsContext::View,
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
            if matches!(app.mode, super::AppMode::Diff) {
                app.run_compliance_check();
            }
        }
        // Cycle policy preset (Shift+P cycles policies)
        KeyCode::Char('p') => {
            if matches!(app.mode, super::AppMode::Diff) {
                app.next_policy();
            }
        }
        // Yank (copy) selected item to clipboard
        KeyCode::Char('y') => {
            handle_yank(app);
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
                .data
                .diff_result
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
                .data
                .diff_result
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
}

/// Get the text that would be copied for the current selection in diff mode.
///
/// Returns `None` if nothing is selected or the tab has no copyable item.
pub fn get_yank_text(app: &super::App) -> Option<String> {
    match app.active_tab {
        super::TabKind::Components => helpers::get_selected_component_name(app),
        super::TabKind::Vulnerabilities => {
            let idx = app.vulnerabilities_state().selected;
            let result = app.data.diff_result.as_ref()?;
            let vulns: Vec<_> = result
                .vulnerabilities
                .introduced
                .iter()
                .chain(result.vulnerabilities.resolved.iter())
                .collect();
            vulns.get(idx).map(|v| v.id.clone())
        }
        super::TabKind::Dependencies => {
            let idx = app.dependencies_state().selected;
            let result = app.data.diff_result.as_ref()?;
            let deps: Vec<_> = result
                .dependencies
                .added
                .iter()
                .chain(result.dependencies.removed.iter())
                .collect();
            deps.get(idx)
                .map(|dep| format!("{} → {}", dep.from, dep.to))
        }
        super::TabKind::Licenses => {
            let idx = app.licenses_state().selected;
            let result = app.data.diff_result.as_ref()?;
            let licenses: Vec<_> = result
                .licenses
                .new_licenses
                .iter()
                .chain(result.licenses.removed_licenses.iter())
                .collect();
            licenses.get(idx).map(|lic| lic.license.clone())
        }
        super::TabKind::Quality => {
            let report = app
                .data
                .new_quality
                .as_ref()
                .or(app.data.old_quality.as_ref())?;
            report
                .recommendations
                .get(app.quality_state().selected_recommendation)
                .map(|rec| rec.message.clone())
        }
        super::TabKind::Compliance => {
            let results = app
                .data
                .new_compliance_results
                .as_ref()
                .or(app.data.old_compliance_results.as_ref())?;
            let result = results.get(app.diff_compliance_state().selected_standard)?;
            result
                .violations
                .get(app.diff_compliance_state().selected_violation)
                .map(|v| v.message.clone())
        }
        super::TabKind::Source => {
            let source = app.source_state();
            let panel = match source.active_side {
                crate::tui::app_states::SourceSide::Old => &source.old_panel,
                crate::tui::app_states::SourceSide::New => &source.new_panel,
            };
            match panel.view_mode {
                super::app_states::SourceViewMode::Tree => {
                    // Cache is already warm from rendering
                    panel.cached_flat_items.get(panel.selected).map(|item| {
                        if !item.value_preview.is_empty() {
                            // Strip surrounding quotes for string values
                            let v = &item.value_preview;
                            if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
                                v[1..v.len() - 1].to_string()
                            } else {
                                v.clone()
                            }
                        } else {
                            item.node_id.clone()
                        }
                    })
                }
                super::app_states::SourceViewMode::Raw => panel
                    .raw_lines
                    .get(panel.selected)
                    .map(|line| line.trim().to_string()),
            }
        }
        _ => None,
    }
}

/// Handle `y` / `Ctrl+C` to copy the focused item to clipboard.
fn handle_yank(app: &mut super::App) {
    let Some(text) = get_yank_text(app) else {
        app.set_status_message("Nothing selected to copy");
        return;
    };

    if crate::tui::clipboard::copy_to_clipboard(&text) {
        let display = if text.len() > 50 {
            let end = crate::tui::shared::floor_char_boundary(&text, 47);
            format!("{}...", &text[..end])
        } else {
            text
        };
        app.set_status_message(format!("Copied: {display}"));
    } else {
        app.set_status_message("Failed to copy to clipboard");
    }
}

/// Route an export to either the standard reporter pipeline or the
/// compliance-specific exporter depending on the active tab.
fn dispatch_export(app: &mut super::App, format: crate::tui::export::ExportFormat) {
    if app.active_tab == super::TabKind::Compliance {
        app.export_compliance(format);
    } else {
        app.export(format);
    }
}

#[cfg(test)]
mod dispatch_precedence_tests {
    //! Single-dispatch precedence contract for the diff key handler.
    //!
    //! The dispatcher gives the active tab (and multi-comparison mode) first
    //! crack at every key via [`dispatch_tab_key`]/[`dispatch_mode_key`]; only
    //! keys they *don't* consume reach [`handle_global_fallback`]. These tests
    //! lock that contract per-tab: a tab-local binding always wins over a
    //! colliding global one, universal chrome keys are never shadowed, and
    //! navigation is never starved on the tabs whose global `select_*` is a
    //! no-op.
    //!
    //! Routing is asserted directly on the `bool` returned by `dispatch_tab_key`
    //! (data-independent — it does not depend on how many rows the demo fixture
    //! happens to have); the individual views' navigation *effects* are covered
    //! by each view's own unit tests.

    use super::{dispatch_tab_key, handle_key_event};
    use crate::tui::test_support::{DEMO_NEW, DEMO_OLD, demo_diff, pin_theme};
    use crate::tui::{App, TabKind};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn diff_app(active_tab: TabKind) -> App {
        pin_theme();
        let (diff, old, new) = demo_diff();
        let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
        app.active_tab = active_tab;
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Navigation must reach every list-bearing tab. Tabs whose global
    /// `select_*` is a no-op (SideBySide/Quality/Compliance/GraphChanges) — plus
    /// Licenses/Dependencies, whose views own navigation — MUST consume `j`/`k`
    /// locally. Tabs that navigate through the global list handler
    /// (Components/Vulnerabilities/Source) MUST let `j`/`k` fall through. Either
    /// way navigation is never starved.
    #[test]
    fn nav_keys_route_to_the_correct_layer() {
        for tab in [
            TabKind::SideBySide,
            TabKind::Quality,
            TabKind::Compliance,
            TabKind::GraphChanges,
            TabKind::Licenses,
            TabKind::Dependencies,
        ] {
            let mut app = diff_app(tab);
            assert!(
                dispatch_tab_key(&mut app, k(KeyCode::Char('j'))),
                "{tab:?} must consume 'j' locally (global select_down is a no-op there)"
            );
            assert!(
                dispatch_tab_key(&mut app, k(KeyCode::Char('k'))),
                "{tab:?} must consume 'k' locally"
            );
        }

        for tab in [
            TabKind::Components,
            TabKind::Vulnerabilities,
            TabKind::Source,
        ] {
            let mut app = diff_app(tab);
            assert!(
                !dispatch_tab_key(&mut app, k(KeyCode::Char('j'))),
                "{tab:?} must defer 'j' to the global list navigation"
            );
            assert!(
                !dispatch_tab_key(&mut app, k(KeyCode::Char('k'))),
                "{tab:?} must defer 'k' to the global list navigation"
            );
        }
    }

    /// The confirmed global/tab key collisions resolve tab-first: the tab owns
    /// the key and the colliding global binding never fires.
    #[test]
    fn tab_bindings_win_over_colliding_global_bindings() {
        // '/': SideBySide has its own search; Components has none and defers to
        // the global search overlay.
        assert!(
            dispatch_tab_key(&mut diff_app(TabKind::SideBySide), k(KeyCode::Char('/'))),
            "SideBySide consumes '/' for its own search"
        );
        assert!(
            !dispatch_tab_key(&mut diff_app(TabKind::Components), k(KeyCode::Char('/'))),
            "Components has no '/'; it falls through to the global search overlay"
        );

        // '1'-'8': Components quick filters vs. the global tab-select.
        assert!(
            dispatch_tab_key(&mut diff_app(TabKind::Components), k(KeyCode::Char('1'))),
            "Components consumes '1' as a quick filter"
        );
        assert!(
            !dispatch_tab_key(&mut diff_app(TabKind::Summary), k(KeyCode::Char('1'))),
            "Summary has no handler; '1' falls through to the global tab-select"
        );

        // 'p': panel focus toggle vs. the global next-policy binding.
        for tab in [TabKind::Components, TabKind::SideBySide] {
            assert!(
                dispatch_tab_key(&mut diff_app(tab), k(KeyCode::Char('p'))),
                "{tab:?} consumes 'p' for panel focus, not global next-policy"
            );
        }
    }

    /// Universal chrome keys must never be shadowed by a tab: `Tab` (tab
    /// switching) and `q` (quit) fall through on *every* tab — including the
    /// tabs that used to bind `Tab` to panel focus.
    #[test]
    fn universal_keys_are_never_consumed_by_a_tab() {
        for tab in [
            TabKind::Components,
            TabKind::Licenses,
            TabKind::SideBySide,
            TabKind::Vulnerabilities,
            TabKind::Dependencies,
            TabKind::Source,
            TabKind::Quality,
            TabKind::Compliance,
            TabKind::GraphChanges,
        ] {
            assert!(
                !dispatch_tab_key(&mut diff_app(tab), k(KeyCode::Tab)),
                "'Tab' must fall through to global tab-switching on {tab:?}"
            );
            assert!(
                !dispatch_tab_key(&mut diff_app(tab), k(KeyCode::Char('q'))),
                "'q' (quit) must fall through to the global fallback on {tab:?}"
            );
        }
    }

    /// End-to-end through the real dispatcher: the global fallback applies only
    /// to keys the active tab did not consume.
    #[test]
    fn global_fallback_only_fires_for_unconsumed_keys() {
        // '1' on Components toggles a filter, so the global tab-select must NOT
        // fire and the tab stays put.
        let mut app = diff_app(TabKind::Components);
        handle_key_event(&mut app, k(KeyCode::Char('1')));
        assert_eq!(
            app.active_tab,
            TabKind::Components,
            "'1' on Components toggles a filter; the global tab-select must not fire"
        );

        // '/' on SideBySide opens the tab-local search, not the global overlay.
        let mut app = diff_app(TabKind::SideBySide);
        handle_key_event(&mut app, k(KeyCode::Char('/')));
        assert!(
            !app.overlays.search.active,
            "SideBySide '/' must not open the global search overlay"
        );
        assert!(
            app.side_by_side_state().search_active,
            "SideBySide '/' activates the tab-local search"
        );

        // 'Tab' switches tabs from Components (the view no longer steals it).
        let mut app = diff_app(TabKind::Components);
        handle_key_event(&mut app, k(KeyCode::Tab));
        assert_ne!(
            app.active_tab,
            TabKind::Components,
            "Tab must switch tabs from Components, not toggle panel focus"
        );
    }
}
