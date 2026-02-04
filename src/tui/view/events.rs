//! Event handling for the ViewApp.

use super::app::{ComponentDetailTab, FocusPanel, ViewApp, ViewTab};
use crate::tui::app_states::SourceViewMode;
use crate::config::TuiPreferences;
use crate::tui::toggle_theme;
use crossterm::event::{
    self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers, MouseEventKind,
};
use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Terminal events.
#[allow(dead_code)]
pub enum Event {
    Key(KeyEvent),
    Mouse(event::MouseEvent),
    Resize(u16, u16),
    Tick,
}

/// Event handler.
pub struct EventHandler {
    rx: mpsc::Receiver<Event>,
    _tx: mpsc::Sender<Event>,
}

impl Default for EventHandler {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let tick_rate = Duration::from_millis(100);

        let event_tx = tx.clone();
        thread::spawn(move || loop {
            if event::poll(tick_rate).unwrap_or(false) {
                match event::read() {
                    Ok(CrosstermEvent::Key(key)) => {
                        if event_tx.send(Event::Key(key)).is_err() {
                            break;
                        }
                    }
                    Ok(CrosstermEvent::Mouse(mouse)) => {
                        if event_tx.send(Event::Mouse(mouse)).is_err() {
                            break;
                        }
                    }
                    Ok(CrosstermEvent::Resize(w, h)) => {
                        if event_tx.send(Event::Resize(w, h)).is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            } else if event_tx.send(Event::Tick).is_err() {
                break;
            }
        });

        Self { rx, _tx: tx }
    }
}

impl EventHandler {
    pub fn next(&self) -> io::Result<Event> {
        self.rx
            .recv()
            .map_err(io::Error::other)
    }
}

/// Handle key events for ViewApp.
pub fn handle_key_event(app: &mut ViewApp, key: KeyEvent) {
    // Clear any status message on key press
    app.clear_status_message();

    // Handle source-local search input
    if app.active_tab == ViewTab::Source && app.source_state.search_active {
        match key.code {
            KeyCode::Esc => {
                app.source_state.stop_search();
                app.source_state.search_query.clear();
                app.source_state.search_matches.clear();
            }
            KeyCode::Enter => {
                app.source_state.stop_search();
            }
            KeyCode::Backspace => {
                app.source_state.search_pop_char();
            }
            KeyCode::Char(c) => {
                app.source_state.search_push_char(c);
            }
            _ => {}
        }
        return;
    }

    // Handle overlays first
    if app.search_state.active {
        handle_search_key(app, key);
        return;
    }

    // Handle overlays consistently - toggle or close with Esc/q
    if app.has_overlay() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.close_overlays(),
            KeyCode::Char('?') if app.show_help => app.toggle_help(),
            KeyCode::Char('e') if app.show_export => app.toggle_export(),
            KeyCode::Char('l') if app.show_legend => app.toggle_legend(),
            // Export format selection
            KeyCode::Char('j') | KeyCode::Char('m') | KeyCode::Char('c') | KeyCode::Char('v')
                if app.show_export =>
            {
                handle_export_key(app, key);
            }
            _ => {} // Ignore other keys when overlay is shown
        }
        return;
    }

    if app.focus_panel == FocusPanel::Right
        && app.selected_component.is_some()
        && app.active_tab == ViewTab::Tree
    {
        match key.code {
            KeyCode::Char('1') => {
                app.select_component_tab(ComponentDetailTab::Overview);
                return;
            }
            KeyCode::Char('2') => {
                app.select_component_tab(ComponentDetailTab::Identifiers);
                return;
            }
            KeyCode::Char('3') => {
                app.select_component_tab(ComponentDetailTab::Vulnerabilities);
                return;
            }
            KeyCode::Char('4') => {
                app.select_component_tab(ComponentDetailTab::Dependencies);
                return;
            }
            _ => {}
        }
    }

    // Handle Source tab map panel navigation when map is focused
    if app.focus_panel == FocusPanel::Right && app.active_tab == ViewTab::Source {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                app.source_state.map_selected = app.source_state.map_selected.saturating_sub(1);
                return;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.source_state.map_selected += 1;
                // Clamping happens in render
                return;
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                app.handle_source_map_enter();
                return;
            }
            KeyCode::Char('p') => {
                app.toggle_focus();
                return;
            }
            KeyCode::Char('t') => {
                // Jump to Tree tab for the component in context footer
                if let Some(comp_id) = app.get_map_context_component_id() {
                    app.selected_component = Some(comp_id.clone());
                    app.active_tab = ViewTab::Tree;
                    app.component_tab = ComponentDetailTab::Overview;
                    app.focus_panel = FocusPanel::Right;
                    app.jump_to_component_in_tree(&comp_id);
                }
                return;
            }
            KeyCode::Char('u') => {
                // Jump to Vulnerabilities tab for the component in context footer
                if let Some(comp_id) = app.get_map_context_component_id() {
                    app.selected_component = Some(comp_id);
                    app.active_tab = ViewTab::Vulnerabilities;
                }
                return;
            }
            _ => {}
        }
    }

    // Global keys
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Char('?') => {
            app.toggle_help();
        }
        KeyCode::Char('/') => {
            if app.active_tab == ViewTab::Source {
                app.source_state.start_search();
            } else {
                app.start_search();
            }
        }
        KeyCode::Char('e') => {
            app.toggle_export();
        }
        KeyCode::Char('l') => {
            app.toggle_legend();
        }
        KeyCode::Char('T') => {
            // Toggle theme (dark -> light -> high-contrast) and save preference
            let theme_name = toggle_theme();
            let prefs = TuiPreferences {
                theme: theme_name.to_string(),
            };
            let _ = prefs.save();
        }
        KeyCode::Char('b') | KeyCode::Backspace => {
            // Navigate back using breadcrumb history
            if app.navigation_ctx.has_history() {
                app.go_back();
            }
        }

        // Tab navigation
        KeyCode::Char('1') => app.select_tab(ViewTab::Overview),
        KeyCode::Char('2') => app.select_tab(ViewTab::Tree),
        KeyCode::Char('3') => app.select_tab(ViewTab::Vulnerabilities),
        KeyCode::Char('4') => app.select_tab(ViewTab::Licenses),
        KeyCode::Char('5') => app.select_tab(ViewTab::Dependencies),
        KeyCode::Char('6') => app.select_tab(ViewTab::Quality),
        KeyCode::Char('7') => app.select_tab(ViewTab::Compliance),
        KeyCode::Char('8') => app.select_tab(ViewTab::Source),

        KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.prev_tab();
        }
        KeyCode::BackTab => {
            app.prev_tab();
        }
        KeyCode::Tab => {
            app.next_tab();
        }

        // View-specific keys
        _ => handle_view_key(app, key),
    }
}

fn handle_view_key(app: &mut ViewApp, key: KeyEvent) {
    // Handle component detail tab switching when right panel is focused
    if app.focus_panel == FocusPanel::Right
        && app.selected_component.is_some()
        && app.active_tab == ViewTab::Tree
    {
        match key.code {
            KeyCode::Char('[') => {
                app.prev_component_tab();
                return;
            }
            KeyCode::Char(']') => {
                app.next_component_tab();
                return;
            }
            // Number keys 1-4 for direct component detail tab selection
            KeyCode::Char('!') => {
                app.select_component_tab(ComponentDetailTab::Overview);
                return;
            }
            KeyCode::Char('@') => {
                app.select_component_tab(ComponentDetailTab::Identifiers);
                return;
            }
            KeyCode::Char('#') => {
                app.select_component_tab(ComponentDetailTab::Vulnerabilities);
                return;
            }
            KeyCode::Char('$') => {
                app.select_component_tab(ComponentDetailTab::Dependencies);
                return;
            }
            _ => {}
        }
    }

    match key.code {
        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.navigate_up();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.navigate_down();
        }
        KeyCode::PageUp => {
            app.page_up();
        }
        KeyCode::PageDown => {
            app.page_down();
        }
        KeyCode::Home => {
            app.go_first();
        }
        KeyCode::End | KeyCode::Char('G') => {
            app.go_last();
        }

        // Actions
        KeyCode::Enter => {
            app.handle_enter();
        }
        // 'l' or Right arrow with Ctrl to toggle focus between panels
        KeyCode::Char('p') => {
            app.toggle_focus();
        }

        // View-specific
        KeyCode::Char('g') => match app.active_tab {
            ViewTab::Tree => app.toggle_tree_grouping(),
            ViewTab::Vulnerabilities => app.vuln_state.toggle_group(),
            ViewTab::Licenses => app.license_state.toggle_group(),
            _ => {}
        },
        // Scroll component list in License details (Ctrl+Up/Down or K/J)
        KeyCode::Char('K') => {
            if app.active_tab == ViewTab::Licenses {
                app.license_state.scroll_components_up();
            }
        }
        KeyCode::Char('J') => {
            if app.active_tab == ViewTab::Licenses {
                // Calculate visible count based on typical panel height
                app.license_state.scroll_components_down(10);
            }
        }
        KeyCode::Char('f') => match app.active_tab {
            ViewTab::Tree => app.toggle_tree_filter(),
            ViewTab::Vulnerabilities => app.vuln_state.toggle_filter(),
            _ => {}
        },
        KeyCode::Char('d') => {
            if app.active_tab == ViewTab::Vulnerabilities {
                app.vuln_state.toggle_deduplicate();
            }
        }
        KeyCode::Char('n') if app.active_tab == ViewTab::Source => {
            app.source_state.next_search_match();
        }
        KeyCode::Char('N') if app.active_tab == ViewTab::Source => {
            app.source_state.prev_search_match();
        }
        KeyCode::Char('v') => {
            if app.active_tab == ViewTab::Quality {
                app.quality_state.toggle_view();
            } else if app.active_tab == ViewTab::Source {
                app.source_state.toggle_view_mode();
            }
        }

        // Left/Right for tree expand/collapse or compliance standard switching
        KeyCode::Left | KeyCode::Char('h') => {
            match app.active_tab {
                ViewTab::Tree => {
                    // Collapse current node or go to parent
                    if let Some(node_id) = get_selected_node_id(app) {
                        if app.tree_state.is_expanded(&node_id) {
                            app.tree_state.collapse(&node_id);
                        }
                    }
                }
                ViewTab::Dependencies => {
                    // Collapse current dependency node
                    if let Some(node_id) = app.get_selected_dependency_node_id() {
                        if app.dependency_state.is_expanded(&node_id) {
                            app.dependency_state.expanded.remove(&node_id);
                        }
                    }
                }
                ViewTab::Compliance => {
                    // Switch to previous compliance standard
                    app.compliance_state.prev_standard();
                }
                ViewTab::Source => {
                    // Collapse current node in tree mode
                    if app.source_state.view_mode == SourceViewMode::Tree {
                        if let Some(ref tree) = app.source_state.json_tree {
                            let mut items = Vec::new();
                            crate::tui::shared::source::flatten_json_tree(
                                tree, "", 0, &app.source_state.expanded, &mut items,
                                true, &[],
                            );
                            if let Some(item) = items.get(app.source_state.selected) {
                                if item.is_expandable && item.is_expanded {
                                    let node_id = item.node_id.clone();
                                    app.source_state.toggle_expand(&node_id);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        KeyCode::Char('E') if app.active_tab == ViewTab::Compliance => {
            // Export compliance results as JSON
            app.export_compliance(crate::tui::export::ExportFormat::Json);
        }
        KeyCode::Right | KeyCode::Char('l') if app.active_tab == ViewTab::Compliance => {
            // Switch to next compliance standard
            app.compliance_state.next_standard();
        }
        KeyCode::Right => {
            match app.active_tab {
                ViewTab::Tree => {
                    // Expand current node
                    if let Some(node_id) = get_selected_node_id(app) {
                        app.tree_state.expand(&node_id);
                    }
                }
                ViewTab::Dependencies => {
                    // Expand current dependency node
                    if let Some(node_id) = app.get_selected_dependency_node_id() {
                        app.dependency_state.expanded.insert(node_id);
                    }
                }
                ViewTab::Source => {
                    // Expand current node in tree mode
                    if app.source_state.view_mode == SourceViewMode::Tree {
                        if let Some(ref tree) = app.source_state.json_tree {
                            let mut items = Vec::new();
                            crate::tui::shared::source::flatten_json_tree(
                                tree, "", 0, &app.source_state.expanded, &mut items,
                                true, &[],
                            );
                            if let Some(item) = items.get(app.source_state.selected) {
                                if item.is_expandable && !item.is_expanded {
                                    let node_id = item.node_id.clone();
                                    app.source_state.toggle_expand(&node_id);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        KeyCode::Char('H') if app.active_tab == ViewTab::Source => {
            app.source_state.collapse_all();
        }
        KeyCode::Char('L') if app.active_tab == ViewTab::Source => {
            app.source_state.expand_all();
        }

        _ => {}
    }
}

fn get_selected_node_id(app: &ViewApp) -> Option<String> {
    let nodes = app.build_tree_nodes();
    let mut flat_items: Vec<String> = Vec::new();
    flatten_tree_ids(&nodes, &app.tree_state, &mut flat_items);

    flat_items.get(app.tree_state.selected).cloned()
}

fn flatten_tree_ids(
    nodes: &[crate::tui::widgets::TreeNode],
    state: &crate::tui::widgets::TreeState,
    items: &mut Vec<String>,
) {
    for node in nodes {
        items.push(node.id().to_string());
        if state.is_expanded(node.id()) {
            if let Some(children) = node.children() {
                flatten_tree_ids(children, state, items);
            }
        }
    }
}

fn handle_search_key(app: &mut ViewApp, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.stop_search();
        }
        KeyCode::Enter => {
            // Jump to selected result
            if let Some(result) = app
                .search_state
                .results
                .get(app.search_state.selected)
                .cloned()
            {
                match result {
                    super::app::SearchResult::Component { id, .. } => {
                        app.selected_component = Some(id.clone());
                        app.active_tab = ViewTab::Tree;
                        app.component_tab = ComponentDetailTab::Overview;
                        app.focus_panel = FocusPanel::Right;
                        app.jump_to_component_in_tree(&id);
                    }
                    super::app::SearchResult::Vulnerability {
                        id: _,
                        component_id,
                        component_name: _,
                        ..
                    } => {
                        // Navigate directly by ID - no name lookup needed
                        app.selected_component = Some(component_id.clone());
                        app.jump_to_component_in_tree(&component_id);
                        app.active_tab = ViewTab::Vulnerabilities;
                    }
                }
                app.stop_search();
            }
        }
        KeyCode::Up => {
            app.search_state.select_prev();
        }
        KeyCode::Down => {
            app.search_state.select_next();
        }
        KeyCode::Backspace => {
            app.search_state.pop_char();
            app.execute_search();
        }
        KeyCode::Char(c) => {
            app.search_state.push_char(c);
            app.execute_search();
        }
        _ => {}
    }
}

fn handle_export_key(app: &mut ViewApp, key: KeyEvent) {
    use crate::tui::export::ExportFormat;

    match key.code {
        KeyCode::Esc => {
            app.show_export = false;
        }
        KeyCode::Char('j') => {
            app.show_export = false;
            app.export(ExportFormat::Json);
        }
        KeyCode::Char('m') => {
            app.show_export = false;
            app.export(ExportFormat::Markdown);
        }
        KeyCode::Char('c') => {
            app.show_export = false;
            app.export(ExportFormat::Csv);
        }
        KeyCode::Char('v') => {
            // 'v' was for "Vulns CSV" - use regular CSV
            app.show_export = false;
            app.export(ExportFormat::Csv);
        }
        _ => {}
    }
}

/// Handle mouse events for ViewApp.
pub fn handle_mouse_event(app: &mut ViewApp, mouse: event::MouseEvent) {
    // Clear status message on any mouse interaction
    app.clear_status_message();

    // If overlay is showing, close on click
    if app.has_overlay() {
        if let MouseEventKind::Down(_) = mouse.kind {
            app.close_overlays();
        }
        return;
    }

    match mouse.kind {
        MouseEventKind::Down(_) => {
            // Handle click on list items
            // The y coordinate after header/tabs is approximately row 3+
            let y = mouse.row;
            let x = mouse.column;

            // Check if click is in tab bar area (typically row 1-2)
            if y <= 2 {
                handle_tab_click(app, x);
                return;
            }

            // Calculate which list item was clicked
            // Assuming list content starts around row 4 (after header + tabs + list header)
            let list_start_row = 4;
            if y >= list_start_row {
                let clicked_index = (y - list_start_row) as usize;
                handle_list_click(app, clicked_index, x);
            }
        }
        MouseEventKind::ScrollDown => {
            app.navigate_down();
        }
        MouseEventKind::ScrollUp => {
            app.navigate_up();
        }
        _ => {}
    }
}

/// Handle click on tab bar
fn handle_tab_click(app: &mut ViewApp, x: u16) {
    // Approximate tab positions based on typical tab widths
    // Each tab is roughly 12-15 chars wide
    let tabs = [
        (0, 12, ViewTab::Overview),         // "1:Overview"
        (12, 26, ViewTab::Tree),            // "2:Components"
        (26, 44, ViewTab::Vulnerabilities), // "3:Vulnerabilities"
        (44, 56, ViewTab::Licenses),        // "4:Licenses"
        (56, 72, ViewTab::Dependencies),    // "5:Dependencies"
        (72, 84, ViewTab::Quality),         // "6:Quality"
    ];

    for (start, end, tab) in tabs {
        if x >= start && x < end {
            app.select_tab(tab);
            return;
        }
    }
}

/// Handle click on list items
fn handle_list_click(app: &mut ViewApp, clicked_index: usize, _x: u16) {
    match app.active_tab {
        ViewTab::Tree => {
            // For tree view, just select the item
            let nodes = app.build_tree_nodes();
            let mut flat_count = 0;
            count_visible_tree_nodes(&nodes, &app.tree_state, &mut flat_count);
            if clicked_index < flat_count {
                app.tree_state.selected = clicked_index;
            }
        }
        ViewTab::Vulnerabilities => {
            if clicked_index < app.vuln_state.total {
                app.vuln_state.selected = clicked_index;
            }
        }
        ViewTab::Licenses => {
            if clicked_index < app.license_state.total {
                app.license_state.selected = clicked_index;
                app.license_state.reset_component_scroll();
            }
        }
        ViewTab::Dependencies => {
            if clicked_index < app.dependency_state.total {
                app.dependency_state.selected = clicked_index;
            }
        }
        ViewTab::Quality => {
            if clicked_index < app.quality_state.total_recommendations {
                app.quality_state.selected_recommendation = clicked_index;
            }
        }
        ViewTab::Compliance => {
            app.ensure_compliance_results();
            let max = app.compliance_results.as_ref()
                .and_then(|r| r.get(app.compliance_state.selected_standard))
                .map(|r| r.violations.len())
                .unwrap_or(0);
            if clicked_index < max {
                app.compliance_state.selected_violation = clicked_index;
            }
        }
        ViewTab::Source => {
            // Source tab uses its own scrolling
        }
        ViewTab::Overview => {
            // Overview doesn't have list navigation
        }
    }
}

/// Count visible tree nodes for click handling
fn count_visible_tree_nodes(
    nodes: &[crate::tui::widgets::TreeNode],
    state: &crate::tui::widgets::TreeState,
    count: &mut usize,
) {
    for node in nodes {
        *count += 1;
        if state.is_expanded(node.id()) {
            if let Some(children) = node.children() {
                count_visible_tree_nodes(children, state, count);
            }
        }
    }
}
