//! Event handling for the `ViewApp`.

use super::app::{ComponentDetailTab, FocusPanel, ViewApp, ViewTab};
use crate::config::TuiPreferences;
use crate::tui::app_states::SourceViewMode;
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
        thread::spawn(move || {
            loop {
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
            }
        });

        Self { rx, _tx: tx }
    }
}

impl EventHandler {
    pub fn next(&self) -> io::Result<Event> {
        self.rx.recv().map_err(io::Error::other)
    }
}

/// Handle key events for `ViewApp`.
pub fn handle_key_event(app: &mut ViewApp, key: KeyEvent) {
    // Clear any status message on key press
    app.clear_status_message();

    // Ctrl+C copies the selected item (universal shortcut)
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        handle_yank(app);
        return;
    }

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

    // Handle vulnerability-local search input
    if app.active_tab == ViewTab::Vulnerabilities && app.vuln_state.search_active {
        match key.code {
            KeyCode::Esc => {
                app.vuln_state.clear_vuln_search();
            }
            KeyCode::Enter => {
                app.vuln_state.stop_vuln_search();
            }
            KeyCode::Backspace => {
                app.vuln_state.search_pop();
            }
            KeyCode::Char(c) => {
                app.vuln_state.search_push(c);
            }
            _ => {}
        }
        return;
    }

    // Handle dependency search input
    if app.active_tab == ViewTab::Dependencies && app.dependency_state.search_active {
        match key.code {
            KeyCode::Esc => {
                app.dependency_state.clear_search();
            }
            KeyCode::Enter => {
                app.dependency_state.stop_search();
            }
            KeyCode::Backspace => {
                app.dependency_state.search_pop();
            }
            KeyCode::Char(c) => {
                app.dependency_state.search_push(c);
            }
            _ => {}
        }
        return;
    }

    // Handle tree search input
    if app.active_tab == ViewTab::Tree && app.tree_search_active {
        match key.code {
            KeyCode::Esc => {
                app.clear_tree_search();
            }
            KeyCode::Enter => {
                app.stop_tree_search();
            }
            KeyCode::Backspace => {
                app.tree_search_pop_char();
            }
            KeyCode::Char(c) => {
                app.tree_search_push_char(c);
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
            KeyCode::Char('j' | 's' | 'm' | 'h' | 'c') if app.show_export => {
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

    // Handle Vulnerabilities detail panel scrolling when right panel is focused
    if app.focus_panel == FocusPanel::Right && app.active_tab == ViewTab::Vulnerabilities {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                app.vuln_state.detail_scroll_up();
                return;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.vuln_state.detail_scroll_down();
                return;
            }
            KeyCode::Char('p') => {
                app.toggle_focus();
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
            // Save last active tab before quitting
            let mut prefs = TuiPreferences::load();
            prefs.last_view_tab = Some(app.active_tab.as_str().to_string());
            let _ = prefs.save();
            app.should_quit = true;
        }
        KeyCode::Char('?') => {
            app.toggle_help();
        }
        KeyCode::Char('/') => {
            if app.active_tab == ViewTab::Source {
                app.source_state.start_search();
            } else if app.active_tab == ViewTab::Tree {
                app.start_tree_search();
            } else if app.active_tab == ViewTab::Vulnerabilities {
                app.vuln_state.start_vuln_search();
            } else if app.active_tab == ViewTab::Dependencies {
                app.dependency_state.start_search();
            } else {
                app.start_search();
            }
        }
        KeyCode::Char('e') => {
            if app.active_tab == ViewTab::Dependencies {
                // Expand all dependency nodes
                let all_ids: Vec<String> = app
                    .sbom
                    .components
                    .keys()
                    .map(|id| id.value().to_string())
                    .collect();
                app.dependency_state.expand_all(&all_ids);
            } else {
                app.toggle_export();
            }
        }
        KeyCode::Char('l') => {
            app.toggle_legend();
        }
        KeyCode::Char('T') => {
            // Toggle theme (dark -> light -> high-contrast) and save preference
            let theme_name = toggle_theme();
            let mut prefs = TuiPreferences::load();
            prefs.theme = theme_name.to_string();
            let _ = prefs.save();
        }
        KeyCode::Char('b') | KeyCode::Backspace => {
            // Navigate back using breadcrumb history
            if app.navigation_ctx.has_history() {
                app.go_back();
            }
        }
        KeyCode::Char('y') => {
            handle_yank(app);
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
            if app.active_tab == ViewTab::Source
                && app.source_state.view_mode == SourceViewMode::Tree
            {
                app.source_state.ensure_flat_cache();
                if let Some(item) = app
                    .source_state
                    .cached_flat_items
                    .get(app.source_state.selected)
                    && item.is_expandable
                {
                    let node_id = item.node_id.clone();
                    app.source_state.toggle_expand(&node_id);
                }
            } else {
                app.handle_enter();
            }
        }
        KeyCode::Char(' ') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Tree {
                app.source_state.ensure_flat_cache();
                if let Some(item) = app
                    .source_state
                    .cached_flat_items
                    .get(app.source_state.selected)
                    && item.is_expandable
                {
                    let node_id = item.node_id.clone();
                    app.source_state.toggle_expand(&node_id);
                }
            }
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
        // Scroll component list in License details / Dependency stats (K/J)
        KeyCode::Char('K') => match app.active_tab {
            ViewTab::Licenses => app.license_state.scroll_components_up(),
            ViewTab::Dependencies => {
                app.dependency_state.detail_scroll =
                    app.dependency_state.detail_scroll.saturating_sub(1);
            }
            _ => {}
        },
        KeyCode::Char('J') => match app.active_tab {
            ViewTab::Licenses => {
                app.license_state
                    .scroll_components_down(crate::tui::constants::PAGE_SIZE);
            }
            ViewTab::Dependencies => {
                app.dependency_state.detail_scroll += 1;
            }
            _ => {}
        },
        KeyCode::Char('m') => {
            if app.active_tab == ViewTab::Tree {
                app.toggle_bookmark();
            }
        }
        KeyCode::Char('f') => match app.active_tab {
            ViewTab::Tree => app.toggle_tree_filter(),
            ViewTab::Vulnerabilities => app.vuln_state.toggle_filter(),
            ViewTab::Compliance => {
                app.compliance_state.severity_filter = app.compliance_state.severity_filter.next();
                app.compliance_state.selected_violation = 0;
                app.compliance_state.scroll_offset = 0;
            }
            _ => {}
        },
        KeyCode::Char('s') => {
            if app.active_tab == ViewTab::Vulnerabilities {
                app.vuln_state.toggle_sort();
            }
        }
        KeyCode::Char('d') => {
            if app.active_tab == ViewTab::Vulnerabilities {
                app.vuln_state.toggle_deduplicate();
            }
        }
        KeyCode::Char('c') if app.active_tab == ViewTab::Dependencies => {
            // Jump to selected dependency's component in the Tree tab
            if let Some(node_id) = app.get_selected_dependency_node_id() {
                app.selected_component = Some(node_id.clone());
                app.active_tab = ViewTab::Tree;
                app.component_tab = ComponentDetailTab::Overview;
                app.focus_panel = FocusPanel::Right;
                app.jump_to_component_in_tree(&node_id);
            }
        }
        KeyCode::Char('w') if app.active_tab == ViewTab::Source => {
            app.toggle_focus();
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
                    if let Some(node_id) = get_selected_node_id(app)
                        && app.tree_state.is_expanded(&node_id)
                    {
                        app.tree_state.collapse(&node_id);
                    }
                }
                ViewTab::Dependencies => {
                    // Collapse current dependency node
                    if let Some(node_id) = app.get_selected_dependency_node_id()
                        && app.dependency_state.is_expanded(&node_id)
                    {
                        app.dependency_state.expanded.remove(&node_id);
                    }
                }
                ViewTab::Compliance => {
                    // Switch to previous compliance standard
                    app.compliance_state.prev_standard();
                }
                ViewTab::Source => {
                    if app.source_state.view_mode == SourceViewMode::Raw {
                        app.source_state.scroll_left();
                    } else {
                        app.source_state.ensure_flat_cache();
                        if let Some(item) = app
                            .source_state
                            .cached_flat_items
                            .get(app.source_state.selected)
                            && item.is_expandable
                            && item.is_expanded
                        {
                            let node_id = item.node_id.clone();
                            app.source_state.toggle_expand(&node_id);
                        }
                    }
                }
                _ => {}
            }
        }
        KeyCode::Char('E') if app.active_tab == ViewTab::Dependencies => {
            // Collapse all dependency nodes
            app.dependency_state.collapse_all();
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
                    if app.source_state.view_mode == SourceViewMode::Raw {
                        app.source_state.scroll_right();
                    } else {
                        app.source_state.ensure_flat_cache();
                        if let Some(item) = app
                            .source_state
                            .cached_flat_items
                            .get(app.source_state.selected)
                            && item.is_expandable
                            && !item.is_expanded
                        {
                            let node_id = item.node_id.clone();
                            app.source_state.toggle_expand(&node_id);
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
        // Fold depth presets for Source tab: Shift+1/2/3
        KeyCode::Char('!') if app.active_tab == ViewTab::Source => {
            app.source_state.expand_to_depth(1);
        }
        KeyCode::Char('@') if app.active_tab == ViewTab::Source => {
            app.source_state.expand_to_depth(2);
        }
        KeyCode::Char('#') if app.active_tab == ViewTab::Source => {
            app.source_state.expand_to_depth(3);
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
        if state.is_expanded(node.id())
            && let Some(children) = node.children()
        {
            flatten_tree_ids(children, state, items);
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

    let format = match key.code {
        KeyCode::Esc => {
            app.show_export = false;
            return;
        }
        KeyCode::Char('j') => ExportFormat::Json,
        KeyCode::Char('s') => ExportFormat::Sarif,
        KeyCode::Char('m') => ExportFormat::Markdown,
        KeyCode::Char('h') => ExportFormat::Html,
        KeyCode::Char('c') => ExportFormat::Csv,
        _ => return,
    };

    app.show_export = false;
    if app.active_tab == ViewTab::Compliance {
        app.export_compliance(format);
    } else {
        app.export(format);
    }
}

/// Handle mouse events for `ViewApp`.
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
            let max = app.filtered_compliance_violation_count();
            if clicked_index < max {
                app.compliance_state.selected_violation = clicked_index;
            }
        }
        ViewTab::Source | ViewTab::Overview => {
            // Source uses its own scrolling; Overview has no list navigation
        }
    }
}

/// Get the text that would be copied for the current selection.
///
/// Returns `None` if nothing is selected or the tab has no copyable item.
pub fn get_yank_text(app: &ViewApp) -> Option<String> {
    match app.active_tab {
        ViewTab::Tree | ViewTab::Overview => {
            let comp = app.get_selected_component()?;
            Some(if let Some(ref purl) = comp.identifiers.purl {
                purl.clone()
            } else {
                let ver = comp.version.as_deref().unwrap_or("unknown");
                format!("{}@{ver}", comp.name)
            })
        }
        ViewTab::Vulnerabilities => {
            let (_comp_id, vuln) = app.vuln_state.get_selected(&app.sbom)?;
            Some(vuln.id.clone())
        }
        ViewTab::Dependencies => {
            let node_id = app.get_selected_dependency_node_id()?;
            Some(
                app.sbom
                    .components
                    .iter()
                    .find(|(id, _)| id.value() == node_id)
                    .map_or(node_id, |(_, comp)| comp.name.clone()),
            )
        }
        ViewTab::Licenses => {
            let mut licenses: Vec<String> = Vec::new();
            for comp in app.sbom.components.values() {
                for lic in &comp.licenses.declared {
                    if !licenses.contains(&lic.expression) {
                        licenses.push(lic.expression.clone());
                    }
                }
            }
            licenses.sort();
            licenses.get(app.license_state.selected).cloned()
        }
        ViewTab::Quality => app
            .quality_report
            .recommendations
            .get(app.quality_state.selected_recommendation)
            .map(|rec| rec.message.clone()),
        ViewTab::Compliance => {
            let results = app.compliance_results.as_ref()?;
            let result = results.get(app.compliance_state.selected_standard)?;
            let violations: Vec<_> = result
                .violations
                .iter()
                .filter(|v| app.compliance_state.severity_filter.matches(v.severity))
                .collect();
            violations
                .get(app.compliance_state.selected_violation)
                .map(|v| v.message.clone())
        }
        ViewTab::Source => match app.source_state.view_mode {
            SourceViewMode::Tree => {
                // Need to ensure flat cache is warm — it normally is from rendering
                // but we can't call ensure_flat_cache on an immutable ref.
                // The cache is already warm from the last render, so read directly.
                app.source_state
                    .cached_flat_items
                    .get(app.source_state.selected)
                    .map(|item| {
                        if !item.value_preview.is_empty() {
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
            SourceViewMode::Raw => app
                .source_state
                .raw_lines
                .get(app.source_state.selected)
                .map(|line| line.trim().to_string()),
        },
    }
}

/// Handle `y` / `Ctrl+C` to copy the focused item to clipboard.
fn handle_yank(app: &mut ViewApp) {
    let Some(text) = get_yank_text(app) else {
        if app.active_tab == ViewTab::Source {
            app.set_status_message("Shift+drag to select text, then Cmd/Ctrl+C");
        } else {
            app.set_status_message("Nothing selected to copy");
        }
        return;
    };

    if crate::tui::clipboard::copy_to_clipboard(&text) {
        let display = if text.len() > 50 {
            format!("{}...", &text[..47])
        } else {
            text
        };
        app.set_status_message(format!("Copied: {display}"));
    } else {
        app.set_status_message("Failed to copy to clipboard");
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
        if state.is_expanded(node.id())
            && let Some(children) = node.children()
        {
            count_visible_tree_nodes(children, state, count);
        }
    }
}
