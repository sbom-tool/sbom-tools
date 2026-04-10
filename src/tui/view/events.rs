//! Event handling for the `ViewApp`.

use super::app::{ComponentDetailTab, FocusPanel, ViewApp, ViewTab};
use super::views::resolve_source_reference;
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

/// Action for Enter key on Source tab (computed before borrow to avoid borrow conflicts).
enum SourceEnterAction {
    ToggleExpand(String),
    Link(super::views::SourceLink),
}

/// Determine the Enter action for the Source tab, handling both tree and raw modes.
fn source_enter_action(app: &ViewApp) -> Option<SourceEnterAction> {
    match app.source_state.view_mode {
        SourceViewMode::Tree => {
            let item = app
                .source_state
                .cached_flat_items
                .get(app.source_state.selected)?;
            // Try cross-tab link first (works for both leaf refs AND expandable components)
            if let Some(link) = resolve_source_reference(item, &app.sbom) {
                // For expandable items that resolve (component/vuln objects), navigate
                // For leaf refs, navigate
                return Some(SourceEnterAction::Link(link));
            }
            // Expandable but not a navigable object → toggle expand
            if item.is_expandable {
                return Some(SourceEnterAction::ToggleExpand(item.node_id.clone()));
            }
            None
        }
        SourceViewMode::Raw => {
            // Bridge raw line → tree node via raw_line_node_ids mapping
            let node_id = app
                .source_state
                .raw_line_node_ids
                .get(app.source_state.selected)
                .filter(|nid| !nid.is_empty())?;
            // Find the matching FlatJsonItem by node_id
            let item = app
                .source_state
                .cached_flat_items
                .iter()
                .find(|i| i.node_id == *node_id)?;
            resolve_source_reference(item, &app.sbom).map(SourceEnterAction::Link)
        }
    }
}

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
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.source_state.toggle_search_regex();
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
            KeyCode::Up | KeyCode::Char('k') => {
                app.component_detail_scroll = app.component_detail_scroll.saturating_sub(1);
                return;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.component_detail_scroll = app.component_detail_scroll.saturating_add(1);
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
                    app.focus_panel = FocusPanel::Left;
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
            prefs.theme = theme_name.parse().unwrap_or_default();
            let _ = prefs.save();
        }
        KeyCode::Char('P') => {
            // Toggle BOM profile (SBOM <-> CBOM) and re-score
            app.bom_profile = match app.bom_profile {
                crate::model::BomProfile::Sbom => crate::model::BomProfile::Cbom,
                crate::model::BomProfile::Cbom => crate::model::BomProfile::Sbom,
            };
            let scoring_profile = match app.bom_profile {
                crate::model::BomProfile::Cbom => crate::quality::ScoringProfile::Cbom,
                crate::model::BomProfile::Sbom => crate::quality::ScoringProfile::Standard,
            };
            let scorer = crate::quality::QualityScorer::new(scoring_profile);
            app.quality_report = scorer.score(&app.sbom);
            app.active_tab = ViewTab::Overview;
            app.status_message = Some(format!("Switched to {} mode", app.bom_profile.label()));
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
        // Number keys 1-9: positional tab selection based on profile
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as usize) - ('1' as usize);
            let tabs = ViewTab::tabs_for_profile(app.bom_profile);
            if let Some(&tab) = tabs.get(idx) {
                app.select_tab(tab);
            }
        }

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
            if app.active_tab == ViewTab::Source {
                app.source_state.ensure_flat_cache();
                // Resolve the current item — works for both tree and raw mode
                let action = source_enter_action(app);
                match action {
                    Some(SourceEnterAction::ToggleExpand(node_id)) => {
                        app.source_state.toggle_expand(&node_id);
                    }
                    Some(SourceEnterAction::Link(link)) => {
                        app.navigation_ctx.push_breadcrumb(
                            ViewTab::Source,
                            link.display_label.clone(),
                            app.source_state.selected,
                        );
                        match link.tab {
                            ViewTab::Tree => {
                                app.selected_component = Some(link.entity_id.clone());
                                app.component_tab = ComponentDetailTab::Overview;
                                app.focus_panel = FocusPanel::Right;
                                app.jump_to_component_in_tree(&link.entity_id);
                            }
                            ViewTab::Vulnerabilities => {
                                app.jump_to_vuln_by_id(&link.entity_id);
                            }
                            _ => {}
                        }
                        app.active_tab = link.tab;
                        app.set_status_message(format!(
                            "\u{2192} {} (Backspace to return)",
                            link.display_label
                        ));
                    }
                    None => {}
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
        KeyCode::Char('p') if app.active_tab == ViewTab::Vulnerabilities => {
            // Previous affected component for multi-component vulns
            if let Some(cache) = &app.vuln_state.cached_data.clone() {
                if let Some(vuln) = app.vuln_state.get_selected_vuln_row(cache) {
                    let total = vuln.affected_component_ids.len();
                    if total > 1 {
                        let new_idx = if app.vuln_state.inspect_component_idx == 0 {
                            total - 1
                        } else {
                            app.vuln_state.inspect_component_idx - 1
                        };
                        app.vuln_state.inspect_component_idx = new_idx;
                        let comp_name = vuln
                            .affected_components
                            .get(new_idx)
                            .map(|s| s.as_str())
                            .unwrap_or("?");
                        app.set_status_message(format!(
                            "Component {}/{total}: {comp_name}",
                            new_idx + 1
                        ));
                    } else {
                        app.toggle_focus();
                    }
                } else {
                    app.toggle_focus();
                }
            } else {
                app.toggle_focus();
            }
        }
        KeyCode::Char('p') => {
            app.toggle_focus();
        }

        // View-specific
        KeyCode::Char('g') => match app.active_tab {
            ViewTab::Tree => app.toggle_tree_grouping(),
            ViewTab::Vulnerabilities => app.vuln_state.toggle_group(),
            ViewTab::Licenses => app.license_state.toggle_group(),
            ViewTab::Compliance => app.compliance_state.toggle_grouped(),
            _ => {}
        },
        // Scroll component list in License details / Dependency stats / Compliance affected (K/J)
        KeyCode::Char('K') => match app.active_tab {
            ViewTab::Licenses => app.license_state.scroll_components_up(),
            ViewTab::Dependencies => {
                app.dependency_state.detail_scroll =
                    app.dependency_state.detail_scroll.saturating_sub(1);
            }
            ViewTab::Compliance => app.compliance_state.affected_scroll_up(),
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
            ViewTab::Compliance => {
                // Max lines is approximate — the panel will clamp
                app.compliance_state.affected_scroll_down(500);
            }
            _ => {}
        },
        KeyCode::Char('m') => {
            if app.active_tab == ViewTab::Source {
                app.source_state.toggle_bookmark();
            } else if app.active_tab == ViewTab::Tree {
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
            ViewTab::Source => {
                if app.source_state.view_mode == SourceViewMode::Tree {
                    app.source_state.cycle_filter_type();
                }
            }
            _ => {}
        },
        KeyCode::Char('s') => match app.active_tab {
            ViewTab::Vulnerabilities => app.vuln_state.toggle_sort(),
            ViewTab::Algorithms => {
                app.algorithm_sort_by = app.algorithm_sort_by.next();
            }
            _ => {}
        },
        KeyCode::Char('d') => {
            if app.active_tab == ViewTab::Vulnerabilities {
                app.vuln_state.toggle_deduplicate();
            }
        }
        KeyCode::Char('i') if app.active_tab == ViewTab::Vulnerabilities => {
            // Inspect: jump to component in Tree tab (same as Enter on a Vuln item)
            if let Some(cache) = &app.vuln_state.cached_data.clone()
                && let Some((comp_id, vuln_id)) = app.vuln_state.get_nav_component_id(cache)
            {
                app.navigation_ctx.push_breadcrumb(
                    ViewTab::Vulnerabilities,
                    vuln_id.clone(),
                    app.vuln_state.selected,
                );
                app.selected_component = Some(comp_id.clone());
                app.component_tab = ComponentDetailTab::Overview;
                app.active_tab = ViewTab::Tree;
                app.focus_panel = FocusPanel::Right;
                app.jump_to_component_in_tree(&comp_id);
                let vuln = app.vuln_state.get_selected_vuln_row(cache);
                let total = vuln.map_or(1, |v| v.affected_component_ids.len());
                let idx = app.vuln_state.inspect_component_idx + 1;
                if total > 1 {
                    app.set_status_message(format!(
                        "→ {vuln_id} [{idx}/{total}] (Backspace to return, [n]/[p] to cycle)"
                    ));
                } else {
                    app.set_status_message(format!("→ {vuln_id} (Backspace to return)"));
                }
            }
        }
        KeyCode::Char('n') if app.active_tab == ViewTab::Vulnerabilities => {
            // Next affected component for multi-component vulns
            if let Some(cache) = &app.vuln_state.cached_data.clone()
                && let Some(vuln) = app.vuln_state.get_selected_vuln_row(cache)
            {
                let total = vuln.affected_component_ids.len();
                if total > 1 {
                    let new_idx = (app.vuln_state.inspect_component_idx + 1) % total;
                    app.vuln_state.inspect_component_idx = new_idx;
                    let comp_name = vuln
                        .affected_components
                        .get(new_idx)
                        .map(|s| s.as_str())
                        .unwrap_or("?");
                    app.set_status_message(format!(
                        "Component {}/{total}: {comp_name}",
                        new_idx + 1
                    ));
                }
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
        // Reverse navigation: jump to Source tab for the selected entity
        KeyCode::Char('S')
            if matches!(
                app.active_tab,
                ViewTab::Tree | ViewTab::Vulnerabilities | ViewTab::Dependencies
            ) =>
        {
            let ref_value = match app.active_tab {
                ViewTab::Tree => app.selected_component.as_ref().and_then(|comp_id| {
                    app.sbom
                        .components
                        .iter()
                        .find(|(id, _)| id.value() == comp_id)
                        .map(|(_, c)| (c.identifiers.format_id.clone(), comp_id.clone()))
                }),
                ViewTab::Vulnerabilities => app
                    .vuln_state
                    .cached_data
                    .as_ref()
                    .and_then(|cache| app.vuln_state.get_selected_vuln_row(cache))
                    .map(|v| (v.vuln_id.clone(), v.vuln_id.clone())),
                ViewTab::Dependencies => app.get_selected_dependency_node_id().and_then(|nid| {
                    app.sbom
                        .components
                        .iter()
                        .find(|(id, _)| id.value() == nid)
                        .map(|(_, c)| (c.identifiers.format_id.clone(), nid))
                }),
                _ => None,
            };
            if let Some((format_id, label)) = ref_value {
                let sel_index = match app.active_tab {
                    ViewTab::Tree => app.tree_state.selected,
                    ViewTab::Vulnerabilities => app.vuln_state.selected,
                    ViewTab::Dependencies => app.dependency_state.selected,
                    _ => 0,
                };
                if let Some(source_idx) = app.find_source_item_for_ref(&format_id) {
                    app.navigation_ctx
                        .push_breadcrumb(app.active_tab, label.clone(), sel_index);
                    app.source_state.selected = source_idx;
                    app.source_state.view_mode = SourceViewMode::Tree;
                    // Ensure the item is visible by adjusting scroll
                    if source_idx < app.source_state.scroll_offset
                        || source_idx
                            >= app.source_state.scroll_offset + app.source_state.viewport_height
                    {
                        app.source_state.scroll_offset =
                            source_idx.saturating_sub(app.source_state.viewport_height / 3);
                    }
                    app.active_tab = ViewTab::Source;
                    app.set_status_message(format!("Source: {label} (Backspace to return)"));
                } else {
                    app.set_status_message("Reference not found in source".to_string());
                }
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
        // Source: Line numbers toggle
        KeyCode::Char('I') if app.active_tab == ViewTab::Source => {
            app.source_state.toggle_line_numbers();
        }
        // Source: Word wrap toggle (raw mode only)
        KeyCode::Char('W') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Raw {
                app.source_state.toggle_word_wrap();
            }
        }
        // Source: Next bookmark
        KeyCode::Char('\'') if app.active_tab == ViewTab::Source => {
            app.source_state.next_bookmark();
        }
        // Source: Copy JSON path
        KeyCode::Char('c') if app.active_tab == ViewTab::Source => {
            app.source_state.ensure_flat_cache();
            if let Some(item) = app
                .source_state
                .cached_flat_items
                .get(app.source_state.selected)
            {
                let path = item.node_id.clone();
                if crate::tui::clipboard::copy_to_clipboard(&path) {
                    app.set_status_message(format!("Copied path: {path}"));
                }
            }
        }
        // Source: Export content
        KeyCode::Char('E') if app.active_tab == ViewTab::Source => {
            let content = app.source_state.get_full_content();
            let result = crate::tui::export::export_source_content(&content, "source");
            app.set_status_message(result.message);
        }
        // Source: Sort cycle (tree mode only)
        KeyCode::Char('S') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Tree {
                app.source_state.cycle_sort();
            }
        }
        // Source: Toggle fold at current line (raw mode)
        KeyCode::Char('z') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Raw {
                app.source_state.toggle_fold();
            }
        }
        // Source: Fold all top-level / Unfold all (raw mode)
        KeyCode::Char('Z') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Raw {
                if app.source_state.folded_lines.is_empty() {
                    app.source_state.fold_all_top_level();
                } else {
                    app.source_state.unfold_all();
                }
            }
        }
        // Source: Jump to matching bracket (raw mode)
        KeyCode::Char('%') if app.active_tab == ViewTab::Source => {
            if app.source_state.view_mode == SourceViewMode::Raw {
                app.source_state.jump_to_matching_bracket();
            }
        }
        // Source: Toggle indent guides
        KeyCode::Char('|') if app.active_tab == ViewTab::Source => {
            app.source_state.show_indent_guides = !app.source_state.show_indent_guides;
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
        KeyCode::Char('E') if app.active_tab == ViewTab::Vulnerabilities => {
            // Expand all vuln groups — use cached display items
            let labels: Vec<String> = app
                .vuln_state
                .cached_display_items
                .iter()
                .filter_map(|item| match item {
                    super::views::VulnDisplayItem::GroupHeader { label, .. } => Some(label.clone()),
                    _ => None,
                })
                .collect();
            app.vuln_state.expand_all_groups(&labels);
            // Rebuild to reveal sub-groups, then expand those too
            app.vuln_state.rebuild_display_items();
            let sub_labels: Vec<String> = app
                .vuln_state
                .cached_display_items
                .iter()
                .filter_map(|item| match item {
                    super::views::VulnDisplayItem::SubGroupHeader {
                        parent_label,
                        label,
                        ..
                    } => Some(format!("{parent_label}::{label}")),
                    _ => None,
                })
                .collect();
            if !sub_labels.is_empty() {
                app.vuln_state.expand_all_groups(&sub_labels);
                app.vuln_state.rebuild_display_items();
            }
        }
        KeyCode::Char('C') if app.active_tab == ViewTab::Vulnerabilities => {
            // Collapse all vuln groups
            app.vuln_state.collapse_all_groups();
            app.vuln_state.rebuild_display_items();
            // Move selection to nearest group header
            if let Some(pos) =
                app.vuln_state.cached_display_items.iter().position(|item| {
                    matches!(item, super::views::VulnDisplayItem::GroupHeader { .. })
                })
            {
                app.vuln_state.selected = pos;
            }
        }
        KeyCode::Tab if app.active_tab == ViewTab::Vulnerabilities => {
            // Jump to next group header — use cached display items
            app.vuln_state.jump_next_group_cached();
        }
        KeyCode::BackTab if app.active_tab == ViewTab::Vulnerabilities => {
            // Jump to previous group header — use cached display items
            app.vuln_state.jump_prev_group_cached();
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
    flatten_tree_ids(nodes, &app.tree_state, &mut flat_items);

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
                        app.focus_panel = FocusPanel::Left;
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
            if app.active_tab == ViewTab::Source {
                app.source_state.select_next();
            } else {
                app.navigate_down();
            }
        }
        MouseEventKind::ScrollUp => {
            if app.active_tab == ViewTab::Source {
                app.source_state.select_prev();
            } else {
                app.navigate_up();
            }
        }
        _ => {}
    }
}

/// Handle click on tab bar
fn handle_tab_click(app: &mut ViewApp, x: u16) {
    // Tab labels matching view/ui.rs render_tabs (format: "[N] Title " + " | " separator)
    let tab_labels: &[(&str, ViewTab)] = &[
        ("Overview", ViewTab::Overview),
        ("Components", ViewTab::Tree),
        ("Vulnerabilities", ViewTab::Vulnerabilities),
        ("Licenses", ViewTab::Licenses),
        ("Dependencies", ViewTab::Dependencies),
        ("Quality", ViewTab::Quality),
        ("Compliance", ViewTab::Compliance),
        ("Source", ViewTab::Source),
    ];

    // Compute cumulative positions: each tab is "[N] Title " (4 + title.len + 1) + 3 for separator
    let mut pos: u16 = 0;
    for (label, tab) in tab_labels {
        let width = 4 + label.len() as u16 + 1; // "[N] " + title + " "
        if x >= pos && x < pos + width {
            app.select_tab(*tab);
            return;
        }
        pos += width + 3; // " | " separator
    }
}

/// Handle click on list items
fn handle_list_click(app: &mut ViewApp, clicked_index: usize, _x: u16) {
    match app.active_tab {
        ViewTab::Tree => {
            // For tree view, just select the item
            let nodes = app.build_tree_nodes();
            let mut flat_count = 0;
            count_visible_tree_nodes(nodes, &app.tree_state, &mut flat_count);
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
        ViewTab::Source => {
            let max = match app.source_state.view_mode {
                SourceViewMode::Tree => {
                    app.source_state.ensure_flat_cache();
                    app.source_state.cached_flat_items.len()
                }
                SourceViewMode::Raw => app.source_state.raw_lines.len(),
            };
            let idx = app.source_state.scroll_offset + clicked_index;
            if idx < max {
                app.source_state.selected = idx;
            }
        }
        ViewTab::Overview | ViewTab::PqcCompliance => {
            // No list navigation
        }
        ViewTab::Crypto
        | ViewTab::Algorithms
        | ViewTab::Certificates
        | ViewTab::Keys
        | ViewTab::Protocols => {
            let max = app.crypto_count_for_tab();
            if clicked_index < max {
                *app.active_crypto_selected_mut() = clicked_index;
            }
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
            if app.compliance_state.grouped {
                let groups =
                    super::views::build_groups(result, app.compliance_state.severity_filter);
                groups
                    .get(app.compliance_state.selected_violation)
                    .map(|g| format!("{} ({})", g.pattern, g.violations.len()))
            } else {
                let violations: Vec<_> = result
                    .violations
                    .iter()
                    .filter(|v| app.compliance_state.severity_filter.matches(v.severity))
                    .collect();
                violations
                    .get(app.compliance_state.selected_violation)
                    .map(|v| v.message.clone())
            }
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
        ViewTab::Crypto
        | ViewTab::Algorithms
        | ViewTab::Certificates
        | ViewTab::Keys
        | ViewTab::Protocols => {
            let crypto_components: Vec<_> = app
                .sbom
                .components
                .values()
                .filter(|c| c.component_type == crate::model::ComponentType::Cryptographic)
                .collect();
            let selected = app
                .active_crypto_selected()
                .min(crypto_components.len().saturating_sub(1));
            crypto_components.get(selected).map(|c| c.name.clone())
        }
        ViewTab::PqcCompliance => None,
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
