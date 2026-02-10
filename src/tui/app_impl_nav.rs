//! Navigation-related methods for App.

use super::app::{App, AppMode, TabKind};
use super::app_states::ComponentFilter;
use super::state::ListNavigation;

impl App {
    /// Switch to next tab
    pub fn next_tab(&mut self) {
        let has_graph_changes = self
            .data.diff_result
            .as_ref()
            .is_some_and(|r| !r.graph_changes.is_empty());

        self.active_tab = match self.active_tab {
            TabKind::Summary => TabKind::Components,
            TabKind::Components => TabKind::Dependencies,
            TabKind::Dependencies => TabKind::Licenses,
            TabKind::Licenses => TabKind::Vulnerabilities,
            TabKind::Vulnerabilities => TabKind::Quality,
            TabKind::Quality => {
                if self.mode == AppMode::Diff {
                    TabKind::Compliance
                } else {
                    TabKind::Summary
                }
            }
            TabKind::Compliance => TabKind::SideBySide,
            TabKind::SideBySide => {
                if has_graph_changes {
                    TabKind::GraphChanges
                } else {
                    TabKind::Source
                }
            }
            TabKind::GraphChanges => TabKind::Source,
            TabKind::Source => TabKind::Summary,
        };
    }

    /// Switch to previous tab
    pub fn prev_tab(&mut self) {
        let has_graph_changes = self
            .data.diff_result
            .as_ref()
            .is_some_and(|r| !r.graph_changes.is_empty());

        self.active_tab = match self.active_tab {
            TabKind::Summary => {
                if self.mode == AppMode::Diff {
                    TabKind::Source
                } else {
                    TabKind::Quality
                }
            }
            TabKind::Components => TabKind::Summary,
            TabKind::Dependencies => TabKind::Components,
            TabKind::Licenses => TabKind::Dependencies,
            TabKind::Vulnerabilities => TabKind::Licenses,
            TabKind::Quality => TabKind::Vulnerabilities,
            TabKind::Compliance => TabKind::Quality,
            TabKind::SideBySide => TabKind::Compliance,
            TabKind::GraphChanges => TabKind::SideBySide,
            TabKind::Source => {
                if has_graph_changes {
                    TabKind::GraphChanges
                } else {
                    TabKind::SideBySide
                }
            }
        };
    }

    /// Select a specific tab
    pub const fn select_tab(&mut self, tab: TabKind) {
        self.active_tab = tab;
    }

    /// Move selection up
    pub fn select_up(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.select_prev(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.select_prev(),
            TabKind::Licenses => self.tabs.licenses.select_prev(),
            TabKind::Source => self.tabs.source.select_prev(),
            _ => {}
        }
    }

    /// Move selection down
    pub fn select_down(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.select_next(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.select_next(),
            TabKind::Licenses => self.tabs.licenses.select_next(),
            TabKind::Source => self.tabs.source.select_next(),
            _ => {}
        }
    }

    /// Move selection to first item
    pub fn select_first(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.go_first(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.go_first(),
            TabKind::Licenses => self.tabs.licenses.go_first(),
            TabKind::Source => self.tabs.source.select_first(),
            _ => {}
        }
    }

    /// Move selection to last item
    pub fn select_last(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.go_last(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.go_last(),
            TabKind::Source => self.tabs.source.select_last(),
            _ => {}
        }
    }

    /// Page up
    pub fn page_up(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.page_up(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.page_up(),
            TabKind::Source => self.tabs.source.page_up(),
            _ => {}
        }
    }

    /// Page down
    pub fn page_down(&mut self) {
        match self.active_tab {
            TabKind::Components => self.tabs.components.page_down(),
            TabKind::Vulnerabilities => self.tabs.vulnerabilities.page_down(),
            TabKind::Source => self.tabs.source.page_down(),
            _ => {}
        }
    }

    // ========================================================================
    // Cross-view Navigation
    // ========================================================================

    /// Navigate from vulnerability to the affected component
    pub fn navigate_vuln_to_component(&mut self, vuln_id: &str, component_name: &str) {
        // Save current position as breadcrumb
        self.navigation_ctx.push_breadcrumb(
            TabKind::Vulnerabilities,
            vuln_id.to_string(),
            self.tabs.vulnerabilities.selected,
        );

        // Set target and switch to components tab
        self.navigation_ctx.target_component = Some(component_name.to_string());
        self.active_tab = TabKind::Components;

        // Try to find and select the component
        self.find_and_select_component(component_name);
    }

    /// Navigate from dependency to the component
    pub fn navigate_dep_to_component(&mut self, dep_name: &str) {
        let dep_name = dep_name
            .split_once(":+:")
            .map(|(_, dep)| dep)
            .or_else(|| dep_name.split_once(":-:").map(|(_, dep)| dep))
            .unwrap_or(dep_name);

        if dep_name.starts_with("__") {
            return;
        }

        // Save current position as breadcrumb
        self.navigation_ctx.push_breadcrumb(
            TabKind::Dependencies,
            dep_name.to_string(),
            self.tabs.dependencies.selected,
        );

        // Set target and switch to components tab
        self.navigation_ctx.target_component = Some(dep_name.to_string());
        self.active_tab = TabKind::Components;

        // Try to find and select the component
        self.find_and_select_component(dep_name);
    }

    /// Navigate back using breadcrumbs
    pub fn navigate_back(&mut self) -> bool {
        if let Some(breadcrumb) = self.navigation_ctx.pop_breadcrumb() {
            self.active_tab = breadcrumb.tab;

            // Restore selection based on the tab we're returning to
            match breadcrumb.tab {
                TabKind::Vulnerabilities => {
                    self.tabs.vulnerabilities.selected = breadcrumb.selection_index;
                }
                TabKind::Components => {
                    self.tabs.components.selected = breadcrumb.selection_index;
                }
                TabKind::Dependencies => {
                    self.tabs.dependencies.selected = breadcrumb.selection_index;
                }
                TabKind::Licenses => {
                    self.tabs.licenses.selected = breadcrumb.selection_index;
                }
                TabKind::Source => {
                    self.tabs.source.active_panel_mut().selected = breadcrumb.selection_index;
                }
                _ => {}
            }

            self.navigation_ctx.clear_targets();
            true
        } else {
            false
        }
    }

    /// Find and select a component by name in the current view
    pub(super) fn find_and_select_component(&mut self, name: &str) {
        if self.data.diff_result.is_some() {
            // Reset filter to All to ensure we can find it
            self.tabs.components.filter = ComponentFilter::All;

            let name_lower = name.to_lowercase();
            let index = {
                let items = self.diff_component_items(ComponentFilter::All);
                items
                    .iter()
                    .position(|comp| comp.name.to_lowercase() == name_lower)
            };

            if let Some(index) = index {
                self.tabs.components.selected = index;
            }
        }
    }

    /// Check if we have navigation history
    #[must_use] 
    pub fn has_navigation_history(&self) -> bool {
        self.navigation_ctx.has_history()
    }

    /// Get the breadcrumb trail for display
    #[must_use] 
    pub fn breadcrumb_trail(&self) -> String {
        self.navigation_ctx.breadcrumb_trail()
    }

    /// Navigate to a target tab or item
    pub(super) fn navigate_to_target(&mut self, target: super::traits::TabTarget) {
        use super::traits::TabTarget;

        match target {
            TabTarget::Summary => self.active_tab = TabKind::Summary,
            TabTarget::Components => self.active_tab = TabKind::Components,
            TabTarget::Dependencies => self.active_tab = TabKind::Dependencies,
            TabTarget::Licenses => self.active_tab = TabKind::Licenses,
            TabTarget::Vulnerabilities => self.active_tab = TabKind::Vulnerabilities,
            TabTarget::Quality => self.active_tab = TabKind::Quality,
            TabTarget::Compliance => self.active_tab = TabKind::Compliance,
            TabTarget::SideBySide => self.active_tab = TabKind::SideBySide,
            TabTarget::GraphChanges => self.active_tab = TabKind::GraphChanges,
            TabTarget::Source => self.active_tab = TabKind::Source,
            TabTarget::ComponentByName(name) => {
                self.active_tab = TabKind::Components;
                self.find_and_select_component(&name);
            }
            TabTarget::VulnerabilityById(id) => {
                self.active_tab = TabKind::Vulnerabilities;
                if let Some(idx) = self.find_vulnerability_index(&id) {
                    self.tabs.vulnerabilities.selected = idx;
                }
            }
        }
    }
}
