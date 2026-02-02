//! Search-related methods for App.

use super::app::{App, TabKind};
use super::app_states::{
    ChangeType, ComponentFilter, DiffSearchResult, VulnChangeType, VulnFilter, VulnSort,
};

impl App {
    /// Start searching
    pub fn start_search(&mut self) {
        self.overlays.search.active = true;
        self.overlays.search.clear();
        self.overlays.show_help = false;
        self.overlays.show_export = false;
        self.overlays.show_legend = false;
    }

    /// Stop searching
    pub fn stop_search(&mut self) {
        self.overlays.search.active = false;
    }

    /// Add character to search query
    pub fn search_push(&mut self, c: char) {
        self.overlays.search.push_char(c);
    }

    /// Remove character from search query
    pub fn search_pop(&mut self) {
        self.overlays.search.pop_char();
    }

    /// Execute search with current query
    pub fn execute_search(&mut self) {
        if self.overlays.search.query.len() < 2 {
            self.overlays.search.results.clear();
            return;
        }

        let query_lower = self.overlays.search.query.to_lowercase();
        let mut results = Vec::new();

        // Search through diff results if available
        if let Some(ref diff) = self.data.diff_result {
            // Search added components
            for comp in &diff.components.added {
                if comp.name.to_lowercase().contains(&query_lower) {
                    results.push(DiffSearchResult::Component {
                        name: comp.name.clone(),
                        version: comp.new_version.clone(),
                        change_type: ChangeType::Added,
                        match_field: "name".to_string(),
                    });
                }
            }

            // Search removed components
            for comp in &diff.components.removed {
                if comp.name.to_lowercase().contains(&query_lower) {
                    results.push(DiffSearchResult::Component {
                        name: comp.name.clone(),
                        version: comp.old_version.clone(),
                        change_type: ChangeType::Removed,
                        match_field: "name".to_string(),
                    });
                }
            }

            // Search modified components
            for change in &diff.components.modified {
                if change.name.to_lowercase().contains(&query_lower) {
                    results.push(DiffSearchResult::Component {
                        name: change.name.clone(),
                        version: change.new_version.clone(),
                        change_type: ChangeType::Modified,
                        match_field: "name".to_string(),
                    });
                }
            }

            // Search introduced vulnerabilities
            for vuln in &diff.vulnerabilities.introduced {
                if vuln.id.to_lowercase().contains(&query_lower) {
                    results.push(DiffSearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_name: vuln.component_name.clone(),
                        severity: Some(vuln.severity.clone()),
                        change_type: VulnChangeType::Introduced,
                    });
                }
            }

            // Search resolved vulnerabilities
            for vuln in &diff.vulnerabilities.resolved {
                if vuln.id.to_lowercase().contains(&query_lower) {
                    results.push(DiffSearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_name: vuln.component_name.clone(),
                        severity: Some(vuln.severity.clone()),
                        change_type: VulnChangeType::Resolved,
                    });
                }
            }

            // Search license changes (new licenses)
            for lic_change in &diff.licenses.new_licenses {
                if lic_change.license.to_lowercase().contains(&query_lower) {
                    let component_name = lic_change
                        .components
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "multiple".to_string());
                    results.push(DiffSearchResult::License {
                        license: lic_change.license.clone(),
                        component_name,
                        change_type: ChangeType::Added,
                    });
                }
            }

            // Search license changes (removed licenses)
            for lic_change in &diff.licenses.removed_licenses {
                if lic_change.license.to_lowercase().contains(&query_lower) {
                    let component_name = lic_change
                        .components
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "multiple".to_string());
                    results.push(DiffSearchResult::License {
                        license: lic_change.license.clone(),
                        component_name,
                        change_type: ChangeType::Removed,
                    });
                }
            }
        }

        // Limit results
        results.truncate(50);
        self.overlays.search.results = results;
        self.overlays.search.selected = 0;
    }

    /// Jump to the currently selected search result
    pub fn jump_to_search_result(&mut self) {
        if let Some(result) = self
            .overlays.search
            .results
            .get(self.overlays.search.selected)
            .cloned()
        {
            match result {
                DiffSearchResult::Component {
                    name,
                    version,
                    change_type,
                    ..
                } => {
                    // Prefer matching by change type + version when possible
                    if let Some(index) =
                        self.find_component_index_all(&name, Some(change_type), version.as_deref())
                    {
                        self.tabs.components.filter = ComponentFilter::All;
                        self.tabs.components.selected = index;
                        self.select_tab(TabKind::Components);
                        self.stop_search();
                        return;
                    }

                    // Fall back to name-only match across all components
                    if let Some(index) = self.find_component_index_all(&name, None, None) {
                        self.tabs.components.filter = ComponentFilter::All;
                        self.tabs.components.selected = index;
                        self.select_tab(TabKind::Components);
                        self.stop_search();
                        return;
                    }

                    self.tabs.components.filter = ComponentFilter::All;
                    self.select_tab(TabKind::Components);
                }
                DiffSearchResult::Vulnerability {
                    id, change_type, ..
                } => {
                    // Align filter/sort so the selection is stable
                    self.tabs.vulnerabilities.sort_by = VulnSort::Id;
                    self.tabs.vulnerabilities.filter = match change_type {
                        VulnChangeType::Introduced => VulnFilter::Introduced,
                        VulnChangeType::Resolved => VulnFilter::Resolved,
                        VulnChangeType::Persistent => VulnFilter::All,
                    };

                    if let Some(index) = self.find_vulnerability_index(&id) {
                        self.tabs.vulnerabilities.selected = index;
                    }

                    self.select_tab(TabKind::Vulnerabilities);
                }
                DiffSearchResult::License { license, .. } => {
                    // Find the license index
                    if let Some(ref diff) = self.data.diff_result {
                        let mut index = 0;

                        // Search new licenses first
                        for lic in &diff.licenses.new_licenses {
                            if lic.license == license {
                                self.tabs.licenses.selected = index;
                                self.select_tab(TabKind::Licenses);
                                self.stop_search();
                                return;
                            }
                            index += 1;
                        }

                        // Then removed licenses
                        for lic in &diff.licenses.removed_licenses {
                            if lic.license == license {
                                self.tabs.licenses.selected = index;
                                self.select_tab(TabKind::Licenses);
                                self.stop_search();
                                return;
                            }
                            index += 1;
                        }
                    }
                    self.select_tab(TabKind::Licenses);
                }
            }
            self.stop_search();
        }
    }
}
