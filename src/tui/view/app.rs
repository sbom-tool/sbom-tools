//! `ViewApp` - Dedicated TUI for exploring a single SBOM.
//!
//! This provides a rich, purpose-built interface for SBOM analysis
//! with hierarchical navigation, search, and deep inspection.

use crate::model::{Component, NormalizedSbom, NormalizedSbomIndex, VulnerabilityRef};
use crate::quality::{ComplianceResult, QualityReport, QualityScorer, ScoringProfile};
use crate::tui::app_states::SourcePanelState;
use crate::tui::state::ListNavigation;
use crate::tui::widgets::TreeState;
use std::collections::{HashMap, HashSet};

use super::views::{compute_compliance_results, StandardComplianceState};

/// Main application state for single SBOM viewing.
pub struct ViewApp {
    /// The SBOM being viewed
    pub(crate) sbom: NormalizedSbom,

    /// Current active view/tab
    pub(crate) active_tab: ViewTab,

    /// Tree navigation state
    pub(crate) tree_state: TreeState,

    /// Current tree grouping mode
    pub(crate) tree_group_by: TreeGroupBy,

    /// Current tree filter
    pub(crate) tree_filter: TreeFilter,

    /// Tree search query (inline filter)
    pub(crate) tree_search_query: String,

    /// Whether tree search is active
    pub(crate) tree_search_active: bool,

    /// Selected component ID (for detail panel)
    pub(crate) selected_component: Option<String>,

    /// Component detail sub-tab
    pub(crate) component_tab: ComponentDetailTab,

    /// Vulnerability explorer state
    pub(crate) vuln_state: VulnExplorerState,

    /// License view state
    pub(crate) license_state: LicenseViewState,

    /// Dependency view state
    pub(crate) dependency_state: DependencyViewState,

    /// Global search state
    pub(crate) search_state: SearchState,

    /// Focus panel (left list vs right detail)
    pub(crate) focus_panel: FocusPanel,

    /// Show help overlay
    pub(crate) show_help: bool,

    /// Show export dialog
    pub(crate) show_export: bool,

    /// Show legend overlay
    pub(crate) show_legend: bool,

    /// Status message to display temporarily
    pub(crate) status_message: Option<String>,

    /// Navigation context for breadcrumbs
    pub(crate) navigation_ctx: ViewNavigationContext,

    /// Should quit
    pub(crate) should_quit: bool,

    /// Animation tick counter
    pub(crate) tick: u64,

    /// Cached statistics
    pub(crate) stats: SbomStats,

    /// Quality report for the SBOM
    pub(crate) quality_report: QualityReport,

    /// Quality view state
    pub(crate) quality_state: QualityViewState,

    /// Compliance validation results for all standards (lazily computed)
    pub(crate) compliance_results: Option<Vec<ComplianceResult>>,

    /// Compliance view state
    pub(crate) compliance_state: StandardComplianceState,

    /// Precomputed index for fast lookups
    pub(crate) sbom_index: NormalizedSbomIndex,

    /// Source tab state
    pub(crate) source_state: SourcePanelState,

    /// Bookmarked component canonical IDs (in-memory, no persistence)
    pub(crate) bookmarked: HashSet<String>,
}

impl ViewApp {
    /// Create a new `ViewApp` for the given SBOM.
    #[must_use] 
    pub fn new(sbom: NormalizedSbom, raw_content: &str) -> Self {
        let stats = SbomStats::from_sbom(&sbom);

        // Calculate quality score
        let scorer = QualityScorer::new(ScoringProfile::Standard);
        let quality_report = scorer.score(&sbom);
        let quality_state = QualityViewState::new(quality_report.recommendations.len());

        let compliance_state = StandardComplianceState::new();

        // Build index for fast lookups (O(1) instead of O(n))
        let sbom_index = sbom.build_index();

        // Build source panel state from raw content
        let source_state = SourcePanelState::new(raw_content);

        // Pre-expand the first few ecosystems
        let mut tree_state = TreeState::new();
        for eco in stats.ecosystem_counts.keys().take(3) {
            tree_state.expand(&format!("eco:{eco}"));
        }

        Self {
            sbom,
            active_tab: ViewTab::Overview,
            tree_state,
            tree_group_by: TreeGroupBy::Ecosystem,
            tree_filter: TreeFilter::All,
            tree_search_query: String::new(),
            tree_search_active: false,
            selected_component: None,
            component_tab: ComponentDetailTab::Overview,
            vuln_state: VulnExplorerState::new(),
            license_state: LicenseViewState::new(),
            dependency_state: DependencyViewState::new(),
            search_state: SearchState::new(),
            focus_panel: FocusPanel::Left,
            show_help: false,
            show_export: false,
            show_legend: false,
            status_message: None,
            navigation_ctx: ViewNavigationContext::new(),
            should_quit: false,
            tick: 0,
            stats,
            quality_report,
            quality_state,
            compliance_results: None,
            compliance_state,
            sbom_index,
            source_state,
            bookmarked: HashSet::new(),
        }
    }

    /// Lazily compute compliance results for all standards when first needed.
    pub fn ensure_compliance_results(&mut self) {
        if self.compliance_results.is_none() {
            self.compliance_results = Some(compute_compliance_results(&self.sbom));
        }
    }

    /// Switch to the next tab.
    pub const fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            ViewTab::Overview => ViewTab::Tree,
            ViewTab::Tree => ViewTab::Vulnerabilities,
            ViewTab::Vulnerabilities => ViewTab::Licenses,
            ViewTab::Licenses => ViewTab::Dependencies,
            ViewTab::Dependencies => ViewTab::Quality,
            ViewTab::Quality => ViewTab::Compliance,
            ViewTab::Compliance => ViewTab::Source,
            ViewTab::Source => ViewTab::Overview,
        };
    }

    /// Switch to the previous tab.
    pub const fn prev_tab(&mut self) {
        self.active_tab = match self.active_tab {
            ViewTab::Overview => ViewTab::Source,
            ViewTab::Tree => ViewTab::Overview,
            ViewTab::Vulnerabilities => ViewTab::Tree,
            ViewTab::Licenses => ViewTab::Vulnerabilities,
            ViewTab::Dependencies => ViewTab::Licenses,
            ViewTab::Quality => ViewTab::Dependencies,
            ViewTab::Compliance => ViewTab::Quality,
            ViewTab::Source => ViewTab::Compliance,
        };
    }

    /// Select a specific tab.
    pub const fn select_tab(&mut self, tab: ViewTab) {
        self.active_tab = tab;
    }

    // ========================================================================
    // Index access methods for O(1) lookups
    // ========================================================================

    /// Get the sort key for a component using the cached index.
    ///
    /// Returns pre-computed lowercase strings to avoid repeated allocations during sorting.
    #[must_use] 
    pub fn get_sort_key(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Option<&crate::model::ComponentSortKey> {
        self.sbom_index.sort_key(id)
    }

    /// Get dependencies of a component using the cached index (O(k) instead of O(edges)).
    #[must_use] 
    pub fn get_dependencies(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Vec<&crate::model::DependencyEdge> {
        self.sbom_index.dependencies_of(id, &self.sbom.edges)
    }

    /// Get dependents of a component using the cached index (O(k) instead of O(edges)).
    #[must_use] 
    pub fn get_dependents(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Vec<&crate::model::DependencyEdge> {
        self.sbom_index.dependents_of(id, &self.sbom.edges)
    }

    /// Search components by name using the cached index.
    #[must_use] 
    pub fn search_components_by_name(&self, query: &str) -> Vec<&crate::model::Component> {
        self.sbom.search_by_name_indexed(query, &self.sbom_index)
    }

    /// Toggle focus between left and right panels.
    pub const fn toggle_focus(&mut self) {
        self.focus_panel = match self.focus_panel {
            FocusPanel::Left => FocusPanel::Right,
            FocusPanel::Right => FocusPanel::Left,
        };
    }

    /// Start search mode.
    pub fn start_search(&mut self) {
        self.search_state.active = true;
        self.search_state.query.clear();
        self.search_state.results.clear();
    }

    /// Stop search mode.
    pub const fn stop_search(&mut self) {
        self.search_state.active = false;
    }

    /// Execute search with current query.
    pub fn execute_search(&mut self) {
        self.search_state.results = self.search(&self.search_state.query.clone());
        self.search_state.selected = 0;
    }

    /// Search across the SBOM for matching items.
    fn search(&self, query: &str) -> Vec<SearchResult> {
        if query.len() < 2 {
            return Vec::new();
        }

        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // Search components
        for (id, comp) in &self.sbom.components {
            if comp.name.to_lowercase().contains(&query_lower) {
                results.push(SearchResult::Component {
                    id: id.value().to_string(),
                    name: comp.name.clone(),
                    version: comp.version.clone(),
                    match_field: "name".to_string(),
                });
            } else if let Some(purl) = &comp.identifiers.purl {
                if purl.to_lowercase().contains(&query_lower) {
                    results.push(SearchResult::Component {
                        id: id.value().to_string(),
                        name: comp.name.clone(),
                        version: comp.version.clone(),
                        match_field: "purl".to_string(),
                    });
                }
            }
        }

        // Search vulnerabilities
        for (_, comp) in &self.sbom.components {
            for vuln in &comp.vulnerabilities {
                if vuln.id.to_lowercase().contains(&query_lower) {
                    results.push(SearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_id: comp.canonical_id.to_string(),  // Store ID for navigation
                        component_name: comp.name.clone(),
                        severity: vuln.severity.as_ref().map(std::string::ToString::to_string),
                    });
                }
            }
        }

        // Limit results
        results.truncate(50);
        results
    }

    /// Get the currently selected component.
    #[must_use] 
    pub fn get_selected_component(&self) -> Option<&Component> {
        self.selected_component.as_ref().and_then(|selected_id| {
            self.sbom
                .components
                .iter()
                .find(|(id, _)| id.value() == selected_id)
                .map(|(_, comp)| comp)
        })
    }

    /// Jump tree selection to a component, expanding its group if needed.
    pub fn jump_to_component_in_tree(&mut self, component_id: &str) -> bool {
        let group_id = {
            let Some(comp) = self
                .sbom
                .components
                .iter()
                .find(|(id, _)| id.value() == component_id)
                .map(|(_, comp)| comp)
            else {
                return false;
            };
            self.tree_group_id_for_component(comp)
        };
        if let Some(ref group_id) = group_id {
            self.tree_state.expand(group_id);
        }

        let nodes = self.build_tree_nodes();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(&nodes, &self.tree_state, &mut flat_items);

        if let Some(index) = flat_items
            .iter()
            .position(|item| matches!(item, SelectedTreeNode::Component(id) if id == component_id))
        {
            self.tree_state.selected = index;
            return true;
        }

        if let Some(group_id) = group_id {
            if let Some(index) = flat_items
                .iter()
                .position(|item| matches!(item, SelectedTreeNode::Group(id) if id == &group_id))
            {
                self.tree_state.selected = index;
            }
        }

        false
    }

    /// Get the currently selected tree node info (Group label + children component IDs,
    /// or None if a component is selected or nothing is selected).
    #[must_use]
    pub fn get_selected_group_info(&self) -> Option<(String, Vec<String>)> {
        let nodes = self.build_tree_nodes();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(&nodes, &self.tree_state, &mut flat_items);

        let selected = flat_items.get(self.tree_state.selected)?;
        match selected {
            SelectedTreeNode::Group(group_id) => {
                // Find the group in tree nodes and collect child component IDs
                fn find_group_children(
                    nodes: &[crate::tui::widgets::TreeNode],
                    target_id: &str,
                ) -> Option<(String, Vec<String>)> {
                    for node in nodes {
                        if let crate::tui::widgets::TreeNode::Group {
                            id,
                            label,
                            children,
                            ..
                        } = node
                        {
                            if id == target_id {
                                let child_ids: Vec<String> = children
                                    .iter()
                                    .filter_map(|c| match c {
                                        crate::tui::widgets::TreeNode::Component { id, .. } => {
                                            Some(id.clone())
                                        }
                                        crate::tui::widgets::TreeNode::Group { .. } => None,
                                    })
                                    .collect();
                                return Some((label.clone(), child_ids));
                            }
                            // Recurse into subgroups
                            if let Some(result) = find_group_children(children, target_id) {
                                return Some(result);
                            }
                        }
                    }
                    None
                }
                find_group_children(&nodes, group_id)
            }
            SelectedTreeNode::Component(_) => None,
        }
    }

    /// Toggle bookmark on the currently selected component.
    pub fn toggle_bookmark(&mut self) {
        if let Some(ref comp_id) = self.selected_component {
            if self.bookmarked.contains(comp_id) {
                self.bookmarked.remove(comp_id);
            } else {
                self.bookmarked.insert(comp_id.clone());
            }
        } else if let Some(node) = self.get_selected_tree_node() {
            match node {
                SelectedTreeNode::Component(id) => {
                    if self.bookmarked.contains(&id) {
                        self.bookmarked.remove(&id);
                    } else {
                        self.bookmarked.insert(id);
                    }
                }
                SelectedTreeNode::Group(_) => {}
            }
        }
    }

    /// Toggle tree grouping mode.
    pub fn toggle_tree_grouping(&mut self) {
        self.tree_group_by = match self.tree_group_by {
            TreeGroupBy::Ecosystem => TreeGroupBy::License,
            TreeGroupBy::License => TreeGroupBy::VulnStatus,
            TreeGroupBy::VulnStatus => TreeGroupBy::ComponentType,
            TreeGroupBy::ComponentType => TreeGroupBy::Flat,
            TreeGroupBy::Flat => TreeGroupBy::Ecosystem,
        };
        self.tree_state = TreeState::new(); // Reset tree state on grouping change
    }

    /// Toggle tree filter.
    pub fn toggle_tree_filter(&mut self) {
        self.tree_filter = match self.tree_filter {
            TreeFilter::All => TreeFilter::HasVulnerabilities,
            TreeFilter::HasVulnerabilities => TreeFilter::Critical,
            TreeFilter::Critical => TreeFilter::Bookmarked,
            TreeFilter::Bookmarked => TreeFilter::All,
        };
        self.tree_state = TreeState::new();
    }

    /// Start tree search mode.
    pub fn start_tree_search(&mut self) {
        self.tree_search_active = true;
        self.tree_search_query.clear();
    }

    /// Stop tree search mode.
    pub const fn stop_tree_search(&mut self) {
        self.tree_search_active = false;
    }

    /// Clear tree search and exit search mode.
    pub fn clear_tree_search(&mut self) {
        self.tree_search_query.clear();
        self.tree_search_active = false;
        self.tree_state = TreeState::new();
    }

    /// Add character to tree search query.
    pub fn tree_search_push_char(&mut self, c: char) {
        self.tree_search_query.push(c);
        self.tree_state = TreeState::new();
    }

    /// Remove character from tree search query.
    pub fn tree_search_pop_char(&mut self) {
        self.tree_search_query.pop();
        self.tree_state = TreeState::new();
    }

    /// Cycle to next component detail tab.
    pub const fn next_component_tab(&mut self) {
        self.component_tab = match self.component_tab {
            ComponentDetailTab::Overview => ComponentDetailTab::Identifiers,
            ComponentDetailTab::Identifiers => ComponentDetailTab::Vulnerabilities,
            ComponentDetailTab::Vulnerabilities => ComponentDetailTab::Dependencies,
            ComponentDetailTab::Dependencies => ComponentDetailTab::Overview,
        };
    }

    /// Cycle to previous component detail tab.
    pub const fn prev_component_tab(&mut self) {
        self.component_tab = match self.component_tab {
            ComponentDetailTab::Overview => ComponentDetailTab::Dependencies,
            ComponentDetailTab::Identifiers => ComponentDetailTab::Overview,
            ComponentDetailTab::Vulnerabilities => ComponentDetailTab::Identifiers,
            ComponentDetailTab::Dependencies => ComponentDetailTab::Vulnerabilities,
        };
    }

    /// Select a specific component detail tab.
    pub(crate) const fn select_component_tab(&mut self, tab: ComponentDetailTab) {
        self.component_tab = tab;
    }

    /// Toggle help overlay.
    pub const fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        if self.show_help {
            self.show_export = false;
            self.show_legend = false;
        }
    }

    /// Toggle export dialog.
    pub const fn toggle_export(&mut self) {
        self.show_export = !self.show_export;
        if self.show_export {
            self.show_help = false;
            self.show_legend = false;
        }
    }

    /// Toggle legend overlay.
    pub const fn toggle_legend(&mut self) {
        self.show_legend = !self.show_legend;
        if self.show_legend {
            self.show_help = false;
            self.show_export = false;
        }
    }

    /// Close all overlays.
    pub const fn close_overlays(&mut self) {
        self.show_help = false;
        self.show_export = false;
        self.show_legend = false;
        self.search_state.active = false;
        self.compliance_state.show_detail = false;
    }

    /// Check if any overlay is open.
    #[must_use] 
    pub const fn has_overlay(&self) -> bool {
        self.show_help
            || self.show_export
            || self.show_legend
            || self.search_state.active
            || self.compliance_state.show_detail
    }

    /// Set a temporary status message.
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    /// Clear the status message.
    pub fn clear_status_message(&mut self) {
        self.status_message = None;
    }

    /// Export the current SBOM to a file.
    pub fn export(&mut self, format: crate::tui::export::ExportFormat) {
        use crate::tui::export::export_view;

        let result = export_view(format, &self.sbom, None);

        if result.success {
            self.set_status_message(result.message);
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    /// Export compliance results from the compliance tab
    pub fn export_compliance(&mut self, format: crate::tui::export::ExportFormat) {
        use crate::tui::export::export_compliance;

        self.ensure_compliance_results();
        let results = match self.compliance_results.as_ref() {
            Some(r) if !r.is_empty() => r,
            _ => {
                self.set_status_message("No compliance results to export");
                return;
            }
        };

        let result = export_compliance(
            format,
            results,
            self.compliance_state.selected_standard,
            None,
        );
        if result.success {
            self.set_status_message(result.message);
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    /// Navigate back using breadcrumb history.
    pub fn go_back(&mut self) -> bool {
        if let Some(breadcrumb) = self.navigation_ctx.pop_breadcrumb() {
            self.active_tab = breadcrumb.tab;
            // Restore selection index based on tab
            match breadcrumb.tab {
                ViewTab::Vulnerabilities => {
                    self.vuln_state.selected = breadcrumb.selection_index;
                }
                ViewTab::Licenses => {
                    self.license_state.selected = breadcrumb.selection_index;
                }
                ViewTab::Dependencies => {
                    self.dependency_state.selected = breadcrumb.selection_index;
                }
                ViewTab::Tree => {
                    self.tree_state.selected = breadcrumb.selection_index;
                }
                ViewTab::Source => {
                    self.source_state.selected = breadcrumb.selection_index;
                }
                _ => {}
            }
            self.focus_panel = FocusPanel::Left;
            true
        } else {
            false
        }
    }

    /// Handle navigation in current view.
    pub fn navigate_up(&mut self) {
        match self.active_tab {
            ViewTab::Tree => self.tree_state.select_prev(),
            ViewTab::Vulnerabilities => self.vuln_state.select_prev(),
            ViewTab::Licenses => self.license_state.select_prev(),
            ViewTab::Dependencies => self.dependency_state.select_prev(),
            ViewTab::Quality => self.quality_state.select_prev(),
            ViewTab::Compliance => self.compliance_state.select_prev(),
            ViewTab::Source => self.source_state.select_prev(),
            ViewTab::Overview => {} // Overview has no list navigation
        }
    }

    /// Handle navigation in current view.
    pub fn navigate_down(&mut self) {
        match self.active_tab {
            ViewTab::Tree => self.tree_state.select_next(),
            ViewTab::Vulnerabilities => self.vuln_state.select_next(),
            ViewTab::Licenses => self.license_state.select_next(),
            ViewTab::Dependencies => self.dependency_state.select_next(),
            ViewTab::Quality => self.quality_state.select_next(),
            ViewTab::Compliance => {
                self.ensure_compliance_results();
                let max = self.filtered_compliance_violation_count();
                self.compliance_state.select_next(max);
            }
            ViewTab::Source => self.source_state.select_next(),
            ViewTab::Overview => {} // Overview has no list navigation
        }
    }

    /// Count compliance violations that pass the current severity filter.
    pub(crate) fn filtered_compliance_violation_count(&self) -> usize {
        self.compliance_results
            .as_ref()
            .and_then(|r| r.get(self.compliance_state.selected_standard))
            .map_or(0, |r| {
                r.violations
                    .iter()
                    .filter(|v| self.compliance_state.severity_filter.matches(v.severity))
                    .count()
            })
    }

    /// Page up - move up by page size.
    pub fn page_up(&mut self) {
        use crate::tui::constants::PAGE_SIZE;
        if self.active_tab == ViewTab::Source {
            self.source_state.page_up();
        } else {
            for _ in 0..PAGE_SIZE {
                self.navigate_up();
            }
        }
    }

    /// Page down - move down by page size.
    pub fn page_down(&mut self) {
        use crate::tui::constants::PAGE_SIZE;
        if self.active_tab == ViewTab::Source {
            self.source_state.page_down();
        } else {
            for _ in 0..PAGE_SIZE {
                self.navigate_down();
            }
        }
    }

    /// Go to first item in current view.
    pub const fn go_first(&mut self) {
        match self.active_tab {
            ViewTab::Tree => self.tree_state.select_first(),
            ViewTab::Vulnerabilities => self.vuln_state.selected = 0,
            ViewTab::Licenses => self.license_state.selected = 0,
            ViewTab::Dependencies => self.dependency_state.selected = 0,
            ViewTab::Quality => self.quality_state.scroll_offset = 0,
            ViewTab::Compliance => self.compliance_state.selected_violation = 0,
            ViewTab::Source => self.source_state.select_first(),
            ViewTab::Overview => {}
        }
    }

    /// Go to last item in current view.
    pub fn go_last(&mut self) {
        match self.active_tab {
            ViewTab::Tree => self.tree_state.select_last(),
            ViewTab::Vulnerabilities => {
                self.vuln_state.selected = self.vuln_state.total.saturating_sub(1);
            }
            ViewTab::Licenses => {
                self.license_state.selected = self.license_state.total.saturating_sub(1);
            }
            ViewTab::Dependencies => {
                self.dependency_state.selected = self.dependency_state.total.saturating_sub(1);
            }
            ViewTab::Quality => {
                self.quality_state.scroll_offset =
                    self.quality_state.total_recommendations.saturating_sub(1);
            }
            ViewTab::Compliance => {
                self.ensure_compliance_results();
                let max = self.filtered_compliance_violation_count();
                self.compliance_state.selected_violation = max.saturating_sub(1);
            }
            ViewTab::Source => self.source_state.select_last(),
            ViewTab::Overview => {}
        }
    }

    /// Handle enter/select action.
    pub fn handle_enter(&mut self) {
        match self.active_tab {
            ViewTab::Tree => {
                // Toggle expand or select component
                if let Some(node) = self.get_selected_tree_node() {
                    match node {
                        SelectedTreeNode::Group(id) => {
                            self.tree_state.toggle_expand(&id);
                        }
                        SelectedTreeNode::Component(id) => {
                            self.selected_component = Some(id);
                            self.focus_panel = FocusPanel::Right;
                            self.component_tab = ComponentDetailTab::Overview;
                        }
                    }
                }
            }
            ViewTab::Vulnerabilities => {
                // In grouped mode, check if we're on a group header
                if self.vuln_state.group_by != VulnGroupBy::Flat {
                    if let Some(cache) = &self.vuln_state.cached_data {
                        let items = super::views::build_display_items(
                            &cache.vulns,
                            &self.vuln_state.group_by,
                            &self.vuln_state.expanded_groups,
                        );
                        if let Some(item) = items.get(self.vuln_state.selected) {
                            match item {
                                super::views::VulnDisplayItem::GroupHeader { label, .. } => {
                                    let label = label.clone();
                                    self.vuln_state.toggle_vuln_group(&label);
                                    return;
                                }
                                super::views::VulnDisplayItem::Vuln(_) => {
                                    // Fall through to normal navigation
                                }
                            }
                        }
                    }
                }
                // Select vulnerability's component - push breadcrumb for back navigation
                if let Some((comp_id, vuln)) = self.vuln_state.get_selected(&self.sbom) {
                    // Push breadcrumb so we can go back
                    self.navigation_ctx.push_breadcrumb(
                        ViewTab::Vulnerabilities,
                        vuln.id.clone(),
                        self.vuln_state.selected,
                    );
                    self.selected_component = Some(comp_id);
                    self.component_tab = ComponentDetailTab::Overview;
                    self.active_tab = ViewTab::Tree;
                }
            }
            ViewTab::Dependencies => {
                // Toggle expand on the selected dependency node
                // Node ID is calculated from the flattened view
                if let Some(node_id) = self.get_selected_dependency_node_id() {
                    self.dependency_state.toggle_expand(&node_id);
                }
            }
            ViewTab::Compliance => {
                // Toggle violation detail overlay
                self.ensure_compliance_results();
                let idx = self.compliance_state.selected_standard;
                let has_violations = self
                    .compliance_results.as_ref()
                    .and_then(|r| r.get(idx))
                    .is_some_and(|r| !r.violations.is_empty());
                if has_violations {
                    self.compliance_state.show_detail = !self.compliance_state.show_detail;
                }
            }
            ViewTab::Source => {
                // Toggle expand/collapse in tree mode
                if self.source_state.view_mode == crate::tui::app_states::SourceViewMode::Tree {
                    if let Some(ref tree) = self.source_state.json_tree {
                        let mut items = Vec::new();
                        crate::tui::shared::source::flatten_json_tree(
                            tree,
                            "",
                            0,
                            &self.source_state.expanded,
                            &mut items,
                            true,
                            &[],
                        );
                        if let Some(item) = items.get(self.source_state.selected) {
                            if item.is_expandable {
                                let node_id = item.node_id.clone();
                                self.source_state.toggle_expand(&node_id);
                            }
                        }
                    }
                }
            }
            ViewTab::Quality => {
                if self.quality_state.view_mode == QualityViewMode::Summary {
                    // Jump to Recommendations view preserving selection
                    self.quality_state.view_mode = QualityViewMode::Recommendations;
                }
            }
            ViewTab::Licenses | ViewTab::Overview => {}
        }
    }

    /// Jump the source panel to the section selected in the map.
    pub fn handle_source_map_enter(&mut self) {
        // Build sections from JSON tree root children
        let Some(tree) = &self.source_state.json_tree else {
            return;
        };
        let Some(children) = tree.children() else {
            return;
        };

        // Find the Nth expandable section
        let expandable: Vec<_> = children
            .iter()
            .filter(|c| c.is_expandable())
            .collect();

        let target = match expandable.get(self.source_state.map_selected) {
            Some(t) => *t,
            None => return,
        };

        let target_id = target.node_id("root");

        match self.source_state.view_mode {
            crate::tui::app_states::SourceViewMode::Tree => {
                // Ensure section is expanded
                if !self.source_state.expanded.contains(&target_id) {
                    self.source_state.expanded.insert(target_id.clone());
                }
                // Flatten and find the target node's index
                let mut items = Vec::new();
                crate::tui::shared::source::flatten_json_tree(
                    tree, "", 0, &self.source_state.expanded, &mut items, true, &[],
                );
                if let Some(idx) = items.iter().position(|item| item.node_id == target_id) {
                    self.source_state.selected = idx;
                    self.source_state.scroll_offset = idx.saturating_sub(2);
                }
            }
            crate::tui::app_states::SourceViewMode::Raw => {
                // Find the line that starts this section
                let key = match target {
                    crate::tui::app_states::source::JsonTreeNode::Object { key, .. }
                    | crate::tui::app_states::source::JsonTreeNode::Array { key, .. }
                    | crate::tui::app_states::source::JsonTreeNode::Leaf { key, .. } => key.clone(),
                };
                // Search raw_lines for the top-level key
                for (i, line) in self.source_state.raw_lines.iter().enumerate() {
                    let search = format!("\"{key}\":");
                    if line.contains(&search) && line.starts_with("  ") && !line.starts_with("    ") {
                        self.source_state.selected = i;
                        self.source_state.scroll_offset = i.saturating_sub(2);
                        break;
                    }
                }
            }
        }

        // Switch focus back to source panel after jumping
        self.focus_panel = FocusPanel::Left;
    }

    /// Get the component ID currently shown in the source map context footer.
    /// Returns the canonical ID value string if inside the "components" section.
    #[must_use] 
    pub fn get_map_context_component_id(&self) -> Option<String> {
        let tree = self.source_state.json_tree.as_ref()?;
        let mut items = Vec::new();
        crate::tui::shared::source::flatten_json_tree(
            tree,
            "",
            0,
            &self.source_state.expanded,
            &mut items,
            true,
            &[],
        );
        let item = items.get(self.source_state.selected)?;
        let parts: Vec<&str> = item.node_id.split('.').collect();
        if parts.len() < 3 || parts[1] != "components" {
            return None;
        }
        let idx_part = parts[2];
        if idx_part.starts_with('[') && idx_part.ends_with(']') {
            let idx: usize = idx_part[1..idx_part.len() - 1].parse().ok()?;
            let (canon_id, _) = self.sbom.components.iter().nth(idx)?;
            Some(canon_id.value().to_string())
        } else {
            None
        }
    }

    /// Get the currently selected dependency node ID (if any).
    #[must_use] 
    pub fn get_selected_dependency_node_id(&self) -> Option<String> {
        // Build the flattened list of visible dependency nodes
        let mut visible_nodes = Vec::new();
        self.collect_visible_dependency_nodes(&mut visible_nodes);
        visible_nodes.get(self.dependency_state.selected).cloned()
    }

    /// Collect visible dependency nodes in tree order.
    fn collect_visible_dependency_nodes(&self, nodes: &mut Vec<String>) {
        // Build edges map from sbom.edges
        let mut edges: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut has_parent: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut all_nodes: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (id, _) in &self.sbom.components {
            all_nodes.insert(id.value().to_string());
        }

        for edge in &self.sbom.edges {
            let from = edge.from.value().to_string();
            let to = edge.to.value().to_string();
            if all_nodes.contains(&from) && all_nodes.contains(&to) {
                edges.entry(from).or_default().push(to.clone());
                has_parent.insert(to);
            }
        }

        // Find roots, sorted for stable ordering matching render traversal
        let mut roots: Vec<_> = all_nodes
            .iter()
            .filter(|id| !has_parent.contains(*id))
            .cloned()
            .collect();
        roots.sort();

        // Traverse and collect visible nodes
        for root in roots {
            self.collect_dep_nodes_recursive(
                &root,
                &edges,
                nodes,
                &mut std::collections::HashSet::new(),
            );
        }
    }

    fn collect_dep_nodes_recursive(
        &self,
        node_id: &str,
        edges: &std::collections::HashMap<String, Vec<String>>,
        nodes: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
    ) {
        if visited.contains(node_id) {
            return;
        }
        visited.insert(node_id.to_string());
        nodes.push(node_id.to_string());

        if self.dependency_state.is_expanded(node_id) {
            if let Some(children) = edges.get(node_id) {
                for child in children {
                    self.collect_dep_nodes_recursive(child, edges, nodes, visited);
                }
            }
        }
    }

    /// Get the currently selected tree node.
    fn get_selected_tree_node(&self) -> Option<SelectedTreeNode> {
        let nodes = self.build_tree_nodes();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(&nodes, &self.tree_state, &mut flat_items);

        flat_items.get(self.tree_state.selected).cloned()
    }

    /// Build tree nodes based on current grouping.
    #[must_use] 
    pub fn build_tree_nodes(&self) -> Vec<crate::tui::widgets::TreeNode> {
        match self.tree_group_by {
            TreeGroupBy::Ecosystem => self.build_ecosystem_tree(),
            TreeGroupBy::License => self.build_license_tree(),
            TreeGroupBy::VulnStatus => self.build_vuln_status_tree(),
            TreeGroupBy::ComponentType => self.build_type_tree(),
            TreeGroupBy::Flat => self.build_flat_tree(),
        }
    }

    fn build_ecosystem_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use crate::tui::widgets::TreeNode;

        let mut ecosystem_map: HashMap<String, Vec<&Component>> = HashMap::new();

        for comp in self.sbom.components.values() {
            if !self.matches_filter(comp) {
                continue;
            }
            let eco = comp
                .ecosystem
                .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
            ecosystem_map.entry(eco).or_default().push(comp);
        }

        let mut groups: Vec<TreeNode> = ecosystem_map
            .into_iter()
            .map(|(eco, mut components)| {
                let vuln_count: usize = components.iter().map(|c| c.vulnerabilities.len()).sum();
                components.sort_by(|a, b| a.name.cmp(&b.name));
                let children: Vec<TreeNode> = components
                    .into_iter()
                    .map(|c| TreeNode::Component {
                        id: c.canonical_id.value().to_string(),
                        name: c.name.clone(),
                        version: c.version.clone(),
                        vuln_count: c.vulnerabilities.len(),
                        max_severity: get_max_severity(c),
                        component_type: Some(
                            crate::tui::widgets::detect_component_type(&c.name).to_string(),
                        ),
                        ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                        is_bookmarked: self.bookmarked.contains(c.canonical_id.value()),
                    })
                    .collect();
                let count = children.len();
                TreeNode::Group {
                    id: format!("eco:{eco}"),
                    label: eco,
                    children,
                    item_count: count,
                    vuln_count,
                }
            })
            .collect();

        groups.sort_by(|a, b| match (a, b) {
            (
                TreeNode::Group { item_count: ac, label: al, .. },
                TreeNode::Group { item_count: bc, label: bl, .. },
            ) => bc.cmp(ac).then_with(|| al.cmp(bl)),
            _ => std::cmp::Ordering::Equal,
        });

        groups
    }

    fn build_license_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use crate::tui::widgets::TreeNode;

        let mut license_map: HashMap<String, Vec<&Component>> = HashMap::new();

        for comp in self.sbom.components.values() {
            if !self.matches_filter(comp) {
                continue;
            }
            let license = if comp.licenses.declared.is_empty() {
                "Unknown".to_string()
            } else {
                comp.licenses.declared[0].expression.clone()
            };
            license_map.entry(license).or_default().push(comp);
        }

        let mut groups: Vec<TreeNode> = license_map
            .into_iter()
            .map(|(license, mut components)| {
                let vuln_count: usize = components.iter().map(|c| c.vulnerabilities.len()).sum();
                components.sort_by(|a, b| a.name.cmp(&b.name));
                let children: Vec<TreeNode> = components
                    .into_iter()
                    .map(|c| TreeNode::Component {
                        id: c.canonical_id.value().to_string(),
                        name: c.name.clone(),
                        version: c.version.clone(),
                        vuln_count: c.vulnerabilities.len(),
                        max_severity: get_max_severity(c),
                        component_type: Some(
                            crate::tui::widgets::detect_component_type(&c.name).to_string(),
                        ),
                        ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                        is_bookmarked: self.bookmarked.contains(c.canonical_id.value()),
                    })
                    .collect();
                let count = children.len();
                TreeNode::Group {
                    id: format!("lic:{license}"),
                    label: license,
                    children,
                    item_count: count,
                    vuln_count,
                }
            })
            .collect();

        groups.sort_by(|a, b| match (a, b) {
            (
                TreeNode::Group { item_count: ac, label: al, .. },
                TreeNode::Group { item_count: bc, label: bl, .. },
            ) => bc.cmp(ac).then_with(|| al.cmp(bl)),
            _ => std::cmp::Ordering::Equal,
        });

        groups
    }

    fn build_vuln_status_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use crate::tui::widgets::TreeNode;
        use super::severity::severity_category;

        let mut critical_comps = Vec::new();
        let mut high_comps = Vec::new();
        let mut other_vuln_comps = Vec::new();
        let mut clean_comps = Vec::new();

        for comp in self.sbom.components.values() {
            if !self.matches_filter(comp) {
                continue;
            }

            match severity_category(&comp.vulnerabilities) {
                "critical" => critical_comps.push(comp),
                "high" => high_comps.push(comp),
                "clean" => clean_comps.push(comp),
                _ => other_vuln_comps.push(comp),
            }
        }

        let build_group = |label: &str, id: &str, comps: Vec<&Component>, bookmarked: &HashSet<String>| -> TreeNode {
            let vuln_count: usize = comps.iter().map(|c| c.vulnerabilities.len()).sum();
            let children: Vec<TreeNode> = comps
                .into_iter()
                .map(|c| TreeNode::Component {
                    id: c.canonical_id.value().to_string(),
                    name: c.name.clone(),
                    version: c.version.clone(),
                    vuln_count: c.vulnerabilities.len(),
                    max_severity: get_max_severity(c),
                    component_type: Some(
                        crate::tui::widgets::detect_component_type(&c.name).to_string(),
                    ),
                    ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                    is_bookmarked: bookmarked.contains(c.canonical_id.value()),
                })
                .collect();
            let count = children.len();
            TreeNode::Group {
                id: id.to_string(),
                label: label.to_string(),
                children,
                item_count: count,
                vuln_count,
            }
        };

        let mut groups = Vec::new();
        if !critical_comps.is_empty() {
            groups.push(build_group("Critical", "vuln:critical", critical_comps, &self.bookmarked));
        }
        if !high_comps.is_empty() {
            groups.push(build_group("High", "vuln:high", high_comps, &self.bookmarked));
        }
        if !other_vuln_comps.is_empty() {
            groups.push(build_group(
                "Other Vulnerabilities",
                "vuln:other",
                other_vuln_comps,
                &self.bookmarked,
            ));
        }
        if !clean_comps.is_empty() {
            groups.push(build_group("No Vulnerabilities", "vuln:clean", clean_comps, &self.bookmarked));
        }

        groups
    }

    fn build_type_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use crate::tui::widgets::TreeNode;

        let mut type_map: HashMap<&'static str, Vec<&Component>> = HashMap::new();

        for comp in self.sbom.components.values() {
            if !self.matches_filter(comp) {
                continue;
            }
            let comp_type = crate::tui::widgets::detect_component_type(&comp.name);
            type_map.entry(comp_type).or_default().push(comp);
        }

        // Define type order and labels
        let type_order = vec![
            ("lib", "Libraries"),
            ("bin", "Binaries"),
            ("cert", "Certificates"),
            ("fs", "Filesystems"),
            ("file", "Other Files"),
        ];

        let mut groups = Vec::new();
        for (type_key, type_label) in type_order {
            if let Some(mut components) = type_map.remove(type_key) {
                if components.is_empty() {
                    continue;
                }
                let vuln_count: usize = components.iter().map(|c| c.vulnerabilities.len()).sum();
                components.sort_by(|a, b| a.name.cmp(&b.name));
                let children: Vec<TreeNode> = components
                    .into_iter()
                    .map(|c| TreeNode::Component {
                        id: c.canonical_id.value().to_string(),
                        name: c.name.clone(),
                        version: c.version.clone(),
                        vuln_count: c.vulnerabilities.len(),
                        max_severity: get_max_severity(c),
                        component_type: Some(type_key.to_string()),
                        ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                        is_bookmarked: self.bookmarked.contains(c.canonical_id.value()),
                    })
                    .collect();
                let count = children.len();
                groups.push(TreeNode::Group {
                    id: format!("type:{type_key}"),
                    label: type_label.to_string(),
                    children,
                    item_count: count,
                    vuln_count,
                });
            }
        }

        groups
    }

    fn build_flat_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use crate::tui::widgets::TreeNode;

        self.sbom
            .components
            .values()
            .filter(|c| self.matches_filter(c))
            .map(|c| TreeNode::Component {
                id: c.canonical_id.value().to_string(),
                name: c.name.clone(),
                version: c.version.clone(),
                vuln_count: c.vulnerabilities.len(),
                max_severity: get_max_severity(c),
                component_type: Some(
                    crate::tui::widgets::detect_component_type(&c.name).to_string(),
                ),
                ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                is_bookmarked: self.bookmarked.contains(c.canonical_id.value()),
            })
            .collect()
    }

    fn matches_filter(&self, comp: &Component) -> bool {
        use super::severity::severity_matches;

        // Check tree filter first
        let passes_filter = match self.tree_filter {
            TreeFilter::All => true,
            TreeFilter::HasVulnerabilities => !comp.vulnerabilities.is_empty(),
            TreeFilter::Critical => comp
                .vulnerabilities
                .iter()
                .any(|v| severity_matches(v.severity.as_ref(), "critical")),
            TreeFilter::Bookmarked => self.bookmarked.contains(comp.canonical_id.value()),
        };

        if !passes_filter {
            return false;
        }

        // Check search query
        if self.tree_search_query.is_empty() {
            return true;
        }

        let query_lower = self.tree_search_query.to_lowercase();
        let name_lower = comp.name.to_lowercase();

        // Match against name
        if name_lower.contains(&query_lower) {
            return true;
        }

        // Match against version
        if let Some(ref version) = comp.version {
            if version.to_lowercase().contains(&query_lower) {
                return true;
            }
        }

        // Match against ecosystem
        if let Some(ref eco) = comp.ecosystem {
            if eco.to_string().to_lowercase().contains(&query_lower) {
                return true;
            }
        }

        false
    }

    fn tree_group_id_for_component(&self, comp: &Component) -> Option<String> {
        match self.tree_group_by {
            TreeGroupBy::Ecosystem => {
                let eco = comp
                    .ecosystem
                    .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
                Some(format!("eco:{eco}"))
            }
            TreeGroupBy::License => {
                let license = if comp.licenses.declared.is_empty() {
                    "Unknown".to_string()
                } else {
                    comp.licenses.declared[0].expression.clone()
                };
                Some(format!("lic:{license}"))
            }
            TreeGroupBy::VulnStatus => {
                use super::severity::severity_category;
                let group = match severity_category(&comp.vulnerabilities) {
                    "critical" => "vuln:critical",
                    "high" => "vuln:high",
                    "clean" => "vuln:clean",
                    _ => "vuln:other",
                };
                Some(group.to_string())
            }
            TreeGroupBy::ComponentType => {
                let comp_type = crate::tui::widgets::detect_component_type(&comp.name);
                Some(format!("type:{comp_type}"))
            }
            TreeGroupBy::Flat => None,
        }
    }
}

/// Get the maximum severity level from a component's vulnerabilities
fn get_max_severity(comp: &Component) -> Option<String> {
    super::severity::max_severity_from_vulns(&comp.vulnerabilities)
}

/// Selected tree node for navigation.
#[derive(Debug, Clone)]
enum SelectedTreeNode {
    Group(String),
    Component(String),
}

fn flatten_tree_for_selection(
    nodes: &[crate::tui::widgets::TreeNode],
    state: &TreeState,
    items: &mut Vec<SelectedTreeNode>,
) {
    use crate::tui::widgets::TreeNode;

    for node in nodes {
        match node {
            TreeNode::Group { id, children, .. } => {
                items.push(SelectedTreeNode::Group(id.clone()));
                if state.is_expanded(id) {
                    flatten_tree_for_selection(children, state, items);
                }
            }
            TreeNode::Component { id, .. } => {
                items.push(SelectedTreeNode::Component(id.clone()));
            }
        }
    }
}

/// View tabs for the single SBOM viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewTab {
    /// High-level SBOM overview with stats
    Overview,
    /// Hierarchical component tree
    Tree,
    /// Vulnerability explorer
    Vulnerabilities,
    /// License analysis view
    Licenses,
    /// Dependency graph view
    Dependencies,
    /// Quality score view
    Quality,
    /// Compliance validation view
    Compliance,
    /// Original SBOM source viewer
    Source,
}

impl ViewTab {
    #[must_use] 
    pub const fn title(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Tree => "Components",
            Self::Vulnerabilities => "Vulnerabilities",
            Self::Licenses => "Licenses",
            Self::Dependencies => "Dependencies",
            Self::Quality => "Quality",
            Self::Compliance => "Compliance",
            Self::Source => "Source",
        }
    }

    #[must_use] 
    pub const fn shortcut(&self) -> &'static str {
        match self {
            Self::Overview => "1",
            Self::Tree => "2",
            Self::Vulnerabilities => "3",
            Self::Licenses => "4",
            Self::Dependencies => "5",
            Self::Quality => "6",
            Self::Compliance => "7",
            Self::Source => "8",
        }
    }
}

/// Tree grouping modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeGroupBy {
    Ecosystem,
    License,
    VulnStatus,
    ComponentType,
    Flat,
}

impl TreeGroupBy {
    #[must_use] 
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Ecosystem => "Ecosystem",
            Self::License => "License",
            Self::VulnStatus => "Vuln Status",
            Self::ComponentType => "Type",
            Self::Flat => "Flat List",
        }
    }
}

/// Tree filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeFilter {
    All,
    HasVulnerabilities,
    Critical,
    Bookmarked,
}

impl TreeFilter {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::HasVulnerabilities => "Has Vulns",
            Self::Critical => "Critical",
            Self::Bookmarked => "Bookmarked",
        }
    }
}

/// Component detail sub-tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ComponentDetailTab {
    #[default]
    Overview,
    Identifiers,
    Vulnerabilities,
    Dependencies,
}

impl ComponentDetailTab {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Identifiers => "Identifiers",
            Self::Vulnerabilities => "Vulnerabilities",
            Self::Dependencies => "Dependencies",
        }
    }

    pub const fn shortcut(self) -> &'static str {
        match self {
            Self::Overview => "1",
            Self::Identifiers => "2",
            Self::Vulnerabilities => "3",
            Self::Dependencies => "4",
        }
    }

    pub const fn all() -> [Self; 4] {
        [
            Self::Overview,
            Self::Identifiers,
            Self::Vulnerabilities,
            Self::Dependencies,
        ]
    }
}

/// Focus panel (for split views).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FocusPanel {
    Left,
    Right,
}

/// State for vulnerability explorer.
#[derive(Debug, Clone)]
pub(crate) struct VulnExplorerState {
    pub selected: usize,
    pub total: usize,
    pub scroll_offset: usize,
    pub group_by: VulnGroupBy,
    pub sort_by: VulnSortBy,
    pub filter_severity: Option<String>,
    /// When true, deduplicate vulnerabilities by CVE ID and show affected component count
    pub deduplicate: bool,
    /// Local search/filter query for vulnerability list
    pub search_query: String,
    /// Whether search input mode is active
    pub search_active: bool,
    /// Scroll offset for the detail panel (right side)
    pub detail_scroll: u16,
    /// Expanded group IDs for grouped view (severity labels or component names)
    pub expanded_groups: HashSet<String>,
    /// Cache key to detect when we need to rebuild the vulnerability list
    cache_key: Option<VulnCacheKey>,
    /// Cached vulnerability list for performance (Arc-wrapped for zero-cost cloning)
    pub cached_data: Option<super::views::VulnCacheRef>,
}

/// Cache key for vulnerability list - rebuild when any of these change
#[derive(Debug, Clone, PartialEq, Eq)]
struct VulnCacheKey {
    filter_severity: Option<String>,
    deduplicate: bool,
    sort_by: VulnSortBy,
    search_query: String,
}

impl VulnExplorerState {
    pub fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            scroll_offset: 0,
            group_by: VulnGroupBy::Severity,
            sort_by: VulnSortBy::Severity,
            filter_severity: None,
            deduplicate: true,
            search_query: String::new(),
            search_active: false,
            detail_scroll: 0,
            expanded_groups: HashSet::new(),
            cache_key: None,
            cached_data: None,
        }
    }

    /// Get current cache key based on filter settings
    fn current_cache_key(&self) -> VulnCacheKey {
        VulnCacheKey {
            filter_severity: self.filter_severity.clone(),
            deduplicate: self.deduplicate,
            sort_by: self.sort_by,
            search_query: self.search_query.clone(),
        }
    }

    /// Check if cache is valid
    pub fn is_cache_valid(&self) -> bool {
        self.cache_key.as_ref() == Some(&self.current_cache_key()) && self.cached_data.is_some()
    }

    /// Store cache with current settings (wraps in Arc for cheap cloning)
    pub fn set_cache(&mut self, cache: super::views::VulnCache) {
        self.cache_key = Some(self.current_cache_key());
        self.cached_data = Some(std::sync::Arc::new(cache));
    }

    /// Invalidate the cache
    pub fn invalidate_cache(&mut self) {
        self.cache_key = None;
        self.cached_data = None;
    }

    pub const fn select_next(&mut self) {
        if self.total > 0 && self.selected < self.total.saturating_sub(1) {
            self.selected += 1;
            self.detail_scroll = 0;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.detail_scroll = 0;
        }
    }

    /// Scroll detail panel down
    pub const fn detail_scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    /// Scroll detail panel up
    pub const fn detail_scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    /// Ensure selected index is within bounds
    pub const fn clamp_selection(&mut self) {
        if self.total == 0 {
            self.selected = 0;
        } else if self.selected >= self.total {
            self.selected = self.total.saturating_sub(1);
        }
    }

    pub fn toggle_group(&mut self) {
        self.group_by = match self.group_by {
            VulnGroupBy::Severity => VulnGroupBy::Component,
            VulnGroupBy::Component => VulnGroupBy::Flat,
            VulnGroupBy::Flat => VulnGroupBy::Severity,
        };
        self.selected = 0;
        self.expanded_groups.clear();
        self.invalidate_cache();
    }

    /// Toggle expansion of a vulnerability group header.
    pub fn toggle_vuln_group(&mut self, group_id: &str) {
        if self.expanded_groups.contains(group_id) {
            self.expanded_groups.remove(group_id);
        } else {
            self.expanded_groups.insert(group_id.to_string());
        }
    }

    pub fn toggle_filter(&mut self) {
        self.filter_severity = match &self.filter_severity {
            None => Some("critical".to_string()),
            Some(s) if s == "critical" => Some("high".to_string()),
            Some(s) if s == "high" => Some("medium".to_string()),
            Some(s) if s == "medium" => Some("low".to_string()),
            Some(s) if s == "low" => Some("unknown".to_string()),
            Some(s) if s == "unknown" => None,
            _ => None,
        };
        self.selected = 0;
        self.invalidate_cache();
    }

    pub fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
        self.selected = 0;
        self.invalidate_cache();
    }

    pub fn toggle_deduplicate(&mut self) {
        self.deduplicate = !self.deduplicate;
        self.selected = 0;
        self.invalidate_cache();
    }

    /// Start local search mode for vulnerability list
    pub fn start_vuln_search(&mut self) {
        self.search_active = true;
        self.search_query.clear();
    }

    /// Stop search mode (keep query for filtering)
    pub const fn stop_vuln_search(&mut self) {
        self.search_active = false;
    }

    /// Clear search completely
    pub fn clear_vuln_search(&mut self) {
        self.search_active = false;
        self.search_query.clear();
        self.selected = 0;
        self.invalidate_cache();
    }

    /// Push a character to search query
    pub fn search_push(&mut self, c: char) {
        self.search_query.push(c);
        self.selected = 0;
        self.invalidate_cache();
    }

    /// Pop a character from search query
    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.selected = 0;
        self.invalidate_cache();
    }

    /// Get the selected vulnerability.
    pub fn get_selected<'a>(
        &self,
        sbom: &'a NormalizedSbom,
    ) -> Option<(String, &'a VulnerabilityRef)> {
        let mut idx = 0;
        for (comp_id, comp) in &sbom.components {
            for vuln in &comp.vulnerabilities {
                if let Some(ref filter) = self.filter_severity {
                    let sev = vuln.severity.as_ref().map(|s| s.to_string().to_lowercase());
                    if sev.as_deref() != Some(filter) {
                        continue;
                    }
                }
                if idx == self.selected {
                    return Some((comp_id.value().to_string(), vuln));
                }
                idx += 1;
            }
        }
        None
    }
}

impl Default for VulnExplorerState {
    fn default() -> Self {
        Self::new()
    }
}

impl ListNavigation for VulnExplorerState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

/// View mode for quality panel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum QualityViewMode {
    #[default]
    Summary,
    Breakdown,
    Metrics,
    Recommendations,
}

/// Quality view state
pub(crate) struct QualityViewState {
    pub view_mode: QualityViewMode,
    pub selected_recommendation: usize,
    pub total_recommendations: usize,
    pub scroll_offset: usize,
}

impl QualityViewState {
    pub const fn new(total_recommendations: usize) -> Self {
        Self {
            view_mode: QualityViewMode::Summary,
            selected_recommendation: 0,
            total_recommendations,
            scroll_offset: 0,
        }
    }

    pub const fn toggle_view(&mut self) {
        self.view_mode = match self.view_mode {
            QualityViewMode::Summary => QualityViewMode::Breakdown,
            QualityViewMode::Breakdown => QualityViewMode::Metrics,
            QualityViewMode::Metrics => QualityViewMode::Recommendations,
            QualityViewMode::Recommendations => QualityViewMode::Summary,
        };
        self.selected_recommendation = 0;
        self.scroll_offset = 0;
    }

}

impl ListNavigation for QualityViewState {
    fn selected(&self) -> usize {
        self.selected_recommendation
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected_recommendation = idx;
    }

    fn total(&self) -> usize {
        self.total_recommendations
    }

    fn set_total(&mut self, total: usize) {
        self.total_recommendations = total;
    }
}

impl Default for QualityViewState {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Vulnerability grouping modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VulnGroupBy {
    Severity,
    Component,
    Flat,
}

/// Vulnerability sorting modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VulnSortBy {
    Severity,
    Cvss,
    CveId,
    Component,
}

impl VulnSortBy {
    pub const fn next(self) -> Self {
        match self {
            Self::Severity => Self::Cvss,
            Self::Cvss => Self::CveId,
            Self::CveId => Self::Component,
            Self::Component => Self::Severity,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Severity => "Severity",
            Self::Cvss => "CVSS",
            Self::CveId => "CVE ID",
            Self::Component => "Component",
        }
    }
}

/// State for license view.
#[derive(Debug, Clone)]
pub(crate) struct LicenseViewState {
    pub selected: usize,
    pub total: usize,
    pub scroll_offset: usize,
    pub group_by: LicenseGroupBy,
    /// Scroll position within component list in details panel
    pub component_scroll: usize,
    /// Total components for the selected license
    pub component_total: usize,
}

impl LicenseViewState {
    pub const fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            scroll_offset: 0,
            group_by: LicenseGroupBy::License,
            component_scroll: 0,
            component_total: 0,
        }
    }

    /// Scroll component list up
    pub const fn scroll_components_up(&mut self) {
        if self.component_scroll > 0 {
            self.component_scroll -= 1;
        }
    }

    /// Scroll component list down
    pub const fn scroll_components_down(&mut self, visible_count: usize) {
        if self.component_total > visible_count
            && self.component_scroll < self.component_total - visible_count
        {
            self.component_scroll += 1;
        }
    }

    /// Reset component scroll when license selection changes
    pub const fn reset_component_scroll(&mut self) {
        self.component_scroll = 0;
    }

    pub const fn select_next(&mut self) {
        if self.total > 0 && self.selected < self.total.saturating_sub(1) {
            self.selected += 1;
            self.reset_component_scroll();
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.reset_component_scroll();
        }
    }

    /// Ensure selected index is within bounds
    pub const fn clamp_selection(&mut self) {
        if self.total == 0 {
            self.selected = 0;
        } else if self.selected >= self.total {
            self.selected = self.total.saturating_sub(1);
        }
    }

    pub const fn toggle_group(&mut self) {
        self.group_by = match self.group_by {
            LicenseGroupBy::License => LicenseGroupBy::Category,
            LicenseGroupBy::Category => LicenseGroupBy::License,
        };
        self.selected = 0;
        self.reset_component_scroll();
    }
}

impl Default for LicenseViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl ListNavigation for LicenseViewState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

/// License grouping modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LicenseGroupBy {
    License,
    Category,
}

/// Dependency view state.
#[derive(Debug, Clone)]
pub(crate) struct DependencyViewState {
    /// Currently selected node in the dependency tree
    pub selected: usize,
    /// Total number of visible nodes
    pub total: usize,
    /// Set of expanded node IDs
    pub expanded: HashSet<String>,
    /// Scroll offset for the tree view
    pub scroll_offset: usize,
}

impl DependencyViewState {
    pub fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            expanded: HashSet::new(),
            scroll_offset: 0,
        }
    }

    pub fn toggle_expand(&mut self, node_id: &str) {
        if self.expanded.contains(node_id) {
            self.expanded.remove(node_id);
        } else {
            self.expanded.insert(node_id.to_string());
        }
    }

    pub fn is_expanded(&self, node_id: &str) -> bool {
        self.expanded.contains(node_id)
    }
}

impl Default for DependencyViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl ListNavigation for DependencyViewState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

/// Global search state.
#[derive(Debug, Clone)]
pub(crate) struct SearchState {
    pub active: bool,
    pub query: String,
    pub results: Vec<SearchResult>,
    pub selected: usize,
}

impl SearchState {
    pub const fn new() -> Self {
        Self {
            active: false,
            query: String::new(),
            results: Vec::new(),
            selected: 0,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
    }

    pub fn select_next(&mut self) {
        if !self.results.is_empty() && self.selected < self.results.len() - 1 {
            self.selected += 1;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
}

impl Default for SearchState {
    fn default() -> Self {
        Self::new()
    }
}

/// Search result types.
#[derive(Debug, Clone)]
pub(crate) enum SearchResult {
    Component {
        id: String,
        name: String,
        version: Option<String>,
        match_field: String,
    },
    Vulnerability {
        id: String,
        /// Component canonical ID for navigation
        component_id: String,
        /// Component name for display
        component_name: String,
        severity: Option<String>,
    },
}

/// Cached SBOM statistics.
#[derive(Debug, Clone)]
pub struct SbomStats {
    pub component_count: usize,
    pub vuln_count: usize,
    pub license_count: usize,
    pub ecosystem_counts: HashMap<String, usize>,
    pub vuln_by_severity: HashMap<String, usize>,
    pub license_counts: HashMap<String, usize>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unknown_count: usize,
}

impl SbomStats {
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut ecosystem_counts: HashMap<String, usize> = HashMap::new();
        let mut vuln_by_severity: HashMap<String, usize> = HashMap::new();
        let mut license_counts: HashMap<String, usize> = HashMap::new();
        let mut vuln_count = 0;
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut unknown_count = 0;

        for comp in sbom.components.values() {
            // Count ecosystems
            let eco = comp
                .ecosystem
                .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
            *ecosystem_counts.entry(eco).or_insert(0) += 1;

            // Count licenses
            for lic in &comp.licenses.declared {
                *license_counts.entry(lic.expression.clone()).or_insert(0) += 1;
            }
            if comp.licenses.declared.is_empty() {
                *license_counts.entry("Unknown".to_string()).or_insert(0) += 1;
            }

            // Count vulnerabilities
            for vuln in &comp.vulnerabilities {
                vuln_count += 1;
                let sev = vuln
                    .severity
                    .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
                *vuln_by_severity.entry(sev.clone()).or_insert(0) += 1;

                match sev.to_lowercase().as_str() {
                    "critical" => critical_count += 1,
                    "high" => high_count += 1,
                    "medium" => medium_count += 1,
                    "low" => low_count += 1,
                    _ => unknown_count += 1,
                }
            }
        }

        Self {
            component_count: sbom.components.len(),
            vuln_count,
            license_count: license_counts.len(),
            ecosystem_counts,
            vuln_by_severity,
            license_counts,
            critical_count,
            high_count,
            medium_count,
            low_count,
            unknown_count,
        }
    }
}

/// Breadcrumb entry for navigation history in view mode.
#[derive(Debug, Clone)]
pub struct ViewBreadcrumb {
    /// Tab we came from
    pub tab: ViewTab,
    /// Description of what was selected (e.g., "CVE-2024-1234", "lodash")
    pub label: String,
    /// Selection index to restore when going back
    pub selection_index: usize,
}

/// Navigation context for cross-view navigation and breadcrumbs in view mode.
#[derive(Debug, Clone, Default)]
pub struct ViewNavigationContext {
    /// Breadcrumb trail for back navigation
    pub breadcrumbs: Vec<ViewBreadcrumb>,
    /// Target component name to navigate to (for vuln → component navigation)
    pub target_component: Option<String>,
    /// Target vulnerability ID to navigate to (for component → vuln navigation)
    pub target_vulnerability: Option<String>,
}

impl ViewNavigationContext {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            breadcrumbs: Vec::new(),
            target_component: None,
            target_vulnerability: None,
        }
    }

    /// Push a new breadcrumb onto the trail
    pub fn push_breadcrumb(&mut self, tab: ViewTab, label: String, selection_index: usize) {
        self.breadcrumbs.push(ViewBreadcrumb {
            tab,
            label,
            selection_index,
        });
    }

    /// Pop the last breadcrumb and return it (for back navigation)
    pub fn pop_breadcrumb(&mut self) -> Option<ViewBreadcrumb> {
        self.breadcrumbs.pop()
    }

    /// Clear all breadcrumbs (on explicit tab switch)
    pub fn clear_breadcrumbs(&mut self) {
        self.breadcrumbs.clear();
    }

    /// Check if we have navigation history
    #[must_use] 
    pub fn has_history(&self) -> bool {
        !self.breadcrumbs.is_empty()
    }

    /// Get the current breadcrumb trail as a string
    #[must_use] 
    pub fn breadcrumb_trail(&self) -> String {
        self.breadcrumbs
            .iter()
            .map(|b| format!("{}: {}", b.tab.title(), b.label))
            .collect::<Vec<_>>()
            .join(" > ")
    }

    /// Clear navigation targets
    pub fn clear_targets(&mut self) {
        self.target_component = None;
        self.target_vulnerability = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NormalizedSbom;

    #[test]
    fn test_view_app_creation() {
        let sbom = NormalizedSbom::default();
        let app = ViewApp::new(sbom, "");
        assert_eq!(app.active_tab, ViewTab::Overview);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_tab_navigation() {
        let sbom = NormalizedSbom::default();
        let mut app = ViewApp::new(sbom, "");

        app.next_tab();
        assert_eq!(app.active_tab, ViewTab::Tree);

        app.next_tab();
        assert_eq!(app.active_tab, ViewTab::Vulnerabilities);

        app.prev_tab();
        assert_eq!(app.active_tab, ViewTab::Tree);
    }

    #[test]
    fn test_vuln_state_navigation_with_zero_total() {
        // This was causing a crash due to underflow: total - 1 when total = 0
        let mut state = VulnExplorerState::new();
        assert_eq!(state.total, 0);
        assert_eq!(state.selected, 0);

        // This should not panic or change selection
        state.select_next();
        assert_eq!(state.selected, 0);

        state.select_prev();
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn test_vuln_state_clamp_selection() {
        let mut state = VulnExplorerState::new();
        state.total = 5;
        state.selected = 10; // Out of bounds

        state.clamp_selection();
        assert_eq!(state.selected, 4); // Should be clamped to last valid index

        state.total = 0;
        state.clamp_selection();
        assert_eq!(state.selected, 0); // Should be 0 when empty
    }

    #[test]
    fn test_license_state_navigation_with_zero_total() {
        let mut state = LicenseViewState::new();
        assert_eq!(state.total, 0);
        assert_eq!(state.selected, 0);

        // This should not panic or change selection
        state.select_next();
        assert_eq!(state.selected, 0);

        state.select_prev();
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn test_license_state_clamp_selection() {
        let mut state = LicenseViewState::new();
        state.total = 3;
        state.selected = 5; // Out of bounds

        state.clamp_selection();
        assert_eq!(state.selected, 2); // Should be clamped to last valid index
    }

    #[test]
    fn test_dependency_state_navigation() {
        let mut state = DependencyViewState::new();
        assert_eq!(state.total, 0);
        assert_eq!(state.selected, 0);

        // Test with zero total - should not change
        state.select_next();
        assert_eq!(state.selected, 0);

        // Test with items
        state.total = 5;
        state.select_next();
        assert_eq!(state.selected, 1);

        state.select_next();
        state.select_next();
        state.select_next();
        assert_eq!(state.selected, 4); // At end

        state.select_next();
        assert_eq!(state.selected, 4); // Should not go past end

        state.select_prev();
        assert_eq!(state.selected, 3);
    }

    #[test]
    fn test_dependency_state_expand_collapse() {
        let mut state = DependencyViewState::new();

        assert!(!state.is_expanded("node1"));

        state.toggle_expand("node1");
        assert!(state.is_expanded("node1"));

        state.toggle_expand("node1");
        assert!(!state.is_expanded("node1"));
    }
}
