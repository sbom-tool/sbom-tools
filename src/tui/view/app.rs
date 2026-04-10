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

use super::views::{StandardComplianceState, compute_compliance_results};

/// Main application state for single SBOM viewing.
pub struct ViewApp {
    /// The SBOM being viewed
    pub(crate) sbom: NormalizedSbom,

    /// BOM profile (SBOM / CBOM) — determines tab set and mode-specific behavior
    pub(crate) bom_profile: crate::model::BomProfile,

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

    /// Cached tree nodes — rebuilt only when group_by, filter, or search_query change
    pub(crate) cached_tree_nodes: Vec<crate::tui::widgets::TreeNode>,
    /// Cache key for tree nodes
    tree_cache_key: Option<TreeCacheKey>,

    /// Selected component ID (for detail panel)
    pub(crate) selected_component: Option<String>,

    /// Component detail sub-tab
    pub(crate) component_tab: ComponentDetailTab,

    /// Scroll offset for the component detail panel (Overview/Identifiers etc.)
    pub(crate) component_detail_scroll: u16,

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

    /// When true, the status message survives one extra keypress before clearing.
    pub(crate) status_sticky: bool,

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

    /// Legacy Crypto tab: selected list index (all asset types)
    pub(crate) crypto_list_selected: usize,
    /// CBOM Algorithms tab: selected index
    pub(crate) algorithms_selected: usize,
    /// CBOM Certificates tab: selected index
    pub(crate) certificates_selected: usize,
    /// CBOM Keys tab: selected index
    pub(crate) keys_selected: usize,
    /// CBOM Protocols tab: selected index
    pub(crate) protocols_selected: usize,

    /// CBOM Algorithms tab: sort order
    pub(crate) algorithm_sort_by: AlgorithmSortBy,

    /// Bookmarked component canonical IDs (in-memory, no persistence)
    pub(crate) bookmarked: HashSet<String>,

    /// Optional export filename template (from `--export-template` CLI arg).
    pub(crate) export_template: Option<String>,
}

impl ViewApp {
    /// Create a new `ViewApp` for the given SBOM.
    #[must_use]
    pub fn new(
        sbom: NormalizedSbom,
        raw_content: &str,
        bom_profile: crate::model::BomProfile,
    ) -> Self {
        let stats = SbomStats::from_sbom(&sbom);

        // Calculate quality score
        let scoring_profile = match bom_profile {
            crate::model::BomProfile::Cbom => ScoringProfile::Cbom,
            crate::model::BomProfile::Sbom => ScoringProfile::Standard,
        };
        let scorer = QualityScorer::new(scoring_profile);
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

        // Restore last active tab from preferences (must be valid for this profile)
        let available_tabs = ViewTab::tabs_for_profile(bom_profile);
        let initial_tab = crate::config::TuiPreferences::load()
            .last_view_tab
            .as_deref()
            .and_then(ViewTab::from_str_opt)
            .filter(|t| available_tabs.contains(t))
            .unwrap_or(ViewTab::Overview);

        let mut app = Self {
            sbom,
            bom_profile,
            active_tab: initial_tab,
            tree_state,
            tree_group_by: TreeGroupBy::Ecosystem,
            tree_filter: TreeFilter::All,
            tree_search_query: String::new(),
            tree_search_active: false,
            cached_tree_nodes: Vec::new(),
            tree_cache_key: None,
            selected_component: None,
            component_tab: ComponentDetailTab::Overview,
            component_detail_scroll: 0,
            vuln_state: VulnExplorerState::new(),
            license_state: LicenseViewState::new(),
            dependency_state: DependencyViewState::new(),
            search_state: SearchState::new(),
            focus_panel: FocusPanel::Left,
            show_help: false,
            show_export: false,
            show_legend: false,
            status_message: None,
            status_sticky: false,
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
            crypto_list_selected: 0,
            algorithms_selected: 0,
            certificates_selected: 0,
            keys_selected: 0,
            protocols_selected: 0,
            algorithm_sort_by: AlgorithmSortBy::default(),
            bookmarked: HashSet::new(),
            export_template: None,
        };

        // Pre-compute vuln cache at startup to avoid freeze on first tab visit
        let cache = super::views::build_vuln_cache(&app);
        app.vuln_state.set_cache(cache);

        app
    }

    /// Lazily compute compliance results for all standards when first needed.
    pub fn ensure_compliance_results(&mut self) {
        if self.compliance_results.is_none() {
            self.compliance_results = Some(compute_compliance_results(&self.sbom));
        }
    }

    /// Switch to the next tab (cycles within profile's tab set).
    pub fn next_tab(&mut self) {
        let tabs = ViewTab::tabs_for_profile(self.bom_profile);
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + 1) % tabs.len()];
        self.focus_panel = FocusPanel::Left;
    }

    /// Switch to the previous tab (cycles within profile's tab set).
    pub fn prev_tab(&mut self) {
        let tabs = ViewTab::tabs_for_profile(self.bom_profile);
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + tabs.len() - 1) % tabs.len()];
        self.focus_panel = FocusPanel::Left;
    }

    /// Select a specific tab, resetting focus to the left (list) panel.
    pub fn select_tab(&mut self, tab: ViewTab) {
        self.active_tab = tab;
        self.focus_panel = FocusPanel::Left;
    }

    // ========================================================================
    // CBOM per-tab selection helpers
    // ========================================================================

    /// Get the selection index for the active CBOM tab.
    pub fn active_crypto_selected(&self) -> usize {
        match self.active_tab {
            ViewTab::Algorithms => self.algorithms_selected,
            ViewTab::Certificates => self.certificates_selected,
            ViewTab::Keys => self.keys_selected,
            ViewTab::Protocols => self.protocols_selected,
            _ => self.crypto_list_selected,
        }
    }

    /// Get a mutable reference to the selection index for the active CBOM tab.
    pub fn active_crypto_selected_mut(&mut self) -> &mut usize {
        match self.active_tab {
            ViewTab::Algorithms => &mut self.algorithms_selected,
            ViewTab::Certificates => &mut self.certificates_selected,
            ViewTab::Keys => &mut self.keys_selected,
            ViewTab::Protocols => &mut self.protocols_selected,
            _ => &mut self.crypto_list_selected,
        }
    }

    /// Count crypto components for the active tab (filtered by asset type).
    pub fn crypto_count_for_tab(&self) -> usize {
        use crate::model::{ComponentType, CryptoAssetType};
        let filter = match self.active_tab {
            ViewTab::Algorithms => Some(CryptoAssetType::Algorithm),
            ViewTab::Certificates => Some(CryptoAssetType::Certificate),
            ViewTab::Keys => Some(CryptoAssetType::RelatedCryptoMaterial),
            ViewTab::Protocols => Some(CryptoAssetType::Protocol),
            _ => None,
        };
        self.sbom
            .components
            .values()
            .filter(|c| {
                c.component_type == ComponentType::Cryptographic
                    && filter.as_ref().is_none_or(|f| {
                        c.crypto_properties
                            .as_ref()
                            .is_some_and(|cp| &cp.asset_type == f)
                    })
            })
            .count()
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
            } else if let Some(purl) = &comp.identifiers.purl
                && purl.to_lowercase().contains(&query_lower)
            {
                results.push(SearchResult::Component {
                    id: id.value().to_string(),
                    name: comp.name.clone(),
                    version: comp.version.clone(),
                    match_field: "purl".to_string(),
                });
            }
        }

        // Search vulnerabilities
        for (_, comp) in &self.sbom.components {
            for vuln in &comp.vulnerabilities {
                if vuln.id.to_lowercase().contains(&query_lower) {
                    results.push(SearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_id: comp.canonical_id.to_string(), // Store ID for navigation
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

        self.ensure_tree_cache();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(&self.cached_tree_nodes, &self.tree_state, &mut flat_items);

        if let Some(index) = flat_items
            .iter()
            .position(|item| matches!(item, SelectedTreeNode::Component(id) if id == component_id))
        {
            self.tree_state.selected = index;
            return true;
        }

        if let Some(group_id) = group_id
            && let Some(index) = flat_items
                .iter()
                .position(|item| matches!(item, SelectedTreeNode::Group(id) if id == &group_id))
        {
            self.tree_state.selected = index;
        }

        false
    }

    /// Jump to a vulnerability by its ID (e.g., "CVE-2024-1234") in the Vulnerabilities tab.
    ///
    /// Returns `true` if the vulnerability was found and selected.
    pub fn jump_to_vuln_by_id(&mut self, vuln_id: &str) -> bool {
        // Ensure cache is built
        if self.vuln_state.cached_data.is_none() {
            let cache = super::views::build_vuln_cache(self);
            self.vuln_state.cached_data = Some(std::sync::Arc::new(cache));
        }
        let Some(cache) = &self.vuln_state.cached_data else {
            return false;
        };
        // Find the vuln in the cache by ID
        if let Some(vuln_idx) = cache.vulns.iter().position(|v| v.vuln_id == vuln_id) {
            // In flat mode, the display item index matches the vuln index
            // In grouped mode, we need to find the VulnDisplayItem that wraps this vuln
            let display_idx = self
                .vuln_state
                .cached_display_items
                .iter()
                .position(|item| {
                    matches!(item, super::views::VulnDisplayItem::Vuln { idx, .. } if *idx == vuln_idx)
                })
                .unwrap_or(vuln_idx);
            self.vuln_state.selected = display_idx;
            return true;
        }
        false
    }

    /// Find a source tree item whose value matches a given reference string (bom-ref, CVE ID, etc.)
    /// and return its index in `cached_flat_items`.
    pub fn find_source_item_for_ref(&mut self, ref_value: &str) -> Option<usize> {
        self.source_state.ensure_flat_cache();
        let quoted = format!("\"{ref_value}\"");
        self.source_state
            .cached_flat_items
            .iter()
            .position(|item| item.value_preview == quoted || item.value_preview == ref_value)
    }

    /// Get the currently selected tree node info (Group label + children component IDs,
    /// or None if a component is selected or nothing is selected).
    #[must_use]
    pub fn get_selected_group_info(&self) -> Option<(String, Vec<String>)> {
        let nodes = self.build_tree_nodes();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(nodes, &self.tree_state, &mut flat_items);

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
                find_group_children(nodes, group_id)
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
        self.component_detail_scroll = 0;
    }

    /// Cycle to previous component detail tab.
    pub const fn prev_component_tab(&mut self) {
        self.component_tab = match self.component_tab {
            ComponentDetailTab::Overview => ComponentDetailTab::Dependencies,
            ComponentDetailTab::Identifiers => ComponentDetailTab::Overview,
            ComponentDetailTab::Vulnerabilities => ComponentDetailTab::Identifiers,
            ComponentDetailTab::Dependencies => ComponentDetailTab::Vulnerabilities,
        };
        self.component_detail_scroll = 0;
    }

    /// Select a specific component detail tab.
    pub(crate) const fn select_component_tab(&mut self, tab: ComponentDetailTab) {
        self.component_tab = tab;
        self.component_detail_scroll = 0;
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
    ///
    /// If `status_sticky` is set the message is kept for one extra keypress,
    /// then cleared on the subsequent call.
    pub fn clear_status_message(&mut self) {
        if self.status_sticky {
            self.status_sticky = false;
        } else {
            self.status_message = None;
        }
    }

    /// Export the current SBOM to a file.
    ///
    /// The export is scoped to the active tab: e.g. if the user is on the
    /// Vulnerabilities tab only vulnerability data is included.
    pub fn export(&mut self, format: crate::tui::export::ExportFormat) {
        use crate::reports::ReportConfig;
        use crate::tui::export::{export_view, view_tab_to_report_type};

        let report_type = view_tab_to_report_type(self.active_tab);
        let config = ReportConfig::with_types(vec![report_type]);
        let result = export_view(
            format,
            &self.sbom,
            None,
            &config,
            self.export_template.as_deref(),
        );

        if result.success {
            self.set_status_message(result.message);
            self.status_sticky = true;
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
            self.export_template.as_deref(),
        );
        if result.success {
            self.set_status_message(result.message);
            self.status_sticky = true;
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
            ViewTab::Crypto
            | ViewTab::Algorithms
            | ViewTab::Certificates
            | ViewTab::Keys
            | ViewTab::Protocols => {
                let sel = self.active_crypto_selected_mut();
                *sel = sel.saturating_sub(1);
            }
            ViewTab::Overview | ViewTab::PqcCompliance => {}
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
            ViewTab::Crypto
            | ViewTab::Algorithms
            | ViewTab::Certificates
            | ViewTab::Keys
            | ViewTab::Protocols => {
                let max = self.crypto_count_for_tab().saturating_sub(1);
                let sel = self.active_crypto_selected_mut();
                *sel = sel.saturating_add(1).min(max);
            }
            ViewTab::Overview | ViewTab::PqcCompliance => {}
        }
    }

    /// Count compliance violations that pass the current severity filter.
    pub(crate) fn filtered_compliance_violation_count(&self) -> usize {
        self.compliance_results
            .as_ref()
            .and_then(|r| r.get(self.compliance_state.selected_standard))
            .map_or(0, |r| {
                if self.compliance_state.grouped {
                    // In grouped mode, count is the number of groups
                    super::views::build_groups(r, self.compliance_state.severity_filter).len()
                } else {
                    r.violations
                        .iter()
                        .filter(|v| self.compliance_state.severity_filter.matches(v.severity))
                        .count()
                }
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
    pub fn go_first(&mut self) {
        match self.active_tab {
            ViewTab::Tree => self.tree_state.select_first(),
            ViewTab::Vulnerabilities => self.vuln_state.selected = 0,
            ViewTab::Licenses => self.license_state.selected = 0,
            ViewTab::Dependencies => self.dependency_state.selected = 0,
            ViewTab::Quality => self.quality_state.scroll_offset = 0,
            ViewTab::Compliance => self.compliance_state.selected_violation = 0,
            ViewTab::Source => self.source_state.select_first(),
            ViewTab::Crypto
            | ViewTab::Algorithms
            | ViewTab::Certificates
            | ViewTab::Keys
            | ViewTab::Protocols => *self.active_crypto_selected_mut() = 0,
            ViewTab::Overview | ViewTab::PqcCompliance => {}
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
            ViewTab::Crypto
            | ViewTab::Algorithms
            | ViewTab::Certificates
            | ViewTab::Keys
            | ViewTab::Protocols => {
                let max = self.crypto_count_for_tab();
                *self.active_crypto_selected_mut() = max.saturating_sub(1);
            }
            ViewTab::Overview | ViewTab::PqcCompliance => {}
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
                if self.vuln_state.group_by != VulnGroupBy::Flat
                    && let Some(item) = self
                        .vuln_state
                        .cached_display_items
                        .get(self.vuln_state.selected)
                {
                    match item {
                        super::views::VulnDisplayItem::GroupHeader { label, .. } => {
                            let label = label.clone();
                            self.vuln_state.toggle_vuln_group(&label);
                            return;
                        }
                        super::views::VulnDisplayItem::SubGroupHeader {
                            parent_label,
                            label,
                            ..
                        } => {
                            let key = format!("{parent_label}::{label}");
                            self.vuln_state.toggle_vuln_group(&key);
                            return;
                        }
                        super::views::VulnDisplayItem::Vuln { .. } => {
                            // Fall through to normal navigation
                        }
                    }
                }
                // Navigate to component in Tree tab with proper targeting
                if let Some(cache) = &self.vuln_state.cached_data.clone()
                    && let Some((comp_id, vuln_id)) = self.vuln_state.get_nav_component_id(cache)
                {
                    // Push breadcrumb so Backspace returns here
                    self.navigation_ctx.push_breadcrumb(
                        ViewTab::Vulnerabilities,
                        vuln_id.clone(),
                        self.vuln_state.selected,
                    );
                    self.selected_component = Some(comp_id.clone());
                    self.component_tab = ComponentDetailTab::Overview;
                    self.active_tab = ViewTab::Tree;
                    self.focus_panel = FocusPanel::Right;
                    self.jump_to_component_in_tree(&comp_id);
                    self.set_status_message(format!("→ {vuln_id} (Backspace to return)"));
                }
            }
            ViewTab::Licenses => {
                // Navigate to the first component with this license in the Tree tab
                let license_data = super::views::build_license_data_from_app(self);
                let selected_idx = self
                    .license_state
                    .selected
                    .min(license_data.len().saturating_sub(1));
                if let Some((license, _, _)) = license_data.get(selected_idx)
                    && let Some(comp_id) =
                        super::views::get_first_component_id_for_license(self, license)
                {
                    self.navigation_ctx.push_breadcrumb(
                        ViewTab::Licenses,
                        license.clone(),
                        self.license_state.selected,
                    );
                    self.selected_component = Some(comp_id.clone());
                    self.component_tab = ComponentDetailTab::Overview;
                    self.active_tab = ViewTab::Tree;
                    self.focus_panel = FocusPanel::Right;
                    self.jump_to_component_in_tree(&comp_id);
                    self.set_status_message(format!("→ {license} (Backspace to return)"));
                }
            }
            ViewTab::Dependencies => {
                if let Some(node_id) = self.get_selected_dependency_node_id() {
                    // If node has children, toggle expand; if leaf, navigate to Tree tab
                    let is_leaf = self
                        .dependency_state
                        .cached_flat_nodes
                        .get(self.dependency_state.selected)
                        .is_some_and(|n| !n.has_children);
                    if is_leaf {
                        // Cross-tab navigation: jump to component in Tree view
                        let display_name = self
                            .dependency_state
                            .cached_flat_nodes
                            .get(self.dependency_state.selected)
                            .map(|n| n.name.clone())
                            .unwrap_or_default();
                        self.navigation_ctx.push_breadcrumb(
                            ViewTab::Dependencies,
                            display_name.clone(),
                            self.dependency_state.selected,
                        );
                        self.selected_component = Some(node_id.clone());
                        self.component_tab = ComponentDetailTab::Overview;
                        self.active_tab = ViewTab::Tree;
                        self.focus_panel = FocusPanel::Right;
                        self.jump_to_component_in_tree(&node_id);
                        self.set_status_message(format!("→ {display_name} (Backspace to return)"));
                    } else {
                        self.dependency_state.toggle_expand(&node_id);
                    }
                }
            }
            ViewTab::Compliance => {
                // Toggle violation detail overlay
                self.ensure_compliance_results();
                let idx = self.compliance_state.selected_standard;
                let has_violations = self
                    .compliance_results
                    .as_ref()
                    .and_then(|r| r.get(idx))
                    .is_some_and(|r| !r.violations.is_empty());
                if has_violations {
                    self.compliance_state.show_detail = !self.compliance_state.show_detail;
                }
            }
            ViewTab::Source => {
                // Toggle expand/collapse in tree mode
                if self.source_state.view_mode == crate::tui::app_states::SourceViewMode::Tree
                    && let Some(ref tree) = self.source_state.json_tree
                {
                    let mut items = Vec::new();
                    crate::tui::shared::source::flatten_json_tree(
                        tree,
                        "",
                        0,
                        &self.source_state.expanded,
                        &mut items,
                        true,
                        &[],
                        self.source_state.sort_mode,
                        "",
                    );
                    if let Some(item) = items.get(self.source_state.selected)
                        && item.is_expandable
                    {
                        let node_id = item.node_id.clone();
                        self.source_state.toggle_expand(&node_id);
                    }
                }
            }
            ViewTab::Quality => {
                if self.quality_state.view_mode == QualityViewMode::Summary {
                    // Jump to Recommendations view preserving selection
                    self.quality_state.view_mode = QualityViewMode::Recommendations;
                }
            }
            ViewTab::Overview
            | ViewTab::Crypto
            | ViewTab::Algorithms
            | ViewTab::Certificates
            | ViewTab::Keys
            | ViewTab::Protocols
            | ViewTab::PqcCompliance => {}
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
        let expandable: Vec<_> = children.iter().filter(|c| c.is_expandable()).collect();

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
                    tree,
                    "",
                    0,
                    &self.source_state.expanded,
                    &mut items,
                    true,
                    &[],
                    self.source_state.sort_mode,
                    "",
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
                    if line.contains(&search) && line.starts_with("  ") && !line.starts_with("    ")
                    {
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
            self.source_state.sort_mode,
            "",
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
        // Use cached flat nodes if available (much faster than rebuilding tree)
        if !self.dependency_state.cached_flat_nodes.is_empty() {
            return self
                .dependency_state
                .cached_flat_nodes
                .get(self.dependency_state.selected)
                .map(|n| n.id.clone());
        }
        // Fallback: build the flattened list (only before first render)
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

        if self.dependency_state.is_expanded(node_id)
            && let Some(children) = edges.get(node_id)
        {
            for child in children {
                self.collect_dep_nodes_recursive(child, edges, nodes, visited);
            }
        }
    }

    /// Get the currently selected tree node.
    fn get_selected_tree_node(&self) -> Option<SelectedTreeNode> {
        let nodes = self.build_tree_nodes();
        let mut flat_items = Vec::new();
        flatten_tree_for_selection(nodes, &self.tree_state, &mut flat_items);

        flat_items.get(self.tree_state.selected).cloned()
    }

    /// Ensure tree node cache is valid, rebuilding if needed.
    pub fn ensure_tree_cache(&mut self) {
        let current_key = TreeCacheKey {
            group_by: self.tree_group_by,
            filter: self.tree_filter,
            search_query: self.tree_search_query.clone(),
        };
        if self.tree_cache_key.as_ref() != Some(&current_key) {
            self.cached_tree_nodes = match self.tree_group_by {
                TreeGroupBy::Ecosystem => self.build_ecosystem_tree(),
                TreeGroupBy::License => self.build_license_tree(),
                TreeGroupBy::VulnStatus => self.build_vuln_status_tree(),
                TreeGroupBy::ComponentType => self.build_type_tree(),
                TreeGroupBy::Flat => self.build_flat_tree(),
            };
            self.tree_cache_key = Some(current_key);
        }
    }

    /// Get tree nodes from cache (returns empty slice if cache not yet built).
    /// For render paths, call `ensure_tree_cache()` first.
    /// For event handlers that only need to read, the cache is always warm after first render.
    pub fn build_tree_nodes(&self) -> &[crate::tui::widgets::TreeNode] {
        &self.cached_tree_nodes
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
                .as_ref()
                .map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
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
                TreeNode::Group {
                    item_count: ac,
                    label: al,
                    ..
                },
                TreeNode::Group {
                    item_count: bc,
                    label: bl,
                    ..
                },
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
                TreeNode::Group {
                    item_count: ac,
                    label: al,
                    ..
                },
                TreeNode::Group {
                    item_count: bc,
                    label: bl,
                    ..
                },
            ) => bc.cmp(ac).then_with(|| al.cmp(bl)),
            _ => std::cmp::Ordering::Equal,
        });

        groups
    }

    fn build_vuln_status_tree(&self) -> Vec<crate::tui::widgets::TreeNode> {
        use super::severity::severity_category;
        use crate::tui::widgets::TreeNode;

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

        let build_group = |label: &str,
                           id: &str,
                           comps: Vec<&Component>,
                           bookmarked: &HashSet<String>|
         -> TreeNode {
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
            groups.push(build_group(
                "Critical",
                "vuln:critical",
                critical_comps,
                &self.bookmarked,
            ));
        }
        if !high_comps.is_empty() {
            groups.push(build_group(
                "High",
                "vuln:high",
                high_comps,
                &self.bookmarked,
            ));
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
            groups.push(build_group(
                "No Vulnerabilities",
                "vuln:clean",
                clean_comps,
                &self.bookmarked,
            ));
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
        if let Some(ref version) = comp.version
            && version.to_lowercase().contains(&query_lower)
        {
            return true;
        }

        // Match against ecosystem
        if let Some(ref eco) = comp.ecosystem
            && eco.to_string().to_lowercase().contains(&query_lower)
        {
            return true;
        }

        false
    }

    fn tree_group_id_for_component(&self, comp: &Component) -> Option<String> {
        match self.tree_group_by {
            TreeGroupBy::Ecosystem => {
                let eco = comp
                    .ecosystem
                    .as_ref()
                    .map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
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
    // ── Shared across profiles ──
    /// Overview: SBOM stats or CBOM quantum dashboard (adapts per profile)
    Overview,
    /// Quality score view (metrics adapt per profile)
    Quality,
    /// Original SBOM source viewer
    Source,

    // ── SBOM-specific ──
    /// Hierarchical component tree
    Tree,
    /// Vulnerability explorer
    Vulnerabilities,
    /// License analysis view
    Licenses,
    /// Dependency graph view
    Dependencies,
    /// Compliance validation view (NTIA/CRA/FDA/SSDF/EO14028)
    Compliance,

    // ── CBOM-specific ──
    /// Algorithm inventory with quantum readiness indicators
    Algorithms,
    /// Certificate validity tracking and expiry timeline
    Certificates,
    /// Key material state monitoring
    Keys,
    /// Protocol and cipher suite analysis
    Protocols,
    /// PQC compliance (CNSA 2.0 + NIST PQC dedicated view)
    PqcCompliance,

    // ── Legacy ──
    /// Single crypto tab (kept for preference migration)
    Crypto,
}

impl ViewTab {
    /// Tab display title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Quality => "Quality",
            Self::Source => "Source",
            Self::Tree => "Components",
            Self::Vulnerabilities => "Vulns",
            Self::Licenses => "Licenses",
            Self::Dependencies => "Deps",
            Self::Compliance => "Compliance",
            Self::Algorithms => "Algorithms",
            Self::Certificates => "Certs",
            Self::Keys => "Keys",
            Self::Protocols => "Protocols",
            Self::PqcCompliance => "PQC Compliance",
            Self::Crypto => "Crypto",
        }
    }

    /// Positional shortcut key based on tab position in the profile's tab set.
    #[must_use]
    pub fn shortcut_for_profile(&self, profile: crate::model::BomProfile) -> Option<usize> {
        Self::tabs_for_profile(profile)
            .iter()
            .position(|t| t == self)
            .map(|i| i + 1)
    }

    /// Stable string identifier for persistence.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Quality => "quality",
            Self::Source => "source",
            Self::Tree => "tree",
            Self::Vulnerabilities => "vulnerabilities",
            Self::Licenses => "licenses",
            Self::Dependencies => "dependencies",
            Self::Compliance => "compliance",
            Self::Algorithms => "algorithms",
            Self::Certificates => "certificates",
            Self::Keys => "keys",
            Self::Protocols => "protocols",
            Self::PqcCompliance => "pqc-compliance",
            Self::Crypto => "crypto",
        }
    }

    /// Get the tab set for a given BOM profile.
    ///
    /// Each profile defines its own ordered set of tabs.
    /// Number keys 1-8 map positionally to this slice.
    #[must_use]
    pub const fn tabs_for_profile(profile: crate::model::BomProfile) -> &'static [ViewTab] {
        match profile {
            crate::model::BomProfile::Sbom => &[
                Self::Overview,
                Self::Tree,
                Self::Vulnerabilities,
                Self::Licenses,
                Self::Dependencies,
                Self::Quality,
                Self::Compliance,
                Self::Source,
            ],
            crate::model::BomProfile::Cbom => &[
                Self::Overview,
                Self::Algorithms,
                Self::Certificates,
                Self::Keys,
                Self::Protocols,
                Self::Quality,
                Self::PqcCompliance,
                Self::Source,
            ],
        }
    }

    /// Parse from a persisted string identifier.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "overview" => Some(Self::Overview),
            "quality" => Some(Self::Quality),
            "source" => Some(Self::Source),
            "tree" => Some(Self::Tree),
            "vulnerabilities" => Some(Self::Vulnerabilities),
            "licenses" => Some(Self::Licenses),
            "dependencies" => Some(Self::Dependencies),
            "compliance" => Some(Self::Compliance),
            "algorithms" => Some(Self::Algorithms),
            "certificates" => Some(Self::Certificates),
            "keys" => Some(Self::Keys),
            "protocols" => Some(Self::Protocols),
            "pqc-compliance" => Some(Self::PqcCompliance),
            "crypto" => Some(Self::Crypto),
            _ => None,
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
    /// Cached display items (group headers + vuln indices) — rebuilt only when
    /// cache or expanded_groups change, NOT every frame
    pub cached_display_items: Vec<super::views::VulnDisplayItem>,
    /// Snapshot of expanded_groups when display items were last built
    display_items_expanded_snapshot: HashSet<String>,
    /// Snapshot of group_by when display items were last built
    display_items_group_by: VulnGroupBy,
    /// Index into affected_component_ids for cycling with [n]/[p] after inspect
    pub inspect_component_idx: usize,
}

/// Cache key for vulnerability list - rebuild when any of these change
/// Cache key for tree node list
#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeCacheKey {
    group_by: TreeGroupBy,
    filter: TreeFilter,
    search_query: String,
}

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
            group_by: VulnGroupBy::Component,
            sort_by: VulnSortBy::Severity,
            filter_severity: None,
            deduplicate: true,
            search_query: String::new(),
            search_active: false,
            detail_scroll: 0,
            expanded_groups: HashSet::new(),
            cache_key: None,
            cached_data: None,
            cached_display_items: Vec::new(),
            display_items_expanded_snapshot: HashSet::new(),
            display_items_group_by: VulnGroupBy::Component,
            inspect_component_idx: 0,
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

    /// Check if cache is valid (allocation-free comparison)
    pub fn is_cache_valid(&self) -> bool {
        if let Some(key) = &self.cache_key {
            self.cached_data.is_some()
                && key.filter_severity == self.filter_severity
                && key.deduplicate == self.deduplicate
                && key.sort_by == self.sort_by
                && key.search_query == self.search_query
        } else {
            false
        }
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
        self.cached_display_items.clear();
    }

    /// Check if display items need rebuilding (expanded_groups or group_by changed)
    pub fn are_display_items_valid(&self) -> bool {
        !self.cached_display_items.is_empty()
            && self.display_items_expanded_snapshot == self.expanded_groups
            && self.display_items_group_by == self.group_by
    }

    /// Rebuild and cache display items
    pub fn rebuild_display_items(&mut self) {
        if let Some(cache) = &self.cached_data {
            self.cached_display_items = super::views::build_display_items(
                &cache.vulns,
                &self.group_by,
                &self.expanded_groups,
            );
            self.display_items_expanded_snapshot = self.expanded_groups.clone();
            self.display_items_group_by = self.group_by;
        }
    }

    pub const fn select_next(&mut self) {
        if self.total > 0 && self.selected < self.total.saturating_sub(1) {
            self.selected += 1;
            self.detail_scroll = 0;
            self.inspect_component_idx = 0;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.detail_scroll = 0;
            self.inspect_component_idx = 0;
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

    /// Get the selected VulnRow from the cached display items.
    /// Returns the vuln row and its index into `VulnCache.vulns`.
    pub fn get_selected_vuln_row<'a>(
        &self,
        cache: &'a super::views::VulnCache,
    ) -> Option<&'a super::views::VulnRow> {
        let item = self.cached_display_items.get(self.selected)?;
        match item {
            super::views::VulnDisplayItem::Vuln { idx, .. } => cache.vulns.get(*idx),
            _ => None,
        }
    }

    /// Get the component ID to navigate to for the selected vuln.
    /// Uses `inspect_component_idx` to cycle through multi-affected components.
    pub fn get_nav_component_id(
        &self,
        cache: &super::views::VulnCache,
    ) -> Option<(String, String)> {
        let vuln = self.get_selected_vuln_row(cache)?;
        let idx = self
            .inspect_component_idx
            .min(vuln.affected_component_ids.len().saturating_sub(1));
        let comp_id = vuln.affected_component_ids.get(idx)?;
        Some((comp_id.clone(), vuln.vuln_id.clone()))
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

    /// Expand all groups.
    pub fn expand_all_groups(&mut self, labels: &[String]) {
        for label in labels {
            self.expanded_groups.insert(label.clone());
        }
    }

    /// Collapse all groups.
    pub fn collapse_all_groups(&mut self) {
        self.expanded_groups.clear();
    }

    /// Jump to next group header using cached display items.
    pub fn jump_next_group_cached(&mut self) {
        for (i, item) in self
            .cached_display_items
            .iter()
            .enumerate()
            .skip(self.selected + 1)
        {
            if matches!(item, super::views::VulnDisplayItem::GroupHeader { .. }) {
                self.selected = i;
                self.detail_scroll = 0;
                return;
            }
        }
        // Wrap to first group
        for (i, item) in self.cached_display_items.iter().enumerate() {
            if matches!(item, super::views::VulnDisplayItem::GroupHeader { .. }) {
                self.selected = i;
                self.detail_scroll = 0;
                return;
            }
        }
    }

    /// Jump to previous group header using cached display items.
    pub fn jump_prev_group_cached(&mut self) {
        for (i, item) in self
            .cached_display_items
            .iter()
            .enumerate()
            .take(self.selected)
            .rev()
        {
            if matches!(item, super::views::VulnDisplayItem::GroupHeader { .. }) {
                self.selected = i;
                self.detail_scroll = 0;
                return;
            }
        }
        // Wrap to last group
        for (i, item) in self.cached_display_items.iter().enumerate().rev() {
            if matches!(item, super::views::VulnDisplayItem::GroupHeader { .. }) {
                self.selected = i;
                self.detail_scroll = 0;
                return;
            }
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

/// Sort order for the Algorithms tab.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AlgorithmSortBy {
    #[default]
    Name,
    Family,
    QuantumLevel,
    Strength,
}

impl AlgorithmSortBy {
    pub const fn next(self) -> Self {
        match self {
            Self::Name => Self::Family,
            Self::Family => Self::QuantumLevel,
            Self::QuantumLevel => Self::Strength,
            Self::Strength => Self::Name,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Family => "Family",
            Self::QuantumLevel => "Quantum",
            Self::Strength => "Strength",
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
    /// Search query for dependency tree filtering
    pub search_query: String,
    /// Whether search input is active
    pub search_active: bool,
    /// Scroll offset for the detail/stats panel
    pub detail_scroll: u16,
    /// Whether roots have been auto-expanded on first visit
    pub roots_initialized: bool,
    /// Snapshot of expanded set when flat nodes were last built
    expanded_snapshot: HashSet<String>,
    /// Cached flattened tree nodes
    pub cached_flat_nodes: Vec<super::views::FlatDepNode>,
    /// Cached search match count (query, count)
    cached_search_match: (String, Option<usize>),
}

impl DependencyViewState {
    pub fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            expanded: HashSet::new(),
            scroll_offset: 0,
            search_query: String::new(),
            search_active: false,
            detail_scroll: 0,
            roots_initialized: false,
            expanded_snapshot: HashSet::new(),
            cached_flat_nodes: Vec::new(),
            cached_search_match: (String::new(), None),
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

    pub fn expand_all(&mut self, all_node_ids: &[String]) {
        self.expanded.extend(all_node_ids.iter().cloned());
    }

    pub fn collapse_all(&mut self) {
        self.expanded.clear();
    }

    pub fn start_search(&mut self) {
        self.search_active = true;
    }

    pub fn stop_search(&mut self) {
        self.search_active = false;
    }

    pub fn clear_search(&mut self) {
        self.search_query.clear();
        self.search_active = false;
    }

    pub fn search_push(&mut self, c: char) {
        self.search_query.push(c);
    }

    pub fn search_pop(&mut self) {
        self.search_query.pop();
    }

    /// Check if cached flat nodes are still valid
    pub fn are_flat_nodes_valid(&self) -> bool {
        !self.cached_flat_nodes.is_empty() && self.expanded_snapshot == self.expanded
    }

    /// Cache flat nodes and snapshot expanded state
    pub fn set_cached_flat_nodes(&mut self, nodes: Vec<super::views::FlatDepNode>) {
        self.cached_flat_nodes = nodes;
        self.expanded_snapshot = self.expanded.clone();
    }

    /// Get cached search match count, recomputing only when query changed
    pub fn get_search_match_count(&mut self) -> Option<usize> {
        if self.search_query.is_empty() {
            return None;
        }
        if self.cached_search_match.0 == self.search_query {
            return self.cached_search_match.1;
        }
        let q = self.search_query.to_lowercase();
        let count = self
            .cached_flat_nodes
            .iter()
            .filter(|n| n.name.to_lowercase().contains(&q))
            .count();
        self.cached_search_match = (self.search_query.clone(), Some(count));
        Some(count)
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
    pub eol_count: usize,
    pub eol_approaching_count: usize,
    pub eol_supported_count: usize,
    pub eol_security_only_count: usize,
    pub eol_enriched: bool,
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
        let mut eol_count = 0;
        let mut eol_approaching_count = 0;
        let mut eol_supported_count = 0;
        let mut eol_security_only_count = 0;
        let mut eol_enriched = false;

        for comp in sbom.components.values() {
            // Count ecosystems
            let eco = comp
                .ecosystem
                .as_ref()
                .map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
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
                    .as_ref()
                    .map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
                *vuln_by_severity.entry(sev.clone()).or_insert(0) += 1;

                match sev.to_lowercase().as_str() {
                    "critical" => critical_count += 1,
                    "high" => high_count += 1,
                    "medium" => medium_count += 1,
                    "low" => low_count += 1,
                    _ => unknown_count += 1,
                }
            }

            // Count EOL statuses
            if let Some(eol) = &comp.eol {
                use crate::model::EolStatus;
                eol_enriched = true;
                match eol.status {
                    EolStatus::EndOfLife => eol_count += 1,
                    EolStatus::ApproachingEol => eol_approaching_count += 1,
                    EolStatus::Supported => eol_supported_count += 1,
                    EolStatus::SecurityOnly => eol_security_only_count += 1,
                    _ => {}
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
            eol_count,
            eol_approaching_count,
            eol_supported_count,
            eol_security_only_count,
            eol_enriched,
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
        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
        // Reset to known state (preferences may override default)
        app.active_tab = ViewTab::Overview;
        assert_eq!(app.active_tab, ViewTab::Overview);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_tab_navigation() {
        let sbom = NormalizedSbom::default();
        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
        // Start from known state regardless of saved preferences
        app.active_tab = ViewTab::Overview;

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

    #[test]
    fn test_tabs_for_profile_sbom() {
        let tabs = ViewTab::tabs_for_profile(crate::model::BomProfile::Sbom);
        assert_eq!(tabs.len(), 8);
        assert_eq!(tabs[0], ViewTab::Overview);
        assert_eq!(tabs[1], ViewTab::Tree);
        assert_eq!(tabs[7], ViewTab::Source);
        assert!(!tabs.contains(&ViewTab::Algorithms));
    }

    #[test]
    fn test_tabs_for_profile_cbom() {
        let tabs = ViewTab::tabs_for_profile(crate::model::BomProfile::Cbom);
        assert_eq!(tabs.len(), 8);
        assert_eq!(tabs[0], ViewTab::Overview);
        assert_eq!(tabs[1], ViewTab::Algorithms);
        assert_eq!(tabs[2], ViewTab::Certificates);
        assert_eq!(tabs[3], ViewTab::Keys);
        assert_eq!(tabs[4], ViewTab::Protocols);
        assert_eq!(tabs[5], ViewTab::Quality);
        assert_eq!(tabs[6], ViewTab::PqcCompliance);
        assert_eq!(tabs[7], ViewTab::Source);
        assert!(!tabs.contains(&ViewTab::Tree));
    }

    #[test]
    fn test_cbom_tab_navigation_cycles() {
        let sbom = NormalizedSbom::default();
        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);
        app.active_tab = ViewTab::Overview;

        app.next_tab();
        assert_eq!(app.active_tab, ViewTab::Algorithms);

        app.next_tab();
        assert_eq!(app.active_tab, ViewTab::Certificates);

        // Cycle back from Source → Overview
        app.active_tab = ViewTab::Source;
        app.next_tab();
        assert_eq!(app.active_tab, ViewTab::Overview);

        // Prev from Overview → Source
        app.prev_tab();
        assert_eq!(app.active_tab, ViewTab::Source);
    }

    #[test]
    fn test_per_tab_selection_independent() {
        let mut sbom = NormalizedSbom::default();
        // Add crypto components for navigation
        for i in 0..5 {
            let mut c = crate::model::Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = crate::model::ComponentType::Cryptographic;
            c.crypto_properties = Some(crate::model::CryptoProperties::new(
                crate::model::CryptoAssetType::Algorithm,
            ));
            sbom.add_component(c);
        }
        for i in 0..2 {
            let mut c = crate::model::Component::new(format!("cert-{i}"), format!("cert-{i}@1.0"));
            c.component_type = crate::model::ComponentType::Cryptographic;
            c.crypto_properties = Some(crate::model::CryptoProperties::new(
                crate::model::CryptoAssetType::Certificate,
            ));
            sbom.add_component(c);
        }

        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);

        // Navigate on Algorithms tab
        app.active_tab = ViewTab::Algorithms;
        app.navigate_down();
        app.navigate_down();
        assert_eq!(app.algorithms_selected, 2);

        // Switch to Certificates — selection should be independent
        app.active_tab = ViewTab::Certificates;
        assert_eq!(app.certificates_selected, 0);

        // Navigate on Certificates
        app.navigate_down();
        assert_eq!(app.certificates_selected, 1);

        // Switch back to Algorithms — preserved at 2
        app.active_tab = ViewTab::Algorithms;
        assert_eq!(app.algorithms_selected, 2);
    }

    #[test]
    fn test_crypto_count_for_tab() {
        let mut sbom = NormalizedSbom::default();
        for i in 0..3 {
            let mut c = crate::model::Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = crate::model::ComponentType::Cryptographic;
            c.crypto_properties = Some(crate::model::CryptoProperties::new(
                crate::model::CryptoAssetType::Algorithm,
            ));
            sbom.add_component(c);
        }
        let mut c = crate::model::Component::new("cert-0".to_string(), "cert-0@1.0".to_string());
        c.component_type = crate::model::ComponentType::Cryptographic;
        c.crypto_properties = Some(crate::model::CryptoProperties::new(
            crate::model::CryptoAssetType::Certificate,
        ));
        sbom.add_component(c);

        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);

        app.active_tab = ViewTab::Algorithms;
        assert_eq!(app.crypto_count_for_tab(), 3);

        app.active_tab = ViewTab::Certificates;
        assert_eq!(app.crypto_count_for_tab(), 1);

        app.active_tab = ViewTab::Keys;
        assert_eq!(app.crypto_count_for_tab(), 0);

        // Legacy Crypto tab counts all
        app.active_tab = ViewTab::Crypto;
        assert_eq!(app.crypto_count_for_tab(), 4);
    }
}
