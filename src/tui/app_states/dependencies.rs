//! Dependencies state types.

use crate::tui::state::{ListNavigation, TreeNavigation};
use std::collections::{HashMap, HashSet};

/// State for dependencies view
/// Sort order for dependencies
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DependencySort {
    #[default]
    Name,
    Depth,
    VulnCount,
    DependentCount,
}

impl DependencySort {
    pub const fn next(self) -> Self {
        match self {
            Self::Name => Self::Depth,
            Self::Depth => Self::VulnCount,
            Self::VulnCount => Self::DependentCount,
            Self::DependentCount => Self::Name,
        }
    }

    pub const fn display_name(&self) -> &str {
        match self {
            Self::Name => "Name",
            Self::Depth => "Depth",
            Self::VulnCount => "Vulnerabilities",
            Self::DependentCount => "Dependents",
        }
    }
}

pub struct DependenciesState {
    pub show_transitive: bool,
    pub highlight_changes: bool,
    pub expanded_nodes: HashSet<String>,
    pub selected: usize,
    pub total: usize,
    /// Node IDs in display order (populated during rendering)
    pub visible_nodes: Vec<String>,
    /// Maximum depth to display in tree (1-10)
    pub max_depth: usize,
    /// Maximum number of root nodes to display (10-100)
    pub max_roots: usize,
    /// Show cycle detection warnings
    pub show_cycles: bool,
    /// Detected circular dependency chains (cached)
    pub detected_cycles: Vec<Vec<String>>,
    /// Hash of graph structure for cache invalidation
    pub graph_hash: u64,
    /// Search mode active
    pub search_active: bool,
    /// Current search query
    pub search_query: String,
    /// Node IDs that match the search query
    pub search_matches: HashSet<String>,
    /// Filter mode (show only matches) vs highlight mode
    pub filter_mode: bool,

    // === Performance cache fields ===
    /// Cached dependency graph: source -> [targets]
    pub cached_graph: HashMap<String, Vec<String>>,
    /// Cached root nodes (components with no parent dependencies)
    pub cached_roots: Vec<String>,
    /// Cached vulnerability components for O(1) lookup
    pub cached_vuln_components: HashSet<String>,
    /// Cached cycle nodes (flattened) for O(1) lookup
    pub cached_cycle_nodes: HashSet<String>,
    /// Whether the cache is valid
    pub cache_valid: bool,
    /// Scroll offset for virtual scrolling
    pub scroll_offset: usize,
    /// Viewport height for virtual scrolling
    pub viewport_height: usize,

    // === Phase C: UX improvements ===
    /// Breadcrumb trail: path from root to currently selected node
    pub breadcrumb_trail: Vec<String>,
    /// Show breadcrumb bar
    pub show_breadcrumbs: bool,
    /// Show dependencies-specific help overlay
    pub show_deps_help: bool,

    // === Transitive filtering and sorting ===
    /// Direct dependencies (depth 1 from roots)
    pub cached_direct_deps: HashSet<String>,
    /// Reverse dependency graph: child -> [parents that depend on it]
    pub cached_reverse_graph: HashMap<String, Vec<String>>,
    /// Forward dependency graph (inverted reverse graph): parent -> [children that depend on parent]
    pub cached_forward_graph: HashMap<String, Vec<String>>,
    /// Current sort order
    pub sort_order: DependencySort,
    /// Cached depth for each node
    pub cached_depths: HashMap<String, usize>,
}

impl DependenciesState {
    pub fn new() -> Self {
        Self {
            show_transitive: false,
            highlight_changes: true,
            expanded_nodes: HashSet::new(),
            selected: 0,
            total: 0,
            visible_nodes: Vec::new(),
            max_depth: crate::tui::constants::DEFAULT_TREE_MAX_DEPTH,
            max_roots: crate::tui::constants::DEFAULT_TREE_MAX_ROOTS,
            show_cycles: true,
            detected_cycles: Vec::new(),
            graph_hash: 0,
            search_active: false,
            search_query: String::new(),
            search_matches: HashSet::new(),
            filter_mode: false,
            // Performance cache fields
            cached_graph: HashMap::new(),
            cached_roots: Vec::new(),
            cached_vuln_components: HashSet::new(),
            cached_cycle_nodes: HashSet::new(),
            cache_valid: false,
            scroll_offset: 0,
            viewport_height: 0,
            // Phase C: UX improvements
            breadcrumb_trail: Vec::new(),
            show_breadcrumbs: true,
            show_deps_help: false,
            // Transitive filtering and sorting
            cached_direct_deps: HashSet::new(),
            cached_reverse_graph: HashMap::new(),
            cached_forward_graph: HashMap::new(),
            sort_order: DependencySort::default(),
            cached_depths: HashMap::new(),
        }
    }

    /// Invalidate cache (call when data changes)
    pub const fn invalidate_cache(&mut self) {
        self.cache_valid = false;
    }

    /// Check if cache needs refresh based on graph hash
    pub const fn needs_cache_refresh(&self, new_hash: u64) -> bool {
        !self.cache_valid || self.graph_hash != new_hash
    }

    /// Update cached graph structure
    pub fn update_graph_cache(
        &mut self,
        graph: HashMap<String, Vec<String>>,
        roots: Vec<String>,
        hash: u64,
    ) {
        self.cached_graph = graph;
        self.cached_roots = roots;
        self.graph_hash = hash;
        self.cache_valid = true;
    }

    /// Update cached vulnerability components
    pub fn update_vuln_cache(&mut self, vuln_components: HashSet<String>) {
        self.cached_vuln_components = vuln_components;
    }

    /// Update cached cycle nodes
    pub fn update_cycle_cache(&mut self, cycles: Vec<Vec<String>>) {
        self.detected_cycles.clone_from(&cycles);
        self.cached_cycle_nodes = cycles.into_iter().flatten().collect();
    }

    /// Check if a node has vulnerabilities (O(1) lookup)
    pub fn has_vulnerability(&self, node_id: &str) -> bool {
        self.cached_vuln_components.contains(node_id)
    }

    /// Check if a node is in a cycle (O(1) lookup)
    pub fn is_in_cached_cycle(&self, node_id: &str) -> bool {
        self.cached_cycle_nodes.contains(node_id)
    }

    /// Update viewport for virtual scrolling
    pub const fn update_viewport(&mut self, height: usize) {
        self.viewport_height = height;
    }

    /// Get visible range for virtual scrolling
    pub fn get_visible_range(&self) -> (usize, usize) {
        let start = self.scroll_offset;
        let end = (self.scroll_offset + self.viewport_height).min(self.total);
        (start, end)
    }

    /// Adjust scroll to keep selection visible
    pub fn adjust_scroll_to_selection(&mut self) {
        if self.viewport_height == 0 {
            return;
        }
        let padding = 2.min(self.viewport_height.saturating_sub(1)); // Clamp padding to viewport
        if self.selected < self.scroll_offset.saturating_add(padding) {
            self.scroll_offset = self.selected.saturating_sub(padding);
        } else if self.selected >= self.scroll_offset.saturating_add(self.viewport_height.saturating_sub(padding)) {
            self.scroll_offset = self.selected.saturating_sub(self.viewport_height.saturating_sub(padding).saturating_sub(1));
        }
    }

    /// Increase max depth (up to `MAX_TREE_DEPTH`)
    pub const fn increase_depth(&mut self) {
        if self.max_depth < crate::tui::constants::MAX_TREE_DEPTH {
            self.max_depth += 1;
        }
    }

    /// Decrease max depth (down to 1)
    pub const fn decrease_depth(&mut self) {
        if self.max_depth > 1 {
            self.max_depth -= 1;
        }
    }

    /// Increase max roots (up to `MAX_TREE_ROOTS`)
    pub const fn increase_roots(&mut self) {
        use crate::tui::constants::{MAX_TREE_ROOTS, TREE_ROOTS_STEP};
        if self.max_roots < MAX_TREE_ROOTS {
            self.max_roots += TREE_ROOTS_STEP;
        }
    }

    /// Decrease max roots (down to `MIN_TREE_ROOTS`)
    pub const fn decrease_roots(&mut self) {
        use crate::tui::constants::{MIN_TREE_ROOTS, TREE_ROOTS_STEP};
        if self.max_roots > MIN_TREE_ROOTS {
            self.max_roots -= TREE_ROOTS_STEP;
        }
    }

    /// Toggle cycle detection display
    pub const fn toggle_cycles(&mut self) {
        self.show_cycles = !self.show_cycles;
    }

    /// Check if a node is part of a detected cycle
    pub fn is_in_cycle(&self, node_id: &str) -> bool {
        self.detected_cycles
            .iter()
            .any(|cycle| cycle.iter().any(|n| n == node_id))
    }

    pub const fn toggle_transitive(&mut self) {
        self.show_transitive = !self.show_transitive;
    }

    pub const fn toggle_highlight(&mut self) {
        self.highlight_changes = !self.highlight_changes;
    }

    /// Cycle to next sort order
    pub const fn toggle_sort(&mut self) {
        self.sort_order = self.sort_order.next();
    }

    /// Check if a dependency is a direct dependency (depth 1)
    pub fn is_direct_dependency(&self, node_id: &str) -> bool {
        self.cached_direct_deps.contains(node_id)
    }

    /// Get all components that depend on this node (reverse lookup)
    pub fn get_dependents(&self, node_id: &str) -> Option<&[String]> {
        self.cached_reverse_graph.get(node_id).map(std::vec::Vec::as_slice)
    }

    /// Get the cached depth of a node (0 = root)
    pub fn get_depth(&self, node_id: &str) -> usize {
        self.cached_depths.get(node_id).copied().unwrap_or(0)
    }

    /// Update transitive caches: direct deps, reverse graph, forward graph, and depths
    pub fn update_transitive_cache(&mut self) {
        self.cached_direct_deps.clear();
        self.cached_reverse_graph.clear();
        self.cached_forward_graph.clear();
        self.cached_depths.clear();

        // Build reverse graph and track direct deps (depth 1)
        for (source, targets) in &self.cached_graph {
            // Set depth for root nodes (they're sources with no parent)
            if !self.cached_depths.contains_key(source) && self.cached_roots.contains(source) {
                self.cached_depths.insert(source.clone(), 0);
            }

            for target in targets {
                // Add to reverse graph
                self.cached_reverse_graph
                    .entry(target.clone())
                    .or_default()
                    .push(source.clone());

                // Mark as direct if parent is a root
                if self.cached_roots.contains(source) {
                    self.cached_direct_deps.insert(target.clone());
                }
            }
        }

        // Compute depths using BFS from roots
        let mut queue: std::collections::VecDeque<(String, usize)> = self
            .cached_roots
            .iter()
            .map(|r| (r.clone(), 0))
            .collect();

        while let Some((node, depth)) = queue.pop_front() {
            if let Some(&existing_depth) = self.cached_depths.get(node.as_str()) {
                if existing_depth <= depth {
                    continue; // Already visited with smaller or equal depth
                }
            }

            // Enqueue children before consuming node
            if let Some(children) = self.cached_graph.get(node.as_str()) {
                for child in children {
                    let dominated = self
                        .cached_depths
                        .get(child.as_str())
                        .is_none_or(|&d| d > depth + 1);
                    if dominated {
                        queue.push_back((child.clone(), depth + 1));
                    }
                }
            }

            // Consume node directly — no clone needed
            self.cached_depths.insert(node, depth);
        }

        // Build forward graph by inverting reverse graph
        // reverse_graph: child -> [parents], forward_graph: parent -> [children]
        for (child, parents) in &self.cached_reverse_graph {
            for parent in parents {
                self.cached_forward_graph
                    .entry(parent.clone())
                    .or_default()
                    .push(child.clone());
            }
        }
    }

    /// Get count of dependents for a node (for sorting)
    pub fn get_dependent_count(&self, node_id: &str) -> usize {
        self.cached_reverse_graph
            .get(node_id)
            .map_or(0, std::vec::Vec::len)
    }

    pub fn toggle_node(&mut self, node_id: &str) {
        if self.expanded_nodes.contains(node_id) {
            self.expanded_nodes.remove(node_id);
        } else {
            self.expanded_nodes.insert(node_id.to_string());
        }
    }

    pub fn is_expanded(&self, node_id: &str) -> bool {
        self.expanded_nodes.contains(node_id)
    }

    pub fn expand(&mut self, node_id: &str) {
        self.expanded_nodes.insert(node_id.to_string());
    }

    pub fn collapse(&mut self, node_id: &str) {
        self.expanded_nodes.remove(node_id);
    }

    /// Get the node ID for the currently selected item
    pub fn get_selected_node_id(&self) -> Option<&str> {
        self.visible_nodes.get(self.selected).map(std::string::String::as_str)
    }

    /// Set the visible nodes and update total (called during rendering)
    pub fn set_visible_nodes(&mut self, nodes: Vec<String>) {
        self.total = nodes.len();
        self.visible_nodes = nodes;
        // Clamp selection to valid bounds without disrupting position
        if self.total == 0 {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(self.total - 1);
        }
    }

    // Search methods

    /// Start search mode
    pub fn start_search(&mut self) {
        self.search_active = true;
        self.search_query.clear();
        self.search_matches.clear();
    }

    /// Stop search mode (keep matches for highlighting)
    pub const fn stop_search(&mut self) {
        self.search_active = false;
    }

    /// Clear search completely
    pub fn clear_search(&mut self) {
        self.search_active = false;
        self.search_query.clear();
        self.search_matches.clear();
        self.filter_mode = false;
    }

    /// Check if search mode is active
    pub const fn is_searching(&self) -> bool {
        self.search_active
    }

    /// Check if we have an active search query (even if not in search mode)
    pub fn has_search_query(&self) -> bool {
        !self.search_query.is_empty()
    }

    /// Toggle filter mode
    pub const fn toggle_filter_mode(&mut self) {
        self.filter_mode = !self.filter_mode;
    }

    /// Check if a node matches the search
    pub fn matches_search(&self, node_id: &str) -> bool {
        self.search_matches.contains(node_id)
    }

    /// Update search matches based on query and available nodes
    pub fn update_search_matches(&mut self, all_node_names: &[(String, String)]) {
        self.search_matches.clear();
        if self.search_query.is_empty() {
            return;
        }
        let query_lower = self.search_query.to_lowercase();
        for (node_id, node_name) in all_node_names {
            if node_name.to_lowercase().contains(&query_lower) {
                self.search_matches.insert(node_id.clone());
            }
        }
    }

    /// Add a character to search query
    pub fn search_push(&mut self, c: char) {
        self.search_query.push(c);
    }

    /// Remove last character from search query
    pub fn search_pop(&mut self) {
        self.search_query.pop();
    }

    /// Navigate to next search match
    pub fn next_match(&mut self) {
        if self.search_matches.is_empty() || self.visible_nodes.is_empty() {
            return;
        }
        // Find next match after current selection
        for i in (self.selected + 1)..self.visible_nodes.len() {
            if self.search_matches.contains(&self.visible_nodes[i]) {
                self.selected = i;
                return;
            }
        }
        // Wrap around
        for i in 0..=self.selected {
            if self.search_matches.contains(&self.visible_nodes[i]) {
                self.selected = i;
                return;
            }
        }
    }

    /// Navigate to previous search match
    pub fn prev_match(&mut self) {
        if self.search_matches.is_empty() || self.visible_nodes.is_empty() {
            return;
        }
        // Find previous match before current selection
        for i in (0..self.selected).rev() {
            if self.search_matches.contains(&self.visible_nodes[i]) {
                self.selected = i;
                return;
            }
        }
        // Wrap around
        for i in (self.selected..self.visible_nodes.len()).rev() {
            if self.search_matches.contains(&self.visible_nodes[i]) {
                self.selected = i;
                return;
            }
        }
    }

    // === Phase C: UX improvement methods ===

    /// Expand all nodes in the tree
    pub fn expand_all(&mut self) {
        // Add all root nodes and their cached children
        for root in &self.cached_roots {
            self.expanded_nodes.insert(root.clone());
        }
        // Add all nodes that have children in the cached graph
        for (node, children) in &self.cached_graph {
            if !children.is_empty() {
                self.expanded_nodes.insert(node.clone());
            }
        }
    }

    /// Collapse all nodes in the tree
    pub fn collapse_all(&mut self) {
        self.expanded_nodes.clear();
    }

    /// Toggle breadcrumb display
    pub const fn toggle_breadcrumbs(&mut self) {
        self.show_breadcrumbs = !self.show_breadcrumbs;
    }

    /// Toggle dependencies help overlay
    pub const fn toggle_deps_help(&mut self) {
        self.show_deps_help = !self.show_deps_help;
    }

    /// Update breadcrumb trail based on current selection
    pub fn update_breadcrumbs(&mut self) {
        self.breadcrumb_trail.clear();

        let Some(selected_id) = self.visible_nodes.get(self.selected) else {
            return;
        };

        // Parse the node ID to extract the path
        // Node IDs are structured as "root" or "parent:+:child" or "parent:-:child"
        // We need to trace back through the hierarchy

        if selected_id.starts_with("__") {
            // Placeholder node, no breadcrumbs
            return;
        }

        // Build path from the node ID structure
        let parts: Vec<&str> = selected_id.split(':').collect();
        if parts.len() == 1 {
            // Root node
            self.breadcrumb_trail.push(parts[0].to_string());
        } else {
            // Child node - the ID contains the path encoded
            // Format: "root:+:child1:+:child2" etc.
            for part in &parts {
                if *part == "+" || *part == "-" {
                    continue; // Skip change markers
                }
                self.breadcrumb_trail.push(part.to_string());
            }
        }
    }

    /// Get formatted breadcrumb string
    pub fn get_breadcrumb_display(&self) -> String {
        if self.breadcrumb_trail.is_empty() {
            return String::new();
        }
        self.breadcrumb_trail.join(" → ")
    }

    /// Navigate to a specific node by name (for quick jump)
    pub fn jump_to_node(&mut self, node_name: &str) -> bool {
        // Find the node in visible_nodes
        for (i, node_id) in self.visible_nodes.iter().enumerate() {
            // Check if the node ID ends with the name (to match child nodes)
            let display_name = node_id.split(':').next_back().unwrap_or(node_id);
            if display_name == node_name {
                self.selected = i;
                self.adjust_scroll_to_selection();
                return true;
            }
        }
        false
    }

    /// Get list of all unique component names for quick jump menu
    pub fn get_all_component_names(&self) -> Vec<String> {
        let mut names: HashSet<String> = HashSet::new();
        for root in &self.cached_roots {
            names.insert(root.clone());
        }
        for (parent, children) in &self.cached_graph {
            names.insert(parent.clone());
            for child in children {
                names.insert(child.clone());
            }
        }
        let mut sorted: Vec<String> = names.into_iter().collect();
        sorted.sort();
        sorted
    }
}

impl ListNavigation for DependenciesState {
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
        self.clamp_selection();
    }
}

impl TreeNavigation for DependenciesState {
    fn is_expanded(&self, node_id: &str) -> bool {
        self.expanded_nodes.contains(node_id)
    }

    fn expand(&mut self, node_id: &str) {
        self.expanded_nodes.insert(node_id.to_string());
    }

    fn collapse(&mut self, node_id: &str) {
        self.expanded_nodes.remove(node_id);
    }

    fn expand_all(&mut self) {
        for root in &self.cached_roots {
            self.expanded_nodes.insert(root.clone());
        }
        for (node, children) in &self.cached_graph {
            if !children.is_empty() {
                self.expanded_nodes.insert(node.clone());
            }
        }
    }

    fn collapse_all(&mut self) {
        self.expanded_nodes.clear();
    }
}

impl Default for DependenciesState {
    fn default() -> Self {
        Self::new()
    }
}

