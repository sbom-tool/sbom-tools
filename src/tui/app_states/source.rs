//! Source tab state for viewing raw SBOM file content.
//!
//! Provides a JSON tree model and panel state for both single-SBOM
//! viewing (`ViewApp`) and side-by-side diff viewing (App).

use std::collections::HashSet;

/// View mode for the Source tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceViewMode {
    /// Interactive JSON tree with expand/collapse
    #[default]
    Tree,
    /// Raw pretty-printed text with line numbers
    Raw,
}

/// JSON value type for syntax coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonValueType {
    String,
    Number,
    Boolean,
    Null,
}

/// A node in the JSON tree, built from `serde_json::Value`.
#[derive(Debug, Clone)]
pub enum JsonTreeNode {
    Object {
        key: String,
        index: Option<usize>,
        children: Vec<Self>,
    },
    Array {
        key: String,
        index: Option<usize>,
        children: Vec<Self>,
        len: usize,
    },
    Leaf {
        key: String,
        index: Option<usize>,
        value: String,
        value_type: JsonValueType,
    },
}

impl JsonTreeNode {
    /// Build a tree from a `serde_json::Value`.
    pub fn from_value(key: String, index: Option<usize>, value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Object(map) => {
                let children = map
                    .iter()
                    .map(|(k, v)| Self::from_value(k.clone(), None, v))
                    .collect();
                Self::Object {
                    key,
                    index,
                    children,
                }
            }
            serde_json::Value::Array(arr) => {
                let children = arr
                    .iter()
                    .enumerate()
                    .map(|(i, v)| Self::from_value(String::new(), Some(i), v))
                    .collect();
                Self::Array {
                    key,
                    index,
                    children,
                    len: arr.len(),
                }
            }
            serde_json::Value::String(s) => Self::Leaf {
                key,
                index,
                value: format!("\"{}\"", truncate_value(s, 120)),
                value_type: JsonValueType::String,
            },
            serde_json::Value::Number(n) => Self::Leaf {
                key,
                index,
                value: n.to_string(),
                value_type: JsonValueType::Number,
            },
            serde_json::Value::Bool(b) => Self::Leaf {
                key,
                index,
                value: b.to_string(),
                value_type: JsonValueType::Boolean,
            },
            serde_json::Value::Null => Self::Leaf {
                key,
                index,
                value: "null".to_string(),
                value_type: JsonValueType::Null,
            },
        }
    }

    /// Unique path-based ID for expand/collapse tracking.
    pub fn node_id(&self, parent_path: &str) -> String {
        let key_part = match self {
            Self::Object { key, index, .. }
            | Self::Array { key, index, .. }
            | Self::Leaf { key, index, .. } => {
                index.as_ref().map_or_else(|| key.clone(), |i| format!("[{i}]"))
            }
        };
        if parent_path.is_empty() {
            key_part
        } else {
            format!("{parent_path}.{key_part}")
        }
    }

    pub const fn is_expandable(&self) -> bool {
        matches!(
            self,
            Self::Object { .. } | Self::Array { .. }
        )
    }

    pub fn children(&self) -> Option<&[Self]> {
        match self {
            Self::Object { children, .. } | Self::Array { children, .. } => {
                Some(children)
            }
            Self::Leaf { .. } => None,
        }
    }

    pub fn child_count_label(&self) -> String {
        match self {
            Self::Object { children, .. } => {
                format!("{{}} ({} keys)", children.len())
            }
            Self::Array { len, .. } => {
                format!("[] ({len} items)")
            }
            Self::Leaf { .. } => String::new(),
        }
    }

    pub fn display_key(&self) -> String {
        match self {
            Self::Object { key, index, .. }
            | Self::Array { key, index, .. }
            | Self::Leaf { key, index, .. } => {
                index.as_ref().map_or_else(|| key.clone(), |i| format!("[{i}]"))
            }
        }
    }
}

fn truncate_value(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn count_tree_nodes(node: &JsonTreeNode) -> usize {
    let mut count = 1;
    if let Some(children) = node.children() {
        for child in children {
            count += count_tree_nodes(child);
        }
    }
    count
}

// ── Raw line ↔ node_id mapping ──────────────────────────────────────────────

/// Stack entry for tracking JSON structure during raw line mapping.
enum RawMapEntry {
    Object(String),
    Array(String, usize),
}

/// Build a mapping from each raw line index to the corresponding tree `node_id`.
///
/// Walks the pretty-printed JSON lines (`serde_json::to_string_pretty`) with a
/// stack to track the current path through the JSON structure.
fn build_raw_line_mapping(raw_lines: &[String]) -> Vec<String> {
    let mut result = Vec::with_capacity(raw_lines.len());
    let mut stack: Vec<RawMapEntry> = Vec::new();

    for line in raw_lines {
        let trimmed = line.trim();
        let content = trimmed.trim_end_matches(',');

        if content.is_empty() {
            result.push(stack_to_node_id(&stack));
            continue;
        }

        if let Some((key, value_part)) = parse_json_kv(content) {
            match value_part {
                "{" => {
                    stack.push(RawMapEntry::Object(key));
                    result.push(stack_to_node_id(&stack));
                }
                "[" => {
                    stack.push(RawMapEntry::Array(key, 0));
                    result.push(stack_to_node_id(&stack));
                }
                _ => {
                    let parent = stack_to_node_id(&stack);
                    result.push(if parent.is_empty() {
                        key
                    } else {
                        format!("{parent}.{key}")
                    });
                }
            }
        } else if content == "{" || content == "[" {
            if stack.is_empty() {
                if content == "[" {
                    stack.push(RawMapEntry::Array("root".to_string(), 0));
                } else {
                    stack.push(RawMapEntry::Object("root".to_string()));
                }
            } else {
                let idx = take_next_array_index(&mut stack);
                if content == "[" {
                    stack.push(RawMapEntry::Array(format!("[{idx}]"), 0));
                } else {
                    stack.push(RawMapEntry::Object(format!("[{idx}]")));
                }
            }
            result.push(stack_to_node_id(&stack));
        } else if content == "}" || content == "]" {
            result.push(stack_to_node_id(&stack));
            stack.pop();
        } else {
            // Bare value in array
            let idx = take_next_array_index(&mut stack);
            let parent = stack_to_node_id(&stack);
            result.push(format!("{parent}.[{idx}]"));
        }
    }

    result
}

fn stack_to_node_id(stack: &[RawMapEntry]) -> String {
    stack
        .iter()
        .map(|e| match e {
            RawMapEntry::Object(s) | RawMapEntry::Array(s, _) => s.as_str(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn take_next_array_index(stack: &mut [RawMapEntry]) -> usize {
    if let Some(RawMapEntry::Array(_, idx)) = stack.last_mut() {
        let current = *idx;
        *idx += 1;
        current
    } else {
        0
    }
}

/// Parse `"key": rest` from a trimmed JSON line.
fn parse_json_kv(s: &str) -> Option<(String, &str)> {
    if !s.starts_with('"') {
        return None;
    }
    let bytes = s.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let key = s[1..i].to_string();
    s[i + 1..].strip_prefix(": ").map(|rest| (key, rest))
}

/// State for a single source panel (used once in `ViewApp`, twice in diff App).
#[derive(Debug, Clone)]
pub struct SourcePanelState {
    /// Tree vs Raw view mode
    pub view_mode: SourceViewMode,
    /// Expanded node paths for tree mode
    pub expanded: HashSet<String>,
    /// Currently selected line index (in flattened tree or raw lines)
    pub selected: usize,
    /// Scroll offset for viewport
    pub scroll_offset: usize,
    /// Total visible items (updated during render)
    pub visible_count: usize,
    /// JSON tree (built from raw content; None if not valid JSON)
    pub json_tree: Option<JsonTreeNode>,
    /// Raw content lines (pretty-printed JSON or original lines for non-JSON)
    pub raw_lines: Vec<String>,
    /// Mapping from raw line index to the corresponding tree node_id
    pub raw_line_node_ids: Vec<String>,
    /// Total node count in JSON tree (computed once)
    pub total_node_count: usize,
    /// Saved tree mode position
    pub tree_selected: usize,
    pub tree_scroll_offset: usize,
    /// Saved raw mode position
    pub raw_selected: usize,
    pub raw_scroll_offset: usize,
    /// Search state
    pub search_query: String,
    pub search_active: bool,
    pub search_matches: Vec<usize>,
    pub search_current: usize,
    /// SBOM map panel: selected section index
    pub map_selected: usize,
    /// SBOM map panel: scroll offset for section list
    pub map_scroll_offset: usize,
    /// Cached flattened tree items; rebuilt only when expanded set changes.
    pub cached_flat_items: Vec<crate::tui::shared::source::FlatJsonItem>,
    /// Whether the cached flat items are valid (invalidated on expand/collapse).
    pub flat_cache_valid: bool,
}

impl SourcePanelState {
    /// Create a new panel state by parsing raw SBOM content.
    pub fn new(raw_content: &str) -> Self {
        let (json_tree, raw_lines) = serde_json::from_str::<serde_json::Value>(raw_content).map_or_else(
            |_| {
                // Not valid JSON (e.g. XML, tag-value) — raw mode only
                let lines: Vec<String> = raw_content.lines().map(std::string::ToString::to_string).collect();
                (None, lines)
            },
            |value| {
                let tree = JsonTreeNode::from_value("root".to_string(), None, &value);
                let pretty = serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| raw_content.to_string());
                let lines: Vec<String> = pretty.lines().map(std::string::ToString::to_string).collect();
                (Some(tree), lines)
            },
        );

        // Auto-expand root in tree mode
        let mut expanded = HashSet::new();
        if json_tree.is_some() {
            expanded.insert("root".to_string());
        }

        let total_node_count = json_tree.as_ref().map_or(0, count_tree_nodes);
        let raw_line_node_ids = if json_tree.is_some() {
            build_raw_line_mapping(&raw_lines)
        } else {
            Vec::new()
        };

        Self {
            view_mode: if json_tree.is_some() {
                SourceViewMode::Tree
            } else {
                SourceViewMode::Raw
            },
            expanded,
            selected: 0,
            scroll_offset: 0,
            visible_count: 0,
            json_tree,
            raw_lines,
            raw_line_node_ids,
            total_node_count,
            tree_selected: 0,
            tree_scroll_offset: 0,
            raw_selected: 0,
            raw_scroll_offset: 0,
            search_query: String::new(),
            search_active: false,
            search_matches: Vec::new(),
            search_current: 0,
            map_selected: 0,
            map_scroll_offset: 0,
            cached_flat_items: Vec::new(),
            flat_cache_valid: false,
        }
    }

    /// Invalidate the cached flat tree items (call after expand/collapse changes).
    pub const fn invalidate_flat_cache(&mut self) {
        self.flat_cache_valid = false;
    }

    /// Ensure the cached flat tree items are up-to-date. No-op if already valid.
    pub fn ensure_flat_cache(&mut self) {
        if self.flat_cache_valid {
            return;
        }
        self.cached_flat_items.clear();
        if let Some(ref tree) = self.json_tree {
            crate::tui::shared::source::flatten_json_tree(
                tree, "", 0, &self.expanded, &mut self.cached_flat_items, true, &[],
            );
        }
        self.flat_cache_valid = true;
    }

    pub fn toggle_view_mode(&mut self) {
        // Save current position for fallback
        match self.view_mode {
            SourceViewMode::Tree => {
                self.tree_selected = self.selected;
                self.tree_scroll_offset = self.scroll_offset;
            }
            SourceViewMode::Raw => {
                self.raw_selected = self.selected;
                self.raw_scroll_offset = self.scroll_offset;
            }
        }

        // Compute synced position BEFORE switching mode
        let synced = self.compute_synced_position();

        // Switch mode
        let new_mode = match self.view_mode {
            SourceViewMode::Tree => SourceViewMode::Raw,
            SourceViewMode::Raw => {
                if self.json_tree.is_some() {
                    SourceViewMode::Tree
                } else {
                    return;
                }
            }
        };
        self.view_mode = new_mode;

        // Apply synced position, falling back to saved position
        if let Some((sel, scroll)) = synced {
            self.selected = sel;
            self.scroll_offset = scroll;
        } else {
            match self.view_mode {
                SourceViewMode::Tree => {
                    self.selected = self.tree_selected;
                    self.scroll_offset = self.tree_scroll_offset;
                }
                SourceViewMode::Raw => {
                    self.selected = self.raw_selected;
                    self.scroll_offset = self.raw_scroll_offset;
                }
            }
        }
    }

    /// Compute the synced position in the target mode based on current position.
    fn compute_synced_position(&mut self) -> Option<(usize, usize)> {
        match self.view_mode {
            SourceViewMode::Tree => self.sync_tree_to_raw(),
            SourceViewMode::Raw => self.sync_raw_to_tree(),
        }
    }

    /// Find the raw line corresponding to the current tree selection.
    fn sync_tree_to_raw(&mut self) -> Option<(usize, usize)> {
        self.ensure_flat_cache();
        let node_id = self
            .cached_flat_items
            .get(self.selected)
            .map(|item| item.node_id.clone())?;
        let raw_idx = self
            .raw_line_node_ids
            .iter()
            .position(|id| *id == node_id)?;
        Some((raw_idx, raw_idx.saturating_sub(5)))
    }

    /// Find the tree item corresponding to the current raw line.
    fn sync_raw_to_tree(&mut self) -> Option<(usize, usize)> {
        let node_id = self.raw_line_node_ids.get(self.selected)?.clone();
        if node_id.is_empty() {
            return None;
        }
        // Expand ancestors to reveal the target node
        let parts: Vec<&str> = node_id.split('.').collect();
        let mut changed = false;
        for len in 1..parts.len() {
            let ancestor = parts[..len].join(".");
            if !self.expanded.contains(&ancestor) {
                self.expanded.insert(ancestor);
                changed = true;
            }
        }
        if changed {
            self.invalidate_flat_cache();
        }
        self.ensure_flat_cache();
        // Try exact match first, then progressively shorter ancestor paths
        for len in (1..=parts.len()).rev() {
            let candidate = parts[..len].join(".");
            if let Some(idx) = self
                .cached_flat_items
                .iter()
                .position(|item| item.node_id == candidate)
            {
                return Some((idx, idx.saturating_sub(5)));
            }
        }
        None
    }

    pub fn toggle_expand(&mut self, node_id: &str) {
        if self.expanded.contains(node_id) {
            self.expanded.remove(node_id);
        } else {
            self.expanded.insert(node_id.to_string());
        }
        self.invalidate_flat_cache();
    }

    pub fn expand_all(&mut self) {
        if let Some(ref tree) = self.json_tree {
            expand_all_recursive(tree, "", &mut self.expanded);
        }
        self.invalidate_flat_cache();
    }

    pub fn collapse_all(&mut self) {
        self.expanded.clear();
        self.expanded.insert("root".to_string());
        self.selected = 0;
        self.scroll_offset = 0;
        self.map_scroll_offset = 0;
        self.invalidate_flat_cache();
    }

    pub fn select_next(&mut self) {
        let max = self.effective_count();
        if max > 0 && self.selected < max.saturating_sub(1) {
            self.selected += 1;
        }
    }

    pub const fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub const fn select_first(&mut self) {
        self.selected = 0;
        self.scroll_offset = 0;
    }

    pub fn select_last(&mut self) {
        let max = self.effective_count();
        if max > 0 {
            self.selected = max.saturating_sub(1);
        }
    }

    pub fn page_down(&mut self) {
        let max = self.effective_count();
        self.selected = (self.selected + 20).min(max.saturating_sub(1));
    }

    pub const fn page_up(&mut self) {
        self.selected = self.selected.saturating_sub(20);
    }

    fn effective_count(&self) -> usize {
        if self.visible_count > 0 {
            self.visible_count
        } else {
            self.raw_lines.len()
        }
    }

    pub fn start_search(&mut self) {
        self.search_active = true;
        self.search_query.clear();
        self.search_matches.clear();
        self.search_current = 0;
    }

    pub const fn stop_search(&mut self) {
        self.search_active = false;
    }

    pub fn search_push_char(&mut self, c: char) {
        self.search_query.push(c);
        self.execute_search();
    }

    pub fn search_pop_char(&mut self) {
        self.search_query.pop();
        self.execute_search();
    }

    pub fn next_search_match(&mut self) {
        if !self.search_matches.is_empty() {
            self.search_current = (self.search_current + 1) % self.search_matches.len();
            self.selected = self.search_matches[self.search_current];
        }
    }

    pub fn prev_search_match(&mut self) {
        if !self.search_matches.is_empty() {
            self.search_current = if self.search_current == 0 {
                self.search_matches.len() - 1
            } else {
                self.search_current - 1
            };
            self.selected = self.search_matches[self.search_current];
        }
    }

    pub fn execute_search(&mut self) {
        self.search_matches.clear();
        self.search_current = 0;

        if self.search_query.len() < 2 {
            return;
        }

        let query = self.search_query.to_lowercase();

        match self.view_mode {
            SourceViewMode::Tree => {
                self.ensure_flat_cache();
                for (i, item) in self.cached_flat_items.iter().enumerate() {
                    if item.display_key.to_lowercase().contains(&query)
                        || item.value_preview.to_lowercase().contains(&query)
                    {
                        self.search_matches.push(i);
                    }
                }
            }
            SourceViewMode::Raw => {
                for (i, line) in self.raw_lines.iter().enumerate() {
                    if line.to_lowercase().contains(&query) {
                        self.search_matches.push(i);
                    }
                }
            }
        }

        // Jump to first match
        if !self.search_matches.is_empty() {
            self.selected = self.search_matches[0];
        }
    }
}

fn expand_all_recursive(node: &JsonTreeNode, path: &str, expanded: &mut HashSet<String>) {
    let id = node.node_id(path);
    if node.is_expandable() {
        expanded.insert(id.clone());
        if let Some(children) = node.children() {
            for child in children {
                expand_all_recursive(child, &id, expanded);
            }
        }
    }
}

/// Which side is active in diff mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSide {
    Old,
    New,
}

/// Diff mode state: two panels with active-side tracking and optional sync.
#[derive(Debug, Clone)]
pub struct SourceDiffState {
    pub old_panel: SourcePanelState,
    pub new_panel: SourcePanelState,
    pub active_side: SourceSide,
    pub sync_mode: super::ScrollSyncMode,
}

impl SourceDiffState {
    pub fn new(old_raw: &str, new_raw: &str) -> Self {
        Self {
            old_panel: SourcePanelState::new(old_raw),
            new_panel: SourcePanelState::new(new_raw),
            active_side: SourceSide::New,
            sync_mode: super::ScrollSyncMode::Locked,
        }
    }

    pub const fn active_panel_mut(&mut self) -> &mut SourcePanelState {
        match self.active_side {
            SourceSide::Old => &mut self.old_panel,
            SourceSide::New => &mut self.new_panel,
        }
    }

    pub const fn inactive_panel_mut(&mut self) -> &mut SourcePanelState {
        match self.active_side {
            SourceSide::Old => &mut self.new_panel,
            SourceSide::New => &mut self.old_panel,
        }
    }

    pub const fn is_synced(&self) -> bool {
        matches!(self.sync_mode, super::ScrollSyncMode::Locked)
    }

    pub const fn toggle_sync(&mut self) {
        self.sync_mode = match self.sync_mode {
            super::ScrollSyncMode::Independent => super::ScrollSyncMode::Locked,
            super::ScrollSyncMode::Locked => super::ScrollSyncMode::Independent,
        };
    }

    pub fn toggle_side(&mut self) {
        if self.is_synced() {
            self.sync_target_to_active();
        }
        self.active_side = match self.active_side {
            SourceSide::Old => SourceSide::New,
            SourceSide::New => SourceSide::Old,
        };
    }

    /// Try to jump the inactive panel to the same node path as the active panel.
    fn sync_target_to_active(&mut self) {
        // Get the current node_id from the active panel (tree mode only)
        let target_node_id = {
            let active = match self.active_side {
                SourceSide::Old => &mut self.old_panel,
                SourceSide::New => &mut self.new_panel,
            };
            if active.view_mode != SourceViewMode::Tree {
                return;
            }
            active.ensure_flat_cache();
            active
                .cached_flat_items
                .get(active.selected)
                .map(|item| item.node_id.clone())
        };

        let Some(node_id) = target_node_id else {
            return;
        };

        // Find the matching node in the inactive panel
        let inactive = match self.active_side {
            SourceSide::Old => &mut self.new_panel,
            SourceSide::New => &mut self.old_panel,
        };
        if inactive.view_mode != SourceViewMode::Tree {
            return;
        }

        // Try exact match first, then progressively shorter ancestor paths
        let parts: Vec<&str> = node_id.split('.').collect();
        for len in (1..=parts.len()).rev() {
            let candidate = parts[..len].join(".");
            // Ensure the candidate node is expanded (expand ancestors)
            for ancestor_len in 1..len {
                let ancestor = parts[..ancestor_len].join(".");
                if !inactive.expanded.contains(&ancestor) {
                    inactive.expanded.insert(ancestor);
                    inactive.invalidate_flat_cache();
                }
            }
            inactive.ensure_flat_cache();
            if let Some(idx) = inactive
                .cached_flat_items
                .iter()
                .position(|item| item.node_id == candidate)
            {
                inactive.selected = idx;
                // Reset scroll so render can recompute it
                inactive.scroll_offset = idx.saturating_sub(5);
                return;
            }
        }
    }

    // --- Synchronized navigation methods ---

    pub fn select_next(&mut self) {
        self.active_panel_mut().select_next();
        if self.is_synced() {
            self.inactive_panel_mut().select_next();
        }
    }

    pub fn select_prev(&mut self) {
        self.active_panel_mut().select_prev();
        if self.is_synced() {
            self.inactive_panel_mut().select_prev();
        }
    }

    pub fn select_first(&mut self) {
        self.active_panel_mut().select_first();
        if self.is_synced() {
            self.inactive_panel_mut().select_first();
        }
    }

    pub fn select_last(&mut self) {
        self.active_panel_mut().select_last();
        if self.is_synced() {
            self.inactive_panel_mut().select_last();
        }
    }

    pub fn page_up(&mut self) {
        self.active_panel_mut().page_up();
        if self.is_synced() {
            self.inactive_panel_mut().page_up();
        }
    }

    pub fn page_down(&mut self) {
        self.active_panel_mut().page_down();
        if self.is_synced() {
            self.inactive_panel_mut().page_down();
        }
    }
}
