//! Source tab state for viewing raw SBOM file content.
//!
//! Provides a JSON tree model and panel state for both single-SBOM
//! viewing (`ViewApp`) and side-by-side diff viewing (App).

use std::collections::{BTreeSet, HashMap, HashSet};

/// A node in the XML tree, built from XML content via `quick_xml`.
#[derive(Debug, Clone)]
pub enum XmlTreeNode {
    Element {
        name: String,
        attributes: Vec<(String, String)>,
        children: Vec<Self>,
    },
    Text(String),
}

/// Parse XML content into an `XmlTreeNode` tree.
pub fn xml_tree_from_str(xml: &str) -> Option<XmlTreeNode> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<XmlTreeNode> = Vec::new();

    // Virtual root to collect top-level elements
    stack.push(XmlTreeNode::Element {
        name: "root".to_string(),
        attributes: Vec::new(),
        children: Vec::new(),
    });

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| {
                        a.ok().map(|attr| {
                            (
                                String::from_utf8_lossy(attr.key.as_ref()).to_string(),
                                String::from_utf8_lossy(&attr.value).to_string(),
                            )
                        })
                    })
                    .collect();
                stack.push(XmlTreeNode::Element {
                    name,
                    attributes,
                    children: Vec::new(),
                });
            }
            Ok(Event::End(_)) => {
                if stack.len() > 1 {
                    let child = stack.pop()?;
                    if let Some(XmlTreeNode::Element { children, .. }) = stack.last_mut() {
                        children.push(child);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| {
                        a.ok().map(|attr| {
                            (
                                String::from_utf8_lossy(attr.key.as_ref()).to_string(),
                                String::from_utf8_lossy(&attr.value).to_string(),
                            )
                        })
                    })
                    .collect();
                if let Some(XmlTreeNode::Element { children, .. }) = stack.last_mut() {
                    children.push(XmlTreeNode::Element {
                        name,
                        attributes,
                        children: Vec::new(),
                    });
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.decode().unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    if let Some(XmlTreeNode::Element { children, .. }) = stack.last_mut() {
                        children.push(XmlTreeNode::Text(text));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    stack.pop()
}

/// Flatten an XML tree into `FlatJsonItem` values for rendering compatibility.
pub fn flatten_xml_tree(
    node: &XmlTreeNode,
    parent_path: &str,
    depth: usize,
    expanded: &HashSet<String>,
    items: &mut Vec<crate::tui::shared::source::FlatJsonItem>,
    is_last_sibling: bool,
    ancestors_last: &[bool],
) {
    match node {
        XmlTreeNode::Element {
            name,
            attributes,
            children,
            ..
        } => {
            let node_id = if parent_path.is_empty() {
                name.clone()
            } else {
                format!("{parent_path}.{name}")
            };
            let is_expanded = expanded.contains(&node_id);
            let has_children = !children.is_empty();

            // Show attributes inline in the value_preview
            let attr_preview = if attributes.is_empty() {
                String::new()
            } else {
                attributes
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(" ")
            };

            let child_count_label = if has_children {
                format!("<> ({} children)", children.len())
            } else if !attr_preview.is_empty() {
                String::new()
            } else {
                "</>".to_string()
            };

            items.push(crate::tui::shared::source::FlatJsonItem {
                node_id: node_id.clone(),
                depth,
                display_key: format!("<{name}>"),
                value_preview: attr_preview,
                value_type: None,
                is_expandable: has_children,
                is_expanded,
                child_count_label,
                is_last_sibling,
                ancestors_last: ancestors_last.to_vec(),
            });

            if is_expanded {
                let mut current_ancestors = ancestors_last.to_vec();
                current_ancestors.push(is_last_sibling);
                for (i, child) in children.iter().enumerate() {
                    let child_is_last = i == children.len() - 1;
                    flatten_xml_tree(
                        child,
                        &node_id,
                        depth + 1,
                        expanded,
                        items,
                        child_is_last,
                        &current_ancestors,
                    );
                }
            }
        }
        XmlTreeNode::Text(text) => {
            let node_id = if parent_path.is_empty() {
                "#text".to_string()
            } else {
                format!("{parent_path}.#text")
            };
            items.push(crate::tui::shared::source::FlatJsonItem {
                node_id,
                depth,
                display_key: String::new(),
                value_preview: format!("\"{text}\""),
                value_type: Some(JsonValueType::String),
                is_expandable: false,
                is_expanded: false,
                child_count_label: String::new(),
                is_last_sibling,
                ancestors_last: ancestors_last.to_vec(),
            });
        }
    }
}

/// Count nodes in an XML tree.
fn count_xml_nodes(node: &XmlTreeNode) -> usize {
    match node {
        XmlTreeNode::Element { children, .. } => {
            1 + children.iter().map(count_xml_nodes).sum::<usize>()
        }
        XmlTreeNode::Text(_) => 1,
    }
}

/// Pretty-print an XML tree for raw mode display.
fn pretty_print_xml(node: &XmlTreeNode, depth: usize) -> Vec<String> {
    let indent = "  ".repeat(depth);
    match node {
        XmlTreeNode::Element {
            name,
            attributes,
            children,
            ..
        } => {
            let attrs = if attributes.is_empty() {
                String::new()
            } else {
                attributes
                    .iter()
                    .map(|(k, v)| format!(" {k}=\"{v}\""))
                    .collect::<String>()
            };
            let mut lines = Vec::new();
            if children.is_empty() {
                lines.push(format!("{indent}<{name}{attrs}/>"));
            } else if children.len() == 1 && matches!(&children[0], XmlTreeNode::Text(_)) {
                let text = match &children[0] {
                    XmlTreeNode::Text(t) => t.as_str(),
                    _ => "",
                };
                lines.push(format!("{indent}<{name}{attrs}>{text}</{name}>"));
            } else {
                lines.push(format!("{indent}<{name}{attrs}>"));
                for child in children {
                    lines.extend(pretty_print_xml(child, depth + 1));
                }
                lines.push(format!("{indent}</{name}>"));
            }
            lines
        }
        XmlTreeNode::Text(text) => {
            vec![format!("{indent}{text}")]
        }
    }
}

/// Change status for diff highlighting in the source tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceChangeStatus {
    Added,
    Removed,
    Modified,
}

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

/// Sort mode for tree view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceSortMode {
    #[default]
    None,
    KeyAsc,
    KeyDesc,
}

impl SourceSortMode {
    /// Cycle to the next sort mode.
    pub const fn next(self) -> Self {
        match self {
            Self::None => Self::KeyAsc,
            Self::KeyAsc => Self::KeyDesc,
            Self::KeyDesc => Self::None,
        }
    }

    /// Label for display.
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "",
            Self::KeyAsc => "[A-Z]",
            Self::KeyDesc => "[Z-A]",
        }
    }
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
            | Self::Leaf { key, index, .. } => index
                .as_ref()
                .map_or_else(|| key.clone(), |i| format!("[{i}]")),
        };
        if parent_path.is_empty() {
            key_part
        } else {
            format!("{parent_path}.{key_part}")
        }
    }

    pub const fn is_expandable(&self) -> bool {
        matches!(self, Self::Object { .. } | Self::Array { .. })
    }

    pub fn children(&self) -> Option<&[Self]> {
        match self {
            Self::Object { children, .. } | Self::Array { children, .. } => Some(children),
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
            | Self::Leaf { key, index, .. } => index
                .as_ref()
                .map_or_else(|| key.clone(), |i| format!("[{i}]")),
        }
    }
}

fn truncate_value(s: &str, max_len: usize) -> String {
    crate::tui::widgets::truncate_str(s, max_len)
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
    /// XML tree (built from raw content; None if not valid XML)
    pub xml_tree: Option<XmlTreeNode>,
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
    /// Change annotations for diff highlighting (node_id → status)
    pub change_annotations: HashMap<String, SourceChangeStatus>,
    /// Viewport height in rows (set during render, used for page_up/page_down)
    pub viewport_height: usize,
    /// Horizontal scroll offset for raw mode
    pub h_scroll_offset: usize,
    /// Cached flattened tree items; rebuilt only when expanded set changes.
    pub cached_flat_items: Vec<crate::tui::shared::source::FlatJsonItem>,
    /// Whether the cached flat items are valid (invalidated on expand/collapse).
    pub flat_cache_valid: bool,
    /// Show line numbers in tree mode.
    pub show_line_numbers: bool,
    /// Word wrap in raw mode (disables horizontal scroll).
    pub word_wrap: bool,
    /// Bookmarked line indices.
    pub bookmarks: BTreeSet<usize>,
    /// Indices of lines with change annotations (for jump-to-change navigation).
    pub change_indices: Vec<usize>,
    /// Current position within change_indices.
    pub current_change_idx: Option<usize>,
    /// Whether regex search mode is active.
    pub search_regex_mode: bool,
    /// Compiled regex (when regex mode is on and query is valid).
    pub compiled_regex: Option<regex::Regex>,
    /// Filter by JSON value type (tree mode only).
    pub filter_type: Option<JsonValueType>,
    /// Sort mode for tree children (tree mode only).
    pub sort_mode: SourceSortMode,
}

impl SourcePanelState {
    /// Create a new panel state by parsing raw SBOM content.
    pub fn new(raw_content: &str) -> Self {
        let (json_tree, xml_tree, raw_lines) =
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_content) {
                let tree = JsonTreeNode::from_value("root".to_string(), None, &value);
                let pretty = serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| raw_content.to_string());
                let lines: Vec<String> = pretty
                    .lines()
                    .map(std::string::ToString::to_string)
                    .collect();
                (Some(tree), None, lines)
            } else if raw_content.trim_start().starts_with('<') {
                // Try XML parsing
                if let Some(xml) = xml_tree_from_str(raw_content) {
                    let lines = pretty_print_xml(&xml, 0);
                    (None, Some(xml), lines)
                } else {
                    let lines: Vec<String> = raw_content
                        .lines()
                        .map(std::string::ToString::to_string)
                        .collect();
                    (None, None, lines)
                }
            } else {
                let lines: Vec<String> = raw_content
                    .lines()
                    .map(std::string::ToString::to_string)
                    .collect();
                (None, None, lines)
            };

        let has_tree = json_tree.is_some() || xml_tree.is_some();

        // Auto-expand root in tree mode
        let mut expanded = HashSet::new();
        if has_tree {
            expanded.insert("root".to_string());
        }

        let total_node_count = if let Some(ref jt) = json_tree {
            count_tree_nodes(jt)
        } else if let Some(ref xt) = xml_tree {
            count_xml_nodes(xt)
        } else {
            0
        };
        let raw_line_node_ids = if json_tree.is_some() {
            build_raw_line_mapping(&raw_lines)
        } else {
            Vec::new()
        };

        Self {
            view_mode: if has_tree {
                SourceViewMode::Tree
            } else {
                SourceViewMode::Raw
            },
            expanded,
            selected: 0,
            scroll_offset: 0,
            visible_count: 0,
            json_tree,
            xml_tree,
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
            change_annotations: HashMap::new(),
            viewport_height: 20,
            h_scroll_offset: 0,
            cached_flat_items: Vec::new(),
            flat_cache_valid: false,
            show_line_numbers: false,
            word_wrap: false,
            bookmarks: BTreeSet::new(),
            change_indices: Vec::new(),
            current_change_idx: None,
            search_regex_mode: false,
            compiled_regex: None,
            filter_type: None,
            sort_mode: SourceSortMode::None,
        }
    }

    /// Invalidate the cached flat tree items (call after expand/collapse changes).
    pub fn invalidate_flat_cache(&mut self) {
        self.flat_cache_valid = false;
        self.change_indices.clear();
        self.current_change_idx = None;
    }

    /// Ensure the cached flat tree items are up-to-date. No-op if already valid.
    pub fn ensure_flat_cache(&mut self) {
        if self.flat_cache_valid {
            return;
        }
        self.cached_flat_items.clear();
        if let Some(ref tree) = self.json_tree {
            crate::tui::shared::source::flatten_json_tree(
                tree,
                "",
                0,
                &self.expanded,
                &mut self.cached_flat_items,
                true,
                &[],
                self.sort_mode,
            );
        } else if let Some(ref xml) = self.xml_tree {
            flatten_xml_tree(
                xml,
                "",
                0,
                &self.expanded,
                &mut self.cached_flat_items,
                true,
                &[],
            );
        }

        // Apply type filter (retain expandable nodes + matching leaf types)
        if let Some(filter_type) = self.filter_type {
            self.cached_flat_items
                .retain(|item| item.is_expandable || item.value_type == Some(filter_type));
        }

        self.flat_cache_valid = true;
    }

    pub fn toggle_view_mode(&mut self) {
        // Reset horizontal scroll when switching modes
        self.h_scroll_offset = 0;

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
        let has_tree = self.json_tree.is_some() || self.xml_tree.is_some();
        let new_mode = match self.view_mode {
            SourceViewMode::Tree => SourceViewMode::Raw,
            SourceViewMode::Raw => {
                if has_tree {
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
        } else if let Some(ref xml) = self.xml_tree {
            expand_all_xml_recursive(xml, "", &mut self.expanded);
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
        self.selected = (self.selected + self.viewport_height).min(max.saturating_sub(1));
    }

    pub fn page_up(&mut self) {
        self.selected = self.selected.saturating_sub(self.viewport_height);
    }

    fn effective_count(&self) -> usize {
        if self.visible_count > 0 {
            self.visible_count
        } else {
            self.raw_lines.len()
        }
    }

    pub fn scroll_left(&mut self) {
        self.h_scroll_offset = self.h_scroll_offset.saturating_sub(4);
    }

    pub fn scroll_right(&mut self) {
        self.h_scroll_offset += 4;
    }

    /// Expand all nodes up to (but not including) the given depth.
    /// Depth 0 = root only, 1 = root + direct children, etc.
    pub fn expand_to_depth(&mut self, max_depth: usize) {
        self.expanded.clear();
        if let Some(ref tree) = self.json_tree {
            expand_to_depth_recursive(tree, "", 0, max_depth, &mut self.expanded);
        } else if let Some(ref xml) = self.xml_tree {
            expand_to_depth_xml_recursive(xml, "", 0, max_depth, &mut self.expanded);
        }
        self.invalidate_flat_cache();
    }

    /// Find a change annotation for a node_id, checking ancestors if no direct match.
    pub fn find_annotation(&self, node_id: &str) -> Option<SourceChangeStatus> {
        if let Some(status) = self.change_annotations.get(node_id) {
            return Some(*status);
        }
        // Walk ancestor paths
        let parts: Vec<&str> = node_id.split('.').collect();
        for len in (1..parts.len()).rev() {
            let ancestor = parts[..len].join(".");
            if let Some(status) = self.change_annotations.get(&ancestor) {
                return Some(*status);
            }
        }
        None
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
        self.update_compiled_regex();
        self.execute_search();
    }

    pub fn search_pop_char(&mut self) {
        self.search_query.pop();
        self.update_compiled_regex();
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

        // Use regex matching if regex mode is on and regex compiles
        if self.search_regex_mode {
            // Clone the regex to avoid borrow conflict with ensure_flat_cache
            if let Some(re) = self.compiled_regex.clone() {
                match self.view_mode {
                    SourceViewMode::Tree => {
                        self.ensure_flat_cache();
                        for (i, item) in self.cached_flat_items.iter().enumerate() {
                            if re.is_match(&item.display_key) || re.is_match(&item.value_preview) {
                                self.search_matches.push(i);
                            }
                        }
                    }
                    SourceViewMode::Raw => {
                        for (i, line) in self.raw_lines.iter().enumerate() {
                            if re.is_match(line) {
                                self.search_matches.push(i);
                            }
                        }
                    }
                }
            }
            // If regex doesn't compile, no matches (intentional)
        } else {
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
        }

        // Jump to first match
        if !self.search_matches.is_empty() {
            self.selected = self.search_matches[0];
        }
    }

    // --- Line numbers ---

    pub fn toggle_line_numbers(&mut self) {
        self.show_line_numbers = !self.show_line_numbers;
    }

    // --- Word wrap ---

    pub fn toggle_word_wrap(&mut self) {
        self.word_wrap = !self.word_wrap;
        if self.word_wrap {
            self.h_scroll_offset = 0;
        }
    }

    // --- Bookmarks ---

    pub fn toggle_bookmark(&mut self) {
        if !self.bookmarks.remove(&self.selected) {
            self.bookmarks.insert(self.selected);
        }
    }

    pub fn next_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            return;
        }
        // Find next bookmark after current selection
        if let Some(&next) = self.bookmarks.range((self.selected + 1)..).next() {
            self.selected = next;
        } else {
            // Wrap around
            if let Some(&first) = self.bookmarks.iter().next() {
                self.selected = first;
            }
        }
    }

    pub fn prev_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            return;
        }
        if let Some(&prev) = self.bookmarks.range(..self.selected).next_back() {
            self.selected = prev;
        } else {
            // Wrap around
            if let Some(&last) = self.bookmarks.iter().next_back() {
                self.selected = last;
            }
        }
    }

    // --- Change navigation ---

    /// Build the change_indices list by scanning for annotated items.
    pub fn build_change_indices(&mut self) {
        self.change_indices.clear();
        self.current_change_idx = None;

        if self.change_annotations.is_empty() {
            return;
        }

        match self.view_mode {
            SourceViewMode::Tree => {
                self.ensure_flat_cache();
                for (i, item) in self.cached_flat_items.iter().enumerate() {
                    if self.find_annotation(&item.node_id).is_some() {
                        self.change_indices.push(i);
                    }
                }
            }
            SourceViewMode::Raw => {
                for (i, node_id) in self.raw_line_node_ids.iter().enumerate() {
                    if !node_id.is_empty() && self.find_annotation(node_id).is_some() {
                        self.change_indices.push(i);
                    }
                }
            }
        }

        // Deduplicate (annotations can repeat via ancestors)
        self.change_indices.dedup();
    }

    pub fn next_change(&mut self) {
        if self.change_indices.is_empty() {
            self.build_change_indices();
        }
        if self.change_indices.is_empty() {
            return;
        }
        let idx = match self.current_change_idx {
            Some(i) => {
                if i + 1 < self.change_indices.len() {
                    i + 1
                } else {
                    0
                }
            }
            None => {
                // Find first change at or after current selection
                self.change_indices
                    .iter()
                    .position(|&ci| ci >= self.selected)
                    .unwrap_or(0)
            }
        };
        self.current_change_idx = Some(idx);
        self.selected = self.change_indices[idx];
    }

    pub fn prev_change(&mut self) {
        if self.change_indices.is_empty() {
            self.build_change_indices();
        }
        if self.change_indices.is_empty() {
            return;
        }
        let idx = match self.current_change_idx {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    self.change_indices.len() - 1
                }
            }
            None => self
                .change_indices
                .iter()
                .rposition(|&ci| ci <= self.selected)
                .unwrap_or(self.change_indices.len() - 1),
        };
        self.current_change_idx = Some(idx);
        self.selected = self.change_indices[idx];
    }

    // --- Regex search ---

    pub fn toggle_search_regex(&mut self) {
        self.search_regex_mode = !self.search_regex_mode;
        self.update_compiled_regex();
        self.execute_search();
    }

    fn update_compiled_regex(&mut self) {
        if self.search_regex_mode && !self.search_query.is_empty() {
            self.compiled_regex = regex::RegexBuilder::new(&self.search_query)
                .case_insensitive(true)
                .build()
                .ok();
        } else {
            self.compiled_regex = None;
        }
    }

    // --- Filter/Sort ---

    pub fn cycle_filter_type(&mut self) {
        self.filter_type = match self.filter_type {
            None => Some(JsonValueType::String),
            Some(JsonValueType::String) => Some(JsonValueType::Number),
            Some(JsonValueType::Number) => Some(JsonValueType::Boolean),
            Some(JsonValueType::Boolean) => None,
            Some(JsonValueType::Null) => None,
        };
        self.invalidate_flat_cache();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.invalidate_flat_cache();
    }

    /// Get a display label for the current filter type.
    pub fn filter_label(&self) -> &'static str {
        match self.filter_type {
            None => "",
            Some(JsonValueType::String) => "[Str]",
            Some(JsonValueType::Number) => "[Num]",
            Some(JsonValueType::Boolean) => "[Bool]",
            Some(JsonValueType::Null) => "[Null]",
        }
    }

    /// Get the full raw content as a single string.
    pub fn get_full_content(&self) -> String {
        self.raw_lines.join("\n")
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

fn expand_all_xml_recursive(node: &XmlTreeNode, path: &str, expanded: &mut HashSet<String>) {
    if let XmlTreeNode::Element { name, children, .. } = node {
        let id = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        if !children.is_empty() {
            expanded.insert(id.clone());
            for child in children {
                expand_all_xml_recursive(child, &id, expanded);
            }
        }
    }
}

fn expand_to_depth_xml_recursive(
    node: &XmlTreeNode,
    path: &str,
    depth: usize,
    max_depth: usize,
    expanded: &mut HashSet<String>,
) {
    if let XmlTreeNode::Element { name, children, .. } = node {
        let id = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        if !children.is_empty() && depth < max_depth {
            expanded.insert(id.clone());
            for child in children {
                expand_to_depth_xml_recursive(child, &id, depth + 1, max_depth, expanded);
            }
        }
    }
}

fn expand_to_depth_recursive(
    node: &JsonTreeNode,
    path: &str,
    depth: usize,
    max_depth: usize,
    expanded: &mut HashSet<String>,
) {
    let id = node.node_id(path);
    if node.is_expandable() && depth < max_depth {
        expanded.insert(id.clone());
        if let Some(children) = node.children() {
            for child in children {
                expand_to_depth_recursive(child, &id, depth + 1, max_depth, expanded);
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
    /// Whether the detail panel is visible.
    pub show_detail: bool,
    /// Scroll offset within the detail panel.
    pub detail_scroll: usize,
}

impl SourceDiffState {
    pub fn new(old_raw: &str, new_raw: &str) -> Self {
        Self {
            old_panel: SourcePanelState::new(old_raw),
            new_panel: SourcePanelState::new(new_raw),
            active_side: SourceSide::New,
            sync_mode: super::ScrollSyncMode::Locked,
            show_detail: false,
            detail_scroll: 0,
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

    /// Populate change annotations from a diff result.
    ///
    /// Maps component indices to JSON paths and marks them as added/removed/modified
    /// on the appropriate panel.
    pub fn populate_annotations(&mut self, diff: &crate::diff::DiffResult) {
        // Build component name → array index mapping for old panel
        let old_comp_indices = build_component_index(&self.old_panel);
        // Build component name → array index mapping for new panel
        let new_comp_indices = build_component_index(&self.new_panel);

        // Mark removed components on old panel
        for comp in &diff.components.removed {
            if let Some(&idx) = old_comp_indices.get(&comp.name) {
                let path = format!("root.components.[{idx}]");
                self.old_panel
                    .change_annotations
                    .insert(path, SourceChangeStatus::Removed);
            }
        }

        // Mark added components on new panel
        for comp in &diff.components.added {
            if let Some(&idx) = new_comp_indices.get(&comp.name) {
                let path = format!("root.components.[{idx}]");
                self.new_panel
                    .change_annotations
                    .insert(path, SourceChangeStatus::Added);
            }
        }

        // Mark modified components on both panels
        for comp in &diff.components.modified {
            if let Some(&idx) = old_comp_indices.get(&comp.name) {
                let path = format!("root.components.[{idx}]");
                self.old_panel
                    .change_annotations
                    .insert(path, SourceChangeStatus::Modified);
            }
            if let Some(&idx) = new_comp_indices.get(&comp.name) {
                let path = format!("root.components.[{idx}]");
                self.new_panel
                    .change_annotations
                    .insert(path, SourceChangeStatus::Modified);
            }
        }
    }

    /// Count change annotations by status.
    pub fn annotation_counts(panel: &SourcePanelState) -> (usize, usize, usize) {
        let mut added = 0;
        let mut removed = 0;
        let mut modified = 0;
        for status in panel.change_annotations.values() {
            match status {
                SourceChangeStatus::Added => added += 1,
                SourceChangeStatus::Removed => removed += 1,
                SourceChangeStatus::Modified => modified += 1,
            }
        }
        (added, removed, modified)
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

    // --- Detail panel ---

    pub fn toggle_detail(&mut self) {
        self.show_detail = !self.show_detail;
        self.detail_scroll = 0;
    }

    /// Get details for the currently selected item in the active panel.
    pub fn get_selected_detail(&mut self) -> Option<String> {
        let panel = self.active_panel_mut();
        panel.ensure_flat_cache();
        let item = panel.cached_flat_items.get(panel.selected)?;
        let mut lines = Vec::new();
        lines.push(format!("Path: {}", item.node_id));
        lines.push(format!("Key: {}", item.display_key));
        if !item.value_preview.is_empty() {
            lines.push(format!("Value: {}", item.value_preview));
        }
        if let Some(vt) = item.value_type {
            lines.push(format!("Type: {vt:?}"));
        }
        if item.is_expandable {
            lines.push(format!("Children: {}", item.child_count_label));
        }
        lines.push(format!("Depth: {}", item.depth));
        if let Some(status) = panel.find_annotation(&item.node_id) {
            lines.push(format!("Change: {status:?}"));
        }
        Some(lines.join("\n"))
    }
}

/// Build a name→index mapping for top-level "components" array entries in a panel's JSON tree.
fn build_component_index(panel: &SourcePanelState) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let Some(ref tree) = panel.json_tree else {
        return map;
    };
    let Some(children) = tree.children() else {
        return map;
    };
    // Find the "components" child
    for child in children {
        if let JsonTreeNode::Array { key, children, .. } = child {
            if key == "components" {
                for (idx, comp_node) in children.iter().enumerate() {
                    if let Some(name) = extract_component_name(comp_node) {
                        map.insert(name, idx);
                    }
                }
            }
        }
    }
    map
}

/// Extract the "name" field from a component JSON object node.
fn extract_component_name(node: &JsonTreeNode) -> Option<String> {
    if let JsonTreeNode::Object { children, .. } = node {
        for child in children {
            if let JsonTreeNode::Leaf { key, value, .. } = child {
                if key == "name" {
                    // Strip surrounding quotes from the value
                    let v = value.trim_matches('"');
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}
