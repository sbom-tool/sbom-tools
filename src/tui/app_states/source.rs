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
                let name = e.name().as_ref().to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| {
                        a.ok()
                            .map(|attr| (attr.key.as_ref().to_string(), attr.value.to_string()))
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
                let name = e.name().as_ref().to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| {
                        a.ok()
                            .map(|attr| (attr.key.as_ref().to_string(), attr.value.to_string()))
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
                let raw: &str = e.as_ref();
                let text = raw.trim().to_string();
                if !text.is_empty()
                    && let Some(XmlTreeNode::Element { children, .. }) = stack.last_mut()
                {
                    children.push(XmlTreeNode::Text(text));
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
                preview: String::new(),
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
                preview: String::new(),
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
        use crate::tui::shared::text::count_noun;
        match self {
            Self::Object { children, .. } => {
                format!("{{}} ({})", count_noun(children.len(), "key"))
            }
            Self::Array { len, .. } => {
                format!("[] ({})", count_noun(*len, "item"))
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

    /// The key name of this node (without index formatting).
    pub fn key(&self) -> &str {
        match self {
            Self::Object { key, .. } | Self::Array { key, .. } | Self::Leaf { key, .. } => key,
        }
    }

    /// Extract a smart preview label for an array element based on the parent array's key.
    ///
    /// Returns a human-readable summary for collapsed object nodes that are children
    /// of known SBOM arrays (components, dependencies, vulnerabilities, etc.).
    /// Falls back to the first string leaf value for unknown arrays.
    pub fn preview_label(&self, parent_key: &str) -> String {
        let Self::Object { children, .. } = self else {
            return String::new();
        };

        match parent_key {
            "components" => self.preview_component(children),
            "dependencies" => self.preview_dependency(children),
            "vulnerabilities" => self.preview_vulnerability(children),
            "licenses" | "evidence" => self.preview_license(children),
            "externalReferences" => self.preview_ext_ref(children),
            "services" => self.preview_named(children),
            "tools" => self.preview_named(children),
            "compositions" => self.preview_composition(children),
            "formulation" => self.preview_named(children),
            // SPDX
            "packages" => self.preview_spdx_package(children),
            "relationships" => self.preview_spdx_relationship(children),
            "hasExtractedLicensingInfos" => self.preview_spdx_license(children),
            // Generic: first string leaf
            _ => self.preview_first_string(children),
        }
    }

    fn preview_component(&self, children: &[Self]) -> String {
        let name = find_leaf_str(children, "name");
        let version = find_leaf_str(children, "version");
        let comp_type = find_leaf_str(children, "type");
        match (name, version) {
            (Some(n), Some(v)) => {
                let suffix = comp_type.map_or(String::new(), |t| format!(" ({t})"));
                format!("{n}@{v}{suffix}")
            }
            (Some(n), None) => {
                let suffix = comp_type.map_or(String::new(), |t| format!(" ({t})"));
                format!("{n}{suffix}")
            }
            _ => String::new(),
        }
    }

    fn preview_dependency(&self, children: &[Self]) -> String {
        let ref_name = find_leaf_str(children, "ref");
        let depends_on = children.iter().find(|c| c.key() == "dependsOn");
        let dep_count = match depends_on {
            Some(Self::Array { len, .. }) => Some(*len),
            _ => None,
        };
        match (ref_name, dep_count) {
            (Some(r), Some(n)) => {
                let short = truncate_value(&r, 40);
                format!("{short} \u{2192} {n} deps")
            }
            (Some(r), None) => {
                let short = truncate_value(&r, 50);
                format!("{short} \u{2192} 0 deps")
            }
            _ => String::new(),
        }
    }

    fn preview_vulnerability(&self, children: &[Self]) -> String {
        let id = find_leaf_str(children, "id");
        // CycloneDX: ratings[0].severity, SPDX: severity
        let severity = find_leaf_str(children, "severity").or_else(|| {
            children
                .iter()
                .find(|c| c.key() == "ratings")
                .and_then(|arr| arr.children())
                .and_then(|ratings| ratings.first())
                .and_then(|r| r.children())
                .and_then(|fields| find_leaf_str(fields, "severity"))
        });
        match (id, severity) {
            (Some(i), Some(s)) => format!("{i} ({s})"),
            (Some(i), None) => i,
            _ => String::new(),
        }
    }

    fn preview_license(&self, children: &[Self]) -> String {
        // CycloneDX: license.id or expression
        let expression = find_leaf_str(children, "expression");
        if let Some(e) = expression {
            return e;
        }
        // Nested: { license: { id: "MIT" } }
        children
            .iter()
            .find(|c| c.key() == "license")
            .and_then(|lic| lic.children())
            .and_then(|fields| {
                find_leaf_str(fields, "id").or_else(|| find_leaf_str(fields, "name"))
            })
            .unwrap_or_default()
    }

    fn preview_ext_ref(&self, children: &[Self]) -> String {
        let ref_type = find_leaf_str(children, "type");
        let url = find_leaf_str(children, "url");
        match (ref_type, url) {
            (Some(t), Some(u)) => format!("{t}: {}", truncate_value(&u, 40)),
            (Some(t), None) => t,
            (None, Some(u)) => truncate_value(&u, 50),
            _ => String::new(),
        }
    }

    fn preview_named(&self, children: &[Self]) -> String {
        find_leaf_str(children, "name")
            .or_else(|| find_leaf_str(children, "vendor"))
            .unwrap_or_default()
    }

    fn preview_composition(&self, children: &[Self]) -> String {
        find_leaf_str(children, "aggregate").unwrap_or_default()
    }

    fn preview_spdx_package(&self, children: &[Self]) -> String {
        let name = find_leaf_str(children, "name");
        let version = find_leaf_str(children, "versionInfo");
        match (name, version) {
            (Some(n), Some(v)) => format!("{n}@{v}"),
            (Some(n), None) => n,
            _ => String::new(),
        }
    }

    fn preview_spdx_relationship(&self, children: &[Self]) -> String {
        let rel_type = find_leaf_str(children, "relationshipType");
        let element = find_leaf_str(children, "spdxElementId");
        let related = find_leaf_str(children, "relatedSpdxElement");
        match (element, rel_type, related) {
            (Some(e), Some(t), Some(r)) => {
                format!(
                    "{} {} {}",
                    truncate_value(&e, 20),
                    t,
                    truncate_value(&r, 20)
                )
            }
            (_, Some(t), _) => t,
            _ => String::new(),
        }
    }

    fn preview_spdx_license(&self, children: &[Self]) -> String {
        find_leaf_str(children, "licenseId")
            .or_else(|| find_leaf_str(children, "name"))
            .unwrap_or_default()
    }

    fn preview_first_string(&self, children: &[Self]) -> String {
        for child in children {
            if let Self::Leaf {
                value,
                value_type: JsonValueType::String,
                ..
            } = child
            {
                // Strip surrounding quotes from the stored value
                let s = value.trim_matches('"');
                if !s.is_empty() {
                    return truncate_value(s, 50);
                }
            }
        }
        String::new()
    }
}

fn truncate_value(s: &str, max_len: usize) -> String {
    crate::tui::widgets::truncate_str(s, max_len)
}

/// Find a direct child leaf by key name and return its unquoted string value.
fn find_leaf_str(children: &[JsonTreeNode], key: &str) -> Option<String> {
    children.iter().find_map(|c| {
        if let JsonTreeNode::Leaf {
            key: k,
            value,
            value_type: JsonValueType::String,
            ..
        } = c
            && k == key
        {
            Some(value.trim_matches('"').to_string())
        } else {
            None
        }
    })
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

/// Compute bracket pairs from pretty-printed JSON lines.
/// Returns (opening→closing, closing→opening) mappings.
fn compute_bracket_pairs(raw_lines: &[String]) -> (HashMap<usize, usize>, HashMap<usize, usize>) {
    let mut forward = HashMap::new();
    let mut reverse = HashMap::new();
    let mut stack: Vec<usize> = Vec::new();

    for (i, line) in raw_lines.iter().enumerate() {
        let trimmed = line.trim().trim_end_matches(',');
        // Check for opening brackets at end of line or standalone
        if trimmed.ends_with('{') || trimmed.ends_with('[') {
            stack.push(i);
        } else if (trimmed == "}" || trimmed == "]")
            && let Some(open) = stack.pop()
        {
            forward.insert(open, i);
            reverse.insert(i, open);
        }
    }

    (forward, reverse)
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
    /// Bracket pairs: opening line → closing line (raw JSON mode).
    pub bracket_pairs: HashMap<usize, usize>,
    /// Reverse bracket pairs: closing line → opening line (raw JSON mode).
    pub bracket_pairs_reverse: HashMap<usize, usize>,
    /// Set of opening bracket line indices that are currently folded (raw mode).
    pub folded_lines: HashSet<usize>,
    /// Show indent guides in raw mode.
    pub show_indent_guides: bool,
    /// Pre-computed link labels for navigable references (item index → display label).
    /// Populated before render by the ViewApp's source renderer.
    pub link_labels: HashMap<usize, String>,
    /// Compact tree mode: narrower connectors and indicators to save horizontal space.
    pub compact_mode: bool,
    /// Version transitions for modified components: node_id prefix -> (old_version, new_version).
    pub version_diffs: HashMap<String, (String, String)>,
    /// Whether to auto-collapse unchanged regions in diff mode.
    pub collapse_unchanged: bool,
    /// Minimum consecutive unchanged items before collapsing.
    pub collapse_threshold: usize,
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

        let (bracket_pairs, bracket_pairs_reverse) = if json_tree.is_some() {
            compute_bracket_pairs(&raw_lines)
        } else {
            (HashMap::new(), HashMap::new())
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
            bracket_pairs,
            bracket_pairs_reverse,
            folded_lines: HashSet::new(),
            show_indent_guides: true,
            link_labels: HashMap::new(),
            compact_mode: false,
            version_diffs: HashMap::new(),
            collapse_unchanged: false,
            collapse_threshold: 3,
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
                "",
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

        // Collapse long runs of unchanged items into placeholders
        self.collapse_unchanged_regions();

        self.flat_cache_valid = true;
    }

    /// Replace long runs of unchanged items with a single placeholder.
    ///
    /// Only active in diff mode when `collapse_unchanged` is enabled.
    /// Items at depth 0-1 (root/top-level structure) are always kept visible.
    /// One context item is preserved before and after each collapsed region.
    fn collapse_unchanged_regions(&mut self) {
        if !self.collapse_unchanged || self.change_annotations.is_empty() {
            return;
        }

        let items = &self.cached_flat_items;
        let mut result: Vec<crate::tui::shared::source::FlatJsonItem> =
            Vec::with_capacity(items.len());
        let mut run_start: Option<usize> = None;
        let mut run_count: usize = 0;

        for i in 0..items.len() {
            let item = &items[i];
            let has_annotation = self.find_annotation(&item.node_id).is_some();
            let is_structural = item.depth <= 1;

            if has_annotation || is_structural {
                // Flush any accumulated unchanged run
                if run_count > self.collapse_threshold {
                    if let Some(start) = run_start {
                        // Context: first unchanged item
                        result.push(items[start].clone());
                        // Placeholder
                        let collapsed_count = run_count.saturating_sub(2);
                        result.push(crate::tui::shared::source::FlatJsonItem {
                            node_id: format!("__collapsed_{start}"),
                            depth: 3,
                            display_key: format!(
                                "\u{00b7}\u{00b7}\u{00b7} {collapsed_count} unchanged items \u{00b7}\u{00b7}\u{00b7}"
                            ),
                            value_preview: String::new(),
                            value_type: None,
                            is_expandable: false,
                            is_expanded: false,
                            child_count_label: String::new(),
                            preview: String::new(),
                            is_last_sibling: false,
                            ancestors_last: vec![],
                        });
                        // Context: last unchanged item
                        if run_count > 1 {
                            result.push(items[i - 1].clone());
                        }
                    }
                } else if let Some(start) = run_start {
                    // Run too short to collapse, keep all items
                    for item in items.iter().take(i).skip(start) {
                        result.push(item.clone());
                    }
                }
                // Add the current (annotated/structural) item
                result.push(item.clone());
                run_start = None;
                run_count = 0;
            } else {
                if run_start.is_none() {
                    run_start = Some(i);
                }
                run_count += 1;
            }
        }

        // Handle trailing unchanged run
        if run_count > self.collapse_threshold {
            if let Some(start) = run_start {
                // Context: first unchanged item
                result.push(items[start].clone());
                let collapsed_count = run_count.saturating_sub(1);
                result.push(crate::tui::shared::source::FlatJsonItem {
                    node_id: format!("__collapsed_{start}"),
                    depth: 3,
                    display_key: format!(
                        "\u{00b7}\u{00b7}\u{00b7} {collapsed_count} unchanged items \u{00b7}\u{00b7}\u{00b7}"
                    ),
                    value_preview: String::new(),
                    value_type: None,
                    is_expandable: false,
                    is_expanded: false,
                    child_count_label: String::new(),
                    preview: String::new(),
                    is_last_sibling: false,
                    ancestors_last: vec![],
                });
            }
        } else if let Some(start) = run_start {
            for item in items.iter().skip(start) {
                result.push(item.clone());
            }
        }

        self.cached_flat_items = result;
    }

    /// Toggle compact tree mode (narrower connectors/indicators).
    pub fn toggle_compact_mode(&mut self) {
        self.compact_mode = !self.compact_mode;
    }

    /// Pre-compute render state before frame render to avoid mutations during rendering.
    /// Call this before `render_source_panel()` to fix flickering caused by
    /// state mutations inside the render path.
    pub fn prepare_source_render(&mut self, viewport_height: usize) {
        self.ensure_flat_cache();

        match self.view_mode {
            SourceViewMode::Tree => {
                let item_count = self.cached_flat_items.len();
                self.visible_count = item_count;

                // Clamp selection
                if self.selected >= item_count && item_count > 0 {
                    self.selected = item_count - 1;
                }

                // Scroll adjustment
                if viewport_height > 0 {
                    if self.selected >= self.scroll_offset + viewport_height {
                        self.scroll_offset = self.selected.saturating_sub(viewport_height - 1);
                    } else if self.selected < self.scroll_offset {
                        self.scroll_offset = self.selected;
                    }
                }

                self.viewport_height = viewport_height;
            }
            SourceViewMode::Raw => {
                self.visible_count = self.raw_lines.len();

                // Clamp selection
                if self.selected >= self.raw_lines.len() && !self.raw_lines.is_empty() {
                    self.selected = self.raw_lines.len() - 1;
                }

                // Scroll adjustment (for non-folded fast path)
                if self.folded_lines.is_empty() && viewport_height > 0 {
                    if self.selected >= self.scroll_offset + viewport_height {
                        self.scroll_offset = self.selected.saturating_sub(viewport_height - 1);
                    } else if self.selected < self.scroll_offset {
                        self.scroll_offset = self.selected;
                    }
                }

                self.viewport_height = viewport_height;
            }
        }
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

    /// Toggle fold at the current line in raw mode.
    /// If on an opening bracket line, fold/unfold the region.
    /// If on a closing bracket line, fold/unfold the matching opening.
    pub fn toggle_fold(&mut self) {
        let line = self.selected;
        let open_line = if self.bracket_pairs.contains_key(&line) {
            line
        } else if let Some(&open) = self.bracket_pairs_reverse.get(&line) {
            open
        } else {
            return;
        };
        if self.folded_lines.contains(&open_line) {
            self.folded_lines.remove(&open_line);
        } else {
            self.folded_lines.insert(open_line);
        }
    }

    /// Unfold all folded regions.
    pub fn unfold_all(&mut self) {
        self.folded_lines.clear();
    }

    /// Fold all top-level regions (depth 1).
    pub fn fold_all_top_level(&mut self) {
        for &open in self.bracket_pairs.keys() {
            if let Some(line) = self.raw_lines.get(open) {
                let indent = line.len() - line.trim_start().len();
                if indent <= 2 {
                    self.folded_lines.insert(open);
                }
            }
        }
    }

    /// Get the matching bracket line for the given line index.
    pub fn matching_bracket(&self, line: usize) -> Option<usize> {
        self.bracket_pairs
            .get(&line)
            .or_else(|| self.bracket_pairs_reverse.get(&line))
            .copied()
    }

    /// Jump to the matching bracket.
    pub fn jump_to_matching_bracket(&mut self) {
        if let Some(target) = self.matching_bracket(self.selected) {
            self.selected = target;
            // Ensure the target is visible (unfold if needed)
            if let Some(&open) = self.bracket_pairs_reverse.get(&target) {
                self.folded_lines.remove(&open);
            }
            if self.folded_lines.contains(&target) {
                self.folded_lines.remove(&target);
            }
        }
    }

    /// Check if a raw line index is inside a folded region (hidden).
    pub fn is_line_folded(&self, line: usize) -> bool {
        for &open in &self.folded_lines {
            if let Some(&close) = self.bracket_pairs.get(&open)
                && line > open
                && line <= close
            {
                return true;
            }
        }
        false
    }

    /// Get the next visible line after `line` (skipping folded regions).
    pub fn next_visible_line(&self, line: usize) -> usize {
        let max = self.raw_lines.len().saturating_sub(1);
        let mut next = line + 1;
        while next <= max && self.is_line_folded(next) {
            next += 1;
        }
        next.min(max)
    }

    /// Get the previous visible line before `line` (skipping folded regions).
    pub fn prev_visible_line(&self, line: usize) -> usize {
        if line == 0 {
            return 0;
        }
        let mut prev = line - 1;
        while prev > 0 && self.is_line_folded(prev) {
            prev -= 1;
        }
        prev
    }

    pub fn select_next(&mut self) {
        let max = self.effective_count();
        if max > 0 && self.selected < max.saturating_sub(1) {
            if self.view_mode == SourceViewMode::Raw && !self.folded_lines.is_empty() {
                self.selected = self.next_visible_line(self.selected);
            } else {
                self.selected += 1;
            }
        }
    }

    pub fn select_prev(&mut self) {
        if self.view_mode == SourceViewMode::Raw && !self.folded_lines.is_empty() {
            self.selected = self.prev_visible_line(self.selected);
        } else {
            self.selected = self.selected.saturating_sub(1);
        }
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
        let target = (self.selected + self.viewport_height).min(max.saturating_sub(1));
        if self.view_mode == SourceViewMode::Raw && !self.folded_lines.is_empty() {
            // Skip to target, avoiding folded interiors
            self.selected = target;
            while self.selected > 0 && self.is_line_folded(self.selected) {
                self.selected = self.next_visible_line(self.selected);
            }
        } else {
            self.selected = target;
        }
    }

    pub fn page_up(&mut self) {
        let target = self.selected.saturating_sub(self.viewport_height);
        if self.view_mode == SourceViewMode::Raw && !self.folded_lines.is_empty() {
            self.selected = target;
            while self.selected > 0 && self.is_line_folded(self.selected) {
                self.selected = self.prev_visible_line(self.selected);
            }
        } else {
            self.selected = target;
        }
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
    /// Expand every strict ancestor of each annotated path so the annotated
    /// rows are visible with their +/-/~ gutters without dumping their
    /// children (e.g. `root.components.[3]` expands `root` and
    /// `root.components` but not the component node itself).
    ///
    /// The tree previously opened fully collapsed: gutter blank, minimap
    /// reporting "0 changes", and n/N inert until the user expanded by hand.
    pub fn expand_annotated_paths(&mut self) {
        let mut inserted = false;
        let keys: Vec<String> = self.change_annotations.keys().cloned().collect();
        for key in keys {
            let parts: Vec<&str> = key.split('.').collect();
            for len in 1..parts.len() {
                let ancestor = parts[..len].join(".");
                if self.expanded.insert(ancestor) {
                    inserted = true;
                }
            }
        }
        if inserted {
            self.invalidate_flat_cache();
        }
    }

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
        // The user may have re-collapsed the tree; reveal the annotated
        // paths again. Not gated on empty indices: a top-level annotation
        // (e.g. the CycloneDX `root.version` bump) keeps one change row
        // visible even when everything else is collapsed, and n/N must not
        // get stuck cycling it. `expand_annotated_paths` is a no-op when
        // nothing is collapsed. Indices are NOT rebuilt here:
        // expand_annotated_paths invalidates the flat cache, and rebuilding
        // mid-event would mark it valid again BEFORE the render path's
        // cross-panel alignment runs — the render rebuilds (aligned) on the
        // next frame and the jump lands on the following press.
        if !self.change_annotations.is_empty() && self.view_mode == SourceViewMode::Tree {
            self.expand_annotated_paths();
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
        if !self.change_annotations.is_empty() && self.view_mode == SourceViewMode::Tree {
            // See next_change: expand only; the render path rebuilds aligned.
            self.expand_annotated_paths();
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

    /// Get the change status for an item at a specific index (tree or raw mode).
    pub fn change_status_at_index(&self, idx: usize) -> Option<SourceChangeStatus> {
        if self.change_annotations.is_empty() {
            return None;
        }
        match self.view_mode {
            SourceViewMode::Tree => self
                .cached_flat_items
                .get(idx)
                .and_then(|item| self.find_annotation(&item.node_id)),
            SourceViewMode::Raw => self
                .raw_line_node_ids
                .get(idx)
                .and_then(|node_id| self.find_annotation(node_id)),
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
    /// Whether to align items across panels in diff mode by inserting gap placeholders.
    pub align_enabled: bool,
    /// Whether alignment gaps have been inserted into the current flat caches.
    /// Reset when either panel's flat cache is invalidated.
    pub(crate) alignment_applied: bool,
    /// Frame row where the detail bottom strip starts (set by the render
    /// path while `show_detail` is on; `None` otherwise). The mouse handler
    /// uses it to keep strip clicks from falling through to the tree lists.
    pub(crate) detail_strip_top: Option<u16>,
}

impl SourceDiffState {
    pub fn new(old_raw: &str, new_raw: &str) -> Self {
        Self {
            old_panel: SourcePanelState::new(old_raw),
            new_panel: SourcePanelState::new(new_raw),
            detail_strip_top: None,
            active_side: SourceSide::New,
            sync_mode: super::ScrollSyncMode::Locked,
            show_detail: false,
            detail_scroll: 0,
            align_enabled: true,
            alignment_applied: false,
        }
    }

    pub const fn active_panel(&self) -> &SourcePanelState {
        match self.active_side {
            SourceSide::Old => &self.old_panel,
            SourceSide::New => &self.new_panel,
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
            // Store version transition for inline display
            if let (Some(old_v), Some(new_v)) = (&comp.old_version, &comp.new_version)
                && old_v != new_v
            {
                if let Some(&idx) = old_comp_indices.get(&comp.name) {
                    let path = format!("root.components.[{idx}]");
                    self.old_panel
                        .version_diffs
                        .insert(path, (old_v.clone(), new_v.clone()));
                }
                if let Some(&idx) = new_comp_indices.get(&comp.name) {
                    let path = format!("root.components.[{idx}]");
                    self.new_panel
                        .version_diffs
                        .insert(path, (old_v.clone(), new_v.clone()));
                }
            }
        }

        // Mark document-metadata changes too: the change gutter previously
        // covered only component rows, so "created" or the primary
        // component's version bump scrolled by unmarked and were excluded
        // from n/N navigation. Field keys map to their well-known JSON
        // paths per format; paths absent from a document are never looked
        // up (annotations are keyed by existing node ids), so listing both
        // CycloneDX and SPDX candidates is harmless.
        // One path per panel, chosen by that panel's format, so each change
        // contributes exactly one annotation (the minimap counts stay honest).
        fn metadata_path(panel: &SourcePanelState, field: &str) -> Option<&'static str> {
            let is_spdx = panel
                .raw_lines
                .iter()
                .take(20)
                .any(|l| l.contains("\"spdxVersion\""));
            match (field, is_spdx) {
                ("name", false) => Some("root.metadata.component.name"),
                ("name", true) => Some("root.name"),
                ("spec_version", false) => Some("root.specVersion"),
                ("spec_version", true) => Some("root.spdxVersion"),
                ("created", false) => Some("root.metadata.timestamp"),
                ("created", true) => Some("root.creationInfo.created"),
                ("serial_number", false) => Some("root.serialNumber"),
                ("doc_version", false) => Some("root.version"),
                ("primary_component_version", false) => Some("root.metadata.component.version"),
                ("data_license", true) => Some("root.dataLicense"),
                ("lifecycle_phase", false) => Some("root.metadata.lifecycles"),
                _ => None,
            }
        }
        use crate::diff::MetadataChangeKind;
        for mc in &diff.metadata_changes {
            if matches!(
                mc.kind,
                MetadataChangeKind::Removed | MetadataChangeKind::Modified
            ) && let Some(path) = metadata_path(&self.old_panel, &mc.field)
            {
                let status = if mc.kind == MetadataChangeKind::Removed {
                    SourceChangeStatus::Removed
                } else {
                    SourceChangeStatus::Modified
                };
                self.old_panel
                    .change_annotations
                    .insert(path.to_string(), status);
            }
            if matches!(
                mc.kind,
                MetadataChangeKind::Added | MetadataChangeKind::Modified
            ) && let Some(path) = metadata_path(&self.new_panel, &mc.field)
            {
                let status = if mc.kind == MetadataChangeKind::Added {
                    SourceChangeStatus::Added
                } else {
                    SourceChangeStatus::Modified
                };
                self.new_panel
                    .change_annotations
                    .insert(path.to_string(), status);
            }
        }

        // Open with the diff revealed: expand the ancestors of every
        // annotated path so gutters, the minimap count, and n/N all work
        // from the first frame.
        self.old_panel.expand_annotated_paths();
        self.new_panel.expand_annotated_paths();
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

    /// Toggle panel alignment mode.
    pub fn toggle_align(&mut self) {
        self.align_enabled = !self.align_enabled;
        self.alignment_applied = false;
        self.old_panel.invalidate_flat_cache();
        self.new_panel.invalidate_flat_cache();
    }

    /// Align items between old and new panels by inserting gap placeholders.
    ///
    /// Only aligns at the components array level (depth 2 items under `root.components`).
    /// For each removed component (in old, not in new), inserts a gap in the new panel.
    /// For each added component (in new, not in old), inserts a gap in the old panel.
    /// Gaps are single-line placeholders showing `·····` in dimmed style.
    pub fn align_component_panels(&mut self) {
        if !self.align_enabled || self.old_panel.change_annotations.is_empty() {
            return;
        }
        if self.alignment_applied {
            return;
        }

        // Ensure flat caches are built
        self.old_panel.ensure_flat_cache();
        self.new_panel.ensure_flat_cache();

        // Collect component-level entries from each panel (depth 2, under root.components)
        // Each entry is (flat_index, node_id, component_status)
        let old_comp_entries: Vec<(usize, String, Option<SourceChangeStatus>)> = self
            .old_panel
            .cached_flat_items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.depth == 2 && item.node_id.starts_with("root.components.["))
            .map(|(i, item)| {
                let status = self
                    .old_panel
                    .change_annotations
                    .get(&item.node_id)
                    .copied();
                (i, item.node_id.clone(), status)
            })
            .collect();

        let new_comp_entries: Vec<(usize, String, Option<SourceChangeStatus>)> = self
            .new_panel
            .cached_flat_items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.depth == 2 && item.node_id.starts_with("root.components.["))
            .map(|(i, item)| {
                let status = self
                    .new_panel
                    .change_annotations
                    .get(&item.node_id)
                    .copied();
                (i, item.node_id.clone(), status)
            })
            .collect();

        if old_comp_entries.is_empty() && new_comp_entries.is_empty() {
            return;
        }

        // Count how many visible rows each component occupies (component item + expanded children)
        let old_comp_spans =
            compute_component_spans(&self.old_panel.cached_flat_items, &old_comp_entries);
        let new_comp_spans =
            compute_component_spans(&self.new_panel.cached_flat_items, &new_comp_entries);

        // Walk both component lists, building gap insertions
        // Removed components (in old panel) need a gap in new panel
        // Added components (in new panel) need a gap in old panel
        let mut old_insertions: Vec<(usize, usize)> = Vec::new(); // (position, gap_count)
        let mut new_insertions: Vec<(usize, usize)> = Vec::new();

        let mut old_idx = 0;
        let mut new_idx = 0;

        // Walk through components, matching unchanged/modified between panels
        while old_idx < old_comp_entries.len() || new_idx < new_comp_entries.len() {
            if old_idx < old_comp_entries.len()
                && matches!(
                    old_comp_entries[old_idx].2,
                    Some(SourceChangeStatus::Removed)
                )
            {
                // Removed: exists in old, not in new. Insert gap in new panel.
                let span = old_comp_spans[old_idx];
                let insert_pos = if new_idx < new_comp_entries.len() {
                    new_comp_entries[new_idx].0
                } else if let Some(last) = new_comp_entries.last() {
                    // Past the end of the new panel's components — insert at
                    // the end of the components REGION (last component + its
                    // span), not after the whole panel, or later sections
                    // (vulnerabilities, dependencies) render above the gap.
                    last.0 + new_comp_spans[new_comp_entries.len() - 1]
                } else {
                    self.new_panel.cached_flat_items.len()
                };
                new_insertions.push((insert_pos, span));
                old_idx += 1;
                continue;
            }

            if new_idx < new_comp_entries.len()
                && matches!(new_comp_entries[new_idx].2, Some(SourceChangeStatus::Added))
            {
                // Added: exists in new, not in old. Insert gap in old panel.
                let span = new_comp_spans[new_idx];
                let insert_pos = if old_idx < old_comp_entries.len() {
                    old_comp_entries[old_idx].0
                } else if let Some(last) = old_comp_entries.last() {
                    // See above: keep the gap inside the components region.
                    last.0 + old_comp_spans[old_comp_entries.len() - 1]
                } else {
                    self.old_panel.cached_flat_items.len()
                };
                old_insertions.push((insert_pos, span));
                new_idx += 1;
                continue;
            }

            // Both are unchanged or modified — advance both
            if old_idx < old_comp_entries.len() {
                old_idx += 1;
            }
            if new_idx < new_comp_entries.len() {
                new_idx += 1;
            }
        }

        // Insert gap items into panels (process from end to avoid shifting)
        insert_gap_items(&mut self.old_panel.cached_flat_items, &old_insertions);
        insert_gap_items(&mut self.new_panel.cached_flat_items, &new_insertions);

        // Update visible counts to reflect inserted gaps
        self.old_panel.visible_count = self.old_panel.cached_flat_items.len();
        self.new_panel.visible_count = self.new_panel.cached_flat_items.len();

        self.alignment_applied = true;
    }
}

/// Compute how many flat items each component occupies (1 if collapsed, more if expanded).
fn compute_component_spans(
    items: &[crate::tui::shared::source::FlatJsonItem],
    comp_entries: &[(usize, String, Option<SourceChangeStatus>)],
) -> Vec<usize> {
    comp_entries
        .iter()
        .enumerate()
        .map(|(ci, (start_idx, _, _))| {
            // Count items from this component until the next component or end of components
            let next_start = if ci + 1 < comp_entries.len() {
                comp_entries[ci + 1].0
            } else {
                // Find end of components region: next item at depth <= 1, or end
                items
                    .iter()
                    .enumerate()
                    .skip(start_idx + 1)
                    .find(|(_, item)| {
                        item.depth <= 1
                            || (item.depth == 2 && !item.node_id.starts_with("root.components.["))
                    })
                    .map_or(items.len(), |(i, _)| i)
            };
            next_start - start_idx
        })
        .collect()
}

/// Insert gap placeholder items into a flat item list.
/// `insertions` is a list of (position, gap_count) pairs.
/// Processes from end to start to avoid index shifting.
fn insert_gap_items(
    items: &mut Vec<crate::tui::shared::source::FlatJsonItem>,
    insertions: &[(usize, usize)],
) {
    // Process insertions from the highest position to lowest
    let mut sorted: Vec<(usize, usize)> = insertions.to_vec();
    sorted.sort_by_key(|a| std::cmp::Reverse(a.0));

    for (pos, count) in sorted {
        let insert_pos = pos.min(items.len());
        let gap_items: Vec<crate::tui::shared::source::FlatJsonItem> = (0..count)
            .map(|i| crate::tui::shared::source::FlatJsonItem {
                node_id: format!("__gap_{insert_pos}_{i}"),
                depth: 2,
                display_key: "\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}".to_string(),
                value_preview: String::new(),
                value_type: None,
                is_expandable: false,
                is_expanded: false,
                child_count_label: String::new(),
                preview: String::new(),
                is_last_sibling: false,
                ancestors_last: vec![],
            })
            .collect();
        // Splice gap items at the insertion point
        items.splice(insert_pos..insert_pos, gap_items);
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
        if let JsonTreeNode::Array { key, children, .. } = child
            && key == "components"
        {
            for (idx, comp_node) in children.iter().enumerate() {
                if let Some(name) = extract_component_name(comp_node) {
                    map.insert(name, idx);
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
            if let JsonTreeNode::Leaf { key, value, .. } = child
                && key == "name"
            {
                // Strip surrounding quotes from the value
                let v = value.trim_matches('"');
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod auto_expand_tests {
    use super::*;
    use crate::tui::test_support::{DEMO_NEW, DEMO_OLD, demo_diff};

    fn populated_state() -> SourceDiffState {
        let (diff, _, _) = demo_diff();
        let mut source = SourceDiffState::new(DEMO_OLD, DEMO_NEW);
        source.populate_annotations(&diff);
        source
    }

    /// Regression for the "0 changes" open: populate must reveal the
    /// annotated rows so gutters/minimap/n-N work from the first frame.
    #[test]
    fn annotated_paths_expanded_on_populate() {
        let mut source = populated_state();
        assert!(
            source.old_panel.expanded.contains("root.components"),
            "ancestors of annotated paths must be expanded"
        );
        source.old_panel.build_change_indices();
        source.new_panel.build_change_indices();
        assert!(
            !source.old_panel.change_indices.is_empty(),
            "old panel must have visible change rows"
        );
        assert!(
            !source.new_panel.change_indices.is_empty(),
            "new panel must have visible change rows"
        );
    }

    /// Ancestors expand; the annotated leaf itself stays collapsed so its
    /// children aren't dumped.
    #[test]
    fn expand_annotated_paths_expands_ancestors_not_leaf() {
        let source = populated_state();
        let leaf = source
            .new_panel
            .change_annotations
            .keys()
            .find(|k| k.starts_with("root.components.["))
            .expect("component annotations exist")
            .clone();
        assert!(source.new_panel.expanded.contains("root"));
        assert!(source.new_panel.expanded.contains("root.components"));
        assert!(
            !source.new_panel.expanded.contains(&leaf),
            "the annotated node itself must stay collapsed: {leaf}"
        );
    }

    /// If the user re-collapses the tree, the change jumper re-reveals it
    /// (expansion only — the index rebuild is deferred to the render path so
    /// cross-panel alignment always precedes it).
    #[test]
    fn next_change_reveals_recollapsed_tree() {
        let mut source = populated_state();
        source.new_panel.expanded.clear();
        source.new_panel.expanded.insert("root".to_string());
        source.new_panel.invalidate_flat_cache();

        source.new_panel.next_change();
        assert!(
            source.new_panel.expanded.contains("root.components"),
            "next_change must re-expand the annotated ancestors"
        );
        // The render path's lazy rebuild then finds the change rows again.
        source.new_panel.build_change_indices();
        assert!(
            !source.new_panel.change_indices.is_empty(),
            "the deferred rebuild must find the revealed change rows"
        );
    }
}
