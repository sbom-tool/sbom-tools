//! Hierarchical tree widget for component navigation.

use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget},
};
use std::collections::HashSet;

/// A node in the component tree.
#[derive(Debug, Clone)]
pub enum TreeNode {
    /// A group node (ecosystem, namespace, etc.)
    Group {
        id: String,
        label: String,
        children: Vec<Self>,
        item_count: usize,
        vuln_count: usize,
    },
    /// A leaf component node
    Component {
        id: String,
        name: String,
        version: Option<String>,
        vuln_count: usize,
        /// Maximum severity level of vulnerabilities (critical/high/medium/low)
        max_severity: Option<String>,
        /// Component type indicator (library, binary, file, etc.)
        component_type: Option<String>,
        /// Ecosystem (npm, pypi, etc.) for display tag
        ecosystem: Option<String>,
        /// Whether this component is bookmarked by the user
        is_bookmarked: bool,
    },
}

impl TreeNode {
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Group { id, .. } | Self::Component { id, .. } => id,
        }
    }

    pub(crate) fn label(&self) -> String {
        match self {
            Self::Group {
                label, item_count, ..
            } => format!("{label} ({item_count})"),
            Self::Component {
                name,
                version,
                ecosystem,
                is_bookmarked,
                ..
            } => {
                let display_name = extract_display_name(name);
                let mut result = if let Some(v) = version {
                    format!("{display_name}@{v}")
                } else {
                    display_name
                };
                // Append ecosystem tag if present and not "Unknown"
                if let Some(eco) = ecosystem
                    && eco != "Unknown"
                {
                    use std::fmt::Write;
                    let _ = write!(result, " [{eco}]");
                }
                // Prepend bookmark star
                if *is_bookmarked {
                    result = format!("\u{2605} {result}");
                }
                result
            }
        }
    }

    pub(crate) const fn vuln_count(&self) -> usize {
        match self {
            Self::Group { vuln_count, .. } | Self::Component { vuln_count, .. } => *vuln_count,
        }
    }

    pub(crate) fn max_severity(&self) -> Option<&str> {
        match self {
            Self::Component { max_severity, .. } => max_severity.as_deref(),
            Self::Group { .. } => None,
        }
    }

    pub(crate) const fn is_group(&self) -> bool {
        matches!(self, Self::Group { .. })
    }

    pub(crate) fn children(&self) -> Option<&[Self]> {
        match self {
            Self::Group { children, .. } => Some(children),
            Self::Component { .. } => None,
        }
    }
}

/// Extract a meaningful display name from a component path
pub fn extract_display_name(name: &str) -> String {
    // If it's a clean package name (no path separators, reasonable length), use it as-is
    if !name.contains('/') && !name.starts_with('.') && name.len() <= 40 {
        return name.to_string();
    }

    // Extract the meaningful part from a path
    if let Some(filename) = name.rsplit('/').next() {
        // Clean up common suffixes
        let clean = filename
            .trim_end_matches(".squashfs")
            .trim_end_matches(".squ")
            .trim_end_matches(".img")
            .trim_end_matches(".bin")
            .trim_end_matches(".unknown")
            .trim_end_matches(".crt")
            .trim_end_matches(".so")
            .trim_end_matches(".a")
            .trim_end_matches(".elf32");

        // If the remaining name is a hash-like string, try to get parent directory context
        if is_hash_like(clean) {
            // Try to find a meaningful parent directory
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() >= 2 {
                // Look for meaningful directory names
                for part in parts.iter().rev().skip(1) {
                    if !part.is_empty()
                        && !part.starts_with('.')
                        && !is_hash_like(part)
                        && part.len() > 2
                    {
                        return format!("{}/{}", part, truncate_name(filename, 20));
                    }
                }
            }
            return truncate_name(filename, 25);
        }

        return clean.to_string();
    }

    truncate_name(name, 30)
}

/// Check if a name looks like a hash (hex digits and dashes)
fn is_hash_like(name: &str) -> bool {
    if name.len() < 8 {
        return false;
    }
    let clean = name.replace(['-', '_'], "");
    clean.chars().all(|c| c.is_ascii_hexdigit())
        || (clean.chars().filter(char::is_ascii_digit).count() > clean.len() / 2)
}

/// Truncate a name with ellipsis
fn truncate_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}...", &name[..max_len.saturating_sub(3)])
    }
}

/// Get component type from path/name
pub fn detect_component_type(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    let ext = std::path::Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if matches!(ext, "so") || lower.contains(".so.") {
        return "lib";
    }
    if matches!(ext, "a") {
        return "lib";
    }
    if matches!(ext, "crt" | "pem" | "key") {
        return "cert";
    }
    if matches!(ext, "img" | "bin" | "elf" | "elf32") {
        return "bin";
    }
    if matches!(ext, "squashfs" | "squ") {
        return "fs";
    }
    if matches!(ext, "unknown") {
        return "unk";
    }
    if lower.contains("lib") {
        return "lib";
    }

    "file"
}

/// State for the tree widget.
#[derive(Debug, Clone, Default)]
pub struct TreeState {
    /// Currently selected node index in flattened view
    pub selected: usize,
    /// Set of expanded node IDs
    pub expanded: HashSet<String>,
    /// Scroll offset
    pub offset: usize,
    /// Total visible items
    pub visible_count: usize,
}

impl TreeState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn toggle_expand(&mut self, node_id: &str) {
        if self.expanded.contains(node_id) {
            self.expanded.remove(node_id);
        } else {
            self.expanded.insert(node_id.to_string());
        }
    }

    pub(crate) fn expand(&mut self, node_id: &str) {
        self.expanded.insert(node_id.to_string());
    }

    pub(crate) fn collapse(&mut self, node_id: &str) {
        self.expanded.remove(node_id);
    }

    pub(crate) fn is_expanded(&self, node_id: &str) -> bool {
        self.expanded.contains(node_id)
    }

    pub(crate) const fn select_next(&mut self) {
        if self.visible_count > 0 && self.selected < self.visible_count - 1 {
            self.selected += 1;
        }
    }

    pub(crate) const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub(crate) const fn select_first(&mut self) {
        self.selected = 0;
    }

    pub(crate) const fn select_last(&mut self) {
        if self.visible_count > 0 {
            self.selected = self.visible_count - 1;
        }
    }
}

/// A flattened tree item for rendering.
#[derive(Debug, Clone)]
pub struct FlattenedItem {
    pub label: String,
    pub depth: usize,
    pub is_group: bool,
    pub is_expanded: bool,
    pub is_last_sibling: bool,
    pub vuln_count: usize,
    pub ancestors_last: Vec<bool>,
    /// Maximum severity for components with vulnerabilities
    pub max_severity: Option<String>,
}

/// The tree widget.
pub struct Tree<'a> {
    roots: &'a [TreeNode],
    block: Option<Block<'a>>,
    highlight_style: Style,
    highlight_symbol: &'a str,
    group_style: Style,
    component_style: Style,
}

impl<'a> Tree<'a> {
    pub(crate) fn new(roots: &'a [TreeNode]) -> Self {
        let scheme = colors();
        Self {
            roots,
            block: None,
            highlight_style: Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
            highlight_symbol: "▶ ",
            group_style: Style::default().fg(scheme.primary).bold(),
            component_style: Style::default().fg(scheme.text),
        }
    }

    pub(crate) fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub(crate) const fn highlight_style(mut self, style: Style) -> Self {
        self.highlight_style = style;
        self
    }

    /// Flatten the tree into a list of items for rendering.
    fn flatten(&self, state: &TreeState) -> Vec<FlattenedItem> {
        let mut items = Vec::new();
        self.flatten_nodes(self.roots, 0, state, &mut items, &[]);
        items
    }

    #[allow(clippy::only_used_in_recursion)]
    fn flatten_nodes(
        &self,
        nodes: &[TreeNode],
        depth: usize,
        state: &TreeState,
        items: &mut Vec<FlattenedItem>,
        ancestors_last: &[bool],
    ) {
        for (i, node) in nodes.iter().enumerate() {
            let is_last = i == nodes.len() - 1;
            let is_expanded = state.is_expanded(node.id());

            let mut current_ancestors = ancestors_last.to_vec();
            current_ancestors.push(is_last);

            items.push(FlattenedItem {
                label: node.label(),
                depth,
                is_group: node.is_group(),
                is_expanded,
                is_last_sibling: is_last,
                vuln_count: node.vuln_count(),
                ancestors_last: current_ancestors.clone(),
                max_severity: node.max_severity().map(std::string::ToString::to_string),
            });

            // Recursively add children if expanded
            if is_expanded && let Some(children) = node.children() {
                self.flatten_nodes(children, depth + 1, state, items, &current_ancestors);
            }
        }
    }
}

impl StatefulWidget for Tree<'_> {
    type State = TreeState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Handle block separately to avoid borrow issues
        let inner_area = self.block.as_ref().map_or(area, |b| {
            let inner = b.inner(area);
            b.clone().render(area, buf);
            inner
        });

        if inner_area.width < 4 || inner_area.height < 1 {
            return;
        }

        let items = self.flatten(state);
        let area = inner_area;
        state.visible_count = items.len();

        // Calculate scroll offset to keep selected item visible
        let visible_height = area.height as usize;
        if state.selected >= state.offset + visible_height {
            state.offset = state.selected - visible_height + 1;
        } else if state.selected < state.offset {
            state.offset = state.selected;
        }

        // Render visible items
        for (i, item) in items
            .iter()
            .skip(state.offset)
            .take(visible_height)
            .enumerate()
        {
            let y = area.y + i as u16;
            let is_selected = state.offset + i == state.selected;

            // Build the tree prefix with box-drawing characters
            let mut prefix = String::new();
            for (depth, is_last) in item.ancestors_last.iter().take(item.depth).enumerate() {
                if depth < item.depth {
                    if *is_last {
                        prefix.push_str("   ");
                    } else {
                        prefix.push_str("│  ");
                    }
                }
            }

            // Add the branch character for this node
            if item.depth > 0 {
                if item.is_last_sibling {
                    prefix.push_str("└─ ");
                } else {
                    prefix.push_str("├─ ");
                }
            }

            // Add expand/collapse indicator for groups
            let expand_indicator = if item.is_group {
                if item.is_expanded { "▼ " } else { "▶ " }
            } else {
                "  "
            };

            // Build the line
            let mut x = area.x;

            // Selection indicator
            let scheme = colors();
            if is_selected {
                let symbol = self.highlight_symbol;
                for ch in symbol.chars() {
                    if x < area.x + area.width {
                        if let Some(cell) = buf.cell_mut((x, y)) {
                            cell.set_char(ch)
                                .set_style(Style::default().fg(scheme.accent));
                        }
                        x += 1;
                    }
                }
            } else {
                x += self.highlight_symbol.len() as u16;
            }

            // Tree prefix
            for ch in prefix.chars() {
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(scheme.muted));
                    }
                    x += 1;
                }
            }

            // Expand indicator
            let indicator_style = if item.is_group {
                Style::default().fg(scheme.accent)
            } else {
                Style::default()
            };
            for ch in expand_indicator.chars() {
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(ch).set_style(indicator_style);
                    }
                    x += 1;
                }
            }

            // Label
            let label_style = if is_selected {
                self.highlight_style
            } else if item.is_group {
                self.group_style
            } else {
                self.component_style
            };

            for ch in item.label.chars() {
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(ch).set_style(label_style);
                    }
                    x += 1;
                }
            }

            // Vulnerability indicator with severity badge
            if item.vuln_count > 0 {
                // Get severity color
                let (sev_char, sev_color) =
                    item.max_severity
                        .as_ref()
                        .map_or(('!', scheme.warning), |sev| {
                            match sev.to_lowercase().as_str() {
                                "critical" => ('C', scheme.critical),
                                "high" => ('H', scheme.high),
                                "medium" => ('M', scheme.medium),
                                "low" => ('L', scheme.low),
                                _ => ('!', scheme.warning),
                            }
                        });

                // Space before indicator
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(' ');
                    }
                    x += 1;
                }

                // Severity badge [C], [H], [M], [L]
                let badge_style = Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(sev_color)
                    .bold();

                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(sev_char).set_style(badge_style);
                    }
                    x += 1;
                }

                // Vuln count
                let count_text = format!("{}", item.vuln_count);
                let count_style = Style::default().fg(sev_color).bold();
                for ch in count_text.chars() {
                    if x < area.x + area.width {
                        if let Some(cell) = buf.cell_mut((x, y)) {
                            cell.set_char(ch).set_style(count_style);
                        }
                        x += 1;
                    }
                }
            }

            // Fill rest with background if selected
            if is_selected {
                while x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_style(self.highlight_style);
                    }
                    x += 1;
                }
            }
        }

        // Render scrollbar if needed
        if items.len() > visible_height {
            let scheme = colors();
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .thumb_style(Style::default().fg(scheme.accent))
                .track_style(Style::default().fg(scheme.muted));
            let mut scrollbar_state = ScrollbarState::new(items.len()).position(state.selected);
            scrollbar.render(area, buf, &mut scrollbar_state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_state() {
        let mut state = TreeState::new();
        assert!(!state.is_expanded("test"));

        state.toggle_expand("test");
        assert!(state.is_expanded("test"));

        state.toggle_expand("test");
        assert!(!state.is_expanded("test"));
    }

    #[test]
    fn test_tree_node() {
        let node = TreeNode::Component {
            id: "comp-1".to_string(),
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            vuln_count: 2,
            max_severity: Some("high".to_string()),
            component_type: Some("lib".to_string()),
            ecosystem: Some("npm".to_string()),
            is_bookmarked: false,
        };

        assert_eq!(node.label(), "lodash@4.17.21 [npm]");
        assert_eq!(node.vuln_count(), 2);
        assert_eq!(node.max_severity(), Some("high"));
        assert!(!node.is_group());
    }

    #[test]
    fn test_tree_node_bookmarked() {
        let node = TreeNode::Component {
            id: "comp-1".to_string(),
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            vuln_count: 0,
            max_severity: None,
            component_type: None,
            ecosystem: None,
            is_bookmarked: true,
        };

        assert_eq!(node.label(), "\u{2605} lodash@4.17.21");
    }

    #[test]
    fn test_tree_node_unknown_ecosystem_hidden() {
        let node = TreeNode::Component {
            id: "comp-1".to_string(),
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            vuln_count: 0,
            max_severity: None,
            component_type: None,
            ecosystem: Some("Unknown".to_string()),
            is_bookmarked: false,
        };

        assert_eq!(node.label(), "lodash@4.17.21");
    }

    #[test]
    fn test_extract_display_name() {
        // Path-like names - extracts the filename
        assert_eq!(
            extract_display_name("./6488064-48136192.squashfs_v4_le_extract/SMASH/ShowProperty"),
            "ShowProperty"
        );

        // Clean package names should pass through
        assert_eq!(extract_display_name("lodash"), "lodash");
        assert_eq!(extract_display_name("openssl-1.1.1"), "openssl-1.1.1");

        // Hash-like filenames with meaningful parent get parent/file format
        let hash_result = extract_display_name("./6488064-48136192.squashfs");
        assert!(hash_result.len() <= 30);
    }

    #[test]
    fn test_detect_component_type() {
        assert_eq!(detect_component_type("libssl.so"), "lib");
        assert_eq!(detect_component_type("libcrypto.so.1.1"), "lib");
        assert_eq!(detect_component_type("server.crt"), "cert");
        assert_eq!(detect_component_type("firmware.img"), "bin");
        assert_eq!(detect_component_type("rootfs.squashfs"), "fs");
        assert_eq!(detect_component_type("random.unknown"), "unk");
    }
}
