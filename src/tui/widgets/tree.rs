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
        children: Vec<TreeNode>,
        item_count: usize,
        vuln_count: usize,
    },
    /// A leaf component node
    Component {
        id: String,
        name: String,
        version: Option<String>,
        vuln_count: usize,
    },
}

impl TreeNode {
    pub fn id(&self) -> &str {
        match self {
            TreeNode::Group { id, .. } => id,
            TreeNode::Component { id, .. } => id,
        }
    }

    pub fn label(&self) -> String {
        match self {
            TreeNode::Group {
                label, item_count, ..
            } => format!("{} ({})", label, item_count),
            TreeNode::Component { name, version, .. } => {
                if let Some(v) = version {
                    format!("{}@{}", name, v)
                } else {
                    name.clone()
                }
            }
        }
    }

    pub fn vuln_count(&self) -> usize {
        match self {
            TreeNode::Group { vuln_count, .. } => *vuln_count,
            TreeNode::Component { vuln_count, .. } => *vuln_count,
        }
    }

    pub fn is_group(&self) -> bool {
        matches!(self, TreeNode::Group { .. })
    }

    pub fn children(&self) -> Option<&[TreeNode]> {
        match self {
            TreeNode::Group { children, .. } => Some(children),
            TreeNode::Component { .. } => None,
        }
    }
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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn toggle_expand(&mut self, node_id: &str) {
        if self.expanded.contains(node_id) {
            self.expanded.remove(node_id);
        } else {
            self.expanded.insert(node_id.to_string());
        }
    }

    pub fn expand(&mut self, node_id: &str) {
        self.expanded.insert(node_id.to_string());
    }

    pub fn collapse(&mut self, node_id: &str) {
        self.expanded.remove(node_id);
    }

    pub fn is_expanded(&self, node_id: &str) -> bool {
        self.expanded.contains(node_id)
    }

    pub fn select_next(&mut self) {
        if self.visible_count > 0 && self.selected < self.visible_count - 1 {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    pub fn select_last(&mut self) {
        if self.visible_count > 0 {
            self.selected = self.visible_count - 1;
        }
    }

    pub fn page_down(&mut self, page_size: usize) {
        self.selected = (self.selected + page_size).min(self.visible_count.saturating_sub(1));
    }

    pub fn page_up(&mut self, page_size: usize) {
        self.selected = self.selected.saturating_sub(page_size);
    }
}

/// A flattened tree item for rendering.
#[derive(Debug, Clone)]
pub struct FlattenedItem {
    pub node_id: String,
    pub label: String,
    pub depth: usize,
    pub is_group: bool,
    pub is_expanded: bool,
    pub is_last_sibling: bool,
    pub vuln_count: usize,
    pub ancestors_last: Vec<bool>,
}

/// The tree widget.
pub struct Tree<'a> {
    roots: &'a [TreeNode],
    block: Option<Block<'a>>,
    highlight_style: Style,
    highlight_symbol: &'a str,
    group_style: Style,
    component_style: Style,
    vuln_style: Style,
}

impl<'a> Tree<'a> {
    pub fn new(roots: &'a [TreeNode]) -> Self {
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
            vuln_style: Style::default().fg(scheme.critical).bold(),
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn highlight_style(mut self, style: Style) -> Self {
        self.highlight_style = style;
        self
    }

    pub fn highlight_symbol(mut self, symbol: &'a str) -> Self {
        self.highlight_symbol = symbol;
        self
    }

    /// Flatten the tree into a list of items for rendering.
    fn flatten(&self, state: &TreeState) -> Vec<FlattenedItem> {
        let mut items = Vec::new();
        self.flatten_nodes(self.roots, 0, state, &mut items, &[]);
        items
    }

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
                node_id: node.id().to_string(),
                label: node.label(),
                depth,
                is_group: node.is_group(),
                is_expanded,
                is_last_sibling: is_last,
                vuln_count: node.vuln_count(),
                ancestors_last: current_ancestors.clone(),
            });

            // Recursively add children if expanded
            if is_expanded {
                if let Some(children) = node.children() {
                    self.flatten_nodes(children, depth + 1, state, items, &current_ancestors);
                }
            }
        }
    }
}

impl<'a> StatefulWidget for Tree<'a> {
    type State = TreeState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Handle block separately to avoid borrow issues
        let inner_area = if let Some(ref b) = self.block {
            let inner = b.inner(area);
            b.clone().render(area, buf);
            inner
        } else {
            area
        };

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
                if item.is_expanded {
                    "▼ "
                } else {
                    "▶ "
                }
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

            // Vulnerability indicator
            if item.vuln_count > 0 {
                let vuln_text = format!(" ⚠{}", item.vuln_count);
                for ch in vuln_text.chars() {
                    if x < area.x + area.width {
                        if let Some(cell) = buf.cell_mut((x, y)) {
                            cell.set_char(ch).set_style(self.vuln_style);
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

/// Get the currently selected node ID.
pub fn get_selected_node<'a>(roots: &'a [TreeNode], state: &TreeState) -> Option<&'a TreeNode> {
    let mut items = Vec::new();
    flatten_for_selection(roots, state, &mut items);
    items.get(state.selected).copied()
}

fn flatten_for_selection<'a>(
    nodes: &'a [TreeNode],
    state: &TreeState,
    items: &mut Vec<&'a TreeNode>,
) {
    for node in nodes {
        items.push(node);
        if state.is_expanded(node.id()) {
            if let Some(children) = node.children() {
                flatten_for_selection(children, state, items);
            }
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
        };

        assert_eq!(node.label(), "lodash@4.17.21");
        assert_eq!(node.vuln_count(), 2);
        assert!(!node.is_group());
    }
}
