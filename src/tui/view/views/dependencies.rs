//! Dependencies view for ViewApp.

use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use crate::tui::widgets::{self, truncate_str};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::collections::{HashMap, HashSet};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn render_dependencies(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Build the dependency graph once and reuse it
    let deps = build_dependency_graph(app);
    render_dependency_tree(frame, chunks[0], app, &deps);
    render_dependency_stats(frame, chunks[1], app, &deps);
}

/// A flattened dependency node for rendering.
#[allow(dead_code)]
struct FlatDepNode {
    id: String, // Used for expand/collapse operations
    name: String,
    depth: usize,
    is_last: bool,
    has_children: bool,
    is_expanded: bool,
    vuln_count: usize,
    ancestors_last: Vec<bool>,
}

fn render_dependency_tree(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    deps: &DependencyGraph,
) {
    let scheme = colors();

    // Flatten the tree based on expanded state
    let flat_nodes = flatten_dependency_tree(deps, &app.dependency_state.expanded);

    // Update the total count for navigation bounds
    app.dependency_state.total = flat_nodes.len();
    app.dependency_state.clamp_selection();

    let block = Block::default()
        .title(format!(" Dependency Tree ({} nodes) ", flat_nodes.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.primary));
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    // Clear the inner area to prevent glitchy rendering
    for y in inner_area.y..inner_area.y + inner_area.height {
        for x in inner_area.x..inner_area.x + inner_area.width {
            if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                cell.reset();
            }
        }
    }

    if flat_nodes.is_empty() {
        widgets::render_empty_state_enhanced(
            frame,
            inner_area,
            "🔗",
            "No dependency relationships found",
            Some("This SBOM does not contain dependency graph information"),
            Some("SBOM may only include component inventory without relationships"),
        );
        return;
    }

    let visible_height = inner_area.height as usize;
    let selected = app.dependency_state.selected;

    // Calculate scroll offset
    let scroll_offset = if visible_height == 0 {
        0
    } else if selected >= app.dependency_state.scroll_offset + visible_height {
        selected.saturating_sub(visible_height.saturating_sub(1))
    } else if selected < app.dependency_state.scroll_offset {
        selected
    } else {
        app.dependency_state.scroll_offset
    };
    app.dependency_state.scroll_offset = scroll_offset;

    let max_width = inner_area.width as usize;

    // Render visible nodes
    for (i, node) in flat_nodes
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .enumerate()
    {
        let y = inner_area.y + i as u16;
        let is_selected = scroll_offset + i == selected;

        // Build tree prefix
        let mut prefix = String::new();
        for (j, is_last) in node.ancestors_last.iter().enumerate() {
            if j < node.depth {
                if *is_last {
                    prefix.push_str("   ");
                } else {
                    prefix.push_str("│  ");
                }
            }
        }

        // Branch character
        let branch = if node.depth > 0 {
            if node.is_last {
                "└─ "
            } else {
                "├─ "
            }
        } else {
            ""
        };

        // Expand/collapse indicator
        let expand_char = if node.has_children {
            if node.is_expanded {
                "▼ "
            } else {
                "▶ "
            }
        } else {
            "  "
        };

        // Vulnerability indicator
        let vuln_indicator = if node.vuln_count > 0 {
            format!(" ⚠{}", node.vuln_count)
        } else {
            String::new()
        };

        // Calculate available width for name using display width
        let used_width = 2
            + UnicodeWidthStr::width(prefix.as_str())
            + UnicodeWidthStr::width(branch)
            + UnicodeWidthStr::width(expand_char)
            + UnicodeWidthStr::width(vuln_indicator.as_str());
        let name_max = max_width.saturating_sub(used_width);
        let display_name = truncate_str(&node.name, name_max);

        let mut x = inner_area.x;

        // Selection indicator
        if is_selected {
            let symbol = "▶ ";
            for ch in symbol.chars() {
                let w = UnicodeWidthChar::width(ch).unwrap_or(1);
                if x + w as u16 <= inner_area.x + inner_area.width {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(scheme.accent));
                    }
                    x += w as u16;
                }
            }
        } else {
            x += 2;
        }

        // Tree prefix
        for ch in prefix.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(scheme.muted));
                }
                x += w as u16;
            }
        }

        // Branch
        for ch in branch.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(scheme.muted));
                }
                x += w as u16;
            }
        }

        // Expand indicator
        let expand_style = if node.has_children {
            Style::default().fg(scheme.accent)
        } else {
            Style::default()
        };
        for ch in expand_char.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch).set_style(expand_style);
                }
                x += w as u16;
            }
        }

        // Name
        let name_style = if is_selected {
            Style::default().bg(scheme.selection).fg(scheme.text).bold()
        } else {
            Style::default().fg(scheme.text)
        };
        for ch in display_name.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch).set_style(name_style);
                }
                x += w as u16;
            }
        }

        // Vulnerability indicator
        let vuln_style = if is_selected {
            Style::default().fg(scheme.error).bg(scheme.selection).bold()
        } else {
            Style::default().fg(scheme.error).bold()
        };
        for ch in vuln_indicator.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch).set_style(vuln_style);
                }
                x += w as u16;
            }
        }

        // Fill rest if selected
        if is_selected {
            while x < inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_style(Style::default().bg(scheme.selection));
                }
                x += 1;
            }
        }
    }

    // Render scrollbar if needed
    if flat_nodes.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.primary))
            .track_style(Style::default().fg(scheme.muted));
        let mut scrollbar_state = ScrollbarState::new(flat_nodes.len()).position(selected);
        frame.render_stateful_widget(scrollbar, inner_area, &mut scrollbar_state);
    }
}

fn flatten_dependency_tree(deps: &DependencyGraph, expanded: &HashSet<String>) -> Vec<FlatDepNode> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();

    for (i, root_id) in deps.roots.iter().enumerate() {
        let is_last = i == deps.roots.len() - 1;
        flatten_node(
            root_id,
            deps,
            expanded,
            0,
            is_last,
            &mut result,
            &mut visited,
            &[],
        );
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn flatten_node(
    node_id: &str,
    deps: &DependencyGraph,
    expanded: &HashSet<String>,
    depth: usize,
    is_last: bool,
    result: &mut Vec<FlatDepNode>,
    visited: &mut HashSet<String>,
    ancestors_last: &[bool],
) {
    if visited.contains(node_id) || depth > 20 {
        return;
    }
    visited.insert(node_id.to_string());

    let name = deps
        .names
        .get(node_id)
        .cloned()
        .unwrap_or_else(|| node_id.to_string());
    let has_children = deps
        .edges
        .get(node_id)
        .is_some_and(|c| !c.is_empty());
    let is_expanded = expanded.contains(node_id);
    let vuln_count = deps.vuln_counts.get(node_id).copied().unwrap_or(0);

    let mut current_ancestors = ancestors_last.to_vec();
    current_ancestors.push(is_last);

    result.push(FlatDepNode {
        id: node_id.to_string(),
        name,
        depth,
        is_last,
        has_children,
        is_expanded,
        vuln_count,
        ancestors_last: current_ancestors.clone(),
    });

    if is_expanded {
        if let Some(children) = deps.edges.get(node_id) {
            for (i, child_id) in children.iter().enumerate() {
                let child_is_last = i == children.len() - 1;
                flatten_node(
                    child_id,
                    deps,
                    expanded,
                    depth + 1,
                    child_is_last,
                    result,
                    visited,
                    &current_ancestors,
                );
            }
        }
    }

    visited.remove(node_id);
}

fn render_dependency_stats(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    deps: &DependencyGraph,
) {
    let scheme = colors();

    let mut lines = vec![];

    // Summary stats
    lines.push(Line::styled(
        "Dependency Statistics",
        Style::default().fg(scheme.primary).bold(),
    ));
    lines.push(Line::from(""));

    let total_components = deps.names.len();
    let total_edges = deps.edges.values().map(std::vec::Vec::len).sum::<usize>();
    let root_count = deps.roots.len();

    lines.push(Line::from(vec![
        Span::styled("Total Components: ", Style::default().fg(scheme.muted)),
        Span::styled(
            total_components.to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("Dependency Edges: ", Style::default().fg(scheme.muted)),
        Span::styled(
            total_edges.to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("Root Components:  ", Style::default().fg(scheme.muted)),
        Span::styled(
            root_count.to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    let max_depth = calculate_max_depth(deps);
    lines.push(Line::from(vec![
        Span::styled("Maximum Depth:    ", Style::default().fg(scheme.muted)),
        Span::styled(
            max_depth.to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Navigation",
        Style::default().fg(scheme.primary).bold(),
    ));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "↑/↓ or j/k  Navigate",
        Style::default().fg(scheme.muted),
    ));
    lines.push(Line::styled(
        "Enter/→/l   Expand node",
        Style::default().fg(scheme.muted),
    ));
    lines.push(Line::styled(
        "←/h         Collapse node",
        Style::default().fg(scheme.muted),
    ));

    // Show selected node info
    if let Some(node_id) = app.get_selected_dependency_node_id() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Selected Node",
            Style::default().fg(scheme.accent).bold(),
        ));
        lines.push(Line::from(""));

        if let Some(name) = deps.names.get(&node_id) {
            lines.push(Line::from(vec![
                Span::styled("Name: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    truncate_str(name, area.width as usize - 10),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }

        if let Some(children) = deps.edges.get(&node_id) {
            lines.push(Line::from(vec![
                Span::styled("Dependencies: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    children.len().to_string(),
                    Style::default().fg(scheme.primary),
                ),
            ]));
        }

        if let Some(vuln_count) = deps.vuln_counts.get(&node_id) {
            if *vuln_count > 0 {
                lines.push(Line::from(vec![
                    Span::styled("Vulnerabilities: ", Style::default().fg(scheme.muted)),
                    Span::styled(
                        vuln_count.to_string(),
                        Style::default().fg(scheme.error).bold(),
                    ),
                ]));
            }
        }
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Stats & Info ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(para, area);
}

struct DependencyGraph {
    /// Node ID -> display name
    names: HashMap<String, String>,
    /// Node ID -> list of child IDs
    edges: HashMap<String, Vec<String>>,
    /// Root nodes (no incoming edges)
    roots: Vec<String>,
    /// Node ID -> vulnerability count
    vuln_counts: HashMap<String, usize>,
}

fn build_dependency_graph(app: &mut ViewApp) -> DependencyGraph {
    let mut names: HashMap<String, String> = HashMap::new();
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut has_parent: HashSet<String> = HashSet::new();
    let mut vuln_counts: HashMap<String, usize> = HashMap::new();

    // Build name mapping and vuln counts
    for (id, comp) in &app.sbom.components {
        let id_str = id.value().to_string();
        let display_name = comp.version.as_ref().map_or_else(|| comp.name.clone(), |v| format!("{}@{}", comp.name, v));
        names.insert(id_str.clone(), display_name);
        vuln_counts.insert(id_str, comp.vulnerabilities.len());
    }

    // Build edges from dependency edges in the SBOM
    for edge in &app.sbom.edges {
        let from_str = edge.from.value().to_string();
        let to_str = edge.to.value().to_string();

        // Only add edge if both nodes exist in our names map
        if names.contains_key(&from_str) && names.contains_key(&to_str) {
            edges.entry(from_str).or_default().push(to_str.clone());
            has_parent.insert(to_str);
        }
    }

    // Find roots (components with no incoming edges), sorted for stable ordering
    let mut roots: Vec<_> = names
        .keys()
        .filter(|id| !has_parent.contains(*id))
        .cloned()
        .collect();
    roots.sort();

    DependencyGraph {
        names,
        edges,
        roots,
        vuln_counts,
    }
}

fn calculate_max_depth(deps: &DependencyGraph) -> usize {
    let mut max_depth = 0;

    fn depth_of(node: &str, deps: &DependencyGraph, visited: &mut HashSet<String>) -> usize {
        if visited.contains(node) {
            return 0;
        }
        visited.insert(node.to_string());

        let child_depth = deps.edges.get(node).map_or(0, |children| {
            children
                .iter()
                .map(|c| depth_of(c, deps, visited))
                .max()
                .unwrap_or(0)
        });

        visited.remove(node);
        child_depth + 1
    }

    for root in &deps.roots {
        let d = depth_of(root, deps, &mut HashSet::new());
        max_depth = max_depth.max(d);
    }

    max_depth
}
