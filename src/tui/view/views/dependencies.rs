//! Dependencies view for `ViewApp`.

use crate::model::DependencyType;
use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, ViewApp};
use crate::tui::view::severity::severity_category;
use crate::tui::widgets::{self, SeverityBadge, extract_display_name, truncate_str};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::collections::{HashMap, HashSet};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Format a number with thousands separators (e.g., 3354 -> "3,354").
fn format_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Render a horizontal section separator line.
fn push_separator(lines: &mut Vec<Line>, width: usize, color: Color) {
    let sep = "─".repeat(width.saturating_sub(4));
    lines.push(Line::styled(sep, Style::default().fg(color)));
}

pub fn render_dependencies(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Build the dependency graph once on first render and cache it. `app.sbom`
    // is immutable during view mode, so the graph never needs invalidation.
    if app.dependency_state.cached_graph.is_none() {
        let graph = build_dependency_graph(app);
        app.dependency_state.cached_graph = Some(graph);
    }
    let deps = app
        .dependency_state
        .cached_graph
        .take()
        .expect("graph cached above");

    // Auto-expand root nodes on first visit
    if !deps.roots.is_empty() && !app.dependency_state.roots_initialized {
        app.dependency_state.roots_initialized = true;
        for root in &deps.roots {
            app.dependency_state.expanded.insert(root.clone());
        }
    }

    render_dependency_tree(frame, chunks[0], app, &deps);
    render_dependency_stats(frame, chunks[1], app, &deps);

    app.dependency_state.cached_graph = Some(deps);
}

/// A flattened dependency node for rendering.
#[derive(Debug, Clone)]
pub struct FlatDepNode {
    pub id: String,
    pub name: String,
    pub depth: usize,
    pub is_last: bool,
    pub has_children: bool,
    pub is_expanded: bool,
    pub vuln_count: usize,
    pub max_severity: Option<String>,
    pub relationship: Option<DependencyType>,
    pub ancestors_last: Vec<bool>,
}

fn render_dependency_tree(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    deps: &DependencyGraph,
) {
    let scheme = colors();

    // Split into filter bar + tree
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(5)])
        .split(area);

    // Flatten the tree based on expanded state — cached, only rebuilt when expanded set changes
    if !app.dependency_state.are_flat_nodes_valid() {
        let flat_nodes = flatten_dependency_tree(deps, &app.dependency_state.expanded);
        app.dependency_state.set_cached_flat_nodes(flat_nodes);
    }

    // Count search matches — cached, only recomputed when query changes
    let match_count = app.dependency_state.get_search_match_count();
    let search_query = app.dependency_state.search_query.clone();

    // Render filter bar
    render_filter_bar(frame, chunks[0], app, match_count);

    // Update the total count for navigation bounds
    let node_count = app.dependency_state.cached_flat_nodes.len();
    app.dependency_state.total = node_count;
    app.dependency_state.clamp_selection();

    let title = if !search_query.is_empty() {
        let filtered = match_count.unwrap_or(0);
        format!(" Dependency Tree ({filtered}/{node_count} nodes) ")
    } else {
        format!(" Dependency Tree ({node_count} nodes) ")
    };

    // P6: Focused panel border highlighting
    let tree_border_color = if app.focus_panel == FocusPanel::Left {
        scheme.border_focused
    } else {
        scheme.border
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(tree_border_color));
    let inner_area = block.inner(chunks[1]);
    frame.render_widget(block, chunks[1]);

    // Clear the inner area to prevent glitchy rendering
    for y in inner_area.y..inner_area.y + inner_area.height {
        for x in inner_area.x..inner_area.x + inner_area.width {
            if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                cell.reset();
            }
        }
    }

    let flat_nodes = &app.dependency_state.cached_flat_nodes;

    if flat_nodes.is_empty() {
        widgets::render_empty_state_enhanced(
            frame,
            inner_area,
            "--",
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
    let search_lower = search_query.to_lowercase();

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
            if node.is_last { "└─ " } else { "├─ " }
        } else {
            ""
        };

        // P8: Expand/collapse indicator — leaves get empty space instead of ambiguous dash
        let expand_char = if node.has_children {
            if node.is_expanded { "▼ " } else { "▶ " }
        } else {
            "· "
        };

        // Relationship tag
        let rel_tag = node.relationship.as_ref().map_or("", |r| dependency_tag(r));

        // Severity badge indicator (replaces old ⚠ indicator)
        let (badge_text, badge_width) = if node.vuln_count > 0 {
            let sev = node.max_severity.as_deref().unwrap_or("low");
            let indicator = SeverityBadge::indicator(sev);
            let text = format!(" [{indicator}]{}", node.vuln_count);
            let w = UnicodeWidthStr::width(text.as_str());
            (Some((text, sev.to_string())), w)
        } else {
            (None, 0)
        };

        // Calculate available width for name using display width
        let used_width = 2
            + UnicodeWidthStr::width(prefix.as_str())
            + UnicodeWidthStr::width(branch)
            + UnicodeWidthStr::width(expand_char)
            + UnicodeWidthStr::width(rel_tag)
            + badge_width;
        let name_max = max_width.saturating_sub(used_width);
        let display_name = truncate_str(&node.name, name_max);

        // Check if name matches search
        let is_search_match =
            !search_lower.is_empty() && node.name.to_lowercase().contains(&search_lower);

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

        // P2: Brighter tree structure lines (text_muted instead of muted/DarkGray)
        let tree_line_color = scheme.text_muted;
        for ch in prefix.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(1);
            if x + w as u16 <= inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(tree_line_color));
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
                        .set_style(Style::default().fg(tree_line_color));
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

        // P1: Depth-based color gradient for node names. Depth 2+ merges into
        // text_muted: a dedicated light-gray RGB step was near-invisible on
        // the light theme's background (matches widgets/tree.rs).
        let depth_color = match node.depth {
            0 | 1 => scheme.text,   // Root and direct deps
            _ => scheme.text_muted, // Depth 2+: muted
        };
        let name_style = if is_selected {
            Style::default().bg(scheme.selection).fg(scheme.text).bold()
        } else if is_search_match {
            Style::default().fg(scheme.accent).bold()
        } else if node.depth == 0 {
            Style::default().fg(depth_color).bold()
        } else {
            Style::default().fg(depth_color)
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

        // Relationship tag
        if !rel_tag.is_empty() {
            let tag_style = if is_selected {
                Style::default().fg(scheme.info).bg(scheme.selection)
            } else {
                Style::default().fg(scheme.info)
            };
            for ch in rel_tag.chars() {
                let w = UnicodeWidthChar::width(ch).unwrap_or(1);
                if x + w as u16 <= inner_area.x + inner_area.width {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_char(ch).set_style(tag_style);
                    }
                    x += w as u16;
                }
            }
        }

        // Severity badge (colored [C]3 / [H]2 / [M]1 / [L]1 style)
        if let Some((ref badge, ref sev)) = badge_text {
            let sev_color = SeverityBadge::fg_color(sev);
            let indicator = SeverityBadge::indicator(sev);
            // Space before badge
            if x < inner_area.x + inner_area.width {
                if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                    cell.set_char(' ');
                    if is_selected {
                        cell.set_style(Style::default().bg(scheme.selection));
                    }
                }
                x += 1;
            }
            // [X] badge with severity background
            let badge_chars = format!("[{indicator}]");
            let badge_style = Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(sev_color)
                .bold();
            for ch in badge_chars.chars() {
                let w = UnicodeWidthChar::width(ch).unwrap_or(1);
                if x + w as u16 <= inner_area.x + inner_area.width {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_char(ch).set_style(badge_style);
                    }
                    x += w as u16;
                }
            }
            // Count in severity color
            let count_str = node.vuln_count.to_string();
            let count_style = if is_selected {
                Style::default().fg(sev_color).bg(scheme.selection).bold()
            } else {
                Style::default().fg(sev_color).bold()
            };
            for ch in count_str.chars() {
                let w = UnicodeWidthChar::width(ch).unwrap_or(1);
                if x + w as u16 <= inner_area.x + inner_area.width {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_char(ch).set_style(count_style);
                    }
                    x += w as u16;
                }
            }
            // Suppress unused variable warning - badge_text used for width calculation
            let _ = badge;
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
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));
        let mut scrollbar_state = ScrollbarState::new(flat_nodes.len()).position(selected);
        frame.render_stateful_widget(scrollbar, inner_area, &mut scrollbar_state);
    }
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &ViewApp, match_count: Option<usize>) {
    let scheme = colors();

    if app.dependency_state.search_active {
        let cursor = if app.tick % 10 < 5 { "▌" } else { " " };
        let mut spans = vec![
            Span::styled("Search: ", Style::default().fg(scheme.accent).bold()),
            Span::styled(
                format!("{}{cursor}", app.dependency_state.search_query),
                Style::default().fg(scheme.text).bg(scheme.selection),
            ),
        ];
        if let Some(count) = match_count {
            spans.push(Span::styled(
                format!(" ({count})"),
                Style::default().fg(scheme.text_muted),
            ));
        }
        spans.extend([
            Span::raw("  "),
            Span::styled("[Esc]", Style::default().fg(scheme.text_muted)),
            Span::styled(" cancel  ", Style::default().fg(scheme.text_muted)),
            Span::styled("[Enter]", Style::default().fg(scheme.text_muted)),
            Span::styled(" done", Style::default().fg(scheme.text_muted)),
        ]);
        let para = Paragraph::new(Line::from(spans));
        frame.render_widget(para, area);
        return;
    }

    let mut spans = Vec::new();

    // Show search query if present
    if !app.dependency_state.search_query.is_empty() {
        spans.push(Span::styled(
            "Search: ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled(
            format!("\"{}\"", app.dependency_state.search_query),
            Style::default().fg(scheme.info),
        ));
        if let Some(count) = match_count {
            spans.push(Span::styled(
                format!(" ({count})"),
                Style::default().fg(scheme.text_muted),
            ));
        }
        spans.push(Span::raw("  │  "));
    }

    // Expand/collapse-all live on x/X ('e' is export, app-wide). Hints are
    // fitted whole to the panel width so none is clipped mid-token by the
    // adjacent Stats panel.
    super::push_fitted_hints(
        &mut spans,
        &[
            ("[/]", "search"),
            ("[x]", "expand all"),
            ("[X]", "collapse all"),
            ("[c]", "component"),
            ("[p]", "panel"),
            ("[J/K]", "scroll"),
        ],
        area.width as usize,
    );

    let para = Paragraph::new(Line::from(spans));
    frame.render_widget(para, area);
}

fn flatten_dependency_tree(deps: &DependencyGraph, expanded: &HashSet<String>) -> Vec<FlatDepNode> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();

    for (i, root_id) in deps.roots.iter().enumerate() {
        let is_last = i == deps.roots.len() - 1;
        flatten_node(
            root_id,
            None, // roots have no parent
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
    parent_id: Option<&str>,
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
    let has_children = deps.edges.get(node_id).is_some_and(|c| !c.is_empty());
    let is_expanded = expanded.contains(node_id);
    let vuln_count = deps.vuln_counts.get(node_id).copied().unwrap_or(0);
    let max_severity = deps.max_severities.get(node_id).cloned();
    let relationship = parent_id.and_then(|pid| {
        deps.relationships
            .get(&(pid.to_string(), node_id.to_string()))
            .cloned()
    });

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
        max_severity,
        relationship,
        ancestors_last: current_ancestors.clone(),
    });

    if is_expanded && let Some(children) = deps.edges.get(node_id) {
        for (i, child_id) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            flatten_node(
                child_id,
                Some(node_id),
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

    visited.remove(node_id);
}

/// Calculate how many list items can fit in the remaining detail panel space.
/// `area_height` is the total panel height, `used_lines` is how many lines are already used,
/// `reserved` is extra lines to keep for following sections.
fn available_detail_slots(area_height: u16, used_lines: usize, reserved: usize) -> usize {
    let total = area_height as usize;
    // Leave room for border (2) + reserved lines
    total
        .saturating_sub(used_lines)
        .saturating_sub(reserved + 2)
        .max(3) // always show at least 3
}

/// Short badge for component type.
fn component_type_badge(ct: &crate::model::ComponentType) -> (&'static str, Color) {
    use crate::model::ComponentType;
    let scheme = colors();
    match ct {
        ComponentType::Application => ("APP", scheme.accent),
        ComponentType::Framework => ("FW", scheme.info),
        ComponentType::Library => ("LIB", scheme.primary),
        ComponentType::Container => ("CTR", scheme.secondary),
        ComponentType::OperatingSystem => ("OS", scheme.warning),
        ComponentType::Device => ("DEV", scheme.text_muted),
        // Distinct from Framework's "FW" so the two are unambiguous when the
        // badge color is hard to read.
        ComponentType::Firmware => ("FRMW", scheme.warning),
        ComponentType::File => ("FILE", scheme.text_muted),
        ComponentType::Data => ("DATA", scheme.text_muted),
        ComponentType::MachineLearningModel => ("ML", scheme.info),
        ComponentType::Platform => ("PLAT", scheme.secondary),
        ComponentType::DeviceDriver => ("DRV", scheme.text_muted),
        ComponentType::Cryptographic => ("CRYPT", scheme.accent),
        ComponentType::Other(_) => ("OTHER", scheme.text_muted),
    }
}

fn render_dependency_stats(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    deps: &DependencyGraph,
) {
    let scheme = colors();
    let sep_width = area.width.saturating_sub(4) as usize;

    let mut lines = vec![];

    // Compact single-line stats
    let total_components = deps.names.len();
    let total_edges: usize = deps.edges.values().map(Vec::len).sum();
    let root_count = deps.roots.len();
    let max_depth = deps.max_depth;

    lines.push(Line::from(vec![
        Span::styled("Components: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format_thousands(total_components),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled("  Edges: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format_thousands(total_edges),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled("  Roots: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format_thousands(root_count),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled("  Depth: ", Style::default().fg(scheme.muted)),
        Span::styled(
            // calculate_max_depth counts NODES (root chain = 1); the per-node
            // "Depth:" field below is 0-based (roots = 0). Convert so the two
            // depths on this panel share one convention.
            max_depth.saturating_sub(1).to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));

    // Relationship counts
    let mut rel_counts: HashMap<&str, usize> = HashMap::new();
    for edge in &app.sbom.edges {
        let tag = dependency_tag(&edge.relationship).trim();
        let label = if tag.is_empty() { "depends-on" } else { tag };
        *rel_counts.entry(label).or_insert(0) += 1;
    }

    if !rel_counts.is_empty() {
        if rel_counts.len() == 1 {
            let (label, count) = rel_counts.iter().next().expect("checked non-empty");
            lines.push(Line::from(vec![
                Span::styled("Relationships: ", Style::default().fg(scheme.info).bold()),
                Span::styled(
                    format!("{} {label}", format_thousands(*count)),
                    Style::default().fg(scheme.text),
                ),
            ]));
        } else {
            // Multiple types — show bar chart
            let bar_width = (area.width.saturating_sub(4) as usize)
                .saturating_sub(20)
                .min(30);
            lines.push(Line::styled(
                "Relationship Types:",
                Style::default().fg(scheme.info).bold(),
            ));

            let max_rel_count = rel_counts.values().copied().max().unwrap_or(1);
            let mut rel_entries: Vec<_> = rel_counts.iter().collect();
            rel_entries.sort_by(|a, b| b.1.cmp(a.1));

            for (label, count) in &rel_entries {
                let count = **count;
                let bar_len = (count * bar_width).checked_div(max_rel_count).unwrap_or(0);
                let bar = "█".repeat(bar_len);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {label:12}"), Style::default().fg(scheme.info)),
                    Span::styled(
                        format!("{:>5} ", format_thousands(count)),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(bar, Style::default().fg(scheme.info)),
                ]));
            }
        }
    }

    // Vulnerability severity bar chart with percentage headline
    let bar_width = (area.width.saturating_sub(4) as usize)
        .saturating_sub(22)
        .min(30);

    let mut vuln_severity_counts: HashMap<&str, usize> = HashMap::new();
    vuln_severity_counts.insert("critical", 0);
    vuln_severity_counts.insert("high", 0);
    vuln_severity_counts.insert("medium", 0);
    vuln_severity_counts.insert("low", 0);
    vuln_severity_counts.insert("clean", 0);

    for (node_id, &count) in &deps.vuln_counts {
        if count > 0 {
            let category = deps
                .max_severities
                .get(node_id)
                .map_or("low", |s| s.as_str());
            *vuln_severity_counts.entry(category).or_insert(0) += 1;
        } else {
            *vuln_severity_counts.entry("clean").or_insert(0) += 1;
        }
    }

    let affected: usize = vuln_severity_counts
        .iter()
        .filter(|(k, _)| **k != "clean")
        .map(|(_, &v)| v)
        .sum();
    let has_vulns = affected > 0;

    if has_vulns {
        lines.push(Line::from(""));

        // Percentage affected headline
        let pct = if total_components > 0 {
            (affected as f64 / total_components as f64) * 100.0
        } else {
            0.0
        };
        lines.push(Line::from(vec![
            Span::styled(
                "Vulnerabilities:  ",
                Style::default().fg(scheme.critical).bold(),
            ),
            Span::styled(
                format!("{pct:.1}% affected"),
                Style::default().fg(scheme.warning).bold(),
            ),
        ]));

        let vuln_order = [
            ("critical", "Critical", scheme.critical, "C"),
            ("high", "High", scheme.high, "H"),
            ("medium", "Medium", scheme.warning, "M"),
            ("low", "Low", scheme.low, "L"),
            ("clean", "Clean", scheme.success, "\u{2713}"),
        ];

        let max_vuln_count = vuln_severity_counts.values().copied().max().unwrap_or(1);
        for (key, label, color, badge) in &vuln_order {
            let count = vuln_severity_counts.get(key).copied().unwrap_or(0);
            if count == 0 && *key != "clean" {
                continue;
            }
            let bar_len = (count * bar_width)
                .checked_div(max_vuln_count)
                .unwrap_or(0)
                .max(usize::from(count > 0)); // at least 1 char if non-zero
            let bar = "█".repeat(bar_len);

            let badge_style = Style::default().fg(scheme.badge_fg_dark).bg(*color).bold();
            lines.push(Line::from(vec![
                Span::styled(format!(" [{badge}]"), badge_style),
                Span::styled(format!(" {label:8}"), Style::default().fg(*color)),
                Span::styled(
                    format!("{:>5} ", format_thousands(count)),
                    Style::default().fg(scheme.text),
                ),
                Span::styled(bar, Style::default().fg(*color)),
            ]));
        }
    }

    // Separator before selected node
    push_separator(&mut lines, sep_width, scheme.border);

    // Selected Node details
    if let Some(node_id) = app.get_selected_dependency_node_id() {
        // Get depth from cached flat nodes
        let node_depth = app
            .dependency_state
            .cached_flat_nodes
            .get(app.dependency_state.selected)
            .map(|n| n.depth);

        // Look up component in SBOM for rich details
        let component = app.sbom.components.iter().find_map(|(id, comp)| {
            if id.value() == node_id {
                Some(comp)
            } else {
                None
            }
        });

        let dep_count = deps.edges.get(&node_id).map_or(0, Vec::len);
        let depended_on_count = deps.reverse_edges.get(&node_id).map_or(0, Vec::len);
        let is_root = depended_on_count == 0;

        if let Some(comp) = component {
            // Line 1: Display name + [TYPE] badge + Root badge
            let display_name = deps
                .names
                .get(&node_id)
                .cloned()
                .unwrap_or_else(|| node_id.clone());
            // Strip version from display name for cleaner title
            let clean_title = display_name
                .rsplit_once('@')
                .map_or(display_name.clone(), |(name, _)| name.to_string());
            let (type_tag, type_color) = component_type_badge(&comp.component_type);

            let mut title_spans = vec![
                Span::styled(clean_title, Style::default().fg(scheme.text).bold()),
                Span::raw("  "),
                Span::styled(
                    format!("[{type_tag}]"),
                    Style::default()
                        .fg(scheme.badge_fg_dark)
                        .bg(type_color)
                        .bold(),
                ),
            ];
            if is_root {
                title_spans.push(Span::raw("  "));
                title_spans.push(Span::styled(
                    "Root",
                    Style::default().fg(scheme.accent).bold(),
                ));
            }
            lines.push(Line::from(title_spans));

            // Line 2: Version | Supplier | License (compact metadata line)
            let mut meta_spans: Vec<Span<'_>> = Vec::new();
            if let Some(ref ver) = comp.version {
                meta_spans.push(Span::styled(ver.as_str(), Style::default().fg(scheme.text)));
            }
            if let Some(ref supplier) = comp.supplier
                && !supplier.name.is_empty()
            {
                if !meta_spans.is_empty() {
                    meta_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                }
                meta_spans.push(Span::styled(
                    &supplier.name,
                    Style::default().fg(scheme.info),
                ));
            }
            if !comp.licenses.declared.is_empty() {
                if !meta_spans.is_empty() {
                    meta_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                }
                let license_text = comp
                    .licenses
                    .declared
                    .iter()
                    .take(2)
                    .map(|l| l.expression.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                meta_spans.push(Span::styled(license_text, Style::default().fg(scheme.text)));
                if comp.licenses.declared.len() > 2 {
                    meta_spans.push(Span::styled(
                        format!(" +{}", comp.licenses.declared.len() - 2),
                        Style::default().fg(scheme.muted),
                    ));
                }
            }
            if !meta_spans.is_empty() {
                lines.push(Line::from(meta_spans));
            }

            // Line 3: Dependencies count | Depth | Used by
            let mut dep_spans = vec![
                Span::styled("Dependencies: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format_thousands(dep_count),
                    Style::default().fg(scheme.primary),
                ),
            ];
            if let Some(depth) = node_depth {
                dep_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                dep_spans.push(Span::styled("Depth: ", Style::default().fg(scheme.muted)));
                dep_spans.push(Span::styled(
                    depth.to_string(),
                    Style::default().fg(scheme.text),
                ));
            }
            if !is_root {
                dep_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                dep_spans.push(Span::styled("Used by: ", Style::default().fg(scheme.muted)));
                dep_spans.push(Span::styled(
                    format_thousands(depended_on_count),
                    Style::default().fg(scheme.primary),
                ));
            }
            lines.push(Line::from(dep_spans));

            // Line 4: Hash (best available, truncated)
            if let Some(hash) = comp.hashes.first() {
                let hash_display = if hash.value.len() > 16 {
                    format!(
                        "{}...{}",
                        &hash.value[..8],
                        &hash.value[hash.value.len() - 8..]
                    )
                } else {
                    hash.value.clone()
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{}: ", hash.algorithm),
                        Style::default().fg(scheme.muted),
                    ),
                    Span::styled(hash_display, Style::default().fg(scheme.text_muted)),
                ]));
            }

            // Vulnerability list with CVE details
            if !comp.vulnerabilities.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::styled(
                    format!("Vulnerabilities ({}):", comp.vulnerabilities.len()),
                    Style::default().fg(scheme.error).bold(),
                ));
                let max_vulns = available_detail_slots(area.height, lines.len(), 8);
                for vuln in comp.vulnerabilities.iter().take(max_vulns) {
                    let sev_str = vuln.severity.as_ref().map_or("unknown", |s| match s {
                        crate::model::Severity::Critical => "critical",
                        crate::model::Severity::High => "high",
                        crate::model::Severity::Medium => "medium",
                        crate::model::Severity::Low => "low",
                        _ => "info",
                    });
                    let sev_color = SeverityBadge::fg_color(sev_str);
                    let indicator = SeverityBadge::indicator(sev_str);
                    let mut spans = vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(&vuln.id, Style::default().fg(scheme.text)),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{indicator}]"),
                            Style::default()
                                .fg(scheme.badge_fg_dark)
                                .bg(sev_color)
                                .bold(),
                        ),
                    ];
                    if let Some(cvss) = vuln.cvss.first() {
                        spans.push(Span::styled(
                            format!(" ({:.1})", cvss.base_score),
                            Style::default().fg(sev_color),
                        ));
                    }
                    // Truncated description
                    if let Some(ref desc) = vuln.description
                        && !desc.is_empty()
                    {
                        let max_desc = (area.width as usize).saturating_sub(30);
                        let short = truncate_str(desc, max_desc);
                        spans.push(Span::styled(
                            format!("  {short}"),
                            Style::default().fg(scheme.text_muted),
                        ));
                    }
                    lines.push(Line::from(spans));
                }
                if comp.vulnerabilities.len() > max_vulns {
                    lines.push(Line::styled(
                        format!("  ... and {} more", comp.vulnerabilities.len() - max_vulns),
                        Style::default().fg(scheme.muted),
                    ));
                }
            }

            // PURL (if different from node_id)
            if let Some(ref purl) = comp.identifiers.purl
                && purl != &node_id
            {
                lines.push(Line::from(vec![
                    Span::styled("PURL: ", Style::default().fg(scheme.muted)),
                    Span::styled(purl, Style::default().fg(scheme.accent)),
                ]));
            }
        } else {
            // No component found — show basic info
            if let Some(name) = deps.names.get(&node_id) {
                lines.push(Line::styled(name, Style::default().fg(scheme.text).bold()));
            }

            let mut dep_spans = vec![
                Span::styled("Dependencies: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format_thousands(dep_count),
                    Style::default().fg(scheme.primary),
                ),
            ];
            if is_root {
                dep_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                dep_spans.push(Span::styled(
                    "Root",
                    Style::default().fg(scheme.accent).bold(),
                ));
            } else {
                dep_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
                dep_spans.push(Span::styled("Used by: ", Style::default().fg(scheme.muted)));
                dep_spans.push(Span::styled(
                    format_thousands(depended_on_count),
                    Style::default().fg(scheme.primary),
                ));
            }
            lines.push(Line::from(dep_spans));
        }

        // Determine which list to show scrollable: the larger one gets scroll,
        // the smaller one gets a compact count-only line
        let parents = deps.reverse_edges.get(&node_id);
        let children = deps.edges.get(&node_id);
        let parent_count = parents.map_or(0, Vec::len);
        let child_count = children.map_or(0, Vec::len);
        let scroll_parents = parent_count > 0 && parent_count >= child_count;

        if scroll_parents {
            // Parents get scrollable list, deps get compact line
            if child_count > 0 {
                // Don't repeat if already shown in the stats line above
            }

            if let Some(parents) = parents {
                lines.push(Line::from(""));

                let inner_height = area.height.saturating_sub(2) as usize;
                let header_lines = lines.len() + 1;
                let visible_slots = inner_height.saturating_sub(header_lines).max(3);

                let dep_scroll = app.dependency_state.detail_scroll as usize;
                let total = parents.len();
                let effective_scroll = dep_scroll.min(total.saturating_sub(visible_slots));

                let pos_end = (effective_scroll + visible_slots).min(total);
                let pos_indicator = if total > visible_slots {
                    format!(
                        "  {}-{}/{}",
                        effective_scroll + 1,
                        pos_end,
                        format_thousands(total)
                    )
                } else {
                    String::new()
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("Used by ({}):", format_thousands(total)),
                        Style::default().fg(scheme.secondary).bold(),
                    ),
                    Span::styled(pos_indicator, Style::default().fg(scheme.text_muted)),
                ]));

                for parent_id in parents.iter().skip(effective_scroll).take(visible_slots) {
                    let parent_name = deps
                        .names
                        .get(parent_id)
                        .map_or(parent_id.as_str(), String::as_str);
                    lines.push(Line::from(vec![
                        Span::styled("  \u{2190} ", Style::default().fg(scheme.muted)),
                        Span::styled(parent_name, Style::default().fg(scheme.text)),
                    ]));
                }
            }
        } else {
            // Deps get scrollable list, parents get compact line
            if parent_count > 0 {
                lines.push(Line::from(""));
                // Compact parent summary — show first few inline
                if let Some(parents) = parents {
                    let preview: Vec<&str> = parents
                        .iter()
                        .take(3)
                        .map(|id| deps.names.get(id).map_or(id.as_str(), String::as_str))
                        .collect();
                    let mut spans = vec![
                        Span::styled(
                            format!("Used by ({}):", format_thousands(parent_count)),
                            Style::default().fg(scheme.secondary).bold(),
                        ),
                        Span::styled(
                            format!(" {}", preview.join(", ")),
                            Style::default().fg(scheme.text_muted),
                        ),
                    ];
                    if parent_count > 3 {
                        spans.push(Span::styled(
                            format!(" +{}", parent_count - 3),
                            Style::default().fg(scheme.muted),
                        ));
                    }
                    lines.push(Line::from(spans));
                }
            }

            if let Some(children) = children
                && !children.is_empty()
            {
                lines.push(Line::from(""));

                let inner_height = area.height.saturating_sub(2) as usize;
                let header_lines = lines.len() + 1;
                let visible_slots = inner_height.saturating_sub(header_lines).max(3);

                let dep_scroll = app.dependency_state.detail_scroll as usize;
                let total_deps = children.len();
                let effective_scroll = dep_scroll.min(total_deps.saturating_sub(visible_slots));

                let pos_end = (effective_scroll + visible_slots).min(total_deps);
                let pos_indicator = if total_deps > visible_slots {
                    format!(
                        "  {}-{}/{}",
                        effective_scroll + 1,
                        pos_end,
                        format_thousands(total_deps)
                    )
                } else {
                    String::new()
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("Dependencies ({}):", format_thousands(total_deps)),
                        Style::default().fg(scheme.primary).bold(),
                    ),
                    Span::styled(pos_indicator, Style::default().fg(scheme.text_muted)),
                ]));

                for child_id in children.iter().skip(effective_scroll).take(visible_slots) {
                    let child_name = deps
                        .names
                        .get(child_id)
                        .map_or(child_id.as_str(), String::as_str);
                    let tag = deps
                        .relationships
                        .get(&(node_id.clone(), child_id.clone()))
                        .map(|r| dependency_tag(r))
                        .unwrap_or("");
                    let mut spans = vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(child_name, Style::default().fg(scheme.text)),
                    ];
                    let tag = tag.trim();
                    if !tag.is_empty() {
                        spans.push(Span::styled(
                            format!(" {tag}"),
                            Style::default().fg(scheme.info),
                        ));
                    }
                    lines.push(Line::from(spans));
                }
            }
        }
    } else {
        lines.push(Line::styled(
            "Select a node to view details",
            Style::default().fg(scheme.muted),
        ));
    }

    // Scrolling support
    let content_height = lines.len().min(u16::MAX as usize) as u16;
    // Focused panel border highlighting
    let detail_border_color = if app.focus_panel == FocusPanel::Right {
        scheme.border_focused
    } else {
        scheme.border
    };
    let block = Block::default()
        .title(" Stats & Info ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(detail_border_color));
    let inner_height = block.inner(area).height;

    // Clamp scroll
    let max_scroll = content_height.saturating_sub(inner_height);
    if app.dependency_state.detail_scroll > max_scroll {
        app.dependency_state.detail_scroll = max_scroll;
    }

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: false })
        .scroll((app.dependency_state.detail_scroll, 0));

    frame.render_widget(para, area);

    // Render scrollbar on detail panel if content overflows
    if content_height > inner_height {
        let inner_area = Block::default().borders(Borders::ALL).inner(area);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.secondary))
            .track_style(Style::default().fg(scheme.muted));
        let mut scrollbar_state = ScrollbarState::new(content_height as usize)
            .position(app.dependency_state.detail_scroll as usize);
        frame.render_stateful_widget(scrollbar, inner_area, &mut scrollbar_state);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DependencyGraph {
    /// Node ID -> display name
    names: HashMap<String, String>,
    /// Node ID -> list of child IDs
    edges: HashMap<String, Vec<String>>,
    /// Root nodes (no incoming edges)
    roots: Vec<String>,
    /// Node ID -> vulnerability count
    vuln_counts: HashMap<String, usize>,
    /// Node ID -> max severity category string
    max_severities: HashMap<String, String>,
    /// (from_id, to_id) -> relationship type
    relationships: HashMap<(String, String), DependencyType>,
    /// Reverse edges: node ID -> list of parent IDs (pre-computed for O(1) "used by" lookup)
    reverse_edges: HashMap<String, Vec<String>>,
    /// Max depth of the dependency tree (pre-computed)
    max_depth: usize,
}

/// Sort component IDs by their display name (falling back to the raw ID when
/// unmapped), with the ID as tiebreaker for stability. Case-sensitive cmp,
/// matching the component tree's name ordering.
fn sort_ids_by_display_name(ids: &mut [String], names: &HashMap<String, String>) {
    ids.sort_by(|a, b| {
        let name_a = names.get(a).map_or(a.as_str(), String::as_str);
        let name_b = names.get(b).map_or(b.as_str(), String::as_str);
        name_a.cmp(name_b).then_with(|| a.cmp(b))
    });
}

fn build_dependency_graph(app: &ViewApp) -> DependencyGraph {
    let mut names: HashMap<String, String> = HashMap::new();
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut has_parent: HashSet<String> = HashSet::new();
    let mut vuln_counts: HashMap<String, usize> = HashMap::new();
    let mut max_severities: HashMap<String, String> = HashMap::new();
    let mut relationships: HashMap<(String, String), DependencyType> = HashMap::new();

    // Build name mapping, vuln counts, and max severities
    for (id, comp) in &app.sbom.components {
        let id_str = id.value().to_string();
        let clean_name = extract_display_name(&comp.name);
        let display_name = comp
            .version
            .as_ref()
            .map_or_else(|| clean_name.clone(), |v| format!("{clean_name}@{v}"));
        names.insert(id_str.clone(), display_name);
        vuln_counts.insert(id_str.clone(), comp.vulnerabilities.len());

        let category = severity_category(&comp.vulnerabilities);
        if category != "clean" {
            max_severities.insert(id_str, category.to_string());
        }
    }

    // Build edges from dependency edges in the SBOM
    for edge in &app.sbom.edges {
        let from_str = edge.from.value().to_string();
        let to_str = edge.to.value().to_string();

        // Only add edge if both nodes exist in our names map
        if names.contains_key(&from_str) && names.contains_key(&to_str) {
            edges
                .entry(from_str.clone())
                .or_default()
                .push(to_str.clone());
            has_parent.insert(to_str.clone());
            relationships.insert((from_str, to_str), edge.relationship.clone());
        }
    }

    // Sort edge children by the display name users actually see (raw
    // canonical-ID order looked arbitrary on screen), stable across renders.
    for children in edges.values_mut() {
        sort_ids_by_display_name(children, &names);
    }

    // Build reverse edges for O(1) "used by" lookups
    let mut reverse_edges: HashMap<String, Vec<String>> = HashMap::new();
    for (parent, children) in &edges {
        for child in children {
            reverse_edges
                .entry(child.clone())
                .or_default()
                .push(parent.clone());
        }
    }
    // Sort parent lists for stable display ordering
    for parents in reverse_edges.values_mut() {
        sort_ids_by_display_name(parents, &names);
    }

    // Find roots (components with no incoming edges), sorted for stable ordering
    let mut roots: Vec<_> = names
        .keys()
        .filter(|id| !has_parent.contains(*id))
        .cloned()
        .collect();
    sort_ids_by_display_name(&mut roots, &names);

    let mut graph = DependencyGraph {
        names,
        edges,
        roots,
        vuln_counts,
        max_severities,
        relationships,
        reverse_edges,
        max_depth: 0,
    };
    graph.max_depth = calculate_max_depth(&graph);
    graph
}

fn dependency_tag(rel: &DependencyType) -> &'static str {
    match rel {
        DependencyType::DevDependsOn => " dev",
        DependencyType::BuildDependsOn => " build",
        DependencyType::TestDependsOn => " test",
        DependencyType::OptionalDependsOn => " opt",
        DependencyType::ProvidedDependsOn => " provided",
        DependencyType::RuntimeDependsOn => " runtime",
        DependencyType::Contains => " contains",
        DependencyType::StaticLink => " static",
        DependencyType::DynamicLink => " dynamic",
        _ => "",
    }
}

/// Compute the longest dependency chain (in node count) using an iterative
/// Kahn topological pass with memoized per-node depth.
///
/// Nodes that remain with non-zero in-degree after the queue drains are members
/// of a cycle; they keep depth 0, matching the prior recursive semantics where a
/// back-edge into a node already on the path contributed 0. No recursion and no
/// path enumeration, so diamond-heavy DAGs and very deep chains stay linear.
fn calculate_max_depth(deps: &DependencyGraph) -> usize {
    // In-degree over the edges that actually exist between known nodes.
    let mut in_degree: HashMap<&str, usize> =
        deps.names.keys().map(|id| (id.as_str(), 0usize)).collect();
    for children in deps.edges.values() {
        for child in children {
            if let Some(d) = in_degree.get_mut(child.as_str()) {
                *d += 1;
            }
        }
    }

    // depth[node] = longest chain ending at this node, counted in nodes.
    let mut depth: HashMap<&str, usize> = HashMap::with_capacity(deps.names.len());
    let mut queue: std::collections::VecDeque<&str> = in_degree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut max_depth = 0;
    while let Some(node) = queue.pop_front() {
        let node_depth = *depth.entry(node).or_insert(1);
        max_depth = max_depth.max(node_depth);

        if let Some(children) = deps.edges.get(node) {
            for child in children {
                let child = child.as_str();
                let entry = depth.entry(child).or_insert(0);
                *entry = (*entry).max(node_depth + 1);
                if let Some(d) = in_degree.get_mut(child) {
                    *d -= 1;
                    if *d == 0 {
                        queue.push_back(child);
                    }
                }
            }
        }
    }

    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: dependency lists must order by the visible display name,
    /// not the raw canonical ID (SPDXRef IDs made the tree look unsorted).
    #[test]
    fn sort_ids_by_display_name_orders_by_visible_label() {
        let mut names = HashMap::new();
        names.insert("SPDXRef-2".to_string(), "alpha@1.0".to_string());
        names.insert("SPDXRef-1".to_string(), "zeta@2.0".to_string());

        let mut ids = vec!["SPDXRef-1".to_string(), "SPDXRef-2".to_string()];
        sort_ids_by_display_name(&mut ids, &names);
        assert_eq!(
            ids,
            ["SPDXRef-2", "SPDXRef-1"],
            "alpha sorts before zeta despite the reverse ID order"
        );

        // Tiebreak: identical display names fall back to ID order.
        names.insert("SPDXRef-3".to_string(), "alpha@1.0".to_string());
        let mut ids = vec!["SPDXRef-3".to_string(), "SPDXRef-2".to_string()];
        sort_ids_by_display_name(&mut ids, &names);
        assert_eq!(ids, ["SPDXRef-2", "SPDXRef-3"]);
    }

    /// Build a minimal graph from edges (parent -> children); roots are nodes
    /// with no incoming edge. Only the fields `calculate_max_depth` reads are
    /// populated.
    fn graph_from_edges(node_count: usize, edges: &[(usize, usize)]) -> DependencyGraph {
        let id = |n: usize| format!("n{n}");
        let mut names = HashMap::new();
        let mut edge_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut has_parent = HashSet::new();
        for n in 0..node_count {
            names.insert(id(n), id(n));
        }
        for &(from, to) in edges {
            edge_map.entry(id(from)).or_default().push(id(to));
            has_parent.insert(id(to));
        }
        let mut roots: Vec<String> = (0..node_count)
            .map(id)
            .filter(|n| !has_parent.contains(n))
            .collect();
        roots.sort();

        DependencyGraph {
            names,
            edges: edge_map,
            roots,
            vuln_counts: HashMap::new(),
            max_severities: HashMap::new(),
            relationships: HashMap::new(),
            reverse_edges: HashMap::new(),
            max_depth: 0,
        }
    }

    #[test]
    fn max_depth_simple_chain() {
        // n0 -> n1 -> n2 -> n3 : longest chain is 4 nodes.
        let graph = graph_from_edges(4, &[(0, 1), (1, 2), (2, 3)]);
        assert_eq!(calculate_max_depth(&graph), 4);
    }

    #[test]
    fn max_depth_single_node() {
        let graph = graph_from_edges(1, &[]);
        assert_eq!(calculate_max_depth(&graph), 1);
    }

    #[test]
    fn firmware_and_framework_have_distinct_badge_labels() {
        use crate::model::ComponentType;
        let (framework_label, _) = component_type_badge(&ComponentType::Framework);
        let (firmware_label, _) = component_type_badge(&ComponentType::Firmware);
        // The two used to collapse to the same "FW" label; they must now be
        // unambiguous even when badge color is hard to read.
        assert_ne!(
            framework_label, firmware_label,
            "Framework and Firmware must not share a badge label"
        );
        assert_eq!(framework_label, "FW");
        assert_eq!(firmware_label, "FRMW");
    }

    #[test]
    fn max_depth_cycle_members_contribute_zero() {
        // A pure cycle (no in-degree-0 node) has no topological order; every node
        // stays at depth 0.
        let graph = graph_from_edges(3, &[(0, 1), (1, 2), (2, 0)]);
        assert_eq!(calculate_max_depth(&graph), 0);

        // n0 feeds into a 2-node cycle (n1 <-> n2). Under Kahn, any node with an
        // incoming cycle edge keeps non-zero in-degree and never gets a depth, so
        // only the acyclic prefix n0 is counted.
        let graph = graph_from_edges(3, &[(0, 1), (1, 2), (2, 1)]);
        assert_eq!(calculate_max_depth(&graph), 1);

        // An acyclic prefix that is longer before reaching the cycle is measured
        // fully: n0 -> n1 -> n2, then n2 <-> n3 cycle. n2 and n3 are cycle members
        // (each has an incoming cycle edge), so only n0 -> n1 counts: depth 2.
        let graph = graph_from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 2)]);
        assert_eq!(calculate_max_depth(&graph), 2);
    }

    #[test]
    fn max_depth_diamond_lattice_is_linear() {
        // A layered diamond lattice: each node in layer L points to both nodes in
        // layer L+1. The number of distinct root->leaf simple paths is 2^layers,
        // which is exponential — the old path-enumerating recursion blows up here.
        // The iterative pass visits each node/edge once and must finish instantly.
        const LAYERS: usize = 50;
        let mut edges = Vec::new();
        // Layout: node index = layer * 2 + slot, slot in {0,1}.
        let idx = |layer: usize, slot: usize| layer * 2 + slot;
        for layer in 0..LAYERS {
            for from_slot in 0..2 {
                for to_slot in 0..2 {
                    edges.push((idx(layer, from_slot), idx(layer + 1, to_slot)));
                }
            }
        }
        let node_count = (LAYERS + 1) * 2;
        let graph = graph_from_edges(node_count, &edges);
        // Longest chain walks one node per layer plus the final layer: LAYERS + 1.
        assert_eq!(calculate_max_depth(&graph), LAYERS + 1);
    }

    #[test]
    fn max_depth_deep_chain_no_stack_overflow() {
        // A 40K-node linear chain would overflow the stack under the old
        // recursion (recursion depth == chain length). Iterative Kahn handles it.
        const N: usize = 40_000;
        let edges: Vec<(usize, usize)> = (0..N - 1).map(|i| (i, i + 1)).collect();
        let graph = graph_from_edges(N, &edges);
        assert_eq!(calculate_max_depth(&graph), N);
    }
}
