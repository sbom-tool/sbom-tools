//! Dependencies view for `ViewApp`.

use crate::model::DependencyType;
use crate::tui::state::ListNavigation;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use crate::tui::view::severity::severity_category;
use crate::tui::widgets::{self, SeverityBadge, truncate_str};
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
    id: String, // Used for expand/collapse tracking via get_selected_dependency_node_id
    name: String,
    depth: usize,
    is_last: bool,
    has_children: bool,
    is_expanded: bool,
    vuln_count: usize,
    max_severity: Option<String>,
    relationship: Option<DependencyType>,
    ancestors_last: Vec<bool>,
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

    // Flatten the tree based on expanded state
    let flat_nodes = flatten_dependency_tree(deps, &app.dependency_state.expanded);

    // Count search matches for the filter bar
    let search_query = app.dependency_state.search_query.clone();
    let match_count = if search_query.is_empty() {
        None
    } else {
        let q = search_query.to_lowercase();
        Some(flat_nodes.iter().filter(|n| n.name.to_lowercase().contains(&q)).count())
    };

    // Render filter bar
    render_filter_bar(frame, chunks[0], app, match_count);

    // Update the total count for navigation bounds
    app.dependency_state.total = flat_nodes.len();
    app.dependency_state.clamp_selection();

    let title = if !search_query.is_empty() {
        let filtered = match_count.unwrap_or(0);
        format!(" Dependency Tree ({filtered}/{} nodes) ", flat_nodes.len())
    } else {
        format!(" Dependency Tree ({} nodes) ", flat_nodes.len())
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.primary));
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

        // Expand/collapse indicator
        let expand_char = if node.has_children {
            if node.is_expanded { "▼ " } else { "▶ " }
        } else {
            "  "
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
        let is_search_match = !search_lower.is_empty()
            && node.name.to_lowercase().contains(&search_lower);

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

        // Name (with search highlight)
        let name_style = if is_selected {
            Style::default().bg(scheme.selection).fg(scheme.text).bold()
        } else if is_search_match {
            Style::default().fg(scheme.accent).bold()
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
            .thumb_style(Style::default().fg(scheme.primary))
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
        spans.push(Span::styled("Search: ", Style::default().fg(scheme.text_muted)));
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

    spans.push(Span::styled("[/]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" search  "));
    spans.push(Span::styled("[e]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" expand all  "));
    spans.push(Span::styled("[E]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" collapse all  "));
    spans.push(Span::styled("[c]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" go to component"));

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
        deps.relationships.get(&(pid.to_string(), node_id.to_string())).cloned()
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

fn render_dependency_stats(frame: &mut Frame, area: Rect, app: &mut ViewApp, deps: &DependencyGraph) {
    let scheme = colors();

    let mut lines = vec![];

    // Summary stats
    lines.push(Line::styled(
        "Dependency Statistics",
        Style::default().fg(scheme.primary).bold(),
    ));
    lines.push(Line::from(""));

    let total_components = deps.names.len();
    let total_edges: usize = deps.edges.values().map(Vec::len).sum();
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

    // Vulnerability severity bar chart
    let width = area.width.saturating_sub(4) as usize;
    let bar_width = width.saturating_sub(20).min(30);

    let mut vuln_severity_counts: HashMap<&str, usize> = HashMap::new();
    vuln_severity_counts.insert("critical", 0);
    vuln_severity_counts.insert("high", 0);
    vuln_severity_counts.insert("medium", 0);
    vuln_severity_counts.insert("low", 0);
    vuln_severity_counts.insert("clean", 0);

    for (node_id, &count) in &deps.vuln_counts {
        if count > 0 {
            let category = deps.max_severities.get(node_id).map_or("low", |s| s.as_str());
            *vuln_severity_counts.entry(category).or_insert(0) += 1;
        } else {
            *vuln_severity_counts.entry("clean").or_insert(0) += 1;
        }
    }

    let has_vulns = vuln_severity_counts.iter().any(|(&k, &v)| k != "clean" && v > 0);
    if has_vulns {
        lines.push(Line::styled(
            "Vulnerability Status:",
            Style::default().fg(scheme.critical).bold(),
        ));

        let vuln_order = [
            ("critical", "Critical", scheme.critical),
            ("high", "High", scheme.high),
            ("medium", "Medium", scheme.warning),
            ("low", "Low", scheme.info),
            ("clean", "Clean", scheme.success),
        ];

        let max_vuln_count = vuln_severity_counts.values().copied().max().unwrap_or(1);
        for (key, label, color) in &vuln_order {
            let count = vuln_severity_counts.get(key).copied().unwrap_or(0);
            let bar_len = if max_vuln_count > 0 {
                (count * bar_width) / max_vuln_count
            } else {
                0
            };
            let bar = "█".repeat(bar_len);
            lines.push(Line::from(vec![
                Span::styled(format!("  {label:12}"), Style::default().fg(*color)),
                Span::styled(format!("{count:>5} "), Style::default().fg(scheme.text)),
                Span::styled(bar, Style::default().fg(*color)),
            ]));
        }

        lines.push(Line::from(""));
    }

    // Relationship type bar chart
    let mut rel_counts: HashMap<&str, usize> = HashMap::new();
    for edge in &app.sbom.edges {
        let tag = dependency_tag(&edge.relationship).trim();
        let label = if tag.is_empty() { "depends-on" } else { tag };
        *rel_counts.entry(label).or_insert(0) += 1;
    }

    if !rel_counts.is_empty() {
        lines.push(Line::styled(
            "Relationship Types:",
            Style::default().fg(scheme.info).bold(),
        ));

        let max_rel_count = rel_counts.values().copied().max().unwrap_or(1);
        let mut rel_entries: Vec<_> = rel_counts.iter().collect();
        rel_entries.sort_by(|a, b| b.1.cmp(a.1));

        for (label, count) in &rel_entries {
            let count = **count;
            let bar_len = if max_rel_count > 0 {
                (count * bar_width) / max_rel_count
            } else {
                0
            };
            let bar = "█".repeat(bar_len);
            lines.push(Line::from(vec![
                Span::styled(format!("  {label:12}"), Style::default().fg(scheme.info)),
                Span::styled(format!("{count:>5} "), Style::default().fg(scheme.text)),
                Span::styled(bar, Style::default().fg(scheme.info)),
            ]));
        }

        lines.push(Line::from(""));
    }

    // Navigation help
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
    lines.push(Line::styled(
        "e/E         Expand/collapse all",
        Style::default().fg(scheme.muted),
    ));
    lines.push(Line::styled(
        "/           Search",
        Style::default().fg(scheme.muted),
    ));
    lines.push(Line::styled(
        "J/K         Scroll detail panel",
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
                Span::styled(name, Style::default().fg(scheme.text).bold()),
            ]));
        }

        // Look up component in SBOM for rich details
        let component = app.sbom.components.iter().find_map(|(id, comp)| {
            if id.value() == node_id {
                Some(comp)
            } else {
                None
            }
        });

        if let Some(comp) = component {
            if let Some(ref ver) = comp.version {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(scheme.muted)),
                    Span::styled(ver, Style::default().fg(scheme.text)),
                ]));
            }

            lines.push(Line::from(vec![
                Span::styled("Type: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format!("{:?}", comp.component_type),
                    Style::default().fg(scheme.text),
                ),
            ]));

            if let Some(ref eco) = comp.ecosystem {
                lines.push(Line::from(vec![
                    Span::styled("Ecosystem: ", Style::default().fg(scheme.muted)),
                    Span::styled(format!("{eco:?}"), Style::default().fg(scheme.text)),
                ]));
            }

            if let Some(ref purl) = comp.identifiers.purl
                && purl != &node_id
            {
                lines.push(Line::from(vec![
                    Span::styled("PURL: ", Style::default().fg(scheme.muted)),
                    Span::styled(purl, Style::default().fg(scheme.accent)),
                ]));
            }

            // Vulnerability details
            if !comp.vulnerabilities.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::styled(
                    format!("Vulnerabilities ({}):", comp.vulnerabilities.len()),
                    Style::default().fg(scheme.error).bold(),
                ));
                for vuln in comp.vulnerabilities.iter().take(5) {
                    let sev_str = vuln.severity.as_ref().map_or("unknown", |s| {
                        match s {
                            crate::model::Severity::Critical => "critical",
                            crate::model::Severity::High => "high",
                            crate::model::Severity::Medium => "medium",
                            crate::model::Severity::Low => "low",
                            _ => "info",
                        }
                    });
                    let sev_color = SeverityBadge::fg_color(sev_str);
                    let indicator = SeverityBadge::indicator(sev_str);
                    let mut spans = vec![
                        Span::styled("  • ", Style::default().fg(scheme.muted)),
                        Span::styled(&vuln.id, Style::default().fg(scheme.text)),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{indicator}]"),
                            Style::default().fg(scheme.badge_fg_dark).bg(sev_color).bold(),
                        ),
                    ];
                    if let Some(cvss) = vuln.cvss.first() {
                        spans.push(Span::styled(
                            format!(" ({:.1})", cvss.base_score),
                            Style::default().fg(sev_color),
                        ));
                    }
                    lines.push(Line::from(spans));
                }
                if comp.vulnerabilities.len() > 5 {
                    lines.push(Line::styled(
                        format!("  ... and {} more", comp.vulnerabilities.len() - 5),
                        Style::default().fg(scheme.muted),
                    ));
                }
            }

            // License info
            if !comp.licenses.declared.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::styled(
                    "Licenses:",
                    Style::default().fg(scheme.highlight).bold(),
                ));
                for lic in comp.licenses.declared.iter().take(3) {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(scheme.muted)),
                        Span::raw(&lic.expression),
                    ]));
                }
                if comp.licenses.declared.len() > 3 {
                    lines.push(Line::styled(
                        format!("  ... and {} more", comp.licenses.declared.len() - 3),
                        Style::default().fg(scheme.muted),
                    ));
                }
            }
        }

        // Direct dependencies with relationship tags
        if let Some(children) = deps.edges.get(&node_id) {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!("Dependencies ({}):", children.len()),
                Style::default().fg(scheme.primary).bold(),
            ));
            for child_id in children.iter().take(5) {
                let child_name = deps.names.get(child_id).map_or(child_id.as_str(), String::as_str);
                let tag = deps.relationships.get(&(node_id.clone(), child_id.clone()))
                    .map(|r| dependency_tag(r))
                    .unwrap_or("");
                let mut spans = vec![
                    Span::styled("  → ", Style::default().fg(scheme.muted)),
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
            if children.len() > 5 {
                lines.push(Line::styled(
                    format!("  ... and {} more", children.len() - 5),
                    Style::default().fg(scheme.muted),
                ));
            }
        }

        // Depended-on-by count (reverse graph)
        let depended_on_count = deps
            .edges
            .values()
            .filter(|children| children.contains(&node_id))
            .count();
        if depended_on_count > 0 {
            lines.push(Line::from(vec![
                Span::styled("Depended-on-by: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    depended_on_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
            ]));
        }

        // Canonical ID (dimmed, for reference when it differs from name)
        if deps
            .names
            .get(&node_id)
            .is_some_and(|name| name != &node_id)
        {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                "Canonical ID:",
                Style::default().fg(scheme.muted),
            ));
            lines.push(Line::styled(
                node_id.clone(),
                Style::default().fg(scheme.muted).dim(),
            ));
        }
    }

    // Scrolling support
    let content_height = lines.len() as u16;
    let block = Block::default()
        .title(" Stats & Info ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.secondary));
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
        let inner_area = Block::default()
            .borders(Borders::ALL)
            .inner(area);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.secondary))
            .track_style(Style::default().fg(scheme.muted));
        let mut scrollbar_state = ScrollbarState::new(content_height as usize)
            .position(app.dependency_state.detail_scroll as usize);
        frame.render_stateful_widget(scrollbar, inner_area, &mut scrollbar_state);
    }
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
    /// Node ID -> max severity category string
    max_severities: HashMap<String, String>,
    /// (from_id, to_id) -> relationship type
    relationships: HashMap<(String, String), DependencyType>,
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
        let display_name = comp
            .version
            .as_ref()
            .map_or_else(|| comp.name.clone(), |v| format!("{}@{}", comp.name, v));
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
            edges.entry(from_str.clone()).or_default().push(to_str.clone());
            has_parent.insert(to_str.clone());
            relationships.insert((from_str, to_str), edge.relationship.clone());
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
        max_severities,
        relationships,
    }
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

fn calculate_max_depth(deps: &DependencyGraph) -> usize {
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

    let mut max_depth = 0;

    for root in &deps.roots {
        let d = depth_of(root, deps, &mut HashSet::new());
        max_depth = max_depth.max(d);
    }

    max_depth
}
