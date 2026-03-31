//! Dependencies view with tree widget.

use crate::tui::app::{AppMode, DataContext};
use crate::tui::app_states::{DependenciesState, DependencyChangeFilter};
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

/// Compute a hash of the dependency graph for cache invalidation
fn compute_graph_hash(edges: &[(String, String)]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    edges.len().hash(&mut hasher);
    for (from, to) in edges {
        from.hash(&mut hasher);
        to.hash(&mut hasher);
    }
    hasher.finish()
}

/// Update the graph cache if needed (call before rendering).
///
/// Takes `&mut DependenciesState` and `&DataContext` separately to avoid
/// borrow conflicts when accessing both data and state on `App`.
pub fn update_graph_cache(deps: &mut DependenciesState, data: &DataContext, mode: AppMode) {
    if matches!(mode, AppMode::Diff | AppMode::View) {
        update_diff_mode_cache(deps, data);
    }
}

fn update_diff_mode_cache(deps: &mut DependenciesState, data: &DataContext) {
    // Always rebuild visible nodes and update total (needed for arrow key navigation + detail panel)
    let total = rebuild_visible_nodes(deps, data);
    deps.total = total;
    // Set viewport_height if not yet set (needed for scroll adjustment)
    if deps.viewport_height == 0 {
        deps.viewport_height = 30; // reasonable default until render sets it precisely
    }
    // Clamp selection to valid range
    if total == 0 {
        deps.selected = 0;
        deps.scroll_offset = 0;
    } else if deps.selected >= total {
        deps.selected = total - 1;
    }
    // Auto-adjust scroll_offset to keep selection visible
    // Use a viewport estimate (will be refined during render)
    let viewport_est = 30usize; // reasonable estimate
    if deps.selected >= deps.scroll_offset + viewport_est {
        deps.scroll_offset = deps.selected.saturating_sub(viewport_est / 2);
    } else if deps.selected < deps.scroll_offset {
        deps.scroll_offset = deps.selected;
    }
    if deps.scroll_offset >= total {
        deps.scroll_offset = total.saturating_sub(1);
    }

    // Fast path: once the cache is valid, skip entirely.
    // The diff_result is immutable during TUI operation, so the graph
    // structure never changes after the initial cache build.
    if deps.cache_valid {
        return;
    }

    if let Some(result) = &data.diff_result {
        let mut edges: Vec<(String, String)> = Vec::new();
        for dep in &result.dependencies.added {
            edges.push((dep.from.clone(), dep.to.clone()));
        }
        for dep in &result.dependencies.removed {
            edges.push((dep.from.clone(), dep.to.clone()));
        }
        edges.sort();
        let new_hash = compute_graph_hash(&edges);

        if deps.needs_cache_refresh(new_hash) {
            let mut by_source: HashMap<String, Vec<String>> = HashMap::new();
            for dep in &result.dependencies.added {
                by_source
                    .entry(dep.from.clone())
                    .or_default()
                    .push(dep.to.clone());
            }
            for dep in &result.dependencies.removed {
                by_source
                    .entry(dep.from.clone())
                    .or_default()
                    .push(dep.to.clone());
            }

            let mut sources: Vec<String> = by_source.keys().cloned().collect();
            sources.sort();

            deps.update_graph_cache(by_source, sources, new_hash);
            deps.update_transitive_cache();

            let vuln_components: HashSet<String> = result
                .vulnerabilities
                .introduced
                .iter()
                .chain(result.vulnerabilities.resolved.iter())
                .map(|v| v.component_name.clone())
                .collect();
            deps.update_vuln_cache(vuln_components);

            let mut display_names = HashMap::new();
            for sbom in data.new_sbom.iter().chain(data.old_sbom.iter()) {
                for (id, comp) in &sbom.components {
                    let id_str = id.value().to_string();
                    display_names.entry(id_str).or_insert_with(|| {
                        comp.version
                            .as_ref()
                            .map_or_else(|| comp.name.clone(), |v| format!("{}@{}", comp.name, v))
                    });
                }
            }
            deps.cached_display_names = display_names;

            // Cache edge relationship/scope info
            let mut edge_info = HashMap::new();
            for dep in result
                .dependencies
                .added
                .iter()
                .chain(result.dependencies.removed.iter())
            {
                edge_info
                    .entry((dep.from.clone(), dep.to.clone()))
                    .or_insert_with(|| crate::tui::app_states::EdgeInfo {
                        relationship: dep.relationship.clone(),
                        scope: dep.scope.clone(),
                    });
            }
            deps.cached_edge_info = edge_info;
        }
    }
}

/// Compute visible tree nodes for navigation and detail panel.
///
/// Builds the `visible_nodes` list matching what `render_diff_tree_cached` produces,
/// using the same node ID format (`source:+:child`, `source:-:child`).
/// This runs in `prepare_render()` so the detail panel can look up the selected node.
fn rebuild_visible_nodes(deps: &mut DependenciesState, data: &DataContext) -> usize {
    let max_roots = deps.max_roots;
    let mut roots: Vec<String> = if deps.show_transitive {
        deps.cached_roots.to_vec()
    } else {
        deps.cached_roots
            .iter()
            .filter(|id| deps.cached_depths.get(id.as_str()).copied().unwrap_or(0) <= 1)
            .cloned()
            .collect()
    };
    deps.sort_roots(&mut roots);
    roots.truncate(max_roots);

    deps.visible_nodes.clear();

    // Header + spacer (matching render_diff_tree_cached)
    deps.visible_nodes.push("__header__".to_string());
    deps.visible_nodes.push("__spacer__".to_string());

    // Build added/removed lookup matching render logic
    let mut added_by_source: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut removed_by_source: HashMap<&str, Vec<&str>> = HashMap::new();

    if let Some(result) = &data.diff_result {
        if !matches!(deps.change_filter, DependencyChangeFilter::Removed) {
            for dep in &result.dependencies.added {
                added_by_source.entry(&dep.from).or_default().push(&dep.to);
            }
        }
        if !matches!(deps.change_filter, DependencyChangeFilter::Added) {
            for dep in &result.dependencies.removed {
                removed_by_source
                    .entry(&dep.from)
                    .or_default()
                    .push(&dep.to);
            }
        }
    }

    for source in &roots {
        deps.visible_nodes.push(source.clone());

        if deps.expanded_nodes.contains(source) {
            // Added children
            if let Some(added) = added_by_source.get(source.as_str()) {
                for dep in added {
                    deps.visible_nodes.push(format!("{source}:+:{dep}"));
                }
            }
            // Removed children
            if let Some(removed) = removed_by_source.get(source.as_str()) {
                for dep in removed {
                    deps.visible_nodes.push(format!("{source}:-:{dep}"));
                }
            }
            // If no children at all, add empty placeholder
            let has_added = added_by_source
                .get(source.as_str())
                .is_some_and(|v| !v.is_empty());
            let has_removed = removed_by_source
                .get(source.as_str())
                .is_some_and(|v| !v.is_empty());
            if !has_added && !has_removed {
                deps.visible_nodes.push("__empty__".to_string());
            }
        }
    }

    deps.visible_nodes.len()
}

pub fn render_dependencies(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();

    // Caches and breadcrumbs are updated in prepare_render via update_graph_cache

    // Adjust context bar height based on search mode and breadcrumbs
    let is_searching = ctx.dependencies.is_searching();
    let has_search_query = ctx.dependencies.has_search_query();
    let show_breadcrumbs =
        ctx.dependencies.show_breadcrumbs && !ctx.dependencies.breadcrumb_trail.is_empty();

    let mut context_height = 2u16;
    if is_searching || has_search_query {
        context_height += 1;
    }
    if show_breadcrumbs {
        context_height += 1;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(context_height), Constraint::Min(5)])
        .split(area);

    let selected = ctx.dependencies.selected;
    let total = ctx.dependencies.total;
    let expanded_count = ctx.dependencies.expanded_nodes.len();
    let max_depth = ctx.dependencies.max_depth;
    let max_roots = ctx.dependencies.max_roots;
    let show_cycles = ctx.dependencies.show_cycles;
    let cycle_count = ctx.dependencies.detected_cycles.len();
    let (root_overflow, depth_limited) = dependency_limit_info_ctx(ctx, max_roots, max_depth);
    let vuln_count = ctx.dependencies.cached_vuln_components.len();
    let is_diff_mode = ctx.mode == AppMode::Diff;

    let on_style = Style::default().fg(scheme.success).bold();
    let off_style = Style::default().fg(scheme.text_muted);
    let sort_order = ctx.dependencies.sort_order.display_name();

    // Line 1: Toggles (color = state) │ Settings │ Filter (only when non-default)
    let mut line1_spans = vec![
        Span::styled(
            "Transitive",
            if ctx.dependencies.show_transitive {
                on_style
            } else {
                off_style
            },
        ),
        Span::styled("  ", Style::default()),
    ];

    if is_diff_mode {
        line1_spans.push(Span::styled(
            "Highlight",
            if ctx.dependencies.highlight_changes {
                on_style
            } else {
                off_style
            },
        ));
        line1_spans.push(Span::styled("  ", Style::default()));
    }

    line1_spans.push(Span::styled(
        "Cycles",
        if show_cycles { on_style } else { off_style },
    ));

    line1_spans.extend(vec![
        Span::styled("  │  ", Style::default().fg(scheme.border)),
        Span::styled(
            format!("Depth:{max_depth}"),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!("Roots:{max_roots}"),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!("Sort:{sort_order}"),
            Style::default().fg(scheme.primary).bold(),
        ),
    ]);

    // Show Filter only when non-default
    if is_diff_mode && !matches!(ctx.dependencies.change_filter, DependencyChangeFilter::All) {
        let filter_label = ctx.dependencies.change_filter.label();
        line1_spans.push(Span::styled("  ", Style::default()));
        line1_spans.push(Span::styled(
            format!("Filter:{filter_label}"),
            Style::default().fg(scheme.accent).bold(),
        ));
    }

    let line1 = Line::from(line1_spans);

    // Line 2: Selection + change counts │ Graph stats + Expanded │ Alerts │ Warnings
    let node_count = ctx.dependencies.cached_graph.len();
    let edge_count: usize = ctx.dependencies.cached_graph.values().map(Vec::len).sum();
    let direct_count = ctx.dependencies.cached_direct_deps.len();
    let expandable_count = ctx.dependencies.cached_roots.len().min(max_roots);

    let mut line2_spans = vec![Span::styled(
        format!("{}/{}", if total > 0 { selected + 1 } else { 0 }, total),
        Style::default().fg(scheme.primary).bold(),
    )];

    // Added/removed summary from diff result
    if let Some(result) = ctx.diff_result {
        let added = result.dependencies.added.len();
        let removed = result.dependencies.removed.len();
        line2_spans.push(Span::styled("  ", Style::default()));
        line2_spans.push(Span::styled(
            format!("+{added}"),
            Style::default().fg(scheme.added).bold(),
        ));
        line2_spans.push(Span::styled("  ", Style::default()));
        line2_spans.push(Span::styled(
            format!("-{removed}"),
            Style::default().fg(scheme.removed).bold(),
        ));
    }

    line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
    line2_spans.push(Span::styled(
        format!("{node_count} nodes  {edge_count} edges ({direct_count} direct)"),
        Style::default().fg(scheme.text_muted),
    ));
    line2_spans.push(Span::styled("  ", Style::default()));
    line2_spans.push(Span::styled(
        format!("Expanded: {expanded_count}/{expandable_count}"),
        if expanded_count > 0 {
            Style::default().fg(scheme.success)
        } else {
            Style::default().fg(scheme.text_muted)
        },
    ));

    if vuln_count > 0 {
        line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line2_spans.push(Span::styled(
            format!("⚠ {vuln_count} vulnerabilities"),
            Style::default().fg(scheme.critical).bold(),
        ));
    }

    if show_cycles && cycle_count > 0 {
        line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line2_spans.push(Span::styled(
            format!("⟳ {cycle_count} cycles"),
            Style::default().fg(scheme.warning).bold(),
        ));
    }

    if root_overflow > 0 || depth_limited {
        line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        if root_overflow > 0 {
            line2_spans.push(Span::styled(
                format!("+{root_overflow} roots"),
                Style::default().fg(scheme.warning),
            ));
        }
        if root_overflow > 0 && depth_limited {
            line2_spans.push(Span::styled(", ", Style::default().fg(scheme.text_muted)));
        }
        if depth_limited {
            line2_spans.push(Span::styled(
                format!("depth≤{max_depth}"),
                Style::default().fg(scheme.warning),
            ));
        }
    }

    let line2 = Line::from(line2_spans);

    let mut context_lines = vec![line1, line2];

    // Add search bar if searching
    if is_searching {
        let query = &ctx.dependencies.search_query;
        let match_count = ctx.dependencies.search_matches.len();
        let filter_mode = ctx.dependencies.filter_mode;

        let mut search_spans = vec![
            Span::styled("[/]", Style::default().fg(scheme.accent)),
            Span::styled(" Search: ", Style::default().fg(scheme.text)),
            Span::styled(
                if query.is_empty() { "_" } else { query },
                Style::default().fg(scheme.primary).bold(),
            ),
            Span::styled("█", Style::default().fg(scheme.accent)), // cursor
        ];

        if !query.is_empty() {
            search_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
            search_spans.push(Span::styled(
                format!("{match_count} matches"),
                if match_count > 0 {
                    Style::default().fg(scheme.success)
                } else {
                    Style::default().fg(scheme.warning)
                },
            ));

            search_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
            search_spans.push(Span::styled("[f]", Style::default().fg(scheme.accent)));
            search_spans.push(Span::raw(" Filter: "));
            search_spans.push(Span::styled(
                if filter_mode { "On" } else { "Off" },
                if filter_mode {
                    Style::default().fg(scheme.success).bold()
                } else {
                    Style::default().fg(scheme.text_muted)
                },
            ));
        }

        search_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        search_spans.push(Span::styled("[Esc]", Style::default().fg(scheme.accent)));
        search_spans.push(Span::raw(" close  "));
        search_spans.push(Span::styled("[n/N]", Style::default().fg(scheme.accent)));
        search_spans.push(Span::raw(" next/prev"));

        context_lines.push(Line::from(search_spans));
    } else if ctx.dependencies.has_search_query() {
        // Show persistent search indicator when not actively searching
        let match_count = ctx.dependencies.search_matches.len();
        let filter_mode = ctx.dependencies.filter_mode;
        let query = &ctx.dependencies.search_query;

        let mut search_spans = vec![
            Span::styled("[/]", Style::default().fg(scheme.accent)),
            Span::styled(" Search: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("\"{query}\""),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(
                format!(" ({match_count} matches)"),
                Style::default().fg(scheme.text_muted),
            ),
        ];

        if filter_mode {
            search_spans.push(Span::styled(
                " [filtered]",
                Style::default().fg(scheme.warning),
            ));
        }

        search_spans.push(Span::styled("  ", Style::default()));
        search_spans.push(Span::styled("[Esc]", Style::default().fg(scheme.accent)));
        search_spans.push(Span::raw(" clear"));

        context_lines.push(Line::from(search_spans));
    }

    // Add breadcrumb bar if enabled and there's a trail
    if show_breadcrumbs {
        let breadcrumb_display = ctx.dependencies.get_breadcrumb_display();
        let breadcrumb_line = Line::from(vec![
            Span::styled("> ", Style::default().fg(scheme.accent)),
            Span::styled(breadcrumb_display, Style::default().fg(scheme.text_muted)),
            Span::styled("  │  ", Style::default().fg(scheme.border)),
            Span::styled("[b]", Style::default().fg(scheme.accent)),
            Span::raw(" toggle"),
        ]);
        context_lines.push(breadcrumb_line);
    }

    let options = Paragraph::new(context_lines)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(scheme.border)),
        )
        .style(Style::default().fg(scheme.text));

    frame.render_widget(options, chunks[0]);

    // Dependency tree
    render_dependency_tree(frame, chunks[1], ctx);

    // Render help overlay if active
    if ctx.dependencies.show_deps_help {
        render_deps_help_overlay(frame, area);
    }
}

fn render_dependency_tree(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();

    // Split into tree (60%) and detail panel (40%)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let tree_with_scrollbar = main_chunks[0];
    let detail_area = main_chunks[1];

    // Split tree area into main area and scrollbar
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(tree_with_scrollbar);

    let tree_area = chunks[0];

    // Compute viewport height locally (writeback removed — prepare_render handles it)
    let viewport_height = tree_area.height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = vec![];
    let mut visible_nodes: Vec<String> = vec![];

    // Read search state from ctx
    let search_matches = &ctx.dependencies.search_matches;
    let filter_mode = ctx.dependencies.filter_mode;
    let has_search = !search_matches.is_empty();

    // Read cached vulnerability components from ctx
    let vuln_components = &ctx.dependencies.cached_vuln_components;

    match ctx.mode {
        AppMode::Diff | AppMode::View => {
            render_diff_tree_cached(
                &mut lines,
                &mut visible_nodes,
                ctx,
                tree_area.width as usize,
                vuln_components,
                search_matches,
                filter_mode,
            );
        }
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }

    // visible_nodes and scroll adjustment are handled in prepare_render;
    // here we use the pre-computed state from ctx.

    // Apply selection and search highlighting with virtual scrolling
    let total_len = visible_nodes.len();
    if total_len == 0 {
        // Nothing to render — show empty tree block and return
        let block = Block::default()
            .title(" Dependency Tree ")
            .title_style(Style::default().fg(scheme.primary).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.border));
        frame.render_widget(block, tree_area);
        render_detail_panel(frame, detail_area, ctx);
        return;
    }

    let selected = ctx.dependencies.selected.min(total_len - 1);
    let scroll_offset = ctx.dependencies.scroll_offset.min(total_len - 1);

    // Only process lines in the visible range (virtual scrolling)
    let visible_start = scroll_offset;
    let visible_end = (scroll_offset + viewport_height)
        .min(total_len)
        .min(lines.len());

    let highlighted_lines: Vec<Line> = lines
        .into_iter()
        .enumerate()
        .skip(visible_start)
        .take(visible_end.saturating_sub(visible_start))
        .map(|(idx, line)| {
            let node_id = visible_nodes.get(idx);
            let is_match = node_id.is_some_and(|id| has_search && search_matches.contains(id));

            if idx == selected {
                // Highlight selected line with selection background
                Line::from(
                    line.spans
                        .into_iter()
                        .map(|span| Span::styled(span.content, span.style.bg(scheme.selection)))
                        .collect::<Vec<_>>(),
                )
            } else if is_match {
                // Highlight search matches with accent color background
                Line::from(
                    line.spans
                        .into_iter()
                        .map(|span| {
                            Span::styled(
                                span.content,
                                span.style.bg(Color::Rgb(60, 60, 20)), // subtle yellow bg
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                line
            }
        })
        .collect();

    // Use total nodes count for scrollbar, not just visible lines
    let total_nodes = visible_nodes.len();

    // Paragraph doesn't need scroll since we're doing virtual scrolling
    let paragraph = Paragraph::new(highlighted_lines).block(
        Block::default()
            .title(" Dependency Tree ")
            .title_style(Style::default().fg(scheme.primary).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.border)),
    );

    frame.render_widget(paragraph, tree_area);

    // Scrollbar reflects actual position in full list
    let mut scrollbar_state = ScrollbarState::default()
        .content_length(total_nodes)
        .position(scroll_offset);

    frame.render_stateful_widget(
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.primary))
            .track_style(Style::default().fg(scheme.border)),
        chunks[1],
        &mut scrollbar_state,
    );

    // Render detail panel for selected node
    render_detail_panel(frame, detail_area, ctx);
}

/// Render the detail panel showing info about the selected dependency node
fn render_detail_panel(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    use ratatui::widgets::Wrap;

    let scheme = colors();
    let mut lines = vec![];

    lines.push(Line::styled(
        "Node Details",
        Style::default().fg(scheme.primary).bold(),
    ));
    lines.push(Line::from(""));

    let selected_node = ctx.dependencies.get_selected_node_id();

    if let Some(raw_id) = selected_node {
        // Skip placeholder nodes
        if raw_id.starts_with("__") {
            lines.push(Line::styled(
                "Select a dependency node to view details",
                Style::default().fg(scheme.text_muted),
            ));
        } else {
            // For diff mode child nodes, extract the actual component ID
            // Format: "parent:+:child" or "parent:-:child"
            let (parent_id, component_id, change_marker) = if let Some(pos) = raw_id.find(":+:") {
                (Some(&raw_id[..pos]), &raw_id[pos + 3..], Some("+"))
            } else if let Some(pos) = raw_id.find(":-:") {
                (Some(&raw_id[..pos]), &raw_id[pos + 3..], Some("-"))
            } else {
                (None, raw_id, None)
            };

            // Section header with display name
            let display_name = ctx.dependencies.cached_display_names.get(component_id);
            let header = display_name.map_or(component_id.to_string(), Clone::clone);
            lines.push(Line::styled(
                header,
                Style::default().fg(scheme.accent).bold(),
            ));

            // Change type (diff mode)
            if let Some(marker) = change_marker {
                let (label, style) = if marker == "+" {
                    ("Added", Style::default().fg(scheme.added).bold())
                } else {
                    ("Removed", Style::default().fg(scheme.removed).bold())
                };
                lines.push(Line::from(vec![
                    Span::styled("Change: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(label, style),
                ]));
            }

            // Edge relationship and scope (for child nodes)
            if let Some(parent) = parent_id
                && let Some(info) = ctx
                    .dependencies
                    .cached_edge_info
                    .get(&(parent.to_string(), component_id.to_string()))
            {
                lines.push(Line::from(vec![
                    Span::styled("Relationship: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(&info.relationship, Style::default().fg(scheme.text)),
                ]));
                if let Some(scope) = &info.scope {
                    lines.push(Line::from(vec![
                        Span::styled("Scope: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(scope, Style::default().fg(scheme.text)),
                    ]));
                }
            }

            // Look up component in SBOMs for rich details
            let component = find_component_in_sboms(component_id, ctx);

            // Gather dependency context
            let depth = ctx.dependencies.cached_depths.get(component_id).copied();
            let deps_out = ctx
                .dependencies
                .cached_graph
                .get(component_id)
                .map_or(0, Vec::len);
            let deps_in = ctx
                .dependencies
                .cached_reverse_graph
                .get(component_id)
                .map_or(0, Vec::len);

            if let Some(comp) = component {
                // Use shared component info renderer
                lines.extend(crate::tui::shared::components::render_component_info_lines(
                    comp, depth, deps_out, deps_in,
                ));
            } else {
                // Fallback: show basic info from cached data
                if deps_out > 0 || deps_in > 0 {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("Dependencies: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(deps_out.to_string(), Style::default().fg(scheme.primary)),
                        Span::styled("  Dependents: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(deps_in.to_string(), Style::default().fg(scheme.primary)),
                    ]));
                }
            }

            // "Depends on:" listing (children from forward graph)
            if let Some(children) = ctx.dependencies.cached_graph.get(component_id)
                && !children.is_empty()
            {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("━━━ ", Style::default().fg(scheme.border)),
                    Span::styled("Depends on", Style::default().fg(scheme.accent).bold()),
                    Span::styled(" ━━━", Style::default().fg(scheme.border)),
                ]));
                for child in children.iter().take(8) {
                    let display = ctx
                        .dependencies
                        .cached_display_names
                        .get(child.as_str())
                        .map_or_else(|| child.clone(), Clone::clone);
                    lines.push(Line::from(vec![
                        Span::styled("  \u{2022} ", Style::default().fg(scheme.text_muted)),
                        Span::styled(display, Style::default().fg(scheme.text)),
                    ]));
                }
                if children.len() > 8 {
                    lines.push(Line::styled(
                        format!("    ... and {} more", children.len() - 8),
                        Style::default().fg(scheme.text_muted),
                    ));
                }
            }

            // "Depended on by:" listing (parents from reverse graph)
            if let Some(parents) = ctx.dependencies.cached_reverse_graph.get(component_id)
                && !parents.is_empty()
            {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("━━━ ", Style::default().fg(scheme.border)),
                    Span::styled("Depended on by", Style::default().fg(scheme.accent).bold()),
                    Span::styled(" ━━━", Style::default().fg(scheme.border)),
                ]));
                for parent in parents.iter().take(8) {
                    let display = ctx
                        .dependencies
                        .cached_display_names
                        .get(parent.as_str())
                        .map_or_else(|| parent.clone(), Clone::clone);
                    lines.push(Line::from(vec![
                        Span::styled("  \u{2022} ", Style::default().fg(scheme.text_muted)),
                        Span::styled(display, Style::default().fg(scheme.text)),
                    ]));
                }
                if parents.len() > 8 {
                    lines.push(Line::styled(
                        format!("    ... and {} more", parents.len() - 8),
                        Style::default().fg(scheme.text_muted),
                    ));
                }
            }

            // Vulnerability details
            if let Some(result) = ctx.diff_result {
                let vulns: Vec<(&crate::diff::VulnerabilityDetail, &str)> = result
                    .vulnerabilities
                    .introduced
                    .iter()
                    .filter(|v| v.component_name == component_id || v.component_id == component_id)
                    .map(|v| (v, "introduced"))
                    .chain(
                        result
                            .vulnerabilities
                            .resolved
                            .iter()
                            .filter(|v| {
                                v.component_name == component_id || v.component_id == component_id
                            })
                            .map(|v| (v, "resolved")),
                    )
                    .chain(
                        result
                            .vulnerabilities
                            .persistent
                            .iter()
                            .filter(|v| {
                                v.component_name == component_id || v.component_id == component_id
                            })
                            .map(|v| (v, "persistent")),
                    )
                    .collect();

                if !vulns.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("━━━ ", Style::default().fg(scheme.border)),
                        Span::styled(
                            format!("Vulnerabilities ({})", vulns.len()),
                            Style::default().fg(scheme.critical).bold(),
                        ),
                        Span::styled(" ━━━", Style::default().fg(scheme.border)),
                    ]));
                    for (vuln, status) in vulns.iter().take(5) {
                        let sev_color = scheme.severity_color(&vuln.severity);
                        let status_style = match *status {
                            "introduced" => Style::default().fg(scheme.removed),
                            "resolved" => Style::default().fg(scheme.added),
                            _ => Style::default().fg(scheme.text_muted),
                        };
                        let mut vuln_spans = vec![
                            Span::styled("  ", Style::default()),
                            Span::styled(&vuln.severity, Style::default().fg(sev_color).bold()),
                            Span::styled(" ", Style::default()),
                            Span::styled(&vuln.id, Style::default().fg(scheme.text)),
                            Span::styled(format!(" ({status})"), status_style),
                        ];
                        if vuln.is_kev {
                            vuln_spans.push(Span::styled(
                                " KEV",
                                Style::default().fg(scheme.critical).bold(),
                            ));
                        }
                        lines.push(Line::from(vuln_spans));
                    }
                    if vulns.len() > 5 {
                        lines.push(Line::styled(
                            format!("    ... and {} more", vulns.len() - 5),
                            Style::default().fg(scheme.text_muted),
                        ));
                    }
                }
            }

            // Canonical ID (dimmed, for reference)
            lines.push(Line::from(""));
            lines.push(Line::styled(
                "Canonical ID:",
                Style::default().fg(scheme.text_muted),
            ));
            lines.push(Line::styled(
                component_id,
                Style::default().fg(scheme.text_muted).dim(),
            ));
        }
    } else {
        lines.push(Line::styled(
            "No node selected",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let detail_scroll = ctx.dependencies.detail_scroll as u16;
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Details ")
                .title_style(Style::default().fg(scheme.primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .wrap(Wrap { trim: false })
        .scroll((detail_scroll, 0));

    frame.render_widget(para, area);
}

/// Look up a component by canonical ID in available SBOMs
fn find_component_in_sboms<'a>(
    id: &str,
    ctx: &'a RenderContext,
) -> Option<&'a crate::model::Component> {
    // Try view-mode SBOM first, then diff-mode SBOMs
    for sbom in ctx
        .sbom
        .iter()
        .chain(ctx.new_sbom.iter())
        .chain(ctx.old_sbom.iter())
    {
        for (canonical_id, comp) in &sbom.components {
            if canonical_id.value() == id {
                return Some(comp);
            }
        }
    }
    None
}

/// Generate an edge-info badge span (e.g., `[dev]`, `[opt]`) for non-default relationships.
fn edge_badge<'a>(
    from: &str,
    to: &str,
    edge_info: &HashMap<(String, String), crate::tui::app_states::EdgeInfo>,
    scheme: crate::tui::theme::ColorScheme,
) -> Option<Span<'a>> {
    let info = edge_info.get(&(from.to_string(), to.to_string()))?;
    let label = match info.relationship.as_str() {
        "DevDependsOn" => "dev",
        "BuildDependsOn" => "build",
        "TestDependsOn" => "test",
        "OptionalDependsOn" => "opt",
        "RuntimeDependsOn" => "rt",
        "ProvidedDependsOn" => "provided",
        "DependsOn" => match info.scope.as_deref() {
            Some("Optional") => "opt",
            Some("Excluded") => "excluded",
            _ => return None,
        },
        _ => match info.scope.as_deref() {
            Some("Optional") => "opt",
            Some("Excluded") => "excluded",
            _ => return None,
        },
    };
    Some(Span::styled(
        format!(" [{label}]"),
        Style::default().fg(scheme.text_muted).dim(),
    ))
}

/// Render diff dependency tree using cached graph structure.
fn render_diff_tree_cached(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    ctx: &RenderContext,
    max_width: usize,
    vuln_components: &HashSet<String>,
    search_matches: &HashSet<String>,
    filter_mode: bool,
) {
    let scheme = colors();
    let max_roots = ctx.dependencies.max_roots;
    let highlight = ctx.dependencies.highlight_changes;

    if let Some(result) = ctx.diff_result {
        // Build tree from dependency changes
        let added_count = result.dependencies.added.len();
        let removed_count = result.dependencies.removed.len();

        // Summary header
        lines.push(Line::from(vec![
            Span::styled("Changes: ", Style::default().fg(scheme.text).bold()),
            Span::styled(
                format!("+{added_count}"),
                Style::default().fg(scheme.added).bold(),
            ),
            Span::raw(" added, "),
            Span::styled(
                format!("-{removed_count}"),
                Style::default().fg(scheme.removed).bold(),
            ),
            Span::raw(" removed"),
        ]));
        visible_nodes.push("__header__".to_string());
        lines.push(Line::raw(""));
        visible_nodes.push("__spacer__".to_string());

        // Use cached roots (sources)
        let sources = &ctx.dependencies.cached_roots;
        let expanded = &ctx.dependencies.expanded_nodes;
        let display_names = &ctx.dependencies.cached_display_names;

        // Build added/removed lookup from result, respecting change filter
        let mut added_by_source: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut removed_by_source: HashMap<&str, Vec<&str>> = HashMap::new();
        let change_filter = ctx.dependencies.change_filter;

        if !matches!(change_filter, DependencyChangeFilter::Removed) {
            for dep in &result.dependencies.added {
                added_by_source.entry(&dep.from).or_default().push(&dep.to);
            }
        }
        if !matches!(change_filter, DependencyChangeFilter::Added) {
            for dep in &result.dependencies.removed {
                removed_by_source
                    .entry(&dep.from)
                    .or_default()
                    .push(&dep.to);
            }
        }

        // Sort + filter sources
        let show_transitive = ctx.dependencies.show_transitive;
        let depths = &ctx.dependencies.cached_depths;
        let mut sorted_sources: Vec<String> = if filter_mode && !search_matches.is_empty() {
            sources
                .iter()
                .filter(|s| search_matches.contains(*s))
                .filter(|s| show_transitive || depths.get(s.as_str()).copied().unwrap_or(0) <= 1)
                .cloned()
                .collect()
        } else if !show_transitive {
            sources
                .iter()
                .filter(|s| depths.get(s.as_str()).copied().unwrap_or(0) <= 1)
                .cloned()
                .collect()
        } else {
            sources.clone()
        };
        ctx.dependencies.sort_roots(&mut sorted_sources);
        sorted_sources.truncate(max_roots);
        let sources_to_show: Vec<&String> = sorted_sources.iter().collect();

        for (idx, source) in sources_to_show.iter().enumerate() {
            let source_str: &str = source;
            let added = added_by_source.get(source_str);
            let removed = removed_by_source.get(source_str);

            let added_count = added.map_or(0, std::vec::Vec::len);
            let removed_count = removed.map_or(0, std::vec::Vec::len);
            let is_expanded = expanded.contains(*source);
            let is_last = idx == sources_to_show.len() - 1;

            let source_has_vuln = vuln_components.contains(*source);

            let branch = if is_last { "└─" } else { "├─" };
            let expand_icon = if is_expanded { "▼" } else { "▶" };

            let source_style = if highlight {
                if added.is_some() && removed.is_some() {
                    Style::default().fg(scheme.modified)
                } else if added.is_some() {
                    Style::default().fg(scheme.added)
                } else {
                    Style::default().fg(scheme.removed)
                }
            } else {
                Style::default().fg(scheme.text)
            };

            let short_source = resolve_display_name(source, display_names, max_width - 20);
            let mut spans = vec![
                Span::styled(branch, Style::default().fg(scheme.border)),
                Span::styled(expand_icon, Style::default().fg(scheme.accent)),
                Span::raw(" "),
                Span::styled(short_source, source_style.bold()),
            ];

            // Show child count breakdown: (+N -M), (+N), or (-M)
            match (added_count, removed_count) {
                (0, 0) => {}
                (a, 0) => spans.push(Span::styled(
                    format!(" (+{a})"),
                    Style::default().fg(scheme.added),
                )),
                (0, r) => spans.push(Span::styled(
                    format!(" (-{r})"),
                    Style::default().fg(scheme.removed),
                )),
                (a, r) => {
                    spans.push(Span::styled(
                        format!(" (+{a}"),
                        Style::default().fg(scheme.added),
                    ));
                    spans.push(Span::styled(
                        format!(" -{r})"),
                        Style::default().fg(scheme.removed),
                    ));
                }
            }

            if source_has_vuln {
                spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
            }

            // Depth badge
            if let Some(&d) = ctx.dependencies.cached_depths.get(source_str) {
                let badge = format!("D{d}");
                let color = match d {
                    0 => scheme.accent,
                    1 => scheme.primary,
                    _ => scheme.text_muted,
                };
                spans.push(Span::styled(
                    format!(" {badge}"),
                    Style::default().fg(color),
                ));
            }

            lines.push(Line::from(spans));
            visible_nodes.push((*source).clone());

            // Children if expanded
            if is_expanded {
                let prefix = if is_last { "   " } else { "│  " };

                if let Some(added_deps) = added {
                    for (i, dep) in added_deps.iter().enumerate() {
                        let is_last_child = removed.is_none() && i == added_deps.len() - 1;
                        let child_branch = if is_last_child { "└─" } else { "├─" };
                        let short_dep = resolve_display_name(dep, display_names, max_width - 25);
                        let dep_has_vuln = vuln_components.contains(*dep);

                        let dep_style = if highlight {
                            Style::default().fg(scheme.added)
                        } else {
                            Style::default().fg(scheme.text)
                        };
                        let mut dep_spans = vec![
                            Span::styled(prefix, Style::default().fg(scheme.border)),
                            Span::styled(child_branch, Style::default().fg(scheme.border)),
                            Span::styled(" + ", dep_style.bold()),
                            Span::styled(short_dep, dep_style),
                        ];

                        if dep_has_vuln {
                            dep_spans
                                .push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
                        }

                        // Depth badge
                        if let Some(&d) = ctx.dependencies.cached_depths.get(*dep) {
                            let badge = format!("D{d}");
                            let color = match d {
                                0 => scheme.accent,
                                1 => scheme.primary,
                                _ => scheme.text_muted,
                            };
                            dep_spans.push(Span::styled(
                                format!(" {badge}"),
                                Style::default().fg(color),
                            ));
                        }

                        // Edge relationship badge
                        if let Some(badge) =
                            edge_badge(source, dep, &ctx.dependencies.cached_edge_info, scheme)
                        {
                            dep_spans.push(badge);
                        }

                        lines.push(Line::from(dep_spans));
                        visible_nodes.push(format!("{source}:+:{dep}"));
                    }
                }

                if let Some(removed_deps) = removed {
                    for (i, dep) in removed_deps.iter().enumerate() {
                        let is_last_child = i == removed_deps.len() - 1;
                        let child_branch = if is_last_child { "└─" } else { "├─" };
                        let short_dep = resolve_display_name(dep, display_names, max_width - 25);
                        let dep_has_vuln = vuln_components.contains(*dep);

                        let dep_style = if highlight {
                            Style::default().fg(scheme.removed)
                        } else {
                            Style::default().fg(scheme.text)
                        };
                        let mut dep_spans = vec![
                            Span::styled(prefix, Style::default().fg(scheme.border)),
                            Span::styled(child_branch, Style::default().fg(scheme.border)),
                            Span::styled(" - ", dep_style.bold()),
                            Span::styled(short_dep, dep_style),
                        ];

                        if dep_has_vuln {
                            dep_spans
                                .push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
                        }

                        // Depth badge
                        if let Some(&d) = ctx.dependencies.cached_depths.get(*dep) {
                            let badge = format!("D{d}");
                            let color = match d {
                                0 => scheme.accent,
                                1 => scheme.primary,
                                _ => scheme.text_muted,
                            };
                            dep_spans.push(Span::styled(
                                format!(" {badge}"),
                                Style::default().fg(color),
                            ));
                        }

                        // Edge relationship badge
                        if let Some(badge) =
                            edge_badge(source, dep, &ctx.dependencies.cached_edge_info, scheme)
                        {
                            dep_spans.push(badge);
                        }

                        lines.push(Line::from(dep_spans));
                        visible_nodes.push(format!("{source}:-:{dep}"));
                    }
                }
            }
        }

        if sources.is_empty() {
            lines.push(Line::styled(
                "No dependency changes detected",
                Style::default().fg(scheme.text_muted),
            ));
            visible_nodes.push("__empty__".to_string());
        }
    }
}

/// Cached version of `dependency_limit_info` using RenderContext
fn dependency_limit_info_ctx(
    ctx: &RenderContext,
    max_roots: usize,
    max_depth: usize,
) -> (usize, bool) {
    let roots = &ctx.dependencies.cached_roots;
    let graph = &ctx.dependencies.cached_graph;

    if graph.is_empty() {
        return (0, false);
    }

    let root_overflow = roots.len().saturating_sub(max_roots);
    let depth_limited = depth_exceeds_limit(graph, roots, max_depth);

    (root_overflow, depth_limited)
}

fn depth_exceeds_limit(
    by_source: &HashMap<String, Vec<String>>,
    roots: &[String],
    max_depth: usize,
) -> bool {
    if max_depth == 0 {
        return !by_source.is_empty();
    }

    let mut seen_depth: HashMap<String, usize> = HashMap::new();
    let mut stack: Vec<(String, usize)> = roots.iter().cloned().map(|root| (root, 1)).collect();

    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            return true;
        }
        if seen_depth
            .get(node.as_str())
            .is_some_and(|&seen| seen >= depth)
        {
            continue;
        }
        // Enqueue children before consuming node
        if let Some(children) = by_source.get(node.as_str()) {
            for child in children {
                stack.push((child.clone(), depth + 1));
            }
        }
        seen_depth.insert(node, depth);
    }

    false
}

/// Resolve a canonical ID to a display name, falling back to truncated ID
fn resolve_display_name(id: &str, names: &HashMap<String, String>, budget: usize) -> String {
    names.get(id).map_or_else(
        || truncate_component(id, budget),
        |name| truncate_component(name, budget),
    )
}

/// Truncate component ID to fit width, with PURL and path-aware strategies.
///
/// Strategy:
/// 1. If it fits → return as-is
/// 2. If PURL → strip `pkg:type/` prefix, try again
/// 3. If path-like (contains `/`) → show last segments that fit, prepend `…/`
/// 4. Final fallback → tail truncate with `…`
fn truncate_component(id: &str, max_width: usize) -> String {
    use unicode_width::UnicodeWidthStr;

    let width = UnicodeWidthStr::width(id);
    if width <= max_width {
        return id.to_string();
    }

    // PURL: strip "pkg:type/" prefix to get "name@version"
    if let Some(rest) = id.strip_prefix("pkg:")
        && let Some(slash_pos) = rest.find('/')
    {
        let name_ver = &rest[slash_pos + 1..];
        let clean = name_ver.split('?').next().unwrap_or(name_ver);
        if UnicodeWidthStr::width(clean) <= max_width {
            return clean.to_string();
        }
        // Still too long — fall through to general truncation on the clean name
        return truncate_by_width(clean, max_width);
    }

    // Path-like: show last segments that fit, prepend "…/"
    if id.contains('/') && max_width > 4 {
        let segments: Vec<&str> = id.rsplit('/').collect();
        let mut result = String::new();
        let ellipsis_prefix = "…/";

        for (i, seg) in segments.iter().enumerate() {
            let candidate = if i == 0 {
                // Just the last segment
                seg.to_string()
            } else {
                format!("{ellipsis_prefix}{seg}/{result}")
            };
            let candidate_w = UnicodeWidthStr::width(candidate.as_str());
            if candidate_w > max_width {
                break;
            }
            if i == 0 {
                result = seg.to_string();
            } else {
                result = format!("{seg}/{result}");
            }
        }

        if !result.is_empty() {
            let result_w = UnicodeWidthStr::width(result.as_str());
            if result_w < width {
                // We truncated something, add ellipsis prefix
                let with_ellipsis = format!("{ellipsis_prefix}{result}");
                if UnicodeWidthStr::width(with_ellipsis.as_str()) <= max_width {
                    return with_ellipsis;
                }
                // Just the result without ellipsis if it fits
                if result_w <= max_width {
                    return format!("…{result}");
                }
            } else if result_w <= max_width {
                return result;
            }
        }
    }

    truncate_by_width(id, max_width)
}

/// Unicode-width-aware truncation with ellipsis
fn truncate_by_width(s: &str, max_width: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

    if UnicodeWidthStr::width(s) <= max_width {
        return s.to_string();
    }

    if max_width <= 1 {
        return "…".to_string();
    }

    let mut width = 0;
    let truncated: String = s
        .chars()
        .take_while(|ch| {
            let w = UnicodeWidthChar::width(*ch).unwrap_or(0);
            if width + w > max_width - 1 {
                return false;
            }
            width += w;
            true
        })
        .collect();
    format!("{truncated}…")
}

/// Render the dependencies keyboard shortcut help overlay
fn render_deps_help_overlay(frame: &mut Frame, area: Rect) {
    use ratatui::widgets::Clear;
    let scheme = colors();

    // Center the help window
    let help_width = 60u16;
    let help_height = 22u16;
    let x = area.x + (area.width.saturating_sub(help_width)) / 2;
    let y = area.y + (area.height.saturating_sub(help_height)) / 2;
    let help_area = Rect::new(
        x,
        y,
        help_width.min(area.width),
        help_height.min(area.height),
    );

    // Clear the background
    frame.render_widget(Clear, help_area);

    let help_lines = vec![
        Line::from(Span::styled(
            "Dependencies View Shortcuts",
            Style::default().fg(scheme.primary).bold(),
        )),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().fg(scheme.accent).bold(),
        )]),
        Line::from(vec![
            Span::styled("  j/↓      ", Style::default().fg(scheme.text)),
            Span::styled("Move down", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  k/↑      ", Style::default().fg(scheme.text)),
            Span::styled("Move up", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  G/End    ", Style::default().fg(scheme.text)),
            Span::styled("Jump to last", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  Home     ", Style::default().fg(scheme.text)),
            Span::styled("Jump to first", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  PgUp/Dn  ", Style::default().fg(scheme.text)),
            Span::styled("Page scroll", Style::default().fg(scheme.text_muted)),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Tree Controls",
            Style::default().fg(scheme.accent).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Enter/→  ", Style::default().fg(scheme.text)),
            Span::styled("Expand node", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  ←        ", Style::default().fg(scheme.text)),
            Span::styled("Collapse node", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  e        ", Style::default().fg(scheme.text)),
            Span::styled("Expand all", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  E        ", Style::default().fg(scheme.text)),
            Span::styled("Collapse all", Style::default().fg(scheme.text_muted)),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Display Options",
            Style::default().fg(scheme.accent).bold(),
        )]),
        Line::from(vec![
            Span::styled("  /        ", Style::default().fg(scheme.text)),
            Span::styled("Search nodes", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  t        ", Style::default().fg(scheme.text)),
            Span::styled(
                "Toggle transitive deps",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  h        ", Style::default().fg(scheme.text)),
            Span::styled(
                "Toggle highlight (diff)",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  y        ", Style::default().fg(scheme.text)),
            Span::styled(
                "Toggle cycle detection",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  b        ", Style::default().fg(scheme.text)),
            Span::styled("Toggle breadcrumbs", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  +/-      ", Style::default().fg(scheme.text)),
            Span::styled("Adjust depth limit", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  </>      ", Style::default().fg(scheme.text)),
            Span::styled("Adjust root limit", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  c        ", Style::default().fg(scheme.text)),
            Span::styled(
                "Jump to component view",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ?/Esc    ", Style::default().fg(scheme.text)),
            Span::styled("Close this help", Style::default().fg(scheme.text_muted)),
        ]),
    ];

    let help = Paragraph::new(help_lines)
        .block(
            Block::default()
                .title(" Keyboard Shortcuts ")
                .title_style(Style::default().fg(scheme.primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent))
                .style(Style::default().bg(scheme.background)),
        )
        .style(Style::default().bg(scheme.background));

    frame.render_widget(help, help_area);
}
