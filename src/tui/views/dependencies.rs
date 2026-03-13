//! Dependencies view with tree widget.

use crate::tui::app::{AppMode, DataContext};
use crate::tui::app_states::DependenciesState;
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
    if mode == AppMode::Diff {
        update_diff_mode_cache(deps, data);
    }
}

fn update_diff_mode_cache(deps: &mut DependenciesState, data: &DataContext) {
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
        }
    }
}

pub fn render_dependencies(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();

    // Caches and breadcrumbs are updated in prepare_render via update_graph_cache

    // Adjust context bar height based on search mode and breadcrumbs
    let is_searching = ctx.dependencies.is_searching();
    let has_search_query = ctx.dependencies.has_search_query();
    let show_breadcrumbs =
        ctx.dependencies.show_breadcrumbs && !ctx.dependencies.breadcrumb_trail.is_empty();

    let mut context_height = 3u16;
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

    // Context bar with options and selection info (compact 3-line layout)
    let selected = ctx.dependencies.selected;
    let total = ctx.dependencies.total;
    let expanded_count = ctx.dependencies.expanded_nodes.len();
    let max_depth = ctx.dependencies.max_depth;
    let max_roots = ctx.dependencies.max_roots;
    let show_cycles = ctx.dependencies.show_cycles;
    let cycle_count = ctx.dependencies.detected_cycles.len();
    let (root_overflow, depth_limited) = dependency_limit_info_ctx(ctx, max_roots, max_depth);

    // Use cached vulnerability components (O(1) lookup, no rebuild)
    let vuln_count = ctx.dependencies.cached_vuln_components.len();

    let is_diff_mode = ctx.mode == AppMode::Diff;

    // Line 1: Toggles + Depth/Roots (merged from old lines 1 & 2)
    let on_style = Style::default().fg(scheme.success).bold();
    let off_style = Style::default().fg(scheme.text_muted);
    let trans_style = if ctx.dependencies.show_transitive {
        on_style
    } else {
        off_style
    };
    let cycle_style = if show_cycles { on_style } else { off_style };
    let sort_order = ctx.dependencies.sort_order.display_name();

    let mut line1_spans = vec![
        Span::styled("[t]", Style::default().fg(scheme.accent)),
        Span::styled(
            if ctx.dependencies.show_transitive {
                " Trans:On"
            } else {
                " Trans:Off"
            },
            trans_style,
        ),
    ];

    if is_diff_mode {
        let hl_style = if ctx.dependencies.highlight_changes {
            on_style
        } else {
            off_style
        };
        line1_spans.push(Span::styled("  [h]", Style::default().fg(scheme.accent)));
        line1_spans.push(Span::styled(
            if ctx.dependencies.highlight_changes {
                " HL:On"
            } else {
                " HL:Off"
            },
            hl_style,
        ));
    }

    line1_spans.extend(vec![
        Span::styled("  [y]", Style::default().fg(scheme.accent)),
        Span::styled(
            if show_cycles {
                " Cycles:On"
            } else {
                " Cycles:Off"
            },
            cycle_style,
        ),
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

    let line1 = Line::from(line1_spans);

    // Line 2: Selection info + stats (merged from old line3 + hints)
    let mut line2_spans = vec![
        Span::styled(
            format!("{}/{}", if total > 0 { selected + 1 } else { 0 }, total),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled(" selected", Style::default().fg(scheme.text_muted)),
        Span::styled("  │  ", Style::default().fg(scheme.border)),
        Span::styled(
            format!("Expanded: {expanded_count}"),
            if expanded_count > 0 {
                Style::default().fg(scheme.success)
            } else {
                Style::default().fg(scheme.text_muted)
            },
        ),
    ];

    if vuln_count > 0 {
        line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line2_spans.push(Span::styled(
            format!("⚠ {vuln_count} vuln"),
            Style::default().fg(scheme.critical).bold(),
        ));
    }

    if show_cycles && cycle_count > 0 {
        line2_spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line2_spans.push(Span::styled(
            format!("⟳ {cycle_count}"),
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

    // Line 3: Key hints (compact)
    let line3 = Line::from(vec![
        Span::styled("[+/-]", Style::default().fg(scheme.accent)),
        Span::styled(" depth ", Style::default().fg(scheme.text_muted)),
        Span::styled("[</>]", Style::default().fg(scheme.accent)),
        Span::styled(" roots ", Style::default().fg(scheme.text_muted)),
        Span::styled("[s]", Style::default().fg(scheme.accent)),
        Span::styled(" sort ", Style::default().fg(scheme.text_muted)),
        Span::styled("[e/E]", Style::default().fg(scheme.accent)),
        Span::styled(" expand/collapse ", Style::default().fg(scheme.text_muted)),
        Span::styled("[?]", Style::default().fg(scheme.accent)),
        Span::styled(" help", Style::default().fg(scheme.text_muted)),
    ]);

    let mut context_lines = vec![line1, line2, line3];

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
            Span::styled("📍 ", Style::default().fg(scheme.accent)),
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
        AppMode::Diff => {
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
    let selected = ctx.dependencies.selected;
    let scroll_offset = ctx.dependencies.scroll_offset;

    // Only process lines in the visible range (virtual scrolling)
    let visible_start = scroll_offset;
    let visible_end = (scroll_offset + viewport_height).min(visible_nodes.len());

    let highlighted_lines: Vec<Line> = lines
        .into_iter()
        .enumerate()
        .skip(visible_start)
        .take(visible_end - visible_start)
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
            let (component_id, change_marker) = if let Some(pos) = raw_id.find(":+:") {
                (&raw_id[pos + 3..], Some("+"))
            } else if let Some(pos) = raw_id.find(":-:") {
                (&raw_id[pos + 3..], Some("-"))
            } else {
                (raw_id, None)
            };

            // Display name
            let display_name = ctx.dependencies.cached_display_names.get(component_id);

            if let Some(name) = display_name {
                lines.push(Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(name, Style::default().fg(scheme.text).bold()),
                ]));
            }

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

            // Look up component in SBOMs for rich details
            let component = find_component_in_sboms(component_id, ctx);

            if let Some(comp) = component {
                if let Some(ref ver) = comp.version {
                    lines.push(Line::from(vec![
                        Span::styled("Version: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(ver, Style::default().fg(scheme.text)),
                    ]));
                }

                lines.push(Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        format!("{:?}", comp.component_type),
                        Style::default().fg(scheme.text),
                    ),
                ]));

                if let Some(ref eco) = comp.ecosystem {
                    lines.push(Line::from(vec![
                        Span::styled("Ecosystem: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(format!("{eco:?}"), Style::default().fg(scheme.text)),
                    ]));
                }

                if let Some(ref purl) = comp.identifiers.purl
                    && purl != component_id
                {
                    lines.push(Line::from(vec![
                        Span::styled("PURL: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(purl, Style::default().fg(scheme.accent)),
                    ]));
                }

                if !comp.vulnerabilities.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("Vulns: ", Style::default().fg(scheme.text_muted)),
                        Span::styled(
                            format!("{}", comp.vulnerabilities.len()),
                            Style::default().fg(scheme.critical).bold(),
                        ),
                    ]));
                }
            }

            // Dependency counts from cached graphs
            let dep_count = ctx
                .dependencies
                .cached_graph
                .get(component_id)
                .map_or(0, Vec::len);
            let depended_on_count = ctx
                .dependencies
                .cached_reverse_graph
                .get(component_id)
                .map_or(0, Vec::len);

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Dependencies: ", Style::default().fg(scheme.text_muted)),
                Span::styled(dep_count.to_string(), Style::default().fg(scheme.primary)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Depended-on-by: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    depended_on_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
            ]));

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

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Details ")
                .title_style(Style::default().fg(scheme.primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .wrap(Wrap { trim: false });

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

        // Build added/removed lookup from result
        let mut added_by_source: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut removed_by_source: HashMap<&str, Vec<&str>> = HashMap::new();

        for dep in &result.dependencies.added {
            added_by_source.entry(&dep.from).or_default().push(&dep.to);
        }
        for dep in &result.dependencies.removed {
            removed_by_source
                .entry(&dep.from)
                .or_default()
                .push(&dep.to);
        }

        // Apply search filter if active
        let sources_to_show: Vec<&String> = if filter_mode && !search_matches.is_empty() {
            sources
                .iter()
                .filter(|s| search_matches.contains(*s))
                .take(max_roots)
                .collect()
        } else {
            sources.iter().take(max_roots).collect()
        };

        for (idx, source) in sources_to_show.iter().enumerate() {
            let source_str: &str = source;
            let added = added_by_source.get(source_str);
            let removed = removed_by_source.get(source_str);

            let child_count =
                added.map_or(0, std::vec::Vec::len) + removed.map_or(0, std::vec::Vec::len);
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
                Span::styled(
                    format!(" ({child_count})"),
                    Style::default().fg(scheme.text_muted),
                ),
            ];

            if source_has_vuln {
                spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
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
