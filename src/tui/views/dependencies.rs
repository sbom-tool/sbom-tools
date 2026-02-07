//! Dependencies view with tree widget.

use crate::tui::app::{App, AppMode};
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

/// Update the graph cache if needed (call before rendering)
pub fn update_graph_cache(app: &mut App) {
    match app.mode {
        AppMode::View => update_view_mode_cache(app),
        AppMode::Diff => update_diff_mode_cache(app),
        _ => {}
    }
}

fn update_view_mode_cache(app: &mut App) {
    if let Some(sbom) = &app.data.sbom {
        // Compute hash of current edges
        let edges: Vec<(String, String)> = sbom
            .edges
            .iter()
            .map(|e| (e.from.value().to_string(), e.to.value().to_string()))
            .collect();
        let new_hash = compute_graph_hash(&edges);

        // Check if cache needs refresh
        if app.tabs.dependencies.needs_cache_refresh(new_hash) {
            // Build graph structure
            let mut by_source: HashMap<String, Vec<String>> = HashMap::new();
            for (from, to) in &edges {
                by_source.entry(from.clone()).or_default().push(to.clone());
            }

            // Find root nodes
            let all_deps: HashSet<String> = by_source.values().flatten().cloned().collect();
            let mut sources: Vec<String> = by_source.keys().cloned().collect();
            sources.sort();
            let roots: Vec<String> = sources
                .into_iter()
                .filter(|s| !all_deps.contains(s))
                .collect();

            // Detect cycles
            if app.tabs.dependencies.show_cycles {
                let cycles = detect_cycles(&by_source);
                app.tabs.dependencies.update_cycle_cache(cycles);
            } else {
                app.tabs.dependencies.update_cycle_cache(Vec::new());
            }

            // Update graph cache
            app.tabs.dependencies.update_graph_cache(by_source, roots, new_hash);

            // Update transitive caches (direct deps, reverse graph, depths)
            app.tabs.dependencies.update_transitive_cache();

            // Update vulnerability cache
            let vuln_components: HashSet<String> = sbom
                .components
                .values()
                .filter(|c| !c.vulnerabilities.is_empty())
                .map(|c| c.name.clone())
                .collect();
            app.tabs.dependencies.update_vuln_cache(vuln_components);
        }
    }
}

fn update_diff_mode_cache(app: &mut App) {
    if let Some(result) = &app.data.diff_result {
        // Compute hash based on dependency changes
        let mut edges: Vec<(String, String)> = Vec::new();
        for dep in &result.dependencies.added {
            edges.push((dep.from.clone(), dep.to.clone()));
        }
        for dep in &result.dependencies.removed {
            edges.push((dep.from.clone(), dep.to.clone()));
        }
        edges.sort();
        let new_hash = compute_graph_hash(&edges);

        if app.tabs.dependencies.needs_cache_refresh(new_hash) {
            // Build graph for diff mode
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

            app.tabs.dependencies.update_graph_cache(by_source, sources, new_hash);

            // Update transitive caches (direct deps, reverse graph, depths)
            app.tabs.dependencies.update_transitive_cache();

            // Update vulnerability cache from diff result
            let vuln_components: HashSet<String> = result
                .vulnerabilities
                .introduced
                .iter()
                .chain(result.vulnerabilities.resolved.iter())
                .map(|v| v.component_name.clone())
                .collect();
            app.tabs.dependencies.update_vuln_cache(vuln_components);
        }
    }
}

/// Tree node for rendering
#[allow(dead_code)]
struct TreeNode {
    id: String,
    label: String,
    children: Vec<Self>,
    change_type: ChangeType,
    depth: usize,
}

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ChangeType {
    None,
    Added,
    Removed,
}

pub fn render_dependencies(frame: &mut Frame, area: Rect, app: &mut App) {
    let scheme = colors();

    // Update cache before rendering (only recomputes if data changed)
    update_graph_cache(app);

    // Update breadcrumbs based on current selection
    app.tabs.dependencies.update_breadcrumbs();

    // Adjust context bar height based on search mode and breadcrumbs
    let is_searching = app.tabs.dependencies.is_searching();
    let has_search_query = app.tabs.dependencies.has_search_query();
    let show_breadcrumbs = app.tabs.dependencies.show_breadcrumbs
        && !app.tabs.dependencies.breadcrumb_trail.is_empty();

    let mut context_height = 6u16;
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

    // Context bar with options and selection info
    let selected = app.tabs.dependencies.selected;
    let total = app.tabs.dependencies.total;
    let expanded_count = app.tabs.dependencies.expanded_nodes.len();
    let max_depth = app.tabs.dependencies.max_depth;
    let max_roots = app.tabs.dependencies.max_roots;
    let show_cycles = app.tabs.dependencies.show_cycles;
    let cycle_count = app.tabs.dependencies.detected_cycles.len();
    let (root_overflow, depth_limited) = dependency_limit_info_cached(app, max_roots, max_depth);

    // Use cached vulnerability components (O(1) lookup, no rebuild)
    let vuln_count = app.tabs.dependencies.cached_vuln_components.len();

    let is_diff_mode = app.mode == AppMode::Diff;

    let mut line1_spans = vec![
        Span::styled("[t]", Style::default().fg(scheme.accent)),
        Span::raw(" Transitive: "),
        Span::styled(
            if app.tabs.dependencies.show_transitive {
                "On"
            } else {
                "Off"
            },
            if app.tabs.dependencies.show_transitive {
                Style::default().fg(scheme.success).bold()
            } else {
                Style::default().fg(scheme.text_muted)
            },
        ),
    ];

    // Highlight changes only available in Diff mode
    if is_diff_mode {
        line1_spans.push(Span::styled("  ", Style::default().fg(scheme.border)));
        line1_spans.push(Span::styled("[h]", Style::default().fg(scheme.accent)));
        line1_spans.push(Span::raw(" Highlight: "));
        line1_spans.push(Span::styled(
            if app.tabs.dependencies.highlight_changes {
                "On"
            } else {
                "Off"
            },
            if app.tabs.dependencies.highlight_changes {
                Style::default().fg(scheme.success).bold()
            } else {
                Style::default().fg(scheme.text_muted)
            },
        ));
    }

    line1_spans.push(Span::styled("  ", Style::default().fg(scheme.border)));
    line1_spans.push(Span::styled("[y]", Style::default().fg(scheme.accent)));
    line1_spans.push(Span::raw(" Cycles: "));
    line1_spans.push(Span::styled(
        if show_cycles { "On" } else { "Off" },
        if show_cycles {
            Style::default().fg(scheme.success).bold()
        } else {
            Style::default().fg(scheme.text_muted)
        },
    ));

    let line1 = Line::from(line1_spans);

    let sort_order = app.tabs.dependencies.sort_order.display_name();
    let line2 = Line::from(vec![
        Span::styled("[+/-]", Style::default().fg(scheme.accent)),
        Span::raw(" Depth: "),
        Span::styled(
            format!("{max_depth}"),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled("  ", Style::default().fg(scheme.border)),
        Span::styled("[</>]", Style::default().fg(scheme.accent)),
        Span::raw(" Roots: "),
        Span::styled(
            format!("{max_roots}"),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled("  ", Style::default().fg(scheme.border)),
        Span::styled("[s]", Style::default().fg(scheme.accent)),
        Span::raw(" Sort: "),
        Span::styled(
            sort_order,
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled("  │  ", Style::default().fg(scheme.border)),
        Span::styled("[e/E]", Style::default().fg(scheme.accent)),
        Span::raw(" expand/collapse all  "),
        Span::styled("[?]", Style::default().fg(scheme.accent)),
        Span::raw(" help"),
    ]);

    let mut line3 = Vec::new();

    line3.push(Span::styled(
        "Item ",
        Style::default().fg(scheme.text_muted),
    ));
    line3.push(Span::styled(
        format!("{}/{}", if total > 0 { selected + 1 } else { 0 }, total),
        Style::default().fg(scheme.primary).bold(),
    ));
    line3.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
    line3.push(Span::styled(
        "Expanded: ",
        Style::default().fg(scheme.text_muted),
    ));
    line3.push(Span::styled(
        format!("{expanded_count}"),
        if expanded_count > 0 {
            Style::default().fg(scheme.success)
        } else {
            Style::default().fg(scheme.text_muted)
        },
    ));

    if vuln_count > 0 {
        line3.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line3.push(Span::styled(
            format!("⚠ {vuln_count} vuln"),
            Style::default().fg(scheme.critical).bold(),
        ));
    }

    if show_cycles && cycle_count > 0 {
        line3.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line3.push(Span::styled(
            format!("⟳ {cycle_count} cycles"),
            Style::default().fg(scheme.warning).bold(),
        ));
    }

    if root_overflow > 0 || depth_limited {
        line3.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        line3.push(Span::styled(
            "Limited: ",
            Style::default().fg(scheme.text_muted),
        ));
        if root_overflow > 0 {
            line3.push(Span::styled(
                format!("roots +{root_overflow}"),
                Style::default().fg(scheme.warning).bold(),
            ));
        }
        if root_overflow > 0 && depth_limited {
            line3.push(Span::styled(", ", Style::default().fg(scheme.text_muted)));
        }
        if depth_limited {
            line3.push(Span::styled(
                format!("depth >{max_depth}"),
                Style::default().fg(scheme.warning).bold(),
            ));
        }
    }

    let mut context_lines = vec![line1, line2, Line::from(line3)];

    // Add search bar if searching
    if is_searching {
        let query = &app.tabs.dependencies.search_query;
        let match_count = app.tabs.dependencies.search_matches.len();
        let filter_mode = app.tabs.dependencies.filter_mode;

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
    } else if app.tabs.dependencies.has_search_query() {
        // Show persistent search indicator when not actively searching
        let match_count = app.tabs.dependencies.search_matches.len();
        let filter_mode = app.tabs.dependencies.filter_mode;
        let query = &app.tabs.dependencies.search_query;

        let mut search_spans = vec![
            Span::styled("[/]", Style::default().fg(scheme.accent)),
            Span::styled(" Search: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("\"{query}\""), Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!(" ({match_count} matches)"),
                Style::default().fg(scheme.text_muted),
            ),
        ];

        if filter_mode {
            search_spans.push(Span::styled(" [filtered]", Style::default().fg(scheme.warning)));
        }

        search_spans.push(Span::styled("  ", Style::default()));
        search_spans.push(Span::styled("[Esc]", Style::default().fg(scheme.accent)));
        search_spans.push(Span::raw(" clear"));

        context_lines.push(Line::from(search_spans));
    }

    // Add breadcrumb bar if enabled and there's a trail
    if show_breadcrumbs {
        let breadcrumb_display = app.tabs.dependencies.get_breadcrumb_display();
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
    render_dependency_tree(frame, chunks[1], app);

    // Render help overlay if active
    if app.tabs.dependencies.show_deps_help {
        render_deps_help_overlay(frame, area);
    }
}

fn render_dependency_tree(frame: &mut Frame, area: Rect, app: &mut App) {
    let scheme = colors();

    // Split into main area and scrollbar
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    let tree_area = chunks[0];

    // Update viewport height for virtual scrolling
    let viewport_height = tree_area.height.saturating_sub(2) as usize;
    app.tabs.dependencies.update_viewport(viewport_height);

    let mut lines: Vec<Line> = vec![];
    let mut visible_nodes: Vec<String> = vec![];

    // Get search state (clone to avoid borrow issues)
    let search_matches = app.tabs.dependencies.search_matches.clone();
    let filter_mode = app.tabs.dependencies.filter_mode;
    let has_search = !search_matches.is_empty();

    // Clone cached vulnerability components to avoid borrow issues
    let vuln_components = app.tabs.dependencies.cached_vuln_components.clone();

    match app.mode {
        AppMode::Diff => {
            render_diff_tree_cached(
                &mut lines,
                &mut visible_nodes,
                app,
                tree_area.width as usize,
                &vuln_components,
                &search_matches,
                filter_mode,
            );
        }
        AppMode::View => {
            render_view_tree_cached(
                &mut lines,
                &mut visible_nodes,
                app,
                tree_area.width as usize,
                &vuln_components,
                &search_matches,
                filter_mode,
            );
        }
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }

    // Update state with visible nodes
    app.tabs.dependencies.set_visible_nodes(visible_nodes.clone());

    // Adjust scroll to keep selection visible
    app.tabs.dependencies.adjust_scroll_to_selection();

    // Apply selection and search highlighting with virtual scrolling
    let selected = app.tabs.dependencies.selected;
    let scroll_offset = app.tabs.dependencies.scroll_offset;

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
            let is_match = node_id
                .is_some_and(|id| has_search && search_matches.contains(id));

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
    let paragraph = Paragraph::new(highlighted_lines)
        .block(
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
}

#[allow(dead_code)]
fn render_diff_tree(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    app: &App,
    max_width: usize,
    vuln_components: &HashSet<String>,
    search_matches: &HashSet<String>,
    filter_mode: bool,
) {
    let scheme = colors();
    let max_roots = app.tabs.dependencies.max_roots;
    let highlight = app.tabs.dependencies.highlight_changes;

    if let Some(result) = &app.data.diff_result {
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

        // Group dependencies by source component
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

        // Get all unique source components
        let mut all_sources: HashSet<&str> = HashSet::new();
        all_sources.extend(added_by_source.keys());
        all_sources.extend(removed_by_source.keys());

        let mut sources: Vec<_> = all_sources.into_iter().collect();
        sources.sort_unstable();

        let expanded = &app.tabs.dependencies.expanded_nodes;

        // Apply search filter if active
        let sources_to_show: Vec<_> = if filter_mode && !search_matches.is_empty() {
            sources
                .iter()
                .filter(|s| search_matches.contains(**s))
                .take(max_roots)
                .collect()
        } else {
            sources.iter().take(max_roots).collect()
        };

        for (idx, source) in sources_to_show.iter().enumerate() {
            let added = added_by_source.get(**source);
            let removed = removed_by_source.get(**source);

            let child_count = added.map_or(0, std::vec::Vec::len) + removed.map_or(0, std::vec::Vec::len);
            let is_expanded = expanded.contains(**source);
            let is_last = idx == sources_to_show.len() - 1;

            // Check for vulnerabilities
            let source_has_vuln = vuln_components.contains(**source);

            // Tree branch characters
            let branch = if is_last { "└─" } else { "├─" };
            let expand_icon = if is_expanded { "▼" } else { "▶" };

            // Determine color based on changes
            let source_style = if highlight {
                if added.is_some() && removed.is_some() {
                    Style::default().fg(scheme.modified) // Both added and removed
                } else if added.is_some() {
                    Style::default().fg(scheme.added)
                } else {
                    Style::default().fg(scheme.removed)
                }
            } else {
                Style::default().fg(scheme.text)
            };

            // Source component line
            let short_source = truncate_component(source, max_width - 20);
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

            // Add vulnerability indicator
            if source_has_vuln {
                spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
            }

            lines.push(Line::from(spans));
            visible_nodes.push((**source).to_string());

            // Children if expanded
            if is_expanded {
                let prefix = if is_last { "   " } else { "│  " };

                // Added dependencies
                if let Some(added_deps) = added {
                    for (i, dep) in added_deps.iter().enumerate() {
                        let is_last_child = removed.is_none() && i == added_deps.len() - 1;
                        let child_branch = if is_last_child { "└─" } else { "├─" };
                        let short_dep = truncate_component(dep, max_width - 25);
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
                        visible_nodes.push(format!("{}:+:{}", **source, dep));
                    }
                }

                // Removed dependencies
                if let Some(removed_deps) = removed {
                    for (i, dep) in removed_deps.iter().enumerate() {
                        let is_last_child = i == removed_deps.len() - 1;
                        let child_branch = if is_last_child { "└─" } else { "├─" };
                        let short_dep = truncate_component(dep, max_width - 25);
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
                        visible_nodes.push(format!("{}:-:{}", **source, dep));
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

#[allow(dead_code)]
fn render_view_tree(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    app: &mut App,
    max_width: usize,
    vuln_components: &HashSet<String>,
    search_matches: &HashSet<String>,
    filter_mode: bool,
) {
    let scheme = colors();
    let max_roots = app.tabs.dependencies.max_roots;
    let max_depth = app.tabs.dependencies.max_depth;
    let show_cycles = app.tabs.dependencies.show_cycles;
    let _has_search = !search_matches.is_empty();

    if let Some(sbom) = &app.data.sbom {
        // Build tree from edges - group by source
        let mut by_source: HashMap<String, Vec<String>> = HashMap::new();

        for edge in &sbom.edges {
            by_source
                .entry(edge.from.value().to_string())
                .or_default()
                .push(edge.to.value().to_string());
        }

        // Detect cycles if enabled
        let cycles_in_deps: HashSet<String> = if show_cycles {
            let cycles = detect_cycles(&by_source);
            app.tabs.dependencies.detected_cycles.clone_from(&cycles);
            cycles.into_iter().flatten().collect()
        } else {
            app.tabs.dependencies.detected_cycles.clear();
            HashSet::new()
        };

        // Summary
        lines.push(Line::from(vec![
            Span::styled("Total: ", Style::default().fg(scheme.text).bold()),
            Span::styled(
                format!("{} dependencies", sbom.edges.len()),
                Style::default().fg(scheme.primary).bold(),
            ),
            if cycles_in_deps.is_empty() {
                Span::raw("")
            } else {
                Span::styled(
                    format!("  (⟳ {} in cycles)", cycles_in_deps.len()),
                    Style::default().fg(scheme.warning),
                )
            },
        ]));
        visible_nodes.push("__header__".to_string());
        lines.push(Line::raw(""));
        visible_nodes.push("__spacer__".to_string());

        let mut sources: Vec<_> = by_source.keys().cloned().collect();
        sources.sort();
        let has_sources = !sources.is_empty();

        let expanded = &app.tabs.dependencies.expanded_nodes;

        // Root components (components that are not dependencies of others)
        let all_deps: HashSet<_> = by_source.values().flatten().cloned().collect();
        let mut roots: Vec<String> = sources
            .iter()
            .filter(|s| !all_deps.contains(*s))
            .cloned()
            .collect();

        // Apply search filter if active
        if filter_mode && !search_matches.is_empty() {
            roots.retain(|r| search_matches.contains(r));
        }

        let mut flat_view = false;
        if roots.is_empty() && has_sources {
            flat_view = true;
            lines.push(Line::styled(
                "Dependencies (flat view):",
                Style::default().fg(scheme.primary),
            ));
            visible_nodes.push("__flat_header__".to_string());
            let source_roots: Vec<String> = if filter_mode && !search_matches.is_empty() {
                sources
                    .iter()
                    .filter(|s| search_matches.contains(*s))
                    .take(max_roots)
                    .cloned()
                    .collect()
            } else {
                sources.iter().take(max_roots).cloned().collect()
            };
            roots = source_roots;
        } else {
            roots.truncate(max_roots);
        }

        let mut path = Vec::new();
        for (idx, source) in roots.iter().enumerate() {
            let is_last = idx == roots.len().saturating_sub(1);
            render_view_node(
                lines,
                visible_nodes,
                source,
                &by_source,
                expanded,
                &[],
                is_last,
                1,
                max_depth,
                max_width,
                &scheme,
                vuln_components,
                &cycles_in_deps,
                show_cycles,
                &mut path,
            );
        }

        if flat_view && roots.is_empty() && has_sources {
            lines.push(Line::styled(
                "No dependency roots found",
                Style::default().fg(scheme.text_muted),
            ));
            visible_nodes.push("__flat_empty__".to_string());
        }

        if sbom.edges.is_empty() {
            lines.push(Line::styled(
                "No dependencies found",
                Style::default().fg(scheme.text_muted),
            ));
            visible_nodes.push("__empty__".to_string());
        }
    }
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn render_view_node(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    node_id: &str,
    by_source: &HashMap<String, Vec<String>>,
    expanded: &HashSet<String>,
    ancestors_last: &[bool],
    is_last: bool,
    depth: usize,
    max_depth: usize,
    max_width: usize,
    scheme: &crate::tui::theme::ColorScheme,
    vuln_components: &HashSet<String>,
    cycles_in_deps: &HashSet<String>,
    show_cycles: bool,
    path: &mut Vec<String>,
) {
    let children = by_source.get(node_id);
    let child_count = children.map_or(0, std::vec::Vec::len);
    let is_expanded = expanded.contains(node_id);

    render_view_node_line(
        lines,
        visible_nodes,
        node_id,
        child_count,
        is_expanded,
        ancestors_last,
        is_last,
        depth,
        max_width,
        scheme,
        vuln_components,
        cycles_in_deps,
        show_cycles,
        false,
    );

    if child_count == 0 || !is_expanded || depth >= max_depth {
        return;
    }

    path.push(node_id.to_string());
    if let Some(children) = children {
        for (i, child) in children.iter().enumerate() {
            let is_last_child = i == children.len().saturating_sub(1);
            let mut next_ancestors = ancestors_last.to_vec();
            next_ancestors.push(is_last);
            let is_cycle_ref = path.iter().any(|ancestor| ancestor == child);

            if is_cycle_ref {
                let grand_child_count = by_source.get(child).map_or(0, std::vec::Vec::len);
                render_view_node_line(
                    lines,
                    visible_nodes,
                    child,
                    grand_child_count,
                    false,
                    &next_ancestors,
                    is_last_child,
                    depth + 1,
                    max_width,
                    scheme,
                    vuln_components,
                    cycles_in_deps,
                    show_cycles,
                    true,
                );
                continue;
            }

            render_view_node(
                lines,
                visible_nodes,
                child,
                by_source,
                expanded,
                &next_ancestors,
                is_last_child,
                depth + 1,
                max_depth,
                max_width,
                scheme,
                vuln_components,
                cycles_in_deps,
                show_cycles,
                path,
            );
        }
    }
    path.pop();
}

#[allow(clippy::too_many_arguments)]
fn render_view_node_line(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    node_id: &str,
    child_count: usize,
    is_expanded: bool,
    ancestors_last: &[bool],
    is_last: bool,
    depth: usize,
    max_width: usize,
    scheme: &crate::tui::theme::ColorScheme,
    vuln_components: &HashSet<String>,
    cycles_in_deps: &HashSet<String>,
    show_cycles: bool,
    cycle_ref: bool,
) {
    let mut prefix = String::new();
    for last in ancestors_last {
        if *last {
            prefix.push_str("   ");
        } else {
            prefix.push_str("│  ");
        }
    }
    prefix.push_str(if is_last { "└─" } else { "├─" });

    let expand_icon = if cycle_ref {
        "⟳"
    } else if child_count > 0 {
        if is_expanded {
            "▼"
        } else {
            "▶"
        }
    } else {
        "─"
    };

    let name_budget = max_width.saturating_sub(prefix.len() + 6);
    let short_name = truncate_component(node_id, name_budget.max(6));
    let has_vuln = vuln_components.contains(node_id);
    let in_cycle = cycles_in_deps.contains(node_id) || cycle_ref;

    let name_style = if cycle_ref {
        Style::default().fg(scheme.warning)
    } else if depth == 1 {
        Style::default().fg(scheme.text).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let mut spans = vec![
        Span::styled(prefix, Style::default().fg(scheme.border)),
        Span::styled(
            expand_icon,
            Style::default().fg(if child_count > 0 {
                scheme.accent
            } else {
                scheme.text_muted
            }),
        ),
        Span::raw(" "),
        Span::styled(short_name, name_style),
    ];

    if child_count > 0 && !cycle_ref {
        spans.push(Span::styled(
            format!(" ({child_count})"),
            Style::default().fg(scheme.text_muted),
        ));
    }

    if has_vuln {
        spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
    }

    if show_cycles && in_cycle {
        spans.push(Span::styled(" ⟳", Style::default().fg(scheme.warning)));
    }

    lines.push(Line::from(spans));
    visible_nodes.push(node_id.to_string());
}

// === CACHED VERSIONS OF RENDER FUNCTIONS ===
// These use the cached graph structure and avoid rebuilding on every frame

/// Cached version of `render_diff_tree` - uses cached graph structure
fn render_diff_tree_cached(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    app: &App,
    max_width: usize,
    vuln_components: &HashSet<String>,
    search_matches: &HashSet<String>,
    filter_mode: bool,
) {
    let scheme = colors();
    let max_roots = app.tabs.dependencies.max_roots;
    let highlight = app.tabs.dependencies.highlight_changes;

    if let Some(result) = &app.data.diff_result {
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
        let sources = &app.tabs.dependencies.cached_roots;
        let expanded = &app.tabs.dependencies.expanded_nodes;

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

            let child_count = added.map_or(0, std::vec::Vec::len) + removed.map_or(0, std::vec::Vec::len);
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

            let short_source = truncate_component(source, max_width - 20);
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
                        let short_dep = truncate_component(dep, max_width - 25);
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
                            dep_spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
                        }

                        lines.push(Line::from(dep_spans));
                        visible_nodes.push(format!("{source}:+:{dep}"));
                    }
                }

                if let Some(removed_deps) = removed {
                    for (i, dep) in removed_deps.iter().enumerate() {
                        let is_last_child = i == removed_deps.len() - 1;
                        let child_branch = if is_last_child { "└─" } else { "├─" };
                        let short_dep = truncate_component(dep, max_width - 25);
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
                            dep_spans.push(Span::styled(" ⚠", Style::default().fg(scheme.critical)));
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

/// Cached version of `render_view_tree` - uses cached graph and cycle nodes
fn render_view_tree_cached(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    app: &App,
    max_width: usize,
    vuln_components: &HashSet<String>,
    search_matches: &HashSet<String>,
    filter_mode: bool,
) {
    use crate::tui::app_states::DependencySort;

    let scheme = colors();
    let max_roots = app.tabs.dependencies.max_roots;
    let max_depth = app.tabs.dependencies.max_depth;
    let show_cycles = app.tabs.dependencies.show_cycles;
    let show_transitive = app.tabs.dependencies.show_transitive;
    let sort_order = app.tabs.dependencies.sort_order;

    // Use cached graph structure
    let by_source = &app.tabs.dependencies.cached_graph;
    let cached_roots = &app.tabs.dependencies.cached_roots;
    let cycles_in_deps = &app.tabs.dependencies.cached_cycle_nodes;
    let cached_depths = &app.tabs.dependencies.cached_depths;
    let cached_reverse_graph = &app.tabs.dependencies.cached_reverse_graph;

    if by_source.is_empty() && app.data.sbom.is_none() {
        return;
    }

    // Get edge count from SBOM for summary
    let edge_count = app.data.sbom.as_ref().map_or(0, |s| s.edges.len());

    // Summary
    lines.push(Line::from(vec![
        Span::styled("Total: ", Style::default().fg(scheme.text).bold()),
        Span::styled(
            format!("{edge_count} dependencies"),
            Style::default().fg(scheme.primary).bold(),
        ),
        if show_cycles && !cycles_in_deps.is_empty() {
            Span::styled(
                format!("  (⟳ {} in cycles)", cycles_in_deps.len()),
                Style::default().fg(scheme.warning),
            )
        } else {
            Span::raw("")
        },
    ]));
    visible_nodes.push("__header__".to_string());
    lines.push(Line::raw(""));
    visible_nodes.push("__spacer__".to_string());

    let has_sources = !by_source.is_empty();
    let expanded = &app.tabs.dependencies.expanded_nodes;

    // Apply search filter to roots
    let mut roots: Vec<String> = if filter_mode && !search_matches.is_empty() {
        cached_roots
            .iter()
            .filter(|r| search_matches.contains(*r))
            .cloned()
            .collect()
    } else {
        cached_roots.clone()
    };

    let mut flat_view = false;
    if roots.is_empty() && has_sources {
        flat_view = true;
        lines.push(Line::styled(
            "Dependencies (flat view):",
            Style::default().fg(scheme.primary),
        ));
        visible_nodes.push("__flat_header__".to_string());

        // Use sources as roots in flat view
        let sources: Vec<String> = by_source.keys().cloned().collect();
        roots = if filter_mode && !search_matches.is_empty() {
            sources
                .into_iter()
                .filter(|s| search_matches.contains(s))
                .take(max_roots)
                .collect()
        } else {
            sources.into_iter().take(max_roots).collect()
        };
    } else {
        roots.truncate(max_roots);
    }

    // Sort roots based on sort_order
    match sort_order {
        DependencySort::Name => roots.sort(),
        DependencySort::Depth => {
            roots.sort_by(|a, b| {
                let depth_a = cached_depths.get(a).copied().unwrap_or(0);
                let depth_b = cached_depths.get(b).copied().unwrap_or(0);
                depth_a.cmp(&depth_b).then_with(|| a.cmp(b))
            });
        }
        DependencySort::VulnCount => {
            roots.sort_by(|a, b| {
                let vuln_a = i32::from(vuln_components.contains(a));
                let vuln_b = i32::from(vuln_components.contains(b));
                // Sort vulnerable first (descending), then by name
                vuln_b.cmp(&vuln_a).then_with(|| a.cmp(b))
            });
        }
        DependencySort::DependentCount => {
            roots.sort_by(|a, b| {
                let count_a = cached_reverse_graph.get(a).map_or(0, std::vec::Vec::len);
                let count_b = cached_reverse_graph.get(b).map_or(0, std::vec::Vec::len);
                // Sort by most dependents first, then by name
                count_b.cmp(&count_a).then_with(|| a.cmp(b))
            });
        }
    }

    let mut path = Vec::new();
    for (idx, source) in roots.iter().enumerate() {
        let is_last = idx == roots.len().saturating_sub(1);
        render_view_node_cached(
            lines,
            visible_nodes,
            source,
            by_source,
            expanded,
            &[],
            is_last,
            1,
            max_depth,
            max_width,
            &scheme,
            vuln_components,
            cycles_in_deps,
            show_cycles,
            show_transitive,
            &mut path,
        );
    }

    if flat_view && roots.is_empty() && has_sources {
        lines.push(Line::styled(
            "No dependency roots found",
            Style::default().fg(scheme.text_muted),
        ));
        visible_nodes.push("__flat_empty__".to_string());
    }

    if !has_sources && app.data.sbom.is_some() {
        lines.push(Line::styled(
            "No dependencies found",
            Style::default().fg(scheme.text_muted),
        ));
        visible_nodes.push("__empty__".to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn render_view_node_cached(
    lines: &mut Vec<Line>,
    visible_nodes: &mut Vec<String>,
    node_id: &str,
    by_source: &HashMap<String, Vec<String>>,
    expanded: &HashSet<String>,
    ancestors_last: &[bool],
    is_last: bool,
    depth: usize,
    max_depth: usize,
    max_width: usize,
    scheme: &crate::tui::theme::ColorScheme,
    vuln_components: &HashSet<String>,
    cycles_in_deps: &HashSet<String>,
    show_cycles: bool,
    show_transitive: bool,
    path: &mut Vec<String>,
) {
    let children = by_source.get(node_id);
    let child_count = children.map_or(0, std::vec::Vec::len);
    let is_expanded = expanded.contains(node_id);

    // When show_transitive is false, adjust child_count display for non-root nodes
    // Depth 1 = root nodes, depth 2 = direct deps (show these), depth > 2 = transitive (hide if show_transitive=false)
    let effective_child_count = if !show_transitive && depth > 1 {
        0 // Don't show expansion indicator for transitive deps when hidden
    } else {
        child_count
    };

    render_view_node_line(
        lines,
        visible_nodes,
        node_id,
        effective_child_count,
        is_expanded,
        ancestors_last,
        is_last,
        depth,
        max_width,
        scheme,
        vuln_components,
        cycles_in_deps,
        show_cycles,
        false,
    );

    // Skip rendering children if:
    // - No children
    // - Not expanded
    // - Depth limit reached
    // - show_transitive is false and we're past depth 1 (only show direct deps)
    if child_count == 0 || !is_expanded || depth >= max_depth {
        return;
    }

    // When show_transitive is false, only show depth 1 (direct dependencies)
    // Depth 1 = roots, depth 2 = direct deps of roots
    if !show_transitive && depth > 1 {
        return;
    }

    path.push(node_id.to_string());
    if let Some(children) = children {
        for (i, child) in children.iter().enumerate() {
            let is_last_child = i == children.len().saturating_sub(1);
            let mut next_ancestors = ancestors_last.to_vec();
            next_ancestors.push(is_last);
            let is_cycle_ref = path.iter().any(|ancestor| ancestor == child);

            if is_cycle_ref {
                let grand_child_count = by_source.get(child).map_or(0, std::vec::Vec::len);
                render_view_node_line(
                    lines,
                    visible_nodes,
                    child,
                    grand_child_count,
                    false,
                    &next_ancestors,
                    is_last_child,
                    depth + 1,
                    max_width,
                    scheme,
                    vuln_components,
                    cycles_in_deps,
                    show_cycles,
                    true,
                );
                continue;
            }

            render_view_node_cached(
                lines,
                visible_nodes,
                child,
                by_source,
                expanded,
                &next_ancestors,
                is_last_child,
                depth + 1,
                max_depth,
                max_width,
                scheme,
                vuln_components,
                cycles_in_deps,
                show_cycles,
                show_transitive,
                path,
            );
        }
    }
    path.pop();
}

/// Cached version of `dependency_limit_info` - uses cached graph structure
fn dependency_limit_info_cached(app: &App, max_roots: usize, max_depth: usize) -> (usize, bool) {
    let roots = &app.tabs.dependencies.cached_roots;
    let graph = &app.tabs.dependencies.cached_graph;

    if graph.is_empty() {
        return (0, false);
    }

    let root_overflow = roots.len().saturating_sub(max_roots);
    let depth_limited = depth_exceeds_limit(graph, roots, max_depth);

    (root_overflow, depth_limited)
}

#[allow(dead_code)]
fn dependency_limit_info(app: &App, max_roots: usize, max_depth: usize) -> (usize, bool) {
    match app.mode {
        AppMode::Diff => {
            let mut sources: HashSet<&str> = HashSet::new();
            if let Some(result) = &app.data.diff_result {
                for dep in &result.dependencies.added {
                    sources.insert(dep.from.as_str());
                }
                for dep in &result.dependencies.removed {
                    sources.insert(dep.from.as_str());
                }
            }
            (sources.len().saturating_sub(max_roots), false)
        }
        AppMode::View => {
            let mut by_source: HashMap<String, Vec<String>> = HashMap::new();
            if let Some(sbom) = &app.data.sbom {
                for edge in &sbom.edges {
                    by_source
                        .entry(edge.from.value().to_string())
                        .or_default()
                        .push(edge.to.value().to_string());
                }
            }

            if by_source.is_empty() {
                return (0, false);
            }

            let mut sources: Vec<String> = by_source.keys().cloned().collect();
            sources.sort();

            let all_deps: HashSet<String> = by_source.values().flatten().cloned().collect();
            let roots: Vec<String> = sources
                .into_iter()
                .filter(|s| !all_deps.contains(s))
                .collect();

            let root_overflow = roots.len().saturating_sub(max_roots);
            let depth_limited = depth_exceeds_limit(&by_source, &roots, max_depth);

            (root_overflow, depth_limited)
        }
        _ => (0, false),
    }
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
        if seen_depth.get(node.as_str()).is_some_and(|&seen| seen >= depth) {
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

/// Truncate component ID to fit width, preferring name@version over full PURL
fn truncate_component(id: &str, max_width: usize) -> String {
    // Try to extract name@version from PURL
    if id.starts_with("pkg:") {
        if let Some(rest) = id.strip_prefix("pkg:") {
            // Find the part after the ecosystem/
            if let Some(slash_pos) = rest.find('/') {
                let name_ver = &rest[slash_pos + 1..];
                // Remove any query params
                let clean = name_ver.split('?').next().unwrap_or(name_ver);
                if clean.len() <= max_width {
                    return clean.to_string();
                }
            }
        }
    }

    // Truncate with ellipsis
    if id.len() <= max_width {
        id.to_string()
    } else if max_width > 3 {
        format!("{}...", &id[..max_width - 3])
    } else {
        id[..max_width].to_string()
    }
}

/// Detect circular dependencies in a dependency graph.
/// Returns a list of cycles, where each cycle is a vector of node IDs.
fn detect_cycles(graph: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    fn dfs(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = graph.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    dfs(neighbor, graph, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(neighbor) {
                    // Found a cycle - extract it from path
                    if let Some(start_idx) = path.iter().position(|n| n == neighbor) {
                        let cycle: Vec<String> = path[start_idx..].to_vec();
                        if !cycle.is_empty() && cycles.len() < 10 {
                            // Limit to 10 cycles
                            cycles.push(cycle);
                        }
                    }
                }
            }
        }

        path.pop();
        rec_stack.remove(node);
    }

    let mut cycles: Vec<Vec<String>> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut rec_stack: HashSet<String> = HashSet::new();
    let mut path: Vec<String> = Vec::new();

    // Start DFS from each unvisited node
    for node in graph.keys() {
        if !visited.contains(node) {
            dfs(
                node,
                graph,
                &mut visited,
                &mut rec_stack,
                &mut path,
                &mut cycles,
            );
        }
    }

    cycles
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
    let help_area = Rect::new(x, y, help_width.min(area.width), help_height.min(area.height));

    // Clear the background
    frame.render_widget(Clear, help_area);

    let help_lines = vec![
        Line::from(Span::styled(
            "Dependencies View Shortcuts",
            Style::default().fg(scheme.primary).bold(),
        )),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Navigation", Style::default().fg(scheme.accent).bold()),
        ]),
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
        Line::from(vec![
            Span::styled("Tree Controls", Style::default().fg(scheme.accent).bold()),
        ]),
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
        Line::from(vec![
            Span::styled("Display Options", Style::default().fg(scheme.accent).bold()),
        ]),
        Line::from(vec![
            Span::styled("  /        ", Style::default().fg(scheme.text)),
            Span::styled("Search nodes", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  t        ", Style::default().fg(scheme.text)),
            Span::styled("Toggle transitive deps", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  h        ", Style::default().fg(scheme.text)),
            Span::styled("Toggle highlight (diff)", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  y        ", Style::default().fg(scheme.text)),
            Span::styled("Toggle cycle detection", Style::default().fg(scheme.text_muted)),
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
            Span::styled("Jump to component view", Style::default().fg(scheme.text_muted)),
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
