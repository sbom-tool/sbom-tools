//! Tree view for ViewApp - hierarchical component navigation.

use crate::model::Component;
use crate::tui::theme::colors;
use crate::tui::view::app::{ComponentDetailTab, FocusPanel, ViewApp};
use crate::tui::widgets::{truncate_str, SeverityBadge, Tree};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render_tree(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    // Split into tree (left) and detail (right) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_tree_panel(frame, chunks[0], app);
    render_detail_panel(frame, chunks[1], app);
}

fn render_tree_panel(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(5)])
        .split(area);

    // Filter/group bar
    render_filter_bar(frame, chunks[0], app);

    // Tree
    let nodes = app.build_tree_nodes();
    let scheme = colors();

    let border_color = if app.focus_panel == FocusPanel::Left {
        scheme.border_focused
    } else {
        scheme.border
    };

    let tree = Tree::new(&nodes)
        .block(
            Block::default()
                .title(format!(" Components ({}) ", app.stats.component_count))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(tree, chunks[1], &mut app.tree_state);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();

    // If search is active, show search input
    if app.tree_search_active {
        let cursor = if app.tick % 10 < 5 { "▌" } else { " " };
        let spans = vec![
            Span::styled("Search: ", Style::default().fg(scheme.accent).bold()),
            Span::styled(
                format!("{}{}", app.tree_search_query, cursor),
                Style::default().fg(scheme.text).bg(scheme.selection),
            ),
            Span::raw("  "),
            Span::styled("[Esc]", Style::default().fg(scheme.text_muted)),
            Span::styled(" cancel  ", Style::default().fg(scheme.text_muted)),
            Span::styled("[Enter]", Style::default().fg(scheme.text_muted)),
            Span::styled(" done", Style::default().fg(scheme.text_muted)),
        ];
        let para = Paragraph::new(Line::from(spans));
        frame.render_widget(para, area);
        return;
    }

    let mut spans = vec![
        Span::styled("Group: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {} ", app.tree_group_by.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Filter: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {} ", app.tree_filter.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.highlight)
                .bold(),
        ),
    ];

    // Show search query if present
    if !app.tree_search_query.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("Search: ", Style::default().fg(scheme.text_muted)));
        spans.push(Span::styled(
            format!("\"{}\"", app.tree_search_query),
            Style::default().fg(scheme.info),
        ));
    }

    spans.push(Span::raw("  │  "));
    spans.push(Span::styled("[/]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" search  "));
    spans.push(Span::styled("[g]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" group  "));
    spans.push(Span::styled("[f]", Style::default().fg(scheme.accent)));
    spans.push(Span::raw(" filter"));

    let para = Paragraph::new(Line::from(spans));
    frame.render_widget(para, area);
}

fn render_detail_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let border_color = if app.focus_panel == FocusPanel::Right {
        scheme.primary
    } else {
        scheme.border
    };

    if let Some(comp) = app.get_selected_component() {
        // Split area for tab bar and content
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Tab bar
                Constraint::Min(5),    // Tab content
            ])
            .split(area);

        render_component_tab_bar(frame, chunks[0], app);

        // Render tab content based on selected tab
        match app.component_tab {
            ComponentDetailTab::Overview => {
                render_overview_tab(frame, chunks[1], comp, border_color);
            }
            ComponentDetailTab::Identifiers => {
                render_identifiers_tab(frame, chunks[1], comp, border_color);
            }
            ComponentDetailTab::Vulnerabilities => {
                render_vulnerabilities_tab(frame, chunks[1], comp, border_color);
            }
            ComponentDetailTab::Dependencies => {
                render_dependencies_tab(frame, chunks[1], app, comp, border_color);
            }
        }
    } else {
        // No component selected - show quick stats overview
        render_component_stats_panel(frame, area, app, scheme.border);
    }
}

fn render_component_tab_bar(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let tabs = ComponentDetailTab::all();
    let selected_idx = match app.component_tab {
        ComponentDetailTab::Overview => 0,
        ComponentDetailTab::Identifiers => 1,
        ComponentDetailTab::Vulnerabilities => 2,
        ComponentDetailTab::Dependencies => 3,
    };

    let mut spans = Vec::new();
    for (i, tab) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(scheme.border)));
        }
        let is_selected = i == selected_idx;
        let key_style = if is_selected {
            Style::default().fg(scheme.accent).bold()
        } else {
            Style::default().fg(scheme.text_muted)
        };
        let label_style = if is_selected {
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold()
        } else {
            Style::default().fg(scheme.text_muted)
        };

        spans.push(Span::styled(format!("[{}]", tab.shortcut()), key_style));
        spans.push(Span::styled(format!(" {} ", tab.title()), label_style));
    }

    spans.push(Span::styled("  ", Style::default()));
    spans.push(Span::styled("[[]/[]]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        " cycle",
        Style::default().fg(scheme.text_muted),
    ));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Render the Overview tab - basic component info
fn render_overview_tab(frame: &mut Frame, area: Rect, comp: &Component, border_color: Color) {
    let scheme = colors();
    let mut lines = vec![];

    // Component name
    lines.push(Line::from(vec![Span::styled(
        &comp.name,
        Style::default().fg(scheme.text).bold(),
    )]));

    // Version
    if let Some(ver) = &comp.version {
        lines.push(Line::from(vec![
            Span::styled("Version: ", Style::default().fg(scheme.text_muted)),
            Span::styled(ver, Style::default().fg(scheme.accent)),
        ]));
    }

    // Ecosystem
    if let Some(eco) = &comp.ecosystem {
        lines.push(Line::from(vec![
            Span::styled("Ecosystem: ", Style::default().fg(scheme.text_muted)),
            Span::styled(eco.to_string(), Style::default().fg(scheme.success)),
        ]));
    }

    // Type
    lines.push(Line::from(vec![
        Span::styled("Type: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            comp.component_type.to_string(),
            Style::default().fg(scheme.highlight),
        ),
    ]));

    // Supplier
    if let Some(supplier) = &comp.supplier {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Supplier:",
            Style::default().fg(scheme.accent).bold(),
        ));
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::raw(&supplier.name),
        ]));
        if let Some(url) = supplier.urls.first() {
            lines.push(Line::from(vec![
                Span::styled("  URL: ", Style::default().fg(scheme.text_muted)),
                Span::styled(url, Style::default().fg(scheme.info)),
            ]));
        }
    }

    // Licenses summary
    if !comp.licenses.declared.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Licenses:",
            Style::default().fg(scheme.success).bold(),
        ));
        for lic in comp.licenses.declared.iter().take(3) {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(scheme.text_muted)),
                Span::raw(&lic.expression),
            ]));
        }
        if comp.licenses.declared.len() > 3 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more", comp.licenses.declared.len() - 3),
                Style::default().fg(scheme.text_muted),
            )]));
        }
    }

    // Vulnerability summary
    if !comp.vulnerabilities.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                "Vulnerabilities: ",
                Style::default().fg(scheme.critical).bold(),
            ),
            Span::styled(
                format!("{}", comp.vulnerabilities.len()),
                Style::default().fg(scheme.critical).bold(),
            ),
            Span::styled(
                " (see [3] Vulnerabilities tab)",
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    // VEX status
    if let Some(vex) = &comp.vex_status {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("VEX Status: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                vex.status.to_string(),
                Style::default().fg(scheme.highlight).bold(),
            ),
        ]));
        if let Some(just) = &vex.justification {
            lines.push(Line::from(vec![
                Span::styled("  Justification: ", Style::default().fg(scheme.text_muted)),
                Span::raw(just.to_string()),
            ]));
        }
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Overview ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

/// Render the Identifiers tab - PURL, CPE, SWID, hashes
fn render_identifiers_tab(frame: &mut Frame, area: Rect, comp: &Component, border_color: Color) {
    let scheme = colors();
    let mut lines = vec![];
    let width = area.width as usize;

    // PURL
    if let Some(purl) = &comp.identifiers.purl {
        lines.push(Line::styled(
            "Package URL (PURL):",
            Style::default().fg(scheme.accent).bold(),
        ));
        // Wrap long PURLs across multiple lines
        let purl_display = if purl.len() > width - 6 {
            format!("{}...", &purl[..width.saturating_sub(9)])
        } else {
            purl.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::raw(purl_display),
        ]));
        lines.push(Line::from(""));
    }

    // CPE entries
    if !comp.identifiers.cpe.is_empty() {
        lines.push(Line::styled(
            format!("CPE ({}):", comp.identifiers.cpe.len()),
            Style::default().fg(scheme.accent).bold(),
        ));
        for cpe in &comp.identifiers.cpe {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::raw(truncate_str(cpe, width - 4)),
            ]));
        }
        lines.push(Line::from(""));
    }

    // SWID
    if let Some(swid) = &comp.identifiers.swid {
        lines.push(Line::styled(
            "SWID Tag:",
            Style::default().fg(scheme.accent).bold(),
        ));
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::raw(truncate_str(swid, width - 4)),
        ]));
        lines.push(Line::from(""));
    }

    // Hashes
    if !comp.hashes.is_empty() {
        lines.push(Line::styled(
            format!("Hashes ({}):", comp.hashes.len()),
            Style::default().fg(scheme.highlight).bold(),
        ));
        for hash in &comp.hashes {
            let hash_display = if hash.value.len() > 48 {
                format!("{}...", &hash.value[..48])
            } else {
                hash.value.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {}: ", hash.algorithm),
                    Style::default().fg(scheme.text_muted),
                ),
                Span::raw(hash_display),
            ]));
        }
        lines.push(Line::from(""));
    }

    // External references
    if !comp.external_refs.is_empty() {
        lines.push(Line::styled(
            format!("External References ({}):", comp.external_refs.len()),
            Style::default().fg(scheme.info).bold(),
        ));
        for ext_ref in comp.external_refs.iter().take(5) {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{}] ", ext_ref.ref_type),
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(
                    truncate_str(&ext_ref.url, width - 15),
                    Style::default().fg(scheme.info),
                ),
            ]));
        }
        if comp.external_refs.len() > 5 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more", comp.external_refs.len() - 5),
                Style::default().fg(scheme.text_muted),
            )]));
        }
    }

    // Show message if no identifiers
    if lines.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "No identifiers available for this component",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Identifiers ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

/// Render the Vulnerabilities tab - detailed vuln list
fn render_vulnerabilities_tab(
    frame: &mut Frame,
    area: Rect,
    comp: &Component,
    border_color: Color,
) {
    let scheme = colors();
    let mut lines = vec![];
    let width = area.width as usize;

    if comp.vulnerabilities.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "No vulnerabilities detected",
            Style::default().fg(scheme.success),
        ));
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "This component has no known security issues.",
            Style::default().fg(scheme.text_muted),
        ));
    } else {
        // Summary header
        lines.push(Line::from(vec![Span::styled(
            format!("{} vulnerabilities found", comp.vulnerabilities.len()),
            Style::default().fg(scheme.critical).bold(),
        )]));
        lines.push(Line::from(""));

        // Detailed list
        for vuln in &comp.vulnerabilities {
            let sev = vuln
                .severity
                .as_ref().map_or_else(|| "?".to_string(), std::string::ToString::to_string);
            let sev_color = SeverityBadge::fg_color(&sev);

            // Vuln ID line
            let mut vuln_line = vec![
                Span::styled("• ", Style::default().fg(scheme.critical)),
                Span::styled(&vuln.id, Style::default().fg(sev_color).bold()),
            ];

            if let Some(cvss) = vuln.max_cvss_score() {
                vuln_line.push(Span::styled(
                    format!(" [CVSS: {cvss:.1}]"),
                    Style::default().fg(sev_color),
                ));
            }

            vuln_line.push(Span::styled(
                format!(" [{}]", sev.to_uppercase()),
                Style::default().fg(sev_color),
            ));

            lines.push(Line::from(vuln_line));

            // Description
            if let Some(desc) = &vuln.description {
                let desc_short = truncate_str(desc, width - 4);
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(desc_short, Style::default().fg(scheme.text_muted)),
                ]));
            }

            // Source
            lines.push(Line::from(vec![
                Span::styled("  Source: ", Style::default().fg(scheme.text_muted)),
                Span::styled(vuln.source.to_string(), Style::default().fg(scheme.info)),
            ]));

            lines.push(Line::from(""));
        }
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Vulnerabilities ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

/// Render the Dependencies tab - direct dependencies
fn render_dependencies_tab(
    frame: &mut Frame,
    area: Rect,
    app: &ViewApp,
    comp: &Component,
    border_color: Color,
) {
    let scheme = colors();
    let mut lines = vec![];

    // Find direct dependencies from edges
    let comp_id = &comp.canonical_id;
    let mut direct_deps: Vec<&Component> = Vec::new();
    let mut dependents: Vec<&Component> = Vec::new();

    for edge in &app.sbom.edges {
        if edge.from == *comp_id {
            // This component depends on edge.to
            if let Some(dep) = app.sbom.components.get(&edge.to) {
                direct_deps.push(dep);
            }
        }
        if edge.to == *comp_id {
            // edge.from depends on this component
            if let Some(dependent) = app.sbom.components.get(&edge.from) {
                dependents.push(dependent);
            }
        }
    }

    // Dependencies (what this component depends on)
    lines.push(Line::styled(
        format!("Dependencies ({}):", direct_deps.len()),
        Style::default().fg(scheme.accent).bold(),
    ));

    if direct_deps.is_empty() {
        lines.push(Line::styled(
            "  No direct dependencies",
            Style::default().fg(scheme.text_muted),
        ));
    } else {
        for dep in direct_deps.iter().take(10) {
            let version = dep.version.as_deref().unwrap_or("");
            let vuln_indicator = if dep.vulnerabilities.is_empty() {
                String::new()
            } else {
                format!(" [{}]", dep.vulnerabilities.len())
            };
            let vuln_color = if dep.vulnerabilities.is_empty() {
                scheme.text_muted
            } else {
                scheme.critical
            };

            lines.push(Line::from(vec![
                Span::styled("  → ", Style::default().fg(scheme.accent)),
                Span::styled(&dep.name, Style::default().fg(scheme.text)),
                Span::styled(
                    format!(" {version}"),
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(vuln_indicator, Style::default().fg(vuln_color)),
            ]));
        }
        if direct_deps.len() > 10 {
            lines.push(Line::styled(
                format!("  ... and {} more", direct_deps.len() - 10),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }

    lines.push(Line::from(""));

    // Dependents (what depends on this component)
    lines.push(Line::styled(
        format!("Dependents ({}):", dependents.len()),
        Style::default().fg(scheme.highlight).bold(),
    ));

    if dependents.is_empty() {
        lines.push(Line::styled(
            "  No components depend on this",
            Style::default().fg(scheme.text_muted),
        ));
    } else {
        for dep in dependents.iter().take(10) {
            let version = dep.version.as_deref().unwrap_or("");

            lines.push(Line::from(vec![
                Span::styled("  ← ", Style::default().fg(scheme.highlight)),
                Span::styled(&dep.name, Style::default().fg(scheme.text)),
                Span::styled(
                    format!(" {version}"),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }
        if dependents.len() > 10 {
            lines.push(Line::styled(
                format!("  ... and {} more", dependents.len() - 10),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Dependencies ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

/// Render component stats panel when no component is selected
fn render_component_stats_panel(frame: &mut Frame, area: Rect, app: &ViewApp, border_color: Color) {
    use crate::tui::view::severity::severity_category;

    let scheme = colors();
    let mut lines = Vec::with_capacity(30);
    let width = area.width.saturating_sub(4) as usize;

    // Title
    lines.push(Line::from(vec![Span::styled(
        "Component Statistics",
        Style::default().fg(scheme.accent).bold(),
    )]));
    lines.push(Line::from(""));

    // Total count
    lines.push(Line::from(vec![
        Span::styled("Total Components: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            app.stats.component_count.to_string(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));
    lines.push(Line::from(""));

    // Count components by type - pre-allocate with known capacity
    let mut type_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(5);
    let mut vuln_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(5);
    vuln_counts.insert("critical", 0);
    vuln_counts.insert("high", 0);
    vuln_counts.insert("medium", 0);
    vuln_counts.insert("low", 0);
    vuln_counts.insert("clean", 0);

    for comp in app.sbom.components.values() {
        // Type detection
        let comp_type = crate::tui::widgets::detect_component_type(&comp.name);
        *type_counts.entry(comp_type).or_insert(0) += 1;

        // Vulnerability severity - use shared helper
        let category = severity_category(&comp.vulnerabilities);
        *vuln_counts.entry(category).or_insert(0) += 1;
    }

    // By Type section
    lines.push(Line::styled(
        "By Type:",
        Style::default().fg(scheme.highlight).bold(),
    ));

    let type_order = vec![
        ("lib", "Libraries", scheme.info),
        ("bin", "Binaries", scheme.accent),
        ("cert", "Certificates", scheme.success),
        ("fs", "Filesystems", scheme.highlight),
        ("file", "Other Files", scheme.text_muted),
    ];

    let max_type_count = type_counts.values().copied().max().unwrap_or(1);
    let bar_width = width.saturating_sub(20).min(30);

    for (key, label, color) in &type_order {
        let count = type_counts.get(key).copied().unwrap_or(0);
        if count == 0 {
            continue;
        }
        let bar_len = if max_type_count > 0 {
            (count * bar_width) / max_type_count
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

    // Vulnerability Status section
    lines.push(Line::styled(
        "Vulnerability Status:",
        Style::default().fg(scheme.critical).bold(),
    ));

    let vuln_order = vec![
        ("critical", "Critical", scheme.critical),
        ("high", "High", scheme.high),
        ("medium", "Medium", scheme.warning),
        ("low", "Low", scheme.info),
        ("clean", "Clean", scheme.success),
    ];

    let max_vuln_count = vuln_counts.values().copied().max().unwrap_or(1);

    for (key, label, color) in &vuln_order {
        let count = vuln_counts.get(key).copied().unwrap_or(0);
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
    lines.push(Line::from(""));

    // Navigation hints
    lines.push(Line::styled(
        "Navigation:",
        Style::default().fg(scheme.text_muted),
    ));
    lines.push(Line::from(vec![
        Span::styled("  [↑↓]", Style::default().fg(scheme.accent)),
        Span::styled(" select component", Style::default().fg(scheme.text_muted)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  [←→]", Style::default().fg(scheme.accent)),
        Span::styled(" expand/collapse", Style::default().fg(scheme.text_muted)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  [g]", Style::default().fg(scheme.accent)),
        Span::styled(" change grouping", Style::default().fg(scheme.text_muted)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  [f]", Style::default().fg(scheme.accent)),
        Span::styled(" filter components", Style::default().fg(scheme.text_muted)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  [/]", Style::default().fg(scheme.accent)),
        Span::styled(" search", Style::default().fg(scheme.text_muted)),
    ]));

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Component Overview ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}
