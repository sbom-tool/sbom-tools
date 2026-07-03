//! License view for `ViewApp`.

use crate::tui::theme::colors;
use crate::tui::view::app::{LicenseGroupBy, ViewApp};
use crate::tui::views::licenses::categorize_license;
use crate::tui::widgets::extract_display_name;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
};
use std::collections::{BTreeMap, HashMap};

/// Component info for detail panel display.
struct ComponentInfo {
    display_name: String,
    version: Option<String>,
    component_type: String,
}

pub fn render_licenses(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Build license data once, not per sub-panel
    let license_data = build_license_data(app);

    render_license_list(frame, chunks[0], app, &license_data);
    render_license_details(frame, chunks[1], app, &license_data);
}

fn render_license_list(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    license_data: &[(String, usize, String)],
) {
    let scheme = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Filter bar with risk summary (Phase 4)
    let group_label = match app.license_state.group_by {
        LicenseGroupBy::License => "License",
        LicenseGroupBy::Category => "Category",
    };

    // Compute risk summary
    let (permissive, copyleft, unknown) = compute_risk_summary(license_data);

    let filter_line1 = Line::from(vec![
        Span::styled("Group: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {group_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.success)
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" toggle  "),
        Span::styled("[Enter]", Style::default().fg(scheme.accent)),
        Span::raw(" inspect"),
    ]);

    let filter_line2 = Line::from(vec![
        Span::styled(
            format!("✓ {permissive}"),
            Style::default().fg(scheme.success),
        ),
        Span::raw("  "),
        Span::styled(format!("⚠ {copyleft}"), Style::default().fg(scheme.warning)),
        Span::raw("  "),
        Span::styled(
            format!("? {unknown}"),
            Style::default().fg(scheme.text_muted),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("{} total", license_data.len()),
            Style::default().fg(scheme.text_muted),
        ),
    ]);

    let filter_bar = Paragraph::new(vec![filter_line1, filter_line2]);
    frame.render_widget(filter_bar, chunks[0]);

    // Update total and clamp selection to valid bounds
    app.license_state.total = license_data.len();
    app.license_state.clamp_selection();

    // Phase 3: Full license expressions (no truncation), use Min() constraint
    let rows: Vec<Row> = license_data
        .iter()
        .enumerate()
        .map(|(i, (license, count, category))| {
            let cat_color = scheme.license_color(category);

            // Show distribution bar in count column
            let max_count = license_data.first().map_or(1, |d| d.1.max(1));
            let bar_width = ((*count as f64 / max_count as f64) * 8.0).ceil() as usize;
            let bar = "█".repeat(bar_width);

            let count_cell = Line::from(vec![
                Span::styled(format!("{count:>4} "), Style::default().fg(scheme.text)),
                Span::styled(bar, Style::default().fg(cat_color)),
            ]);

            // Highlight copyleft/unknown licenses
            let license_style = if i == app.license_state.selected {
                Style::default()
            } else if category == "Unknown" || category == "Proprietary" {
                Style::default().fg(scheme.text_muted)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(Span::styled(license.as_str(), license_style)),
                Cell::from(count_cell),
                Cell::from(Span::styled(
                    category.as_str(),
                    Style::default().fg(cat_color),
                )),
            ])
        })
        .collect();

    let header = Row::new(vec!["License", "Count", "Category"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(14),
        Constraint::Length(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Licenses ({}) ", license_data.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    // Use scroll_offset to maintain scroll position
    let mut state = TableState::default()
        .with_offset(app.license_state.scroll_offset)
        .with_selected(if license_data.is_empty() {
            None
        } else {
            Some(app.license_state.selected)
        });

    frame.render_stateful_widget(table, chunks[1], &mut state);

    // Save the scroll offset for next frame
    app.license_state.scroll_offset = state.offset();

    // Table scrollbar
    if license_data.len() > chunks[1].height.saturating_sub(3) as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        let sb_area = Rect {
            x: chunks[1].x + chunks[1].width - 1,
            y: chunks[1].y + 1,
            width: 1,
            height: chunks[1].height.saturating_sub(2),
        };
        let mut sb_state =
            ScrollbarState::new(license_data.len()).position(app.license_state.selected);
        frame.render_stateful_widget(scrollbar, sb_area, &mut sb_state);
    }
}

fn render_license_details(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    license_data: &[(String, usize, String)],
) {
    let scheme = colors();

    // Safely get the selected license with bounds checking
    let selected_idx = app
        .license_state
        .selected
        .min(license_data.len().saturating_sub(1));
    if let Some((license, count, _category)) = license_data.get(selected_idx) {
        let components = get_components_with_license(app, license);
        app.license_state.component_total = components.len();

        let info = crate::tui::license_utils::LicenseInfo::from_spdx(license);
        let is_dual = crate::tui::license_utils::SpdxExpression::parse(license).is_choice();

        let mut lines = crate::tui::shared::licenses::render_license_metadata_lines(
            license,
            info.category,
            info.risk_level,
            info.family,
            *count,
            is_dual,
        );

        // Phase 3: Show parsed SPDX expression structure for compound licenses
        if is_dual || license.contains(" AND ") {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Expression: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    render_spdx_structure(license),
                    Style::default().fg(scheme.accent),
                ),
            ]));
        }

        lines.push(Line::from(""));

        // License characteristics
        lines.extend(crate::tui::shared::licenses::render_license_characteristics_lines(license));

        lines.push(Line::from(""));

        // Phase 5: Group components by type
        let grouped = group_components_by_type(&components);
        let total_groups = grouped.len();

        // Calculate available space for components. Count the header lines *after
        // wrapping* at the panel width (the paragraph renders with Wrap) so a wrapped
        // header doesn't cause the component list to over-fill and overflow the panel.
        let inner_width = area.width.saturating_sub(2); // borders
        let header_lines =
            crate::tui::shared::text::wrapped_line_count(&lines, inner_width) + 2; // +2 for block borders
        let available = (area.height as usize)
            .saturating_sub(header_lines + 2)
            .max(3);

        // Components header with scroll info
        let scroll_offset = app.license_state.component_scroll;
        let flat_items = flatten_grouped_components(&grouped);
        let total_items = flat_items.len();

        let page_info = if total_items > available {
            format!(" ({}/{})", scroll_offset + 1, total_items)
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled("Components:", Style::default().fg(scheme.primary).bold()),
            Span::styled(format!(" {count}"), Style::default().fg(scheme.text_muted)),
            Span::styled(page_info, Style::default().fg(scheme.muted)),
        ]));

        // Phase 4: Navigation hint
        if !components.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("[Enter]", Style::default().fg(scheme.accent)),
                Span::raw(" jump to component  "),
                Span::styled("[K/J]", Style::default().fg(scheme.accent)),
                Span::raw(" scroll"),
            ]));
        }

        // Render grouped components with scroll
        if total_groups > 1 {
            // Multiple type groups — show grouped
            for item in flat_items.iter().skip(scroll_offset).take(available) {
                lines.push(item.clone());
            }
        } else {
            // Single group or simple list — show flat
            for comp in components.iter().skip(scroll_offset).take(available) {
                let type_icon = component_type_symbol(&comp.component_type);
                let version_str = comp
                    .version
                    .as_deref()
                    .map_or(String::new(), |v| format!("@{v}"));
                lines.push(Line::from(vec![
                    Span::styled(format!("  {type_icon} "), Style::default().fg(scheme.muted)),
                    Span::styled(comp.display_name.clone(), Style::default().fg(scheme.text)),
                    Span::styled(version_str, Style::default().fg(scheme.text_muted)),
                ]));
            }
        }

        // Scroll indicator
        let item_count = if total_groups > 1 {
            total_items
        } else {
            components.len()
        };
        if scroll_offset > 0 || scroll_offset + available < item_count {
            let indicator = if scroll_offset > 0 && scroll_offset + available < item_count {
                "  ↑↓ more"
            } else if scroll_offset > 0 {
                "  ↑ scroll up"
            } else {
                "  ↓ more below"
            };
            lines.push(Line::styled(indicator, Style::default().fg(scheme.muted)));
        }

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" License Details ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(scheme.critical)),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(detail, area);

        // Render scrollbar if there are many items
        let scroll_total = if total_groups > 1 {
            total_items
        } else {
            components.len()
        };
        if scroll_total > available {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"));

            let scrollbar_area = Rect {
                x: area.x + area.width - 1,
                y: area.y + 1,
                width: 1,
                height: area.height.saturating_sub(2),
            };

            let mut scrollbar_state = ScrollbarState::new(scroll_total).position(scroll_offset);

            frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
        }
    } else {
        // Phase 2: Distribution chart when nothing selected
        render_distribution_overview(frame, area, license_data);
    }
}

/// Phase 2: Render license distribution chart as empty/overview state.
fn render_distribution_overview(
    frame: &mut Frame,
    area: Rect,
    license_data: &[(String, usize, String)],
) {
    let scheme = colors();

    if license_data.is_empty() {
        crate::tui::shared::components::render_empty_detail_panel(
            frame,
            area,
            " License Details ",
            "",
            "No license data available",
            &[],
            false,
        );
        return;
    }

    let mut lines = vec![];
    lines.push(Line::from(vec![Span::styled(
        "License Distribution",
        Style::default().fg(scheme.text).bold(),
    )]));
    lines.push(Line::from(""));

    // Category breakdown
    let mut cat_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, count, category) in license_data {
        *cat_counts.entry(category.as_str()).or_insert(0) += count;
    }
    let total: usize = cat_counts.values().sum();

    for (cat, count) in &cat_counts {
        let pct = if total > 0 {
            (*count as f64 / total as f64 * 100.0) as usize
        } else {
            0
        };
        let bar_width = (pct as f64 / 100.0 * 20.0).ceil() as usize;
        let bar = "█".repeat(bar_width);
        let cat_color = scheme.license_color(cat);

        lines.push(Line::from(vec![
            Span::styled(
                format!("{cat:>15} "),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(bar, Style::default().fg(cat_color)),
            Span::styled(
                format!(" {count} ({pct}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Total: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            total.to_string(),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled(
            " component-licenses",
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Select a license to view details →",
        Style::default().fg(scheme.muted),
    ));

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" License Overview ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    frame.render_widget(detail, area);
}

/// Build license data from a ViewApp (public for cross-module access).
pub fn build_license_data_from_app(app: &ViewApp) -> Vec<(String, usize, String)> {
    build_license_data(app)
}

fn build_license_data(app: &ViewApp) -> Vec<(String, usize, String)> {
    let mut license_map: HashMap<String, usize> = HashMap::new();

    for comp in app.sbom.components.values() {
        if comp.licenses.declared.is_empty() {
            *license_map.entry("Unknown".to_string()).or_insert(0) += 1;
        } else {
            for lic in &comp.licenses.declared {
                *license_map.entry(lic.expression.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut data: Vec<_> = license_map
        .into_iter()
        .map(|(license, count)| {
            let category = categorize_license(&license);
            (license, count, category)
        })
        .collect();

    data.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    data
}

/// Phase 1: Return rich component info instead of just names.
fn get_components_with_license(app: &ViewApp, license: &str) -> Vec<ComponentInfo> {
    let mut components = Vec::new();

    for comp in app.sbom.components.values() {
        let has_license = if license == "Unknown" {
            comp.licenses.declared.is_empty()
        } else {
            comp.licenses
                .declared
                .iter()
                .any(|l| l.expression == license)
        };

        if has_license {
            components.push(ComponentInfo {
                display_name: extract_display_name(&comp.name),
                version: comp.version.clone(),
                component_type: format!("{:?}", comp.component_type),
            });
        }
    }

    components.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    components
}

/// Phase 4: Get the canonical ID of the first component for the selected license.
pub fn get_first_component_id_for_license(app: &ViewApp, license: &str) -> Option<String> {
    for comp in app.sbom.components.values() {
        let has_license = if license == "Unknown" {
            comp.licenses.declared.is_empty()
        } else {
            comp.licenses
                .declared
                .iter()
                .any(|l| l.expression == license)
        };
        if has_license {
            return Some(comp.canonical_id.value().to_string());
        }
    }
    None
}

/// Phase 4: Compute risk summary counts for filter bar.
fn compute_risk_summary(license_data: &[(String, usize, String)]) -> (usize, usize, usize) {
    let mut permissive = 0usize;
    let mut copyleft = 0usize;
    let mut unknown = 0usize;

    for (_, count, category) in license_data {
        match category.as_str() {
            "Permissive" | "Public Domain" => permissive += count,
            "Weak Copyleft" | "Strong Copyleft" | "Network Copyleft" => copyleft += count,
            _ => unknown += count,
        }
    }

    (permissive, copyleft, unknown)
}

/// Phase 3: Render SPDX expression structure as readable string.
fn render_spdx_structure(license: &str) -> String {
    if license.contains(" OR ") {
        let parts: Vec<&str> = license.split(" OR ").collect();
        format!("Choice: {}", parts.join(" | "))
    } else if license.contains(" AND ") {
        let parts: Vec<&str> = license.split(" AND ").collect();
        format!("All required: {}", parts.join(" + "))
    } else {
        license.to_string()
    }
}

/// Phase 5: Group components by their type.
fn group_components_by_type(components: &[ComponentInfo]) -> BTreeMap<String, Vec<&ComponentInfo>> {
    let mut groups: BTreeMap<String, Vec<&ComponentInfo>> = BTreeMap::new();
    for comp in components {
        let group_name = match comp.component_type.as_str() {
            "File" => "Files",
            "Library" => "Libraries",
            "Application" => "Applications",
            "Framework" => "Frameworks",
            "Container" => "Containers",
            "Firmware" => "Firmware",
            "Data" => "Data",
            _ => "Other",
        };
        groups.entry(group_name.to_string()).or_default().push(comp);
    }
    groups
}

/// Phase 5: Flatten grouped components into display lines.
fn flatten_grouped_components(
    groups: &BTreeMap<String, Vec<&ComponentInfo>>,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = Vec::new();

    for (group_name, comps) in groups {
        // Group header
        lines.push(Line::from(vec![
            Span::styled(
                format!("  ┌ {group_name}"),
                Style::default().fg(scheme.accent).bold(),
            ),
            Span::styled(
                format!(" ({})", comps.len()),
                Style::default().fg(scheme.text_muted),
            ),
        ]));

        for (i, comp) in comps.iter().enumerate() {
            let connector = if i == comps.len() - 1 { "└" } else { "├" };
            let type_icon = component_type_symbol(&comp.component_type);
            let version_str = comp
                .version
                .as_deref()
                .map_or(String::new(), |v| format!("@{v}"));

            lines.push(Line::from(vec![
                Span::styled(
                    format!("  │ {connector} {type_icon} "),
                    Style::default().fg(scheme.muted),
                ),
                Span::styled(comp.display_name.clone(), Style::default().fg(scheme.text)),
                Span::styled(version_str, Style::default().fg(scheme.text_muted)),
            ]));
        }
    }

    lines
}

/// Get a symbol for a component type (consistent with TUI Unicode style).
fn component_type_symbol(component_type: &str) -> &'static str {
    match component_type {
        "File" => "f",
        "Library" => "L",
        "Application" => "A",
        "Framework" => "F",
        "Container" => "C",
        "Firmware" => "W",
        "Data" => "D",
        _ => "·",
    }
}
