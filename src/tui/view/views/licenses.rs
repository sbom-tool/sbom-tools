//! License view for ViewApp.

use crate::tui::theme::colors;
use crate::tui::view::app::{LicenseGroupBy, ViewApp};
use crate::tui::views::licenses::{categorize_license, get_license_characteristics};
use crate::tui::widgets::truncate_str;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
};
use std::collections::HashMap;

pub fn render_licenses(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_license_list(frame, chunks[0], app);
    render_license_details(frame, chunks[1], app);
}

fn render_license_list(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(5)])
        .split(area);

    // Filter bar
    let group_label = match app.license_state.group_by {
        LicenseGroupBy::License => "License",
        LicenseGroupBy::Category => "Category",
    };

    let filter_spans = vec![
        Span::styled("Group: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {} ", group_label),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.success)
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" toggle group"),
    ];

    let filter_bar = Paragraph::new(Line::from(filter_spans));
    frame.render_widget(filter_bar, chunks[0]);

    // Build license data
    let license_data = build_license_data(app);

    // Update total and clamp selection to valid bounds
    app.license_state.total = license_data.len();
    app.license_state.clamp_selection();

    let rows: Vec<Row> = license_data
        .iter()
        .map(|(license, count, category)| {
            let cat_color = scheme.license_color(category);

            Row::new(vec![
                Cell::from(truncate_str(license, 30)),
                Cell::from(count.to_string()),
                Cell::from(Span::styled(category, Style::default().fg(cat_color))),
            ])
        })
        .collect();

    let header = Row::new(vec!["License", "Count", "Category"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(8),
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
}

fn render_license_details(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let license_data = build_license_data(app);

    // Safely get the selected license with bounds checking
    let selected_idx = app
        .license_state
        .selected
        .min(license_data.len().saturating_sub(1));
    if let Some((license, count, category)) = license_data.get(selected_idx) {
        // Calculate available space for components
        // Header takes ~10 lines (title, category, count, characteristics ~6 lines, "Components:" header)
        let header_lines = 12;
        let visible_components = (area.height as usize).saturating_sub(header_lines).max(3);

        let components = get_components_with_license(app, license);
        app.license_state.component_total = components.len();

        let mut lines = vec![];

        lines.push(Line::from(vec![Span::styled(
            license,
            Style::default().fg(scheme.text).bold(),
        )]));

        lines.push(Line::from(""));

        let cat_color = scheme.license_color(category);

        lines.push(Line::from(vec![
            Span::styled("Category: ", Style::default().fg(scheme.muted)),
            Span::styled(category, Style::default().fg(cat_color).bold()),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Components: ", Style::default().fg(scheme.muted)),
            Span::styled(count.to_string(), Style::default().fg(scheme.primary)),
        ]));

        lines.push(Line::from(""));

        // License characteristics
        lines.push(Line::styled(
            "Characteristics:",
            Style::default().fg(scheme.primary).bold(),
        ));

        let characteristics = get_license_characteristics(license);
        for char in characteristics {
            let (icon, color) = match char.1 {
                true => ("✓", scheme.success),
                false => ("✗", scheme.error),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", icon), Style::default().fg(color)),
                Span::raw(char.0),
            ]));
        }

        lines.push(Line::from(""));

        // Components using this license with pagination
        let scroll_offset = app.license_state.component_scroll;
        let page_info = if components.len() > visible_components {
            let current_page = scroll_offset / visible_components + 1;
            let total_pages = components.len().div_ceil(visible_components);
            format!(" ({}/{}) [Ctrl+↑↓]", current_page, total_pages)
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled("Components:", Style::default().fg(scheme.primary).bold()),
            Span::styled(page_info, Style::default().fg(scheme.muted)),
        ]));

        // Show components with scrolling
        for comp in components
            .iter()
            .skip(scroll_offset)
            .take(visible_components)
        {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(scheme.muted)),
                Span::raw(truncate_str(comp, area.width as usize - 6)),
            ]));
        }

        // Scroll indicator
        if scroll_offset > 0 || scroll_offset + visible_components < components.len() {
            let indicator =
                if scroll_offset > 0 && scroll_offset + visible_components < components.len() {
                    "  ↑↓ more components"
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

        // Render scrollbar if there are many components
        if components.len() > visible_components {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"));

            let scrollbar_area = Rect {
                x: area.x + area.width - 1,
                y: area.y + header_lines as u16,
                width: 1,
                height: area.height.saturating_sub(header_lines as u16 + 1),
            };

            let mut scrollbar_state = ScrollbarState::new(components.len()).position(scroll_offset);

            frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
        }
    } else {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::styled(
                "Select a license to view details",
                Style::default().fg(scheme.muted),
            ),
        ])
        .block(
            Block::default()
                .title(" License Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.muted)),
        )
        .alignment(Alignment::Center);

        frame.render_widget(empty, area);
    }
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

fn get_components_with_license(app: &ViewApp, license: &str) -> Vec<String> {
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
            let name = if let Some(v) = &comp.version {
                format!("{}@{}", comp.name, v)
            } else {
                comp.name.clone()
            };
            components.push(name);
        }
    }

    components.sort();
    components
}
