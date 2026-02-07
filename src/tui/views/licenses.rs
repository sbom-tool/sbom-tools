//! Licenses view with enhanced categorization, compatibility checking, and risk assessment.

use crate::tui::app::{App, AppMode, LicenseGroupBy, LicenseRiskFilter, LicenseSort};
use crate::tui::license_conflicts::{ConflictDetector, ConflictSeverity};
use crate::tui::state::ListNavigation;
use crate::tui::license_utils::{
    analyze_license_compatibility, LicenseCategory, LicenseInfo, LicenseStats, RiskLevel,
    SpdxExpression,
};
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use std::collections::HashMap;

pub fn render_licenses(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Filter bar with group by and sort
    render_filter_bar(frame, chunks[0], app);

    // License content - both modes now use &mut App for state updates
    match app.mode {
        AppMode::Diff => render_diff_licenses(frame, chunks[1], app),
        AppMode::View => render_view_licenses(frame, chunks[1], app),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_filter_bar(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();
    let group = &app.tabs.licenses.group_by;
    let sort = &app.tabs.licenses.sort_by;
    let is_diff_mode = app.mode == AppMode::Diff;

    let group_label = match group {
        LicenseGroupBy::License => "License",
        LicenseGroupBy::Component => "Component",
        LicenseGroupBy::Compatibility => "Category",
        LicenseGroupBy::Family => "Family",
        LicenseGroupBy::Risk => "Risk",
    };

    let sort_label = match sort {
        LicenseSort::License => "License",
        LicenseSort::Count => "Count",
        LicenseSort::Permissiveness => "Permissive",
        LicenseSort::Risk => "Risk",
    };

    let risk_filter_label = match app.tabs.licenses.risk_filter {
        None => "All",
        Some(LicenseRiskFilter::Low) => "Low+",
        Some(LicenseRiskFilter::Medium) => "Medium+",
        Some(LicenseRiskFilter::High) => "High+",
        Some(LicenseRiskFilter::Critical) => "Critical",
    };

    let compat_label = if app.tabs.licenses.show_compatibility {
        "On"
    } else {
        "Off"
    };

    let mut spans = vec![
        Span::styled("Group: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {group_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  "),
        Span::styled("Sort: ", Style::default().fg(scheme.text_muted)),
        Span::styled(sort_label, Style::default().fg(scheme.accent).bold()),
        Span::styled("  │  ", Style::default().fg(scheme.border)),
        Span::styled("Risk: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {risk_filter_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if app.tabs.licenses.risk_filter.is_some() {
                    scheme.warning
                } else {
                    scheme.success
                })
                .bold(),
        ),
        Span::styled("  │  ", Style::default().fg(scheme.border)),
        Span::styled("Compat: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {compat_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if app.tabs.licenses.show_compatibility {
                    scheme.accent
                } else {
                    scheme.border
                })
                .bold(),
        ),
    ];

    // Show panel focus indicator only in Diff mode
    if is_diff_mode {
        let focus_label = if app.tabs.licenses.focus_left {
            "New"
        } else {
            "Removed"
        };
        spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        spans.push(Span::styled("Focus: ", Style::default().fg(scheme.text_muted)));
        spans.push(Span::styled(
            format!(" {focus_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if app.tabs.licenses.focus_left {
                    scheme.added
                } else {
                    scheme.removed
                })
                .bold(),
        ));
    }

    // Keyboard hints
    spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
    spans.push(Span::styled("[g]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(" grp ", Style::default().fg(scheme.text_muted)));
    spans.push(Span::styled("[s]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(" sort ", Style::default().fg(scheme.text_muted)));
    spans.push(Span::styled("[r]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(" risk ", Style::default().fg(scheme.text_muted)));
    spans.push(Span::styled("[c]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(" compat", Style::default().fg(scheme.text_muted)));

    // Panel switch hint only in Diff mode
    if is_diff_mode {
        spans.push(Span::styled(" [Tab]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(" panel", Style::default().fg(scheme.text_muted)));
    }

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(scheme.border)),
    );

    frame.render_widget(paragraph, area);
}

fn render_diff_licenses(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some(result) = app.data.diff_result.as_ref() else {
        return;
    };

    // Layout depends on whether compatibility panel is shown
    let main_chunks = if app.tabs.licenses.show_compatibility {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    };

    // Left panel: split between new and removed (or compatibility stats)
    let list_area = if app.tabs.licenses.show_compatibility {
        // When showing compatibility, give more space to lists
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0]);

        // Render compatibility panel on the right
        render_compatibility_panel(frame, main_chunks[1], app);

        left_chunks
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0])
    };

    let sort = app.tabs.licenses.sort_by;
    let group = app.tabs.licenses.group_by;
    let risk_filter = app.tabs.licenses.risk_filter;

    // Build sorted and filtered license data
    let new_licenses = build_license_list(&result.licenses.new_licenses, sort, group, risk_filter);
    let removed_licenses =
        build_license_list(&result.licenses.removed_licenses, sort, group, risk_filter);

    // Update total based on focus
    app.tabs.licenses.total = if app.tabs.licenses.focus_left {
        new_licenses.len()
    } else {
        removed_licenses.len()
    };
    app.tabs.licenses.clamp_selection();

    // Render new licenses table
    render_license_table(
        frame,
        list_area[0],
        &new_licenses,
        " + New Licenses ",
        true,
        app.tabs.licenses.focus_left,
        if app.tabs.licenses.focus_left {
            Some(app.tabs.licenses.selected)
        } else {
            None
        },
        &mut app.tabs.licenses.scroll_offset_new,
        group,
    );

    // Render removed licenses table
    render_license_table(
        frame,
        list_area[1],
        &removed_licenses,
        " - Removed Licenses ",
        false,
        !app.tabs.licenses.focus_left,
        if app.tabs.licenses.focus_left {
            None
        } else {
            Some(app.tabs.licenses.selected)
        },
        &mut app.tabs.licenses.scroll_offset_removed,
        group,
    );

    // Detail panel (only when compatibility is off)
    if !app.tabs.licenses.show_compatibility {
        let selected_license = if app.tabs.licenses.focus_left {
            new_licenses.get(app.tabs.licenses.selected)
        } else {
            removed_licenses.get(app.tabs.licenses.selected)
        };

        render_license_details(
            frame,
            main_chunks[1],
            selected_license,
            app.tabs.licenses.focus_left,
            app.data.diff_result.as_ref(),
        );
    }
}

/// Render compatibility analysis panel
fn render_compatibility_panel(frame: &mut Frame, area: Rect, app: &App) {
    let scheme = colors();

    let Some(result) = app.data.diff_result.as_ref() else {
        return;
    };

    // Collect all licenses from both new and existing
    let all_licenses: Vec<&str> = result
        .licenses
        .new_licenses
        .iter()
        .map(|l| l.license.as_str())
        .chain(
            result
                .licenses
                .removed_licenses
                .iter()
                .map(|l| l.license.as_str()),
        )
        .collect();

    let report = analyze_license_compatibility(&all_licenses);

    let mut lines = vec![];

    // Overall score
    let score_color = if report.overall_score >= 80 {
        scheme.success
    } else if report.overall_score >= 50 {
        scheme.warning
    } else {
        scheme.error
    };

    lines.push(Line::from(vec![
        Span::styled("Compatibility Score: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{}%", report.overall_score),
            Style::default().fg(score_color).bold(),
        ),
    ]));
    lines.push(Line::from(""));

    // Category distribution
    lines.push(Line::styled(
        "License Categories:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let category_order = [
        LicenseCategory::Permissive,
        LicenseCategory::WeakCopyleft,
        LicenseCategory::StrongCopyleft,
        LicenseCategory::NetworkCopyleft,
        LicenseCategory::PublicDomain,
        LicenseCategory::Proprietary,
        LicenseCategory::Unknown,
    ];

    for cat in category_order {
        if let Some(licenses) = report.categories.get(&cat) {
            let cat_color = crate::tui::shared::licenses::category_color(cat);

            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(scheme.text_muted)),
                Span::styled(cat.as_str(), Style::default().fg(cat_color)),
                Span::styled(
                    format!(": {}", licenses.len()),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
    }

    // Issues
    lines.push(Line::from(""));
    if report.issues.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("✓ ", Style::default().fg(scheme.success)),
            Span::styled(
                "No compatibility issues detected",
                Style::default().fg(scheme.success),
            ),
        ]));
    } else {
        lines.push(Line::styled(
            "Compatibility Issues:",
            Style::default().fg(scheme.error).bold(),
        ));

        for issue in report.issues.iter().take(5) {
            let icon = match issue.severity {
                crate::tui::license_utils::IssueSeverity::Error => "✗",
                crate::tui::license_utils::IssueSeverity::Warning => "⚠",
            };
            let color = match issue.severity {
                crate::tui::license_utils::IssueSeverity::Error => scheme.error,
                crate::tui::license_utils::IssueSeverity::Warning => scheme.warning,
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {icon} "), Style::default().fg(color)),
                Span::raw(widgets::truncate_str(&issue.message, area.width as usize - 6)),
            ]));
        }

        if report.issues.len() > 5 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more issues", report.issues.len() - 5),
                Style::default().fg(scheme.text_muted),
            )]));
        }
    }

    // Conflict Detection using the enhanced ConflictDetector
    let detector = ConflictDetector::new();

    // Build license -> components map for conflict detection
    let mut license_map: HashMap<String, Vec<String>> = HashMap::new();
    for lic in &result.licenses.new_licenses {
        license_map
            .entry(lic.license.clone())
            .or_default()
            .extend(lic.components.clone());
    }
    for lic in &result.licenses.removed_licenses {
        license_map
            .entry(lic.license.clone())
            .or_default()
            .extend(lic.components.clone());
    }

    let conflicts = detector.detect_conflicts(&license_map);

    if !conflicts.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!("License Conflicts ({}):", conflicts.len()),
            Style::default().fg(scheme.critical).bold(),
        ));

        for conflict in conflicts.iter().take(4) {
            let (icon, color) = match conflict.rule.severity {
                ConflictSeverity::Error => ("✗", scheme.critical),
                ConflictSeverity::Warning => ("⚠", scheme.warning),
                ConflictSeverity::Info => ("ℹ", scheme.info),
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {icon} "), Style::default().fg(color)),
                Span::styled(
                    format!("{} + {}", conflict.license_a, conflict.license_b),
                    Style::default().fg(color).bold(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {}: ", conflict.rule.conflict_type),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
            // Show truncated description
            let desc = widgets::truncate_str(&conflict.rule.description, area.width as usize - 6);
            lines.push(Line::from(vec![
                Span::styled("    ", Style::default()),
                Span::styled(desc, Style::default().fg(scheme.text).italic()),
            ]));
        }

        if conflicts.len() > 4 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more conflicts", conflicts.len() - 4),
                Style::default().fg(scheme.text_muted),
            )]));
        }
    }

    // Family distribution
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "License Families:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let mut families: Vec<_> = report.families.iter().collect();
    families.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    for (family, licenses) in families.iter().take(6) {
        lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(scheme.text_muted)),
            Span::styled(family.to_string(), Style::default().fg(scheme.accent)),
            Span::styled(
                format!(": {}", licenses.len()),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    let block = Block::default()
        .title(" Compatibility Analysis ")
        .title_style(Style::default().fg(scheme.primary).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));

    let paragraph = Paragraph::new(lines).block(block);

    frame.render_widget(paragraph, area);
}

/// Enhanced license entry with additional metadata
struct LicenseEntry {
    license: String,
    components: Vec<String>,
    category: LicenseCategory,
    risk_level: RiskLevel,
    family: String,
    is_dual_licensed: bool,
}

fn build_license_list(
    licenses: &[crate::diff::LicenseChange],
    sort: LicenseSort,
    group: LicenseGroupBy,
    risk_filter: Option<LicenseRiskFilter>,
) -> Vec<LicenseEntry> {
    let mut entries: Vec<LicenseEntry> = licenses
        .iter()
        .map(|lic| {
            let info = LicenseInfo::from_spdx(&lic.license);
            let parsed = SpdxExpression::parse(&lic.license);

            LicenseEntry {
                license: lic.license.clone(),
                components: lic.components.clone(),
                category: info.category,
                risk_level: info.risk_level,
                family: info.family.to_string(),
                is_dual_licensed: parsed.is_choice(),
            }
        })
        .collect();

    // Apply risk filter
    if let Some(min_risk) = risk_filter {
        let min_level = match min_risk {
            LicenseRiskFilter::Low => RiskLevel::Low,
            LicenseRiskFilter::Medium => RiskLevel::Medium,
            LicenseRiskFilter::High => RiskLevel::High,
            LicenseRiskFilter::Critical => RiskLevel::Critical,
        };
        entries.retain(|e| e.risk_level >= min_level);
    }

    // Apply sorting
    match sort {
        LicenseSort::License => entries.sort_by(|a, b| a.license.cmp(&b.license)),
        LicenseSort::Count => entries.sort_by(|a, b| b.components.len().cmp(&a.components.len())),
        LicenseSort::Permissiveness => {
            entries.sort_by(|a, b| {
                a.category
                    .copyleft_strength()
                    .cmp(&b.category.copyleft_strength())
            });
        }
        LicenseSort::Risk => {
            entries.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
        }
    }

    // Apply grouping (affects display order)
    match group {
        LicenseGroupBy::Family => {
            entries.sort_by(|a, b| a.family.cmp(&b.family));
        }
        LicenseGroupBy::Compatibility => {
            entries.sort_by(|a, b| {
                a.category
                    .copyleft_strength()
                    .cmp(&b.category.copyleft_strength())
            });
        }
        LicenseGroupBy::Risk => {
            entries.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
        }
        _ => {} // License and Component grouping use default sort
    }

    entries
}

#[allow(clippy::too_many_arguments)]
fn render_license_table(
    frame: &mut Frame,
    area: Rect,
    licenses: &[LicenseEntry],
    title: &str,
    is_new: bool,
    is_focused: bool,
    selected: Option<usize>,
    scroll_offset: &mut usize,
    group: LicenseGroupBy,
) {
    let scheme = colors();
    let border_color = if is_new { scheme.added } else { scheme.removed };
    let focus_border = if is_focused {
        border_color
    } else {
        scheme.border
    };

    // Determine columns based on grouping
    let (headers, widths, rows) = match group {
        LicenseGroupBy::Family => {
            let headers = vec!["License", "Family", "Risk"];
            let widths = [
                Constraint::Min(15),
                Constraint::Length(10),
                Constraint::Length(8),
            ];
            let rows: Vec<Row> = licenses
                .iter()
                .map(|entry| {
                    let risk_color = match entry.risk_level {
                        RiskLevel::Low => scheme.success,
                        RiskLevel::Medium => scheme.info,
                        RiskLevel::High => scheme.warning,
                        RiskLevel::Critical => scheme.error,
                    };
                    Row::new(vec![
                        Cell::from(widgets::truncate_str(&entry.license, 20)),
                        Cell::from(widgets::truncate_str(&entry.family, 10)),
                        Cell::from(Span::styled(
                            entry.risk_level.as_str(),
                            Style::default().fg(risk_color),
                        )),
                    ])
                })
                .collect();
            (headers, widths, rows)
        }
        LicenseGroupBy::Risk => {
            let headers = vec!["License", "Risk", "Count"];
            let widths = [
                Constraint::Min(15),
                Constraint::Length(8),
                Constraint::Length(6),
            ];
            let rows: Vec<Row> = licenses
                .iter()
                .map(|entry| {
                    let risk_color = match entry.risk_level {
                        RiskLevel::Low => scheme.success,
                        RiskLevel::Medium => scheme.info,
                        RiskLevel::High => scheme.warning,
                        RiskLevel::Critical => scheme.error,
                    };
                    Row::new(vec![
                        Cell::from(widgets::truncate_str(&entry.license, 20)),
                        Cell::from(Span::styled(
                            entry.risk_level.as_str(),
                            Style::default().fg(risk_color),
                        )),
                        Cell::from(entry.components.len().to_string()),
                    ])
                })
                .collect();
            (headers, widths, rows)
        }
        _ => {
            // Default: License, Count, Category
            let headers = vec!["License", "Count", "Category"];
            let widths = [
                Constraint::Min(15),
                Constraint::Length(6),
                Constraint::Length(12),
            ];
            let rows: Vec<Row> = licenses
                .iter()
                .map(|entry| {
                    let cat_color = crate::tui::shared::licenses::category_color(entry.category);

                    let license_display = if entry.is_dual_licensed {
                        format!("{} ⊕", widgets::truncate_str(&entry.license, 18))
                    } else {
                        widgets::truncate_str(&entry.license, 20)
                    };

                    Row::new(vec![
                        Cell::from(license_display),
                        Cell::from(entry.components.len().to_string()),
                        Cell::from(Span::styled(
                            widgets::truncate_str(entry.category.as_str(), 12),
                            Style::default().fg(cat_color),
                        )),
                    ])
                })
                .collect();
            (headers, widths, rows)
        }
    };

    let header = Row::new(headers).style(Style::default().fg(scheme.accent).bold());

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!("{} ({}) ", title, licenses.len()))
                .title_style(Style::default().fg(border_color).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(focus_border)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(if is_focused { "▶ " } else { "  " });

    let mut state = TableState::default()
        .with_offset(*scroll_offset)
        .with_selected(selected);

    frame.render_stateful_widget(table, area, &mut state);

    // Update scroll offset only when focused
    if is_focused {
        *scroll_offset = state.offset();
    }
}

fn render_license_details(
    frame: &mut Frame,
    area: Rect,
    entry: Option<&LicenseEntry>,
    is_new: bool,
    diff_result: Option<&crate::diff::DiffResult>,
) {
    let scheme = colors();

    let Some(entry) = entry else {
        crate::tui::shared::components::render_empty_detail_panel(
            frame,
            area,
            " License Details ",
            "",
            "Select a license to view details",
            &[],
            false,
        );
        return;
    };

    // Status badge (diff-specific, before metadata)
    let (status_text, status_color) = if is_new {
        ("+ NEW LICENSE", scheme.added)
    } else {
        ("- REMOVED LICENSE", scheme.removed)
    };

    let mut lines = vec![Line::from(vec![Span::styled(
        status_text,
        Style::default().fg(status_color).bold(),
    )])];

    lines.extend(crate::tui::shared::licenses::render_license_metadata_lines(
        &entry.license,
        entry.category,
        entry.risk_level,
        &entry.family,
        entry.components.len(),
        entry.is_dual_licensed,
    ));

    lines.push(Line::from(""));

    lines.extend(crate::tui::shared::licenses::render_license_characteristics_lines(
        &entry.license,
    ));

    lines.push(Line::from(""));

    // Affected components
    lines.push(Line::styled(
        "Affected Components:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let max_components = (area.height as usize).saturating_sub(22).max(3);
    for comp in entry.components.iter().take(max_components) {
        // Check if component has vulnerabilities
        let has_vulns = diff_result
            .is_some_and(|r| {
                r.vulnerabilities
                    .introduced
                    .iter()
                    .chain(r.vulnerabilities.resolved.iter())
                    .any(|v| v.component_name == *comp)
            });

        let vuln_indicator = if has_vulns {
            Span::styled(" ⚠", Style::default().fg(scheme.critical))
        } else {
            Span::raw("")
        };

        lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(scheme.text_muted)),
            Span::raw(widgets::truncate_str(comp, area.width as usize - 8)),
            vuln_indicator,
        ]));
    }

    if entry.components.len() > max_components {
        lines.push(Line::from(vec![Span::styled(
            format!("  ... and {} more", entry.components.len() - max_components),
            Style::default().fg(scheme.text_muted),
        )]));
    }

    let border_color = if is_new { scheme.added } else { scheme.removed };

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" License Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    frame.render_widget(detail, area);
}

fn render_view_licenses(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some(sbom) = app.data.sbom.as_ref() else {
        return;
    };
    let sort = app.tabs.licenses.sort_by;
    let risk_filter = app.tabs.licenses.risk_filter;

    // Collect license usage
    let mut license_counts: HashMap<String, Vec<String>> = HashMap::new();

    for comp in sbom.components.values() {
        for lic in &comp.licenses.declared {
            license_counts
                .entry(lic.expression.clone())
                .or_default()
                .push(comp.name.clone());
        }
    }

    // Handle empty state
    if license_counts.is_empty() {
        widgets::render_empty_state_enhanced(
            frame,
            area,
            "📜",
            "No license information found",
            Some("Components in this SBOM do not have declared licenses"),
            Some("License data may be incomplete or missing from the source"),
        );
        return;
    }

    // Layout with optional stats/details panel
    let chunks = if app.tabs.licenses.show_compatibility {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area)
    };

    // Build license entries with metadata
    let mut licenses: Vec<_> = license_counts
        .into_iter()
        .map(|(license, components)| {
            let info = LicenseInfo::from_spdx(&license);
            let parsed = SpdxExpression::parse(&license);
            LicenseEntry {
                license,
                components,
                category: info.category,
                risk_level: info.risk_level,
                family: info.family.to_string(),
                is_dual_licensed: parsed.is_choice(),
            }
        })
        .collect();

    // Apply risk filter
    if let Some(min_risk) = risk_filter {
        let min_level = match min_risk {
            LicenseRiskFilter::Low => RiskLevel::Low,
            LicenseRiskFilter::Medium => RiskLevel::Medium,
            LicenseRiskFilter::High => RiskLevel::High,
            LicenseRiskFilter::Critical => RiskLevel::Critical,
        };
        licenses.retain(|e| e.risk_level >= min_level);
    }

    // Apply sorting (with license name tiebreaker for stable ordering)
    match sort {
        LicenseSort::License => {
            licenses.sort_by(|a, b| a.license.cmp(&b.license));
        }
        LicenseSort::Count => {
            licenses.sort_by(|a, b| {
                b.components.len().cmp(&a.components.len())
                    .then_with(|| a.license.cmp(&b.license))
            });
        }
        LicenseSort::Permissiveness => {
            licenses.sort_by(|a, b| {
                a.category
                    .copyleft_strength()
                    .cmp(&b.category.copyleft_strength())
                    .then_with(|| a.license.cmp(&b.license))
            });
        }
        LicenseSort::Risk => {
            licenses.sort_by(|a, b| {
                b.risk_level.cmp(&a.risk_level)
                    .then_with(|| a.license.cmp(&b.license))
            });
        }
    }

    // Update total and clamp selection
    app.tabs.licenses.total = licenses.len();
    app.tabs.licenses.clamp_selection();

    let scheme = colors();

    // Build all rows (no limit)
    let rows: Vec<Row> = licenses
        .iter()
        .map(|entry| {
            let cat_color = crate::tui::shared::licenses::category_color(entry.category);

            let risk_color = crate::tui::shared::licenses::risk_level_color(entry.risk_level);

            let license_display = if entry.is_dual_licensed {
                format!("{} ⊕", widgets::truncate_str(&entry.license, 28))
            } else {
                widgets::truncate_str(&entry.license, 30)
            };

            Row::new(vec![
                Cell::from(license_display),
                Cell::from(entry.components.len().to_string()),
                Cell::from(Span::styled(
                    entry.category.as_str(),
                    Style::default().fg(cat_color),
                )),
                Cell::from(Span::styled(
                    entry.risk_level.as_str(),
                    Style::default().fg(risk_color),
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["License", "Count", "Category", "Risk"])
            .style(Style::default().bold().fg(scheme.accent)),
    )
    .block(
        Block::default()
            .title(format!(" License Usage ({}) ", licenses.len()))
            .title_style(Style::default().fg(scheme.primary).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.accent)),
    )
    .row_highlight_style(
        Style::default()
            .bg(scheme.selection)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    // Create table state for selection and scrolling
    let mut state = TableState::default()
        .with_offset(app.tabs.licenses.scroll_offset_view)
        .with_selected(Some(app.tabs.licenses.selected));

    frame.render_stateful_widget(table, chunks[0], &mut state);

    // Update scroll offset from state
    app.tabs.licenses.scroll_offset_view = state.offset();

    // Render right panel based on mode
    if app.tabs.licenses.show_compatibility {
        // Show statistics panel
        render_view_stats_panel(frame, chunks[1], &licenses);
    } else {
        // Show details for selected license
        let selected_license = licenses.get(app.tabs.licenses.selected);
        render_view_license_details(frame, chunks[1], selected_license);
    }
}

/// Render license statistics panel for view mode
fn render_view_stats_panel(frame: &mut Frame, area: Rect, licenses: &[LicenseEntry]) {
    let scheme = colors();

    let mut lines = vec![];

    // Stats summary
    let stats = LicenseStats::from_licenses(
        &licenses
            .iter()
            .map(|e| e.license.as_str())
            .collect::<Vec<_>>(),
    );

    lines.push(Line::styled(
        "License Statistics",
        Style::default().fg(scheme.primary).bold(),
    ));
    lines.push(Line::from(""));

    lines.push(Line::from(vec![
        Span::styled("Total: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            stats.total_licenses.to_string(),
            Style::default().fg(scheme.text),
        ),
        Span::styled(" licenses (", Style::default().fg(scheme.text_muted)),
        Span::styled(
            stats.unique_licenses.to_string(),
            Style::default().fg(scheme.accent),
        ),
        Span::styled(" unique)", Style::default().fg(scheme.text_muted)),
    ]));

    lines.push(Line::from(""));

    // Category breakdown
    lines.push(Line::styled(
        "By Category:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let total = stats.unique_licenses.max(1) as f64;

    for (cat, count) in &stats.by_category {
        let pct = (*count as f64 / total * 100.0) as u16;
        let bar_width = (area.width as usize).saturating_sub(25);
        let filled = (bar_width as f64 * (*count as f64 / total)) as usize;

        let cat_color = crate::tui::shared::licenses::category_color(*cat);

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:14}", cat.as_str()),
                Style::default().fg(cat_color),
            ),
            Span::styled(
                "█".repeat(filled),
                Style::default().fg(cat_color),
            ),
            Span::styled(
                "░".repeat(bar_width.saturating_sub(filled)),
                Style::default().fg(scheme.border),
            ),
            Span::styled(
                format!(" {pct}%"),
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    lines.push(Line::from(""));

    // Risk breakdown
    lines.push(Line::styled(
        "By Risk Level:",
        Style::default().fg(scheme.primary).bold(),
    ));

    for (risk, count) in &stats.by_risk {
        let risk_color = match risk {
            RiskLevel::Low => scheme.success,
            RiskLevel::Medium => scheme.info,
            RiskLevel::High => scheme.warning,
            RiskLevel::Critical => scheme.error,
        };

        lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(scheme.text_muted)),
            Span::styled(risk.as_str(), Style::default().fg(risk_color)),
            Span::styled(format!(": {count}"), Style::default().fg(scheme.text)),
        ]));
    }

    // Copyleft summary
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Permissive: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{}%", (stats.permissive_count as f64 / total * 100.0) as u8),
            Style::default().fg(scheme.success),
        ),
        Span::styled("  Copyleft: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{}%", (stats.copyleft_count as f64 / total * 100.0) as u8),
            Style::default().fg(scheme.warning),
        ),
    ]));

    let block = Block::default()
        .title(" License Statistics ")
        .title_style(Style::default().fg(scheme.primary).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));

    let paragraph = Paragraph::new(lines).block(block);

    frame.render_widget(paragraph, area);
}

/// Render license details panel for view mode
fn render_view_license_details(frame: &mut Frame, area: Rect, entry: Option<&LicenseEntry>) {
    let scheme = colors();

    let Some(entry) = entry else {
        crate::tui::shared::components::render_empty_detail_panel(
            frame,
            area,
            " License Details ",
            "",
            "Select a license to view details",
            &[],
            false,
        );
        return;
    };

    let mut lines = crate::tui::shared::licenses::render_license_metadata_lines(
        &entry.license,
        entry.category,
        entry.risk_level,
        &entry.family,
        entry.components.len(),
        entry.is_dual_licensed,
    );

    lines.push(Line::from(""));

    lines.extend(crate::tui::shared::licenses::render_license_characteristics_lines(
        &entry.license,
    ));

    lines.push(Line::from(""));

    // Affected components
    lines.push(Line::styled(
        "Using Components:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let max_components = (area.height as usize).saturating_sub(18).max(3);
    for comp in entry.components.iter().take(max_components) {
        lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(scheme.text_muted)),
            Span::raw(widgets::truncate_str(comp, area.width as usize - 8)),
        ]));
    }

    if entry.components.len() > max_components {
        lines.push(Line::from(vec![Span::styled(
            format!("  ... and {} more", entry.components.len() - max_components),
            Style::default().fg(scheme.text_muted),
        )]));
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" License Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    frame.render_widget(detail, area);
}

/// Categorize a license by type (legacy function for compatibility)
pub fn categorize_license(license: &str) -> String {
    LicenseInfo::from_spdx(license).category.as_str().to_string()
}
