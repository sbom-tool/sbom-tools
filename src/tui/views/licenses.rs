//! Licenses view with enhanced categorization, compatibility checking, and risk assessment.

use crate::tui::app::{AppMode, LicenseGroupBy, LicenseRiskFilter, LicenseSort};
use crate::tui::license_conflicts::{ConflictDetector, ConflictSeverity};
use crate::tui::license_utils::{
    LicenseCategory, LicenseInfo, RiskLevel, SpdxExpression, analyze_license_compatibility,
};
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use std::collections::HashMap;

pub fn render_licenses(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(widgets::FILTER_BAR_HEIGHT),
            Constraint::Min(5),
        ])
        .split(area);

    // Filter bar with group by and sort
    render_filter_bar(frame, chunks[0], ctx);

    // License content
    match ctx.mode {
        AppMode::Diff => render_diff_licenses(frame, chunks[1], ctx),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_filter_bar(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let group = &ctx.licenses.group_by;
    let sort = &ctx.licenses.sort_by;
    let is_diff_mode = ctx.mode == AppMode::Diff;

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

    let risk_filter_label = match ctx.licenses.risk_filter {
        None => "All",
        Some(LicenseRiskFilter::Low) => "Low+",
        Some(LicenseRiskFilter::Medium) => "Medium+",
        Some(LicenseRiskFilter::High) => "High+",
        Some(LicenseRiskFilter::Critical) => "Critical",
    };

    let compat_label = if ctx.licenses.show_compatibility {
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
                .bg(if ctx.licenses.risk_filter.is_some() {
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
                .bg(if ctx.licenses.show_compatibility {
                    scheme.accent
                } else {
                    scheme.border
                })
                .bold(),
        ),
    ];

    // Show panel focus indicator only in Diff mode
    if is_diff_mode {
        let focus_label = if ctx.licenses.focus_left {
            "New"
        } else {
            "Removed"
        };
        spans.push(Span::styled("  │  ", Style::default().fg(scheme.border)));
        spans.push(Span::styled(
            "Focus: ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled(
            format!(" {focus_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(if ctx.licenses.focus_left {
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
    spans.push(Span::styled(
        " grp ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled("[s]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        " sort ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled("[r]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        " risk ",
        Style::default().fg(scheme.text_muted),
    ));
    spans.push(Span::styled("[c]", Style::default().fg(scheme.accent)));
    spans.push(Span::styled(
        " compat",
        Style::default().fg(scheme.text_muted),
    ));

    // Panel switch hint only in Diff mode
    if is_diff_mode {
        spans.push(Span::styled(" [Tab]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " panel",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(scheme.border)),
    );

    frame.render_widget(paragraph, area);
}

fn render_diff_licenses(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result else {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "📜",
            "No license data available",
            Some("License analysis requires a completed diff"),
            None,
        );
        return;
    };

    if result.licenses.new_licenses.is_empty() && result.licenses.removed_licenses.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "✓",
            "No license changes detected",
            Some("All licenses remain the same between both SBOMs"),
            None,
        );
        return;
    }

    // Layout depends on whether compatibility panel is shown
    let main_chunks = if ctx.licenses.show_compatibility {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints(widgets::MASTER_DETAIL_SPLIT)
            .split(area)
    };

    // Left panel: split between new and removed (or compatibility stats)
    let list_area = if ctx.licenses.show_compatibility {
        // When showing compatibility, give more space to lists
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0]);

        // Render compatibility panel on the right
        render_compatibility_panel(frame, main_chunks[1], ctx);

        left_chunks
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0])
    };

    let sort = ctx.licenses.sort_by;
    let group = ctx.licenses.group_by;
    let risk_filter = ctx.licenses.risk_filter;

    // Build sorted and filtered license data
    let new_licenses = build_license_list(&result.licenses.new_licenses, sort, group, risk_filter);
    let removed_licenses =
        build_license_list(&result.licenses.removed_licenses, sort, group, risk_filter);

    // Render new licenses table
    render_license_table(
        frame,
        list_area[0],
        &new_licenses,
        " + New Licenses ",
        true,
        ctx.licenses.focus_left,
        if ctx.licenses.focus_left {
            Some(ctx.licenses.selected)
        } else {
            None
        },
        ctx.licenses.scroll_offset_new,
        group,
    );

    // Render removed licenses table
    render_license_table(
        frame,
        list_area[1],
        &removed_licenses,
        " - Removed Licenses ",
        false,
        !ctx.licenses.focus_left,
        if ctx.licenses.focus_left {
            None
        } else {
            Some(ctx.licenses.selected)
        },
        ctx.licenses.scroll_offset_removed,
        group,
    );

    // Detail panel (only when compatibility is off)
    if !ctx.licenses.show_compatibility {
        let selected_license = if ctx.licenses.focus_left {
            new_licenses.get(ctx.licenses.selected)
        } else {
            removed_licenses.get(ctx.licenses.selected)
        };

        render_license_details(
            frame,
            main_chunks[1],
            selected_license,
            ctx.licenses.focus_left,
            ctx.diff_result,
        );
    }
}

/// Render compatibility analysis panel
fn render_compatibility_panel(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();

    let Some(result) = ctx.diff_result else {
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
        Span::styled(
            "Compatibility Score: ",
            Style::default().fg(scheme.text_muted),
        ),
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
                Span::raw(widgets::truncate_str(
                    &issue.message,
                    area.width as usize - 6,
                )),
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
            lines.push(Line::from(vec![Span::styled(
                format!("    {}: ", conflict.rule.conflict_type),
                Style::default().fg(scheme.text_muted),
            )]));
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
    scroll_offset: usize,
    group: LicenseGroupBy,
) {
    let scheme = colors();
    let border_color = if is_new { scheme.added } else { scheme.removed };
    let focus_border = if is_focused {
        scheme.border_focused
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
        .with_offset(scroll_offset)
        .with_selected(selected);

    frame.render_stateful_widget(table, area, &mut state);

    // Render scrollbar
    if licenses.len() > area.height.saturating_sub(3) as usize {
        crate::tui::widgets::render_scrollbar(
            frame,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            licenses.len(),
            scroll_offset,
        );
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

    lines
        .extend(crate::tui::shared::licenses::render_license_characteristics_lines(&entry.license));

    lines.push(Line::from(""));

    // Affected components
    lines.push(Line::styled(
        "Affected Components:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let max_components = (area.height as usize).saturating_sub(22).max(3);
    for comp in entry.components.iter().take(max_components) {
        // Check if component has vulnerabilities
        let has_vulns = diff_result.is_some_and(|r| {
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

/// Categorize a license by type (legacy function for compatibility)
pub fn categorize_license(license: &str) -> String {
    LicenseInfo::from_spdx(license)
        .category
        .as_str()
        .to_string()
}
