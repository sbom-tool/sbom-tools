//! Compliance tab for `ViewApp` - SBOM compliance validation against standards.

use std::collections::HashMap;

use crate::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, Violation, ViolationCategory,
    ViolationSeverity,
};
use crate::tui::shared::compliance as shared_compliance;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table,
    },
};

// ---------------------------------------------------------------------------
// Grouped violation — a set of violations collapsed by message pattern
// ---------------------------------------------------------------------------

/// A group of violations sharing the same severity + category + message pattern.
pub(crate) struct ViolationGroup<'a> {
    pub(crate) severity: ViolationSeverity,
    pub(crate) category: ViolationCategory,
    /// The shared message (with component name stripped).
    pub(crate) pattern: String,
    /// All individual violations in this group.
    pub(crate) violations: Vec<&'a Violation>,
}

/// Build grouped violations from a compliance result, respecting severity filter.
pub(crate) fn build_groups<'a>(
    result: &'a ComplianceResult,
    severity_filter: SeverityFilter,
) -> Vec<ViolationGroup<'a>> {
    // Key: (severity_ordinal, category, pattern)
    let mut map: HashMap<(u8, ViolationCategory, String), Vec<&'a Violation>> = HashMap::new();

    for v in &result.violations {
        if !severity_filter.matches(v.severity) {
            continue;
        }
        let sev_ord = match v.severity {
            ViolationSeverity::Error => 0,
            ViolationSeverity::Warning => 1,
            ViolationSeverity::Info => 2,
        };
        // Extract the pattern: strip component name from message for grouping.
        // Messages typically look like "Component 'foo' missing version" →
        // pattern = "missing version"
        let pattern = extract_pattern(&v.message);
        map.entry((sev_ord, v.category, pattern))
            .or_default()
            .push(v);
    }

    let mut groups: Vec<ViolationGroup<'a>> = map
        .into_iter()
        .map(|((_, category, pattern), violations)| ViolationGroup {
            severity: violations[0].severity,
            category,
            pattern,
            violations,
        })
        .collect();

    // Sort: errors first, then by count descending, then by pattern for stability
    groups.sort_by(|a, b| {
        let sev_a = severity_ordinal(a.severity);
        let sev_b = severity_ordinal(b.severity);
        sev_a
            .cmp(&sev_b)
            .then(b.violations.len().cmp(&a.violations.len()))
            .then(a.pattern.cmp(&b.pattern))
    });

    groups
}

/// Extract a grouping pattern from a violation message.
/// Strips the component name quoted in single quotes to create a shared pattern.
fn extract_pattern(msg: &str) -> String {
    // Match "Component 'xxx' <rest>" → "Component <rest>"
    if let Some(start) = msg.find('\'')
        && let Some(end) = msg[start + 1..].find('\'')
    {
        let before = &msg[..start];
        let after = &msg[start + 1 + end + 1..];
        return format!("{before}{after}").trim().to_string();
    }
    msg.to_string()
}

fn severity_ordinal(s: ViolationSeverity) -> u8 {
    match s {
        ViolationSeverity::Error => 0,
        ViolationSeverity::Warning => 1,
        ViolationSeverity::Info => 2,
    }
}

fn severity_text(s: ViolationSeverity) -> &'static str {
    match s {
        ViolationSeverity::Error => "ERROR",
        ViolationSeverity::Warning => "WARN",
        ViolationSeverity::Info => "INFO",
    }
}

fn severity_style(s: ViolationSeverity) -> Style {
    let scheme = colors();
    match s {
        ViolationSeverity::Error => Style::default().fg(scheme.error).bold(),
        ViolationSeverity::Warning => Style::default().fg(scheme.warning),
        ViolationSeverity::Info => Style::default().fg(scheme.info),
    }
}

// ---------------------------------------------------------------------------
// Main render entry point
// ---------------------------------------------------------------------------

pub fn render_compliance(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    app.ensure_compliance_results();

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Standard selector tabs
            Constraint::Length(7), // Category breakdown summary
            Constraint::Min(10),   // Violations list (grouped or flat)
            Constraint::Length(3), // Help bar
        ])
        .split(area);

    // Adjust scroll before borrowing results (avoids borrow conflict)
    let violations_viewport = chunks[2].height.saturating_sub(4) as usize;
    app.compliance_state.adjust_scroll(violations_viewport);

    // Snapshot scroll state before immutable borrows
    let selected_standard = app.compliance_state.selected_standard;
    let selected_violation = app.compliance_state.selected_violation;
    let scroll_offset = app.compliance_state.scroll_offset;
    let show_detail = app.compliance_state.show_detail;
    let grouped = app.compliance_state.grouped;
    let affected_scroll = app.compliance_state.affected_scroll;

    // Render standard selector with violation counts
    render_standard_selector(frame, chunks[0], app);

    // Get compliance result for selected standard
    let Some(results) = app.compliance_results.as_ref() else {
        return;
    };
    let result = &results[selected_standard];

    // Render category breakdown summary (replaces old gauge + counts)
    render_category_breakdown(frame, chunks[1], result);

    // Render violations with scroll + filter
    let severity_filter = app.compliance_state.severity_filter;
    if grouped {
        render_grouped_violations(
            frame,
            chunks[2],
            result,
            results,
            selected_violation,
            scroll_offset,
            severity_filter,
            affected_scroll,
        );
    } else {
        render_flat_violations(
            frame,
            chunks[2],
            result,
            results,
            selected_violation,
            scroll_offset,
            severity_filter,
        );
    }

    // Render help bar
    render_help_bar(frame, chunks[3], severity_filter, grouped);

    // Render detail overlay if active
    if show_detail {
        if grouped {
            // In grouped mode, find the group and show first violation's detail
            let groups = build_groups(result, severity_filter);
            if let Some(group) = groups.get(selected_violation) {
                shared_compliance::render_violation_detail_overlay(
                    frame,
                    area,
                    group.violations[0],
                );
            }
        } else if let Some(violation) = app
            .compliance_results
            .as_ref()
            .and_then(|rs| rs.get(selected_standard))
            .and_then(|r| {
                r.violations
                    .iter()
                    .filter(|v| severity_filter.matches(v.severity))
                    .nth(selected_violation)
            })
        {
            shared_compliance::render_violation_detail_overlay(frame, area, violation);
        }
    }
}

// ---------------------------------------------------------------------------
// Standard selector with violation counts
// ---------------------------------------------------------------------------

/// One tab segment: short label + optional violation count, pre-measured.
struct StandardTab {
    label: String,
    count: String,
    /// Display width of " {status} {label}{count} " including padding.
    width: usize,
    status_icon: &'static str,
    status_color: Color,
}

fn render_standard_selector(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let Some(compliance_results) = app.compliance_results.as_ref() else {
        return;
    };

    // Build short-labelled segments. Short labels (e.g. "AI-Act", "BSI-AI")
    // keep each tab compact so all ~16 standards stay reachable.
    let tabs: Vec<StandardTab> = ComplianceLevel::all()
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let result = &compliance_results[i];
            let (status_icon, status_color) = if result.is_compliant {
                if result.warning_count > 0 {
                    ("\u{26a0}", scheme.warning)
                } else {
                    ("\u{2713}", scheme.success)
                }
            } else {
                ("\u{2717}", scheme.error)
            };
            let label = level.short_name().to_string();
            let total = result.violations.len();
            let count = if total > 0 {
                format!("({total})")
            } else {
                String::new()
            };
            // " {icon} {label}{count} " — icon + label + count + 3 spaces.
            let width = 3 + label.chars().count() + count.chars().count() + 1;
            StandardTab {
                label,
                count,
                width,
                status_icon,
                status_color,
            }
        })
        .collect();

    let block = Block::default()
        .title(" Compliance Standards (\u{2190}/\u{2192} to switch) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.primary));
    let inner_width = block.inner(area).width as usize;
    frame.render_widget(&block, area);

    let selected = app
        .compliance_state
        .selected_standard
        .min(tabs.len().saturating_sub(1));

    // Compute a contiguous window of tabs around the selection that fits the
    // inner width. Reserve 1 col on each side for the `‹`/`›` overflow markers
    // so the selected standard is ALWAYS visible regardless of terminal width.
    let budget = inner_width.saturating_sub(2);
    let mut start = selected;
    let mut end = selected; // inclusive
    let mut used = tabs.get(selected).map_or(0, |t| t.width);
    loop {
        let grew_left = start > 0 && used + tabs[start - 1].width <= budget;
        if grew_left {
            start -= 1;
            used += tabs[start].width;
        }
        let grew_right = end + 1 < tabs.len() && used + tabs[end + 1].width <= budget;
        if grew_right {
            end += 1;
            used += tabs[end].width;
        }
        if !grew_left && !grew_right {
            break;
        }
    }

    let mut spans: Vec<Span<'static>> = Vec::new();
    // Left overflow indicator.
    spans.push(Span::styled(
        if start > 0 { "\u{2039}" } else { " " }.to_string(),
        Style::default().fg(scheme.muted),
    ));
    for (i, tab) in tabs.iter().enumerate().take(end + 1).skip(start) {
        let is_selected = i == selected;
        let style = if is_selected {
            Style::default().fg(scheme.text).bold().bg(scheme.selection)
        } else {
            Style::default().fg(scheme.muted)
        };
        spans.push(Span::styled(
            format!(" {} ", tab.status_icon),
            Style::default().fg(tab.status_color),
        ));
        spans.push(Span::styled(tab.label.clone(), style));
        if !tab.count.is_empty() {
            spans.push(Span::styled(
                tab.count.clone(),
                Style::default().fg(scheme.muted),
            ));
        }
        spans.push(Span::styled(" ", style));
    }
    // Right overflow indicator.
    if end + 1 < tabs.len() {
        spans.push(Span::styled(
            "\u{203a}".to_string(),
            Style::default().fg(scheme.muted),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), block.inner(area));
}

// ---------------------------------------------------------------------------
// Category breakdown summary (replaces gauge + counts)
// ---------------------------------------------------------------------------

fn render_category_breakdown(frame: &mut Frame, area: Rect, result: &ComplianceResult) {
    let scheme = colors();

    let (status_color, status_text) = if result.is_compliant {
        if result.warning_count == 0 && result.info_count == 0 {
            (scheme.success, "COMPLIANT \u{2014} All checks passed")
        } else if result.warning_count == 0 {
            (scheme.success, "COMPLIANT \u{2014} With recommendations")
        } else {
            (scheme.warning, "COMPLIANT \u{2014} With warnings")
        }
    } else {
        (scheme.error, "NON-COMPLIANT \u{2014} Errors must be fixed")
    };

    // Count violations by category
    let mut cat_counts: HashMap<ViolationCategory, (usize, usize, usize)> = HashMap::new();
    for v in &result.violations {
        let entry = cat_counts.entry(v.category).or_default();
        match v.severity {
            ViolationSeverity::Error => entry.0 += 1,
            ViolationSeverity::Warning => entry.1 += 1,
            ViolationSeverity::Info => entry.2 += 1,
        }
    }

    // Sort categories by total count descending
    let mut sorted_cats: Vec<(ViolationCategory, usize, usize, usize)> = cat_counts
        .into_iter()
        .map(|(cat, (e, w, i))| (cat, e, w, i))
        .collect();
    sorted_cats.sort_by(|a, b| {
        (b.1 + b.2 + b.3)
            .cmp(&(a.1 + a.2 + a.3))
            .then(a.0.short_name().cmp(b.0.short_name()))
    });

    let total = result.violations.len().max(1) as f32;

    // Split: left = status + category bars, right = summary counts
    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Left panel: status line + top category breakdown bars
    let mut lines: Vec<Line> = vec![Line::from(vec![Span::styled(
        format!("  {status_text}"),
        Style::default().fg(status_color).bold(),
    )])];

    // Conformity-assessment route (CRA-P4.3): only when product class pinned.
    if let Some(summary) = result.conformity_summary.as_ref() {
        let satisfied = summary.evidence.iter().filter(|e| e.satisfied).count();
        let total = summary.evidence.len();
        lines.push(Line::from(vec![
            Span::styled("  Annex VIII: ", Style::default().fg(scheme.muted)),
            Span::styled(
                summary.route.label(),
                Style::default().fg(scheme.text).bold(),
            ),
            Span::styled(
                format!("  ({})", summary.product_class.label()),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!("  {satisfied}/{total} evidence"),
                Style::default().fg(if satisfied == total {
                    scheme.success
                } else {
                    scheme.warning
                }),
            ),
        ]));
    }

    // Show up to 4 categories with proportional bars
    let bar_max = (h_chunks[0].width as usize).saturating_sub(30).clamp(8, 40);
    for (cat, errors, warnings, infos) in sorted_cats.iter().take(4) {
        let count = errors + warnings + infos;
        let pct = (count as f32 / total) * 100.0;
        let filled = ((count as f32 / total) * bar_max as f32).round().max(1.0) as usize;
        let empty = bar_max.saturating_sub(filled);

        let bar_color = if *errors > 0 {
            scheme.error
        } else if *warnings > 0 {
            scheme.warning
        } else {
            scheme.info
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<10}", cat.short_name()),
                Style::default().fg(scheme.muted),
            ),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(bar_color)),
            Span::styled("\u{2591}".repeat(empty), Style::default().fg(scheme.border)),
            Span::styled(
                format!(" {count:>5} ({pct:.1}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    let left_widget = Paragraph::new(lines).block(
        Block::default()
            .title(format!(" {} ", result.level.name()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(status_color)),
    );
    frame.render_widget(left_widget, h_chunks[0]);

    // Right panel: severity counts
    let right_lines = vec![
        Line::from(vec![
            Span::styled(" Errors:   ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{:>6}", result.error_count),
                if result.error_count > 0 {
                    Style::default().fg(scheme.error).bold()
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(" Warnings: ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{:>6}", result.warning_count),
                if result.warning_count > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(" Info:     ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{:>6}", result.info_count),
                Style::default().fg(scheme.info),
            ),
        ]),
        Line::from(vec![Span::styled(
            " \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(scheme.border),
        )]),
        Line::from(vec![
            Span::styled(" Total:    ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{:>6}", result.violations.len()),
                Style::default().fg(scheme.text).bold(),
            ),
        ]),
    ];

    let right_widget = Paragraph::new(right_lines).block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.muted)),
    );
    frame.render_widget(right_widget, h_chunks[1]);
}

// ---------------------------------------------------------------------------
// Grouped violations view
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn render_grouped_violations(
    frame: &mut Frame,
    area: Rect,
    result: &ComplianceResult,
    all_results: &[ComplianceResult],
    selected: usize,
    scroll_offset: usize,
    severity_filter: SeverityFilter,
    affected_scroll: usize,
) {
    let scheme = colors();

    if result.violations.is_empty() {
        render_empty_compliance(frame, area, result, all_results);
        return;
    }

    let groups = build_groups(result, severity_filter);
    if groups.is_empty() {
        render_empty_compliance(frame, area, result, all_results);
        return;
    }

    let total_groups = groups.len();
    let total_violations: usize = groups.iter().map(|g| g.violations.len()).sum();

    // Compute layout: left = grouped table, right = affected elements for selected group
    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // --- Left: grouped table ---
    let viewport_height = h_chunks[0].height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(total_groups);

    let rows: Vec<Row> = groups
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_end.saturating_sub(scroll_offset))
        .map(|(i, group)| {
            let is_selected = i == selected;
            let row_style = if is_selected {
                Style::default().bg(scheme.selection)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(severity_text(group.severity)).style(severity_style(group.severity)),
                Cell::from(group.category.short_name()),
                Cell::from(group.pattern.clone()),
                Cell::from(format!("{}", group.violations.len()))
                    .style(Style::default().fg(scheme.text).bold()),
            ])
            .style(row_style)
        })
        .collect();

    let header = Row::new(vec!["Severity", "Category", "Issue Pattern", "Count"])
        .style(Style::default().fg(scheme.primary).bold())
        .bottom_margin(1);

    let widths = [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Min(20),
        Constraint::Length(7),
    ];

    let filter_label = if severity_filter == SeverityFilter::All {
        String::new()
    } else {
        format!(" [{}]", severity_filter.label())
    };
    let title = format!(
        " Violations (grouped: {total_groups} patterns, {total_violations} total){filter_label} ",
    );

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if result.is_compliant {
                scheme.warning
            } else {
                scheme.error
            })),
    );

    frame.render_widget(table, h_chunks[0]);

    // Scrollbar for left panel
    if total_groups > viewport_height {
        let mut scrollbar_state = ScrollbarState::new(total_groups.saturating_sub(viewport_height))
            .position(scroll_offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        frame.render_stateful_widget(
            scrollbar,
            h_chunks[0].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }

    // --- Right: affected elements for selected group ---
    if let Some(group) = groups.get(selected) {
        render_affected_elements(frame, h_chunks[1], group, affected_scroll);
    }
}

/// Render the right panel showing affected elements for a selected violation group.
///
/// Canonical representation across all compliance standards:
/// 1. Pattern header line (what the violation is)
/// 2. Summary line (N named components, M file paths)
/// 3. Named components listed individually with dup counts
/// 4. File paths collapsed by directory with file counts
fn render_affected_elements(
    frame: &mut Frame,
    area: Rect,
    group: &ViolationGroup<'_>,
    scroll_offset: usize,
) {
    let scheme = colors();
    let count = group.violations.len();
    let max_width = area.width.saturating_sub(5) as usize;

    // --- Build all content lines first, then apply scroll ---
    let mut content_lines: Vec<Line> = Vec::new();

    // --- Line 1: pattern header ---
    let pattern_display = crate::tui::widgets::truncate_str(&group.pattern, max_width);
    content_lines.push(Line::from(vec![Span::styled(
        format!("  {pattern_display}"),
        Style::default().fg(scheme.warning).italic(),
    )]));

    // --- Collect and classify elements ---
    let mut element_counts: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for v in &group.violations {
        let name = v.element.as_deref().unwrap_or("(document)");
        *element_counts.entry(name).or_default() += 1;
    }

    // Classify: named components vs file paths
    let mut named: Vec<(&str, usize)> = Vec::new();
    let mut paths: Vec<(&str, usize)> = Vec::new();
    for (name, cnt) in &element_counts {
        if name.contains('/') || name.starts_with('.') {
            paths.push((name, *cnt));
        } else {
            named.push((name, *cnt));
        }
    }
    named.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(b.0)));
    paths.sort_by(|a, b| a.0.cmp(b.0));

    // --- Line 2: summary counts ---
    let named_total: usize = named.iter().map(|(_, c)| c).sum();
    let path_total: usize = paths.iter().map(|(_, c)| c).sum();
    let mut summary_spans = vec![Span::styled("  ", Style::default())];
    if !named.is_empty() {
        summary_spans.push(Span::styled(
            format!("{named_total} named"),
            Style::default().fg(scheme.text),
        ));
    }
    if !named.is_empty() && !paths.is_empty() {
        summary_spans.push(Span::styled(
            " \u{2502} ",
            Style::default().fg(scheme.border),
        ));
    }
    if !paths.is_empty() {
        summary_spans.push(Span::styled(
            format!("{path_total} paths"),
            Style::default().fg(scheme.muted),
        ));
    }
    content_lines.push(Line::from(summary_spans));

    // Separator
    let sep_width = max_width.min(30);
    content_lines.push(Line::styled(
        format!("  {}", "\u{2500}".repeat(sep_width)),
        Style::default().fg(scheme.border),
    ));

    // --- Named components section ---
    for (name, dup_count) in &named {
        let mut spans = vec![Span::styled(
            format!("  {name}"),
            Style::default().fg(scheme.text),
        )];
        if *dup_count > 1 {
            spans.push(Span::styled(
                format!(" (\u{00d7}{dup_count})"),
                Style::default().fg(scheme.muted),
            ));
        }
        content_lines.push(Line::from(spans));
    }

    // --- File paths section (collapsed by directory) ---
    if !paths.is_empty() {
        let common_prefix = find_common_prefix(&paths);

        if !common_prefix.is_empty() {
            let prefix_display = if common_prefix.len() > max_width.saturating_sub(4) {
                format!(
                    "\u{2026}{}",
                    &common_prefix[common_prefix
                        .len()
                        .saturating_sub(max_width.saturating_sub(5))..]
                )
            } else {
                common_prefix.clone()
            };
            content_lines.push(Line::from(""));
            content_lines.push(Line::from(vec![
                Span::styled("  Paths: ", Style::default().fg(scheme.muted)),
                Span::styled(prefix_display, Style::default().fg(scheme.muted).italic()),
            ]));
        } else {
            content_lines.push(Line::from(""));
            content_lines.push(Line::styled("  Paths:", Style::default().fg(scheme.muted)));
        }

        // Group paths by first directory component after common prefix
        let mut dir_groups: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (path, cnt) in &paths {
            let suffix = if !common_prefix.is_empty() && path.starts_with(&common_prefix) {
                &path[common_prefix.len()..]
            } else {
                path
            };
            let dir = if let Some(slash_pos) = suffix.find('/') {
                format!("{}/", &suffix[..slash_pos])
            } else {
                suffix.to_string()
            };
            *dir_groups.entry(dir).or_default() += cnt;
        }

        let mut dir_sorted: Vec<(String, usize)> = dir_groups.into_iter().collect();
        dir_sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        for (dir, file_count) in &dir_sorted {
            let dir_display = crate::tui::widgets::truncate_str(dir, max_width.saturating_sub(12));
            content_lines.push(Line::from(vec![
                Span::styled(
                    format!("    {dir_display}"),
                    Style::default().fg(scheme.text),
                ),
                Span::styled(
                    format!(" ({file_count})"),
                    Style::default().fg(scheme.muted),
                ),
            ]));
        }
    }

    // --- Apply scroll and render ---
    let viewport_height = area.height.saturating_sub(2) as usize; // borders
    let total_lines = content_lines.len();
    let max_scroll = total_lines.saturating_sub(viewport_height);
    let effective_scroll = scroll_offset.min(max_scroll);

    let visible_lines: Vec<Line> = content_lines
        .into_iter()
        .skip(effective_scroll)
        .take(viewport_height)
        .collect();

    let scroll_hint = if total_lines > viewport_height {
        " K/J scroll "
    } else {
        ""
    };
    let title = format!(" Affected ({count}){scroll_hint}");

    let widget = Paragraph::new(visible_lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.info)),
    );
    frame.render_widget(widget, area);

    // Scrollbar for affected panel
    if total_lines > viewport_height {
        let mut scrollbar_state = ScrollbarState::new(max_scroll).position(effective_scroll);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Find the longest common directory prefix among file paths.
fn find_common_prefix(paths: &[(&str, usize)]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let first = paths[0].0;
    let mut prefix_len = match first.rfind('/') {
        Some(pos) => pos + 1,
        None => return String::new(),
    };

    for (path, _) in &paths[1..] {
        while prefix_len > 0 && !path.starts_with(&first[..prefix_len]) {
            // Shrink to previous directory boundary
            prefix_len = match first[..prefix_len.saturating_sub(1)].rfind('/') {
                Some(pos) => pos + 1,
                None => 0,
            };
        }
        if prefix_len == 0 {
            break;
        }
    }

    // Only use prefix if it's a meaningful directory (not just "./")
    let prefix = &first[..prefix_len];
    if prefix.len() <= 2 {
        String::new()
    } else {
        prefix.to_string()
    }
}

// ---------------------------------------------------------------------------
// Flat (ungrouped) violations view — original but with scrollbar + short names
// ---------------------------------------------------------------------------

fn render_flat_violations(
    frame: &mut Frame,
    area: Rect,
    result: &ComplianceResult,
    all_results: &[ComplianceResult],
    selected_violation: usize,
    scroll_offset: usize,
    severity_filter: SeverityFilter,
) {
    let scheme = colors();

    if result.violations.is_empty() {
        render_empty_compliance(frame, area, result, all_results);
        return;
    }

    // Apply severity filter
    let filtered: Vec<(usize, &Violation)> = result
        .violations
        .iter()
        .enumerate()
        .filter(|(_, v)| severity_filter.matches(v.severity))
        .collect();

    // Viewport scrolling: compute visible range
    let viewport_height = area.height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(filtered.len());

    // Create table rows from visible filtered violations
    let rows: Vec<Row> = filtered
        .iter()
        .skip(scroll_offset)
        .take(visible_end.saturating_sub(scroll_offset))
        .map(|&(i, violation)| {
            let is_selected = i == selected_violation;

            let row_style = if is_selected {
                Style::default().bg(scheme.selection)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(severity_text(violation.severity))
                    .style(severity_style(violation.severity)),
                Cell::from(violation.category.short_name()),
                Cell::from(violation.message.clone()),
                Cell::from(violation.element.clone().unwrap_or_default())
                    .style(Style::default().fg(scheme.muted)),
            ])
            .style(row_style)
        })
        .collect();

    let header = Row::new(vec!["Severity", "Category", "Issue", "Element"])
        .style(Style::default().fg(scheme.primary).bold())
        .bottom_margin(1);

    let widths = [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Min(30),
        Constraint::Length(20),
    ];

    // Show scroll position in title when scrolled, and filter info
    let filter_label = if severity_filter == SeverityFilter::All {
        String::new()
    } else {
        format!(" [{}]", severity_filter.label())
    };
    let title = if scroll_offset > 0 || visible_end < filtered.len() {
        format!(
            " Violations ({}/{}) [{}-{}/{}]{} ",
            filtered.len(),
            result.violations.len(),
            scroll_offset + 1,
            visible_end,
            filtered.len(),
            filter_label,
        )
    } else {
        format!(" Violations ({}){} ", filtered.len(), filter_label,)
    };

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if result.is_compliant {
                scheme.warning
            } else {
                scheme.error
            })),
    );

    frame.render_widget(table, area);

    // Scrollbar
    if filtered.len() > viewport_height {
        let mut scrollbar_state =
            ScrollbarState::new(filtered.len().saturating_sub(viewport_height))
                .position(scroll_offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Render empty compliance state with cross-standard overview.
fn render_empty_compliance(
    frame: &mut Frame,
    area: Rect,
    result: &ComplianceResult,
    all_results: &[ComplianceResult],
) {
    let scheme = colors();

    let mut lines = vec![
        Line::from(""),
        Line::styled(
            "  \u{2713} All compliance checks passed!",
            Style::default().fg(scheme.success).bold(),
        ),
        Line::from(""),
        Line::styled(
            format!("  This SBOM meets {} requirements.", result.level.name()),
            Style::default().fg(scheme.text),
        ),
        Line::styled(
            format!("  {}", result.level.description()),
            Style::default().fg(scheme.muted),
        ),
        Line::from(""),
    ];

    // Cross-standard overview: show status of all standards
    lines.push(Line::styled(
        "  Cross-Standard Overview:",
        Style::default().fg(scheme.text).bold(),
    ));
    lines.push(Line::from(""));

    let all_levels = ComplianceLevel::all();
    for (i, level) in all_levels.iter().enumerate() {
        if let Some(r) = all_results.get(i) {
            let (icon, icon_color) = if r.is_compliant {
                if r.warning_count > 0 {
                    ("\u{26a0}", scheme.warning)
                } else {
                    ("\u{2713}", scheme.success)
                }
            } else {
                ("\u{2717}", scheme.error)
            };

            let detail = if r.is_compliant && r.violations.is_empty() {
                "passed".to_string()
            } else if r.is_compliant {
                format!("{} warnings", r.warning_count)
            } else {
                format!("{} errors, {} warnings", r.error_count, r.warning_count)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("    {icon} "), Style::default().fg(icon_color)),
                Span::styled(
                    format!("{:<25}", level.name()),
                    Style::default().fg(scheme.text),
                ),
                Span::styled(detail, Style::default().fg(scheme.muted)),
            ]));
        }
    }

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Compliance Status ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.success)),
    );
    frame.render_widget(widget, area);
}

// ---------------------------------------------------------------------------
// Help bar
// ---------------------------------------------------------------------------

fn render_help_bar(frame: &mut Frame, area: Rect, severity_filter: SeverityFilter, grouped: bool) {
    let scheme = colors();

    let group_label = if grouped { "Grouped" } else { "Flat" };

    let help = Line::from(vec![
        Span::styled("\u{2190}/\u{2192}", Style::default().fg(scheme.primary)),
        Span::styled(" standard  ", Style::default().fg(scheme.muted)),
        Span::styled("j/k", Style::default().fg(scheme.primary)),
        Span::styled(" navigate  ", Style::default().fg(scheme.muted)),
        Span::styled("Enter", Style::default().fg(scheme.primary)),
        Span::styled(" details  ", Style::default().fg(scheme.muted)),
        Span::styled("g", Style::default().fg(scheme.primary)),
        Span::styled(
            format!(" view [{group_label}]  "),
            Style::default().fg(scheme.muted),
        ),
        Span::styled("f", Style::default().fg(scheme.primary)),
        Span::styled(
            format!(" filter [{}]  ", severity_filter.label()),
            Style::default().fg(scheme.muted),
        ),
        Span::styled("E", Style::default().fg(scheme.primary)),
        Span::styled(" export  ", Style::default().fg(scheme.muted)),
        Span::styled("?", Style::default().fg(scheme.primary)),
        Span::styled(" help", Style::default().fg(scheme.muted)),
    ]);

    let paragraph = Paragraph::new(help).block(Block::default().borders(Borders::ALL));

    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/// Severity filter for violation display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityFilter {
    /// Show all violations
    #[default]
    All,
    /// Show only errors
    ErrorsOnly,
    /// Show errors and warnings
    WarningsAndAbove,
}

impl SeverityFilter {
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::ErrorsOnly,
            Self::ErrorsOnly => Self::WarningsAndAbove,
            Self::WarningsAndAbove => Self::All,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::ErrorsOnly => "Errors",
            Self::WarningsAndAbove => "Warn+",
        }
    }

    pub const fn matches(self, severity: ViolationSeverity) -> bool {
        match self {
            Self::All => true,
            Self::ErrorsOnly => matches!(severity, ViolationSeverity::Error),
            Self::WarningsAndAbove => matches!(
                severity,
                ViolationSeverity::Error | ViolationSeverity::Warning
            ),
        }
    }
}

/// Compliance view state for multi-standard comparison (view mode)
#[derive(Debug, Clone)]
pub struct StandardComplianceState {
    /// Currently selected compliance standard
    pub selected_standard: usize,
    /// Currently selected violation in the list
    pub selected_violation: usize,
    /// Scroll offset for violations
    pub scroll_offset: usize,
    /// Whether the detail overlay is shown for the selected violation
    pub show_detail: bool,
    /// Severity filter for displayed violations
    pub severity_filter: SeverityFilter,
    /// Whether to show grouped (true) or flat (false) view
    pub grouped: bool,
    /// Scroll offset for the affected elements panel (right side, grouped mode)
    pub affected_scroll: usize,
}

impl Default for StandardComplianceState {
    fn default() -> Self {
        Self {
            selected_standard: 2, // Default to NTIA
            selected_violation: 0,
            scroll_offset: 0,
            show_detail: false,
            severity_filter: SeverityFilter::All,
            grouped: true, // Default to grouped view
            affected_scroll: 0,
        }
    }
}

impl StandardComplianceState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn next_standard(&mut self) {
        let max = ComplianceLevel::all().len();
        self.selected_standard = (self.selected_standard + 1) % max;
        self.selected_violation = 0;
        self.scroll_offset = 0;
        self.affected_scroll = 0;
    }

    pub const fn prev_standard(&mut self) {
        let max = ComplianceLevel::all().len();
        self.selected_standard = if self.selected_standard == 0 {
            max - 1
        } else {
            self.selected_standard - 1
        };
        self.selected_violation = 0;
        self.scroll_offset = 0;
        self.affected_scroll = 0;
    }

    pub fn select_next(&mut self, max_violations: usize) {
        if max_violations > 0 {
            let new = (self.selected_violation + 1).min(max_violations - 1);
            if new != self.selected_violation {
                self.selected_violation = new;
                self.affected_scroll = 0; // reset right panel scroll on selection change
            }
        }
    }

    pub const fn select_prev(&mut self) {
        let old = self.selected_violation;
        self.selected_violation = self.selected_violation.saturating_sub(1);
        if self.selected_violation != old {
            self.affected_scroll = 0;
        }
    }

    /// Toggle between grouped and flat view modes.
    pub fn toggle_grouped(&mut self) {
        self.grouped = !self.grouped;
        self.selected_violation = 0;
        self.scroll_offset = 0;
        self.affected_scroll = 0;
    }

    /// Scroll affected panel up.
    pub const fn affected_scroll_up(&mut self) {
        self.affected_scroll = self.affected_scroll.saturating_sub(1);
    }

    /// Scroll affected panel down.
    pub fn affected_scroll_down(&mut self, max_lines: usize) {
        if self.affected_scroll < max_lines.saturating_sub(1) {
            self.affected_scroll += 1;
        }
    }

    /// Adjust `scroll_offset` to keep the selected violation visible within the viewport.
    pub const fn adjust_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        if self.selected_violation < self.scroll_offset {
            self.scroll_offset = self.selected_violation;
        } else if self.selected_violation >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_violation + 1 - viewport_height;
        }
    }
}

/// Compute compliance results for all standards
#[must_use]
pub fn compute_compliance_results(
    sbom: &crate::model::NormalizedSbom,
    sidecar: Option<&crate::model::CraSidecarMetadata>,
) -> Vec<ComplianceResult> {
    ComplianceLevel::all()
        .iter()
        .map(|level| {
            let mut checker = ComplianceChecker::new(*level);
            if let Some(sc) = sidecar {
                checker = checker.with_sidecar(sc.clone());
            }
            checker.check(sbom)
        })
        .collect()
}
