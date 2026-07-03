//! Summary view with visual gauges and charts.

use crate::tui::app::AppMode;
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Paragraph},
};

pub fn render_summary(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    match ctx.mode {
        AppMode::Diff | AppMode::View => render_diff_summary(frame, area, ctx),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_summary(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result else {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "--",
            "No diff data loaded",
            Some("Summary requires a completed diff analysis"),
            None,
        );
        return;
    };
    let old_count = ctx
        .old_sbom
        .map_or(0, crate::model::NormalizedSbom::component_count);
    let new_count = ctx
        .new_sbom
        .map_or(0, crate::model::NormalizedSbom::component_count);

    // Check if vulnerability chart has data (used for dynamic height)
    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let has_vulns = severity_counts.values().any(|&v| v > 0);
    let chart_height = if has_vulns { 10 } else { 3 };

    // Count findings for dynamic height
    let findings_count = count_findings(result);

    // Determine height for insights + policy merged row
    let has_quality_delta = result.quality_delta.is_some();
    let has_match_metrics = result.match_metrics.is_some();
    let has_vex_data = result
        .vulnerabilities
        .introduced
        .iter()
        .chain(&result.vulnerabilities.resolved)
        .chain(&result.vulnerabilities.persistent)
        .any(|v| v.vex_state.is_some())
        || !result.vulnerabilities.vex_changes.is_empty();
    let insights_policy_h: u16 = if has_quality_delta || has_match_metrics || has_vex_data {
        5
    } else {
        3
    };

    // Merged summary height: risk (2 lines) + blank line + findings + border (2)
    let summary_height = (findings_count + 5).clamp(7, 13) as u16;

    // Main layout: merged summary, stats, insights+policy, charts, all changes
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(summary_height), // Row 0: Risk + Findings (merged)
            Constraint::Length(6),              // Row 1: Stats cards (4 columns)
            Constraint::Length(insights_policy_h), // Row 2: Insights + Policy (merged)
            Constraint::Length(chart_height),   // Row 3: Charts
            Constraint::Min(6),                 // Row 4: All changes (scrollable)
        ])
        .split(area);

    // Row 0: Merged risk assessment + key findings
    render_summary_header(frame, main_chunks[0], ctx);

    // Row 1: Stats cards (6 lines, 4 columns)
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(main_chunks[1]);

    render_components_card(frame, stats_chunks[0], result, old_count, new_count);
    render_dependencies_card(frame, stats_chunks[1], result);
    render_vulnerabilities_card(frame, stats_chunks[2], ctx);
    render_license_card(frame, stats_chunks[3], ctx);

    // Row 2: Insights + Policy merged
    render_insights_policy_row(frame, main_chunks[2], ctx);

    // Row 3: Bar charts (or collapsed when no vulns)
    if has_vulns {
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[3]);

        render_ecosystem_breakdown_chart(frame, chart_chunks[0], result);
        render_severity_chart(frame, chart_chunks[1], result);
    } else {
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[3]);

        render_ecosystem_breakdown_chart(frame, chart_chunks[0], result);
        render_sbom_comparison(frame, chart_chunks[1], ctx);
    }

    // Row 4: All changes (scrollable, sorted by importance)
    render_all_changes(frame, main_chunks[4], ctx);
}

/// Render the Quality Delta / Matching / VEX insights row (items 1.1, 1.2, 1.3).
fn render_insights_row(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let has_quality = result.quality_delta.is_some();
    let has_matching = result.match_metrics.is_some();
    let total_vulns = result.vulnerabilities.introduced.len()
        + result.vulnerabilities.resolved.len()
        + result.vulnerabilities.persistent.len();
    let has_vex = total_vulns > 0
        && (result
            .vulnerabilities
            .introduced
            .iter()
            .chain(&result.vulnerabilities.resolved)
            .chain(&result.vulnerabilities.persistent)
            .any(|v| v.vex_state.is_some())
            || !result.vulnerabilities.vex_changes.is_empty());

    // Split row into columns for each present insight card
    let col_count = usize::from(has_quality) + usize::from(has_matching) + usize::from(has_vex);
    if col_count == 0 {
        return;
    }
    let pct = 100u16 / col_count as u16;
    let constraints: Vec<Constraint> = (0..col_count)
        .map(|_| Constraint::Percentage(pct))
        .collect();
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

    let mut col = 0;

    // --- 1.1: Quality Delta card ---
    if let Some(qd) = &result.quality_delta {
        render_quality_delta_card(frame, chunks[col], qd);
        col += 1;
    }

    // --- 1.2: Match Metrics card ---
    if let Some(mm) = &result.match_metrics {
        render_match_metrics_card(frame, chunks[col], mm);
        col += 1;
    }

    // --- 1.3: VEX Coverage card ---
    if has_vex {
        render_vex_coverage_card(frame, chunks[col], result);
    }
}

/// Render quality delta card (item 1.1).
fn render_quality_delta_card(frame: &mut Frame, area: Rect, qd: &crate::diff::QualityDelta) {
    let scheme = colors();
    let delta = qd.overall_score_delta;
    let is_improvement = delta > 0.0;
    let delta_color = if is_improvement {
        scheme.success
    } else if delta < 0.0 {
        scheme.error
    } else {
        scheme.text_muted
    };
    let arrow = if is_improvement {
        "\u{25b2}"
    } else if delta < 0.0 {
        "\u{25bc}"
    } else {
        "="
    };

    // Line 1: grade transition + delta
    let old_grade = qd
        .old_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);
    let new_grade = qd
        .new_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);

    let mut lines = vec![Line::from(vec![
        Span::styled("Quality: ", Style::default().fg(scheme.text_muted)),
        Span::styled(old_grade, Style::default().fg(scheme.text).bold()),
        Span::styled(" \u{2192} ", Style::default().fg(scheme.text_muted)),
        Span::styled(new_grade, Style::default().fg(scheme.text).bold()),
        Span::styled(
            format!(" ({arrow} {delta:+.1})"),
            Style::default().fg(delta_color).bold(),
        ),
    ])];

    // Line 2: regressions
    if !qd.regressions.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Regressions: ", Style::default().fg(scheme.error)),
            Span::styled(qd.regressions.join(", "), Style::default().fg(scheme.error)),
        ]));
    }

    // Line 3: improvements
    if !qd.improvements.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Improvements: ", Style::default().fg(scheme.success)),
            Span::styled(
                qd.improvements.join(", "),
                Style::default().fg(scheme.success),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Quality Impact ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(delta_color)),
    );
    frame.render_widget(paragraph, area);
}

/// Render match metrics card (item 1.2).
fn render_match_metrics_card(frame: &mut Frame, area: Rect, mm: &crate::diff::MatchMetrics) {
    let scheme = colors();
    let total_matched = mm.exact_matches + mm.fuzzy_matches + mm.rule_matches;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Matched: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", mm.exact_matches),
                Style::default().fg(scheme.success).bold(),
            ),
            Span::styled(" exact, ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", mm.fuzzy_matches),
                Style::default().fg(scheme.warning).bold(),
            ),
            Span::styled(" fuzzy", Style::default().fg(scheme.text_muted)),
            if mm.rule_matches > 0 {
                Span::styled(
                    format!(", {} rule", mm.rule_matches),
                    Style::default().fg(scheme.secondary),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled("Unmatched: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} old", mm.unmatched_old),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(", ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} new", mm.unmatched_new),
                Style::default().fg(scheme.added),
            ),
        ]),
    ];

    if total_matched > 0 {
        lines.push(Line::from(vec![
            Span::styled("Avg score: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.2}", mm.avg_match_score),
                Style::default().fg(if mm.avg_match_score >= 0.9 {
                    scheme.success
                } else if mm.avg_match_score >= 0.7 {
                    scheme.warning
                } else {
                    scheme.error
                }),
            ),
            Span::styled("  Min: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.2}", mm.min_match_score),
                Style::default().fg(if mm.min_match_score >= 0.8 {
                    scheme.success
                } else if mm.min_match_score >= 0.6 {
                    scheme.warning
                } else {
                    scheme.error
                }),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Matching ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );
    frame.render_widget(paragraph, area);
}

/// Render VEX coverage card (item 1.3).
fn render_vex_coverage_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let vex = result.vulnerabilities.vex_summary();

    let coverage_color = if vex.coverage_pct >= 80.0 {
        scheme.success
    } else if vex.coverage_pct >= 50.0 {
        scheme.warning
    } else {
        scheme.error
    };

    let mut lines = vec![Line::from(vec![
        Span::styled("VEX: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{:.0}%", vex.coverage_pct),
            Style::default().fg(coverage_color).bold(),
        ),
        Span::styled(
            format!(" ({}/{} covered)", vex.with_vex, vex.total_vulns),
            Style::default().fg(scheme.text_muted),
        ),
    ])];

    if vex.actionable > 0 {
        lines.push(Line::from(vec![
            Span::styled("Actionable: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", vex.actionable),
                Style::default().fg(scheme.warning).bold(),
            ),
            Span::styled(" require attention", Style::default().fg(scheme.text_muted)),
        ]));
    }

    let vex_changes_count = result.vulnerabilities.vex_changes.len();
    if vex_changes_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("VEX transitions: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{vex_changes_count}"),
                Style::default().fg(scheme.accent).bold(),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" VEX Coverage ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(coverage_color)),
    );
    frame.render_widget(paragraph, area);
}

/// Compute risk level label and color from a diff result.
fn compute_risk_level(
    result: &crate::diff::DiffResult,
    scheme: &crate::tui::theme::ColorScheme,
) -> (&'static str, Color) {
    let major_bumps = count_major_bumps(&result.components.modified);
    let critical_vulns = *result
        .vulnerabilities
        .introduced_by_severity()
        .get("Critical")
        .unwrap_or(&0);
    let high_vulns = *result
        .vulnerabilities
        .introduced_by_severity()
        .get("High")
        .unwrap_or(&0);
    let new_vulns = result.summary.vulnerabilities_introduced;
    let total_changes = result.summary.components_added
        + result.summary.components_removed
        + result.summary.components_modified;

    if critical_vulns > 0 {
        ("Critical Risk", scheme.critical)
    } else if high_vulns > 0 || major_bumps >= 3 {
        ("High Risk", scheme.error)
    } else if major_bumps > 0 || new_vulns > 0 || result.summary.components_removed > 3 {
        ("Medium Risk", scheme.warning)
    } else if total_changes > 0 {
        ("Low Risk", scheme.success)
    } else {
        ("No Changes", scheme.muted)
    }
}

/// Count major version bumps in modified components.
fn count_major_bumps(modified: &[crate::diff::ComponentChange]) -> usize {
    modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .count()
}

/// Count the number of key findings that will be generated (used for dynamic height).
fn count_findings(result: &crate::diff::DiffResult) -> usize {
    let mut count = 0;

    // Critical vulnerabilities (up to 2)
    let critical_vulns = result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .count();
    count += critical_vulns.min(2);

    // Major version bumps (up to 3)
    let major_bumps: usize = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .take(3)
        .count();
    count += major_bumps;

    // License conflicts
    if !result.licenses.conflicts.is_empty() {
        count += 1;
    }

    // Quality regressions
    if let Some(delta) = &result.quality_delta
        && !delta.regressions.is_empty()
    {
        count += 1;
    }

    // Added components
    if !result.components.added.is_empty() {
        count += 1;
    }

    // Removed components
    if !result.components.removed.is_empty() {
        count += 1;
    }

    // Vulnerability status (always 1 line)
    count += 1;

    count
}

/// Merged summary header: risk assessment + key findings in one bordered card.
/// Reduces visual clutter by combining two sections into one with a separator.
fn render_summary_header(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let (risk_label, risk_color) = compute_risk_level(result, &scheme);
    let score = result.semantic_score;
    let total_changes = result.summary.total_changes;
    let major_bumps = count_major_bumps(&result.components.modified);

    let mut lines: Vec<Line> = Vec::new();

    // Line 1: Risk badge + Score + Changes
    let mut line1 = vec![
        Span::styled(
            format!(" {risk_label} "),
            Style::default().fg(Color::Black).bg(risk_color).bold(),
        ),
        Span::raw("  Score: "),
        Span::styled(
            format!("{score:.1}"),
            Style::default().fg(risk_color).bold(),
        ),
        Span::raw("  \u{2502}  "),
        Span::styled(
            format!("{total_changes} changes"),
            Style::default().fg(scheme.text),
        ),
    ];
    if major_bumps > 0 {
        line1.push(Span::styled(
            format!(", {major_bumps} major bumps"),
            Style::default().fg(scheme.warning).bold(),
        ));
    }
    lines.push(Line::from(line1));

    // Line 2: SBOM metadata + Quality + Matching
    let mut line2: Vec<Span> = Vec::new();
    if let Some(old) = ctx.old_sbom {
        line2.push(Span::styled(
            format!("{} {}", old.document.format, old.document.format_version),
            Style::default().fg(scheme.accent),
        ));
        line2.push(Span::raw("  "));
    }
    if let Some(delta) = result.quality_delta.as_ref() {
        let old_g = delta
            .old_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        let new_g = delta
            .new_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        line2.push(Span::styled(
            format!("Quality: {old_g}\u{2192}{new_g}"),
            Style::default().fg(scheme.muted),
        ));
        line2.push(Span::raw("  "));
    }
    if let Some(metrics) = result.match_metrics.as_ref() {
        line2.push(Span::styled(
            format!(
                "Match: {} exact, {} fuzzy",
                metrics.exact_matches, metrics.fuzzy_matches
            ),
            Style::default().fg(scheme.muted),
        ));
    }
    if !line2.is_empty() {
        lines.push(Line::from(line2));
    }

    // Separator line
    lines.push(Line::from(Span::styled(
        "\u{2500}".repeat(area.width.saturating_sub(2) as usize),
        Style::default().fg(scheme.border),
    )));

    // Key findings (reuse logic from render_key_findings)
    // Critical vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .take(2)
    {
        lines.push(Line::from(vec![
            Span::styled(
                " \u{26a0} CRITICAL ",
                Style::default().fg(Color::Black).bg(scheme.critical).bold(),
            ),
            Span::styled(
                format!(" {} in {}", vuln.id, vuln.component_name),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }
    // Major version bumps
    for comp in result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .take(3)
    {
        let old_v = comp.old_version.as_deref().unwrap_or("?");
        let new_v = comp.new_version.as_deref().unwrap_or("?");
        lines.push(Line::from(vec![
            Span::styled(
                " \u{25b2} MAJOR ",
                Style::default().fg(Color::Black).bg(scheme.warning).bold(),
            ),
            Span::raw(format!(" {} ", comp.name)),
            Span::styled(old_v.to_string(), Style::default().fg(scheme.muted)),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.modified)),
            Span::styled(
                new_v.to_string(),
                Style::default().fg(scheme.modified).bold(),
            ),
        ]));
    }
    // License conflicts
    if !result.licenses.conflicts.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!("{} license conflicts", result.licenses.conflicts.len()),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }
    // Quality regressions
    if let Some(delta) = &result.quality_delta
        && !delta.regressions.is_empty()
    {
        lines.push(Line::from(vec![
            Span::styled(" \u{25bc} ", Style::default().fg(scheme.warning)),
            Span::styled(
                format!("Quality regressions: {}", delta.regressions.join(", ")),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }
    // Added/removed summaries
    let added_count = result.components.added.len();
    if added_count > 0 {
        let names: Vec<&str> = result
            .components
            .added
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if added_count > 4 {
            format!(", +{} more", added_count - 4)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(" + ", Style::default().fg(scheme.added).bold()),
            Span::styled(
                format!("{added_count} added"),
                Style::default().fg(scheme.added),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }
    let removed_count = result.components.removed.len();
    if removed_count > 0 {
        let names: Vec<&str> = result
            .components
            .removed
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if removed_count > 4 {
            format!(", +{} more", removed_count - 4)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
            Span::styled(
                format!("{removed_count} removed"),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }
    // Vulnerability status
    let new_vulns = result.vulnerabilities.introduced.len();
    if new_vulns > 0 {
        lines.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!("{new_vulns} new vulnerabilities"),
                Style::default().fg(scheme.critical),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(" \u{2713} ", Style::default().fg(scheme.added)),
            Span::styled("No new vulnerabilities", Style::default().fg(scheme.added)),
        ]));
    }

    let block = Block::default()
        .title(" Summary ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(risk_color));
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Compact risk header (kept for reference, no longer called from main layout).
#[allow(dead_code)]
fn render_risk_header(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let (risk_label, risk_color) = compute_risk_level(result, &scheme);
    let score = result.semantic_score;
    let total_changes = result.summary.total_changes;
    let major_bumps = count_major_bumps(&result.components.modified);

    // Line 1: Risk badge + Score + Changes
    let mut line1_spans = vec![
        Span::styled(
            format!(" {risk_label} "),
            Style::default().fg(Color::Black).bg(risk_color).bold(),
        ),
        Span::raw("  Score: "),
        Span::styled(
            format!("{score:.1}"),
            Style::default().fg(risk_color).bold(),
        ),
        Span::raw("  \u{2502}  "),
        Span::styled(
            format!("{total_changes} changes"),
            Style::default().fg(scheme.text),
        ),
    ];
    if major_bumps > 0 {
        line1_spans.push(Span::styled(
            format!(", {major_bumps} major bumps"),
            Style::default().fg(scheme.warning).bold(),
        ));
    }
    let line1 = Line::from(line1_spans);

    // Line 2: Quality delta + Matching + Enrichment
    let mut line2_spans: Vec<Span> = Vec::new();
    if let Some(delta) = result.quality_delta.as_ref() {
        let old_g = delta
            .old_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        let new_g = delta
            .new_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        let delta_str = if delta.overall_score_delta > 0.5 {
            format!(" (+{:.1})", delta.overall_score_delta)
        } else if delta.overall_score_delta < -0.5 {
            format!(" ({:.1})", delta.overall_score_delta)
        } else {
            " (unchanged)".to_string()
        };
        line2_spans.push(Span::raw("Quality: "));
        line2_spans.push(Span::styled(
            format!("{old_g} \u{2192} {new_g}"),
            Style::default().fg(scheme.text).bold(),
        ));
        line2_spans.push(Span::styled(delta_str, Style::default().fg(scheme.muted)));
    }
    if let Some(metrics) = result.match_metrics.as_ref() {
        if !line2_spans.is_empty() {
            line2_spans.push(Span::raw("  \u{2502}  "));
        }
        line2_spans.push(Span::raw("Matching: "));
        line2_spans.push(Span::styled(
            format!(
                "{} exact, {} fuzzy",
                metrics.exact_matches, metrics.fuzzy_matches
            ),
            Style::default().fg(scheme.text),
        ));
        if metrics.avg_match_score > 0.0 {
            line2_spans.push(Span::styled(
                format!("  Avg: {:.2}", metrics.avg_match_score),
                Style::default().fg(scheme.muted),
            ));
        }
    }
    #[cfg(feature = "enrichment")]
    {
        if ctx.enrichment_stats_old.is_some() || ctx.enrichment_stats_new.is_some() {
            line2_spans.push(Span::styled(
                "  [enriched]",
                Style::default().fg(scheme.added),
            ));
        }
    }
    let line2 = Line::from(line2_spans);

    // Line 3: SBOM metadata (format, component counts, dependency counts)
    let mut line3_spans: Vec<Span> = Vec::new();
    if let Some(old) = ctx.old_sbom {
        let fmt = &old.document.format;
        line3_spans.push(Span::styled(
            format!("{fmt} {}", old.document.format_version),
            Style::default().fg(scheme.accent),
        ));
    }
    if let (Some(old), Some(new)) = (ctx.old_sbom, ctx.new_sbom) {
        line3_spans.push(Span::raw("  \u{2502}  ")); // │ separator
        line3_spans.push(Span::styled(
            format!(
                "Old: {} comps, {} deps",
                old.component_count(),
                old.edges.len()
            ),
            Style::default().fg(scheme.muted),
        ));
        line3_spans.push(Span::raw("  "));
        line3_spans.push(Span::styled(
            format!(
                "New: {} comps, {} deps",
                new.component_count(),
                new.edges.len()
            ),
            Style::default().fg(scheme.text),
        ));
    }
    let line3 = Line::from(line3_spans);

    let block = Block::default()
        .title(" Risk Assessment ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(risk_color));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height >= 1 {
        frame
            .buffer_mut()
            .set_line(inner.x, inner.y, &line1, inner.width);
    }
    if inner.height >= 2 {
        frame
            .buffer_mut()
            .set_line(inner.x, inner.y + 1, &line2, inner.width);
    }
    if inner.height >= 3 {
        frame
            .buffer_mut()
            .set_line(inner.x, inner.y + 2, &line3, inner.width);
    }
}

/// Key findings section (kept for reference, logic merged into render_summary_header).
#[allow(dead_code)]
fn render_key_findings(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let mut findings: Vec<Line> = Vec::new();

    // 1. Critical vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .take(2)
    {
        findings.push(Line::from(vec![
            Span::styled(
                " \u{26a0} CRITICAL ",
                Style::default().fg(Color::Black).bg(scheme.critical).bold(),
            ),
            Span::styled(
                format!(" {} in {}", vuln.id, vuln.component_name),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }

    // 2. Major version bumps
    for comp in result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .take(3)
    {
        let old_v = comp.old_version.as_deref().unwrap_or("?");
        let new_v = comp.new_version.as_deref().unwrap_or("?");
        findings.push(Line::from(vec![
            Span::styled(
                " \u{25b2} MAJOR ",
                Style::default().fg(Color::Black).bg(scheme.warning).bold(),
            ),
            Span::raw(format!(" {} ", comp.name)),
            Span::styled(old_v.to_string(), Style::default().fg(scheme.muted)),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.modified)),
            Span::styled(
                new_v.to_string(),
                Style::default().fg(scheme.modified).bold(),
            ),
        ]));
    }

    // 3. License conflicts
    if !result.licenses.conflicts.is_empty() {
        findings.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!(
                    "{} license conflicts detected",
                    result.licenses.conflicts.len()
                ),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }

    // 4. Quality regressions
    if let Some(delta) = &result.quality_delta
        && !delta.regressions.is_empty()
    {
        findings.push(Line::from(vec![
            Span::styled(" \u{25bc} ", Style::default().fg(scheme.warning)),
            Span::styled(
                format!("Quality regressions: {}", delta.regressions.join(", ")),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }

    // 5. Added components summary
    let added_count = result.components.added.len();
    if added_count > 0 {
        let names: Vec<&str> = result
            .components
            .added
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if added_count > 4 {
            format!(", +{} more", added_count - 4)
        } else {
            String::new()
        };
        findings.push(Line::from(vec![
            Span::styled(" + ", Style::default().fg(scheme.added).bold()),
            Span::styled(
                format!("{added_count} added"),
                Style::default().fg(scheme.added),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    // 6. Removed components summary
    let removed_count = result.components.removed.len();
    if removed_count > 0 {
        let names: Vec<&str> = result
            .components
            .removed
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if removed_count > 4 {
            format!(", +{} more", removed_count - 4)
        } else {
            String::new()
        };
        findings.push(Line::from(vec![
            Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
            Span::styled(
                format!("{removed_count} removed"),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    // 7. Vulnerability status
    let new_vulns = result.vulnerabilities.introduced.len();
    if new_vulns > 0 {
        findings.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!("{new_vulns} new vulnerabilities introduced"),
                Style::default().fg(scheme.critical),
            ),
        ]));
    } else {
        findings.push(Line::from(vec![
            Span::styled(" \u{2713} ", Style::default().fg(scheme.added)),
            Span::styled("No new vulnerabilities", Style::default().fg(scheme.added)),
        ]));
    }

    let block = Block::default()
        .title(" Key Findings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));
    let paragraph = Paragraph::new(findings).block(block);
    frame.render_widget(paragraph, area);
}

fn render_components_card(
    frame: &mut Frame,
    area: Rect,
    result: &crate::diff::DiffResult,
    old_count: usize,
    new_count: usize,
) {
    let scheme = colors();
    let added = result.summary.components_added;
    let removed = result.summary.components_removed;
    let modified = result.summary.components_modified;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED    ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED  ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(vec![
            Span::styled(
                " ~ MODIFIED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {modified}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Old: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{old_count}  ")),
            Span::styled("New: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{new_count}  ")),
            Span::styled("Changed: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{}", added + removed + modified)),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Components ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(paragraph, area);
}

fn render_dependencies_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let added = result.summary.dependencies_added;
    let removed = result.summary.dependencies_removed;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(""),
        {
            let net = added as i32 - removed as i32;
            if net == 0 {
                Line::from(Span::styled(
                    "No net change",
                    Style::default().fg(scheme.muted),
                ))
            } else {
                Line::from(vec![
                    Span::styled("Net change: ", Style::default().fg(scheme.muted)),
                    Span::styled(
                        format!("{net:+}"),
                        if net > 0 {
                            Style::default().fg(scheme.added)
                        } else {
                            Style::default().fg(scheme.removed)
                        },
                    ),
                ])
            }
        },
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Dependencies ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.critical)),
    );

    frame.render_widget(paragraph, area);
}

fn render_license_card(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let new_count = result.licenses.new_licenses.len();
    let removed_count = result.licenses.removed_licenses.len();
    let changed_count = result.licenses.component_changes.len();
    let conflicts = result.licenses.conflicts.len();

    let border_color = if conflicts > 0 {
        scheme.critical
    } else if new_count + removed_count > 0 {
        scheme.warning
    } else {
        scheme.border
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" New:      ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{new_count}"),
                Style::default().fg(if new_count > 0 {
                    scheme.added
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Removed:  ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{removed_count}"),
                Style::default().fg(if removed_count > 0 {
                    scheme.removed
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Changed:  ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{changed_count}"),
                Style::default().fg(if changed_count > 0 {
                    scheme.modified
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Conflicts:", Style::default().fg(scheme.muted)),
            Span::styled(
                format!(" {conflicts}"),
                Style::default().fg(if conflicts > 0 {
                    scheme.critical
                } else {
                    scheme.text
                }),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" Licenses ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Merged insights + policy row.
fn render_insights_policy_row(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let has_quality = result.quality_delta.is_some();
    let has_matching = result.match_metrics.is_some();
    let total_vulns = result.vulnerabilities.introduced.len()
        + result.vulnerabilities.resolved.len()
        + result.vulnerabilities.persistent.len();
    let has_vex = total_vulns > 0
        && (result
            .vulnerabilities
            .introduced
            .iter()
            .chain(&result.vulnerabilities.resolved)
            .chain(&result.vulnerabilities.persistent)
            .any(|v| v.vex_state.is_some())
            || !result.vulnerabilities.vex_changes.is_empty());
    let has_insights = has_quality || has_matching || has_vex;

    if has_insights {
        // Split: insights on left, policy on right
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        render_insights_row(frame, cols[0], result);
        render_policy_compact(frame, cols[1], ctx);
    } else {
        // Policy takes full width
        render_policy_compact(frame, area, ctx);
    }
}

/// Compact policy compliance widget.
fn render_policy_compact(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let compliance = ctx.compliance_state;

    let mut spans = vec![
        Span::styled("Policy: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {} ", compliance.policy_preset.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  "),
    ];

    if let Some(ref result) = compliance.result {
        let (status, status_style) = if result.passes {
            (
                " PASS ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.success)
                    .bold(),
            )
        } else {
            (
                " FAIL ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.error)
                    .bold(),
            )
        };

        spans.push(Span::styled(status, status_style));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("Score: {}", result.score),
            Style::default().fg(if result.score >= 80 {
                scheme.success
            } else if result.score >= 50 {
                scheme.warning
            } else {
                scheme.error
            }),
        ));
        spans.push(Span::raw("  "));

        let critical = result.count_by_severity(crate::tui::security::PolicySeverity::Critical);
        let high = result.count_by_severity(crate::tui::security::PolicySeverity::High);
        let medium = result.count_by_severity(crate::tui::security::PolicySeverity::Medium);
        let low = result.count_by_severity(crate::tui::security::PolicySeverity::Low);

        if critical > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{critical} "),
                Style::default().fg(scheme.critical).bold(),
            ));
        }
        if high > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{high} "),
                Style::default().fg(scheme.high),
            ));
        }
        if medium > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{medium} "),
                Style::default().fg(scheme.medium),
            ));
        }
        if low > 0 {
            spans.push(Span::styled(
                format!("\u{25cb}{low} "),
                Style::default().fg(scheme.low),
            ));
        }

        if let Some(violation) = result.violations.first() {
            spans.push(Span::styled(
                "\u{2502} ",
                Style::default().fg(scheme.border),
            ));
            spans.push(Span::styled(
                crate::tui::widgets::truncate_str(&violation.description, 50),
                Style::default().fg(scheme.text_muted).italic(),
            ));
        }
    } else {
        spans.push(Span::styled(
            "Not checked  ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled("[P]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " check  ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled("[p]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " cycle",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let border_style = if compliance.passes() {
        Style::default().fg(scheme.success)
    } else if compliance.checked {
        Style::default().fg(scheme.error)
    } else {
        Style::default().fg(scheme.border)
    };

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .title(" Security Policy ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(paragraph, area);
}

fn render_vulnerabilities_card(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let introduced = result.summary.vulnerabilities_introduced;
    let resolved = result.summary.vulnerabilities_resolved;
    let persistent = result.summary.vulnerabilities_persistent;

    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0);
    let high = *severity_counts.get("High").unwrap_or(&0);

    #[cfg(feature = "enrichment")]
    let is_enriched = ctx.enrichment_stats_old.is_some() || ctx.enrichment_stats_new.is_some();
    #[cfg(not(feature = "enrichment"))]
    let is_enriched = false;

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                " \u{25b2} NEW     ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {introduced}")),
        ]),
        Line::from(vec![
            Span::styled(
                " \u{25bc} FIXED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {resolved}")),
        ]),
        Line::from(vec![
            Span::styled(
                " \u{25cf} PERSIST ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {persistent}")),
        ]),
    ];

    if !is_enriched && introduced == 0 && resolved == 0 && persistent == 0 {
        lines.push(Line::from(Span::styled(
            " Not enriched",
            Style::default().fg(scheme.muted).italic(),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Critical: ", Style::default().fg(scheme.critical).bold()),
            Span::raw(format!("{critical}  ")),
            Span::styled("High: ", Style::default().fg(scheme.high)),
            Span::raw(format!("{high}")),
        ]));
    }

    let border_color = if critical > 0 {
        scheme.critical
    } else if introduced > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Vulnerabilities ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    frame.render_widget(paragraph, area);
}

fn render_ecosystem_breakdown_chart(
    frame: &mut Frame,
    area: Rect,
    result: &crate::diff::DiffResult,
) {
    let scheme = colors();

    // Count changes per ecosystem across added, removed, modified
    let mut eco_counts: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for comp in &result.components.added {
        let eco = comp.ecosystem.as_deref().unwrap_or("unknown");
        *eco_counts.entry(eco).or_default() += 1;
    }
    for comp in &result.components.removed {
        let eco = comp.ecosystem.as_deref().unwrap_or("unknown");
        *eco_counts.entry(eco).or_default() += 1;
    }
    for comp in &result.components.modified {
        let eco = comp.ecosystem.as_deref().unwrap_or("unknown");
        *eco_counts.entry(eco).or_default() += 1;
    }

    let mut ecosystems: Vec<_> = eco_counts.into_iter().collect();
    ecosystems.sort_by(|a, b| b.1.cmp(&a.1));

    let palette = scheme.chart_palette();
    let bars: Vec<Bar> = ecosystems
        .iter()
        .take(5)
        .enumerate()
        .map(|(i, (name, count))| {
            Bar::default()
                .value(*count)
                .label(Line::from(crate::tui::widgets::truncate_str(name, 8)))
                .style(Style::default().fg(palette[i % palette.len()]))
        })
        .collect();

    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" Changes by Ecosystem ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .bar_width(7)
        .bar_gap(1)
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text))
        .data(BarGroup::default().bars(&bars));

    frame.render_widget(bar_chart, area);
}

fn render_severity_chart(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0) as u64;
    let high = *severity_counts.get("High").unwrap_or(&0) as u64;
    let medium = *severity_counts.get("Medium").unwrap_or(&0) as u64;
    let low = *severity_counts.get("Low").unwrap_or(&0) as u64;

    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" New Vulnerabilities by Severity ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .bar_width(6)
        .bar_gap(1)
        .bar_style(Style::default().fg(scheme.error))
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text))
        .data(
            BarGroup::default().bars(&[
                Bar::default()
                    .value(critical)
                    .label(Line::from("Crit"))
                    .style(Style::default().fg(scheme.critical)),
                Bar::default()
                    .value(high)
                    .label(Line::from("High"))
                    .style(Style::default().fg(scheme.high)),
                Bar::default()
                    .value(medium)
                    .label(Line::from("Med"))
                    .style(Style::default().fg(scheme.medium)),
                Bar::default()
                    .value(low)
                    .label(Line::from("Low"))
                    .style(Style::default().fg(scheme.low)),
            ]),
        );

    frame.render_widget(bar_chart, area);
}

/// Priority for sorting changes by importance.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum ChangePriority {
    CriticalVuln,
    MajorBump,
    Downgrade,
    HighVuln,
    Removed,
    Added,
    MinorBump,
    PatchBump,
    Other,
}

/// Map a [`MetadataChangeKind`] to a short badge label and the scheme color
/// used for both the badge background and the field name.
fn metadata_badge(
    kind: crate::diff::MetadataChangeKind,
    scheme: &crate::tui::theme::ColorScheme,
) -> (&'static str, Color) {
    match kind {
        crate::diff::MetadataChangeKind::Added => (" + META ", scheme.added),
        crate::diff::MetadataChangeKind::Removed => (" - META ", scheme.removed),
        crate::diff::MetadataChangeKind::Modified => (" ~ META ", scheme.modified),
    }
}

/// Build the document-metadata change lines for the All Changes panel.
///
/// These mirror the `field: old -> new` rows the CLI summary report renders
/// (`reports/summary.rs`) but were previously invisible in the diff TUI even
/// though `summary.total_changes` already counts them — so the "N changes"
/// header was inflated by rows the user could not see. Rendered as a labeled
/// block at the top of the panel (rather than appended to the priority-sorted
/// list, where they would be clipped) so metadata changes stay visible. Each
/// row is colored by add/removed/modified kind.
fn metadata_change_lines<'a>(
    result: &'a crate::diff::DiffResult,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Line<'a>> {
    if result.metadata_changes.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![Line::from(vec![
        Span::styled("\u{2500}\u{2500} ", Style::default().fg(scheme.border)),
        Span::styled(
            "Metadata Changes",
            Style::default().fg(scheme.accent).bold(),
        ),
        Span::styled(" \u{2500}\u{2500}", Style::default().fg(scheme.border)),
    ])];

    for change in &result.metadata_changes {
        let (badge, color) = metadata_badge(change.kind, scheme);
        let old = change.old_value.as_deref().unwrap_or("\u{2205}");
        let new = change.new_value.as_deref().unwrap_or("\u{2205}");
        lines.push(Line::from(vec![
            Span::styled(badge, Style::default().fg(Color::Black).bg(color).bold()),
            Span::raw(" "),
            Span::styled(change.field.clone(), Style::default().fg(color)),
            Span::styled(": ", Style::default().fg(scheme.muted)),
            Span::styled(old.to_string(), Style::default().fg(scheme.removed)),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.muted)),
            Span::styled(new.to_string(), Style::default().fg(scheme.added)),
        ]));
    }

    lines
}

/// A single change entry with priority and rendered line.
struct ChangeEntry<'a> {
    priority: ChangePriority,
    line: Line<'a>,
}

/// All changes section with importance sorting and scrollable list.
fn render_sbom_comparison(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let (Some(old), Some(new)) = (ctx.old_sbom, ctx.new_sbom) else {
        return;
    };

    let rows: Vec<(&str, usize, usize)> = vec![
        ("Components", old.component_count(), new.component_count()),
        ("Dependencies", old.edges.len(), new.edges.len()),
        (
            "With licenses",
            old.components
                .values()
                .filter(|c| !c.licenses.declared.is_empty())
                .count(),
            new.components
                .values()
                .filter(|c| !c.licenses.declared.is_empty())
                .count(),
        ),
        (
            "With vulns",
            old.components
                .values()
                .filter(|c| !c.vulnerabilities.is_empty())
                .count(),
            new.components
                .values()
                .filter(|c| !c.vulnerabilities.is_empty())
                .count(),
        ),
    ];

    let mut lines: Vec<Line> = Vec::new();

    // Header row
    lines.push(Line::from(vec![
        Span::styled(format!("{:<14}", ""), Style::default()),
        Span::styled(
            format!("{:>8}", "Old"),
            Style::default().fg(scheme.muted).bold(),
        ),
        Span::styled(
            format!("{:>8}", "New"),
            Style::default().fg(scheme.muted).bold(),
        ),
        Span::styled(
            format!("{:>8}", "Delta"),
            Style::default().fg(scheme.muted).bold(),
        ),
    ]));

    // Data rows
    for (label, old_v, new_v) in &rows {
        let diff = *new_v as isize - *old_v as isize;
        let delta_span = match diff.cmp(&0) {
            std::cmp::Ordering::Greater => {
                Span::styled(format!("+{diff}"), Style::default().fg(scheme.added))
            }
            std::cmp::Ordering::Less => {
                Span::styled(format!("{diff}"), Style::default().fg(scheme.removed))
            }
            std::cmp::Ordering::Equal => {
                Span::styled("0".to_string(), Style::default().fg(scheme.muted))
            }
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {label:<13}"), Style::default().fg(scheme.text)),
            Span::styled(format!("{old_v:>8}"), Style::default().fg(scheme.muted)),
            Span::styled(format!("{new_v:>8}"), Style::default().fg(scheme.text)),
            Span::raw("    "),
            delta_span,
        ]));
    }

    // Timestamps
    let old_date = old.document.created.format("%Y-%m-%d").to_string();
    let new_date = new.document.created.format("%Y-%m-%d").to_string();
    lines.push(Line::from(vec![
        Span::styled(" Created      ", Style::default().fg(scheme.text)),
        Span::styled(format!("{old_date:>8}"), Style::default().fg(scheme.muted)),
        Span::styled(format!("   {new_date}"), Style::default().fg(scheme.text)),
    ]));

    let block = Block::default()
        .title(" SBOM Comparison ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_all_changes(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result else {
        return;
    };

    let mut entries: Vec<ChangeEntry> = Vec::new();

    // Critical vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
    {
        entries.push(ChangeEntry {
            priority: ChangePriority::CriticalVuln,
            line: Line::from(vec![
                Span::styled(
                    " \u{26a0} CRITICAL ",
                    Style::default()
                        .fg(scheme.badge_fg_light)
                        .bg(scheme.critical)
                        .bold(),
                ),
                Span::raw(" "),
                Span::styled(vuln.id.clone(), Style::default().fg(scheme.critical).bold()),
                Span::styled(" in ", Style::default().fg(scheme.muted)),
                Span::raw(vuln.component_name.clone()),
                Span::styled(
                    vuln.description
                        .as_ref()
                        .map(|d| format!(" - {}", crate::tui::widgets::truncate_str(d, 40)))
                        .unwrap_or_default(),
                    Style::default().fg(scheme.muted),
                ),
            ]),
        });
    }

    // High vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "High")
    {
        entries.push(ChangeEntry {
            priority: ChangePriority::HighVuln,
            line: Line::from(vec![
                Span::styled(
                    " \u{26a0} HIGH ",
                    Style::default()
                        .fg(scheme.badge_fg_light)
                        .bg(scheme.high)
                        .bold(),
                ),
                Span::raw(" "),
                Span::styled(vuln.id.clone(), Style::default().fg(scheme.high).bold()),
                Span::styled(" in ", Style::default().fg(scheme.muted)),
                Span::raw(vuln.component_name.clone()),
            ]),
        });
    }

    // Modified components (sorted by version change level)
    for comp in &result.components.modified {
        let level = version_change_level(comp.old_version.as_deref(), comp.new_version.as_deref());

        let (priority, name_color, level_label) = match level {
            VersionLevel::Major => (
                ChangePriority::MajorBump,
                scheme.error,
                Some(Span::styled(
                    " MAJOR",
                    Style::default().fg(scheme.error).bold(),
                )),
            ),
            VersionLevel::Downgrade => (
                ChangePriority::Downgrade,
                scheme.error,
                Some(Span::styled(
                    " \u{26a0} downgrade",
                    Style::default().fg(scheme.error).bold(),
                )),
            ),
            VersionLevel::Minor => (
                ChangePriority::MinorBump,
                scheme.warning,
                Some(Span::styled(" minor", Style::default().fg(scheme.warning))),
            ),
            VersionLevel::Patch => (
                ChangePriority::PatchBump,
                scheme.success,
                Some(Span::styled(" patch", Style::default().fg(scheme.success))),
            ),
            VersionLevel::Unknown => (ChangePriority::Other, scheme.modified, None),
        };

        let mut spans = vec![
            Span::styled(" ~ ", Style::default().fg(name_color).bold()),
            Span::styled(comp.name.clone(), Style::default().fg(name_color)),
            Span::raw(" "),
            Span::styled(
                comp.old_version.as_deref().unwrap_or("?").to_string(),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.muted)),
            Span::styled(
                comp.new_version.as_deref().unwrap_or("?").to_string(),
                Style::default().fg(scheme.added),
            ),
        ];
        if let Some(label) = level_label {
            spans.push(label);
        }

        entries.push(ChangeEntry {
            priority,
            line: Line::from(spans),
        });
    }

    // Removed components
    for comp in &result.components.removed {
        entries.push(ChangeEntry {
            priority: ChangePriority::Removed,
            line: Line::from(vec![
                Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
                Span::styled(comp.name.clone(), Style::default().fg(scheme.removed)),
                Span::styled(
                    format!(" {}", comp.old_version.as_deref().unwrap_or("")),
                    Style::default().fg(scheme.muted),
                ),
            ]),
        });
    }

    // Added components (with vuln warning)
    for comp in &result.components.added {
        let has_vuln = result
            .vulnerabilities
            .introduced
            .iter()
            .any(|v| v.component_id == comp.id);
        let icon = if has_vuln { "\u{26a0}" } else { "+" };
        let style = if has_vuln {
            Style::default().fg(scheme.error)
        } else {
            Style::default().fg(scheme.added)
        };

        let mut spans = vec![
            Span::styled(format!(" {icon} "), style.bold()),
            Span::styled(comp.name.clone(), style),
            Span::styled(
                format!(" {}", comp.new_version.as_deref().unwrap_or("")),
                Style::default().fg(scheme.muted),
            ),
        ];
        if has_vuln {
            spans.push(Span::styled(
                " (has vulnerabilities)",
                Style::default().fg(scheme.error),
            ));
        }

        entries.push(ChangeEntry {
            priority: ChangePriority::Added,
            line: Line::from(spans),
        });
    }

    // Sort by priority
    entries.sort_by_key(|e| e.priority);

    // Count of real change rows (component/vuln entries + metadata changes),
    // excluding the metadata section header, for the panel title.
    let total = entries.len() + result.metadata_changes.len();

    // Document-metadata changes (author/tool/timestamp/spec-version/lifecycle/
    // signature/version) are counted in summary.total_changes but were
    // otherwise unrepresented in the diff TUI. Render them as a labeled block at
    // the top so they reconcile the "N changes" header and stay visible above
    // the priority-sorted component/vuln entries.
    let mut lines: Vec<Line> = metadata_change_lines(result, &scheme);

    if entries.is_empty() {
        if lines.is_empty() {
            lines.push(Line::styled(
                "No significant changes to highlight",
                Style::default().fg(scheme.muted),
            ));
        }
    } else {
        lines.extend(entries.into_iter().map(|e| e.line));
    }
    let major = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .count();
    let minor = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Minor
            )
        })
        .count();
    let patch = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Patch
            )
        })
        .count();
    let added = result.components.added.len();
    let removed = result.components.removed.len();
    let meta = result.metadata_changes.len();
    let meta_suffix = if meta > 0 {
        format!("meta:{meta} ")
    } else {
        String::new()
    };
    let title = format!(
        " All Changes ({total}) \u{2014} MAJOR:{major} minor:{minor} patch:{patch} +{added} -{removed} {meta_suffix}"
    );

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .scroll((0, 0));

    frame.render_widget(paragraph, area);
}


enum VersionLevel {
    Patch,
    Minor,
    Major,
    Downgrade,
    Unknown,
}

fn version_change_level(old: Option<&str>, new: Option<&str>) -> VersionLevel {
    match (old, new) {
        (Some(o), Some(n)) => {
            if let (Ok(old_v), Ok(new_v)) = (semver::Version::parse(o), semver::Version::parse(n)) {
                if new_v.major > old_v.major {
                    VersionLevel::Major
                } else if new_v.major < old_v.major {
                    VersionLevel::Downgrade
                } else if new_v.minor > old_v.minor {
                    VersionLevel::Minor
                } else if new_v.minor < old_v.minor {
                    VersionLevel::Downgrade
                } else if new_v.patch > old_v.patch {
                    VersionLevel::Patch
                } else if new_v.patch < old_v.patch {
                    VersionLevel::Downgrade
                } else {
                    VersionLevel::Unknown
                }
            } else {
                VersionLevel::Unknown
            }
        }
        _ => VersionLevel::Unknown,
    }
}
