//! Overview tab for `ViewApp` - high-level SBOM statistics.

use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use crate::tui::widgets::{extract_display_name, format_count};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
};

pub fn render_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    match app.bom_profile {
        crate::model::BomProfile::Cbom => render_cbom_overview(frame, area, app),
        crate::model::BomProfile::AiBom => render_aibom_overview(frame, area, app),
        crate::model::BomProfile::Sbom => render_sbom_overview(frame, area, app),
    }
}

fn render_sbom_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    // Split into left (stats) and right (details) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_stats_panel(frame, chunks[0], app);
    render_details_panel(frame, chunks[1], app);
}

fn render_cbom_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    use crate::model::{ComponentType, CryptoAssetType};
    use crate::quality::CryptographyMetrics;

    let metrics = CryptographyMetrics::from_sbom(&app.sbom);
    let scheme = colors();

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // ── Left: asset summary ──
    // A zero denominator must read n/a: quantum_readiness_score() is `None`
    // when there are no algorithms, and a full green gauge over zero crypto
    // assets is a lie (mirrors the status bar's "Quantum: n/a").
    let gauge_line = match metrics.quantum_readiness_score() {
        None => Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "n/a — no cryptographic assets found",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Some(readiness) => {
            // Gauge thresholds keep green/yellow/red semantics via the theme's
            // success/warning/error slots (error, not critical, preserves the
            // red hue).
            let readiness_color = if readiness >= 80.0 {
                scheme.success
            } else if readiness >= 40.0 {
                scheme.warning
            } else {
                scheme.error
            };

            let bar_filled = ((readiness / 100.0) * 20.0) as usize;
            let bar_empty = 20_usize.saturating_sub(bar_filled);
            let bar = format!(
                "{}{}",
                "\u{2588}".repeat(bar_filled),
                "\u{2591}".repeat(bar_empty)
            );

            Line::from(vec![
                Span::raw(" "),
                Span::styled(bar, Style::default().fg(readiness_color)),
                Span::styled(
                    format!(" {readiness:.0}%"),
                    Style::default()
                        .fg(readiness_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "  ({}/{})",
                    metrics.quantum_safe_count, metrics.algorithms_count
                )),
            ])
        }
    };

    let mut left_lines = vec![
        Line::from(vec![Span::styled(
            " Quantum Readiness  ",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        gauge_line,
        Line::raw(""),
        Line::styled(
            format!(" Algorithms:    {}", metrics.algorithms_count),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("   Quantum-safe  {}", metrics.quantum_safe_count)),
        Line::from(format!(
            "   Vulnerable    {}",
            metrics.quantum_vulnerable_count
        )),
    ];

    if metrics.weak_algorithm_count > 0 {
        // Weak/broken crypto aligns with the SBOM screens' critical severity.
        left_lines.push(Line::styled(
            format!("   Weak/broken   {}", metrics.weak_algorithm_count),
            Style::default().fg(scheme.critical),
        ));
    }
    if metrics.hybrid_pqc_count > 0 {
        left_lines.push(Line::styled(
            format!("   Hybrid PQC    {}", metrics.hybrid_pqc_count),
            Style::default().fg(scheme.info),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Certificates:  {}", metrics.certificates_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if metrics.expired_certificates > 0 {
        left_lines.push(Line::styled(
            format!("   Expired       {}", metrics.expired_certificates),
            Style::default().fg(scheme.error),
        ));
    }
    if metrics.expiring_soon_certificates > 0 {
        left_lines.push(Line::styled(
            format!("   Expiring      {}", metrics.expiring_soon_certificates),
            Style::default().fg(scheme.warning),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Keys:          {}", metrics.keys_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if metrics.compromised_keys > 0 {
        left_lines.push(Line::styled(
            format!("   Compromised   {}", metrics.compromised_keys),
            Style::default().fg(scheme.critical),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Protocols:     {}", metrics.protocols_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));

    let left_panel = Paragraph::new(left_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" CBOM Overview "),
    );
    frame.render_widget(left_panel, chunks[0]);

    // ── Right: PQC migration status + warnings ──
    let mut right_lines = vec![
        Line::styled(
            " PQC Migration Status",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
    ];

    // List algorithms with their PQC status
    let algos: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Algorithm)
        })
        .collect();

    for comp in &algos {
        // Shared indicator (!/Q/V/?) — the same broken-practice predicate the
        // Algorithms tab and PQC Compliance use, so AES-128-ECB can never
        // show a blessing here while failing SBOM-PQC-008 one tab over.
        let qi = crate::tui::shared::crypto::quantum_indicator(comp);
        right_lines.push(Line::from(vec![
            Span::raw("  "),
            qi,
            Span::raw(" "),
            Span::raw(&comp.name),
        ]));
    }

    // Weak algorithm warnings
    if !metrics.weak_algorithm_names.is_empty() {
        right_lines.push(Line::raw(""));
        right_lines.push(Line::styled(
            " Weak Algorithms",
            Style::default()
                .fg(scheme.critical)
                .add_modifier(Modifier::BOLD),
        ));
        for name in &metrics.weak_algorithm_names {
            right_lines.push(Line::styled(
                format!("  ! {name}"),
                Style::default().fg(scheme.critical),
            ));
        }
    }

    let right_panel = Paragraph::new(right_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Migration & Warnings ")
                // Explain the !/Q/V/? glyphs (same legend as the Algorithms tab).
                .title_bottom(crate::tui::shared::crypto::quantum_legend(
                    chunks[1].width.saturating_sub(2),
                )),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(right_panel, chunks[1]);
}

/// AI-BOM overview: shared stat cards on top, then AI-tailored panels
/// (model/dataset inventory + AI-readiness gauge). The generic
/// vulnerability/ecosystem panels keep the remainder only when the terminal
/// is tall enough to hold them whole.
fn render_aibom_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let compact = area.height < 20;
    let cards_h: u16 = if compact { 5 } else { 8 };
    let generic_h: u16 = 8;
    // AI panels need at least ~10 rows to say anything useful; only spend
    // rows on the generic panels beyond that.
    let show_generic = area.height >= cards_h + 12 + generic_h;

    let mut constraints = vec![Constraint::Length(cards_h), Constraint::Min(8)];
    if show_generic {
        constraints.push(Constraint::Length(generic_h));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_summary_cards(frame, rows[0], app, compact);

    let ai_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_ai_inventory_panel(frame, ai_cols[0], app);
    render_ai_readiness_panel(frame, ai_cols[1], app);

    if show_generic {
        let generic_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[2]);
        render_vuln_breakdown(frame, generic_cols[0], app);
        render_ecosystem_dist(frame, generic_cols[1], app);
    }
}

/// Left AI panel: model and dataset inventories by name, mirroring what the
/// Models/Datasets tabs list (`MachineLearningModel` / `Data` components).
fn render_ai_inventory_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    use crate::model::ComponentType;
    use crate::tui::widgets::truncate_str;

    let scheme = colors();
    let name_width = area.width.saturating_sub(6) as usize;

    let mut models: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::MachineLearningModel)
        .collect();
    models.sort_by(|a, b| a.name.cmp(&b.name));
    let mut datasets: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::Data)
        .collect();
    datasets.sort_by(|a, b| a.name.cmp(&b.name));

    // Split the inner rows between the two sections: each gets its header
    // plus an equal share of the remaining rows (min 1 name row each).
    let inner_rows = area.height.saturating_sub(2) as usize;
    let name_budget = inner_rows.saturating_sub(3) / 2; // 2 headers + 1 spacer
    let per_section = name_budget.max(1);

    let mut lines: Vec<Line> = Vec::new();
    let push_section = |lines: &mut Vec<Line>, title: &str, comps: &[&crate::model::Component]| {
        lines.push(Line::from(vec![Span::styled(
            format!(" {}: {}", title, comps.len()),
            Style::default().fg(scheme.accent).bold(),
        )]));
        // Reserve the last budgeted row for the rollup when overflowing.
        let shown = if comps.len() > per_section {
            per_section.saturating_sub(1)
        } else {
            comps.len()
        };
        for comp in comps.iter().take(shown) {
            let ver = comp.version.as_deref().unwrap_or("");
            lines.push(Line::from(vec![
                Span::styled(
                    format!("   {}", truncate_str(&comp.name, name_width)),
                    Style::default().fg(scheme.text),
                ),
                Span::styled(format!("  {ver}"), Style::default().fg(scheme.text_muted)),
            ]));
        }
        if comps.len() > shown {
            lines.push(Line::styled(
                format!("   ... and {} more", comps.len() - shown),
                Style::default().fg(scheme.text_muted),
            ));
        }
        if comps.is_empty() {
            lines.push(Line::styled("   none", Style::default().fg(scheme.muted)));
        }
    };

    push_section(&mut lines, "Models", &models);
    lines.push(Line::raw(""));
    push_section(&mut lines, "Datasets", &datasets);

    let panel = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" AI Inventory ")
            .border_style(Style::default().fg(colors().primary)),
    );
    frame.render_widget(panel, area);
}

/// Right AI panel: the AI-readiness score the app already computed for this
/// profile (`quality_report` is scored with the AiReadiness profile), plus
/// model-card completeness — no new scoring, just the headline numbers with
/// a pointer at the dedicated tab.
fn render_ai_readiness_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let report = &app.quality_report;

    let mut lines: Vec<Line> = Vec::new();

    match report.ai_readiness_metrics.as_ref() {
        None => {
            lines.push(Line::styled(
                " n/a — no AI readiness metrics for this document",
                Style::default().fg(scheme.text_muted),
            ));
        }
        Some(metrics) if metrics.is_not_applicable() => {
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(
                    format!(
                        "n/a — {}",
                        metrics
                            .na_reason
                            .as_deref()
                            .unwrap_or("no ML model components found")
                    ),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }
        Some(metrics) => {
            // Same gauge semantics as the AI-Readiness tab header: rounded
            // score, grade-colored 20-cell bar.
            let score = report.overall_score.round() as u16;
            let (grade_col, grade_word) =
                crate::tui::shared::quality::grade_color_and_label(report.grade);
            let bar_max = 20usize;
            let filled = ((f32::from(score.min(100)) / 100.0) * bar_max as f32).round() as usize;
            let bar = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(bar_max - filled);
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(bar, Style::default().fg(grade_col)),
                Span::styled(
                    format!(" {score}/100"),
                    Style::default().fg(scheme.text).bold(),
                ),
                Span::styled(
                    format!("  {} {}", report.grade.letter(), grade_word),
                    Style::default().fg(grade_col).bold(),
                ),
            ]));
            lines.push(Line::raw(""));

            let passed = metrics.checks.iter().filter(|c| c.passed).count();
            lines.push(Line::from(vec![
                Span::styled(
                    " Checks passed:    ",
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(
                    format!("{passed}/{}", metrics.checks.len()),
                    Style::default().fg(scheme.text).bold(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    " Fully documented: ",
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(
                    format!(
                        "{}/{} models",
                        metrics.components_fully_documented, metrics.ml_component_count
                    ),
                    Style::default().fg(scheme.text).bold(),
                ),
            ]));
        }
    }

    // Honest pointer at the dedicated tab, using its live ordinal.
    if let Some(pos) =
        crate::tui::view::app::ViewTab::AiReadiness.shortcut_for_profile(app.bom_profile)
    {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled(format!(" [{pos}]"), Style::default().fg(scheme.accent)),
            Span::styled(
                " AI-Readiness tab: per-check detail",
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" AI Readiness ")
                .border_style(Style::default().fg(scheme.primary)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(panel, area);
}

fn render_stats_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    // Compute adaptive height for ecosystem panel: entries + 2 (borders)
    let eco_count = app.stats.ecosystem_counts.len();
    let eco_height = (eco_count + 2).min(12) as u16; // cap at 12 rows

    // The stacked bordered panels need this much height; below it (e.g. the
    // 80x24 minimum, where the severity panel rendered as an empty box) fall
    // back to a single compact panel that keeps every section visible.
    // License is a Min(6) constraint that degrades gracefully in the tall
    // layout; treat its true minimum as 3 so borderline heights (e.g. an
    // EOL-enriched SBOM at 120x40) keep the richer stacked panels.
    let required = 8 + 8 + (if app.stats.eol_enriched { 8 } else { 0 }) + eco_height + 3;
    if area.height < required {
        render_stats_panel_compact(frame, area, app);
        return;
    }

    if app.stats.eol_enriched {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),          // Summary cards
                Constraint::Length(8),          // EOL breakdown
                Constraint::Length(8),          // Vulnerability breakdown
                Constraint::Length(eco_height), // Ecosystem distribution (adaptive)
                Constraint::Min(6),             // License distribution
            ])
            .split(area);

        render_summary_cards(frame, chunks[0], app, false);
        render_eol_breakdown(frame, chunks[1], app);
        render_vuln_breakdown(frame, chunks[2], app);
        render_ecosystem_dist(frame, chunks[3], app);
        render_license_dist(frame, chunks[4], app);
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),          // Summary cards
                Constraint::Length(8),          // Vulnerability breakdown
                Constraint::Length(eco_height), // Ecosystem distribution (adaptive)
                Constraint::Min(6),             // License distribution
            ])
            .split(area);

        render_summary_cards(frame, chunks[0], app, false);
        render_vuln_breakdown(frame, chunks[1], app);
        render_ecosystem_dist(frame, chunks[2], app);
        render_license_dist(frame, chunks[3], app);
    }
}

/// Compact stats layout for short terminals: summary cards on top, then ONE
/// bordered panel interleaving section headers with the distribution lines,
/// severity first (the highest-value signal always renders).
fn render_stats_panel_compact(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    render_summary_cards(frame, chunks[0], app, true);

    let section_header = |title: &str| -> Line<'static> {
        Line::from(Span::styled(
            format!("\u{2500}\u{2500} {title} \u{2500}\u{2500}"),
            Style::default().fg(scheme.border),
        ))
    };

    let inner_height = chunks[1].height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_header("Vulnerability Severity"));
    lines.extend(vuln_breakdown_lines(app));
    if app.stats.eol_enriched {
        lines.push(section_header("End-of-Life Status"));
        lines.extend(eol_breakdown_lines(app));
    }

    // Split whatever height remains between ecosystem and license sections
    // (header + rows each); zero-row budgets still show the header so users
    // know the content exists.
    let rem = inner_height.saturating_sub(lines.len());
    let eco_budget = rem / 2;
    let lic_budget = rem.saturating_sub(eco_budget);
    if eco_budget >= 1 {
        lines.push(section_header("Ecosystems"));
        // Budget counts the header; give every remaining row to data (the
        // "Other" rollup line may nudge into the next section's budget).
        lines.extend(ecosystem_dist_lines(app, eco_budget.saturating_sub(1)));
    }
    if lic_budget >= 1 {
        lines.push(section_header("Licenses"));
        lines.extend(license_dist_lines(app, lic_budget.saturating_sub(1)));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Statistics ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );
    frame.render_widget(para, chunks[1]);
}

fn render_summary_cards(frame: &mut Frame, area: Rect, app: &ViewApp, compact: bool) {
    let scheme = colors();
    let stats = &app.stats;

    let card_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    // Components card
    let mut comp_content = Vec::new();
    if !compact {
        comp_content.push(Line::from(""));
    }
    comp_content.push(Line::from(vec![Span::styled(
        format_count(stats.component_count),
        Style::default()
            .fg(scheme.primary)
            .bold()
            .add_modifier(Modifier::BOLD),
    )]));
    comp_content.push(Line::styled(
        "Components",
        Style::default().fg(scheme.muted),
    ));
    if !compact {
        comp_content.push(Line::from(""));
    }
    comp_content.push(Line::from(vec![Span::styled(
        crate::tui::shared::text::count_noun(stats.ecosystem_counts.len(), "ecosystem"),
        Style::default().fg(scheme.muted),
    )]));

    let comp_para = Paragraph::new(comp_content)
        .block(
            Block::default()
                .title(" Components ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(comp_para, card_chunks[0]);

    // Vulnerabilities card
    let vuln_color = if stats.critical_count > 0 {
        scheme.critical
    } else if stats.high_count > 0 {
        scheme.high
    } else if stats.vuln_count > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    // Width-aware label: at narrow card widths "Vulnerabilities" was hard-
    // clipped to "Vulnerabili" — use a short form that stays a real word.
    let vuln_narrow = card_chunks[1].width < 19;
    let vuln_label = if vuln_narrow {
        "Vulns"
    } else {
        "Vulnerabilities"
    };
    let mut vuln_content = Vec::new();
    if !compact {
        vuln_content.push(Line::from(""));
    }
    vuln_content.push(Line::from(vec![Span::styled(
        format_count(stats.vuln_count),
        Style::default()
            .fg(vuln_color)
            .bold()
            .add_modifier(Modifier::BOLD),
    )]));
    vuln_content.push(Line::styled(vuln_label, Style::default().fg(scheme.muted)));
    if !compact {
        vuln_content.push(Line::from(""));
    }
    vuln_content.push(Line::from(vec![Span::styled(
        format!(
            "{}C {}H {}M {}L",
            stats.critical_count, stats.high_count, stats.medium_count, stats.low_count
        ),
        Style::default().fg(scheme.muted),
    )]));

    let vuln_para = Paragraph::new(vuln_content)
        .block(
            Block::default()
                .title(if vuln_narrow {
                    " Vulns "
                } else {
                    " Vulnerabilities "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(vuln_color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(vuln_para, card_chunks[1]);

    // Licenses card
    let mut lic_content = Vec::new();
    if !compact {
        lic_content.push(Line::from(""));
    }
    lic_content.push(Line::from(vec![Span::styled(
        stats.license_count.to_string(),
        Style::default()
            .fg(scheme.success)
            .bold()
            .add_modifier(Modifier::BOLD),
    )]));
    lic_content.push(Line::styled(
        // Width-aware: "Unique Licenses" hard-clipped to "Unique Licens".
        if card_chunks[2].width < 17 {
            "Licenses"
        } else {
            "Unique Licenses"
        },
        Style::default().fg(scheme.muted),
    ));
    if !compact {
        lic_content.push(Line::from(""));
    }
    lic_content.push(Line::from(vec![Span::styled(
        format!(
            "{} unknown",
            stats.license_counts.get("Unknown").unwrap_or(&0)
        ),
        Style::default().fg(scheme.muted),
    )]));

    let lic_para = Paragraph::new(lic_content)
        .block(
            Block::default()
                .title(" Licenses ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(lic_para, card_chunks[2]);
}

fn render_vuln_breakdown(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let para = Paragraph::new(vuln_breakdown_lines(app)).block(
        Block::default()
            .title(" Vulnerability Severity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(para, area);
}

fn vuln_breakdown_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let scheme = colors();
    let stats = &app.stats;
    let total = stats.vuln_count.max(1);

    let mut lines = Vec::new();

    // Percentage breakdown (the labelled inline bars below are the real rendering)
    let add_severity_line = |lines: &mut Vec<Line>, label: &str, count: usize, color: Color| {
        let pct = (count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 20;
        let filled = (count * bar_width / total.max(1)).max(usize::from(count > 0));
        let scheme = colors();

        lines.push(Line::from(vec![
            Span::styled(format!("{label:>10} "), Style::default().fg(color).bold()),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>4} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    };

    add_severity_line(
        &mut lines,
        "Critical",
        stats.critical_count,
        scheme.critical,
    );
    add_severity_line(&mut lines, "High", stats.high_count, scheme.high);
    add_severity_line(&mut lines, "Medium", stats.medium_count, scheme.medium);
    add_severity_line(&mut lines, "Low", stats.low_count, scheme.low);

    lines
}

fn render_eol_breakdown(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;
    let border_color = if stats.eol_count > 0 {
        scheme.critical
    } else if stats.eol_approaching_count > 0 {
        scheme.high
    } else {
        scheme.success
    };

    let para = Paragraph::new(eol_breakdown_lines(app)).block(
        Block::default()
            .title(format!(
                " End-of-Life Status ({} at risk) ",
                stats.eol_count + stats.eol_approaching_count
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    frame.render_widget(para, area);
}

fn eol_breakdown_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let scheme = colors();
    let stats = &app.stats;
    let total = stats.component_count.max(1);

    let mut lines = Vec::new();

    let add_eol_line = |lines: &mut Vec<Line>, label: &str, count: usize, color: Color| {
        let pct = (count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 20;
        let filled = (count * bar_width / total.max(1)).max(usize::from(count > 0));
        let scheme = colors();

        lines.push(Line::from(vec![
            Span::styled(format!("{label:>10} "), Style::default().fg(color).bold()),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "\u{2591}".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>4} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    };

    add_eol_line(&mut lines, "EOL", stats.eol_count, scheme.critical);
    add_eol_line(
        &mut lines,
        "Near EOL",
        stats.eol_approaching_count,
        scheme.high,
    );
    add_eol_line(
        &mut lines,
        "Sec Only",
        stats.eol_security_only_count,
        scheme.warning,
    );
    add_eol_line(
        &mut lines,
        "Supported",
        stats.eol_supported_count,
        scheme.success,
    );

    lines
}

fn render_ecosystem_dist(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    // Line budget = inner height (borders only). ecosystem_dist_lines
    // reserves the "Other" rollup row itself, and only when rows overflow —
    // the old extra -1 here demoted the last ecosystem into "Other" even
    // when it fit, and rendered NOTHING for a 1-ecosystem SBOM.
    let max_eco_rows = area.height.saturating_sub(2) as usize;
    let para = Paragraph::new(ecosystem_dist_lines(app, max_eco_rows)).block(
        Block::default()
            .title(" Ecosystem Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );

    frame.render_widget(para, area);
}

/// Ecosystem bars fitted into `max_rows` total lines. When the ecosystems
/// overflow the budget, the LAST line becomes a rollup that labels its units
/// explicitly ("Other: 2 ecosystems (5 components)") — rows count ecosystems
/// while the sums count components, and unlabeled mixing misled readers.
fn ecosystem_dist_lines(app: &ViewApp, max_rows: usize) -> Vec<Line<'static>> {
    use crate::tui::shared::text::count_noun;
    let scheme = colors();
    let stats = &app.stats;

    // Sort ecosystems by count
    let mut ecosystems: Vec<_> = stats.ecosystem_counts.iter().collect();
    ecosystems.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let total = stats.component_count.max(1);

    let mut lines = vec![];

    let palette = scheme.chart_palette();

    // Reserve one row for the rollup ONLY when the entries overflow.
    let shown = if ecosystems.len() > max_rows {
        max_rows.saturating_sub(1)
    } else {
        ecosystems.len()
    };

    for (i, (eco, count)) in ecosystems.iter().take(shown).enumerate() {
        let pct = (**count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 25;
        let filled = (**count * bar_width / total).max(usize::from(**count > 0));
        let color = palette[i % palette.len()];

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", crate::tui::widgets::truncate_str(eco, 12)),
                Style::default().fg(color).bold(),
            ),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>4} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    if ecosystems.len() > shown {
        let hidden = ecosystems.len() - shown;
        let hidden_components: usize = ecosystems.iter().skip(shown).map(|(_, c)| *c).sum();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", "Other:"),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(
                    "{} ({})",
                    count_noun(hidden, "ecosystem"),
                    count_noun(hidden_components, "component")
                ),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    lines
}

fn render_license_dist(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    // Line budget = inner height; license_dist_lines reserves its own
    // rollup/unlicensed rows only when needed.
    let max_rows = area.height.saturating_sub(2) as usize;
    let para = Paragraph::new(license_dist_lines(app, max_rows)).block(
        Block::default()
            .title(" License Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.success)),
    );

    frame.render_widget(para, area);
}

/// License bars fitted into `max_rows` total lines. Overflowing licenses
/// roll up into an explicitly-labelled line ("Other: 2 licenses (5
/// components)"), and unlicensed components get their own labelled line
/// instead of being folded into an ambiguous "N more (N unknown)".
fn license_dist_lines(app: &ViewApp, max_rows: usize) -> Vec<Line<'static>> {
    use crate::tui::shared::text::count_noun;
    let scheme = colors();
    let stats = &app.stats;

    // Sort licenses by count, exclude the synthetic "Unknown" bucket
    let mut licenses: Vec<_> = stats
        .license_counts
        .iter()
        .filter(|(name, _)| name.as_str() != "Unknown")
        .collect();
    licenses.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let total = stats.component_count.max(1);
    let unknown_count = *stats.license_counts.get("Unknown").unwrap_or(&0);

    let mut lines = vec![];

    let palette = scheme.chart_palette();

    // Reserve rows: one for the unlicensed line (when any), and one for the
    // rollup ONLY when the license entries overflow what remains.
    let reserved_unlicensed = usize::from(unknown_count > 0);
    let bar_budget = max_rows.saturating_sub(reserved_unlicensed);
    let shown = if licenses.len() > bar_budget {
        bar_budget.saturating_sub(1)
    } else {
        licenses.len()
    };

    for (i, (lic, count)) in licenses.iter().take(shown).enumerate() {
        let pct = (**count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 25;
        let filled = (**count * bar_width / total).max(usize::from(**count > 0));
        let color = palette[i % palette.len()];

        lines.push(Line::from(vec![
            Span::styled(
                // Ellipsized, never silently sliced ("(Apache-2.0").
                format!("{:>12} ", crate::tui::widgets::truncate_str(lic, 12)),
                Style::default().fg(color).bold(),
            ),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "\u{2591}".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>4} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    if licenses.len() > shown {
        let hidden = licenses.len() - shown;
        let hidden_components: usize = licenses.iter().skip(shown).map(|(_, c)| *c).sum();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", "Other:"),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(
                    "{} ({})",
                    count_noun(hidden, "license"),
                    count_noun(hidden_components, "component")
                ),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    if unknown_count > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", "unlicensed:"),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                count_noun(unknown_count, "component"),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    lines
}

fn render_details_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let has_edges = !app.sbom.edges.is_empty();

    let doc_info_height = compute_doc_info_height(&app.sbom.document);
    let remaining = area.height.saturating_sub(doc_info_height);
    let half = remaining / 2;

    let chunks = if has_edges {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(doc_info_height), // Document info
                Constraint::Length(half),            // Top vulnerable components
                Constraint::Min(6),                  // Top depended-on components
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(doc_info_height), // Document info
                Constraint::Min(6),                  // Top components with vulns
            ])
            .split(area)
    };

    // Document info
    render_document_info(frame, chunks[0], app);

    // Top vulnerable components
    render_top_vulnerable(frame, chunks[1], app);

    // Top depended-on components (only when dependency edges exist)
    if has_edges {
        render_top_depended_on(frame, chunks[2], app);
    }
}

/// Compute the height needed for the document info panel.
///
/// Counts identity lines + trust/compliance section + security section + export hint + borders.
fn compute_doc_info_height(doc: &crate::model::DocumentMetadata) -> u16 {
    use crate::model::CompletenessDeclaration;

    // Identity group: format + created are always shown (2 lines minimum)
    let mut lines: u16 = 2;
    if doc.name.is_some() {
        lines += 1;
    }
    let has_authors = doc.creators.iter().any(|c| {
        matches!(
            c.creator_type,
            crate::model::CreatorType::Person | crate::model::CreatorType::Organization
        )
    });
    if has_authors {
        lines += 1;
    }
    if doc
        .creators
        .iter()
        .any(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
    {
        lines += 1;
    }
    if doc.serial_number.is_some() {
        lines += 1;
    }

    // Trust & Compliance group
    let has_completeness = !matches!(
        doc.completeness_declaration,
        CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
    );
    let trust_lines = u16::from(has_completeness)
        + u16::from(doc.signature.is_some())
        + u16::from(doc.lifecycle_phase.is_some())
        + u16::from(doc.distribution_classification.is_some())
        + u16::from(doc.citations_count > 0);
    if trust_lines > 0 {
        lines += 1 + trust_lines; // section header + fields
    }

    // Security group
    let security_lines = u16::from(doc.security_contact.is_some())
        + u16::from(doc.vulnerability_disclosure_url.is_some())
        + u16::from(doc.support_end_date.is_some());
    if security_lines > 0 {
        lines += 1 + security_lines; // section header + fields
    }

    // Export hint (empty line + hint line) + borders (top + bottom)
    lines += 2 + 2;

    lines
}

fn render_document_info(frame: &mut Frame, area: Rect, app: &ViewApp) {
    use crate::model::CompletenessDeclaration;

    let scheme = colors();
    let doc = &app.sbom.document;

    let mut lines = vec![];
    let label_style = Style::default().fg(scheme.muted);

    // ── Group 1: Identity ──

    if let Some(name) = &doc.name {
        lines.push(Line::from(vec![
            Span::styled("Name:    ", label_style),
            Span::styled(name, Style::default().fg(scheme.text).bold()),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Format:  ", label_style),
        Span::styled(
            format!(" {} {} ", doc.format, doc.format_version),
            Style::default().fg(scheme.badge_fg_dark).bg(scheme.primary),
        ),
    ]));

    // A missing timestamp is the epoch sentinel, not a genuine 1970 date —
    // don't render a fabricated "~56 years ago" for it.
    if doc.has_known_timestamp() {
        let (age_str, age_color) = format_age(doc.created);
        let mut spans = vec![
            Span::styled("Created: ", label_style),
            Span::raw(doc.created.format("%Y-%m-%d %H:%M:%S").to_string()),
        ];
        // Append the relative age only when it fits whole — narrow panels
        // clipped it to a meaningless "(2 y".
        let age_suffix = format!("  ({age_str})");
        if 9 + 19 + age_suffix.len() <= area.width.saturating_sub(2) as usize {
            spans.push(Span::styled(age_suffix, Style::default().fg(age_color)));
        }
        lines.push(Line::from(spans));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Created: ", label_style),
            Span::styled("unknown", Style::default().fg(scheme.warning)),
        ]));
    }

    // Creators (people and orgs)
    let authors: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| {
            matches!(
                c.creator_type,
                crate::model::CreatorType::Person | crate::model::CreatorType::Organization
            )
        })
        .map(|c| c.name.clone())
        .collect();
    if !authors.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Authors: ", label_style),
            Span::raw(authors.join(", ")),
        ]));
    }

    // Tools
    let tools: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
        .map(|c| c.name.clone())
        .collect();
    if !tools.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tools:   ", label_style),
            Span::raw(tools.join(", ")),
        ]));
    }

    if let Some(serial) = &doc.serial_number {
        lines.push(Line::from(vec![
            Span::styled("Serial:  ", label_style),
            Span::styled(
                if serial.len() > 36 {
                    let end = crate::tui::shared::floor_char_boundary(serial, 36);
                    format!("{}...", &serial[..end])
                } else {
                    serial.clone()
                },
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    // ── Group 2: Trust & Compliance (conditional) ──

    let has_completeness = !matches!(
        doc.completeness_declaration,
        CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
    );
    let has_signature = doc.signature.is_some();
    let has_lifecycle = doc.lifecycle_phase.is_some();
    let has_distribution = doc.distribution_classification.is_some();
    let has_citations = doc.citations_count > 0;

    if has_completeness || has_signature || has_lifecycle || has_distribution || has_citations {
        lines.push(Line::styled(
            "── Trust & Compliance ──",
            Style::default().fg(scheme.border),
        ));

        if has_completeness {
            let (badge_label, badge_fg, badge_bg) = match doc.completeness_declaration {
                CompletenessDeclaration::Complete => {
                    (" Complete ", scheme.badge_fg_dark, scheme.success)
                }
                CompletenessDeclaration::Incomplete
                | CompletenessDeclaration::IncompleteFirstPartyOnly
                | CompletenessDeclaration::IncompleteThirdPartyOnly => {
                    (" Incomplete ", scheme.badge_fg_dark, scheme.warning)
                }
                // Unknown/NotSpecified filtered above
                _ => (" Unknown ", scheme.text, scheme.muted),
            };
            lines.push(Line::from(vec![
                Span::styled("Completeness: ", label_style),
                Span::styled(badge_label, Style::default().fg(badge_fg).bg(badge_bg)),
            ]));
        }

        if let Some(sig) = &doc.signature {
            let (badge_label, badge_fg, badge_bg) = if sig.has_value {
                (
                    format!(" Signed ({}) ", sig.algorithm),
                    scheme.badge_fg_dark,
                    scheme.success,
                )
            } else {
                (" Unsigned ".to_string(), scheme.text, scheme.muted)
            };
            lines.push(Line::from(vec![
                Span::styled("Signature:    ", label_style),
                Span::styled(badge_label, Style::default().fg(badge_fg).bg(badge_bg)),
            ]));
        }

        if let Some(phase) = &doc.lifecycle_phase {
            lines.push(Line::from(vec![
                Span::styled("Lifecycle:    ", label_style),
                Span::styled(
                    format!(" {phase} "),
                    Style::default().fg(scheme.badge_fg_dark).bg(scheme.primary),
                ),
            ]));
        }

        if let Some(classification) = &doc.distribution_classification {
            let bg = match classification.to_uppercase().as_str() {
                s if s.contains("RED") => scheme.critical,
                s if s.contains("AMBER") => scheme.warning,
                s if s.contains("GREEN") => scheme.success,
                _ => scheme.primary,
            };
            lines.push(Line::from(vec![
                Span::styled("Distribution: ", label_style),
                Span::styled(
                    format!(" {classification} "),
                    Style::default().fg(scheme.badge_fg_dark).bg(bg),
                ),
            ]));
        }

        if has_citations {
            lines.push(Line::from(vec![
                Span::styled("Citations:    ", label_style),
                Span::styled(
                    format!("{} provenance citations", doc.citations_count),
                    Style::default().fg(scheme.accent),
                ),
            ]));
        }
    }

    // ── Group 3: Security (conditional) ──

    let has_contact = doc.security_contact.is_some();
    let has_disclosure = doc.vulnerability_disclosure_url.is_some();
    let has_eol = doc.support_end_date.is_some();

    if has_contact || has_disclosure || has_eol {
        lines.push(Line::styled(
            "── Security ──",
            Style::default().fg(scheme.border),
        ));

        if let Some(contact) = &doc.security_contact {
            lines.push(Line::from(vec![
                Span::styled("Contact:  ", label_style),
                Span::styled(contact, Style::default().fg(scheme.accent)),
            ]));
        }

        if let Some(url) = &doc.vulnerability_disclosure_url {
            let display_url = if url.len() > 40 {
                let end = crate::tui::shared::floor_char_boundary(url, 40);
                format!("{}...", &url[..end])
            } else {
                url.clone()
            };
            lines.push(Line::from(vec![
                Span::styled("Disclose: ", label_style),
                Span::styled(display_url, Style::default().fg(scheme.text_muted)),
            ]));
        }

        if let Some(eol) = doc.support_end_date {
            let (eol_str, eol_color) = format_support_eol(eol);
            lines.push(Line::from(vec![
                Span::styled("EOL:      ", label_style),
                Span::raw(eol.format("%Y-%m-%d").to_string()),
                Span::styled(format!("  ({eol_str})"), Style::default().fg(eol_color)),
            ]));
        }
    }

    // Export hint (width-aware: the format list hard-clipped at 80 cols).
    // Only spend a spacer row when the panel still has room for it plus the
    // hint — tight layouts shrink this panel and silently dropped the hint.
    if lines.len() as u16 + 4 <= area.height {
        lines.push(Line::from(""));
    }
    let export_label = " Export (JSON, SARIF, Markdown, HTML, CSV)";
    lines.push(Line::from(vec![
        Span::styled("[e]", Style::default().fg(scheme.accent)),
        Span::styled(
            if area.width as usize >= export_label.len() + 5 {
                export_label.to_string()
            } else {
                " Export…".to_string()
            },
            Style::default().fg(scheme.muted),
        ),
    ]));

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Document Info ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(para, area);
}

/// Format support end-of-life date with color coding.
fn format_support_eol(eol: chrono::DateTime<chrono::Utc>) -> (String, Color) {
    let scheme = colors();
    let days_until = (eol - chrono::Utc::now()).num_days();

    let label = if days_until < 0 {
        let days_past = -days_until;
        if days_past < 30 {
            format!("expired {days_past}d ago")
        } else if days_past < 365 {
            format!("expired {}mo ago", days_past / 30)
        } else {
            format!("expired {}y ago", days_past / 365)
        }
    } else if days_until == 0 {
        "expires today".to_string()
    } else if days_until < 30 {
        format!("{days_until}d remaining")
    } else if days_until < 365 {
        format!("{}mo remaining", days_until / 30)
    } else {
        format!("{}y remaining", days_until / 365)
    };

    let color = if days_until < 0 {
        scheme.critical
    } else if days_until < 90 {
        scheme.warning
    } else {
        scheme.success
    };

    (label, color)
}

fn render_top_vulnerable(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();

    // Get components sorted by vulnerability count
    let mut vuln_comps: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| !c.vulnerabilities.is_empty())
        .map(|c| (c.name.clone(), c.vulnerabilities.len(), c.max_severity()))
        .collect();

    vuln_comps.sort_by_key(|a| std::cmp::Reverse(a.1));

    // Dynamic row count based on available area height
    let max_rows = area.height.saturating_sub(3) as usize; // subtract header + borders

    let rows: Vec<Row> = vuln_comps
        .iter()
        .take(max_rows)
        .map(|(name, count, max_sev)| {
            let sev_str = max_sev.as_deref().unwrap_or("Unknown");
            let sev_color = scheme.severity_color(sev_str);
            let display_name = extract_display_name(name);

            Row::new(vec![
                if display_name.len() > 45 {
                    let end = crate::tui::shared::floor_char_boundary(&display_name, 42);
                    format!("{}...", &display_name[..end])
                } else {
                    display_name
                },
                count.to_string(),
                sev_str.to_string(),
            ])
            .style(Style::default().fg(sev_color))
        })
        .collect();

    // "Max Sev" + Length(8) fits "Critical" and survives 80-col layouts where
    // "Max Severity" degraded to a meaningless single letter.
    let header = Row::new(vec!["Component", "CVEs", "Max Sev"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(4),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(
                " Top Vulnerable Components ({}) ",
                vuln_comps.len()
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(table, area);
}

fn render_top_depended_on(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();

    // Count how many times each component appears as a dependency target
    let mut dependent_counts: std::collections::HashMap<&crate::model::CanonicalId, usize> =
        std::collections::HashMap::new();
    for edge in &app.sbom.edges {
        *dependent_counts.entry(&edge.to).or_insert(0) += 1;
    }

    // Build sorted list of (name, dependents_count, vuln_count)
    let mut top_deps: Vec<_> = dependent_counts
        .iter()
        .filter_map(|(id, &dep_count)| {
            app.sbom
                .components
                .get(*id)
                .map(|c| (c.name.clone(), dep_count, c.vulnerabilities.len()))
        })
        .collect();

    top_deps.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let max_rows = area.height.saturating_sub(3) as usize;

    let rows: Vec<Row> = top_deps
        .iter()
        .take(max_rows)
        .map(|(name, dep_count, vuln_count)| {
            let display_name = extract_display_name(name);

            Row::new(vec![
                if display_name.len() > 35 {
                    let end = crate::tui::shared::floor_char_boundary(&display_name, 32);
                    format!("{}...", &display_name[..end])
                } else {
                    display_name
                },
                dep_count.to_string(),
                vuln_count.to_string(),
            ])
            .style(Style::default().fg(scheme.text))
        })
        .collect();

    let header = Row::new(vec!["Component", "Deps", "Vulns"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(6),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(" Top Depended-On Components ({}) ", top_deps.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );

    frame.render_widget(table, area);
}

/// Format SBOM age as a human-readable string with appropriate color.
fn format_age(created: chrono::DateTime<chrono::Utc>) -> (String, Color) {
    let scheme = colors();
    let age_days = (chrono::Utc::now() - created).num_days();

    let age_str = if age_days < 0 {
        "in the future".to_string()
    } else if age_days == 0 {
        "today".to_string()
    } else if age_days == 1 {
        "1 day ago".to_string()
    } else if age_days < 30 {
        format!("{age_days} days ago")
    } else if age_days < 60 {
        "1 month ago".to_string()
    } else if age_days < 365 {
        format!("{} months ago", age_days / 30)
    } else if age_days < 730 {
        "1 year ago".to_string()
    } else {
        format!("{} years ago", age_days / 365)
    };

    let color = if age_days < 30 {
        scheme.success
    } else if age_days < 180 {
        scheme.warning
    } else {
        scheme.critical
    };

    (age_str, color)
}

/// Extension trait for Component to get max severity.
trait ComponentExt {
    fn max_severity(&self) -> Option<String>;
}

impl ComponentExt for crate::model::Component {
    fn max_severity(&self) -> Option<String> {
        self.vulnerabilities
            .iter()
            .filter_map(|v| v.severity.as_ref())
            .max_by(|a, b| {
                let order = |s: &crate::model::Severity| match s.to_string().to_lowercase().as_str()
                {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    "low" => 1,
                    _ => 0,
                };
                order(a).cmp(&order(b))
            })
            .map(std::string::ToString::to_string)
    }
}
