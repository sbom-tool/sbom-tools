//! Shared quality rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! All functions take domain types directly (`&QualityReport`, `&QualityGrade`, etc.)
//! and have no dependency on App or `ViewApp` state.

use crate::quality::{
    QualityGrade, QualityReport, RecommendationCategory, SCORING_ENGINE_VERSION, ScoringProfile,
};
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Gauge, Paragraph, Row, Table},
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns display weights for the 8 scoring categories.
///
/// Order: (completeness, identifiers, licenses, vulnerabilities, dependencies,
///          integrity, provenance, lifecycle)
pub const fn get_profile_weights(
    profile: ScoringProfile,
) -> (f32, f32, f32, f32, f32, f32, f32, f32) {
    match profile {
        ScoringProfile::Minimal => (0.35, 0.20, 0.10, 0.05, 0.10, 0.05, 0.10, 0.05),
        ScoringProfile::Standard => (0.25, 0.20, 0.12, 0.08, 0.10, 0.08, 0.10, 0.07),
        ScoringProfile::Security => (0.12, 0.18, 0.05, 0.20, 0.10, 0.15, 0.10, 0.10),
        ScoringProfile::LicenseCompliance => (0.15, 0.12, 0.35, 0.05, 0.10, 0.05, 0.10, 0.08),
        ScoringProfile::Cra => (0.12, 0.18, 0.08, 0.15, 0.12, 0.12, 0.15, 0.08),
        ScoringProfile::Comprehensive => (0.15, 0.13, 0.13, 0.10, 0.12, 0.12, 0.13, 0.12),
    }
}

pub fn explain_completeness_score(report: &QualityReport) -> String {
    let m = &report.completeness_metrics;
    if m.components_with_version >= 90.0 && m.components_with_purl >= 80.0 {
        "Good coverage".to_string()
    } else if m.components_with_version < 50.0 {
        "Missing versions".to_string()
    } else if m.components_with_purl < 50.0 {
        "Need more PURLs".to_string()
    } else {
        "Partial coverage".to_string()
    }
}

pub fn explain_identifier_score(report: &QualityReport) -> String {
    let m = &report.identifier_metrics;
    if m.invalid_purls > 0 || m.invalid_cpes > 0 {
        format!("{} invalid IDs", m.invalid_purls + m.invalid_cpes)
    } else if m.missing_all_identifiers > 0 {
        format!("{} missing IDs", m.missing_all_identifiers)
    } else {
        "All identified".to_string()
    }
}

pub fn explain_license_score(report: &QualityReport) -> String {
    let m = &report.license_metrics;
    if m.noassertion_count > 0 {
        format!("{} NOASSERTION", m.noassertion_count)
    } else if m.non_standard_licenses > 0 {
        format!("{} non-SPDX", m.non_standard_licenses)
    } else if m.with_declared > 0 {
        "Good coverage".to_string()
    } else {
        "No licenses".to_string()
    }
}

pub fn explain_vulnerability_score(report: &QualityReport) -> String {
    let m = &report.vulnerability_metrics;
    if m.total_vulnerabilities == 0 {
        "No vulns tracked".to_string()
    } else if m.with_cvss == m.total_vulnerabilities {
        "All have CVSS".to_string()
    } else {
        format!("{} missing CVSS", m.total_vulnerabilities - m.with_cvss)
    }
}

pub fn explain_dependency_score(report: &QualityReport) -> String {
    let m = &report.dependency_metrics;
    if m.total_dependencies == 0 {
        "No deps defined".to_string()
    } else if m.cycle_count > 0 {
        format!("{} cycle(s)", m.cycle_count)
    } else if m.orphan_components > 5 {
        format!("{} orphans", m.orphan_components)
    } else {
        "Good graph".to_string()
    }
}

pub fn explain_integrity_score(report: &QualityReport) -> String {
    let m = &report.hash_quality_metrics;
    if m.components_with_any_hash == 0 {
        "No hashes".to_string()
    } else if m.components_with_weak_only > 0 {
        format!("{} weak-only", m.components_with_weak_only)
    } else if m.components_with_strong_hash == m.components_with_any_hash {
        "All strong hashes".to_string()
    } else {
        "Partial coverage".to_string()
    }
}

pub fn explain_provenance_score(report: &QualityReport) -> String {
    let m = &report.provenance_metrics;
    if m.has_tool_creator && m.has_org_creator && m.is_fresh {
        "Good provenance".to_string()
    } else if !m.has_tool_creator {
        "No tool info".to_string()
    } else if !m.is_fresh {
        "Stale SBOM".to_string()
    } else {
        "Partial provenance".to_string()
    }
}

pub fn explain_lifecycle_score(report: &QualityReport) -> String {
    match report.lifecycle_score {
        None => "N/A (no enrichment)".to_string(),
        Some(score) if score >= 90.0 => "Healthy lifecycle".to_string(),
        Some(_) => {
            let m = &report.lifecycle_metrics;
            if m.eol_components > 0 {
                format!("{} EOL", m.eol_components)
            } else if m.stale_components > 0 {
                format!("{} stale", m.stale_components)
            } else {
                "Some concerns".to_string()
            }
        }
    }
}

pub fn generate_key_factors(report: &QualityReport) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = vec![];

    lines.push(Line::styled(
        " Positive Factors:",
        Style::default().fg(scheme.success).bold(),
    ));

    let m = &report.completeness_metrics;
    if m.components_with_version >= 80.0 {
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                format!(
                    "{:.0}% of components have versions",
                    m.components_with_version
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.identifier_metrics.valid_purls > 0 {
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                format!(
                    "{} valid PURL identifiers",
                    report.identifier_metrics.valid_purls
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.license_metrics.valid_spdx_expressions > 0 {
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                format!(
                    "{} SPDX-compliant licenses",
                    report.license_metrics.valid_spdx_expressions
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        " Areas for Improvement:",
        Style::default().fg(scheme.warning).bold(),
    ));

    if m.components_with_version < 80.0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{:.0}% components missing versions",
                    100.0 - m.components_with_version
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.identifier_metrics.missing_all_identifiers > 0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{} components without any identifier",
                    report.identifier_metrics.missing_all_identifiers
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.license_metrics.noassertion_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{} licenses marked as NOASSERTION",
                    report.license_metrics.noassertion_count
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.hash_quality_metrics.components_with_strong_hash > 0 {
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                format!(
                    "{} components with strong hashes",
                    report.hash_quality_metrics.components_with_strong_hash
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.provenance_metrics.has_signature {
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled("SBOM is digitally signed", Style::default().fg(scheme.text)),
        ]));
    }

    if report.dependency_metrics.orphan_components > 3 {
        lines.push(Line::from(vec![
            Span::styled("   ! ", Style::default().fg(scheme.warning)),
            Span::styled(
                format!(
                    "{} orphan components (no dependency links)",
                    report.dependency_metrics.orphan_components
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.hash_quality_metrics.components_with_weak_only > 0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{} components with weak-only hashes (MD5/SHA-1)",
                    report.hash_quality_metrics.components_with_weak_only
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.lifecycle_metrics.eol_components > 0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{} end-of-life components",
                    report.lifecycle_metrics.eol_components
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    if report.dependency_metrics.cycle_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("   - ", Style::default().fg(scheme.error)),
            Span::styled(
                format!(
                    "{} dependency cycle(s) detected",
                    report.dependency_metrics.cycle_count
                ),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    lines
}

pub fn get_recommendation_reason(category: RecommendationCategory) -> String {
    match category {
        RecommendationCategory::Completeness => {
            "Complete data enables accurate vulnerability scanning and license compliance"
                .to_string()
        }
        RecommendationCategory::Identifiers => {
            "Package URLs (PURLs) enable precise matching in vulnerability databases".to_string()
        }
        RecommendationCategory::Licenses => {
            "Clear licensing is required for legal compliance and distribution".to_string()
        }
        RecommendationCategory::Vulnerabilities => {
            "CVSS scores help prioritize security remediation efforts".to_string()
        }
        RecommendationCategory::Dependencies => {
            "Dependency info reveals transitive risks and update impacts".to_string()
        }
        RecommendationCategory::Compliance => {
            "Meeting standards ensures SBOM is usable by tools and partners".to_string()
        }
        RecommendationCategory::Integrity => {
            "Strong hashes verify component integrity and detect tampering".to_string()
        }
        RecommendationCategory::Provenance => {
            "Provenance metadata traces SBOM origin and enables supply chain auditing".to_string()
        }
        RecommendationCategory::Lifecycle => {
            "Lifecycle awareness identifies end-of-life and outdated components".to_string()
        }
    }
}

pub fn grade_color_and_label(grade: QualityGrade) -> (Color, &'static str) {
    let scheme = colors();
    match grade {
        QualityGrade::A => (scheme.success, "Excellent"),
        QualityGrade::B => (scheme.primary, "Good"),
        QualityGrade::C => (scheme.warning, "Fair"),
        QualityGrade::D => (scheme.high, "Poor"),
        QualityGrade::F => (scheme.error, "Failing"),
    }
}

pub fn grade_color(grade: QualityGrade) -> Color {
    grade_color_and_label(grade).0
}

pub fn priority_style(priority: u8) -> Style {
    let scheme = colors();
    match priority {
        1 => Style::default().fg(scheme.error).bold(),
        2 => Style::default().fg(scheme.warning),
        3 => Style::default().fg(scheme.primary),
        _ => Style::default().fg(scheme.muted),
    }
}

/// Continuous RGB gradient bar color for better visual differentiation.
/// Score 0 → dark red, 50 → yellow, 100 → green.
fn bar_grade_style(score: f32) -> Style {
    let t = score.clamp(0.0, 100.0) / 100.0;
    let (r, g, b) = if t < 0.5 {
        // 0..50: dark red (180,40,40) → yellow (220,180,0)
        let s = t / 0.5;
        (
            40.0_f32.mul_add(s, 180.0),
            140.0_f32.mul_add(s, 40.0),
            (-40.0_f32).mul_add(s, 40.0),
        )
    } else {
        // 50..100: yellow (220,180,0) → green (40,200,40)
        let s = (t - 0.5) / 0.5;
        (
            (-180.0_f32).mul_add(s, 220.0),
            20.0_f32.mul_add(s, 180.0),
            40.0_f32.mul_add(s, 0.0),
        )
    };
    Style::default().fg(Color::Rgb(r as u8, g as u8, b as u8))
}

pub fn score_color(score: f32) -> Color {
    let scheme = colors();
    if score >= 80.0 {
        scheme.success
    } else if score >= 50.0 {
        scheme.warning
    } else {
        scheme.error
    }
}

pub fn score_style(score: f32) -> Style {
    Style::default().fg(score_color(score))
}

// ---------------------------------------------------------------------------
// Rendering functions
// ---------------------------------------------------------------------------

pub fn render_quality_summary(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    selected_rec: usize,
) {
    let scheme = colors();
    // Adaptive layout: size recommendations panel to content, give remaining space to bar chart
    let rec_count = report.recommendations.len().min(5);
    let rec_height = if rec_count == 0 {
        5_u16 // "No issues found" + border
    } else {
        (rec_count as u16) * 2 + 3 // 2 lines per item + title/border
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),          // Compact header
            Constraint::Min(10),            // Bar chart + checklist (gets remaining space)
            Constraint::Length(rec_height), // Recommendations sized to content
        ])
        .split(area);

    // --- Compact header (items 2+3) ---
    render_compact_header(frame, chunks[0], report);

    // Middle row: bar chart (left) + checklist (right)
    let mid_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    // Bar chart with 8 category scores
    // Use max(1) so even 0% bars have a stub for the text_value to render on
    let lifecycle_val = report.lifecycle_score.unwrap_or(0.0);
    let lifecycle_is_na = report.lifecycle_score.is_none();
    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" Category Scores (passing: 70) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.muted)),
        )
        .bar_width(6)
        .bar_gap(1)
        .value_style(Style::default().fg(Color::White).bold())
        .data(
            BarGroup::default().bars(&[
                Bar::default()
                    .value((report.completeness_score as u64).max(1))
                    .label(Line::from("Cmpl"))
                    .style(bar_grade_style(report.completeness_score))
                    .text_value(format!("{}", report.completeness_score as u64)),
                Bar::default()
                    .value((report.identifier_score as u64).max(1))
                    .label(Line::from("IDs"))
                    .style(bar_grade_style(report.identifier_score))
                    .text_value(format!("{}", report.identifier_score as u64)),
                Bar::default()
                    .value((report.license_score as u64).max(1))
                    .label(Line::from("Lic"))
                    .style(bar_grade_style(report.license_score))
                    .text_value(format!("{}", report.license_score as u64)),
                Bar::default()
                    .value((report.vulnerability_score as u64).max(1))
                    .label(Line::from("VDoc"))
                    .style(bar_grade_style(report.vulnerability_score))
                    .text_value(format!("{}", report.vulnerability_score as u64)),
                Bar::default()
                    .value((report.dependency_score as u64).max(1))
                    .label(Line::from("Deps"))
                    .style(bar_grade_style(report.dependency_score))
                    .text_value(format!("{}", report.dependency_score as u64)),
                Bar::default()
                    .value((report.integrity_score as u64).max(1))
                    .label(Line::from("Hash"))
                    .style(bar_grade_style(report.integrity_score))
                    .text_value(format!("{}", report.integrity_score as u64)),
                Bar::default()
                    .value((report.provenance_score as u64).max(1))
                    .label(Line::from("Prov"))
                    .style(bar_grade_style(report.provenance_score))
                    .text_value(format!("{}", report.provenance_score as u64)),
                Bar::default()
                    .value(if lifecycle_is_na {
                        1
                    } else {
                        (lifecycle_val as u64).max(1)
                    })
                    .label(if lifecycle_is_na {
                        Line::styled("Life", Style::default().fg(scheme.muted))
                    } else {
                        Line::from("Life")
                    })
                    .style(if lifecycle_is_na {
                        Style::default().fg(scheme.muted)
                    } else {
                        bar_grade_style(lifecycle_val)
                    })
                    .text_value(if lifecycle_is_na {
                        "N/A".to_string()
                    } else {
                        format!("{}", lifecycle_val as u64)
                    }),
            ]),
        );
    frame.render_widget(bar_chart, mid_chunks[0]);

    render_completeness_checklist(frame, mid_chunks[1], report);

    // Bottom row: full-width recommendations (items 4+7)
    render_top_recommendations(frame, chunks[2], report, selected_rec);
}

/// Render a compact 4-line header with grade, inline bar, score, profile, and strongest/weakest.
fn render_compact_header(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let score = report.overall_score as u16;
    let (gauge_color, grade_label) = grade_color_and_label(report.grade);

    // Build inline gauge bar using block characters
    // Use area width minus borders and padding for bar width
    let bar_max = 20usize;
    let filled = ((f32::from(score.min(100)) / 100.0) * bar_max as f32).round() as usize;
    let empty = bar_max.saturating_sub(filled);
    let bar_str: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(empty);

    // Identify strongest and weakest across all 8 categories
    let mut scores = vec![
        ("Completeness", report.completeness_score),
        ("Identifiers", report.identifier_score),
        ("Licenses", report.license_score),
        ("Vuln Docs", report.vulnerability_score),
        ("Dependencies", report.dependency_score),
        ("Integrity", report.integrity_score),
        ("Provenance", report.provenance_score),
    ];
    if let Some(lc) = report.lifecycle_score {
        scores.push(("Lifecycle", lc));
    }
    let strongest = scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&scores[0]);
    let weakest = scores
        .iter()
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&scores[0]);

    // Line 1: grade + label + bar + score + profile
    let line1 = Line::from(vec![
        Span::styled(
            format!(" {} ", report.grade.letter()),
            Style::default().fg(gauge_color).bold(),
        ),
        Span::styled(format!("{grade_label} "), Style::default().fg(scheme.text)),
        Span::styled(bar_str, Style::default().fg(gauge_color)),
        Span::styled(
            format!(" {score}/100"),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled("  Profile: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!("{:?}", report.profile),
            Style::default().fg(scheme.primary),
        ),
        Span::styled(
            format!("  Engine v{SCORING_ENGINE_VERSION}"),
            Style::default().fg(scheme.muted),
        ),
    ]);

    // Line 2: strongest + weakest
    let mut line2_spans = vec![
        Span::styled(" Best: ", Style::default().fg(scheme.success)),
        Span::styled(
            format!("{} ({:.0}%)", strongest.0, strongest.1),
            Style::default().fg(scheme.text),
        ),
    ];
    if weakest.1 < 70.0 {
        line2_spans.push(Span::styled(
            "  Focus: ",
            Style::default().fg(scheme.warning),
        ));
        line2_spans.push(Span::styled(
            format!("{} ({:.0}%)", weakest.0, weakest.1),
            Style::default().fg(scheme.text),
        ));
    }
    let line2 = Line::from(line2_spans);

    let widget = Paragraph::new(vec![line1, line2]).block(
        Block::default()
            .title(" SBOM Quality Score ")
            .title_style(Style::default().bold().fg(scheme.text))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(gauge_color)),
    );
    frame.render_widget(widget, area);
}

fn render_completeness_checklist(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let m = &report.completeness_metrics;

    let check = |val: bool| -> Span<'static> {
        if val {
            Span::styled("  \u{2713} ", Style::default().fg(scheme.success))
        } else {
            Span::styled("  \u{2717} ", Style::default().fg(scheme.error))
        }
    };

    let pct_bar = |label: &str, pct: f32, width: usize| -> Line<'static> {
        let filled = if pct > 0.0 {
            ((pct / 100.0) * width as f32).round().max(1.0) as usize
        } else {
            0
        };
        let empty = width.saturating_sub(filled);
        let bar: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(empty);
        Line::from(vec![
            Span::styled(format!("  {label:<10}"), Style::default().fg(scheme.muted)),
            Span::styled(format!("{pct:>3.0}%  "), score_style(pct)),
            Span::styled(bar, score_style(pct)),
        ])
    };

    let mut lines = vec![Line::from(vec![
        check(m.has_creator_info),
        Span::styled("Creator info", Style::default().fg(scheme.text)),
        check(m.has_serial_number),
        Span::styled("Serial number", Style::default().fg(scheme.text)),
    ])];
    lines.push(Line::from(vec![
        check(m.has_timestamp),
        Span::styled("Timestamp", Style::default().fg(scheme.text)),
    ]));
    lines.push(Line::from(""));

    // Component field coverage bars (wider for better visual resolution)
    lines.push(pct_bar("Versions", m.components_with_version, 15));
    lines.push(pct_bar("PURLs", m.components_with_purl, 15));
    lines.push(pct_bar("Licenses", m.components_with_licenses, 15));
    lines.push(pct_bar("Suppliers", m.components_with_supplier, 15));
    lines.push(pct_bar("Hashes", m.components_with_hashes, 15));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" SBOM Checklist ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.accent)),
    );
    frame.render_widget(widget, area);
}

fn render_top_recommendations(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    selected_rec: usize,
) {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];

    if report.recommendations.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "  No issues found",
            Style::default().fg(scheme.success).bold(),
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  \u{2713} ", Style::default().fg(scheme.success)),
            Span::styled(
                "SBOM meets all quality checks",
                Style::default().fg(scheme.text),
            ),
        ]));
    } else {
        for (i, rec) in report.recommendations.iter().take(5).enumerate() {
            let is_selected = i == selected_rec;
            let prefix = if is_selected { "> " } else { "  " };
            let msg_style = if is_selected {
                Style::default().fg(scheme.text).bold()
            } else {
                Style::default().fg(scheme.text)
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(scheme.primary)),
                Span::styled(
                    format!("[P{}] ", rec.priority),
                    priority_style(rec.priority),
                ),
                Span::styled(
                    format!("[{}] ", rec.category.name()),
                    Style::default().fg(scheme.info),
                ),
                Span::styled(&rec.message, msg_style),
            ]));
            lines.push(Line::from(vec![
                Span::raw("       "),
                Span::styled(
                    format!("{} affected", rec.affected_count),
                    Style::default().fg(scheme.muted),
                ),
                Span::styled("  |  ", Style::default().fg(scheme.border)),
                Span::styled(
                    format!("+{:.1}pts", rec.impact),
                    Style::default().fg(scheme.success),
                ),
            ]));
        }
    }

    let title = if report.recommendations.is_empty() {
        " Top Recommendations (0) ".to_string()
    } else {
        format!(
            " Top Recommendations ({}) [\u{2191}\u{2193} select, Enter\u{2192}detail] ",
            report.recommendations.len()
        )
    };

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.warning)),
    );
    frame.render_widget(widget, area);
}

pub fn render_score_gauge(frame: &mut Frame, area: Rect, report: &QualityReport, title: &str) {
    let scheme = colors();
    let score = report.overall_score as u16;
    let (gauge_color, grade_label) = grade_color_and_label(report.grade);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" {title} "))
                .title_style(Style::default().bold().fg(scheme.text))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(gauge_color)),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(scheme.muted))
        .percent(score.min(100))
        .label(format!("{score}/100 - {grade_label}"));
    frame.render_widget(gauge, area);
}

pub fn render_score_breakdown(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(15), // 8 category rows + header + margin
            Constraint::Min(8),
        ])
        .split(area);

    // Header with overall score
    let (_, grade_label) = grade_color_and_label(report.grade);
    let header = Paragraph::new(Line::from(vec![
        Span::styled("Overall Score: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("{:.0}/100", report.overall_score),
            Style::default().fg(grade_color(report.grade)).bold(),
        ),
        Span::styled(
            format!(" ({grade_label}) "),
            Style::default().fg(scheme.muted),
        ),
        Span::styled("| Profile: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("{:?}", report.profile),
            Style::default().fg(scheme.primary),
        ),
    ]))
    .block(
        Block::default()
            .title(" Score Calculation ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );
    frame.render_widget(header, chunks[0]);

    // Weighted breakdown table (8 categories)
    let weights = get_profile_weights(report.profile);
    let lifecycle_val = report.lifecycle_score.unwrap_or(0.0);
    let rows = vec![
        create_breakdown_row(
            "Completeness",
            report.completeness_score,
            weights.0,
            &explain_completeness_score(report),
        ),
        create_breakdown_row(
            "Identifiers",
            report.identifier_score,
            weights.1,
            &explain_identifier_score(report),
        ),
        create_breakdown_row(
            "Licenses",
            report.license_score,
            weights.2,
            &explain_license_score(report),
        ),
        create_breakdown_row(
            "Vuln Docs",
            report.vulnerability_score,
            weights.3,
            &explain_vulnerability_score(report),
        ),
        create_breakdown_row(
            "Dependencies",
            report.dependency_score,
            weights.4,
            &explain_dependency_score(report),
        ),
        create_breakdown_row(
            "Integrity",
            report.integrity_score,
            weights.5,
            &explain_integrity_score(report),
        ),
        create_breakdown_row(
            "Provenance",
            report.provenance_score,
            weights.6,
            &explain_provenance_score(report),
        ),
        create_breakdown_row(
            "Lifecycle",
            lifecycle_val,
            if report.lifecycle_score.is_some() {
                weights.7
            } else {
                0.0
            },
            &explain_lifecycle_score(report),
        ),
    ];

    let widths = [
        Constraint::Length(15),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Min(25),
    ];

    let table = Table::new(rows, widths)
        .block(
            Block::default()
                .title(" Weighted Category Contributions ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        )
        .header(
            Row::new(vec![
                "Category",
                "Score",
                "Weight",
                "Contrib.",
                "Explanation",
            ])
            .style(Style::default().fg(scheme.accent).bold())
            .bottom_margin(1),
        );
    frame.render_widget(table, chunks[1]);

    // Key factors
    let factors = generate_key_factors(report);
    let factors_widget = Paragraph::new(factors).block(
        Block::default()
            .title(" Key Score Factors ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.success)),
    );
    frame.render_widget(factors_widget, chunks[2]);
}

fn create_breakdown_row(name: &str, score: f32, weight: f32, explanation: &str) -> Row<'static> {
    let contribution = score * weight;
    let sc = score_color(score);

    Row::new(vec![
        name.to_string(),
        format!("{:.0}%", score),
        format!("{:.0}%", weight * 100.0),
        format!("+{:.1}pts", contribution),
        explanation.to_string(),
    ])
    .style(Style::default().fg(sc))
}

pub fn render_quality_metrics(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(6),
        ])
        .split(area);

    render_completeness_details(frame, chunks[0], report);
    render_id_license_details(frame, chunks[1], report);
    render_integrity_provenance_details(frame, chunks[2], report);
    render_dependency_details(frame, chunks[3], report);
}

pub fn render_completeness_details(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let m = &report.completeness_metrics;
    let total = m.total_components;

    let lines = vec![
        Line::from(vec![Span::styled(
            "Component Field Coverage:",
            Style::default().fg(scheme.primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Versions:    ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", m.components_with_version),
                score_style(m.components_with_version),
            ),
            Span::styled(
                format!(
                    " ({} of {} components)",
                    (m.components_with_version / 100.0 * total as f32) as usize,
                    total
                ),
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  PURLs:       ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", m.components_with_purl),
                score_style(m.components_with_purl),
            ),
            Span::styled(
                " - Package URLs enable precise identification",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Suppliers:   ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", m.components_with_supplier),
                score_style(m.components_with_supplier),
            ),
            Span::styled(
                " - Required for supply chain transparency",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Hashes:      ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", m.components_with_hashes),
                score_style(m.components_with_hashes),
            ),
            Span::styled(
                " - Enables integrity verification",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Completeness Analysis ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );
    frame.render_widget(paragraph, area);
}

pub fn render_id_license_details(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let id_m = &report.identifier_metrics;
    let lic_m = &report.license_metrics;

    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Identifiers
    let id_lines = vec![
        Line::from(vec![
            Span::styled("Valid PURLs: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", id_m.valid_purls),
                Style::default().fg(scheme.success),
            ),
        ]),
        Line::from(vec![
            Span::styled("Invalid PURLs: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", id_m.invalid_purls),
                if id_m.invalid_purls > 0 {
                    Style::default().fg(scheme.error)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("Valid CPEs: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", id_m.valid_cpes),
                Style::default().fg(scheme.primary),
            ),
        ]),
        Line::from(vec![
            Span::styled("Missing IDs: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", id_m.missing_all_identifiers),
                if id_m.missing_all_identifiers > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled(" components", Style::default().fg(scheme.text_muted)),
        ]),
    ];
    let id_widget = Paragraph::new(id_lines).block(
        Block::default()
            .title(" Identifiers ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.info)),
    );
    frame.render_widget(id_widget, h_chunks[0]);

    // Licenses
    let lic_lines = vec![
        Line::from(vec![
            Span::styled("Declared: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", lic_m.with_declared),
                Style::default().fg(scheme.success),
            ),
            Span::styled(" components", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("SPDX Valid: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", lic_m.valid_spdx_expressions),
                Style::default().fg(scheme.success),
            ),
        ]),
        Line::from(vec![
            Span::styled("NOASSERTION: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", lic_m.noassertion_count),
                if lic_m.noassertion_count > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled(
                " - Indicates missing data",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("Non-standard: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", lic_m.non_standard_licenses),
                if lic_m.non_standard_licenses > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
        ]),
    ];
    let lic_widget = Paragraph::new(lic_lines).block(
        Block::default()
            .title(" Licenses ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.error)),
    );
    frame.render_widget(lic_widget, h_chunks[1]);
}

fn render_integrity_provenance_details(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let h = &report.hash_quality_metrics;
    let p = &report.provenance_metrics;

    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Integrity / Hash details
    let hash_lines = vec![
        Line::from(vec![
            Span::styled("Any hash:    ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", h.components_with_any_hash),
                Style::default().fg(scheme.success),
            ),
            Span::styled(" components", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("Strong hash: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", h.components_with_strong_hash),
                Style::default().fg(scheme.success),
            ),
            Span::styled(" (SHA-256+, BLAKE)", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("Weak only:   ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", h.components_with_weak_only),
                if h.components_with_weak_only > 0 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled(" (MD5/SHA-1 only)", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("Signature:   ", Style::default().fg(scheme.text_muted)),
            if p.has_signature {
                Span::styled("\u{2713} Present", Style::default().fg(scheme.success))
            } else {
                Span::styled("\u{2717} None", Style::default().fg(scheme.muted))
            },
        ]),
    ];
    let hash_widget = Paragraph::new(hash_lines).block(
        Block::default()
            .title(" Integrity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.accent)),
    );
    frame.render_widget(hash_widget, h_chunks[0]);

    // Provenance details
    let check = |val: bool| -> Span<'static> {
        if val {
            Span::styled("\u{2713} ", Style::default().fg(scheme.success))
        } else {
            Span::styled("\u{2717} ", Style::default().fg(scheme.error))
        }
    };

    let prov_lines = vec![
        Line::from(vec![
            check(p.has_tool_creator),
            Span::styled("Tool creator", Style::default().fg(scheme.text_muted)),
            Span::styled("  ", Style::default()),
            check(p.has_org_creator),
            Span::styled("Org creator", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            check(p.is_fresh),
            Span::styled(
                format!("Fresh ({} days old)", p.timestamp_age_days),
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(vec![
            check(p.has_primary_component),
            Span::styled("Primary component", Style::default().fg(scheme.text_muted)),
        ]),
        Line::from(vec![
            Span::styled("Completeness: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", p.completeness_declaration),
                Style::default().fg(scheme.text),
            ),
        ]),
    ];
    let prov_widget = Paragraph::new(prov_lines).block(
        Block::default()
            .title(" Provenance ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.info)),
    );
    frame.render_widget(prov_widget, h_chunks[1]);
}

pub fn render_dependency_details(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let d = &report.dependency_metrics;
    let v = &report.vulnerability_metrics;

    let depth_str = d
        .max_depth
        .map_or("N/A".to_string(), |depth| format!("{depth}"));
    let cycle_style = if d.cycle_count > 0 {
        Style::default().fg(scheme.error)
    } else {
        Style::default().fg(scheme.success)
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            "Dependency Graph:",
            Style::default().fg(scheme.primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Edges: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", d.total_dependencies),
                Style::default().fg(scheme.text),
            ),
            Span::styled("  Roots: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", d.root_components),
                Style::default().fg(scheme.text),
            ),
            Span::styled("  Max depth: ", Style::default().fg(scheme.text_muted)),
            Span::styled(&depth_str, Style::default().fg(scheme.text)),
            Span::styled("  Islands: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", d.island_count),
                Style::default().fg(scheme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Orphans: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", d.orphan_components),
                if d.orphan_components > 5 {
                    Style::default().fg(scheme.warning)
                } else {
                    Style::default().fg(scheme.success)
                },
            ),
            Span::styled("  Cycles: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("{}", d.cycle_count), cycle_style),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Vulnerability Data:",
            Style::default().fg(scheme.error).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Total vulns: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", v.total_vulnerabilities),
                Style::default().fg(scheme.text),
            ),
            Span::styled("  |  With CVSS: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("{}", v.with_cvss), Style::default().fg(scheme.text)),
            Span::styled("  |  With CWE: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("{}", v.with_cwe), Style::default().fg(scheme.text)),
        ]),
    ];

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Dependency & Vulnerability Analysis ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.accent)),
    );
    frame.render_widget(paragraph, area);
}

pub fn render_quality_recommendations(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    selected_recommendation: usize,
    scroll_offset: usize,
) {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];

    if report.recommendations.is_empty() {
        lines.push(Line::styled(
            " Excellent! This SBOM meets all quality standards.",
            Style::default().fg(scheme.success).bold(),
        ));
        lines.push(Line::from(""));
        lines.push(Line::styled(
            " No improvements needed - the SBOM includes:",
            Style::default().fg(scheme.text),
        ));
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                "Complete component information",
                Style::default().fg(scheme.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                "Valid package identifiers (PURLs/CPEs)",
                Style::default().fg(scheme.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                "Proper license declarations",
                Style::default().fg(scheme.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("   + ", Style::default().fg(scheme.success)),
            Span::styled(
                "Dependency relationships defined",
                Style::default().fg(scheme.text),
            ),
        ]));
    } else {
        lines.push(Line::styled(
            " Actionable Recommendations (ordered by impact):",
            Style::default().fg(scheme.primary).bold(),
        ));
        lines.push(Line::from(""));

        for (i, rec) in report.recommendations.iter().enumerate() {
            let is_selected = i == selected_recommendation;
            let prefix = if is_selected { "> " } else { "  " };
            let style = if is_selected {
                Style::default().fg(scheme.text).bold()
            } else {
                Style::default().fg(scheme.text)
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(scheme.primary)),
                Span::styled(
                    format!("[P{}] ", rec.priority),
                    priority_style(rec.priority),
                ),
                Span::styled(
                    format!("[{}] ", rec.category.name()),
                    Style::default().fg(scheme.info),
                ),
                Span::styled(&rec.message, style),
            ]));

            if is_selected {
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled("Why: ", Style::default().fg(scheme.accent)),
                    Span::styled(
                        get_recommendation_reason(rec.category),
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled("Affected: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        format!("{} components", rec.affected_count),
                        Style::default().fg(scheme.accent),
                    ),
                    Span::styled(
                        "  |  Potential gain: ",
                        Style::default().fg(scheme.text_muted),
                    ),
                    Span::styled(
                        format!("+{:.1} points", rec.impact),
                        Style::default().fg(scheme.success),
                    ),
                ]));
                lines.push(Line::from(""));
            }
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(
                    " Recommendations ({}) - 'v' to switch view ",
                    report.recommendations.len()
                ))
                .title_style(Style::default().fg(scheme.error).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.error)),
        )
        .scroll((scroll_offset as u16, 0));
    frame.render_widget(paragraph, area);
}
