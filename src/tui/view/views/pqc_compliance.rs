//! PQC compliance view for the CBOM TUI mode.
//!
//! Dedicated CNSA 2.0 + NIST PQC compliance view showing
//! algorithm-by-algorithm assessment.

use crate::model::{ComponentType, CryptoAssetType};
use crate::quality::{ComplianceLevel, ViolationSeverity};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};

/// Render the PQC compliance tab (CBOM mode).
pub fn render_pqc_compliance(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = crate::tui::theme::colors();
    // Ensure compliance results are cached before borrowing sbom
    app.ensure_compliance_results();

    let algorithms: Vec<_> = app
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

    if algorithms.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No algorithms found",
            Some("CBOM data with cryptoProperties is required for PQC assessment"),
            None,
        );
        return;
    }
    let Some(results) = app.compliance_results.as_ref() else {
        return;
    };
    let cnsa2_fallback = crate::quality::ComplianceResult::new(ComplianceLevel::Cnsa2, vec![]);
    let pqc_fallback = crate::quality::ComplianceResult::new(ComplianceLevel::NistPqc, vec![]);
    let cnsa2_result = results
        .iter()
        .find(|r| r.level == ComplianceLevel::Cnsa2)
        .unwrap_or(&cnsa2_fallback);
    let pqc_result = results
        .iter()
        .find(|r| r.level == ComplianceLevel::NistPqc)
        .unwrap_or(&pqc_fallback);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(6),
            Constraint::Length(7),
        ])
        .split(area);

    // ── Header: compliance summary ──
    // Split each standard's error count into errors on the algorithms listed
    // below vs. errors on other assets (certificates/keys/protocols/document
    // checks). The old single total captioned a table it did not match:
    // "(10 errors)" over 6 FAIL rows, with the other 4 invisible on this tab.
    let algo_names: std::collections::HashSet<&str> =
        algorithms.iter().map(|c| c.name.as_str()).collect();
    let split_errors = |result: &crate::quality::ComplianceResult| -> (usize, usize) {
        let mut on_algorithms = 0usize;
        let mut other = 0usize;
        for v in result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
        {
            if v.element.as_deref().is_some_and(|e| algo_names.contains(e)) {
                on_algorithms += 1;
            } else {
                other += 1;
            }
        }
        (on_algorithms, other)
    };
    let (cnsa2_algo_errors, cnsa2_other_errors) = split_errors(cnsa2_result);
    let (pqc_algo_errors, pqc_other_errors) = split_errors(pqc_result);
    let cnsa2_errors = cnsa2_algo_errors + cnsa2_other_errors;
    let pqc_errors = pqc_algo_errors + pqc_other_errors;

    let error_summary = |on_algorithms: usize, other: usize, breakdown: bool| -> String {
        let total = crate::tui::shared::text::count_noun(on_algorithms + other, "error");
        if other == 0 || !breakdown {
            format!(" ({total})")
        } else {
            format!(" ({total}: {on_algorithms} algo + {other} other)")
        }
    };

    let cnsa2_color = if cnsa2_errors == 0 {
        scheme.success
    } else {
        scheme.error
    };
    let pqc_color = if pqc_errors == 0 {
        scheme.success
    } else {
        scheme.error
    };

    let verdict_line = |breakdown: bool| -> Line<'static> {
        Line::from(vec![
            Span::raw(" CNSA 2.0: "),
            Span::styled(
                if cnsa2_errors == 0 {
                    "COMPLIANT"
                } else {
                    "NON-COMPLIANT"
                },
                Style::default()
                    .fg(cnsa2_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(error_summary(
                cnsa2_algo_errors,
                cnsa2_other_errors,
                breakdown,
            )),
            Span::raw("   │   "),
            Span::raw("NIST PQC: "),
            Span::styled(
                if pqc_errors == 0 {
                    "COMPLIANT"
                } else {
                    "NON-COMPLIANT"
                },
                Style::default().fg(pqc_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(error_summary(pqc_algo_errors, pqc_other_errors, breakdown)),
        ])
    };

    // Prefer the per-asset breakdown, but never let it clip mid-token: fall
    // back to plain totals when it doesn't fit (the note line below still
    // explains where the non-algorithm errors live).
    let inner_w = chunks[0].width.saturating_sub(2);
    let line_width = |line: &Line| -> u16 {
        use unicode_width::UnicodeWidthStr;
        line.spans
            .iter()
            .map(|s| UnicodeWidthStr::width(s.content.as_ref()) as u16)
            .sum()
    };
    let mut summary_line = verdict_line(true);
    if line_width(&summary_line) > inner_w {
        summary_line = verdict_line(false);
    }

    // The non-algorithm errors have no rows below — say where they live
    // instead of leaving the header count irreconcilable with the table.
    // Width-aware with an ellipsized last resort: never clip mid-word.
    let other_note = if cnsa2_other_errors + pqc_other_errors > 0 {
        use unicode_width::UnicodeWidthStr;
        const LONG: &str = " Errors on certificates/keys/protocols have no row below \u{2014} \
                            press e to export the full report";
        const SHORT: &str = " Errors on certs/keys/protocols have no row below \u{2014} \
                             press e to export";
        let text = if UnicodeWidthStr::width(LONG) as u16 <= inner_w {
            LONG.to_string()
        } else if UnicodeWidthStr::width(SHORT) as u16 <= inner_w {
            SHORT.to_string()
        } else {
            crate::tui::widgets::truncate_str(SHORT, inner_w as usize)
        };
        Line::styled(text, Style::default().fg(scheme.text_muted))
    } else {
        Line::raw("")
    };

    let header_lines = vec![
        summary_line,
        other_note,
        Line::styled(
            " Algorithm-by-Algorithm Assessment",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" PQC Compliance "),
    );
    frame.render_widget(header, chunks[0]);

    // ── Table: per-algorithm compliance status ──
    let header_row = Row::new(vec![
        "Algorithm",
        "Family",
        "NIST Lvl",
        "CNSA 2.0",
        "NIST PQC",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

    let rows: Vec<Row> = algorithms
        .iter()
        .map(|comp| {
            let algo = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref());

            let family = algo
                .and_then(|a| a.algorithm_family.as_deref())
                .unwrap_or("-");
            let level = algo
                .and_then(|a| a.nist_quantum_security_level)
                .map_or("-".to_string(), |l| l.to_string());

            // Check CNSA 2.0 status for this algorithm
            let cnsa2_status = if cnsa2_result.violations.iter().any(|v| {
                v.element.as_deref() == Some(&comp.name) && v.severity == ViolationSeverity::Error
            }) {
                Span::styled("FAIL", Style::default().fg(scheme.error))
            } else {
                Span::styled("PASS", Style::default().fg(scheme.success))
            };

            // Check NIST PQC status for this algorithm. One green verdict
            // only: the old "OK" (an approval exists) vs "PASS" (no
            // violation at all) split was two unexplained green vocabularies
            // — the approval, a passed check, shows in the detail pane.
            let pqc_status = if pqc_result.violations.iter().any(|v| {
                v.element.as_deref() == Some(&comp.name) && v.severity == ViolationSeverity::Error
            }) {
                Span::styled("FAIL", Style::default().fg(scheme.error))
            } else {
                Span::styled("PASS", Style::default().fg(scheme.success))
            };

            Row::new(vec![
                ratatui::text::Text::from(comp.name.as_str()),
                ratatui::text::Text::from(family),
                ratatui::text::Text::from(level),
                ratatui::text::Text::from(Line::from(cnsa2_status)),
                ratatui::text::Text::from(Line::from(pqc_status)),
            ])
        })
        .collect();

    let selected = app.pqc_selected.min(algorithms.len() - 1);
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(10),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL))
    .row_highlight_style(
        Style::default()
            .bg(scheme.selection)
            .fg(scheme.text)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("\u{25b6}");

    let mut table_state = ratatui::widgets::TableState::default().with_selected(Some(selected));
    frame.render_stateful_widget(table, chunks[1], &mut table_state);
    // Visible rows: borders (2) + header row + its bottom margin (2).
    let visible = chunks[1].height.saturating_sub(4) as usize;
    if algorithms.len() > visible {
        crate::tui::widgets::render_scrollbar(
            frame,
            chunks[1].inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            algorithms.len(),
            selected,
        );
    }

    render_violation_detail(
        frame,
        chunks[2],
        algorithms[selected],
        cnsa2_result,
        pqc_result,
    );
}

/// Detail pane for the selected algorithm: every CNSA 2.0 / NIST PQC
/// violation naming it, with requirement, standard references, and
/// remediation guidance — the data the bare PASS/FAIL cells discard — then
/// one line per check it passed (an approval), which is no violation.
fn render_violation_detail(
    frame: &mut Frame,
    area: Rect,
    comp: &crate::model::Component,
    cnsa2_result: &crate::quality::ComplianceResult,
    pqc_result: &crate::quality::ComplianceResult,
) {
    let scheme = crate::tui::theme::colors();
    let inner_w = area.width.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();

    let severity_color = |sev: ViolationSeverity| match sev {
        ViolationSeverity::Error => scheme.error,
        ViolationSeverity::Warning => scheme.warning,
        ViolationSeverity::Info => scheme.info,
    };

    // One line per fact, each truncated to the pane width with an explicit
    // ellipsis (no Wrap: wrapping made line counts unpredictable and cut
    // remediation text mid-sentence with no marker).
    for (tag, result) in [("[CNSA 2.0]", cnsa2_result), ("[NIST PQC]", pqc_result)] {
        for v in result
            .violations
            .iter()
            .filter(|v| v.element.as_deref() == Some(&comp.name))
        {
            lines.push(Line::from(vec![
                Span::styled(
                    tag,
                    Style::default()
                        .fg(severity_color(v.severity))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    crate::tui::widgets::truncate_str(
                        &v.message,
                        inner_w.saturating_sub(tag.len() + 1),
                    ),
                    Style::default().fg(scheme.text),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Req: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    crate::tui::widgets::truncate_str(&v.requirement, inner_w.saturating_sub(7)),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
            for r in v.standard_refs.iter() {
                // Skip degenerate "CNSA 2.0: CNSA 2.0" citations — a ref
                // whose id merely repeats the standard label adds nothing
                // the [tag] hasn't already said.
                if r.id == r.standard.label() {
                    continue;
                }
                lines.push(Line::from(Span::styled(
                    crate::tui::widgets::truncate_str(
                        &format!("  {}: {}", r.standard.label(), r.id),
                        inner_w,
                    ),
                    Style::default().fg(scheme.text_muted),
                )));
            }
            // Remediation is for findings that need remediating: an
            // informational finding must not be followed by "Fix: Migrate…".
            if v.severity == ViolationSeverity::Info {
                lines.push(Line::from(vec![
                    Span::styled("  Status: ", Style::default().fg(scheme.success)),
                    Span::styled(
                        "informational \u{2014} no action needed",
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  Fix: ", Style::default().fg(scheme.success)),
                    Span::styled(
                        crate::tui::widgets::truncate_str(
                            &v.remediation_guidance(),
                            inner_w.saturating_sub(7),
                        ),
                        Style::default().fg(scheme.text),
                    ),
                ]));
            }
        }
    }

    if lines.is_empty() {
        lines.push(Line::styled(
            "\u{2713} Compliant \u{2014} no violations for this algorithm.",
            Style::default().fg(scheme.success),
        ));
    }

    // The checks the algorithm passed (NIST PQC approvals), after its
    // violations and apart from them.
    for (tag, result) in [("[CNSA 2.0]", cnsa2_result), ("[NIST PQC]", pqc_result)] {
        for pass in result
            .passed
            .iter()
            .filter(|p| p.component_id.as_deref() == Some(comp.canonical_id.value()))
        {
            let prefix = format!("\u{2713} {tag} ");
            lines.push(Line::from(vec![
                Span::styled(
                    prefix.clone(),
                    Style::default()
                        .fg(scheme.success)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    crate::tui::widgets::truncate_str(
                        &pass.message,
                        inner_w.saturating_sub(prefix.chars().count()),
                    ),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
    }

    // Never clip silently: dual-failing algorithms produce more detail than
    // the fixed pane holds. Point at export — the CBOM profile has no
    // Compliance tab, so the old "see the Compliance tab" hint was a dead end.
    let inner_h = area.height.saturating_sub(2) as usize;
    if lines.len() > inner_h && inner_h >= 2 {
        let hidden = lines.len() - (inner_h - 1);
        lines.truncate(inner_h - 1);
        lines.push(Line::styled(
            format!("\u{2026} +{hidden} more lines \u{2014} press e to export the full report"),
            Style::default().fg(scheme.text_muted),
        ));
    }

    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", comp.name)),
    );
    frame.render_widget(detail, area);
}
