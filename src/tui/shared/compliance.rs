//! Shared compliance rendering functions used by both App (diff mode) and `ViewApp` (view mode).

use crate::quality::ViolationSeverity;
use crate::tui::shared::text::wrapped_line_count;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    style::Modifier,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Render a modal overlay showing violation details, centered on the given area.
///
/// The overlay is sized to its content: every field, reference and the
/// wrapped remediation text is measured first, and the box grows (up to the
/// full area height) to hold all of it plus the close hint. When even the
/// full height is too small, trailing lines are replaced by an explicit
/// "+N more lines" marker rather than being clipped silently (#347).
pub fn render_violation_detail_overlay(
    frame: &mut Frame,
    area: Rect,
    violation: &crate::quality::Violation,
) {
    let scheme = colors();

    let overlay_width = (f32::from(area.width) * 0.7)
        .max(40.0)
        .min(f32::from(area.width)) as u16;
    // Inner text width: the block draws a 1-column border on each side.
    let inner_width = overlay_width.saturating_sub(2);

    let (severity_text, severity_color) = match violation.severity {
        ViolationSeverity::Error => ("ERROR", scheme.error),
        ViolationSeverity::Warning => ("WARNING", scheme.warning),
        ViolationSeverity::Info => ("INFO", scheme.info),
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Severity:    ", Style::default().fg(scheme.muted)),
            Span::styled(
                severity_text,
                Style::default()
                    .fg(severity_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Category:    ", Style::default().fg(scheme.muted)),
            Span::styled(violation.category.name(), Style::default().fg(scheme.text)),
        ]),
        Line::from(vec![
            Span::styled("Requirement: ", Style::default().fg(scheme.muted)),
            Span::styled(&violation.requirement, Style::default().fg(scheme.accent)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Issue: ", Style::default().fg(scheme.muted)),
            Span::styled(&violation.message, Style::default().fg(scheme.text)),
        ]),
    ];

    if let Some(ref element) = violation.element {
        lines.push(Line::from(vec![
            Span::styled("Element: ", Style::default().fg(scheme.muted)),
            Span::styled(element, Style::default().fg(scheme.warning)),
        ]));
    }

    // Rule ID — the stable, externally-visible key (matches the SARIF rule ID and
    // the registry-driven references below). The CLI surfaces this; the overlay
    // dropped it previously.
    lines.push(Line::from(vec![
        Span::styled("Rule: ", Style::default().fg(scheme.muted)),
        Span::styled(violation.rule_id, Style::default().fg(scheme.accent)),
    ]));

    // Harmonised-standard / regulation references, e.g. "EU AI Act: Annex IV §2(d)".
    // Mirrors the markdown "Standard refs" column and the SARIF help_uri.
    if !violation.standard_refs.is_empty() {
        lines.push(Line::from(Span::styled(
            "References:",
            Style::default().fg(scheme.muted),
        )));
        for r in &violation.standard_refs {
            let mut spans = vec![
                Span::styled("  • ", Style::default().fg(scheme.muted)),
                Span::styled(
                    format!("{}: {}", r.standard.label(), r.id),
                    Style::default().fg(scheme.text),
                ),
            ];
            if let Some(ref uri) = r.help_uri {
                spans.push(Span::styled(
                    format!("  {uri}"),
                    Style::default().fg(scheme.text_muted),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Remediation:",
        Style::default()
            .fg(scheme.success)
            .add_modifier(Modifier::BOLD),
    )));

    let guidance = violation.remediation_guidance();
    for wrapped_line in textwrap_simple(&guidance, inner_width as usize) {
        lines.push(Line::from(Span::styled(
            wrapped_line,
            Style::default().fg(scheme.text),
        )));
    }

    // Size the box to the wrapped content (+2 for the border). The close hint
    // is appended last so it is always the final visible row.
    let close_hint = Line::from(Span::styled(
        " Press Enter or Esc to close ",
        Style::default().fg(scheme.text_muted),
    ));
    let max_inner_height = area.height.saturating_sub(2) as usize;
    // Content rows + blank spacer + close hint.
    let mut rows = wrapped_line_count(&lines, inner_width) + 2;
    if rows > max_inner_height && max_inner_height >= 3 {
        // Never clip silently: drop trailing content until the marker and the
        // close hint fit, then say how much is hidden.
        let total = lines.len();
        let budget = max_inner_height - 2;
        while !lines.is_empty() && wrapped_line_count(&lines, inner_width) > budget {
            lines.pop();
        }
        let hidden = total - lines.len();
        lines.push(Line::from(Span::styled(
            format!("\u{2026} +{hidden} more lines \u{2014} enlarge the terminal to see all"),
            Style::default().fg(scheme.text_muted),
        )));
        lines.push(close_hint);
        rows = wrapped_line_count(&lines, inner_width);
    } else {
        lines.push(Line::from(""));
        lines.push(close_hint);
    }

    let overlay_height = u16::try_from(rows + 2).unwrap_or(u16::MAX).min(area.height);
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay_area = Rect::new(x, y, overlay_width, overlay_height);

    frame.render_widget(Clear, overlay_area);

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Violation Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, overlay_area);
}

/// Simple text wrapping helper — splits text into lines of at most `max_width` characters.
pub fn textwrap_simple(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() > max_width {
            lines.push(current);
            current = word.to_string();
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use crate::quality::{
        StandardKind, StandardRef, Violation, ViolationCategory, ViolationSeverity,
    };
    use crate::tui::test_support::render_to_text;

    fn ai_act_violation() -> Violation {
        Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: "Missing AI documentation".to_string(),
            element: Some("model-1".to_string()),
            component_id: None,
            counts: None,
            requirement: "EU AI Act Annex IV".to_string(),
            rule_id: "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
            standard_refs: vec![StandardRef::new(StandardKind::EuAiAct, "Annex IV §2(d)")],
            remediation: None,
            finding_detail: None,
            deadline: None,
        }
    }

    #[test]
    fn overlay_shows_rule_id_and_reference() {
        let violation = ai_act_violation();
        let text = render_to_text(100, 24, |frame| {
            super::render_violation_detail_overlay(frame, frame.area(), &violation);
        });
        assert!(text.contains("Rule:"), "overlay must label the rule id");
        assert!(
            text.contains("SBOM-AIACT-ANNEX-IV-2D-DATASETS"),
            "overlay must surface the rule id; got:\n{text}"
        );
        assert!(
            text.contains("References:"),
            "overlay must label references"
        );
        assert!(
            text.contains("EU AI Act: Annex IV"),
            "overlay must render 'label: id' refs; got:\n{text}"
        );
    }

    /// #347: the reporter's CRA Annex I violation (3 references + a multi-line
    /// remediation) overflowed the old fixed 60%-height box at 24 rows, so
    /// the end of the remediation text and the close hint were clipped. The
    /// remediation is the CycloneDX text `ComplianceChecker::check()` stamps.
    fn cra_supply_chain_violation() -> Violation {
        Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DependencyInfo,
            message: "No dependency relationships found; 42 components have no dependency \
                      information"
                .to_string(),
            element: None,
            component_id: None,
            counts: None,
            requirement: "CRA Annex I: Technical documentation".to_string(),
            rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            standard_refs: vec![
                StandardRef::new(StandardKind::CraAnnex, "Annex I Part II"),
                StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-01"),
                StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-03"),
            ],
            remediation: Some(
                crate::quality::rule_meta("SBOM-CRA-ANNEX-I-SUPPLY-CHAIN")
                    .expect("registered rule")
                    .remediation_for(crate::quality::RemediationFormat::CycloneDx),
            ),
            finding_detail: None,
            deadline: None,
        }
    }

    #[test]
    fn overlay_grows_to_fit_remediation_and_close_hint() {
        let violation = cra_supply_chain_violation();
        let guidance = violation.remediation_guidance();
        let last_word = guidance
            .split_whitespace()
            .last()
            .expect("remediation has words");
        for (width, height) in [(166u16, 24u16), (120, 24), (100, 24), (80, 24), (166, 40)] {
            let text = render_to_text(width, height, |frame| {
                super::render_violation_detail_overlay(frame, frame.area(), &violation);
            });
            assert!(
                text.contains(last_word) && text.contains("Remediation:"),
                "remediation must be fully visible to its last word at {width}x{height}; got:\n{text}"
            );
            assert!(
                text.contains("Press Enter or Esc to close"),
                "close hint must be visible at {width}x{height}; got:\n{text}"
            );
            assert!(
                !text.contains("more lines"),
                "no truncation marker when the detail fits at {width}x{height}; got:\n{text}"
            );
        }
    }

    #[test]
    fn overlay_marks_hidden_lines_on_tiny_terminal() {
        let violation = cra_supply_chain_violation();
        let text = render_to_text(80, 10, |frame| {
            super::render_violation_detail_overlay(frame, frame.area(), &violation);
        });
        assert!(
            text.contains("more lines"),
            "overflow must be marked explicitly, not clipped silently; got:\n{text}"
        );
        assert!(
            text.contains("Press Enter or Esc to close"),
            "close hint must survive truncation; got:\n{text}"
        );
        // Degenerate sizes must not panic.
        for (width, height) in [(40u16, 4u16), (40, 2), (10, 1)] {
            let _ = render_to_text(width, height, |frame| {
                super::render_violation_detail_overlay(frame, frame.area(), &violation);
            });
        }
    }

    #[test]
    fn overlay_omits_references_when_empty() {
        let mut violation = ai_act_violation();
        violation.standard_refs.clear();
        let text = render_to_text(100, 24, |frame| {
            super::render_violation_detail_overlay(frame, frame.area(), &violation);
        });
        // Rule line is always shown; References header only when refs exist.
        assert!(text.contains("Rule:"));
        assert!(!text.contains("References:"));
    }
}
