//! Shared compliance rendering functions used by both App (diff mode) and `ViewApp` (view mode).

use crate::quality::ViolationSeverity;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    style::Modifier,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Render a modal overlay showing violation details, centered on the given area.
pub fn render_violation_detail_overlay(
    frame: &mut Frame,
    area: Rect,
    violation: &crate::quality::Violation,
) {
    let scheme = colors();

    let overlay_width = (f32::from(area.width) * 0.7)
        .max(40.0)
        .min(f32::from(area.width)) as u16;
    let overlay_height = (f32::from(area.height) * 0.6)
        .max(12.0)
        .min(f32::from(area.height)) as u16;
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay_area = Rect::new(x, y, overlay_width, overlay_height);

    frame.render_widget(Clear, overlay_area);

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
    let max_line_width = overlay_width.saturating_sub(4) as usize;
    for wrapped_line in textwrap_simple(guidance, max_line_width) {
        lines.push(Line::from(Span::styled(
            wrapped_line,
            Style::default().fg(scheme.text),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Press Enter or Esc to close ",
        Style::default().fg(scheme.text_muted),
    )));

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
            requirement: "EU AI Act Annex IV".to_string(),
            rule_id: "SBOM-AIACT-ANNEX-IV-2D",
            standard_refs: vec![StandardRef::new(StandardKind::EuAiAct, "Annex IV §2(d)")],
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
            text.contains("SBOM-AIACT-ANNEX-IV-2D"),
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
