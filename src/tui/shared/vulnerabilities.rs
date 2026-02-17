//! Shared vulnerability rendering functions used by both diff-mode and view-mode.
//!
//! Pure rendering functions that take domain values directly, with no
//! dependency on `App` or `ViewApp`.

use crate::tui::theme::colors;
use ratatui::prelude::*;

/// Render CWE list as a single line with label.
pub fn render_vuln_cwe_lines(cwes: &[String], max_display: usize) -> Vec<Line<'static>> {
    if cwes.is_empty() {
        return vec![];
    }

    let cwe_list = cwes
        .iter()
        .take(max_display)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");

    vec![Line::from(vec![
        Span::styled("CWEs: ", Style::default().fg(colors().text_muted)),
        Span::styled(cwe_list, Style::default().fg(colors().accent)),
    ])]
}

/// Render KEV badge spans for use in vulnerability row ID cells.
/// Returns `["KEV", " "]` if `is_kev` is true, empty vec otherwise.
pub fn render_kev_badge_spans(
    is_kev: bool,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Span<'static>> {
    if is_kev {
        vec![
            Span::styled(
                "KEV",
                Style::default()
                    .fg(scheme.kev_badge_fg())
                    .bg(scheme.kev())
                    .bold(),
            ),
            Span::raw(" "),
        ]
    } else {
        vec![]
    }
}

/// Render DIR/TRN depth badge spans for use in vulnerability row ID cells.
/// Returns `["DIR"/" TRN", " "]` based on depth, or empty vec if `None`.
pub fn render_depth_badge_spans(
    depth: Option<usize>,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Span<'static>> {
    let Some(depth) = depth else {
        return vec![];
    };
    let (label, bg_color) = if depth == 1 {
        ("DIR", scheme.direct_dep())
    } else {
        ("TRN", scheme.transitive_dep())
    };
    vec![
        Span::styled(
            label,
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(bg_color)
                .bold(),
        ),
        Span::raw(" "),
    ]
}

/// Render RANSOMWARE badge spans for KEV vulns with known ransomware use.
pub fn render_ransomware_badge_spans(
    is_ransomware: bool,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Span<'static>> {
    if is_ransomware {
        vec![
            Span::styled(
                "RW",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.critical)
                    .bold(),
            ),
            Span::raw(" "),
        ]
    } else {
        vec![]
    }
}

/// Render VEX status badge spans for use in vulnerability row ID cells.
///
/// - `NotAffected` → green "NA" badge
/// - `Fixed` → green "FX" badge
/// - `Affected` → red "AF" badge
/// - `UnderInvestigation` → yellow "UI" badge
pub fn render_vex_badge_spans(
    vex_state: Option<&crate::model::VexState>,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Span<'static>> {
    let Some(state) = vex_state else {
        return vec![];
    };
    use crate::model::VexState;
    let (label, bg_color) = match state {
        VexState::NotAffected => ("NA", scheme.low),
        VexState::Fixed => ("FX", scheme.low),
        VexState::Affected => ("AF", scheme.critical),
        VexState::UnderInvestigation => ("UI", scheme.medium),
    };
    vec![
        Span::styled(
            label,
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(bg_color)
                .bold(),
        ),
        Span::raw(" "),
    ]
}

/// Color for a CVSS score value (red ≥9.0, orange ≥7.0, yellow ≥4.0, green <4.0).
pub fn cvss_score_color(score: f32, scheme: &crate::tui::theme::ColorScheme) -> Color {
    if score >= 9.0 {
        scheme.critical
    } else if score >= 7.0 {
        scheme.high
    } else if score >= 4.0 {
        scheme.medium
    } else {
        scheme.low
    }
}

/// Map vulnerability source name to a theme color.
pub fn source_color(source: &str, scheme: &crate::tui::theme::ColorScheme) -> Color {
    match source.to_uppercase().as_str() {
        "OSV" => scheme.accent,
        "NVD" => scheme.highlight,
        "GHSA" => scheme.info,
        _ => scheme.text_muted,
    }
}

/// Severity rank for sorting (lower = more severe).
///
/// Recognises common aliases: "moderate" = "medium", "informational" = "info" = "none".
pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" | "moderate" => 2,
        "low" => 3,
        "info" | "informational" | "none" => 4,
        _ => 5,
    }
}

/// Word-wrap text to fit within `max_width` columns, breaking at word boundaries.
pub fn word_wrap(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= max_width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_wrap_basic() {
        let result = word_wrap("hello world foo bar", 11);
        assert_eq!(result, vec!["hello world", "foo bar"]);
    }

    #[test]
    fn test_word_wrap_empty() {
        let result = word_wrap("", 80);
        assert_eq!(result, vec![""]);
    }

    #[test]
    fn test_word_wrap_single_long_word() {
        let result = word_wrap("superlongword", 5);
        assert_eq!(result, vec!["superlongword"]);
    }

    #[test]
    fn test_render_cwe_lines_empty() {
        let lines = render_vuln_cwe_lines(&[], 3);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_render_cwe_lines_some() {
        let cwes = vec!["CWE-79".to_string(), "CWE-89".to_string()];
        let lines = render_vuln_cwe_lines(&cwes, 3);
        assert_eq!(lines.len(), 1);
    }
}
