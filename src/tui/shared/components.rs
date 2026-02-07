//! Shared component rendering functions used by both diff-mode and view-mode.
//!
//! Pure rendering functions that take domain values directly, with no
//! dependency on `App` or `ViewApp`.

use crate::tui::security::LicenseRisk;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::collections::{HashMap, HashSet, VecDeque};

/// Compute blast radius via BFS on the reverse dependency graph.
/// Returns `(direct_dependents, transitive_count)`.
pub fn compute_blast_radius(
    component_name: &str,
    reverse_graph: &HashMap<String, Vec<String>>,
) -> (usize, usize) {
    let direct_deps = reverse_graph
        .get(component_name)
        .map_or(0, std::vec::Vec::len);

    let mut transitive_count = 0usize;
    if direct_deps > 0 {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(deps) = reverse_graph.get(component_name) {
            for d in deps {
                queue.push_back(d.clone());
            }
        }
        while let Some(node) = queue.pop_front() {
            if visited.insert(node.clone()) {
                transitive_count += 1;
                if let Some(deps) = reverse_graph.get(&node) {
                    for d in deps {
                        if !visited.contains(d) {
                            queue.push_back(d.clone());
                        }
                    }
                }
            }
        }
    }

    (direct_deps, transitive_count)
}

/// Determine risk level and associated color from vulnerability count and blast radius.
pub fn determine_risk_level(vuln_count: usize, transitive_count: usize) -> (&'static str, Color) {
    if vuln_count > 0 && transitive_count > 10 {
        ("Critical", colors().critical)
    } else if vuln_count > 0 || transitive_count > 20 {
        ("High", colors().high)
    } else if transitive_count > 5 {
        ("Medium", colors().medium)
    } else {
        ("Low", colors().low)
    }
}

/// Render the security analysis section: header, risk badge, blast radius, license risk.
pub fn render_security_analysis_lines(
    vuln_count: usize,
    direct_deps: usize,
    transitive_count: usize,
    license_text: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    // Section header
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("━━━ ", Style::default().fg(colors().border)),
        Span::styled(
            "🛡 Security Analysis",
            Style::default().fg(colors().accent).bold(),
        ),
        Span::styled(" ━━━", Style::default().fg(colors().border)),
    ]));

    // Risk level badge
    let (risk_level, risk_color) = determine_risk_level(vuln_count, transitive_count);
    lines.push(Line::from(vec![
        Span::styled("  Risk Level: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!(" {risk_level} "),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(risk_color)
                .bold(),
        ),
    ]));

    // Blast radius
    lines.push(Line::from(vec![
        Span::styled(
            "  Blast Radius: ",
            Style::default().fg(colors().text_muted),
        ),
        Span::styled(
            format!("{direct_deps} direct"),
            Style::default().fg(if direct_deps > 5 {
                colors().warning
            } else {
                colors().text
            }),
        ),
        Span::styled(", ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{transitive_count} transitive"),
            Style::default().fg(if transitive_count > 10 {
                colors().warning
            } else {
                colors().text
            }),
        ),
    ]));

    // Impact (only when there are transitive dependents)
    if transitive_count > 0 {
        let impact = if transitive_count > 50 {
            "Critical - affects many components"
        } else if transitive_count > 20 {
            "Significant impact"
        } else if transitive_count > 5 {
            "Moderate impact"
        } else {
            "Limited impact"
        };
        lines.push(Line::from(vec![
            Span::styled("  Impact: ", Style::default().fg(colors().text_muted)),
            Span::styled(impact, Style::default().fg(colors().text).italic()),
        ]));
    }

    // License risk
    let license_risk = LicenseRisk::from_license(license_text);
    let license_risk_color = match license_risk {
        LicenseRisk::High => colors().high,
        LicenseRisk::Medium => colors().medium,
        LicenseRisk::Low => colors().permissive,
        LicenseRisk::None => colors().text_muted,
    };
    lines.push(Line::from(vec![
        Span::styled(
            "  License Risk: ",
            Style::default().fg(colors().text_muted),
        ),
        Span::styled(
            license_risk.as_str(),
            Style::default().fg(license_risk_color),
        ),
    ]));

    lines
}

/// Render the quick actions hint line for component details.
pub fn render_quick_actions_hint() -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("[y]", Style::default().fg(colors().accent)),
            Span::styled(" copy  ", Style::default().fg(colors().text_muted)),
            Span::styled("[F]", Style::default().fg(colors().accent)),
            Span::styled(" flag  ", Style::default().fg(colors().text_muted)),
            Span::styled("[n]", Style::default().fg(colors().accent)),
            Span::styled(" note  ", Style::default().fg(colors().text_muted)),
            Span::styled("[o]", Style::default().fg(colors().accent)),
            Span::styled(" CVE", Style::default().fg(colors().text_muted)),
        ]),
    ]
}

/// Render vulnerability entries with severity badge + ID + optional description.
/// Each entry is `(severity, id, description)`.
pub fn render_vulnerability_list_lines(
    vulns: &[(&str, &str, Option<&str>)],
    max_display: usize,
    total_count: usize,
    area_width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    for (severity, id, description) in vulns.iter().take(max_display) {
        let sev_color = colors().severity_color(severity);
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                format!(" {} ", severity.chars().next().unwrap_or('?')),
                Style::default()
                    .fg(colors().badge_fg_dark)
                    .bg(sev_color)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(
                id.to_string(),
                Style::default().fg(sev_color).bold(),
            ),
        ]));

        if let Some(desc) = description {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "    {}",
                    crate::tui::widgets::truncate_str(desc, area_width as usize - 6)
                ),
                Style::default().fg(colors().text_muted).italic(),
            )]));
        }
    }

    if total_count > max_display {
        lines.push(Line::styled(
            format!("    ... and {} more", total_count - max_display),
            Style::default().fg(colors().text_muted),
        ));
    }

    lines
}

/// Render flagged indicator and optional analyst note.
/// `suffix` is appended after the badge (e.g. `" for follow-up"` in view mode).
pub fn render_flagged_lines(
    is_flagged: bool,
    note: Option<&str>,
    area_width: u16,
    suffix: &str,
) -> Vec<Line<'static>> {
    if !is_flagged {
        return vec![];
    }

    let scheme = colors();
    let mut lines = vec![];

    let mut badge_spans = vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            " 🚩 FLAGGED ",
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.warning)
                .bold(),
        ),
    ];
    if !suffix.is_empty() {
        badge_spans.push(Span::styled(
            suffix.to_string(),
            Style::default().fg(scheme.warning),
        ));
    }
    lines.push(Line::from(badge_spans));

    if let Some(note) = note {
        lines.push(Line::from(vec![
            Span::styled("  Note: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                crate::tui::widgets::truncate_str(note, area_width as usize - 10),
                Style::default().fg(scheme.text).italic(),
            ),
        ]));
    }

    lines
}

/// Render a detail panel: wraps `lines` in a bordered Paragraph with focus-aware styling.
pub fn render_detail_block(
    frame: &mut Frame,
    area: Rect,
    lines: Vec<Line<'_>>,
    title: &str,
    focused: bool,
) {
    let scheme = colors();
    let border_color = if focused { scheme.accent } else { scheme.border };
    let title_style = if focused {
        Style::default().fg(scheme.accent).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(detail, area);
}

/// Render an empty detail panel with icon, message, and keyboard hints.
pub fn render_empty_detail_panel(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    icon: &str,
    message: &str,
    hints: &[(&str, &str)],
    focused: bool,
) {
    let scheme = colors();
    let border_color = if focused { scheme.accent } else { scheme.border };
    let title_style = if focused {
        Style::default().fg(scheme.accent).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let mut text = vec![
        Line::from(""),
        Line::styled(icon.to_string(), Style::default().fg(scheme.text_muted)),
        Line::from(""),
        Line::styled(message.to_string(), Style::default().fg(scheme.text)),
        Line::from(""),
    ];

    if !hints.is_empty() {
        let mut hint_spans = Vec::new();
        for (key, desc) in hints {
            hint_spans.push(Span::styled(
                key.to_string(),
                Style::default().fg(scheme.accent),
            ));
            hint_spans.push(Span::styled(
                desc.to_string(),
                Style::default().fg(scheme.text_muted),
            ));
        }
        text.push(Line::from(hint_spans));
    }

    let detail = Paragraph::new(text)
        .block(
            Block::default()
                .title(title)
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(detail, area);
}
