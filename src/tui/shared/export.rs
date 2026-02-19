//! Shared export dialog widget used by both diff and view TUIs.

use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

/// Format option row data.
struct FormatRow {
    key: &'static str,
    name: &'static str,
    desc: &'static str,
}

const FORMATS: &[FormatRow] = &[
    FormatRow {
        key: "j",
        name: "JSON",
        desc: "Structured data for automation",
    },
    FormatRow {
        key: "s",
        name: "SARIF",
        desc: "CI/CD integration (GitHub, etc.)",
    },
    FormatRow {
        key: "m",
        name: "Markdown",
        desc: "Documentation & PRs",
    },
    FormatRow {
        key: "h",
        name: "HTML",
        desc: "Stakeholder report",
    },
    FormatRow {
        key: "c",
        name: "CSV",
        desc: "Spreadsheet import",
    },
];

/// Render the export format selection dialog.
///
/// `scope` describes what will be exported (e.g. "Components", "Vulnerabilities",
/// "Report"). It is shown in both the title bar and the header line.
pub fn render_export_dialog(
    frame: &mut Frame,
    area: Rect,
    scope: &str,
    centered_rect_fn: fn(u16, u16, Rect) -> Rect,
) {
    let popup_area = centered_rect_fn(50, 45, area);
    frame.render_widget(Clear, popup_area);

    let header = format!("━━━ Export {scope} ━━━");

    let mut lines = vec![
        Line::styled(header, Style::default().fg(colors().primary).bold())
            .alignment(Alignment::Center),
        Line::from(""),
    ];

    for row in FORMATS {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  [{key}]", key = row.key),
                Style::default().fg(colors().accent).bold(),
            ),
            Span::styled(
                format!("  {name:<10}", name = row.name),
                Style::default().fg(colors().text),
            ),
            Span::styled(
                format!("  {desc}", desc = row.desc),
                Style::default().fg(colors().text_muted),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(
        Line::styled(
            "Press Esc to cancel",
            Style::default().fg(colors().text_muted),
        )
        .alignment(Alignment::Center),
    );

    let title = format!(" Export {scope} ");
    let export = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_style(Style::default().fg(colors().primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().primary)),
        )
        .alignment(Alignment::Left);

    frame.render_widget(export, popup_area);
}
