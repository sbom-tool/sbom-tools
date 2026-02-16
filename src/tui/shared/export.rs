//! Shared export dialog widget used by both diff and view TUIs.

use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

/// Render the export format selection dialog.
///
/// `scope` describes what will be exported (e.g. "Components", "Vulnerabilities",
/// "Report"). It is shown in both the title bar and the header line.
pub fn render_export_dialog(frame: &mut Frame, area: Rect, scope: &str, centered_rect_fn: fn(u16, u16, Rect) -> Rect) {
    let popup_area = centered_rect_fn(50, 45, area);
    frame.render_widget(Clear, popup_area);

    let header = format!("━━━ Export {scope} ━━━");

    let export_text = vec![
        Line::styled(
            header,
            Style::default().fg(colors().primary).bold(),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled("[j]", Style::default().fg(colors().accent).bold()),
            Span::styled(" JSON      ", Style::default().fg(colors().text)),
            Span::styled(
                "- Structured data for automation",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("[s]", Style::default().fg(colors().accent).bold()),
            Span::styled(" SARIF     ", Style::default().fg(colors().text)),
            Span::styled(
                "- CI/CD integration (GitHub, etc.)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("[m]", Style::default().fg(colors().accent).bold()),
            Span::styled(" Markdown  ", Style::default().fg(colors().text)),
            Span::styled(
                "- Documentation & PRs",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("[h]", Style::default().fg(colors().accent).bold()),
            Span::styled(" HTML      ", Style::default().fg(colors().text)),
            Span::styled(
                "- Stakeholder report",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("[c]", Style::default().fg(colors().accent).bold()),
            Span::styled(" CSV       ", Style::default().fg(colors().text)),
            Span::styled(
                "- Component list for spreadsheets",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "Press Esc to cancel",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let title = format!(" Export {scope} ");
    let export = Paragraph::new(export_text)
        .block(
            Block::default()
                .title(title)
                .title_style(Style::default().fg(colors().primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().primary)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(export, popup_area);
}
