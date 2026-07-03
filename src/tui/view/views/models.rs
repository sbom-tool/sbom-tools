//! Machine-learning model inventory view for the AI-BOM TUI mode.
//!
//! Lists `MachineLearningModel` components with a detail panel that reuses the
//! shared ML / dataset metadata renderer (`render_ml_dataset_lines`).

use crate::model::ComponentType;
use crate::tui::shared::components::render_ml_dataset_lines;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the Models tab (AI-BOM mode).
pub fn render_models(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let mut models: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::MachineLearningModel)
        .collect();
    models.sort_by(|a, b| a.name.cmp(&b.name));

    if models.is_empty() {
        let msg = Paragraph::new("No machine-learning models found in this AI-BOM.")
            .block(Block::default().borders(Borders::ALL).title(" Models "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── Left: model list ──
    let selected = app.models_selected.min(models.len().saturating_sub(1));
    let items: Vec<ListItem> = models
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let ver = comp.version.as_deref().unwrap_or("");
            ListItem::new(Line::from(vec![
                Span::styled(comp.name.clone(), Style::default().fg(scheme.text)),
                Span::styled(format!("  {ver}"), Style::default().fg(scheme.text_muted)),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Models ({}) ", models.len())),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !models.is_empty() {
        list_state.select(Some(selected));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let Some(comp) = models.get(selected) else {
        return;
    };
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(comp.name.clone(), Style::default().fg(scheme.accent)),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                comp.version.clone().unwrap_or_else(|| "-".to_string()),
                Style::default().fg(scheme.text),
            ),
        ]),
    ];
    if let Some(purl) = &comp.identifiers.purl {
        lines.push(Line::from(vec![
            Span::styled("PURL: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(purl.clone(), Style::default().fg(scheme.text_muted)),
        ]));
    }
    // Reuse the shared ML / Dataset metadata renderer.
    lines.extend(render_ml_dataset_lines(
        comp.ml_model.as_ref(),
        comp.dataset.as_ref(),
        panels[1].width,
    ));

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Model Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
