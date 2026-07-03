//! Dataset inventory view for the AI-BOM TUI mode.
//!
//! Lists `Data` components (training / evaluation datasets) with a detail panel
//! that reuses the shared ML / dataset metadata renderer.

use crate::model::ComponentType;
use crate::tui::shared::components::render_ml_dataset_lines;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the Datasets tab (AI-BOM mode).
pub fn render_datasets(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let mut datasets: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::Data)
        .collect();
    datasets.sort_by(|a, b| a.name.cmp(&b.name));

    if datasets.is_empty() {
        let msg = Paragraph::new("No datasets found in this AI-BOM.")
            .block(Block::default().borders(Borders::ALL).title(" Datasets "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── Left: dataset list ──
    let selected = app.datasets_selected.min(datasets.len().saturating_sub(1));
    let items: Vec<ListItem> = datasets
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
            .title(format!(" Datasets ({}) ", datasets.len())),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !datasets.is_empty() {
        list_state.select(Some(selected));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let Some(comp) = datasets.get(selected) else {
        return;
    };
    let mut lines: Vec<Line> = vec![Line::from(vec![
        Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(comp.name.clone(), Style::default().fg(scheme.accent)),
    ])];
    if let Some(purl) = &comp.identifiers.purl {
        lines.push(Line::from(vec![
            Span::styled("PURL: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(purl.clone(), Style::default().fg(scheme.text_muted)),
        ]));
    }
    if !comp.licenses.declared.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("License: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                comp.licenses.declared[0].expression.clone(),
                Style::default().fg(scheme.text),
            ),
        ]));
    }
    // Reuse the shared ML / Dataset metadata renderer (dataset governance, etc.).
    lines.extend(render_ml_dataset_lines(
        comp.ml_model.as_ref(),
        comp.dataset.as_ref(),
        panels[1].width,
    ));

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Dataset Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
