//! Key material view for the CBOM TUI mode.
//!
//! Shows cryptographic key material grouped by state with size and type info.

use crate::model::{ComponentType, CryptoAssetType, CryptoMaterialState};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the keys tab (CBOM mode).
pub fn render_keys(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let keys: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::RelatedCryptoMaterial)
        })
        .collect();

    if keys.is_empty() {
        let msg = Paragraph::new("No key material found in this CBOM.")
            .block(Block::default().borders(Borders::ALL).title(" Keys "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: key list ──
    let items: Vec<ListItem> = keys
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let mat = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.related_crypto_material_properties.as_ref());

            let (state_icon, state_color) = mat
                .and_then(|m| m.state.as_ref())
                .map(|s| match s {
                    CryptoMaterialState::Active => ("●", Color::Green),
                    CryptoMaterialState::Compromised => ("!", Color::Red),
                    CryptoMaterialState::Deactivated => ("○", Color::DarkGray),
                    CryptoMaterialState::Destroyed => ("X", Color::DarkGray),
                    _ => ("?", Color::Yellow),
                })
                .unwrap_or(("?", Color::DarkGray));

            let type_label = mat.map(|m| m.material_type.to_string()).unwrap_or_default();

            let style = if i == app.keys_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{state_icon} "), Style::default().fg(state_color)),
                Span::raw(&comp.name),
                Span::styled(
                    format!("  ({type_label})"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Key Material ({}) ", keys.len())),
    );
    frame.render_widget(list, panels[0]);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(keys.len().saturating_sub(1));
    let Some(comp) = keys.get(selected) else {
        frame.render_widget(
            Paragraph::new("No selection")
                .block(Block::default().borders(Borders::ALL).title(" Detail ")),
            panels[1],
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(&comp.name),
    ]));

    if let Some(cp) = &comp.crypto_properties
        && let Some(mat) = &cp.related_crypto_material_properties
    {
        lines.push(Line::raw(""));
        lines.push(Line::from(format!("Type:   {}", mat.material_type)));
        if let Some(state) = &mat.state {
            let color = match state {
                CryptoMaterialState::Active => Color::Green,
                CryptoMaterialState::Compromised => Color::Red,
                CryptoMaterialState::Deactivated => Color::DarkGray,
                _ => Color::Yellow,
            };
            lines.push(Line::from(vec![
                Span::raw("State:  "),
                Span::styled(state.to_string(), Style::default().fg(color)),
            ]));
        }
        if let Some(size) = mat.size {
            lines.push(Line::from(format!("Size:   {size} bits")));
        }
        if let Some(fmt) = &mat.format {
            lines.push(Line::from(format!("Format: {fmt}")));
        }
        if let Some(algo_ref) = &mat.algorithm_ref {
            lines.push(Line::from(format!("Algo:   {algo_ref}")));
        }
        if let Some(sb) = &mat.secured_by {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "-- Secured By --",
                Style::default().fg(Color::Cyan),
            ));
            lines.push(Line::from(format!("Mechanism: {}", sb.mechanism)));
            if let Some(a) = &sb.algorithm_ref {
                lines.push(Line::from(format!("Algorithm: {a}")));
            }
        }
        lines.push(Line::raw(""));
        if let Some(d) = &mat.creation_date {
            lines.push(Line::from(format!("Created:   {}", d.format("%Y-%m-%d"))));
        }
        if let Some(d) = &mat.activation_date {
            lines.push(Line::from(format!("Activated: {}", d.format("%Y-%m-%d"))));
        }
        if let Some(d) = &mat.expiration_date {
            lines.push(Line::from(format!("Expires:   {}", d.format("%Y-%m-%d"))));
        }
    }

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Key Detail "))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
