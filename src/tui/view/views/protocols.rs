//! Protocol and cipher suite view for the CBOM TUI mode.
//!
//! Shows protocols with their cipher suites and version information.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the protocols tab (CBOM mode).
pub fn render_protocols(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let protos: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Protocol)
        })
        .collect();

    if protos.is_empty() {
        let msg = Paragraph::new("No protocols found in this CBOM.")
            .block(Block::default().borders(Borders::ALL).title(" Protocols "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: protocol list ──
    let items: Vec<ListItem> = protos
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let proto = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.protocol_properties.as_ref());

            let version = proto.and_then(|p| p.version.as_deref()).unwrap_or("-");

            let suite_count = proto.map_or(0, |p| p.cipher_suites.len());

            let style = if i == app.protocols_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::raw(&comp.name),
                Span::styled(
                    format!("  v{version}  [{suite_count} suites]"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Protocols ({}) ", protos.len())),
    );
    frame.render_widget(list, panels[0]);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(protos.len().saturating_sub(1));
    let Some(comp) = protos.get(selected) else {
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
        && let Some(proto) = &cp.protocol_properties
    {
        lines.push(Line::raw(""));
        lines.push(Line::from(format!("Protocol: {}", proto.protocol_type)));
        if let Some(v) = &proto.version {
            lines.push(Line::from(format!("Version:  {v}")));
        }

        if !proto.cipher_suites.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!("-- Cipher Suites ({}) --", proto.cipher_suites.len()),
                Style::default().fg(Color::Cyan),
            ));
            for suite in &proto.cipher_suites {
                if let Some(name) = &suite.name {
                    lines.push(Line::from(format!("  {name}")));
                }
                if !suite.algorithms.is_empty() {
                    lines.push(Line::styled(
                        format!("    Algorithms: {}", suite.algorithms.join(", ")),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            }
        }

        if let Some(ikev2) = &proto.ikev2_transform_types {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "-- IKEv2 Transform Types --",
                Style::default().fg(Color::Cyan),
            ));
            if !ikev2.encr.is_empty() {
                lines.push(Line::from(format!("Encryption: {}", ikev2.encr.join(", "))));
            }
            if !ikev2.prf.is_empty() {
                lines.push(Line::from(format!("PRF:        {}", ikev2.prf.join(", "))));
            }
            if !ikev2.integ.is_empty() {
                lines.push(Line::from(format!(
                    "Integrity:  {}",
                    ikev2.integ.join(", ")
                )));
            }
            if !ikev2.ke.is_empty() {
                lines.push(Line::from(format!("Key Exch:   {}", ikev2.ke.join(", "))));
            }
        }

        if !proto.crypto_ref_array.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "-- Referenced Algorithms --",
                Style::default().fg(Color::Cyan),
            ));
            for r in &proto.crypto_ref_array {
                lines.push(Line::from(format!("  {r}")));
            }
        }
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Protocol Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
