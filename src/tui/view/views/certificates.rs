//! Certificate validity view for the CBOM TUI mode.
//!
//! Shows certificates sorted by expiry with validity status coloring.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the certificates tab (CBOM mode).
pub fn render_certificates(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let certs: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Certificate)
        })
        .collect();

    let mut certs = certs;
    certs.sort_by(|a, b| {
        let days_remaining = |c: &&crate::model::Component| -> i64 {
            c.crypto_properties
                .as_ref()
                .and_then(|cp| cp.certificate_properties.as_ref())
                .and_then(|cert| cert.validity_days())
                .unwrap_or(i64::MAX)
        };
        days_remaining(a).cmp(&days_remaining(b)) // most urgent first
    });

    if certs.is_empty() {
        let msg = Paragraph::new("No certificates found in this CBOM.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Certificates "),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: certificate list ──
    let items: Vec<ListItem> = certs
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let cert = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.certificate_properties.as_ref());

            let (status_icon, status_color) = cert
                .map(|c| {
                    if c.is_expired() {
                        ("X", Color::Red)
                    } else if c.is_expiring_soon(90) {
                        ("!", Color::Yellow)
                    } else {
                        ("✓", Color::Green)
                    }
                })
                .unwrap_or(("?", Color::DarkGray));

            let expiry = cert
                .and_then(|c| c.not_valid_after.as_ref())
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "-".to_string());

            let style = if i == app.certificates_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{status_icon} "), Style::default().fg(status_color)),
                Span::raw(&comp.name),
                Span::styled(format!("  {expiry}"), Style::default().fg(Color::DarkGray)),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Certificates ({}) ", certs.len())),
    );
    frame.render_widget(list, panels[0]);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(certs.len().saturating_sub(1));
    let Some(comp) = certs.get(selected) else {
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
        && let Some(cert) = &cp.certificate_properties
    {
        lines.push(Line::raw(""));
        if let Some(s) = &cert.subject_name {
            lines.push(Line::from(format!("Subject:    {s}")));
        }
        if let Some(i) = &cert.issuer_name {
            lines.push(Line::from(format!("Issuer:     {i}")));
        }
        lines.push(Line::raw(""));
        if let Some(nb) = &cert.not_valid_before {
            lines.push(Line::from(format!("Valid From: {}", nb.format("%Y-%m-%d"))));
        }
        if let Some(na) = &cert.not_valid_after {
            let color = if cert.is_expired() {
                Color::Red
            } else if cert.is_expiring_soon(90) {
                Color::Yellow
            } else {
                Color::Green
            };
            let status_label = if cert.is_expired() {
                " EXPIRED"
            } else if cert.is_expiring_soon(90) {
                " EXPIRING SOON"
            } else {
                ""
            };
            lines.push(Line::from(vec![
                Span::raw("Valid To:   "),
                Span::styled(
                    na.format("%Y-%m-%d").to_string(),
                    Style::default().fg(color),
                ),
                Span::styled(status_label, Style::default().fg(color)),
            ]));
            if let Some(days) = cert.validity_days() {
                lines.push(Line::from(format!("Remaining:  {days} days")));
            }
        }
        lines.push(Line::raw(""));
        if let Some(fmt) = &cert.certificate_format {
            lines.push(Line::from(format!("Format:     {fmt}")));
        }
        if let Some(sig_ref) = &cert.signature_algorithm_ref {
            lines.push(Line::from(format!("Sig Algo:   {sig_ref}")));
        }
        if let Some(key_ref) = &cert.subject_public_key_ref {
            lines.push(Line::from(format!("Public Key: {key_ref}")));
        }
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Certificate Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
