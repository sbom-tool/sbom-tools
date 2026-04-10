//! Algorithm inventory view for the CBOM TUI mode.
//!
//! Shows algorithms grouped by family with quantum safety indicators,
//! security levels, and FIPS/CNSA compliance status.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::{AlgorithmSortBy, ViewApp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the algorithms tab (CBOM mode).
pub fn render_algorithms(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let algorithms: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Algorithm)
        })
        .collect();

    let mut algorithms = algorithms;
    algorithms.sort_by(|a, b| match app.algorithm_sort_by {
        AlgorithmSortBy::Name => a.name.cmp(&b.name),
        AlgorithmSortBy::Family => {
            let af = a
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.algorithm_family.as_deref())
                .unwrap_or("");
            let bf = b
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.algorithm_family.as_deref())
                .unwrap_or("");
            af.cmp(bf)
        }
        AlgorithmSortBy::QuantumLevel => {
            let al = a
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.nist_quantum_security_level)
                .unwrap_or(0);
            let bl = b
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.nist_quantum_security_level)
                .unwrap_or(0);
            bl.cmp(&al) // descending: highest quantum level first
        }
        AlgorithmSortBy::Strength => {
            let strength = |c: &&crate::model::Component| -> u8 {
                let Some(cp) = &c.crypto_properties else {
                    return 1;
                };
                let Some(algo) = &cp.algorithm_properties else {
                    return 1;
                };
                if algo.is_weak_by_name(&c.name) {
                    return 0;
                }
                if algo.nist_quantum_security_level == Some(0) {
                    return 1;
                }
                2
            };
            strength(a).cmp(&strength(b))
        }
    });

    if algorithms.is_empty() {
        let msg = Paragraph::new("No algorithms found in this CBOM.")
            .block(Block::default().borders(Borders::ALL).title(" Algorithms "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: algorithm list ──
    let items: Vec<ListItem> = algorithms
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let algo = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref());

            let qi = algo
                .map(|a| {
                    if a.is_weak_by_name(&comp.name) {
                        Span::styled(
                            "!",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        )
                    } else if a.is_quantum_safe() {
                        Span::styled("Q", Style::default().fg(Color::Green))
                    } else {
                        Span::styled("V", Style::default().fg(Color::Yellow))
                    }
                })
                .unwrap_or_else(|| Span::raw(" "));

            let family = algo
                .and_then(|a| a.algorithm_family.as_deref())
                .unwrap_or("-");

            let style = if i == app.algorithms_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                qi,
                Span::raw(" "),
                Span::raw(&comp.name),
                Span::styled(
                    format!("  [{family}]"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(format!(
        " Algorithms ({}) [{}] ",
        algorithms.len(),
        app.algorithm_sort_by.label()
    )));
    frame.render_widget(list, panels[0]);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(algorithms.len().saturating_sub(1));
    let Some(comp) = algorithms.get(selected) else {
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

    if let Some(cp) = &comp.crypto_properties {
        if let Some(oid) = &cp.oid {
            lines.push(Line::from(vec![
                Span::styled("OID:  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(oid.as_str()),
            ]));
        }
        lines.push(Line::raw(""));

        if let Some(algo) = &cp.algorithm_properties {
            lines.push(Line::from(format!("Primitive: {}", algo.primitive)));
            if let Some(f) = &algo.algorithm_family {
                lines.push(Line::from(format!("Family:    {f}")));
            }
            if let Some(p) = &algo.parameter_set_identifier {
                lines.push(Line::from(format!("Params:    {p}")));
            }
            if let Some(m) = &algo.mode {
                lines.push(Line::from(format!("Mode:      {m}")));
            }
            if let Some(c) = &algo.elliptic_curve {
                lines.push(Line::from(format!("Curve:     {c}")));
            }
            if let Some(bits) = algo.classical_security_level {
                lines.push(Line::from(format!("Security:  {bits} bits")));
            }
            if let Some(ql) = algo.nist_quantum_security_level {
                let color = if ql == 0 {
                    Color::Red
                } else if ql >= 3 {
                    Color::Green
                } else {
                    Color::Yellow
                };
                lines.push(Line::from(vec![
                    Span::raw("Quantum:   "),
                    Span::styled(
                        format!("Level {ql}"),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    if ql == 0 {
                        Span::styled(" VULNERABLE", Style::default().fg(Color::Red))
                    } else {
                        Span::styled(" SAFE", Style::default().fg(Color::Green))
                    },
                ]));
            }
            if algo.is_weak_by_name(&comp.name) {
                lines.push(Line::styled(
                    "WARNING: Weak/broken algorithm",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }
            if algo.is_hybrid_pqc() {
                lines.push(Line::styled(
                    "Hybrid PQC combiner",
                    Style::default().fg(Color::Cyan),
                ));
            }
            if !algo.crypto_functions.is_empty() {
                let funcs: Vec<_> = algo
                    .crypto_functions
                    .iter()
                    .map(|f| f.to_string())
                    .collect();
                lines.push(Line::from(format!("Functions: {}", funcs.join(", "))));
            }
            if !algo.certification_level.is_empty() {
                let certs: Vec<_> = algo
                    .certification_level
                    .iter()
                    .map(|c| c.to_string())
                    .collect();
                lines.push(Line::from(format!("Certified: {}", certs.join(", "))));
            }
            if let Some(p) = &algo.padding {
                lines.push(Line::from(format!("Padding:   {p}")));
            }
            if let Some(env) = &algo.execution_environment {
                lines.push(Line::from(format!("Exec Env:  {env}")));
            }
            if let Some(platform) = &algo.implementation_platform {
                lines.push(Line::from(format!("Platform:  {platform}")));
            }
        }
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Algorithm Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
