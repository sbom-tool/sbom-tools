//! Overview tab for `ViewApp` - high-level SBOM statistics.

use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use crate::tui::widgets::{SeverityBar, extract_display_name, format_count};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
};

pub fn render_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    match app.bom_profile {
        crate::model::BomProfile::Cbom => render_cbom_overview(frame, area, app),
        // AI-BOMs use the standard SBOM overview; AI-specific detail lives in
        // the dedicated Models / Datasets / AI-Readiness tabs.
        crate::model::BomProfile::Sbom | crate::model::BomProfile::AiBom => {
            render_sbom_overview(frame, area, app);
        }
    }
}

fn render_sbom_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    // Split into left (stats) and right (details) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_stats_panel(frame, chunks[0], app);
    render_details_panel(frame, chunks[1], app);
}

fn render_cbom_overview(frame: &mut Frame, area: Rect, app: &ViewApp) {
    use crate::model::{ComponentType, CryptoAssetType};
    use crate::quality::CryptographyMetrics;

    let metrics = CryptographyMetrics::from_sbom(&app.sbom);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // ── Left: asset summary ──
    let readiness = metrics.quantum_readiness_score();
    let readiness_color = if readiness >= 80.0 {
        Color::Green
    } else if readiness >= 40.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let bar_filled = ((readiness / 100.0) * 20.0) as usize;
    let bar_empty = 20_usize.saturating_sub(bar_filled);
    let bar = format!(
        "{}{}",
        "\u{2588}".repeat(bar_filled),
        "\u{2591}".repeat(bar_empty)
    );

    let mut left_lines = vec![
        Line::from(vec![Span::styled(
            " Quantum Readiness  ",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::raw(" "),
            Span::styled(&bar, Style::default().fg(readiness_color)),
            Span::styled(
                format!(" {readiness:.0}%"),
                Style::default()
                    .fg(readiness_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  ({}/{})",
                metrics.quantum_safe_count, metrics.algorithms_count
            )),
        ]),
        Line::raw(""),
        Line::styled(
            format!(" Algorithms:    {}", metrics.algorithms_count),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("   Quantum-safe  {}", metrics.quantum_safe_count)),
        Line::from(format!(
            "   Vulnerable    {}",
            metrics.quantum_vulnerable_count
        )),
    ];

    if metrics.weak_algorithm_count > 0 {
        left_lines.push(Line::styled(
            format!("   Weak/broken   {}", metrics.weak_algorithm_count),
            Style::default().fg(Color::Red),
        ));
    }
    if metrics.hybrid_pqc_count > 0 {
        left_lines.push(Line::styled(
            format!("   Hybrid PQC    {}", metrics.hybrid_pqc_count),
            Style::default().fg(Color::Cyan),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Certificates:  {}", metrics.certificates_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if metrics.expired_certificates > 0 {
        left_lines.push(Line::styled(
            format!("   Expired       {}", metrics.expired_certificates),
            Style::default().fg(Color::Red),
        ));
    }
    if metrics.expiring_soon_certificates > 0 {
        left_lines.push(Line::styled(
            format!("   Expiring      {}", metrics.expiring_soon_certificates),
            Style::default().fg(Color::Yellow),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Keys:          {}", metrics.keys_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if metrics.compromised_keys > 0 {
        left_lines.push(Line::styled(
            format!("   Compromised   {}", metrics.compromised_keys),
            Style::default().fg(Color::Red),
        ));
    }

    left_lines.push(Line::raw(""));
    left_lines.push(Line::styled(
        format!(" Protocols:     {}", metrics.protocols_count),
        Style::default().add_modifier(Modifier::BOLD),
    ));

    let left_panel = Paragraph::new(left_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" CBOM Overview "),
    );
    frame.render_widget(left_panel, chunks[0]);

    // ── Right: PQC migration status + warnings ──
    let mut right_lines = vec![
        Line::styled(
            " PQC Migration Status",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
    ];

    // List algorithms with their PQC status
    let algos: Vec<_> = app
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

    for comp in &algos {
        let algo = comp
            .crypto_properties
            .as_ref()
            .and_then(|cp| cp.algorithm_properties.as_ref());
        let (icon, color) = if let Some(a) = algo {
            if a.is_weak_by_name(&comp.name) {
                ("!", Color::Red)
            } else if a.is_quantum_safe() {
                ("\u{2713}", Color::Green)
            } else {
                ("\u{2717}", Color::Yellow)
            }
        } else {
            ("?", Color::DarkGray)
        };
        right_lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{icon} "), Style::default().fg(color)),
            Span::raw(&comp.name),
        ]));
    }

    // Weak algorithm warnings
    if !metrics.weak_algorithm_names.is_empty() {
        right_lines.push(Line::raw(""));
        right_lines.push(Line::styled(
            " Weak Algorithms",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
        for name in &metrics.weak_algorithm_names {
            right_lines.push(Line::styled(
                format!("  ! {name}"),
                Style::default().fg(Color::Red),
            ));
        }
    }

    let right_panel = Paragraph::new(right_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Migration & Warnings "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(right_panel, chunks[1]);
}

fn render_stats_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    // Compute adaptive height for ecosystem panel: entries + 2 (borders)
    let eco_count = app.stats.ecosystem_counts.len();
    let eco_height = (eco_count + 2).min(12) as u16; // cap at 12 rows

    if app.stats.eol_enriched {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),          // Summary cards
                Constraint::Length(8),          // EOL breakdown
                Constraint::Length(8),          // Vulnerability breakdown
                Constraint::Length(eco_height), // Ecosystem distribution (adaptive)
                Constraint::Min(6),             // License distribution
            ])
            .split(area);

        render_summary_cards(frame, chunks[0], app);
        render_eol_breakdown(frame, chunks[1], app);
        render_vuln_breakdown(frame, chunks[2], app);
        render_ecosystem_dist(frame, chunks[3], app);
        render_license_dist(frame, chunks[4], app);
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),          // Summary cards
                Constraint::Length(8),          // Vulnerability breakdown
                Constraint::Length(eco_height), // Ecosystem distribution (adaptive)
                Constraint::Min(6),             // License distribution
            ])
            .split(area);

        render_summary_cards(frame, chunks[0], app);
        render_vuln_breakdown(frame, chunks[1], app);
        render_ecosystem_dist(frame, chunks[2], app);
        render_license_dist(frame, chunks[3], app);
    }
}

fn render_summary_cards(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;

    let card_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    // Components card
    let comp_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format_count(stats.component_count),
            Style::default()
                .fg(scheme.primary)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Components", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("{} ecosystems", stats.ecosystem_counts.len()),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let comp_para = Paragraph::new(comp_content)
        .block(
            Block::default()
                .title(" Components ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(comp_para, card_chunks[0]);

    // Vulnerabilities card
    let vuln_color = if stats.critical_count > 0 {
        scheme.critical
    } else if stats.high_count > 0 {
        scheme.high
    } else if stats.vuln_count > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    let vuln_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format_count(stats.vuln_count),
            Style::default()
                .fg(vuln_color)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Vulnerabilities", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "{}C {}H {}M {}L",
                stats.critical_count, stats.high_count, stats.medium_count, stats.low_count
            ),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let vuln_para = Paragraph::new(vuln_content)
        .block(
            Block::default()
                .title(" Vulnerabilities ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(vuln_color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(vuln_para, card_chunks[1]);

    // Licenses card
    let lic_content = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            stats.license_count.to_string(),
            Style::default()
                .fg(scheme.success)
                .bold()
                .add_modifier(Modifier::BOLD),
        )]),
        Line::styled("Unique Licenses", Style::default().fg(scheme.muted)),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "{} unknown",
                stats.license_counts.get("Unknown").unwrap_or(&0)
            ),
            Style::default().fg(scheme.muted),
        )]),
    ];

    let lic_para = Paragraph::new(lic_content)
        .block(
            Block::default()
                .title(" Licenses ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(lic_para, card_chunks[2]);
}

fn render_vuln_breakdown(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;
    let total = stats.vuln_count.max(1);

    let mut lines = vec![Line::from("")];

    // Severity bar
    let _bar = SeverityBar::new(
        stats.critical_count,
        stats.high_count,
        stats.medium_count,
        stats.low_count,
    );

    // Add percentage breakdown
    let add_severity_line = |lines: &mut Vec<Line>, label: &str, count: usize, color: Color| {
        let pct = (count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 20;
        let filled = (count * bar_width / total.max(1)).max(usize::from(count > 0));
        let scheme = colors();

        lines.push(Line::from(vec![
            Span::styled(format!("{label:>10} "), Style::default().fg(color).bold()),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>5} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    };

    add_severity_line(
        &mut lines,
        "Critical",
        stats.critical_count,
        scheme.critical,
    );
    add_severity_line(&mut lines, "High", stats.high_count, scheme.high);
    add_severity_line(&mut lines, "Medium", stats.medium_count, scheme.medium);
    add_severity_line(&mut lines, "Low", stats.low_count, scheme.low);

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Vulnerability Severity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(para, area);
}

fn render_eol_breakdown(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;
    let total = stats.component_count.max(1);

    let mut lines = vec![Line::from("")];

    let add_eol_line = |lines: &mut Vec<Line>, label: &str, count: usize, color: Color| {
        let pct = (count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 20;
        let filled = (count * bar_width / total.max(1)).max(usize::from(count > 0));
        let scheme = colors();

        lines.push(Line::from(vec![
            Span::styled(format!("{label:>10} "), Style::default().fg(color).bold()),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "\u{2591}".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>5} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    };

    add_eol_line(&mut lines, "EOL", stats.eol_count, scheme.critical);
    add_eol_line(
        &mut lines,
        "Near EOL",
        stats.eol_approaching_count,
        scheme.high,
    );
    add_eol_line(
        &mut lines,
        "Sec Only",
        stats.eol_security_only_count,
        scheme.warning,
    );
    add_eol_line(
        &mut lines,
        "Supported",
        stats.eol_supported_count,
        scheme.success,
    );

    let border_color = if stats.eol_count > 0 {
        scheme.critical
    } else if stats.eol_approaching_count > 0 {
        scheme.high
    } else {
        scheme.success
    };

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(format!(
                " End-of-Life Status ({} at risk) ",
                stats.eol_count + stats.eol_approaching_count
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    frame.render_widget(para, area);
}

fn render_ecosystem_dist(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;

    // Sort ecosystems by count
    let mut ecosystems: Vec<_> = stats.ecosystem_counts.iter().collect();
    ecosystems.sort_by(|a, b| b.1.cmp(a.1));

    let total = stats.component_count.max(1);

    let mut lines = vec![];

    let palette = scheme.chart_palette();

    // Dynamic row count based on available area height
    let max_eco_rows = area.height.saturating_sub(3) as usize; // subtract borders + "Other" line

    for (i, (eco, count)) in ecosystems.iter().take(max_eco_rows).enumerate() {
        let pct = (**count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 25;
        let filled = (**count * bar_width / total).max(usize::from(**count > 0));
        let color = palette[i % palette.len()];

        lines.push(Line::from(vec![
            Span::styled(
                {
                    use crate::tui::shared::floor_char_boundary;
                    let e = if eco.len() > 12 {
                        &eco[..floor_char_boundary(eco, 12)]
                    } else {
                        eco
                    };
                    format!("{e:>12} ")
                },
                Style::default().fg(color).bold(),
            ),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "░".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>5} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    if ecosystems.len() > max_eco_rows {
        let remaining: usize = ecosystems.iter().skip(max_eco_rows).map(|(_, c)| *c).sum();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>12} ", "Other"),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!("{remaining} more"),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Ecosystem Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );

    frame.render_widget(para, area);
}

fn render_license_dist(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();
    let stats = &app.stats;

    // Sort licenses by count, exclude "Unknown"
    let mut licenses: Vec<_> = stats
        .license_counts
        .iter()
        .filter(|(name, _)| name.as_str() != "Unknown")
        .collect();
    licenses.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let total = stats.component_count.max(1);
    let unknown_count = *stats.license_counts.get("Unknown").unwrap_or(&0);

    let mut lines = vec![];

    let palette = scheme.chart_palette();

    let max_rows = area.height.saturating_sub(3) as usize; // borders + possible "Other" line

    for (i, (lic, count)) in licenses.iter().take(max_rows).enumerate() {
        let pct = (**count as f64 / total as f64 * 100.0) as usize;
        let bar_width = 25;
        let filled = (**count * bar_width / total).max(usize::from(**count > 0));
        let color = palette[i % palette.len()];

        let display_name = if lic.len() > 12 {
            &lic[..crate::tui::shared::floor_char_boundary(lic, 12)]
        } else {
            lic.as_str()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{display_name:>12} "),
                Style::default().fg(color).bold(),
            ),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled(
                "\u{2591}".repeat(bar_width - filled),
                Style::default().fg(scheme.muted),
            ),
            Span::styled(
                format!(" {count:>5} ({pct:>2}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    // Show "Other" line for remaining + unknown
    let shown_count: usize = licenses.iter().take(max_rows).map(|(_, c)| *c).sum();
    let remaining = stats.component_count.saturating_sub(shown_count);
    if remaining > 0 || unknown_count > 0 {
        let other_total = remaining;
        if other_total > 0 {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:>12} ", "Other"),
                    Style::default().fg(scheme.muted),
                ),
                Span::styled(
                    format!("{other_total} more ({unknown_count} unknown)"),
                    Style::default().fg(scheme.muted),
                ),
            ]));
        }
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" License Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.success)),
    );

    frame.render_widget(para, area);
}

fn render_details_panel(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let has_edges = !app.sbom.edges.is_empty();

    let doc_info_height = compute_doc_info_height(&app.sbom.document);
    let remaining = area.height.saturating_sub(doc_info_height);
    let half = remaining / 2;

    let chunks = if has_edges {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(doc_info_height), // Document info
                Constraint::Length(half),            // Top vulnerable components
                Constraint::Min(6),                  // Top depended-on components
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(doc_info_height), // Document info
                Constraint::Min(6),                  // Top components with vulns
            ])
            .split(area)
    };

    // Document info
    render_document_info(frame, chunks[0], app);

    // Top vulnerable components
    render_top_vulnerable(frame, chunks[1], app);

    // Top depended-on components (only when dependency edges exist)
    if has_edges {
        render_top_depended_on(frame, chunks[2], app);
    }
}

/// Compute the height needed for the document info panel.
///
/// Counts identity lines + trust/compliance section + security section + export hint + borders.
fn compute_doc_info_height(doc: &crate::model::DocumentMetadata) -> u16 {
    use crate::model::CompletenessDeclaration;

    // Identity group: format + created are always shown (2 lines minimum)
    let mut lines: u16 = 2;
    if doc.name.is_some() {
        lines += 1;
    }
    let has_authors = doc.creators.iter().any(|c| {
        matches!(
            c.creator_type,
            crate::model::CreatorType::Person | crate::model::CreatorType::Organization
        )
    });
    if has_authors {
        lines += 1;
    }
    if doc
        .creators
        .iter()
        .any(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
    {
        lines += 1;
    }
    if doc.serial_number.is_some() {
        lines += 1;
    }

    // Trust & Compliance group
    let has_completeness = !matches!(
        doc.completeness_declaration,
        CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
    );
    let trust_lines = u16::from(has_completeness)
        + u16::from(doc.signature.is_some())
        + u16::from(doc.lifecycle_phase.is_some())
        + u16::from(doc.distribution_classification.is_some())
        + u16::from(doc.citations_count > 0);
    if trust_lines > 0 {
        lines += 1 + trust_lines; // section header + fields
    }

    // Security group
    let security_lines = u16::from(doc.security_contact.is_some())
        + u16::from(doc.vulnerability_disclosure_url.is_some())
        + u16::from(doc.support_end_date.is_some());
    if security_lines > 0 {
        lines += 1 + security_lines; // section header + fields
    }

    // Export hint (empty line + hint line) + borders (top + bottom)
    lines += 2 + 2;

    lines
}

fn render_document_info(frame: &mut Frame, area: Rect, app: &ViewApp) {
    use crate::model::CompletenessDeclaration;

    let scheme = colors();
    let doc = &app.sbom.document;

    let mut lines = vec![];
    let label_style = Style::default().fg(scheme.muted);

    // ── Group 1: Identity ──

    if let Some(name) = &doc.name {
        lines.push(Line::from(vec![
            Span::styled("Name:    ", label_style),
            Span::styled(name, Style::default().fg(scheme.text).bold()),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Format:  ", label_style),
        Span::styled(
            format!(" {} {} ", doc.format, doc.format_version),
            Style::default().fg(scheme.badge_fg_dark).bg(scheme.primary),
        ),
    ]));

    let (age_str, age_color) = format_age(doc.created);
    lines.push(Line::from(vec![
        Span::styled("Created: ", label_style),
        Span::raw(doc.created.format("%Y-%m-%d %H:%M:%S").to_string()),
        Span::styled(format!("  ({age_str})"), Style::default().fg(age_color)),
    ]));

    // Creators (people and orgs)
    let authors: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| {
            matches!(
                c.creator_type,
                crate::model::CreatorType::Person | crate::model::CreatorType::Organization
            )
        })
        .map(|c| c.name.clone())
        .collect();
    if !authors.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Authors: ", label_style),
            Span::raw(authors.join(", ")),
        ]));
    }

    // Tools
    let tools: Vec<_> = doc
        .creators
        .iter()
        .filter(|c| matches!(c.creator_type, crate::model::CreatorType::Tool))
        .map(|c| c.name.clone())
        .collect();
    if !tools.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tools:   ", label_style),
            Span::raw(tools.join(", ")),
        ]));
    }

    if let Some(serial) = &doc.serial_number {
        lines.push(Line::from(vec![
            Span::styled("Serial:  ", label_style),
            Span::styled(
                if serial.len() > 36 {
                    let end = crate::tui::shared::floor_char_boundary(serial, 36);
                    format!("{}...", &serial[..end])
                } else {
                    serial.clone()
                },
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    // ── Group 2: Trust & Compliance (conditional) ──

    let has_completeness = !matches!(
        doc.completeness_declaration,
        CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
    );
    let has_signature = doc.signature.is_some();
    let has_lifecycle = doc.lifecycle_phase.is_some();
    let has_distribution = doc.distribution_classification.is_some();
    let has_citations = doc.citations_count > 0;

    if has_completeness || has_signature || has_lifecycle || has_distribution || has_citations {
        lines.push(Line::styled(
            "── Trust & Compliance ──",
            Style::default().fg(scheme.border),
        ));

        if has_completeness {
            let (badge_label, badge_fg, badge_bg) = match doc.completeness_declaration {
                CompletenessDeclaration::Complete => {
                    (" Complete ", scheme.badge_fg_dark, scheme.success)
                }
                CompletenessDeclaration::Incomplete
                | CompletenessDeclaration::IncompleteFirstPartyOnly
                | CompletenessDeclaration::IncompleteThirdPartyOnly => {
                    (" Incomplete ", scheme.badge_fg_dark, scheme.warning)
                }
                // Unknown/NotSpecified filtered above
                _ => (" Unknown ", scheme.text, scheme.muted),
            };
            lines.push(Line::from(vec![
                Span::styled("Completeness: ", label_style),
                Span::styled(badge_label, Style::default().fg(badge_fg).bg(badge_bg)),
            ]));
        }

        if let Some(sig) = &doc.signature {
            let (badge_label, badge_fg, badge_bg) = if sig.has_value {
                (
                    format!(" Signed ({}) ", sig.algorithm),
                    scheme.badge_fg_dark,
                    scheme.success,
                )
            } else {
                (" Unsigned ".to_string(), scheme.text, scheme.muted)
            };
            lines.push(Line::from(vec![
                Span::styled("Signature:    ", label_style),
                Span::styled(badge_label, Style::default().fg(badge_fg).bg(badge_bg)),
            ]));
        }

        if let Some(phase) = &doc.lifecycle_phase {
            lines.push(Line::from(vec![
                Span::styled("Lifecycle:    ", label_style),
                Span::styled(
                    format!(" {phase} "),
                    Style::default().fg(scheme.badge_fg_dark).bg(scheme.primary),
                ),
            ]));
        }

        if let Some(classification) = &doc.distribution_classification {
            let bg = match classification.to_uppercase().as_str() {
                s if s.contains("RED") => scheme.critical,
                s if s.contains("AMBER") => scheme.warning,
                s if s.contains("GREEN") => scheme.success,
                _ => scheme.primary,
            };
            lines.push(Line::from(vec![
                Span::styled("Distribution: ", label_style),
                Span::styled(
                    format!(" {classification} "),
                    Style::default().fg(scheme.badge_fg_dark).bg(bg),
                ),
            ]));
        }

        if has_citations {
            lines.push(Line::from(vec![
                Span::styled("Citations:    ", label_style),
                Span::styled(
                    format!("{} provenance citations", doc.citations_count),
                    Style::default().fg(scheme.accent),
                ),
            ]));
        }
    }

    // ── Group 3: Security (conditional) ──

    let has_contact = doc.security_contact.is_some();
    let has_disclosure = doc.vulnerability_disclosure_url.is_some();
    let has_eol = doc.support_end_date.is_some();

    if has_contact || has_disclosure || has_eol {
        lines.push(Line::styled(
            "── Security ──",
            Style::default().fg(scheme.border),
        ));

        if let Some(contact) = &doc.security_contact {
            lines.push(Line::from(vec![
                Span::styled("Contact:  ", label_style),
                Span::styled(contact, Style::default().fg(scheme.accent)),
            ]));
        }

        if let Some(url) = &doc.vulnerability_disclosure_url {
            let display_url = if url.len() > 40 {
                let end = crate::tui::shared::floor_char_boundary(url, 40);
                format!("{}...", &url[..end])
            } else {
                url.clone()
            };
            lines.push(Line::from(vec![
                Span::styled("Disclose: ", label_style),
                Span::styled(display_url, Style::default().fg(scheme.text_muted)),
            ]));
        }

        if let Some(eol) = doc.support_end_date {
            let (eol_str, eol_color) = format_support_eol(eol);
            lines.push(Line::from(vec![
                Span::styled("EOL:      ", label_style),
                Span::raw(eol.format("%Y-%m-%d").to_string()),
                Span::styled(format!("  ({eol_str})"), Style::default().fg(eol_color)),
            ]));
        }
    }

    // Export hint
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[e]", Style::default().fg(scheme.accent)),
        Span::styled(
            " Export (JSON, SARIF, Markdown, HTML, CSV)",
            Style::default().fg(scheme.muted),
        ),
    ]));

    let para = Paragraph::new(lines).block(
        Block::default()
            .title(" Document Info ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(para, area);
}

/// Format support end-of-life date with color coding.
fn format_support_eol(eol: chrono::DateTime<chrono::Utc>) -> (String, Color) {
    let scheme = colors();
    let days_until = (eol - chrono::Utc::now()).num_days();

    let label = if days_until < 0 {
        let days_past = -days_until;
        if days_past < 30 {
            format!("expired {days_past}d ago")
        } else if days_past < 365 {
            format!("expired {}mo ago", days_past / 30)
        } else {
            format!("expired {}y ago", days_past / 365)
        }
    } else if days_until == 0 {
        "expires today".to_string()
    } else if days_until < 30 {
        format!("{days_until}d remaining")
    } else if days_until < 365 {
        format!("{}mo remaining", days_until / 30)
    } else {
        format!("{}y remaining", days_until / 365)
    };

    let color = if days_until < 0 {
        scheme.critical
    } else if days_until < 90 {
        scheme.warning
    } else {
        scheme.success
    };

    (label, color)
}

fn render_top_vulnerable(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();

    // Get components sorted by vulnerability count
    let mut vuln_comps: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| !c.vulnerabilities.is_empty())
        .map(|c| (c.name.clone(), c.vulnerabilities.len(), c.max_severity()))
        .collect();

    vuln_comps.sort_by(|a, b| b.1.cmp(&a.1));

    // Dynamic row count based on available area height
    let max_rows = area.height.saturating_sub(3) as usize; // subtract header + borders

    let rows: Vec<Row> = vuln_comps
        .iter()
        .take(max_rows)
        .map(|(name, count, max_sev)| {
            let sev_str = max_sev.as_deref().unwrap_or("Unknown");
            let sev_color = scheme.severity_color(sev_str);
            let display_name = extract_display_name(name);

            Row::new(vec![
                if display_name.len() > 45 {
                    let end = crate::tui::shared::floor_char_boundary(&display_name, 42);
                    format!("{}...", &display_name[..end])
                } else {
                    display_name
                },
                count.to_string(),
                sev_str.to_string(),
            ])
            .style(Style::default().fg(sev_color))
        })
        .collect();

    let header = Row::new(vec!["Component", "CVEs", "Max Severity"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(30),
        Constraint::Length(6),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(
                " Top Vulnerable Components ({}) ",
                vuln_comps.len()
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.high)),
    );

    frame.render_widget(table, area);
}

fn render_top_depended_on(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = colors();

    // Count how many times each component appears as a dependency target
    let mut dependent_counts: std::collections::HashMap<&crate::model::CanonicalId, usize> =
        std::collections::HashMap::new();
    for edge in &app.sbom.edges {
        *dependent_counts.entry(&edge.to).or_insert(0) += 1;
    }

    // Build sorted list of (name, dependents_count, vuln_count)
    let mut top_deps: Vec<_> = dependent_counts
        .iter()
        .filter_map(|(id, &dep_count)| {
            app.sbom
                .components
                .get(*id)
                .map(|c| (c.name.clone(), dep_count, c.vulnerabilities.len()))
        })
        .collect();

    top_deps.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let max_rows = area.height.saturating_sub(3) as usize;

    let rows: Vec<Row> = top_deps
        .iter()
        .take(max_rows)
        .map(|(name, dep_count, vuln_count)| {
            let display_name = extract_display_name(name);

            Row::new(vec![
                if display_name.len() > 35 {
                    let end = crate::tui::shared::floor_char_boundary(&display_name, 32);
                    format!("{}...", &display_name[..end])
                } else {
                    display_name
                },
                dep_count.to_string(),
                vuln_count.to_string(),
            ])
            .style(Style::default().fg(scheme.text))
        })
        .collect();

    let header = Row::new(vec!["Component", "Deps", "Vulns"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(6),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(" Top Depended-On Components ({}) ", top_deps.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.primary)),
    );

    frame.render_widget(table, area);
}

/// Format SBOM age as a human-readable string with appropriate color.
fn format_age(created: chrono::DateTime<chrono::Utc>) -> (String, Color) {
    let scheme = colors();
    let age_days = (chrono::Utc::now() - created).num_days();

    let age_str = if age_days < 0 {
        "in the future".to_string()
    } else if age_days == 0 {
        "today".to_string()
    } else if age_days == 1 {
        "1 day ago".to_string()
    } else if age_days < 30 {
        format!("{age_days} days ago")
    } else if age_days < 60 {
        "1 month ago".to_string()
    } else if age_days < 365 {
        format!("{} months ago", age_days / 30)
    } else if age_days < 730 {
        "1 year ago".to_string()
    } else {
        format!("{} years ago", age_days / 365)
    };

    let color = if age_days < 30 {
        scheme.success
    } else if age_days < 180 {
        scheme.warning
    } else {
        scheme.critical
    };

    (age_str, color)
}

/// Extension trait for Component to get max severity.
trait ComponentExt {
    fn max_severity(&self) -> Option<String>;
}

impl ComponentExt for crate::model::Component {
    fn max_severity(&self) -> Option<String> {
        self.vulnerabilities
            .iter()
            .filter_map(|v| v.severity.as_ref())
            .max_by(|a, b| {
                let order = |s: &crate::model::Severity| match s.to_string().to_lowercase().as_str()
                {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    "low" => 1,
                    _ => 0,
                };
                order(a).cmp(&order(b))
            })
            .map(std::string::ToString::to_string)
    }
}
