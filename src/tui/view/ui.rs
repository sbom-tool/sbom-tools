//! UI rendering for the `ViewApp`.

use super::app::{ViewApp, ViewTab};
use super::views;
use crate::config::TuiPreferences;
use crate::tui::theme::{colors, render_footer_hints, set_theme, FooterHints, Theme};
use crate::tui::widgets::{
    self, check_terminal_size, render_mode_indicator, render_size_warning, MIN_HEIGHT, MIN_WIDTH,
};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
};
use std::io::{self, stdout};

use super::events::{handle_key_event, handle_mouse_event, Event, EventHandler};

/// Run the `ViewApp` TUI.
pub fn run_view_tui(app: &mut ViewApp) -> io::Result<()> {
    // Load theme preference
    let prefs = TuiPreferences::load();
    set_theme(Theme::from_name(&prefs.theme));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Event handler
    let events = EventHandler::default();

    // Main loop
    loop {
        // Render
        terminal.draw(|frame| render(frame, app))?;

        // Handle events
        match events.next()? {
            Event::Key(key) => handle_key_event(app, key),
            Event::Mouse(mouse) => {
                handle_mouse_event(app, mouse);
            }
            Event::Resize(_, _) => {}
            Event::Tick => {
                app.tick += 1;
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Main render function.
fn render(frame: &mut Frame, app: &mut ViewApp) {
    let area = frame.area();

    // Check minimum terminal size
    if check_terminal_size(area.width, area.height).is_err() {
        render_size_warning(frame, area, MIN_WIDTH, MIN_HEIGHT);
        return;
    }

    // Main layout: header, tabs, content, status bar, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(1), // Status bar
            Constraint::Length(1), // Footer
        ])
        .split(area);

    // Render header
    render_header(frame, chunks[0], app);

    // Render tabs
    render_tabs(frame, chunks[1], app);

    // Render content based on active tab
    match app.active_tab {
        ViewTab::Overview => views::render_overview(frame, chunks[2], app),
        ViewTab::Tree => views::render_tree(frame, chunks[2], app),
        ViewTab::Vulnerabilities => views::render_vulnerabilities(frame, chunks[2], app),
        ViewTab::Licenses => views::render_licenses(frame, chunks[2], app),
        ViewTab::Dependencies => views::render_dependencies(frame, chunks[2], app),
        ViewTab::Quality => views::render_quality(frame, chunks[2], app),
        ViewTab::Compliance => views::render_compliance(frame, chunks[2], app),
        ViewTab::Source => views::render_source(frame, chunks[2], app),
    }

    // Render status bar
    render_status_bar(frame, chunks[3], app);

    // Render footer
    render_footer(frame, chunks[4], app);

    // Render overlays
    if app.show_help {
        render_help_overlay(frame, area);
    }

    if app.search_state.active {
        render_search_overlay(frame, area, app);
    }

    if app.show_export {
        render_export_dialog(frame, area);
    }

    if app.show_legend {
        render_legend_overlay(frame, area);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let name = app
        .sbom
        .document
        .name
        .clone()
        .unwrap_or_else(|| "SBOM".to_string());

    let format_info = format!(
        "{} {}",
        app.sbom.document.format, app.sbom.document.format_version
    );

    let header_line = Line::from(vec![
        Span::styled("sbom-tools", Style::default().fg(colors().primary).bold()),
        Span::styled(" ", Style::default()),
        render_mode_indicator("view"),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled(&name, Style::default().fg(colors().text).bold()),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled(format_info, Style::default().fg(colors().text_muted)),
    ]);

    let header = Paragraph::new(header_line);
    frame.render_widget(header, area);
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let tabs_data = [
        (ViewTab::Overview, "1", "Overview"),
        (ViewTab::Tree, "2", "Components"),
        (ViewTab::Vulnerabilities, "3", "Vulns"),
        (ViewTab::Licenses, "4", "Licenses"),
        (ViewTab::Dependencies, "5", "Deps"),
        (ViewTab::Quality, "6", "Quality"),
        (ViewTab::Compliance, "7", "Compliance"),
        (ViewTab::Source, "8", "Source"),
    ];

    let titles: Vec<Line> = tabs_data
        .iter()
        .map(|(kind, key, title)| {
            let is_active = *kind == app.active_tab;
            let key_style = if is_active {
                Style::default().fg(colors().accent).bold()
            } else {
                Style::default().fg(colors().muted)
            };
            let title_style = if is_active {
                Style::default().fg(colors().accent).bold()
            } else {
                Style::default().fg(colors().text_muted)
            };

            Line::from(vec![
                Span::styled(format!("[{key}]"), key_style),
                Span::styled(format!(" {title} "), title_style),
            ])
        })
        .collect();

    let selected_idx = match app.active_tab {
        ViewTab::Overview => 0,
        ViewTab::Tree => 1,
        ViewTab::Vulnerabilities => 2,
        ViewTab::Licenses => 3,
        ViewTab::Dependencies => 4,
        ViewTab::Quality => 5,
        ViewTab::Compliance => 6,
        ViewTab::Source => 7,
    };

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors().border)),
        )
        .highlight_style(Style::default().fg(colors().accent))
        .select(selected_idx)
        .divider(Span::styled(" │ ", Style::default().fg(colors().muted)));

    frame.render_widget(tabs, area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let stats = &app.stats;

    let mut spans = vec![
        Span::styled(" Components: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            widgets::format_count(stats.component_count),
            Style::default().fg(colors().primary).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled("Vulns: ", Style::default().fg(colors().text_muted)),
    ];

    if stats.vuln_count > 0 {
        spans.push(Span::styled(
            widgets::format_count(stats.vuln_count),
            Style::default().fg(colors().error).bold(),
        ));

        if stats.critical_count > 0 {
            spans.push(Span::styled(
                format!(" ({}C", stats.critical_count),
                Style::default().fg(colors().critical).bold(),
            ));
            spans.push(Span::styled(
                format!("/{}H)", stats.high_count),
                Style::default().fg(colors().high),
            ));
        }
    } else {
        spans.push(Span::styled("0", Style::default().fg(colors().success)));
    }

    spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
    spans.push(Span::styled(
        "Licenses: ",
        Style::default().fg(colors().text_muted),
    ));
    spans.push(Span::styled(
        stats.license_count.to_string(),
        Style::default().fg(colors().primary),
    ));

    // Add grouping/filter info for tree tab
    if app.active_tab == ViewTab::Tree {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "Group: ",
            Style::default().fg(colors().text_muted),
        ));
        spans.push(Span::styled(
            format!(" {} ", app.tree_group_by.label()),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(colors().accent)
                .bold(),
        ));
        spans.push(Span::styled(
            " Filter: ",
            Style::default().fg(colors().text_muted),
        ));
        spans.push(Span::styled(
            format!(" {} ", app.tree_filter.label()),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(colors().accent)
                .bold(),
        ));
    }

    // Add breadcrumb trail if there's navigation history
    if app.navigation_ctx.has_history() {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "← ",
            Style::default().fg(colors().accent).bold(),
        ));
        spans.push(Span::styled(
            app.navigation_ctx.breadcrumb_trail(),
            Style::default().fg(colors().text_muted).italic(),
        ));
        spans.push(Span::styled(
            " [b] back",
            Style::default().fg(colors().accent),
        ));
    }

    let status =
        Paragraph::new(Line::from(spans)).style(Style::default().bg(colors().background_alt));

    frame.render_widget(status, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &ViewApp) {
    // Show status message if set, otherwise show tab-specific hints
    if let Some(ref msg) = app.status_message {
        let status_line = Line::from(vec![
            Span::styled("ℹ ", Style::default().fg(colors().accent)),
            Span::styled(msg.as_str(), Style::default().fg(colors().accent).bold()),
        ]);
        let footer = Paragraph::new(status_line)
            .alignment(Alignment::Center)
            .style(Style::default());
        frame.render_widget(footer, area);
        return;
    }

    // Get tab-specific hints
    let tab_name = match app.active_tab {
        ViewTab::Overview => "overview",
        ViewTab::Tree => "tree",
        ViewTab::Vulnerabilities => "vulnerabilities",
        ViewTab::Licenses => "licenses",
        ViewTab::Dependencies => "dependencies",
        ViewTab::Quality => "quality",
        ViewTab::Compliance => "compliance",
        ViewTab::Source => "source",
    };

    let hints = FooterHints::for_view_tab(tab_name);
    let footer_spans = render_footer_hints(&hints);

    let footer = Paragraph::new(Line::from(footer_spans))
        .alignment(Alignment::Center)
        .style(Style::default().fg(colors().text_muted));

    frame.render_widget(footer, area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = widgets::centered_rect(65, 75, area);
    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::styled(
            "━━━ SBOM Viewer Help ━━━",
            Style::default().fg(colors().accent).bold(),
        ),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  1-6            ", Style::default().fg(colors().accent)),
            Span::styled(
                "Jump to tab (Overview/Tree/Vulns/Licenses/Deps/Quality)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Tab            ", Style::default().fg(colors().accent)),
            Span::styled(
                "Next tab / Shift+Tab previous tab",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  p              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Toggle focus between list and detail panel",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ↑/↓ or j/k     ", Style::default().fg(colors().accent)),
            Span::styled("Navigate items up/down", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  Enter/→        ", Style::default().fg(colors().accent)),
            Span::styled("Expand/select item", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  ←/h            ", Style::default().fg(colors().accent)),
            Span::styled("Collapse item", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  PgUp/PgDown    ", Style::default().fg(colors().accent)),
            Span::styled(
                "Page up/down (page)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Tree/Component View",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  g              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Cycle grouping (Ecosystem→License→VulnStatus→Flat)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  f              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Cycle filter (All→HasVulns→Critical)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  [ / ]          ", Style::default().fg(colors().accent)),
            Span::styled(
                "Cycle component detail tabs",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  /              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Search components and vulnerabilities",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  e              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Export report (JSON/Markdown/CSV)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  b / Backspace  ", Style::default().fg(colors().accent)),
            Span::styled(
                "Go back (when navigation history exists)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  l              ", Style::default().fg(colors().accent)),
            Span::styled("Show color legend", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  T              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Toggle theme (dark/light/high-contrast)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ?              ", Style::default().fg(colors().accent)),
            Span::styled("Toggle this help", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  q / Esc        ", Style::default().fg(colors().accent)),
            Span::styled("Quit / Close overlay", Style::default().fg(colors().text)),
        ]),
        Line::from(""),
        Line::styled(
            "Press any key to close",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .title_style(Style::default().fg(colors().accent).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().accent)),
        )
        .style(Style::default().fg(colors().text));

    frame.render_widget(help, popup_area);
}

fn render_search_overlay(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let search = &app.search_state;

    // Search input at bottom
    let input_area = Rect {
        x: area.x + 2,
        y: area.height.saturating_sub(4),
        width: area.width.saturating_sub(4),
        height: 3,
    };

    frame.render_widget(Clear, input_area);

    let cursor_char = "│";

    let search_input = Paragraph::new(Line::from(vec![
        Span::styled("/", Style::default().fg(colors().primary)),
        Span::styled(&search.query, Style::default().fg(colors().text)),
        Span::styled(cursor_char, Style::default().fg(colors().accent)),
    ]))
    .block(
        Block::default()
            .title(format!(
                " Search ({} results) [↑↓] select [Enter] go [Esc] cancel ",
                search.results.len()
            ))
            .title_style(Style::default().fg(colors().primary))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().primary)),
    );

    frame.render_widget(search_input, input_area);

    // Results popup above
    if !search.results.is_empty() {
        let results_height = (search.results.len() + 2).min(15) as u16;
        let results_area = Rect {
            x: area.x + 2,
            y: area.height.saturating_sub(4 + results_height),
            width: area.width.saturating_sub(4),
            height: results_height,
        };

        frame.render_widget(Clear, results_area);

        let mut lines = Vec::new();
        for (i, result) in search.results.iter().take(12).enumerate() {
            let is_selected = i == search.selected;
            let style = if is_selected {
                Style::default().bg(colors().selection).bold()
            } else {
                Style::default()
            };

            let line = match result {
                super::app::SearchResult::Component {
                    name,
                    version,
                    match_field,
                    ..
                } => {
                    let ver = version.as_deref().unwrap_or("");
                    Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default().fg(colors().accent),
                        ),
                        Span::styled("[C] ", style.fg(colors().primary)),
                        Span::styled(name, style.fg(colors().text)),
                        Span::styled(format!("@{ver}"), style.fg(colors().text_muted)),
                        Span::styled(
                            format!(" (matched: {match_field})"),
                            style.fg(colors().text_muted),
                        ),
                    ])
                }
                super::app::SearchResult::Vulnerability {
                    id,
                    component_id: _,  // Not used for display
                    component_name,
                    severity,
                } => {
                    let sev = severity.as_deref().unwrap_or("Unknown");
                    let sev_color = colors().severity_color(sev);
                    Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default().fg(colors().accent),
                        ),
                        Span::styled("[V] ", style.fg(colors().high)),
                        Span::styled(id, style.fg(sev_color).bold()),
                        Span::styled(format!(" [{sev}]"), style.fg(sev_color)),
                        Span::styled(
                            format!(" in {component_name}"),
                            style.fg(colors().text_muted),
                        ),
                    ])
                }
            };
            lines.push(line);
        }

        let results = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().primary)),
        );

        frame.render_widget(results, results_area);
    }
}

fn render_export_dialog(frame: &mut Frame, area: Rect) {
    let popup_area = widgets::centered_rect(55, 45, area);
    frame.render_widget(Clear, popup_area);

    let export_text = vec![
        Line::styled(
            "━━━ Export Report ━━━",
            Style::default().fg(colors().primary).bold(),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled("[j]", Style::default().fg(colors().accent).bold()),
            Span::styled(" JSON      ", Style::default().fg(colors().text)),
            Span::styled(
                "- Full SBOM data for automation",
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
                "- Summary report for documentation",
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

    let export = Paragraph::new(export_text)
        .block(
            Block::default()
                .title(" Export ")
                .title_style(Style::default().fg(colors().primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors().primary)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(export, popup_area);
}

fn render_legend_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = widgets::centered_rect(50, 60, area);
    frame.render_widget(Clear, popup_area);

    // Legend with accessibility patterns (symbols + colors)
    let legend_text = vec![
        Line::styled(
            "━━━ Color & Symbol Legend ━━━",
            Style::default().fg(colors().accent).bold(),
        ),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Vulnerability Severity",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  C ■ ", Style::default().fg(colors().critical)),
            Span::styled("Critical ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 9.0-10.0)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  H ■ ", Style::default().fg(colors().high)),
            Span::styled("High     ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 7.0-8.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  M ■ ", Style::default().fg(colors().medium)),
            Span::styled("Medium   ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 4.0-6.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  L ■ ", Style::default().fg(colors().low)),
            Span::styled("Low      ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 0.1-3.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "License Categories",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  ✓ ■ ", Style::default().fg(colors().permissive)),
            Span::styled("Permissive  ", Style::default().fg(colors().text)),
            Span::styled(
                "(MIT, Apache, BSD)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  © ■ ", Style::default().fg(colors().copyleft)),
            Span::styled("Copyleft    ", Style::default().fg(colors().text)),
            Span::styled("(GPL, AGPL)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  ◐ ■ ", Style::default().fg(colors().weak_copyleft)),
            Span::styled("Weak Copyleft ", Style::default().fg(colors().text)),
            Span::styled("(LGPL, MPL)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  ⊘ ■ ", Style::default().fg(colors().proprietary)),
            Span::styled("Proprietary ", Style::default().fg(colors().text)),
            Span::styled("(Commercial)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(""),
        Line::styled(
            "Press any key to close",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let legend = Paragraph::new(legend_text).block(
        Block::default()
            .title(" Legend ")
            .title_style(Style::default().fg(colors().accent).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().accent)),
    );

    frame.render_widget(legend, popup_area);
}
