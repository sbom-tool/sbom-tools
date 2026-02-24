//! Main UI rendering with enhanced features.

use super::app::{
    App, AppMode, ChangeType, DiffSearchResult, DiffSearchState, TabKind, VulnChangeType,
};
use super::events::{Event, EventHandler, handle_key_event, handle_mouse_event};
use super::theme::{FooterHints, Theme, colors, render_footer_hints, set_theme};
use super::views;
use super::widgets::{
    MIN_HEIGHT, MIN_WIDTH, check_terminal_size, render_mode_indicator, render_size_warning,
};
use crate::config::TuiPreferences;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
};
use std::io::{self, stdout};

/// Run the TUI application
pub fn run_tui(app: &mut App) -> io::Result<()> {
    // Load saved theme preference
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
            Event::Mouse(mouse) => handle_mouse_event(app, mouse),
            Event::Resize(_, _) => {}
            Event::Tick => {
                // Update tick for animations
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

/// Main render function
fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Check minimum terminal size
    if check_terminal_size(area.width, area.height).is_err() {
        render_size_warning(frame, area, MIN_WIDTH, MIN_HEIGHT);
        return;
    }

    // For new multi-comparison modes, use dedicated full-screen views
    match app.mode {
        AppMode::MultiDiff => {
            if let Some(ref result) = app.data.multi_diff_result {
                views::render_multi_dashboard(frame, area, result, &app.tabs.multi_diff);
            }
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        AppMode::Timeline => {
            if let Some(ref result) = app.data.timeline_result {
                views::render_timeline(frame, area, result, &app.tabs.timeline);
            }
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        AppMode::Matrix => {
            if let Some(ref result) = app.data.matrix_result {
                views::render_matrix(frame, area, result, &app.tabs.matrix);
            }
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        // Diff and View modes use the tabbed layout below
        AppMode::Diff | AppMode::View => {}
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

    // Render tabs with shortcuts
    render_tabs(frame, chunks[1], app);

    // Render content based on active tab
    match app.active_tab {
        TabKind::Summary => views::render_summary(frame, chunks[2], app),
        TabKind::Components => views::render_components(frame, chunks[2], app),
        TabKind::Dependencies => views::render_dependencies(frame, chunks[2], app),
        TabKind::Licenses => views::render_licenses(frame, chunks[2], app),
        TabKind::Vulnerabilities => views::render_vulnerabilities(frame, chunks[2], app),
        TabKind::Quality => views::render_quality(frame, chunks[2], app),
        TabKind::Compliance => views::render_diff_compliance(frame, chunks[2], app),
        TabKind::SideBySide => views::render_sidebyside(frame, chunks[2], app),
        TabKind::GraphChanges => views::render_graph_changes(frame, chunks[2], app),
        TabKind::Source => views::render_source(frame, chunks[2], app),
    }

    // Render status bar
    render_status_bar(frame, chunks[3], app);

    // Render footer
    render_footer(frame, chunks[4], app);

    // Render overlays
    if app.overlays.show_help {
        render_help_overlay(frame, area);
    }

    if app.overlays.search.active {
        render_search_overlay(frame, area, &app.overlays.search);
    }

    if app.overlays.show_export {
        let scope = super::export::tab_export_scope(app.active_tab);
        super::shared::export::render_export_dialog(frame, area, scope, centered_rect);
    }

    if app.overlays.show_legend {
        render_legend_overlay(frame, area);
    }

    // Render threshold tuning overlay
    if app.overlays.threshold_tuning.visible {
        super::views::render_threshold_tuning(frame, &app.overlays.threshold_tuning);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let (mode_name, subtitle) = match app.mode {
        AppMode::Diff => {
            let old_name = app
                .data
                .old_sbom
                .as_ref()
                .and_then(|s| s.document.name.clone())
                .unwrap_or_else(|| "SBOM A".to_string());
            let new_name = app
                .data
                .new_sbom
                .as_ref()
                .and_then(|s| s.document.name.clone())
                .unwrap_or_else(|| "SBOM B".to_string());
            ("diff", format!("{old_name} ⟷ {new_name}"))
        }
        AppMode::View => {
            let name = app
                .data
                .sbom
                .as_ref()
                .and_then(|s| s.document.name.clone())
                .unwrap_or_else(|| "SBOM".to_string());
            ("view", name)
        }
        AppMode::MultiDiff => ("multi-diff", "Multi-Diff Comparison".to_string()),
        AppMode::Timeline => ("timeline", "Timeline Analysis".to_string()),
        AppMode::Matrix => ("matrix", "Matrix Comparison".to_string()),
    };

    let header_line = Line::from(vec![
        Span::styled("sbom-tools", Style::default().fg(colors().primary).bold()),
        Span::styled(" ", Style::default()),
        render_mode_indicator(mode_name),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled(subtitle, Style::default().fg(colors().text)),
    ]);

    let header = Paragraph::new(header_line);
    frame.render_widget(header, area);
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    // Build tabs dynamically based on mode
    let mut tabs_data: Vec<(TabKind, &str, &str)> = vec![
        (TabKind::Summary, "1", "Summary"),
        (TabKind::Components, "2", "Components"),
        (TabKind::Dependencies, "3", "Dependencies"),
        (TabKind::Licenses, "4", "Licenses"),
        (TabKind::Vulnerabilities, "5", "Vulns"),
        (TabKind::Quality, "6", "Quality"),
    ];

    // Add compliance and side-by-side tabs only in diff mode
    if app.mode == AppMode::Diff {
        tabs_data.push((TabKind::Compliance, "7", "Compliance"));
        tabs_data.push((TabKind::SideBySide, "8", "Diff"));
    }

    // Add graph changes tab if graph diff data is available
    let has_graph_changes = app
        .data
        .diff_result
        .as_ref()
        .is_some_and(|r| !r.graph_changes.is_empty());
    if has_graph_changes {
        tabs_data.push((TabKind::GraphChanges, "9", "Graph"));
    }

    // Source tab always available in diff mode
    // Use [9] when it's the 9th tab (no graph changes), [0] when it's the 10th
    if app.mode == AppMode::Diff {
        let source_key = if has_graph_changes { "0" } else { "9" };
        tabs_data.push((TabKind::Source, source_key, "Source"));
    }

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
        TabKind::Summary => 0,
        TabKind::Components => 1,
        TabKind::Dependencies => 2,
        TabKind::Licenses => 3,
        TabKind::Vulnerabilities => 4,
        TabKind::Quality => 5,
        TabKind::Compliance => 6,
        TabKind::SideBySide => 7,
        TabKind::GraphChanges => {
            if has_graph_changes {
                8
            } else {
                0
            }
        }
        TabKind::Source => {
            // Source is after GraphChanges (if present) or SideBySide
            if has_graph_changes { 9 } else { 8 }
        }
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

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let (comp_count, vuln_count, score) = match app.mode {
        AppMode::Diff => {
            let result = app.data.diff_result.as_ref();
            let comp = result.map_or(0, |r| r.summary.total_changes);
            let vuln = result.map_or(0, |r| r.summary.vulnerabilities_introduced);
            let score = result.map_or(0.0, |r| r.semantic_score);
            (comp, vuln, Some(score))
        }
        AppMode::View => {
            let sbom = app.data.sbom.as_ref();
            let comp = sbom.map_or(0, crate::model::NormalizedSbom::component_count);
            let vuln = sbom.map_or(0, |s| s.all_vulnerabilities().len());
            (comp, vuln, None)
        }
        // Multi-comparison modes use their own status bars
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => (0, 0, None),
    };

    let critical_count = match app.mode {
        AppMode::Diff => app.data.diff_result.as_ref().map_or(0, |r| {
            r.vulnerabilities
                .introduced
                .iter()
                .filter(|v| v.severity == "Critical")
                .count()
        }),
        AppMode::View => app
            .data
            .sbom
            .as_ref()
            .map_or(0, |s| s.vulnerability_counts().critical),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
    };

    let mut spans = vec![
        Span::styled(" Components: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            comp_count.to_string(),
            Style::default().fg(colors().primary).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled("Vulns: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            vuln_count.to_string(),
            if vuln_count > 0 {
                Style::default().fg(colors().error).bold()
            } else {
                Style::default().fg(colors().success)
            },
        ),
    ];

    if critical_count > 0 {
        spans.push(Span::styled(
            format!(" ({critical_count} Critical)"),
            Style::default().fg(colors().critical).bold(),
        ));
    }

    if let Some(s) = score {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "Score: ",
            Style::default().fg(colors().text_muted),
        ));

        // Color-code the score based on value
        let score_color = if s < 25.0 {
            colors().success
        } else if s < 50.0 {
            colors().warning
        } else {
            colors().error
        };
        spans.push(Span::styled(
            format!("{s:.1}"),
            Style::default().fg(score_color).bold(),
        ));
    }

    // Add breadcrumb trail if there's navigation history
    if app.has_navigation_history() {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "← ",
            Style::default().fg(colors().accent).bold(),
        ));
        spans.push(Span::styled(
            app.breadcrumb_trail(),
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

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
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

    // Get tab-specific hints based on mode
    let tab_name = match app.active_tab {
        TabKind::Summary => "summary",
        TabKind::Components => "components",
        TabKind::Dependencies => "dependencies",
        TabKind::Licenses => "licenses",
        TabKind::Vulnerabilities => "vulnerabilities",
        TabKind::Quality => "quality",
        TabKind::Compliance => "compliance",
        TabKind::SideBySide => "sidebyside",
        TabKind::GraphChanges => "graph",
        TabKind::Source => "source",
    };

    let hints = FooterHints::for_diff_tab(tab_name);
    let mut footer_spans = render_footer_hints(&hints);

    // Append copy preview: [y] copy <value>
    if let Some(yank_text) = super::events::get_yank_text(app) {
        let truncated = if yank_text.len() > 30 {
            format!("{}...", &yank_text[..27])
        } else {
            yank_text
        };
        footer_spans.push(Span::styled(" ", Style::default()));
        footer_spans.push(Span::styled("[y]", Style::default().fg(colors().accent)));
        footer_spans.push(Span::styled(
            format!(" copy {truncated}"),
            Style::default().fg(colors().text_muted),
        ));
    }

    let footer = Paragraph::new(Line::from(footer_spans))
        .alignment(Alignment::Center)
        .style(Style::default().fg(colors().text_muted));

    frame.render_widget(footer, area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = centered_rect(65, 80, area);
    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::styled(
            "━━━ Keyboard Shortcuts ━━━",
            Style::default().fg(colors().accent).bold(),
        ),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Tab/Shift+Tab  ", Style::default().fg(colors().accent)),
            Span::styled("Switch between views", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  1-8            ", Style::default().fg(colors().accent)),
            Span::styled("Jump to specific tab", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  ↑/↓ or j/k     ", Style::default().fg(colors().accent)),
            Span::styled("Navigate items up/down", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  PgUp/PgDown    ", Style::default().fg(colors().accent)),
            Span::styled("Page up/down (page)", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  Home/End       ", Style::default().fg(colors().accent)),
            Span::styled(
                "Jump to start/end of list",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  p / ←→         ", Style::default().fg(colors().accent)),
            Span::styled(
                "Toggle panel focus (Side-by-side)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  J/K            ", Style::default().fg(colors().accent)),
            Span::styled(
                "Scroll both panels (Side-by-side)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  Enter          ", Style::default().fg(colors().accent)),
            Span::styled(
                "View details / Expand node / Go to component",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  b / Backspace  ", Style::default().fg(colors().accent)),
            Span::styled(
                "Navigate back (follow breadcrumb trail)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  c              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Go to component (from Dependencies)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  /              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Search components & vulnerabilities",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  f              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Cycle filter (All→Added→Removed→Modified)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  s              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Cycle sort (Name→Version→Ecosystem)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  g              ", Style::default().fg(colors().accent)),
            Span::styled("Cycle grouping mode", Style::default().fg(colors().text)),
        ]),
        Line::from(vec![
            Span::styled("  t              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Toggle transitive dependencies",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  e              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Export report (JSON/SARIF/Markdown/HTML)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  l              ", Style::default().fg(colors().accent)),
            Span::styled("Show color legend", Style::default().fg(colors().text)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  T              ", Style::default().fg(colors().accent)),
            Span::styled(
                "Toggle theme (dark/light/high-contrast)",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  y / Ctrl+C     ", Style::default().fg(colors().accent)),
            Span::styled(
                "Copy selected item to clipboard",
                Style::default().fg(colors().text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Shift+drag     ", Style::default().fg(colors().accent)),
            Span::styled("Select text with mouse", Style::default().fg(colors().text)),
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

fn render_search_overlay(frame: &mut Frame, area: Rect, search_state: &DiffSearchState) {
    // Calculate popup size based on results
    let result_count = search_state.results.len().min(10);
    let popup_height = (result_count as u16 + 5).max(5);

    let popup_area = Rect {
        x: area.x + 2,
        y: area.height.saturating_sub(popup_height + 1),
        width: area.width.saturating_sub(4),
        height: popup_height,
    };

    frame.render_widget(Clear, popup_area);

    let mut lines = Vec::new();

    // Search input line
    let cursor_char = "│";
    lines.push(Line::from(vec![
        Span::styled("/", Style::default().fg(colors().primary)),
        Span::styled(&search_state.query, Style::default().fg(colors().text)),
        Span::styled(cursor_char, Style::default().fg(colors().accent)),
        if !search_state.results.is_empty() {
            Span::styled(
                format!("  ({} results)", search_state.results.len()),
                Style::default().fg(colors().text_muted),
            )
        } else if search_state.query.len() >= 2 {
            Span::styled("  (no results)", Style::default().fg(colors().text_muted))
        } else {
            Span::styled(
                "  (type to search)",
                Style::default().fg(colors().text_muted),
            )
        },
    ]));

    // Results
    if !search_state.results.is_empty() {
        lines.push(Line::from(""));

        for (i, result) in search_state.results.iter().take(10).enumerate() {
            let is_selected = i == search_state.selected;
            let prefix = if is_selected { "▶ " } else { "  " };

            let line = match result {
                DiffSearchResult::Component {
                    name,
                    version,
                    change_type,
                    ..
                } => {
                    let change_color = match change_type {
                        ChangeType::Added => colors().added,
                        ChangeType::Removed => colors().removed,
                        ChangeType::Modified => colors().modified,
                    };
                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            name,
                            if is_selected {
                                Style::default().fg(colors().text).bold()
                            } else {
                                Style::default().fg(colors().text)
                            },
                        ),
                        version.as_ref().map_or_else(
                            || Span::raw(""),
                            |v| {
                                Span::styled(
                                    format!(" @ {v}"),
                                    Style::default().fg(colors().text_muted),
                                )
                            },
                        ),
                    ])
                }
                DiffSearchResult::Vulnerability {
                    id,
                    component_name,
                    severity,
                    change_type,
                } => {
                    let change_color = match change_type {
                        VulnChangeType::Introduced => colors().removed,
                        VulnChangeType::Resolved => colors().added,
                    };
                    let sev_color = severity
                        .as_ref()
                        .map_or_else(|| colors().text_muted, |s| colors().severity_color(s));

                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            id,
                            if is_selected {
                                Style::default().fg(sev_color).bold()
                            } else {
                                Style::default().fg(sev_color)
                            },
                        ),
                        Span::styled(
                            format!(" in {component_name}"),
                            Style::default().fg(colors().text_muted),
                        ),
                    ])
                }
                DiffSearchResult::License {
                    license,
                    component_name,
                    change_type,
                } => {
                    let change_color = match change_type {
                        ChangeType::Added => colors().added,
                        ChangeType::Removed => colors().removed,
                        ChangeType::Modified => colors().modified,
                    };
                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            license,
                            if is_selected {
                                Style::default().fg(colors().text).bold()
                            } else {
                                Style::default().fg(colors().text)
                            },
                        ),
                        Span::styled(
                            format!(" ({component_name})"),
                            Style::default().fg(colors().text_muted),
                        ),
                    ])
                }
            };
            lines.push(line);
        }
    }

    // Help line
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[↑↓]", Style::default().fg(colors().accent)),
        Span::raw(" navigate "),
        Span::styled("[Enter]", Style::default().fg(colors().accent)),
        Span::raw(" select "),
        Span::styled("[Esc]", Style::default().fg(colors().accent)),
        Span::raw(" close"),
    ]));

    let search = Paragraph::new(lines).block(
        Block::default()
            .title(" Search ")
            .title_style(Style::default().fg(colors().primary).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().primary)),
    );

    frame.render_widget(search, popup_area);
}

fn render_legend_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 60, area);
    frame.render_widget(Clear, popup_area);

    // Legend with accessibility patterns (symbols + colors)
    let legend_text = vec![
        Line::styled(
            "━━━ Color & Symbol Legend ━━━",
            Style::default().fg(colors().accent).bold(),
        ),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Change Status",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  + ■ ", Style::default().fg(colors().added)),
            Span::styled("Added    ", Style::default().fg(colors().text)),
            Span::styled("(new component)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  - ■ ", Style::default().fg(colors().removed)),
            Span::styled("Removed  ", Style::default().fg(colors().text)),
            Span::styled(
                "(component deleted)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ~ ■ ", Style::default().fg(colors().modified)),
            Span::styled("Modified ", Style::default().fg(colors().text)),
            Span::styled(
                "(version/deps changed)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
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

/// Helper function to create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Render cross-view overlays (view switcher, shortcuts, component deep dive)
fn render_cross_view_overlays(frame: &mut Frame, app: &App) {
    // Render view switcher overlay
    views::render_view_switcher(frame, &app.overlays.view_switcher);

    // Render shortcuts overlay
    views::render_shortcuts_overlay(frame, &app.overlays.shortcuts);

    // Render component deep dive modal
    views::render_component_deep_dive(frame, &app.overlays.component_deep_dive);
}
