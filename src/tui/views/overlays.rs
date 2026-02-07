//! Shared overlays for cross-view UI components.
//!
//! Contains rendering functions for view switcher, shortcuts overlay,
//! context bar, and breadcrumbs that can be used across all views.

use crate::tui::app::{
    ComponentDeepDiveState, ShortcutsContext, ShortcutsOverlayState, ViewSwitcherState,
};
use crate::tui::theme::colors;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Render the view switcher overlay
pub fn render_view_switcher(f: &mut Frame, state: &ViewSwitcherState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a centered overlay
    let overlay_width = 50;
    let overlay_height = 10;
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let block = Block::default()
        .title(" Switch View (V) ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Render view options
    let mut lines = vec![
        Line::from(Span::styled(
            "Select a view to switch to:",
            Style::default().fg(scheme.text_muted),
        )),
        Line::from(""),
    ];

    for (i, view) in state.available_views.iter().enumerate() {
        let is_selected = i == state.selected;
        let prefix = if is_selected { "> " } else { "  " };
        let style = if is_selected {
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(scheme.text)
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(
                format!("[{}] ", view.shortcut()),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(view.icon(), style),
            Span::raw(" "),
            Span::styled(view.label(), style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Enter", Style::default().fg(scheme.accent)),
        Span::styled(" select  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" cancel", Style::default().fg(scheme.text_muted)),
    ]));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner_area);
}

/// Render the keyboard shortcuts overlay
pub fn render_shortcuts_overlay(f: &mut Frame, state: &ShortcutsOverlayState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a larger centered overlay
    let overlay_width = 70;
    let overlay_height = 30.min(area.height.saturating_sub(4));
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let title = format!(" Keyboard Shortcuts ({}) ", context_name(state.context));
    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Get shortcuts for the current context
    let shortcuts = get_shortcuts_for_context(state.context);

    let mut lines: Vec<Line> = Vec::new();

    for section in shortcuts {
        // Section header
        lines.push(Line::from(Span::styled(
            section.title,
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        // Shortcuts in this section
        for (key, description) in section.items {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{key:>12}"),
                    Style::default()
                        .fg(scheme.primary)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ", Style::default()),
                Span::styled(description, Style::default().fg(scheme.text)),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Footer
    lines.push(Line::from(vec![
        Span::styled("Press ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" or ", Style::default().fg(scheme.text_muted)),
        Span::styled("K", Style::default().fg(scheme.accent)),
        Span::styled(" to close", Style::default().fg(scheme.text_muted)),
    ]));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner_area);
}

/// Render the component deep dive modal
pub fn render_component_deep_dive(f: &mut Frame, state: &ComponentDeepDiveState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a large centered overlay
    let overlay_width = 80.min(area.width.saturating_sub(4));
    let overlay_height = 35.min(area.height.saturating_sub(4));
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let title = format!(" Component Deep Dive: {} ", state.component_name);
    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Split into tabs and content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(inner_area);

    // Render section tabs
    render_deep_dive_tabs(f, chunks[0], state);

    // Render section content
    render_deep_dive_content(f, chunks[1], state);

    // Render footer
    let footer = Line::from(vec![
        Span::styled("Tab/Arrow", Style::default().fg(scheme.accent)),
        Span::styled(" switch section  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" close", Style::default().fg(scheme.text_muted)),
    ]);
    let footer_para = Paragraph::new(footer).alignment(Alignment::Center);
    f.render_widget(footer_para, chunks[2]);
}

fn render_deep_dive_tabs(f: &mut Frame, area: Rect, state: &ComponentDeepDiveState) {
    let scheme = colors();
    let labels = ComponentDeepDiveState::section_labels();

    let tabs: Vec<Span> = labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let is_selected = i == state.active_section;
            if is_selected {
                Span::styled(
                    format!(" {label} "),
                    Style::default()
                        .bg(scheme.accent)
                        .fg(scheme.badge_fg_dark)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!(" {label} "),
                    Style::default().fg(scheme.text_muted),
                )
            }
        })
        .collect();

    let mut line_spans = vec![Span::raw("  ")];
    for (i, tab) in tabs.into_iter().enumerate() {
        line_spans.push(tab);
        if i < labels.len() - 1 {
            line_spans.push(Span::raw(" | "));
        }
    }

    let line = Line::from(line_spans);
    let para = Paragraph::new(line).alignment(Alignment::Center);
    f.render_widget(para, area);
}

fn render_deep_dive_content(f: &mut Frame, area: Rect, state: &ComponentDeepDiveState) {
    let scheme = colors();
    let data = &state.collected_data;

    let lines: Vec<Line> = match state.active_section {
        0 => {
            // Overview
            vec![
                Line::from(Span::styled(
                    "Component Overview",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(&state.component_name, Style::default().fg(scheme.text)),
                ]),
                Line::from(vec![
                    Span::styled("ID: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        state.component_id.as_deref().unwrap_or("Unknown"),
                        Style::default().fg(scheme.text),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Versions tracked: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.version_history.len().to_string(),
                        Style::default().fg(scheme.primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Targets present: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.target_presence
                            .iter()
                            .filter(|t| t.is_present)
                            .count()
                            .to_string(),
                        Style::default().fg(scheme.primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Vulnerabilities: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.vulnerabilities.len().to_string(),
                        Style::default().fg(if data.vulnerabilities.is_empty() {
                            scheme.added
                        } else {
                            scheme.warning
                        }),
                    ),
                ]),
            ]
        }
        1 => {
            // Versions
            let mut lines = vec![
                Line::from(Span::styled(
                    "Version History",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if data.version_history.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No version history available",
                    Style::default().fg(scheme.text_muted),
                )));
            } else {
                for entry in data.version_history.iter().take(15) {
                    let change_style = match entry.change_type.as_str() {
                        "added" => Style::default().fg(scheme.added),
                        "removed" => Style::default().fg(scheme.removed),
                        "modified" => Style::default().fg(scheme.modified),
                        _ => Style::default().fg(scheme.text_muted),
                    };

                    lines.push(Line::from(vec![
                        Span::styled(&entry.version, Style::default().fg(scheme.text)),
                        Span::raw(" - "),
                        Span::styled(&entry.sbom_label, Style::default().fg(scheme.text_muted)),
                        Span::raw(" ["),
                        Span::styled(&entry.change_type, change_style),
                        Span::raw("]"),
                    ]));
                }
            }
            lines
        }
        2 => {
            // Dependencies
            let mut lines = vec![
                Line::from(Span::styled(
                    "Dependencies",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            lines.push(Line::from(Span::styled(
                "Direct Dependencies:",
                Style::default().fg(scheme.text_muted),
            )));
            if data.dependencies.is_empty() {
                lines.push(Line::from("  (none)"));
            } else {
                for dep in data.dependencies.iter().take(10) {
                    lines.push(Line::from(format!("  - {dep}")));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Dependents (packages that depend on this):",
                Style::default().fg(scheme.text_muted),
            )));
            if data.dependents.is_empty() {
                lines.push(Line::from("  (none)"));
            } else {
                for dep in data.dependents.iter().take(10) {
                    lines.push(Line::from(format!("  - {dep}")));
                }
            }
            lines
        }
        3 => {
            // Vulnerabilities
            let mut lines = vec![
                Line::from(Span::styled(
                    "Associated Vulnerabilities",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if data.vulnerabilities.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No vulnerabilities found",
                    Style::default().fg(scheme.added),
                )));
            } else {
                for vuln in data.vulnerabilities.iter().take(15) {
                    let severity_style = match vuln.severity.to_lowercase().as_str() {
                        "critical" => Style::default()
                            .fg(scheme.removed)
                            .add_modifier(Modifier::BOLD),
                        "high" => Style::default().fg(scheme.removed),
                        "medium" => Style::default().fg(scheme.warning),
                        "low" => Style::default().fg(scheme.modified),
                        _ => Style::default().fg(scheme.text_muted),
                    };

                    lines.push(Line::from(vec![
                        Span::styled(&vuln.vuln_id, Style::default().fg(scheme.primary)),
                        Span::raw(" ["),
                        Span::styled(&vuln.severity, severity_style),
                        Span::raw("] - "),
                        Span::styled(&vuln.status, Style::default().fg(scheme.text_muted)),
                    ]));
                }
            }
            lines
        }
        _ => vec![],
    };

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

// Helper functions

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

const fn context_name(context: ShortcutsContext) -> &'static str {
    match context {
        ShortcutsContext::Global => "Global",
        ShortcutsContext::MultiDiff => "Multi-Diff",
        ShortcutsContext::Timeline => "Timeline",
        ShortcutsContext::Matrix => "Matrix",
        ShortcutsContext::Diff => "Diff",
    }
}

struct ShortcutSection {
    title: &'static str,
    items: Vec<(&'static str, &'static str)>,
}

fn get_shortcuts_for_context(context: ShortcutsContext) -> Vec<ShortcutSection> {
    let mut sections = vec![
        ShortcutSection {
            title: "Global",
            items: vec![
                ("q", "Quit application"),
                ("?", "Toggle help"),
                ("e", "Export dialog"),
                ("l", "Color legend"),
                ("T", "Toggle theme"),
                ("/", "Search"),
                ("K", "Keyboard shortcuts"),
                ("V", "View switcher (multi-views)"),
                ("D", "Component deep dive"),
                ("b/Backspace", "Navigate back"),
            ],
        },
        ShortcutSection {
            title: "Navigation",
            items: vec![
                ("j/k", "Up/Down"),
                ("h/l", "Left/Right"),
                ("g/G", "First/Last"),
                ("PgUp/PgDn", "Page up/down"),
                ("Tab", "Next panel/tab"),
                ("1-8", "Jump to tab"),
            ],
        },
    ];

    match context {
        ShortcutsContext::MultiDiff => {
            sections.push(ShortcutSection {
                title: "Multi-Diff View",
                items: vec![
                    ("p/Tab", "Switch panel"),
                    ("Enter", "View details"),
                    ("f", "Cycle filter preset"),
                    ("s", "Cycle sort field"),
                    ("S", "Toggle sort direction"),
                    ("v", "Variable components drill-down"),
                    ("x", "Toggle cross-target analysis"),
                    ("h", "Toggle heat map mode"),
                ],
            });
        }
        ShortcutsContext::Timeline => {
            sections.push(ShortcutSection {
                title: "Timeline View",
                items: vec![
                    ("p/Tab", "Switch panel"),
                    ("d", "Compare versions"),
                    ("t", "Toggle statistics"),
                    ("g", "Jump to version"),
                    ("+/-", "Zoom chart"),
                    ("h/l", "Scroll chart"),
                    ("f", "Filter components"),
                    ("s", "Sort components"),
                ],
            });
        }
        ShortcutsContext::Matrix => {
            sections.push(ShortcutSection {
                title: "Matrix View",
                items: vec![
                    ("p/Tab", "Switch panel"),
                    ("Enter", "View pair diff"),
                    ("t", "Cycle threshold"),
                    ("z", "Toggle focus mode"),
                    ("H", "Toggle row/col highlight"),
                    ("C", "Show cluster details"),
                    ("x", "Export options"),
                ],
            });
        }
        ShortcutsContext::Diff => {
            sections.push(ShortcutSection {
                title: "Diff View",
                items: vec![
                    ("f", "Filter/toggle options"),
                    ("s", "Sort/cycle options"),
                    ("v", "Multi-select mode"),
                    ("Enter", "View details"),
                    ("n/N", "Navigate to related"),
                ],
            });
        }
        ShortcutsContext::Global => {}
    }

    sections
}

/// State for the threshold tuning overlay.
///
/// Allows users to interactively adjust the match threshold and see
/// a preview of how it affects component matching.
#[derive(Debug, Clone)]
pub struct ThresholdTuningState {
    /// Is the overlay visible
    pub visible: bool,
    /// Current threshold value (0.0 - 1.0)
    pub threshold: f64,
    /// Original threshold (before tuning started)
    pub original_threshold: f64,
    /// Preview: estimated matches at current threshold
    pub estimated_matches: usize,
    /// Preview: total components being compared
    pub total_components: usize,
    /// Step size for adjustment (default 0.05)
    pub step: f64,
}

impl Default for ThresholdTuningState {
    fn default() -> Self {
        Self {
            visible: false,
            threshold: 0.85,
            original_threshold: 0.85,
            estimated_matches: 0,
            total_components: 0,
            step: 0.05,
        }
    }
}

impl ThresholdTuningState {
    /// Create a new threshold tuning state with initial values.
    pub(crate) const fn new(threshold: f64, total_components: usize) -> Self {
        Self {
            visible: true,
            threshold,
            original_threshold: threshold,
            estimated_matches: 0,
            total_components,
            step: 0.05,
        }
    }

    /// Increase threshold (stricter matching).
    pub(crate) fn increase(&mut self) {
        self.threshold = (self.threshold + self.step).min(0.99);
    }

    /// Decrease threshold (more permissive matching).
    pub(crate) fn decrease(&mut self) {
        self.threshold = (self.threshold - self.step).max(0.50);
    }

    /// Fine increase (smaller step).
    pub(crate) fn fine_increase(&mut self) {
        self.threshold = (self.threshold + 0.01).min(0.99);
    }

    /// Fine decrease (smaller step).
    pub(crate) fn fine_decrease(&mut self) {
        self.threshold = (self.threshold - 0.01).max(0.50);
    }

    /// Reset to original value.
    pub(crate) const fn reset(&mut self) {
        self.threshold = self.original_threshold;
    }

    /// Update the estimated matches preview.
    pub(crate) const fn set_estimated_matches(&mut self, matches: usize) {
        self.estimated_matches = matches;
    }

    /// Get the match ratio as a percentage.
    pub(crate) fn match_percentage(&self) -> f64 {
        if self.total_components == 0 {
            0.0
        } else {
            (self.estimated_matches as f64 / self.total_components as f64) * 100.0
        }
    }
}

/// Render the threshold tuning overlay.
///
/// Shows current threshold, estimated matches, and keyboard shortcuts.
pub fn render_threshold_tuning(f: &mut Frame, state: &ThresholdTuningState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a centered overlay
    let overlay_width = 60;
    let overlay_height = 14;
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let block = Block::default()
        .title(" Threshold Tuning ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Render content
    let mut lines = vec![
        Line::from(Span::styled(
            "Adjust matching threshold to control match sensitivity",
            Style::default().fg(scheme.text_muted),
        )),
        Line::from(""),
    ];

    // Current threshold display
    lines.push(Line::from(vec![
        Span::styled("Current threshold: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("{:.0}%", state.threshold * 100.0),
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  (was {:.0}%)", state.original_threshold * 100.0),
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Visual slider
    let slider_width = 40;
    let filled_width = ((state.threshold - 0.5) / 0.49 * slider_width as f64) as usize;
    let empty_width = slider_width - filled_width;

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("50% ", Style::default().fg(scheme.text_muted)),
        Span::styled("▓".repeat(filled_width), Style::default().fg(scheme.accent)),
        Span::styled(
            "░".repeat(empty_width),
            Style::default().fg(scheme.text_muted),
        ),
        Span::styled(" 99%", Style::default().fg(scheme.text_muted)),
    ]));

    // Preview statistics
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Preview: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("~{} components", state.estimated_matches),
            Style::default().fg(scheme.primary),
        ),
        Span::styled(
            format!(" would match ({:.1}%)", state.match_percentage()),
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Threshold presets hints
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Presets: ", Style::default().fg(scheme.text_muted)),
        Span::styled("95%", Style::default().fg(scheme.text)),
        Span::styled("=strict  ", Style::default().fg(scheme.text_muted)),
        Span::styled("85%", Style::default().fg(scheme.text)),
        Span::styled("=balanced  ", Style::default().fg(scheme.text_muted)),
        Span::styled("70%", Style::default().fg(scheme.text)),
        Span::styled("=permissive", Style::default().fg(scheme.text_muted)),
    ]));

    // Controls
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(scheme.accent)),
        Span::styled(" adjust  ", Style::default().fg(scheme.text_muted)),
        Span::styled("+/-", Style::default().fg(scheme.accent)),
        Span::styled(" fine  ", Style::default().fg(scheme.text_muted)),
        Span::styled("r", Style::default().fg(scheme.accent)),
        Span::styled(" reset  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Enter", Style::default().fg(scheme.accent)),
        Span::styled(" apply  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" cancel", Style::default().fg(scheme.text_muted)),
    ]));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner_area);
}
