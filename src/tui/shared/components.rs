//! Shared component rendering functions used by both diff-mode and view-mode.
//!
//! Pure rendering functions that take domain values directly, with no
//! dependency on `App` or `ViewApp`.

use crate::model::{DatasetInfo, MlModelInfo};
use crate::tui::security::LicenseRisk;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::collections::{HashMap, HashSet, VecDeque};

/// Compute blast radius via BFS on the reverse dependency graph.
/// Returns `(direct_dependents, transitive_count)`.
pub fn compute_blast_radius(
    component_name: &str,
    reverse_graph: &HashMap<String, Vec<String>>,
) -> (usize, usize) {
    let direct_deps = reverse_graph
        .get(component_name)
        .map_or(0, std::vec::Vec::len);

    let mut transitive_count = 0usize;
    if direct_deps > 0 {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(deps) = reverse_graph.get(component_name) {
            for d in deps {
                queue.push_back(d.clone());
            }
        }
        while let Some(node) = queue.pop_front() {
            if visited.insert(node.clone()) {
                transitive_count += 1;
                if let Some(deps) = reverse_graph.get(&node) {
                    for d in deps {
                        if !visited.contains(d) {
                            queue.push_back(d.clone());
                        }
                    }
                }
            }
        }
    }

    (direct_deps, transitive_count)
}

/// Determine risk level and associated color from vulnerability count and blast radius.
pub fn determine_risk_level(vuln_count: usize, transitive_count: usize) -> (&'static str, Color) {
    if vuln_count > 0 && transitive_count > 10 {
        ("Critical", colors().critical)
    } else if vuln_count > 0 || transitive_count > 20 {
        ("High", colors().high)
    } else if transitive_count > 5 {
        ("Medium", colors().medium)
    } else {
        ("Low", colors().low)
    }
}

/// Render the security analysis section: header, risk badge, blast radius, license risk.
pub fn render_security_analysis_lines(
    vuln_count: usize,
    direct_deps: usize,
    transitive_count: usize,
    license_text: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    // Section header
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("━━━ ", Style::default().fg(colors().border)),
        Span::styled(
            "Security Analysis",
            Style::default().fg(colors().accent).bold(),
        ),
        Span::styled(" ━━━", Style::default().fg(colors().border)),
    ]));

    // Risk level badge
    let (risk_level, risk_color) = determine_risk_level(vuln_count, transitive_count);
    lines.push(Line::from(vec![
        Span::styled("  Risk Level: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!(" {risk_level} "),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(risk_color)
                .bold(),
        ),
    ]));

    // Blast radius
    if direct_deps == 0 && transitive_count == 0 {
        lines.push(Line::from(vec![
            Span::styled("  Blast Radius: ", Style::default().fg(colors().text_muted)),
            Span::styled(
                "None (no dependents)",
                Style::default().fg(colors().text_muted),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("  Blast Radius: ", Style::default().fg(colors().text_muted)),
            Span::styled(
                format!("{direct_deps} direct"),
                Style::default().fg(if direct_deps > 5 {
                    colors().warning
                } else {
                    colors().text
                }),
            ),
            Span::styled(", ", Style::default().fg(colors().text_muted)),
            Span::styled(
                format!("{transitive_count} transitive"),
                Style::default().fg(if transitive_count > 10 {
                    colors().warning
                } else {
                    colors().text
                }),
            ),
        ]));
    }

    // Impact (only when there are transitive dependents)
    if transitive_count > 0 {
        let impact = if transitive_count > 50 {
            "Critical - affects many components"
        } else if transitive_count > 20 {
            "Significant impact"
        } else if transitive_count > 5 {
            "Moderate impact"
        } else {
            "Limited impact"
        };
        lines.push(Line::from(vec![
            Span::styled("  Impact: ", Style::default().fg(colors().text_muted)),
            Span::styled(impact, Style::default().fg(colors().text).italic()),
        ]));
    }

    // License risk
    let license_risk = LicenseRisk::from_license(license_text);
    let license_risk_color = match license_risk {
        LicenseRisk::High => colors().high,
        LicenseRisk::Medium => colors().medium,
        LicenseRisk::Low => colors().permissive,
        LicenseRisk::None => colors().text_muted,
    };
    lines.push(Line::from(vec![
        Span::styled("  License Risk: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            license_risk.as_str(),
            Style::default().fg(license_risk_color),
        ),
    ]));

    lines
}

/// Render the quick actions hint line for component details.
/// When `has_vulns` is false, the `[o] CVE` action is omitted.
pub fn render_quick_actions_hint(has_vulns: bool) -> Vec<Line<'static>> {
    let mut spans = vec![
        Span::styled("[y]", Style::default().fg(colors().accent)),
        Span::styled(" copy  ", Style::default().fg(colors().text_muted)),
        Span::styled("[F]", Style::default().fg(colors().accent)),
        Span::styled(" flag  ", Style::default().fg(colors().text_muted)),
        Span::styled("[n]", Style::default().fg(colors().accent)),
        Span::styled(" note", Style::default().fg(colors().text_muted)),
    ];
    if has_vulns {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled("[o]", Style::default().fg(colors().accent)));
        spans.push(Span::styled(
            " CVE",
            Style::default().fg(colors().text_muted),
        ));
    }
    vec![Line::from(""), Line::from(spans)]
}

/// Render vulnerability entries with severity badge + ID + optional description.
/// Each entry is `(severity, id, description)`.
pub fn render_vulnerability_list_lines(
    vulns: &[(&str, &str, Option<&str>)],
    max_display: usize,
    total_count: usize,
    area_width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    for (severity, id, description) in vulns.iter().take(max_display) {
        let sev_color = colors().severity_color(severity);
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                format!(" {} ", severity.chars().next().unwrap_or('?')),
                Style::default()
                    .fg(colors().badge_fg_dark)
                    .bg(sev_color)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(id.to_string(), Style::default().fg(sev_color).bold()),
        ]));

        if let Some(desc) = description {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "    {}",
                    crate::tui::widgets::truncate_str(desc, area_width as usize - 6)
                ),
                Style::default().fg(colors().text_muted).italic(),
            )]));
        }
    }

    if total_count > max_display {
        lines.push(Line::styled(
            format!("    ... and {} more", total_count - max_display),
            Style::default().fg(colors().text_muted),
        ));
    }

    lines
}

/// Render flagged indicator and optional analyst note.
/// `suffix` is appended after the badge (e.g. `" for follow-up"` in view mode).
pub fn render_flagged_lines(
    is_flagged: bool,
    note: Option<&str>,
    area_width: u16,
    suffix: &str,
) -> Vec<Line<'static>> {
    if !is_flagged {
        return vec![];
    }

    let scheme = colors();
    let mut lines = vec![];

    let mut badge_spans = vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            " ! FLAGGED ",
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.warning)
                .bold(),
        ),
    ];
    if !suffix.is_empty() {
        badge_spans.push(Span::styled(
            suffix.to_string(),
            Style::default().fg(scheme.warning),
        ));
    }
    lines.push(Line::from(badge_spans));

    if let Some(note) = note {
        lines.push(Line::from(vec![
            Span::styled("  Note: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                crate::tui::widgets::truncate_str(note, area_width as usize - 10),
                Style::default().fg(scheme.text).italic(),
            ),
        ]));
    }

    lines
}

/// Render the ML model / dataset metadata section for a component detail panel.
///
/// Surfaces the raw `MlModelInfo` / `DatasetInfo` captured by the parsers
/// (architecture, datasets, energy, governance, …) — distinct from the
/// AI-readiness *scoring* panels. Returns an empty `Vec` when the component has
/// neither ML model nor dataset metadata, so callers need no surrounding guard.
#[must_use]
pub fn render_ml_dataset_lines(
    ml: Option<&MlModelInfo>,
    dataset: Option<&DatasetInfo>,
    area_width: u16,
) -> Vec<Line<'static>> {
    if ml.is_none() && dataset.is_none() {
        return vec![];
    }
    let scheme = colors();
    let width = area_width as usize;

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("━━━ ", Style::default().fg(scheme.border)),
            Span::styled("ML / Dataset", Style::default().fg(scheme.accent).bold()),
            Span::styled(" ━━━", Style::default().fg(scheme.border)),
        ]),
    ];

    if let Some(ml) = ml {
        // Architecture: "family / name", or whichever single value is present.
        let arch = match (
            ml.architecture_family.as_deref(),
            ml.architecture_name.as_deref(),
        ) {
            (Some(f), Some(n)) => Some(format!("{f} / {n}")),
            (Some(v), None) | (None, Some(v)) => Some(v.to_string()),
            (None, None) => None,
        };
        if let Some(arch) = arch {
            lines.push(Line::from(vec![
                Span::styled("  Architecture: ", Style::default().fg(scheme.text_muted)),
                Span::styled(arch, Style::default().fg(scheme.accent)),
            ]));
        }
        if let Some(approach) = &ml.approach {
            lines.push(Line::from(vec![
                Span::styled("  Approach: ", Style::default().fg(scheme.text_muted)),
                Span::styled(approach.clone(), Style::default().fg(scheme.text)),
            ]));
        }
        if let Some(task) = &ml.task {
            lines.push(Line::from(vec![
                Span::styled("  Task: ", Style::default().fg(scheme.text_muted)),
                Span::styled(task.clone(), Style::default().fg(scheme.text)),
            ]));
        }
        if let Some(energy) = ml.energy_kwh_training {
            lines.push(Line::from(vec![
                Span::styled(
                    "  Training Energy: ",
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(format!("{energy:.2} kWh"), Style::default().fg(scheme.text)),
            ]));
        }
        if let Some(limitations) = &ml.limitations {
            lines.push(Line::from(vec![
                Span::styled("  Limitations: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    crate::tui::widgets::truncate_str(limitations, width.saturating_sub(15)),
                    Style::default().fg(scheme.text).italic(),
                ),
            ]));
        }
        if let Some(url) = &ml.model_card_url {
            lines.push(Line::from(vec![
                Span::styled("  Model Card: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    crate::tui::widgets::truncate_str(url, width.saturating_sub(14)),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
        if !ml.training_datasets.is_empty() {
            lines.push(Line::from(vec![Span::styled(
                format!("  Datasets ({}):", ml.training_datasets.len()),
                Style::default().fg(scheme.text_muted),
            )]));
            const MAX_DATASETS: usize = 5;
            for ds in ml.training_datasets.iter().take(MAX_DATASETS) {
                let label = ds
                    .name
                    .as_deref()
                    .or(ds.reference.as_deref())
                    .or(ds.purl.as_deref())
                    .unwrap_or("(unnamed)");
                lines.push(Line::from(vec![
                    Span::styled("    • ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        crate::tui::widgets::truncate_str(label, width.saturating_sub(8)),
                        Style::default().fg(scheme.text),
                    ),
                ]));
            }
            if ml.training_datasets.len() > MAX_DATASETS {
                lines.push(Line::styled(
                    format!(
                        "    ... and {} more",
                        ml.training_datasets.len() - MAX_DATASETS
                    ),
                    Style::default().fg(scheme.text_muted),
                ));
            }
        }
    }

    if let Some(dataset) = dataset {
        if let Some(dataset_type) = &dataset.dataset_type {
            lines.push(Line::from(vec![
                Span::styled("  Dataset Type: ", Style::default().fg(scheme.text_muted)),
                Span::styled(dataset_type.clone(), Style::default().fg(scheme.text)),
            ]));
        }
        if !dataset.sensitivity_classifications.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Sensitivity: ", Style::default().fg(scheme.text_muted)),
                // Sensitive/PII data is high-attention — flag it with the critical color.
                Span::styled(
                    dataset.sensitivity_classifications.join(", "),
                    Style::default().fg(scheme.critical),
                ),
            ]));
        }
        if !dataset.governance_owners.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Governance: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    crate::tui::widgets::truncate_str(
                        &dataset.governance_owners.join(", "),
                        width.saturating_sub(14),
                    ),
                    Style::default().fg(scheme.text),
                ),
            ]));
        }
    }

    lines
}

/// Render standard component info lines for detail panels.
///
/// Produces a consistent set of sections for any component:
/// Identity, Depth, Dependency counts, Licenses, Hashes, Supplier, Vulnerabilities, PURL.
///
/// Used by both the Components and Dependencies detail panels to ensure
/// consistent presentation.
#[must_use]
pub fn render_component_info_lines(
    component: &crate::model::Component,
    depth: Option<usize>,
    deps_out: usize,
    deps_in: usize,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = vec![];

    // --- Identity ---
    lines.push(Line::from(vec![
        Span::styled("Name: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            component.name.clone(),
            Style::default().fg(scheme.text).bold(),
        ),
    ]));
    if let Some(ref ver) = component.version {
        lines.push(Line::from(vec![
            Span::styled("Version: ", Style::default().fg(scheme.text_muted)),
            Span::styled(ver.clone(), Style::default().fg(scheme.text)),
        ]));
    }
    if let Some(ref eco) = component.ecosystem {
        lines.push(Line::from(vec![
            Span::styled("Ecosystem: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("{eco:?}"), Style::default().fg(scheme.accent)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Type: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{:?}", component.component_type),
            Style::default().fg(scheme.text),
        ),
    ]));

    // --- Depth ---
    if let Some(d) = depth {
        let label = match d {
            0 => "Root",
            1 => "Direct",
            _ => "Transitive",
        };
        let depth_color = match d {
            0 => scheme.primary,
            1 => scheme.accent,
            _ => scheme.text_muted,
        };
        lines.push(Line::from(vec![
            Span::styled("Depth: ", Style::default().fg(scheme.text_muted)),
            Span::styled(format!("D{d}"), Style::default().fg(depth_color).bold()),
            Span::styled(
                format!(" ({label})"),
                Style::default().fg(scheme.text_muted),
            ),
        ]));
    }

    // --- Dependency counts ---
    if deps_out > 0 || deps_in > 0 {
        lines.push(Line::from(vec![
            Span::styled("Dependencies: ", Style::default().fg(scheme.text_muted)),
            Span::styled(deps_out.to_string(), Style::default().fg(scheme.primary)),
            Span::styled("  Dependents: ", Style::default().fg(scheme.text_muted)),
            Span::styled(deps_in.to_string(), Style::default().fg(scheme.primary)),
        ]));
    }

    // --- Licenses ---
    if !component.licenses.declared.is_empty() {
        let license_strs: Vec<String> = component
            .licenses
            .declared
            .iter()
            .take(3)
            .map(|l| l.expression.clone())
            .collect();
        lines.push(Line::from(vec![
            Span::styled("Licenses: ", Style::default().fg(scheme.text_muted)),
            Span::styled(license_strs.join(", "), Style::default().fg(scheme.text)),
        ]));
        if component.licenses.declared.len() > 3 {
            lines.push(Line::styled(
                format!("    ... and {} more", component.licenses.declared.len() - 3),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }

    // --- Hashes ---
    if !component.hashes.is_empty() {
        for hash in component.hashes.iter().take(2) {
            let truncated_value = if hash.value.len() > 16 {
                format!("{}...", &hash.value[..16])
            } else {
                hash.value.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", hash.algorithm),
                    Style::default().fg(scheme.text_muted),
                ),
                Span::styled(truncated_value, Style::default().fg(scheme.text)),
            ]));
        }
        if component.hashes.len() > 2 {
            lines.push(Line::styled(
                format!("    ... and {} more", component.hashes.len() - 2),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }

    // --- Supplier ---
    if let Some(ref supplier) = component.supplier {
        lines.push(Line::from(vec![
            Span::styled("Supplier: ", Style::default().fg(scheme.text_muted)),
            Span::styled(supplier.name.clone(), Style::default().fg(scheme.text)),
        ]));
    }

    // --- Vulnerabilities ---
    if !component.vulnerabilities.is_empty() {
        let count = component.vulnerabilities.len();
        let mut vuln_spans = vec![
            Span::styled("Vulns: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                count.to_string(),
                Style::default().fg(scheme.critical).bold(),
            ),
        ];
        let ids: Vec<String> = component
            .vulnerabilities
            .iter()
            .take(3)
            .map(|v| v.id.clone())
            .collect();
        if !ids.is_empty() {
            vuln_spans.push(Span::styled(
                format!(" ({})", ids.join(", ")),
                Style::default().fg(scheme.text_muted),
            ));
        }
        lines.push(Line::from(vuln_spans));
    }

    // --- PURL ---
    if let Some(ref purl) = component.identifiers.purl {
        lines.push(Line::from(vec![
            Span::styled("PURL: ", Style::default().fg(scheme.text_muted)),
            Span::styled(purl.clone(), Style::default().fg(scheme.accent)),
        ]));
    }

    lines
}

/// Render a detail panel: wraps `lines` in a bordered Paragraph with focus-aware styling.
pub fn render_detail_block(
    frame: &mut Frame,
    area: Rect,
    lines: Vec<Line<'_>>,
    title: &str,
    focused: bool,
) {
    let scheme = colors();
    let border_color = if focused {
        scheme.accent
    } else {
        scheme.border
    };
    let title_style = if focused {
        Style::default().fg(scheme.accent).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(detail, area);
}

/// Render an empty detail panel with icon, message, and keyboard hints.
pub fn render_empty_detail_panel(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    icon: &str,
    message: &str,
    hints: &[(&str, &str)],
    focused: bool,
) {
    let scheme = colors();
    let border_color = if focused {
        scheme.accent
    } else {
        scheme.border
    };
    let title_style = if focused {
        Style::default().fg(scheme.accent).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let mut text = vec![
        Line::from(""),
        Line::styled(icon.to_string(), Style::default().fg(scheme.text_muted)),
        Line::from(""),
        Line::styled(message.to_string(), Style::default().fg(scheme.text)),
        Line::from(""),
    ];

    if !hints.is_empty() {
        let mut hint_spans = Vec::new();
        for (key, desc) in hints {
            hint_spans.push(Span::styled(
                key.to_string(),
                Style::default().fg(scheme.accent),
            ));
            hint_spans.push(Span::styled(
                desc.to_string(),
                Style::default().fg(scheme.text_muted),
            ));
        }
        text.push(Line::from(hint_spans));
    }

    let detail = Paragraph::new(text)
        .block(
            Block::default()
                .title(title)
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(detail, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DatasetRef;

    fn plain_text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn ml_dataset_lines_empty_when_no_metadata() {
        assert!(render_ml_dataset_lines(None, None, 80).is_empty());
    }

    #[test]
    fn ml_dataset_lines_render_model_fields() {
        let ml = MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            architecture_name: Some("bert".to_string()),
            task: Some("nlp".to_string()),
            energy_kwh_training: Some(1500.0),
            model_card_url: Some("https://example.test/card".to_string()),
            training_datasets: vec![DatasetRef {
                reference: None,
                name: Some("wikipedia".to_string()),
                purl: None,
            }],
            ..MlModelInfo::default()
        };
        let text = plain_text(&render_ml_dataset_lines(Some(&ml), None, 80));
        assert!(text.contains("ML / Dataset"));
        assert!(text.contains("Architecture: transformer / bert"));
        assert!(text.contains("Task: nlp"));
        assert!(text.contains("1500.00 kWh"));
        assert!(text.contains("Datasets (1):"));
        assert!(text.contains("wikipedia"));
    }

    #[test]
    fn ml_dataset_lines_render_dataset_sensitivity() {
        let dataset = DatasetInfo {
            dataset_type: Some("dataset".to_string()),
            sensitivity_classifications: vec!["pii".to_string(), "phi".to_string()],
            governance_owners: vec!["Data Team".to_string()],
            ..DatasetInfo::default()
        };
        let text = plain_text(&render_ml_dataset_lines(None, Some(&dataset), 80));
        assert!(text.contains("Dataset Type: dataset"));
        assert!(text.contains("Sensitivity: pii, phi"));
        assert!(text.contains("Governance: Data Team"));
    }

    #[test]
    fn ml_dataset_lines_dataset_ref_precedence_and_overflow() {
        let datasets: Vec<DatasetRef> = (0..7)
            .map(|i| DatasetRef {
                reference: Some(format!("ref-{i}")),
                name: None,
                purl: None,
            })
            .collect();
        let ml = MlModelInfo {
            training_datasets: datasets,
            ..MlModelInfo::default()
        };
        let text = plain_text(&render_ml_dataset_lines(Some(&ml), None, 80));
        // reference is used when name is absent; only 5 shown + overflow line.
        assert!(text.contains("Datasets (7):"));
        assert!(text.contains("ref-0"));
        assert!(text.contains("... and 2 more"));
    }
}
