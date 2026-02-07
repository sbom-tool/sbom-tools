//! Shared license rendering functions used by both diff-mode and view-mode.
//!
//! Pure rendering functions that take domain values directly, with no
//! dependency on `App` or `ViewApp`.

use crate::tui::license_utils::{LicenseCategory, LicenseInfo, RiskLevel};
use crate::tui::theme::colors;
use ratatui::prelude::*;

/// Map a `LicenseCategory` to a theme color.
pub fn category_color(category: LicenseCategory) -> Color {
    let scheme = colors();
    match category {
        LicenseCategory::Permissive | LicenseCategory::PublicDomain => scheme.success,
        LicenseCategory::WeakCopyleft => scheme.info,
        LicenseCategory::StrongCopyleft => scheme.warning,
        LicenseCategory::NetworkCopyleft | LicenseCategory::Proprietary => scheme.error,
        LicenseCategory::Unknown => scheme.text_muted,
    }
}

/// Map a `RiskLevel` to a theme color.
pub fn risk_level_color(risk: RiskLevel) -> Color {
    let scheme = colors();
    match risk {
        RiskLevel::Low => scheme.success,
        RiskLevel::Medium => scheme.info,
        RiskLevel::High => scheme.warning,
        RiskLevel::Critical => scheme.error,
    }
}

/// Render license metadata lines: title (with dual-license indicator), category badge,
/// risk badge, family, and component count.
pub fn render_license_metadata_lines(
    license: &str,
    category: LicenseCategory,
    risk_level: RiskLevel,
    family: &str,
    component_count: usize,
    is_dual_licensed: bool,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = vec![];

    // Title with optional dual-license indicator
    let title = if is_dual_licensed {
        format!("{license} (Dual/Multi License)")
    } else {
        license.to_string()
    };

    lines.push(Line::from(vec![Span::styled(
        title,
        Style::default().fg(scheme.text).bold(),
    )]));

    lines.push(Line::from(""));

    // Category
    lines.push(Line::from(vec![
        Span::styled("Category: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            category.as_str(),
            Style::default().fg(category_color(category)).bold(),
        ),
    ]));

    // Risk
    lines.push(Line::from(vec![
        Span::styled("Risk: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            risk_level.as_str(),
            Style::default().fg(risk_level_color(risk_level)).bold(),
        ),
    ]));

    // Family
    lines.push(Line::from(vec![
        Span::styled("Family: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            family.to_string(),
            Style::default().fg(scheme.accent),
        ),
    ]));

    // Component count
    lines.push(Line::from(vec![
        Span::styled("Components: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            component_count.to_string(),
            Style::default().fg(scheme.primary),
        ),
    ]));

    lines
}

/// Get license characteristics based on category.
///
/// Returns a list of `(description, allowed)` pairs.
pub fn get_license_characteristics(license: &str) -> Vec<(&'static str, bool)> {
    let info = LicenseInfo::from_spdx(license);

    match info.category {
        LicenseCategory::Permissive | LicenseCategory::PublicDomain => vec![
            ("Commercial use allowed", true),
            ("Modification allowed", true),
            ("Distribution allowed", true),
            ("Patent grant", info.patent_grant),
            ("Copyleft/Share-alike", false),
        ],
        LicenseCategory::StrongCopyleft | LicenseCategory::NetworkCopyleft => vec![
            ("Commercial use allowed", true),
            ("Modification allowed", true),
            ("Distribution allowed", true),
            ("Copyleft/Share-alike", true),
            ("Derivative work must be open", true),
        ],
        LicenseCategory::WeakCopyleft => vec![
            ("Commercial use allowed", true),
            ("Modification allowed", true),
            ("Distribution allowed", true),
            ("Copyleft/Share-alike", true),
            ("Linking allowed", true),
        ],
        LicenseCategory::Proprietary => vec![
            ("Commercial use allowed", false),
            ("Modification allowed", false),
            ("Distribution allowed", false),
            ("Source access", false),
        ],
        LicenseCategory::Unknown => vec![("License terms unknown", false)],
    }
}

/// Render license characteristics as check/cross icon lines.
pub fn render_license_characteristics_lines(license: &str) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = vec![];

    lines.push(Line::styled(
        "Characteristics:",
        Style::default().fg(scheme.primary).bold(),
    ));

    let characteristics = get_license_characteristics(license);
    for (desc, allowed) in characteristics {
        let (icon, color) = if allowed {
            ("✓", scheme.success)
        } else {
            ("✗", scheme.error)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {icon} "), Style::default().fg(color)),
            Span::raw(desc),
        ]));
    }

    // Network copyleft warning
    let info = LicenseInfo::from_spdx(license);
    if info.network_copyleft {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("⚠ ", Style::default().fg(scheme.warning)),
            Span::styled(
                "Network copyleft (AGPL-style)",
                Style::default().fg(scheme.warning),
            ),
        ]));
    }

    lines
}
