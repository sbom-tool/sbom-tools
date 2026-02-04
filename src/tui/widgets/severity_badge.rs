//! Severity badge widget for consistent severity display.

use crate::tui::theme::colors;
use ratatui::{prelude::*, widgets::Widget};

/// A styled badge showing vulnerability severity.
#[derive(Debug, Clone)]
pub struct SeverityBadge {
    severity: String,
    compact: bool,
}

impl SeverityBadge {
    pub fn new(severity: impl Into<String>) -> Self {
        Self {
            severity: severity.into(),
            compact: false,
        }
    }

    pub fn compact(mut self) -> Self {
        self.compact = true;
        self
    }

    /// Get the style for a severity level (uses theme colors).
    pub fn style_for(severity: &str) -> Style {
        let scheme = colors();
        let bg_color = scheme.severity_color(severity);
        let fg_color = scheme.severity_badge_fg(severity);

        let style = Style::default().fg(fg_color).bg(bg_color);
        match severity.to_lowercase().as_str() {
            "critical" | "high" => style.bold(),
            _ => style,
        }
    }

    /// Get just the foreground color for a severity level (uses theme colors).
    pub fn fg_color(severity: &str) -> Color {
        colors().severity_color(severity)
    }

    /// Get a single-char indicator for severity.
    pub fn indicator(severity: &str) -> &'static str {
        match severity.to_lowercase().as_str() {
            "critical" => "C",
            "high" => "H",
            "medium" | "moderate" => "M",
            "low" => "L",
            "info" | "informational" => "I",
            "none" => "-",
            "unknown" => "U",
            _ => "U",
        }
    }

    /// Convert to a Span for inline use.
    pub fn to_span(&self) -> Span<'static> {
        let text = if self.compact {
            format!(" {} ", Self::indicator(&self.severity))
        } else {
            format!(" {} ", self.severity.to_uppercase())
        };

        Span::styled(text, Self::style_for(&self.severity))
    }
}

impl Widget for SeverityBadge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let text = if self.compact {
            format!(" {} ", Self::indicator(&self.severity))
        } else {
            let label = self.severity.to_uppercase();
            if area.width as usize >= label.len() + 2 {
                format!(" {} ", label)
            } else {
                format!(" {} ", Self::indicator(&self.severity))
            }
        };

        let style = Self::style_for(&self.severity);
        let x = area.x;
        let y = area.y;

        for (i, ch) in text.chars().enumerate() {
            if i < area.width as usize {
                if let Some(cell) = buf.cell_mut((x + i as u16, y)) {
                    cell.set_char(ch).set_style(style);
                }
            }
        }
    }
}

/// Render a severity distribution bar.
pub struct SeverityBar {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl SeverityBar {
    pub fn new(critical: usize, high: usize, medium: usize, low: usize) -> Self {
        Self {
            critical,
            high,
            medium,
            low,
        }
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }
}

impl Widget for SeverityBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 4 || area.height < 1 {
            return;
        }

        let total = self.total();
        if total == 0 {
            return;
        }

        let scheme = colors();
        let width = area.width as usize;
        let crit_w = (self.critical * width / total).max(if self.critical > 0 { 1 } else { 0 });
        let high_w = (self.high * width / total).max(if self.high > 0 { 1 } else { 0 });
        let med_w = (self.medium * width / total).max(if self.medium > 0 { 1 } else { 0 });
        let low_w = width.saturating_sub(crit_w + high_w + med_w);

        let mut x = area.x;
        let y = area.y;

        // Critical
        for _ in 0..crit_w {
            if x < area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char('█')
                        .set_style(Style::default().fg(scheme.critical));
                }
                x += 1;
            }
        }

        // High
        for _ in 0..high_w {
            if x < area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char('█')
                        .set_style(Style::default().fg(scheme.high));
                }
                x += 1;
            }
        }

        // Medium
        for _ in 0..med_w {
            if x < area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char('█')
                        .set_style(Style::default().fg(scheme.medium));
                }
                x += 1;
            }
        }

        // Low
        for _ in 0..low_w {
            if x < area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char('█')
                        .set_style(Style::default().fg(scheme.low));
                }
                x += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_indicators() {
        assert_eq!(SeverityBadge::indicator("critical"), "C");
        assert_eq!(SeverityBadge::indicator("HIGH"), "H");
        assert_eq!(SeverityBadge::indicator("medium"), "M");
        assert_eq!(SeverityBadge::indicator("low"), "L");
        assert_eq!(SeverityBadge::indicator("info"), "I");
        assert_eq!(SeverityBadge::indicator("none"), "-");
        assert_eq!(SeverityBadge::indicator("unknown"), "U");
        assert_eq!(SeverityBadge::indicator("other"), "U");
    }

    #[test]
    fn test_severity_colors_use_theme() {
        // Colors should come from the theme, which defaults to dark
        let scheme = colors();
        assert_eq!(SeverityBadge::fg_color("critical"), scheme.critical);
        assert_eq!(SeverityBadge::fg_color("high"), scheme.high);
        assert_eq!(SeverityBadge::fg_color("medium"), scheme.medium);
        assert_eq!(SeverityBadge::fg_color("low"), scheme.low);
    }
}
