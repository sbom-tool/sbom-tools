//! Sparkline and mini-chart widgets for statistics display.

use crate::tui::theme::colors;
use ratatui::{prelude::*, widgets::Widget};

/// A simple horizontal bar chart for displaying counts.
pub struct HorizontalBar {
    label: String,
    value: usize,
    max_value: usize,
    color: Color,
    show_count: bool,
}

impl HorizontalBar {
    pub fn new(label: impl Into<String>, value: usize, max_value: usize) -> Self {
        Self {
            label: label.into(),
            value,
            max_value,
            color: colors().primary,
            show_count: true,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn show_count(mut self, show: bool) -> Self {
        self.show_count = show;
        self
    }
}

impl Widget for HorizontalBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 10 || area.height < 1 {
            return;
        }

        let label_width = 12.min(area.width as usize / 3);
        let count_width = if self.show_count { 8 } else { 0 };
        let bar_width = area.width as usize - label_width - count_width - 2;

        let y = area.y;
        let mut x = area.x;

        // Render label
        let label = if self.label.len() > label_width {
            format!("{}...", &self.label[..label_width.saturating_sub(3)])
        } else {
            format!("{:width$}", self.label, width = label_width)
        };

        for ch in label.chars() {
            if x < area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(colors().text));
                }
                x += 1;
            }
        }

        // Space
        if x < area.x + area.width {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(' ');
            }
            x += 1;
        }

        // Render bar
        let filled = if self.max_value > 0 {
            (self.value * bar_width) / self.max_value
        } else {
            0
        };

        for i in 0..bar_width {
            if x < area.x + area.width {
                let ch = if i < filled { '█' } else { '░' };
                let style = if i < filled {
                    Style::default().fg(self.color)
                } else {
                    Style::default().fg(colors().muted)
                };
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char(ch).set_style(style);
                }
                x += 1;
            }
        }

        // Space
        if x < area.x + area.width {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(' ');
            }
            x += 1;
        }

        // Render count
        if self.show_count {
            let count_str = format!("{:>6}", self.value);
            for ch in count_str.chars() {
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(colors().primary).bold());
                    }
                    x += 1;
                }
            }
        }
    }
}

/// A mini sparkline for showing trends.
pub struct MiniSparkline {
    values: Vec<f64>,
    color: Color,
    baseline: f64,
}

impl MiniSparkline {
    pub fn new(values: Vec<f64>) -> Self {
        Self {
            values,
            color: colors().primary,
            baseline: 0.0,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn baseline(mut self, baseline: f64) -> Self {
        self.baseline = baseline;
        self
    }
}

impl Widget for MiniSparkline {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 2 || area.height < 1 || self.values.is_empty() {
            return;
        }

        let _height = area.height as usize;
        let width = area.width as usize;

        // Find min and max
        let min_val = self.values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = self
            .values
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let range = (max_val - min_val).max(1.0);

        // Sparkline characters for sub-cell resolution
        const CHARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

        // Sample values to fit width
        let step = self.values.len() as f64 / width as f64;

        for x in 0..width {
            let idx = (x as f64 * step) as usize;
            if idx < self.values.len() {
                let val = self.values[idx];
                let normalized = (val - min_val) / range;
                let char_idx =
                    ((normalized * (CHARS.len() - 1) as f64) as usize).min(CHARS.len() - 1);

                let ch = CHARS[char_idx];
                let color = if val > self.baseline {
                    self.color
                } else {
                    colors().muted
                };

                if let Some(cell) =
                    buf.cell_mut((area.x + x as u16, area.y + area.height - 1))
                {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(color));
                }
            }
        }
    }
}

/// A donut/pie-style percentage indicator.
pub struct PercentageRing {
    percentage: f64,
    label: String,
    color: Color,
}

impl PercentageRing {
    pub fn new(percentage: f64, label: impl Into<String>) -> Self {
        Self {
            percentage: percentage.clamp(0.0, 100.0),
            label: label.into(),
            color: colors().primary,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }
}

impl Widget for PercentageRing {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 8 || area.height < 3 {
            return;
        }

        // Simple text-based percentage display
        let pct_str = format!("{:.0}%", self.percentage);
        let label = &self.label;

        // Center the display
        let center_y = area.y + area.height / 2;

        // Draw percentage
        let pct_x = area.x + (area.width.saturating_sub(pct_str.len() as u16)) / 2;
        for (i, ch) in pct_str.chars().enumerate() {
            if pct_x + (i as u16) < area.x + area.width {
                if let Some(cell) = buf.cell_mut((pct_x + i as u16, center_y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(self.color).bold());
                }
            }
        }

        // Draw label below
        if center_y + 1 < area.y + area.height {
            let label_x = area.x + (area.width.saturating_sub(label.len() as u16)) / 2;
            for (i, ch) in label.chars().enumerate() {
                if label_x + (i as u16) < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((label_x + i as u16, center_y + 1)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(colors().text_muted));
                    }
                }
            }
        }

        // Draw a simple bar above
        if center_y > area.y {
            let bar_width = area.width.saturating_sub(4) as usize;
            let filled = (self.percentage / 100.0 * bar_width as f64) as usize;
            let bar_x = area.x + 2;

            for i in 0..bar_width {
                if bar_x + (i as u16) < area.x + area.width - 2 {
                    let ch = if i < filled { '█' } else { '░' };
                    let color = if i < filled {
                        self.color
                    } else {
                        colors().muted
                    };
                    if let Some(cell) = buf.cell_mut((bar_x + i as u16, center_y - 1)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(color));
                    }
                }
            }
        }
    }
}

/// Ecosystem distribution bar showing relative sizes.
pub struct EcosystemBar {
    pub ecosystems: Vec<(String, usize, Color)>,
}

impl EcosystemBar {
    pub fn new(ecosystems: Vec<(String, usize, Color)>) -> Self {
        Self { ecosystems }
    }
}

impl Widget for EcosystemBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 10 || area.height < 1 || self.ecosystems.is_empty() {
            return;
        }

        let total: usize = self.ecosystems.iter().map(|(_, count, _)| count).sum();
        if total == 0 {
            return;
        }

        let width = area.width as usize;
        let mut x = area.x;
        let y = area.y;

        for (i, (_name, count, color)) in self.ecosystems.iter().enumerate() {
            // Calculate width for this segment
            let segment_width = if i == self.ecosystems.len() - 1 {
                // Last segment gets remaining space
                (area.x + area.width).saturating_sub(x) as usize
            } else {
                ((count * width) / total).max(1)
            };

            // Draw segment
            for _j in 0..segment_width {
                if x < area.x + area.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_char('█')
                            .set_style(Style::default().fg(*color));
                    }
                    x += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_horizontal_bar() {
        let bar = HorizontalBar::new("Test", 50, 100).color(Color::Green);
        // Just ensure it doesn't panic
        assert_eq!(bar.value, 50);
    }
}
