//! Change type badge widget for consistent change status display.

use crate::tui::theme::colors;
use ratatui::{prelude::*, widgets::Widget};

/// Types of changes that can occur in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    Unchanged,
}

impl ChangeType {
    /// Parse a change type from a label. Returns Unchanged for unrecognized values.
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "added" | "new" | "introduced" => Self::Added,
            "removed" | "deleted" | "resolved" => Self::Removed,
            "modified" | "changed" | "updated" => Self::Modified,
            _ => Self::Unchanged,
        }
    }

    /// Get the symbol for this change type.
    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Added => "+",
            Self::Removed => "-",
            Self::Modified => "~",
            Self::Unchanged => "=",
        }
    }

    /// Get the label for this change type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Added => "ADDED",
            Self::Removed => "REMOVED",
            Self::Modified => "MODIFIED",
            Self::Unchanged => "UNCHANGED",
        }
    }

    /// Get the background color for this change type (uses theme colors).
    pub fn color(&self) -> Color {
        let scheme = colors();
        match self {
            Self::Added => scheme.added,
            Self::Removed => scheme.removed,
            Self::Modified => scheme.modified,
            Self::Unchanged => scheme.unchanged,
        }
    }

    /// Get the foreground color for badges (uses theme colors).
    pub fn badge_fg(&self) -> Color {
        colors().change_badge_fg()
    }
}

/// A styled badge showing change status.
#[derive(Debug, Clone)]
pub struct ChangeTypeBadge {
    change_type: ChangeType,
    compact: bool,
}

impl ChangeTypeBadge {
    /// Create a new change type badge.
    pub fn new(change_type: ChangeType) -> Self {
        Self {
            change_type,
            compact: false,
        }
    }

    /// Create a badge from a label (e.g., "added", "removed", etc.).
    pub fn from_label(s: &str) -> Self {
        Self::new(ChangeType::from_label(s))
    }

    /// Use compact mode (symbol only).
    pub fn compact(mut self) -> Self {
        self.compact = true;
        self
    }

    /// Get the style for this badge.
    pub fn style(&self) -> Style {
        Style::default()
            .fg(self.change_type.badge_fg())
            .bg(self.change_type.color())
            .bold()
    }

    /// Get just the foreground color for text display (not badge).
    pub fn fg_color(&self) -> Color {
        self.change_type.color()
    }

    /// Convert to a Span for inline use.
    pub fn to_span(&self) -> Span<'static> {
        let text = if self.compact {
            format!(" {} ", self.change_type.symbol())
        } else {
            format!(
                " {} {} ",
                self.change_type.symbol(),
                self.change_type.label()
            )
        };

        Span::styled(text, self.style())
    }

    /// Get the change type.
    pub fn change_type(&self) -> ChangeType {
        self.change_type
    }
}

impl Widget for ChangeTypeBadge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let text = if self.compact {
            format!(" {} ", self.change_type.symbol())
        } else {
            let full = format!(
                " {} {} ",
                self.change_type.symbol(),
                self.change_type.label()
            );
            if area.width as usize >= full.len() {
                full
            } else {
                format!(" {} ", self.change_type.symbol())
            }
        };

        let style = self.style();
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

/// A compact change indicator (just the symbol with color, no background).
#[derive(Debug, Clone)]
pub struct ChangeIndicator {
    change_type: ChangeType,
}

impl ChangeIndicator {
    pub fn new(change_type: ChangeType) -> Self {
        Self { change_type }
    }

    pub fn from_label(s: &str) -> Self {
        Self::new(ChangeType::from_label(s))
    }

    /// Convert to a styled span (colored symbol without background).
    pub fn to_span(&self) -> Span<'static> {
        Span::styled(
            self.change_type.symbol().to_string(),
            Style::default().fg(self.change_type.color()).bold(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_from_label() {
        assert_eq!(ChangeType::from_label("added"), ChangeType::Added);
        assert_eq!(ChangeType::from_label("NEW"), ChangeType::Added);
        assert_eq!(ChangeType::from_label("removed"), ChangeType::Removed);
        assert_eq!(ChangeType::from_label("modified"), ChangeType::Modified);
        assert_eq!(ChangeType::from_label("unknown"), ChangeType::Unchanged);
    }

    #[test]
    fn test_change_type_symbols() {
        assert_eq!(ChangeType::Added.symbol(), "+");
        assert_eq!(ChangeType::Removed.symbol(), "-");
        assert_eq!(ChangeType::Modified.symbol(), "~");
        assert_eq!(ChangeType::Unchanged.symbol(), "=");
    }

    #[test]
    fn test_change_type_colors_use_theme() {
        let scheme = colors();
        assert_eq!(ChangeType::Added.color(), scheme.added);
        assert_eq!(ChangeType::Removed.color(), scheme.removed);
        assert_eq!(ChangeType::Modified.color(), scheme.modified);
    }
}
