//! Centralized theme and color scheme for TUI.
//!
//! This module provides consistent styling across all TUI views and modes.

use ratatui::prelude::*;
use std::sync::RwLock;

/// Color scheme for the TUI application.
/// Provides semantic colors for different UI elements.
#[derive(Debug, Clone, Copy)]
pub struct ColorScheme {
    // Change status colors
    pub added: Color,
    pub removed: Color,
    pub modified: Color,
    pub unchanged: Color,

    // Severity colors
    pub critical: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
    pub info: Color,

    // License category colors
    pub permissive: Color,
    pub copyleft: Color,
    pub weak_copyleft: Color,
    pub proprietary: Color,
    pub unknown_license: Color,

    // UI element colors
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,
    pub muted: Color,
    pub border: Color,
    pub border_focused: Color,
    pub background: Color,
    pub background_alt: Color,
    pub text: Color,
    pub text_muted: Color,
    pub selection: Color,
    pub highlight: Color,

    // Status colors
    pub success: Color,
    pub warning: Color,
    pub error: Color,

    // Badge foreground colors (for text on colored backgrounds)
    pub badge_fg_dark: Color, // For badges on bright backgrounds (yellow, cyan)
    pub badge_fg_light: Color, // For badges on dark backgrounds (magenta, red, blue)

    // Side-by-side view colors
    pub selection_bg: Color,        // Background for selected row
    pub search_highlight_bg: Color, // Background for search matches
    pub error_bg: Color,            // Background for removed/error highlights
    pub success_bg: Color,          // Background for added/success highlights
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self::dark()
    }
}

impl ColorScheme {
    /// Const dark theme for static initialization
    const fn dark_const() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::Red,
            modified: Color::Yellow,
            unchanged: Color::Gray,

            // Severity
            critical: Color::Magenta,
            high: Color::Red,
            medium: Color::Yellow,
            low: Color::Cyan,
            info: Color::Blue,

            // License categories
            permissive: Color::Green,
            copyleft: Color::Yellow,
            weak_copyleft: Color::Cyan,
            proprietary: Color::Red,
            unknown_license: Color::DarkGray,

            // UI elements
            primary: Color::Cyan,
            secondary: Color::Blue,
            accent: Color::Yellow,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_focused: Color::Cyan,
            background: Color::Reset,
            background_alt: Color::Rgb(30, 30, 40),
            text: Color::White,
            text_muted: Color::Gray,
            selection: Color::DarkGray,
            highlight: Color::Yellow,

            // Status
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors
            selection_bg: Color::Rgb(60, 60, 80),
            search_highlight_bg: Color::Rgb(100, 80, 0),
            error_bg: Color::Rgb(80, 30, 30),
            success_bg: Color::Rgb(30, 80, 30),
        }
    }

    /// Dark theme (default)
    pub fn dark() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::Red,
            modified: Color::Yellow,
            unchanged: Color::Gray,

            // Severity
            critical: Color::Magenta,
            high: Color::Red,
            medium: Color::Yellow,
            low: Color::Cyan,
            info: Color::Blue,

            // License categories
            permissive: Color::Green,
            copyleft: Color::Yellow,
            weak_copyleft: Color::Cyan,
            proprietary: Color::Red,
            unknown_license: Color::DarkGray,

            // UI elements
            primary: Color::Cyan,
            secondary: Color::Blue,
            accent: Color::Yellow,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_focused: Color::Cyan,
            background: Color::Reset,
            background_alt: Color::Rgb(30, 30, 40),
            text: Color::White,
            text_muted: Color::Gray,
            selection: Color::DarkGray,
            highlight: Color::Yellow,

            // Status
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors
            selection_bg: Color::Rgb(60, 60, 80),
            search_highlight_bg: Color::Rgb(100, 80, 0),
            error_bg: Color::Rgb(80, 30, 30),
            success_bg: Color::Rgb(30, 80, 30),
        }
    }

    /// Light theme
    pub fn light() -> Self {
        Self {
            // Change status
            added: Color::Rgb(0, 128, 0),
            removed: Color::Rgb(200, 0, 0),
            modified: Color::Rgb(180, 140, 0),
            unchanged: Color::Rgb(100, 100, 100),

            // Severity
            critical: Color::Rgb(128, 0, 128),
            high: Color::Rgb(200, 0, 0),
            medium: Color::Rgb(180, 140, 0),
            low: Color::Rgb(0, 128, 128),
            info: Color::Rgb(0, 0, 200),

            // License categories
            permissive: Color::Rgb(0, 128, 0),
            copyleft: Color::Rgb(180, 140, 0),
            weak_copyleft: Color::Rgb(0, 128, 128),
            proprietary: Color::Rgb(200, 0, 0),
            unknown_license: Color::Rgb(100, 100, 100),

            // UI elements
            primary: Color::Rgb(0, 100, 150),
            secondary: Color::Rgb(0, 0, 150),
            accent: Color::Rgb(180, 140, 0),
            muted: Color::Rgb(150, 150, 150),
            border: Color::Rgb(180, 180, 180),
            border_focused: Color::Rgb(0, 100, 150),
            background: Color::Rgb(255, 255, 255),
            background_alt: Color::Rgb(240, 240, 245),
            text: Color::Rgb(30, 30, 30),
            text_muted: Color::Rgb(100, 100, 100),
            selection: Color::Rgb(200, 220, 240),
            highlight: Color::Rgb(180, 140, 0),

            // Status
            success: Color::Rgb(0, 128, 0),
            warning: Color::Rgb(180, 140, 0),
            error: Color::Rgb(200, 0, 0),

            // Badge foregrounds (reversed for light theme)
            badge_fg_dark: Color::Rgb(30, 30, 30),
            badge_fg_light: Color::White,

            // Side-by-side view colors (lighter for light theme)
            selection_bg: Color::Rgb(200, 220, 240),
            search_highlight_bg: Color::Rgb(255, 230, 150),
            error_bg: Color::Rgb(255, 200, 200),
            success_bg: Color::Rgb(200, 255, 200),
        }
    }

    /// High contrast theme (accessibility)
    pub fn high_contrast() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::LightRed,
            modified: Color::LightYellow,
            unchanged: Color::White,

            // Severity
            critical: Color::LightMagenta,
            high: Color::LightRed,
            medium: Color::LightYellow,
            low: Color::LightCyan,
            info: Color::LightBlue,

            // License categories
            permissive: Color::LightGreen,
            copyleft: Color::LightYellow,
            weak_copyleft: Color::LightCyan,
            proprietary: Color::LightRed,
            unknown_license: Color::Gray,

            // UI elements
            primary: Color::LightCyan,
            secondary: Color::LightBlue,
            accent: Color::LightYellow,
            muted: Color::Gray,
            border: Color::White,
            border_focused: Color::LightCyan,
            background: Color::Black,
            background_alt: Color::Rgb(20, 20, 20),
            text: Color::White,
            text_muted: Color::Gray,
            selection: Color::White,
            highlight: Color::LightYellow,

            // Status
            success: Color::LightGreen,
            warning: Color::LightYellow,
            error: Color::LightRed,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors (high contrast)
            selection_bg: Color::Rgb(50, 50, 80),
            search_highlight_bg: Color::Rgb(120, 100, 0),
            error_bg: Color::Rgb(100, 30, 30),
            success_bg: Color::Rgb(30, 100, 30),
        }
    }

    /// Get color for severity level
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical,
            "high" => self.high,
            "medium" | "moderate" => self.medium,
            "low" => self.low,
            "info" | "informational" | "none" => self.info,
            _ => self.text_muted,
        }
    }

    /// Get color for change status
    pub fn change_color(&self, status: &str) -> Color {
        match status.to_lowercase().as_str() {
            "added" | "new" | "introduced" => self.added,
            "removed" | "deleted" | "resolved" => self.removed,
            "modified" | "changed" | "updated" => self.modified,
            _ => self.unchanged,
        }
    }

    /// Get color for license category
    pub fn license_color(&self, category: &str) -> Color {
        match category.to_lowercase().as_str() {
            "permissive" => self.permissive,
            "copyleft" | "strong copyleft" => self.copyleft,
            "weak copyleft" => self.weak_copyleft,
            "proprietary" | "commercial" => self.proprietary,
            _ => self.unknown_license,
        }
    }

    /// Get appropriate foreground color for severity badges
    /// Returns light fg for dark backgrounds (critical, high, info) and dark fg for bright backgrounds
    pub fn severity_badge_fg(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" | "high" | "info" | "informational" => self.badge_fg_light,
            "medium" | "moderate" | "low" => self.badge_fg_dark,
            _ => self.badge_fg_dark,
        }
    }

    /// Get KEV (Known Exploited Vulnerabilities) badge color
    /// Returns a bright red/orange color to indicate active exploitation
    pub fn kev(&self) -> Color {
        Color::Rgb(255, 100, 50) // Bright orange-red for urgency
    }

    /// Get KEV badge foreground color
    pub fn kev_badge_fg(&self) -> Color {
        self.badge_fg_dark
    }

    /// Get direct dependency badge background color (green - easy to fix)
    pub fn direct_dep(&self) -> Color {
        Color::Rgb(46, 160, 67) // GitHub green
    }

    /// Get transitive dependency badge background color (gray - harder to fix)
    pub fn transitive_dep(&self) -> Color {
        Color::Rgb(110, 118, 129) // Muted gray
    }

    /// Get appropriate foreground color for change status badges
    /// All change colors (green, red, yellow) work best with dark foreground
    pub fn change_badge_fg(&self) -> Color {
        self.badge_fg_dark
    }

    /// Get appropriate foreground color for license category badges
    pub fn license_badge_fg(&self, category: &str) -> Color {
        match category.to_lowercase().as_str() {
            "proprietary" | "commercial" => self.badge_fg_light,
            _ => self.badge_fg_dark,
        }
    }

    /// Chart color palette for visualizations
    pub fn chart_palette(&self) -> [Color; 5] {
        [
            self.primary,
            self.success,
            self.warning,
            self.critical,
            self.secondary,
        ]
    }
}

/// Global theme instance (runtime switchable)
static THEME: RwLock<Theme> = RwLock::new(Theme::dark_const());

/// Theme configuration
#[derive(Debug, Clone)]
pub struct Theme {
    pub colors: ColorScheme,
    pub name: &'static str,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    /// Const dark theme for static initialization
    const fn dark_const() -> Self {
        Self {
            colors: ColorScheme::dark_const(),
            name: "dark",
        }
    }

    pub fn dark() -> Self {
        Self {
            colors: ColorScheme::dark(),
            name: "dark",
        }
    }

    pub fn light() -> Self {
        Self {
            colors: ColorScheme::light(),
            name: "light",
        }
    }

    pub fn high_contrast() -> Self {
        Self {
            colors: ColorScheme::high_contrast(),
            name: "high-contrast",
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "light" => Self::light(),
            "high-contrast" | "highcontrast" | "hc" => Self::high_contrast(),
            _ => Self::dark(),
        }
    }

    /// Get the next theme in the rotation
    pub fn next(&self) -> Self {
        match self.name {
            "dark" => Self::light(),
            "light" => Self::high_contrast(),
            _ => Self::dark(),
        }
    }
}

/// Get the current theme name
pub fn current_theme_name() -> &'static str {
    THEME.read().expect("THEME lock not poisoned").name
}

/// Set the current theme
pub fn set_theme(theme: Theme) {
    *THEME.write().expect("THEME lock not poisoned") = theme;
}

/// Toggle to the next theme in rotation (dark -> light -> high-contrast -> dark)
pub fn toggle_theme() -> &'static str {
    let mut theme = THEME.write().expect("THEME lock not poisoned");
    *theme = theme.next();
    theme.name
}

/// Convenience function to get current colors
pub fn colors() -> ColorScheme {
    THEME.read().expect("THEME lock not poisoned").colors
}

// ============================================================================
// Style Helpers
// ============================================================================

/// Common style presets for consistent UI elements
pub struct Styles;

impl Styles {
    /// Header title style
    pub fn header_title() -> Style {
        Style::default().fg(colors().primary).bold()
    }

    /// Section title style
    pub fn section_title() -> Style {
        Style::default().fg(colors().primary).bold()
    }

    /// Subsection title style
    pub fn subsection_title() -> Style {
        Style::default().fg(colors().primary)
    }

    /// Normal text style
    pub fn text() -> Style {
        Style::default().fg(colors().text)
    }

    /// Muted/secondary text style
    pub fn text_muted() -> Style {
        Style::default().fg(colors().text_muted)
    }

    /// Label text style
    pub fn label() -> Style {
        Style::default().fg(colors().muted)
    }

    /// Value text style (for data values)
    pub fn value() -> Style {
        Style::default().fg(colors().text).bold()
    }

    /// Highlighted/accent style
    pub fn highlight() -> Style {
        Style::default().fg(colors().highlight).bold()
    }

    /// Selection style (for selected items)
    pub fn selected() -> Style {
        Style::default()
            .bg(colors().selection)
            .fg(colors().text)
            .bold()
    }

    /// Border style (unfocused)
    pub fn border() -> Style {
        Style::default().fg(colors().border)
    }

    /// Border style (focused)
    pub fn border_focused() -> Style {
        Style::default().fg(colors().border_focused)
    }

    /// Status bar background style
    pub fn status_bar() -> Style {
        Style::default().bg(colors().background_alt)
    }

    /// Keyboard shortcut style
    pub fn shortcut_key() -> Style {
        Style::default().fg(colors().accent)
    }

    /// Shortcut description style
    pub fn shortcut_desc() -> Style {
        Style::default().fg(colors().text_muted)
    }

    /// Success style
    pub fn success() -> Style {
        Style::default().fg(colors().success)
    }

    /// Warning style
    pub fn warning() -> Style {
        Style::default().fg(colors().warning)
    }

    /// Error style
    pub fn error() -> Style {
        Style::default().fg(colors().error)
    }

    /// Added item style
    pub fn added() -> Style {
        Style::default().fg(colors().added)
    }

    /// Removed item style
    pub fn removed() -> Style {
        Style::default().fg(colors().removed)
    }

    /// Modified item style
    pub fn modified() -> Style {
        Style::default().fg(colors().modified)
    }

    /// Critical severity style
    pub fn critical() -> Style {
        Style::default().fg(colors().critical).bold()
    }

    /// High severity style
    pub fn high() -> Style {
        Style::default().fg(colors().high).bold()
    }

    /// Medium severity style
    pub fn medium() -> Style {
        Style::default().fg(colors().medium)
    }

    /// Low severity style
    pub fn low() -> Style {
        Style::default().fg(colors().low)
    }
}

// ============================================================================
// Badge Rendering Helpers
// ============================================================================

/// Render a status badge with consistent styling
pub fn status_badge(status: &str) -> Span<'static> {
    let scheme = colors();
    let (label, color, symbol) = match status.to_lowercase().as_str() {
        "added" | "new" | "introduced" => ("ADDED", scheme.added, "+"),
        "removed" | "deleted" | "resolved" => ("REMOVED", scheme.removed, "-"),
        "modified" | "changed" | "updated" => ("MODIFIED", scheme.modified, "~"),
        _ => ("UNCHANGED", scheme.unchanged, "="),
    };

    Span::styled(
        format!(" {} {} ", symbol, label),
        Style::default()
            .fg(scheme.change_badge_fg())
            .bg(color)
            .bold(),
    )
}

/// Render a severity badge with consistent styling
pub fn severity_badge(severity: &str) -> Span<'static> {
    let scheme = colors();
    let (label, bg_color, is_unknown) = match severity.to_lowercase().as_str() {
        "critical" => ("CRITICAL", scheme.critical, false),
        "high" => ("HIGH", scheme.high, false),
        "medium" | "moderate" => ("MEDIUM", scheme.medium, false),
        "low" => ("LOW", scheme.low, false),
        "info" | "informational" => ("INFO", scheme.info, false),
        "none" => ("NONE", scheme.muted, false),
        _ => ("UNKNOWN", scheme.muted, true),
    };
    let fg_color = scheme.severity_badge_fg(severity);

    let style = if is_unknown {
        Style::default().fg(fg_color).bg(bg_color).dim()
    } else {
        Style::default().fg(fg_color).bg(bg_color).bold()
    };

    Span::styled(format!(" {} ", label), style)
}

/// Render a compact severity indicator (single char)
pub fn severity_indicator(severity: &str) -> Span<'static> {
    let scheme = colors();
    let (symbol, bg_color, is_unknown) = match severity.to_lowercase().as_str() {
        "critical" => ("C", scheme.critical, false),
        "high" => ("H", scheme.high, false),
        "medium" | "moderate" => ("M", scheme.medium, false),
        "low" => ("L", scheme.low, false),
        "info" | "informational" => ("I", scheme.info, false),
        "none" => ("-", scheme.muted, false),
        _ => ("U", scheme.muted, true),
    };
    let fg_color = scheme.severity_badge_fg(severity);

    let style = if is_unknown {
        Style::default().fg(fg_color).bg(bg_color).dim()
    } else {
        Style::default().fg(fg_color).bg(bg_color).bold()
    };

    Span::styled(format!(" {} ", symbol), style)
}

/// Render a count badge
pub fn count_badge(count: usize, bg_color: Color) -> Span<'static> {
    let scheme = colors();
    Span::styled(
        format!(" {} ", count),
        Style::default()
            .fg(scheme.badge_fg_dark)
            .bg(bg_color)
            .bold(),
    )
}

/// Render a filter/group badge showing current state
pub fn filter_badge(label: &str, value: &str) -> Vec<Span<'static>> {
    let scheme = colors();
    vec![
        Span::styled(
            format!("{}: ", label),
            Style::default().fg(scheme.text_muted),
        ),
        Span::styled(
            format!(" {} ", value),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
    ]
}

// ============================================================================
// Mode Indicator
// ============================================================================

/// Render a mode indicator badge
pub fn mode_badge(mode: &str) -> Span<'static> {
    let scheme = colors();
    let color = match mode.to_lowercase().as_str() {
        "diff" => scheme.modified,
        "view" => scheme.primary,
        "multi-diff" | "multidiff" => scheme.added,
        "timeline" => scheme.secondary,
        "matrix" => scheme.high,
        _ => scheme.muted,
    };

    Span::styled(
        format!(" {} ", mode.to_uppercase()),
        Style::default().fg(scheme.badge_fg_dark).bg(color).bold(),
    )
}

// ============================================================================
// Footer Hints
// ============================================================================

/// Tab-specific footer hints
pub struct FooterHints;

impl FooterHints {
    /// Get hints for a specific tab in diff mode
    pub fn for_diff_tab(tab: &str) -> Vec<(&'static str, &'static str)> {
        let mut hints = Self::global();

        match tab.to_lowercase().as_str() {
            "summary" => {
                // Summary has no tab-specific hints
            }
            "components" => {
                hints.insert(0, ("f", "filter: All→Added→Removed→Modified"));
                hints.insert(1, ("s", "sort: Name→Version→Ecosystem"));
            }
            "dependencies" => {
                hints.insert(0, ("t", "toggle transitive"));
                hints.insert(1, ("h", "toggle highlight"));
                hints.insert(2, ("Enter", "expand/collapse"));
                hints.insert(3, ("c", "go to component"));
            }
            "licenses" => {
                hints.insert(0, ("g", "group: License→Component→Compat"));
            }
            "vulnerabilities" | "vulns" => {
                hints.insert(0, ("f", "filter: All→Intro→Resolved→Critical→High"));
            }
            "sidebyside" | "side-by-side" | "diff" => {
                hints.insert(0, ("←→/p", "switch panel"));
                hints.insert(1, ("↑↓/jk", "scroll focused"));
                hints.insert(2, ("J/K", "scroll both"));
            }
            "quality" => {
                hints.insert(0, ("v", "view: Summary→Metrics→Recs"));
                hints.insert(1, ("↑↓", "select recommendation"));
            }
            "graphchanges" | "graph" => {
                hints.insert(0, ("↑↓/jk", "select change"));
                hints.insert(1, ("PgUp/Dn", "page scroll"));
                hints.insert(2, ("Home/End", "first/last"));
            }
            _ => {}
        }

        hints
    }

    /// Get hints for a specific tab in view mode
    pub fn for_view_tab(tab: &str) -> Vec<(&'static str, &'static str)> {
        let mut hints = Self::global();

        match tab.to_lowercase().as_str() {
            "overview" => {
                // Overview has no tab-specific hints
            }
            "tree" | "components" => {
                hints.insert(0, ("g", "group: Eco→License→Vuln→Flat"));
                hints.insert(1, ("f", "filter: All→HasVuln→Critical"));
                hints.insert(2, ("p", "toggle panel focus"));
                hints.insert(3, ("Enter", "expand/select"));
                hints.insert(4, ("[ ]", "detail tabs"));
            }
            "vulnerabilities" | "vulns" => {
                hints.insert(0, ("f", "filter: All→Critical→High"));
                hints.insert(1, ("g", "group: Severity→Component→Flat"));
                hints.insert(2, ("d", "deduplicate by CVE"));
                hints.insert(3, ("Enter", "jump to component"));
            }
            "licenses" => {
                hints.insert(0, ("g", "group: License→Category"));
            }
            "dependencies" => {
                hints.insert(0, ("Enter/→", "expand"));
                hints.insert(1, ("←", "collapse"));
            }
            "quality" => {
                hints.insert(0, ("v", "view: Summary→Metrics→Recs"));
                hints.insert(1, ("↑↓", "select recommendation"));
            }
            "source" => {
                hints.insert(0, ("v", "tree/raw"));
                hints.insert(1, ("p", "panel focus"));
                hints.insert(2, ("H/L", "collapse/expand all"));
                hints.insert(3, ("Enter", "expand/jump"));
            }
            _ => {}
        }

        hints
    }

    /// Global hints (always shown)
    pub fn global() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Tab", "switch"),
            ("↑↓/jk", "navigate"),
            ("/", "search"),
            ("e", "export"),
            ("l", "legend"),
            ("T", "theme"),
            ("?", "help"),
            ("q", "quit"),
        ]
    }
}

/// Render footer hints as spans
pub fn render_footer_hints(hints: &[(&str, &str)]) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(format!("[{}]", key), Styles::shortcut_key()));
        spans.push(Span::styled(desc.to_string(), Styles::shortcut_desc()));
    }

    spans
}
