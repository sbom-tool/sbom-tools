//! Shared rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! These pure rendering functions take domain types directly (`&QualityReport`,
//! `&Violation`) with no app-specific dependencies, enabling both TUIs to
//! delegate to common code.

pub mod compliance;
pub mod components;
pub mod export;
pub mod licenses;
pub mod quality;
pub mod source;
pub mod vulnerabilities;

use crossterm::{
    event::DisableMouseCapture,
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};

/// Restore the terminal to its normal state (cooked mode, main screen,
/// mouse capture off).
///
/// Errors are ignored so this is safe to call from a panic hook and
/// idempotent with the normal TUI exit path.
pub(crate) fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

/// Install a panic hook that restores the terminal before delegating to the
/// previously installed hook, so a panic inside the TUI doesn't leave the
/// shell in raw mode with the backtrace swallowed by the alternate screen.
///
/// Installs at most once per process; subsequent calls are no-ops.
pub(crate) fn install_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
    });
}

/// Find the largest byte index <= `index` that is on a UTF-8 char boundary.
///
/// Equivalent to `str::floor_char_boundary` (stabilized in Rust 1.94,
/// but our MSRV is 1.88).
pub(crate) const fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let bytes = s.as_bytes();
        let mut i = index;
        // Walk backwards to find a leading byte (0xxxxxxx or 11xxxxxx).
        while i > 0 && bytes[i] & 0b1100_0000 == 0b1000_0000 {
            i -= 1;
        }
        i
    }
}

/// RAII guard that switches the terminal into raw + alternate-screen mode on
/// construction and restores it on drop.
///
/// The run loop returns `io::Error` via `?` from `terminal.draw` / `events.next`,
/// which previously skipped the manual teardown and left the shell in raw mode (the
/// panic hook only covers unwinds). Because `Drop` runs on normal return, on the `?`
/// early-return, and during panic unwinding, this restores the terminal on every exit
/// path — and de-duplicates the enter/leave sequence shared by `run_tui` and
/// `run_view_tui`.
pub(crate) struct TerminalGuard;

impl TerminalGuard {
    /// Enter raw + alternate-screen mode with mouse capture.
    pub(crate) fn enter() -> std::io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableMouseCapture
        )?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore; ignore errors (nothing useful to do on failure, and
        // Drop must not panic).
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
    }
}

/// Map a click column to a tab index for a `ratatui` `Tabs` bar.
///
/// `Tabs` renders each tab as `left_pad(1) + title + right_pad(1)` starting at column
/// `left`, joining consecutive tabs with a `divider_width`-column divider (the default
/// padding is a single space on each side — see `ratatui`'s `Tabs`). `labels` are the
/// tab-title strings exactly as rendered, with brackets and inner spaces baked in
/// (e.g. `"[1] Summary "`). Returns the index of the tab whose rendered span contains
/// `click_x`, or `None` for a click on a divider, before the first tab, or past the
/// last — so callers derive hit regions from the real tab set instead of guessing a
/// fixed width.
#[must_use]
pub fn tab_bar_hit(
    labels: &[String],
    left: u16,
    divider_width: u16,
    click_x: u16,
) -> Option<usize> {
    use unicode_width::UnicodeWidthStr;

    if click_x < left {
        return None;
    }
    let last = labels.len().saturating_sub(1);
    let mut cursor = left;
    for (i, label) in labels.iter().enumerate() {
        // 1-column left pad + title + 1-column right pad.
        let span = (UnicodeWidthStr::width(label.as_str()) as u16).saturating_add(2);
        if click_x >= cursor && click_x < cursor.saturating_add(span) {
            return Some(i);
        }
        cursor = cursor.saturating_add(span);
        if i != last {
            cursor = cursor.saturating_add(divider_width);
        }
    }
    None
}

#[cfg(test)]
mod tab_bar_hit_tests {
    use super::tab_bar_hit;

    #[test]
    fn maps_clicks_to_tabs_and_rejects_dividers() {
        // "[1] Summary " => width 12 => span 14 ([0,14)); divider [14,17);
        // "[2] Components " => width 15 => span 17 ([17,34)).
        let labels = vec!["[1] Summary ".to_string(), "[2] Components ".to_string()];
        assert_eq!(tab_bar_hit(&labels, 0, 3, 0), Some(0));
        assert_eq!(tab_bar_hit(&labels, 0, 3, 13), Some(0));
        assert_eq!(tab_bar_hit(&labels, 0, 3, 14), None); // divider
        assert_eq!(tab_bar_hit(&labels, 0, 3, 16), None);
        assert_eq!(tab_bar_hit(&labels, 0, 3, 17), Some(1));
        assert_eq!(tab_bar_hit(&labels, 0, 3, 33), Some(1));
        assert_eq!(tab_bar_hit(&labels, 0, 3, 34), None); // past end
        assert_eq!(tab_bar_hit(&labels, 0, 3, 200), None);
    }

    #[test]
    fn respects_left_offset() {
        let labels = vec!["[1] A ".to_string()]; // width 6 => span 8
        assert_eq!(tab_bar_hit(&labels, 5, 3, 4), None); // before left
        assert_eq!(tab_bar_hit(&labels, 5, 3, 5), Some(0));
        assert_eq!(tab_bar_hit(&labels, 5, 3, 12), Some(0));
        assert_eq!(tab_bar_hit(&labels, 5, 3, 13), None);
    }

    #[test]
    fn counts_double_width_glyphs() {
        // "[1] 字 " => width 7 (字 is 2 cells) => span 9 ([0,9)); divider [9,12);
        // "[2] B " => span 8 ([12,20)).
        let labels = vec!["[1] 字 ".to_string(), "[2] B ".to_string()];
        assert_eq!(tab_bar_hit(&labels, 0, 3, 8), Some(0));
        assert_eq!(tab_bar_hit(&labels, 0, 3, 9), None); // divider
        assert_eq!(tab_bar_hit(&labels, 0, 3, 12), Some(1));
    }
}
