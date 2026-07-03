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
