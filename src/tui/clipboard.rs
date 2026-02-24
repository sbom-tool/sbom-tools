//! Clipboard helper for copying text to the system clipboard.

use std::io::Write;
use std::process::{Command, Stdio};

/// Copy text to the system clipboard.
///
/// Uses `pbcopy` on macOS and `xclip` on Linux.
/// Returns `true` on success.
pub fn copy_to_clipboard(text: &str) -> bool {
    let result = if cfg!(target_os = "macos") {
        Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(text.as_bytes())?;
                }
                child.wait()
            })
    } else {
        Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(text.as_bytes())?;
                }
                child.wait()
            })
    };

    result.is_ok_and(|status| status.success())
}
