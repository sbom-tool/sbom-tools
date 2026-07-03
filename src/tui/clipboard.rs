//! Clipboard helper for copying text to the system clipboard.

use std::io::Write;
use std::process::{Command, Stdio};

/// Copy text to the system clipboard.
///
/// Tries platform clipboard commands first (`pbcopy` on macOS; `wl-copy`, `xclip`,
/// then `xsel` on Linux), and falls back to an OSC 52 escape sequence so copy also
/// works over SSH and inside tmux where no local clipboard tool is reachable. Returns
/// `true` if a backend accepted the text.
pub fn copy_to_clipboard(text: &str) -> bool {
    try_command_backends(text) || osc52_copy(text)
}

/// Try each platform clipboard command in order; returns `true` on the first success.
fn try_command_backends(text: &str) -> bool {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    };
    candidates
        .iter()
        .any(|(cmd, args)| run_clipboard_command(cmd, args, text))
}

/// Spawn a clipboard command, pipe `text` to its stdin, and report exit success.
fn run_clipboard_command(cmd: &str, args: &[&str], text: &str) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes())?;
                // `stdin` drops here, signalling EOF before we wait.
            }
            child.wait()
        })
        .is_ok_and(|status| status.success())
}

/// Write an OSC 52 clipboard-set sequence to stdout. Best-effort: succeeds if the
/// bytes are written; the terminal honours it if it supports OSC 52.
fn osc52_copy(text: &str) -> bool {
    let seq = osc52_sequence(text, std::env::var_os("TMUX").is_some());
    let mut out = std::io::stdout();
    out.write_all(seq.as_bytes())
        .and_then(|()| out.flush())
        .is_ok()
}

/// Build the OSC 52 set-clipboard escape sequence for `text`, wrapped for tmux
/// passthrough when `in_tmux` is set (DCS-wrapped with inner `ESC`s doubled).
fn osc52_sequence(text: &str, in_tmux: bool) -> String {
    let seq = format!("\x1b]52;c;{}\x07", base64_encode(text.as_bytes()));
    if in_tmux {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq
    }
}

/// Minimal standard-alphabet base64 encoder (avoids pulling in a dependency).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, osc52_sequence};

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn osc52_plain_sequence_is_well_formed() {
        assert_eq!(osc52_sequence("foo", false), "\x1b]52;c;Zm9v\x07");
    }

    #[test]
    fn osc52_tmux_wraps_and_doubles_esc() {
        let s = osc52_sequence("foo", true);
        assert!(s.starts_with("\x1bPtmux;"), "must open a tmux DCS passthrough");
        assert!(s.ends_with("\x1b\\"), "must terminate the DCS with ST");
        // Inner ESC (0x1b) doubled for tmux.
        assert!(s.contains("\x1b\x1b]52;c;Zm9v"));
    }
}
