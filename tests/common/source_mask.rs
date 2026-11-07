//! The source masker of the source lints (tests/pinned_clock_tests.rs,
//! tests/evidence_layer_lint.rs): Rust source with its comments and the
//! contents of its literals blanked, so a lint matches code only.

/// `src` with comments and the contents of string and char literals blanked
/// (newlines kept), so text inside them never counts as code.
pub fn mask(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = c.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for ch in &mut out[from..to.min(c.len())] {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
    };
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        let end = match c[i] {
            '/' if next == Some('/') => (i..c.len()).find(|&j| c[j] == '\n').unwrap_or(c.len()),
            '/' if next == Some('*') => {
                let (mut depth, mut j) = (1, i + 2);
                while j < c.len() && depth > 0 {
                    match (c[j], c.get(j + 1)) {
                        ('/', Some('*')) => (depth, j) = (depth + 1, j + 2),
                        ('*', Some('/')) => (depth, j) = (depth - 1, j + 2),
                        _ => j += 1,
                    }
                }
                j
            }
            '"' => {
                let mut j = i + 1;
                while j < c.len() && c[j] != '"' {
                    j += if c[j] == '\\' { 2 } else { 1 };
                }
                j + 1
            }
            // A char literal; anything else after a quote is a lifetime.
            '\'' if next == Some('\\') => (i + 3..c.len())
                .find(|&j| c[j] == '\'')
                .map_or(c.len(), |j| j + 1),
            '\'' if c.get(i + 2) == Some(&'\'') => i + 3,
            ch if ch.is_alphabetic() || ch == '_' => {
                let start = i;
                while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                // Raw strings: r"…", r#"…"#, br"…".
                let hashes = c[i..].iter().take_while(|&&h| h == '#').count();
                let prefix: String = c[start..i].iter().collect();
                if matches!(prefix.as_str(), "r" | "br") && c.get(i + hashes) == Some(&'"') {
                    let closes =
                        |j: usize| c[j] == '"' && (1..=hashes).all(|h| c.get(j + h) == Some(&'#'));
                    let end = (i + hashes + 1..c.len())
                        .find(|&j| closes(j))
                        .map_or(c.len(), |j| j + 1 + hashes);
                    blank(&mut out, start, end);
                    i = end;
                }
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        };
        blank(&mut out, i, end);
        i = end;
    }
    out.into_iter().collect()
}
