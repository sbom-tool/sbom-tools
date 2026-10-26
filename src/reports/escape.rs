//! Escaping utilities for safe report generation.
//!
//! This module provides escaping functions for HTML and Markdown output
//! to prevent injection attacks and format corruption when embedding
//! untrusted data (SBOM component names, versions, etc.) in reports.
//!
//! # Security Considerations
//!
//! SBOM data comes from external sources and may contain:
//! - HTML entities that could inject scripts (XSS)
//! - Markdown syntax that could break table formatting
//! - Control characters that could disrupt rendering
//!
//! All user-controllable data MUST be escaped before embedding in reports.

use std::borrow::Cow;

/// Line breaks a terminal, log viewer or CI runner may honour.
const fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Unicode bidi controls and direction marks (U+061C, U+200E, U+200F,
/// U+202A–U+202E, U+2066–U+2069). `char::is_control` does not cover them, and
/// they make a terminal or browser display text in a different order than it
/// is stored.
const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Characters no report may copy from SBOM text: control characters other
/// than line breaks and tab — C0, DEL and C1, including ESC (0x1B), which
/// starts ANSI escape sequences (cursor movement, screen clearing, title
/// changes) — and bidi controls. Each escaper decides how line breaks and tabs
/// are written.
fn is_stripped(c: char) -> bool {
    (c.is_control() && !is_line_break(c) && c != '\t') || is_bidi_control(c)
}

/// Whether `s`, printed at the start of a line, would make the line start
/// with `:`. GitHub Actions runs a line whose first non-blank characters are
/// `::` as a workflow command (`::error`, `::add-mask`, `::stop-commands`, …),
/// and output layouts can put SBOM text first on a line (the first table
/// column, or a row whose earlier columns are blank), so escapers neutralize
/// a leading `:`.
fn starts_with_colon(s: &str) -> bool {
    s.trim_start().starts_with(':')
}

/// Replace the `:` that [`starts_with_colon`] found with `escaped`, the
/// format's own spelling of it.
fn escape_leading_colon(s: &mut String, escaped: &str) {
    let at = s.len() - s.trim_start().len();
    s.replace_range(at..=at, escaped);
}

/// Sanitize untrusted text printed as (part of) one line of terminal or
/// CI-log output.
///
/// A field must never start a new output line: CI runners parse each line on
/// its own, and GitHub Actions turns a line that starts with `::error` into an
/// annotation, so a component name such as `lib\n::error::forged` could forge
/// one. Line breaks (`\n`, `\r`, NEL, U+2028, U+2029) are therefore rendered as
/// a visible `\n` and a tab becomes a space. Every other control character and
/// every bidi control is removed (see [`is_stripped`]). A field that would
/// start a line with `:` gets a backslash in front (`\::warning::…`), since a
/// field can also be the first thing on a line. Returns the input unchanged
/// when nothing needs changing.
#[must_use]
pub(crate) fn sanitize_line(s: &str) -> Cow<'_, str> {
    fn needs_change(c: char) -> bool {
        c.is_control() || is_line_break(c) || is_bidi_control(c)
    }

    if !s.contains(needs_change) && !starts_with_colon(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if is_line_break(c) {
            out.push_str("\\n");
        } else if c == '\t' {
            out.push(' ');
        } else if !needs_change(c) {
            out.push(c);
        }
    }
    if starts_with_colon(&out) {
        escape_leading_colon(&mut out, "\\:");
    }
    Cow::Owned(out)
}

/// Sanitize untrusted text for one CSV field, before quote doubling.
///
/// Line breaks become spaces, so a field cannot start a new line of a CSV
/// printed to a terminal or CI log; other control characters and bidi
/// controls are removed. A value starting with a spreadsheet formula trigger
/// (`=`, `+`, `-`, `@`, tab, CR) or with `:` (see [`starts_with_colon`]) is
/// prefixed with a single quote, so spreadsheet applications treat it as text
/// (OWASP CSV injection guidance) and the line cannot start with `::`.
#[must_use]
pub(crate) fn sanitize_csv_field(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|&c| !is_stripped(c))
        .map(|c| if is_line_break(c) { ' ' } else { c })
        .collect();
    if s.starts_with(['=', '+', '-', '@', '\t', '\r'])
        || out.trim_start().starts_with(['=', '+', '-', '@', ':'])
    {
        out.insert(0, '\'');
    }
    out
}

/// Escape a string for safe inclusion in HTML content.
///
/// Escapes the following characters:
/// - `&` -> `&amp;`
/// - `<` -> `&lt;`
/// - `>` -> `&gt;`
/// - `"` -> `&quot;`
/// - `'` -> `&#x27;`
/// - `\n` -> `&#10;` and `\r` -> `&#13;` (other line breaks become spaces),
///   so SBOM text cannot start a new line of an HTML report printed to a log
///
/// Control characters and bidi controls are removed, and a leading `:` is
/// written `&#58;`, because GitHub Actions runs a log line that starts with
/// `::` as a workflow command.
///
/// # Examples
///
/// ```
/// use sbom_tools::reports::escape::escape_html;
///
/// assert_eq!(escape_html("<script>alert('xss')</script>"),
///     "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
///
/// assert_eq!(escape_html("safe text"), "safe text");
/// ```
#[must_use]
pub fn escape_html(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            '\n' => result.push_str("&#10;"),
            '\r' => result.push_str("&#13;"),
            c if is_line_break(c) => result.push(' '),
            c if is_stripped(c) => {}
            _ => result.push(c),
        }
    }
    if starts_with_colon(&result) {
        escape_leading_colon(&mut result, "&#58;");
    }
    result
}

/// Escape a string for safe inclusion in HTML attributes.
///
/// This is stricter than content escaping - also handles newlines
/// and other whitespace that could break attribute parsing.
///
/// # Examples
///
/// ```
/// use sbom_tools::reports::escape::escape_html_attr;
///
/// assert_eq!(escape_html_attr("value with \"quotes\""),
///     "value with &quot;quotes&quot;");
/// ```
#[must_use]
pub fn escape_html_attr(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            '\n' => result.push_str("&#10;"),
            '\r' => result.push_str("&#13;"),
            '\t' => result.push_str("&#9;"),
            c if is_line_break(c) => result.push(' '),
            c if is_stripped(c) => {}
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for safe inclusion in Markdown table cells.
///
/// Markdown tables use `|` as column separators and can be broken
/// by unescaped pipe characters. This function also handles newlines
/// and backticks that could break formatting, removes control characters and
/// bidi controls, and escapes a leading `:` so a line of the report printed
/// to a CI log cannot start a workflow command. A backslash is escaped too:
/// otherwise `\|` in the input would come out as `\\|`, an escaped backslash
/// followed by a live pipe.
///
/// # Examples
///
/// ```
/// use sbom_tools::reports::escape::escape_markdown_table;
///
/// assert_eq!(escape_markdown_table("a | b"), "a \\| b");
/// assert_eq!(escape_markdown_table("line1\nline2"), "line1 line2");
/// assert_eq!(escape_markdown_table("`code`"), "\\`code\\`");
/// ```
#[must_use]
pub fn escape_markdown_table(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '|' => result.push_str("\\|"),
            '\n' => result.push(' '),
            '\r' => {}
            '`' => result.push_str("\\`"),
            '[' => result.push_str("\\["),
            ']' => result.push_str("\\]"),
            c if is_line_break(c) => result.push(' '),
            c if is_stripped(c) => {}
            _ => result.push(c),
        }
    }
    if starts_with_colon(&result) {
        escape_leading_colon(&mut result, "\\:");
    }
    result
}

/// Escape a string for safe inclusion in Markdown inline content.
///
/// Escapes characters that have special meaning in Markdown, removes control
/// characters and bidi controls, and escapes a leading `:` so a line of the
/// report printed to a CI log cannot start a workflow command. The backslash
/// is escaped as well: an input of `\<img …>` would otherwise come out as
/// `\\<img …\>`, which CommonMark reads as an escaped backslash followed by a
/// live HTML tag.
///
/// # Examples
///
/// ```
/// use sbom_tools::reports::escape::escape_markdown_inline;
///
/// assert_eq!(escape_markdown_inline("**bold**"), "\\*\\*bold\\*\\*");
/// assert_eq!(escape_markdown_inline("[link](url)"), "\\[link\\](url)");
/// assert_eq!(escape_markdown_inline("\\*"), "\\\\\\*");
/// ```
#[must_use]
pub fn escape_markdown_inline(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '*' => result.push_str("\\*"),
            '_' => result.push_str("\\_"),
            '`' => result.push_str("\\`"),
            '[' => result.push_str("\\["),
            ']' => result.push_str("\\]"),
            '#' => result.push_str("\\#"),
            '!' => result.push_str("\\!"),
            '~' => result.push_str("\\~"),
            '|' => result.push_str("\\|"),
            '<' => result.push_str("\\<"),
            '>' => result.push_str("\\>"),
            '\n' => result.push(' '),
            '\r' => {}
            c if is_line_break(c) => result.push(' '),
            c if is_stripped(c) => {}
            _ => result.push(c),
        }
    }
    if starts_with_colon(&result) {
        escape_leading_colon(&mut result, "\\:");
    }
    result
}

/// Escape a string for use in Markdown list items.
///
/// Similar to inline escaping but preserves some formatting. Control
/// characters and bidi controls are removed, a backslash is escaped (so it
/// cannot cancel the escape of the character after it), and a leading `:` is
/// escaped so a line of the report printed to a CI log cannot start a
/// workflow command.
#[must_use]
pub fn escape_markdown_list(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '*' => result.push_str("\\*"),
            '`' => result.push_str("\\`"),
            '[' => result.push_str("\\["),
            ']' => result.push_str("\\]"),
            '<' => result.push_str("\\<"),
            '>' => result.push_str("\\>"),
            '\n' => result.push_str("; "),
            '\r' => {}
            c if is_line_break(c) => result.push_str("; "),
            c if is_stripped(c) => {}
            _ => result.push(c),
        }
    }
    if starts_with_colon(&result) {
        escape_leading_colon(&mut result, "\\:");
    }
    result
}

/// Helper to escape an Option<&str> for HTML, returning "-" for None.
pub fn escape_html_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_string(), escape_html)
}

/// Helper to escape an Option<&str> for Markdown tables, returning "-" for None.
pub fn escape_md_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_string(), escape_markdown_table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html_basic() {
        assert_eq!(escape_html("hello"), "hello");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("a < b > c"), "a &lt; b &gt; c");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
    }

    #[test]
    fn test_escape_html_xss_vectors() {
        // Script injection
        assert_eq!(
            escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );

        // Event handler injection
        assert_eq!(
            escape_html("<img onerror=\"alert('xss')\">"),
            "&lt;img onerror=&quot;alert(&#x27;xss&#x27;)&quot;&gt;"
        );

        // HTML entity bypass attempt
        assert_eq!(escape_html("&lt;script&gt;"), "&amp;lt;script&amp;gt;");

        // Nested escaping attempt
        assert_eq!(
            escape_html("<a href=\"javascript:alert('xss')\">click</a>"),
            "&lt;a href=&quot;javascript:alert(&#x27;xss&#x27;)&quot;&gt;click&lt;/a&gt;"
        );
    }

    #[test]
    fn test_escape_html_attr() {
        assert_eq!(escape_html_attr("normal"), "normal");
        assert_eq!(escape_html_attr("line1\nline2"), "line1&#10;line2");
        assert_eq!(escape_html_attr("with\ttab"), "with&#9;tab");
    }

    #[test]
    fn test_escape_markdown_table_basic() {
        assert_eq!(escape_markdown_table("hello"), "hello");
        assert_eq!(escape_markdown_table("a | b"), "a \\| b");
        assert_eq!(escape_markdown_table("line1\nline2"), "line1 line2");
        assert_eq!(escape_markdown_table("`code`"), "\\`code\\`");
    }

    #[test]
    fn test_escape_markdown_table_malicious() {
        // Pipe injection to break table structure
        assert_eq!(
            escape_markdown_table("name|version|evil"),
            "name\\|version\\|evil"
        );

        // Newline injection to escape table row
        assert_eq!(
            escape_markdown_table("row1\n| new | row |"),
            "row1 \\| new \\| row \\|"
        );

        // Link injection
        assert_eq!(
            escape_markdown_table("[evil](http://malware.com)"),
            "\\[evil\\](http://malware.com)"
        );

        // Code injection in table
        assert_eq!(
            escape_markdown_table("```\ncode block\n```"),
            "\\`\\`\\` code block \\`\\`\\`"
        );
    }

    #[test]
    fn test_escape_markdown_inline() {
        assert_eq!(escape_markdown_inline("hello"), "hello");
        assert_eq!(escape_markdown_inline("**bold**"), "\\*\\*bold\\*\\*");
        assert_eq!(escape_markdown_inline("_italic_"), "\\_italic\\_");
        assert_eq!(escape_markdown_inline("[link](url)"), "\\[link\\](url)");
        assert_eq!(escape_markdown_inline("# heading"), "\\# heading");
    }

    #[test]
    fn test_escape_markdown_list() {
        assert_eq!(escape_markdown_list("item"), "item");
        assert_eq!(escape_markdown_list("multi\nline"), "multi; line");
        assert_eq!(escape_markdown_list("[link]"), "\\[link\\]");
    }

    /// A backslash in the input must not cancel the escape of the character
    /// after it: CommonMark reads `\\<` as an escaped backslash followed by a
    /// live `<`, and `\\*` as one followed by an emphasis marker.
    #[test]
    fn test_markdown_escapers_escape_the_backslash_itself() {
        let bypass = "\\<img src=x onerror=alert(1)>";
        assert_eq!(
            escape_markdown_inline(bypass),
            "\\\\\\<img src=x onerror=alert(1)\\>"
        );
        assert_eq!(
            escape_markdown_list(bypass),
            "\\\\\\<img src=x onerror=alert(1)\\>"
        );
        assert_eq!(escape_markdown_table("a\\|b"), "a\\\\\\|b");
        assert_eq!(escape_markdown_inline("\\*em\\*"), "\\\\\\*em\\\\\\*");
        // A plain backslash, as in a Windows path, renders as itself.
        assert_eq!(
            escape_markdown_inline("C:\\Program Files"),
            "C:\\\\Program Files"
        );
        for escaper in [
            escape_markdown_inline as fn(&str) -> String,
            escape_markdown_list,
            escape_markdown_table,
        ] {
            for backslashes in 1..=3 {
                let input = format!("{}[x](javascript:alert(1))", "\\".repeat(backslashes));
                let out = escaper(&input);
                // Every special character is preceded by an odd run of
                // backslashes, so none of them is live.
                for (at, c) in out.char_indices() {
                    if matches!(c, '[' | ']' | '<' | '>') {
                        let run = out[..at].chars().rev().take_while(|&b| b == '\\').count();
                        assert_eq!(run % 2, 1, "{c:?} at {at} is live in {out:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_escape_helpers() {
        assert_eq!(escape_html_opt(Some("<test>")), "&lt;test&gt;");
        assert_eq!(escape_html_opt(None), "-");

        assert_eq!(escape_md_opt(Some("a | b")), "a \\| b");
        assert_eq!(escape_md_opt(None), "-");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(escape_html(""), "");
        assert_eq!(escape_markdown_table(""), "");
        assert_eq!(escape_markdown_inline(""), "");
    }

    #[test]
    fn test_unicode_preservation() {
        // Ensure unicode characters pass through correctly
        assert_eq!(escape_html("日本語"), "日本語");
        assert_eq!(escape_markdown_table("émoji 🎉"), "émoji 🎉");
        assert_eq!(escape_html("Ω ≈ ∞"), "Ω ≈ ∞");
    }

    #[test]
    fn test_sanitize_line_ansi_neutralized() {
        // ESC is stripped, so the CSI sequence loses its meaning
        assert_eq!(
            sanitize_line("\x1b[31mevil\x1b[0m"),
            Cow::<str>::Owned("[31mevil[0m".to_string())
        );
        // OSC title change
        assert_eq!(sanitize_line("\x1b]0;pwned\x07name"), "]0;pwnedname");
    }

    #[test]
    fn test_sanitize_line_control_chars_stripped() {
        assert_eq!(sanitize_line("a\x07b\x08c"), "abc");
        assert_eq!(sanitize_line("\x00null\x7f"), "null");
        // C1 controls
        assert_eq!(sanitize_line("a\u{9b}31mb"), "a31mb");
    }

    #[test]
    fn test_sanitize_line_never_starts_a_new_line() {
        // A CI workflow command smuggled into a component name stays on the
        // line it was printed on, visibly escaped.
        let forged = "lib\n::error file=src/main.rs,line=1::FORGED";
        let clean = sanitize_line(forged);
        assert_eq!(clean, "lib\\n::error file=src/main.rs,line=1::FORGED");
        assert!(!clean.contains('\n'));
        assert_eq!(sanitize_line("over\rwrite"), "over\\nwrite");
        assert_eq!(sanitize_line("a\r\nb"), "a\\n\\nb");
        // NEL and the Unicode line and paragraph separators break lines too
        assert_eq!(sanitize_line("a\u{85}b\u{2028}c\u{2029}d"), "a\\nb\\nc\\nd");
        assert_eq!(sanitize_line("col1\tcol2"), "col1 col2");
    }

    #[test]
    fn test_sanitize_line_bidi_controls_stripped() {
        // Right-to-left override (U+202E) would display "exe.txt" as "txt.exe"
        assert_eq!(sanitize_line("invoice\u{202E}txt.exe"), "invoicetxt.exe");
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert_eq!(sanitize_line(&format!("a{c}b")), "ab", "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn test_sanitize_line_escapes_a_leading_colon() {
        // A field printed first on a line (a table's first column) needs no
        // line break to start a workflow command; the runner trims blanks.
        assert_eq!(sanitize_line("::warning::forged"), "\\::warning::forged");
        assert_eq!(sanitize_line("  ::error::x"), "  \\::error::x");
        assert_eq!(sanitize_line(":"), "\\:");
        // NBSP is trimmed by the runner too
        assert_eq!(sanitize_line("\u{a0}::x"), "\u{a0}\\::x");
        // A tab becomes a space before the check, so it cannot hide the colon
        assert_eq!(sanitize_line("\t::x"), " \\::x");
        // Colons elsewhere are untouched
        assert!(matches!(sanitize_line("std::vector"), Cow::Borrowed(_)));
        assert!(matches!(
            sanitize_line("pkg:npm/a@1"),
            Cow::Borrowed("pkg:npm/a@1")
        ));
    }

    #[test]
    fn test_sanitize_csv_field() {
        assert_eq!(
            sanitize_csv_field("x\n::error::forged"),
            "x ::error::forged"
        );
        assert_eq!(sanitize_csv_field("a\r\u{85}\u{2028}b"), "a   b");
        assert_eq!(sanitize_csv_field("::warning::x"), "'::warning::x");
        assert_eq!(sanitize_csv_field(" :x"), "' :x");
        assert_eq!(sanitize_csv_field("=1+2"), "'=1+2");
        assert_eq!(sanitize_csv_field("\x1b[1mbold\u{202E}"), "[1mbold");
        assert_eq!(sanitize_csv_field("std::vector"), "std::vector");
    }

    #[test]
    fn test_document_escapers_strip_controls_and_a_leading_colon() {
        let hostile = "::warning::x\x1b[31m\x07\u{202E}\u{2028}y";
        assert_eq!(escape_markdown_table(hostile), "\\::warning::x\\[31m y");
        assert_eq!(escape_markdown_inline(hostile), "\\::warning::x\\[31m y");
        assert_eq!(escape_markdown_list(hostile), "\\::warning::x\\[31m; y");
        assert_eq!(escape_html(hostile), "&#58;:warning::x[31m y");
        assert_eq!(escape_html_attr("a\x1b\u{202E}b"), "ab");
        // HTML keeps a line break, as an entity, so SBOM text cannot start a
        // new line of the report's source
        assert_eq!(escape_html("a\nb\rc"), "a&#10;b&#13;c");
        assert_eq!(escape_html("std::vector"), "std::vector");
    }

    #[test]
    fn test_sanitize_line_preserves_safe_input() {
        assert!(matches!(
            sanitize_line("lodash@4.17.21"),
            Cow::Borrowed("lodash@4.17.21")
        ));
        assert!(matches!(sanitize_line("日本語 émoji 🎉"), Cow::Borrowed(_)));
        // Arabic and Hebrew letters are text, not controls
        assert!(matches!(sanitize_line("مرحبا שלום"), Cow::Borrowed(_)));
        assert!(matches!(sanitize_line(""), Cow::Borrowed("")));
    }

    #[test]
    fn test_realistic_sbom_data() {
        // Real-world component names that might cause issues
        assert_eq!(escape_html("lodash@4.17.21"), "lodash@4.17.21");
        assert_eq!(escape_markdown_table("@types/node"), "@types/node");

        // Version strings
        assert_eq!(escape_html(">=1.0.0 <2.0.0"), "&gt;=1.0.0 &lt;2.0.0");

        // Purl with special chars
        assert_eq!(
            escape_html("pkg:npm/%40scope/name@1.0.0"),
            "pkg:npm/%40scope/name@1.0.0"
        );
    }
}
