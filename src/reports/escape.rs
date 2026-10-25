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

/// Sanitize untrusted text printed as (part of) one line of terminal or
/// CI-log output.
///
/// A field must never start a new output line: CI runners parse each line on
/// its own, and GitHub Actions turns a line that starts with `::error` into an
/// annotation, so a component name such as `lib\n::error::forged` could forge
/// one. Line breaks (`\n`, `\r`, NEL, U+2028, U+2029) are therefore rendered as
/// a visible `\n` and a tab becomes a space. Every other control character is
/// removed — C0, DEL and C1, including ESC (0x1B), which neutralizes ANSI
/// escape sequences (cursor movement, screen clearing, title changes) — and
/// so are the Unicode bidi controls and direction marks (U+061C, U+200E,
/// U+200F, U+202A–U+202E, U+2066–U+2069), which `char::is_control` does not
/// cover and which make a terminal display text in a different order than it
/// is stored. Returns the input unchanged when nothing needs changing.
#[must_use]
pub(crate) fn sanitize_line(s: &str) -> Cow<'_, str> {
    fn is_line_break(c: char) -> bool {
        matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
    }
    fn is_bidi_control(c: char) -> bool {
        matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
    }
    fn needs_change(c: char) -> bool {
        c.is_control() || is_line_break(c) || is_bidi_control(c)
    }

    if !s.contains(needs_change) {
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
    Cow::Owned(out)
}

/// Escape a string for safe inclusion in HTML content.
///
/// Escapes the following characters:
/// - `&` -> `&amp;`
/// - `<` -> `&lt;`
/// - `>` -> `&gt;`
/// - `"` -> `&quot;`
/// - `'` -> `&#x27;`
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
            _ => result.push(c),
        }
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
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for safe inclusion in Markdown table cells.
///
/// Markdown tables use `|` as column separators and can be broken
/// by unescaped pipe characters. This function also handles newlines
/// and backticks that could break formatting.
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
            '|' => result.push_str("\\|"),
            '\n' => result.push(' '),
            '\r' => {}
            '`' => result.push_str("\\`"),
            '[' => result.push_str("\\["),
            ']' => result.push_str("\\]"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for safe inclusion in Markdown inline content.
///
/// Escapes characters that have special meaning in Markdown.
///
/// # Examples
///
/// ```
/// use sbom_tools::reports::escape::escape_markdown_inline;
///
/// assert_eq!(escape_markdown_inline("**bold**"), "\\*\\*bold\\*\\*");
/// assert_eq!(escape_markdown_inline("[link](url)"), "\\[link\\](url)");
/// ```
#[must_use]
pub fn escape_markdown_inline(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
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
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for use in Markdown list items.
///
/// Similar to inline escaping but preserves some formatting.
#[must_use]
pub fn escape_markdown_list(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' => result.push_str("\\*"),
            '`' => result.push_str("\\`"),
            '[' => result.push_str("\\["),
            ']' => result.push_str("\\]"),
            '<' => result.push_str("\\<"),
            '>' => result.push_str("\\>"),
            '\n' => result.push_str("; "),
            '\r' => {}
            _ => result.push(c),
        }
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
