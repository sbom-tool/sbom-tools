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
    match s {
        Some(v) => escape_html(v),
        None => "-".to_string(),
    }
}

/// Helper to escape an Option<&str> for Markdown tables, returning "-" for None.
pub fn escape_md_opt(s: Option<&str>) -> String {
    match s {
        Some(v) => escape_markdown_table(v),
        None => "-".to_string(),
    }
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
        assert_eq!(
            escape_html_attr("line1\nline2"),
            "line1&#10;line2"
        );
        assert_eq!(
            escape_html_attr("with\ttab"),
            "with&#9;tab"
        );
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
