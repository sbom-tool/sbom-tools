//! Text-measurement helpers for TUI layout.

use ratatui::text::Line;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Number of terminal rows `lines` occupy when rendered with `Wrap { trim: false }`
/// at `width` columns.
///
/// Detail panels render wrapped text but historically bounded scrolling by the
/// *logical* line count (`lines.len()`), so wrapped overflow (long CVE descriptions,
/// URLs) was unreachable and the scrollbar was mis-sized. This counts the *wrapped*
/// rows so callers can compute a correct `max_scroll` and scrollbar length.
///
/// Greedy word-wrap approximating ratatui's `WordWrapper`: a word that would overflow
/// the current row starts a new one, and a word longer than a full row is hard-broken.
#[must_use]
pub(crate) fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    if width == 0 {
        return lines.len().max(1);
    }
    let w = width as usize;
    lines
        .iter()
        .map(|line| wrapped_rows(line, w))
        .sum::<usize>()
        .max(1)
}

fn wrapped_rows(line: &Line<'_>, w: usize) -> usize {
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    if text.is_empty() {
        return 1; // a blank line still occupies one row
    }
    let mut rows = 1usize;
    let mut col = 0usize;
    // `split_inclusive(' ')` keeps the trailing space attached to each word, matching
    // how the wrapper carries whitespace when `trim` is false.
    for word in text.split_inclusive(' ') {
        let word_w = UnicodeWidthStr::width(word);
        if word_w <= w {
            if col + word_w > w {
                rows += 1;
                col = word_w;
            } else {
                col += word_w;
            }
        } else {
            // Word longer than a row: place graphemes greedily, breaking as needed.
            for ch in word.chars() {
                let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                if col + cw > w {
                    rows += 1;
                    col = 0;
                }
                col += cw;
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::wrapped_line_count;
    use ratatui::text::Line;

    #[test]
    fn short_line_is_one_row() {
        assert_eq!(wrapped_line_count(&[Line::from("hello world")], 20), 1);
    }

    #[test]
    fn wraps_on_word_boundary_like_ratatui() {
        // Matches ratatui's Paragraph::line_count doc example ("Hello World" @ 10 => 2).
        assert_eq!(wrapped_line_count(&[Line::from("Hello World")], 10), 2);
    }

    #[test]
    fn long_unbroken_word_is_hard_broken() {
        // 10 columns / width 4 => 3 rows (a long URL/token).
        assert_eq!(wrapped_line_count(&[Line::from("abcdefghij")], 4), 3);
    }

    #[test]
    fn empty_and_multiple_lines() {
        assert_eq!(wrapped_line_count(&[Line::from("")], 10), 1);
        // Two lines that each wrap to 2 rows at width 10 => 4.
        let lines = [Line::from("Hello World"), Line::from("Hello World")];
        assert_eq!(wrapped_line_count(&lines, 10), 4);
    }

    #[test]
    fn zero_width_falls_back_to_logical_count() {
        assert_eq!(
            wrapped_line_count(&[Line::from("a"), Line::from("b")], 0),
            2
        );
    }
}
