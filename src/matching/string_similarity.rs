//! String similarity algorithms for component name matching.
//!
//! This module provides token-based, phonetic, and version-aware
//! similarity functions used by the fuzzy matcher.

use std::collections::HashSet;

/// Compute token-based similarity using Jaccard index on name tokens.
///
/// Splits names on common delimiters (-, _, ., @, /) and compares token sets.
/// This catches reordered names like "react-dom" <-> "dom-react".
#[must_use]
pub fn compute_token_similarity(name_a: &str, name_b: &str) -> f64 {
    let tokens_a: HashSet<&str> = name_a
        .split(['-', '_', '.', '@', '/'])
        .filter(|t| !t.is_empty())
        .collect();

    let tokens_b: HashSet<&str> = name_b
        .split(['-', '_', '.', '@', '/'])
        .filter(|t| !t.is_empty())
        .collect();

    if tokens_a.is_empty() && tokens_b.is_empty() {
        return 1.0;
    }
    if tokens_a.is_empty() || tokens_b.is_empty() {
        return 0.0;
    }

    let intersection = tokens_a.intersection(&tokens_b).count();
    let union = tokens_a.union(&tokens_b).count();

    if union > 0 {
        intersection as f64 / union as f64
    } else {
        0.0
    }
}

/// Compute version similarity with semantic awareness.
///
/// Returns a boost value (0.0 - 0.1) based on how similar versions are:
/// - Exact match: 0.10
/// - Same major.minor: 0.07
/// - Same major: 0.04
/// - Both present but different: 0.0
/// - One or both missing: 0.0
#[must_use]
pub fn compute_version_similarity(va: Option<&String>, vb: Option<&String>) -> f64 {
    match (va, vb) {
        (Some(a), Some(b)) if a == b => 0.10, // Exact match
        (Some(a), Some(b)) => {
            // Parse semantic versions
            let parts_a: Vec<&str> = a.split('.').collect();
            let parts_b: Vec<&str> = b.split('.').collect();

            // Extract major.minor.patch (handle non-numeric gracefully)
            let major_a = parts_a.first().and_then(|s| s.parse::<u32>().ok());
            let major_b = parts_b.first().and_then(|s| s.parse::<u32>().ok());
            let minor_a = parts_a
                .get(1)
                .and_then(|s| s.split('-').next())
                .and_then(|s| s.parse::<u32>().ok());
            let minor_b = parts_b
                .get(1)
                .and_then(|s| s.split('-').next())
                .and_then(|s| s.parse::<u32>().ok());

            match (major_a, major_b, minor_a, minor_b) {
                (Some(ma), Some(mb), Some(mia), Some(mib)) if ma == mb && mia == mib => 0.07,
                (Some(ma), Some(mb), _, _) if ma == mb => 0.04,
                _ => 0.0,
            }
        }
        _ => 0.0, // One or both missing
    }
}

/// Compute Soundex code for phonetic matching.
///
/// Soundex encodes names by their pronunciation, helping match:
/// - "color" <-> "colour"
/// - "jason" <-> "jayson"
/// - "smith" <-> "smyth"
pub fn soundex(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }

    let name_upper: String = name
        .to_uppercase()
        .chars()
        .filter(char::is_ascii_alphabetic)
        .collect();
    if name_upper.is_empty() {
        return String::new();
    }

    let mut chars = name_upper.chars();
    let first_char = chars
        .next()
        .expect("name_upper is non-empty after empty check above");
    let mut code = String::with_capacity(4);
    code.push(first_char);

    let mut last_digit = soundex_digit(first_char);

    for c in chars {
        let digit = soundex_digit(c);
        if digit != '0' && digit != last_digit {
            code.push(digit);
            if code.len() == 4 {
                break;
            }
        }
        if digit != '0' {
            last_digit = digit;
        }
    }

    // Pad with zeros if needed
    while code.len() < 4 {
        code.push('0');
    }

    code
}

/// Get Soundex digit for a character.
#[must_use]
pub const fn soundex_digit(c: char) -> char {
    match c {
        'B' | 'F' | 'P' | 'V' => '1',
        'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
        'D' | 'T' => '3',
        'L' => '4',
        'M' | 'N' => '5',
        'R' => '6',
        _ => '0', // A, E, I, O, U, H, W, Y
    }
}

/// Compute phonetic similarity using Soundex.
///
/// Returns 1.0 if Soundex codes match, 0.0 otherwise.
/// Also checks individual tokens for partial phonetic matches.
#[must_use]
pub fn compute_phonetic_similarity(name_a: &str, name_b: &str) -> f64 {
    // Compare full name Soundex
    let soundex_a = soundex(name_a);
    let soundex_b = soundex(name_b);

    if !soundex_a.is_empty() && soundex_a == soundex_b {
        return 1.0;
    }

    // Compare token-by-token for compound names
    let tokens_a: Vec<&str> = name_a
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let tokens_b: Vec<&str> = name_b
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();

    if tokens_a.is_empty() || tokens_b.is_empty() {
        return 0.0;
    }

    // Count matching Soundex codes between tokens
    let mut matches = 0;
    let total = tokens_a.len().max(tokens_b.len());

    for ta in &tokens_a {
        let sa = soundex(ta);
        if sa.is_empty() {
            continue;
        }
        for tb in &tokens_b {
            let sb = soundex(tb);
            if sa == sb {
                matches += 1;
                break;
            }
        }
    }

    if total == 0 {
        0.0
    } else {
        f64::from(matches) / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_similarity_identical() {
        assert_eq!(compute_token_similarity("react-dom", "react-dom"), 1.0);
    }

    #[test]
    fn test_token_similarity_reordered() {
        assert_eq!(compute_token_similarity("react-dom", "dom-react"), 1.0);
    }

    #[test]
    fn test_token_similarity_partial() {
        let score = compute_token_similarity("react-dom", "react-native");
        assert!(score > 0.0 && score < 1.0);
    }

    #[test]
    fn test_token_similarity_empty() {
        assert_eq!(compute_token_similarity("", ""), 1.0);
        assert_eq!(compute_token_similarity("foo", ""), 0.0);
    }

    #[test]
    fn test_soundex_basic() {
        assert_eq!(soundex("Robert"), "R163");
        assert_eq!(soundex("Smith"), "S530");
    }

    #[test]
    fn test_soundex_empty() {
        assert_eq!(soundex(""), "");
        assert_eq!(soundex("123"), "");
    }

    #[test]
    fn test_phonetic_similarity_match() {
        // Same soundex code
        assert_eq!(compute_phonetic_similarity("smith", "smyth"), 1.0);
    }

    #[test]
    fn test_phonetic_similarity_no_match() {
        assert_eq!(compute_phonetic_similarity("react", "angular"), 0.0);
    }

    #[test]
    fn test_version_similarity_exact() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.3".to_string();
        assert_eq!(compute_version_similarity(Some(&v1), Some(&v2)), 0.10);
    }

    #[test]
    fn test_version_similarity_same_major_minor() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.5".to_string();
        assert_eq!(compute_version_similarity(Some(&v1), Some(&v2)), 0.07);
    }

    #[test]
    fn test_version_similarity_same_major() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.5.0".to_string();
        assert_eq!(compute_version_similarity(Some(&v1), Some(&v2)), 0.04);
    }

    #[test]
    fn test_version_similarity_none() {
        assert_eq!(compute_version_similarity(None, None), 0.0);
    }
}
