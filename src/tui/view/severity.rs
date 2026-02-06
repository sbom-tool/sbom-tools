//! Severity utilities for vulnerability display and comparison.

use crate::model::{Severity, VulnerabilityRef};

/// Get numeric order for severity level (higher = more severe).
#[inline]
pub fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Get numeric order for Severity enum (higher = more severe).
#[inline]
pub fn severity_enum_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info | Severity::None | Severity::Unknown => 0,
    }
}

/// Get the maximum severity from a list of vulnerabilities.
pub fn max_severity_from_vulns(vulns: &[VulnerabilityRef]) -> Option<String> {
    vulns
        .iter()
        .filter_map(|v| v.severity.as_ref())
        .max_by(|a, b| severity_enum_order(a).cmp(&severity_enum_order(b)))
        .map(|s| s.to_string().to_lowercase())
}

/// Check if a Severity enum matches a target string (case-insensitive).
#[inline]
pub fn severity_matches(severity: Option<&Severity>, target: &str) -> bool {
    severity
        .is_some_and(|s| s.to_string().eq_ignore_ascii_case(target))
}

/// Categorize severity into buckets for grouping.
/// Returns: "critical", "high", "medium", "low", or "clean"
pub fn severity_category(vulns: &[VulnerabilityRef]) -> &'static str {
    if vulns.is_empty() {
        return "clean";
    }

    let max = vulns
        .iter()
        .filter_map(|v| v.severity.as_ref().map(severity_enum_order))
        .max()
        .unwrap_or(0);

    match max {
        4 => "critical",
        3 => "high",
        2 => "medium",
        // Unknown/Info/None severity with vulnerabilities -> treat as low
        _ => "low",
    }
}
