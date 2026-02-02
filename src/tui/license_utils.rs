//! License utilities for TUI display.
//!
//! Provides SPDX expression parsing, license compatibility checking,
//! and risk assessment for the license tab.

use std::collections::{HashMap, HashSet};

/// Parsed SPDX expression
#[derive(Debug, Clone, PartialEq)]
pub enum SpdxExpression {
    /// Single license identifier
    License(String),
    /// License with exception (e.g., GPL-2.0 WITH Classpath-exception-2.0)
    WithException { license: String, exception: String },
    /// OR expression (choice of licenses)
    Or(Box<SpdxExpression>, Box<SpdxExpression>),
    /// AND expression (must comply with all)
    And(Box<SpdxExpression>, Box<SpdxExpression>),
}

impl SpdxExpression {
    /// Parse an SPDX expression string
    pub fn parse(expr: &str) -> Self {
        let expr = expr.trim();

        // Handle OR operator (lowest precedence)
        if let Some(pos) = find_operator(expr, " OR ") {
            let left = &expr[..pos];
            let right = &expr[pos + 4..];
            return SpdxExpression::Or(
                Box::new(SpdxExpression::parse(left)),
                Box::new(SpdxExpression::parse(right)),
            );
        }

        // Handle AND operator
        if let Some(pos) = find_operator(expr, " AND ") {
            let left = &expr[..pos];
            let right = &expr[pos + 5..];
            return SpdxExpression::And(
                Box::new(SpdxExpression::parse(left)),
                Box::new(SpdxExpression::parse(right)),
            );
        }

        // Handle WITH exception
        if let Some(pos) = expr.to_uppercase().find(" WITH ") {
            let license = expr[..pos].trim().to_string();
            let exception = expr[pos + 6..].trim().to_string();
            return SpdxExpression::WithException { license, exception };
        }

        // Handle parentheses
        let expr = expr.trim_start_matches('(').trim_end_matches(')').trim();

        // Single license
        SpdxExpression::License(expr.to_string())
    }

    /// Get all license identifiers in the expression
    pub fn licenses(&self) -> Vec<&str> {
        match self {
            SpdxExpression::License(l) => vec![l.as_str()],
            SpdxExpression::WithException { license, .. } => vec![license.as_str()],
            SpdxExpression::Or(left, right) | SpdxExpression::And(left, right) => {
                let mut result = left.licenses();
                result.extend(right.licenses());
                result
            }
        }
    }

    /// Check if this is a choice expression (contains OR)
    pub fn is_choice(&self) -> bool {
        match self {
            SpdxExpression::Or(_, _) => true,
            SpdxExpression::And(left, right) => left.is_choice() || right.is_choice(),
            _ => false,
        }
    }

    /// Get a human-readable description of the expression type
    pub fn expression_type(&self) -> &'static str {
        match self {
            SpdxExpression::License(_) => "Single License",
            SpdxExpression::WithException { .. } => "License with Exception",
            SpdxExpression::Or(_, _) => "Dual/Multi License (Choice)",
            SpdxExpression::And(_, _) => "Combined License (All Apply)",
        }
    }
}

/// Find operator position, respecting parentheses
fn find_operator(expr: &str, op: &str) -> Option<usize> {
    let upper = expr.to_uppercase();
    let mut depth = 0;

    for (i, c) in expr.chars().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && upper[i..].starts_with(op) {
            return Some(i);
        }
    }
    None
}

/// License category for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenseCategory {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
    NetworkCopyleft,
    Proprietary,
    PublicDomain,
    Unknown,
}

impl LicenseCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseCategory::Permissive => "Permissive",
            LicenseCategory::WeakCopyleft => "Weak Copyleft",
            LicenseCategory::StrongCopyleft => "Copyleft",
            LicenseCategory::NetworkCopyleft => "Network Copyleft",
            LicenseCategory::Proprietary => "Proprietary",
            LicenseCategory::PublicDomain => "Public Domain",
            LicenseCategory::Unknown => "Unknown",
        }
    }

    /// Get the copyleft strength (0 = none, 4 = strongest)
    pub fn copyleft_strength(&self) -> u8 {
        match self {
            LicenseCategory::PublicDomain | LicenseCategory::Permissive => 0,
            LicenseCategory::WeakCopyleft => 1,
            LicenseCategory::StrongCopyleft => 2,
            LicenseCategory::NetworkCopyleft => 3,
            LicenseCategory::Proprietary => 4, // Most restrictive
            LicenseCategory::Unknown => 0,
        }
    }
}

/// License risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

/// Detailed license information
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    /// SPDX identifier
    pub spdx_id: String,
    /// License category
    pub category: LicenseCategory,
    /// Risk level for commercial use
    pub risk_level: RiskLevel,
    /// Whether attribution is required
    pub requires_attribution: bool,
    /// Whether source disclosure is required
    pub requires_source_disclosure: bool,
    /// Whether patent grant is included
    pub patent_grant: bool,
    /// Whether modifications must be disclosed
    pub modifications_must_be_disclosed: bool,
    /// Whether derivatives must use same license
    pub same_license_for_derivatives: bool,
    /// Whether network use triggers copyleft
    pub network_copyleft: bool,
    /// License family (e.g., "BSD", "GPL", "Apache")
    pub family: &'static str,
}

impl LicenseInfo {
    /// Get detailed info for a known license
    pub fn from_spdx(spdx_id: &str) -> Self {
        let lower = spdx_id.to_lowercase();

        // MIT family
        if lower.contains("mit") {
            return Self::permissive("MIT", false);
        }

        // Apache family
        if lower.contains("apache") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::Permissive,
                risk_level: RiskLevel::Low,
                requires_attribution: true,
                requires_source_disclosure: false,
                patent_grant: true,
                modifications_must_be_disclosed: false,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family: "Apache",
            };
        }

        // BSD family
        if lower.contains("bsd") {
            let has_advertising = lower.contains("4-clause") || lower.contains("original");
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::Permissive,
                risk_level: if has_advertising {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                },
                requires_attribution: true,
                requires_source_disclosure: false,
                patent_grant: false,
                modifications_must_be_disclosed: false,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family: "BSD",
            };
        }

        // ISC, Unlicense, CC0, WTFPL, Zlib
        if lower.contains("isc")
            || lower.contains("unlicense")
            || lower.contains("cc0")
            || lower.contains("wtfpl")
            || lower.contains("zlib")
        {
            let family = if lower.contains("cc0") {
                "Creative Commons"
            } else if lower.contains("zlib") {
                "Zlib"
            } else {
                "Public Domain-like"
            };
            return Self {
                spdx_id: spdx_id.to_string(),
                category: if lower.contains("cc0") || lower.contains("unlicense") {
                    LicenseCategory::PublicDomain
                } else {
                    LicenseCategory::Permissive
                },
                risk_level: RiskLevel::Low,
                requires_attribution: !lower.contains("cc0") && !lower.contains("unlicense"),
                requires_source_disclosure: false,
                patent_grant: false,
                modifications_must_be_disclosed: false,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family,
            };
        }

        // AGPL (network copyleft)
        if lower.contains("agpl") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::NetworkCopyleft,
                risk_level: RiskLevel::Critical,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: lower.contains("3"),
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: true,
                network_copyleft: true,
                family: "GPL",
            };
        }

        // LGPL (weak copyleft)
        if lower.contains("lgpl") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::WeakCopyleft,
                risk_level: RiskLevel::Medium,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: lower.contains("3"),
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: true, // Only for library modifications
                network_copyleft: false,
                family: "GPL",
            };
        }

        // GPL (strong copyleft)
        if lower.contains("gpl") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::StrongCopyleft,
                risk_level: RiskLevel::High,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: lower.contains("3"),
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: true,
                network_copyleft: false,
                family: "GPL",
            };
        }

        // MPL (weak copyleft)
        if lower.contains("mpl") || lower.contains("mozilla") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::WeakCopyleft,
                risk_level: RiskLevel::Medium,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: true,
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: false, // File-level copyleft
                network_copyleft: false,
                family: "MPL",
            };
        }

        // Eclipse (weak copyleft)
        if lower.contains("eclipse") || lower.contains("epl") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::WeakCopyleft,
                risk_level: RiskLevel::Medium,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: true,
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family: "Eclipse",
            };
        }

        // CDDL
        if lower.contains("cddl") {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::WeakCopyleft,
                risk_level: RiskLevel::Medium,
                requires_attribution: true,
                requires_source_disclosure: true,
                patent_grant: true,
                modifications_must_be_disclosed: true,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family: "CDDL",
            };
        }

        // Proprietary
        if lower.contains("proprietary")
            || lower.contains("commercial")
            || lower.contains("private")
        {
            return Self {
                spdx_id: spdx_id.to_string(),
                category: LicenseCategory::Proprietary,
                risk_level: RiskLevel::Critical,
                requires_attribution: false,
                requires_source_disclosure: false,
                patent_grant: false,
                modifications_must_be_disclosed: false,
                same_license_for_derivatives: false,
                network_copyleft: false,
                family: "Proprietary",
            };
        }

        // Unknown
        Self {
            spdx_id: spdx_id.to_string(),
            category: LicenseCategory::Unknown,
            risk_level: RiskLevel::Medium, // Conservative default
            requires_attribution: true,    // Safe assumption
            requires_source_disclosure: false,
            patent_grant: false,
            modifications_must_be_disclosed: false,
            same_license_for_derivatives: false,
            network_copyleft: false,
            family: "Unknown",
        }
    }

    fn permissive(family: &'static str, patent_grant: bool) -> Self {
        Self {
            spdx_id: family.to_string(),
            category: LicenseCategory::Permissive,
            risk_level: RiskLevel::Low,
            requires_attribution: true,
            requires_source_disclosure: false,
            patent_grant,
            modifications_must_be_disclosed: false,
            same_license_for_derivatives: false,
            network_copyleft: false,
            family,
        }
    }
}

/// License compatibility result
#[derive(Debug, Clone)]
pub struct CompatibilityResult {
    /// Whether the licenses are compatible
    pub compatible: bool,
    /// Compatibility level (0-100)
    pub score: u8,
    /// Warning messages
    pub warnings: Vec<String>,
    /// The resulting license requirements if combined
    pub resulting_category: LicenseCategory,
}

/// Check compatibility between two licenses
pub fn check_compatibility(license_a: &str, license_b: &str) -> CompatibilityResult {
    let info_a = LicenseInfo::from_spdx(license_a);
    let info_b = LicenseInfo::from_spdx(license_b);

    let mut warnings = Vec::new();
    let mut compatible = true;
    let mut score = 100u8;

    // Proprietary is never compatible with copyleft
    if (info_a.category == LicenseCategory::Proprietary
        || info_b.category == LicenseCategory::Proprietary)
        && info_a.category != info_b.category
    {
        compatible = false;
        score = 0;
        warnings.push(format!(
            "Proprietary license '{}' incompatible with '{}'",
            if info_a.category == LicenseCategory::Proprietary {
                license_a
            } else {
                license_b
            },
            if info_a.category == LicenseCategory::Proprietary {
                license_b
            } else {
                license_a
            }
        ));
    }

    // GPL family incompatibilities
    if info_a.family == "GPL" || info_b.family == "GPL" {
        // GPL v2 only vs GPL v3
        let a_lower = license_a.to_lowercase();
        let b_lower = license_b.to_lowercase();

        if (a_lower.contains("gpl-2.0-only") && b_lower.contains("gpl-3"))
            || (b_lower.contains("gpl-2.0-only") && a_lower.contains("gpl-3"))
        {
            compatible = false;
            score = 0;
            warnings.push("GPL-2.0-only is incompatible with GPL-3.0".to_string());
        }

        // Apache 2.0 with GPL 2.0 is problematic
        if ((info_a.family == "Apache" && b_lower.contains("gpl-2"))
            || (info_b.family == "Apache" && a_lower.contains("gpl-2")))
            && !a_lower.contains("gpl-3")
            && !b_lower.contains("gpl-3")
        {
            warnings.push(
                "Apache-2.0 has patent clauses incompatible with GPL-2.0".to_string(),
            );
            score = score.saturating_sub(30);
        }
    }

    // Network copyleft warning
    if info_a.network_copyleft || info_b.network_copyleft {
        warnings.push("Network copyleft license (AGPL) requires source disclosure for network use".to_string());
        score = score.saturating_sub(20);
    }

    // Mixed copyleft strengths
    if info_a.category != info_b.category {
        let strength_diff =
            (info_a.category.copyleft_strength() as i8 - info_b.category.copyleft_strength() as i8)
                .unsigned_abs();

        if strength_diff > 1 {
            warnings.push(format!(
                "Mixing {} ({}) with {} ({}) may have licensing implications",
                license_a,
                info_a.category.as_str(),
                license_b,
                info_b.category.as_str()
            ));
            score = score.saturating_sub(strength_diff * 10);
        }
    }

    // Determine resulting category (most restrictive)
    let resulting_category =
        if info_a.category.copyleft_strength() > info_b.category.copyleft_strength() {
            info_a.category
        } else {
            info_b.category
        };

    CompatibilityResult {
        compatible,
        score,
        warnings,
        resulting_category,
    }
}

/// Analyze all licenses in an SBOM for compatibility issues
pub fn analyze_license_compatibility(licenses: &[&str]) -> LicenseCompatibilityReport {
    let mut issues = Vec::new();
    let mut families: HashMap<&'static str, Vec<String>> = HashMap::new();
    let mut categories: HashMap<LicenseCategory, Vec<String>> = HashMap::new();

    // Collect license info
    for license in licenses {
        let info = LicenseInfo::from_spdx(license);
        families
            .entry(info.family)
            .or_default()
            .push(license.to_string());
        categories
            .entry(info.category)
            .or_default()
            .push(license.to_string());
    }

    // Check pairwise compatibility for problematic combinations
    let unique: Vec<_> = licenses.iter().collect::<HashSet<_>>().into_iter().collect();
    for (i, &license_a) in unique.iter().enumerate() {
        for &license_b in unique.iter().skip(i + 1) {
            let result = check_compatibility(license_a, license_b);
            if !result.compatible || result.score < 70 {
                issues.push(CompatibilityIssue {
                    license_a: license_a.to_string(),
                    license_b: license_b.to_string(),
                    severity: if !result.compatible {
                        IssueSeverity::Error
                    } else {
                        IssueSeverity::Warning
                    },
                    message: result.warnings.join("; "),
                });
            }
        }
    }

    // Calculate overall score
    let overall_score = if issues.iter().any(|i| i.severity == IssueSeverity::Error) {
        0
    } else {
        let warning_count = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
            .count();
        100u8.saturating_sub((warning_count * 15) as u8)
    };

    LicenseCompatibilityReport {
        overall_score,
        issues,
        families,
        categories,
    }
}

/// License compatibility report for an entire SBOM
#[derive(Debug)]
pub struct LicenseCompatibilityReport {
    /// Overall compatibility score (0-100)
    pub overall_score: u8,
    /// Specific compatibility issues
    pub issues: Vec<CompatibilityIssue>,
    /// Licenses grouped by family
    pub families: HashMap<&'static str, Vec<String>>,
    /// Licenses grouped by category
    pub categories: HashMap<LicenseCategory, Vec<String>>,
}

/// A specific compatibility issue
#[derive(Debug, Clone)]
pub struct CompatibilityIssue {
    pub license_a: String,
    pub license_b: String,
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    Warning,
    Error,
}

/// License statistics for display
#[derive(Debug, Default)]
pub struct LicenseStats {
    pub total_licenses: usize,
    pub unique_licenses: usize,
    pub by_category: HashMap<LicenseCategory, usize>,
    pub by_risk: HashMap<RiskLevel, usize>,
    pub by_family: HashMap<String, usize>,
    pub copyleft_count: usize,
    pub permissive_count: usize,
}

impl LicenseStats {
    pub fn from_licenses(licenses: &[&str]) -> Self {
        let mut stats = LicenseStats {
            total_licenses: licenses.len(),
            unique_licenses: 0,
            by_category: HashMap::new(),
            by_risk: HashMap::new(),
            by_family: HashMap::new(),
            copyleft_count: 0,
            permissive_count: 0,
        };

        let unique: HashSet<_> = licenses.iter().collect();
        stats.unique_licenses = unique.len();

        for license in unique {
            let info = LicenseInfo::from_spdx(license);

            *stats.by_category.entry(info.category).or_default() += 1;
            *stats.by_risk.entry(info.risk_level).or_default() += 1;
            *stats
                .by_family
                .entry(info.family.to_string())
                .or_default() += 1;

            match info.category {
                LicenseCategory::Permissive | LicenseCategory::PublicDomain => {
                    stats.permissive_count += 1;
                }
                LicenseCategory::WeakCopyleft
                | LicenseCategory::StrongCopyleft
                | LicenseCategory::NetworkCopyleft => {
                    stats.copyleft_count += 1;
                }
                _ => {}
            }
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx_parse_simple() {
        let expr = SpdxExpression::parse("MIT");
        assert_eq!(expr, SpdxExpression::License("MIT".to_string()));
    }

    #[test]
    fn test_spdx_parse_or() {
        let expr = SpdxExpression::parse("MIT OR Apache-2.0");
        assert!(matches!(expr, SpdxExpression::Or(_, _)));
        assert!(expr.is_choice());
    }

    #[test]
    fn test_spdx_parse_with() {
        let expr = SpdxExpression::parse("GPL-2.0 WITH Classpath-exception-2.0");
        assert!(matches!(expr, SpdxExpression::WithException { .. }));
    }

    #[test]
    fn test_license_category() {
        assert_eq!(
            LicenseInfo::from_spdx("MIT").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseInfo::from_spdx("GPL-3.0").category,
            LicenseCategory::StrongCopyleft
        );
        assert_eq!(
            LicenseInfo::from_spdx("LGPL-2.1").category,
            LicenseCategory::WeakCopyleft
        );
        assert_eq!(
            LicenseInfo::from_spdx("AGPL-3.0").category,
            LicenseCategory::NetworkCopyleft
        );
    }

    #[test]
    fn test_compatibility_mit_apache() {
        let result = check_compatibility("MIT", "Apache-2.0");
        assert!(result.compatible);
        assert!(result.score > 80);
    }

    #[test]
    fn test_compatibility_gpl_proprietary() {
        let result = check_compatibility("GPL-3.0", "Proprietary");
        assert!(!result.compatible);
        assert_eq!(result.score, 0);
    }
}
