//! Quality command handler.
//!
//! Implements the `quality` subcommand for assessing SBOM quality.

use crate::pipeline::{exit_codes, parse_sbom_with_context, write_output, OutputTarget};
use crate::quality::{QualityGrade, QualityReport, QualityScorer, ScoringProfile};
use crate::reports::ReportFormat;
use anyhow::{bail, Result};
use std::path::PathBuf;

/// Quality command configuration
pub struct QualityConfig {
    pub sbom_path: PathBuf,
    pub profile: String,
    #[allow(dead_code)] // Reserved for future JSON/SARIF output support
    pub output: ReportFormat,
    pub output_file: Option<PathBuf>,
    pub show_recommendations: bool,
    pub show_metrics: bool,
    pub min_score: Option<f32>,
    pub no_color: bool,
}

/// Run the quality command, returning the desired exit code.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::too_many_arguments)]
pub fn run_quality(
    sbom_path: PathBuf,
    profile_name: String,
    _output: ReportFormat,
    output_file: Option<PathBuf>,
    show_recommendations: bool,
    show_metrics: bool,
    min_score: Option<f32>,
    no_color: bool,
) -> Result<i32> {
    let config = QualityConfig {
        sbom_path,
        profile: profile_name,
        output: _output,
        output_file,
        show_recommendations,
        show_metrics,
        min_score,
        no_color,
    };

    run_quality_impl(config)
}

fn run_quality_impl(config: QualityConfig) -> Result<i32> {
    let parsed = parse_sbom_with_context(&config.sbom_path, false)?;

    // Parse scoring profile
    let profile = parse_scoring_profile(&config.profile)?;

    tracing::info!("Running quality assessment with {:?} profile", profile);

    let scorer = QualityScorer::new(profile);
    let report = scorer.score(parsed.sbom());

    // Build output
    let output_text = format_quality_report(&report, &config);

    // Write output
    let output_target = OutputTarget::from_option(config.output_file);
    write_output(&output_text, &output_target, false)?;

    // Check minimum score threshold
    if let Some(threshold) = config.min_score {
        if report.overall_score < threshold {
            tracing::error!(
                "Quality score {:.1} is below minimum threshold {:.1}",
                report.overall_score,
                threshold
            );
            return Ok(exit_codes::CHANGES_DETECTED);
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Parse scoring profile from string
fn parse_scoring_profile(profile_name: &str) -> Result<ScoringProfile> {
    match profile_name.to_lowercase().as_str() {
        "minimal" => Ok(ScoringProfile::Minimal),
        "standard" => Ok(ScoringProfile::Standard),
        "security" => Ok(ScoringProfile::Security),
        "license-compliance" | "license" => Ok(ScoringProfile::LicenseCompliance),
        "cra" | "cyber-resilience" => Ok(ScoringProfile::Cra),
        "comprehensive" | "full" => Ok(ScoringProfile::Comprehensive),
        _ => {
            bail!(
                "Unknown scoring profile: {profile_name}. Valid options: minimal, standard, security, license-compliance, cra, comprehensive"
            );
        }
    }
}

/// Format quality report for output
fn format_quality_report(report: &QualityReport, config: &QualityConfig) -> String {
    let mut lines = Vec::new();
    let use_color = !config.no_color && std::env::var("NO_COLOR").is_err();

    // Color codes
    let (grade_color, reset) = if use_color {
        let color = match report.grade {
            QualityGrade::A | QualityGrade::B => "\x1b[32m", // Green
            QualityGrade::C | QualityGrade::D => "\x1b[33m", // Yellow
            QualityGrade::F => "\x1b[31m",                   // Red
        };
        (color, "\x1b[0m")
    } else {
        ("", "")
    };

    // Header
    lines.push(format!(
        "SBOM Quality Report: {}",
        config
            .sbom_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ));
    lines.push(format!("Profile: {}", config.profile));
    lines.push(String::new());

    // Overall score
    lines.push(format!(
        "Overall Score: {}{:.1}/100 (Grade: {}){}",
        grade_color,
        report.overall_score,
        report.grade.letter(),
        reset
    ));
    lines.push(String::new());

    // Category scores
    lines.push("Category Scores:".to_string());
    lines.push(format!(
        "  Completeness:    {:.1}/100",
        report.completeness_score
    ));
    lines.push(format!(
        "  Identifiers:     {:.1}/100",
        report.identifier_score
    ));
    lines.push(format!("  Licenses:        {:.1}/100", report.license_score));
    lines.push(format!(
        "  Vulnerabilities: {:.1}/100",
        report.vulnerability_score
    ));
    lines.push(format!(
        "  Dependencies:    {:.1}/100",
        report.dependency_score
    ));
    lines.push(String::new());

    // Compliance status
    let compliance_status = if report.compliance.is_compliant {
        format!(
            "{}COMPLIANT{}",
            if use_color { "\x1b[32m" } else { "" },
            reset
        )
    } else {
        format!(
            "{}NON-COMPLIANT{}",
            if use_color { "\x1b[31m" } else { "" },
            reset
        )
    };
    lines.push(format!(
        "Compliance ({}): {} ({} errors, {} warnings)",
        report.compliance.level.name(),
        compliance_status,
        report.compliance.error_count,
        report.compliance.warning_count
    ));
    lines.push(String::new());

    // Detailed metrics
    if config.show_metrics {
        lines.push("Detailed Metrics:".to_string());
        lines.push(format!(
            "  Total Components: {}",
            report.completeness_metrics.total_components
        ));
        lines.push(format!(
            "  With Version:     {:.1}%",
            report.completeness_metrics.components_with_version
        ));
        lines.push(format!(
            "  With PURL:        {:.1}%",
            report.completeness_metrics.components_with_purl
        ));
        lines.push(format!(
            "  With License:     {:.1}%",
            report.completeness_metrics.components_with_licenses
        ));
        lines.push(format!(
            "  With Supplier:    {:.1}%",
            report.completeness_metrics.components_with_supplier
        ));
        lines.push(format!(
            "  With Hashes:      {:.1}%",
            report.completeness_metrics.components_with_hashes
        ));
        lines.push(String::new());

        lines.push("  Identifier Quality:".to_string());
        lines.push(format!(
            "    Valid PURLs:    {}",
            report.identifier_metrics.valid_purls
        ));
        lines.push(format!(
            "    Valid CPEs:     {}",
            report.identifier_metrics.valid_cpes
        ));
        lines.push(format!(
            "    Missing IDs:    {}",
            report.identifier_metrics.missing_all_identifiers
        ));
        lines.push(format!(
            "    Ecosystems:     {}",
            report.identifier_metrics.ecosystems.join(", ")
        ));
        lines.push(String::new());

        lines.push("  Dependency Graph:".to_string());
        lines.push(format!(
            "    Total Edges:    {}",
            report.dependency_metrics.total_dependencies
        ));
        lines.push(format!(
            "    Orphan Nodes:   {}",
            report.dependency_metrics.orphan_components
        ));
        lines.push(String::new());
    }

    // Recommendations
    if config.show_recommendations && !report.recommendations.is_empty() {
        lines.push("Recommendations:".to_string());
        for rec in report.recommendations.iter().take(10) {
            let priority_indicator = if use_color {
                match rec.priority {
                    1 => "\x1b[31m[P1]\x1b[0m",
                    2 => "\x1b[33m[P2]\x1b[0m",
                    3 => "\x1b[34m[P3]\x1b[0m",
                    _ => "[P4+]",
                }
            } else {
                match rec.priority {
                    1 => "[P1]",
                    2 => "[P2]",
                    3 => "[P3]",
                    _ => "[P4+]",
                }
            };
            lines.push(format!(
                "  {} {} ({} affected, +{:.1} impact)",
                priority_indicator, rec.message, rec.affected_count, rec.impact
            ));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scoring_profile() {
        assert!(matches!(
            parse_scoring_profile("minimal").unwrap(),
            ScoringProfile::Minimal
        ));
        assert!(matches!(
            parse_scoring_profile("standard").unwrap(),
            ScoringProfile::Standard
        ));
        assert!(matches!(
            parse_scoring_profile("security").unwrap(),
            ScoringProfile::Security
        ));
        assert!(matches!(
            parse_scoring_profile("license-compliance").unwrap(),
            ScoringProfile::LicenseCompliance
        ));
        assert!(matches!(
            parse_scoring_profile("cra").unwrap(),
            ScoringProfile::Cra
        ));
        assert!(matches!(
            parse_scoring_profile("comprehensive").unwrap(),
            ScoringProfile::Comprehensive
        ));
    }

    #[test]
    fn test_parse_scoring_profile_case_insensitive() {
        assert!(matches!(
            parse_scoring_profile("MINIMAL").unwrap(),
            ScoringProfile::Minimal
        ));
        assert!(matches!(
            parse_scoring_profile("Standard").unwrap(),
            ScoringProfile::Standard
        ));
    }

    #[test]
    fn test_parse_scoring_profile_invalid() {
        assert!(parse_scoring_profile("invalid").is_err());
    }

    #[test]
    fn test_parse_scoring_profile_aliases() {
        assert!(matches!(
            parse_scoring_profile("license").unwrap(),
            ScoringProfile::LicenseCompliance
        ));
        assert!(matches!(
            parse_scoring_profile("full").unwrap(),
            ScoringProfile::Comprehensive
        ));
        assert!(matches!(
            parse_scoring_profile("cyber-resilience").unwrap(),
            ScoringProfile::Cra
        ));
    }
}
