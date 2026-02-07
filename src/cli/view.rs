//! View command handler.
//!
//! Implements the `view` subcommand for viewing a single SBOM.

use crate::config::ViewConfig;
use crate::model::{NormalizedSbom, Severity};
use crate::pipeline::{
    auto_detect_format, parse_sbom_with_context, should_use_color, write_output, OutputTarget,
};
use crate::reports::{create_reporter_with_options, ReportConfig, ReportFormat};
use crate::tui::{run_view_tui, ViewApp};
use anyhow::Result;

/// Run the view command
#[allow(clippy::needless_pass_by_value)]
pub fn run_view(config: ViewConfig) -> Result<()> {
    let mut parsed = parse_sbom_with_context(&config.sbom_path, false)?;

    // Apply filters to SBOM
    let filtered_count = apply_view_filters(parsed.sbom_mut(), &config);
    if filtered_count > 0 {
        tracing::info!(
            "Filtered to {} components (removed {})",
            parsed.sbom().component_count(),
            filtered_count
        );
    }

    // Run NTIA validation if requested
    if config.validate_ntia {
        super::validate::validate_ntia_elements(parsed.sbom())?;
    }

    // Output the result
    let output_target = OutputTarget::from_option(config.output.file.clone());
    let effective_output = auto_detect_format(config.output.format, &output_target);

    if effective_output == ReportFormat::Tui {
        let (sbom, raw_content) = parsed.into_parts();
        let mut app = ViewApp::new(sbom, &raw_content);
        run_view_tui(&mut app)?;
    } else {
        parsed.drop_raw_content();
        output_view_report(&config, parsed.sbom(), &output_target)?;
    }

    Ok(())
}

/// Apply view filters to the SBOM, returns number of components removed
pub fn apply_view_filters(sbom: &mut NormalizedSbom, config: &ViewConfig) -> usize {
    let original_count = sbom.component_count();

    // Parse minimum severity if provided
    let min_severity = config
        .min_severity
        .as_ref()
        .map(|s| parse_severity(s));

    // Parse ecosystem filter if provided
    let ecosystem_filter = config.ecosystem_filter.as_ref().map(|e| e.to_lowercase());

    // Collect keys to remove
    let keys_to_remove: Vec<_> = sbom
        .components
        .iter()
        .filter_map(|(key, comp)| {
            // Check vulnerable_only filter
            if config.vulnerable_only && comp.vulnerabilities.is_empty() {
                return Some(key.clone());
            }

            // Check severity filter
            if let Some(min_sev) = &min_severity {
                let has_matching_vuln = comp.vulnerabilities.iter().any(|v| {
                    v.severity
                        .as_ref()
                        .is_some_and(|s| severity_meets_minimum(s, min_sev))
                });
                if !has_matching_vuln && !comp.vulnerabilities.is_empty() {
                    return Some(key.clone());
                }
                // If vulnerable_only is set and min_severity is set, only keep vulns meeting threshold
                if config.vulnerable_only && !has_matching_vuln {
                    return Some(key.clone());
                }
            }

            // Check ecosystem filter
            if let Some(eco_filter) = &ecosystem_filter {
                let comp_eco = comp
                    .ecosystem
                    .as_ref()
                    .map(|e| format!("{e:?}").to_lowercase())
                    .unwrap_or_default();
                if !comp_eco.contains(eco_filter) {
                    return Some(key.clone());
                }
            }

            None
        })
        .collect();

    // Remove filtered components
    for key in &keys_to_remove {
        sbom.components.shift_remove(key);
    }

    original_count - sbom.component_count()
}

/// Parse severity string into Severity enum
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Check if a severity meets the minimum threshold
pub fn severity_meets_minimum(severity: &Severity, minimum: &Severity) -> bool {
    let severity_order = |s: &Severity| match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info | Severity::None | Severity::Unknown => 0,
    };

    severity_order(severity) >= severity_order(minimum)
}

/// Output view report to file or stdout
fn output_view_report(
    config: &ViewConfig,
    sbom: &NormalizedSbom,
    output_target: &OutputTarget,
) -> Result<()> {
    let effective_output = auto_detect_format(config.output.format, output_target);

    // Pre-compute CRA compliance once for reporters
    let cra_result = crate::quality::ComplianceChecker::new(crate::quality::ComplianceLevel::CraPhase2)
        .check(sbom);

    let report_config = ReportConfig {
        metadata: crate::reports::ReportMetadata {
            old_sbom_path: Some(config.sbom_path.to_string_lossy().to_string()),
            ..Default::default()
        },
        view_cra_compliance: Some(cra_result),
        ..Default::default()
    };

    let use_color = should_use_color(config.output.no_color);
    let reporter = create_reporter_with_options(effective_output, use_color);
    let report = reporter.generate_view_report(sbom, &report_config)?;

    write_output(&report, output_target, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("critical"), Severity::Critical));
        assert!(matches!(parse_severity("HIGH"), Severity::High));
        assert!(matches!(parse_severity("Medium"), Severity::Medium));
        assert!(matches!(parse_severity("low"), Severity::Low));
        assert!(matches!(parse_severity("unknown"), Severity::Unknown));
        assert!(matches!(parse_severity("invalid"), Severity::Unknown));
    }

    #[test]
    fn test_severity_meets_minimum() {
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::High));
        assert!(severity_meets_minimum(&Severity::High, &Severity::High));
        assert!(!severity_meets_minimum(&Severity::Medium, &Severity::High));
        assert!(!severity_meets_minimum(&Severity::Low, &Severity::High));
    }

    #[test]
    fn test_severity_order() {
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::Low));
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::Medium));
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::High));
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::Critical));
    }

    #[test]
    fn test_apply_view_filters_no_filters() {
        let mut sbom = NormalizedSbom::default();
        let config = ViewConfig {
            sbom_path: std::path::PathBuf::from("test.json"),
            output: crate::config::OutputConfig {
                format: ReportFormat::Summary,
                file: None,
                report_types: crate::reports::ReportType::All,
                no_color: false,
                streaming: crate::config::StreamingConfig::default(),
            },
            validate_ntia: false,
            min_severity: None,
            vulnerable_only: false,
            ecosystem_filter: None,
        };

        let removed = apply_view_filters(&mut sbom, &config);
        assert_eq!(removed, 0);
    }
}
