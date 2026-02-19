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
pub fn run_view(config: ViewConfig) -> Result<i32> {
    let mut parsed = parse_sbom_with_context(&config.sbom_path, false)?;

    // Enrich with OSV vulnerability data if enabled
    #[cfg(feature = "enrichment")]
    let mut enrichment_warnings: Vec<&str> = Vec::new();

    #[cfg(feature = "enrichment")]
    if config.enrichment.enabled {
        let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
        if crate::pipeline::enrich_sbom(parsed.sbom_mut(), &osv_config, false).is_none() {
            enrichment_warnings.push("OSV vulnerability enrichment failed");
        }
    }

    // Enrich with end-of-life data if enabled
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_eol {
        let eol_config = crate::enrichment::EolClientConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        if crate::pipeline::enrich_eol(parsed.sbom_mut(), &eol_config, false).is_none() {
            enrichment_warnings.push("EOL enrichment failed");
        }
    }

    // Enrich with VEX data if VEX documents provided
    #[cfg(feature = "enrichment")]
    if !config.enrichment.vex_paths.is_empty()
        && crate::pipeline::enrich_vex(parsed.sbom_mut(), &config.enrichment.vex_paths, false).is_none()
    {
        enrichment_warnings.push("VEX enrichment failed");
    }

    // Warn if enrichment requested but feature not enabled
    #[cfg(not(feature = "enrichment"))]
    if config.enrichment.enabled || config.enrichment.enable_eol {
        eprintln!(
            "Warning: enrichment requested but the 'enrichment' feature is not enabled. \
             Rebuild with: cargo build --features enrichment"
        );
    }

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

    // Check for vulnerabilities before rendering (for --fail-on-vuln exit code)
    let vuln_count: usize = parsed
        .sbom()
        .components
        .values()
        .map(|c| c.vulnerabilities.len())
        .sum();

    if effective_output == ReportFormat::Tui {
        let (sbom, raw_content) = parsed.into_parts();
        let mut app = ViewApp::new(sbom, &raw_content);
        app.export_template = config.output.export_template.clone();

        // Show enrichment warnings in TUI footer
        #[cfg(feature = "enrichment")]
        if !enrichment_warnings.is_empty() {
            app.set_status_message(format!("Warning: {}", enrichment_warnings.join(", ")));
            app.status_sticky = true;
        }

        run_view_tui(&mut app)?;
    } else {
        parsed.drop_raw_content();
        output_view_report(&config, parsed.sbom(), &output_target)?;
    }

    if config.fail_on_vuln && vuln_count > 0 {
        return Ok(crate::pipeline::exit_codes::VULNS_INTRODUCED);
    }

    Ok(crate::pipeline::exit_codes::SUCCESS)
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
        report_types: vec![config.output.report_types],
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
                export_template: None,
            },
            validate_ntia: false,
            min_severity: None,
            vulnerable_only: false,
            ecosystem_filter: None,
            fail_on_vuln: false,
            enrichment: crate::config::EnrichmentConfig::default(),
        };

        let removed = apply_view_filters(&mut sbom, &config);
        assert_eq!(removed, 0);
    }
}
