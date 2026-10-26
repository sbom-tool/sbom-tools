//! View command handler.
//!
//! Implements the `view` subcommand for viewing a single SBOM.

use crate::config::ViewConfig;
use crate::model::{BomProfile, NormalizedSbom, Severity};
use crate::pipeline::{
    OutputTarget, auto_detect_format, parse_sbom_with_context, should_use_color, write_output,
};
use crate::reports::{ReportConfig, ReportFormat, create_reporter_with_options};
use crate::tui::{ViewApp, run_view_tui};
use anyhow::Result;

/// Run the view command
#[allow(clippy::needless_pass_by_value)]
pub fn run_view(config: ViewConfig) -> Result<i32> {
    // `view` renders every format except OSCAL (which is compliance-
    // assessment output produced by `validate`); reject it up front instead
    // of silently emitting plain JSON.
    if config.output.format == ReportFormat::OscalJson {
        anyhow::bail!(
            "output format 'oscal-json' is not supported by `sbom-tools view`; \
             use `sbom-tools validate -o oscal-json` for OSCAL assessment results"
        );
    }
    // Same reasoning for the sbomqs comparison view: it is a `quality`
    // renderer, and falling through to the JSON reporter emitted ordinary
    // view JSON under a format the caller did not ask for.
    if config.output.format == ReportFormat::SbomqsJson {
        anyhow::bail!(
            "output format 'sbomqs-json' is not supported by `sbom-tools view`; \
             use `sbom-tools quality -o sbomqs-json` for sbomqs-comparable scores"
        );
    }

    super::check_sarif_base(config.output.format, config.output.sarif_base.as_deref())?;

    // Validate --severity before any parsing or (network) enrichment work so
    // a typo fails fast instead of after expensive I/O.
    if let Some(s) = config.min_severity.as_deref() {
        parse_severity(s)?;
    }

    // Resolve the CRA sidecar once for both the TUI and report paths: an
    // explicit --cra-sidecar that fails to load is a hard error; auto-
    // discovery next to the SBOM stays best-effort.
    let cra_sidecar =
        super::load_cra_sidecar(config.cra_sidecar_path.as_deref(), &config.sbom_path)?;

    // Resolve the effective CRA product class once for both paths as well
    // (the TUI branch used to silently drop the flag while the report path
    // applied it): sidecar wins; an explicitly passed unrecognized value is
    // a hard error.
    let cli_class = super::parse_cra_product_class(config.cra_product_class.as_deref())?;
    let sidecar_class = cra_sidecar.as_ref().and_then(|s| s.product_class);
    if let (Some(cli), Some(side)) = (cli_class, sidecar_class)
        && cli != side
    {
        tracing::warn!(
            "CRA product class mismatch: --cra-product-class={} but sidecar says {}; using sidecar.",
            cli.label(),
            side.label()
        );
    }
    let effective_class = sidecar_class.or(cli_class);

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

    // Enrich with CISA KEV catalog (flags actively exploited vulnerabilities)
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_kev {
        let mut kev_config = crate::enrichment::KevClientConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::kev_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        if let Some(ref url) = config.enrichment.kev_url {
            kev_config.kev_url = url.clone();
        }
        if crate::pipeline::enrich_kev(parsed.sbom_mut(), &kev_config, false).is_none() {
            enrichment_warnings.push("KEV enrichment failed");
        }
    }

    // Enrich with FIRST EPSS exploit-probability scores
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_epss {
        let mut epss_config = crate::enrichment::EpssClientConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::epss_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        if let Some(ref url) = config.enrichment.epss_url {
            epss_config.epss_url = url.clone();
        }
        if crate::pipeline::enrich_epss(parsed.sbom_mut(), &epss_config, false).is_none() {
            enrichment_warnings.push("EPSS enrichment failed");
        }
    }

    // Enrich with dependency staleness data
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_staleness {
        let staleness_config = crate::enrichment::RegistryConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::staleness_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        if crate::pipeline::enrich_staleness(parsed.sbom_mut(), &staleness_config, false).is_none()
        {
            enrichment_warnings.push("Staleness enrichment failed");
        }
    }

    // Enrich ML-model components with HuggingFace Hub data (weight hashes, task)
    #[cfg(feature = "enrichment")]
    if config.enrichment.enable_huggingface {
        let mut hf_config = crate::enrichment::HuggingFaceConfig {
            cache_dir: config
                .enrichment
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::huggingface_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
            bypass_cache: config.enrichment.bypass_cache,
            timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
            ..Default::default()
        };
        if let Some(ref url) = config.enrichment.huggingface_url {
            hf_config.api_url = url.clone();
        }
        if crate::pipeline::enrich_huggingface(parsed.sbom_mut(), &hf_config, false).is_none() {
            enrichment_warnings.push("HuggingFace enrichment failed");
        }
    }

    // Enrich with VEX data if VEX documents provided
    #[cfg(feature = "enrichment")]
    if !config.enrichment.vex_paths.is_empty()
        && crate::pipeline::enrich_vex(parsed.sbom_mut(), &config.enrichment.vex_paths, false)
            .is_none()
    {
        enrichment_warnings.push("VEX enrichment failed");
    }

    // Warn if enrichment requested but feature not enabled
    #[cfg(not(feature = "enrichment"))]
    if config.enrichment.enabled
        || config.enrichment.enable_eol
        || config.enrichment.enable_kev
        || config.enrichment.enable_epss
        || config.enrichment.enable_staleness
    {
        eprintln!(
            "Warning: enrichment requested but the 'enrichment' feature is not enabled. \
             Rebuild with: cargo build --features enrichment"
        );
    }

    // Count vulnerabilities BEFORE display filters are applied: the
    // --fail-on-vuln gate is documented as "if any vulnerabilities are
    // present in the SBOM", so display filters (--severity / --ecosystem /
    // --vulnerable-only) must not mask the exit code.
    let vuln_count: usize = parsed
        .sbom()
        .components
        .values()
        .map(|c| c.vulnerabilities.len())
        .sum();

    // Apply filters to SBOM
    let filtered_count = apply_view_filters(parsed.sbom_mut(), &config)?;
    if filtered_count > 0 {
        tracing::info!(
            "Filtered to {} components (removed {})",
            parsed.sbom().component_count(),
            filtered_count
        );
    }

    // Run NTIA validation if requested
    if config.validate_ntia {
        super::validate::print_ntia_validation(parsed.sbom());
    }

    // Output the result
    let output_target = OutputTarget::from_option(config.output.file.clone());
    let effective_output = auto_detect_format(config.output.format, &output_target);

    // Resolve BOM profile (CLI override or auto-detect)
    let bom_profile = config
        .bom_profile
        .unwrap_or_else(|| BomProfile::detect(parsed.sbom()));
    tracing::info!("BOM profile: {bom_profile}");

    if effective_output == ReportFormat::Tui {
        // The compliance tab's OSS-Steward / EUCC / Article 14 /
        // product-class checks render against the same sidecar metadata and
        // effective product class the CLI report path uses (both resolved
        // once at the top of `run_view`).
        let (sbom, raw_content) = parsed.into_parts();
        let mut app = ViewApp::new(sbom, &raw_content, bom_profile);
        if let Some(sc) = cra_sidecar.clone() {
            app = app.with_cra_sidecar(sc);
        }
        if let Some(c) = effective_class {
            app = app.with_cra_product_class(c);
        }
        app.export_template = config.output.export_template.clone();

        // Show enrichment warnings in TUI footer
        #[cfg(feature = "enrichment")]
        if !enrichment_warnings.is_empty() {
            app.set_status_message(format!("Warning: {}", enrichment_warnings.join(", ")));
            app.status_sticky = true;
        }

        run_view_tui(&mut app, config.output.no_color)?;
    } else {
        // SARIF results point at the SBOM lines of their components, found
        // in the text before it is dropped.
        let sarif_artifact = if effective_output == ReportFormat::Sarif {
            Some(super::sarif_artifact(
                &config.sbom_path,
                config.output.sarif_base.as_deref(),
                parsed.sbom(),
                parsed.raw_content(),
            )?)
        } else {
            None
        };
        parsed.drop_raw_content();
        output_view_report(
            &config,
            cra_sidecar,
            effective_class,
            parsed.sbom(),
            &output_target,
            sarif_artifact,
        )?;
    }

    if config.fail_on_vuln && vuln_count > 0 {
        return Ok(crate::pipeline::exit_codes::VULNS_INTRODUCED);
    }

    Ok(crate::pipeline::exit_codes::SUCCESS)
}

/// Apply view filters to the SBOM, returns number of components removed.
///
/// Errors if `--severity` carries an unrecognized value (which previously
/// disabled severity filtering silently).
pub fn apply_view_filters(sbom: &mut NormalizedSbom, config: &ViewConfig) -> Result<usize> {
    let original_count = sbom.component_count();

    // Parse minimum severity if provided (strict: unknown values hard-error)
    let min_severity = config
        .min_severity
        .as_deref()
        .map(parse_severity)
        .transpose()?;

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

    Ok(original_count - sbom.component_count())
}

/// Parse a `--severity` filter value strictly.
///
/// An unrecognized value used to map to [`Severity::Unknown`] (threshold
/// order 0), which silently disabled the filter entirely — `--severity
/// banana` behaved like no filter at all. It is now a hard error listing the
/// valid values.
fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => anyhow::bail!("invalid --severity '{s}'; valid values: critical, high, medium, low"),
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
    sidecar: Option<crate::model::CraSidecarMetadata>,
    effective_class: Option<crate::model::CraProductClass>,
    sbom: &NormalizedSbom,
    output_target: &OutputTarget,
    sarif_artifact: Option<crate::reports::SarifArtifact>,
) -> Result<()> {
    let effective_output = auto_detect_format(config.output.format, output_target);

    // Pre-compute CRA compliance once for reporters, using the sidecar and
    // effective product class resolved in `run_view` (explicit values
    // hard-error there; sidecar discovery is best-effort).
    let mut checker =
        crate::quality::ComplianceChecker::new(crate::quality::ComplianceLevel::CraPhase2);
    if let Some(sc) = sidecar {
        checker = checker.with_sidecar(sc);
    }
    if let Some(c) = effective_class {
        checker = checker.with_product_class(c);
    }
    let cra_result = checker.check(sbom);

    let report_config = ReportConfig {
        report_types: vec![config.output.report_types],
        metadata: crate::reports::ReportMetadata {
            old_sbom_path: Some(config.sbom_path.to_string_lossy().to_string()),
            ..Default::default()
        },
        view_cra_compliance: Some(cra_result),
        view_sarif_artifact: sarif_artifact,
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
        assert!(matches!(parse_severity("critical"), Ok(Severity::Critical)));
        assert!(matches!(parse_severity("HIGH"), Ok(Severity::High)));
        assert!(matches!(parse_severity("Medium"), Ok(Severity::Medium)));
        assert!(matches!(parse_severity("low"), Ok(Severity::Low)));
    }

    #[test]
    fn test_parse_severity_rejects_unknown() {
        // Regression: unknown values mapped to Severity::Unknown (order 0),
        // which passed every vulnerability and silently disabled the filter.
        for bad in ["banana", "unknown", "info", "none", ""] {
            let err = parse_severity(bad).expect_err("should reject");
            let msg = err.to_string();
            assert!(msg.contains("invalid --severity"), "message: {msg}");
            assert!(
                msg.contains("critical, high, medium, low"),
                "message should list valid values: {msg}"
            );
        }
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
        assert!(severity_meets_minimum(
            &Severity::Critical,
            &Severity::Medium
        ));
        assert!(severity_meets_minimum(&Severity::Critical, &Severity::High));
        assert!(severity_meets_minimum(
            &Severity::Critical,
            &Severity::Critical
        ));
    }

    fn test_view_config(min_severity: Option<&str>) -> ViewConfig {
        ViewConfig {
            sbom_path: std::path::PathBuf::from("test.json"),
            output: crate::config::OutputConfig {
                format: ReportFormat::Summary,
                file: None,
                report_types: crate::reports::ReportType::All,
                no_color: false,
                streaming: crate::config::StreamingConfig::default(),
                export_template: None,
                sarif_base: None,
            },
            validate_ntia: false,
            min_severity: min_severity.map(str::to_string),
            vulnerable_only: false,
            ecosystem_filter: None,
            fail_on_vuln: false,
            bom_profile: None,
            enrichment: crate::config::EnrichmentConfig::default(),
            cra_sidecar_path: None,
            cra_product_class: None,
        }
    }

    #[test]
    fn test_apply_view_filters_no_filters() {
        let mut sbom = NormalizedSbom::default();
        let config = test_view_config(None);

        let removed = apply_view_filters(&mut sbom, &config).expect("no filters should succeed");
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_apply_view_filters_invalid_severity_errors() {
        let mut sbom = NormalizedSbom::default();
        let config = test_view_config(Some("banana"));

        let err = apply_view_filters(&mut sbom, &config).expect_err("should reject");
        assert!(err.to_string().contains("invalid --severity"));
    }
}
