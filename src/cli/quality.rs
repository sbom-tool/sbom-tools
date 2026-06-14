//! Quality command handler.
//!
//! Implements the `quality` subcommand for assessing SBOM quality.

use crate::config::EnrichmentConfig;
use crate::pipeline::{OutputTarget, exit_codes, parse_sbom_with_context, write_output};
use crate::quality::{
    QualityGrade, QualityReport, QualityScorer, ScoringProfile, ViolationSeverity,
};
use crate::reports::ReportFormat;
use anyhow::{Result, bail};
use serde_json::json;
use std::path::PathBuf;

/// Quality command configuration
pub struct QualityConfig {
    pub sbom_path: PathBuf,
    pub profile: String,
    pub output: ReportFormat,
    pub output_file: Option<PathBuf>,
    pub show_recommendations: bool,
    pub show_metrics: bool,
    pub min_score: Option<f32>,
    pub no_color: bool,
    /// Optional CRA sidecar metadata path (auto-discovered next to the SBOM
    /// when None). Supplements the embedded compliance check used by the
    /// `cra` scoring profile.
    pub cra_sidecar_path: Option<PathBuf>,
    /// CRA Annex III/IV product class (CLI string form). Sidecar value wins.
    pub cra_product_class: Option<String>,
    /// Enrichment configuration (OSV / KEV / EOL / staleness / VEX). When any
    /// source is enabled the SBOM is enriched before scoring so the
    /// Lifecycle / `VulnDocs` categories reflect live data.
    pub enrichment: EnrichmentConfig,
}

/// Run the quality command, returning the desired exit code.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::too_many_arguments)]
pub fn run_quality(
    sbom_path: PathBuf,
    profile_name: String,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    show_recommendations: bool,
    show_metrics: bool,
    min_score: Option<f32>,
    no_color: bool,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
    enrichment: EnrichmentConfig,
) -> Result<i32> {
    let config = QualityConfig {
        sbom_path,
        profile: profile_name,
        output,
        output_file,
        show_recommendations,
        show_metrics,
        min_score,
        no_color,
        cra_sidecar_path,
        cra_product_class,
        enrichment,
    };

    run_quality_impl(config)
}

fn run_quality_impl(config: QualityConfig) -> Result<i32> {
    #[cfg_attr(not(feature = "enrichment"), allow(unused_mut))]
    let mut parsed = parse_sbom_with_context(&config.sbom_path, false)?;

    // Enrich before scoring so Lifecycle (staleness/EOL) and VulnDocs (OSV/KEV)
    // categories reflect live data rather than only the static SBOM contents.
    #[cfg(feature = "enrichment")]
    {
        let any_enrichment = config.enrichment.enabled
            || config.enrichment.enable_eol
            || config.enrichment.enable_kev
            || config.enrichment.enable_epss
            || config.enrichment.enable_staleness
            || config.enrichment.enable_huggingface
            || !config.enrichment.vex_paths.is_empty();
        if any_enrichment {
            let stats =
                crate::pipeline::enrich_sbom_full(parsed.sbom_mut(), &config.enrichment, false);
            for warning in &stats.warnings {
                tracing::warn!("{warning}");
            }
        }
    }

    // Parse scoring profile
    let profile = parse_scoring_profile(&config.profile)?;

    tracing::info!("Running quality assessment with {:?} profile", profile);

    // Honour explicit --cra-sidecar; otherwise auto-discover.
    let sidecar = match &config.cra_sidecar_path {
        Some(p) => crate::model::CraSidecarMetadata::from_file(p).ok(),
        None => crate::model::CraSidecarMetadata::find_for_sbom(&config.sbom_path),
    };
    let cli_class = config
        .cra_product_class
        .as_deref()
        .and_then(crate::model::CraProductClass::parse_cli);
    let sidecar_class = sidecar.as_ref().and_then(|s| s.product_class);
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

    let mut scorer = QualityScorer::new(profile);
    if let Some(sc) = sidecar {
        scorer = scorer.with_cra_sidecar(sc);
    }
    if let Some(c) = effective_class {
        scorer = scorer.with_cra_product_class(c);
    }
    let report = scorer.score(parsed.sbom());

    // Build output based on format
    let output_text = match config.output {
        ReportFormat::Json => format_quality_json(&report, &config),
        ReportFormat::Sarif => format_quality_sarif(&report, &config),
        _ => format_quality_report(&report, &config),
    };

    // Write output
    let output_target = OutputTarget::from_option(config.output_file);
    write_output(&output_text, &output_target, false)?;

    // Check minimum score threshold. An N/A AI-readiness report (no ML components)
    // has no meaningful score, so it must not trip the threshold gate.
    let ai_not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);
    if let Some(threshold) = config.min_score
        && !ai_not_applicable
        && report.overall_score < threshold
    {
        tracing::error!(
            "Quality score {:.1} is below minimum threshold {:.1}",
            report.overall_score,
            threshold
        );
        return Ok(exit_codes::QUALITY_BELOW_THRESHOLD);
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
        "bsi" | "tr-03183" | "tr03183" | "bsi-tr-03183-2" => Ok(ScoringProfile::BsiTr03183_2),
        "comprehensive" | "full" => Ok(ScoringProfile::Comprehensive),
        "cbom" | "cryptographic" => Ok(ScoringProfile::Cbom),
        "ai-readiness" | "ai_readiness" => Ok(ScoringProfile::AiReadiness),
        _ => {
            bail!(
                "Unknown scoring profile: {profile_name}. Valid options: minimal, standard, security, license-compliance, cra, bsi, comprehensive, cbom, ai-readiness"
            );
        }
    }
}

/// Format quality report as JSON
fn format_quality_json(report: &QualityReport, config: &QualityConfig) -> String {
    let not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);

    // Serialize the report, then for an N/A AI-readiness result replace the
    // overall_score/grade so machine consumers don't read a 0.0 / "F" as a real
    // failing score (the standard 8-category pipeline did not run).
    let mut report_value = serde_json::to_value(report).unwrap_or_default();
    if not_applicable && let Some(obj) = report_value.as_object_mut() {
        obj.insert("overall_score".to_string(), serde_json::Value::Null);
        obj.insert(
            "grade".to_string(),
            serde_json::Value::String("N/A".to_string()),
        );
    }

    let output = json!({
        "tool": "sbom-tools",
        "version": env!("CARGO_PKG_VERSION"),
        "sbom": config.sbom_path.file_name().unwrap_or_default().to_string_lossy(),
        "profile": config.profile,
        "applicable": !not_applicable,
        "report": report_value,
    });
    serde_json::to_string_pretty(&output).unwrap_or_default()
}

/// Format quality report as SARIF 2.1.0
fn format_quality_sarif(report: &QualityReport, config: &QualityConfig) -> String {
    // AI-readiness uses a dedicated SBOM-AIBOM-* SARIF rule family (one result per
    // failing model-card check), with a rule table and run-level properties.
    if report.profile == ScoringProfile::AiReadiness
        && let Some(metrics) = report.ai_readiness_metrics.as_ref()
    {
        let na = metrics.is_not_applicable();
        let score = if na { None } else { Some(report.overall_score) };
        let grade = if na { "N/A" } else { report.grade.letter() };
        return crate::reports::generate_ai_readiness_sarif(
            metrics,
            &config
                .sbom_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            &config.profile,
            score,
            grade,
        )
        .unwrap_or_else(|_| {
            serde_json::to_string_pretty(&serde_json::json!({ "runs": [] })).unwrap_or_default()
        });
    }

    let not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);
    let mut results = Vec::new();

    // Add compliance violations as SARIF results
    for violation in &report.compliance.violations {
        let level = match violation.severity {
            ViolationSeverity::Error => "error",
            ViolationSeverity::Warning => "warning",
            ViolationSeverity::Info => "note",
        };
        results.push(json!({
            "ruleId": format!("QUALITY-{}", violation.category.name().to_uppercase().replace(' ', "-")),
            "level": level,
            "message": { "text": violation.message },
            "properties": {
                "requirement": violation.requirement,
                "category": violation.category.name(),
                "remediation": violation.remediation_guidance(),
                "element": violation.element,
            }
        }));
    }

    // Add recommendations as informational results
    for rec in &report.recommendations {
        let level = match rec.priority {
            1 => "error",
            2 => "warning",
            _ => "note",
        };
        results.push(json!({
            "ruleId": format!("QUALITY-REC-{}", rec.category.name().to_uppercase().replace(' ', "-")),
            "level": level,
            "message": {
                "text": format!("{} ({} affected, +{:.1} impact)", rec.message, rec.affected_count, rec.impact)
            },
            "properties": {
                "priority": rec.priority,
                "category": rec.category.name(),
                "affected_count": rec.affected_count,
                "impact": rec.impact,
            }
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sbom-tools",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/anthropics/sbom-tools",
                }
            },
            "results": results,
            "properties": {
                "sbom": config.sbom_path.file_name().unwrap_or_default().to_string_lossy(),
                "profile": config.profile,
                "applicable": !not_applicable,
                "overall_score": if not_applicable { serde_json::Value::Null } else { json!(report.overall_score) },
                "grade": if not_applicable { "N/A" } else { report.grade.letter() },
                "compliant": report.compliance.is_compliant,
            }
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Format quality report for output
fn format_quality_report(report: &QualityReport, config: &QualityConfig) -> String {
    let mut lines = Vec::new();
    let use_color = !config.no_color && std::env::var("NO_COLOR").is_err();

    // AI-readiness uses a dedicated report layout (per-check pass/fail, not the
    // standard 8 category scores).
    if report.profile == ScoringProfile::AiReadiness {
        return format_ai_readiness_report(report, config, use_color);
    }

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
    lines.push(format!(
        "  Licenses:        {:.1}/100",
        report.license_score
    ));
    lines.push(match report.vulnerability_score {
        Some(score) => format!("  Vulnerabilities: {score:.1}/100"),
        None => "  Vulnerabilities: N/A".to_string(),
    });
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
        // Software complexity index
        if let Some(simplicity) = report.dependency_metrics.software_complexity_index {
            let level = report
                .dependency_metrics
                .complexity_level
                .as_ref()
                .map_or("N/A", |l| l.label());
            lines.push(format!("    Complexity:     {simplicity:.0}/100 ({level})"));
            if let Some(ref f) = report.dependency_metrics.complexity_factors {
                lines.push(format!(
                    "      Volume: {:.2}  Depth: {:.2}  Fanout: {:.2}  Cycles: {:.2}  Fragmentation: {:.2}",
                    f.dependency_volume, f.normalized_depth, f.fanout_concentration, f.cycle_ratio, f.fragmentation
                ));
            }
        } else {
            lines.push("    Complexity:     N/A (graph analysis skipped)".to_string());
        }
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

/// Render the AI-readiness profile as a per-check pass/fail report.
fn format_ai_readiness_report(
    report: &QualityReport,
    config: &QualityConfig,
    use_color: bool,
) -> String {
    let mut lines = Vec::new();
    let Some(metrics) = report.ai_readiness_metrics.as_ref() else {
        return String::new();
    };
    let reset = if use_color { "\x1b[0m" } else { "" };

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

    if metrics.is_not_applicable() {
        let muted = if use_color { "\x1b[33m" } else { "" };
        lines.push(format!("Overall Score: {muted}N/A{reset}"));
        lines.push(
            metrics
                .na_reason
                .clone()
                .unwrap_or_else(|| "AI readiness is not applicable for this SBOM".to_string()),
        );
        return lines.join("\n");
    }

    let grade_color = if use_color {
        match report.grade {
            QualityGrade::A | QualityGrade::B => "\x1b[32m",
            QualityGrade::C | QualityGrade::D => "\x1b[33m",
            QualityGrade::F => "\x1b[31m",
        }
    } else {
        ""
    };
    lines.push(format!(
        "Overall Score: {}{:.1}/100 (Grade: {}){}",
        grade_color,
        report.overall_score,
        report.grade.letter(),
        reset
    ));
    lines.push(format!(
        "ML Components: {} total, {} fully documented",
        metrics.ml_component_count, metrics.components_fully_documented
    ));
    lines.push(String::new());
    lines.push("AI Readiness Checks:".to_string());

    for check in &metrics.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        let status_color = if use_color {
            if check.passed { "\x1b[32m" } else { "\x1b[31m" }
        } else {
            ""
        };
        lines.push(format!(
            "  {}{}{} {} ({:.0}%)",
            status_color,
            status,
            reset,
            check.id,
            check.weight * 100.0
        ));
        lines.push(format!("    {}", check.name));
        if config.show_metrics
            && let Some(detail) = &check.detail
        {
            lines.push(format!("    {detail}"));
        }
    }
    lines.push(String::new());

    if config.show_recommendations && !report.recommendations.is_empty() {
        lines.push("Recommendations:".to_string());
        for rec in report.recommendations.iter().take(10) {
            lines.push(format!(
                "  [P{}] {} ({} affected, +{:.1} impact)",
                rec.priority, rec.message, rec.affected_count, rec.impact
            ));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, ComponentType, DocumentMetadata, MlModelInfo, NormalizedSbom};

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
        assert!(matches!(
            parse_scoring_profile("ai-readiness").unwrap(),
            ScoringProfile::AiReadiness
        ));
    }

    fn ai_config(output: ReportFormat, min_score: Option<f32>) -> QualityConfig {
        QualityConfig {
            sbom_path: PathBuf::from("model.cdx.json"),
            profile: "ai-readiness".to_string(),
            output,
            output_file: None,
            show_recommendations: true,
            show_metrics: true,
            min_score,
            no_color: true,
            cra_sidecar_path: None,
            cra_product_class: None,
            enrichment: EnrichmentConfig::default(),
        }
    }

    fn fully_documented_ml_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut component = Component::new("bert-base".to_string(), "ml-model-1".to_string())
            .with_version("1.0.0".to_string());
        component.component_type = ComponentType::MachineLearningModel;
        component.ml_model = Some(MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            training_datasets: vec![crate::model::DatasetRef {
                reference: None,
                name: Some("dataset".to_string()),
                purl: None,
            }],
            energy_kwh_training: Some(20.0),
            model_card_url: Some("https://example.test/model-card".to_string()),
            limitations: Some("Only validated for English text".to_string()),
            ..MlModelInfo::default()
        });
        // A weight hash satisfies the AI-010 integrity check.
        component.hashes.push(crate::model::Hash::new(
            crate::model::HashAlgorithm::Sha256,
            "d".repeat(64),
        ));
        component.extensions.raw = Some(json!({
            "mlModel": { "modelCard": {
                "quantitativeAnalysis": { "performanceMetrics": [{ "type": "accuracy", "value": 0.97 }] },
                "considerations": {
                    "fairnessConsiderations": ["Reviewed"],
                    "useCases": ["Classification"],
                    "ethicalConsiderations": ["Human review required"]
                }
            }}
        }));
        sbom.add_component(component);
        sbom
    }

    #[test]
    fn test_format_quality_report_ai_readiness_shows_checks() {
        let sbom = fully_documented_ml_sbom();
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let output = format_quality_report(&report, &ai_config(ReportFormat::Summary, None));
        assert!(output.contains("AI Readiness Checks:"));
        assert!(output.contains("PASS AI-001"));
        assert!(!output.contains("Category Scores:"));
    }

    #[test]
    fn test_format_quality_report_ai_readiness_na_shows_na() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let output = format_quality_report(&report, &ai_config(ReportFormat::Summary, Some(70.0)));
        assert!(output.contains("Overall Score: N/A"));
        assert!(output.contains("No machine-learning-model components found"));
    }

    #[test]
    fn test_format_quality_json_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = format_quality_json(&report, &ai_config(ReportFormat::Json, None));
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        // N/A must not serialize as a real 0.0 / "F" score.
        assert_eq!(value["applicable"], json!(false));
        assert!(value["report"]["overall_score"].is_null());
        assert_eq!(value["report"]["grade"], json!("N/A"));
    }

    #[test]
    fn test_format_quality_sarif_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = format_quality_sarif(&report, &ai_config(ReportFormat::Sarif, None));
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
        let run = &value["runs"][0];
        let props = &run["properties"];
        assert_eq!(props["applicable"], json!(false));
        assert!(props["overall_score"].is_null());
        assert_eq!(props["grade"], json!("N/A"));
        // The dedicated SBOM-AIBOM-* rule family is now emitted (was absent before),
        // and N/A yields no findings.
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert!(
            rules.iter().any(|r| r["id"] == json!("SBOM-AIBOM-001")),
            "expected SBOM-AIBOM rule table"
        );
        assert!(run["results"].as_array().expect("results array").is_empty());
    }
}
