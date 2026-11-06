//! Quality command handler.
//!
//! Implements the `quality` subcommand for assessing SBOM quality.

use crate::config::EnrichmentConfig;
use crate::pipeline::{OutputTarget, exit_codes, parse_sbom_with_context, write_output};
use crate::quality::{QualityGrade, QualityReport, QualityScorer, ScoringProfile};
use crate::reports::ReportFormat;
use anyhow::Result;
use std::path::PathBuf;

/// Output formats the `quality` command has a real renderer for.
/// `auto`/`summary` render the plain-text report; JSON, SARIF, and
/// sbomqs-json are dedicated emitters. All other [`ReportFormat`] values are
/// rejected up front instead of silently falling back to text.
pub const QUALITY_OUTPUT_FORMATS: &[ReportFormat] = &[
    ReportFormat::Auto,
    ReportFormat::Summary,
    ReportFormat::Json,
    ReportFormat::Sarif,
    ReportFormat::SbomqsJson,
];

/// Quality command configuration
pub struct QualityConfig {
    pub sbom_path: PathBuf,
    pub profile: ScoringProfile,
    pub output: ReportFormat,
    pub output_file: Option<PathBuf>,
    pub show_recommendations: bool,
    pub show_metrics: bool,
    pub min_score: Option<f32>,
    /// Exit non-zero when the compliance verdict is non-compliant (opt-in;
    /// the default gate is `--min-score` only, so existing scripts are
    /// unaffected).
    pub fail_on_noncompliant: bool,
    pub no_color: bool,
    /// Optional CRA sidecar metadata path (auto-discovered next to the SBOM
    /// when None). Supplements the embedded compliance check used by the
    /// `cra` scoring profile.
    pub cra_sidecar_path: Option<PathBuf>,
    /// CRA Annex III/IV product class (CLI string form). Sidecar value wins.
    pub cra_product_class: Option<String>,
    /// Pinned evaluation clock (raw `--as-of` CLI form). Deadline-sensitive
    /// compliance checks embedded in the report (CRA Art. 14 readiness, SBOM
    /// age, EUCC certificate expiry) evaluate against this instant instead of
    /// the wall clock, mirroring `validate --as-of`.
    pub as_of: Option<String>,
    /// Enrichment configuration (OSV / KEV / EOL / staleness / VEX). When any
    /// source is enabled the SBOM is enriched before scoring so the
    /// Lifecycle / `VulnDocs` categories reflect live data.
    pub enrichment: EnrichmentConfig,
    /// Directory the SBOM path in `-o sarif` output is relative to
    /// (`--sarif-base`); the SBOM's repository root when `None`.
    pub sarif_base: Option<PathBuf>,
    /// Code-scanning category of `-o sarif` output (`--sarif-category`);
    /// `sbom-tools/quality/<profile>/` when `None`.
    pub sarif_category: Option<String>,
    /// The most results the `-o sarif` run keeps (`--sarif-max-results`;
    /// `0` keeps every result).
    pub sarif_max_results: usize,
    /// How the embedded compliance check judges quantum-vulnerable
    /// cryptography (`--pqc-mode`, `--pqc-profile`, `--cnsa-category`); the
    /// `cbom` profile's NIST PQC check reads it.
    pub pqc: super::PqcOptions,
    /// The rule settings and component scope of the embedded compliance
    /// check (`--rule`, `--include-excluded-scope`), applied as `validate`
    /// applies them.
    pub rules: super::RuleOptions,
}

/// Run the quality command, returning the desired exit code.
///
/// Gate codes (below-threshold / non-compliant) only apply to runs that
/// completed an assessment; usage/configuration errors propagate as `Err`,
/// which the binary's `main()` maps to process exit code 1.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::too_many_arguments)]
pub fn run_quality(
    sbom_path: PathBuf,
    profile: ScoringProfile,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    show_recommendations: bool,
    show_metrics: bool,
    min_score: Option<f32>,
    fail_on_noncompliant: bool,
    no_color: bool,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
    as_of: Option<String>,
    enrichment: EnrichmentConfig,
    sarif_base: Option<PathBuf>,
    sarif_category: Option<String>,
    sarif_max_results: usize,
    pqc: super::PqcOptions,
    rules: super::RuleOptions,
) -> Result<i32> {
    let config = QualityConfig {
        sbom_path,
        profile,
        output,
        output_file,
        show_recommendations,
        show_metrics,
        min_score,
        fail_on_noncompliant,
        no_color,
        cra_sidecar_path,
        cra_product_class,
        as_of,
        enrichment,
        sarif_base,
        sarif_category,
        sarif_max_results,
        pqc,
        rules,
    };

    run_quality_impl(config)
}

fn run_quality_impl(config: QualityConfig) -> Result<i32> {
    super::ensure_output_format_supported("quality", config.output, QUALITY_OUTPUT_FORMATS)?;
    super::check_sarif_flags(
        config.output,
        config.sarif_base.as_deref(),
        config.sarif_category.as_deref(),
    )?;

    // The embedded compliance check's inputs, resolved like `validate`'s
    // before the SBOM is read, so a bad value fails first: the pinned clock,
    // the product class, the CRA sidecar (explicit, else found next to the
    // SBOM), the PQC mode, the rule settings and the component scope.
    let compliance = super::compliance_run_config_for(
        &config.sbom_path,
        config.cra_sidecar_path.as_deref(),
        config.cra_product_class.as_deref(),
        config.as_of.as_deref(),
        config.pqc,
        &config.rules,
    )?;
    compliance.warn_on_unmatched_rules(
        &[config.profile.compliance_level()],
        "the profile's compliance checks",
    );

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

    let profile = config.profile;

    tracing::info!("Running quality assessment with {:?} profile", profile);

    let report = QualityScorer::new(profile)
        .with_compliance(compliance)
        .score(parsed.sbom());

    // sbomqs-compat table for the human summary. Computed straight from the
    // NormalizedSbom (plus the raw document text for file-format /
    // data-license detection) — deliberately NOT from `report`: the
    // 0-100 pipeline and the sbomqs 0-10 model are not convertible, and the
    // compat path must never read `QualityReport.overall_score`.
    // The AI-readiness profile has its own dedicated layout and skips it.
    let sbomqs_input = crate::reports::sbomqs_compat::SbomqsCompatInput {
        sbom: parsed.sbom(),
        file_name: &config.sbom_path.to_string_lossy(),
        raw_content: Some(parsed.raw_content()),
    };

    // Build output based on format
    let output_text = match config.output {
        // The C ABI's score-with-options call returns this same document.
        ReportFormat::Json => crate::reports::generate_quality_json(&report, &config.sbom_path)?,
        ReportFormat::Sarif => {
            // SARIF results point at the SBOM lines of their components.
            let artifact = super::sarif_artifact(
                &config.sbom_path,
                config.sarif_base.as_deref(),
                parsed.sbom(),
                parsed.raw_content(),
            )?;
            let mut options = crate::reports::SarifOptions::new()
                .with_artifact(artifact)
                .with_max_results(config.sarif_max_results);
            if let Some(category) = &config.sarif_category {
                options = options.with_category(category.clone());
            }
            format_quality_sarif(&report, &config, &options)
        }
        ReportFormat::SbomqsJson => crate::reports::sbomqs_compat::render_json(&sbomqs_input),
        _ => {
            let sbomqs_table = (config.profile != ScoringProfile::AiReadiness)
                .then(|| crate::reports::sbomqs_compat::render_summary_table(&sbomqs_input));
            format_quality_report(&report, &config, sbomqs_table.as_deref())
        }
    };

    // Write output
    let output_target = OutputTarget::from_option(config.output_file);
    write_output(&output_text, &output_target, false)?;

    // An N/A AI-readiness report (no ML components) has no meaningful score
    // and no rendered compliance verdict (text and SARIF both show "N/A"),
    // so NEITHER gate below may fire on it.
    let ai_not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);

    // Check minimum score threshold.
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

    // Opt-in: fail the command when the compliance verdict is non-compliant,
    // so the printed "NON-COMPLIANT" cannot be paired with a success exit.
    // Off by default, so `quality --min-score` keeps its score-only contract.
    // Guarded by the same applicability rules as the score gate: an N/A run
    // (AI-readiness without ML components, or a not-applicable compliance
    // standard) renders no verdict and must not flip the exit code.
    if config.fail_on_noncompliant
        && !ai_not_applicable
        && report.compliance.is_applicable()
        && !report.compliance.is_compliant
    {
        tracing::error!(
            "SBOM is non-compliant with {} ({} error(s))",
            report.compliance.level.name(),
            report.compliance.error_count
        );
        return Ok(exit_codes::COMPLIANCE_ERRORS);
    }

    Ok(exit_codes::SUCCESS)
}

/// Format quality report as SARIF 2.1.0
fn format_quality_sarif(
    report: &QualityReport,
    config: &QualityConfig,
    options: &crate::reports::SarifOptions,
) -> String {
    // AI-readiness uses a dedicated SBOM-AIBOM-* SARIF rule family (one result per
    // failing model-card check), with a rule table and run-level properties.
    if report.profile == ScoringProfile::AiReadiness
        && let Some(metrics) = report.ai_readiness_metrics.as_ref()
    {
        let na = metrics.is_not_applicable();
        let score = if na { None } else { Some(report.overall_score) };
        let grade = if na { "N/A" } else { report.grade.letter() };
        return crate::reports::generate_ai_readiness_sarif_with(
            metrics,
            &config
                .sbom_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            &config.profile.to_string(),
            score,
            grade,
            options,
        )
        .unwrap_or_else(|_| {
            serde_json::to_string_pretty(&serde_json::json!({ "runs": [] })).unwrap_or_default()
        });
    }

    // Everything else routes through the shared registry-driven SARIF layer:
    // the compliance violations carry the exact same external rule ids as
    // `validate -o sarif`, and recommendations are merged into the same run
    // as advisory (never `error`) results.
    crate::reports::generate_quality_sarif_with(
        report,
        &config
            .sbom_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        &config.profile.to_string(),
        options,
    )
    .unwrap_or_else(|_| {
        serde_json::to_string_pretty(&serde_json::json!({ "runs": [] })).unwrap_or_default()
    })
}

/// Format quality report for output.
///
/// `sbomqs_table` is the pre-rendered sbomqs-comparable score table (0-10),
/// appended verbatim at the end of the report. `None` for profiles with a
/// dedicated layout (AI-readiness) and for direct test callers.
fn format_quality_report(
    report: &QualityReport,
    config: &QualityConfig,
    sbomqs_table: Option<&str>,
) -> String {
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

    // Compact sbomqs-comparable table (0-10 scores recomputed per-feature
    // with sbomqs' formulas — never overall_score/10).
    if let Some(table) = sbomqs_table {
        lines.push(table.to_string());
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
    use serde_json::json;

    /// Contract test: every documented `--profile` spelling parses to the
    /// right profile through the single shared parser (clap uses the same
    /// name/alias table).
    #[test]
    fn every_documented_profile_alias_parses() {
        let table: &[(&str, ScoringProfile)] = &[
            ("minimal", ScoringProfile::Minimal),
            ("standard", ScoringProfile::Standard),
            ("security", ScoringProfile::Security),
            ("license-compliance", ScoringProfile::LicenseCompliance),
            ("license", ScoringProfile::LicenseCompliance),
            ("cra", ScoringProfile::Cra),
            ("cyber-resilience", ScoringProfile::Cra),
            ("bsi", ScoringProfile::BsiTr03183_2),
            ("tr-03183", ScoringProfile::BsiTr03183_2),
            ("tr03183", ScoringProfile::BsiTr03183_2),
            ("bsi-tr-03183-2", ScoringProfile::BsiTr03183_2),
            ("comprehensive", ScoringProfile::Comprehensive),
            ("full", ScoringProfile::Comprehensive),
            ("cbom", ScoringProfile::Cbom),
            ("cryptographic", ScoringProfile::Cbom),
            ("ai-readiness", ScoringProfile::AiReadiness),
            ("ai_readiness", ScoringProfile::AiReadiness),
        ];
        for (spelling, expected) in table {
            let parsed: ScoringProfile = spelling
                .parse()
                .unwrap_or_else(|e| panic!("'{spelling}' must parse: {e}"));
            assert_eq!(parsed, *expected, "'{spelling}' mapped to wrong profile");
        }
    }

    #[test]
    fn profile_parse_is_case_insensitive_and_rejects_unknown() {
        assert_eq!(
            "MINIMAL".parse::<ScoringProfile>().unwrap(),
            ScoringProfile::Minimal
        );
        assert_eq!(
            "Standard".parse::<ScoringProfile>().unwrap(),
            ScoringProfile::Standard
        );
        let err = "invalid".parse::<ScoringProfile>().unwrap_err();
        assert!(err.contains("Valid values"));
        assert!(err.contains("license-compliance"));
    }

    #[test]
    fn rejects_unsupported_output_format_before_reading_sbom() {
        // html/markdown/csv/oscal-json used to fall through to the text
        // renderer; they must now fail fast (before the SBOM is read — the
        // path here does not exist).
        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
            ReportFormat::OscalJson,
            ReportFormat::Ndjson,
            ReportFormat::Table,
            ReportFormat::SideBySide,
            ReportFormat::Tui,
        ] {
            let err = run_quality(
                PathBuf::from("/nonexistent/never-read.cdx.json"),
                ScoringProfile::Standard,
                format,
                None,
                false,
                false,
                None,
                false,
                true,
                None,
                None,
                None,
                EnrichmentConfig::default(),
                None,
                None,
                crate::reports::DEFAULT_SARIF_MAX_RESULTS,
                crate::cli::PqcOptions::default(),
                crate::cli::RuleOptions::default(),
            )
            .expect_err("unsupported format must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("not supported by `sbom-tools quality`"),
                "unexpected error for {format}: {msg}"
            );
            assert!(
                msg.contains("sarif") && msg.contains("json"),
                "error must list the supported formats: {msg}"
            );
        }
    }

    #[test]
    fn sbomqs_json_output_emits_sbomqs_shaped_report() {
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
                "components":[{"type":"library","name":"lodash","version":"4.17.21",
                               "purl":"pkg:npm/lodash@4.17.21"}]}"#,
        )
        .unwrap();
        let out_path = dir.path().join("out.json");
        let code = run_quality(
            sbom_path,
            ScoringProfile::Standard,
            ReportFormat::SbomqsJson,
            Some(out_path.clone()),
            false,
            false,
            None,
            false,
            true,
            None,
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect("sbomqs-json run must succeed");
        assert_eq!(code, exit_codes::SUCCESS);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .expect("sbomqs-json output must be valid JSON");
        // Exact sbomqs score-report shape, honest identity.
        assert!(value["run_id"].is_string());
        assert_eq!(value["creation_info"]["name"], "sbom-tools");
        let file = &value["files"][0];
        assert_eq!(file["spec"], "cyclonedx");
        assert_eq!(file["file_format"], "json");
        assert!(file["avg_score"].is_number());
        let scores = file["scores"].as_array().expect("scores array");
        assert_eq!(scores.len(), 23);
        assert!(
            scores
                .iter()
                .any(|s| s["feature"] == "comp_with_name" && s["score"] == 10.0)
        );
    }

    #[test]
    fn summary_report_appends_sbomqs_compat_table() {
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = write_minimal_sbom(dir.path());
        let out_path = dir.path().join("out.txt");
        let code = run_quality(
            sbom_path,
            ScoringProfile::Standard,
            ReportFormat::Summary,
            Some(out_path.clone()),
            false,
            false,
            None,
            false,
            true,
            None,
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect("summary run must succeed");
        assert_eq!(code, exit_codes::SUCCESS);
        let text = std::fs::read_to_string(&out_path).unwrap();
        assert!(text.contains("sbomqs-Comparable Scores"));
        assert!(text.contains("NTIA-minimum-elements"));
        assert!(
            text.contains("not convertible"),
            "table must carry the non-convertibility note"
        );
    }

    #[test]
    fn explicit_missing_sidecar_is_a_hard_error() {
        // An explicitly passed --cra-sidecar that fails to load used to be
        // silently ignored (`.ok()`); it must now abort the command.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let err = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Summary,
            None,
            false,
            false,
            None,
            false,
            true,
            Some(dir.path().join("missing.cra.json")),
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect_err("broken explicit sidecar must be a hard error");
        assert!(err.to_string().contains("Failed to load CRA sidecar"));
    }

    fn write_minimal_sbom(dir: &std::path::Path) -> PathBuf {
        let sbom_path = dir.join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        sbom_path
    }

    #[test]
    fn fail_on_noncompliant_does_not_fire_on_na_ai_readiness_run() {
        // Regression: an N/A AI-readiness run (no ML components) used to
        // exit 1 on the hidden Comprehensive-level compliance check that no
        // renderer ever displays. Both gates are armed here; neither may fire.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = write_minimal_sbom(dir.path());
        let code = run_quality(
            sbom_path,
            ScoringProfile::AiReadiness,
            ReportFormat::Summary,
            Some(dir.path().join("out.txt")),
            false,
            false,
            Some(70.0), // --min-score: must not fire on N/A either (P0 guard)
            true,       // --fail-on-noncompliant
            true,
            None,
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect("an N/A AI-readiness run must not error");
        assert_eq!(
            code,
            exit_codes::SUCCESS,
            "N/A AI-readiness run must exit 0 with --fail-on-noncompliant"
        );
    }

    #[test]
    fn fail_on_noncompliant_still_fires_on_applicable_noncompliant_run() {
        // The empty SBOM is genuinely non-compliant with the CRA profile's
        // embedded check, so the opt-in gate must still flip the exit code.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = write_minimal_sbom(dir.path());
        let code = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Summary,
            Some(dir.path().join("out.txt")),
            false,
            false,
            None,
            true, // --fail-on-noncompliant
            true,
            None,
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect("the run itself must succeed");
        assert_eq!(code, exit_codes::COMPLIANCE_ERRORS);
    }

    #[test]
    fn typod_cra_product_class_is_a_hard_error() {
        // Regression: a typo'd --cra-product-class was silently dropped,
        // scoring a critical-class product as Default.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = write_minimal_sbom(dir.path());
        let err = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Summary,
            None,
            false,
            false,
            None,
            false,
            true,
            None,
            Some("critcal".to_string()),
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect_err("typo'd --cra-product-class must be a hard error");
        let msg = err.to_string();
        assert!(msg.contains("critcal"), "must name the bad value: {msg}");
        assert!(
            msg.contains("critical"),
            "must list the valid values: {msg}"
        );
    }

    #[test]
    fn invalid_as_of_is_a_hard_error_before_reading_the_sbom() {
        let err = run_quality(
            PathBuf::from("/nonexistent/never-read.cdx.json"),
            ScoringProfile::Cra,
            ReportFormat::Summary,
            None,
            false,
            false,
            None,
            false,
            true,
            None,
            None,
            Some("not-a-date".to_string()),
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect_err("invalid --as-of must be rejected");
        assert!(err.to_string().contains("invalid --as-of"));
    }

    #[test]
    fn auto_discovered_broken_sidecar_hard_fails() {
        // A discovered-but-broken sidecar is a hard error, matching the
        // explicit --cra-sidecar contract: silently scoring without it would
        // shift the CRA verdict with only a stderr warning.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("app.cra.json"), "{ not json").unwrap();
        let err = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Json,
            Some(dir.path().join("out.json")),
            false,
            false,
            None,
            false,
            true,
            None,
            None,
            None,
            EnrichmentConfig::default(),
            None,
            None,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            crate::cli::PqcOptions::default(),
            crate::cli::RuleOptions::default(),
        )
        .expect_err("a discovered-but-broken sidecar must hard-error");
        assert!(
            err.to_string().contains("CRA sidecar"),
            "error must name the sidecar: {err}"
        );
    }

    fn ai_config(output: ReportFormat, min_score: Option<f32>) -> QualityConfig {
        QualityConfig {
            sbom_path: PathBuf::from("model.cdx.json"),
            profile: ScoringProfile::AiReadiness,
            output,
            output_file: None,
            show_recommendations: true,
            show_metrics: true,
            min_score,
            fail_on_noncompliant: false,
            no_color: true,
            cra_sidecar_path: None,
            cra_product_class: None,
            as_of: None,
            enrichment: EnrichmentConfig::default(),
            sarif_base: None,
            sarif_category: None,
            sarif_max_results: crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            pqc: crate::cli::PqcOptions::default(),
            rules: crate::cli::RuleOptions::default(),
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
        let output = format_quality_report(&report, &ai_config(ReportFormat::Summary, None), None);
        assert!(output.contains("AI Readiness Checks:"));
        assert!(output.contains("PASS AI-001"));
        assert!(!output.contains("Category Scores:"));
    }

    #[test]
    fn test_format_quality_report_ai_readiness_na_shows_na() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let output =
            format_quality_report(&report, &ai_config(ReportFormat::Summary, Some(70.0)), None);
        assert!(output.contains("Overall Score: N/A"));
        assert!(output.contains("No machine-learning-model components found"));
    }

    #[test]
    fn test_format_quality_json_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = crate::reports::generate_quality_json(
            &report,
            &ai_config(ReportFormat::Json, None).sbom_path,
        )
        .expect("renders");
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        // N/A must not serialize as a real 0.0 / "F" score.
        assert_eq!(value["applicable"], json!(false));
        assert!(value["report"]["overall_score"].is_null());
        assert_eq!(value["report"]["grade"], json!("N/A"));
    }

    #[test]
    fn test_format_quality_sarif_routes_compliance_through_registry_rule_ids() {
        // Non-AI profiles route through the shared SARIF layer: violations
        // carry registry SARIF rule ids (never invented QUALITY-* ids) and
        // every emitted ruleId has a reportingDescriptor.
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::Cra).score(&sbom);
        let mut config = ai_config(ReportFormat::Sarif, None);
        config.profile = ScoringProfile::Cra;
        let out = format_quality_sarif(&report, &config, &crate::reports::SarifOptions::new());
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
        let run = &value["runs"][0];
        let results = run["results"].as_array().expect("results array");
        assert!(!results.is_empty(), "empty SBOM must fire CRA violations");
        assert!(
            results.iter().all(|r| r["ruleId"]
                .as_str()
                .is_some_and(|id| id.starts_with("SBOM-"))),
            "quality SARIF must not invent QUALITY-* rule ids"
        );
        assert!(
            run["tool"]["driver"]["rules"]
                .as_array()
                .is_some_and(|rules| !rules.is_empty()),
            "quality SARIF must declare its rule catalogue"
        );
        assert_eq!(run["properties"]["compliant"], json!(false));
    }

    #[test]
    fn test_format_quality_sarif_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = format_quality_sarif(
            &report,
            &ai_config(ReportFormat::Sarif, None),
            &crate::reports::SarifOptions::new(),
        );
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
        let run = &value["runs"][0];
        let props = &run["properties"];
        assert_eq!(props["applicable"], json!(false));
        // The serialized key is camelCase and *omitted* for the unscored N/A
        // case — indexing `props["overall_score"]` would return Null for any
        // absent key, so assert on the real key's absence.
        assert!(
            props.get("overallScore").is_none(),
            "unscored N/A run must omit overallScore entirely"
        );
        assert!(
            props["notApplicableReason"]
                .as_str()
                .is_some_and(|r| r.contains("No machine-learning-model components")),
            "N/A run must carry the metrics' human-readable reason"
        );
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
