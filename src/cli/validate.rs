//! Validate command handler.
//!
//! Implements the `validate` subcommand for validating SBOMs against compliance standards.

use crate::model::NormalizedSbom;
use crate::pipeline::{OutputTarget, exit_codes, parse_sbom_with_context, write_output};
use crate::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, StandardSelector, ViolationSeverity,
};
use crate::reports::escape::sanitize_line;
use crate::reports::{
    ReportFormat, SarifOptions, generate_compliance_json, generate_compliance_sarif_with,
};
use anyhow::Result;
use std::path::PathBuf;

/// Output formats the `validate` command has a real renderer for.
/// `auto`/`summary` render the plain-text report; everything else here is a
/// dedicated machine-readable emitter. All other [`ReportFormat`] values are
/// rejected up front instead of silently falling back to text.
pub const VALIDATE_OUTPUT_FORMATS: &[ReportFormat] = &[
    ReportFormat::Auto,
    ReportFormat::Summary,
    ReportFormat::Json,
    ReportFormat::Sarif,
    ReportFormat::OscalJson,
];

/// Layout of `validate -o json` (`--json-schema`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ValidateJsonSchema {
    /// Deprecated pre-0.4 layout, removed in v0.5.0: a bare result object
    /// for one standard, an array of them for several
    V1,
    /// The `sbom-tools/compliance/v2` envelope: one object for any number
    /// of standards
    #[default]
    V2,
}

/// Run the validate command, returning the desired exit code.
///
/// # Exit codes
/// - [`exit_codes::SUCCESS`] (0): compliant (no errors; no warnings when
///   `--fail-on-warning` is set). A standard that does not apply to the SBOM
///   counts as compliant unless `require_applicable` is set.
/// - [`exit_codes::COMPLIANCE_ERRORS`] (1): one or more compliance errors
///   found, or (with `require_applicable`) a standard did not apply
/// - [`exit_codes::COMPLIANCE_WARNINGS`] (2): warnings found with
///   `--fail-on-warning`
///
/// These gate codes only apply to runs that completed a validation. A
/// usage/configuration error surfaced from this function (unsupported output
/// format, invalid `--as-of` or `--cra-product-class`, broken explicit
/// sidecar) propagates as an `Err`, which the binary's `main()` maps to
/// [`exit_codes::ERROR`] (3) — the code clap's own argument-parse errors
/// exit with too, so exit 2 only ever means the warnings gate.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn run_validate(
    sbom_path: PathBuf,
    standards: Vec<StandardSelector>,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    fail_on_warning: bool,
    summary: bool,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
    as_of: Option<&str>,
    require_applicable: bool,
    json_schema: ValidateJsonSchema,
    sarif_base: Option<PathBuf>,
    sarif_category: Option<String>,
    sarif_include_passes: bool,
    sarif_max_results: usize,
) -> Result<i32> {
    // `--summary` overrides `--output` (documented on the flag), so the
    // requested format is never rendered and must not be gated.
    if !summary {
        super::ensure_output_format_supported("validate", output, VALIDATE_OUTPUT_FORMATS)?;
        super::check_sarif_flags(output, sarif_base.as_deref(), sarif_category.as_deref())?;
    }
    // Pinned evaluation clock for deadline-sensitive checks (shared parser
    // with `quality --as-of`).
    let as_of: Option<chrono::DateTime<chrono::Utc>> = as_of.map(super::parse_as_of).transpose()?;
    anyhow::ensure!(
        !standards.is_empty(),
        "no compliance standard selected; pass --standard (valid values: {})",
        StandardSelector::valid_values()
    );

    let parsed = parse_sbom_with_context(&sbom_path, false)?;

    // Load CRA sidecar — an explicit path is a hard error when broken,
    // otherwise auto-discover next to the SBOM (best-effort).
    let cra_sidecar = super::load_cra_sidecar(cra_sidecar_path.as_deref(), &sbom_path)?;

    // Resolve effective product class: sidecar wins; otherwise CLI flag.
    // An explicitly passed unrecognized class is a hard error (strict parse).
    // Mismatch between explicit CLI flag and sidecar is reported as a Warning
    // on stderr (not turned into a Violation — sidecar is authoritative).
    let cli_class = super::parse_cra_product_class(cra_product_class.as_deref())?;
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

    let mut results = Vec::new();

    for selector in &standards {
        let level = selector.level();
        let mut checker = ComplianceChecker::new(level);
        if let Some(now) = as_of {
            checker = checker.with_as_of(now);
        }
        // Sidecar metadata feeds the CRA family (manufacturer/disclosure/
        // lifecycle fields), EUCC (certificate references), and the AI Act
        // profile (the is_high_risk_ai flag escalates Annex IV findings).
        if matches!(
            level,
            ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::CraOssSteward
                | ComplianceLevel::EuccSubstantial
                | ComplianceLevel::EuAiAct
        ) && let Some(sc) = cra_sidecar.clone()
        {
            checker = checker.with_sidecar(sc);
        }
        // Product class drives severity calibration for the CRA phase checks.
        if matches!(
            level,
            ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2
        ) && let Some(c) = effective_class
        {
            checker = checker.with_product_class(c);
        }
        results.push(checker.check(parsed.sbom()));
    }

    // Inputs that make machine output reproducible: OSCAL derives its UUIDs
    // from the SBOM digest and stamps the --as-of instant. It also describes
    // the SBOM document and the components its findings are about.
    // SARIF results point at the SBOM lines of their components, and list
    // the passed checks only under --sarif-include-passes.
    let mut sarif = SarifOptions::new()
        .with_passes(sarif_include_passes)
        .with_max_results(sarif_max_results);
    if !summary && output == ReportFormat::Sarif {
        sarif = sarif.with_artifact(super::sarif_artifact(
            &sbom_path,
            sarif_base.as_deref(),
            parsed.sbom(),
            parsed.raw_content(),
        )?);
        if let Some(category) = sarif_category {
            sarif = sarif.with_category(category);
        }
    }
    let provenance = OutputProvenance {
        sbom: parsed.sbom(),
        sbom_digest: sha256_hex(parsed.raw_content.as_bytes()),
        as_of,
        sarif,
    };

    if !summary && output == ReportFormat::Json && json_schema == ValidateJsonSchema::V1 {
        tracing::warn!(
            "--json-schema v1 is deprecated and will be removed in v0.5.0; the default \
             v2 envelope is described in docs/compliance-output.md"
        );
    }

    if results.len() == 1 {
        let result = &results[0];
        if summary {
            write_compliance_summary(result, output_file)?;
        } else {
            write_compliance_output(result, output, output_file, &provenance, json_schema)?;
        }
    } else {
        // Multi-standard: merge results for output
        if summary {
            write_multi_compliance_summary(&results, output_file)?;
        } else {
            write_multi_compliance_output(&results, output, output_file, &provenance, json_schema)?;
        }
    }

    let has_errors = results.iter().any(|r| r.error_count > 0);
    let has_warnings = results.iter().any(|r| r.warning_count > 0);
    // `--require-applicable`: a standard that did not evaluate the SBOM is
    // a failed gate, not a pass.
    let not_applicable = require_applicable && results.iter().any(|r| !r.is_applicable());
    if has_errors || not_applicable {
        return Ok(exit_codes::COMPLIANCE_ERRORS);
    }
    if fail_on_warning && has_warnings {
        return Ok(exit_codes::COMPLIANCE_WARNINGS);
    }

    Ok(exit_codes::SUCCESS)
}

/// What a machine-readable report needs to know about the run itself.
struct OutputProvenance<'a> {
    /// The validated SBOM.
    sbom: &'a NormalizedSbom,
    /// Lowercase hex SHA-256 of the SBOM bytes as read.
    sbom_digest: String,
    /// The pinned evaluation instant (`--as-of`), if any.
    as_of: Option<chrono::DateTime<chrono::Utc>>,
    /// How `-o sarif` renders the results: the SBOM file they point into,
    /// their category and whether passed checks are listed.
    sarif: SarifOptions,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn write_compliance_output(
    result: &ComplianceResult,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    provenance: &OutputProvenance<'_>,
    json_schema: ValidateJsonSchema,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);

    let content = match output {
        ReportFormat::Json => match json_schema {
            ValidateJsonSchema::V2 => generate_compliance_json(std::slice::from_ref(result))?,
            ValidateJsonSchema::V1 => serde_json::to_string_pretty(&v1_result(result))
                .map_err(|e| anyhow::anyhow!("Failed to serialize compliance JSON: {e}"))?,
        },
        ReportFormat::Sarif => generate_compliance_sarif_with(result, &provenance.sarif)?,
        ReportFormat::OscalJson => crate::reports::oscal::generate_assessment_results_at(
            std::slice::from_ref(result),
            provenance.sbom,
            &provenance.sbom_digest,
            provenance.as_of,
        )?,
        _ => format_compliance_text(result),
    };

    write_output(&content, &target, false)?;
    Ok(())
}

/// `result` as the deprecated `--json-schema v1` layout prints it: the
/// result's own serialization without the passed checks, which that layout
/// predates. A passed check simply does not appear there (it used to be an
/// Info violation).
fn v1_result(result: &ComplianceResult) -> ComplianceResult {
    let mut v1 = result.clone();
    v1.passed.clear();
    v1
}

/// Compact summary for CI badge generation
#[derive(serde::Serialize)]
struct ComplianceSummary {
    standard: String,
    /// Whether the standard actually evaluated the SBOM. When false,
    /// `compliant` is the documented always-true N/A contract and `score`
    /// is null — dashboards must not read either as a pass.
    applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<String>,
    compliant: bool,
    score: Option<u8>,
    errors: usize,
    warnings: usize,
    info: usize,
}

fn compliance_summary(result: &ComplianceResult) -> ComplianceSummary {
    let not_applicable_reason = match &result.applicability {
        crate::quality::Applicability::NotApplicable(reason) => Some(reason.clone()),
        crate::quality::Applicability::Applicable => None,
    };
    ComplianceSummary {
        standard: result.level.name().to_string(),
        applicable: result.is_applicable(),
        not_applicable_reason,
        compliant: result.is_compliant,
        score: result.score(),
        errors: result.error_count,
        warnings: result.warning_count,
        info: result.info_count,
    }
}

fn write_compliance_summary(result: &ComplianceResult, output_file: Option<PathBuf>) -> Result<()> {
    let target = OutputTarget::from_option(output_file);
    let summary = compliance_summary(result);
    let content = serde_json::to_string(&summary)
        .map_err(|e| anyhow::anyhow!("Failed to serialize summary: {e}"))?;
    write_output(&content, &target, false)?;
    Ok(())
}

fn write_multi_compliance_output(
    results: &[ComplianceResult],
    output: ReportFormat,
    output_file: Option<PathBuf>,
    provenance: &OutputProvenance<'_>,
    json_schema: ValidateJsonSchema,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);

    let content = match output {
        ReportFormat::Json => match json_schema {
            ValidateJsonSchema::V2 => generate_compliance_json(results)?,
            ValidateJsonSchema::V1 => {
                let v1: Vec<ComplianceResult> = results.iter().map(v1_result).collect();
                serde_json::to_string_pretty(&v1)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize compliance JSON: {e}"))?
            }
        },
        ReportFormat::Sarif => {
            crate::reports::generate_multi_compliance_sarif_with(results, &provenance.sarif)?
        }
        ReportFormat::OscalJson => crate::reports::oscal::generate_assessment_results_at(
            results,
            provenance.sbom,
            &provenance.sbom_digest,
            provenance.as_of,
        )?,
        _ => {
            let mut parts = Vec::new();
            for result in results {
                parts.push(format_compliance_text(result));
            }
            parts.join("\n---\n\n")
        }
    };

    write_output(&content, &target, false)?;
    Ok(())
}

fn write_multi_compliance_summary(
    results: &[ComplianceResult],
    output_file: Option<PathBuf>,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);
    let summaries: Vec<ComplianceSummary> = results.iter().map(compliance_summary).collect();

    let content = serde_json::to_string(&summaries)
        .map_err(|e| anyhow::anyhow!("Failed to serialize multi-standard summary: {e}"))?;
    write_output(&content, &target, false)?;
    Ok(())
}

/// The "N checks passed" line under a result's status, when it passed any.
fn passed_checks_line(result: &ComplianceResult) -> Option<String> {
    match result.passed.len() {
        0 => None,
        1 => Some("1 check passed".to_string()),
        n => Some(format!("{n} checks passed")),
    }
}

/// Render a compliance result as plain text, one finding per three lines:
/// the finding, its message, and a `fix:` line with the remediation for the
/// SBOM's format.
///
/// Requirement, element, message and the N/A reason can carry SBOM-supplied
/// text (component names, versions, purls), so each passes through
/// [`sanitize_line`]: a crafted name must not be able to start a new line
/// (CI runners such as GitHub Actions parse a line beginning with `::error`
/// as a workflow command) or smuggle terminal escape or bidi sequences. The
/// remediation is sanitized too: a deserialized violation carries whatever
/// text its payload held.
fn format_compliance_text(result: &ComplianceResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Compliance ({})", result.level.name()));
    if let crate::quality::Applicability::NotApplicable(reason) = &result.applicability {
        lines.push(format!(
            "Status: NOT APPLICABLE — {}",
            sanitize_line(reason)
        ));
    } else {
        lines.push(format!(
            "Status: {} ({} errors, {} warnings, {} info)",
            if result.is_compliant {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            },
            result.error_count,
            result.warning_count,
            result.info_count
        ));
    }
    // Passed checks are no findings: a count, never a finding line.
    if let Some(passed) = passed_checks_line(result) {
        lines.push(passed);
    }
    lines.push(String::new());

    if result.violations.is_empty() {
        lines.push("No violations found.".to_string());
        return lines.join("\n");
    }

    for v in &result.violations {
        let severity = match v.severity {
            ViolationSeverity::Error => "ERROR",
            ViolationSeverity::Warning => "WARN",
            ViolationSeverity::Info => "INFO",
        };
        let element = v.element.as_deref().unwrap_or("-");
        lines.push(format!(
            "[{}] {} | {} | {}",
            severity,
            v.category.name(),
            sanitize_line(&v.requirement),
            sanitize_line(element)
        ));
        lines.push(format!("  {}", sanitize_line(&v.message)));
        lines.push(format!(
            "  fix: {}",
            sanitize_line(&v.remediation_guidance())
        ));
    }

    lines.join("\n")
}

/// Run the engine's NtiaMinimum check and print a compact PASSED/FAILED
/// summary. Used by `view --validate-ntia`; gating errors are listed, each
/// with a `fix:` line, and warnings go to the log.
pub fn print_ntia_validation(sbom: &NormalizedSbom) {
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(sbom);
    for v in result.violations_by_severity(ViolationSeverity::Warning) {
        tracing::warn!("{}", v.message);
    }
    if result.is_compliant {
        tracing::info!("SBOM passes NTIA minimum elements validation");
        println!("NTIA Validation: PASSED");
    } else {
        tracing::warn!("SBOM has {} NTIA validation errors", result.error_count);
        println!("NTIA Validation: FAILED");
        for v in result.violations_by_severity(ViolationSeverity::Error) {
            println!("  - {}", sanitize_line(&v.message));
            println!("    fix: {}", sanitize_line(&v.remediation_guidance()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_ntia_validation_does_not_panic_on_empty_sbom() {
        print_ntia_validation(&NormalizedSbom::default());
    }

    /// The text report counts passed checks under the status and lists none
    /// of them as a finding.
    #[test]
    fn text_counts_passed_checks_and_lists_no_pass() {
        let pass = |name: &str| crate::quality::PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: format!("'{name}' uses NIST-approved PQC algorithm (FIPS 203/204/205)"),
            element: Some(name.to_string()),
            component_id: Some(format!("crypto/algorithm/{name}")),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Vec::new(),
        };
        let result = ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new())
            .with_passed(vec![pass("ML-KEM-1024"), pass("ML-DSA-87")]);
        let text = format_compliance_text(&result);
        assert_eq!(
            text.lines().take(3).collect::<Vec<_>>(),
            [
                "Compliance (NIST PQC Readiness)",
                "Status: COMPLIANT (0 errors, 0 warnings, 0 info)",
                "2 checks passed",
            ],
            "{text}"
        );
        assert!(text.contains("No violations found."), "{text}");
        assert!(!text.contains("NIST-approved"), "no pass is listed: {text}");

        let none = ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new());
        assert!(!format_compliance_text(&none).contains("passed"));
        let one = none.with_passed(vec![pass("XMSS")]);
        assert!(format_compliance_text(&one).contains("\n1 check passed\n"));
    }

    #[test]
    fn rejects_unsupported_output_format_before_reading_sbom() {
        // html/markdown/etc. used to silently fall through to the text
        // renderer; they must now fail fast (before the SBOM is even read —
        // the path here does not exist).
        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
            ReportFormat::Ndjson,
            ReportFormat::Table,
            ReportFormat::SideBySide,
            ReportFormat::Tui,
        ] {
            let err = run_validate(
                PathBuf::from("/nonexistent/never-read.cdx.json"),
                vec![StandardSelector::Ntia],
                format,
                None,
                false,
                false,
                None,
                None,
                None,
                false,
                ValidateJsonSchema::V2,
                None,
                None,
                false,
                crate::reports::DEFAULT_SARIF_MAX_RESULTS,
            )
            .expect_err("unsupported format must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("not supported by `sbom-tools validate`"),
                "unexpected error for {format}: {msg}"
            );
            assert!(
                msg.contains("oscal-json") && msg.contains("sarif"),
                "error must list the supported formats: {msg}"
            );
        }
    }

    #[test]
    fn rejects_empty_standard_list() {
        let err = run_validate(
            PathBuf::from("/nonexistent/never-read.cdx.json"),
            Vec::new(),
            ReportFormat::Summary,
            None,
            false,
            false,
            None,
            None,
            None,
            false,
            ValidateJsonSchema::V2,
            None,
            None,
            false,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect_err("empty standard list must be rejected");
        assert!(err.to_string().contains("no compliance standard selected"));
    }

    #[test]
    fn summary_overrides_output_and_skips_the_format_gate() {
        // `--summary` is documented as "(overrides --output)", so a stray
        // `-o html` must not hard-error; the compact JSON summary is written.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let out = dir.path().join("summary.json");
        run_validate(
            sbom_path,
            vec![StandardSelector::Ntia],
            ReportFormat::Html, // rejected without --summary; ignored with it
            Some(out.clone()),
            false,
            true,
            None,
            None,
            None,
            false,
            ValidateJsonSchema::V2,
            None,
            None,
            false,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect("--summary must override -o html instead of hard-erroring");
        let content = std::fs::read_to_string(out).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(content.trim()).expect("compact summary JSON");
        assert!(json["standard"].is_string(), "summary JSON shape: {json}");
    }

    #[test]
    fn typod_cra_product_class_is_a_hard_error() {
        // Regression: `--cra-product-class critcal` used to be silently
        // dropped (scored as Default class), flipping the CRA verdict.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let err = run_validate(
            sbom_path,
            vec![StandardSelector::Cra],
            ReportFormat::Summary,
            None,
            false,
            true,
            None,
            Some("critcal".to_string()),
            None,
            false,
            ValidateJsonSchema::V2,
            None,
            None,
            false,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect_err("typo'd --cra-product-class must be a hard error");
        let msg = err.to_string();
        assert!(msg.contains("critcal"), "must name the bad value: {msg}");
        assert!(
            msg.contains("important-class-2") && msg.contains("critical"),
            "must list the valid values: {msg}"
        );
    }

    #[test]
    fn as_of_accepts_offsetless_datetime() {
        // Regression: "2027-01-01T00:00:00" used to fail with a misleading
        // "trailing input" error; it now parses as UTC.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        run_validate(
            sbom_path,
            vec![StandardSelector::Cra],
            ReportFormat::Summary,
            Some(dir.path().join("out.json")),
            false,
            true,
            None,
            None,
            Some("2027-01-01T00:00:00"),
            false,
            ValidateJsonSchema::V2,
            None,
            None,
            false,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect("offset-less --as-of datetime must parse (assumed UTC)");
    }

    #[test]
    fn explicit_missing_sidecar_is_a_hard_error() {
        // Regression guard for the loader contract: an explicitly passed
        // sidecar path that cannot be loaded must abort validation.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let err = run_validate(
            sbom_path,
            vec![StandardSelector::Cra],
            ReportFormat::Summary,
            None,
            false,
            true,
            Some(dir.path().join("missing.cra.json")),
            None,
            None,
            false,
            ValidateJsonSchema::V2,
            None,
            None,
            false,
            crate::reports::DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect_err("broken explicit sidecar must be a hard error");
        assert!(err.to_string().contains("Failed to load CRA sidecar"));
    }
}
