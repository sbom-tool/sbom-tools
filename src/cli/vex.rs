//! VEX command handler.
//!
//! Implements the `vex` subcommand for standalone VEX operations:
//! - `vex apply` — Apply VEX documents to an SBOM
//! - `vex status` — Show VEX coverage summary
//! - `vex filter` — Filter vulnerabilities by VEX state

use crate::config::VexConfig;
use crate::model::{NormalizedSbom, VexState};
use crate::pipeline::{OutputTarget, exit_codes, write_output};
use crate::reports::escape::sanitize_line;
use anyhow::Result;

/// VEX action to perform.
#[derive(Debug, Clone)]
pub enum VexAction {
    /// Apply VEX documents to an SBOM and output enriched result
    Apply,
    /// Show VEX coverage summary for an SBOM
    Status,
    /// Filter vulnerabilities by VEX state
    Filter,
    /// Export the SBOM's VEX state as a CSAF v2.0 advisory
    /// (or other advisory format).
    Export(VexExportFormat),
}

/// Export format for `vex export`. CSAF v2.0 is the only one wired up
/// today; OpenVEX / CycloneDX VEX emit can be added later.
#[derive(Debug, Clone, Copy)]
pub enum VexExportFormat {
    Csaf,
}

/// Run the vex subcommand.
#[allow(clippy::needless_pass_by_value)]
pub fn run_vex(config: VexConfig, action: VexAction) -> Result<i32> {
    let quiet = config.quiet;
    let mut parsed = crate::pipeline::parse_sbom_with_context(&config.sbom_path, quiet)?;

    // Apply enrichment if configured
    #[cfg(feature = "enrichment")]
    {
        if config.enrichment.enabled {
            let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
            crate::pipeline::enrich_sbom(parsed.sbom_mut(), &osv_config, quiet);
        }
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
            crate::pipeline::enrich_eol(parsed.sbom_mut(), &eol_config, quiet);
        }
    }

    // Apply external VEX documents. A missing or malformed --vex document is
    // a hard error (exit 3): silently continuing would let CI believe the VEX
    // statements were applied when they were not.
    #[cfg(feature = "enrichment")]
    if !config.vex_paths.is_empty() {
        if !quiet {
            eprintln!(
                "Enriching SBOM with VEX data from {} document(s)...",
                config.vex_paths.len()
            );
        }
        let mut enricher = crate::enrichment::VexEnricher::from_files(&config.vex_paths)
            .map_err(|e| anyhow::anyhow!("failed to load VEX documents: {e}"))?;
        let stats = enricher.enrich_sbom(parsed.sbom_mut());
        if !quiet {
            eprintln!(
                "VEX enrichment: {} documents, {} statements, {} vulns matched, {} components",
                stats.documents_loaded,
                stats.statements_parsed,
                stats.vulns_matched,
                stats.components_with_vex,
            );
        }
    }

    // This flow calls the step-level enrichers directly (not
    // enrich_sbom_full), so refresh content hashes here too: enrichment
    // mutates vulnerability/VEX content after parse-time hashes were
    // computed, and Component.content_hash is a serialized field.
    #[cfg(feature = "enrichment")]
    if config.enrichment.enabled || config.enrichment.enable_eol || !config.vex_paths.is_empty() {
        let sbom = parsed.sbom_mut();
        for comp in sbom.components.values_mut() {
            comp.calculate_content_hash();
        }
        sbom.calculate_content_hash();
    }

    #[cfg(not(feature = "enrichment"))]
    {
        // --vex must not silently no-op: CI would believe the VEX documents
        // were applied. Hard error instead.
        if !config.vex_paths.is_empty() {
            anyhow::bail!(
                "--vex requires the 'enrichment' feature, which is not enabled in this build. \
                 Rebuild with: cargo build --features enrichment"
            );
        }
        // Warn if other enrichment was requested but the feature is not enabled
        if config.enrichment.enabled || config.enrichment.enable_eol {
            eprintln!(
                "Warning: enrichment requested but the 'enrichment' feature is not enabled. \
                 Rebuild with: cargo build --features enrichment"
            );
        }
    }

    match action {
        VexAction::Apply => run_vex_apply(parsed.sbom(), &config),
        VexAction::Status => run_vex_status(parsed.sbom(), &config),
        VexAction::Filter => run_vex_filter(parsed.sbom(), &config),
        VexAction::Export(format) => run_vex_export(parsed.sbom(), &config, format),
    }
}

/// Emit a CSAF v2.0 (or future) advisory document derived from the SBOM's
/// per-vulnerability VEX state.
fn run_vex_export(
    sbom: &NormalizedSbom,
    config: &VexConfig,
    format: VexExportFormat,
) -> Result<i32> {
    let output = match format {
        VexExportFormat::Csaf => {
            let opts = crate::reports::CsafEmitOptions::default();
            crate::reports::emit_csaf(sbom, &opts)
                .map_err(|e| anyhow::anyhow!("CSAF emit failed: {e}"))?
        }
    };
    let target = OutputTarget::from_option(config.output_file.clone());
    write_output(&output, &target, false)?;
    Ok(exit_codes::SUCCESS)
}

/// Apply VEX documents and output the enriched SBOM vulnerability data as JSON.
///
/// `--state` and `--actionable-only` restrict the emitted vulnerability list
/// (AND-composed); they do not affect the exit code here — `apply` is a
/// transformation, gating belongs to `filter`/`status`.
fn run_vex_apply(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let vulns = collect_all_vulns(sbom);
    let filtered = filter_entries(&vulns, config)?;
    let output = serde_json::to_string_pretty(&filtered)?;
    let target = OutputTarget::from_option(config.output_file.clone());
    write_output(&output, &target, false)?;
    Ok(exit_codes::SUCCESS)
}

/// Show VEX coverage summary.
///
/// `--state` restricts the report to vulnerabilities in that state ("none" =
/// vulnerabilities without a VEX statement). `--actionable-only` keeps its
/// documented gate semantics: exit code 1 when actionable vulnerabilities
/// exist (in the possibly state-filtered set).
fn run_vex_status(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let mut vulns = collect_all_vulns(sbom);
    if let Some(target_state) = parsed_state_filter(config)? {
        vulns.retain(|v| v.vex_state.as_ref() == target_state.as_ref());
    }
    let total = vulns.len();
    let with_vex = vulns.iter().filter(|v| v.vex_state.is_some()).count();
    let without_vex = total - with_vex;

    let mut by_state: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut actionable = 0;

    for v in &vulns {
        if let Some(ref state) = v.vex_state {
            *by_state.entry(state.to_string()).or_insert(0) += 1;
        }
        // Consistent with VulnerabilityDetail::is_vex_actionable — excludes NotAffected/Fixed
        if !matches!(
            v.vex_state,
            Some(VexState::NotAffected) | Some(VexState::Fixed)
        ) {
            actionable += 1;
        }
    }

    let coverage_pct = if total > 0 {
        (with_vex as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let output_target = OutputTarget::from_option(config.output_file.clone());

    let use_json = matches!(config.output_format, crate::reports::ReportFormat::Json)
        || (matches!(config.output_format, crate::reports::ReportFormat::Auto)
            && matches!(output_target, OutputTarget::File(_)));

    if use_json {
        // JSON output for piping
        let summary = serde_json::json!({
            "total_vulnerabilities": total,
            "with_vex": with_vex,
            "without_vex": without_vex,
            "actionable": actionable,
            "coverage_pct": (coverage_pct * 10.0).round() / 10.0,
            "by_state": by_state,
            "gaps": vulns.iter()
                .filter(|v| v.vex_state.is_none())
                .map(|v| serde_json::json!({
                    "id": v.id,
                    "severity": v.severity,
                    "component": v.component_name,
                    "version": v.version,
                }))
                .collect::<Vec<_>>(),
        });
        let output = serde_json::to_string_pretty(&summary)?;
        write_output(&output, &output_target, false)?;
    } else {
        // Table output — rendered into a buffer so `-O <file>` writes the
        // table to the file instead of losing it to stdout.
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "VEX Coverage Summary")?;
        writeln!(out, "====================")?;
        writeln!(out)?;
        writeln!(out, "Total vulnerabilities:  {total}")?;
        writeln!(out, "With VEX statement:     {with_vex}")?;
        writeln!(out, "Without VEX statement:  {without_vex}")?;
        writeln!(out, "Actionable:             {actionable}")?;
        writeln!(out, "Coverage:               {coverage_pct:.1}%")?;
        writeln!(out)?;

        if !by_state.is_empty() {
            writeln!(out, "By VEX State:")?;
            for (state, count) in &by_state {
                writeln!(out, "  {state:<20} {count}")?;
            }
            writeln!(out)?;
        }

        if without_vex > 0 {
            writeln!(out, "Gaps (vulnerabilities without VEX):")?;
            // SBOM text is sanitized: a line break or a leading `:` must
            // not let a vulnerability ID start an output line.
            for v in vulns.iter().filter(|v| v.vex_state.is_none()) {
                writeln!(
                    out,
                    "  {} [{}] — {} {}",
                    sanitize_line(&v.id),
                    sanitize_line(&v.severity),
                    sanitize_line(&v.component_name),
                    sanitize_line(v.version.as_deref().unwrap_or(""))
                )?;
            }
        }

        write_output(out.trim_end(), &output_target, config.quiet)?;
    }

    // Exit code 1 if actionable-only mode and actionable vulns exist
    if config.actionable_only && actionable > 0 {
        return Ok(exit_codes::CHANGES_DETECTED);
    }

    Ok(exit_codes::SUCCESS)
}

/// Filter vulnerabilities by VEX state.
///
/// `--actionable-only` and `--state` compose (AND): a vulnerability must
/// satisfy both filters to be kept.
fn run_vex_filter(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let vulns = collect_all_vulns(sbom);
    let filtered = filter_entries(&vulns, config)?;

    let output = serde_json::to_string_pretty(&filtered)?;
    let target = OutputTarget::from_option(config.output_file.clone());
    write_output(&output, &target, false)?;

    if !config.quiet {
        eprintln!(
            "Filtered: {} of {} vulnerabilities",
            filtered.len(),
            vulns.len()
        );
    }

    // Exit code 1 if actionable-only and any remain
    if config.actionable_only && !filtered.is_empty() {
        return Ok(exit_codes::CHANGES_DETECTED);
    }

    Ok(exit_codes::SUCCESS)
}

// ============================================================================
// Helpers
// ============================================================================

/// Simplified vulnerability entry for VEX command output.
#[derive(Debug, serde::Serialize)]
struct VulnEntry {
    id: String,
    severity: String,
    component_name: String,
    version: Option<String>,
    vex_state: Option<VexState>,
    vex_justification: Option<String>,
    vex_impact: Option<String>,
}

/// True when the vulnerability is actionable (not suppressed by a
/// `NotAffected`/`Fixed` VEX statement). Consistent with
/// `VulnerabilityDetail::is_vex_actionable`.
fn is_actionable(v: &VulnEntry) -> bool {
    !matches!(
        v.vex_state,
        Some(VexState::NotAffected) | Some(VexState::Fixed)
    )
}

/// Parse the optional `--state` flag. Outer `None` = flag absent; inner
/// `None` = "none"/"missing" (vulnerabilities without any VEX statement).
fn parsed_state_filter(config: &VexConfig) -> Result<Option<Option<VexState>>> {
    config
        .filter_state
        .as_deref()
        .map(parse_vex_state_filter)
        .transpose()
}

/// Apply the shared `--state` / `--actionable-only` filters (AND-composed).
fn filter_entries<'a>(vulns: &'a [VulnEntry], config: &VexConfig) -> Result<Vec<&'a VulnEntry>> {
    let state = parsed_state_filter(config)?;
    Ok(vulns
        .iter()
        .filter(|v| {
            (!config.actionable_only || is_actionable(v))
                && state
                    .as_ref()
                    .is_none_or(|target| v.vex_state.as_ref() == target.as_ref())
        })
        .collect())
}

/// Collect all vulnerabilities from an SBOM into a flat list.
fn collect_all_vulns(sbom: &NormalizedSbom) -> Vec<VulnEntry> {
    let mut entries = Vec::new();
    for comp in sbom.components.values() {
        for vuln in &comp.vulnerabilities {
            let vex_source = vuln.vex_status.as_ref().or(comp.vex_status.as_ref());
            entries.push(VulnEntry {
                id: vuln.id.clone(),
                severity: vuln
                    .severity
                    .as_ref()
                    .map_or_else(|| "Unknown".to_string(), |s| s.to_string()),
                component_name: comp.name.clone(),
                version: comp.version.clone(),
                vex_state: vex_source.map(|v| v.status.clone()),
                vex_justification: vex_source
                    .and_then(|v| v.justification.as_ref().map(|j| j.to_string())),
                vex_impact: vex_source.and_then(|v| v.impact_statement.clone()),
            });
        }
    }
    entries
}

/// Parse a VEX state filter string into `Option<VexState>`.
///
/// Returns `None` for "none"/"missing" (meaning: match vulns without VEX).
/// Returns `Err` for unrecognized values to prevent silent wrong results.
fn parse_vex_state_filter(s: &str) -> Result<Option<VexState>> {
    match s.to_lowercase().as_str() {
        "not_affected" | "notaffected" => Ok(Some(VexState::NotAffected)),
        "affected" => Ok(Some(VexState::Affected)),
        "fixed" => Ok(Some(VexState::Fixed)),
        "under_investigation" | "underinvestigation" | "in_triage" => {
            Ok(Some(VexState::UnderInvestigation))
        }
        "none" | "missing" => Ok(None),
        other => anyhow::bail!(
            "unknown VEX state filter: '{other}'. Valid values: \
             not_affected, affected, fixed, under_investigation, none"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vex_state_filter() {
        assert_eq!(
            parse_vex_state_filter("not_affected").unwrap(),
            Some(VexState::NotAffected)
        );
        assert_eq!(
            parse_vex_state_filter("affected").unwrap(),
            Some(VexState::Affected)
        );
        assert_eq!(
            parse_vex_state_filter("fixed").unwrap(),
            Some(VexState::Fixed)
        );
        assert_eq!(
            parse_vex_state_filter("under_investigation").unwrap(),
            Some(VexState::UnderInvestigation)
        );
        assert_eq!(parse_vex_state_filter("none").unwrap(), None);
    }

    #[test]
    fn test_parse_vex_state_filter_rejects_unknown() {
        assert!(parse_vex_state_filter("fixd").is_err());
        assert!(parse_vex_state_filter("notaffected_typo").is_err());
    }

    fn entry(id: &str, state: Option<VexState>) -> VulnEntry {
        VulnEntry {
            id: id.to_string(),
            severity: "High".to_string(),
            component_name: "comp".to_string(),
            version: Some("1.0".to_string()),
            vex_state: state,
            vex_justification: None,
            vex_impact: None,
        }
    }

    fn config_with(actionable_only: bool, state: Option<&str>) -> VexConfig {
        VexConfig {
            sbom_path: std::path::PathBuf::from("sbom.json"),
            vex_paths: Vec::new(),
            output_format: crate::reports::ReportFormat::Auto,
            output_file: None,
            quiet: true,
            actionable_only,
            filter_state: state.map(str::to_string),
            enrichment: crate::config::EnrichmentConfig::default(),
        }
    }

    fn sample_vulns() -> Vec<VulnEntry> {
        vec![
            entry("CVE-1", None),
            entry("CVE-2", Some(VexState::NotAffected)),
            entry("CVE-3", Some(VexState::Affected)),
            entry("CVE-4", Some(VexState::Fixed)),
            entry("CVE-5", Some(VexState::UnderInvestigation)),
        ]
    }

    #[test]
    fn filter_entries_no_flags_keeps_all() {
        let vulns = sample_vulns();
        let filtered = filter_entries(&vulns, &config_with(false, None)).unwrap();
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn filter_entries_actionable_only_excludes_not_affected_and_fixed() {
        let vulns = sample_vulns();
        let filtered = filter_entries(&vulns, &config_with(true, None)).unwrap();
        let ids: Vec<&str> = filtered.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-1", "CVE-3", "CVE-5"]);
    }

    #[test]
    fn filter_entries_state_filter_matches_state() {
        let vulns = sample_vulns();
        let filtered = filter_entries(&vulns, &config_with(false, Some("affected"))).unwrap();
        let ids: Vec<&str> = filtered.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-3"]);
    }

    #[test]
    fn filter_entries_state_none_matches_missing_vex() {
        let vulns = sample_vulns();
        let filtered = filter_entries(&vulns, &config_with(false, Some("none"))).unwrap();
        let ids: Vec<&str> = filtered.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-1"]);
    }

    #[test]
    fn filter_entries_actionable_and_state_compose_with_and() {
        let vulns = sample_vulns();
        // fixed is excluded by --actionable-only even though --state matches it
        let filtered = filter_entries(&vulns, &config_with(true, Some("fixed"))).unwrap();
        assert!(filtered.is_empty());

        // affected satisfies both filters
        let filtered = filter_entries(&vulns, &config_with(true, Some("affected"))).unwrap();
        let ids: Vec<&str> = filtered.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-3"]);
    }

    #[test]
    fn filter_entries_rejects_invalid_state() {
        let vulns = sample_vulns();
        assert!(filter_entries(&vulns, &config_with(false, Some("bogus"))).is_err());
    }
}
