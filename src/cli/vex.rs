//! VEX command handler.
//!
//! Implements the `vex` subcommand for standalone VEX operations:
//! - `vex apply` — Apply VEX documents to an SBOM
//! - `vex status` — Show VEX coverage summary
//! - `vex filter` — Filter vulnerabilities by VEX state

use crate::config::VexConfig;
use crate::model::{NormalizedSbom, VexState};
use crate::pipeline::{OutputTarget, exit_codes, write_output};
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

    // Apply external VEX documents
    #[cfg(feature = "enrichment")]
    if !config.vex_paths.is_empty() {
        let stats = crate::pipeline::enrich_vex(parsed.sbom_mut(), &config.vex_paths, quiet);
        if stats.is_none() && !quiet {
            eprintln!("Warning: VEX enrichment failed");
        }
    }

    // Warn if enrichment requested but feature not enabled
    #[cfg(not(feature = "enrichment"))]
    if config.enrichment.enabled || config.enrichment.enable_eol || !config.vex_paths.is_empty() {
        eprintln!(
            "Warning: enrichment requested but the 'enrichment' feature is not enabled. \
             Rebuild with: cargo build --features enrichment"
        );
    }

    match action {
        VexAction::Apply => run_vex_apply(parsed.sbom(), &config),
        VexAction::Status => run_vex_status(parsed.sbom(), &config),
        VexAction::Filter => run_vex_filter(parsed.sbom(), &config),
    }
}

/// Apply VEX documents and output the enriched SBOM vulnerability data as JSON.
fn run_vex_apply(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let vulns = collect_all_vulns(sbom);
    let output = serde_json::to_string_pretty(&vulns)?;
    let target = OutputTarget::from_option(config.output_file.clone());
    write_output(&output, &target, false)?;
    Ok(exit_codes::SUCCESS)
}

/// Show VEX coverage summary.
fn run_vex_status(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let vulns = collect_all_vulns(sbom);
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
        // Table output for terminal
        println!("VEX Coverage Summary");
        println!("====================");
        println!();
        println!("Total vulnerabilities:  {total}");
        println!("With VEX statement:     {with_vex}");
        println!("Without VEX statement:  {without_vex}");
        println!("Actionable:             {actionable}");
        println!("Coverage:               {coverage_pct:.1}%");
        println!();

        if !by_state.is_empty() {
            println!("By VEX State:");
            for (state, count) in &by_state {
                println!("  {state:<20} {count}");
            }
            println!();
        }

        if without_vex > 0 {
            println!("Gaps (vulnerabilities without VEX):");
            for v in vulns.iter().filter(|v| v.vex_state.is_none()) {
                println!(
                    "  {} [{}] — {} {}",
                    v.id,
                    v.severity,
                    v.component_name,
                    v.version.as_deref().unwrap_or("")
                );
            }
        }
    }

    // Exit code 1 if actionable-only mode and actionable vulns exist
    if config.actionable_only && actionable > 0 {
        return Ok(exit_codes::CHANGES_DETECTED);
    }

    Ok(exit_codes::SUCCESS)
}

/// Filter vulnerabilities by VEX state.
fn run_vex_filter(sbom: &NormalizedSbom, config: &VexConfig) -> Result<i32> {
    let vulns = collect_all_vulns(sbom);

    let filtered: Vec<&VulnEntry> = if config.actionable_only {
        vulns
            .iter()
            .filter(|v| {
                !matches!(
                    v.vex_state,
                    Some(VexState::NotAffected) | Some(VexState::Fixed)
                )
            })
            .collect()
    } else if let Some(ref state_filter) = config.filter_state {
        let target_state = parse_vex_state_filter(state_filter)?;
        vulns
            .iter()
            .filter(|v| v.vex_state.as_ref() == target_state.as_ref())
            .collect()
    } else {
        vulns.iter().collect()
    };

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
}
