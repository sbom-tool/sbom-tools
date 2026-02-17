//! Multi-SBOM query command handler.
//!
//! Searches for components across multiple SBOMs by name, PURL, version,
//! license, ecosystem, supplier, or vulnerability ID.

use crate::config::QueryConfig;
use crate::model::{Component, NormalizedSbom, NormalizedSbomIndex};
use crate::pipeline::{auto_detect_format, write_output, OutputTarget};
use crate::reports::ReportFormat;
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::HashMap;

// ============================================================================
// Query Filter
// ============================================================================

/// Filter criteria for querying components across SBOMs.
///
/// All active filters are AND-combined: a component must match every
/// non-None filter to be included in results.
#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    /// Free-text pattern matching across name, purl, version, and id
    pub pattern: Option<String>,
    /// Name substring filter
    pub name: Option<String>,
    /// PURL substring filter
    pub purl: Option<String>,
    /// Version filter: exact match or semver range (e.g., "<2.17.0")
    pub version: Option<String>,
    /// License substring filter
    pub license: Option<String>,
    /// Ecosystem filter (case-insensitive exact match)
    pub ecosystem: Option<String>,
    /// Supplier name substring filter
    pub supplier: Option<String>,
    /// Vulnerability ID filter (exact match on vuln IDs)
    pub affected_by: Option<String>,
}

impl QueryFilter {
    /// Check if a component matches all active filters.
    pub fn matches(&self, component: &Component, sort_key: &crate::model::ComponentSortKey) -> bool {
        if let Some(ref pattern) = self.pattern {
            let pattern_lower = pattern.to_lowercase();
            if !sort_key.contains(&pattern_lower) {
                return false;
            }
        }

        if let Some(ref name) = self.name {
            let name_lower = name.to_lowercase();
            if !sort_key.name_lower.contains(&name_lower) {
                return false;
            }
        }

        if let Some(ref purl) = self.purl {
            let purl_lower = purl.to_lowercase();
            if !sort_key.purl_lower.contains(&purl_lower) {
                return false;
            }
        }

        if let Some(ref version) = self.version {
            if !self.matches_version(component, version) {
                return false;
            }
        }

        if let Some(ref license) = self.license {
            if !self.matches_license(component, license) {
                return false;
            }
        }

        if let Some(ref ecosystem) = self.ecosystem {
            if !self.matches_ecosystem(component, ecosystem) {
                return false;
            }
        }

        if let Some(ref supplier) = self.supplier {
            if !self.matches_supplier(component, supplier) {
                return false;
            }
        }

        if let Some(ref vuln_id) = self.affected_by {
            if !self.matches_vuln(component, vuln_id) {
                return false;
            }
        }

        true
    }

    fn matches_version(&self, component: &Component, version_filter: &str) -> bool {
        let comp_version = match &component.version {
            Some(v) => v,
            None => return false,
        };

        // If the filter starts with an operator, parse as semver range
        let trimmed = version_filter.trim();
        let has_operator = trimmed.starts_with('<')
            || trimmed.starts_with('>')
            || trimmed.starts_with('=')
            || trimmed.starts_with('~')
            || trimmed.starts_with('^')
            || trimmed.contains(',');

        if has_operator {
            if let Ok(req) = semver::VersionReq::parse(trimmed) {
                if let Ok(ver) = semver::Version::parse(comp_version) {
                    return req.matches(&ver);
                }
            }
        }

        // Exact string match (case-insensitive)
        comp_version.to_lowercase() == version_filter.to_lowercase()
    }

    fn matches_license(&self, component: &Component, license_filter: &str) -> bool {
        let filter_lower = license_filter.to_lowercase();
        component
            .licenses
            .all_licenses()
            .iter()
            .any(|l| l.expression.to_lowercase().contains(&filter_lower))
    }

    fn matches_ecosystem(&self, component: &Component, ecosystem_filter: &str) -> bool {
        match &component.ecosystem {
            Some(eco) => eco.to_string().to_lowercase() == ecosystem_filter.to_lowercase(),
            None => false,
        }
    }

    fn matches_supplier(&self, component: &Component, supplier_filter: &str) -> bool {
        let filter_lower = supplier_filter.to_lowercase();
        match &component.supplier {
            Some(org) => org.name.to_lowercase().contains(&filter_lower),
            None => false,
        }
    }

    fn matches_vuln(&self, component: &Component, vuln_id: &str) -> bool {
        let id_upper = vuln_id.to_uppercase();
        component
            .vulnerabilities
            .iter()
            .any(|v| v.id.to_uppercase() == id_upper)
    }

    /// Returns true if no filters are set (would match everything).
    pub fn is_empty(&self) -> bool {
        self.pattern.is_none()
            && self.name.is_none()
            && self.purl.is_none()
            && self.version.is_none()
            && self.license.is_none()
            && self.ecosystem.is_none()
            && self.supplier.is_none()
            && self.affected_by.is_none()
    }

    /// Build a human-readable description of the active filters.
    fn description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref p) = self.pattern {
            parts.push(format!("\"{p}\""));
        }
        if let Some(ref n) = self.name {
            parts.push(format!("name=\"{n}\""));
        }
        if let Some(ref p) = self.purl {
            parts.push(format!("purl=\"{p}\""));
        }
        if let Some(ref v) = self.version {
            parts.push(format!("version={v}"));
        }
        if let Some(ref l) = self.license {
            parts.push(format!("license=\"{l}\""));
        }
        if let Some(ref e) = self.ecosystem {
            parts.push(format!("ecosystem={e}"));
        }
        if let Some(ref s) = self.supplier {
            parts.push(format!("supplier=\"{s}\""));
        }
        if let Some(ref v) = self.affected_by {
            parts.push(format!("affected-by={v}"));
        }
        if parts.is_empty() {
            "*".to_string()
        } else {
            parts.join(" AND ")
        }
    }
}

// ============================================================================
// Query Results
// ============================================================================

/// Source SBOM where a component was found.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SbomSource {
    pub name: String,
    pub path: String,
}

/// A single matched component (possibly found in multiple SBOMs).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryMatch {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub license: String,
    pub purl: String,
    pub supplier: String,
    pub vuln_count: usize,
    pub vuln_ids: Vec<String>,
    pub found_in: Vec<SbomSource>,
    pub eol_status: String,
}

/// Summary of an SBOM that was searched.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SbomSummary {
    pub name: String,
    pub path: String,
    pub component_count: usize,
    pub matches: usize,
}

/// Full query result.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryResult {
    pub filter: String,
    pub sboms_searched: usize,
    pub total_components: usize,
    pub matches: Vec<QueryMatch>,
    pub sbom_summaries: Vec<SbomSummary>,
}

// ============================================================================
// Core Implementation
// ============================================================================

/// Run the query command.
#[allow(clippy::needless_pass_by_value)]
pub fn run_query(config: QueryConfig, filter: QueryFilter) -> Result<()> {
    if config.sbom_paths.is_empty() {
        bail!("No SBOM files specified");
    }

    if filter.is_empty() {
        bail!("No query filters specified. Provide a search pattern or use --name, --purl, --version, --license, --ecosystem, --supplier, or --affected-by");
    }

    let sboms = super::multi::parse_multiple_sboms(&config.sbom_paths)?;

    // Optionally enrich with vulnerability data
    #[cfg(feature = "enrichment")]
    let sboms = enrich_if_needed(sboms, &config.enrichment)?;

    let mut total_components = 0;
    let mut sbom_summaries = Vec::with_capacity(sboms.len());

    // Deduplicate matches by (name_lower, version)
    let mut dedup_map: HashMap<(String, String), QueryMatch> = HashMap::new();

    for (sbom, path) in sboms.iter().zip(config.sbom_paths.iter()) {
        let sbom_name = super::multi::get_sbom_name(path);
        let index = NormalizedSbomIndex::build(sbom);
        let component_count = sbom.component_count();
        total_components += component_count;

        let mut match_count = 0;

        for (_id, component) in &sbom.components {
            let sort_key = index
                .sort_key(&component.canonical_id)
                .cloned()
                .unwrap_or_default();

            if !filter.matches(component, &sort_key) {
                continue;
            }

            match_count += 1;
            let dedup_key = (
                component.name.to_lowercase(),
                component.version.clone().unwrap_or_default(),
            );

            let source = SbomSource {
                name: sbom_name.clone(),
                path: path.to_string_lossy().to_string(),
            };

            dedup_map
                .entry(dedup_key)
                .and_modify(|existing| {
                    // Merge: add source, union vuln IDs
                    existing.found_in.push(source.clone());
                    for vid in &component.vulnerabilities {
                        let id_upper = vid.id.to_uppercase();
                        if !existing.vuln_ids.iter().any(|v| v.to_uppercase() == id_upper) {
                            existing.vuln_ids.push(vid.id.clone());
                        }
                    }
                    existing.vuln_count = existing.vuln_ids.len();
                })
                .or_insert_with(|| build_query_match(component, source));
        }

        sbom_summaries.push(SbomSummary {
            name: sbom_name,
            path: path.to_string_lossy().to_string(),
            component_count,
            matches: match_count,
        });
    }

    let mut matches: Vec<QueryMatch> = dedup_map.into_values().collect();
    matches.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.version.cmp(&b.version))
    });

    // Apply limit
    if let Some(limit) = config.limit {
        matches.truncate(limit);
    }

    let result = QueryResult {
        filter: filter.description(),
        sboms_searched: sbom_summaries.len(),
        total_components,
        matches,
        sbom_summaries,
    };

    // Determine output format
    let target = OutputTarget::from_option(config.output.file.clone());
    let format = auto_detect_format(config.output.format, &target);

    let output = match format {
        ReportFormat::Json => serde_json::to_string_pretty(&result)?,
        ReportFormat::Csv => format_csv_output(&result),
        _ => {
            if config.group_by_sbom {
                format_table_grouped(&result)
            } else {
                format_table_output(&result)
            }
        }
    };

    write_output(&output, &target, false)?;

    // Exit code: 1 if no matches
    if result.matches.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

/// Build a `QueryMatch` from a component and its source.
fn build_query_match(component: &Component, source: SbomSource) -> QueryMatch {
    let vuln_ids: Vec<String> = component.vulnerabilities.iter().map(|v| v.id.clone()).collect();
    let license = component
        .licenses
        .all_licenses()
        .iter()
        .map(|l| l.expression.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    QueryMatch {
        name: component.name.clone(),
        version: component.version.clone().unwrap_or_default(),
        ecosystem: component
            .ecosystem
            .as_ref()
            .map_or_else(String::new, ToString::to_string),
        license,
        purl: component
            .identifiers
            .purl
            .clone()
            .unwrap_or_default(),
        supplier: component
            .supplier
            .as_ref()
            .map_or_else(String::new, |o| o.name.clone()),
        vuln_count: vuln_ids.len(),
        vuln_ids,
        found_in: vec![source],
        eol_status: component
            .eol
            .as_ref()
            .map_or_else(String::new, |e| format!("{:?}", e.status)),
    }
}

// ============================================================================
// Enrichment (feature-gated)
// ============================================================================

#[cfg(feature = "enrichment")]
fn enrich_if_needed(
    mut sboms: Vec<NormalizedSbom>,
    config: &crate::config::EnrichmentConfig,
) -> Result<Vec<NormalizedSbom>> {
    // VEX enrichment
    if !config.vex_paths.is_empty() {
        for sbom in &mut sboms {
            crate::pipeline::enrich_vex(sbom, &config.vex_paths, false);
        }
    }
    if config.enabled {
        let osv_config = crate::pipeline::build_enrichment_config(config);
        for sbom in &mut sboms {
            crate::pipeline::enrich_sbom(sbom, &osv_config, false);
        }
    }
    if config.enable_eol {
        let eol_config = crate::enrichment::EolClientConfig {
            cache_dir: config
                .cache_dir
                .clone()
                .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.cache_ttl_hours * 3600),
            bypass_cache: config.bypass_cache,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
            ..Default::default()
        };
        for sbom in &mut sboms {
            crate::pipeline::enrich_eol(sbom, &eol_config, false);
        }
    }
    Ok(sboms)
}

// ============================================================================
// Output Formatting
// ============================================================================

/// Format results as a table for terminal output.
fn format_table_output(result: &QueryResult) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Query: {} across {} SBOMs ({} total components)\n\n",
        result.filter, result.sboms_searched, result.total_components
    ));

    if result.matches.is_empty() {
        out.push_str("0 components found\n");
        return out;
    }

    // Calculate column widths
    let name_w = result
        .matches
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or(9)
        .clamp(9, 40);
    let ver_w = result
        .matches
        .iter()
        .map(|m| m.version.len())
        .max()
        .unwrap_or(7)
        .clamp(7, 20);
    let eco_w = result
        .matches
        .iter()
        .map(|m| m.ecosystem.len())
        .max()
        .unwrap_or(9)
        .clamp(9, 15);
    let lic_w = result
        .matches
        .iter()
        .map(|m| m.license.len())
        .max()
        .unwrap_or(7)
        .clamp(7, 20);

    // Header
    out.push_str(&format!(
        "{:<name_w$}  {:<ver_w$}  {:<eco_w$}  {:<lic_w$}  {:>5}  FOUND IN\n",
        "COMPONENT", "VERSION", "ECOSYSTEM", "LICENSE", "VULNS",
    ));

    // Rows
    for m in &result.matches {
        let name = truncate(&m.name, name_w);
        let ver = truncate(&m.version, ver_w);
        let eco = truncate(&m.ecosystem, eco_w);
        let lic = truncate(&m.license, lic_w);
        let found_in: Vec<&str> = m.found_in.iter().map(|s| s.name.as_str()).collect();

        out.push_str(&format!(
            "{name:<name_w$}  {ver:<ver_w$}  {eco:<eco_w$}  {lic:<lic_w$}  {:>5}  {}\n",
            m.vuln_count,
            found_in.join(", "),
        ));
    }

    out.push_str(&format!(
        "\n{} components found across {} SBOMs\n",
        result.matches.len(),
        result.sboms_searched
    ));

    out
}

/// Format results grouped by SBOM source.
fn format_table_grouped(result: &QueryResult) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Query: {} across {} SBOMs ({} total components)\n\n",
        result.filter, result.sboms_searched, result.total_components
    ));

    if result.matches.is_empty() {
        out.push_str("0 components found\n");
        return out;
    }

    // Group matches by SBOM
    for summary in &result.sbom_summaries {
        if summary.matches == 0 {
            continue;
        }

        out.push_str(&format!(
            "── {} ({} matches / {} components) ──\n",
            summary.name, summary.matches, summary.component_count
        ));

        for m in &result.matches {
            if m.found_in.iter().any(|s| s.name == summary.name) {
                let vuln_str = if m.vuln_count > 0 {
                    format!(" [{} vulns]", m.vuln_count)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "  {} {} ({}){}\n",
                    m.name, m.version, m.ecosystem, vuln_str
                ));
            }
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "{} components found across {} SBOMs\n",
        result.matches.len(),
        result.sboms_searched
    ));

    out
}

/// Format results as CSV.
fn format_csv_output(result: &QueryResult) -> String {
    let mut out = String::from("Component,Version,Ecosystem,License,Vulns,Vulnerability IDs,Supplier,EOL Status,Found In\n");

    for m in &result.matches {
        let found_in: Vec<&str> = m.found_in.iter().map(|s| s.name.as_str()).collect();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&m.name),
            csv_escape(&m.version),
            csv_escape(&m.ecosystem),
            csv_escape(&m.license),
            m.vuln_count,
            csv_escape(&m.vuln_ids.join("; ")),
            csv_escape(&m.supplier),
            csv_escape(&m.eol_status),
            csv_escape(&found_in.join("; ")),
        ));
    }

    out
}

/// Escape a CSV field value (quote if contains comma, quote, or newline).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Truncate a string to the given width.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max > 3 {
        format!("{}...", &s[..max - 3])
    } else {
        s[..max].to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, ComponentSortKey};

    fn make_component(name: &str, version: &str, purl: Option<&str>) -> Component {
        let mut c = Component::new(name.to_string(), format!("{name}@{version}"));
        c.version = Some(version.to_string());
        if let Some(p) = purl {
            c.identifiers.purl = Some(p.to_string());
        }
        c
    }

    #[test]
    fn test_filter_pattern_match() {
        let filter = QueryFilter {
            pattern: Some("log4j".to_string()),
            ..Default::default()
        };

        let comp = make_component("log4j-core", "2.14.1", Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"));
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("openssl", "1.1.1", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_name_match() {
        let filter = QueryFilter {
            name: Some("openssl".to_string()),
            ..Default::default()
        };

        let comp = make_component("openssl", "3.0.0", None);
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("libssl", "1.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_version_exact() {
        let filter = QueryFilter {
            version: Some("2.14.1".to_string()),
            ..Default::default()
        };

        let comp = make_component("log4j-core", "2.14.1", None);
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("log4j-core", "2.17.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_version_semver_range() {
        let filter = QueryFilter {
            version: Some("<2.17.0".to_string()),
            ..Default::default()
        };

        let comp = make_component("log4j-core", "2.14.1", None);
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("log4j-core", "2.17.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));

        let comp3 = make_component("log4j-core", "2.18.0", None);
        let key3 = ComponentSortKey::from_component(&comp3);
        assert!(!filter.matches(&comp3, &key3));
    }

    #[test]
    fn test_filter_license_match() {
        let filter = QueryFilter {
            license: Some("Apache".to_string()),
            ..Default::default()
        };

        let mut comp = make_component("log4j-core", "2.14.1", None);
        comp.licenses
            .add_declared(crate::model::LicenseExpression::new(
                "Apache-2.0".to_string(),
            ));
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("some-lib", "1.0.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_ecosystem_match() {
        let filter = QueryFilter {
            ecosystem: Some("npm".to_string()),
            ..Default::default()
        };

        let mut comp = make_component("lodash", "4.17.21", None);
        comp.ecosystem = Some(crate::model::Ecosystem::Npm);
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let mut comp2 = make_component("serde", "1.0", None);
        comp2.ecosystem = Some(crate::model::Ecosystem::Cargo);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_affected_by() {
        let filter = QueryFilter {
            affected_by: Some("CVE-2021-44228".to_string()),
            ..Default::default()
        };

        let mut comp = make_component("log4j-core", "2.14.1", None);
        comp.vulnerabilities.push(crate::model::VulnerabilityRef::new(
            "CVE-2021-44228".to_string(),
            crate::model::VulnerabilitySource::Osv,
        ));
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        let comp2 = make_component("log4j-core", "2.17.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));
    }

    #[test]
    fn test_filter_combined() {
        let filter = QueryFilter {
            name: Some("log4j".to_string()),
            version: Some("<2.17.0".to_string()),
            ..Default::default()
        };

        let comp = make_component("log4j-core", "2.14.1", None);
        let key = ComponentSortKey::from_component(&comp);
        assert!(filter.matches(&comp, &key));

        // Name matches but version doesn't
        let comp2 = make_component("log4j-core", "2.17.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(!filter.matches(&comp2, &key2));

        // Version matches but name doesn't
        let comp3 = make_component("openssl", "2.14.1", None);
        let key3 = ComponentSortKey::from_component(&comp3);
        assert!(!filter.matches(&comp3, &key3));
    }

    #[test]
    fn test_dedup_merges_sources() {
        let source1 = SbomSource {
            name: "sbom1".to_string(),
            path: "sbom1.json".to_string(),
        };
        let source2 = SbomSource {
            name: "sbom2".to_string(),
            path: "sbom2.json".to_string(),
        };

        let comp = make_component("lodash", "4.17.21", None);

        let mut dedup_map: HashMap<(String, String), QueryMatch> = HashMap::new();
        let key = ("lodash".to_string(), "4.17.21".to_string());

        dedup_map.insert(key.clone(), build_query_match(&comp, source1));
        dedup_map
            .entry(key)
            .and_modify(|existing| {
                existing.found_in.push(source2);
            });

        let match_entry = dedup_map.values().next().expect("should have one entry");
        assert_eq!(match_entry.found_in.len(), 2);
        assert_eq!(match_entry.found_in[0].name, "sbom1");
        assert_eq!(match_entry.found_in[1].name, "sbom2");
    }

    #[test]
    fn test_filter_is_empty() {
        let filter = QueryFilter::default();
        assert!(filter.is_empty());

        let filter = QueryFilter {
            pattern: Some("test".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_filter_description() {
        let filter = QueryFilter {
            pattern: Some("log4j".to_string()),
            version: Some("<2.17.0".to_string()),
            ..Default::default()
        };
        let desc = filter.description();
        assert!(desc.contains("\"log4j\""));
        assert!(desc.contains("version=<2.17.0"));
        assert!(desc.contains("AND"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("long string here", 10), "long st...");
        assert_eq!(truncate("ab", 2), "ab");
    }

    #[test]
    fn test_format_table_empty_results() {
        let result = QueryResult {
            filter: "\"nonexistent\"".to_string(),
            sboms_searched: 1,
            total_components: 100,
            matches: vec![],
            sbom_summaries: vec![],
        };
        let output = format_table_output(&result);
        assert!(output.contains("0 components found"));
    }

    #[test]
    fn test_format_csv_output() {
        let result = QueryResult {
            filter: "test".to_string(),
            sboms_searched: 1,
            total_components: 10,
            matches: vec![QueryMatch {
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                ecosystem: "npm".to_string(),
                license: "MIT".to_string(),
                purl: "pkg:npm/lodash@4.17.21".to_string(),
                supplier: String::new(),
                vuln_count: 0,
                vuln_ids: vec![],
                found_in: vec![SbomSource {
                    name: "sbom1".to_string(),
                    path: "sbom1.json".to_string(),
                }],
                eol_status: String::new(),
            }],
            sbom_summaries: vec![],
        };
        let csv = format_csv_output(&result);
        assert!(csv.starts_with("Component,Version"));
        assert!(csv.contains("lodash,4.17.21,npm,MIT"));
    }
}
