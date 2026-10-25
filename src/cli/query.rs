//! Multi-SBOM query command handler.
//!
//! Searches for components across multiple SBOMs by name, PURL, version,
//! license, ecosystem, supplier, or vulnerability ID.

use crate::config::QueryConfig;
use crate::model::{
    Component, ComponentType, CryptoAssetType, NormalizedSbom, NormalizedSbomIndex,
};
use crate::pipeline::{OutputTarget, auto_detect_format, exit_codes, write_output};
use crate::reports::ReportFormat;
use crate::reports::escape::{sanitize_csv_field, sanitize_line};
use anyhow::{Result, bail};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

/// Output formats `query` has a real renderer for.
///
/// `auto` resolves to the table renderer (there is no query TUI); JSON and
/// CSV are dedicated emitters; `summary` renders the same compact table.
/// Every other [`ReportFormat`] is rejected up front instead of silently
/// falling back to the table renderer.
pub const QUERY_OUTPUT_FORMATS: &[ReportFormat] = &[
    ReportFormat::Auto,
    ReportFormat::Table,
    ReportFormat::Json,
    ReportFormat::Csv,
    ReportFormat::Summary,
];

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
    /// Crypto asset type filter (algorithm, certificate, key, protocol)
    pub crypto_type: Option<String>,
    /// Algorithm family filter (substring, e.g., "AES", "RSA", "ML-KEM")
    pub algorithm_family: Option<String>,
    /// Quantum safety filter: true = quantum-safe only, false = quantum-vulnerable only
    pub quantum_safe: Option<bool>,
}

impl QueryFilter {
    /// Check if a component matches all active filters.
    pub fn matches(
        &self,
        component: &Component,
        sort_key: &crate::model::ComponentSortKey,
    ) -> bool {
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

        if let Some(ref version) = self.version
            && !self.matches_version(component, version)
        {
            return false;
        }

        if let Some(ref license) = self.license
            && !self.matches_license(component, license)
        {
            return false;
        }

        if let Some(ref ecosystem) = self.ecosystem
            && !self.matches_ecosystem(component, ecosystem)
        {
            return false;
        }

        if let Some(ref supplier) = self.supplier
            && !self.matches_supplier(component, supplier)
        {
            return false;
        }

        if let Some(ref vuln_id) = self.affected_by
            && !self.matches_vuln(component, vuln_id)
        {
            return false;
        }

        if let Some(ref ct) = self.crypto_type
            && !self.matches_crypto_type(component, ct)
        {
            return false;
        }

        if let Some(ref af) = self.algorithm_family
            && !self.matches_algorithm_family(component, af)
        {
            return false;
        }

        if let Some(qs) = self.quantum_safe
            && !self.matches_quantum_safe(component, qs)
        {
            return false;
        }

        true
    }

    fn matches_version(&self, component: &Component, version_filter: &str) -> bool {
        let comp_version = match &component.version {
            Some(v) => v,
            None => return false,
        };

        // If the filter starts with an operator, treat it as a semver range —
        // never fall back to comparing the component version against the range
        // expression itself (that silently exact-matched non-semver versions).
        let trimmed = version_filter.trim();
        if version_filter_is_range(trimmed) {
            let Ok(req) = semver::VersionReq::parse(trimmed) else {
                // Invalid range expressions are rejected up front in
                // `run_query`; defensively exclude here.
                return false;
            };
            return match semver::Version::parse(comp_version) {
                Ok(ver) => req.matches(&ver),
                Err(_) => {
                    warn_non_semver_once(comp_version);
                    false
                }
            };
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

    fn matches_crypto_type(&self, component: &Component, crypto_type: &str) -> bool {
        if component.component_type != ComponentType::Cryptographic {
            return false;
        }
        let Some(cp) = &component.crypto_properties else {
            return false;
        };
        let ct_lower = crypto_type.to_lowercase();
        match ct_lower.as_str() {
            "algorithm" | "algo" => cp.asset_type == CryptoAssetType::Algorithm,
            "certificate" | "cert" => cp.asset_type == CryptoAssetType::Certificate,
            "key" | "material" => cp.asset_type == CryptoAssetType::RelatedCryptoMaterial,
            "protocol" | "proto" => cp.asset_type == CryptoAssetType::Protocol,
            _ => cp.asset_type.to_string().to_lowercase().contains(&ct_lower),
        }
    }

    fn matches_algorithm_family(&self, component: &Component, family_filter: &str) -> bool {
        if component.component_type != ComponentType::Cryptographic {
            return false;
        }
        let Some(cp) = &component.crypto_properties else {
            return false;
        };
        let filter_lower = family_filter.to_lowercase();
        // Check algorithm_properties.algorithm_family
        if let Some(algo) = &cp.algorithm_properties
            && let Some(fam) = &algo.algorithm_family
            && fam.to_lowercase().contains(&filter_lower)
        {
            return true;
        }
        // Fallback: check component name
        component.name.to_lowercase().contains(&filter_lower)
    }

    fn matches_quantum_safe(&self, component: &Component, want_safe: bool) -> bool {
        if component.component_type != ComponentType::Cryptographic {
            return false;
        }
        let Some(cp) = &component.crypto_properties else {
            return false;
        };
        let Some(algo) = &cp.algorithm_properties else {
            // Non-algorithm crypto assets: include them if filtering for safe
            return want_safe;
        };
        if want_safe {
            algo.is_quantum_safe()
        } else {
            !algo.is_quantum_safe()
        }
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
            && self.crypto_type.is_none()
            && self.algorithm_family.is_none()
            && self.quantum_safe.is_none()
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
        if let Some(ref ct) = self.crypto_type {
            parts.push(format!("crypto-type={ct}"));
        }
        if let Some(ref af) = self.algorithm_family {
            parts.push(format!("algorithm-family=\"{af}\""));
        }
        if let Some(qs) = self.quantum_safe {
            parts.push(if qs {
                "quantum-safe".to_string()
            } else {
                "quantum-vulnerable".to_string()
            });
        }
        if parts.is_empty() {
            "*".to_string()
        } else {
            parts.join(" AND ")
        }
    }
}

/// Does a `--version` filter look like a semver range expression (as opposed
/// to an exact version string)?
fn version_filter_is_range(trimmed: &str) -> bool {
    trimmed.starts_with('<')
        || trimmed.starts_with('>')
        || trimmed.starts_with('=')
        || trimmed.starts_with('~')
        || trimmed.starts_with('^')
        || trimmed.contains(',')
}

/// Emit a one-time stderr warning when a component version cannot be parsed
/// as semver during a range query (such components are excluded from the
/// match rather than silently string-compared against the range expression).
fn warn_non_semver_once(version: &str) {
    static NON_SEMVER_WARNED: std::sync::Once = std::sync::Once::new();
    NON_SEMVER_WARNED.call_once(|| {
        eprintln!(
            "warning: version '{version}' is not semver; excluded from range match \
             (further non-semver versions suppressed)"
        );
    });
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_asset_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_quantum_level: Option<u8>,
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

/// Run the query command, returning the desired exit code.
///
/// # Exit codes
/// - [`exit_codes::SUCCESS`] (0): at least one component matched the filter
/// - [`exit_codes::NO_MATCHES`] (1): no components matched the filter
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::needless_pass_by_value)]
pub fn run_query(config: QueryConfig, filter: QueryFilter) -> Result<i32> {
    if config.sbom_paths.is_empty() {
        bail!("No SBOM files specified");
    }

    if filter.is_empty() {
        bail!(
            "No query filters specified. Provide a search pattern or use --name, --purl, --version, --license, --ecosystem, --supplier, --affected-by, --crypto-type, --algorithm-family, --quantum-safe, or --quantum-vulnerable"
        );
    }

    // Reject unsupported output formats and an invalid --version range up
    // front, before any SBOM is parsed.
    super::ensure_output_format_supported("query", config.output.format, QUERY_OUTPUT_FORMATS)?;

    let target = OutputTarget::from_option(config.output.file.clone());
    let format = auto_detect_format(config.output.format, &target);

    if config.group_by_sbom && matches!(format, ReportFormat::Json | ReportFormat::Csv) {
        bail!(
            "--group-by-sbom is only supported with table output; \
             JSON output already lists per-SBOM sources in 'found_in' and 'sbom_summaries', \
             and CSV lists them in the 'Found In' column"
        );
    }

    if let Some(ref version_filter) = filter.version {
        let trimmed = version_filter.trim();
        if version_filter_is_range(trimmed)
            && let Err(e) = semver::VersionReq::parse(trimmed)
        {
            bail!("invalid semver range '{version_filter}' for --version: {e}");
        }
    }

    // Stdin can only be consumed once, so at most one input may be "-".
    if config
        .sbom_paths
        .iter()
        .filter(|p| crate::pipeline::is_stdin_path(p))
        .count()
        > 1
    {
        bail!("Cannot read more than one SBOM from stdin ('-')");
    }

    let sboms = super::multi::parse_multiple_sboms(&config.sbom_paths)?;

    // Optionally enrich with vulnerability data
    #[cfg(feature = "enrichment")]
    let sboms = enrich_if_needed(sboms, &config.enrichment)?;

    let mut total_components = 0;
    let mut sbom_summaries = Vec::with_capacity(sboms.len());

    // Deduplicate matches by (name_lower, version, identity), where identity
    // is the PURL (or the ecosystem when no PURL is present). Two components
    // that share a name and version but come from different ecosystems (e.g.
    // npm and pypi 'requests@2.0.0') are distinct and must not be collapsed
    // into one row carrying the first one's purl/license.
    let mut dedup_map: HashMap<(String, String, String), QueryMatch> = HashMap::new();

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
                component_identity(component),
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
                        if !existing
                            .vuln_ids
                            .iter()
                            .any(|v| v.to_uppercase() == id_upper)
                        {
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

    if result.matches.is_empty() {
        return Ok(exit_codes::NO_MATCHES);
    }

    Ok(exit_codes::SUCCESS)
}

/// Identity discriminator for deduplication beyond (name, version): the PURL
/// when present, otherwise the ecosystem. Components with neither collapse
/// together (matching the old behavior for purl-less, ecosystem-less entries).
fn component_identity(component: &Component) -> String {
    component
        .identifiers
        .purl
        .as_ref()
        .map(|p| p.to_lowercase())
        .or_else(|| {
            component
                .ecosystem
                .as_ref()
                .map(|e| e.to_string().to_lowercase())
        })
        .unwrap_or_default()
}

/// Build a `QueryMatch` from a component and its source.
fn build_query_match(component: &Component, source: SbomSource) -> QueryMatch {
    let vuln_ids: Vec<String> = component
        .vulnerabilities
        .iter()
        .map(|v| v.id.clone())
        .collect();
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
        purl: component.identifiers.purl.clone().unwrap_or_default(),
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
        crypto_asset_type: component
            .crypto_properties
            .as_ref()
            .map(|cp| cp.asset_type.to_string()),
        crypto_quantum_level: component
            .crypto_properties
            .as_ref()
            .and_then(|cp| cp.algorithm_properties.as_ref())
            .and_then(|a| a.nist_quantum_security_level),
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
    // Delegate to the central pipeline so OSV / KEV / EOL / staleness / VEX are
    // all sequenced consistently with the other commands.
    for sbom in &mut sboms {
        crate::pipeline::enrich_sbom_full(sbom, config, false);
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

    // SBOM text is sanitized before anything is measured: a line break or
    // a leading `:` must not let a component name start an output line.
    let cells: Vec<[Cow<'_, str>; 4]> = result
        .matches
        .iter()
        .map(|m| {
            [
                sanitize_line(&m.name),
                sanitize_line(&m.version),
                sanitize_line(&m.ecosystem),
                sanitize_line(&m.license),
            ]
        })
        .collect();

    // Calculate column widths (in characters, not bytes, so multi-byte
    // UTF-8 names don't inflate the column or break truncation)
    let width = |col: usize, min: usize, max: usize| {
        cells
            .iter()
            .map(|row| row[col].chars().count())
            .max()
            .unwrap_or(min)
            .clamp(min, max)
    };
    let name_w = width(0, 9, 40);
    let ver_w = width(1, 7, 20);
    let eco_w = width(2, 9, 15);
    let lic_w = width(3, 7, 20);

    // Header
    out.push_str(&format!(
        "{:<name_w$}  {:<ver_w$}  {:<eco_w$}  {:<lic_w$}  {:>5}  FOUND IN\n",
        "COMPONENT", "VERSION", "ECOSYSTEM", "LICENSE", "VULNS",
    ));

    // Rows
    for (m, [name, ver, eco, lic]) in result.matches.iter().zip(&cells) {
        let name = truncate(name, name_w);
        let ver = truncate(ver, ver_w);
        let eco = truncate(eco, eco_w);
        let lic = truncate(lic, lic_w);
        let found_in: Vec<Cow<'_, str>> =
            m.found_in.iter().map(|s| sanitize_line(&s.name)).collect();

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
            sanitize_line(&summary.name),
            summary.matches,
            summary.component_count
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
                    sanitize_line(&m.name),
                    sanitize_line(&m.version),
                    sanitize_line(&m.ecosystem),
                    vuln_str
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
    let mut out = String::from(
        "Component,Version,Ecosystem,License,Vulns,Vulnerability IDs,Supplier,EOL Status,Found In\n",
    );

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

/// Escape a CSV field value: [`sanitize_csv_field`] flattens line breaks,
/// removes control and bidi characters, and guards formula triggers and a
/// leading `:`; the result is quoted if it contains a comma or quote.
fn csv_escape(s: &str) -> String {
    let s = sanitize_csv_field(s);
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Truncate a string to the given display width (in characters).
///
/// Operates on `char` boundaries, never byte offsets: slicing at a byte
/// offset panics when it lands inside a multi-byte UTF-8 character.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max > 3 {
        let kept: String = s.chars().take(max - 3).collect();
        format!("{kept}...")
    } else {
        s.chars().take(max).collect()
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

        let comp = make_component(
            "log4j-core",
            "2.14.1",
            Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
        );
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
        comp.vulnerabilities
            .push(crate::model::VulnerabilityRef::new(
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

        let mut dedup_map: HashMap<(String, String, String), QueryMatch> = HashMap::new();
        let key = (
            "lodash".to_string(),
            "4.17.21".to_string(),
            component_identity(&comp),
        );

        dedup_map.insert(key.clone(), build_query_match(&comp, source1));
        dedup_map.entry(key).and_modify(|existing| {
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
        // SBOM text cannot start a CSV line printed to a CI log
        assert_eq!(csv_escape("x\n::error::forged"), "x ::error::forged");
        assert_eq!(csv_escape("::warning::forged"), "'::warning::forged");
        assert_eq!(csv_escape("=HYPERLINK(1)"), "'=HYPERLINK(1)");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("long string here", 10), "long st...");
        assert_eq!(truncate("ab", 2), "ab");
    }

    #[test]
    fn test_truncate_multibyte_no_panic() {
        // Regression: a byte-offset slice panicked when the cut landed inside
        // a multi-byte UTF-8 char ('a'*36 + 'é' + 'x'*10 truncated to 40).
        let name = format!("{}é{}", "a".repeat(36), "x".repeat(10));
        let out = truncate(&name, 40);
        assert!(out.ends_with("..."));
        assert_eq!(out.chars().count(), 40);

        // Cut exactly at the multi-byte char
        let s = format!("{}é", "a".repeat(36));
        assert_eq!(truncate(&s, 37), s);
        assert_eq!(truncate("ééééé", 2), "éé");
    }

    #[test]
    fn test_version_range_excludes_non_semver() {
        let filter = QueryFilter {
            version: Some("<2.0.0".to_string()),
            ..Default::default()
        };

        // Non-semver version is excluded from a range match (with a one-time
        // stderr warning), not string-compared.
        let comp = make_component("foo", "1.5", None);
        let key = ComponentSortKey::from_component(&comp);
        assert!(!filter.matches(&comp, &key));

        // Proper semver still matches the range.
        let comp2 = make_component("foo", "1.5.0", None);
        let key2 = ComponentSortKey::from_component(&comp2);
        assert!(filter.matches(&comp2, &key2));

        // A version string literally equal to the range expression must NOT
        // exact-match (the old fallback compared version vs. range text).
        let comp3 = make_component("foo", "<2.0.0", None);
        let key3 = ComponentSortKey::from_component(&comp3);
        assert!(!filter.matches(&comp3, &key3));
    }

    #[test]
    fn test_version_filter_is_range() {
        assert!(version_filter_is_range("<2.0.0"));
        assert!(version_filter_is_range(">=1.0, <2.0"));
        assert!(version_filter_is_range("^1.2"));
        assert!(version_filter_is_range("~1.2"));
        assert!(version_filter_is_range("=1.2.3"));
        assert!(!version_filter_is_range("1.2.3"));
        assert!(!version_filter_is_range("2.0.0-beta.1"));
    }

    #[test]
    fn test_component_identity_purl_over_ecosystem() {
        let npm = make_component("requests", "2.0.0", Some("pkg:npm/requests@2.0.0"));
        let pypi = make_component("requests", "2.0.0", Some("pkg:pypi/requests@2.0.0"));
        assert_ne!(component_identity(&npm), component_identity(&pypi));

        // No purl: fall back to ecosystem
        let mut a = make_component("requests", "2.0.0", None);
        a.ecosystem = Some(crate::model::Ecosystem::Npm);
        let mut b = make_component("requests", "2.0.0", None);
        b.ecosystem = Some(crate::model::Ecosystem::PyPi);
        assert_ne!(component_identity(&a), component_identity(&b));

        // Neither: identical (collapse, matching old behavior)
        let c = make_component("requests", "2.0.0", None);
        let d = make_component("requests", "2.0.0", None);
        assert_eq!(component_identity(&c), component_identity(&d));
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
                crypto_asset_type: None,
                crypto_quantum_level: None,
            }],
            sbom_summaries: vec![],
        };
        let csv = format_csv_output(&result);
        assert!(csv.starts_with("Component,Version"));
        assert!(csv.contains("lodash,4.17.21,npm,MIT"));
    }

    fn make_crypto_component(
        name: &str,
        asset_type: crate::model::CryptoAssetType,
        ql: Option<u8>,
    ) -> Component {
        let mut c = Component::new(name.to_string(), format!("{name}@1.0"));
        c.component_type = ComponentType::Cryptographic;
        let mut props = crate::model::CryptoProperties::new(asset_type);
        if let Some(level) = ql {
            props = props.with_algorithm_properties(
                crate::model::AlgorithmProperties::new(crate::model::CryptoPrimitive::Ae)
                    .with_nist_quantum_security_level(level),
            );
        }
        c.crypto_properties = Some(props);
        c
    }

    #[test]
    fn test_filter_crypto_type_algorithm() {
        let comp = make_crypto_component("AES-256", CryptoAssetType::Algorithm, Some(1));
        let key = ComponentSortKey::from_component(&comp);
        let filter = QueryFilter {
            crypto_type: Some("algorithm".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&comp, &key));

        let filter2 = QueryFilter {
            crypto_type: Some("certificate".to_string()),
            ..Default::default()
        };
        assert!(!filter2.matches(&comp, &key));
    }

    #[test]
    fn test_filter_quantum_safe() {
        let safe = make_crypto_component("ML-KEM-1024", CryptoAssetType::Algorithm, Some(5));
        let key_safe = ComponentSortKey::from_component(&safe);
        let vuln = make_crypto_component("RSA-2048", CryptoAssetType::Algorithm, Some(0));
        let key_vuln = ComponentSortKey::from_component(&vuln);

        let filter = QueryFilter {
            quantum_safe: Some(true),
            ..Default::default()
        };
        assert!(filter.matches(&safe, &key_safe));
        assert!(!filter.matches(&vuln, &key_vuln));
    }

    #[test]
    fn test_filter_quantum_vulnerable() {
        let vuln = make_crypto_component("RSA-2048", CryptoAssetType::Algorithm, Some(0));
        let key = ComponentSortKey::from_component(&vuln);

        let filter = QueryFilter {
            quantum_safe: Some(false),
            ..Default::default()
        };
        assert!(filter.matches(&vuln, &key));
    }

    #[test]
    fn test_filter_algorithm_family() {
        let mut comp = make_crypto_component("AES-256-GCM", CryptoAssetType::Algorithm, Some(1));
        if let Some(ref mut cp) = comp.crypto_properties {
            if let Some(ref mut algo) = cp.algorithm_properties {
                algo.algorithm_family = Some("AES".to_string());
            }
        }
        let key = ComponentSortKey::from_component(&comp);

        let filter = QueryFilter {
            algorithm_family: Some("AES".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&comp, &key));

        let filter2 = QueryFilter {
            algorithm_family: Some("RSA".to_string()),
            ..Default::default()
        };
        assert!(!filter2.matches(&comp, &key));
    }
}
