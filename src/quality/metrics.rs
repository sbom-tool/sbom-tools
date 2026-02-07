//! Quality metrics for SBOM assessment.
//!
//! Provides detailed metrics for different aspects of SBOM quality.

use crate::model::NormalizedSbom;
use serde::{Deserialize, Serialize};

/// Overall completeness metrics for an SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletenessMetrics {
    /// Percentage of components with versions (0-100)
    pub components_with_version: f32,
    /// Percentage of components with PURLs (0-100)
    pub components_with_purl: f32,
    /// Percentage of components with CPEs (0-100)
    pub components_with_cpe: f32,
    /// Percentage of components with suppliers (0-100)
    pub components_with_supplier: f32,
    /// Percentage of components with hashes (0-100)
    pub components_with_hashes: f32,
    /// Percentage of components with licenses (0-100)
    pub components_with_licenses: f32,
    /// Percentage of components with descriptions (0-100)
    pub components_with_description: f32,
    /// Whether document has creator information
    pub has_creator_info: bool,
    /// Whether document has timestamp
    pub has_timestamp: bool,
    /// Whether document has serial number/ID
    pub has_serial_number: bool,
    /// Total component count
    pub total_components: usize,
}

impl CompletenessMetrics {
    /// Calculate completeness metrics from an SBOM
    #[must_use] 
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        if total == 0 {
            return Self::empty();
        }

        let mut with_version = 0;
        let mut with_purl = 0;
        let mut with_cpe = 0;
        let mut with_supplier = 0;
        let mut with_hashes = 0;
        let mut with_licenses = 0;
        let mut with_description = 0;

        for comp in sbom.components.values() {
            if comp.version.is_some() {
                with_version += 1;
            }
            if comp.identifiers.purl.is_some() {
                with_purl += 1;
            }
            if !comp.identifiers.cpe.is_empty() {
                with_cpe += 1;
            }
            if comp.supplier.is_some() {
                with_supplier += 1;
            }
            if !comp.hashes.is_empty() {
                with_hashes += 1;
            }
            if !comp.licenses.declared.is_empty() || comp.licenses.concluded.is_some() {
                with_licenses += 1;
            }
            if comp.description.is_some() {
                with_description += 1;
            }
        }

        let pct = |count: usize| (count as f32 / total as f32) * 100.0;

        Self {
            components_with_version: pct(with_version),
            components_with_purl: pct(with_purl),
            components_with_cpe: pct(with_cpe),
            components_with_supplier: pct(with_supplier),
            components_with_hashes: pct(with_hashes),
            components_with_licenses: pct(with_licenses),
            components_with_description: pct(with_description),
            has_creator_info: !sbom.document.creators.is_empty(),
            has_timestamp: true, // Always set in our model
            has_serial_number: sbom.document.serial_number.is_some(),
            total_components: total,
        }
    }

    /// Create empty metrics
    #[must_use] 
    pub const fn empty() -> Self {
        Self {
            components_with_version: 0.0,
            components_with_purl: 0.0,
            components_with_cpe: 0.0,
            components_with_supplier: 0.0,
            components_with_hashes: 0.0,
            components_with_licenses: 0.0,
            components_with_description: 0.0,
            has_creator_info: false,
            has_timestamp: false,
            has_serial_number: false,
            total_components: 0,
        }
    }

    /// Calculate overall completeness score (0-100)
    #[must_use] 
    pub fn overall_score(&self, weights: &CompletenessWeights) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        // Component field scores
        score += self.components_with_version * weights.version;
        total_weight += weights.version * 100.0;

        score += self.components_with_purl * weights.purl;
        total_weight += weights.purl * 100.0;

        score += self.components_with_cpe * weights.cpe;
        total_weight += weights.cpe * 100.0;

        score += self.components_with_supplier * weights.supplier;
        total_weight += weights.supplier * 100.0;

        score += self.components_with_hashes * weights.hashes;
        total_weight += weights.hashes * 100.0;

        score += self.components_with_licenses * weights.licenses;
        total_weight += weights.licenses * 100.0;

        // Document metadata scores
        if self.has_creator_info {
            score += 100.0 * weights.creator_info;
        }
        total_weight += weights.creator_info * 100.0;

        if self.has_serial_number {
            score += 100.0 * weights.serial_number;
        }
        total_weight += weights.serial_number * 100.0;

        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }
}

/// Weights for completeness score calculation
#[derive(Debug, Clone)]
pub struct CompletenessWeights {
    pub version: f32,
    pub purl: f32,
    pub cpe: f32,
    pub supplier: f32,
    pub hashes: f32,
    pub licenses: f32,
    pub creator_info: f32,
    pub serial_number: f32,
}

impl Default for CompletenessWeights {
    fn default() -> Self {
        Self {
            version: 1.0,
            purl: 1.5, // Higher weight for PURL
            cpe: 0.5,  // Lower weight, nice to have
            supplier: 1.0,
            hashes: 1.0,
            licenses: 1.2, // Important for compliance
            creator_info: 0.3,
            serial_number: 0.2,
        }
    }
}

/// Identifier quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierMetrics {
    /// Components with valid PURLs
    pub valid_purls: usize,
    /// Components with invalid/malformed PURLs
    pub invalid_purls: usize,
    /// Components with valid CPEs
    pub valid_cpes: usize,
    /// Components with invalid/malformed CPEs
    pub invalid_cpes: usize,
    /// Components with SWID tags
    pub with_swid: usize,
    /// Unique ecosystems identified
    pub ecosystems: Vec<String>,
    /// Components missing all identifiers (only name)
    pub missing_all_identifiers: usize,
}

impl IdentifierMetrics {
    /// Calculate identifier metrics from an SBOM
    #[must_use] 
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut valid_purls = 0;
        let mut invalid_purls = 0;
        let mut valid_cpes = 0;
        let mut invalid_cpes = 0;
        let mut with_swid = 0;
        let mut missing_all = 0;
        let mut ecosystems = std::collections::HashSet::new();

        for comp in sbom.components.values() {
            let has_purl = comp.identifiers.purl.is_some();
            let has_cpe = !comp.identifiers.cpe.is_empty();
            let has_swid = comp.identifiers.swid.is_some();

            if let Some(ref purl) = comp.identifiers.purl {
                if is_valid_purl(purl) {
                    valid_purls += 1;
                    // Extract ecosystem from PURL
                    if let Some(eco) = extract_ecosystem_from_purl(purl) {
                        ecosystems.insert(eco);
                    }
                } else {
                    invalid_purls += 1;
                }
            }

            for cpe in &comp.identifiers.cpe {
                if is_valid_cpe(cpe) {
                    valid_cpes += 1;
                } else {
                    invalid_cpes += 1;
                }
            }

            if has_swid {
                with_swid += 1;
            }

            if !has_purl && !has_cpe && !has_swid {
                missing_all += 1;
            }
        }

        let mut ecosystem_list: Vec<String> = ecosystems.into_iter().collect();
        ecosystem_list.sort();

        Self {
            valid_purls,
            invalid_purls,
            valid_cpes,
            invalid_cpes,
            with_swid,
            ecosystems: ecosystem_list,
            missing_all_identifiers: missing_all,
        }
    }

    /// Calculate identifier quality score (0-100)
    #[must_use] 
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        let with_valid_id = self.valid_purls + self.valid_cpes + self.with_swid;
        let coverage =
            (with_valid_id.min(total_components) as f32 / total_components as f32) * 100.0;

        // Penalize invalid identifiers
        let invalid_count = self.invalid_purls + self.invalid_cpes;
        let penalty = (invalid_count as f32 / total_components as f32) * 20.0;

        (coverage - penalty).clamp(0.0, 100.0)
    }
}

/// License quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseMetrics {
    /// Components with declared licenses
    pub with_declared: usize,
    /// Components with concluded licenses
    pub with_concluded: usize,
    /// Components with valid SPDX expressions
    pub valid_spdx_expressions: usize,
    /// Components with non-standard license names
    pub non_standard_licenses: usize,
    /// Components with NOASSERTION license
    pub noassertion_count: usize,
    /// Unique licenses found
    pub unique_licenses: Vec<String>,
}

impl LicenseMetrics {
    /// Calculate license metrics from an SBOM
    #[must_use] 
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_declared = 0;
        let mut with_concluded = 0;
        let mut valid_spdx = 0;
        let mut non_standard = 0;
        let mut noassertion = 0;
        let mut licenses = std::collections::HashSet::new();

        for comp in sbom.components.values() {
            if !comp.licenses.declared.is_empty() {
                with_declared += 1;
                for lic in &comp.licenses.declared {
                    let expr = &lic.expression;
                    licenses.insert(expr.clone());

                    if expr == "NOASSERTION" {
                        noassertion += 1;
                    } else if is_valid_spdx_license(expr) {
                        valid_spdx += 1;
                    } else {
                        non_standard += 1;
                    }
                }
            }

            if comp.licenses.concluded.is_some() {
                with_concluded += 1;
            }
        }

        let mut license_list: Vec<String> = licenses.into_iter().collect();
        license_list.sort();

        Self {
            with_declared,
            with_concluded,
            valid_spdx_expressions: valid_spdx,
            non_standard_licenses: non_standard,
            noassertion_count: noassertion,
            unique_licenses: license_list,
        }
    }

    /// Calculate license quality score (0-100)
    #[must_use] 
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        let coverage = (self.with_declared as f32 / total_components as f32) * 60.0;

        // Bonus for SPDX compliance
        let spdx_ratio = if self.with_declared > 0 {
            self.valid_spdx_expressions as f32 / self.with_declared as f32
        } else {
            0.0
        };
        let spdx_bonus = spdx_ratio * 30.0;

        // Penalty for NOASSERTION
        let noassertion_penalty =
            (self.noassertion_count as f32 / total_components.max(1) as f32) * 10.0;

        (coverage + spdx_bonus - noassertion_penalty).clamp(0.0, 100.0)
    }
}

/// Vulnerability information quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMetrics {
    /// Components with vulnerability information
    pub components_with_vulns: usize,
    /// Total vulnerabilities reported
    pub total_vulnerabilities: usize,
    /// Vulnerabilities with CVSS scores
    pub with_cvss: usize,
    /// Vulnerabilities with CWE information
    pub with_cwe: usize,
    /// Vulnerabilities with remediation info
    pub with_remediation: usize,
    /// Components with VEX status
    pub with_vex_status: usize,
}

impl VulnerabilityMetrics {
    /// Calculate vulnerability metrics from an SBOM
    #[must_use] 
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut components_with_vulns = 0;
        let mut total_vulns = 0;
        let mut with_cvss = 0;
        let mut with_cwe = 0;
        let mut with_remediation = 0;
        let mut with_vex = 0;

        for comp in sbom.components.values() {
            if !comp.vulnerabilities.is_empty() {
                components_with_vulns += 1;
            }

            for vuln in &comp.vulnerabilities {
                total_vulns += 1;

                if !vuln.cvss.is_empty() {
                    with_cvss += 1;
                }
                if !vuln.cwes.is_empty() {
                    with_cwe += 1;
                }
                if vuln.remediation.is_some() {
                    with_remediation += 1;
                }
            }

            if comp.vex_status.is_some() {
                with_vex += 1;
            }
        }

        Self {
            components_with_vulns,
            total_vulnerabilities: total_vulns,
            with_cvss,
            with_cwe,
            with_remediation,
            with_vex_status: with_vex,
        }
    }

    /// Calculate vulnerability documentation quality score (0-100)
    /// Note: This measures how well vulnerabilities are documented, not how many there are
    #[must_use] 
    pub fn documentation_score(&self) -> f32 {
        if self.total_vulnerabilities == 0 {
            return 100.0; // No vulns to document
        }

        let cvss_ratio = self.with_cvss as f32 / self.total_vulnerabilities as f32;
        let cwe_ratio = self.with_cwe as f32 / self.total_vulnerabilities as f32;
        let remediation_ratio = self.with_remediation as f32 / self.total_vulnerabilities as f32;

        remediation_ratio.mul_add(30.0, cvss_ratio.mul_add(40.0, cwe_ratio * 30.0)).min(100.0)
    }
}

/// Dependency graph quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyMetrics {
    /// Total dependency relationships
    pub total_dependencies: usize,
    /// Components with at least one dependency
    pub components_with_deps: usize,
    /// Maximum dependency depth (if calculable)
    pub max_depth: Option<usize>,
    /// Orphan components (no incoming or outgoing deps)
    pub orphan_components: usize,
    /// Root components (no incoming deps)
    pub root_components: usize,
}

impl DependencyMetrics {
    /// Calculate dependency metrics from an SBOM
    #[must_use] 
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let total_deps = sbom.edges.len();

        let mut has_outgoing = std::collections::HashSet::new();
        let mut has_incoming = std::collections::HashSet::new();

        for edge in &sbom.edges {
            has_outgoing.insert(&edge.from);
            has_incoming.insert(&edge.to);
        }

        let all_components: std::collections::HashSet<_> = sbom.components.keys().collect();

        let orphans = all_components
            .iter()
            .filter(|c| !has_outgoing.contains(*c) && !has_incoming.contains(*c))
            .count();

        let roots = has_outgoing
            .iter()
            .filter(|c| !has_incoming.contains(*c))
            .count();

        Self {
            total_dependencies: total_deps,
            components_with_deps: has_outgoing.len(),
            max_depth: None, // Would require graph traversal
            orphan_components: orphans,
            root_components: roots,
        }
    }

    /// Calculate dependency graph quality score (0-100)
    #[must_use] 
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        // Score based on how many components have dependency info
        let coverage = if total_components > 1 {
            (self.components_with_deps as f32 / (total_components - 1) as f32) * 100.0
        } else {
            100.0 // Single component SBOM
        };

        // Slight penalty for orphan components (except for root)
        let orphan_ratio = self.orphan_components as f32 / total_components as f32;
        let penalty = orphan_ratio * 10.0;

        (coverage - penalty).clamp(0.0, 100.0)
    }
}

// Helper functions

fn is_valid_purl(purl: &str) -> bool {
    // Basic PURL validation: pkg:type/namespace/name@version
    purl.starts_with("pkg:") && purl.contains('/')
}

fn extract_ecosystem_from_purl(purl: &str) -> Option<String> {
    // Extract type from pkg:type/...
    if let Some(rest) = purl.strip_prefix("pkg:") {
        if let Some(slash_idx) = rest.find('/') {
            return Some(rest[..slash_idx].to_string());
        }
    }
    None
}

fn is_valid_cpe(cpe: &str) -> bool {
    // Basic CPE validation
    cpe.starts_with("cpe:2.3:") || cpe.starts_with("cpe:/")
}

fn is_valid_spdx_license(expr: &str) -> bool {
    // Common SPDX license identifiers
    const COMMON_SPDX: &[&str] = &[
        "MIT",
        "Apache-2.0",
        "GPL-2.0",
        "GPL-3.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MPL-2.0",
        "LGPL-2.1",
        "LGPL-3.0",
        "AGPL-3.0",
        "Unlicense",
        "CC0-1.0",
        "0BSD",
        "EPL-2.0",
        "CDDL-1.0",
        "Artistic-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    ];

    // Check for common licenses or expressions
    let trimmed = expr.trim();
    COMMON_SPDX.contains(&trimmed)
        || trimmed.contains(" AND ")
        || trimmed.contains(" OR ")
        || trimmed.contains(" WITH ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purl_validation() {
        assert!(is_valid_purl("pkg:npm/@scope/name@1.0.0"));
        assert!(is_valid_purl("pkg:maven/group/artifact@1.0"));
        assert!(!is_valid_purl("npm:something"));
        assert!(!is_valid_purl("invalid"));
    }

    #[test]
    fn test_cpe_validation() {
        assert!(is_valid_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"));
        assert!(is_valid_cpe("cpe:/a:vendor:product:1.0"));
        assert!(!is_valid_cpe("something:else"));
    }

    #[test]
    fn test_spdx_license_validation() {
        assert!(is_valid_spdx_license("MIT"));
        assert!(is_valid_spdx_license("Apache-2.0"));
        assert!(is_valid_spdx_license("MIT AND Apache-2.0"));
        assert!(is_valid_spdx_license("GPL-2.0 OR MIT"));
    }
}
