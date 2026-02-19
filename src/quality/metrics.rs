//! Quality metrics for SBOM assessment.
//!
//! Provides detailed metrics for different aspects of SBOM quality.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::{
    CompletenessDeclaration, CreatorType, EolStatus, ExternalRefType, HashAlgorithm,
    NormalizedSbom, StalenessLevel,
};
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

// ============================================================================
// Hash quality metrics
// ============================================================================

/// Hash/integrity quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashQualityMetrics {
    /// Components with any hash
    pub components_with_any_hash: usize,
    /// Components with at least one strong hash (SHA-256+, SHA-3, BLAKE, Blake3)
    pub components_with_strong_hash: usize,
    /// Components with only weak hashes (MD5, SHA-1) and no strong backup
    pub components_with_weak_only: usize,
    /// Distribution of hash algorithms across all components
    pub algorithm_distribution: BTreeMap<String, usize>,
    /// Total hash entries across all components
    pub total_hashes: usize,
}

impl HashQualityMetrics {
    /// Calculate hash quality metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_any = 0;
        let mut with_strong = 0;
        let mut with_weak_only = 0;
        let mut distribution: BTreeMap<String, usize> = BTreeMap::new();
        let mut total_hashes = 0;

        for comp in sbom.components.values() {
            if comp.hashes.is_empty() {
                continue;
            }
            with_any += 1;
            total_hashes += comp.hashes.len();

            let mut has_strong = false;
            let mut has_weak = false;

            for hash in &comp.hashes {
                let label = hash_algorithm_label(&hash.algorithm);
                *distribution.entry(label).or_insert(0) += 1;

                if is_strong_hash(&hash.algorithm) {
                    has_strong = true;
                } else {
                    has_weak = true;
                }
            }

            if has_strong {
                with_strong += 1;
            } else if has_weak {
                with_weak_only += 1;
            }
        }

        Self {
            components_with_any_hash: with_any,
            components_with_strong_hash: with_strong,
            components_with_weak_only: with_weak_only,
            algorithm_distribution: distribution,
            total_hashes,
        }
    }

    /// Calculate integrity quality score (0-100)
    ///
    /// Base 60% for any-hash coverage + 40% bonus for strong-hash coverage,
    /// with a penalty for weak-only components.
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        let any_coverage = self.components_with_any_hash as f32 / total_components as f32;
        let strong_coverage = self.components_with_strong_hash as f32 / total_components as f32;
        let weak_only_ratio = self.components_with_weak_only as f32 / total_components as f32;

        let base = any_coverage * 60.0;
        let strong_bonus = strong_coverage * 40.0;
        let weak_penalty = weak_only_ratio * 10.0;

        (base + strong_bonus - weak_penalty).clamp(0.0, 100.0)
    }
}

/// Whether a hash algorithm is considered cryptographically strong
fn is_strong_hash(algo: &HashAlgorithm) -> bool {
    matches!(
        algo,
        HashAlgorithm::Sha256
            | HashAlgorithm::Sha384
            | HashAlgorithm::Sha512
            | HashAlgorithm::Sha3_256
            | HashAlgorithm::Sha3_384
            | HashAlgorithm::Sha3_512
            | HashAlgorithm::Blake2b256
            | HashAlgorithm::Blake2b384
            | HashAlgorithm::Blake2b512
            | HashAlgorithm::Blake3
    )
}

/// Human-readable label for a hash algorithm
fn hash_algorithm_label(algo: &HashAlgorithm) -> String {
    match algo {
        HashAlgorithm::Md5 => "MD5".to_string(),
        HashAlgorithm::Sha1 => "SHA-1".to_string(),
        HashAlgorithm::Sha256 => "SHA-256".to_string(),
        HashAlgorithm::Sha384 => "SHA-384".to_string(),
        HashAlgorithm::Sha512 => "SHA-512".to_string(),
        HashAlgorithm::Sha3_256 => "SHA3-256".to_string(),
        HashAlgorithm::Sha3_384 => "SHA3-384".to_string(),
        HashAlgorithm::Sha3_512 => "SHA3-512".to_string(),
        HashAlgorithm::Blake2b256 => "BLAKE2b-256".to_string(),
        HashAlgorithm::Blake2b384 => "BLAKE2b-384".to_string(),
        HashAlgorithm::Blake2b512 => "BLAKE2b-512".to_string(),
        HashAlgorithm::Blake3 => "BLAKE3".to_string(),
        HashAlgorithm::Other(s) => s.clone(),
    }
}

// ============================================================================
// Identifier quality metrics
// ============================================================================

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
    /// Components with deprecated SPDX license identifiers
    pub deprecated_licenses: usize,
    /// Components with restrictive/copyleft licenses (GPL family)
    pub restrictive_licenses: usize,
    /// Specific copyleft license identifiers found
    pub copyleft_license_ids: Vec<String>,
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
        let mut deprecated = 0;
        let mut restrictive = 0;
        let mut licenses = HashSet::new();
        let mut copyleft_ids = HashSet::new();

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

                    if is_deprecated_spdx_license(expr) {
                        deprecated += 1;
                    }
                    if is_restrictive_license(expr) {
                        restrictive += 1;
                        copyleft_ids.insert(expr.clone());
                    }
                }
            }

            if comp.licenses.concluded.is_some() {
                with_concluded += 1;
            }
        }

        let mut license_list: Vec<String> = licenses.into_iter().collect();
        license_list.sort();

        let mut copyleft_list: Vec<String> = copyleft_ids.into_iter().collect();
        copyleft_list.sort();

        Self {
            with_declared,
            with_concluded,
            valid_spdx_expressions: valid_spdx,
            non_standard_licenses: non_standard,
            noassertion_count: noassertion,
            deprecated_licenses: deprecated,
            restrictive_licenses: restrictive,
            copyleft_license_ids: copyleft_list,
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

        // Penalty for deprecated licenses (2 points each, capped)
        let deprecated_penalty = (self.deprecated_licenses as f32 * 2.0).min(10.0);

        (coverage + spdx_bonus - noassertion_penalty - deprecated_penalty).clamp(0.0, 100.0)
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

            if comp.vex_status.is_some()
                || comp.vulnerabilities.iter().any(|v| v.vex_status.is_some())
            {
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

        remediation_ratio
            .mul_add(30.0, cvss_ratio.mul_add(40.0, cwe_ratio * 30.0))
            .min(100.0)
    }
}

// ============================================================================
// Dependency graph quality metrics
// ============================================================================

/// Maximum edge count before skipping expensive graph analysis
const MAX_EDGES_FOR_GRAPH_ANALYSIS: usize = 50_000;

/// Dependency graph quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyMetrics {
    /// Total dependency relationships
    pub total_dependencies: usize,
    /// Components with at least one dependency
    pub components_with_deps: usize,
    /// Maximum dependency depth (computed via BFS from roots)
    pub max_depth: Option<usize>,
    /// Average dependency depth across all reachable components
    pub avg_depth: Option<f32>,
    /// Orphan components (no incoming or outgoing deps)
    pub orphan_components: usize,
    /// Root components (no incoming deps, but has outgoing)
    pub root_components: usize,
    /// Number of dependency cycles detected
    pub cycle_count: usize,
    /// Number of disconnected subgraphs (islands)
    pub island_count: usize,
    /// Whether graph analysis was skipped due to size
    pub graph_analysis_skipped: bool,
}

impl DependencyMetrics {
    /// Calculate dependency metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        use crate::model::CanonicalId;

        let total_deps = sbom.edges.len();

        // Build adjacency lists using CanonicalId.value() for string keys
        let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut has_outgoing: HashSet<&str> = HashSet::new();
        let mut has_incoming: HashSet<&str> = HashSet::new();

        for edge in &sbom.edges {
            children
                .entry(edge.from.value())
                .or_default()
                .push(edge.to.value());
            has_outgoing.insert(edge.from.value());
            has_incoming.insert(edge.to.value());
        }

        let all_ids: Vec<&str> = sbom.components.keys().map(CanonicalId::value).collect();

        let orphans = all_ids
            .iter()
            .filter(|c| !has_outgoing.contains(*c) && !has_incoming.contains(*c))
            .count();

        let roots: Vec<&str> = has_outgoing
            .iter()
            .filter(|c| !has_incoming.contains(*c))
            .copied()
            .collect();
        let root_count = roots.len();

        // Skip expensive graph analysis for very large graphs
        if total_deps > MAX_EDGES_FOR_GRAPH_ANALYSIS {
            return Self {
                total_dependencies: total_deps,
                components_with_deps: has_outgoing.len(),
                max_depth: None,
                avg_depth: None,
                orphan_components: orphans,
                root_components: root_count,
                cycle_count: 0,
                island_count: 0,
                graph_analysis_skipped: true,
            };
        }

        // BFS from roots to compute depth
        let (max_depth, avg_depth) = compute_depth(&roots, &children);

        // DFS cycle detection
        let cycle_count = detect_cycles(&all_ids, &children);

        // Union-Find for island/subgraph detection
        let island_count = count_islands(&all_ids, &sbom.edges);

        Self {
            total_dependencies: total_deps,
            components_with_deps: has_outgoing.len(),
            max_depth,
            avg_depth,
            orphan_components: orphans,
            root_components: root_count,
            cycle_count,
            island_count,
            graph_analysis_skipped: false,
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

        // Slight penalty for orphan components
        let orphan_ratio = self.orphan_components as f32 / total_components as f32;
        let orphan_penalty = orphan_ratio * 10.0;

        // Penalty for cycles (5 points each, capped at 20)
        let cycle_penalty = (self.cycle_count as f32 * 5.0).min(20.0);

        // Penalty for excessive islands (>3 in multi-component SBOMs)
        let island_penalty = if total_components > 5 && self.island_count > 3 {
            ((self.island_count - 3) as f32 * 3.0).min(15.0)
        } else {
            0.0
        };

        (coverage - orphan_penalty - cycle_penalty - island_penalty).clamp(0.0, 100.0)
    }
}

/// BFS from roots to compute max and average depth
fn compute_depth(
    roots: &[&str],
    children: &HashMap<&str, Vec<&str>>,
) -> (Option<usize>, Option<f32>) {
    use std::collections::VecDeque;

    if roots.is_empty() {
        return (None, None);
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
    let mut max_d: usize = 0;
    let mut total_depth: usize = 0;
    let mut count: usize = 0;

    for &root in roots {
        if visited.insert(root) {
            queue.push_back((root, 0));
        }
    }

    while let Some((node, depth)) = queue.pop_front() {
        max_d = max_d.max(depth);
        total_depth += depth;
        count += 1;

        if let Some(kids) = children.get(node) {
            for &kid in kids {
                if visited.insert(kid) {
                    queue.push_back((kid, depth + 1));
                }
            }
        }
    }

    let avg = if count > 0 {
        Some(total_depth as f32 / count as f32)
    } else {
        None
    };

    (Some(max_d), avg)
}

/// DFS-based cycle detection (white/gray/black coloring)
fn detect_cycles(all_nodes: &[&str], children: &HashMap<&str, Vec<&str>>) -> usize {
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;

    let mut color: HashMap<&str, u8> = HashMap::with_capacity(all_nodes.len());
    for &node in all_nodes {
        color.insert(node, WHITE);
    }

    let mut cycles = 0;

    fn dfs<'a>(
        node: &'a str,
        children: &HashMap<&str, Vec<&'a str>>,
        color: &mut HashMap<&'a str, u8>,
        cycles: &mut usize,
    ) {
        color.insert(node, GRAY);

        if let Some(kids) = children.get(node) {
            for &kid in kids {
                match color.get(kid).copied().unwrap_or(WHITE) {
                    GRAY => *cycles += 1, // back edge = cycle
                    WHITE => dfs(kid, children, color, cycles),
                    _ => {}
                }
            }
        }

        color.insert(node, BLACK);
    }

    for &node in all_nodes {
        if color.get(node).copied().unwrap_or(WHITE) == WHITE {
            dfs(node, children, &mut color, &mut cycles);
        }
    }

    cycles
}

/// Union-Find to count disconnected subgraphs (islands)
fn count_islands(all_nodes: &[&str], edges: &[crate::model::DependencyEdge]) -> usize {
    if all_nodes.is_empty() {
        return 0;
    }

    // Map node IDs to indices
    let node_idx: HashMap<&str, usize> =
        all_nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut parent: Vec<usize> = (0..all_nodes.len()).collect();
    let mut rank: Vec<u8> = vec![0; all_nodes.len()];

    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]); // path compression
        }
        parent[x]
    }

    fn union(parent: &mut Vec<usize>, rank: &mut [u8], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            if rank[ra] < rank[rb] {
                parent[ra] = rb;
            } else if rank[ra] > rank[rb] {
                parent[rb] = ra;
            } else {
                parent[rb] = ra;
                rank[ra] += 1;
            }
        }
    }

    for edge in edges {
        if let (Some(&a), Some(&b)) = (
            node_idx.get(edge.from.value()),
            node_idx.get(edge.to.value()),
        ) {
            union(&mut parent, &mut rank, a, b);
        }
    }

    // Count unique roots
    let mut roots = HashSet::new();
    for i in 0..all_nodes.len() {
        roots.insert(find(&mut parent, i));
    }

    roots.len()
}

// ============================================================================
// Provenance metrics
// ============================================================================

/// Document provenance and authorship quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetrics {
    /// Whether the SBOM was created by an identified tool
    pub has_tool_creator: bool,
    /// Whether the tool creator includes version information
    pub has_tool_version: bool,
    /// Whether an organization is identified as creator
    pub has_org_creator: bool,
    /// Whether any creator has a contact email
    pub has_contact_email: bool,
    /// Whether the document has a serial number / namespace
    pub has_serial_number: bool,
    /// Whether the document has a name
    pub has_document_name: bool,
    /// Age of the SBOM in days (since creation timestamp)
    pub timestamp_age_days: u32,
    /// Whether the SBOM is considered fresh (< 90 days old)
    pub is_fresh: bool,
    /// Whether a primary/described component is identified
    pub has_primary_component: bool,
    /// SBOM lifecycle phase (from CycloneDX 1.5+ metadata)
    pub lifecycle_phase: Option<String>,
    /// Self-declared completeness level of the SBOM
    pub completeness_declaration: CompletenessDeclaration,
    /// Whether the SBOM has a digital signature
    pub has_signature: bool,
}

/// Freshness threshold in days
const FRESHNESS_THRESHOLD_DAYS: u32 = 90;

impl ProvenanceMetrics {
    /// Calculate provenance metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let doc = &sbom.document;

        let has_tool_creator = doc
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Tool);
        let has_tool_version = doc.creators.iter().any(|c| {
            c.creator_type == CreatorType::Tool
                && (c.name.contains(' ') || c.name.contains('/') || c.name.contains('@'))
        });
        let has_org_creator = doc
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Organization);
        let has_contact_email = doc.creators.iter().any(|c| c.email.is_some());

        let age_days = (chrono::Utc::now() - doc.created).num_days().max(0) as u32;

        Self {
            has_tool_creator,
            has_tool_version,
            has_org_creator,
            has_contact_email,
            has_serial_number: doc.serial_number.is_some(),
            has_document_name: doc.name.is_some(),
            timestamp_age_days: age_days,
            is_fresh: age_days < FRESHNESS_THRESHOLD_DAYS,
            has_primary_component: sbom.primary_component_id.is_some(),
            lifecycle_phase: doc.lifecycle_phase.clone(),
            completeness_declaration: doc.completeness_declaration.clone(),
            has_signature: doc.signature.is_some(),
        }
    }

    /// Calculate provenance quality score (0-100)
    ///
    /// Weighted checklist: tool creator (15%), tool version (5%), org creator (12%),
    /// contact email (8%), serial number (8%), document name (5%), freshness (12%),
    /// primary component (12%), completeness declaration (8%), signature (5%),
    /// lifecycle phase (10% CDX-only).
    #[must_use]
    pub fn quality_score(&self, is_cyclonedx: bool) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        let completeness_declared =
            self.completeness_declaration != CompletenessDeclaration::Unknown;

        let checks: &[(bool, f32)] = &[
            (self.has_tool_creator, 15.0),
            (self.has_tool_version, 5.0),
            (self.has_org_creator, 12.0),
            (self.has_contact_email, 8.0),
            (self.has_serial_number, 8.0),
            (self.has_document_name, 5.0),
            (self.is_fresh, 12.0),
            (self.has_primary_component, 12.0),
            (completeness_declared, 8.0),
            (self.has_signature, 5.0),
        ];

        for &(present, weight) in checks {
            if present {
                score += weight;
            }
            total_weight += weight;
        }

        // Lifecycle phase: only applicable for CycloneDX 1.5+
        if is_cyclonedx {
            let weight = 10.0;
            if self.lifecycle_phase.is_some() {
                score += weight;
            }
            total_weight += weight;
        }

        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }
}

// ============================================================================
// Auditability metrics
// ============================================================================

/// External reference and auditability quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditabilityMetrics {
    /// Components with VCS (version control) references
    pub components_with_vcs: usize,
    /// Components with website references
    pub components_with_website: usize,
    /// Components with security advisory references
    pub components_with_advisories: usize,
    /// Components with any external reference
    pub components_with_any_external_ref: usize,
    /// Whether the document has a security contact
    pub has_security_contact: bool,
    /// Whether the document has a vulnerability disclosure URL
    pub has_vuln_disclosure_url: bool,
}

impl AuditabilityMetrics {
    /// Calculate auditability metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_vcs = 0;
        let mut with_website = 0;
        let mut with_advisories = 0;
        let mut with_any = 0;

        for comp in sbom.components.values() {
            if comp.external_refs.is_empty() {
                continue;
            }
            with_any += 1;

            let has_vcs = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Vcs);
            let has_website = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Website);
            let has_advisories = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Advisories);

            if has_vcs {
                with_vcs += 1;
            }
            if has_website {
                with_website += 1;
            }
            if has_advisories {
                with_advisories += 1;
            }
        }

        Self {
            components_with_vcs: with_vcs,
            components_with_website: with_website,
            components_with_advisories: with_advisories,
            components_with_any_external_ref: with_any,
            has_security_contact: sbom.document.security_contact.is_some(),
            has_vuln_disclosure_url: sbom.document.vulnerability_disclosure_url.is_some(),
        }
    }

    /// Calculate auditability quality score (0-100)
    ///
    /// Component-level coverage (60%) + document-level security metadata (40%).
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        // Component-level: external ref coverage
        let ref_coverage =
            (self.components_with_any_external_ref as f32 / total_components as f32) * 40.0;
        let vcs_coverage = (self.components_with_vcs as f32 / total_components as f32) * 20.0;

        // Document-level security metadata
        let security_contact_score = if self.has_security_contact { 20.0 } else { 0.0 };
        let disclosure_score = if self.has_vuln_disclosure_url {
            20.0
        } else {
            0.0
        };

        (ref_coverage + vcs_coverage + security_contact_score + disclosure_score).min(100.0)
    }
}

// ============================================================================
// Lifecycle metrics
// ============================================================================

/// Component lifecycle quality metrics (requires enrichment data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleMetrics {
    /// Components that have reached end-of-life
    pub eol_components: usize,
    /// Components classified as stale (no updates for 1+ years)
    pub stale_components: usize,
    /// Components explicitly marked as deprecated
    pub deprecated_components: usize,
    /// Components with archived repositories
    pub archived_components: usize,
    /// Components with a newer version available
    pub outdated_components: usize,
    /// Components that had lifecycle enrichment data
    pub enriched_components: usize,
    /// Enrichment coverage percentage (0-100)
    pub enrichment_coverage: f32,
}

impl LifecycleMetrics {
    /// Calculate lifecycle metrics from an SBOM
    ///
    /// These metrics are only meaningful after enrichment. When
    /// `enrichment_coverage == 0`, the lifecycle score should be
    /// treated as N/A and excluded from the weighted total.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        let mut eol = 0;
        let mut stale = 0;
        let mut deprecated = 0;
        let mut archived = 0;
        let mut outdated = 0;
        let mut enriched = 0;

        for comp in sbom.components.values() {
            let has_lifecycle_data = comp.eol.is_some() || comp.staleness.is_some();
            if has_lifecycle_data {
                enriched += 1;
            }

            if let Some(ref eol_info) = comp.eol
                && eol_info.status == EolStatus::EndOfLife
            {
                eol += 1;
            }

            if let Some(ref stale_info) = comp.staleness {
                match stale_info.level {
                    StalenessLevel::Stale | StalenessLevel::Abandoned => stale += 1,
                    StalenessLevel::Deprecated => deprecated += 1,
                    StalenessLevel::Archived => archived += 1,
                    _ => {}
                }
                if stale_info.is_deprecated {
                    deprecated += 1;
                }
                if stale_info.is_archived {
                    archived += 1;
                }
                if stale_info.latest_version.is_some() {
                    outdated += 1;
                }
            }
        }

        let coverage = if total > 0 {
            (enriched as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        Self {
            eol_components: eol,
            stale_components: stale,
            deprecated_components: deprecated,
            archived_components: archived,
            outdated_components: outdated,
            enriched_components: enriched,
            enrichment_coverage: coverage,
        }
    }

    /// Whether enrichment data is available for scoring
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.enriched_components > 0
    }

    /// Calculate lifecycle quality score (0-100)
    ///
    /// Starts at 100, subtracts penalties for problematic components.
    /// Returns `None` if no enrichment data is available.
    #[must_use]
    pub fn quality_score(&self) -> Option<f32> {
        if !self.has_data() {
            return None;
        }

        let mut score = 100.0_f32;

        // EOL: severe penalty (15 points each, capped at 60)
        score -= (self.eol_components as f32 * 15.0).min(60.0);
        // Stale: moderate penalty (5 points each, capped at 30)
        score -= (self.stale_components as f32 * 5.0).min(30.0);
        // Deprecated/archived: moderate penalty (3 points each, capped at 20)
        score -= ((self.deprecated_components + self.archived_components) as f32 * 3.0).min(20.0);
        // Outdated: mild penalty (1 point each, capped at 10)
        score -= (self.outdated_components as f32 * 1.0).min(10.0);

        Some(score.clamp(0.0, 100.0))
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn is_valid_purl(purl: &str) -> bool {
    // Basic PURL validation: pkg:type/namespace/name@version
    purl.starts_with("pkg:") && purl.contains('/')
}

fn extract_ecosystem_from_purl(purl: &str) -> Option<String> {
    // Extract type from pkg:type/...
    if let Some(rest) = purl.strip_prefix("pkg:")
        && let Some(slash_idx) = rest.find('/')
    {
        return Some(rest[..slash_idx].to_string());
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

/// Whether a license identifier is on the SPDX deprecated list.
///
/// These are license IDs that SPDX has deprecated in favor of more specific
/// identifiers (e.g., `GPL-2.0` → `GPL-2.0-only` or `GPL-2.0-or-later`).
fn is_deprecated_spdx_license(expr: &str) -> bool {
    const DEPRECATED: &[&str] = &[
        "GPL-2.0",
        "GPL-2.0+",
        "GPL-3.0",
        "GPL-3.0+",
        "LGPL-2.0",
        "LGPL-2.0+",
        "LGPL-2.1",
        "LGPL-2.1+",
        "LGPL-3.0",
        "LGPL-3.0+",
        "AGPL-1.0",
        "AGPL-3.0",
        "GFDL-1.1",
        "GFDL-1.2",
        "GFDL-1.3",
        "BSD-2-Clause-FreeBSD",
        "BSD-2-Clause-NetBSD",
        "eCos-2.0",
        "Nunit",
        "StandardML-NJ",
        "wxWindows",
    ];
    let trimmed = expr.trim();
    DEPRECATED.contains(&trimmed)
}

/// Whether a license is considered restrictive/copyleft (GPL family).
///
/// This is informational — restrictive licenses are not inherently a quality
/// issue, but organizations need to know about them for compliance.
fn is_restrictive_license(expr: &str) -> bool {
    let trimmed = expr.trim().to_uppercase();
    trimmed.starts_with("GPL")
        || trimmed.starts_with("LGPL")
        || trimmed.starts_with("AGPL")
        || trimmed.starts_with("EUPL")
        || trimmed.starts_with("SSPL")
        || trimmed.starts_with("OSL")
        || trimmed.starts_with("CPAL")
        || trimmed.starts_with("CC-BY-SA")
        || trimmed.starts_with("CC-BY-NC")
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

    #[test]
    fn test_strong_hash_classification() {
        assert!(is_strong_hash(&HashAlgorithm::Sha256));
        assert!(is_strong_hash(&HashAlgorithm::Sha3_256));
        assert!(is_strong_hash(&HashAlgorithm::Blake3));
        assert!(!is_strong_hash(&HashAlgorithm::Md5));
        assert!(!is_strong_hash(&HashAlgorithm::Sha1));
        assert!(!is_strong_hash(&HashAlgorithm::Other("custom".to_string())));
    }

    #[test]
    fn test_deprecated_license_detection() {
        assert!(is_deprecated_spdx_license("GPL-2.0"));
        assert!(is_deprecated_spdx_license("LGPL-2.1"));
        assert!(is_deprecated_spdx_license("AGPL-3.0"));
        assert!(!is_deprecated_spdx_license("GPL-2.0-only"));
        assert!(!is_deprecated_spdx_license("MIT"));
        assert!(!is_deprecated_spdx_license("Apache-2.0"));
    }

    #[test]
    fn test_restrictive_license_detection() {
        assert!(is_restrictive_license("GPL-3.0-only"));
        assert!(is_restrictive_license("LGPL-2.1-or-later"));
        assert!(is_restrictive_license("AGPL-3.0-only"));
        assert!(is_restrictive_license("EUPL-1.2"));
        assert!(is_restrictive_license("CC-BY-SA-4.0"));
        assert!(!is_restrictive_license("MIT"));
        assert!(!is_restrictive_license("Apache-2.0"));
        assert!(!is_restrictive_license("BSD-3-Clause"));
    }

    #[test]
    fn test_hash_quality_score_no_components() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 0,
            components_with_strong_hash: 0,
            components_with_weak_only: 0,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 0,
        };
        assert_eq!(metrics.quality_score(0), 0.0);
    }

    #[test]
    fn test_hash_quality_score_all_strong() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 10,
            components_with_strong_hash: 10,
            components_with_weak_only: 0,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 10,
        };
        assert_eq!(metrics.quality_score(10), 100.0);
    }

    #[test]
    fn test_hash_quality_score_weak_only_penalty() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 10,
            components_with_strong_hash: 0,
            components_with_weak_only: 10,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 10,
        };
        // 60 (any) + 0 (strong) - 10 (weak penalty) = 50
        assert_eq!(metrics.quality_score(10), 50.0);
    }

    #[test]
    fn test_lifecycle_no_enrichment_returns_none() {
        let metrics = LifecycleMetrics {
            eol_components: 0,
            stale_components: 0,
            deprecated_components: 0,
            archived_components: 0,
            outdated_components: 0,
            enriched_components: 0,
            enrichment_coverage: 0.0,
        };
        assert!(!metrics.has_data());
        assert!(metrics.quality_score().is_none());
    }

    #[test]
    fn test_lifecycle_with_eol_penalty() {
        let metrics = LifecycleMetrics {
            eol_components: 2,
            stale_components: 0,
            deprecated_components: 0,
            archived_components: 0,
            outdated_components: 0,
            enriched_components: 10,
            enrichment_coverage: 100.0,
        };
        // 100 - 30 (2 * 15) = 70
        assert_eq!(metrics.quality_score(), Some(70.0));
    }

    #[test]
    fn test_cycle_detection_no_cycles() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["b"]), ("b", vec!["c"])]);
        let all_nodes = vec!["a", "b", "c"];
        assert_eq!(detect_cycles(&all_nodes, &children), 0);
    }

    #[test]
    fn test_cycle_detection_with_cycle() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["b"]), ("b", vec!["c"]), ("c", vec!["a"])]);
        let all_nodes = vec!["a", "b", "c"];
        assert_eq!(detect_cycles(&all_nodes, &children), 1);
    }

    #[test]
    fn test_depth_computation() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("root", vec!["a", "b"]), ("a", vec!["c"])]);
        let roots = vec!["root"];
        let (max_d, avg_d) = compute_depth(&roots, &children);
        assert_eq!(max_d, Some(2)); // root -> a -> c
        assert!(avg_d.is_some());
    }

    #[test]
    fn test_depth_empty_roots() {
        let children: HashMap<&str, Vec<&str>> = HashMap::new();
        let roots: Vec<&str> = vec![];
        let (max_d, avg_d) = compute_depth(&roots, &children);
        assert_eq!(max_d, None);
        assert_eq!(avg_d, None);
    }

    #[test]
    fn test_provenance_quality_score() {
        let metrics = ProvenanceMetrics {
            has_tool_creator: true,
            has_tool_version: true,
            has_org_creator: true,
            has_contact_email: true,
            has_serial_number: true,
            has_document_name: true,
            timestamp_age_days: 10,
            is_fresh: true,
            has_primary_component: true,
            lifecycle_phase: Some("build".to_string()),
            completeness_declaration: CompletenessDeclaration::Complete,
            has_signature: true,
        };
        // All checks pass for CycloneDX
        assert_eq!(metrics.quality_score(true), 100.0);
    }

    #[test]
    fn test_provenance_score_without_cyclonedx() {
        let metrics = ProvenanceMetrics {
            has_tool_creator: true,
            has_tool_version: true,
            has_org_creator: true,
            has_contact_email: true,
            has_serial_number: true,
            has_document_name: true,
            timestamp_age_days: 10,
            is_fresh: true,
            has_primary_component: true,
            lifecycle_phase: None,
            completeness_declaration: CompletenessDeclaration::Complete,
            has_signature: true,
        };
        // Lifecycle phase excluded for non-CDX
        assert_eq!(metrics.quality_score(false), 100.0);
    }

    #[test]
    fn test_completeness_declaration_display() {
        assert_eq!(CompletenessDeclaration::Complete.to_string(), "complete");
        assert_eq!(
            CompletenessDeclaration::IncompleteFirstPartyOnly.to_string(),
            "incomplete (first-party only)"
        );
        assert_eq!(CompletenessDeclaration::Unknown.to_string(), "unknown");
    }
}
