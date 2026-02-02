//! Multi-SBOM comparison data structures and engines.
//!
//! Supports:
//! - 1:N diff-multi (baseline vs multiple targets)
//! - Timeline analysis (incremental version evolution)
//! - N×N matrix comparison (all pairs)

use super::DiffResult;
use crate::model::{NormalizedSbom, VulnerabilityCounts};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// SBOM Info (common metadata)
// ============================================================================

/// Basic information about an SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomInfo {
    /// Display name (user-provided label or filename)
    pub name: String,
    /// File path
    pub file_path: String,
    /// Format (CycloneDX, SPDX)
    pub format: String,
    /// Number of components
    pub component_count: usize,
    /// Number of dependencies
    pub dependency_count: usize,
    /// Vulnerability counts
    pub vulnerability_counts: VulnerabilityCounts,
    /// Timestamp if available
    pub timestamp: Option<String>,
}

impl SbomInfo {
    pub fn from_sbom(sbom: &NormalizedSbom, name: String, file_path: String) -> Self {
        Self {
            name,
            file_path,
            format: sbom.document.format.to_string(),
            component_count: sbom.component_count(),
            dependency_count: sbom.edges.len(),
            vulnerability_counts: sbom.vulnerability_counts(),
            timestamp: Some(sbom.document.created.to_rfc3339()),
        }
    }
}

// ============================================================================
// 1:N MULTI-DIFF RESULT
// ============================================================================

/// Result of 1:N baseline comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDiffResult {
    /// Baseline SBOM information
    pub baseline: SbomInfo,
    /// Individual comparison results for each target
    pub comparisons: Vec<ComparisonResult>,
    /// Aggregated summary across all comparisons
    pub summary: MultiDiffSummary,
}

/// Individual comparison result (baseline vs one target)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Target SBOM information
    pub target: SbomInfo,
    /// Full diff result (same as 1:1 diff)
    pub diff: DiffResult,
    /// Components unique to this target (not in baseline or other targets)
    pub unique_components: Vec<String>,
    /// Components shared with baseline but different from other targets
    pub divergent_components: Vec<DivergentComponent>,
}

/// Component that differs across targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergentComponent {
    pub id: String,
    pub name: String,
    pub baseline_version: Option<String>,
    pub target_version: String,
    /// All versions across targets: target_name -> version
    pub versions_across_targets: HashMap<String, String>,
    pub divergence_type: DivergenceType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceType {
    /// Version differs from baseline
    VersionMismatch,
    /// Component added (not in baseline)
    Added,
    /// Component removed (in baseline, not in target)
    Removed,
    /// Different license
    LicenseMismatch,
    /// Different supplier
    SupplierMismatch,
}

// ============================================================================
// MULTI-DIFF SUMMARY
// ============================================================================

/// Aggregated summary across all 1:N comparisons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDiffSummary {
    /// Total component count in baseline
    pub baseline_component_count: usize,
    /// Components present in ALL targets (including baseline)
    pub universal_components: Vec<String>,
    /// Components that have different versions across targets
    pub variable_components: Vec<VariableComponent>,
    /// Components missing from one or more targets
    pub inconsistent_components: Vec<InconsistentComponent>,
    /// Per-target deviation scores
    pub deviation_scores: HashMap<String, f64>,
    /// Maximum deviation from baseline
    pub max_deviation: f64,
    /// Aggregate vulnerability exposure across targets
    pub vulnerability_matrix: VulnerabilityMatrix,
}

/// Component with version variation across targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableComponent {
    pub id: String,
    pub name: String,
    pub ecosystem: Option<String>,
    pub version_spread: VersionSpread,
    pub targets_with_component: Vec<String>,
    pub security_impact: SecurityImpact,
}

/// Version distribution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSpread {
    /// Baseline version
    pub baseline: Option<String>,
    /// Lowest version seen (as string, parsed if semver)
    pub min_version: Option<String>,
    /// Highest version seen
    pub max_version: Option<String>,
    /// All unique versions
    pub unique_versions: Vec<String>,
    /// True if all targets have same version
    pub is_consistent: bool,
    /// Number of major version differences
    pub major_version_spread: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityImpact {
    /// Critical security component with version spread (e.g., openssl, curl)
    Critical,
    /// Security-relevant component
    High,
    /// Standard component
    Medium,
    /// Low-risk component
    Low,
}

impl SecurityImpact {
    pub fn label(&self) -> &'static str {
        match self {
            SecurityImpact::Critical => "CRITICAL",
            SecurityImpact::High => "high",
            SecurityImpact::Medium => "medium",
            SecurityImpact::Low => "low",
        }
    }
}

/// Component missing from some targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InconsistentComponent {
    pub id: String,
    pub name: String,
    /// True if in baseline
    pub in_baseline: bool,
    /// Targets that have this component
    pub present_in: Vec<String>,
    /// Targets missing this component
    pub missing_from: Vec<String>,
}

/// Vulnerability counts across all SBOMs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatrix {
    /// Vulnerability counts per SBOM name
    pub per_sbom: HashMap<String, VulnerabilityCounts>,
    /// Vulnerabilities unique to specific targets
    pub unique_vulnerabilities: HashMap<String, Vec<String>>,
    /// Vulnerabilities common to all
    pub common_vulnerabilities: Vec<String>,
}

// ============================================================================
// TIMELINE RESULT
// ============================================================================

/// Timeline analysis result (incremental version evolution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResult {
    /// Ordered list of SBOMs in timeline
    pub sboms: Vec<SbomInfo>,
    /// Incremental diffs: [0→1, 1→2, 2→3, ...]
    pub incremental_diffs: Vec<DiffResult>,
    /// Cumulative diffs from first: [0→1, 0→2, 0→3, ...]
    pub cumulative_from_first: Vec<DiffResult>,
    /// High-level evolution summary
    pub evolution_summary: EvolutionSummary,
}

/// High-level evolution across the timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionSummary {
    /// Components added over the timeline
    pub components_added: Vec<ComponentEvolution>,
    /// Components removed over the timeline
    pub components_removed: Vec<ComponentEvolution>,
    /// Version progression for each component: component_id -> versions at each point
    pub version_history: HashMap<String, Vec<VersionAtPoint>>,
    /// Vulnerability trend over time
    pub vulnerability_trend: Vec<VulnerabilitySnapshot>,
    /// License changes over time
    pub license_changes: Vec<LicenseChange>,
    /// Dependency count trend
    pub dependency_trend: Vec<DependencySnapshot>,
    /// Compliance score trend across SBOM versions
    pub compliance_trend: Vec<ComplianceSnapshot>,
}

/// Component lifecycle in the timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEvolution {
    pub id: String,
    pub name: String,
    /// Index in timeline when first seen
    pub first_seen_index: usize,
    pub first_seen_version: String,
    /// Index when last seen (None if still present at end)
    pub last_seen_index: Option<usize>,
    /// Current version (at end of timeline)
    pub current_version: Option<String>,
    /// Total version changes
    pub version_change_count: usize,
}

/// Version of a component at a point in the timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionAtPoint {
    pub sbom_index: usize,
    pub sbom_name: String,
    pub version: Option<String>,
    pub change_type: VersionChangeType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionChangeType {
    Initial,
    MajorUpgrade,
    MinorUpgrade,
    PatchUpgrade,
    Downgrade,
    Unchanged,
    Removed,
    Absent,
}

impl VersionChangeType {
    pub fn symbol(&self) -> &'static str {
        match self {
            VersionChangeType::Initial => "●",
            VersionChangeType::MajorUpgrade => "⬆",
            VersionChangeType::MinorUpgrade => "↑",
            VersionChangeType::PatchUpgrade => "↗",
            VersionChangeType::Downgrade => "⬇",
            VersionChangeType::Unchanged => "─",
            VersionChangeType::Removed => "✗",
            VersionChangeType::Absent => " ",
        }
    }
}

/// Compliance score at a point in timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSnapshot {
    pub sbom_index: usize,
    pub sbom_name: String,
    /// Compliance scores per standard: (standard_name, error_count, warning_count, is_compliant)
    pub scores: Vec<ComplianceScoreEntry>,
}

/// A single compliance score entry for one standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScoreEntry {
    pub standard: String,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub is_compliant: bool,
}

/// Vulnerability counts at a point in timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySnapshot {
    pub sbom_index: usize,
    pub sbom_name: String,
    pub counts: VulnerabilityCounts,
    pub new_vulnerabilities: Vec<String>,
    pub resolved_vulnerabilities: Vec<String>,
}

/// License change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseChange {
    pub sbom_index: usize,
    pub component_id: String,
    pub component_name: String,
    pub old_license: Vec<String>,
    pub new_license: Vec<String>,
    pub change_type: LicenseChangeType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseChangeType {
    MorePermissive,
    MoreRestrictive,
    Incompatible,
    Equivalent,
}

/// Dependency count at a point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencySnapshot {
    pub sbom_index: usize,
    pub sbom_name: String,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub total_edges: usize,
}

// ============================================================================
// MATRIX RESULT
// ============================================================================

/// N×N comparison matrix result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixResult {
    /// All SBOMs in comparison
    pub sboms: Vec<SbomInfo>,
    /// Upper-triangle matrix of diff results
    /// Access with matrix[i * sboms.len() + j] where i < j
    pub diffs: Vec<Option<DiffResult>>,
    /// Similarity scores (0.0 = completely different, 1.0 = identical)
    /// Same indexing as diffs
    pub similarity_scores: Vec<f64>,
    /// Optional clustering based on similarity
    pub clustering: Option<SbomClustering>,
}

impl MatrixResult {
    /// Get diff between sboms[i] and sboms[j]
    pub fn get_diff(&self, i: usize, j: usize) -> Option<&DiffResult> {
        if i == j {
            return None;
        }
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        let idx = self.matrix_index(a, b);
        self.diffs.get(idx).and_then(|d| d.as_ref())
    }

    /// Get similarity between sboms[i] and sboms[j]
    pub fn get_similarity(&self, i: usize, j: usize) -> f64 {
        if i == j {
            return 1.0;
        }
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        let idx = self.matrix_index(a, b);
        self.similarity_scores.get(idx).copied().unwrap_or(0.0)
    }

    /// Calculate index in flattened upper-triangle matrix
    fn matrix_index(&self, i: usize, j: usize) -> usize {
        let n = self.sboms.len();
        // Upper triangle index formula: i * (2n - i - 1) / 2 + (j - i - 1)
        i * (2 * n - i - 1) / 2 + (j - i - 1)
    }

    /// Number of pairs (n choose 2)
    pub fn num_pairs(&self) -> usize {
        let n = self.sboms.len();
        n * (n - 1) / 2
    }
}

/// Clustering of similar SBOMs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomClustering {
    /// Identified clusters of similar SBOMs
    pub clusters: Vec<SbomCluster>,
    /// Outliers that don't fit any cluster (indices into sboms)
    pub outliers: Vec<usize>,
    /// Clustering algorithm used
    pub algorithm: String,
    /// Threshold used for clustering
    pub threshold: f64,
}

/// A cluster of similar SBOMs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomCluster {
    /// Indices into sboms vec
    pub members: Vec<usize>,
    /// Most representative SBOM (centroid)
    pub centroid_index: usize,
    /// Average internal similarity
    pub internal_similarity: f64,
    /// Cluster label (auto-generated or user-provided)
    pub label: Option<String>,
}

// ============================================================================
// INCREMENTAL CHANGE SUMMARY (for timeline)
// ============================================================================

/// Summary of changes between two adjacent versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalChange {
    pub from_index: usize,
    pub to_index: usize,
    pub from_name: String,
    pub to_name: String,
    pub components_added: usize,
    pub components_removed: usize,
    pub components_modified: usize,
    pub vulnerabilities_introduced: usize,
    pub vulnerabilities_resolved: usize,
}

impl IncrementalChange {
    pub fn from_diff(
        from_idx: usize,
        to_idx: usize,
        from_name: &str,
        to_name: &str,
        diff: &DiffResult,
    ) -> Self {
        Self {
            from_index: from_idx,
            to_index: to_idx,
            from_name: from_name.to_string(),
            to_name: to_name.to_string(),
            components_added: diff.summary.components_added,
            components_removed: diff.summary.components_removed,
            components_modified: diff.summary.components_modified,
            vulnerabilities_introduced: diff.summary.vulnerabilities_introduced,
            vulnerabilities_resolved: diff.summary.vulnerabilities_resolved,
        }
    }
}
