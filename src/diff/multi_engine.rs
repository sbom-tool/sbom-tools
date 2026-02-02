//! Multi-SBOM comparison engines.
//!
//! Uses [`IncrementalDiffEngine`] internally to cache diff results across
//! repeated comparisons (timeline, matrix, diff-multi), avoiding redundant
//! recomputation when the same SBOM pair is compared multiple times.

use super::incremental::IncrementalDiffEngine;
use super::multi::*;
use super::{DiffEngine, DiffResult};
use crate::matching::FuzzyMatchConfig;
use crate::model::{NormalizedSbom, VulnerabilityCounts};
use std::collections::{HashMap, HashSet};

/// Engine for multi-SBOM comparisons.
///
/// Internally wraps an [`IncrementalDiffEngine`] so that repeated comparisons
/// of the same SBOM pairs (common in timeline and matrix modes) benefit from
/// result caching.
pub struct MultiDiffEngine {
    /// Fuzzy matching configuration (applied when building the engine).
    fuzzy_config: Option<FuzzyMatchConfig>,
    /// Whether to include unchanged components in diff results.
    include_unchanged: bool,
    /// Caching wrapper built lazily on first diff operation.
    incremental: Option<IncrementalDiffEngine>,
}

impl MultiDiffEngine {
    pub fn new() -> Self {
        Self {
            fuzzy_config: None,
            include_unchanged: false,
            incremental: None,
        }
    }

    /// Configure fuzzy matching
    pub fn with_fuzzy_config(mut self, config: FuzzyMatchConfig) -> Self {
        self.fuzzy_config = Some(config);
        self.incremental = None;
        self
    }

    /// Include unchanged components
    pub fn include_unchanged(mut self, include: bool) -> Self {
        self.include_unchanged = include;
        self.incremental = None;
        self
    }

    /// Build the configured DiffEngine and wrap it in an IncrementalDiffEngine.
    fn ensure_engine(&mut self) {
        if self.incremental.is_none() {
            let mut engine = DiffEngine::new();
            if let Some(config) = self.fuzzy_config.clone() {
                engine = engine.with_fuzzy_config(config);
            }
            engine = engine.include_unchanged(self.include_unchanged);
            self.incremental = Some(IncrementalDiffEngine::new(engine));
        }
    }

    /// Perform a single diff using the cached incremental engine.
    fn cached_diff(&mut self, old: &NormalizedSbom, new: &NormalizedSbom) -> DiffResult {
        self.ensure_engine();
        self.incremental
            .as_ref()
            .expect("engine initialized by ensure_engine")
            .diff(old, new)
            .into_result()
    }

    /// Perform 1:N diff-multi comparison (baseline vs multiple targets)
    pub fn diff_multi(
        &mut self,
        baseline: &NormalizedSbom,
        baseline_name: &str,
        baseline_path: &str,
        targets: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
    ) -> MultiDiffResult {
        let baseline_info = SbomInfo::from_sbom(
            baseline,
            baseline_name.to_string(),
            baseline_path.to_string(),
        );

        // Compute individual diffs
        let mut comparisons: Vec<ComparisonResult> = Vec::new();
        let mut all_versions: HashMap<String, HashMap<String, String>> = HashMap::new(); // component_id -> (target_name -> version)

        // Collect baseline versions
        for (id, comp) in &baseline.components {
            let version = comp.version.clone().unwrap_or_default();
            all_versions
                .entry(id.value().to_string())
                .or_default()
                .insert(baseline_name.to_string(), version);
        }

        for (target_sbom, target_name, target_path) in targets {
            let diff = self.cached_diff(baseline, target_sbom);
            let target_info = SbomInfo::from_sbom(
                target_sbom,
                target_name.to_string(),
                target_path.to_string(),
            );

            // Collect target versions
            for (id, comp) in &target_sbom.components {
                let version = comp.version.clone().unwrap_or_default();
                all_versions
                    .entry(id.value().to_string())
                    .or_default()
                    .insert(target_name.to_string(), version);
            }

            comparisons.push(ComparisonResult {
                target: target_info,
                diff,
                unique_components: vec![],    // Computed in summary phase
                divergent_components: vec![], // Computed in summary phase
            });
        }

        // Compute summary
        let summary = self.compute_multi_diff_summary(
            &baseline_info,
            baseline,
            &comparisons,
            targets,
            &all_versions,
        );

        // Update comparisons with divergent component info
        for (i, comp) in comparisons.iter_mut().enumerate() {
            let (target_sbom, target_name, _) = &targets[i];
            comp.divergent_components =
                self.find_divergent_components(baseline, target_sbom, target_name, &all_versions);
        }

        MultiDiffResult {
            baseline: baseline_info,
            comparisons,
            summary,
        }
    }

    fn compute_multi_diff_summary(
        &self,
        baseline_info: &SbomInfo,
        baseline: &NormalizedSbom,
        comparisons: &[ComparisonResult],
        targets: &[(&NormalizedSbom, &str, &str)],
        all_versions: &HashMap<String, HashMap<String, String>>,
    ) -> MultiDiffSummary {
        let baseline_components: HashSet<_> = baseline
            .components
            .keys()
            .map(|k| k.value().to_string())
            .collect();
        let _target_names: Vec<_> = targets
            .iter()
            .map(|(_, name, _)| name.to_string())
            .collect();

        // Find universal components (in baseline and ALL targets)
        let mut universal: HashSet<String> = baseline_components.clone();
        for (target_sbom, _, _) in targets {
            let target_components: HashSet<_> = target_sbom
                .components
                .keys()
                .map(|k| k.value().to_string())
                .collect();
            universal = universal
                .intersection(&target_components)
                .cloned()
                .collect();
        }

        // Find variable components (different versions across targets)
        let mut variable_components: Vec<VariableComponent> = vec![];
        for (comp_id, versions) in all_versions {
            let unique_versions: HashSet<_> = versions.values().collect();
            if unique_versions.len() > 1 {
                let name = baseline
                    .components
                    .iter()
                    .find(|(id, _)| id.value() == comp_id)
                    .map(|(_, c)| c.name.clone())
                    .or_else(|| {
                        targets.iter().find_map(|(sbom, _, _)| {
                            sbom.components
                                .iter()
                                .find(|(id, _)| id.value() == comp_id)
                                .map(|(_, c)| c.name.clone())
                        })
                    })
                    .unwrap_or_else(|| comp_id.clone());

                let baseline_version = versions.get(&baseline_info.name.to_string()).cloned();
                let all_versions_vec: Vec<_> = unique_versions.into_iter().cloned().collect();

                // Calculate major version spread
                let major_spread = calculate_major_version_spread(&all_versions_vec);

                variable_components.push(VariableComponent {
                    id: comp_id.clone(),
                    name: name.clone(),
                    ecosystem: None,
                    version_spread: VersionSpread {
                        baseline: baseline_version,
                        min_version: all_versions_vec.iter().min().cloned(),
                        max_version: all_versions_vec.iter().max().cloned(),
                        unique_versions: all_versions_vec,
                        is_consistent: false,
                        major_version_spread: major_spread,
                    },
                    targets_with_component: versions.keys().cloned().collect(),
                    security_impact: classify_security_impact(&name),
                });
            }
        }

        // Find inconsistent components (missing from some targets)
        let mut inconsistent_components: Vec<InconsistentComponent> = vec![];
        let all_component_ids: HashSet<_> = all_versions.keys().cloned().collect();

        for comp_id in &all_component_ids {
            if universal.contains(comp_id) {
                continue; // Present everywhere, not inconsistent
            }

            let in_baseline = baseline_components.contains(comp_id);
            let mut present_in: Vec<String> = vec![];
            let mut missing_from: Vec<String> = vec![];

            if in_baseline {
                present_in.push(baseline_info.name.clone());
            } else {
                missing_from.push(baseline_info.name.clone());
            }

            for (target_sbom, target_name, _) in targets {
                let has_component = target_sbom
                    .components
                    .iter()
                    .any(|(id, _)| id.value() == comp_id);
                if has_component {
                    present_in.push(target_name.to_string());
                } else {
                    missing_from.push(target_name.to_string());
                }
            }

            if !missing_from.is_empty() {
                let name = all_versions
                    .get(comp_id)
                    .and_then(|_| {
                        baseline
                            .components
                            .iter()
                            .find(|(id, _)| id.value() == comp_id)
                            .map(|(_, c)| c.name.clone())
                    })
                    .unwrap_or_else(|| comp_id.clone());

                inconsistent_components.push(InconsistentComponent {
                    id: comp_id.clone(),
                    name,
                    in_baseline,
                    present_in,
                    missing_from,
                });
            }
        }

        // Compute deviation scores
        let mut deviation_scores: HashMap<String, f64> = HashMap::new();
        let mut max_deviation = 0.0f64;

        for comp in comparisons {
            let score = 100.0 - comp.diff.semantic_score;
            deviation_scores.insert(comp.target.name.clone(), score);
            max_deviation = max_deviation.max(score);
        }

        // Build vulnerability matrix with unique and common vulnerabilities
        let vulnerability_matrix =
            compute_vulnerability_matrix(baseline, &baseline_info.name, targets);

        MultiDiffSummary {
            baseline_component_count: baseline_info.component_count,
            universal_components: universal.into_iter().collect(),
            variable_components,
            inconsistent_components,
            deviation_scores,
            max_deviation,
            vulnerability_matrix,
        }
    }

    fn find_divergent_components(
        &self,
        baseline: &NormalizedSbom,
        target: &NormalizedSbom,
        _target_name: &str,
        all_versions: &HashMap<String, HashMap<String, String>>,
    ) -> Vec<DivergentComponent> {
        let mut divergent = vec![];

        for (id, comp) in &target.components {
            let comp_id = id.value().to_string();
            let target_version = comp.version.clone().unwrap_or_default();

            // Check if baseline has different version
            let baseline_version = baseline
                .components
                .iter()
                .find(|(bid, _)| bid.value() == comp_id)
                .and_then(|(_, bc)| bc.version.clone());

            let divergence_type = if baseline_version.is_none() {
                DivergenceType::Added
            } else if baseline_version.as_ref() != Some(&target_version) {
                DivergenceType::VersionMismatch
            } else {
                continue; // Same version, not divergent
            };

            divergent.push(DivergentComponent {
                id: comp_id.clone(),
                name: comp.name.clone(),
                baseline_version,
                target_version,
                versions_across_targets: all_versions.get(&comp_id).cloned().unwrap_or_default(),
                divergence_type,
            });
        }

        // Check for removed components
        for (id, comp) in &baseline.components {
            let comp_id = id.value().to_string();
            let in_target = target
                .components
                .iter()
                .any(|(tid, _)| tid.value() == comp_id);

            if !in_target {
                divergent.push(DivergentComponent {
                    id: comp_id.clone(),
                    name: comp.name.clone(),
                    baseline_version: comp.version.clone(),
                    target_version: String::new(),
                    versions_across_targets: all_versions
                        .get(&comp_id)
                        .cloned()
                        .unwrap_or_default(),
                    divergence_type: DivergenceType::Removed,
                });
            }
        }

        divergent
    }

    /// Perform timeline analysis across ordered SBOM versions
    pub fn timeline(
        &mut self,
        sboms: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
    ) -> TimelineResult {
        let sbom_infos: Vec<SbomInfo> = sboms
            .iter()
            .map(|(sbom, name, path)| SbomInfo::from_sbom(sbom, name.to_string(), path.to_string()))
            .collect();

        // Compute incremental diffs (adjacent pairs)
        let mut incremental_diffs: Vec<DiffResult> = vec![];
        for i in 0..sboms.len().saturating_sub(1) {
            let diff = self.cached_diff(sboms[i].0, sboms[i + 1].0);
            incremental_diffs.push(diff);
        }

        // Compute cumulative diffs from first
        let mut cumulative_from_first: Vec<DiffResult> = vec![];
        if !sboms.is_empty() {
            for i in 1..sboms.len() {
                let diff = self.cached_diff(sboms[0].0, sboms[i].0);
                cumulative_from_first.push(diff);
            }
        }

        // Build evolution summary
        let evolution_summary =
            self.build_evolution_summary(sboms, &sbom_infos, &incremental_diffs);

        TimelineResult {
            sboms: sbom_infos,
            incremental_diffs,
            cumulative_from_first,
            evolution_summary,
        }
    }

    fn build_evolution_summary(
        &self,
        sboms: &[(&NormalizedSbom, &str, &str)],
        sbom_infos: &[SbomInfo],
        _incremental_diffs: &[DiffResult],
    ) -> EvolutionSummary {
        // Track component versions across timeline
        let mut version_history: HashMap<String, Vec<VersionAtPoint>> = HashMap::new();
        let mut components_added: Vec<ComponentEvolution> = vec![];
        let mut components_removed: Vec<ComponentEvolution> = vec![];
        let mut all_components: HashSet<String> = HashSet::new();

        // Collect all component IDs
        for (sbom, _, _) in sboms {
            for (id, _) in &sbom.components {
                all_components.insert(id.value().to_string());
            }
        }

        // Build version history for each component
        for comp_id in &all_components {
            let mut history: Vec<VersionAtPoint> = vec![];
            let mut first_seen: Option<(usize, String)> = None;
            let mut last_seen: Option<usize> = None;
            let mut prev_version: Option<String> = None;
            let mut version_change_count: usize = 0;

            for (i, (sbom, name, _)) in sboms.iter().enumerate() {
                let comp = sbom.components.iter().find(|(id, _)| id.value() == comp_id);

                let (version, change_type) = if let Some((_, c)) = comp {
                    let ver = c.version.clone();
                    let change = if first_seen.is_none() {
                        first_seen = Some((i, ver.clone().unwrap_or_default()));
                        VersionChangeType::Initial
                    } else {
                        let ct = classify_version_change(&prev_version, &ver);
                        // Count actual version changes (not unchanged or absent)
                        if !matches!(ct, VersionChangeType::Unchanged | VersionChangeType::Absent) {
                            version_change_count += 1;
                        }
                        ct
                    };
                    last_seen = Some(i);
                    prev_version = ver.clone();
                    (ver, change)
                } else if first_seen.is_some() {
                    (None, VersionChangeType::Removed)
                } else {
                    (None, VersionChangeType::Absent)
                };

                history.push(VersionAtPoint {
                    sbom_index: i,
                    sbom_name: name.to_string(),
                    version,
                    change_type,
                });
            }

            version_history.insert(comp_id.clone(), history);

            // Track added/removed
            if let Some((first_idx, first_ver)) = first_seen {
                let still_present = last_seen == Some(sboms.len() - 1);
                let current_version = if still_present {
                    sboms.last().and_then(|(sbom, _, _)| {
                        sbom.components
                            .iter()
                            .find(|(id, _)| id.value() == comp_id)
                            .and_then(|(_, c)| c.version.clone())
                    })
                } else {
                    None
                };

                let name = sboms
                    .iter()
                    .find_map(|(sbom, _, _)| {
                        sbom.components
                            .iter()
                            .find(|(id, _)| id.value() == comp_id)
                            .map(|(_, c)| c.name.clone())
                    })
                    .unwrap_or_else(|| comp_id.clone());

                let evolution = ComponentEvolution {
                    id: comp_id.clone(),
                    name,
                    first_seen_index: first_idx,
                    first_seen_version: first_ver,
                    last_seen_index: if still_present { None } else { last_seen },
                    current_version,
                    version_change_count,
                };

                if first_idx > 0 {
                    components_added.push(evolution.clone());
                }
                if !still_present {
                    components_removed.push(evolution);
                }
            }
        }

        // Build vulnerability trend
        let vulnerability_trend: Vec<VulnerabilitySnapshot> = sbom_infos
            .iter()
            .enumerate()
            .map(|(i, info)| VulnerabilitySnapshot {
                sbom_index: i,
                sbom_name: info.name.clone(),
                counts: info.vulnerability_counts.clone(),
                new_vulnerabilities: vec![],
                resolved_vulnerabilities: vec![],
            })
            .collect();

        // Build dependency trend
        let dependency_trend: Vec<DependencySnapshot> = sbom_infos
            .iter()
            .enumerate()
            .map(|(i, info)| DependencySnapshot {
                sbom_index: i,
                sbom_name: info.name.clone(),
                direct_dependencies: info.dependency_count,
                transitive_dependencies: 0,
                total_edges: info.dependency_count,
            })
            .collect();

        // Build compliance trend
        let compliance_trend: Vec<ComplianceSnapshot> = sboms
            .iter()
            .enumerate()
            .map(|(i, (sbom, name, _))| {
                use crate::quality::{ComplianceChecker, ComplianceLevel};
                let scores = ComplianceLevel::all()
                    .iter()
                    .map(|level| {
                        let result = ComplianceChecker::new(*level).check(sbom);
                        ComplianceScoreEntry {
                            standard: level.name().to_string(),
                            error_count: result.error_count,
                            warning_count: result.warning_count,
                            info_count: result.info_count,
                            is_compliant: result.is_compliant,
                        }
                    })
                    .collect();
                ComplianceSnapshot {
                    sbom_index: i,
                    sbom_name: name.to_string(),
                    scores,
                }
            })
            .collect();

        EvolutionSummary {
            components_added,
            components_removed,
            version_history,
            vulnerability_trend,
            license_changes: vec![],
            dependency_trend,
            compliance_trend,
        }
    }

    /// Perform N×N matrix comparison
    pub fn matrix(
        &mut self,
        sboms: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
        similarity_threshold: Option<f64>,
    ) -> MatrixResult {
        let sbom_infos: Vec<SbomInfo> = sboms
            .iter()
            .map(|(sbom, name, path)| SbomInfo::from_sbom(sbom, name.to_string(), path.to_string()))
            .collect();

        let n = sboms.len();
        let num_pairs = n * (n - 1) / 2;

        let mut diffs: Vec<Option<DiffResult>> = vec![None; num_pairs];
        let mut similarity_scores: Vec<f64> = vec![0.0; num_pairs];

        // Compute upper triangle
        let mut idx = 0;
        for i in 0..n {
            for j in (i + 1)..n {
                let diff = self.cached_diff(sboms[i].0, sboms[j].0);
                let similarity = diff.semantic_score / 100.0;
                similarity_scores[idx] = similarity;
                diffs[idx] = Some(diff);
                idx += 1;
            }
        }

        // Optional clustering
        let clustering = similarity_threshold
            .map(|threshold| self.cluster_sboms(&sbom_infos, &similarity_scores, threshold));

        MatrixResult {
            sboms: sbom_infos,
            diffs,
            similarity_scores,
            clustering,
        }
    }

    fn cluster_sboms(
        &self,
        sboms: &[SbomInfo],
        similarity_scores: &[f64],
        threshold: f64,
    ) -> SbomClustering {
        let n = sboms.len();
        let mut clusters: Vec<SbomCluster> = vec![];
        let mut assigned: HashSet<usize> = HashSet::new();

        // Simple greedy clustering
        for i in 0..n {
            if assigned.contains(&i) {
                continue;
            }

            let mut cluster_members = vec![i];
            assigned.insert(i);

            for j in (i + 1)..n {
                if assigned.contains(&j) {
                    continue;
                }

                // Get similarity between i and j
                let idx = i * (2 * n - i - 1) / 2 + (j - i - 1);
                let similarity = similarity_scores.get(idx).copied().unwrap_or(0.0);

                if similarity >= threshold {
                    cluster_members.push(j);
                    assigned.insert(j);
                }
            }

            if cluster_members.len() > 1 {
                // Calculate average internal similarity
                let mut total_sim = 0.0;
                let mut count = 0;
                for (mi, &a) in cluster_members.iter().enumerate() {
                    for &b in cluster_members.iter().skip(mi + 1) {
                        let (x, y) = if a < b { (a, b) } else { (b, a) };
                        let idx = x * (2 * n - x - 1) / 2 + (y - x - 1);
                        total_sim += similarity_scores.get(idx).copied().unwrap_or(0.0);
                        count += 1;
                    }
                }

                clusters.push(SbomCluster {
                    members: cluster_members.clone(),
                    centroid_index: cluster_members[0],
                    internal_similarity: if count > 0 {
                        total_sim / count as f64
                    } else {
                        1.0
                    },
                    label: None,
                });
            }
        }

        // Find outliers
        let outliers: Vec<usize> = (0..n).filter(|i| !assigned.contains(i)).collect();

        SbomClustering {
            clusters,
            outliers,
            algorithm: "greedy".to_string(),
            threshold,
        }
    }
}

impl Default for MultiDiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify security impact based on component name
fn classify_security_impact(name: &str) -> SecurityImpact {
    let name_lower = name.to_lowercase();
    let critical_components = [
        "openssl",
        "curl",
        "libcurl",
        "gnutls",
        "mbedtls",
        "wolfssl",
        "boringssl",
    ];
    let high_components = [
        "zlib", "libssh", "openssh", "gnupg", "gpg", "sqlite", "kernel", "glibc",
    ];

    if critical_components.iter().any(|c| name_lower.contains(c)) {
        SecurityImpact::Critical
    } else if high_components.iter().any(|c| name_lower.contains(c)) {
        SecurityImpact::High
    } else {
        SecurityImpact::Low
    }
}

/// Calculate major version spread from a list of version strings
fn calculate_major_version_spread(versions: &[String]) -> u32 {
    let mut major_versions: HashSet<u64> = HashSet::new();

    for version in versions {
        // Try to parse as semver first
        if let Ok(v) = semver::Version::parse(version) {
            major_versions.insert(v.major);
        } else {
            // Fallback: try to extract leading number
            if let Some(major_str) = version.split(['.', '-', '_']).next() {
                if let Ok(major) = major_str.parse::<u64>() {
                    major_versions.insert(major);
                }
            }
        }
    }

    match (major_versions.iter().min(), major_versions.iter().max()) {
        (Some(&min), Some(&max)) => (max - min) as u32,
        _ => 0,
    }
}

/// Compute vulnerability matrix with unique and common vulnerabilities
fn compute_vulnerability_matrix(
    baseline: &NormalizedSbom,
    baseline_name: &str,
    targets: &[(&NormalizedSbom, &str, &str)],
) -> VulnerabilityMatrix {
    // Collect all vulnerabilities per SBOM
    let mut vuln_sets: HashMap<String, HashSet<String>> = HashMap::new();
    let mut per_sbom: HashMap<String, VulnerabilityCounts> = HashMap::new();

    // Baseline vulnerabilities
    let baseline_vulns: HashSet<String> = baseline
        .all_vulnerabilities()
        .iter()
        .map(|(_, v)| v.id.clone())
        .collect();
    vuln_sets.insert(baseline_name.to_string(), baseline_vulns);
    per_sbom.insert(baseline_name.to_string(), baseline.vulnerability_counts());

    // Target vulnerabilities
    for (sbom, name, _) in targets {
        let target_vulns: HashSet<String> = sbom
            .all_vulnerabilities()
            .iter()
            .map(|(_, v)| v.id.clone())
            .collect();
        vuln_sets.insert(name.to_string(), target_vulns);
        per_sbom.insert(name.to_string(), sbom.vulnerability_counts());
    }

    // Find common vulnerabilities (in ALL SBOMs)
    let mut common_vulnerabilities: HashSet<String> =
        vuln_sets.values().next().cloned().unwrap_or_default();

    for vulns in vuln_sets.values() {
        common_vulnerabilities = common_vulnerabilities
            .intersection(vulns)
            .cloned()
            .collect();
    }

    // Find unique vulnerabilities per SBOM
    let mut unique_vulnerabilities: HashMap<String, Vec<String>> = HashMap::new();

    for (sbom_name, vulns) in &vuln_sets {
        let mut unique: HashSet<String> = vulns.clone();

        // Remove vulnerabilities that exist in any other SBOM
        for (other_name, other_vulns) in &vuln_sets {
            if other_name != sbom_name {
                unique = unique.difference(other_vulns).cloned().collect();
            }
        }

        if !unique.is_empty() {
            unique_vulnerabilities.insert(sbom_name.clone(), unique.into_iter().collect());
        }
    }

    VulnerabilityMatrix {
        per_sbom,
        unique_vulnerabilities,
        common_vulnerabilities: common_vulnerabilities.into_iter().collect(),
    }
}

/// Classify version change type
fn classify_version_change(old: &Option<String>, new: &Option<String>) -> VersionChangeType {
    match (old, new) {
        (None, Some(_)) => VersionChangeType::Initial,
        (Some(_), None) => VersionChangeType::Removed,
        (Some(o), Some(n)) if o == n => VersionChangeType::Unchanged,
        (Some(o), Some(n)) => {
            // Try to parse as semver
            if let (Ok(old_v), Ok(new_v)) = (semver::Version::parse(o), semver::Version::parse(n)) {
                if new_v.major > old_v.major {
                    VersionChangeType::MajorUpgrade
                } else if new_v.major < old_v.major {
                    VersionChangeType::Downgrade
                } else if new_v.minor > old_v.minor {
                    VersionChangeType::MinorUpgrade
                } else if new_v.minor < old_v.minor {
                    VersionChangeType::Downgrade
                } else if new_v.patch > old_v.patch {
                    VersionChangeType::PatchUpgrade
                } else {
                    VersionChangeType::Downgrade
                }
            } else {
                // String comparison fallback
                if n > o {
                    VersionChangeType::PatchUpgrade
                } else {
                    VersionChangeType::Downgrade
                }
            }
        }
        (None, None) => VersionChangeType::Absent,
    }
}
