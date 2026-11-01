//! Multi-SBOM comparison engines.
//!
//! Uses [`IncrementalDiffEngine`] internally to cache diff results across
//! repeated comparisons (timeline, matrix, diff-multi), avoiding redundant
//! recomputation when the same SBOM pair is compared multiple times.

use super::incremental::IncrementalDiffEngine;
use super::multi::{
    ComparisonResult, ComplianceScoreEntry, ComplianceSnapshot, ComponentEvolution,
    DependencySnapshot, DivergenceType, DivergentComponent, EvolutionSummary,
    InconsistentComponent, MatrixResult, MultiDiffResult, MultiDiffSummary, SbomCluster,
    SbomClustering, SbomInfo, SecurityImpact, TimelineResult, VariableComponent, VersionAtPoint,
    VersionChangeType, VersionSpread, VulnerabilityMatrix, VulnerabilitySnapshot,
};
use super::{DiffEngine, DiffResult};
use crate::error::SbomDiffError;
use crate::matching::{FuzzyMatchConfig, MatchingRulesConfig};
use crate::model::{NormalizedSbom, VulnerabilityCounts};
use crate::quality::ComplianceRunConfig;
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
    /// Graph diff configuration (optional).
    graph_diff_config: Option<super::GraphDiffConfig>,
    /// Custom matching rules (applied when building the engine).
    matching_rules: Option<MatchingRulesConfig>,
    /// The compliance run the timeline's compliance trend checks every SBOM
    /// with (the wall clock, no sidecar, unless set).
    compliance: ComplianceRunConfig,
    /// Caching wrapper built lazily on first diff operation.
    incremental: Option<IncrementalDiffEngine>,
}

impl MultiDiffEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fuzzy_config: None,
            include_unchanged: false,
            graph_diff_config: None,
            matching_rules: None,
            compliance: ComplianceRunConfig::new(),
            incremental: None,
        }
    }

    /// Configure fuzzy matching
    #[must_use]
    pub fn with_fuzzy_config(mut self, config: FuzzyMatchConfig) -> Self {
        self.fuzzy_config = Some(config);
        self.incremental = None;
        self
    }

    /// Include unchanged components
    #[must_use]
    pub fn include_unchanged(mut self, include: bool) -> Self {
        self.include_unchanged = include;
        self.incremental = None;
        self
    }

    /// Enable graph-aware diffing with the given configuration
    #[must_use]
    pub fn with_graph_diff(mut self, config: super::GraphDiffConfig) -> Self {
        self.graph_diff_config = Some(config);
        self.incremental = None;
        self
    }

    /// Apply custom matching rules to every pairwise diff.
    #[must_use]
    pub fn with_matching_rules(mut self, rules: MatchingRulesConfig) -> Self {
        self.matching_rules = Some(rules);
        self.incremental = None;
        self
    }

    /// Check every SBOM of a timeline's compliance trend with `compliance`'s
    /// inputs (for instance a pinned `as_of` clock).
    #[must_use]
    pub fn with_compliance(mut self, compliance: ComplianceRunConfig) -> Self {
        self.compliance = compliance;
        self
    }

    /// Build the configured `DiffEngine` and wrap it in an `IncrementalDiffEngine`.
    fn ensure_engine(&mut self) {
        if self.incremental.is_none() {
            let mut engine = DiffEngine::new();
            if let Some(config) = self.fuzzy_config.clone() {
                engine = engine.with_fuzzy_config(config);
            }
            engine = engine.include_unchanged(self.include_unchanged);
            if let Some(config) = self.graph_diff_config.clone() {
                engine = engine.with_graph_diff(config);
            }
            if let Some(rules) = self.matching_rules.clone() {
                match crate::matching::RuleEngine::new(rules) {
                    Ok(rule_engine) => engine = engine.with_rule_engine(rule_engine),
                    Err(err) => {
                        tracing::warn!("Failed to initialize matching rule engine: {err}");
                    }
                }
            }
            self.incremental = Some(IncrementalDiffEngine::new(engine));
        }
    }

    /// Perform a single diff using the cached incremental engine.
    fn cached_diff(
        &mut self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
    ) -> Result<DiffResult, SbomDiffError> {
        self.ensure_engine();
        Ok(self
            .incremental
            .as_ref()
            .expect("engine initialized by ensure_engine")
            .diff(old, new)?
            .into_result())
    }

    /// Perform 1:N diff-multi comparison (baseline vs multiple targets)
    ///
    /// # Errors
    ///
    /// Returns an error if any pairwise diff computation fails.
    pub fn diff_multi(
        &mut self,
        baseline: &NormalizedSbom,
        baseline_name: &str,
        baseline_path: &str,
        targets: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
    ) -> Result<MultiDiffResult, SbomDiffError> {
        let baseline_info = SbomInfo::from_sbom(
            baseline,
            baseline_name.to_string(),
            baseline_path.to_string(),
        );

        // Compute individual diffs
        let mut comparisons: Vec<ComparisonResult> = Vec::new();
        // logical component id (version-stripped) -> (sbom_name -> version).
        // Keyed logically so a version bump is ONE component with two
        // versions, not two half-present components (see strip_purl_version).
        let mut all_versions: HashMap<String, HashMap<String, String>> = HashMap::new();

        // Collect baseline versions
        for (id, comp) in &baseline.components {
            let version = comp.version.clone().unwrap_or_default();
            all_versions
                .entry(strip_purl_version(id.value()).to_string())
                .or_default()
                .insert(baseline_name.to_string(), version);
        }

        for (target_sbom, target_name, target_path) in targets {
            let diff = self.cached_diff(baseline, target_sbom)?;
            let target_info = SbomInfo::from_sbom(
                target_sbom,
                target_name.to_string(),
                target_path.to_string(),
            );

            // Collect target versions
            for (id, comp) in &target_sbom.components {
                let version = comp.version.clone().unwrap_or_default();
                all_versions
                    .entry(strip_purl_version(id.value()).to_string())
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

        Ok(MultiDiffResult {
            baseline: baseline_info,
            comparisons,
            summary,
        })
    }

    fn compute_multi_diff_summary(
        &self,
        baseline_info: &SbomInfo,
        baseline: &NormalizedSbom,
        comparisons: &[ComparisonResult],
        targets: &[(&NormalizedSbom, &str, &str)],
        all_versions: &HashMap<String, HashMap<String, String>>,
    ) -> MultiDiffSummary {
        // All presence sets/maps below are keyed by LOGICAL (version-stripped)
        // identity, matching `all_versions`, so universal/variable/inconsistent
        // partition components rather than component@version strings.
        let baseline_components: HashSet<_> = baseline
            .components
            .keys()
            .map(|k| strip_purl_version(k.value()).to_string())
            .collect();

        // Per-SBOM component sets and name maps, built once — the loops below
        // previously did a linear iter().find() per component per SBOM,
        // O(components² × SBOMs) overall.
        let target_component_sets: Vec<HashSet<&str>> = targets
            .iter()
            .map(|(target_sbom, _, _)| {
                target_sbom
                    .components
                    .keys()
                    .map(|k| strip_purl_version(k.value()))
                    .collect()
            })
            .collect();
        let baseline_names: HashMap<&str, &str> = baseline
            .components
            .iter()
            .map(|(id, c)| (strip_purl_version(id.value()), c.name.as_str()))
            .collect();
        let target_names: Vec<HashMap<&str, &str>> = targets
            .iter()
            .map(|(target_sbom, _, _)| {
                target_sbom
                    .components
                    .iter()
                    .map(|(id, c)| (strip_purl_version(id.value()), c.name.as_str()))
                    .collect()
            })
            .collect();

        // Find universal components (in baseline and ALL targets)
        let mut universal: HashSet<String> = baseline_components.clone();
        universal.retain(|comp_id| {
            target_component_sets
                .iter()
                .all(|set| set.contains(comp_id.as_str()))
        });

        // Find variable components (different versions across targets)
        let mut variable_components: Vec<VariableComponent> = vec![];
        for (comp_id, versions) in all_versions {
            let unique_versions: HashSet<_> = versions.values().collect();
            if unique_versions.len() > 1 {
                let name = baseline_names
                    .get(comp_id.as_str())
                    .copied()
                    .or_else(|| {
                        target_names
                            .iter()
                            .find_map(|names| names.get(comp_id.as_str()).copied())
                    })
                    .map_or_else(|| comp_id.clone(), str::to_string);

                let baseline_version = versions.get(&baseline_info.name.clone()).cloned();
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

            for ((_, target_name, _), component_set) in targets.iter().zip(&target_component_sets) {
                if component_set.contains(comp_id.as_str()) {
                    present_in.push(target_name.to_string());
                } else {
                    missing_from.push(target_name.to_string());
                }
            }

            if !missing_from.is_empty() {
                let name = baseline_names
                    .get(comp_id.as_str())
                    .map_or_else(|| comp_id.clone(), |n| (*n).to_string());

                inconsistent_components.push(InconsistentComponent {
                    id: comp_id.clone(),
                    name,
                    in_baseline,
                    present_in,
                    missing_from,
                });
            }
        }

        // Compute deviation scores as 0-1 FRACTIONS (semantic_score is 0-100).
        // Every consumer (TUI bands/gauges, CLI logging) multiplies by 100 for
        // display; storing the 0-100 value here double-scaled every rendered
        // percentage ("Max Deviation: 10000.0%") and saturated the deviation
        // gauge/band thresholds, which are calibrated for 0-1 fractions.
        let mut deviation_scores: HashMap<String, f64> = HashMap::new();
        let mut max_deviation = 0.0f64;

        for comp in comparisons {
            let score = ((100.0 - comp.diff.semantic_score) / 100.0).clamp(0.0, 1.0);
            deviation_scores.insert(comp.target.name.clone(), score);
            max_deviation = max_deviation.max(score);
        }

        // Build vulnerability matrix with unique and common vulnerabilities
        let vulnerability_matrix =
            compute_vulnerability_matrix(baseline, &baseline_info.name, targets);

        // Sorted/BTreeMap outputs: several of these collections come from
        // HashSet/HashMap iteration, whose order differs run to run —
        // serialized multi results were not byte-reproducible.
        let mut universal_components: Vec<String> = universal.into_iter().collect();
        universal_components.sort_unstable();
        variable_components.sort_by(|a, b| a.id.cmp(&b.id));
        inconsistent_components.sort_by(|a, b| a.id.cmp(&b.id));

        MultiDiffSummary {
            baseline_component_count: baseline_info.component_count,
            universal_components,
            variable_components,
            inconsistent_components,
            deviation_scores: deviation_scores.into_iter().collect(),
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

        // Hashed lookup tables keyed by LOGICAL (version-stripped) identity —
        // matching a purl-versioned id verbatim classified every version bump
        // as Added-in-target plus Removed-from-baseline instead of one
        // VersionMismatch. The loops below previously also did a linear
        // find/any per component, O(components²) per target.
        let baseline_by_value: HashMap<&str, &crate::model::Component> = baseline
            .components
            .iter()
            .map(|(id, c)| (strip_purl_version(id.value()), c))
            .collect();
        let target_ids: HashSet<&str> = target
            .components
            .keys()
            .map(|k| strip_purl_version(k.value()))
            .collect();

        for (id, comp) in &target.components {
            let comp_id = strip_purl_version(id.value()).to_string();
            let target_version = comp.version.clone().unwrap_or_default();

            // Presence and version availability are separate questions: a
            // baseline component without a version (common for SPDX packages
            // lacking versionInfo) is PRESENT, not Added.
            let baseline_comp = baseline_by_value.get(comp_id.as_str()).copied();

            let divergence_type = match baseline_comp {
                None => DivergenceType::Added,
                Some(bc) if bc.version != comp.version => DivergenceType::VersionMismatch,
                Some(_) => continue, // Same version (or both versionless), not divergent
            };
            let baseline_version = baseline_comp.and_then(|bc| bc.version.clone());

            divergent.push(DivergentComponent {
                id: comp_id.clone(),
                name: comp.name.clone(),
                baseline_version,
                target_version,
                versions_across_targets: all_versions
                    .get(&comp_id)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default(),
                divergence_type,
            });
        }

        // Check for removed components (logically absent from the target, not
        // merely present at another version)
        for (id, comp) in &baseline.components {
            let comp_id = strip_purl_version(id.value()).to_string();
            if !target_ids.contains(comp_id.as_str()) {
                divergent.push(DivergentComponent {
                    id: comp_id.clone(),
                    name: comp.name.clone(),
                    baseline_version: comp.version.clone(),
                    target_version: String::new(),
                    versions_across_targets: all_versions
                        .get(&comp_id)
                        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        .unwrap_or_default(),
                    divergence_type: DivergenceType::Removed,
                });
            }
        }

        divergent
    }

    /// Perform timeline analysis across ordered SBOM versions
    ///
    /// # Errors
    ///
    /// Returns an error if any pairwise diff computation fails.
    pub fn timeline(
        &mut self,
        sboms: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
    ) -> Result<TimelineResult, SbomDiffError> {
        let sbom_infos: Vec<SbomInfo> = sboms
            .iter()
            .map(|(sbom, name, path)| SbomInfo::from_sbom(sbom, name.to_string(), path.to_string()))
            .collect();

        // Compute incremental diffs (adjacent pairs), labelling each with the
        // pair it compares so consumers need not rely on array position.
        let mut incremental_diffs: Vec<DiffResult> = vec![];
        let mut incremental_pairs: Vec<crate::diff::TimelinePair> = vec![];
        for i in 0..sboms.len().saturating_sub(1) {
            let diff = self.cached_diff(sboms[i].0, sboms[i + 1].0)?;
            incremental_diffs.push(diff);
            incremental_pairs.push(crate::diff::TimelinePair {
                from_index: i,
                to_index: i + 1,
                from_name: sbom_infos[i].name.clone(),
                to_name: sbom_infos[i + 1].name.clone(),
            });
        }

        // Compute cumulative diffs from first
        let mut cumulative_from_first: Vec<DiffResult> = vec![];
        let mut cumulative_pairs: Vec<crate::diff::TimelinePair> = vec![];
        if !sboms.is_empty() {
            for i in 1..sboms.len() {
                let diff = self.cached_diff(sboms[0].0, sboms[i].0)?;
                cumulative_from_first.push(diff);
                cumulative_pairs.push(crate::diff::TimelinePair {
                    from_index: 0,
                    to_index: i,
                    from_name: sbom_infos[0].name.clone(),
                    to_name: sbom_infos[i].name.clone(),
                });
            }
        }

        // Build evolution summary
        let evolution_summary =
            self.build_evolution_summary(sboms, &sbom_infos, &incremental_diffs);

        Ok(TimelineResult {
            sboms: sbom_infos,
            incremental_diffs,
            incremental_pairs,
            cumulative_from_first,
            cumulative_pairs,
            evolution_summary,
        })
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

        // Collect all component IDs, and per-SBOM lookup maps — the history
        // loop below runs all_components × sboms and previously did a linear
        // find per cell. Keyed by LOGICAL (version-stripped) identity: keying
        // on raw purl-with-version ids made every upgrade TWO evolutions (the
        // old version "removed", the new one "added"), double-listing it in
        // the evolution lists and hiding the actual version change from the
        // per-component history.
        let mut sbom_maps: Vec<HashMap<&str, &crate::model::Component>> =
            Vec::with_capacity(sboms.len());
        for (sbom, _, _) in sboms {
            for (id, _) in &sbom.components {
                all_components.insert(strip_purl_version(id.value()).to_string());
            }
            sbom_maps.push(
                sbom.components
                    .iter()
                    .map(|(id, c)| (strip_purl_version(id.value()), c))
                    .collect(),
            );
        }

        // Build version history for each component
        for comp_id in &all_components {
            let mut history: Vec<VersionAtPoint> = vec![];
            let mut first_seen: Option<(usize, String)> = None;
            let mut last_seen: Option<usize> = None;
            let mut prev_version: Option<String> = None;
            // Presence at the previous timeline point: Removed marks only the
            // FIRST absent point after a presence (later gap points are
            // Absent), and a component reappearing after a gap re-enters as
            // Initial rather than being version-compared against the stale
            // pre-gap version.
            let mut was_present = false;
            let mut version_change_count: usize = 0;

            for (i, (_, name, _)) in sboms.iter().enumerate() {
                let comp = sbom_maps[i].get(comp_id.as_str()).copied();

                let (version, change_type) = if let Some(c) = comp {
                    let ver = c.version.clone();
                    let change = if first_seen.is_none() {
                        first_seen = Some((i, ver.clone().unwrap_or_default()));
                        VersionChangeType::Initial
                    } else if !was_present {
                        // Reappearance after a gap
                        VersionChangeType::Initial
                    } else {
                        let ct = classify_version_change(prev_version.as_ref(), ver.as_ref());
                        // Count actual version changes (not unchanged or absent)
                        if !matches!(ct, VersionChangeType::Unchanged | VersionChangeType::Absent) {
                            version_change_count += 1;
                        }
                        ct
                    };
                    last_seen = Some(i);
                    prev_version.clone_from(&ver);
                    was_present = true;
                    (ver, change)
                } else {
                    let change = if was_present {
                        VersionChangeType::Removed
                    } else {
                        VersionChangeType::Absent
                    };
                    was_present = false;
                    prev_version = None;
                    (None, change)
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
                    sbom_maps
                        .last()
                        .and_then(|map| map.get(comp_id.as_str()))
                        .and_then(|c| c.version.clone())
                } else {
                    None
                };

                let name = sbom_maps
                    .iter()
                    .find_map(|map| map.get(comp_id.as_str()).map(|c| c.name.clone()))
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

        // Build dependency trend, computing transitive deps from edge depth data
        let dependency_trend: Vec<DependencySnapshot> = sboms
            .iter()
            .enumerate()
            .map(|(i, (sbom, _, _))| {
                let total_edges = sbom.edges.len();
                // Count root nodes (no incoming edges) to determine direct vs transitive
                let targets: HashSet<_> = sbom.edges.iter().map(|e| &e.to).collect();
                let sources: HashSet<_> = sbom.edges.iter().map(|e| &e.from).collect();
                let roots: HashSet<_> = sources.difference(&targets).collect();
                let direct = sbom
                    .edges
                    .iter()
                    .filter(|e| roots.contains(&&e.from))
                    .count();
                let transitive = total_edges.saturating_sub(direct);

                DependencySnapshot {
                    sbom_index: i,
                    sbom_name: sbom_infos[i].name.clone(),
                    direct_dependencies: direct,
                    transitive_dependencies: transitive,
                    total_edges,
                }
            })
            .collect();

        // Build compliance trend
        let compliance_trend: Vec<ComplianceSnapshot> = sboms
            .iter()
            .enumerate()
            .map(|(i, (sbom, name, _))| {
                let scores = self
                    .compliance
                    .check_levels(crate::quality::ComplianceLevel::all(), sbom)
                    .into_iter()
                    .map(|result| {
                        let level = result.level;
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

        components_added.sort_by(|a, b| a.id.cmp(&b.id));
        components_removed.sort_by(|a, b| a.id.cmp(&b.id));

        EvolutionSummary {
            components_added,
            components_removed,
            version_history: version_history.into_iter().collect(),
            vulnerability_trend,
            license_changes: vec![],
            dependency_trend,
            compliance_trend,
        }
    }

    /// Perform N×N matrix comparison
    ///
    /// # Errors
    ///
    /// Returns an error if any pairwise diff computation fails.
    pub fn matrix(
        &mut self,
        sboms: &[(&NormalizedSbom, &str, &str)], // (sbom, name, path)
        similarity_threshold: Option<f64>,
    ) -> Result<MatrixResult, SbomDiffError> {
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
                let diff = self.cached_diff(sboms[i].0, sboms[j].0)?;
                let similarity = diff.semantic_score / 100.0;
                similarity_scores[idx] = similarity;
                diffs[idx] = Some(diff);
                idx += 1;
            }
        }

        // Optional clustering
        let clustering = similarity_threshold
            .map(|threshold| self.cluster_sboms(&sbom_infos, &similarity_scores, threshold));

        Ok(MatrixResult {
            sboms: sbom_infos,
            diffs,
            similarity_scores,
            clustering,
        })
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

        // Simple greedy clustering. A seed is only marked assigned when it
        // actually forms a cluster: unconditionally assigning every seed made
        // singleton SBOMs vanish from the output entirely (in no cluster) and
        // left the outliers list structurally empty.
        for i in 0..n {
            if assigned.contains(&i) {
                continue;
            }

            let mut cluster_members = vec![i];

            for j in (i + 1)..n {
                if assigned.contains(&j) {
                    continue;
                }

                // Get similarity between i and j
                let idx = i * (2 * n - i - 1) / 2 + (j - i - 1);
                let similarity = similarity_scores.get(idx).copied().unwrap_or(0.0);

                if similarity >= threshold {
                    cluster_members.push(j);
                }
            }

            if cluster_members.len() > 1 {
                for &member in &cluster_members {
                    assigned.insert(member);
                }
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
                        total_sim / f64::from(count)
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

/// Version-independent component identity for cross-SBOM presence/version
/// aggregation.
///
/// Purl-shaped canonical ids embed the version (`pkg:npm/lodash@4.17.20`), so
/// keying presence sets on the raw id counted every version bump as TWO
/// distinct components — one "missing" from the new SBOMs and one "missing"
/// from the old ones — inflating the Inconsistent count past the number of
/// packages in the fleet and hiding upgrades from the Variable list. Strips
/// the `@version` suffix (and any qualifiers) from purl ids; non-purl ids are
/// returned unchanged. Note: if one SBOM genuinely vendors two versions of the
/// same purl, they intentionally aggregate as one logical component here.
pub(crate) fn strip_purl_version(id: &str) -> &str {
    if !id.starts_with("pkg:") {
        return id;
    }
    // Version (if any) sits before qualifiers (`?`) / subpath (`#`).
    let core_end = id.find(['?', '#']).unwrap_or(id.len());
    let core = &id[..core_end];
    match core.rfind('@') {
        // An '@' directly after '/' is an npm scope ("pkg:npm/@scope/name"),
        // not a version separator.
        Some(pos) if pos > 0 && !core[..pos].ends_with('/') => &id[..pos],
        _ => id,
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
            if let Some(major_str) = version.split(['.', '-', '_']).next()
                && let Ok(major) = major_str.parse::<u64>()
            {
                major_versions.insert(major);
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

    let mut common: Vec<String> = common_vulnerabilities.into_iter().collect();
    common.sort_unstable();
    VulnerabilityMatrix {
        per_sbom: per_sbom.into_iter().collect(),
        unique_vulnerabilities: unique_vulnerabilities
            .into_iter()
            .map(|(k, mut v)| {
                v.sort_unstable();
                (k, v)
            })
            .collect(),
        common_vulnerabilities: common,
    }
}

/// Classify version change type.
///
/// Semver-aware, including pre-release ordering: `1.0.0-alpha -> 1.0.0` and
/// `1.0.0-alpha -> 1.0.0-beta` are upgrades (the old comparison ignored the
/// pre-release field and fell through to Downgrade), and a build-metadata-only
/// change is Unchanged. Non-semver schemes are compared by numeric
/// dot-segments (`9.0 -> 10.0` is a major upgrade, not the lexicographic
/// Downgrade the old fallback produced); genuinely incomparable strings
/// report [`VersionChangeType::Changed`] rather than a fabricated direction.
fn classify_version_change(old: Option<&String>, new: Option<&String>) -> VersionChangeType {
    match (old, new) {
        (None, Some(_)) => VersionChangeType::Initial,
        (Some(_), None) => VersionChangeType::Removed,
        (Some(o), Some(n)) if o == n => VersionChangeType::Unchanged,
        (Some(o), Some(n)) => classify_version_strings(o, n),
        (None, None) => VersionChangeType::Absent,
    }
}

pub(crate) fn classify_version_strings(old: &str, new: &str) -> VersionChangeType {
    use std::cmp::Ordering;

    if let (Some(old_v), Some(new_v)) = (parse_semver_lenient(old), parse_semver_lenient(new)) {
        // cmp_precedence implements spec precedence, which ignores build
        // metadata — differing strings can still compare equal, and a
        // build-metadata-only change is not a version change. (Version::cmp
        // would tie-break on build metadata.)
        return match new_v.cmp_precedence(&old_v) {
            Ordering::Equal => VersionChangeType::Unchanged,
            Ordering::Less => VersionChangeType::Downgrade,
            Ordering::Greater => {
                if new_v.major > old_v.major {
                    VersionChangeType::MajorUpgrade
                } else if new_v.minor > old_v.minor {
                    VersionChangeType::MinorUpgrade
                } else {
                    // Patch bump, or a pre-release promotion within the same
                    // major.minor.patch triple
                    VersionChangeType::PatchUpgrade
                }
            }
        };
    }

    // Non-semver schemes (e.g. "1.2.3.4", "20240101"): compare numeric
    // dot-segments positionally.
    if let Some(change) = classify_numeric_segments(old, new) {
        return change;
    }

    VersionChangeType::Changed
}

/// Lenient semver parse: trims whitespace and a leading `v`/`V`, and pads
/// missing minor/patch components (`9` -> `9.0.0`, `1.2-rc1` -> `1.2.0-rc1`).
fn parse_semver_lenient(version: &str) -> Option<semver::Version> {
    let version = version.trim();
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    if let Ok(v) = semver::Version::parse(version) {
        return Some(v);
    }
    // Pad a 1- or 2-segment numeric core, preserving pre-release/build parts.
    let split_at = version.find(['-', '+']).unwrap_or(version.len());
    let (core, rest) = version.split_at(split_at);
    let padded = match core.matches('.').count() {
        0 => format!("{core}.0.0{rest}"),
        1 => format!("{core}.0{rest}"),
        _ => return None,
    };
    semver::Version::parse(&padded).ok()
}

/// Compare dot-separated numeric segments (shorter side zero-padded).
/// Returns `None` when any differing segment pair is non-numeric.
fn classify_numeric_segments(old: &str, new: &str) -> Option<VersionChangeType> {
    let old = old.trim();
    let old = old.strip_prefix(['v', 'V']).unwrap_or(old);
    let new = new.trim();
    let new = new.strip_prefix(['v', 'V']).unwrap_or(new);
    let old_segments: Vec<&str> = old.split('.').collect();
    let new_segments: Vec<&str> = new.split('.').collect();
    let len = old_segments.len().max(new_segments.len());

    for position in 0..len {
        let old_seg = old_segments.get(position).copied().unwrap_or("0");
        let new_seg = new_segments.get(position).copied().unwrap_or("0");
        if old_seg == new_seg {
            continue;
        }
        let (old_num, new_num) = (old_seg.parse::<u64>().ok()?, new_seg.parse::<u64>().ok()?);
        if old_num == new_num {
            continue; // e.g. "02" vs "2"
        }
        let upgrade = new_num > old_num;
        return Some(match (upgrade, position) {
            (false, _) => VersionChangeType::Downgrade,
            (true, 0) => VersionChangeType::MajorUpgrade,
            (true, 1) => VersionChangeType::MinorUpgrade,
            (true, _) => VersionChangeType::PatchUpgrade,
        });
    }

    // All segments numerically or textually equal (e.g. "1.02" vs "1.2")
    Some(VersionChangeType::Unchanged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, DocumentMetadata};

    fn classify(old: &str, new: &str) -> VersionChangeType {
        classify_version_change(Some(&old.to_string()), Some(&new.to_string()))
    }

    /// The full classification matrix, including the cases the old
    /// implementation got wrong: pre-release transitions and non-semver
    /// numeric versions were all reported as Downgrade.
    #[test]
    fn classify_version_change_matrix() {
        use VersionChangeType::{
            Absent, Changed, Downgrade, Initial, MajorUpgrade, MinorUpgrade, PatchUpgrade, Removed,
            Unchanged,
        };

        // Plain semver
        assert_eq!(classify("1.0.0", "2.0.0"), MajorUpgrade);
        assert_eq!(classify("1.2.0", "1.3.0"), MinorUpgrade);
        assert_eq!(classify("1.2.3", "1.2.4"), PatchUpgrade);
        assert_eq!(classify("2.0.0", "1.9.9"), Downgrade);

        // Pre-release ordering (previously all Downgrade)
        assert_eq!(classify("1.0.0-alpha", "1.0.0"), PatchUpgrade);
        assert_eq!(classify("1.0.0-alpha", "1.0.0-beta"), PatchUpgrade);
        assert_eq!(classify("1.0.0", "1.0.0-alpha"), Downgrade);

        // Build metadata is not a version change
        assert_eq!(classify("1.0.0", "1.0.0+build2"), Unchanged);

        // Non-semver numeric (previously lexicographic: 9.0 -> 10.0 was a
        // Downgrade and 10.0 -> 9.0 a PatchUpgrade)
        assert_eq!(classify("9.0", "10.0"), MajorUpgrade);
        assert_eq!(classify("10.0", "9.0"), Downgrade);
        assert_eq!(classify("1.2.3.4", "1.2.3.5"), PatchUpgrade);
        assert_eq!(classify("1.02", "1.2"), Unchanged);

        // Lenient parsing
        assert_eq!(classify("v1.2.3", "v2.0.0"), MajorUpgrade);
        assert_eq!(classify("1.2", "1.3"), MinorUpgrade);
        assert_eq!(classify("2", "3"), MajorUpgrade);

        // Incomparable schemes report Changed, never a fabricated direction
        assert_eq!(classify("abc", "def"), Changed);
        assert_eq!(classify("release-A", "release-B"), Changed);

        // Presence transitions
        assert_eq!(
            classify_version_change(None, Some(&"1.0.0".to_string())),
            Initial
        );
        assert_eq!(
            classify_version_change(Some(&"1.0.0".to_string()), None),
            Removed
        );
        assert_eq!(classify_version_change(None, None), Absent);
        assert_eq!(classify("1.0.0", "1.0.0"), Unchanged);
    }

    fn info(name: &str) -> SbomInfo {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        SbomInfo::from_sbom(&sbom, name.to_string(), format!("{name}.json"))
    }

    /// Singleton SBOMs must surface as outliers: previously every seed was
    /// marked assigned unconditionally, so singletons appeared in neither
    /// clusters nor outliers and the outliers list was structurally empty.
    #[test]
    fn cluster_sboms_reports_singletons_as_outliers() {
        let engine = MultiDiffEngine::new();
        let sboms = vec![info("a"), info("b"), info("c")];

        // Upper triangle for n=3: [s(0,1), s(0,2), s(1,2)]
        let scores = vec![0.95, 0.10, 0.10];
        let clustering = engine.cluster_sboms(&sboms, &scores, 0.9);
        assert_eq!(clustering.clusters.len(), 1);
        assert_eq!(clustering.clusters[0].members, vec![0, 1]);
        assert_eq!(
            clustering.outliers,
            vec![2],
            "the dissimilar SBOM must be an outlier"
        );

        // All dissimilar: no clusters, everything an outlier
        let scores = vec![0.1, 0.1, 0.1];
        let clustering = engine.cluster_sboms(&sboms, &scores, 0.9);
        assert!(clustering.clusters.is_empty());
        assert_eq!(clustering.outliers, vec![0, 1, 2]);
    }

    fn timeline_sbom(component_version: Option<&str>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        // A stable second component so the SBOM is never empty
        let mut anchor = Component::new("anchor".to_string(), "pkg:npm/anchor@1.0.0".to_string());
        anchor.version = Some("1.0.0".to_string());
        anchor.calculate_content_hash();
        sbom.add_component(anchor);
        if let Some(version) = component_version {
            let mut c = Component::new("libgap".to_string(), "pkg:npm/libgap".to_string());
            c.version = Some(version.to_string());
            c.calculate_content_hash();
            sbom.add_component(c);
        }
        sbom.calculate_content_hash();
        sbom
    }

    /// A purl-versioned upgrade is ONE evolution with a version change, not a
    /// Removed(old version) + Added(new version) pair.
    #[test]
    fn timeline_upgrade_is_one_evolution_not_added_plus_removed() {
        let v1 = purl_sbom(&[("lodash", "4.17.20"), ("react", "18.0.0")]);
        let v2 = purl_sbom(&[("lodash", "4.17.21"), ("react", "18.0.0")]);

        let mut engine = MultiDiffEngine::new();
        let sboms: Vec<(&NormalizedSbom, &str, &str)> =
            vec![(&v1, "v1", "v1.json"), (&v2, "v2", "v2.json")];
        let result = engine.timeline(&sboms).expect("timeline");
        let summary = &result.evolution_summary;

        assert!(
            summary.components_added.is_empty(),
            "nothing appeared after v1: {:?}",
            summary.components_added
        );
        assert!(
            summary.components_removed.is_empty(),
            "nothing is absent from the latest version: {:?}",
            summary.components_removed
        );

        let history = summary
            .version_history
            .get("pkg:npm/lodash")
            .expect("logical lodash history");
        let changes: Vec<_> = history.iter().map(|p| p.change_type.clone()).collect();
        assert_eq!(
            changes,
            vec![VersionChangeType::Initial, VersionChangeType::PatchUpgrade],
            "the upgrade must be visible as a version change in ONE history"
        );
    }

    /// Gap handling: Removed marks only the FIRST absent point; later gap
    /// points are Absent; a reappearing component re-enters as Initial
    /// rather than being version-compared against the stale pre-gap version
    /// (previously: Removed, Removed, then MajorUpgrade against a version
    /// from two revisions ago).
    #[test]
    fn timeline_gap_and_reappearance_handling() {
        let r0 = timeline_sbom(Some("1.0.0"));
        let r1 = timeline_sbom(None);
        let r2 = timeline_sbom(None);
        let r3 = timeline_sbom(Some("2.0.0"));

        let mut engine = MultiDiffEngine::new();
        let sboms: Vec<(&NormalizedSbom, &str, &str)> = vec![
            (&r0, "r0", "r0.json"),
            (&r1, "r1", "r1.json"),
            (&r2, "r2", "r2.json"),
            (&r3, "r3", "r3.json"),
        ];
        let result = engine.timeline(&sboms).expect("timeline");

        let history = result
            .evolution_summary
            .version_history
            .iter()
            .find(|(id, _)| id.contains("libgap"))
            .map(|(_, h)| h)
            .expect("libgap history");

        let changes: Vec<_> = history.iter().map(|p| p.change_type.clone()).collect();
        assert_eq!(
            changes,
            vec![
                VersionChangeType::Initial,
                VersionChangeType::Removed,
                VersionChangeType::Absent,
                VersionChangeType::Initial,
            ],
            "gap must be Removed-then-Absent and reappearance must be Initial"
        );
    }

    /// `strip_purl_version` removes only the version segment of purl-shaped
    /// ids and leaves everything else alone.
    #[test]
    fn strip_purl_version_matrix() {
        assert_eq!(
            strip_purl_version("pkg:npm/lodash@4.17.20"),
            "pkg:npm/lodash"
        );
        assert_eq!(
            strip_purl_version("pkg:npm/@scope/name@1.2.3"),
            "pkg:npm/@scope/name"
        );
        // Scoped purl WITHOUT a version: the scope '@' must survive.
        assert_eq!(
            strip_purl_version("pkg:npm/@scope/name"),
            "pkg:npm/@scope/name"
        );
        assert_eq!(
            strip_purl_version("pkg:maven/org.apache/log4j@2.17.0?type=jar"),
            "pkg:maven/org.apache/log4j"
        );
        assert_eq!(strip_purl_version("pkg:npm/lodash"), "pkg:npm/lodash");
        // Non-purl ids pass through untouched (even with embedded '@').
        assert_eq!(strip_purl_version("acme-webapp"), "acme-webapp");
        assert_eq!(strip_purl_version("SPDXRef-Package-a"), "SPDXRef-Package-a");
        assert_eq!(strip_purl_version("name@1.0"), "name@1.0");
    }

    fn purl_sbom(entries: &[(&str, &str)]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for (name, version) in entries {
            let mut c = Component::new((*name).to_string(), format!("pkg:npm/{name}@{version}"));
            c.version = Some((*version).to_string());
            c.calculate_content_hash();
            sbom.add_component(c);
        }
        sbom.calculate_content_hash();
        sbom
    }

    /// The three similarity/deviation scales must stay in their documented
    /// relationship: the embedded per-pair `DiffResult` keeps the 0-100
    /// single-diff `semantic_score`, while the multi-SBOM layer exposes
    /// 0-1 fractions (`similarity = semantic_score / 100`, `deviation =
    /// 1 - similarity`). They drifted apart silently once already.
    #[test]
    fn similarity_and_deviation_scales_match_their_documented_contract() {
        let a = purl_sbom(&[("lodash", "4.17.20"), ("react", "18.0.0")]);
        let b = purl_sbom(&[("lodash", "4.17.21"), ("zod", "3.0.0")]);

        let mut engine = MultiDiffEngine::new();
        let matrix = engine
            .matrix(&[(&a, "a", "a.json"), (&b, "b", "b.json")], None)
            .expect("matrix must succeed");

        let similarity = matrix.similarity_scores[0];
        assert!(
            (0.0..=1.0).contains(&similarity),
            "matrix similarity must be a 0-1 fraction, got {similarity}"
        );
        let embedded = matrix.diffs[0]
            .as_ref()
            .expect("pair diff present")
            .semantic_score;
        assert!(
            (0.0..=100.0).contains(&embedded),
            "embedded semantic_score must stay on the 0-100 scale, got {embedded}"
        );
        assert!(
            (similarity - embedded / 100.0).abs() < 1e-9,
            "similarity ({similarity}) must equal semantic_score/100 ({})",
            embedded / 100.0
        );

        let multi = engine
            .diff_multi(&a, "a", "a.json", &[(&b, "b", "b.json")])
            .expect("diff_multi must succeed");
        let deviation = multi.summary.deviation_scores["b"];
        assert!(
            (0.0..=1.0).contains(&deviation),
            "deviation must be a 0-1 fraction, got {deviation}"
        );
        let pair_score = multi.comparisons[0].diff.semantic_score;
        assert!(
            (deviation - (1.0 - pair_score / 100.0)).abs() < 1e-9,
            "deviation ({deviation}) must equal 1 - semantic_score/100"
        );
    }

    /// A version bump must be ONE variable component, never TWO inconsistent
    /// ones (raw purl-with-version keying counted `lodash@1` missing from the
    /// target and `lodash@2` missing from the baseline). Deviation scores must
    /// be 0-1 fractions — consumers multiply by 100 for display.
    #[test]
    fn version_bump_is_variable_not_double_inconsistent_and_deviation_is_fraction() {
        let baseline = purl_sbom(&[("lodash", "4.17.20"), ("react", "18.0.0")]);
        let target = purl_sbom(&[("lodash", "4.17.21"), ("react", "18.0.0")]);

        let mut engine = MultiDiffEngine::new();
        let result = engine
            .diff_multi(
                &baseline,
                "baseline",
                "baseline.json",
                &[(&target, "target", "target.json")],
            )
            .expect("diff_multi");

        let summary = &result.summary;
        assert!(
            summary.inconsistent_components.is_empty(),
            "a version bump is not a presence inconsistency: {:?}",
            summary.inconsistent_components
        );
        assert_eq!(
            summary
                .variable_components
                .iter()
                .map(|vc| vc.name.as_str())
                .collect::<Vec<_>>(),
            vec!["lodash"],
            "the bumped package must surface exactly once as variable"
        );
        let lodash = &summary.variable_components[0];
        assert_eq!(lodash.id, "pkg:npm/lodash", "id must be version-stripped");
        assert_eq!(
            lodash.targets_with_component.len(),
            2,
            "present (at some version) in baseline and target"
        );
        // react is untouched and present everywhere -> universal, counted once.
        assert_eq!(
            summary.universal_components,
            vec!["pkg:npm/lodash", "pkg:npm/react"]
        );

        // Deviation contract: 0-1 fraction, never the 0-100 semantic scale.
        assert!(
            summary.max_deviation >= 0.0 && summary.max_deviation <= 1.0,
            "deviation must be a 0-1 fraction, got {}",
            summary.max_deviation
        );
        for (name, dev) in &summary.deviation_scores {
            assert!(
                (0.0..=1.0).contains(dev),
                "deviation for {name} must be a 0-1 fraction, got {dev}"
            );
        }

        // Divergence: the bump is one VersionMismatch, not Added+Removed.
        let divergent = &result.comparisons[0].divergent_components;
        assert_eq!(divergent.len(), 1, "only lodash diverges: {divergent:?}");
        assert_eq!(
            divergent[0].divergence_type,
            DivergenceType::VersionMismatch
        );
        assert_eq!(divergent[0].baseline_version.as_deref(), Some("4.17.20"));
        assert_eq!(divergent[0].target_version, "4.17.21");
    }

    /// An identical target deviates 0.0; a fully disjoint target still stays
    /// within the 0-1 fraction contract (the old code stored 100.0).
    #[test]
    fn deviation_bounds_identical_and_disjoint() {
        let baseline = purl_sbom(&[("a", "1.0.0"), ("b", "1.0.0")]);
        let same = purl_sbom(&[("a", "1.0.0"), ("b", "1.0.0")]);
        let disjoint = purl_sbom(&[("x", "1.0.0"), ("y", "1.0.0")]);

        let mut engine = MultiDiffEngine::new();
        let result = engine
            .diff_multi(
                &baseline,
                "baseline",
                "baseline.json",
                &[
                    (&same, "same", "same.json"),
                    (&disjoint, "disjoint", "disjoint.json"),
                ],
            )
            .expect("diff_multi");

        let same_dev = result.summary.deviation_scores["same"];
        let disjoint_dev = result.summary.deviation_scores["disjoint"];
        assert!(
            same_dev.abs() < f64::EPSILON,
            "identical target must deviate 0.0, got {same_dev}"
        );
        assert!(
            disjoint_dev > same_dev && disjoint_dev <= 1.0,
            "disjoint target deviation must be in (0, 1], got {disjoint_dev}"
        );
        assert!(result.summary.max_deviation <= 1.0);
    }

    /// A baseline component that is present but versionless (SPDX without
    /// versionInfo) must not be reported as Added in every target.
    #[test]
    fn versionless_baseline_component_is_not_added() {
        let make = |version: Option<&str>| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let mut c = Component::new("libfoo".to_string(), "SPDXRef-Package-libfoo".to_string());
            c.version = version.map(str::to_string);
            c.calculate_content_hash();
            sbom.add_component(c);
            sbom.calculate_content_hash();
            sbom
        };

        let baseline = make(None);
        let same = make(None);
        let versioned = make(Some("2.0.0"));

        let engine = MultiDiffEngine::new();
        let all_versions = HashMap::new();

        let divergent = engine.find_divergent_components(&baseline, &same, "same", &all_versions);
        assert!(
            divergent.is_empty(),
            "identical versionless components must not diverge: {divergent:?}"
        );

        let divergent =
            engine.find_divergent_components(&baseline, &versioned, "versioned", &all_versions);
        assert_eq!(divergent.len(), 1);
        assert_eq!(
            divergent[0].divergence_type,
            DivergenceType::VersionMismatch,
            "present-but-versionless baseline is a version mismatch, not Added"
        );
    }
}
