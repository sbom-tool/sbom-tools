//! Component matching logic for the diff engine.
//!
//! This module contains the matching algorithms used to pair components
//! between old and new SBOMs.

use crate::matching::{
    BatchCandidateConfig, BatchCandidateGenerator, ComponentIndex, ComponentMatcher,
    CrossEcosystemDb, FuzzyMatchConfig,
};
use crate::model::{CanonicalId, NormalizedSbom};
use std::collections::{HashMap, HashSet};

use super::engine_config::LargeSbomConfig;

/// Simple result of component matching (`old_id` -> Option<`new_id`>).
pub type MatchResult = HashMap<CanonicalId, Option<CanonicalId>>;

/// Rich result of component matching with score information.
///
/// This struct provides both the match mappings and the scores for each matched pair,
/// which is needed for reliable `match_info` population.
#[derive(Debug, Clone)]
pub struct ComponentMatchResult {
    /// Map from `old_id` -> Option<`new_id`>
    pub matches: MatchResult,
    /// Score for each matched pair (`old_id`, `new_id`) -> score
    pub pairs: HashMap<(CanonicalId, CanonicalId), f64>,
}

impl ComponentMatchResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            matches: HashMap::new(),
            pairs: HashMap::new(),
        }
    }
}

impl Default for ComponentMatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Matches components between old and new SBOMs.
///
/// Uses 1:1 exclusive matching to ensure each new component is matched to at most
/// one old component. This prevents multiple old components from matching the same
/// new component, which could cause confusing diff results.
///
/// Returns a `ComponentMatchResult` containing both the match mappings and scores
/// for each matched pair.
pub fn match_components(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    matcher: &dyn ComponentMatcher,
    fuzzy_config: &FuzzyMatchConfig,
    large_sbom_config: &LargeSbomConfig,
) -> ComponentMatchResult {
    let mut result = ComponentMatchResult::new();
    let mut used_new_ids: HashSet<CanonicalId> = HashSet::new();

    // Phase 1: Exact matches by canonical ID (fast, highest priority)
    for old_id in old.components.keys() {
        if new.components.contains_key(old_id) {
            let id = old_id.clone();
            result.pairs.insert((id.clone(), id.clone()), 1.0);
            result.matches.insert(id.clone(), Some(id.clone()));
            used_new_ids.insert(id);
        }
    }

    let unmatched_old: Vec<_> = old
        .components
        .keys()
        .filter(|id| !result.matches.contains_key(*id))
        .collect();

    // Determine if we should use enhanced matching for large SBOMs
    let total_components = old.component_count().max(new.component_count());
    let use_batch_generator = total_components >= large_sbom_config.lsh_threshold;

    // Phase 2 & 3: Collect candidates (strategy depends on SBOM size)
    let candidates: Vec<(CanonicalId, CanonicalId, f64)> = if use_batch_generator {
        match_with_batch_generator(
            old,
            new,
            &unmatched_old,
            &used_new_ids,
            matcher,
            fuzzy_config,
            large_sbom_config,
        )
    } else {
        match_with_component_index(
            old,
            new,
            &unmatched_old,
            &used_new_ids,
            matcher,
            fuzzy_config,
            large_sbom_config,
        )
    };

    // Phase 4: Optimal assignment using Hungarian algorithm or fallback
    let assignment = optimal_assignment(
        &candidates,
        &unmatched_old,
        large_sbom_config,
    );

    // Apply assignment results
    for (old_id, new_id, score) in assignment {
        if used_new_ids.insert(new_id.clone()) {
            result.pairs.insert((old_id.clone(), new_id.clone()), score);
            result.matches.insert(old_id, Some(new_id));
        }
    }

    // Phase 6: Mark remaining unmatched old components as removed (None)
    for old_id in old.components.keys() {
        if !result.matches.contains_key(old_id) {
            result.matches.insert(old_id.clone(), None);
        }
    }

    result
}

/// Use `BatchCandidateGenerator` (LSH + cross-ecosystem) for large SBOMs.
fn match_with_batch_generator(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    unmatched_old: &[&CanonicalId],
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    fuzzy_config: &FuzzyMatchConfig,
    large_sbom_config: &LargeSbomConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use rayon::prelude::*;

    // Build batch candidate generator for the new SBOM
    let batch_config = BatchCandidateConfig {
        max_candidates: large_sbom_config.max_candidates,
        max_length_diff: 10,
        lsh_threshold: large_sbom_config.lsh_threshold,
        enable_cross_ecosystem: large_sbom_config.cross_ecosystem.enabled,
    };
    let generator = BatchCandidateGenerator::build(new, batch_config);

    // Collect source components for batch processing
    let sources: Vec<_> = unmatched_old
        .iter()
        .filter_map(|id| old.components.get(*id).map(|comp| (*id, comp)))
        .collect();

    // Use parallel processing for large batches
    let parallel_threshold = 50;
    if sources.len() > parallel_threshold {
        sources
            .par_iter()
            .flat_map(|(old_id, old_comp)| {
                let batch_result = generator.find_candidates(old_id, old_comp);

                // Combine all candidate sources
                let mut all_candidates = batch_result.index_candidates;
                all_candidates.extend(batch_result.lsh_candidates);
                all_candidates.extend(batch_result.cross_ecosystem_candidates);

                all_candidates
                    .iter()
                    .filter(|new_id| !used_new_ids.contains(*new_id))
                    .filter_map(|new_id| {
                        new.components.get(new_id).and_then(|new_comp| {
                            let score = matcher.match_score(old_comp, new_comp);
                            if score >= fuzzy_config.threshold {
                                Some(((*old_id).clone(), new_id.clone(), score))
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    } else {
        let mut candidates = Vec::new();
        for (old_id, old_comp) in sources {
            let batch_result = generator.find_candidates(old_id, old_comp);

            // Combine all candidate sources
            let mut all_candidates = batch_result.index_candidates;
            all_candidates.extend(batch_result.lsh_candidates);
            all_candidates.extend(batch_result.cross_ecosystem_candidates);

            for new_id in all_candidates {
                if used_new_ids.contains(&new_id) {
                    continue;
                }
                if let Some(new_comp) = new.components.get(&new_id) {
                    let score = matcher.match_score(old_comp, new_comp);
                    if score >= fuzzy_config.threshold {
                        candidates.push((old_id.clone(), new_id, score));
                    }
                }
            }
        }
        candidates
    }
}

/// Use standard `ComponentIndex` for smaller SBOMs.
///
/// Also includes cross-ecosystem matching when enabled, with score penalty applied.
fn match_with_component_index(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    unmatched_old: &[&CanonicalId],
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    fuzzy_config: &FuzzyMatchConfig,
    large_sbom_config: &LargeSbomConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use rayon::prelude::*;

    let new_index = ComponentIndex::build(new);
    let old_index = ComponentIndex::build(old);

    // Build cross-ecosystem DB if enabled
    let cross_eco_db = if large_sbom_config.cross_ecosystem.enabled {
        Some(CrossEcosystemDb::default())
    } else {
        None
    };

    // Build ecosystem index for cross-ecosystem lookups
    let new_by_ecosystem: HashMap<_, Vec<_>> = if cross_eco_db.is_some() {
        let mut map: HashMap<crate::model::Ecosystem, Vec<_>> = HashMap::new();
        for (id, comp) in &new.components {
            if let Some(eco) = &comp.ecosystem {
                map.entry(eco.clone()).or_default().push((id.clone(), comp));
            }
        }
        map
    } else {
        HashMap::new()
    };

    let max_candidates = 50;
    let max_length_diff = 10;
    let parallel_threshold = 50;
    let cross_eco_config = &large_sbom_config.cross_ecosystem;

    if unmatched_old.len() > parallel_threshold {
        unmatched_old
            .par_iter()
            .flat_map(|old_id| {
                let old_entry = old_index.get_entry(old_id);
                let old_comp = old.components.get(*old_id);

                match (old_entry, old_comp) {
                    (Some(entry), Some(old_comp)) => {
                        // Same-ecosystem candidates (primary)
                        let candidate_ids = new_index.find_candidates(
                            old_id,
                            entry,
                            max_candidates,
                            max_length_diff,
                        );

                        let mut results: Vec<_> = candidate_ids
                            .iter()
                            .filter(|new_id| !used_new_ids.contains(*new_id))
                            .filter_map(|new_id| {
                                new.components.get(new_id).and_then(|new_comp| {
                                    let score = matcher.match_score(old_comp, new_comp);
                                    if score >= fuzzy_config.threshold {
                                        Some(((*old_id).clone(), new_id.clone(), score))
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect();

                        // Cross-ecosystem candidates (secondary, with penalty)
                        if let (Some(db), Some(old_eco)) =
                            (&cross_eco_db, &old_comp.ecosystem)
                        {
                            let cross_matches = find_cross_ecosystem_candidates(
                                old_id,
                                old_comp,
                                old_eco,
                                db,
                                &new_by_ecosystem,
                                used_new_ids,
                                matcher,
                                cross_eco_config,
                            );
                            results.extend(cross_matches);
                        }

                        results
                    }
                    _ => Vec::new(),
                }
            })
            .collect()
    } else {
        let mut candidates = Vec::new();
        for old_id in unmatched_old {
            if let (Some(old_entry), Some(old_comp)) =
                (old_index.get_entry(old_id), old.components.get(*old_id))
            {
                // Same-ecosystem candidates (primary)
                let candidate_ids = new_index.find_candidates(
                    old_id,
                    old_entry,
                    max_candidates,
                    max_length_diff,
                );

                for new_id in candidate_ids {
                    if used_new_ids.contains(&new_id) {
                        continue;
                    }
                    if let Some(new_comp) = new.components.get(&new_id) {
                        let score = matcher.match_score(old_comp, new_comp);
                        if score >= fuzzy_config.threshold {
                            candidates.push(((*old_id).clone(), new_id, score));
                        }
                    }
                }

                // Cross-ecosystem candidates (secondary, with penalty)
                if let (Some(db), Some(old_eco)) = (&cross_eco_db, &old_comp.ecosystem) {
                    let cross_matches = find_cross_ecosystem_candidates(
                        old_id,
                        old_comp,
                        old_eco,
                        db,
                        &new_by_ecosystem,
                        used_new_ids,
                        matcher,
                        cross_eco_config,
                    );
                    candidates.extend(cross_matches);
                }
            }
        }
        candidates
    }
}

/// Find cross-ecosystem candidates for a component.
///
/// Looks up the component in the cross-ecosystem DB and finds equivalent
/// packages in other ecosystems within the new SBOM.
#[allow(clippy::too_many_arguments)]
fn find_cross_ecosystem_candidates(
    old_id: &CanonicalId,
    old_comp: &crate::model::Component,
    old_eco: &crate::model::Ecosystem,
    db: &CrossEcosystemDb,
    new_by_ecosystem: &HashMap<crate::model::Ecosystem, Vec<(CanonicalId, &crate::model::Component)>>,
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    config: &crate::matching::CrossEcosystemConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    let mut results = Vec::new();

    // Find equivalent packages in other ecosystems
    let equivalents = db.find_equivalents(old_eco, &old_comp.name);

    for equiv in equivalents {
        // Skip if only using verified mappings and this isn't verified
        if config.verified_only && !equiv.verified {
            continue;
        }

        // Look for components in the target ecosystem
        if let Some(target_comps) = new_by_ecosystem.get(&equiv.target_ecosystem) {
            let mut count = 0;
            for (new_id, new_comp) in target_comps {
                if count >= config.max_candidates {
                    break;
                }
                if used_new_ids.contains(new_id) {
                    continue;
                }

                // Check if names match the cross-ecosystem mapping
                if new_comp.name.eq_ignore_ascii_case(&equiv.target_name) {
                    let base_score = matcher.match_score(old_comp, new_comp);
                    // Apply penalty for cross-ecosystem match
                    let adjusted_score = (base_score - config.score_penalty).max(0.0);

                    if adjusted_score >= config.min_score {
                        results.push((old_id.clone(), new_id.clone(), adjusted_score));
                        count += 1;
                    }
                }
            }
        }
    }

    results
}

/// Perform optimal assignment using Hungarian algorithm or fallback strategies.
///
/// For small to medium problems, uses the Hungarian algorithm (Kuhn-Munkres)
/// for globally optimal bipartite matching. For large problems, falls back
/// to greedy with 2-opt swaps for performance.
fn optimal_assignment(
    candidates: &[(CanonicalId, CanonicalId, f64)],
    _unmatched_old: &[&CanonicalId],
    config: &LargeSbomConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    if candidates.is_empty() {
        return Vec::new();
    }

    // Build unique sets of old and new IDs from candidates
    let old_ids: Vec<CanonicalId> = {
        let set: HashSet<_> = candidates.iter().map(|(o, _, _)| o.clone()).collect();
        set.into_iter().collect()
    };

    let new_ids: Vec<CanonicalId> = {
        let set: HashSet<_> = candidates.iter().map(|(_, n, _)| n.clone()).collect();
        set.into_iter().collect()
    };

    let n = old_ids.len().max(new_ids.len());

    // Choose assignment method based on problem size
    if n <= config.hungarian_threshold {
        hungarian_assignment(candidates, &old_ids, &new_ids)
    } else if config.enable_swap_optimization {
        greedy_with_swaps(candidates, config.max_swap_iterations)
    } else {
        greedy_assignment(candidates)
    }
}

/// Hungarian algorithm (Kuhn-Munkres) for optimal bipartite matching.
///
/// Returns the globally optimal assignment that maximizes total score.
fn hungarian_assignment(
    candidates: &[(CanonicalId, CanonicalId, f64)],
    old_ids: &[CanonicalId],
    new_ids: &[CanonicalId],
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use pathfinding::kuhn_munkres::kuhn_munkres_min;
    use pathfinding::matrix::Matrix;

    if old_ids.is_empty() || new_ids.is_empty() {
        return Vec::new();
    }

    // Build index maps
    let old_idx: HashMap<&CanonicalId, usize> = old_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();
    let new_idx: HashMap<&CanonicalId, usize> = new_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();

    // Build score matrix (we need to track actual scores separately)
    let mut scores: HashMap<(usize, usize), f64> = HashMap::new();
    for (old_id, new_id, score) in candidates {
        if let (Some(&oi), Some(&ni)) = (old_idx.get(old_id), new_idx.get(new_id)) {
            // Keep the best score if there are duplicates
            let entry = scores.entry((oi, ni)).or_insert(0.0);
            if *score > *entry {
                *entry = *score;
            }
        }
    }

    // Create cost matrix for Hungarian algorithm
    // Scale to i64 and negate for minimization (we want max score)
    let n = old_ids.len().max(new_ids.len());
    let scale = 1_000_000i64;

    let weights: Vec<Vec<i64>> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    if i < old_ids.len() && j < new_ids.len() {
                        // Negate score for minimization, use large value for no edge
                        let score = scores.get(&(i, j)).copied().unwrap_or(0.0);
                        if score > 0.0 {
                            -((score * scale as f64) as i64)
                        } else {
                            scale // Large cost for no edge
                        }
                    } else {
                        0 // Padding for square matrix
                    }
                })
                .collect()
        })
        .collect();

    let matrix = Matrix::from_rows(weights).expect("Matrix creation failed");

    // Run Hungarian algorithm
    let (_, assignment) = kuhn_munkres_min(&matrix);

    // Convert assignment back to result
    let mut result = Vec::new();
    for (old_i, new_i) in assignment.into_iter().enumerate() {
        if old_i < old_ids.len() && new_i < new_ids.len() {
            if let Some(&score) = scores.get(&(old_i, new_i)) {
                if score > 0.0 {
                    result.push((old_ids[old_i].clone(), new_ids[new_i].clone(), score));
                }
            }
        }
    }

    result
}

/// Simple greedy assignment (sort by score, assign greedily).
fn greedy_assignment(candidates: &[(CanonicalId, CanonicalId, f64)]) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use std::cmp::Ordering;

    let mut sorted: Vec<_> = candidates.to_vec();
    sorted.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));

    let mut result = Vec::new();
    let mut used_old: HashSet<CanonicalId> = HashSet::new();
    let mut used_new: HashSet<CanonicalId> = HashSet::new();

    for (old_id, new_id, score) in sorted {
        if !used_old.contains(&old_id) && !used_new.contains(&new_id) {
            used_old.insert(old_id.clone());
            used_new.insert(new_id.clone());
            result.push((old_id, new_id, score));
        }
    }

    result
}

/// Greedy assignment with 2-opt swap optimization.
///
/// Starts with greedy assignment, then iteratively swaps pairs that
/// would improve total score.
fn greedy_with_swaps(
    candidates: &[(CanonicalId, CanonicalId, f64)],
    max_iterations: usize,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    // Start with greedy assignment
    let mut result = greedy_assignment(candidates);

    if result.len() < 2 {
        return result;
    }

    // Build lookup for quick score access
    let score_lookup: HashMap<(&CanonicalId, &CanonicalId), f64> = candidates
        .iter()
        .map(|(o, n, s)| ((o, n), *s))
        .collect();

    // 2-opt: Try swapping pairs to improve total score
    let mut improved = true;
    let mut iterations = 0;

    while improved && iterations < max_iterations {
        improved = false;
        iterations += 1;

        for i in 0..result.len() {
            for j in (i + 1)..result.len() {
                // Clone values to avoid borrow issues
                let (old_i, new_i, score_i) = result[i].clone();
                let (old_j, new_j, score_j) = result[j].clone();

                // Current total score for these two pairs
                let current_score = score_i + score_j;

                // Score if we swap new assignments
                let swapped_score_i = score_lookup.get(&(&old_i, &new_j)).copied().unwrap_or(0.0);
                let swapped_score_j = score_lookup.get(&(&old_j, &new_i)).copied().unwrap_or(0.0);
                let swapped_total = swapped_score_i + swapped_score_j;

                // If swap improves score, apply it
                if swapped_total > current_score && swapped_score_i > 0.0 && swapped_score_j > 0.0 {
                    result[i] = (old_i, new_j, swapped_score_i);
                    result[j] = (old_j, new_i, swapped_score_j);
                    improved = true;
                }
            }
        }
    }

    result
}
