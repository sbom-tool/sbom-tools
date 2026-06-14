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
    let _span = tracing::info_span!(
        "diff_engine::match_components",
        old_count = old.component_count(),
        new_count = new.component_count(),
    )
    .entered();

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

    // Phase 4: Optimal assignment over the sparse candidate edge list
    let assignment = sparse_assignment(&candidates);

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
                let candidate_ids =
                    new_index.find_candidates(old_id, old_entry, max_candidates, max_length_diff);

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
    new_by_ecosystem: &HashMap<
        crate::model::Ecosystem,
        Vec<(CanonicalId, &crate::model::Component)>,
    >,
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

/// Cost matrix scaling factor: float scores in `[0, 1]` are mapped to integer
/// costs so the solver can use exact comparisons (no float epsilon issues).
const ASSIGNMENT_COST_SCALE: i64 = 1_000_000;

/// Sparse assignment over the candidate edge list via successive shortest
/// augmenting paths (Dijkstra with reduced costs / dual potentials).
///
/// Solves maximum-weight bipartite matching without materializing a dense n×n
/// matrix: the graph is stored as per-source adjacency lists of the actual
/// candidate edges, so both memory and time scale with the number of candidate
/// edges (≤~100 per source), not with the product of the two SBOM sizes.
///
/// Each real edge has non-negative integer cost `SCALE − score·SCALE` (lower =
/// better match), and every source additionally gets a dummy "leave unmatched"
/// object of cost `SCALE` (= score 0). The result is therefore a min-cost
/// **perfect** matching over non-negative costs — a setting where Dijkstra with
/// potentials is exact — and a source prefers a real object precisely when its
/// score is positive, recovering max-weight behavior. Re-routing existing
/// matches along augmenting paths is what makes this globally optimal rather
/// than greedy.
///
/// Determinism: old/new IDs are indexed in sorted value order (preserving
/// #218's ordering invariant), adjacency lists are object-index sorted, and
/// path-search ties break by smaller object index, so repeated runs over
/// identical input produce identical output.
fn sparse_assignment(
    candidates: &[(CanonicalId, CanonicalId, f64)],
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    // Stable, sorted index spaces for old and new IDs so tie-breaking is
    // reproducible across runs (keeps #218's determinism guarantee).
    let old_ids = sorted_unique_ids(candidates.iter().map(|(o, _, _)| o));
    let new_ids = sorted_unique_ids(candidates.iter().map(|(_, n, _)| n));

    let old_idx: HashMap<&CanonicalId, usize> =
        old_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();
    let new_idx: HashMap<&CanonicalId, usize> =
        new_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();

    let num_old = old_ids.len();
    let num_real = new_ids.len();
    // One dummy object per source (indices num_real..num_real+num_old) lets a
    // source stay unmatched at cost SCALE without breaking the perfect-matching
    // formulation. Dummy `num_real + i` is reachable only from source `i`.
    let num_obj = num_real + num_old;

    // Per-source adjacency: (object index, non-negative integer cost). Duplicate
    // (old, new) edges collapse to the lowest cost (= highest score). Edges are
    // object-index sorted so the search is deterministic regardless of HashMap
    // iteration order.
    let mut adjacency: Vec<Vec<(usize, i64)>> = vec![Vec::new(); num_old];
    {
        let mut edge_best: HashMap<(usize, usize), i64> = HashMap::new();
        for (old_id, new_id, score) in candidates {
            if let (Some(&oi), Some(&ni)) = (old_idx.get(old_id), new_idx.get(new_id)) {
                let clamped = score.clamp(0.0, 1.0);
                let cost = ASSIGNMENT_COST_SCALE - (clamped * ASSIGNMENT_COST_SCALE as f64) as i64;
                let entry = edge_best.entry((oi, ni)).or_insert(i64::MAX);
                if cost < *entry {
                    *entry = cost;
                }
            }
        }
        for ((oi, ni), cost) in edge_best {
            adjacency[oi].push((ni, cost));
        }
        for (src, edges) in adjacency.iter_mut().enumerate() {
            // Dummy object for this source: cost SCALE == score 0.
            edges.push((num_real + src, ASSIGNMENT_COST_SCALE));
            edges.sort_by_key(|&(obj, _)| obj);
        }
    }

    // Matching state: object -> source, source -> object.
    let mut object_owner: Vec<Option<usize>> = vec![None; num_obj];
    let mut source_obj: Vec<Option<usize>> = vec![None; num_old];
    // Dual potentials for reduced-cost Dijkstra (keeps reduced edge costs ≥ 0).
    let mut potential: Vec<i64> = vec![0; num_obj];

    // Per-augmentation scratch reused across iterations. `touched` records which
    // objects had their dist set this round, so reset, the settle scan, and the
    // potential update all run over only the reachable objects — keeping cost
    // proportional to the candidate edges, not to num_obj.
    let mut dist: Vec<i64> = vec![i64::MAX; num_obj];
    let mut src_for_obj: Vec<Option<usize>> = vec![None; num_obj];
    let mut visited: Vec<bool> = vec![false; num_obj];
    let mut touched: Vec<usize> = Vec::new();

    // Augment one source at a time, in sorted order, via the shortest
    // alternating path to a free object. Every source can always reach its own
    // free dummy, so each augmentation succeeds.
    for start in 0..num_old {
        for &obj in &touched {
            dist[obj] = i64::MAX;
            src_for_obj[obj] = None;
            visited[obj] = false;
        }
        touched.clear();

        // Seed: relax the free start source's own edges.
        for &(obj, cost) in &adjacency[start] {
            let reduced = cost - potential[obj];
            if reduced < dist[obj] {
                if dist[obj] == i64::MAX {
                    touched.push(obj);
                }
                dist[obj] = reduced;
                src_for_obj[obj] = Some(start);
            }
        }

        let mut found_obj: Option<usize> = None;

        loop {
            // Settle the unvisited touched object with minimum distance (ties:
            // lowest index, which keeps the search deterministic).
            let mut best_obj = None;
            let mut best_dist = i64::MAX;
            for &obj in &touched {
                if !visited[obj] && dist[obj] < best_dist {
                    best_dist = dist[obj];
                    best_obj = Some(obj);
                }
            }

            let Some(obj) = best_obj else { break };
            visited[obj] = true;

            match object_owner[obj] {
                None => {
                    // Free object reached: this is the shortest augmenting path.
                    found_obj = Some(obj);
                    break;
                }
                Some(owner) => {
                    // Object is taken. Extend the path through its owner: the
                    // owner gives up `obj` (subtract that edge's reduced cost)
                    // and bids on each of its other objects.
                    let owner_obj_reduced = adjacency[owner]
                        .iter()
                        .find(|(o, _)| *o == obj)
                        .map_or(0, |&(_, c)| c - potential[obj]);
                    for &(obj2, cost) in &adjacency[owner] {
                        if visited[obj2] {
                            continue;
                        }
                        let reduced = cost - potential[obj2];
                        let nd = dist[obj] - owner_obj_reduced + reduced;
                        if nd < dist[obj2] {
                            if dist[obj2] == i64::MAX {
                                touched.push(obj2);
                            }
                            dist[obj2] = nd;
                            src_for_obj[obj2] = Some(owner);
                        }
                    }
                }
            }
        }

        // Shift potentials by the settled distances so reduced costs stay
        // non-negative for the next augmentation.
        for &obj in &touched {
            if visited[obj] {
                potential[obj] += dist[obj];
            }
        }

        // Augment: walk the alternating path back to `start`, flipping matches.
        if let Some(mut obj) = found_obj {
            loop {
                let src = src_for_obj[obj].expect("path object has a source");
                let prev_obj = source_obj[src];
                object_owner[obj] = Some(src);
                source_obj[src] = Some(obj);
                match prev_obj {
                    Some(p) => obj = p,
                    None => break,
                }
            }
        }
    }

    // Cost lookup for materializing the final scores (real edges only).
    let edge_cost: HashMap<(usize, usize), i64> = adjacency
        .iter()
        .enumerate()
        .flat_map(|(src, edges)| {
            edges
                .iter()
                .filter(move |(obj, _)| *obj < num_real)
                .map(move |&(obj, cost)| ((src, obj), cost))
        })
        .collect();

    let mut result = Vec::new();
    for (src, obj) in source_obj.iter().enumerate() {
        if let Some(obj) = obj
            && *obj < num_real
            && let Some(&cost) = edge_cost.get(&(src, *obj))
        {
            let score = (ASSIGNMENT_COST_SCALE - cost) as f64 / ASSIGNMENT_COST_SCALE as f64;
            if score > 0.0 {
                result.push((old_ids[src].clone(), new_ids[*obj].clone(), score));
            }
        }
    }
    result
}

/// Collect a sorted, de-duplicated list of IDs in value order.
fn sorted_unique_ids<'a, I>(ids: I) -> Vec<CanonicalId>
where
    I: Iterator<Item = &'a CanonicalId>,
{
    let set: HashSet<&CanonicalId> = ids.collect();
    let mut ids: Vec<CanonicalId> = set.into_iter().cloned().collect();
    ids.sort_by(|a, b| a.value().cmp(b.value()));
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(s: &str) -> CanonicalId {
        CanonicalId::from_format_id(s)
    }

    /// Total score of an assignment, for comparing solver output against the
    /// known optimum.
    fn total_score(assignment: &[(CanonicalId, CanonicalId, f64)]) -> f64 {
        assignment.iter().map(|(_, _, s)| s).sum()
    }

    #[test]
    fn empty_candidates_yield_empty_assignment() {
        assert!(sparse_assignment(&[]).is_empty());
    }

    #[test]
    fn sparse_assignment_is_one_to_one() {
        // Two sources both prefer the same object; solver must split them.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.9),
            (cid("o1"), cid("n2"), 0.6),
            (cid("o2"), cid("n1"), 0.8),
            (cid("o2"), cid("n2"), 0.5),
        ];
        let result = sparse_assignment(&candidates);

        let old_used: HashSet<_> = result.iter().map(|(o, _, _)| o.clone()).collect();
        let new_used: HashSet<_> = result.iter().map(|(_, n, _)| n.clone()).collect();
        assert_eq!(
            old_used.len(),
            result.len(),
            "each old id used at most once"
        );
        assert_eq!(
            new_used.len(),
            result.len(),
            "each new id used at most once"
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn sparse_assignment_finds_global_optimum_over_greedy_trap() {
        // Greedy by score would take (o1,n1)=0.95 first, forcing o2->n2=0.10
        // (total 1.05). The optimal assignment is o1->n2=0.80, o2->n1=0.90
        // (total 1.70). The solver must find the optimum, not the greedy pick.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.95),
            (cid("o1"), cid("n2"), 0.80),
            (cid("o2"), cid("n1"), 0.90),
            (cid("o2"), cid("n2"), 0.10),
        ];
        let result = sparse_assignment(&candidates);

        assert!(
            (total_score(&result) - 1.70).abs() < 1e-9,
            "expected optimal total 1.70, got {} from {:?}",
            total_score(&result),
            result
        );
    }

    #[test]
    fn sparse_assignment_handles_more_sources_than_objects() {
        // Three sources, two objects: one source must remain unassigned.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.9),
            (cid("o2"), cid("n1"), 0.7),
            (cid("o2"), cid("n2"), 0.6),
            (cid("o3"), cid("n2"), 0.8),
        ];
        let result = sparse_assignment(&candidates);

        // At most two matches (two objects), all distinct objects.
        assert!(result.len() <= 2);
        let new_used: HashSet<_> = result.iter().map(|(_, n, _)| n.clone()).collect();
        assert_eq!(new_used.len(), result.len());
        // Optimum is o1->n1 (0.9) + o3->n2 (0.8) = 1.7.
        assert!(
            (total_score(&result) - 1.70).abs() < 1e-9,
            "expected optimal total 1.70, got {}",
            total_score(&result)
        );
    }

    #[test]
    fn sparse_assignment_is_deterministic() {
        // Symmetric scores create ties; output must be stable across runs and
        // independent of input edge order.
        let candidates = vec![
            (cid("a"), cid("x"), 0.5),
            (cid("a"), cid("y"), 0.5),
            (cid("b"), cid("x"), 0.5),
            (cid("b"), cid("y"), 0.5),
        ];
        let mut shuffled = candidates.clone();
        shuffled.reverse();

        let r1 = sparse_assignment(&candidates);
        let r2 = sparse_assignment(&candidates);
        let r3 = sparse_assignment(&shuffled);

        assert_eq!(r1, r2, "repeated runs must match");
        assert_eq!(r1, r3, "result must not depend on edge insertion order");
    }
}
