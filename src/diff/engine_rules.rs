//! Rule engine integration for the diff engine.

use super::engine_matching::ComponentMatchResult;
use crate::matching::RuleEngine;
use crate::model::{CanonicalId, NormalizedSbom};
use indexmap::IndexMap;
use std::collections::HashMap;

/// Result of applying matching rules.
pub struct RuleApplicationResult {
    pub old_filtered: NormalizedSbom,
    pub new_filtered: NormalizedSbom,
    pub old_canonical: HashMap<CanonicalId, CanonicalId>,
    pub new_canonical: HashMap<CanonicalId, CanonicalId>,
    pub rules_count: usize,
}

/// Apply matching rules and return filtered SBOMs with canonical mappings.
pub fn apply_rules(
    rule_engine: Option<&RuleEngine>,
    old: &NormalizedSbom,
    new: &NormalizedSbom,
) -> Option<RuleApplicationResult> {
    let engine = rule_engine?;

    let old_result = engine.apply(&old.components);
    let new_result = engine.apply(&new.components);

    // Filter out excluded components
    let old_components: IndexMap<_, _> = old
        .components
        .iter()
        .filter(|(id, _)| !old_result.excluded.contains(*id))
        .map(|(id, c)| (id.clone(), c.clone()))
        .collect();
    let new_components: IndexMap<_, _> = new
        .components
        .iter()
        .filter(|(id, _)| !new_result.excluded.contains(*id))
        .map(|(id, c)| (id.clone(), c.clone()))
        .collect();

    // Create filtered SBOMs
    let mut old_filtered = old.clone();
    old_filtered.components = old_components;
    let mut new_filtered = new.clone();
    new_filtered.components = new_components;

    // Count applied rules
    let rules_count = old_result.applied_rules.len() + new_result.applied_rules.len();

    Some(RuleApplicationResult {
        old_filtered,
        new_filtered,
        old_canonical: old_result.canonical_map,
        new_canonical: new_result.canonical_map,
        rules_count,
    })
}

/// Remap a ComponentMatchResult through canonical IDs from rule engine.
pub fn remap_match_result(
    result: &ComponentMatchResult,
    old_canonical: &HashMap<CanonicalId, CanonicalId>,
    new_canonical: &HashMap<CanonicalId, CanonicalId>,
) -> ComponentMatchResult {
    let mut remapped = ComponentMatchResult::new();

    // Remap matches
    for (old_id, new_id_opt) in &result.matches {
        let canonical_old = old_canonical
            .get(old_id)
            .cloned()
            .unwrap_or_else(|| old_id.clone());
        let canonical_new = new_id_opt.as_ref().and_then(|nid| {
            new_canonical
                .get(nid)
                .cloned()
                .or_else(|| Some(nid.clone()))
        });
        remapped.matches.insert(canonical_old, canonical_new);
    }

    // Remap pairs
    for ((old_id, new_id), score) in &result.pairs {
        let canonical_old = old_canonical
            .get(old_id)
            .cloned()
            .unwrap_or_else(|| old_id.clone());
        let canonical_new = new_canonical
            .get(new_id)
            .cloned()
            .unwrap_or_else(|| new_id.clone());
        remapped.pairs.insert((canonical_old, canonical_new), *score);
    }

    remapped
}
