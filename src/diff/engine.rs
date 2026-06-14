//! Semantic diff engine implementation.

use super::changes::{
    ComponentChangeComputer, DependencyChangeComputer, LicenseChangeComputer,
    VulnerabilityChangeComputer, compute_metadata_changes,
};
pub use super::engine_config::LargeSbomConfig;
use super::engine_matching::{ComponentMatchResult, match_components};
use super::engine_rules::{apply_rules, remap_match_result};
use super::incremental::ChangedSections;
use super::result::MatchMetrics;
use super::traits::ChangeComputer;
use super::{CostModel, DiffResult, GraphDiffConfig, MatchInfo, diff_dependency_graph};
use crate::error::SbomDiffError;
use crate::matching::{
    ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher, MatchingRulesConfig, RuleEngine,
};
use crate::model::NormalizedSbom;
use std::borrow::Cow;

/// Semantic diff engine for comparing SBOMs.
#[must_use]
pub struct DiffEngine {
    cost_model: CostModel,
    fuzzy_config: FuzzyMatchConfig,
    include_unchanged: bool,
    graph_diff_config: Option<GraphDiffConfig>,
    rule_engine: Option<RuleEngine>,
    custom_matcher: Option<Box<dyn ComponentMatcher>>,
    large_sbom_config: LargeSbomConfig,
}

impl DiffEngine {
    /// Create a new diff engine with default settings
    pub fn new() -> Self {
        Self {
            cost_model: CostModel::default(),
            fuzzy_config: FuzzyMatchConfig::balanced(),
            include_unchanged: false,
            graph_diff_config: None,
            rule_engine: None,
            custom_matcher: None,
            large_sbom_config: LargeSbomConfig::default(),
        }
    }

    /// Create a diff engine with a custom cost model
    pub const fn with_cost_model(mut self, cost_model: CostModel) -> Self {
        self.cost_model = cost_model;
        self
    }

    /// Set fuzzy matching configuration
    pub const fn with_fuzzy_config(mut self, config: FuzzyMatchConfig) -> Self {
        self.fuzzy_config = config;
        self
    }

    /// Include unchanged components in the result
    pub const fn include_unchanged(mut self, include: bool) -> Self {
        self.include_unchanged = include;
        self
    }

    /// Enable graph-aware diffing with the given configuration
    pub fn with_graph_diff(mut self, config: GraphDiffConfig) -> Self {
        self.graph_diff_config = Some(config);
        self
    }

    /// Set custom matching rules from a configuration
    pub fn with_matching_rules(mut self, config: MatchingRulesConfig) -> Result<Self, String> {
        self.rule_engine = Some(RuleEngine::new(config)?);
        Ok(self)
    }

    /// Set custom matching rules engine directly
    pub fn with_rule_engine(mut self, engine: RuleEngine) -> Self {
        self.rule_engine = Some(engine);
        self
    }

    /// Set a custom component matcher.
    pub fn with_matcher(mut self, matcher: Box<dyn ComponentMatcher>) -> Self {
        self.custom_matcher = Some(matcher);
        self
    }

    /// Configure large SBOM optimization settings.
    pub const fn with_large_sbom_config(mut self, config: LargeSbomConfig) -> Self {
        self.large_sbom_config = config;
        self
    }

    /// Get the large SBOM configuration.
    #[must_use]
    pub const fn large_sbom_config(&self) -> &LargeSbomConfig {
        &self.large_sbom_config
    }

    /// Check if a custom matcher is configured
    #[must_use]
    pub fn has_custom_matcher(&self) -> bool {
        self.custom_matcher.is_some()
    }

    /// Check if graph diffing is enabled
    #[must_use]
    pub const fn graph_diff_enabled(&self) -> bool {
        self.graph_diff_config.is_some()
    }

    /// Check if custom matching rules are configured
    #[must_use]
    pub const fn has_matching_rules(&self) -> bool {
        self.rule_engine.is_some()
    }

    /// Compare two SBOMs and return the diff result
    #[must_use = "diff result contains all changes and should not be discarded"]
    pub fn diff(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
    ) -> Result<DiffResult, SbomDiffError> {
        let _span = tracing::info_span!(
            "diff_engine::diff",
            old_components = old.component_count(),
            new_components = new.component_count(),
        )
        .entered();

        let mut result = DiffResult::new();

        // Quick check: if content hashes match, SBOMs are identical
        if old.content_hash == new.content_hash && old.content_hash != 0 {
            result.semantic_score = PERCENT_MAX;
            return Ok(result);
        }

        // Apply custom matching rules if configured
        // Use Cow to avoid cloning SBOMs when no rules are applied
        let (old_filtered, new_filtered, canonical_maps) =
            if let Some(rule_result) = apply_rules(self.rule_engine.as_ref(), old, new) {
                result.rules_applied = rule_result.rules_count;
                (
                    Cow::Owned(rule_result.old_filtered),
                    Cow::Owned(rule_result.new_filtered),
                    Some((rule_result.old_canonical, rule_result.new_canonical)),
                )
            } else {
                (Cow::Borrowed(old), Cow::Borrowed(new), None)
            };

        // Build component mappings using the configured matcher
        let default_matcher = FuzzyMatcher::new(self.fuzzy_config.clone());
        let matcher: &dyn ComponentMatcher = self
            .custom_matcher
            .as_ref()
            .map_or(&default_matcher as &dyn ComponentMatcher, |m| m.as_ref());

        let mut component_matches = match_components(
            &old_filtered,
            &new_filtered,
            matcher,
            &self.fuzzy_config,
            &self.large_sbom_config,
        );

        // Apply canonical mappings from rule engine
        if let Some((old_canonical, new_canonical)) = &canonical_maps {
            component_matches =
                remap_match_result(&component_matches, old_canonical, new_canonical);
        }

        // Compute match metrics for observability
        {
            // Sorted so float accumulation order (and thus the serialized
            // average) is identical across runs
            let mut scores: Vec<f64> = component_matches.pairs.values().copied().collect();
            scores.sort_unstable_by(f64::total_cmp);
            let exact = scores.iter().filter(|&&s| s >= 0.99).count();
            let fuzzy = scores.len() - exact;
            let matched_count = scores.len();
            let unmatched_old = old_filtered.component_count().saturating_sub(matched_count);
            let unmatched_new = new_filtered.component_count().saturating_sub(matched_count);
            let avg = if scores.is_empty() {
                0.0
            } else {
                scores.iter().sum::<f64>() / scores.len() as f64
            };
            let min = scores.iter().copied().fold(f64::INFINITY, f64::min);

            result.match_metrics = Some(MatchMetrics {
                exact_matches: exact,
                fuzzy_matches: fuzzy,
                rule_matches: result.rules_applied,
                unmatched_old,
                unmatched_new,
                avg_match_score: avg,
                min_match_score: if min.is_infinite() { 0.0 } else { min },
            });
        }

        // Compute changes using the modular change computers
        self.compute_all_changes(
            &old_filtered,
            &new_filtered,
            &component_matches,
            matcher,
            &mut result,
        );

        // Perform graph-aware diffing if enabled
        if let Some(ref graph_config) = self.graph_diff_config {
            let (graph_changes, graph_summary) = diff_dependency_graph(
                &old_filtered,
                &new_filtered,
                &component_matches.matches,
                graph_config,
            );
            result.graph_changes = graph_changes;
            result.graph_summary = Some(graph_summary);
        }

        // Calculate semantic score
        result.semantic_score = self.compute_semantic_score(&result, old, new);

        result.calculate_summary();
        Ok(result)
    }

    /// Compute all changes using the modular change computers.
    fn compute_all_changes(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        match_result: &ComponentMatchResult,
        matcher: &dyn ComponentMatcher,
        result: &mut DiffResult,
    ) {
        // Component changes
        let comp_computer = ComponentChangeComputer::new(self.cost_model.clone());
        let comp_changes = comp_computer.compute(old, new, &match_result.matches);
        result.components.added = comp_changes.added;
        result.components.removed = comp_changes.removed;
        result.components.modified = comp_changes
            .modified
            .into_iter()
            .map(|mut change| {
                // Add match explanation for modified components
                // Use stored canonical IDs directly instead of reconstructing from name+version
                if let (Some(old_id), Some(new_id)) =
                    (&change.old_canonical_id, &change.canonical_id)
                    && let (Some(old_comp), Some(new_comp)) =
                        (old.components.get(old_id), new.components.get(new_id))
                {
                    let explanation = matcher.explain_match(old_comp, new_comp);
                    let mut match_info = MatchInfo::from_explanation(&explanation);

                    // Use the actual score from the matching phase if available
                    if let Some(&score) = match_result.pairs.get(&(old_id.clone(), new_id.clone()))
                    {
                        match_info.score = score;
                    }

                    change = change.with_match_info(match_info);
                }
                change
            })
            .collect();

        // Dependency changes
        let dep_computer = DependencyChangeComputer::new();
        let dep_changes = dep_computer.compute(old, new, &match_result.matches);
        result.dependencies.added = dep_changes.added;
        result.dependencies.removed = dep_changes.removed;

        // License changes
        let lic_computer = LicenseChangeComputer::new();
        let lic_changes = lic_computer.compute(old, new, &match_result.matches);
        result.licenses.new_licenses = lic_changes.new_licenses;
        result.licenses.removed_licenses = lic_changes.removed_licenses;
        result.licenses.component_changes = lic_changes.component_changes;

        // Vulnerability changes
        let vuln_computer = VulnerabilityChangeComputer::new();
        let vuln_changes = vuln_computer.compute(old, new, &match_result.matches);
        result.vulnerabilities.introduced = vuln_changes.introduced;
        result.vulnerabilities.resolved = vuln_changes.resolved;
        result.vulnerabilities.persistent = vuln_changes.persistent;
        result.vulnerabilities.vex_changes = vuln_changes.vex_changes;

        // Document-level metadata changes (author/tool/timestamp/spec-version/etc.)
        result.metadata_changes = compute_metadata_changes(old, new);
    }

    /// Diff only the specified sections, reusing cached results for unchanged sections.
    ///
    /// This enables true incremental diffing: when only some SBOM sections changed,
    /// we skip recomputing the unchanged sections and reuse them from the cached result.
    /// Component matching is always recomputed since it's needed by all section computers.
    ///
    /// Falls back to a full diff if no cached result is provided.
    pub(crate) fn diff_sections(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        sections: &ChangedSections,
        cached: &DiffResult,
    ) -> Result<DiffResult, SbomDiffError> {
        // Start with the cached result so unchanged sections are preserved
        let mut result = cached.clone();

        // Apply custom matching rules if configured
        let (old_filtered, new_filtered, canonical_maps) =
            if let Some(rule_result) = apply_rules(self.rule_engine.as_ref(), old, new) {
                result.rules_applied = rule_result.rules_count;
                (
                    Cow::Owned(rule_result.old_filtered),
                    Cow::Owned(rule_result.new_filtered),
                    Some((rule_result.old_canonical, rule_result.new_canonical)),
                )
            } else {
                (Cow::Borrowed(old), Cow::Borrowed(new), None)
            };

        // Always recompute matching — it's needed for any section computer
        let default_matcher = FuzzyMatcher::new(self.fuzzy_config.clone());
        let matcher: &dyn ComponentMatcher = self
            .custom_matcher
            .as_ref()
            .map_or(&default_matcher as &dyn ComponentMatcher, |m| m.as_ref());

        let mut component_matches = match_components(
            &old_filtered,
            &new_filtered,
            matcher,
            &self.fuzzy_config,
            &self.large_sbom_config,
        );

        // Apply canonical mappings from rule engine
        if let Some((old_canonical, new_canonical)) = &canonical_maps {
            component_matches =
                remap_match_result(&component_matches, old_canonical, new_canonical);
        }

        // Selectively recompute only the changed sections
        if sections.components {
            let comp_computer = ComponentChangeComputer::new(self.cost_model.clone());
            let comp_changes =
                comp_computer.compute(&old_filtered, &new_filtered, &component_matches.matches);
            result.components.added = comp_changes.added;
            result.components.removed = comp_changes.removed;
            result.components.modified = comp_changes
                .modified
                .into_iter()
                .map(|mut change| {
                    if let (Some(old_id), Some(new_id)) =
                        (&change.old_canonical_id, &change.canonical_id)
                        && let (Some(old_comp), Some(new_comp)) = (
                            old_filtered.components.get(old_id),
                            new_filtered.components.get(new_id),
                        )
                    {
                        let explanation = matcher.explain_match(old_comp, new_comp);
                        let mut match_info = MatchInfo::from_explanation(&explanation);
                        if let Some(&score) = component_matches
                            .pairs
                            .get(&(old_id.clone(), new_id.clone()))
                        {
                            match_info.score = score;
                        }
                        change = change.with_match_info(match_info);
                    }
                    change
                })
                .collect();
        }

        if sections.dependencies {
            let dep_computer = DependencyChangeComputer::new();
            let dep_changes =
                dep_computer.compute(&old_filtered, &new_filtered, &component_matches.matches);
            result.dependencies.added = dep_changes.added;
            result.dependencies.removed = dep_changes.removed;
        }

        if sections.licenses {
            let lic_computer = LicenseChangeComputer::new();
            let lic_changes =
                lic_computer.compute(&old_filtered, &new_filtered, &component_matches.matches);
            result.licenses.new_licenses = lic_changes.new_licenses;
            result.licenses.removed_licenses = lic_changes.removed_licenses;
            result.licenses.component_changes = lic_changes.component_changes;
        }

        if sections.vulnerabilities {
            let vuln_computer = VulnerabilityChangeComputer::new();
            let vuln_changes =
                vuln_computer.compute(&old_filtered, &new_filtered, &component_matches.matches);
            result.vulnerabilities.introduced = vuln_changes.introduced;
            result.vulnerabilities.resolved = vuln_changes.resolved;
            result.vulnerabilities.persistent = vuln_changes.persistent;
            result.vulnerabilities.vex_changes = vuln_changes.vex_changes;
        }

        // Document-metadata changes are cheap and not tracked by `ChangedSections`,
        // so always recompute them rather than risk serving a stale cached vec
        // when only the document header changed.
        result.metadata_changes = compute_metadata_changes(&old_filtered, &new_filtered);

        // Always recompute summary and semantic score since they depend on all sections
        result.semantic_score = self.compute_semantic_score(&result, &old_filtered, &new_filtered);
        result.calculate_summary();
        Ok(result)
    }

    /// Compute the semantic score from a `DiffResult`.
    fn compute_semantic_score(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> f64 {
        let raw_cost = self.cost_model.calculate_semantic_score(
            result.components.added.len(),
            result.components.removed.len(),
            result.components.modified.len(),
            result.licenses.component_changes.len(),
            result.vulnerabilities.introduced.len(),
            result.vulnerabilities.resolved.len(),
            result.dependencies.added.len(),
            result.dependencies.removed.len(),
        );

        self.normalize_semantic_score(raw_cost, result, old_sbom, new_sbom)
    }

    /// Normalize `raw_cost` to a 0–100 similarity percentage against an
    /// SBOM-derived upper-bound budget.
    ///
    /// For each cost axis we compute the worst-case contribution given the
    /// inputs (e.g. every component on both sides being added or removed) and
    /// sum them to form `total_budget`. The score is then
    /// `PERCENT_MAX * (1 - raw_cost / total_budget)`, clamped to `[0, PERCENT_MAX]`
    /// to defend against future cost-model changes where the bound might no
    /// longer dominate. When both SBOMs are empty the budget collapses to ~0
    /// and the function returns `PERCENT_MAX` (an empty diff is fully similar).
    ///
    /// Note: `modification_budget` uses the actual `modified.len()` rather
    /// than `min(old, new)`. The actual count is still a valid upper bound on
    /// `raw_modification_cost` (each modification contributes at most
    /// `max(version_major, license_changed)`), and using it keeps the per-axis
    /// scoring sensitive to the modifications that actually occurred.
    /// `vulnerability_resolved` is intentionally excluded from the budget: it
    /// is a reward (negative cost in `CostModel`), so it can only reduce
    /// `raw_cost`, never push it above the bound.
    fn normalize_semantic_score(
        &self,
        raw_cost: f64,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> f64 {
        let component_budget = (old_sbom.component_count() + new_sbom.component_count()) as f64
            * f64::from(
                self.cost_model
                    .component_added
                    .max(self.cost_model.component_removed),
            );
        let dependency_budget = (old_sbom.edges.len() + new_sbom.edges.len()) as f64
            * f64::from(
                self.cost_model
                    .dependency_added
                    .max(self.cost_model.dependency_removed),
            );
        let vulnerability_budget = (old_sbom.vulnerability_counts().total()
            + new_sbom.vulnerability_counts().total()) as f64
            * f64::from(self.cost_model.vulnerability_introduced);
        let modification_budget = result.components.modified.len() as f64
            * f64::from(
                self.cost_model
                    .version_major
                    .max(self.cost_model.license_changed),
            );

        let total_budget =
            component_budget + dependency_budget + vulnerability_budget + modification_budget;

        if total_budget <= f64::EPSILON {
            return PERCENT_MAX;
        }

        (PERCENT_MAX * (1.0 - (raw_cost / total_budget))).clamp(0.0, PERCENT_MAX)
    }
}

/// Upper bound of the 0–100 similarity percentage emitted by
/// [`DiffEngine::normalize_semantic_score`].
const PERCENT_MAX: f64 = 100.0;

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_diff() {
        let engine = DiffEngine::new();
        let sbom = NormalizedSbom::default();
        let result = engine.diff(&sbom, &sbom).expect("diff should succeed");
        assert!(!result.has_changes());
    }
}
