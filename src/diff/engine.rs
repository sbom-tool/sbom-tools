//! Semantic diff engine implementation.

use super::changes::{
    ComponentChangeComputer, DependencyChangeComputer, LicenseChangeComputer,
    VulnerabilityChangeComputer,
};
pub use super::engine_config::LargeSbomConfig;
use super::engine_matching::{match_components, ComponentMatchResult};
use super::engine_rules::{apply_rules, remap_match_result};
use super::traits::ChangeComputer;
use super::{diff_dependency_graph, CostModel, DiffResult, GraphDiffConfig, MatchInfo};
use crate::error::SbomDiffError;
use crate::matching::{
    ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher, MatchingRulesConfig, RuleEngine,
};
use crate::model::NormalizedSbom;
use std::borrow::Cow;

/// Semantic diff engine for comparing SBOMs.
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
    pub fn with_cost_model(mut self, cost_model: CostModel) -> Self {
        self.cost_model = cost_model;
        self
    }

    /// Set fuzzy matching configuration
    pub fn with_fuzzy_config(mut self, config: FuzzyMatchConfig) -> Self {
        self.fuzzy_config = config;
        self
    }

    /// Include unchanged components in the result
    pub fn include_unchanged(mut self, include: bool) -> Self {
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
    pub fn with_large_sbom_config(mut self, config: LargeSbomConfig) -> Self {
        self.large_sbom_config = config;
        self
    }

    /// Get the large SBOM configuration.
    pub fn large_sbom_config(&self) -> &LargeSbomConfig {
        &self.large_sbom_config
    }

    /// Check if a custom matcher is configured
    pub fn has_custom_matcher(&self) -> bool {
        self.custom_matcher.is_some()
    }

    /// Check if graph diffing is enabled
    pub fn graph_diff_enabled(&self) -> bool {
        self.graph_diff_config.is_some()
    }

    /// Check if custom matching rules are configured
    pub fn has_matching_rules(&self) -> bool {
        self.rule_engine.is_some()
    }

    /// Compare two SBOMs and return the diff result
    pub fn diff(&self, old: &NormalizedSbom, new: &NormalizedSbom) -> Result<DiffResult, SbomDiffError> {
        let mut result = DiffResult::new();

        // Quick check: if content hashes match, SBOMs are identical
        if old.content_hash == new.content_hash && old.content_hash != 0 {
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
        let default_matcher;
        let matcher: &dyn ComponentMatcher = match &self.custom_matcher {
            Some(m) => m.as_ref(),
            None => {
                default_matcher = FuzzyMatcher::new(self.fuzzy_config.clone());
                &default_matcher
            }
        };

        let mut component_matches = match_components(
            &old_filtered,
            &new_filtered,
            matcher,
            &self.fuzzy_config,
            &self.large_sbom_config,
        );

        // Apply canonical mappings from rule engine
        if let Some((old_canonical, new_canonical)) = &canonical_maps {
            component_matches = remap_match_result(&component_matches, old_canonical, new_canonical);
        }

        // Compute changes using the modular change computers
        self.compute_all_changes(&old_filtered, &new_filtered, &component_matches, matcher, &mut result);

        // Perform graph-aware diffing if enabled
        if let Some(ref graph_config) = self.graph_diff_config {
            let (graph_changes, graph_summary) =
                diff_dependency_graph(&old_filtered, &new_filtered, &component_matches.matches, graph_config);
            result.graph_changes = graph_changes;
            result.graph_summary = Some(graph_summary);
        }

        // Calculate semantic score
        result.semantic_score = self.cost_model.calculate_semantic_score(
            result.components.added.len(),
            result.components.removed.len(),
            result.components.modified.len(),
            result.licenses.component_changes.len(),
            result.vulnerabilities.introduced.len(),
            result.vulnerabilities.resolved.len(),
            result.dependencies.added.len(),
            result.dependencies.removed.len(),
        );

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
                if let (Some(ref old_id), Some(ref new_id)) =
                    (&change.old_canonical_id, &change.canonical_id)
                {
                    if let (Some(old_comp), Some(new_comp)) =
                        (old.components.get(old_id), new.components.get(new_id))
                    {
                        let explanation = matcher.explain_match(old_comp, new_comp);
                        let mut match_info = MatchInfo::from_explanation(&explanation);

                        // Use the actual score from the matching phase if available
                        if let Some(&score) =
                            match_result.pairs.get(&(old_id.clone(), new_id.clone()))
                        {
                            match_info.score = score;
                        }

                        change = change.with_match_info(match_info);
                    }
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

        // Vulnerability changes
        let vuln_computer = VulnerabilityChangeComputer::new();
        let vuln_changes = vuln_computer.compute(old, new, &match_result.matches);
        result.vulnerabilities.introduced = vuln_changes.introduced;
        result.vulnerabilities.resolved = vuln_changes.resolved;
        result.vulnerabilities.persistent = vuln_changes.persistent;
    }
}

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
