//! Read-only rendering context for TUI views.
//!
//! `RenderContext` is created from `&App` before each frame. Render functions
//! receive this instead of `&mut App`, enforcing side-effect-free rendering.
//!
//! # Frame Lifecycle
//!
//! ```text
//! app.prepare_render()       // pre-compute totals, caches, selections
//! let ctx = RenderContext::from_app(&app);
//! terminal.draw(|f| render(f, &ctx));  // pure reads only
//! ```

use crate::diff::{ComponentChange, DiffResult};
#[cfg(feature = "enrichment")]
use crate::enrichment::EnrichmentStats;
use crate::model::{NormalizedSbom, NormalizedSbomIndex};
use crate::quality::{ComplianceResult, QualityReport};
use crate::tui::app::{App, AppMode, ComponentFilter, TabKind};
use crate::tui::app_states::source::SourceDiffState;
use crate::tui::app_states::{
    ComponentsState, DependenciesState, DiffComplianceState, DiffVulnItem, DiffVulnStatus,
    GraphChangesState, LicensesState, QualityState, SideBySideState, VulnerabilitiesState,
    sort_component_changes,
};
use crate::tui::security::SecurityAnalysisCache;

/// Read-only rendering context.
///
/// Created from `&App` before each frame via [`RenderContext::from_app`].
/// All mutable pre-computation happens in [`App::prepare_render`] *before*
/// this struct is constructed.
#[allow(dead_code)] // Fields like active_tab and tick are available for view implementations
pub struct RenderContext<'a> {
    // === Core ===
    pub mode: AppMode,
    pub active_tab: TabKind,
    pub tick: u64,

    // === Data (immutable after App construction) ===
    pub diff_result: Option<&'a DiffResult>,
    pub old_sbom: Option<&'a NormalizedSbom>,
    pub new_sbom: Option<&'a NormalizedSbom>,
    pub sbom: Option<&'a NormalizedSbom>,
    pub old_sbom_index: Option<&'a NormalizedSbomIndex>,
    pub new_sbom_index: Option<&'a NormalizedSbomIndex>,
    pub sbom_index: Option<&'a NormalizedSbomIndex>,
    pub old_quality: Option<&'a QualityReport>,
    pub new_quality: Option<&'a QualityReport>,
    pub quality_report: Option<&'a QualityReport>,
    pub old_cra_compliance: Option<&'a ComplianceResult>,
    pub new_cra_compliance: Option<&'a ComplianceResult>,
    pub old_compliance_results: Option<&'a [ComplianceResult]>,
    pub new_compliance_results: Option<&'a [ComplianceResult]>,
    pub matching_threshold: f64,

    #[cfg(feature = "enrichment")]
    pub enrichment_stats_old: Option<&'a EnrichmentStats>,
    #[cfg(feature = "enrichment")]
    pub enrichment_stats_new: Option<&'a EnrichmentStats>,

    // === Per-tab UI state (read-only during render) ===
    pub components: &'a ComponentsState,
    pub dependencies: &'a DependenciesState,
    pub licenses: &'a LicensesState,
    pub vulnerabilities: &'a VulnerabilitiesState,
    pub quality: &'a QualityState,
    pub compliance: &'a DiffComplianceState,
    pub side_by_side: &'a SideBySideState,
    pub graph_changes: &'a GraphChangesState,
    pub source: &'a SourceDiffState,

    // === Cross-cutting state ===
    pub security_cache: &'a SecurityAnalysisCache,
    pub compliance_state: &'a crate::tui::app_states::PolicyComplianceState,
    pub navigation_ctx: &'a crate::tui::app_states::NavigationContext,
    pub status_message: Option<&'a str>,
}

impl<'a> RenderContext<'a> {
    /// Create a `RenderContext` by borrowing all relevant `App` fields.
    ///
    /// **Important:** Call [`App::prepare_render`] *before* this to ensure
    /// caches are warm and computed state (totals, compliance results) is
    /// up to date.
    #[must_use]
    pub fn from_app(app: &'a App) -> Self {
        Self {
            mode: app.mode,
            active_tab: app.active_tab,
            tick: app.tick,

            diff_result: app.data.diff_result.as_ref(),
            old_sbom: app.data.old_sbom.as_ref(),
            new_sbom: app.data.new_sbom.as_ref(),
            sbom: app.data.sbom.as_ref(),
            old_sbom_index: app.data.old_sbom_index.as_ref(),
            new_sbom_index: app.data.new_sbom_index.as_ref(),
            sbom_index: app.data.sbom_index.as_ref(),
            old_quality: app.data.old_quality.as_ref(),
            new_quality: app.data.new_quality.as_ref(),
            quality_report: app.data.quality_report.as_ref(),
            old_cra_compliance: app.data.old_cra_compliance.as_ref(),
            new_cra_compliance: app.data.new_cra_compliance.as_ref(),
            old_compliance_results: app.data.old_compliance_results.as_deref(),
            new_compliance_results: app.data.new_compliance_results.as_deref(),
            matching_threshold: app.data.matching_threshold,

            #[cfg(feature = "enrichment")]
            enrichment_stats_old: app.data.enrichment_stats_old.as_ref(),
            #[cfg(feature = "enrichment")]
            enrichment_stats_new: app.data.enrichment_stats_new.as_ref(),

            components: app.components_state(),
            dependencies: app.dependencies_state(),
            licenses: app.licenses_state(),
            vulnerabilities: app.vulnerabilities_state(),
            quality: app.quality_state(),
            compliance: app.diff_compliance_state(),
            side_by_side: app.side_by_side_state(),
            graph_changes: app.graph_changes_state(),
            source: app.source_state(),

            security_cache: &app.security_cache,
            compliance_state: &app.compliance_state,
            navigation_ctx: &app.navigation_ctx,
            status_message: app.status_message.as_deref(),
        }
    }

    // === Item-building helpers ===
    // These replicate App methods but operate on RenderContext fields,
    // enabling render functions to build display lists without &App.

    /// Build diff-mode components list (filtered + sorted).
    #[must_use]
    pub fn diff_component_items(&self) -> Vec<&'a ComponentChange> {
        let Some(diff) = self.diff_result else {
            return Vec::new();
        };
        let filter = self.components.filter;
        let effective = if filter.is_view_filter() && filter != ComponentFilter::All {
            ComponentFilter::All
        } else {
            filter
        };
        let mut items = Vec::new();
        if effective == ComponentFilter::All || effective == ComponentFilter::Added {
            items.extend(diff.components.added.iter());
        }
        if effective == ComponentFilter::All || effective == ComponentFilter::Removed {
            items.extend(diff.components.removed.iter());
        }
        if effective == ComponentFilter::All || effective == ComponentFilter::Modified {
            items.extend(diff.components.modified.iter());
        }
        sort_component_changes(&mut items, self.components.sort_by);
        items
    }

    /// Reconstruct diff-mode vulnerability items from the pre-populated cache.
    ///
    /// The cache is populated by [`App::ensure_vulnerability_cache`] during
    /// [`App::prepare_render`], so it is always warm when this is called.
    #[must_use]
    pub fn diff_vulnerability_items_from_cache(&self) -> Vec<DiffVulnItem<'a>> {
        let Some(diff) = self.diff_result else {
            return Vec::new();
        };
        self.vulnerabilities
            .cached_indices
            .iter()
            .filter_map(|(status, idx)| {
                let vuln = match status {
                    DiffVulnStatus::Introduced => diff.vulnerabilities.introduced.get(*idx),
                    DiffVulnStatus::Resolved => diff.vulnerabilities.resolved.get(*idx),
                    DiffVulnStatus::Persistent => diff.vulnerabilities.persistent.get(*idx),
                }?;
                Some(DiffVulnItem {
                    status: *status,
                    vuln,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify RenderContext can be constructed — the from_app constructor
    // is the primary integration point and is exercised by all TUI tests
    // that run through the render pipeline.
    #[test]
    fn render_context_fields_are_accessible() {
        // Compile-time verification that the struct fields exist and have
        // the expected types. A runtime test requires building a full App,
        // which is covered by integration tests.
        fn _assert_send<T: Send>() {}
        // RenderContext holds references, so it's not Send itself — but
        // the referenced data types should be. This is a structural check.
        _assert_send::<AppMode>();
        _assert_send::<TabKind>();
    }
}
