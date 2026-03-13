//! Constructor methods for App.

use super::app::{App, AppMode, AppOverlays, DataContext, ModeStates, TabKind};
use super::app_states::{
    MatrixState, MultiDiffState, NavigationContext, SourceDiffState, TimelineState,
};
use crate::diff::{DiffResult, MatrixResult, MultiDiffResult, TimelineResult};
use crate::model::NormalizedSbom;
use crate::quality::{ComplianceChecker, ComplianceLevel, QualityScorer, ScoringProfile};

impl App {
    /// Shared default initialization for all mode-independent fields.
    /// Mode-specific fields (mode, `active_tab`, and data fields) must be set by the caller.
    fn base(mode: AppMode) -> Self {
        Self {
            mode,
            active_tab: crate::config::TuiPreferences::load()
                .last_tab
                .as_deref()
                .and_then(TabKind::from_str_opt)
                .unwrap_or(TabKind::Summary),
            data: DataContext {
                diff_result: None,
                old_sbom: None,
                new_sbom: None,
                sbom: None,
                multi_diff_result: None,
                timeline_result: None,
                matrix_result: None,
                old_sbom_index: None,
                new_sbom_index: None,
                sbom_index: None,
                old_quality: None,
                new_quality: None,
                quality_report: None,
                old_cra_compliance: None,
                new_cra_compliance: None,
                old_compliance_results: None,
                new_compliance_results: None,
                matching_threshold: 0.85,
                #[cfg(feature = "enrichment")]
                enrichment_stats_old: None,
                #[cfg(feature = "enrichment")]
                enrichment_stats_new: None,
            },
            tabs: ModeStates {
                multi_diff: MultiDiffState::new(),
                timeline: TimelineState::new(),
                matrix: MatrixState::new(),
            },
            overlays: AppOverlays::new(),
            should_quit: false,
            status_message: None,
            status_sticky: false,
            tick: 0,
            last_export_path: None,
            navigation_ctx: NavigationContext::new(),
            security_cache: crate::tui::security::SecurityAnalysisCache::new(),
            compliance_state: crate::tui::app_states::PolicyComplianceState::new(),
            export_template: None,
            components_view: Some(crate::tui::view_states::ComponentsView::new()),
            dependencies_view: Some(crate::tui::view_states::DependenciesView::new()),
            licenses_view: Some(crate::tui::view_states::LicensesView::new()),
            vulnerabilities_view: Some(crate::tui::view_states::VulnerabilitiesView::new()),
            quality_view: Some(crate::tui::view_states::QualityView::new()),
            compliance_view: Some(crate::tui::view_states::ComplianceView::new()),
            sidebyside_view: Some(crate::tui::view_states::SideBySideView::new()),
            graph_changes_view: Some(crate::tui::view_states::GraphChangesView::new()),
            source_view: Some(crate::tui::view_states::SourceView::new()),
        }
    }

    /// Create a new app for diff mode
    #[must_use]
    pub fn new_diff(
        diff_result: DiffResult,
        old_sbom: NormalizedSbom,
        new_sbom: NormalizedSbom,
        old_raw: &str,
        new_raw: &str,
    ) -> Self {
        // Calculate quality reports for both SBOMs
        let scorer = QualityScorer::new(ScoringProfile::Standard);
        let old_quality = Some(scorer.score(&old_sbom));
        let new_quality = Some(scorer.score(&new_sbom));

        // Compute only CRA Phase2 for the summary card; full compliance is lazy
        let old_cra_compliance =
            Some(ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&old_sbom));
        let new_cra_compliance =
            Some(ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&new_sbom));

        // Build indexes for fast lookups (O(1) instead of O(n))
        let old_sbom_index = Some(old_sbom.build_index());
        let new_sbom_index = Some(new_sbom.build_index());

        let mut app = Self::base(AppMode::Diff);
        let mut source = SourceDiffState::new(old_raw, new_raw);
        source.populate_annotations(&diff_result);
        app.source_view = Some(crate::tui::view_states::SourceView::with_state(source));
        app.data.diff_result = Some(diff_result);
        app.data.old_sbom = Some(old_sbom);
        app.data.new_sbom = Some(new_sbom);
        app.data.old_quality = old_quality;
        app.data.new_quality = new_quality;
        app.data.old_cra_compliance = old_cra_compliance;
        app.data.new_cra_compliance = new_cra_compliance;
        app.data.old_sbom_index = old_sbom_index;
        app.data.new_sbom_index = new_sbom_index;
        app
    }

    /// Set enrichment statistics for the diff mode
    #[must_use]
    #[cfg(feature = "enrichment")]
    pub fn with_enrichment_stats(
        mut self,
        old_stats: Option<crate::enrichment::EnrichmentStats>,
        new_stats: Option<crate::enrichment::EnrichmentStats>,
    ) -> Self {
        self.data.enrichment_stats_old = old_stats;
        self.data.enrichment_stats_new = new_stats;
        self
    }

    /// Get combined enrichment stats for display
    #[cfg(feature = "enrichment")]
    #[must_use]
    pub fn combined_enrichment_stats(&self) -> Option<crate::enrichment::EnrichmentStats> {
        match (
            &self.data.enrichment_stats_old,
            &self.data.enrichment_stats_new,
        ) {
            (Some(old), Some(new)) => {
                let mut combined = old.clone();
                combined.merge(new);
                Some(combined)
            }
            (Some(stats), None) | (None, Some(stats)) => Some(stats.clone()),
            (None, None) => None,
        }
    }

    /// Create a new app for multi-diff mode
    #[must_use]
    pub fn new_multi_diff(result: MultiDiffResult) -> Self {
        let target_count = result.comparisons.len();

        let mut app = Self::base(AppMode::MultiDiff);
        app.data.multi_diff_result = Some(result);
        app.tabs.multi_diff = MultiDiffState::new_with_targets(target_count);
        app
    }

    /// Create a new app for timeline mode
    #[must_use]
    pub fn new_timeline(result: TimelineResult) -> Self {
        let version_count = result.sboms.len();

        let mut app = Self::base(AppMode::Timeline);
        app.data.timeline_result = Some(result);
        app.tabs.timeline = TimelineState::new_with_versions(version_count);
        app
    }

    /// Create a new app for matrix mode
    #[must_use]
    pub fn new_matrix(result: MatrixResult) -> Self {
        let sbom_count = result.sboms.len();

        let mut app = Self::base(AppMode::Matrix);
        app.data.matrix_result = Some(result);
        app.tabs.matrix = MatrixState::new_with_size(sbom_count);
        app
    }
}
