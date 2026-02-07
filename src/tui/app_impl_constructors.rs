//! Constructor methods for App.

use crate::diff::{DiffResult, MatrixResult, MultiDiffResult, TimelineResult};
use crate::model::NormalizedSbom;
use crate::quality::{ComplianceChecker, ComplianceLevel, QualityScorer, ScoringProfile};
use ratatui::widgets::ScrollbarState;

use super::app::{App, AppMode, AppOverlays, DataContext, TabKind, TabStates};
use super::app_states::{
    ComponentsState, DependenciesState, GraphChangesState, LicensesState,
    MatrixState, MultiDiffState, NavigationContext, QualityState,
    SideBySideState, SourceDiffState, TimelineState, VulnerabilitiesState,
};

impl App {
    /// Shared default initialization for all mode-independent fields.
    /// Mode-specific fields (mode, `active_tab`, and data fields) must be set by the caller.
    fn base(mode: AppMode, components_len: usize, vulns_len: usize) -> Self {
        Self {
            mode,
            active_tab: TabKind::Summary,
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
            tabs: TabStates {
                components: ComponentsState::new(components_len),
                dependencies: DependenciesState::new(),
                licenses: LicensesState::new(),
                vulnerabilities: VulnerabilitiesState::new(vulns_len),
                quality: QualityState::new(),
                graph_changes: GraphChangesState::new(),
                side_by_side: SideBySideState::new(),
                diff_compliance: crate::tui::app_states::DiffComplianceState::new(),
                multi_diff: MultiDiffState::new(),
                timeline: TimelineState::new(),
                matrix: MatrixState::new(),
                source: SourceDiffState::new("", ""),
            },
            overlays: AppOverlays::new(),
            scroll_state: ScrollbarState::default(),
            should_quit: false,
            status_message: None,
            tick: 0,
            last_export_path: None,
            navigation_ctx: NavigationContext::new(),
            security_cache: crate::tui::security::SecurityAnalysisCache::new(),
            compliance_state: crate::tui::app_states::PolicyComplianceState::new(),
            quality_view: Some(crate::tui::view_states::QualityView::new()),
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
        let components_len = diff_result.components.total();
        let vulns_len = diff_result.vulnerabilities.introduced.len()
            + diff_result.vulnerabilities.resolved.len()
            + diff_result.vulnerabilities.persistent.len();

        // Calculate quality reports for both SBOMs
        let scorer = QualityScorer::new(ScoringProfile::Standard);
        let old_quality = Some(scorer.score(&old_sbom));
        let new_quality = Some(scorer.score(&new_sbom));

        // Compute only CRA Phase2 for the summary card; full compliance is lazy
        let old_cra_compliance = Some(ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&old_sbom));
        let new_cra_compliance = Some(ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&new_sbom));

        // Build indexes for fast lookups (O(1) instead of O(n))
        let old_sbom_index = Some(old_sbom.build_index());
        let new_sbom_index = Some(new_sbom.build_index());

        let mut app = Self::base(AppMode::Diff, components_len, vulns_len);
        app.tabs.source = SourceDiffState::new(old_raw, new_raw);
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
        match (&self.data.enrichment_stats_old, &self.data.enrichment_stats_new) {
            (Some(old), Some(new)) => {
                let mut combined = old.clone();
                combined.merge(new);
                Some(combined)
            }
            (Some(stats), None) | (None, Some(stats)) => Some(stats.clone()),
            (None, None) => None,
        }
    }

    /// Create a new app for view mode
    #[must_use] 
    pub fn new_view(sbom: NormalizedSbom) -> Self {
        let components_len = sbom.component_count();
        let vulns_len = sbom.all_vulnerabilities().len();

        // Calculate quality report
        let scorer = QualityScorer::new(ScoringProfile::Standard);
        let quality_report = Some(scorer.score(&sbom));

        // Build index for fast lookups
        let sbom_index = Some(sbom.build_index());

        let mut app = Self::base(AppMode::View, components_len, vulns_len);
        app.data.sbom = Some(sbom);
        app.data.quality_report = quality_report;
        app.data.sbom_index = sbom_index;
        app
    }

    /// Create a new app for multi-diff mode
    #[must_use] 
    pub fn new_multi_diff(result: MultiDiffResult) -> Self {
        let target_count = result.comparisons.len();

        let mut app = Self::base(AppMode::MultiDiff, 0, 0);
        app.data.multi_diff_result = Some(result);
        app.tabs.multi_diff = MultiDiffState::new_with_targets(target_count);
        app
    }

    /// Create a new app for timeline mode
    #[must_use] 
    pub fn new_timeline(result: TimelineResult) -> Self {
        let version_count = result.sboms.len();

        let mut app = Self::base(AppMode::Timeline, 0, 0);
        app.data.timeline_result = Some(result);
        app.tabs.timeline = TimelineState::new_with_versions(version_count);
        app
    }

    /// Create a new app for matrix mode
    #[must_use] 
    pub fn new_matrix(result: MatrixResult) -> Self {
        let sbom_count = result.sboms.len();

        let mut app = Self::base(AppMode::Matrix, 0, 0);
        app.data.matrix_result = Some(result);
        app.tabs.matrix = MatrixState::new_with_size(sbom_count);
        app
    }
}
