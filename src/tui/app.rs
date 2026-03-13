//! Application state for the TUI.

use crate::diff::{DiffResult, MatrixResult, MultiDiffResult, TimelineResult};
#[cfg(feature = "enrichment")]
use crate::enrichment::EnrichmentStats;
use crate::model::{NormalizedSbom, NormalizedSbomIndex};
use crate::quality::{ComplianceResult, QualityReport};
use crate::tui::state::ListNavigation;
use crate::tui::views::ThresholdTuningState;

// Re-export state types from app_states module for backwards compatibility
#[allow(unused_imports)]
pub use super::app_states::{
    // Side-by-side states
    AlignmentMode,
    // Navigation states
    Breadcrumb,
    // Search states
    ChangeType,
    ChangeTypeFilter,
    // Component deep dive states
    ComponentDeepDiveData,
    ComponentDeepDiveState,
    // Component states
    ComponentFilter,
    ComponentSimilarityInfo,
    ComponentSort,
    ComponentTargetPresence,
    ComponentVersionEntry,
    ComponentVulnInfo,
    ComponentsState,
    // Dependencies state
    DependenciesState,
    DiffSearchResult,
    DiffSearchState,
    // Vulnerability states
    DiffVulnItem,
    DiffVulnStatus,
    // Graph changes state
    GraphChangesState,
    // License states
    LicenseGroupBy,
    LicenseRiskFilter,
    LicenseSort,
    LicensesState,
    // Matrix states
    MatrixSortBy,
    MatrixState,
    // Multi-view states
    MultiDiffState,
    MultiViewFilterPreset,
    MultiViewSearchState,
    MultiViewSortBy,
    // View switcher states
    MultiViewType,
    NavigationContext,
    // Quality states
    QualityState,
    QualityViewMode,
    ScrollSyncMode,
    // Shortcuts overlay states
    ShortcutsContext,
    ShortcutsOverlayState,
    SideBySideState,
    SimilarityThreshold,
    SortDirection,
    // Timeline states
    TimelineComponentFilter,
    TimelineSortBy,
    TimelineState,
    ViewSwitcherState,
    VulnChangeType,
    VulnFilter,
    VulnSort,
    VulnerabilitiesState,
    sort_component_changes,
};

/// Mode-specific UI state for multi-comparison views.
///
/// Contains state for multi_diff, timeline, and matrix modes only.
/// Per-tab state for standard tabs lives in their respective ViewState impls.
pub struct ModeStates {
    pub(crate) multi_diff: MultiDiffState,
    pub(crate) timeline: TimelineState,
    pub(crate) matrix: MatrixState,
}

/// Overlay UI state container.
///
/// Groups all overlay visibility flags and complex overlay states.
pub struct AppOverlays {
    pub(crate) show_help: bool,
    pub(crate) show_export: bool,
    pub(crate) show_legend: bool,
    pub(crate) search: DiffSearchState,
    pub(crate) threshold_tuning: ThresholdTuningState,
    pub(crate) view_switcher: ViewSwitcherState,
    pub(crate) shortcuts: ShortcutsOverlayState,
    pub(crate) component_deep_dive: ComponentDeepDiveState,
}

impl AppOverlays {
    pub fn new() -> Self {
        Self {
            show_help: false,
            show_export: false,
            show_legend: false,
            search: DiffSearchState::new(),
            threshold_tuning: ThresholdTuningState::default(),
            view_switcher: ViewSwitcherState::new(),
            shortcuts: ShortcutsOverlayState::new(),
            component_deep_dive: ComponentDeepDiveState::new(),
        }
    }

    pub const fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        if self.show_help {
            self.show_export = false;
            self.show_legend = false;
        }
    }

    pub const fn toggle_export(&mut self) {
        self.show_export = !self.show_export;
        if self.show_export {
            self.show_help = false;
            self.show_legend = false;
        }
    }

    pub const fn toggle_legend(&mut self) {
        self.show_legend = !self.show_legend;
        if self.show_legend {
            self.show_help = false;
            self.show_export = false;
        }
    }

    pub const fn close_all(&mut self) {
        self.show_help = false;
        self.show_export = false;
        self.show_legend = false;
        self.search.active = false;
        self.threshold_tuning.visible = false;
    }

    pub const fn has_active(&self) -> bool {
        self.show_help
            || self.show_export
            || self.show_legend
            || self.search.active
            || self.threshold_tuning.visible
    }
}

/// Data context: SBOM data, diff results, indexes, quality, and compliance.
///
/// Groups all immutable-after-construction data that tabs read from.
pub struct DataContext {
    pub(crate) diff_result: Option<DiffResult>,
    pub(crate) old_sbom: Option<NormalizedSbom>,
    pub(crate) new_sbom: Option<NormalizedSbom>,
    pub(crate) sbom: Option<NormalizedSbom>,
    pub(crate) multi_diff_result: Option<MultiDiffResult>,
    pub(crate) timeline_result: Option<TimelineResult>,
    pub(crate) matrix_result: Option<MatrixResult>,
    pub(crate) old_sbom_index: Option<NormalizedSbomIndex>,
    pub(crate) new_sbom_index: Option<NormalizedSbomIndex>,
    pub(crate) sbom_index: Option<NormalizedSbomIndex>,
    pub(crate) old_quality: Option<QualityReport>,
    pub(crate) new_quality: Option<QualityReport>,
    pub(crate) quality_report: Option<QualityReport>,
    pub(crate) old_cra_compliance: Option<ComplianceResult>,
    pub(crate) new_cra_compliance: Option<ComplianceResult>,
    pub(crate) old_compliance_results: Option<Vec<ComplianceResult>>,
    pub(crate) new_compliance_results: Option<Vec<ComplianceResult>>,
    pub(crate) matching_threshold: f64,
    #[cfg(feature = "enrichment")]
    pub(crate) enrichment_stats_old: Option<EnrichmentStats>,
    #[cfg(feature = "enrichment")]
    pub(crate) enrichment_stats_new: Option<EnrichmentStats>,
}

/// Main application state
pub struct App {
    /// Current mode (diff or view)
    pub(crate) mode: AppMode,
    /// Active tab
    pub(crate) active_tab: TabKind,
    /// SBOM data, diff results, indexes, quality, and compliance
    pub(crate) data: DataContext,
    /// Per-tab UI state
    pub(crate) tabs: ModeStates,
    /// Overlay UI state
    pub(crate) overlays: AppOverlays,
    /// Should quit
    pub(crate) should_quit: bool,
    /// Status message to display temporarily
    pub(crate) status_message: Option<String>,
    /// When true, the status message survives one extra keypress before clearing.
    pub(crate) status_sticky: bool,
    /// Animation tick counter
    pub(crate) tick: u64,
    /// Last exported file path
    pub(crate) last_export_path: Option<String>,
    /// Navigation context for cross-view navigation
    pub(crate) navigation_ctx: NavigationContext,
    /// Security analysis cache for blast radius, risk indicators, and flagged items
    pub(crate) security_cache: crate::tui::security::SecurityAnalysisCache,
    /// Compliance/policy checking state
    pub(crate) compliance_state: crate::tui::app_states::PolicyComplianceState,
    /// Optional export filename template (from `--export-template` CLI arg).
    pub(crate) export_template: Option<String>,
    // ========================================================================
    // ViewState implementations
    // ========================================================================
    // Each view handles its own key events via the ViewState trait.
    // State is synced back to `tabs.*` after each event for rendering.
    pub(crate) components_view: Option<crate::tui::view_states::ComponentsView>,
    pub(crate) dependencies_view: Option<crate::tui::view_states::DependenciesView>,
    pub(crate) licenses_view: Option<crate::tui::view_states::LicensesView>,
    pub(crate) vulnerabilities_view: Option<crate::tui::view_states::VulnerabilitiesView>,
    pub(crate) quality_view: Option<crate::tui::view_states::QualityView>,
    pub(crate) compliance_view: Option<crate::tui::view_states::ComplianceView>,
    pub(crate) sidebyside_view: Option<crate::tui::view_states::SideBySideView>,
    pub(crate) graph_changes_view: Option<crate::tui::view_states::GraphChangesView>,
    pub(crate) source_view: Option<crate::tui::view_states::SourceView>,
}

impl App {
    /// Lazily compute compliance results for all standards when first needed.
    pub fn ensure_compliance_results(&mut self) {
        if self.data.old_compliance_results.is_none()
            && let Some(old_sbom) = &self.data.old_sbom
        {
            self.data.old_compliance_results = Some(
                crate::quality::ComplianceLevel::all()
                    .iter()
                    .map(|level| crate::quality::ComplianceChecker::new(*level).check(old_sbom))
                    .collect(),
            );
        }
        if self.data.new_compliance_results.is_none()
            && let Some(new_sbom) = &self.data.new_sbom
        {
            self.data.new_compliance_results = Some(
                crate::quality::ComplianceLevel::all()
                    .iter()
                    .map(|level| crate::quality::ComplianceChecker::new(*level).check(new_sbom))
                    .collect(),
            );
        }
    }

    /// Toggle help overlay
    pub const fn toggle_help(&mut self) {
        self.overlays.toggle_help();
    }

    /// Toggle export dialog
    pub const fn toggle_export(&mut self) {
        self.overlays.toggle_export();
    }

    /// Toggle legend overlay
    pub const fn toggle_legend(&mut self) {
        self.overlays.toggle_legend();
    }

    /// Close all overlays
    pub const fn close_overlays(&mut self) {
        self.overlays.close_all();
    }

    /// Check if any overlay is open
    #[must_use]
    pub const fn has_overlay(&self) -> bool {
        self.overlays.has_active()
    }

    /// Toggle threshold tuning overlay
    pub fn toggle_threshold_tuning(&mut self) {
        if self.overlays.threshold_tuning.visible {
            self.overlays.threshold_tuning.visible = false;
        } else {
            self.show_threshold_tuning();
        }
    }

    /// Show threshold tuning overlay and compute initial estimated matches
    pub fn show_threshold_tuning(&mut self) {
        // Close other overlays
        self.overlays.close_all();

        // Get total components count
        let total = match self.mode {
            AppMode::Diff => {
                self.data
                    .old_sbom
                    .as_ref()
                    .map_or(0, crate::model::NormalizedSbom::component_count)
                    + self
                        .data
                        .new_sbom
                        .as_ref()
                        .map_or(0, crate::model::NormalizedSbom::component_count)
            }
            _ => 0,
        };

        // Initialize threshold tuning state
        self.overlays.threshold_tuning =
            ThresholdTuningState::new(self.data.matching_threshold, total);
        self.update_threshold_preview();
    }

    /// Update the estimated matches preview based on current threshold
    pub fn update_threshold_preview(&mut self) {
        if !self.overlays.threshold_tuning.visible {
            return;
        }

        // Estimate matches at current threshold
        // For now, use a simple heuristic based on the diff result
        let estimated = if let Some(ref result) = self.data.diff_result {
            // Count modified components (matches) and estimate how threshold changes would affect
            let current_matches = result.components.modified.len();
            let threshold = self.overlays.threshold_tuning.threshold;
            let base_threshold = self.data.matching_threshold;

            // Simple estimation: lower threshold = more matches, higher = fewer
            let ratio = if threshold < base_threshold {
                (base_threshold - threshold).mul_add(2.0, 1.0)
            } else {
                (threshold - base_threshold).mul_add(-1.5, 1.0)
            };
            ((current_matches as f64 * ratio).max(0.0)) as usize
        } else {
            0
        };

        self.overlays
            .threshold_tuning
            .set_estimated_matches(estimated);
    }

    /// Apply the tuned threshold and potentially re-diff
    pub fn apply_threshold(&mut self) {
        self.data.matching_threshold = self.overlays.threshold_tuning.threshold;
        self.overlays.threshold_tuning.visible = false;
        self.set_status_message(format!(
            "Threshold set to {:.0}% - Re-run diff to apply",
            self.data.matching_threshold * 100.0
        ));
    }

    /// Set a temporary status message
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    /// Clear the status message.
    ///
    /// If `status_sticky` is set the message is kept for one extra keypress,
    /// then cleared on the subsequent call.
    pub fn clear_status_message(&mut self) {
        if self.status_sticky {
            self.status_sticky = false;
        } else {
            self.status_message = None;
        }
    }

    /// Export the current diff to a file.
    ///
    /// The export is scoped to the active tab: e.g. if the user is on the
    /// Vulnerabilities tab only vulnerability data is included.
    pub fn export(&mut self, format: super::export::ExportFormat) {
        use super::export::{export_diff, tab_to_report_type};
        use crate::reports::ReportConfig;

        let report_type = tab_to_report_type(self.active_tab);
        let config = ReportConfig::with_types(vec![report_type]);

        let result = match self.mode {
            AppMode::Diff => {
                if let (Some(diff_result), Some(old_sbom), Some(new_sbom)) = (
                    &self.data.diff_result,
                    &self.data.old_sbom,
                    &self.data.new_sbom,
                ) {
                    export_diff(
                        format,
                        diff_result,
                        old_sbom,
                        new_sbom,
                        None,
                        &config,
                        self.export_template.as_deref(),
                    )
                } else {
                    self.set_status_message("No diff data to export");
                    return;
                }
            }
            _ => {
                self.set_status_message("Export not supported for this mode");
                return;
            }
        };

        if result.success {
            self.last_export_path = Some(result.path.display().to_string());
            self.set_status_message(result.message);
            self.status_sticky = true;
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    /// Export compliance results from the active compliance tab
    pub fn export_compliance(&mut self, format: super::export::ExportFormat) {
        use super::export::export_compliance;

        self.ensure_compliance_results();

        // Determine which compliance results and selected standard to use
        let selected_standard = self.diff_compliance_state().selected_standard;
        let (results, selected) = if let Some(ref results) = self.data.new_compliance_results {
            if !results.is_empty() {
                (results, selected_standard)
            } else if let Some(ref old_results) = self.data.old_compliance_results {
                if old_results.is_empty() {
                    self.set_status_message("No compliance results to export");
                    return;
                }
                (old_results, selected_standard)
            } else {
                self.set_status_message("No compliance results to export");
                return;
            }
        } else if let Some(ref old_results) = self.data.old_compliance_results {
            if old_results.is_empty() {
                self.set_status_message("No compliance results to export");
                return;
            }
            (old_results, selected_standard)
        } else {
            self.set_status_message("No compliance results to export");
            return;
        };

        let result = export_compliance(
            format,
            results,
            selected,
            None,
            self.export_template.as_deref(),
        );
        if result.success {
            self.last_export_path = Some(result.path.display().to_string());
            self.set_status_message(result.message);
            self.status_sticky = true;
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    /// Export matrix results to a file
    pub fn export_matrix(&mut self, format: super::export::ExportFormat) {
        use super::export::export_matrix;

        let Some(ref matrix_result) = self.data.matrix_result else {
            self.set_status_message("No matrix data to export");
            return;
        };

        let result = export_matrix(format, matrix_result, self.export_template.as_deref());
        if result.success {
            self.last_export_path = Some(result.path.display().to_string());
            self.set_status_message(result.message);
            self.status_sticky = true;
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    // ========================================================================
    // Compliance / Policy Checking
    // ========================================================================

    /// Run compliance check against the current policy
    pub fn run_compliance_check(&mut self) {
        use crate::tui::security::{SecurityPolicy, check_compliance};

        let preset = self.compliance_state.policy_preset;

        // Standards-based presets delegate to the quality::ComplianceChecker
        if preset.is_standards_based() {
            self.run_standards_compliance_check(preset);
            return;
        }

        let policy = match preset {
            super::app_states::PolicyPreset::Enterprise => SecurityPolicy::enterprise_default(),
            super::app_states::PolicyPreset::Strict => SecurityPolicy::strict(),
            super::app_states::PolicyPreset::Permissive => SecurityPolicy::permissive(),
            // Standards-based presets handled above
            _ => unreachable!(),
        };

        // Collect component data for compliance checking
        let components = self.collect_compliance_data();

        if components.is_empty() {
            self.set_status_message("No components to check");
            return;
        }

        let result = check_compliance(&policy, &components);
        let passes = result.passes;
        let score = result.score;
        let violation_count = result.violations.len();

        self.compliance_state.result = Some(result);
        self.compliance_state.checked = true;
        self.compliance_state.selected_violation = 0;

        if passes {
            self.set_status_message(format!("Policy: {} - PASS (score: {})", policy.name, score));
        } else {
            self.set_status_message(format!(
                "Policy: {} - FAIL ({} violations, score: {})",
                policy.name, violation_count, score
            ));
        }
    }

    /// Run a standards-based compliance check (CRA, NTIA, FDA) and convert
    /// the result into a PolicyViolation-based `ComplianceResult` for unified display.
    fn run_standards_compliance_check(&mut self, preset: super::app_states::PolicyPreset) {
        use crate::quality::{ComplianceChecker, ViolationSeverity};
        use crate::tui::security::{
            ComplianceResult as PolicyResult, PolicySeverity, PolicyViolation,
        };

        let Some(level) = preset.compliance_level() else {
            return;
        };

        // Find the SBOM to check (prefer new_sbom in diff mode, sbom in view mode)
        let sbom = match self.mode {
            AppMode::Diff => self.data.new_sbom.as_ref(),
            _ => self.data.sbom.as_ref(),
        };
        let Some(sbom) = sbom else {
            self.set_status_message("No SBOM loaded to check");
            return;
        };

        let checker = ComplianceChecker::new(level);
        let std_result = checker.check(sbom);

        // Convert quality::Violation → PolicyViolation
        let violations: Vec<PolicyViolation> = std_result
            .violations
            .iter()
            .map(|v| {
                let severity = match v.severity {
                    ViolationSeverity::Error => PolicySeverity::High,
                    ViolationSeverity::Warning => PolicySeverity::Medium,
                    ViolationSeverity::Info => PolicySeverity::Low,
                };
                PolicyViolation {
                    rule_name: v.requirement.clone(),
                    severity,
                    component: v.element.clone(),
                    description: v.message.clone(),
                    remediation: v.remediation_guidance().to_string(),
                }
            })
            .collect();

        // Calculate score: errors weigh 10pts, warnings 5pts, info 1pt
        let penalty: u32 = violations
            .iter()
            .map(|v| match v.severity {
                PolicySeverity::High | PolicySeverity::Critical => 10,
                PolicySeverity::Medium => 5,
                PolicySeverity::Low => 1,
            })
            .sum();
        let score = 100u8.saturating_sub(penalty.min(100) as u8);

        let passes = std_result.is_compliant;
        let policy_name = format!("{} Compliance", preset.label());
        let violation_count = violations.len();

        let result = PolicyResult {
            policy_name: policy_name.clone(),
            components_checked: sbom.components.len(),
            violations,
            score,
            passes,
        };

        self.compliance_state.result = Some(result);
        self.compliance_state.checked = true;
        self.compliance_state.selected_violation = 0;

        if passes {
            self.set_status_message(format!("{policy_name} - COMPLIANT (score: {score})"));
        } else {
            self.set_status_message(format!(
                "{policy_name} - NON-COMPLIANT ({violation_count} violations, score: {score})"
            ));
        }
    }

    /// Collect component data for compliance checking
    fn collect_compliance_data(&self) -> Vec<crate::tui::security::ComplianceComponentData> {
        let mut components = Vec::new();

        if self.mode == AppMode::Diff {
            if let Some(sbom) = &self.data.new_sbom {
                for comp in sbom.components.values() {
                    let licenses: Vec<String> = comp
                        .licenses
                        .declared
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    let vulns: Vec<(String, String)> = comp
                        .vulnerabilities
                        .iter()
                        .map(|v| {
                            let severity = v.severity.as_ref().map_or_else(
                                || "Unknown".to_string(),
                                std::string::ToString::to_string,
                            );
                            (v.id.clone(), severity)
                        })
                        .collect();
                    components.push((comp.name.clone(), comp.version.clone(), licenses, vulns));
                }
            }
        }

        components
    }

    /// Toggle compliance view details
    pub const fn toggle_compliance_details(&mut self) {
        self.compliance_state.toggle_details();
    }

    /// Cycle to next policy preset
    pub fn next_policy(&mut self) {
        self.compliance_state.toggle_policy();
        // Re-run check with new policy if already checked
        if self.compliance_state.checked {
            self.run_compliance_check();
        }
    }

    // ========================================================================
    // ViewState trait integration methods
    // ========================================================================

    /// Get the current view mode for `ViewContext`
    #[must_use]
    pub const fn view_mode(&self) -> super::traits::ViewMode {
        super::traits::ViewMode::from_app_mode(self.mode)
    }

    /// Handle an `EventResult` from a view state
    ///
    /// This method processes the result of a view's event handling,
    /// performing navigation, showing overlays, or setting status messages.
    pub fn handle_event_result(&mut self, result: super::traits::EventResult) {
        use super::traits::EventResult;

        match result {
            EventResult::Consumed | EventResult::Ignored => {
                // Event was handled, or not handled -- nothing else to do
            }
            EventResult::NavigateTo(target) => {
                self.navigate_to_target(target);
            }
            EventResult::Exit => {
                self.should_quit = true;
            }
            EventResult::ShowOverlay(kind) => {
                self.show_overlay_kind(&kind);
            }
            EventResult::StatusMessage(msg) => {
                self.set_status_message(msg);
            }
        }
    }

    /// Show an overlay based on the kind
    fn show_overlay_kind(&mut self, kind: &super::traits::OverlayKind) {
        use super::traits::OverlayKind;

        // Close any existing overlays first
        self.overlays.close_all();

        match kind {
            OverlayKind::Help => self.overlays.show_help = true,
            OverlayKind::Export => self.overlays.show_export = true,
            OverlayKind::Legend => self.overlays.show_legend = true,
            OverlayKind::Search => {
                self.overlays.search.active = true;
                self.overlays.search.query.clear();
            }
            OverlayKind::Shortcuts => self.overlays.shortcuts.visible = true,
        }
    }

    /// Get the current tab as a `TabTarget`
    #[must_use]
    pub const fn current_tab_target(&self) -> super::traits::TabTarget {
        super::traits::TabTarget::from_tab_kind(self.active_tab)
    }

    /// Get keyboard shortcuts for the current view
    #[must_use]
    pub fn current_shortcuts(&self) -> Vec<super::traits::Shortcut> {
        use super::traits::Shortcut;

        let mut shortcuts = vec![
            Shortcut::primary("?", "Help"),
            Shortcut::primary("q", "Quit"),
            Shortcut::primary("Tab", "Next tab"),
            Shortcut::primary("/", "Search"),
        ];

        // Add view-specific shortcuts
        match self.active_tab {
            TabKind::Components => {
                shortcuts.push(Shortcut::new("f", "Filter"));
                shortcuts.push(Shortcut::new("s", "Sort"));
                shortcuts.push(Shortcut::new("m", "Multi-select"));
            }
            TabKind::Dependencies => {
                shortcuts.push(Shortcut::new("t", "Transitive"));
                shortcuts.push(Shortcut::new("+/-", "Depth"));
            }
            TabKind::Vulnerabilities => {
                shortcuts.push(Shortcut::new("f", "Filter"));
                shortcuts.push(Shortcut::new("s", "Sort"));
            }
            TabKind::Quality => {
                shortcuts.push(Shortcut::new("v", "View mode"));
            }
            _ => {}
        }

        shortcuts
    }

    // ========================================================================
    // ViewState inner state accessors
    // ========================================================================

    pub(crate) fn quality_state(&self) -> &super::app_states::QualityState {
        self.quality_view.as_ref().expect("quality_view").inner()
    }
    pub(crate) fn quality_state_mut(&mut self) -> &mut super::app_states::QualityState {
        self.quality_view
            .as_mut()
            .expect("quality_view")
            .inner_mut()
    }

    pub(crate) fn graph_changes_state(&self) -> &super::app_states::GraphChangesState {
        self.graph_changes_view
            .as_ref()
            .expect("graph_changes_view")
            .inner()
    }
    pub(crate) fn graph_changes_state_mut(&mut self) -> &mut super::app_states::GraphChangesState {
        self.graph_changes_view
            .as_mut()
            .expect("graph_changes_view")
            .inner_mut()
    }

    pub(crate) fn licenses_state(&self) -> &super::app_states::LicensesState {
        self.licenses_view.as_ref().expect("licenses_view").inner()
    }
    pub(crate) fn licenses_state_mut(&mut self) -> &mut super::app_states::LicensesState {
        self.licenses_view
            .as_mut()
            .expect("licenses_view")
            .inner_mut()
    }

    pub(crate) fn diff_compliance_state(&self) -> &super::app_states::DiffComplianceState {
        self.compliance_view
            .as_ref()
            .expect("compliance_view")
            .inner()
    }
    pub(crate) fn components_state(&self) -> &ComponentsState {
        self.components_view
            .as_ref()
            .expect("components_view")
            .inner()
    }
    pub(crate) fn components_state_mut(&mut self) -> &mut ComponentsState {
        self.components_view
            .as_mut()
            .expect("components_view")
            .inner_mut()
    }

    pub(crate) fn vulnerabilities_state(&self) -> &super::app_states::VulnerabilitiesState {
        self.vulnerabilities_view
            .as_ref()
            .expect("vulnerabilities_view")
            .inner()
    }
    pub(crate) fn vulnerabilities_state_mut(
        &mut self,
    ) -> &mut super::app_states::VulnerabilitiesState {
        self.vulnerabilities_view
            .as_mut()
            .expect("vulnerabilities_view")
            .inner_mut()
    }

    pub(crate) fn side_by_side_state(&self) -> &super::app_states::SideBySideState {
        self.sidebyside_view
            .as_ref()
            .expect("sidebyside_view")
            .inner()
    }
    pub(crate) fn side_by_side_state_mut(&mut self) -> &mut super::app_states::SideBySideState {
        self.sidebyside_view
            .as_mut()
            .expect("sidebyside_view")
            .inner_mut()
    }

    pub(crate) fn dependencies_state(&self) -> &DependenciesState {
        self.dependencies_view
            .as_ref()
            .expect("dependencies_view")
            .inner()
    }
    pub(crate) fn dependencies_state_mut(&mut self) -> &mut DependenciesState {
        self.dependencies_view
            .as_mut()
            .expect("dependencies_view")
            .inner_mut()
    }

    pub(crate) fn source_state(&self) -> &crate::tui::app_states::SourceDiffState {
        self.source_view.as_ref().expect("source_view").inner()
    }
    pub(crate) fn source_state_mut(&mut self) -> &mut crate::tui::app_states::SourceDiffState {
        self.source_view.as_mut().expect("source_view").inner_mut()
    }

    // ========================================================================
    // Pre-render preparation
    // ========================================================================

    /// Prepare mutable state that render functions previously computed inline.
    ///
    /// Call this once per frame, **before** creating a [`RenderContext`].
    /// After this method returns, all render functions can operate on `&App`
    /// (read-only) instead of `&mut App`.
    ///
    /// [`RenderContext`]: super::render_context::RenderContext
    pub fn prepare_render(&mut self) {
        // 1. Graph cache for dependencies (was inline in render_dependencies)
        super::views::update_graph_cache(
            self.dependencies_view
                .as_mut()
                .expect("dependencies_view")
                .inner_mut(),
            &self.data,
            self.mode,
        );

        // 2. Compliance results (was inline in render_diff_compliance)
        self.ensure_compliance_results();

        // 3. Vulnerability cache (was inline in render_vulnerabilities)
        if self.mode == AppMode::Diff {
            self.ensure_vulnerability_cache();
        }

        // 4. Component totals (was inline in render_components)
        let comp_filter = self.components_state().filter;
        let comp_total = match self.mode {
            AppMode::Diff => self.diff_component_count(comp_filter),
            AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
        };
        self.components_state_mut().total = comp_total;
        self.components_state_mut().clamp_selection();

        // 5. Vulnerability totals (was inline in render_vulnerabilities)
        self.prepare_vulnerability_totals();

        // 6. Graph changes total (was inline in render_graph_changes)
        let graph_total = self
            .data
            .diff_result
            .as_ref()
            .map_or(0, |r| r.graph_changes.len());
        self.graph_changes_state_mut().set_total(graph_total);

        // 7. Dependencies breadcrumbs (was inline in render_dependencies)
        self.dependencies_state_mut().update_breadcrumbs();

        // 8. License totals (was inline in render_licenses)
        self.prepare_license_totals();

        // 9. Side-by-side totals (was inline in render_sidebyside)
        // Totals are set by set_totals in the render function, which is now
        // hoisted here using cached aligned rows or diff data.
        if self.mode == AppMode::Diff {
            if let Some(ref result) = self.data.diff_result {
                let left = result.components.removed.len() + result.components.modified.len();
                let right = result.components.added.len() + result.components.modified.len();
                self.side_by_side_state_mut().set_totals(left, right);
            }
        }
    }

    /// Pre-compute license totals for rendering.
    fn prepare_license_totals(&mut self) {
        match self.mode {
            AppMode::Diff => {
                if let Some(ref result) = self.data.diff_result {
                    let focus_left = self.licenses_state().focus_left;
                    let risk_filter = self.licenses_state().risk_filter;
                    let count = if focus_left {
                        Self::filtered_license_count(&result.licenses.new_licenses, risk_filter)
                    } else {
                        Self::filtered_license_count(&result.licenses.removed_licenses, risk_filter)
                    };
                    self.licenses_state_mut().total = count;
                }
            }
            AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {
                self.licenses_state_mut().total = 0;
            }
        }
        self.licenses_state_mut().clamp_selection();
    }

    /// Count licenses after applying risk filter.
    fn filtered_license_count(
        licenses: &[crate::diff::LicenseChange],
        risk_filter: Option<crate::tui::app_states::LicenseRiskFilter>,
    ) -> usize {
        use crate::tui::license_utils::{LicenseInfo, RiskLevel};
        if let Some(min_risk) = risk_filter {
            let min_level = match min_risk {
                crate::tui::app_states::LicenseRiskFilter::Low => RiskLevel::Low,
                crate::tui::app_states::LicenseRiskFilter::Medium => RiskLevel::Medium,
                crate::tui::app_states::LicenseRiskFilter::High => RiskLevel::High,
                crate::tui::app_states::LicenseRiskFilter::Critical => RiskLevel::Critical,
            };
            licenses
                .iter()
                .filter(|l| LicenseInfo::from_spdx(&l.license).risk_level >= min_level)
                .count()
        } else {
            licenses.len()
        }
    }

    /// Pre-compute vulnerability totals for rendering.
    fn prepare_vulnerability_totals(&mut self) {
        let vuln_total = match self.mode {
            AppMode::Diff => self.diff_vulnerability_count(),
            AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
        };
        self.vulnerabilities_state_mut().total = vuln_total;
        self.vulnerabilities_state_mut().clamp_selection();

        // Grouped mode adjusts total to match visible render items
        if self.vulnerabilities_state().group_by_component {
            let grouped_count = super::views::count_grouped_items(self);
            self.vulnerabilities_state_mut().total = grouped_count;
            self.vulnerabilities_state_mut().clamp_selection();
        }
    }
}

/// Application mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Comparing two SBOMs
    Diff,
    /// 1:N multi-diff comparison
    MultiDiff,
    /// Timeline analysis
    Timeline,
    /// N×N matrix comparison
    Matrix,
}

/// Tab kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKind {
    Summary,
    Components,
    Dependencies,
    Licenses,
    Vulnerabilities,
    Quality,
    Compliance,
    SideBySide,
    GraphChanges,
    Source,
}

impl TabKind {
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Components => "Components",
            Self::Dependencies => "Dependencies",
            Self::Licenses => "Licenses",
            Self::Vulnerabilities => "Vulnerabilities",
            Self::Quality => "Quality",
            Self::Compliance => "Compliance",
            Self::SideBySide => "Side-by-Side",
            Self::GraphChanges => "Graph",
            Self::Source => "Source",
        }
    }

    /// Stable string identifier for persistence.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Components => "components",
            Self::Dependencies => "dependencies",
            Self::Licenses => "licenses",
            Self::Vulnerabilities => "vulnerabilities",
            Self::Quality => "quality",
            Self::Compliance => "compliance",
            Self::SideBySide => "side-by-side",
            Self::GraphChanges => "graph",
            Self::Source => "source",
        }
    }

    /// Parse from a persisted string identifier.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "summary" => Some(Self::Summary),
            "components" => Some(Self::Components),
            "dependencies" => Some(Self::Dependencies),
            "licenses" => Some(Self::Licenses),
            "vulnerabilities" => Some(Self::Vulnerabilities),
            "quality" => Some(Self::Quality),
            "compliance" => Some(Self::Compliance),
            "side-by-side" => Some(Self::SideBySide),
            "graph" => Some(Self::GraphChanges),
            "source" => Some(Self::Source),
            _ => None,
        }
    }
}
