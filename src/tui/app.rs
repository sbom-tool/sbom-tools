//! Application state for the TUI.

use crate::diff::{DiffResult, MatrixResult, MultiDiffResult, TimelineResult};
#[cfg(feature = "enrichment")]
use crate::enrichment::EnrichmentStats;
use crate::model::{NormalizedSbom, NormalizedSbomIndex};
use crate::quality::{ComplianceResult, QualityReport};
use crate::tui::views::ThresholdTuningState;
use ratatui::widgets::ScrollbarState;

// Re-export state types from app_states module for backwards compatibility
#[allow(unused_imports)]
pub use super::app_states::{
    // Component states
    ComponentFilter, ComponentSort, ComponentsState, sort_component_changes, sort_components,
    // Dependencies state
    DependenciesState,
    // License states
    LicenseGroupBy, LicenseRiskFilter, LicenseSort, LicensesState,
    // Vulnerability states
    DiffVulnItem, DiffVulnStatus, VulnFilter, VulnSort, VulnerabilitiesState,
    // Quality states
    QualityState, QualityViewMode,
    // Graph changes state
    GraphChangesState,
    // Side-by-side states
    AlignmentMode, ChangeTypeFilter, ScrollSyncMode, SideBySideState,
    // Multi-view states
    MultiDiffState, MultiViewFilterPreset, MultiViewSearchState, MultiViewSortBy, SortDirection,
    // Timeline states
    TimelineComponentFilter, TimelineSortBy, TimelineState,
    // Matrix states
    MatrixSortBy, MatrixState, SimilarityThreshold,
    // Search states
    ChangeType, DiffSearchResult, DiffSearchState, VulnChangeType,
    // Navigation states
    Breadcrumb, NavigationContext,
    // View switcher states
    MultiViewType, ViewSwitcherState,
    // Component deep dive states
    ComponentDeepDiveData, ComponentDeepDiveState, ComponentSimilarityInfo,
    ComponentTargetPresence, ComponentVersionEntry, ComponentVulnInfo,
    // Shortcuts overlay states
    ShortcutsContext, ShortcutsOverlayState,
};

/// Per-tab UI state container.
///
/// Groups all tab-specific state structs that were previously
/// flat fields on `App`. Access via `app.tabs.components`, etc.
pub struct TabStates {
    pub components: ComponentsState,
    pub dependencies: DependenciesState,
    pub licenses: LicensesState,
    pub vulnerabilities: VulnerabilitiesState,
    pub quality: QualityState,
    pub graph_changes: GraphChangesState,
    pub side_by_side: SideBySideState,
    pub diff_compliance: crate::tui::app_states::DiffComplianceState,
    pub multi_diff: MultiDiffState,
    pub timeline: TimelineState,
    pub matrix: MatrixState,
    pub source: crate::tui::app_states::SourceDiffState,
}

/// Overlay UI state container.
///
/// Groups all overlay visibility flags and complex overlay states.
pub struct AppOverlays {
    pub show_help: bool,
    pub show_export: bool,
    pub show_legend: bool,
    pub search: DiffSearchState,
    pub threshold_tuning: ThresholdTuningState,
    pub view_switcher: ViewSwitcherState,
    pub shortcuts: ShortcutsOverlayState,
    pub component_deep_dive: ComponentDeepDiveState,
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

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        if self.show_help {
            self.show_export = false;
            self.show_legend = false;
        }
    }

    pub fn toggle_export(&mut self) {
        self.show_export = !self.show_export;
        if self.show_export {
            self.show_help = false;
            self.show_legend = false;
        }
    }

    pub fn toggle_legend(&mut self) {
        self.show_legend = !self.show_legend;
        if self.show_legend {
            self.show_help = false;
            self.show_export = false;
        }
    }

    pub fn close_all(&mut self) {
        self.show_help = false;
        self.show_export = false;
        self.show_legend = false;
        self.search.active = false;
        self.threshold_tuning.visible = false;
    }

    pub fn has_active(&self) -> bool {
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
    pub diff_result: Option<DiffResult>,
    pub old_sbom: Option<NormalizedSbom>,
    pub new_sbom: Option<NormalizedSbom>,
    pub sbom: Option<NormalizedSbom>,
    pub multi_diff_result: Option<MultiDiffResult>,
    pub timeline_result: Option<TimelineResult>,
    pub matrix_result: Option<MatrixResult>,
    pub old_sbom_index: Option<NormalizedSbomIndex>,
    pub new_sbom_index: Option<NormalizedSbomIndex>,
    pub sbom_index: Option<NormalizedSbomIndex>,
    pub old_quality: Option<QualityReport>,
    pub new_quality: Option<QualityReport>,
    pub quality_report: Option<QualityReport>,
    pub old_cra_compliance: Option<ComplianceResult>,
    pub new_cra_compliance: Option<ComplianceResult>,
    pub old_compliance_results: Option<Vec<ComplianceResult>>,
    pub new_compliance_results: Option<Vec<ComplianceResult>>,
    pub matching_threshold: f64,
    #[cfg(feature = "enrichment")]
    pub enrichment_stats_old: Option<EnrichmentStats>,
    #[cfg(feature = "enrichment")]
    pub enrichment_stats_new: Option<EnrichmentStats>,
}

/// Main application state
pub struct App {
    /// Current mode (diff or view)
    pub mode: AppMode,
    /// Active tab
    pub active_tab: TabKind,
    /// SBOM data, diff results, indexes, quality, and compliance
    pub data: DataContext,
    /// Per-tab UI state
    pub tabs: TabStates,
    /// Overlay UI state
    pub overlays: AppOverlays,
    /// Scrollbar state
    pub scroll_state: ScrollbarState,
    /// Should quit
    pub should_quit: bool,
    /// Status message to display temporarily
    pub status_message: Option<String>,
    /// Animation tick counter
    pub tick: u64,
    /// Last exported file path
    pub last_export_path: Option<String>,
    /// Navigation context for cross-view navigation
    pub navigation_ctx: NavigationContext,
    /// Security analysis cache for blast radius, risk indicators, and flagged items
    pub security_cache: crate::tui::security::SecurityAnalysisCache,
    /// Compliance/policy checking state
    pub compliance_state: crate::tui::app_states::PolicyComplianceState,
    /// Quality tab ViewState implementation (proof of concept).
    ///
    /// When present, quality tab key events are dispatched through this
    /// ViewState instead of the direct handler. State is synced back to
    /// `tabs.quality` after each event for rendering compatibility.
    pub quality_view: Option<crate::tui::view_states::QualityView>,
}

impl App {
    /// Lazily compute compliance results for all standards when first needed.
    pub fn ensure_compliance_results(&mut self) {
        if self.data.old_compliance_results.is_none() {
            if let Some(old_sbom) = &self.data.old_sbom {
                self.data.old_compliance_results = Some(
                    crate::quality::ComplianceLevel::all()
                        .iter()
                        .map(|level| crate::quality::ComplianceChecker::new(*level).check(old_sbom))
                        .collect(),
                );
            }
        }
        if self.data.new_compliance_results.is_none() {
            if let Some(new_sbom) = &self.data.new_sbom {
                self.data.new_compliance_results = Some(
                    crate::quality::ComplianceLevel::all()
                        .iter()
                        .map(|level| crate::quality::ComplianceChecker::new(*level).check(new_sbom))
                        .collect(),
                );
            }
        }
    }

    /// Toggle help overlay
    pub fn toggle_help(&mut self) {
        self.overlays.toggle_help();
    }

    /// Toggle export dialog
    pub fn toggle_export(&mut self) {
        self.overlays.toggle_export();
    }

    /// Toggle legend overlay
    pub fn toggle_legend(&mut self) {
        self.overlays.toggle_legend();
    }

    /// Close all overlays
    pub fn close_overlays(&mut self) {
        self.overlays.close_all();
    }

    /// Check if any overlay is open
    pub fn has_overlay(&self) -> bool {
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
                self.data.old_sbom
                    .as_ref()
                    .map(|s| s.component_count())
                    .unwrap_or(0)
                    + self.data
                        .new_sbom
                        .as_ref()
                        .map(|s| s.component_count())
                        .unwrap_or(0)
            }
            AppMode::View => self.data.sbom.as_ref().map(|s| s.component_count()).unwrap_or(0),
            _ => 0,
        };

        // Initialize threshold tuning state
        self.overlays.threshold_tuning = ThresholdTuningState::new(self.data.matching_threshold, total);
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
                1.0 + (base_threshold - threshold) * 2.0
            } else {
                1.0 - (threshold - base_threshold) * 1.5
            };
            ((current_matches as f64 * ratio).max(0.0)) as usize
        } else {
            0
        };

        self.overlays.threshold_tuning.set_estimated_matches(estimated);
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

    /// Clear the status message
    pub fn clear_status_message(&mut self) {
        self.status_message = None;
    }

    /// Export the current diff to a file
    pub fn export(&mut self, format: super::export::ExportFormat) {
        use super::export::{export_diff, export_view};

        let result = match self.mode {
            AppMode::Diff => {
                if let (Some(ref diff_result), Some(ref old_sbom), Some(ref new_sbom)) =
                    (&self.data.diff_result, &self.data.old_sbom, &self.data.new_sbom)
                {
                    export_diff(format, diff_result, old_sbom, new_sbom, None)
                } else {
                    self.set_status_message("No diff data to export");
                    return;
                }
            }
            AppMode::View => {
                if let Some(ref sbom) = self.data.sbom {
                    export_view(format, sbom, None)
                } else {
                    self.set_status_message("No SBOM data to export");
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
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    /// Export compliance results from the active compliance tab
    pub fn export_compliance(&mut self, format: super::export::ExportFormat) {
        use super::export::export_compliance;

        self.ensure_compliance_results();

        // Determine which compliance results and selected standard to use
        let (results, selected) = if let Some(ref results) = self.data.new_compliance_results {
            if !results.is_empty() {
                (results, self.tabs.diff_compliance.selected_standard)
            } else if let Some(ref old_results) = self.data.old_compliance_results {
                if !old_results.is_empty() {
                    (old_results, self.tabs.diff_compliance.selected_standard)
                } else {
                    self.set_status_message("No compliance results to export");
                    return;
                }
            } else {
                self.set_status_message("No compliance results to export");
                return;
            }
        } else if let Some(ref old_results) = self.data.old_compliance_results {
            if !old_results.is_empty() {
                (old_results, self.tabs.diff_compliance.selected_standard)
            } else {
                self.set_status_message("No compliance results to export");
                return;
            }
        } else {
            self.set_status_message("No compliance results to export");
            return;
        };

        let result = export_compliance(format, results, selected, None);
        if result.success {
            self.last_export_path = Some(result.path.display().to_string());
            self.set_status_message(result.message);
        } else {
            self.set_status_message(format!("Export failed: {}", result.message));
        }
    }

    // ========================================================================
    // Compliance / Policy Checking
    // ========================================================================

    /// Run compliance check against the current policy
    pub fn run_compliance_check(&mut self) {
        let preset = self.compliance_state.policy_preset;

        // Standards-based presets delegate to the quality::ComplianceChecker
        if preset.is_standards_based() {
            self.run_standards_compliance_check(preset);
            return;
        }

        use crate::tui::security::{check_compliance, SecurityPolicy};

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
            self.set_status_message(format!(
                "Policy: {} - PASS (score: {})",
                policy.name, score
            ));
        } else {
            self.set_status_message(format!(
                "Policy: {} - FAIL ({} violations, score: {})",
                policy.name, violation_count, score
            ));
        }
    }

    /// Run a standards-based compliance check (CRA, NTIA, FDA) and convert
    /// the result into a PolicyViolation-based ComplianceResult for unified display.
    fn run_standards_compliance_check(&mut self, preset: super::app_states::PolicyPreset) {
        use crate::quality::{ComplianceChecker, ViolationSeverity};
        use crate::tui::security::{ComplianceResult as PolicyResult, PolicySeverity, PolicyViolation};

        let level = match preset.compliance_level() {
            Some(l) => l,
            None => return,
        };

        // Find the SBOM to check (prefer new_sbom in diff mode, sbom in view mode)
        let sbom = match self.mode {
            AppMode::Diff => self.data.new_sbom.as_ref(),
            _ => self.data.sbom.as_ref(),
        };
        let sbom = match sbom {
            Some(s) => s,
            None => {
                self.set_status_message("No SBOM loaded to check");
                return;
            }
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
        let penalty: u32 = violations.iter().map(|v| match v.severity {
            PolicySeverity::High | PolicySeverity::Critical => 10,
            PolicySeverity::Medium => 5,
            PolicySeverity::Low => 1,
        }).sum();
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
            self.set_status_message(format!(
                "{} - COMPLIANT (score: {})",
                policy_name, score
            ));
        } else {
            self.set_status_message(format!(
                "{} - NON-COMPLIANT ({} violations, score: {})",
                policy_name, violation_count, score
            ));
        }
    }

    /// Collect component data for compliance checking
    fn collect_compliance_data(
        &self,
    ) -> Vec<crate::tui::security::ComplianceComponentData> {
        let mut components = Vec::new();

        match self.mode {
            AppMode::Diff => {
                if let Some(sbom) = &self.data.new_sbom {
                    for comp in sbom.components.values() {
                        let licenses: Vec<String> = comp
                            .licenses
                            .declared
                            .iter()
                            .map(|l| l.to_string())
                            .collect();
                        let vulns: Vec<(String, String)> = comp
                            .vulnerabilities
                            .iter()
                            .map(|v| {
                                let severity = v
                                    .severity
                                    .as_ref()
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "Unknown".to_string());
                                (v.id.clone(), severity)
                            })
                            .collect();
                        components.push((
                            comp.name.clone(),
                            comp.version.clone(),
                            licenses,
                            vulns,
                        ));
                    }
                }
            }
            AppMode::View => {
                if let Some(sbom) = &self.data.sbom {
                    for comp in sbom.components.values() {
                        let licenses: Vec<String> = comp
                            .licenses
                            .declared
                            .iter()
                            .map(|l| l.to_string())
                            .collect();
                        let vulns: Vec<(String, String)> = comp
                            .vulnerabilities
                            .iter()
                            .map(|v| {
                                let severity = v
                                    .severity
                                    .as_ref()
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "Unknown".to_string());
                                (v.id.clone(), severity)
                            })
                            .collect();
                        components.push((
                            comp.name.clone(),
                            comp.version.clone(),
                            licenses,
                            vulns,
                        ));
                    }
                }
            }
            _ => {}
        }

        components
    }

    /// Toggle compliance view details
    pub fn toggle_compliance_details(&mut self) {
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

    /// Get the current view mode for ViewContext
    pub fn view_mode(&self) -> super::traits::ViewMode {
        super::traits::ViewMode::from_app_mode(self.mode)
    }

    /// Handle an EventResult from a view state
    ///
    /// This method processes the result of a view's event handling,
    /// performing navigation, showing overlays, or setting status messages.
    pub fn handle_event_result(&mut self, result: super::traits::EventResult) {
        use super::traits::EventResult;

        match result {
            EventResult::Consumed => {
                // Event was handled, nothing else to do
            }
            EventResult::Ignored => {
                // Event was not handled, could try parent handlers
            }
            EventResult::NavigateTo(target) => {
                self.navigate_to_target(target);
            }
            EventResult::Exit => {
                self.should_quit = true;
            }
            EventResult::ShowOverlay(kind) => {
                self.show_overlay_kind(kind);
            }
            EventResult::StatusMessage(msg) => {
                self.set_status_message(msg);
            }
        }
    }

    /// Show an overlay based on the kind
    fn show_overlay_kind(&mut self, kind: super::traits::OverlayKind) {
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

    /// Get the current tab as a TabTarget
    pub fn current_tab_target(&self) -> super::traits::TabTarget {
        super::traits::TabTarget::from_tab_kind(self.active_tab)
    }

    /// Get keyboard shortcuts for the current view
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
}

/// Application mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Comparing two SBOMs
    Diff,
    /// Viewing a single SBOM
    View,
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
    pub fn title(&self) -> &'static str {
        match self {
            TabKind::Summary => "Summary",
            TabKind::Components => "Components",
            TabKind::Dependencies => "Dependencies",
            TabKind::Licenses => "Licenses",
            TabKind::Vulnerabilities => "Vulnerabilities",
            TabKind::Quality => "Quality",
            TabKind::Compliance => "Compliance",
            TabKind::SideBySide => "Side-by-Side",
            TabKind::GraphChanges => "Graph",
            TabKind::Source => "Source",
        }
    }
}
