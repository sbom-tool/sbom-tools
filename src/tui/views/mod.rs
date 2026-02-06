//! Tab views for the TUI.

mod components;
mod dependencies;
mod diff_compliance;
mod graph_changes;
pub(crate) mod licenses;
mod matrix;
mod multi_dashboard;
mod overlays;
mod quality;
mod sidebyside;
mod source;
mod summary;
mod timeline;
mod vulnerabilities;

pub(crate) use components::render_components;
pub(crate) use dependencies::render_dependencies;
pub(crate) use diff_compliance::{diff_compliance_violation_count, render_diff_compliance};
pub(crate) use graph_changes::render_graph_changes;
pub(crate) use licenses::render_licenses;
pub(crate) use matrix::{render_matrix, MatrixPanel};
pub(crate) use multi_dashboard::{render_multi_dashboard, MultiDashboardPanel};
pub(crate) use overlays::{
    render_component_deep_dive, render_shortcuts_overlay, render_threshold_tuning,
    render_view_switcher, ThresholdTuningState,
};
pub(crate) use quality::render_quality;
pub(crate) use sidebyside::render_sidebyside;
pub(crate) use source::render_source;
pub(crate) use summary::render_summary;
pub(crate) use timeline::{render_timeline, TimelinePanel};
pub(crate) use vulnerabilities::render_vulnerabilities;
