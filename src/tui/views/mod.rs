//! Tab views for the TUI.

mod components;
mod dependencies;
mod diff_compliance;
mod graph_changes;
pub mod licenses;
mod matrix;
mod multi_dashboard;
mod overlays;
mod quality;
mod sidebyside;
mod source;
mod summary;
mod timeline;
mod vulnerabilities;

pub use components::render_components;
pub use dependencies::render_dependencies;
pub use diff_compliance::{diff_compliance_violation_count, render_diff_compliance};
pub use graph_changes::render_graph_changes;
pub use licenses::{categorize_license, get_license_characteristics, render_licenses};
pub use matrix::{render_matrix, MatrixPanel};
pub use multi_dashboard::{render_multi_dashboard, MultiDashboardPanel};
pub use overlays::{
    render_breadcrumbs, render_component_deep_dive, render_shortcuts_overlay,
    render_threshold_tuning, render_view_switcher, ThresholdTuningState,
};
pub use quality::render_quality;
pub use sidebyside::render_sidebyside;
pub use source::render_source;
pub use summary::render_summary;
pub use timeline::{render_timeline, TimelinePanel};
pub use vulnerabilities::render_vulnerabilities;
