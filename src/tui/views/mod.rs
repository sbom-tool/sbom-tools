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
pub use licenses::render_licenses;
pub use matrix::{MatrixPanel, render_matrix};
pub use multi_dashboard::{MultiDashboardPanel, render_multi_dashboard};
pub use overlays::{
    ThresholdTuningState, render_component_deep_dive, render_shortcuts_overlay,
    render_threshold_tuning, render_view_switcher,
};
pub use quality::render_quality;
pub use sidebyside::render_sidebyside;
pub use source::render_source;
pub use summary::render_summary;
pub use timeline::{TimelinePanel, render_timeline};
pub use vulnerabilities::render_vulnerabilities;
