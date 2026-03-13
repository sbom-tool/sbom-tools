//! Concrete `ViewState` implementations.
//!
//! This module contains view state machines that implement the `ViewState`
//! trait from `tui::traits`. Each view handles its own key events and
//! state management independently.
//!
//! The views are wired into the event system via sync bridges in
//! `tui::events`, which delegate event handling to the ViewState impl
//! and handle data-dependent operations that need access to App.

pub mod compliance;
pub mod components;
pub mod dependencies;
pub mod graph_changes;
pub mod licenses;
pub mod quality;
pub mod sidebyside;
pub mod source;
pub mod summary;
pub mod vulnerabilities;

pub use compliance::ComplianceView;
pub use components::ComponentsView;
pub use dependencies::DependenciesView;
pub use graph_changes::GraphChangesView;
pub use licenses::LicensesView;
pub use quality::QualityView;
pub use sidebyside::SideBySideView;
pub use source::SourceView;
pub use vulnerabilities::VulnerabilitiesView;
