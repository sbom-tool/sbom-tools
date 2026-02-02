//! ViewApp - Dedicated TUI for exploring a single SBOM.
//!
//! This module provides a rich, purpose-built interface for SBOM analysis
//! with hierarchical navigation, search, and deep inspection.

mod app;
mod events;
mod ui;
pub mod views;

pub use app::{
    SbomStats, TreeFilter, TreeGroupBy, ViewApp, ViewBreadcrumb, ViewNavigationContext, ViewTab,
};
pub use ui::run_view_tui;
