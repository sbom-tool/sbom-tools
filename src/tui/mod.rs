//! Rich TUI interface using ratatui.
//!
//! This module provides an interactive terminal UI for exploring
//! SBOM diffs and viewing SBOM contents.
//!
//! Two distinct TUI applications are available:
//! - `ViewApp` - For exploring a single SBOM with hierarchical navigation
//! - `App` (DiffApp) - For comparing SBOMs and viewing differences
//!
//! # Architecture
//!
//! The TUI follows a state machine pattern with the `ViewState` trait
//! enabling decomposition of the monolithic App into focused, testable views.
//! See `traits` module for the core abstractions.

mod app;
mod app_impl_constructors;
mod app_impl_items;
mod app_impl_nav;
mod app_impl_search;
mod app_states;
mod events;
pub mod export;
pub mod license_conflicts;
pub mod license_utils;
pub mod security;
pub mod state;
pub mod theme;
pub mod traits;
mod ui;
pub mod view;
pub mod viewmodel;
pub mod shared;
pub mod view_states;
pub mod views;
pub mod widgets;

// Theme exports
pub use theme::{
    colors, current_theme_name, set_theme, toggle_theme, ColorScheme, FooterHints, Styles, Theme,
};

// Trait exports for view state machines
pub use traits::{
    EventResult, ListViewState, OverlayKind, Shortcut, TabTarget, ViewContext, ViewMode, ViewState,
};

// Shared state exports
pub use state::{ListNavigation, ListState, TreeNavigation};

// ViewModel exports for shared TUI state management
pub use viewmodel::{
    CycleFilter, FilterState, LicenseCategory, OverlayState, QualityViewMode, QualityViewState,
    QuickFilter, RiskLevel, SearchState, SearchStateCore, SecurityFilterCriteria,
    SecurityFilterState, StatusMessage, ViewModelOverlayKind,
};

// Legacy/Diff TUI exports
pub use app::{App, AppMode, TabKind, TabStates};
pub use events::Event;
pub use ui::run_tui;

// New View TUI exports
pub use view::{run_view_tui, ViewApp, ViewTab};
