//! Rich TUI interface using ratatui.
//!
//! This module provides an interactive terminal UI for exploring
//! SBOM diffs and viewing SBOM contents.
//!
//! Two distinct TUI applications are available:
//! - `ViewApp` - For exploring a single SBOM with hierarchical navigation
//! - `App` (`DiffApp`) - For comparing SBOMs and viewing differences
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
pub(crate) mod clipboard;
pub(crate) mod constants;
mod events;
pub(crate) mod export;
pub(crate) mod license_conflicts;
pub(crate) mod license_utils;
pub(crate) mod security;
pub(crate) mod shared;
pub mod state;
pub mod theme;
pub mod traits;
mod ui;
pub mod view;
pub(crate) mod view_states;
pub mod viewmodel;
pub(crate) mod views;
pub(crate) mod widgets;

// Theme exports
pub use theme::{
    ColorScheme, FooterHints, Styles, Theme, colors, current_theme_name, set_theme, toggle_theme,
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
pub use view::{ViewApp, ViewTab, run_view_tui};
