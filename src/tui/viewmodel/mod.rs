//! Shared `ViewModel` layer for TUI views.
//!
//! This module provides reusable state management components that can be
//! shared between the diff TUI (`App`) and view TUI (`ViewApp`).
//!
//! # Components
//!
//! - [`SearchState`] - Generic search state with query and results
//! - [`OverlayState`] - Overlay management (help, export, legend)
//! - [`StatusMessage`] - Temporary status message display
//! - [`FilterState`] - Generic filter/toggle state with cycling
//! - [`QualityViewState`] - Quality report display state
//!
//! # Usage
//!
//! Instead of duplicating state structs in each TUI app, embed these
//! shared components:
//!
//! ```ignore
//! use crate::tui::viewmodel::{OverlayState, SearchState, StatusMessage};
//!
//! pub struct MyApp {
//!     // ... other fields ...
//!     pub overlay: OverlayState,
//!     pub search: SearchState<MySearchResult>,
//!     pub status: StatusMessage,
//! }
//! ```
//!
//! # Migration Guide
//!
//! ## `SearchState` Migration
//!
//! Replace `DiffSearchState` or local `SearchState` with:
//! ```ignore
//! // Old: pub search_state: DiffSearchState,
//! // New:
//! pub search_state: SearchState<YourResultType>,
//! ```
//!
//! ## Overlay Migration
//!
//! Replace individual `show_help`, `show_export`, `show_legend` booleans with:
//! ```ignore
//! // Old:
//! // pub show_help: bool,
//! // pub show_export: bool,
//! // pub show_legend: bool,
//!
//! // New:
//! pub overlay: OverlayState,
//!
//! // Update toggle methods:
//! // fn toggle_help(&mut self) { self.overlay.toggle_help(); }
//! ```
//!
//! ## Filter Migration
//!
//! For enum-based filters that cycle through options:
//! ```ignore
//! // Implement CycleFilter for your enum
//! impl CycleFilter for MyFilter { ... }
//!
//! // Then use FilterState
//! pub filter: FilterState<MyFilter>,
//!
//! // Cycle: filter.next() or filter.prev()
//! ```
//!
//! # Backwards Compatibility
//!
//! Existing types in `app.rs` and `view/app.rs` remain functional.
//! These shared types enable incremental migration without breaking changes.

mod filter;
mod overlay;
mod search;
pub mod security_filter;
mod status;

pub use filter::{CycleFilter, FilterState};
pub use overlay::{OverlayKind as ViewModelOverlayKind, OverlayState};
pub use search::{SearchState, SearchStateCore};
pub use security_filter::{
    LicenseCategory, QuickFilter, RiskLevel, SecurityFilterCriteria, SecurityFilterState,
};
pub use status::StatusMessage;

/// Quality view state shared between diff and view modes.
///
/// Provides common state for quality report display including
/// recommendation selection and scroll position.
#[derive(Debug, Clone)]
pub struct QualityViewState {
    /// Current view mode (summary, recommendations, metrics)
    pub view_mode: QualityViewMode,
    /// Selected recommendation index
    pub selected_recommendation: usize,
    /// Total recommendations count
    pub total_recommendations: usize,
    /// Scroll offset for content
    pub scroll_offset: usize,
}

impl Default for QualityViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl QualityViewState {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            view_mode: QualityViewMode::Summary,
            selected_recommendation: 0,
            total_recommendations: 0,
            scroll_offset: 0,
        }
    }

    #[must_use] 
    pub const fn with_recommendations(total: usize) -> Self {
        Self {
            view_mode: QualityViewMode::Summary,
            selected_recommendation: 0,
            total_recommendations: total,
            scroll_offset: 0,
        }
    }

    /// Cycle to the next view mode.
    pub const fn next_mode(&mut self) {
        self.view_mode = match self.view_mode {
            QualityViewMode::Summary => QualityViewMode::Recommendations,
            QualityViewMode::Recommendations => QualityViewMode::Metrics,
            QualityViewMode::Metrics => QualityViewMode::Summary,
        };
    }

    /// Select next recommendation.
    pub const fn select_next(&mut self) {
        if self.selected_recommendation < self.total_recommendations.saturating_sub(1) {
            self.selected_recommendation += 1;
        }
    }

    /// Select previous recommendation.
    pub const fn select_prev(&mut self) {
        if self.selected_recommendation > 0 {
            self.selected_recommendation -= 1;
        }
    }

    /// Go to first recommendation.
    pub const fn go_first(&mut self) {
        self.selected_recommendation = 0;
        self.scroll_offset = 0;
    }

    /// Go to last recommendation.
    pub const fn go_last(&mut self) {
        self.selected_recommendation = self.total_recommendations.saturating_sub(1);
    }

    /// Update total recommendations count.
    pub const fn set_total(&mut self, total: usize) {
        self.total_recommendations = total;
        if self.selected_recommendation >= total {
            self.selected_recommendation = total.saturating_sub(1);
        }
    }
}

/// Quality view modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QualityViewMode {
    #[default]
    Summary,
    Recommendations,
    Metrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_view_state_navigation() {
        let mut state = QualityViewState::with_recommendations(10);

        assert_eq!(state.selected_recommendation, 0);

        state.select_next();
        assert_eq!(state.selected_recommendation, 1);

        state.select_prev();
        assert_eq!(state.selected_recommendation, 0);

        // Can't go below 0
        state.select_prev();
        assert_eq!(state.selected_recommendation, 0);

        // Go to last
        state.go_last();
        assert_eq!(state.selected_recommendation, 9);

        // Can't go past end
        state.select_next();
        assert_eq!(state.selected_recommendation, 9);

        // Go to first
        state.go_first();
        assert_eq!(state.selected_recommendation, 0);
    }

    #[test]
    fn test_quality_view_state_mode_cycling() {
        let mut state = QualityViewState::new();

        assert_eq!(state.view_mode, QualityViewMode::Summary);

        state.next_mode();
        assert_eq!(state.view_mode, QualityViewMode::Recommendations);

        state.next_mode();
        assert_eq!(state.view_mode, QualityViewMode::Metrics);

        state.next_mode();
        assert_eq!(state.view_mode, QualityViewMode::Summary);
    }

    #[test]
    fn test_quality_view_state_set_total() {
        let mut state = QualityViewState::with_recommendations(10);
        state.selected_recommendation = 8;

        // Shrink total - selection should clamp
        state.set_total(5);
        assert_eq!(state.total_recommendations, 5);
        assert_eq!(state.selected_recommendation, 4);

        // Grow total - selection should stay
        state.set_total(20);
        assert_eq!(state.total_recommendations, 20);
        assert_eq!(state.selected_recommendation, 4);
    }
}
