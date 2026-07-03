//! Shared `ViewModel` layer for TUI views.
//!
//! Hosts the security / quick-filter state shared by the diff (`App`) and view
//! (`ViewApp`) TUIs.
//!
//! Earlier generic `SearchState` / `OverlayState` / `FilterState` / `StatusMessage`
//! and a `QualityViewState` were added here for both stacks to adopt, but neither
//! stack ever did (each hand-rolls its own), so that unused scaffolding has been
//! removed. The live quality view state lives in `app_states::quality` (diff) and
//! `view::app` (view).

pub mod security_filter;

pub use security_filter::{
    LicenseCategory, QuickFilter, RiskLevel, SecurityFilterCriteria, SecurityFilterState,
};
