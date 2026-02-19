//! Application state types for the TUI.
//!
//! This module contains all the state types used by the TUI application.
//! Each sub-module groups related state types by feature area.

pub mod compliance;
pub mod components;
pub mod dependencies;
pub mod graph_changes;
pub mod licenses;
pub mod matrix;
pub mod multi_diff;
pub mod navigation;
pub mod overlays;
pub mod quality;
pub mod search;
pub mod sidebyside;
pub mod source;
pub mod timeline;
pub mod vulnerabilities;

// Re-export all public types for backward compatibility.
// All existing `use super::app_states::{...}` imports continue to work.

pub use compliance::{
    DiffComplianceState, DiffComplianceViewMode, PolicyComplianceState, PolicyPreset,
};
pub use components::{
    ComponentFilter, ComponentSort, ComponentsState, sort_component_changes, sort_components,
};
pub use dependencies::{DependenciesState, DependencySort};
pub use graph_changes::GraphChangesState;
pub use licenses::{LicenseGroupBy, LicenseRiskFilter, LicenseSort, LicensesState};
pub use matrix::{MatrixSortBy, MatrixState, SimilarityThreshold};
pub use multi_diff::{
    MultiDiffState, MultiViewFilterPreset, MultiViewSearchState, MultiViewSortBy, SortDirection,
};
pub use navigation::{Breadcrumb, NavigationContext};
pub use overlays::{
    ComponentDeepDiveData, ComponentDeepDiveState, ComponentSimilarityInfo,
    ComponentTargetPresence, ComponentVersionEntry, ComponentVulnInfo, MultiViewType,
    ShortcutsContext, ShortcutsOverlayState, ViewSwitcherState,
};
pub use quality::{QualityState, QualityViewMode};
pub use search::{ChangeType, DiffSearchResult, DiffSearchState, VulnChangeType};
pub use sidebyside::{AlignmentMode, ChangeTypeFilter, ScrollSyncMode, SideBySideState};
pub use source::{SourceDiffState, SourcePanelState, SourceSide, SourceViewMode};
pub use timeline::{TimelineComponentFilter, TimelineSortBy, TimelineState};
pub use vulnerabilities::{
    DiffVulnItem, DiffVulnStatus, VulnFilter, VulnSort, VulnerabilitiesState,
};
