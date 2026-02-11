//! Timeline state types.

use crate::tui::views::TimelinePanel;
use super::multi_diff::{MultiViewSearchState, SortDirection};

/// State for timeline view
pub struct TimelineState {
    pub selected_version: usize,
    pub selected_component: usize,
    pub total_versions: usize,
    pub total_components: usize,
    pub active_panel: TimelinePanel,
    /// Search state
    pub search: MultiViewSearchState,
    /// Sort by field
    pub sort_by: TimelineSortBy,
    /// Sort direction
    pub sort_direction: SortDirection,
    /// Component filter
    pub component_filter: TimelineComponentFilter,
    /// Show version diff modal (compare two versions)
    pub show_version_diff_modal: bool,
    /// Second version for diff comparison
    pub compare_version: Option<usize>,
    /// Show statistics panel
    pub show_statistics: bool,
    /// Show component history detail modal
    pub show_component_history: bool,
    /// Jump to version mode
    pub jump_mode: bool,
    /// Jump target input
    pub jump_input: String,
    /// Chart zoom level (1-5, default 1)
    pub chart_zoom: u8,
    /// Scroll offset for bar chart
    pub chart_scroll: usize,
}

impl TimelineState {
    pub fn new() -> Self {
        Self {
            selected_version: 0,
            selected_component: 0,
            total_versions: 0,
            total_components: 0,
            active_panel: TimelinePanel::Versions,
            search: MultiViewSearchState::new(),
            sort_by: TimelineSortBy::default(),
            sort_direction: SortDirection::default(),
            component_filter: TimelineComponentFilter::default(),
            show_version_diff_modal: false,
            compare_version: None,
            show_statistics: false,
            show_component_history: false,
            jump_mode: false,
            jump_input: String::new(),
            chart_zoom: 1,
            chart_scroll: 0,
        }
    }

    pub fn new_with_versions(count: usize) -> Self {
        Self {
            selected_version: 0,
            selected_component: 0,
            total_versions: count,
            total_components: 0,
            active_panel: TimelinePanel::Versions,
            search: MultiViewSearchState::new(),
            sort_by: TimelineSortBy::default(),
            sort_direction: SortDirection::default(),
            component_filter: TimelineComponentFilter::default(),
            show_version_diff_modal: false,
            compare_version: None,
            show_statistics: false,
            show_component_history: false,
            jump_mode: false,
            jump_input: String::new(),
            chart_zoom: 1,
            chart_scroll: 0,
        }
    }

    pub const fn select_next(&mut self) {
        match self.active_panel {
            TimelinePanel::Versions => {
                if self.total_versions > 0 && self.selected_version < self.total_versions - 1 {
                    self.selected_version += 1;
                }
            }
            TimelinePanel::Components => {
                if self.total_components > 0 && self.selected_component < self.total_components - 1
                {
                    self.selected_component += 1;
                }
            }
        }
    }

    pub const fn select_prev(&mut self) {
        match self.active_panel {
            TimelinePanel::Versions => {
                if self.selected_version > 0 {
                    self.selected_version -= 1;
                }
            }
            TimelinePanel::Components => {
                if self.selected_component > 0 {
                    self.selected_component -= 1;
                }
            }
        }
    }

    pub const fn toggle_panel(&mut self) {
        self.active_panel = match self.active_panel {
            TimelinePanel::Versions => TimelinePanel::Components,
            TimelinePanel::Components => TimelinePanel::Versions,
        };
    }

    pub const fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
    }

    pub const fn toggle_sort_direction(&mut self) {
        self.sort_direction.toggle();
    }

    pub const fn toggle_component_filter(&mut self) {
        self.component_filter = self.component_filter.next();
    }

    pub const fn toggle_version_diff_modal(&mut self) {
        self.show_version_diff_modal = !self.show_version_diff_modal;
        if self.show_version_diff_modal {
            // Default to comparing with previous version
            if self.selected_version > 0 {
                self.compare_version = Some(self.selected_version - 1);
            } else if self.total_versions > 1 {
                self.compare_version = Some(1);
            }
        } else {
            self.compare_version = None;
        }
    }

    pub const fn close_version_diff_modal(&mut self) {
        self.show_version_diff_modal = false;
        self.compare_version = None;
    }

    pub const fn set_compare_version(&mut self, version: usize) {
        if version < self.total_versions && version != self.selected_version {
            self.compare_version = Some(version);
        }
    }

    pub const fn toggle_statistics(&mut self) {
        self.show_statistics = !self.show_statistics;
    }

    pub const fn toggle_component_history(&mut self) {
        self.show_component_history = !self.show_component_history;
    }

    pub const fn close_component_history(&mut self) {
        self.show_component_history = false;
    }

    pub fn start_jump_mode(&mut self) {
        self.jump_mode = true;
        self.jump_input.clear();
    }

    pub fn cancel_jump_mode(&mut self) {
        self.jump_mode = false;
        self.jump_input.clear();
    }

    pub fn execute_jump(&mut self) {
        if let Ok(version) = self.jump_input.parse::<usize>() {
            // Convert to 0-indexed
            let target = version.saturating_sub(1);
            if target < self.total_versions {
                self.selected_version = target;
            }
        }
        self.jump_mode = false;
        self.jump_input.clear();
    }

    pub fn jump_push(&mut self, c: char) {
        if c.is_ascii_digit() {
            self.jump_input.push(c);
        }
    }

    pub fn jump_pop(&mut self) {
        self.jump_input.pop();
    }

    pub const fn zoom_in(&mut self) {
        if self.chart_zoom < 5 {
            self.chart_zoom += 1;
        }
    }

    pub const fn zoom_out(&mut self) {
        if self.chart_zoom > 1 {
            self.chart_zoom -= 1;
        }
    }

    pub const fn scroll_chart_left(&mut self) {
        self.chart_scroll = self.chart_scroll.saturating_sub(1);
    }

    pub const fn scroll_chart_right(&mut self) {
        if self.chart_scroll < self.total_versions.saturating_sub(1) {
            self.chart_scroll += 1;
        }
    }

}

impl Default for TimelineState {
    fn default() -> Self {
        Self::new()
    }
}

/// Sort options for timeline view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimelineSortBy {
    #[default]
    Chronological,
    Changes,
    ComponentCount,
    Name,
}

impl TimelineSortBy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Chronological => "Chronological",
            Self::Changes => "Changes",
            Self::ComponentCount => "Component Count",
            Self::Name => "Name",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Chronological => Self::Changes,
            Self::Changes => Self::ComponentCount,
            Self::ComponentCount => Self::Name,
            Self::Name => Self::Chronological,
        }
    }
}

/// Filter for timeline component evolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimelineComponentFilter {
    #[default]
    All,
    Added,
    Removed,
    VersionChanged,
    Stable,
}

impl TimelineComponentFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::VersionChanged => "Version Changed",
            Self::Stable => "Stable",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::Added,
            Self::Added => Self::Removed,
            Self::Removed => Self::VersionChanged,
            Self::VersionChanged => Self::Stable,
            Self::Stable => Self::All,
        }
    }
}

