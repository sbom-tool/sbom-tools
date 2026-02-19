//! Multi Diff state types.

use crate::tui::views::MultiDashboardPanel;

// Multi-View Unified Components
// ============================================================================

/// Search state for multi-comparison views
#[derive(Debug, Clone, Default)]
pub struct MultiViewSearchState {
    /// Whether search is active
    pub active: bool,
    /// Current search query
    pub query: String,
    /// Matched indices
    pub matches: Vec<usize>,
    /// Current match index
    pub current_match: usize,
}

impl MultiViewSearchState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.active = true;
        self.query.clear();
        self.matches.clear();
        self.current_match = 0;
    }

    pub fn cancel(&mut self) {
        self.active = false;
        self.query.clear();
        self.matches.clear();
    }

    pub const fn confirm(&mut self) {
        self.active = false;
    }

    pub fn push(&mut self, c: char) {
        self.query.push(c);
    }

    pub fn pop(&mut self) {
        self.query.pop();
    }

    pub fn update_matches(&mut self, matches: Vec<usize>) {
        self.matches = matches;
        self.current_match = 0;
    }

    pub fn next_match(&mut self) {
        if !self.matches.is_empty() {
            self.current_match = (self.current_match + 1) % self.matches.len();
        }
    }

    pub fn prev_match(&mut self) {
        if !self.matches.is_empty() {
            if self.current_match > 0 {
                self.current_match -= 1;
            } else {
                self.current_match = self.matches.len() - 1;
            }
        }
    }

    pub fn current_match_index(&self) -> Option<usize> {
        self.matches.get(self.current_match).copied()
    }

    pub fn match_position(&self) -> String {
        if self.matches.is_empty() {
            "0/0".to_string()
        } else {
            format!("{}/{}", self.current_match + 1, self.matches.len())
        }
    }
}

/// Filter presets for multi-comparison views
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultiViewFilterPreset {
    #[default]
    All,
    /// Show only targets with high deviation
    HighDeviation,
    /// Show only targets with changes
    ChangesOnly,
    /// Show only targets with vulnerabilities
    WithVulnerabilities,
    /// Show only targets with added components
    AddedOnly,
    /// Show only targets with removed components
    RemovedOnly,
}

impl MultiViewFilterPreset {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::HighDeviation => "High Deviation",
            Self::ChangesOnly => "Changes Only",
            Self::WithVulnerabilities => "With Vulns",
            Self::AddedOnly => "Added Only",
            Self::RemovedOnly => "Removed Only",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::HighDeviation,
            Self::HighDeviation => Self::ChangesOnly,
            Self::ChangesOnly => Self::WithVulnerabilities,
            Self::WithVulnerabilities => Self::AddedOnly,
            Self::AddedOnly => Self::RemovedOnly,
            Self::RemovedOnly => Self::All,
        }
    }
}

/// Sort options for multi-view lists
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultiViewSortBy {
    #[default]
    Name,
    Deviation,
    Changes,
    Components,
    Vulnerabilities,
}

impl MultiViewSortBy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Deviation => "Deviation",
            Self::Changes => "Changes",
            Self::Components => "Components",
            Self::Vulnerabilities => "Vulnerabilities",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Name => Self::Deviation,
            Self::Deviation => Self::Changes,
            Self::Changes => Self::Components,
            Self::Components => Self::Vulnerabilities,
            Self::Vulnerabilities => Self::Name,
        }
    }
}

/// Sort direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    #[default]
    Ascending,
    Descending,
}

impl SortDirection {
    pub const fn toggle(&mut self) {
        *self = match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        };
    }

    pub const fn indicator(self) -> &'static str {
        match self {
            Self::Ascending => "↑",
            Self::Descending => "↓",
        }
    }
}

/// State for multi-diff view
pub struct MultiDiffState {
    pub selected_target: usize,
    pub total_targets: usize,
    pub active_panel: MultiDashboardPanel,
    /// Search state
    pub search: MultiViewSearchState,
    /// Filter preset
    pub filter_preset: MultiViewFilterPreset,
    /// Sort by field
    pub sort_by: MultiViewSortBy,
    /// Sort direction
    pub sort_direction: SortDirection,
    /// Show detail modal
    pub show_detail_modal: bool,
    /// Selected variable component index (for drill-down)
    pub selected_variable_component: usize,
    /// Total variable components
    pub total_variable_components: usize,
    /// Show variable component drill-down modal
    pub show_variable_drill_down: bool,
    /// Show cross-target analysis panel
    pub show_cross_target: bool,
    /// Heat map mode (show deviation as heat map)
    pub heat_map_mode: bool,
}

impl MultiDiffState {
    pub fn new() -> Self {
        Self {
            selected_target: 0,
            total_targets: 0,
            active_panel: MultiDashboardPanel::Targets,
            search: MultiViewSearchState::new(),
            filter_preset: MultiViewFilterPreset::default(),
            sort_by: MultiViewSortBy::default(),
            sort_direction: SortDirection::default(),
            show_detail_modal: false,
            selected_variable_component: 0,
            total_variable_components: 0,
            show_variable_drill_down: false,
            show_cross_target: false,
            heat_map_mode: false,
        }
    }

    pub fn new_with_targets(count: usize) -> Self {
        Self {
            selected_target: 0,
            total_targets: count,
            active_panel: MultiDashboardPanel::Targets,
            search: MultiViewSearchState::new(),
            filter_preset: MultiViewFilterPreset::default(),
            sort_by: MultiViewSortBy::default(),
            sort_direction: SortDirection::default(),
            show_detail_modal: false,
            selected_variable_component: 0,
            total_variable_components: 0,
            show_variable_drill_down: false,
            show_cross_target: false,
            heat_map_mode: false,
        }
    }

    pub const fn select_next(&mut self) {
        if self.total_targets > 0 && self.selected_target < self.total_targets - 1 {
            self.selected_target += 1;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected_target > 0 {
            self.selected_target -= 1;
        }
    }

    pub const fn toggle_panel(&mut self) {
        self.active_panel = match self.active_panel {
            MultiDashboardPanel::Targets => MultiDashboardPanel::Details,
            MultiDashboardPanel::Details => MultiDashboardPanel::Targets,
        };
    }

    pub const fn toggle_filter(&mut self) {
        self.filter_preset = self.filter_preset.next();
    }

    pub const fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
    }

    pub const fn toggle_sort_direction(&mut self) {
        self.sort_direction.toggle();
    }

    pub const fn toggle_detail_modal(&mut self) {
        self.show_detail_modal = !self.show_detail_modal;
    }

    pub const fn close_detail_modal(&mut self) {
        self.show_detail_modal = false;
    }

    pub const fn toggle_variable_drill_down(&mut self) {
        self.show_variable_drill_down = !self.show_variable_drill_down;
    }

    pub const fn close_variable_drill_down(&mut self) {
        self.show_variable_drill_down = false;
    }

    pub const fn toggle_cross_target(&mut self) {
        self.show_cross_target = !self.show_cross_target;
    }

    pub const fn toggle_heat_map(&mut self) {
        self.heat_map_mode = !self.heat_map_mode;
    }

    pub const fn select_next_variable_component(&mut self) {
        if self.total_variable_components > 0
            && self.selected_variable_component < self.total_variable_components - 1
        {
            self.selected_variable_component += 1;
        }
    }

    pub const fn select_prev_variable_component(&mut self) {
        if self.selected_variable_component > 0 {
            self.selected_variable_component -= 1;
        }
    }
}

impl Default for MultiDiffState {
    fn default() -> Self {
        Self::new()
    }
}
