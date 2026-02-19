//! Components state types.

use crate::tui::state::ListNavigation;
use std::collections::HashSet;

/// State for components view
pub struct ComponentsState {
    pub selected: usize,
    pub total: usize,
    pub filter: ComponentFilter,
    pub sort_by: ComponentSort,
    /// Multi-selection: set of selected indices
    pub multi_selected: HashSet<usize>,
    /// Whether multi-selection mode is active
    pub multi_select_mode: bool,
    /// Whether detail panel is focused (vs table)
    pub focus_detail: bool,
    /// Security filter state (quick filters)
    pub security_filter: crate::tui::viewmodel::security_filter::SecurityFilterState,
    /// Scroll offset preserved between frames for stable viewport
    pub scroll_offset: usize,
}

impl ComponentsState {
    pub fn new(total: usize) -> Self {
        Self {
            selected: 0,
            total,
            filter: ComponentFilter::All,
            sort_by: ComponentSort::Name,
            multi_selected: HashSet::new(),
            multi_select_mode: false,
            focus_detail: false,
            security_filter: crate::tui::viewmodel::security_filter::SecurityFilterState::new(),
            scroll_offset: 0,
        }
    }

    /// Toggle focus between table and detail panel
    pub const fn toggle_focus(&mut self) {
        self.focus_detail = !self.focus_detail;
    }

    pub fn toggle_filter(&mut self) {
        self.filter = match self.filter {
            ComponentFilter::All => ComponentFilter::Added,
            ComponentFilter::Added => ComponentFilter::Removed,
            ComponentFilter::Removed => ComponentFilter::Modified,
            ComponentFilter::Modified => ComponentFilter::EolOnly,
            ComponentFilter::EolOnly => ComponentFilter::EolRisk,
            ComponentFilter::EolRisk => ComponentFilter::All,
        };
        self.selected = 0; // Reset selection on filter change
        self.multi_selected.clear(); // Clear multi-selection on filter change
    }

    /// Toggle filter in view mode (only view-relevant filters)
    pub fn toggle_view_filter(&mut self) {
        self.filter = match self.filter {
            ComponentFilter::All => ComponentFilter::EolOnly,
            ComponentFilter::EolOnly => ComponentFilter::EolRisk,
            _ => ComponentFilter::All,
        };
        self.selected = 0;
        self.multi_selected.clear();
    }

    pub const fn toggle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            ComponentSort::Name => ComponentSort::Version,
            ComponentSort::Version => ComponentSort::Ecosystem,
            ComponentSort::Ecosystem => ComponentSort::Name,
        };
    }

    /// Toggle selection of current item in multi-select mode
    pub fn toggle_current_selection(&mut self) {
        if self.multi_selected.contains(&self.selected) {
            self.multi_selected.remove(&self.selected);
        } else {
            self.multi_selected.insert(self.selected);
        }
    }

    /// Toggle multi-select mode
    pub fn toggle_multi_select_mode(&mut self) {
        self.multi_select_mode = !self.multi_select_mode;
        if !self.multi_select_mode {
            self.multi_selected.clear();
        }
    }

    /// Select all items
    pub fn select_all(&mut self) {
        self.multi_selected = (0..self.total).collect();
    }

    /// Check if an index is selected
    pub fn is_selected(&self, index: usize) -> bool {
        self.multi_selected.contains(&index)
    }

    /// Get count of selected items
    pub fn selection_count(&self) -> usize {
        self.multi_selected.len()
    }
}

impl ListNavigation for ComponentsState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentFilter {
    All,
    Added,
    Removed,
    Modified,
    /// Show only components that have reached end-of-life
    EolOnly,
    /// Show only components that are EOL or approaching EOL
    EolRisk,
}

impl ComponentFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::Modified => "Modified",
            Self::EolOnly => "EOL",
            Self::EolRisk => "EOL Risk",
        }
    }

    /// Whether this filter applies to view mode (non-diff)
    pub const fn is_view_filter(self) -> bool {
        matches!(self, Self::All | Self::EolOnly | Self::EolRisk)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentSort {
    Name,
    Version,
    Ecosystem,
}

pub fn sort_component_changes(
    items: &mut Vec<&crate::diff::ComponentChange>,
    sort_by: ComponentSort,
) {
    match sort_by {
        ComponentSort::Name => {
            items.sort_by_key(|comp| {
                (
                    comp.name.to_lowercase(),
                    comp.new_version
                        .as_deref()
                        .or(comp.old_version.as_deref())
                        .unwrap_or("")
                        .to_lowercase(),
                    comp.id.to_lowercase(),
                )
            });
        }
        ComponentSort::Version => {
            items.sort_by_key(|comp| {
                (
                    comp.new_version
                        .as_deref()
                        .or(comp.old_version.as_deref())
                        .unwrap_or("")
                        .to_lowercase(),
                    comp.name.to_lowercase(),
                    comp.id.to_lowercase(),
                )
            });
        }
        ComponentSort::Ecosystem => {
            items.sort_by_key(|comp| {
                (
                    comp.ecosystem.as_deref().unwrap_or("").to_lowercase(),
                    comp.name.to_lowercase(),
                    comp.id.to_lowercase(),
                )
            });
        }
    }
}

pub fn sort_components(items: &mut Vec<&crate::model::Component>, sort_by: ComponentSort) {
    match sort_by {
        ComponentSort::Name => {
            items.sort_by_key(|comp| {
                (
                    comp.name.to_lowercase(),
                    comp.version.as_deref().unwrap_or("").to_lowercase(),
                    comp.canonical_id.value().to_lowercase(),
                )
            });
        }
        ComponentSort::Version => {
            items.sort_by_key(|comp| {
                (
                    comp.version.as_deref().unwrap_or("").to_lowercase(),
                    comp.name.to_lowercase(),
                    comp.canonical_id.value().to_lowercase(),
                )
            });
        }
        ComponentSort::Ecosystem => {
            items.sort_by_key(|comp| {
                (
                    comp.ecosystem
                        .as_ref()
                        .map(|eco| eco.to_string().to_lowercase())
                        .unwrap_or_default(),
                    comp.name.to_lowercase(),
                    comp.canonical_id.value().to_lowercase(),
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::ListNavigation;

    #[test]
    fn component_filter_labels() {
        assert_eq!(ComponentFilter::All.label(), "All");
        assert_eq!(ComponentFilter::Added.label(), "Added");
        assert_eq!(ComponentFilter::Removed.label(), "Removed");
        assert_eq!(ComponentFilter::Modified.label(), "Modified");
        assert_eq!(ComponentFilter::EolOnly.label(), "EOL");
        assert_eq!(ComponentFilter::EolRisk.label(), "EOL Risk");
    }

    #[test]
    fn component_filter_is_view_filter() {
        assert!(ComponentFilter::All.is_view_filter());
        assert!(ComponentFilter::EolOnly.is_view_filter());
        assert!(ComponentFilter::EolRisk.is_view_filter());
        assert!(!ComponentFilter::Added.is_view_filter());
        assert!(!ComponentFilter::Removed.is_view_filter());
        assert!(!ComponentFilter::Modified.is_view_filter());
    }

    #[test]
    fn view_filter_cycling() {
        let mut state = ComponentsState::new(10);
        assert_eq!(state.filter, ComponentFilter::All);

        state.toggle_view_filter();
        assert_eq!(state.filter, ComponentFilter::EolOnly);

        state.toggle_view_filter();
        assert_eq!(state.filter, ComponentFilter::EolRisk);

        state.toggle_view_filter();
        assert_eq!(state.filter, ComponentFilter::All);
    }

    #[test]
    fn diff_filter_cycling_includes_eol() {
        let mut state = ComponentsState::new(10);
        assert_eq!(state.filter, ComponentFilter::All);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::Added);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::Removed);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::Modified);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::EolOnly);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::EolRisk);

        state.toggle_filter();
        assert_eq!(state.filter, ComponentFilter::All);
    }

    #[test]
    fn filter_change_resets_selection() {
        let mut state = ComponentsState::new(10);
        state.set_selected(5);
        state.multi_selected.insert(3);

        state.toggle_view_filter();
        assert_eq!(
            state.selected(),
            0,
            "Selection should reset on filter change"
        );
        assert!(
            state.multi_selected.is_empty(),
            "Multi-selection should clear on filter change"
        );
    }

    #[test]
    fn view_filter_change_resets_selection() {
        let mut state = ComponentsState::new(10);
        state.set_selected(5);

        state.toggle_view_filter();
        assert_eq!(state.selected(), 0);
        assert_eq!(state.filter, ComponentFilter::EolOnly);
    }
}
