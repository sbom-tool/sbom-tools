//! Licenses state types.

use crate::tui::state::ListNavigation;

pub struct LicensesState {
    pub group_by: LicenseGroupBy,
    pub sort_by: LicenseSort,
    pub selected: usize,
    pub total: usize,
    pub scroll_offset_new: usize,
    pub scroll_offset_removed: usize,
    pub scroll_offset_view: usize,
    pub focus_left: bool,
    pub show_compatibility: bool,
    pub risk_filter: Option<LicenseRiskFilter>,
    pub selected_new: usize,
    pub selected_removed: usize,
}

impl LicensesState {
    pub const fn new() -> Self {
        Self {
            group_by: LicenseGroupBy::License,
            sort_by: LicenseSort::License,
            selected: 0,
            total: 0,
            scroll_offset_new: 0,
            scroll_offset_removed: 0,
            scroll_offset_view: 0,
            focus_left: true,
            show_compatibility: false,
            risk_filter: None,
            selected_new: 0,
            selected_removed: 0,
        }
    }

    pub const fn toggle_compatibility(&mut self) {
        self.show_compatibility = !self.show_compatibility;
    }

    pub const fn toggle_risk_filter(&mut self) {
        self.risk_filter = match self.risk_filter {
            None => Some(LicenseRiskFilter::Low),
            Some(LicenseRiskFilter::Low) => Some(LicenseRiskFilter::Medium),
            Some(LicenseRiskFilter::Medium) => Some(LicenseRiskFilter::High),
            Some(LicenseRiskFilter::High) => Some(LicenseRiskFilter::Critical),
            Some(LicenseRiskFilter::Critical) => None,
        };
        self.selected = 0;
        self.selected_new = 0;
        self.selected_removed = 0;
    }

    pub const fn toggle_focus(&mut self) {
        if self.focus_left {
            self.selected_new = self.selected;
        } else {
            self.selected_removed = self.selected;
        }
        self.focus_left = !self.focus_left;
        self.selected = if self.focus_left {
            self.selected_new
        } else {
            self.selected_removed
        };
    }

    pub const fn toggle_group(&mut self) {
        self.group_by = match self.group_by {
            LicenseGroupBy::License => LicenseGroupBy::Component,
            LicenseGroupBy::Component => LicenseGroupBy::Compatibility,
            LicenseGroupBy::Compatibility => LicenseGroupBy::Family,
            LicenseGroupBy::Family => LicenseGroupBy::Risk,
            LicenseGroupBy::Risk => LicenseGroupBy::License,
        };
        self.selected = 0;
    }

    pub const fn toggle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            LicenseSort::License => LicenseSort::Count,
            LicenseSort::Count => LicenseSort::Permissiveness,
            LicenseSort::Permissiveness => LicenseSort::Risk,
            LicenseSort::Risk => LicenseSort::License,
        };
        self.selected = 0;
    }
}

impl ListNavigation for LicensesState {
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

impl Default for LicensesState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseGroupBy {
    License,
    Component,
    Compatibility,
    Family,
    Risk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseSort {
    License,
    Count,
    Permissiveness,
    Risk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseRiskFilter {
    Low,
    Medium,
    High,
    Critical,
}
