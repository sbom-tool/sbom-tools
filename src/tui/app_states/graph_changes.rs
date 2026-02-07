//! Graph Changes state types.

use crate::tui::state::ListNavigation;

pub struct GraphChangesState {
    pub selected: usize,
    pub total: usize,
    pub scroll_offset: usize,
}

impl GraphChangesState {
    pub const fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            scroll_offset: 0,
        }
    }

}

impl ListNavigation for GraphChangesState {
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
        self.clamp_selection();
    }
}

impl Default for GraphChangesState {
    fn default() -> Self {
        Self::new()
    }
}

