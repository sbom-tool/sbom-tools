//! Shared state definitions for TUI views.
//!
//! This module provides common traits and utilities for list/table navigation
//! that are shared between diff mode and view mode.

/// Trait for list-based navigation state.
///
/// Provides common selection and navigation methods for any view
/// that displays a selectable list of items.
pub trait ListNavigation {
    /// Get the current selection index.
    fn selected(&self) -> usize;

    /// Set the selection index.
    fn set_selected(&mut self, idx: usize);

    /// Get the total number of items.
    fn total(&self) -> usize;

    /// Set the total number of items.
    fn set_total(&mut self, total: usize);

    /// Move selection to the next item.
    fn select_next(&mut self) {
        let total = self.total();
        let selected = self.selected();
        if total > 0 && selected < total.saturating_sub(1) {
            self.set_selected(selected + 1);
        }
    }

    /// Move selection to the previous item.
    fn select_prev(&mut self) {
        let selected = self.selected();
        if selected > 0 {
            self.set_selected(selected - 1);
        }
    }

    /// Ensure selection is within valid bounds.
    fn clamp_selection(&mut self) {
        let total = self.total();
        let selected = self.selected();
        if total == 0 {
            self.set_selected(0);
        } else if selected >= total {
            self.set_selected(total.saturating_sub(1));
        }
    }

    /// Move selection up by a page.
    fn page_up(&mut self) {
        use super::constants::PAGE_SIZE;
        let selected = self.selected();
        self.set_selected(selected.saturating_sub(PAGE_SIZE));
    }

    /// Move selection down by a page.
    fn page_down(&mut self) {
        use super::constants::PAGE_SIZE;
        let total = self.total();
        let selected = self.selected();
        if total > 0 {
            self.set_selected((selected + PAGE_SIZE).min(total.saturating_sub(1)));
        }
    }

    /// Move to the first item.
    fn go_first(&mut self) {
        self.set_selected(0);
    }

    /// Move to the last item.
    fn go_last(&mut self) {
        let total = self.total();
        if total > 0 {
            self.set_selected(total.saturating_sub(1));
        }
    }
}

/// Base state for simple list navigation.
///
/// Can be embedded in more complex state structs to provide
/// common navigation functionality.
#[derive(Debug, Clone, Default)]
pub struct ListState {
    pub selected: usize,
    pub total: usize,
    pub scroll_offset: usize,
}

impl ListState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_total(total: usize) -> Self {
        Self {
            selected: 0,
            total,
            scroll_offset: 0,
        }
    }
}

impl ListNavigation for ListState {
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

/// Trait for tree-based navigation state.
///
/// Extends list navigation with expand/collapse functionality
/// for hierarchical views.
pub trait TreeNavigation: ListNavigation {
    /// Check if a node is expanded.
    fn is_expanded(&self, node_id: &str) -> bool;

    /// Expand a node.
    fn expand(&mut self, node_id: &str);

    /// Collapse a node.
    fn collapse(&mut self, node_id: &str);

    /// Toggle a node's expanded state.
    fn toggle_expand(&mut self, node_id: &str) {
        if self.is_expanded(node_id) {
            self.collapse(node_id);
        } else {
            self.expand(node_id);
        }
    }

    /// Expand all nodes.
    fn expand_all(&mut self);

    /// Collapse all nodes.
    fn collapse_all(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_state_navigation() {
        let mut state = ListState::with_total(10);

        assert_eq!(state.selected(), 0);

        state.select_next();
        assert_eq!(state.selected(), 1);

        state.select_prev();
        assert_eq!(state.selected(), 0);

        // Can't go below 0
        state.select_prev();
        assert_eq!(state.selected(), 0);

        // Go to last
        state.go_last();
        assert_eq!(state.selected(), 9);

        // Can't go past end
        state.select_next();
        assert_eq!(state.selected(), 9);

        // Go to first
        state.go_first();
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn test_list_state_page_navigation() {
        let mut state = ListState::with_total(50);

        state.page_down();
        assert_eq!(state.selected(), 10);

        state.page_down();
        assert_eq!(state.selected(), 20);

        state.page_up();
        assert_eq!(state.selected(), 10);

        state.page_up();
        assert_eq!(state.selected(), 0);

        // Can't go below 0
        state.page_up();
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn test_list_state_clamp() {
        let mut state = ListState::with_total(10);
        state.selected = 15;

        state.clamp_selection();
        assert_eq!(state.selected(), 9);

        state.set_total(0);
        state.clamp_selection();
        assert_eq!(state.selected(), 0);
    }
}
