//! Sidebyside state types.

/// Alignment mode for side-by-side view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    /// Group by change type (removed, modified, added) - original behavior
    #[default]
    Grouped,
    /// Align matched components on same row for easy comparison
    Aligned,
}

impl AlignmentMode {
    /// Toggle to next mode
    pub fn toggle(&mut self) {
        *self = match self {
            Self::Grouped => Self::Aligned,
            Self::Aligned => Self::Grouped,
        };
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Grouped => "Grouped",
            Self::Aligned => "Aligned",
        }
    }
}

/// Scroll synchronization mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScrollSyncMode {
    /// Independent scrolling (default)
    #[default]
    Independent,
    /// Lock scroll positions together
    Locked,
}

impl ScrollSyncMode {
    /// Toggle to next mode
    pub fn toggle(&mut self) {
        *self = match self {
            Self::Independent => Self::Locked,
            Self::Locked => Self::Independent,
        };
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Independent => "Independent",
            Self::Locked => "Locked",
        }
    }
}

/// Filter for visible change types
#[derive(Debug, Clone)]
pub struct ChangeTypeFilter {
    pub show_added: bool,
    pub show_removed: bool,
    pub show_modified: bool,
}

impl Default for ChangeTypeFilter {
    fn default() -> Self {
        Self {
            show_added: true,
            show_removed: true,
            show_modified: true,
        }
    }
}

impl ChangeTypeFilter {
    /// Toggle added visibility
    pub fn toggle_added(&mut self) {
        self.show_added = !self.show_added;
    }

    /// Toggle removed visibility
    pub fn toggle_removed(&mut self) {
        self.show_removed = !self.show_removed;
    }

    /// Toggle modified visibility
    pub fn toggle_modified(&mut self) {
        self.show_modified = !self.show_modified;
    }

    /// Show all change types
    pub fn show_all(&mut self) {
        self.show_added = true;
        self.show_removed = true;
        self.show_modified = true;
    }

    /// Check if any filter is active
    pub fn is_filtered(&self) -> bool {
        !self.show_added || !self.show_removed || !self.show_modified
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        if !self.is_filtered() {
            return "All".to_string();
        }
        let mut parts = Vec::new();
        if self.show_added {
            parts.push("+");
        }
        if self.show_removed {
            parts.push("-");
        }
        if self.show_modified {
            parts.push("~");
        }
        parts.join("")
    }
}

/// State for side-by-side diff view with independent panel scrolling
pub struct SideBySideState {
    /// Left panel (old SBOM) scroll offset
    pub left_scroll: usize,
    /// Right panel (new SBOM) scroll offset
    pub right_scroll: usize,
    /// Total lines in left panel
    pub left_total: usize,
    /// Total lines in right panel
    pub right_total: usize,
    /// Which panel is currently focused (true = right, false = left)
    pub focus_right: bool,
    /// Alignment mode (grouped vs aligned)
    pub alignment_mode: AlignmentMode,
    /// Scroll synchronization mode
    pub sync_mode: ScrollSyncMode,
    /// Change type filter
    pub filter: ChangeTypeFilter,
    /// Currently selected row index (for aligned mode)
    pub selected_row: usize,
    /// Total rows in aligned mode
    pub total_rows: usize,
    /// Change indices for navigation (row indices with changes)
    pub change_indices: Vec<usize>,
    /// Current change index for next/prev navigation
    pub current_change_idx: Option<usize>,
    /// Search query (if active)
    pub search_query: Option<String>,
    /// Search matches (row indices)
    pub search_matches: Vec<usize>,
    /// Current search match index
    pub current_match_idx: usize,
    /// Is search input mode active
    pub search_active: bool,
    /// Show component detail modal
    pub show_detail_modal: bool,
    /// Selected component for detail modal (left side)
    pub detail_component_left: Option<String>,
    /// Selected component for detail modal (right side)
    pub detail_component_right: Option<String>,
}

impl SideBySideState {
    pub fn new() -> Self {
        Self {
            left_scroll: 0,
            right_scroll: 0,
            left_total: 0,
            right_total: 0,
            focus_right: false,
            alignment_mode: AlignmentMode::default(),
            sync_mode: ScrollSyncMode::default(),
            filter: ChangeTypeFilter::default(),
            selected_row: 0,
            total_rows: 0,
            change_indices: Vec::new(),
            current_change_idx: None,
            search_query: None,
            search_matches: Vec::new(),
            current_match_idx: 0,
            search_active: false,
            show_detail_modal: false,
            detail_component_left: None,
            detail_component_right: None,
        }
    }

    /// Scroll the currently focused panel up
    pub fn scroll_up(&mut self) {
        match self.sync_mode {
            ScrollSyncMode::Independent => {
                if self.focus_right {
                    self.right_scroll = self.right_scroll.saturating_sub(1);
                } else {
                    self.left_scroll = self.left_scroll.saturating_sub(1);
                }
            }
            ScrollSyncMode::Locked => {
                self.scroll_both_up();
            }
        }
        // Update selected row in aligned mode
        if self.alignment_mode == AlignmentMode::Aligned {
            self.selected_row = self.selected_row.saturating_sub(1);
        }
    }

    /// Scroll the currently focused panel down
    pub fn scroll_down(&mut self) {
        match self.sync_mode {
            ScrollSyncMode::Independent => {
                if self.focus_right {
                    if self.right_total > 0
                        && self.right_scroll < self.right_total.saturating_sub(1)
                    {
                        self.right_scroll += 1;
                    }
                } else if self.left_total > 0
                    && self.left_scroll < self.left_total.saturating_sub(1)
                {
                    self.left_scroll += 1;
                }
            }
            ScrollSyncMode::Locked => {
                self.scroll_both_down();
            }
        }
        // Update selected row in aligned mode
        if self.alignment_mode == AlignmentMode::Aligned && self.total_rows > 0 {
            self.selected_row = (self.selected_row + 1).min(self.total_rows.saturating_sub(1));
        }
    }

    /// Page up on currently focused panel
    pub fn page_up(&mut self) {
        let page_size = crate::tui::constants::PAGE_SIZE;
        match self.sync_mode {
            ScrollSyncMode::Independent => {
                if self.focus_right {
                    self.right_scroll = self.right_scroll.saturating_sub(page_size);
                } else {
                    self.left_scroll = self.left_scroll.saturating_sub(page_size);
                }
            }
            ScrollSyncMode::Locked => {
                self.left_scroll = self.left_scroll.saturating_sub(page_size);
                self.right_scroll = self.right_scroll.saturating_sub(page_size);
            }
        }
        if self.alignment_mode == AlignmentMode::Aligned {
            self.selected_row = self.selected_row.saturating_sub(page_size);
        }
    }

    /// Page down on currently focused panel
    pub fn page_down(&mut self) {
        let page_size = crate::tui::constants::PAGE_SIZE;
        match self.sync_mode {
            ScrollSyncMode::Independent => {
                if self.focus_right {
                    self.right_scroll =
                        (self.right_scroll + page_size).min(self.right_total.saturating_sub(1));
                } else {
                    self.left_scroll =
                        (self.left_scroll + page_size).min(self.left_total.saturating_sub(1));
                }
            }
            ScrollSyncMode::Locked => {
                self.left_scroll =
                    (self.left_scroll + page_size).min(self.left_total.saturating_sub(1));
                self.right_scroll =
                    (self.right_scroll + page_size).min(self.right_total.saturating_sub(1));
            }
        }
        if self.alignment_mode == AlignmentMode::Aligned && self.total_rows > 0 {
            self.selected_row =
                (self.selected_row + page_size).min(self.total_rows.saturating_sub(1));
        }
    }

    /// Toggle focus between left and right panels
    pub fn toggle_focus(&mut self) {
        self.focus_right = !self.focus_right;
    }

    /// Toggle alignment mode
    pub fn toggle_alignment(&mut self) {
        self.alignment_mode.toggle();
    }

    /// Toggle sync mode
    pub fn toggle_sync(&mut self) {
        self.sync_mode.toggle();
    }

    /// Scroll both panels together (synchronized scroll)
    pub fn scroll_both_up(&mut self) {
        self.left_scroll = self.left_scroll.saturating_sub(1);
        self.right_scroll = self.right_scroll.saturating_sub(1);
    }

    /// Scroll both panels together (synchronized scroll)
    pub fn scroll_both_down(&mut self) {
        if self.left_total > 0 && self.left_scroll < self.left_total.saturating_sub(1) {
            self.left_scroll += 1;
        }
        if self.right_total > 0 && self.right_scroll < self.right_total.saturating_sub(1) {
            self.right_scroll += 1;
        }
    }

    /// Set total lines for panels
    pub fn set_totals(&mut self, left: usize, right: usize) {
        self.left_total = left;
        self.right_total = right;
    }

    /// Set total rows for aligned mode
    pub fn set_total_rows(&mut self, total: usize) {
        self.total_rows = total;
        if self.selected_row >= total && total > 0 {
            self.selected_row = total - 1;
        }
    }

    /// Set change indices for navigation
    pub fn set_change_indices(&mut self, indices: Vec<usize>) {
        self.change_indices = indices;
        self.current_change_idx = None;
    }

    /// Go to top of focused panel
    pub fn go_to_top(&mut self) {
        if self.focus_right {
            self.right_scroll = 0;
        } else {
            self.left_scroll = 0;
        }
        if self.alignment_mode == AlignmentMode::Aligned {
            self.selected_row = 0;
        }
    }

    /// Go to bottom of focused panel
    pub fn go_to_bottom(&mut self) {
        if self.focus_right {
            self.right_scroll = self.right_total.saturating_sub(1);
        } else {
            self.left_scroll = self.left_total.saturating_sub(1);
        }
        if self.alignment_mode == AlignmentMode::Aligned && self.total_rows > 0 {
            self.selected_row = self.total_rows - 1;
        }
    }

    /// Navigate to next change
    pub fn next_change(&mut self) {
        if self.change_indices.is_empty() {
            return;
        }

        let next_idx = match self.current_change_idx {
            Some(idx) => {
                if idx + 1 < self.change_indices.len() {
                    idx + 1
                } else {
                    0 // Wrap around
                }
            }
            None => 0,
        };

        self.current_change_idx = Some(next_idx);
        self.scroll_to_row(self.change_indices[next_idx]);
    }

    /// Navigate to previous change
    pub fn prev_change(&mut self) {
        if self.change_indices.is_empty() {
            return;
        }

        let prev_idx = match self.current_change_idx {
            Some(idx) => {
                if idx > 0 {
                    idx - 1
                } else {
                    self.change_indices.len() - 1 // Wrap around
                }
            }
            None => self.change_indices.len() - 1,
        };

        self.current_change_idx = Some(prev_idx);
        self.scroll_to_row(self.change_indices[prev_idx]);
    }

    /// Scroll to a specific row
    pub fn scroll_to_row(&mut self, row: usize) {
        self.selected_row = row;
        // Adjust scroll to keep row visible (assuming ~20 visible rows)
        let visible_rows = 20;
        if row < self.left_scroll {
            self.left_scroll = row;
            self.right_scroll = row;
        } else if row >= self.left_scroll + visible_rows {
            self.left_scroll = row.saturating_sub(visible_rows / 2);
            self.right_scroll = row.saturating_sub(visible_rows / 2);
        }
    }

    /// Start search mode
    pub fn start_search(&mut self) {
        self.search_active = true;
        self.search_query = Some(String::new());
        self.search_matches.clear();
        self.current_match_idx = 0;
    }

    /// Cancel search mode
    pub fn cancel_search(&mut self) {
        self.search_active = false;
        self.search_query = None;
        self.search_matches.clear();
    }

    /// Confirm search (exit input mode but keep highlights)
    pub fn confirm_search(&mut self) {
        self.search_active = false;
    }

    /// Add character to search query
    pub fn search_push(&mut self, c: char) {
        if let Some(ref mut query) = self.search_query {
            query.push(c);
        }
    }

    /// Remove character from search query
    pub fn search_pop(&mut self) {
        if let Some(ref mut query) = self.search_query {
            query.pop();
        }
    }

    /// Update search matches based on current query
    pub fn update_search_matches(&mut self, matches: Vec<usize>) {
        self.search_matches = matches;
        self.current_match_idx = 0;
        // Jump to first match
        if !self.search_matches.is_empty() {
            self.scroll_to_row(self.search_matches[0]);
        }
    }

    /// Navigate to next search match
    pub fn next_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        self.current_match_idx = (self.current_match_idx + 1) % self.search_matches.len();
        self.scroll_to_row(self.search_matches[self.current_match_idx]);
    }

    /// Navigate to previous search match
    pub fn prev_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        if self.current_match_idx > 0 {
            self.current_match_idx -= 1;
        } else {
            self.current_match_idx = self.search_matches.len() - 1;
        }
        self.scroll_to_row(self.search_matches[self.current_match_idx]);
    }

    /// Toggle detail modal
    pub fn toggle_detail_modal(&mut self) {
        self.show_detail_modal = !self.show_detail_modal;
    }

    /// Close detail modal
    pub fn close_detail_modal(&mut self) {
        self.show_detail_modal = false;
        self.detail_component_left = None;
        self.detail_component_right = None;
    }

    /// Get current change position string (e.g., "3/15")
    pub fn change_position(&self) -> String {
        if self.change_indices.is_empty() {
            return "0/0".to_string();
        }
        match self.current_change_idx {
            Some(idx) => format!("{}/{}", idx + 1, self.change_indices.len()),
            None => format!("-/{}", self.change_indices.len()),
        }
    }

    /// Get current search match position string
    pub fn match_position(&self) -> String {
        if self.search_matches.is_empty() {
            return "0/0".to_string();
        }
        format!(
            "{}/{}",
            self.current_match_idx + 1,
            self.search_matches.len()
        )
    }
}

impl Default for SideBySideState {
    fn default() -> Self {
        Self::new()
    }
}

