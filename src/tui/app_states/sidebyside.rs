//! Sidebyside state types.

use crate::diff::ChangeType;

/// An aligned row for side-by-side comparison
#[derive(Debug, Clone)]
pub struct AlignedRow {
    /// Left side component (old SBOM)
    pub left_name: Option<String>,
    pub left_version: Option<String>,
    /// Right side component (new SBOM)
    pub right_name: Option<String>,
    pub right_version: Option<String>,
    /// Type of change
    pub change_type: crate::diff::ChangeType,
    /// Component ID for detail lookup
    pub component_id: Option<String>,
}

/// Entry in the unified upgrade view
#[derive(Debug, Clone)]
pub struct UnifiedEntry {
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub change_type: UnifiedChangeType,
}

/// Classification for unified view entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedChangeType {
    Upgrade,
    Downgrade,
    Modified,
    Added,
    Removed,
}

/// Alignment mode for side-by-side view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    /// Group by change type (removed, modified, added) - original behavior
    Grouped,
    /// Align matched components on same row for easy comparison.
    ///
    /// The default: it is the only opening mode where row selection, the
    /// detail modal, yank, search highlighting, and change navigation all
    /// work. Grouped is an explicit opt-in via `a`.
    #[default]
    Aligned,
    /// Unified upgrade view matching removed+added by name to show version upgrades
    Unified,
}

impl AlignmentMode {
    /// Cycle to next mode
    pub const fn toggle(&mut self) {
        *self = match self {
            Self::Grouped => Self::Aligned,
            Self::Aligned => Self::Unified,
            Self::Unified => Self::Grouped,
        };
    }

    /// Get display name
    pub const fn name(self) -> &'static str {
        match self {
            Self::Grouped => "Grouped",
            Self::Aligned => "Aligned",
            Self::Unified => "Unified",
        }
    }

    /// Returns true if this mode uses row-based selection (not panel scrolling)
    pub const fn uses_row_selection(self) -> bool {
        matches!(self, Self::Aligned | Self::Unified)
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
    pub const fn toggle(&mut self) {
        *self = match self {
            Self::Independent => Self::Locked,
            Self::Locked => Self::Independent,
        };
    }

    /// Get display name
    pub const fn name(self) -> &'static str {
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
    pub const fn toggle_added(&mut self) {
        self.show_added = !self.show_added;
    }

    /// Toggle removed visibility
    pub const fn toggle_removed(&mut self) {
        self.show_removed = !self.show_removed;
    }

    /// Toggle modified visibility
    pub const fn toggle_modified(&mut self) {
        self.show_modified = !self.show_modified;
    }

    /// Show all change types
    pub const fn show_all(&mut self) {
        self.show_added = true;
        self.show_removed = true;
        self.show_modified = true;
    }

    /// Check if any filter is active
    pub const fn is_filtered(&self) -> bool {
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
    /// Cached aligned rows (rebuilt each frame in `App::prepare_render`)
    pub aligned_rows: Vec<AlignedRow>,
    /// Cached unified entries (rebuilt each frame in `App::prepare_render`)
    pub unified_entries: Vec<UnifiedEntry>,
    /// Visible row count of the aligned panels (content height minus context
    /// bar and borders; Unified subtracts 2 more for its header + separator).
    /// Set by the render path each frame; defaults to 20 before first render.
    pub viewport_rows: usize,
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
            aligned_rows: Vec::new(),
            unified_entries: Vec::new(),
            viewport_rows: 20,
        }
    }

    /// Record the panel viewport height (rows) measured by the render path.
    pub const fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = if rows == 0 { 1 } else { rows };
    }

    /// Keep the selected row inside the visible window in row-selection
    /// modes, whatever mutated it. Called at the end of every
    /// `recompute_row_model` (i.e. every frame) so all paths self-heal.
    fn clamp_scroll_to_selection(&mut self) {
        if !self.alignment_mode.uses_row_selection() {
            return;
        }
        // Unified draws a header + separator inside the panel; while search
        // input is active the query overlay covers the bottom rows, so keep
        // the target row clear of it.
        let mut chrome = if self.alignment_mode == AlignmentMode::Unified {
            2
        } else {
            0
        };
        if self.search_active {
            chrome += 4;
        }
        let visible = self.viewport_rows.saturating_sub(chrome).max(1);
        let min_scroll = self.selected_row.saturating_sub(visible - 1);
        // Never start the window deeper than the list can fill.
        let max_scroll = self
            .total_rows
            .saturating_sub(visible)
            .max(min_scroll)
            .min(self.selected_row);
        self.left_scroll = self.left_scroll.clamp(min_scroll, max_scroll);
        self.right_scroll = self.left_scroll;
    }

    /// Recompute the row-navigation model (`total_rows`, `change_indices`) from
    /// the cached row list for the active alignment mode, clamping any stale
    /// selection/navigation indices. For row-selection modes, `left_total` /
    /// `right_total` are synced to `total_rows` so panel scrolling can follow
    /// the selected row across every row; Grouped keeps the counts set by
    /// [`set_totals`](Self::set_totals).
    pub fn recompute_row_model(&mut self) {
        let (total, change_indices) = match self.alignment_mode {
            AlignmentMode::Aligned => {
                let indices = self
                    .aligned_rows
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.change_type != ChangeType::Unchanged)
                    .map(|(i, _)| i)
                    .collect();
                (self.aligned_rows.len(), indices)
            }
            AlignmentMode::Unified => {
                let total = self.unified_entries.len();
                (total, (0..total).collect())
            }
            AlignmentMode::Grouped => (0, Vec::new()),
        };

        self.total_rows = total;
        self.change_indices = change_indices;

        // Clamp selection so it never points past the current row set.
        if total == 0 {
            self.selected_row = 0;
        } else {
            self.selected_row = self.selected_row.min(total - 1);
        }

        // Clamp the change cursor so next/prev_change can never index OOB.
        if self.change_indices.is_empty() {
            self.current_change_idx = None;
        } else if let Some(i) = self.current_change_idx
            && i >= self.change_indices.len()
        {
            self.current_change_idx = Some(self.change_indices.len() - 1);
        }

        // Row-selection modes drive both panels off the single row list.
        if self.alignment_mode.uses_row_selection() {
            self.left_total = total;
            self.right_total = total;
        }

        // Self-heal the scroll window around the selection every frame.
        self.clamp_scroll_to_selection();
    }

    /// Scroll the currently focused panel up
    pub fn scroll_up(&mut self) {
        // Row-selection modes move the selection cursor; the scroll window
        // follows it regardless of which panel is focused (routing movement
        // through the focused panel's offset walked the cursor off-screen).
        if self.alignment_mode.uses_row_selection() {
            self.selected_row = self.selected_row.saturating_sub(1);
            self.clamp_scroll_to_selection();
            return;
        }
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
    }

    /// Scroll the currently focused panel down
    pub fn scroll_down(&mut self) {
        if self.alignment_mode.uses_row_selection() {
            if self.total_rows > 0 {
                self.selected_row = (self.selected_row + 1).min(self.total_rows.saturating_sub(1));
            }
            self.clamp_scroll_to_selection();
            return;
        }
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
    }

    /// Page up on currently focused panel
    pub fn page_up(&mut self) {
        let page_size = crate::tui::constants::PAGE_SIZE;
        if self.alignment_mode.uses_row_selection() {
            self.selected_row = self.selected_row.saturating_sub(page_size);
            self.clamp_scroll_to_selection();
            return;
        }
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
    }

    /// Page down on currently focused panel
    pub fn page_down(&mut self) {
        let page_size = crate::tui::constants::PAGE_SIZE;
        if self.alignment_mode.uses_row_selection() {
            if self.total_rows > 0 {
                self.selected_row =
                    (self.selected_row + page_size).min(self.total_rows.saturating_sub(1));
            }
            self.clamp_scroll_to_selection();
            return;
        }
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
    }

    /// Toggle focus between left and right panels
    pub const fn toggle_focus(&mut self) {
        self.focus_right = !self.focus_right;
    }

    /// Toggle alignment mode
    pub const fn toggle_alignment(&mut self) {
        self.alignment_mode.toggle();
    }

    /// Toggle sync mode
    pub const fn toggle_sync(&mut self) {
        self.sync_mode.toggle();
    }

    /// Scroll both panels together (synchronized scroll)
    pub const fn scroll_both_up(&mut self) {
        self.left_scroll = self.left_scroll.saturating_sub(1);
        self.right_scroll = self.right_scroll.saturating_sub(1);
    }

    /// Scroll both panels together (synchronized scroll)
    pub const fn scroll_both_down(&mut self) {
        if self.left_total > 0 && self.left_scroll < self.left_total.saturating_sub(1) {
            self.left_scroll += 1;
        }
        if self.right_total > 0 && self.right_scroll < self.right_total.saturating_sub(1) {
            self.right_scroll += 1;
        }
    }

    /// Set total lines for panels
    pub const fn set_totals(&mut self, left: usize, right: usize) {
        self.left_total = left;
        self.right_total = right;
    }

    /// Go to top of focused panel
    pub fn go_to_top(&mut self) {
        if self.alignment_mode.uses_row_selection() {
            self.selected_row = 0;
            self.clamp_scroll_to_selection();
            return;
        }
        if self.focus_right {
            self.right_scroll = 0;
        } else {
            self.left_scroll = 0;
        }
    }

    /// Go to bottom of focused panel
    pub fn go_to_bottom(&mut self) {
        if self.alignment_mode.uses_row_selection() {
            if self.total_rows > 0 {
                self.selected_row = self.total_rows - 1;
            }
            self.clamp_scroll_to_selection();
            return;
        }
        if self.focus_right {
            self.right_scroll = self.right_total.saturating_sub(1);
        } else {
            self.left_scroll = self.left_total.saturating_sub(1);
        }
    }

    /// Navigate to next change
    pub fn next_change(&mut self) {
        if self.change_indices.is_empty() {
            return;
        }

        let next_idx = match self.current_change_idx {
            Some(idx) if idx + 1 < self.change_indices.len() => idx + 1,
            // Wrap around (or start from the top when nothing is selected).
            _ => 0,
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
        // The clamp uses the real measured viewport height; the previous
        // hardcoded 20-row assumption landed jumps below the fold at 80x24.
        self.selected_row = row;
        self.clamp_scroll_to_selection();
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
    pub const fn confirm_search(&mut self) {
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
    pub const fn toggle_detail_modal(&mut self) {
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
        self.current_change_idx.map_or_else(
            || format!("-/{}", self.change_indices.len()),
            |idx| format!("{}/{}", idx + 1, self.change_indices.len()),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn aligned_row(change_type: ChangeType) -> AlignedRow {
        AlignedRow {
            left_name: Some("pkg".to_string()),
            left_version: Some("1.0".to_string()),
            right_name: Some("pkg".to_string()),
            right_version: Some("2.0".to_string()),
            change_type,
            component_id: Some("pkg".to_string()),
        }
    }

    fn unified_entry() -> UnifiedEntry {
        UnifiedEntry {
            name: "pkg".to_string(),
            old_version: Some("1.0".to_string()),
            new_version: Some("2.0".to_string()),
            change_type: UnifiedChangeType::Upgrade,
        }
    }

    #[test]
    fn recompute_row_model_aligned_populates_totals() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Aligned;
        s.aligned_rows = vec![
            aligned_row(ChangeType::Removed),
            aligned_row(ChangeType::Modified),
            aligned_row(ChangeType::Added),
        ];
        s.recompute_row_model();
        assert_eq!(s.total_rows, 3);
        assert_eq!(s.change_indices, vec![0, 1, 2]);
        assert_eq!(s.left_total, 3);
        assert_eq!(s.right_total, 3);
    }

    #[test]
    fn recompute_row_model_unified_populates_totals() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Unified;
        s.unified_entries = vec![
            unified_entry(),
            unified_entry(),
            unified_entry(),
            unified_entry(),
        ];
        s.recompute_row_model();
        assert_eq!(s.total_rows, 4);
        assert_eq!(s.change_indices, vec![0, 1, 2, 3]);
        assert_eq!(s.left_total, 4);
        assert_eq!(s.right_total, 4);
    }

    #[test]
    fn default_alignment_is_aligned() {
        // Regression for the default flip: Aligned is the only opening mode
        // where selection/detail/yank/search-highlight all work.
        assert_eq!(
            SideBySideState::new().alignment_mode,
            AlignmentMode::Aligned
        );
    }

    #[test]
    fn recompute_row_model_grouped_preserves_grouped_totals() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Grouped;
        s.set_totals(5, 7);
        s.recompute_row_model();
        assert_eq!(s.total_rows, 0);
        assert!(s.change_indices.is_empty());
        assert_eq!(s.left_total, 5);
        assert_eq!(s.right_total, 7);
    }

    #[test]
    fn scroll_down_advances_selected_in_aligned_after_recompute() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Aligned;
        s.aligned_rows = vec![
            aligned_row(ChangeType::Removed),
            aligned_row(ChangeType::Modified),
            aligned_row(ChangeType::Added),
        ];
        s.recompute_row_model();
        assert_eq!(s.selected_row, 0);
        s.scroll_down();
        s.scroll_down();
        s.scroll_down();
        assert_eq!(s.selected_row, 2);
    }

    #[test]
    fn next_change_cycles_and_wraps() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Aligned;
        s.aligned_rows = vec![
            aligned_row(ChangeType::Removed),
            aligned_row(ChangeType::Modified),
            aligned_row(ChangeType::Added),
        ];
        s.recompute_row_model();
        s.next_change();
        assert_eq!(s.current_change_idx, Some(0));
        assert_eq!(s.selected_row, 0);
        assert_eq!(s.change_position(), "1/3");
        s.next_change();
        assert_eq!(s.current_change_idx, Some(1));
        s.next_change();
        assert_eq!(s.current_change_idx, Some(2));
        s.next_change();
        assert_eq!(s.current_change_idx, Some(0));
    }

    #[test]
    fn recompute_clamps_stale_current_change_idx_no_panic() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Aligned;
        s.aligned_rows = (0..5).map(|_| aligned_row(ChangeType::Modified)).collect();
        s.recompute_row_model();
        s.current_change_idx = Some(4);
        s.aligned_rows.truncate(2);
        s.recompute_row_model();
        assert_eq!(s.current_change_idx, Some(1));
        // Must not panic indexing change_indices out of bounds.
        s.prev_change();
        assert_eq!(s.current_change_idx, Some(0));
    }

    #[test]
    fn recompute_clamps_selected_row_when_rows_shrink() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Aligned;
        s.aligned_rows = (0..5).map(|_| aligned_row(ChangeType::Modified)).collect();
        s.recompute_row_model();
        s.selected_row = 4;
        s.aligned_rows.truncate(2);
        s.recompute_row_model();
        assert_eq!(s.selected_row, 1);
    }

    #[test]
    fn next_prev_change_noop_when_grouped_or_empty() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Grouped;
        s.recompute_row_model();
        s.next_change();
        assert_eq!(s.current_change_idx, None);
        s.prev_change();
        assert_eq!(s.current_change_idx, None);
        assert_eq!(s.change_position(), "0/0");
    }
}

#[cfg(test)]
mod viewport_clamp_tests {
    use super::*;
    use crate::diff::ChangeType;

    fn state_with_rows(n: usize, mode: AlignmentMode) -> SideBySideState {
        let mut s = SideBySideState::new();
        s.alignment_mode = mode;
        s.aligned_rows = (0..n)
            .map(|_| AlignedRow {
                left_name: Some("a".to_string()),
                left_version: None,
                right_name: Some("a".to_string()),
                right_version: None,
                change_type: ChangeType::Modified,
                component_id: None,
            })
            .collect();
        s.recompute_row_model();
        s
    }

    /// Regression for the off-screen cursor: with the RIGHT panel focused,
    /// repeated scroll_down must keep the selection inside the scroll window
    /// (movement previously routed through the focused panel's offset only).
    #[test]
    fn row_scroll_follows_selection_regardless_of_focus() {
        let mut s = state_with_rows(30, AlignmentMode::Aligned);
        s.set_viewport_rows(10);
        s.focus_right = true;

        for _ in 0..15 {
            s.scroll_down();
        }
        assert_eq!(s.selected_row, 15);
        assert!(
            (s.left_scroll..s.left_scroll + 10).contains(&s.selected_row),
            "selection {} must be inside the window starting at {}",
            s.selected_row,
            s.left_scroll
        );
        assert_eq!(s.right_scroll, s.left_scroll, "panels stay in lockstep");
    }

    /// Regression for the hardcoded 20-row assumption: jumps use the real
    /// measured viewport height.
    #[test]
    fn scroll_to_row_respects_viewport_rows() {
        // 13 visible rows (the real 80x24 height): row 15 needs scrolling.
        let mut s = state_with_rows(30, AlignmentMode::Aligned);
        s.set_viewport_rows(13);
        s.scroll_to_row(15);
        assert!(
            s.left_scroll >= 3,
            "row 15 must be scrolled into a 13-row window, scroll={}",
            s.left_scroll
        );

        // 34 visible rows (120x40): row 15 is already visible, no scrolling.
        let mut s = state_with_rows(30, AlignmentMode::Aligned);
        s.set_viewport_rows(34);
        s.scroll_to_row(15);
        assert_eq!(s.left_scroll, 0, "no needless jump when already visible");
    }

    /// Every frame self-heals: recompute_row_model clamps a stale scroll.
    #[test]
    fn recompute_row_model_clamps_scroll() {
        let mut s = state_with_rows(30, AlignmentMode::Aligned);
        s.set_viewport_rows(10);
        s.selected_row = 25;
        s.left_scroll = 0;
        s.recompute_row_model();
        assert!(
            (s.left_scroll..s.left_scroll + 10).contains(&s.selected_row),
            "selection must be inside the window after recompute"
        );
        assert_eq!(s.right_scroll, s.left_scroll);
    }

    /// Unified reserves 2 rows of panel chrome (header + separator).
    #[test]
    fn unified_viewport_accounts_for_chrome() {
        let mut s = SideBySideState::new();
        s.alignment_mode = AlignmentMode::Unified;
        s.unified_entries = Vec::new();
        s.set_viewport_rows(10);
        s.selected_row = 20;
        s.clamp_scroll_to_selection();
        // visible = 10 - 2 = 8, so the window must start at >= 13.
        assert!(
            s.left_scroll >= 13,
            "Unified window must subtract its chrome, scroll={}",
            s.left_scroll
        );
    }
}
