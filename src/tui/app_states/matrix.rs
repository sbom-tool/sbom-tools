//! Matrix state types.

use crate::tui::views::MatrixPanel;
use super::multi_diff::{MultiViewSearchState, SortDirection};

pub struct MatrixState {
    pub selected_row: usize,
    pub selected_col: usize,
    pub sbom_count: usize,
    pub active_panel: MatrixPanel,
    /// Search state
    pub search: MultiViewSearchState,
    /// Sort by field
    pub sort_by: MatrixSortBy,
    /// Sort direction
    pub sort_direction: SortDirection,
    /// Similarity threshold filter
    pub threshold: SimilarityThreshold,
    /// Custom threshold value (0.0 - 1.0)
    pub custom_threshold: f64,
    /// Zoom/Focus mode - highlight single row/column
    pub focus_mode: bool,
    /// Focused row index (when focus_mode is true)
    pub focus_row: Option<usize>,
    /// Focused column index (when focus_mode is true)
    pub focus_col: Option<usize>,
    /// Show diff for selected pair
    pub show_pair_diff: bool,
    /// Show export options
    pub show_export_options: bool,
    /// Show clustering details
    pub show_clustering_details: bool,
    /// Highlight current row/column
    pub highlight_row_col: bool,
    /// Selected cluster index (for navigation)
    pub selected_cluster: usize,
    /// Total clusters
    pub total_clusters: usize,
}

impl MatrixState {
    pub fn new() -> Self {
        Self {
            selected_row: 0,
            selected_col: 1,
            sbom_count: 0,
            active_panel: MatrixPanel::Matrix,
            search: MultiViewSearchState::new(),
            sort_by: MatrixSortBy::default(),
            sort_direction: SortDirection::default(),
            threshold: SimilarityThreshold::default(),
            custom_threshold: 0.5,
            focus_mode: false,
            focus_row: None,
            focus_col: None,
            show_pair_diff: false,
            show_export_options: false,
            show_clustering_details: false,
            highlight_row_col: true,
            selected_cluster: 0,
            total_clusters: 0,
        }
    }

    pub fn new_with_size(count: usize) -> Self {
        Self {
            selected_row: 0,
            selected_col: if count > 1 { 1 } else { 0 },
            sbom_count: count,
            active_panel: MatrixPanel::Matrix,
            search: MultiViewSearchState::new(),
            sort_by: MatrixSortBy::default(),
            sort_direction: SortDirection::default(),
            threshold: SimilarityThreshold::default(),
            custom_threshold: 0.5,
            focus_mode: false,
            focus_row: None,
            focus_col: None,
            show_pair_diff: false,
            show_export_options: false,
            show_clustering_details: false,
            highlight_row_col: true,
            selected_cluster: 0,
            total_clusters: 0,
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_row > 0 {
            self.selected_row -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.sbom_count > 0 && self.selected_row < self.sbom_count - 1 {
            self.selected_row += 1;
        }
    }

    pub fn move_left(&mut self) {
        if self.selected_col > 0 {
            self.selected_col -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.sbom_count > 0 && self.selected_col < self.sbom_count - 1 {
            self.selected_col += 1;
        }
    }

    pub fn toggle_panel(&mut self) {
        self.active_panel = match self.active_panel {
            MatrixPanel::Matrix => MatrixPanel::Details,
            MatrixPanel::Details => MatrixPanel::Matrix,
        };
    }

    pub fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
    }

    pub fn toggle_sort_direction(&mut self) {
        self.sort_direction.toggle();
    }

    pub fn toggle_threshold(&mut self) {
        self.threshold = self.threshold.next();
    }

    pub fn toggle_focus_mode(&mut self) {
        self.focus_mode = !self.focus_mode;
        if self.focus_mode {
            self.focus_row = Some(self.selected_row);
            self.focus_col = Some(self.selected_col);
        } else {
            self.focus_row = None;
            self.focus_col = None;
        }
    }

    pub fn focus_on_row(&mut self, row: usize) {
        self.focus_mode = true;
        self.focus_row = Some(row);
        self.focus_col = None;
    }

    pub fn focus_on_col(&mut self, col: usize) {
        self.focus_mode = true;
        self.focus_row = None;
        self.focus_col = Some(col);
    }

    pub fn clear_focus(&mut self) {
        self.focus_mode = false;
        self.focus_row = None;
        self.focus_col = None;
    }

    pub fn toggle_pair_diff(&mut self) {
        // Only toggle if not same cell
        if self.selected_row != self.selected_col {
            self.show_pair_diff = !self.show_pair_diff;
        }
    }

    pub fn close_pair_diff(&mut self) {
        self.show_pair_diff = false;
    }

    pub fn toggle_export_options(&mut self) {
        self.show_export_options = !self.show_export_options;
    }

    pub fn close_export_options(&mut self) {
        self.show_export_options = false;
    }

    pub fn toggle_clustering_details(&mut self) {
        self.show_clustering_details = !self.show_clustering_details;
    }

    pub fn close_clustering_details(&mut self) {
        self.show_clustering_details = false;
    }

    pub fn toggle_row_col_highlight(&mut self) {
        self.highlight_row_col = !self.highlight_row_col;
    }

    pub fn select_next_cluster(&mut self) {
        if self.total_clusters > 0 && self.selected_cluster < self.total_clusters - 1 {
            self.selected_cluster += 1;
        }
    }

    pub fn select_prev_cluster(&mut self) {
        if self.selected_cluster > 0 {
            self.selected_cluster -= 1;
        }
    }

    /// Check if cell passes current threshold filter
    pub fn passes_threshold(&self, similarity: f64) -> bool {
        match self.threshold {
            SimilarityThreshold::None => true,
            SimilarityThreshold::High => similarity >= 0.9,
            SimilarityThreshold::Medium => similarity >= 0.7,
            SimilarityThreshold::Low => similarity < 0.5,
            SimilarityThreshold::Custom => similarity >= self.custom_threshold,
        }
    }

    /// Check if any modal/overlay is open
    pub fn has_overlay(&self) -> bool {
        self.show_pair_diff
            || self.show_export_options
            || self.show_clustering_details
            || self.search.active
    }
}

impl Default for MatrixState {
    fn default() -> Self {
        Self::new()
    }
}

/// Similarity threshold presets for matrix view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SimilarityThreshold {
    #[default]
    None,
    /// Show only high similarity (>= 90%)
    High,
    /// Show only medium similarity (>= 70%)
    Medium,
    /// Show only low similarity (< 50%)
    Low,
    /// Custom threshold (use threshold_value)
    Custom,
}

impl SimilarityThreshold {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "All",
            Self::High => ">= 90%",
            Self::Medium => ">= 70%",
            Self::Low => "< 50%",
            Self::Custom => "Custom",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Self::None => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low => Self::None,
            Self::Custom => Self::None,
        }
    }
}

/// Sort options for matrix view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatrixSortBy {
    #[default]
    Name,
    AvgSimilarity,
    ComponentCount,
    Cluster,
}

impl MatrixSortBy {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::AvgSimilarity => "Avg Similarity",
            Self::ComponentCount => "Components",
            Self::Cluster => "Cluster",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Name => Self::AvgSimilarity,
            Self::AvgSimilarity => Self::ComponentCount,
            Self::ComponentCount => Self::Cluster,
            Self::Cluster => Self::Name,
        }
    }
}

