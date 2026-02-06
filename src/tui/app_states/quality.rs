//! Quality state types.

use crate::tui::state::ListNavigation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QualityViewMode {
    #[default]
    Summary,
    Breakdown,
    Metrics,
    Recommendations,
}

impl QualityViewMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Breakdown => "Score Breakdown",
            Self::Metrics => "Detailed Metrics",
            Self::Recommendations => "Recommendations",
        }
    }
}

pub struct QualityState {
    pub view_mode: QualityViewMode,
    pub selected_recommendation: usize,
    pub total_recommendations: usize,
    pub scroll_offset: usize,
}

impl QualityState {
    pub fn new() -> Self {
        Self {
            view_mode: QualityViewMode::Summary,
            selected_recommendation: 0,
            total_recommendations: 0,
            scroll_offset: 0,
        }
    }

    pub fn with_recommendations(total: usize) -> Self {
        Self {
            view_mode: QualityViewMode::Summary,
            selected_recommendation: 0,
            total_recommendations: total,
            scroll_offset: 0,
        }
    }

    pub fn toggle_view(&mut self) {
        self.view_mode = match self.view_mode {
            QualityViewMode::Summary => QualityViewMode::Breakdown,
            QualityViewMode::Breakdown => QualityViewMode::Metrics,
            QualityViewMode::Metrics => QualityViewMode::Recommendations,
            QualityViewMode::Recommendations => QualityViewMode::Summary,
        };
        self.selected_recommendation = 0;
        self.scroll_offset = 0;
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }
}

impl ListNavigation for QualityState {
    fn selected(&self) -> usize {
        self.selected_recommendation
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected_recommendation = idx;
    }

    fn total(&self) -> usize {
        self.total_recommendations
    }

    fn set_total(&mut self, total: usize) {
        self.total_recommendations = total;
    }
}

impl Default for QualityState {
    fn default() -> Self {
        Self::new()
    }
}

