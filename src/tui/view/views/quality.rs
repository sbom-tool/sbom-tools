//! Quality tab for ViewApp - delegates to shared rendering functions.

use crate::tui::shared::quality as shared;
use crate::tui::view::app::ViewApp;
use crate::tui::view::app::QualityViewMode;
use ratatui::{prelude::*, Frame};

pub fn render_quality(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let report = &app.quality_report;

    match app.quality_state.view_mode {
        QualityViewMode::Summary => shared::render_quality_summary(frame, area, report),
        QualityViewMode::Breakdown => shared::render_score_breakdown(frame, area, report),
        QualityViewMode::Metrics => shared::render_quality_metrics(frame, area, report),
        QualityViewMode::Recommendations => shared::render_quality_recommendations(
            frame,
            area,
            report,
            app.quality_state.selected_recommendation,
            app.quality_state.scroll_offset,
        ),
    }
}
