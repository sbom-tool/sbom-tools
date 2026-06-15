//! AI-readiness dashboard view for the AI-BOM TUI mode.
//!
//! Reuses the existing shared AI-readiness renderer in `shared::quality`. The
//! renderer is reached through `render_quality_summary`, which dispatches to
//! `render_ai_readiness_summary` when `report.profile == ScoringProfile::AiReadiness`.
//! The `ViewApp` quality report carries that profile for AI-BOMs (see
//! `scoring_profile_for`), so the dedicated panels activate here. The summary
//! is a self-contained dashboard (score, overview, per-check checklist, and
//! recommendations) and owns its own vertical layout, so it is rendered at the
//! full tab area.

use crate::tui::shared::quality as shared;
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::Rect;

/// Render the AI-Readiness tab (AI-BOM mode).
pub fn render_ai_readiness(frame: &mut Frame, area: Rect, app: &ViewApp) {
    shared::render_quality_summary(frame, area, &app.quality_report, 0);
}
