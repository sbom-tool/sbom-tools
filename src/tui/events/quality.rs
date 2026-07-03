//! Quality tab event handlers.

use crate::quality::RecommendationCategory;
use crate::tui::App;
use crate::tui::traits::{EventResult, TabTarget, ViewContext, ViewMode, ViewState};
use crossterm::event::KeyEvent;

pub(super) fn handle_quality_keys(app: &mut App, key: KeyEvent) -> bool {
    let quality_view = &mut app.quality_view;

    let mut ctx = ViewContext {
        mode: ViewMode::from_app_mode(app.mode),
        focused: true,
        width: 0,
        height: 0,
        tick: app.tick,
        status_message: &mut app.status_message,
    };

    let result = quality_view.handle_key(key, &mut ctx);
    let consumed = !matches!(result, EventResult::Ignored);

    // Handle Enter on recommendation → navigate to related tab
    if quality_view.enter_requested {
        quality_view.enter_requested = false;
        let selected = quality_view.inner().selected_recommendation;

        // Look up the recommendation's category from the quality report
        let target = app
            .data
            .new_quality
            .as_ref()
            .or(app.data.old_quality.as_ref())
            .and_then(|report| report.recommendations.get(selected))
            .map(|rec| match rec.category {
                RecommendationCategory::Compliance => TabTarget::Compliance,
                RecommendationCategory::Identifiers
                | RecommendationCategory::Completeness
                | RecommendationCategory::Licenses => TabTarget::Components,
                RecommendationCategory::Vulnerabilities => TabTarget::Vulnerabilities,
                RecommendationCategory::Dependencies => TabTarget::Dependencies,
                _ => TabTarget::Quality,
            });

        if let Some(target) = target
            && target != TabTarget::Quality
        {
            app.status_message = Some(format!(
                "Navigated to {} for recommendation",
                target.to_tab_kind().map_or("tab", |k| k.title())
            ));
            app.handle_event_result(EventResult::NavigateTo(target));
            return true;
        }
    }

    if let EventResult::StatusMessage(msg) = result {
        app.status_message = Some(msg);
    }
    consumed
}
