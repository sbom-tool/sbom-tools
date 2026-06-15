//! Snapshot + key-event tests for the single-SBOM `ViewApp` TUI.
//!
//! Locks render output and event handling of the view-mode app before the
//! planned `App`/`ViewApp` unification. Render tests snapshot a [`TestBackend`]
//! buffer via `insta`; event tests drive the real key handler and assert on
//! `ViewApp` state.
//!
//! [`TestBackend`]: ratatui::backend::TestBackend

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{ViewApp, ViewTab, render};
use crate::tui::test_support::{
    AIBOM_BSI, DEMO_NEW, SIZES, aibom_single, demo_single, pin_theme, render_to_text,
};
use crate::tui::view::events::handle_key_event;

/// Build a `ViewApp` from the demo fixture with a deterministic tab.
///
/// `active_tab` is forced because the constructor restores the last-used tab
/// from on-disk `TuiPreferences`, which would make snapshots environment-dependent.
fn demo_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let (sbom, profile) = demo_single();
    let mut app = ViewApp::new(sbom, DEMO_NEW, profile);
    app.active_tab = active_tab;
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Render one view tab at a given size and return the trimmed buffer text.
fn render_tab(active_tab: ViewTab, width: u16, height: u16) -> String {
    let mut app = demo_view_app(active_tab);
    render_to_text(width, height, |frame| {
        render(frame, &mut app);
    })
}

/// The SBOM-profile view tabs (the demo fixture is a plain SBOM).
const VIEW_TABS: [(&str, ViewTab); 8] = [
    ("overview", ViewTab::Overview),
    ("tree", ViewTab::Tree),
    ("vulnerabilities", ViewTab::Vulnerabilities),
    ("licenses", ViewTab::Licenses),
    ("dependencies", ViewTab::Dependencies),
    ("quality", ViewTab::Quality),
    ("compliance", ViewTab::Compliance),
    ("source", ViewTab::Source),
];

#[test]
fn snapshot_all_view_tabs() {
    // The Overview tab renders the document's relative age (e.g. "1 year ago")
    // next to its fixed creation timestamp. The age is derived from `Utc::now()`
    // and drifts over time (and is truncated at narrow widths), so anchor on the
    // ISO timestamp and redact everything after it on that line.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\([^│\n]*",
        "$1 (AGE)",
    );
    // Lifecycle "Age: 728d" drifts daily; redact the day count.
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.bind(|| {
        for (name, tab) in VIEW_TABS {
            for (w, h) in SIZES {
                let text = render_tab(tab, w, h);
                insta::assert_snapshot!(format!("view_{name}_{w}x{h}"), text);
            }
        }
    });
}

// ============================================================================
// Key-event behaviour tests (real assertions, not snapshots)
// ============================================================================

#[test]
fn tab_switch_cycles_within_profile() {
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, ViewTab::Tree);

    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, ViewTab::Vulnerabilities);

    handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
    assert_eq!(app.active_tab, ViewTab::Tree);
}

#[test]
fn numeric_keys_jump_to_view_tab() {
    let mut app = demo_view_app(ViewTab::Overview);
    // Position 3 in the SBOM profile is Vulnerabilities.
    handle_key_event(&mut app, key(KeyCode::Char('3')));
    assert_eq!(app.active_tab, ViewTab::Vulnerabilities);
    handle_key_event(&mut app, key(KeyCode::Char('1')));
    assert_eq!(app.active_tab, ViewTab::Overview);
}

#[test]
fn help_overlay_toggles() {
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.show_help);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.show_help);
}

#[test]
fn tree_search_entry_activates_filter() {
    let mut app = demo_view_app(ViewTab::Tree);
    assert!(!app.tree_search_active);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(
        app.tree_search_active,
        "'/' on the Tree tab starts the inline tree filter"
    );
}

// ============================================================================
// AI-BOM (first-class profile) tests
// ============================================================================

/// Build a `ViewApp` from the BSI AI-BOM fixture with a deterministic tab.
fn aibom_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let (sbom, profile) = aibom_single();
    let mut app = ViewApp::new(sbom, AIBOM_BSI, profile);
    app.active_tab = active_tab;
    app
}

#[test]
fn aibom_fixture_detected_as_aibom_profile() {
    let (_sbom, profile) = aibom_single();
    assert_eq!(profile, crate::model::BomProfile::AiBom);
}

#[test]
fn aibom_view_app_uses_ai_readiness_scoring() {
    // The single shared `scoring_profile_for` must route AI-BOMs to the
    // dedicated AI-readiness scoring path (which activates the AI renderer).
    let app = aibom_view_app(ViewTab::AiReadiness);
    assert_eq!(
        app.quality_report.profile,
        crate::quality::ScoringProfile::AiReadiness
    );
}

#[test]
fn aibom_profile_exposes_ai_tab_suite() {
    let tabs = ViewTab::tabs_for_profile(crate::model::BomProfile::AiBom);
    assert!(tabs.contains(&ViewTab::Models));
    assert!(tabs.contains(&ViewTab::Datasets));
    assert!(tabs.contains(&ViewTab::AiReadiness));
}

/// The AI-BOM-profile view tabs (rendered from the BSI AI-BOM fixture).
const AIBOM_TABS: [(&str, ViewTab); 3] = [
    ("models", ViewTab::Models),
    ("datasets", ViewTab::Datasets),
    ("ai_readiness", ViewTab::AiReadiness),
];

#[test]
fn snapshot_aibom_tabs() {
    let mut settings = insta::Settings::clone_current();
    // Lifecycle/age content can drift; redact day counts defensively.
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.bind(|| {
        for (name, tab) in AIBOM_TABS {
            let mut app = aibom_view_app(tab);
            // Render at the wide size where AI panels have room to breathe.
            let text = render_to_text(120, 40, |frame| {
                render(frame, &mut app);
            });
            insta::assert_snapshot!(format!("aibom_{name}_120x40"), text);
        }
    });
}
