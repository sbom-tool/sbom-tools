//! Snapshot + key-event tests for the diff `App` TUI.
//!
//! These tests lock the render output and event-handling behaviour of the
//! diff-mode `App` before the planned `App`/`ViewApp` unification touches this
//! code. Render tests use `insta` string snapshots of a [`TestBackend`] buffer;
//! event tests drive the real key handlers and assert on `ViewState` accessors.
//!
//! [`TestBackend`]: ratatui::backend::TestBackend
//!
//! Note: the Components table is locked only at 80x24. At 120 wide the version
//! columns hit a ratatui width-distribution tie-break that resolves
//! non-deterministically across processes, so that one size is intentionally
//! skipped rather than asserted on a value that flaps.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, TabKind, render};
use crate::tui::events::handle_key_event;
use crate::tui::test_support::{DEMO_NEW, DEMO_OLD, SIZES, demo_diff, pin_theme, render_to_text};

/// Build a diff-mode `App` from the demo fixtures with a deterministic tab.
///
/// `active_tab` is forced rather than read from the constructor default because
/// `App::base` restores the last-used tab from on-disk `TuiPreferences`, which
/// would make snapshots depend on the developer's environment.
fn demo_app(active_tab: TabKind) -> App {
    pin_theme();
    let (diff, old, new) = demo_diff();
    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = active_tab;
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Render one diff tab at a given size and return the trimmed buffer text.
///
/// Encodes the documented call-ordering contract: `prepare_render` MUST run
/// before `render` builds a `RenderContext` from the app.
fn render_tab(active_tab: TabKind, width: u16, height: u16) -> String {
    let mut app = demo_app(active_tab);
    render_to_text(width, height, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    })
}

/// All diff tabs that the tabbed layout renders (multi-comparison modes use
/// dedicated full-screen renders and are not part of this matrix).
const DIFF_TABS: [(&str, TabKind); 10] = [
    ("summary", TabKind::Summary),
    ("components", TabKind::Components),
    ("dependencies", TabKind::Dependencies),
    ("licenses", TabKind::Licenses),
    ("vulnerabilities", TabKind::Vulnerabilities),
    ("quality", TabKind::Quality),
    ("compliance", TabKind::Compliance),
    ("sidebyside", TabKind::SideBySide),
    ("graph", TabKind::GraphChanges),
    ("source", TabKind::Source),
];

#[test]
fn snapshot_all_diff_tabs() {
    // Redact any "N(d|days|months|years) ago" fragments that some views derive
    // from `Utc::now()`. The demo fixture has no dated vulnerabilities today, so
    // this is defensive: it keeps snapshots stable if a fixture later gains them.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(r"\d+d ago", "Nd ago");
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.add_filter(
        r"\((?:today|in the future|(?:\d+|1) (?:days?|months?|years?) ago)\)",
        "(AGE)",
    );
    settings.bind(|| {
        for (name, tab) in DIFF_TABS {
            for (w, h) in SIZES {
                // The Components table at 120 wide hits a ratatui column-width
                // tie-break that resolves non-deterministically per process (the
                // version columns gain/lose one space of padding run-to-run). It
                // is locked only at 80x24; see the module-level note. All other
                // tabs are snapshotted at both sizes.
                if tab == TabKind::Components && w >= 120 {
                    continue;
                }
                let text = render_tab(tab, w, h);
                insta::assert_snapshot!(format!("diff_{name}_{w}x{h}"), text);
            }
        }
    });
}

// ============================================================================
// Key-event behaviour tests (real assertions, not snapshots)
// ============================================================================

#[test]
fn tab_switch_advances_and_wraps() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, TabKind::Components);

    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, TabKind::Dependencies);

    // Shift+Tab moves back.
    handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
    assert_eq!(app.active_tab, TabKind::Components);
}

#[test]
fn numeric_keys_jump_to_tab() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('5')));
    assert_eq!(app.active_tab, TabKind::Vulnerabilities);
    handle_key_event(&mut app, key(KeyCode::Char('2')));
    assert_eq!(app.active_tab, TabKind::Components);
}

#[test]
fn components_filter_toggle_cycles() {
    let mut app = demo_app(TabKind::Components);
    let initial = app.components_state().filter;
    handle_key_event(&mut app, key(KeyCode::Char('f')));
    assert_ne!(
        app.components_state().filter,
        initial,
        "'f' should advance the component filter"
    );
}

#[test]
fn components_sort_toggle_cycles() {
    let mut app = demo_app(TabKind::Components);
    let initial = app.components_state().sort_by;
    handle_key_event(&mut app, key(KeyCode::Char('s')));
    assert_ne!(
        app.components_state().sort_by,
        initial,
        "'s' should advance the component sort"
    );
}

#[test]
fn search_entry_opens_overlay_and_accepts_input() {
    let mut app = demo_app(TabKind::Components);
    assert!(!app.has_overlay());

    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(app.overlays.search.active, "'/' opens the search overlay");

    for c in ['l', 'o', 'd'] {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(app.overlays.search.query, "lod");

    handle_key_event(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.overlays.search.query, "lo");

    handle_key_event(&mut app, key(KeyCode::Esc));
    assert!(!app.overlays.search.active, "Esc closes the search overlay");
}

#[test]
fn detail_navigation_moves_component_selection() {
    let mut app = demo_app(TabKind::Components);
    // Totals are computed in prepare_render; needed for selection clamping.
    app.prepare_render();
    assert_eq!(app.components_state().selected, 0);

    handle_key_event(&mut app, key(KeyCode::Down));
    let after_down = app.components_state().selected;
    assert!(
        after_down >= 1 || app.components_state().total <= 1,
        "Down should advance selection when more than one item exists"
    );

    handle_key_event(&mut app, key(KeyCode::Up));
    assert_eq!(
        app.components_state().selected,
        0,
        "Up should return to the first item"
    );
}

#[test]
fn help_overlay_toggles() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.overlays.show_help);
    // Any key while help is open with '?' toggles it back off.
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.overlays.show_help);
}
