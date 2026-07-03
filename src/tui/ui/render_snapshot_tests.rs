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

#[test]
fn sidebyside_aligned_navigation_wired_via_prepare_render() {
    use crate::tui::app_states::AlignmentMode;

    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Aligned;
    // prepare_render must build the aligned-row cache AND populate the
    // navigation model (total_rows / change_indices) it drives.
    app.prepare_render();

    {
        let st = app.side_by_side_state();
        assert!(st.total_rows > 0, "aligned mode must populate total_rows");
        assert_eq!(
            st.total_rows,
            st.aligned_rows.len(),
            "total_rows must track the cached row list"
        );
        assert_eq!(
            st.change_indices.len(),
            st.total_rows,
            "every aligned row is a change row"
        );
    }

    app.side_by_side_state_mut().next_change();
    let st = app.side_by_side_state();
    assert_eq!(st.current_change_idx, Some(0));
    assert_eq!(
        st.selected_row, st.change_indices[0],
        "next_change must move the selected row onto the first change"
    );
}

#[test]
fn sidebyside_grouped_scroll_totals_unchanged() {
    use crate::tui::app_states::AlignmentMode;

    // demo_app leaves the side-by-side view in its default Grouped mode.
    let mut app = demo_app(TabKind::SideBySide);
    app.prepare_render();

    let (diff, _, _) = demo_diff();
    let expected_left = diff.components.removed.len() + diff.components.modified.len();
    let expected_right = diff.components.added.len() + diff.components.modified.len();

    let st = app.side_by_side_state();
    assert_eq!(st.alignment_mode, AlignmentMode::Grouped);
    assert_eq!(st.total_rows, 0, "grouped mode uses panel scrolling, not rows");
    assert!(st.change_indices.is_empty());
    assert_eq!(
        st.left_total, expected_left,
        "grouped left panel keeps removed+modified count"
    );
    assert_eq!(
        st.right_total, expected_right,
        "grouped right panel keeps added+modified count"
    );
}

// ============================================================================
// Diff-side alignment regression tests (PR-B): surface metadata changes,
// the CRA sidecar compliance verdict, component license changes, and ML-risk
// styling that the diff TUI previously dropped.
// ============================================================================

mod diff_alignment {
    use super::{App, TabKind, render};
    use crate::diff::{
        ComponentLicenseChange, DiffResult, FieldChange, MetadataChange, MetadataChangeKind,
    };
    use crate::model::{
        Component, ComponentType, CraSidecarMetadata, DatasetRef, MlModelInfo, NormalizedSbom,
    };
    use crate::quality::ComplianceLevel;
    use crate::tui::test_support::{pin_theme, render_to_text};

    /// Build a minimal diff-mode `App` from two empty SBOMs, then let the caller
    /// install a synthetic [`DiffResult`] so each test exercises exactly one
    /// diff signal. Raw source strings are placeholders (the Source tab is not
    /// under test here).
    fn app_with_result(result: DiffResult, tab: TabKind) -> App {
        pin_theme();
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let mut app = App::new_diff(result, old, new, "{}", "{}");
        app.active_tab = tab;
        app
    }

    fn render_tab_text(app: &mut App, w: u16, h: u16) -> String {
        render_to_text(w, h, |frame| {
            app.prepare_render();
            render(frame, app);
        })
    }

    #[test]
    fn summary_renders_metadata_changes_section() {
        let mut result = DiffResult::new();
        result.metadata_changes = vec![
            MetadataChange {
                field: "spec_version".to_string(),
                old_value: Some("1.5".to_string()),
                new_value: Some("1.7".to_string()),
                kind: MetadataChangeKind::Modified,
            },
            MetadataChange {
                field: "signature.algorithm".to_string(),
                old_value: None,
                new_value: Some("Ed25519".to_string()),
                kind: MetadataChangeKind::Added,
            },
        ];
        result.calculate_summary();
        // The bug: total_changes counts metadata changes, so the header must not
        // claim changes the body never shows.
        assert_eq!(result.summary.total_changes, 2);

        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            text.contains("spec_version"),
            "metadata field must be listed in the diff summary:\n{text}"
        );
        assert!(
            text.contains("META"),
            "metadata changes must carry a META badge:\n{text}"
        );
        assert!(
            text.contains("1.5") && text.contains("1.7"),
            "old -> new metadata values must render:\n{text}"
        );
    }

    fn high_risk_ml_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        let mut model = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        model.component_type = ComponentType::MachineLearningModel;
        // Bare ML metadata: Annex IV documentation gaps are present.
        model.ml_model = Some(MlModelInfo::default());
        sbom.components.insert(model.canonical_id.clone(), model);
        sbom
    }

    #[test]
    fn high_risk_ai_sidecar_marks_ai_act_non_compliant() {
        // Without a high-risk sidecar the bare ML SBOM passes AI-Act (gaps are
        // advisory). The diff App must apply the sidecar so the verdict flips,
        // matching the CLI.
        let new = high_risk_ml_sbom();
        let old = high_risk_ml_sbom();
        let mut app = App::new_diff(DiffResult::new(), old, new, "{}", "{}");
        app = app.with_cra_sidecar(CraSidecarMetadata {
            is_high_risk_ai: true,
            ..Default::default()
        });

        app.ensure_compliance_results();

        let results = app
            .data
            .new_compliance_results
            .as_ref()
            .expect("compliance results computed");
        let ai_act = results
            .iter()
            .find(|r| r.level == ComplianceLevel::EuAiAct)
            .expect("AI-Act standard present");
        assert!(
            !ai_act.is_compliant,
            "high-risk AI SBOM with Annex IV gaps must be NON-COMPLIANT in the diff TUI"
        );
        assert!(ai_act.error_count > 0, "gaps must escalate to errors");
    }

    #[test]
    fn without_sidecar_ai_act_stays_compliant() {
        // Guards the inverse: the escalation must be sidecar-driven, not a
        // blanket failure for any ML SBOM.
        let new = high_risk_ml_sbom();
        let old = high_risk_ml_sbom();
        let mut app = App::new_diff(DiffResult::new(), old, new, "{}", "{}");
        app.ensure_compliance_results();

        let results = app.data.new_compliance_results.as_ref().unwrap();
        let ai_act = results
            .iter()
            .find(|r| r.level == ComplianceLevel::EuAiAct)
            .unwrap();
        assert!(
            ai_act.is_compliant,
            "non-high-risk ML SBOM gaps are advisory, not blocking"
        );
    }

    #[test]
    fn licenses_tab_lists_component_changes_without_aggregates() {
        // Only per-component churn (no net new/removed license across the SBOM):
        // previously the tab early-returned "No license changes detected".
        let mut result = DiffResult::new();
        result.licenses.component_changes = vec![ComponentLicenseChange {
            component_id: "pkg:cargo/libfoo@1.0.0".to_string(),
            component_name: "libfoo".to_string(),
            old_licenses: vec!["MIT".to_string()],
            new_licenses: vec!["GPL-3.0-only".to_string()],
        }];

        let mut app = app_with_result(result, TabKind::Licenses);
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            !text.contains("No license changes detected"),
            "component license churn must not be reported as no changes:\n{text}"
        );
        assert!(
            text.contains("Component License Changes"),
            "the component license-change panel must render:\n{text}"
        );
        assert!(
            text.contains("libfoo") && text.contains("GPL-3.0-only"),
            "the changed component and its new license must be listed:\n{text}"
        );
    }

    /// Build a modified-component change carrying an `ml_training_dataset`
    /// removal field change (old value present, new absent), as the diff engine
    /// emits for provenance loss.
    fn training_dataset_removal_change() -> DiffResult {
        let mut old = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        old.component_type = ComponentType::MachineLearningModel;
        old.ml_model = Some(MlModelInfo {
            training_datasets: vec![DatasetRef {
                reference: Some("dataset-1".to_string()),
                name: Some("reviews".to_string()),
                purl: None,
            }],
            ..MlModelInfo::default()
        });

        let mut new = old.clone();
        new.ml_model = Some(MlModelInfo::default());

        let mut change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0);
        change.field_changes = vec![FieldChange {
            field: "ml_training_dataset".to_string(),
            old_value: Some("dataset-1".to_string()),
            new_value: None,
        }];

        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();
        result
    }

    #[test]
    fn component_detail_flags_training_dataset_removal() {
        let mut app = app_with_result(training_dataset_removal_change(), TabKind::Components);
        // Selection clamping + master/detail totals are computed in prepare_render.
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            text.contains("ml_training_dataset"),
            "the field key must still render:\n{text}"
        );
        assert!(
            text.contains("PROVENANCE LOSS"),
            "training-dataset removal must carry a provenance-loss risk badge:\n{text}"
        );
    }
}

#[test]
fn diff_tab_click_selects_the_rendered_tab_including_source() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use unicode_width::UnicodeWidthStr;

    let mut app = demo_app(TabKind::Summary);
    // Wide enough that every tab (incl. the rightmost Source) is on-screen.
    // Tab titles render on row 2 (header Length(2) + Tabs' top row).
    let text = render_to_text(240, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let tab_row = text.lines().nth(2).expect("tab bar row").to_string();

    // Both sit past where the old fixed-13-col estimate placed them; "Source"
    // (rightmost) was entirely unreachable before this fix.
    for (needle, expected) in [
        ("Vulnerabilities", TabKind::Vulnerabilities),
        ("Source", TabKind::Source),
    ] {
        let byte = tab_row
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not in tab row: {tab_row:?}"));
        let col = UnicodeWidthStr::width(&tab_row[..byte]) as u16; // display col, not byte
        app.active_tab = TabKind::Summary;
        handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: col,
                row: 2,
                modifiers: KeyModifiers::empty(),
            },
        );
        assert_eq!(app.active_tab, expected, "click on {needle} @col {col}");
    }
}
