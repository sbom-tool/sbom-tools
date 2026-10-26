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
    pin_snapshot_compliance(&mut app);
    render_to_text(width, height, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    })
}

/// Keep render fixtures independent of the Article 14 calendar boundary.
/// Deadline transitions are exercised by the compliance module's clock tests.
fn pin_snapshot_compliance(app: &mut App) {
    use crate::quality::{ComplianceChecker, ComplianceLevel, QualityScorer};
    let as_of = chrono::DateTime::parse_from_rfc3339("2026-04-26T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let results = |sbom: &crate::model::NormalizedSbom| {
        ComplianceLevel::all()
            .iter()
            .map(|level| ComplianceChecker::new(*level).with_as_of(as_of).check(sbom))
            .collect()
    };
    for (sbom, quality, cra, compliance) in [
        (
            &app.data.old_sbom,
            &mut app.data.old_quality,
            &mut app.data.old_cra_compliance,
            &mut app.data.old_compliance_results,
        ),
        (
            &app.data.new_sbom,
            &mut app.data.new_quality,
            &mut app.data.new_cra_compliance,
            &mut app.data.new_compliance_results,
        ),
    ] {
        let sbom = sbom.as_ref().unwrap();
        let profile = crate::tui::scoring_profile_for(crate::model::BomProfile::detect(sbom));
        *quality = Some(QualityScorer::new(profile).with_as_of(as_of).score(sbom));
        *cra = Some(
            ComplianceChecker::new(ComplianceLevel::CraPhase2)
                .with_as_of(as_of)
                .check(sbom),
        );
        *compliance = Some(results(sbom));
    }
    // The constructor derived this from wall-clock reports; keep the delta
    // coherent with the pinned reports consumed by the renderer.
    if let (Some(old), Some(new), Some(diff)) = (
        app.data.old_quality.as_ref(),
        app.data.new_quality.as_ref(),
        app.data.diff_result.as_mut(),
    ) {
        diff.quality_delta = Some(crate::diff::QualityDelta::from_reports(old, new));
    }
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

/// The diff-mode detail panel must render the RANSOMWARE badge for an
/// introduced ransomware-KEV vulnerability (the flag was previously dropped at
/// the `VulnerabilityDetail` boundary, leaving the badge unreachable in diff
/// mode).
#[test]
fn diff_vuln_detail_shows_ransomware_badge() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let mut vuln = crate::model::VulnerabilityRef::new(
        "CVE-2021-44228".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    vuln.is_kev = true;
    let mut kev = crate::model::KevInfo::new(
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::days(30),
        "patch".to_string(),
    );
    kev.known_ransomware_use = true;
    vuln.kev_info = Some(kev);

    let comp = crate::model::Component::new(
        "log4j-core".to_string(),
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0".to_string(),
    );
    diff.vulnerabilities
        .introduced
        .push(crate::diff::VulnerabilityDetail::from_ref(&vuln, &comp));

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // The injected severity-less vuln sorts last behind the demo fixture's
    // own introduced vulns; select it so the detail panel shows it.
    app.prepare_render();
    handle_key_event(&mut app, key(KeyCode::End));
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("RANSOMWARE"),
        "diff-mode detail panel must render the RANSOMWARE badge:\n{text}"
    );
}

/// The Graph Changes master table drops its Details column below 60 inner
/// columns (at 80x24 the Min(30) Details column collapsed to zero width and
/// squeezed Component into unreadability).
#[test]
fn graph_details_column_gated_by_width() {
    pin_theme();

    fn render_with_graph_change(width: u16, height: u16) -> String {
        let (mut diff, old, new) = demo_diff();
        diff.graph_changes.push(crate::diff::DependencyGraphChange {
            component_id: crate::model::CanonicalId::from_name_version(
                "acme-webapp",
                Some("2.0.0"),
            ),
            component_name: "acme-webapp".to_string(),
            change: crate::diff::DependencyChangeType::DependencyAdded {
                dependency_id: crate::model::CanonicalId::from_name_version(
                    "left-pad",
                    Some("1.3.0"),
                ),
                dependency_name: "left-pad".to_string(),
            },
            impact: crate::diff::GraphChangeImpact::Medium,
        });
        // graph_summary marks "graph analysis actually ran" — without it the
        // tab honestly renders the not-run empty state instead of the table.
        diff.graph_summary = Some(crate::diff::GraphChangeSummary::from_changes(
            &diff.graph_changes,
        ));
        let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
        app.active_tab = TabKind::GraphChanges;
        render_to_text(width, height, |frame| {
            app.prepare_render();
            render(frame, &mut app);
        })
    }

    // Assert on the table header row (the line containing both Impact and
    // Type) — "Details" also appears in the " Change Details " pane title, so
    // a whole-buffer check would false-positive.
    let header_line = |text: &str| -> String {
        text.lines()
            .find(|l| l.contains("Impact") && l.contains("Type"))
            .expect("graph changes table header must render")
            .to_string()
    };

    let narrow = render_with_graph_change(80, 24);
    assert!(
        !header_line(&narrow).contains("Details"),
        "at 80 cols the Details column must be dropped"
    );
    assert!(
        header_line(&narrow).contains("Component"),
        "Component column must survive at 80 cols"
    );

    let wide = render_with_graph_change(120, 40);
    assert!(
        header_line(&wide).contains("Details"),
        "at 120 cols the Details column must render"
    );
}

#[test]
fn help_overlay_toggles() {
    // '?' and K are one surface now: the shortcuts overlay with a This-Tab
    // section from the active tab's ViewState::shortcuts().
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.overlays.shortcuts.visible);
    assert_eq!(
        app.overlays.shortcuts.context,
        crate::tui::app::ShortcutsContext::Diff
    );
    assert_eq!(app.overlays.shortcuts.tab_title.as_deref(), Some("Summary"));
    assert!(!app.overlays.shortcuts.tab_items.is_empty());
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.overlays.shortcuts.visible, "'?' must toggle closed");

    // K opens the same surface and closes on K.
    handle_key_event(&mut app, key(KeyCode::Char('K')));
    assert!(app.overlays.shortcuts.visible);
    handle_key_event(&mut app, key(KeyCode::Char('K')));
    assert!(
        !app.overlays.shortcuts.visible,
        "K must close the overlay it opened (was dead code behind has_overlay)"
    );

    // Regression: the Dependencies tab used to swallow '?' for its own
    // bespoke help overlay, so the unified surface never opened there.
    let mut app = demo_app(TabKind::Dependencies);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(
        app.overlays.shortcuts.visible,
        "'?' on Dependencies must open the unified shortcuts overlay"
    );
    assert_eq!(
        app.overlays.shortcuts.tab_title.as_deref(),
        Some("Dependencies")
    );
    assert!(
        app.overlays
            .shortcuts
            .tab_items
            .iter()
            .any(|(k, _)| k == "y"),
        "the old deps-help rows (e.g. y/copy path) must live in shortcuts()"
    );
}

#[test]
fn shortcuts_overlay_scrolls_when_clipped() {
    // At 80x24 the box is 20 rows; the Diff context + This-Tab section
    // exceeds that, so j/k must reveal the hidden tail instead of clipping.
    pin_theme();
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        app.overlays.shortcuts.max_scroll > 0,
        "content taller than the box must expose a scroll range:\n{text}"
    );
    assert!(
        text.contains("more"),
        "the clipped overlay must advertise its hidden rows:\n{text}"
    );
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.overlays.shortcuts.scroll, 1, "j must scroll down");
    handle_key_event(&mut app, key(KeyCode::Up));
    assert_eq!(app.overlays.shortcuts.scroll, 0, "Up must scroll back");
    for _ in 0..500 {
        handle_key_event(&mut app, key(KeyCode::Down));
    }
    assert_eq!(
        app.overlays.shortcuts.scroll, app.overlays.shortcuts.max_scroll,
        "scroll must clamp to the measured ceiling"
    );
    // Reopening resets the offset.
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert_eq!(app.overlays.shortcuts.scroll, 0);
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

    // Grouped is no longer the default (Aligned is); force it explicitly.
    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Grouped;
    app.prepare_render();

    let (diff, _, _) = demo_diff();
    let expected_left = diff.components.removed.len() + diff.components.modified.len();
    let expected_right = diff.components.added.len() + diff.components.modified.len();

    let st = app.side_by_side_state();
    assert_eq!(st.alignment_mode, AlignmentMode::Grouped);
    assert_eq!(
        st.total_rows, 0,
        "grouped mode uses panel scrolling, not rows"
    );
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
        let sidecar = CraSidecarMetadata {
            is_high_risk_ai: true,
            ..Default::default()
        };
        app = app.with_cra_sidecars(Some(sidecar.clone()), Some(sidecar));

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

    /// Build a modified model-a change with one ml_metric field change.
    fn ml_metric_change(metric: &str, old_v: &str, new_v: &str) -> DiffResult {
        let old = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        let new = old.clone();
        let mut change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0);
        change.field_changes = vec![FieldChange {
            field: format!("ml_metric:{metric}"),
            old_value: Some(old_v.to_string()),
            new_value: Some(new_v.to_string()),
        }];
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();
        result
    }

    /// The CLI's --fail-on-ml-regression signal must be visible interactively:
    /// the Summary names each regressed metric with its transition.
    #[test]
    fn summary_lists_ml_regressions() {
        let mut result = DiffResult::default();
        result.ml_regressions.push(crate::diff::MlRegression {
            component: "model-a".to_string(),
            metric: "accuracy".to_string(),
            previous_value: 0.9,
            new_value: 0.8,
        });
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("ML REGRESSION"),
            "summary must badge the regression:\n{text}"
        );
        assert!(
            text.contains("model-a accuracy: 0.90 \u{2192} 0.80"),
            "summary must name the component, metric and transition:\n{text}"
        );
    }

    /// Regression for the inverted-color bug: a dropped accuracy previously
    /// painted green (added). Text snapshots drop color, so the direction
    /// arrow is the observable contract.
    #[test]
    fn component_detail_ml_metric_regression_shows_down_arrow() {
        let mut result = ml_metric_change("accuracy", "0.9", "0.8");
        // The CLI populates ml_regressions for regressed components; the
        // detail panel must badge them.
        result.ml_regressions.push(crate::diff::MlRegression {
            component: "model-a".to_string(),
            metric: "accuracy".to_string(),
            previous_value: 0.9,
            new_value: 0.8,
        });
        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("ML REGRESSION"),
            "detail panel must badge the regressed component:\n{text}"
        );
        assert!(
            text.contains("\u{25bc}"),
            "regressed metric must carry a down arrow:\n{text}"
        );
        assert!(
            !text.contains("\u{25b2}"),
            "regressed metric must not carry an up arrow:\n{text}"
        );

        let mut app = app_with_result(
            ml_metric_change("accuracy", "0.8", "0.9"),
            TabKind::Components,
        );
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("\u{25b2}"),
            "improved metric must carry an up arrow:\n{text}"
        );
    }

    /// A fuzzy match must expose its confidence interval and normalization
    /// audit trail; previously a fuzzy 0.75 rendered identically to a
    /// near-exact 0.75.
    #[test]
    fn match_panel_shows_ci_and_normalizations() {
        let old = Component::new("fuzzy-lib".to_string(), "fuzzy-lib".to_string())
            .with_version("1.0".to_string());
        let new = old.clone();
        let mut mi = crate::diff::MatchInfo::simple(0.75, "Fuzzy", "name similarity");
        mi.normalizations = vec!["lowercase".to_string(), "suffix_stripped".to_string()];
        let change =
            crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0).with_match_info(mi);
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();

        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("CI: 0.67\u{2013}0.83 (95%)"),
            "Fuzzy tier margin is 0.08 -> CI 0.67-0.83:\n{text}"
        );
        assert!(
            text.contains("Normalized: lowercase, suffix_stripped"),
            "normalization audit trail must render:\n{text}"
        );
    }

    /// #76: a point score outside its own displayed confidence interval must
    /// be annotated — 'Score: 1.00' must not sit unexplained beside a CI
    /// that excludes it.
    #[test]
    fn match_panel_annotates_score_outside_ci() {
        let old = Component::new("fuzzy-lib".to_string(), "fuzzy-lib".to_string())
            .with_version("1.0".to_string());
        let new = old.clone();
        let mi = crate::diff::MatchInfo::simple(1.0, "Fuzzy", "name similarity")
            .with_confidence_interval(crate::diff::ConfidenceInterval::new(0.83, 0.99, 0.95));
        let change =
            crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0).with_match_info(mi);
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();

        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("score outside CI"),
            "a score excluded by its CI must be annotated:\n{text}"
        );

        // Sanity: an in-interval score stays unannotated.
        let old = Component::new("fuzzy-lib".to_string(), "fuzzy-lib".to_string())
            .with_version("1.0".to_string());
        let new = old.clone();
        let mi = crate::diff::MatchInfo::simple(0.9, "Fuzzy", "name similarity")
            .with_confidence_interval(crate::diff::ConfidenceInterval::new(0.83, 0.99, 0.95));
        let change =
            crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0).with_match_info(mi);
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();
        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("CI: 0.83\u{2013}0.99 (95%)") && !text.contains("score outside CI"),
            "an in-interval score must not be annotated:\n{text}"
        );
    }

    fn vuln_detail(
        id: &str,
        vex: Option<crate::model::VexState>,
    ) -> crate::diff::VulnerabilityDetail {
        let vref = crate::model::VulnerabilityRef::new(
            id.to_string(),
            crate::model::VulnerabilitySource::Osv,
        );
        let comp =
            crate::model::Component::new("libv".to_string(), "pkg:npm/libv@1.0.0".to_string());
        let mut detail = crate::diff::VulnerabilityDetail::from_ref(&vref, &comp);
        detail.vex_state = vex;
        detail
    }

    /// introduced_without_vex is the security worklist; it is computed but was
    /// never rendered. The card must show gap counts and the by_state tail.
    #[test]
    fn vex_card_lists_gap_counts() {
        let mut result = DiffResult::default();
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0001", None));
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0002", None));
        result
            .vulnerabilities
            .persistent
            .push(vuln_detail("CVE-2024-0003", None));
        result.vulnerabilities.introduced.push(vuln_detail(
            "CVE-2024-0004",
            Some(crate::model::VexState::Affected),
        ));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        for needle in ["Gaps:", "2 new", "1 ongoing", "AF:1"] {
            assert!(
                text.contains(needle),
                "VEX card must render {needle}:\n{text}"
            );
        }
    }

    /// Regression for the gate relaxation: a diff whose vulns have ZERO VEX
    /// coverage — the pure gap case — previously hid the card entirely.
    #[test]
    fn vex_card_renders_with_zero_coverage() {
        let mut result = DiffResult::default();
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0001", None));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("VEX: 0%"),
            "zero-coverage card must render with 0%:\n{text}"
        );
        assert!(
            text.contains("Gaps:") && text.contains("1 new"),
            "gap line must render:\n{text}"
        );
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

    /// App::new_diff must backfill the engine QualityDelta when the pipeline
    /// didn't provide one (TUI-only construction paths previously saw None,
    /// hiding the Quality Impact card and the regression chips).
    #[test]
    fn new_diff_backfills_quality_delta() {
        let app = app_with_result(DiffResult::default(), TabKind::Quality);
        assert!(
            app.data
                .diff_result
                .as_ref()
                .is_some_and(|r| r.quality_delta.is_some()),
            "constructor must backfill quality_delta from the scored reports"
        );
    }

    /// The Quality tab renders the engine's regressed/improved chips, the
    /// violation delta, and ALL category transitions (the previous 4-category
    /// recompute silently omitted Integrity/Provenance regressions).
    #[test]
    fn quality_tab_renders_engine_delta() {
        let mut result = DiffResult::default();
        // overall_score_delta 0.0: both fixture SBOMs are empty, so the tab
        // only trusts the engine delta when it matches the displayed 0-point
        // transition (profile-mismatch guard in render_diff_quality).
        result.quality_delta = Some(crate::diff::QualityDelta {
            overall_score_delta: 0.0,
            old_grade: None,
            new_grade: None,
            category_deltas: vec![
                crate::diff::CategoryDelta {
                    category: "Integrity".to_string(),
                    old_score: 80.0,
                    new_score: 60.0,
                    delta: -20.0,
                },
                crate::diff::CategoryDelta {
                    category: "Licenses".to_string(),
                    old_score: 50.0,
                    new_score: 70.0,
                    delta: 20.0,
                },
            ],
            regressions: vec!["Provenance".to_string(), "Integrity".to_string()],
            improvements: vec!["Licenses".to_string()],
            violation_count_delta: 2,
        });
        let mut app = app_with_result(result, TabKind::Quality);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            // The engine's "Integrity" category displays as "Hashes" — one
            // name per category across the header, chart, and chips.
            text.contains("Regressed: Provenance, Hashes"),
            "regression chips must render (Integrity displayed as Hashes):\n{text}"
        );
        assert!(
            text.contains("Improved: Licenses"),
            "improvement chips must render:\n{text}"
        );
        assert!(
            text.contains("Compliance violations: +2"),
            "violation delta must render:\n{text}"
        );
        assert!(
            text.contains("Integrity: 80% → 60%"),
            "Integrity transition (previously invisible) must render:\n{text}"
        );
    }

    /// The Licenses tab leads with a before→after risk posture header.
    #[test]
    fn licenses_tab_renders_delta_header() {
        let mut result = DiffResult::default();
        result
            .licenses
            .new_licenses
            .push(crate::diff::LicenseChange {
                license: "GPL-3.0-only".to_string(),
                components: vec!["libx".to_string()],
                family: "GPL".to_string(),
            });
        result
            .licenses
            .removed_licenses
            .push(crate::diff::LicenseChange {
                license: "MIT".to_string(),
                components: vec!["liby".to_string()],
                family: "MIT".to_string(),
            });
        let mut app = app_with_result(result, TabKind::Licenses);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("Licenses: +1 new"),
            "header title must render:\n{text}"
        );
        assert!(
            text.contains("High/Critical: 0 \u{2192} 1"),
            "risk transition must render (GPL is High risk):\n{text}"
        );
        assert!(
            text.contains("regressed"),
            "posture label must render:\n{text}"
        );
    }

    /// Compliance selection must be visible without color: the selected row
    /// carries a \u{25b6} marker.
    #[test]
    fn compliance_selection_marker_visible() {
        let mut app = super::demo_app(TabKind::Compliance);
        // Cycle Overview -> NewViolations so a violation table renders.
        crate::tui::events::handle_key_event(
            &mut app,
            super::key(crossterm::event::KeyCode::Char('v')),
        );
        let text = render_to_text(120, 40, |frame| {
            app.prepare_render();
            render(frame, &mut app);
        });
        assert!(
            text.contains("\u{25b6} ERROR")
                || text.contains("\u{25b6} WARN")
                || text.contains("\u{25b6} INFO"),
            "selected violation row must carry the marker:\n{text}"
        );
    }

    /// Multi-ecosystem diffs render grouped +/-/~ bars; single-ecosystem
    /// diffs render a labelled tally row instead of a labelless bar.
    #[test]
    fn ecosystem_chart_is_semantic() {
        fn comp(name: &str, eco: &str) -> crate::diff::ComponentChange {
            let component = Component::new(name.to_string(), format!("pkg:{eco}/{name}@1.0.0"));
            let mut c = crate::diff::ComponentChange::added(&component, 0);
            c.ecosystem = Some(eco.to_string());
            c
        }
        // Two ecosystems -> grouped bars with +/-/~ labels.
        let mut result = DiffResult::default();
        for i in 0..3 {
            result.components.added.push(comp(&format!("np{i}"), "npm"));
        }
        result.components.removed.push(comp("py0", "pypi"));
        result.components.modified.push(comp("py1", "pypi"));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("npm") && text.contains("pypi"),
            "both ecosystem groups must label:\n{text}"
        );
        // The semantic +/-/~ bar-label row is what distinguishes the grouped
        // chart from the old flat per-ecosystem bars.
        assert!(
            text.contains(" +  -  ~"),
            "grouped chart must label its +/-/~ bars:\n{text}"
        );

        // Single ecosystem -> tally row, no bar glyphs in that panel.
        let mut result = DiffResult::default();
        for i in 0..4 {
            result.components.added.push(comp(&format!("np{i}"), "npm"));
        }
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        // The full labelled tally row — "+4" alone also appears in the All
        // Changes panel title, which would make this assertion vacuous.
        assert!(
            text.contains("npm          +4  -0  ~0"),
            "single ecosystem must render the labelled tally row:\n{text}"
        );
    }
}

// ============================================================================
// Applicability (N/A) rendering: the diff compliance tab and the policy
// widget must never render an unevaluated standard as a pass. Readiness
// profiles keep `is_compliant = true` for out-of-scope SBOMs by contract,
// so every surface has to gate on `is_applicable()` first.
// ============================================================================

#[test]
fn diff_compliance_na_standard_renders_na_not_pass() {
    use crate::quality::ComplianceLevel;

    // The demo fixtures are ordinary (non-AI) SBOMs: the EU AI Act
    // readiness profile does not evaluate them.
    let mut app = demo_app(TabKind::Compliance);
    let ai_idx = ComplianceLevel::all()
        .iter()
        .position(|l| *l == ComplianceLevel::EuAiAct)
        .expect("EU AI Act must be in ComplianceLevel::all()");
    app.compliance_view.inner_mut().selected_standard = ai_idx;

    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });

    assert!(
        text.contains("N/A \u{2192} N/A"),
        "header must render N/A for both unevaluated sides:\n{text}"
    );
    assert!(
        text.contains("not applicable"),
        "delta label must read 'not applicable', not a trend:\n{text}"
    );
    assert!(
        !text.contains("PASS 100%"),
        "an unevaluated standard must never render as a pass:\n{text}"
    );
    assert!(
        !text.contains("PASS") && !text.contains("FAIL"),
        "no verdict text may render for an unevaluated standard:\n{text}"
    );
}

#[test]
fn diff_compliance_header_uses_shared_score_formula() {
    // The header percentage must come from ComplianceResult::score()
    // (100/(errors+warnings+1), Info-neutral) — the same formula the
    // exports and markdown/HTML reports render — not a bespoke weighting.
    let mut app = demo_app(TabKind::Compliance);
    let idx = app.diff_compliance_state().selected_standard;
    app.ensure_compliance_results();
    let expected: Vec<Option<u8>> = [
        &app.data.old_compliance_results,
        &app.data.new_compliance_results,
    ]
    .iter()
    .map(|results| results.as_ref().expect("computed")[idx].score())
    .collect();

    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });

    let old_pct = expected[0].expect("demo standard is applicable");
    let new_pct = expected[1].expect("demo standard is applicable");
    assert!(
        text.contains(&format!("{old_pct}% \u{2192}")) && text.contains(&format!("{new_pct}%")),
        "header must render the shared score ({old_pct}% -> {new_pct}%):\n{text}"
    );
}

#[test]
fn policy_preset_na_standard_is_not_rendered_as_pass() {
    use crate::tui::app_states::PolicyPreset;

    let mut app = demo_app(TabKind::Summary);
    app.compliance_state.policy_preset = PolicyPreset::EuAiAct;
    app.run_compliance_check();

    let result = app
        .compliance_state
        .result
        .as_ref()
        .expect("compliance check ran");
    assert!(
        result.not_applicable.is_some(),
        "EU AI Act must be not-applicable for the non-AI demo SBOM"
    );

    // Status line: NOT APPLICABLE, never "COMPLIANT (score: 99)".
    let msg = app.status_message.clone().expect("status message set");
    assert!(
        msg.contains("NOT APPLICABLE"),
        "status must report N/A: {msg}"
    );
    assert!(
        !msg.contains("score"),
        "an unevaluated standard has no score: {msg}"
    );

    // Summary-tab policy widget: N/A badge, no PASS badge, no score.
    // Scope the assertions to the widget's own line — the quality card and
    // the footer legitimately render "Score:" elsewhere on this tab.
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let policy_line = text
        .lines()
        .find(|l| l.contains("Policy:"))
        .unwrap_or_else(|| panic!("policy widget must render on the summary tab:\n{text}"))
        .to_string();
    assert!(
        policy_line.contains("N/A"),
        "policy widget must show an N/A badge: {policy_line}"
    );
    assert!(
        !policy_line.contains("PASS") && !policy_line.contains("Score:"),
        "policy widget must not render a PASS badge or score for N/A: {policy_line}"
    );
}

#[test]
fn policy_preset_uses_shared_score_formula() {
    use crate::quality::{ComplianceChecker, ComplianceLevel};
    use crate::tui::app_states::PolicyPreset;

    let mut app = demo_app(TabKind::Summary);
    app.compliance_state.policy_preset = PolicyPreset::Cra;
    app.run_compliance_check();

    // `run_compliance_check` evaluates at the wall clock (the TUI has no
    // clock seam), so the expectation must too.
    let expected = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_as_of(chrono::Utc::now())
        .check(app.data.new_sbom.as_ref().expect("demo new SBOM"))
        .score()
        .expect("CRA applies to the demo SBOM");

    let result = app.compliance_state.result.as_ref().expect("check ran");
    assert_eq!(
        result.score, expected,
        "policy widget score must be ComplianceResult::score(), not an ad-hoc 10/5/1 penalty"
    );
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

/// Shift+Tab arrives from real terminals as `KeyCode::BackTab`; it must
/// reverse-cycle tabs (previously only the synthetic Tab+SHIFT combination
/// was handled, so BackTab was silently dropped).
#[test]
fn backtab_cycles_to_previous_tab_in_diff() {
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::BackTab));
    assert_eq!(app.active_tab, TabKind::Summary);
}

/// End/G, PageUp and PageDown must navigate the Licenses tab (they were
/// documented but dead: the view returned Ignored and the global fallback
/// had no Licenses arm).
#[test]
fn licenses_end_and_paging_keys_navigate() {
    let mut app = demo_app(TabKind::Licenses);
    app.prepare_render();
    // The diff Licenses tab lists CHANGED licenses; the all-MIT demo fixture
    // yields at most one, so seed a synthetic bound — the wiring under test
    // is the global-fallback arms, which read this state directly.
    app.licenses_state_mut().total = 25;
    let total = app.licenses_state().total;

    handle_key_event(&mut app, key(KeyCode::End));
    assert_eq!(
        app.licenses_state().selected,
        total - 1,
        "End jumps to the last license row"
    );

    handle_key_event(&mut app, key(KeyCode::PageUp));
    assert_eq!(
        app.licenses_state().selected,
        (total - 1).saturating_sub(crate::tui::constants::PAGE_SIZE),
        "PageUp moves the selection up by exactly one page"
    );

    handle_key_event(&mut app, key(KeyCode::Home));
    assert_eq!(app.licenses_state().selected, 0, "Home returns to the top");
}

/// K (shortcuts) and D (deep dive) previously set their overlay visible in
/// Diff mode without any render path painting it — an invisible modal that
/// swallowed all input. The overlays must now actually render.
#[test]
fn shortcuts_overlay_renders_in_diff_mode() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('K')));
    assert!(
        app.overlays.shortcuts.visible,
        "'K' opens the shortcuts overlay"
    );
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Keyboard Shortcuts (Diff)"),
        "the shortcuts overlay must be painted in diff mode:\n{text}"
    );
    insta::assert_snapshot!("diff_shortcuts_overlay_80x24", text);
}

#[test]
fn deep_dive_overlay_renders_in_diff_mode() {
    let mut app = demo_app(TabKind::Components);
    app.prepare_render();
    handle_key_event(&mut app, key(KeyCode::Char('D')));
    assert!(
        app.overlays.component_deep_dive.visible,
        "'D' opens the deep-dive overlay for the selected component"
    );
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let expected = app.overlays.component_deep_dive.component_name.clone();
    assert!(
        text.contains(&format!("Component Deep Dive: {expected}")),
        "the deep-dive overlay must be painted with the selected component:\n{text}"
    );
}

/// Lock the Grouped layout (including the Modified-section alignment padding)
/// now that it is opt-in rather than the default.
#[test]
fn snapshot_sidebyside_grouped() {
    use crate::tui::app_states::AlignmentMode;

    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Grouped;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    insta::assert_snapshot!("diff_sidebyside_grouped_80x24", text);
}

// ============================================================================
// Multi-comparison modes: baseline snapshots + navigation regression tests
// ============================================================================

/// Baseline snapshots for the three multi-comparison full-screen renders.
/// None existed before (DIFF_TABS deliberately excludes these modes); later
/// multi-mode PRs update these baselines.
#[test]
fn snapshot_multi_modes() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    pin_theme();
    let apps: [(&str, App); 3] = [
        ("multidiff", App::new_multi_diff(demo_multi_diff())),
        ("timeline", App::new_timeline(demo_timeline())),
        ("matrix", App::new_matrix(demo_matrix())),
    ];
    for (name, mut app) in apps {
        for (w, h) in SIZES {
            let text = render_to_text(w, h, |frame| {
                app.prepare_render();
                render(frame, &mut app);
            });
            insta::assert_snapshot!(format!("{name}_{w}x{h}"), text);
        }
    }
}

/// Regression for the frozen multi-diff drill-down: total_variable_components
/// was never populated, so the `total > 0` guard kept j/k stuck at index 0.
#[test]
fn multi_diff_drill_down_unfrozen() {
    use crate::tui::test_support::demo_multi_diff;

    pin_theme();
    let mut app = App::new_multi_diff(demo_multi_diff());
    assert!(
        app.tabs.multi_diff.total_variable_components > 0,
        "constructor must populate the variable-component bound"
    );

    handle_key_event(&mut app, key(KeyCode::Char('v')));
    assert!(app.tabs.multi_diff.show_variable_drill_down);
    let total = app.tabs.multi_diff.total_variable_components;
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(
        app.tabs.multi_diff.selected_variable_component,
        1.min(total - 1),
        "j must advance the drill-down selection when more than one row exists"
    );

    // Guard-level regression independent of fixture size: with the bound set,
    // navigation advances; with the old bound of 0 it froze at index 0.
    app.tabs.multi_diff.total_variable_components = 3;
    app.tabs.multi_diff.selected_variable_component = 0;
    app.tabs.multi_diff.select_next_variable_component();
    app.tabs.multi_diff.select_next_variable_component();
    assert_eq!(app.tabs.multi_diff.selected_variable_component, 2);
}

/// Regression for the frozen Timeline Components panel (total_components
/// never populated).
#[test]
fn timeline_components_panel_navigable() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    assert!(
        app.tabs.timeline.total_components > 0,
        "constructor must populate the component bound"
    );

    handle_key_event(&mut app, key(KeyCode::Tab)); // Versions -> Components
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(
        app.tabs.timeline.selected_component, 1,
        "j must advance the component selection"
    );
}

/// Regression for the frozen Matrix clustering navigation (total_clusters
/// never populated).
#[test]
fn matrix_cluster_navigation_unfrozen() {
    use crate::tui::test_support::demo_matrix;

    pin_theme();
    let app = App::new_matrix(demo_matrix());
    assert!(
        app.tabs.matrix.total_clusters > 0,
        "constructor must populate the cluster bound (threshold 0.5 clusters the fixtures)"
    );

    let mut app = app;
    app.tabs.matrix.select_next_cluster();
    assert_eq!(
        app.tabs.matrix.selected_cluster,
        1.min(app.tabs.matrix.total_clusters - 1),
        "cluster selection must move once the bound is set"
    );
}

/// Regression for the filtered-list desync: under a component filter, the
/// history modal and the event-side name lookup must resolve the SAME entry
/// the Components panel highlights.
#[test]
fn timeline_selection_resolves_through_filtered_list() {
    use crate::tui::app::TimelineComponentFilter;
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::filtered_evolution_entries;

    pin_theme();
    let result = demo_timeline();

    let removed = filtered_evolution_entries(&result, TimelineComponentFilter::Removed);
    assert!(
        !removed.is_empty(),
        "fixture must have removed components (v2 -> v3 is a near-total replacement)"
    );
    assert!(
        removed.iter().all(|(_, is_removed)| *is_removed),
        "Removed filter must only yield removed components"
    );

    // The first REMOVED component differs from the first UNFILTERED entry
    // (which is an added one) — the old unfiltered lookup returned the wrong
    // component under a filter.
    let unfiltered = filtered_evolution_entries(&result, TimelineComponentFilter::All);
    assert!(
        !unfiltered.is_empty() && !unfiltered[0].1,
        "unfiltered list starts with added components"
    );
    assert_ne!(
        removed[0].0.name, unfiltered[0].0.name,
        "filtered index 0 must not resolve to the unfiltered head"
    );
}

/// Regression for the filter resync: narrowing the filter must clamp the
/// selection and update the navigation bound.
#[test]
fn timeline_filter_resync_clamps_selection() {
    use crate::tui::app::TimelineComponentFilter;
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::filtered_evolution_entries;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    // Park the selection on the last unfiltered component.
    app.tabs.timeline.selected_component = app.tabs.timeline.total_components - 1;

    // Cycle 'f' until a narrower filter than All is active.
    for _ in 0..4 {
        handle_key_event(&mut app, key(KeyCode::Char('f')));
        if app.tabs.timeline.component_filter != TimelineComponentFilter::All {
            break;
        }
    }
    let filter = app.tabs.timeline.component_filter;
    assert_ne!(filter, TimelineComponentFilter::All);

    let visible = filtered_evolution_entries(
        app.data.timeline_result.as_ref().expect("timeline data"),
        filter,
    )
    .len();
    assert_eq!(
        app.tabs.timeline.total_components, visible,
        "'f' must resync the navigation bound to the filtered length"
    );
    assert!(
        app.tabs.timeline.selected_component < visible.max(1),
        "'f' must clamp the selection into the filtered list"
    );
}

/// Regression: the Summary "All Changes" panel silently clipped everything
/// below the fold with a pinned scroll of (0,0) and no key handling — users
/// read the visible handful as the complete change set.
#[test]
fn summary_all_changes_scrolls_below_the_fold() {
    let mut app = demo_app(TabKind::Summary);
    let first = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // '~ lodash' is a patch-level bump, priority-sorted to the very end of
    // the list and below the panel's fold.
    assert!(
        !first.contains("~ lodash"),
        "precondition: the patch entry starts below the fold:\n{first}"
    );

    handle_key_event(&mut app, key(KeyCode::End));
    assert!(
        app.summary_state().scroll_offset > 0,
        "End must move the scroll offset"
    );
    let scrolled = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        scrolled.contains("~ lodash"),
        "scrolling must reveal the entries below the fold:\n{scrolled}"
    );
}

/// all_changes_line_count mirrors render_all_changes' line construction.
#[test]
fn all_changes_line_count_matches_fixture() {
    let (diff, _, _) = demo_diff();
    // Demo fixture: 5 modified + 4 removed + 4 added, 1 introduced Critical
    // + 1 introduced High vuln, 3 metadata changes (+1 section header) — the
    // document revision counter (top-level `version` 1 -> 2) now joins the
    // created-timestamp and primary-component-version entries.
    assert_eq!(crate::tui::views::all_changes_line_count(&diff), 19);

    let empty = crate::diff::DiffResult::default();
    assert_eq!(
        crate::tui::views::all_changes_line_count(&empty),
        1,
        "empty diff renders the single empty-state line"
    );
}

/// The engine's KEV deadline and affected version were discarded before
/// render; the detail panel must now show both.
#[test]
fn diff_vuln_detail_shows_kev_deadline_and_affected_version() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let mut vuln = crate::model::VulnerabilityRef::new(
        "CVE-2024-1234".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    vuln.is_kev = true;
    let comp = crate::model::Component::new("liba".to_string(), "pkg:npm/liba@1.2.3".to_string())
        .with_version("1.2.3".to_string());
    let mut detail = crate::diff::VulnerabilityDetail::from_ref(&vuln, &comp);
    detail.kev_due_date = Some("2026-08-01".to_string());
    detail.days_until_due = Some(-5);
    diff.vulnerabilities.introduced.push(detail);

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // The injected severity-less vuln sorts last behind the demo fixture's
    // own introduced vulns; select it so the detail panel shows it.
    app.prepare_render();
    handle_key_event(&mut app, key(KeyCode::End));
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("KEV due: 2026-08-01"),
        "detail panel must show the CISA deadline:\n{text}"
    );
    assert!(
        text.contains("5d overdue"),
        "overdue urgency must render:\n{text}"
    );
    assert!(
        text.contains("Affects: 1.2.3"),
        "affected version must render:\n{text}"
    );
}

/// VEX transitions must be summarized in the filter bar and marked on rows.
#[test]
fn diff_vuln_filter_bar_shows_vex_transitions() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let vref = crate::model::VulnerabilityRef::new(
        "CVE-2024-7777".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    let comp = crate::model::Component::new("libv".to_string(), "pkg:npm/libv@1.0.0".to_string());
    diff.vulnerabilities
        .persistent
        .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));
    diff.vulnerabilities
        .vex_changes
        .push(crate::diff::VexStatusChange {
            vuln_id: "CVE-2024-7777".to_string(),
            component_name: "libv".to_string(),
            old_state: Some(crate::model::VexState::UnderInvestigation),
            new_state: Some(crate::model::VexState::NotAffected),
        });

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // Flat list mode: a collapsed component group would hide the row.
    app.vulnerabilities_state_mut().group_by_component = false;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("VEX \u{394}:") && text.contains("1\u{2192}Not Affected"),
        "filter bar must summarize VEX transitions:\n{text}"
    );
    assert!(
        text.contains("\u{394} CVE-"),
        "the transitioned row must carry the delta marker (ID may truncate):\n{text}"
    );
}

/// Regression: the diff vuln filter bar hard-truncated its View toggle and
/// hints at 80 cols; the second row must carry them now.
#[test]
fn diff_vuln_filter_bar_hints_visible_at_80_cols() {
    let text = render_tab(TabKind::Vulnerabilities, 80, 24);
    assert!(
        text.contains("[f] filter"),
        "hints must be visible at 80 cols:\n{text}"
    );
    assert!(
        text.contains("View:"),
        "View toggle must be visible at 80 cols:\n{text}"
    );
}

/// Lock the Source detail bottom-strip layout ('d' previously squeezed both
/// panels to ~30 cols for a six-line side column).
#[test]
fn snapshot_source_detail_strip() {
    let mut app = demo_app(TabKind::Source);
    handle_key_event(&mut app, key(KeyCode::Char('d')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    insta::assert_snapshot!("diff_source_detail_80x24", text);
}

/// Clicking the tab-bar overflow markers must page hidden tabs into view
/// (they were previously plain truncation with no affordance at all).
#[test]
fn tab_marker_click_selects_adjacent_hidden_tab() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    let mut app = demo_app(TabKind::Source);
    // Render at 80 cols so the bar windows around Source (last tab) and the
    // leading « marker appears; the render stashes the window geometry.
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        app.tab_window.clipped_left,
        "Source at 80 cols must clip earlier tabs: {:?}",
        app.tab_window
    );
    let before = app.tab_window.start;

    crate::tui::events::handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0, // the « marker cell
            row: 1,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
    );
    let entries = crate::tui::ui::diff_tab_entries(&app);
    assert_eq!(
        app.active_tab,
        entries[before - 1].0,
        "« click must select the tab just left of the window"
    );
}

/// Regression: at 80x24 the Summary previously collapsed every box to ~1
/// line (empty Matching/Security Policy shells, 3 visible changes). The
/// compact strip + tall All Changes list must surface far more.
#[test]
fn compact_summary_shows_many_changes_at_80x24() {
    let text = render_tab(TabKind::Summary, 80, 24);
    assert!(
        text.contains("axios") && text.contains("- jquery"),
        "entries previously below the fold must be visible:\n{text}"
    );
    assert!(
        text.contains("Comp +4 -4 ~5"),
        "the dense stat strip must render:\n{text}"
    );
    assert!(
        !text.contains(" Matching ") && !text.contains("Changes by Ecosystem"),
        "compact mode must not render empty shells:\n{text}"
    );
}

/// Lock the mid-tier degradation (charts dropped, stats+insights kept) so
/// the cascade order cannot regress silently. Height 31 is the smallest that
/// keeps insights (content 24 = demand with insights, without charts); at 30
/// the insights row is dropped too and the tier would go unguarded.
#[test]
fn snapshot_summary_100x31() {
    let text = render_tab(TabKind::Summary, 100, 31);
    assert!(
        text.contains(" Matching ") && !text.contains("Changes by Ecosystem"),
        "100x31 must sit exactly in the charts-dropped, insights-kept tier:\n{text}"
    );
    insta::assert_snapshot!("diff_summary_100x31", text);
}

/// Regression: the Matrix 's' key changed the Sort label but never reordered
/// anything. Sort is a symmetric axis permutation; all consumers of
/// selected_row/col resolve raw indices through it.
#[test]
fn matrix_sort_reorders_axes_symmetrically() {
    use crate::tui::test_support::demo_matrix;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    // Default Name sort under the default Ascending direction: A -> Z.
    {
        let result = app.data.matrix_result.as_ref().unwrap();
        let order = ordered_sbom_indices(result, &app.tabs.matrix);
        let names: Vec<&str> = order
            .iter()
            .map(|&i| result.sboms[i].name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "Name ascending must be A->Z");
        let mut perm = order.clone();
        perm.sort_unstable();
        assert_eq!(perm, (0..result.sboms.len()).collect::<Vec<_>>());
    }

    // Name DESCENDING is a deterministic non-identity permutation
    // (gamma, beta, alpha) — the old inert sort rendered alpha first.
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::Name;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    let gamma_row = text
        .lines()
        .position(|l| l.trim_start().starts_with("│gamma"))
        .expect("gamma must be a row label");
    let alpha_row = text
        .lines()
        .position(|l| l.trim_start().starts_with("│alpha"))
        .expect("alpha must be a row label");
    assert!(
        gamma_row < alpha_row,
        "Name descending must render gamma's row above alpha's:\n{text}"
    );
}

/// Cluster sort must group every cluster's members contiguously (the
/// block-diagonal heatmap property).
#[test]
fn cluster_sort_groups_members_contiguously() {
    use crate::tui::test_support::demo_matrix_large;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    // 8 SBOMs alternating between two identical contents: clustering yields
    // interleaved members ({v1,v3,..} vs {v2,v4,..}), so raw order is NOT
    // contiguous and an identity (no-op) sort fails this test.
    let mut app = App::new_matrix(demo_matrix_large());
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::Cluster;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;
    let result = app.data.matrix_result.as_ref().unwrap();
    let order = ordered_sbom_indices(result, &app.tabs.matrix);
    let mut perm = order.clone();
    perm.sort_unstable();
    assert_eq!(perm, (0..result.sboms.len()).collect::<Vec<_>>());
    let clustering = result.clustering.as_ref().expect("fixture clusters");
    let mut multi_member = 0;
    let mut non_trivial = false;
    for cluster in &clustering.clusters {
        let positions: Vec<usize> = cluster
            .members
            .iter()
            .map(|m| order.iter().position(|&x| x == *m).unwrap())
            .collect();
        let (min, max) = (
            *positions.iter().min().unwrap(),
            *positions.iter().max().unwrap(),
        );
        assert_eq!(
            max - min + 1,
            positions.len(),
            "cluster members must occupy a contiguous run of the display order"
        );
        if cluster.members.len() > 1 {
            multi_member += 1;
            // Raw-order contiguity would make this test vacuous.
            let mut sorted_members = cluster.members.clone();
            sorted_members.sort_unstable();
            if sorted_members.windows(2).any(|w| w[1] != w[0] + 1) {
                non_trivial = true;
            }
        }
    }
    assert!(multi_member >= 2, "fixture must produce multiple clusters");
    assert!(
        non_trivial,
        "at least one cluster must be raw-discontiguous or the test can't discriminate"
    );
}

/// Regression: search matches were raw indices; under a sort Enter selected
/// a different SBOM than the one highlighted.
#[test]
fn matrix_search_selects_display_row_under_sort() {
    use crate::tui::test_support::demo_matrix;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('s'))); // AvgSimilarity sort
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "gamma".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    handle_key_event(&mut app, key(KeyCode::Enter));
    let result = app.data.matrix_result.as_ref().unwrap();
    let order = ordered_sbom_indices(result, &app.tabs.matrix);
    let raw = order[app.tabs.matrix.selected_row];
    assert!(
        result.sboms[raw].name.contains("gamma"),
        "Enter must select the row whose SBOM matched the query, got {}",
        result.sboms[raw].name
    );
}

/// New snapshots: sorted matrix, column focus dimming, and the 8-SBOM column
/// viewport at 80 cols.
#[test]
fn snapshot_matrix_interactions() {
    use crate::tui::test_support::{demo_matrix, demo_matrix_large};

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('s')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_sort_avg_80x24", text);

    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('c'))); // column focus
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_col_focus_80x24", text);

    let mut app = App::new_matrix(demo_matrix_large());
    for _ in 0..7 {
        handle_key_event(&mut app, key(KeyCode::Right));
    }
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_viewport_8sboms_80x24", text);
}

/// Regression: comparing v1 against any non-adjacent version reported "no
/// diff available" even though cumulative_from_first holds exactly that data.
#[test]
fn baseline_pair_resolves_cumulative_diff() {
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::resolve_version_diff;

    let result = demo_timeline();
    let diff = resolve_version_diff(&result, 0, 2).expect("baseline pair must resolve");
    let expected = &result.cumulative_from_first[1];
    assert_eq!(
        diff.summary.total_changes, expected.summary.total_changes,
        "0->2 must be the cumulative 0->2 diff"
    );
    // Symmetric: the same diff regardless of endpoint order.
    let rev = resolve_version_diff(&result, 2, 0).expect("reversed pair must resolve");
    assert_eq!(rev.summary.total_changes, expected.summary.total_changes);

    // Adjacent pairs still resolve incrementally.
    let adj = resolve_version_diff(&result, 1, 2).expect("adjacent pair must resolve");
    assert_eq!(
        adj.summary.total_changes,
        result.incremental_diffs[1].summary.total_changes
    );
    // Same version: nothing to diff.
    assert!(resolve_version_diff(&result, 1, 1).is_none());
}

/// The Sort control was inert under Changes/ComponentCount/Name.
#[test]
fn ordered_version_indices_is_truthful() {
    use crate::tui::app::{SortDirection, TimelineSortBy};
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::ordered_version_indices;

    pin_theme();
    let result = demo_timeline();
    let mut app = App::new_timeline(demo_timeline());

    // Chronological = identity.
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![0, 1, 2]
    );

    // Name ascending is A->Z (identity for v1/v2/v3); Descending must be the
    // reverse — the discriminating case an inert sort would fail.
    app.tabs.timeline.sort_by = TimelineSortBy::Name;
    app.tabs.timeline.sort_direction = SortDirection::Ascending;
    let order = ordered_version_indices(&result, &app.tabs.timeline);
    let names: Vec<&str> = order
        .iter()
        .map(|&i| result.sboms[i].name.as_str())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![2, 1, 0],
        "Name descending is Z->A"
    );

    // Chronological honors the direction too ('S' was inert).
    app.tabs.timeline.sort_by = TimelineSortBy::Chronological;
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![2, 1, 0],
        "Chronological descending is newest-first"
    );
    app.tabs.timeline.sort_direction = SortDirection::Ascending;

    // Changes descending puts the largest incremental diff first.
    app.tabs.timeline.sort_by = TimelineSortBy::Changes;
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    let order = ordered_version_indices(&result, &app.tabs.timeline);
    let changes = |i: usize| {
        if i == 0 {
            0
        } else {
            result.incremental_diffs[i - 1].summary.total_changes
        }
    };
    assert!(
        changes(order[0]) >= changes(order[1]) && changes(order[1]) >= changes(order[2]),
        "Changes descending must be monotone"
    );
    let mut perm = order.clone();
    perm.sort_unstable();
    assert_eq!(perm, vec![0, 1, 2], "always a permutation");
}

/// Regression: 'g 1 Enter' after a sort selected whatever row sat at display
/// position 0 instead of version 1.
#[test]
fn jump_maps_raw_to_display_under_sort() {
    use crate::tui::app::{SortDirection, TimelineSortBy};
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::ordered_version_indices;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    // Name DESCENDING: v3,v2,v1 — a non-identity permutation, so an unmapped
    // jump (raw 0 as display 0) would select the WRONG row and fail.
    app.tabs.timeline.sort_by = TimelineSortBy::Name;
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    {
        let result = app.data.timeline_result.as_ref().unwrap();
        let order = ordered_version_indices(result, &app.tabs.timeline);
        assert_ne!(
            order[0], 0,
            "precondition: permutation must be non-identity"
        );
    }

    handle_key_event(&mut app, key(KeyCode::Char('g')));
    handle_key_event(&mut app, key(KeyCode::Char('1')));
    handle_key_event(&mut app, key(KeyCode::Enter));

    let result = app.data.timeline_result.as_ref().unwrap();
    let order = ordered_version_indices(result, &app.tabs.timeline);
    assert_eq!(
        order[app.tabs.timeline.selected_version], 0,
        "the display selection must resolve to raw version 1"
    );

    // A rejected jump (out-of-range) must leave the selection untouched.
    let before = app.tabs.timeline.selected_version;
    handle_key_event(&mut app, key(KeyCode::Char('g')));
    handle_key_event(&mut app, key(KeyCode::Char('9')));
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.tabs.timeline.selected_version, before,
        "rejected jump must not move the selection"
    );
}

/// 'm' cycles the chart metric and falls back to Components when a series is
/// missing.
#[test]
fn chart_metric_cycles_and_falls_back() {
    use crate::tui::app::TimelineChartMetric;
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Components
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Vulnerabilities
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Dependencies
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Components
    );

    // Fallback: strip the dependency series and the render must not panic
    // (falls back to component counts).
    let mut app = App::new_timeline(demo_timeline());
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .dependency_trend
        .clear();
    app.tabs.timeline.chart_metric = TimelineChartMetric::Dependencies;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Components Evolution"),
        "missing series must fall back to the Components metric:\n{text}"
    );
}

/// New snapshots: sorted versions table, stats with license churn, and the
/// baseline cumulative diff modal.
#[test]
fn snapshot_timeline_interactions() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('s'))); // -> Changes sort
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("timeline_sort_changes_80x24", text);

    // 120x40: at 80x24 the squeezed Statistics panel clips the second stats
    // line, hiding exactly the License Δ figure this snapshot exists to lock.
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('t'))); // stats panel
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("License \u{394}:"),
        "stats must show the license churn figure:\n{text}"
    );
    insta::assert_snapshot!("timeline_stats_120x40", text);

    // The figure must read the per-step diffs (the old evolution_summary
    // field is never populated): inject one component license change and one
    // conflict and both must surface.
    let mut app = App::new_timeline(demo_timeline());
    {
        let result = app.data.timeline_result.as_mut().unwrap();
        result.incremental_diffs[0].licenses.component_changes.push(
            crate::diff::ComponentLicenseChange {
                component_id: "libx".to_string(),
                component_name: "libx".to_string(),
                old_licenses: vec!["MIT".to_string()],
                new_licenses: vec!["GPL-3.0-only".to_string()],
            },
        );
    }
    handle_key_event(&mut app, key(KeyCode::Char('t')));
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("License \u{394}: 1"),
        "the churn figure must read the per-step diffs:\n{text}"
    );

    // Select v3, open the diff modal, move compare to v1: the baseline
    // cumulative diff must render instead of "No precomputed diff".
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    handle_key_event(&mut app, key(KeyCode::Char('j'))); // select v3
    handle_key_event(&mut app, key(KeyCode::Char('d'))); // modal (compare defaults)
    handle_key_event(&mut app, key(KeyCode::Left));
    handle_key_event(&mut app, key(KeyCode::Left)); // compare -> v1
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        !text.contains("No precomputed diff"),
        "v1<->v3 must resolve the cumulative diff:\n{text}"
    );
    insta::assert_snapshot!("timeline_modal_baseline_diff_80x24", text);
}

/// Regression: diff-tab clicks assumed 6 rows of chrome; every tab whose
/// chrome differs (or whose list is scrolled) selected the wrong row. The
/// click must land on the row under the cursor, located from the buffer.
#[test]
fn diff_list_click_selects_the_item_under_the_cursor() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = demo_app(TabKind::Components);
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let row = text
        .lines()
        .position(|line| line.contains("axios"))
        .expect("axios must render") as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.components_state().selected,
        1,
        "axios is index 1 under the Name sort (click landed at row {row})"
    );
}

/// Same contract for the other mapped tabs: the demo diff has no vulns or
/// dependency changes, so build synthetic results.
#[test]
fn diff_vuln_and_dependency_clicks_select_under_cursor() {
    use crate::diff::DiffResult;
    use crate::model::NormalizedSbom;
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    // Vulnerabilities: three introduced vulns, click the second row.
    let mut result = DiffResult::default();
    for (i, name) in ["libv-a", "libv-b", "libv-c"].iter().enumerate() {
        let vref = crate::model::VulnerabilityRef::new(
            format!("CVE-2024-9{i:02}"),
            crate::model::VulnerabilitySource::Osv,
        );
        let comp =
            crate::model::Component::new((*name).to_string(), format!("pkg:npm/{name}@1.0.0"));
        result
            .vulnerabilities
            .introduced
            .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));
    }
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Vulnerabilities;
    // Flat list: grouped rows have their own geometry.
    app.vulnerabilities_state_mut().group_by_component = false;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let rows: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("+ NEW"))
        .map(|(i, _)| i)
        .collect();
    assert!(rows.len() >= 2, "vuln rows must render:\n{text}");
    let row = rows[1] as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.vulnerabilities_state().selected,
        1,
        "click must select the vuln under the cursor (row {row})"
    );

    // Dependencies: three added edges, click the third row.
    let mut result = DiffResult::default();
    for (i, to) in ["dep-a", "dep-b", "dep-c"].iter().enumerate() {
        result
            .dependencies
            .added
            .push(crate::diff::DependencyChange {
                from: format!("root-{i}"),
                to: (*to).to_string(),
                relationship: "depends_on".to_string(),
                scope: None,
                change_type: crate::diff::ChangeType::Added,
            });
    }
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Dependencies;
    // Two frames: the first prepare_render builds the graph cache AFTER the
    // visible-node list; the second sees the populated roots (production
    // renders every frame, so this staleness self-corrects immediately).
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // The tree renders roots; its selectable line list starts with the
    // "Changes:" header (0) and a spacer (1), so root-2 is index 4 — the
    // same index the keyboard reaches.
    let row = text
        .lines()
        .position(|line| line.contains("root-2"))
        .unwrap_or_else(|| panic!("third root must render:\n{text}")) as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.dependencies_state().selected,
        4,
        "click must select the line under the cursor (row {row})"
    );
}

/// Timeline clicks select the version row under the cursor, with and without
/// the statistics panel shifting the layout.
#[test]
fn timeline_click_selects_version_under_cursor() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::demo_timeline;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    for stats in [false, true] {
        let mut app = App::new_timeline(demo_timeline());
        if stats {
            handle_key_event(&mut app, key(KeyCode::Char('t')));
        }
        let text = render_to_text(80, 24, |frame| {
            app.prepare_render();
            crate::tui::ui::render(frame, &mut app);
        });
        let row = text
            .lines()
            .position(|line| line.contains("v2"))
            .expect("v2 must render") as u16;
        handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row,
                modifiers: KeyModifiers::empty(),
            },
        );
        assert_eq!(
            app.tabs.timeline.selected_version, 1,
            "click must select v2 (stats={stats}, row {row})"
        );
    }
}

/// Regression: with the selection scrolled past the viewport, ratatui
/// auto-scrolls the table but the click math ignored it.
#[test]
fn diff_click_accounts_for_scroll() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = demo_app(TabKind::Components);
    // First render populates the navigation totals select_down clamps on.
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // Drive the selection past the 11-row viewport at 80x24.
    for _ in 0..12 {
        app.select_down();
    }
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let visible_rows = 24 - 13;
    let expected_offset = app
        .components_state()
        .selected
        .saturating_sub(visible_rows - 1);
    assert!(expected_offset > 0, "selection must be past the viewport");
    // Click the FIRST visible data row (row 10): must select the offset item,
    // not item 0.
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 10,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.components_state().selected,
        expected_offset,
        "the first visible row is the auto-scroll offset item"
    );
}

/// The wheel must move the selection in all three multi modes (previously a
/// no-op or a mis-route into the diff tab logic).
#[test]
fn multi_mode_wheel_moves_selection() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    pin_theme();
    let wheel = |kind| MouseEvent {
        kind,
        column: 10,
        row: 12,
        modifiers: KeyModifiers::empty(),
    };

    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.multi_diff.selected_target, 1);
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.tabs.multi_diff.selected_target, 0);

    let mut app = App::new_timeline(demo_timeline());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.timeline.selected_version, 1);

    let mut app = App::new_matrix(demo_matrix());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.matrix.selected_row, 1);
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollRight));
    assert_eq!(app.tabs.matrix.selected_col, 2);
}

/// Clicks in the Multi-Diff targets list select the row under the cursor;
/// clicks in the top rows must NOT fall through to the diff tab bar.
#[test]
fn multi_diff_click_selects_target() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::demo_multi_diff;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = App::new_multi_diff(demo_multi_diff());
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    // Under the Name sort ai-service is display index 0; webapp is 1. The
    // details-panel title also contains "ai-service", so anchor on webapp.
    let row = text
        .lines()
        .position(|line| line.contains("webapp"))
        .expect("second target must render") as u16;
    let tab_before = app.active_tab;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.tabs.multi_diff.selected_target, 1,
        "click must select the second target (row {row})"
    );

    // A click at y<=2 previously mis-routed into select_tab.
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 1,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.active_tab, tab_before,
        "multi-mode clicks must not reach the diff tab bar"
    );
}

/// Multi-mode chrome: status feedback renders (previously silently dropped),
/// shared footer hints, heatmap glyphs, and degenerate-state chrome.
#[test]
fn snapshot_multi_mode_chrome() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    pin_theme();
    // Status message replaces the hints for the frame.
    let mut app = App::new_matrix(demo_matrix());
    app.set_status_message("Threshold: >= 90%".to_string());
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Threshold: >= 90%"),
        "the status message must render:\n{text}"
    );
    insta::assert_snapshot!("matrix_status_message_80x24", text);

    // Heatmap: the magnitude glyphs are text-visible at 120 cols (at 80 the
    // Deviation column truncates them away; the digits keep priority).
    let mut app = App::new_multi_diff(demo_multi_diff());
    app.tabs.multi_diff.heat_map_mode = true;
    // The demo's engine deviations are pathological (10000%); realistic
    // magnitudes keep the glyph inside the Deviation column.
    for v in app
        .data
        .multi_diff_result
        .as_mut()
        .unwrap()
        .summary
        .deviation_scores
        .values_mut()
    {
        *v = 0.35;
    }
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains('\u{2587}')
            || text.contains('\u{2585}')
            || text.contains('\u{2583}')
            || text.contains('\u{2581}'),
        "deviation magnitude glyphs must render at 120 cols:\n{text}"
    );
    insta::assert_snapshot!("multi_dashboard_heatmap_120x40", text);

    // Single-SBOM matrix: enhanced empty state instead of a lone '-' table.
    let mut single = demo_matrix();
    single.sboms.truncate(1);
    single.similarity_scores.clear();
    single.diffs.clear();
    single.clustering = None;
    let mut app = App::new_matrix(single);
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Need at least 2 SBOMs"),
        "degenerate matrix must explain itself:\n{text}"
    );
    insta::assert_snapshot!("matrix_single_sbom_80x24", text);

    // Zero-match component filter: shared no-results state.
    let mut app = App::new_timeline(demo_timeline());
    // Cycle to a filter with no matches: Stable requires current == first
    // version; if the fixture has stable components, fall back to asserting
    // the no-results copy via an impossible filter by emptying the data.
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .components_added
        .clear();
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .components_removed
        .clear();
    app.tabs.timeline.total_components = 0;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("No results"),
        "empty component history must use the shared no-results state:\n{text}"
    );
    insta::assert_snapshot!("timeline_filter_no_results_80x24", text);
}

/// Lock the diff search overlay: mode badge + the [^R] regex discoverability
/// hint (the toggle worked but was invisible).
#[test]
fn diff_search_overlay_shows_regex_hint() {
    pin_theme();
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "ax".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("[^R]") && text.contains("regex"),
        "the regex toggle must be discoverable:\n{text}"
    );
    assert!(
        text.contains("[substring]"),
        "the mode badge must render:\n{text}"
    );
    insta::assert_snapshot!("diff_search_overlay_80x24", text);
}

/// The unified search contract in the multi modes: Up/Down live-preview the
/// selection, Enter confirms, n/N cycle in place, Ctrl+R toggles regex.
#[test]
fn multi_search_previews_and_cycles() {
    use crate::tui::test_support::{demo_matrix, demo_timeline};
    use crossterm::event::KeyModifiers;

    pin_theme();
    // Timeline: 3 versions all matching "v": Down previews the next match
    // BEFORE Enter.
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('v')));
    assert_eq!(app.tabs.timeline.search.matches.len(), 3);
    handle_key_event(&mut app, key(KeyCode::Down));
    assert_eq!(
        app.tabs.timeline.selected_version, 1,
        "Down must live-preview the second match before Enter"
    );
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(!app.tabs.timeline.search.active);
    // n/N cycle in place after confirm.
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(app.tabs.timeline.selected_version, 2);
    handle_key_event(&mut app, key(KeyCode::Char('N')));
    assert_eq!(app.tabs.timeline.selected_version, 1);

    // Matrix: Ctrl+R toggles regex; an invalid pattern sets the error.
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    assert_eq!(
        app.tabs.matrix.search.mode,
        crate::tui::app_states::SearchMode::Regex
    );
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    assert!(app.tabs.matrix.search.error.is_some());
    assert!(app.tabs.matrix.search.matches.is_empty());
    // Regex that matches: "gam.a"
    for _ in 0..2 {
        handle_key_event(&mut app, key(KeyCode::Backspace));
    }
    for c in "gam.a".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(app.tabs.matrix.search.matches.len(), 1);
    handle_key_event(&mut app, key(KeyCode::Enter));
    let result = app.data.matrix_result.as_ref().unwrap();
    let order = crate::tui::views::ordered_sbom_indices(result, &app.tabs.matrix);
    assert!(
        result.sboms[order[app.tabs.matrix.selected_row]]
            .name
            .contains("gamma")
    );

    // MultiDiff: the same contract — Ctrl+R toggles regex (with error
    // reporting), Down live-previews, and S recomputes the display-space
    // matches so n still lands on the right target after a resort.
    let mut app = App::new_multi_diff(crate::tui::test_support::demo_multi_diff());
    let selected_name = |app: &App| {
        let result = app.data.multi_diff_result.as_ref().unwrap();
        let order = crate::tui::views::ordered_comparison_indices(result, &app.tabs.multi_diff);
        result.comparisons[order[app.tabs.multi_diff.selected_target]]
            .target
            .name
            .clone()
    };
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    assert_eq!(
        app.tabs.multi_diff.search.mode,
        crate::tui::app_states::SearchMode::Regex
    );
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    assert!(app.tabs.multi_diff.search.error.is_some());
    assert!(app.tabs.multi_diff.search.matches.is_empty());
    handle_key_event(&mut app, key(KeyCode::Backspace));
    for c in "web.pp".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(app.tabs.multi_diff.search.matches.len(), 1);
    handle_key_event(&mut app, key(KeyCode::Down));
    assert_eq!(
        selected_name(&app),
        "webapp",
        "Down must live-preview the match before Enter"
    );
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(!app.tabs.multi_diff.search.active);
    // S reverses the display order; matches are display positions, so a
    // stale set would send n to the wrong row after the resort.
    handle_key_event(&mut app, key(KeyCode::Char('S')));
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(
        selected_name(&app),
        "webapp",
        "n must follow the match through the resort"
    );
}

/// The sync guarantee the three-sources bug violated: every diff tab's
/// rendered footer carries each of its ViewState::shortcuts() primary keys
/// (width permitting) ahead of the global tail — both surfaces now read the
/// same data.
#[test]
fn footer_primary_hints_match_viewstate_shortcuts() {
    pin_theme();
    for tab in [
        TabKind::Summary,
        TabKind::Components,
        TabKind::Dependencies,
        TabKind::Licenses,
        TabKind::Vulnerabilities,
        TabKind::Quality,
        TabKind::Compliance,
        TabKind::SideBySide,
        TabKind::GraphChanges,
        TabKind::Source,
    ] {
        let mut app = demo_app(tab);
        // 200 cols: wide enough that the width fitter drops nothing.
        let text = render_to_text(200, 40, |frame| {
            app.prepare_render();
            render(frame, &mut app);
        });
        let footer = text.lines().last().unwrap_or("").to_string();
        let full_text = text.clone();
        let primaries: Vec<(String, String)> = app
            .active_view_state()
            .expect("diff tabs have view states")
            .shortcuts()
            .into_iter()
            .filter(|s| s.primary)
            .map(|s| (s.key, s.description))
            .collect();
        assert!(!primaries.is_empty(), "{tab:?} must have primary shortcuts");
        for (key, desc) in &primaries {
            // The footer renders each hint as " key desc" — asserting the
            // pair (not just the key) catches a hint whose key merely
            // appears inside some other description.
            assert!(
                footer.contains(&format!(" {key} {desc}")),
                "{tab:?} footer must show primary hint '{key} {desc}':\n{full_text}"
            );
        }
        assert!(
            footer.contains("q") && footer.contains("?"),
            "{tab:?} footer keeps the global tail"
        );
    }
}

/// '?' renders the unified shortcuts overlay (the old prose help is gone).
#[test]
fn diff_help_via_question_mark() {
    pin_theme();
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Keyboard Shortcuts (Diff"),
        "'?' must render the shortcuts overlay:\n{text}"
    );
    assert!(
        text.contains("This Tab") && text.contains("Components"),
        "the This-Tab section must name the active tab:\n{text}"
    );
    insta::assert_snapshot!("diff_help_via_question_mark_120x40", text);
}

/// Timeline search's own Ctrl+R arm + SearchMatcher rewrite (duplicated in
/// src/tui/events/timeline.rs, not shared with matrix/multi_diff): pins the
/// regex toggle, the invalid-pattern error report, and that regex matches are
/// display positions Enter/n consume.
#[test]
fn timeline_search_ctrl_r_toggles_regex_and_reports_errors() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(
        app.tabs.timeline.search.active,
        "'/' must open timeline search"
    );
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    assert_eq!(
        app.tabs.timeline.search.mode,
        crate::tui::app_states::SearchMode::Regex,
        "Ctrl+R must switch timeline search to regex mode"
    );

    // Invalid pattern: the error is reported and the matches empty out.
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    assert!(
        app.tabs
            .timeline
            .search
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("Invalid regex")),
        "an unclosed group must set the Invalid regex error, got {:?}",
        app.tabs.timeline.search.error
    );
    assert!(
        app.tabs.timeline.search.matches.is_empty(),
        "an invalid pattern must clear the matches"
    );

    // Clearing the query clears the error; a valid pattern then matches
    // v1/v3 as display positions (default chronological order is identity).
    handle_key_event(&mut app, key(KeyCode::Backspace));
    assert!(
        app.tabs.timeline.search.error.is_none(),
        "emptying the query must clear the regex error"
    );
    for c in "v[13]".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert!(app.tabs.timeline.search.error.is_none());
    assert_eq!(
        app.tabs.timeline.search.matches,
        vec![0, 2],
        "regex v[13] must match v1 and v3 as display positions"
    );

    // Enter confirms onto the first regex match; n cycles to the second.
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(!app.tabs.timeline.search.active);
    assert_eq!(app.tabs.timeline.selected_version, 0);
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(
        app.tabs.timeline.selected_version, 2,
        "n must cycle to the second regex match (v3)"
    );
}

/// Matrix search must carry the full unified contract: Up/Down live-preview
/// selected_row through the matches BEFORE Enter (events/matrix.rs:214-225),
/// and n/N cycle in place after confirm (events/matrix.rs:79-90) — these arms
/// are separate copies of the timeline/multi_diff code and no other test
/// presses Up/Down or n/N in matrix search.
#[test]
fn matrix_search_up_down_previews_and_n_cycles() {
    use crate::tui::test_support::demo_matrix;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('a')));
    // alpha/beta/gamma all contain 'a'; the default Name-ascending order is
    // the identity, so the display positions are [0, 1, 2].
    assert_eq!(app.tabs.matrix.search.matches, vec![0, 1, 2]);

    handle_key_event(&mut app, key(KeyCode::Down));
    assert_eq!(
        app.tabs.matrix.selected_row, 1,
        "Down must live-preview the second match before Enter"
    );
    handle_key_event(&mut app, key(KeyCode::Up));
    assert_eq!(
        app.tabs.matrix.selected_row, 0,
        "Up must preview back to the first match"
    );

    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        !app.tabs.matrix.search.active,
        "Enter must confirm and close the search input"
    );
    assert_eq!(app.tabs.matrix.selected_row, 0);

    // Post-confirm in-place cycling.
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(
        app.tabs.matrix.selected_row, 1,
        "n must advance to the next confirmed match"
    );
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(app.tabs.matrix.selected_row, 2);
    handle_key_event(&mut app, key(KeyCode::Char('N')));
    assert_eq!(
        app.tabs.matrix.selected_row, 1,
        "N must step back to the previous match"
    );
}

/// MultiDiff must recompute the display-space search matches (and resync
/// total_targets) on 'f' filter-preset change and 's' sort-field change —
/// src/tui/events/multi_diff.rs:69-98 — not only on the 'S' arm the existing
/// multi_search_previews_and_cycles test pins.
#[test]
fn multi_diff_refilter_and_resort_recompute_search_matches() {
    use crate::tui::test_support::demo_multi_diff;

    pin_theme();

    let selected_name = |app: &App| {
        let result = app.data.multi_diff_result.as_ref().unwrap();
        let order = crate::tui::views::ordered_comparison_indices(result, &app.tabs.multi_diff);
        result.comparisons[order[app.tabs.multi_diff.selected_target]]
            .target
            .name
            .clone()
    };

    // --- 'f' leg: skew deviations so only webapp passes HighDeviation (>0.3).
    let mut app = App::new_multi_diff(demo_multi_diff());
    {
        let scores = &mut app
            .data
            .multi_diff_result
            .as_mut()
            .unwrap()
            .summary
            .deviation_scores;
        scores.insert("webapp".to_string(), 0.9);
        scores.insert("ai-service".to_string(), 0.0);
    }
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('a')));
    // Both targets contain 'a'; Name-ascending puts ai-service at display 0
    // and webapp at display 1 under the All preset.
    assert_eq!(app.tabs.multi_diff.search.matches, vec![0, 1]);
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(!app.tabs.multi_diff.search.active);

    handle_key_event(&mut app, key(KeyCode::Char('f'))); // All -> HighDeviation
    assert_eq!(
        app.tabs.multi_diff.total_targets, 1,
        "'f' must resync the navigation bound to the filtered set"
    );
    assert_eq!(
        app.tabs.multi_diff.search.matches,
        vec![0],
        "'f' must recompute matches as display positions under the new filter"
    );
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(
        selected_name(&app),
        "webapp",
        "n after a refilter must land on the surviving match, not a stale row"
    );

    // --- 's' leg: Name -> Deviation moves webapp from display 1 to display 0.
    let mut app = App::new_multi_diff(demo_multi_diff());
    {
        let scores = &mut app
            .data
            .multi_diff_result
            .as_mut()
            .unwrap()
            .summary
            .deviation_scores;
        scores.insert("webapp".to_string(), 0.0);
        scores.insert("ai-service".to_string(), 0.9);
    }
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "webapp".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(
        app.tabs.multi_diff.search.matches,
        vec![1],
        "webapp sits at display 1 under Name-ascending"
    );
    handle_key_event(&mut app, key(KeyCode::Enter));

    handle_key_event(&mut app, key(KeyCode::Char('s'))); // Name -> Deviation
    assert_eq!(
        app.tabs.multi_diff.search.matches,
        vec![0],
        "'s' must recompute matches under the new sort (webapp deviates least)"
    );
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    assert_eq!(
        selected_name(&app),
        "webapp",
        "n after a resort must follow the match; a stale display index would select ai-service"
    );
}

/// All three multi-mode search bars render through the one shared helper
/// (render_multi_search_bar, src/tui/views/matrix.rs): mode badge, live match
/// position, the unified [^R]/[n/N] hints, and the inline regex error. No
/// committed snapshot contains any of this chrome.
#[test]
fn multi_mode_search_bar_renders_badge_hints_and_errors() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    pin_theme();

    // Timeline: label + substring badge + query/cursor + match position.
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('v')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Search: [substring]"),
        "the timeline bar must show its label and the substring badge:\n{text}"
    );
    assert!(
        text.contains("v\u{2502}  1/3"),
        "query, cursor and match position (3 versions match 'v') must render:\n{text}"
    );
    assert!(
        text.contains("[^R] regex") && text.contains("[n/N] match"),
        "the unified search hints must render:\n{text}"
    );

    // An invalid regex replaces the hints with the error for the frame.
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("[regex]"),
        "Ctrl+R must flip the badge to [regex]:\n{text}"
    );
    assert!(
        text.contains("Invalid regex"),
        "the regex error must render inline in the bar:\n{text}"
    );
    assert!(
        !text.contains("[n/N] match"),
        "the error must replace the hints, not sit next to them:\n{text}"
    );

    // Matrix: same shared bar, matrix-specific label.
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('a')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Search SBOM: [substring]"),
        "the matrix bar must use the shared helper with its own label:\n{text}"
    );
    assert!(
        text.contains("a\u{2502}  1/3"),
        "all three SBOM names contain 'a', so the position must be 1/3:\n{text}"
    );
    assert!(
        text.contains("[^R] regex") && text.contains("[n/N] match"),
        "the unified hints must render on the matrix bar:\n{text}"
    );

    // MultiDiff: same shared bar.
    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, key(KeyCode::Char('a')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Search: [substring]"),
        "the multi-diff bar must use the shared helper:\n{text}"
    );
    assert!(
        text.contains("a\u{2502}  1/2"),
        "webapp and ai-service both contain 'a', so the position must be 1/2:\n{text}"
    );
    assert!(
        text.contains("[^R] regex") && text.contains("[n/N] match"),
        "the unified hints must render on the multi-diff bar:\n{text}"
    );
}

/// F1 opens (events/mod.rs global fallback) and, while visible, closes
/// (events/mod.rs overlay handler) the same unified shortcuts overlay as '?'
/// and K — no other test anywhere sends KeyCode::F(1).
#[test]
fn f1_toggles_the_unified_shortcuts_overlay() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::F(1)));
    assert!(
        app.overlays.shortcuts.visible,
        "F1 must open the unified shortcuts overlay"
    );
    assert_eq!(
        app.overlays.shortcuts.context,
        crate::tui::app::ShortcutsContext::Diff
    );
    assert_eq!(
        app.overlays.shortcuts.tab_title.as_deref(),
        Some("Summary"),
        "F1 must populate the This-Tab section exactly like '?'"
    );
    handle_key_event(&mut app, key(KeyCode::F(1)));
    assert!(
        !app.overlays.shortcuts.visible,
        "F1 must close the overlay it opened"
    );

    // Cross-parity: F1 closes an overlay '?' opened, and vice versa.
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.overlays.shortcuts.visible);
    handle_key_event(&mut app, key(KeyCode::F(1)));
    assert!(
        !app.overlays.shortcuts.visible,
        "F1 must close an overlay opened by '?'"
    );
    handle_key_event(&mut app, key(KeyCode::F(1)));
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(
        !app.overlays.shortcuts.visible,
        "'?' must close an overlay opened by F1"
    );
}

/// Ctrl+R gives visible feedback on every App search surface: the diff
/// overlay (events/mod.rs) and all three multi modes (events/timeline.rs,
/// events/matrix.rs, events/multi_diff.rs) set the 'Search mode: ...' status
/// message on toggle. The ViewApp surface is pinned in the view test file.
#[test]
fn ctrl_r_sets_search_mode_status_on_diff_and_multi_surfaces() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    let ctrl_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);

    // Diff search overlay.
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: regex"),
        "diff-overlay Ctrl+R must announce regex mode"
    );
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: substring"),
        "toggling back must announce substring mode"
    );

    // Timeline.
    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: regex"),
        "timeline Ctrl+R must set the status message"
    );

    // Matrix.
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: regex"),
        "matrix Ctrl+R must set the status message"
    );

    // MultiDiff.
    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: regex"),
        "multi-diff Ctrl+R must set the status message"
    );
}

/// Grouped mode threads the VEX-transition flag into its own
/// build_single_diff_row call site (src/tui/views/vulnerabilities.rs
/// build_grouped_rows): the transitioned row must carry the 'Δ ' marker under
/// an expanded component group, not only in the flat list.
#[test]
fn grouped_vuln_rows_carry_vex_transition_marker() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let vref = crate::model::VulnerabilityRef::new(
        "CVE-2024-7777".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    let comp = crate::model::Component::new("libv".to_string(), "pkg:npm/libv@1.0.0".to_string());
    diff.vulnerabilities
        .persistent
        .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));
    diff.vulnerabilities
        .vex_changes
        .push(crate::diff::VexStatusChange {
            vuln_id: "CVE-2024-7777".to_string(),
            component_name: "libv".to_string(),
            old_state: Some(crate::model::VexState::UnderInvestigation),
            new_state: Some(crate::model::VexState::NotAffected),
        });

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // Grouped mode with the component's group expanded, so the row renders
    // through build_grouped_rows' separate vex_changed call site (group keys
    // are component names; expand_all_groups also invalidates the grouped
    // render cache).
    app.vulnerabilities_state_mut().toggle_grouped_mode();
    assert!(app.vulnerabilities_state().group_by_component);
    app.vulnerabilities_state_mut()
        .expand_all_groups(&["libv".to_string()]);

    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("\u{25bc} libv"),
        "the expanded group header must render (grouped path did not run):\n{text}"
    );
    assert!(
        text.contains("\u{394} CVE-"),
        "a VEX-transitioned row under an expanded group must carry the delta marker:\n{text}"
    );
}

/// The footer's '[y] copy <value>' preview is sacrificed BEFORE the global
/// ?/q tail would overflow, and its width is re-offered to the tab-specific
/// hints (the drop-yank refit branch in src/tui/ui.rs render_footer).
#[test]
fn footer_drops_yank_preview_before_global_tail_overflows() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();
    // A >=30-char vuln id truncates to 27+"..." in the preview, so the
    // " [y] copy <text>" suffix costs 40 cols: globals (47) + elision (2)
    // + 40 = 89 > 80, forcing the drop-yank refit at 80 cols.
    let vref = crate::model::VulnerabilityRef::new(
        "CVE-2024-99999-EXTREMELY-LONG-IDENT".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    let comp = crate::model::Component::new("liba".to_string(), "pkg:npm/liba@1.2.3".to_string());
    diff.vulnerabilities
        .introduced
        .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // Point the selection at the injected long-id vuln (the demo fixture now
    // carries its own shorter introduced CVEs at the front of the list).
    let long_idx = app
        .data
        .diff_result
        .as_ref()
        .unwrap()
        .vulnerabilities
        .introduced
        .len()
        - 1;
    app.vulnerabilities_state_mut().selected = long_idx;

    let narrow = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let footer = narrow.lines().last().unwrap_or("").to_string();
    assert!(
        !footer.contains("[y] copy"),
        "the yank preview must be sacrificed before the footer overflows 80 cols:\n{narrow}"
    );
    assert!(
        footer.contains(" ? help") && footer.contains(" q quit"),
        "the global ?/q tail must survive the refit:\n{narrow}"
    );
    assert!(
        footer.contains("g group"),
        "dropping the yank must re-offer its width to the tab-specific hints (refit branch):\n{narrow}"
    );

    let wide = render_to_text(200, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let footer = wide.lines().last().unwrap_or("").to_string();
    assert!(
        footer.contains("[y] copy CVE-2024-99999"),
        "the yank preview must be kept when hints + preview fit:\n{wide}"
    );
}

/// The mouse wheel scrolls the Summary All Changes list: ScrollUp/ScrollDown
/// route through App::select_up/select_down, whose TabKind::Summary arms
/// (src/tui/app_impl_nav.rs) move summary_state's scroll_offset.
#[test]
fn summary_wheel_scrolls_all_changes_list() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{MouseEvent, MouseEventKind};

    let mut app = demo_app(TabKind::Summary);
    // First render runs prepare_render, which sets total_lines (16 on the
    // demo fixture) — the bound select_next needs to move at all.
    let first = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        first.contains("[Ln 1-"),
        "precondition: the All Changes list must overflow and show its window indicator:\n{first}"
    );
    assert_eq!(app.summary_state().scroll_offset, 0);

    let wheel = |kind| MouseEvent {
        kind,
        column: 40,
        row: 12,
        modifiers: KeyModifiers::NONE,
    };

    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(
        app.summary_state().scroll_offset,
        1,
        "wheel-down on the Summary tab must advance the All Changes scroll"
    );

    let scrolled = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        scrolled.contains("[Ln 2-"),
        "the panel's window indicator must reflect the wheel scroll:\n{scrolled}"
    );

    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));
    assert_eq!(
        app.summary_state().scroll_offset,
        0,
        "wheel-up on the Summary tab must scroll back to the top"
    );
}

/// The OSV enrichment chip in the diff vuln filter bar is width-gated
/// (area.width >= 100 in src/tui/views/vulnerabilities.rs): it renders at
/// 120 cols and yields at 80 so it cannot push row-1 badges off screen.
#[cfg(feature = "enrichment")]
#[test]
fn osv_enrichment_chip_gated_on_filter_bar_width() {
    let mut app = demo_app(TabKind::Vulnerabilities);
    app.data.enrichment_stats_old = Some(crate::enrichment::EnrichmentStats {
        total_vulns_found: 3,
        ..Default::default()
    });

    let wide = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        wide.contains("OSV +3"),
        "the OSV enrichment chip must render in the filter bar at >= 100 cols:\n{wide}"
    );

    let narrow = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        !narrow.contains("OSV +"),
        "the OSV chip must be suppressed below 100 cols (width gate):\n{narrow}"
    );
}

/// Clicks inside the open Source detail strip must not fall through to the
/// tree-list row-selection math below it (detail_strip_top guard in
/// src/tui/events/mouse.rs, stashed by the render in src/tui/views/source.rs).
#[test]
fn source_detail_strip_click_does_not_fall_through_to_tree() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    let mut app = demo_app(TabKind::Source);
    handle_key_event(&mut app, key(KeyCode::Char('d')));
    // The render stashes detail_strip_top and last_frame_area, both of which
    // the mouse handler needs.
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let top = app
        .source_state()
        .detail_strip_top
        .expect("open detail strip must stash its top row");
    let click = |app: &mut App, row: u16| {
        handle_mouse_event(
            app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 10,
                row,
                modifiers: KeyModifiers::NONE,
            },
        );
    };

    // Control first: a click on a tree row ABOVE the strip must move the
    // selection — otherwise the guard assertion below could pass vacuously
    // because the click path itself is dead. (Active panel is the New side.)
    let before = app.source_state().new_panel.selected;
    click(&mut app, top - 5);
    assert_ne!(
        app.source_state().new_panel.selected,
        before,
        "precondition: tree clicks above the strip must move the selection"
    );

    // A click INSIDE the open strip must not reach the tree index math
    // (without the guard it would map to flat index (row - 6) and mutate).
    let selected = app.source_state().new_panel.selected;
    click(&mut app, top + 2);
    assert_eq!(
        app.source_state().new_panel.selected,
        selected,
        "clicks inside the open Source detail strip must not mutate the tree selection"
    );
}

/// Pins: matrix cells paint similarity as a BACKGROUND color with a
/// luminance-picked foreground (bg = similarity_to_color, fg = badge_fg_for)
/// so the grid reads as a heatmap. render_to_text strips styles, so this is
/// a TestBackend buffer-style scan (same idiom as
/// cbom_selected_row_uses_theme_selection_bg).
#[test]
fn matrix_cells_paint_similarity_as_background() {
    use crate::tui::test_support::demo_matrix;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| {
            app.prepare_render();
            render(frame, &mut app);
        })
        .expect("render");

    let buffer = terminal.backend().buffer();
    let scheme = crate::tui::theme::colors();
    // Every '%' glyph inside the similarity grid carries a heatmap bg; the
    // '%' glyphs elsewhere (status bar Avg, clustering threshold, pair
    // details) keep the default Reset background and are skipped.
    let mut heat_cells = 0;
    let mut saw_dark_fg = false;
    let mut saw_light_fg = false;
    for y in 0..24u16 {
        for x in 0..80u16 {
            let Some(cell) = buffer.cell((x, y)) else {
                continue;
            };
            if cell.symbol() != "%" {
                continue;
            }
            if let Some(bg) = cell.style().bg
                && bg != Color::Reset
            {
                heat_cells += 1;
                let fg = cell.style().fg;
                assert_eq!(
                    fg,
                    Some(scheme.badge_fg_for(bg)),
                    "heatmap cell fg must be luminance-picked via badge_fg_for \
                     (bg {bg:?} at {x},{y})"
                );
                if fg == Some(scheme.badge_fg_dark) {
                    saw_dark_fg = true;
                }
                if fg == Some(scheme.badge_fg_light) {
                    saw_light_fg = true;
                }
            }
        }
    }
    assert!(
        heat_cells >= 2,
        "matrix similarity cells must carry a heatmap background \
         (found {heat_cells} bg-styled '%' cells; the bg painting was dropped)"
    );
    // The demo grid mixes 53% (accent=Yellow -> dark fg) and 0% (removed=Red
    // -> light fg) cells, so an unconditional fixed foreground cannot pass.
    assert!(
        saw_dark_fg && saw_light_fg,
        "heatmap must pick BOTH foregrounds by bg luminance \
         (dark_fg_seen={saw_dark_fg}, light_fg_seen={saw_light_fg})"
    );
}

/// Pins: the pair-diff modal (Enter) and the deep-dive 'D' name lookup
/// resolve selected_row/col through ordered_sbom_indices, not raw indexing.
/// Name-descending display order is gamma,beta,alpha, so display (0,1) must
/// diff gamma <-> beta while raw (0,1) would be alpha <-> beta.
#[test]
fn matrix_modal_and_deep_dive_resolve_through_sort_permutation() {
    use crate::tui::test_support::demo_matrix;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    // App::base restores the last tab from on-disk prefs; Summary never
    // consumes keys, so force it to keep the tab dispatch inert.
    app.active_tab = TabKind::Summary;
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::Name;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;

    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        app.tabs.matrix.show_pair_diff,
        "Enter must open the pair-diff modal"
    );
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Diff: gamma \u{2194} beta"),
        "the modal must diff the DISPLAY pair (0,1) = gamma <-> beta under \
         Name descending:\n{text}"
    );
    assert!(
        !text.contains("Diff: alpha"),
        "raw (unpermuted) indexing would open alpha <-> beta:\n{text}"
    );

    handle_key_event(&mut app, key(KeyCode::Esc));
    assert!(!app.tabs.matrix.show_pair_diff, "Esc must close the modal");

    // 'D' is disabled in Matrix: rows are SBOMs, not components, so the
    // component-shaped modal would be nonsense. It explains itself instead.
    handle_key_event(&mut app, key(KeyCode::Char('D')));
    assert!(
        !app.overlays.component_deep_dive.visible,
        "'D' must NOT open the component deep dive in matrix mode"
    );
    assert!(
        app.status_message
            .as_deref()
            .is_some_and(|m| m.contains("press Enter for pair diff")),
        "'D' in Matrix must explain the alternative, got {:?}",
        app.status_message
    );
}

/// Pins: 's'/'S' clear focus_row/focus_col when the sort changes
/// (events/matrix.rs) because focus is display-space and would silently
/// point at different SBOMs after the reorder.
#[test]
fn matrix_sort_clears_display_space_focus() {
    use crate::tui::test_support::demo_matrix;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    app.active_tab = TabKind::Summary; // keep the tab dispatch inert
    handle_key_event(&mut app, key(KeyCode::Char('c')));
    assert_eq!(
        app.tabs.matrix.focus_col,
        Some(1),
        "precondition: 'c' must focus the default selected column"
    );
    handle_key_event(&mut app, key(KeyCode::Char('s')));
    assert!(
        app.tabs.matrix.focus_col.is_none() && app.tabs.matrix.focus_row.is_none(),
        "'s' must clear display-space focus when the sort key changes"
    );
    assert!(
        !app.tabs.matrix.focus_mode,
        "'s' must also leave focus mode, not just drop the indices"
    );

    let mut app = App::new_matrix(demo_matrix());
    app.active_tab = TabKind::Summary;
    handle_key_event(&mut app, key(KeyCode::Char('r')));
    assert_eq!(
        app.tabs.matrix.focus_row,
        Some(0),
        "precondition: 'r' must focus the default selected row"
    );
    handle_key_event(&mut app, key(KeyCode::Char('S')));
    assert!(
        app.tabs.matrix.focus_row.is_none() && app.tabs.matrix.focus_col.is_none(),
        "'S' must clear display-space focus when the direction flips"
    );
}

/// Pins: toggling sort direction ('S') in Matrix and Timeline recomputes the
/// pinned display-space search matches (update_matrix_search_matches /
/// update_timeline_search_matches called from the sort arms) so 'n' lands on
/// the right row after a resort. Every other test searches AFTER sorting.
#[test]
fn matrix_and_timeline_resort_recompute_search_matches() {
    use crate::tui::test_support::{demo_matrix, demo_timeline};
    use crate::tui::views::{ordered_sbom_indices, ordered_version_indices};

    pin_theme();
    // Matrix: confirm "gamma" under Name ascending (display 2), then resort.
    let mut app = App::new_matrix(demo_matrix());
    app.active_tab = TabKind::Summary; // keep the tab dispatch inert
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "gamma".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.tabs.matrix.selected_row, 2,
        "precondition: gamma sits at display 2 under the default Name ascending"
    );
    handle_key_event(&mut app, key(KeyCode::Char('S'))); // reverse: gamma -> display 0
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    {
        let result = app.data.matrix_result.as_ref().unwrap();
        let order = ordered_sbom_indices(result, &app.tabs.matrix);
        assert_eq!(
            result.sboms[order[app.tabs.matrix.selected_row]].name, "gamma",
            "'S' must recompute display-space matches so n follows gamma \
             through the resort (stale matches would send n to display 2 = alpha)"
        );
    }

    // Timeline: confirm "v1" chronologically (display 0), then resort.
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary;
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "v1".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.tabs.timeline.selected_version, 0,
        "precondition: v1 sits at display 0 under Chronological ascending"
    );
    handle_key_event(&mut app, key(KeyCode::Char('S'))); // newest-first: v1 -> display 2
    handle_key_event(&mut app, key(KeyCode::Char('n')));
    let result = app.data.timeline_result.as_ref().unwrap();
    let order = ordered_version_indices(result, &app.tabs.timeline);
    assert_eq!(
        order[app.tabs.timeline.selected_version], 0,
        "'S' must recompute display-space matches so n still resolves raw v1 \
         (stale matches would leave the selection on display 0 = v3)"
    );
}

/// Pins: an out-of-range matrix pair selection keeps the ' Pair Details '
/// chrome with a muted 'No pair selected' placeholder (views/matrix.rs), and
/// an empty variable_components list renders its titled block with the
/// 'No variable components' explanation (views/multi_dashboard.rs).
#[test]
fn degenerate_selections_render_placeholder_chrome() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff};

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    app.tabs.matrix.selected_row = 99;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Pair Details"),
        "the Pair Details block chrome must survive a degenerate selection:\n{text}"
    );
    assert!(
        text.contains("No pair selected"),
        "a degenerate pair selection must render the placeholder, not a void:\n{text}"
    );

    let mut app = App::new_multi_diff(demo_multi_diff());
    app.data
        .multi_diff_result
        .as_mut()
        .unwrap()
        .summary
        .variable_components
        .clear();
    // 120 cols: the placeholder line fits the 65% details pane un-clipped.
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Variable Components (0 total)"),
        "the empty list must keep its titled block:\n{text}"
    );
    assert!(
        text.contains("No variable components") && text.contains("all targets match the baseline"),
        "the empty list must explain itself:\n{text}"
    );
}

/// Pins: under a non-identity sort the '#' column keeps the TRUE
/// chronological version number (raw + 1) and per-row diff data keys off the
/// RAW index — v3 sorted to the top still reads '3.' with v3's own changes,
/// not '1.' or v1's 'initial' marker (views/timeline.rs:550-552, 491-498).
#[test]
fn timeline_sorted_rows_keep_raw_version_numbers() {
    use crate::tui::app::{SortDirection, TimelineSortBy};
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::ordered_version_indices;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    app.tabs.timeline.sort_by = TimelineSortBy::Name;
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    {
        let result = app.data.timeline_result.as_ref().unwrap();
        assert_eq!(
            ordered_version_indices(result, &app.tabs.timeline),
            vec![2, 1, 0],
            "precondition: Name descending must display v3 first"
        );
    }
    // v3's own incremental changes (v2 -> v3), computed from the fixture so
    // the assertion tracks the data, not a hardcoded '+3 -9'.
    let v3_changes = {
        let result = app.data.timeline_result.as_ref().unwrap();
        let s = &result.incremental_diffs[1].summary;
        format!("+{} -{}", s.components_added, s.components_removed)
    };

    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let lines: Vec<&str> = text.lines().collect();
    let header = lines
        .iter()
        .position(|l| l.contains("Comps") && l.contains("CRA"))
        .unwrap_or_else(|| panic!("versions table header must render:\n{text}"));
    assert!(lines.len() > header + 4, "table rows must render:\n{text}");
    // Left 40% pane only (48 cols at 120 wide): the Component Evolution panel
    // shares these lines and must not satisfy the assertions by accident.
    let left_pane = |line: &str| -> String { line.chars().take(48).collect() };

    // header + bottom_margin(1): first data row is two lines below.
    let v3_row = left_pane(lines[header + 2]);
    assert!(
        v3_row.contains("v3"),
        "display row 0 must be v3 under Name descending, got: {v3_row}"
    );
    assert!(
        v3_row.contains("3."),
        "the '#' column must keep v3's TRUE chronological number under sort \
         (display renumbering would print '1.'), got: {v3_row}"
    );
    assert!(
        v3_row.contains(&v3_changes) && !v3_row.contains("initial"),
        "v3's row must carry v3's own raw-keyed changes '{v3_changes}', got: {v3_row}"
    );

    let v1_row = left_pane(lines[header + 4]);
    assert!(
        v1_row.contains("v1") && v1_row.contains("1.") && v1_row.contains("initial"),
        "v1 sorted to the bottom keeps '1.' and its 'initial' marker, got: {v1_row}"
    );
}

/// Pins: multi-mode mouse is modal-aware (events/mouse.rs guards) — the
/// wheel must not mutate the underlying selection while a modal is open,
/// left clicks close open modals, and the Multi-Diff wheel redirects into
/// the open drill-down list instead of leaking into the targets selection.
#[test]
fn multi_mode_mouse_is_modal_aware() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let event = |kind| MouseEvent {
        kind,
        column: 10,
        row: 12,
        modifiers: KeyModifiers::empty(),
    };

    // Timeline: wheel is inert under the version-diff modal; click closes it.
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary; // keep the tab dispatch inert
    handle_key_event(&mut app, key(KeyCode::Char('d')));
    assert!(app.tabs.timeline.show_version_diff_modal);
    handle_mouse_event(&mut app, event(MouseEventKind::ScrollDown));
    assert_eq!(
        app.tabs.timeline.selected_version, 0,
        "wheel must not move the timeline selection under the diff modal"
    );
    handle_mouse_event(&mut app, event(MouseEventKind::Down(MouseButton::Left)));
    assert!(
        !app.tabs.timeline.show_version_diff_modal,
        "a left click must close the timeline diff modal"
    );
    assert_eq!(
        app.tabs.timeline.selected_version, 0,
        "the modal-closing click must not fall through to row selection"
    );

    // Matrix: same contract under the pair-diff modal.
    let mut app = App::new_matrix(demo_matrix());
    app.active_tab = TabKind::Summary;
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(app.tabs.matrix.show_pair_diff);
    handle_mouse_event(&mut app, event(MouseEventKind::ScrollDown));
    assert_eq!(
        app.tabs.matrix.selected_row, 0,
        "wheel must not move the matrix selection under the pair-diff modal"
    );
    handle_mouse_event(&mut app, event(MouseEventKind::Down(MouseButton::Left)));
    assert!(
        !app.tabs.matrix.show_pair_diff,
        "a left click must close the pair-diff modal"
    );

    // MultiDiff: the wheel redirects into the open drill-down list.
    let mut app = App::new_multi_diff(demo_multi_diff());
    app.active_tab = TabKind::Summary;
    handle_key_event(&mut app, key(KeyCode::Char('v')));
    assert!(app.tabs.multi_diff.show_variable_drill_down);
    // The demo fixture has a single variable component; widen the bound so
    // the wheel has room (same trick as multi_diff_drill_down_unfrozen).
    app.tabs.multi_diff.total_variable_components = 3;
    app.tabs.multi_diff.selected_variable_component = 0;
    handle_mouse_event(&mut app, event(MouseEventKind::ScrollDown));
    assert_eq!(
        app.tabs.multi_diff.selected_variable_component, 1,
        "wheel must scroll the open drill-down list"
    );
    assert_eq!(
        app.tabs.multi_diff.selected_target, 0,
        "wheel must redirect to the drill-down, not leak into the targets selection"
    );
    handle_mouse_event(&mut app, event(MouseEventKind::Down(MouseButton::Left)));
    assert!(
        !app.tabs.multi_diff.show_variable_drill_down,
        "a left click must close the drill-down"
    );
}

/// Pins: Licenses and Quality clicks are gated to a safe no-op
/// (diff_click_index returns None for them at events/mouse.rs) because their
/// geometry has no stable 1:1 row-to-item mapping — a reintroduced wrong-row
/// mapping would overwrite the pre-set distinctive selections below.
#[test]
fn licenses_and_quality_clicks_are_safe_no_ops() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 5,
        row: 12, // well inside the content area at 80x24
        modifiers: KeyModifiers::empty(),
    };

    let mut app = demo_app(TabKind::Licenses);
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    }); // populates last_frame_area, which diff_click_index requires
    app.licenses_state_mut().selected = 1;
    app.licenses_state_mut().selected_new = 1;
    app.licenses_state_mut().selected_removed = 1;
    handle_mouse_event(&mut app, click);
    assert_eq!(
        (
            app.licenses_state().selected,
            app.licenses_state().selected_new,
            app.licenses_state().selected_removed
        ),
        (1, 1, 1),
        "Licenses has no stable row-to-item mapping; a click must not move \
         any of its selections"
    );

    let mut app = demo_app(TabKind::Quality);
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    app.quality_state_mut().selected_recommendation = 1;
    handle_mouse_event(&mut app, click);
    assert_eq!(
        app.quality_state().selected_recommendation,
        1,
        "Quality is a line-scrolled paragraph; a click must not move the \
         recommendation selection"
    );
}

/// Pins: the side-by-side [n/N] context-bar hint reads 'match' only in
/// Aligned mode with a confirmed non-empty search, and 'ext/prev' otherwise
/// (views/sidebyside.rs) — Unified must not advertise match navigation its
/// n/N never perform.
#[test]
fn sxs_nn_hint_reads_match_only_for_aligned_confirmed_search() {
    use crate::tui::app_states::AlignmentMode;

    pin_theme();
    let mut app = demo_app(TabKind::SideBySide); // Aligned is the default
    let baseline = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        baseline.contains("[n/N]ext/prev") && !baseline.contains("[n/N]match"),
        "without a confirmed search the hint must stay ext/prev:\n{baseline}"
    );

    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "axios".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    handle_key_event(&mut app, key(KeyCode::Enter)); // confirm: query pinned
    assert!(!app.side_by_side_state().search_active);
    assert!(
        !app.side_by_side_state().search_matches.is_empty(),
        "precondition: 'axios' must match a demo row"
    );
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("[n/N]match"),
        "Aligned mode with a confirmed search must advertise match navigation:\n{text}"
    );

    // Unified routes n/N through changes, never matches — the label must
    // not lie despite the still-pinned query.
    handle_key_event(&mut app, key(KeyCode::Char('a'))); // Aligned -> Unified
    assert_eq!(
        app.side_by_side_state().alignment_mode,
        AlignmentMode::Unified
    );
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("[n/N]ext/prev") && !text.contains("[n/N]match"),
        "Unified must not advertise match navigation it never performs:\n{text}"
    );
}

/// Pins: status messages render in the Multi-Diff dashboard status bar too
/// (ui.rs threads app.status_message -> render_multi_dashboard ->
/// render_status_bar -> matrix_status_tail). Matrix and Timeline each have a
/// snapshot; this is the Multi-Diff leg.
#[test]
fn multi_diff_status_message_renders_in_status_bar() {
    use crate::tui::test_support::demo_multi_diff;

    pin_theme();
    let mut app = App::new_multi_diff(demo_multi_diff());
    app.set_status_message("Sort: Name \u{2191}");
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("\u{2139} Sort: Name"),
        "the multi-diff status bar must render pending status feedback \
         instead of silently dropping it:\n{text}"
    );
}

/// Stronger leg for the matrix sort claim: the ComponentCount key (the one
/// key with zero coverage) must produce a monotone, non-identity permutation
/// in both directions. gamma has 3 components vs alpha/beta's 9 (pinned by
/// matrix_sort_avg_80x24.snap's Pair Details), so ascending must be gamma-
/// first — an inert or non-monotone ComponentCount arm fails.
#[test]
fn matrix_component_count_sort_is_monotone_permutation() {
    use crate::tui::test_support::demo_matrix;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::ComponentCount;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Ascending;
    {
        let result = app.data.matrix_result.as_ref().unwrap();
        let order = ordered_sbom_indices(result, &app.tabs.matrix);
        let mut perm = order.clone();
        perm.sort_unstable();
        assert_eq!(
            perm,
            vec![0, 1, 2],
            "ComponentCount order must be a permutation"
        );
        let counts: Vec<usize> = order
            .iter()
            .map(|&i| result.sboms[i].component_count)
            .collect();
        assert!(
            counts.windows(2).all(|w| w[0] <= w[1]),
            "ComponentCount ascending must be monotone, got {counts:?}"
        );
        assert_eq!(
            result.sboms[order[0]].name, "gamma",
            "gamma (3 components) must sort ahead of alpha/beta (9) — the \
             non-identity order an inert ComponentCount arm cannot produce"
        );
    }

    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;
    {
        let result = app.data.matrix_result.as_ref().unwrap();
        let order = ordered_sbom_indices(result, &app.tabs.matrix);
        let counts: Vec<usize> = order
            .iter()
            .map(|&i| result.sboms[i].component_count)
            .collect();
        assert!(
            counts.windows(2).all(|w| w[0] >= w[1]),
            "ComponentCount descending must be monotone, got {counts:?}"
        );
        assert_eq!(
            result.sboms[order[2]].name, "gamma",
            "ComponentCount descending must put gamma (3 components) last"
        );
    }
}

/// Stronger leg for the chart-metric claim: the existing test only pins the
/// STATE cycling and the fallback render (which shows exactly what a
/// metric-ignoring regression would show). This renders both non-fallback
/// non-Components metrics: the engine populates vulnerability_trend and
/// dependency_trend for every SBOM, so no fallback fires.
#[test]
fn timeline_chart_title_follows_selected_metric() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary; // keep the tab dispatch inert

    handle_key_event(&mut app, key(KeyCode::Char('m'))); // -> Vulnerabilities
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Vulnerabilities Evolution") && !text.contains("Components Evolution"),
        "the chart must plot the selected Vulnerabilities metric, not \
         silently fall back to Components:\n{text}"
    );

    handle_key_event(&mut app, key(KeyCode::Char('m'))); // -> Dependencies
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Dependencies Evolution") && !text.contains("Components Evolution"),
        "the chart must plot the selected Dependencies metric:\n{text}"
    );
}

/// Pins the profile guard in render_diff_quality (src/tui/views/quality.rs:39-45):
/// a pipeline QualityDelta whose overall delta disagrees with the displayed
/// profile-aware reports by >= 0.75 points must be distrusted entirely — the
/// headline falls back to the display-derived (0-point) delta and none of the
/// engine chips (Regressed/Improved/violation delta) may render.
#[test]
fn quality_tab_distrusts_engine_delta_mismatching_displayed_reports() {
    use crate::diff::{DiffResult, QualityDelta};
    use crate::model::NormalizedSbom;

    pin_theme();
    let mut result = DiffResult::default();
    // Both fixture SBOMs are empty, so the displayed transition is 0.0 points.
    // 42.0 mismatches far beyond the 0.75 tolerance; the constructor backfill
    // only fires on None, so this pipeline value survives to the guard.
    result.quality_delta = Some(QualityDelta {
        overall_score_delta: 42.0,
        old_grade: None,
        new_grade: None,
        category_deltas: vec![],
        regressions: vec!["Integrity".to_string()],
        improvements: vec![],
        violation_count_delta: 3,
    });
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Quality;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Quality score unchanged"),
        "a distrusted engine delta must fall back to the display-derived 0-point headline:\n{text}"
    );
    assert!(
        !text.contains("improved by 42"),
        "the mismatched engine delta (42.0) must not drive the headline:\n{text}"
    );
    assert!(
        !text.contains("Regressed: Integrity"),
        "engine regression chips must not render when the delta is distrusted:\n{text}"
    );
    assert!(
        !text.contains("Compliance violations: +3"),
        "the engine violation delta must not render when the delta is distrusted:\n{text}"
    );
}

/// Pins the rounded-delta branching in render_combined_recommendations
/// (src/tui/views/quality.rs:750-764): the headline branches on
/// score_diff.round(), so an engine delta of 5.4 (rounds to 5, NOT > 5) says
/// "unchanged" instead of printing "Quality improved by 5 points" from inside
/// the strictly-more-than-5 branch.
#[test]
fn quality_headline_branches_on_rounded_delta() {
    use crate::diff::{DiffResult, QualityDelta};
    use crate::model::NormalizedSbom;

    pin_theme();
    let mut result = DiffResult::default();
    result.quality_delta = Some(QualityDelta {
        overall_score_delta: 5.4,
        old_grade: None,
        new_grade: None,
        category_deltas: vec![],
        regressions: vec![],
        improvements: vec![],
        violation_count_delta: 0,
    });
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Quality;
    // Make the displayed reports agree with the engine delta (55.4 - 50.0 =
    // 5.4) so the profile-mismatch guard passes and the headline sees 5.4.
    app.data
        .old_quality
        .as_mut()
        .expect("diff constructor scores the old SBOM")
        .overall_score = 50.0;
    app.data
        .new_quality
        .as_mut()
        .expect("diff constructor scores the new SBOM")
        .overall_score = 55.4;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Quality score unchanged"),
        "5.4 rounds to 5, which is NOT > 5: the headline must branch on the ROUNDED delta:\n{text}"
    );
    assert!(
        !text.contains("improved by 5 points"),
        "raw-float branching regression: {{:.0}} of 5.4 prints 'improved by 5 points' from inside the >5 branch:\n{text}"
    );
}

/// Pins the >999 text_value compaction in render_ecosystem_breakdown_chart
/// (src/tui/views/summary.rs:1457-1463): ratatui only prints a bar's value
/// when it fits in bar_width(3), so a 1200 count must render as the 2-char
/// "1k" instead of being silently dropped.
#[test]
fn ecosystem_bar_values_above_999_render_compacted() {
    use crate::diff::DiffResult;
    use crate::model::NormalizedSbom;

    fn comp(name: &str, eco: &str) -> crate::diff::ComponentChange {
        let component =
            crate::model::Component::new(name.to_string(), format!("pkg:{eco}/{name}@1.0.0"));
        let mut c = crate::diff::ComponentChange::added(&component, 0);
        c.ecosystem = Some(eco.to_string());
        c
    }

    pin_theme();
    let mut result = DiffResult::default();
    for i in 0..1200 {
        result.components.added.push(comp(&format!("np{i}"), "npm"));
    }
    // A second ecosystem forces the grouped BarChart path (a single ecosystem
    // renders the labelled tally row instead of bars).
    result.components.removed.push(comp("py0", "pypi"));
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Summary;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("npm") && text.contains("pypi"),
        "grouped ecosystem chart must render both groups:\n{text}"
    );
    assert!(
        text.contains("1k"),
        "the 1200-count bar must render its compacted '1k' text_value — the raw '1200' does not fit bar_width(3) and ratatui silently drops it:\n{text}"
    );
}

/// Pins the shared category_glyph prefix in the DIFF-mode license tables
/// (default grouping in render_license_table, src/tui/views/licenses.rs:865-877):
/// the Category cell must read "<glyph> <category>" exactly as view mode does.
#[test]
fn diff_license_tables_prefix_category_with_shared_glyph() {
    use crate::diff::{DiffResult, LicenseChange};
    use crate::model::NormalizedSbom;

    pin_theme();
    let mut result = DiffResult::default();
    result.licenses.new_licenses.push(LicenseChange {
        license: "GPL-3.0-only".to_string(),
        components: vec!["libx".to_string()],
        family: "GPL".to_string(),
    });
    result.licenses.removed_licenses.push(LicenseChange {
        license: "MIT".to_string(),
        components: vec!["liby".to_string()],
        family: "MIT".to_string(),
    });
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Licenses;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // Glyph + category-name pairs: the standalone \u{2713} also appears in the
    // characteristics detail panel, so assert the full Category-cell text.
    assert!(
        text.contains("\u{a9} Copyleft"),
        "the GPL-3.0-only new-license row must carry the copyleft glyph in its Category cell:\n{text}"
    );
    assert!(
        text.contains("\u{2713} Permissive"),
        "the MIT removed-license row must carry the permissive glyph in its Category cell:\n{text}"
    );
}

/// Pins monochrome stickiness through the real 'T' key path plus the
/// save-skip guard in the theme-toggle handler (src/tui/events/mod.rs:310-324):
/// a no-op toggle (monochrome -> monochrome) must neither change the live
/// theme nor write TuiPreferences (which would clobber the user's saved
/// colored theme for future non-NO_COLOR sessions).
#[test]
fn t_toggle_on_monochrome_is_noop_and_skips_pref_save() {
    let mut app = demo_app(TabKind::Summary);
    let saved_theme_before = crate::config::TuiPreferences::load().theme;
    crate::tui::theme::set_theme(crate::tui::theme::Theme::monochrome());
    handle_key_event(&mut app, key(KeyCode::Char('T')));
    let live_theme_after = crate::tui::theme::current_theme_name();
    let saved_theme_after = crate::config::TuiPreferences::load().theme;
    // Restore the pinned theme before asserting so a failure cannot leak
    // monochrome into other tests.
    pin_theme();
    assert_eq!(
        live_theme_after, "monochrome",
        "'T' on monochrome must stay monochrome (NO_COLOR stickiness through the real key path)"
    );
    assert_eq!(
        saved_theme_after, saved_theme_before,
        "a no-op 'T' toggle must skip the TuiPreferences save — a regressed guard writes theme=monochrome over the user's saved colored preference"
    );
}

/// Grouped-table sibling of compliance_selection_marker_visible: the grouped
/// violation table (render_grouped_violation_table,
/// src/tui/views/diff_compliance.rs:1109-1199) builds its own selection
/// marker, so the \u{25b6} must also appear on a selected violation row under
/// an expanded group — not just in the flat table.
#[test]
fn compliance_grouped_selection_marker_visible() {
    let mut app = demo_app(TabKind::Compliance);
    // Compliance results are computed lazily in prepare_render; the key
    // handler needs them up-front to resolve navigation bounds (Enter is
    // gated on max_violations > 0).
    app.ensure_compliance_results();
    handle_key_event(&mut app, key(KeyCode::Char('v'))); // Overview -> NewViolations
    handle_key_event(&mut app, key(KeyCode::Char('g'))); // group by element
    handle_key_event(&mut app, key(KeyCode::Enter)); // expand the selected (first) group
    handle_key_event(&mut app, key(KeyCode::Char('j'))); // first violation inside it
    assert!(
        app.diff_compliance_state().group_by_element,
        "precondition: 'g' must enable grouped mode"
    );
    assert_eq!(
        app.diff_compliance_state().selected_violation,
        1,
        "precondition: selection must sit on the first violation row under the expanded group header"
    );
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("[grouped]"),
        "the grouped violation table must render:\n{text}"
    );
    assert!(
        text.contains("\u{25b6} ERROR")
            || text.contains("\u{25b6} WARN")
            || text.contains("\u{25b6} INFO"),
        "the selected violation row in the GROUPED table must carry the \u{25b6} marker in its severity cell:\n{text}"
    );
}

/// Buffer-level pin for the dependency-tree search highlight: a matched row
/// must carry scheme.search_highlight_bg (src/tui/views/dependencies.rs:600-609),
/// not the old hardcoded Rgb(60,60,20), not another scheme slot, and not
/// nothing — text snapshots strip styles, so only a cell scan can see this.
#[test]
fn dependency_search_match_row_uses_themed_highlight_bg() {
    use crate::diff::{ChangeType, DependencyChange, DiffResult};
    use crate::model::NormalizedSbom;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pin_theme();
    let mut result = DiffResult::default();
    result.dependencies.added.push(DependencyChange {
        from: "rootpkg".to_string(),
        to: "leafpkg".to_string(),
        relationship: "depends_on".to_string(),
        scope: None,
        change_type: ChangeType::Added,
    });
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Dependencies;
    app.dependencies_state_mut().expand("rootpkg");

    // Two frames: the first prepare_render builds the graph cache AFTER the
    // visible-node list; the second sees the populated roots (production
    // renders every frame, so this staleness self-corrects immediately).
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });

    // Search for the child node; matches recompute on every keypress.
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "leaf".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert!(
        app.dependencies_state()
            .search_matches
            .contains("rootpkg:+:leafpkg"),
        "precondition: the query must match the child node, got {:?}",
        app.dependencies_state().search_matches
    );
    assert_eq!(
        app.dependencies_state().selected,
        0,
        "precondition: the matched row must NOT be the selected row (selection bg takes precedence)"
    );
    assert_eq!(
        app.dependencies_state().search_query,
        "leaf",
        "typing must append every char — 'f' used to toggle filter mode mid-query"
    );
    assert!(
        !app.dependencies_state().filter_mode,
        "typing 'f' in the query must not flip match-only filter mode (Ctrl+F does)"
    );

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| {
            app.prepare_render();
            render(frame, &mut app);
        })
        .expect("render");
    let buffer = terminal.backend().buffer();

    // Locate the added child row ("+ leafpkg") and check its background.
    let expected = crate::tui::theme::colors().search_highlight_bg;
    let mut found_row = None;
    for y in 0..24u16 {
        let row: String = (0..80u16)
            .map(|x| buffer.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
            .collect();
        if row.contains("+ leafpkg") {
            found_row = Some((y, row));
            break;
        }
    }
    let (y, row) = found_row.expect("the added child row '+ leafpkg' must render");
    let byte_idx = row.find("leafpkg").expect("label present");
    let x = row[..byte_idx].chars().count() as u16;
    let bg = buffer.cell((x, y)).and_then(|c| c.style().bg);
    assert_eq!(
        bg,
        Some(expected),
        "the search-match row must carry the THEMED search_highlight_bg — a deleted or re-slotted highlight leaves {bg:?} at ({x},{y}):\n{row}"
    );
}

/// Pins: the side-by-side viewport is MEASURED from the real render height
/// (src/tui/ui.rs wires `chunks[2].height - 4` into `set_viewport_rows`; at
/// 80x24 that is 17 content rows - 2 context-bar rows - 2 border rows = 13),
/// and the row cursor therefore stays inside the rendered window end-to-end.
/// Deleting the ui.rs wiring leaves the pre-render default of 20 and
/// reintroduces the walk-off-screen bug while the four unit-level clamp tests
/// in app_states/sidebyside.rs stay green.
#[test]
fn sidebyside_viewport_measured_from_real_render_and_selection_stays_onscreen() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();
    // Pad the diff so the aligned row list (4 removed + 4 modified + 4 added
    // in the demo) overflows the 13-row 80x24 window.
    for i in 0..20 {
        let comp =
            crate::model::Component::new(format!("padpkg-{i:02}"), format!("padpkg-{i:02}-ref"))
                .with_version("1.0.0".to_string());
        diff.components
            .added
            .push(crate::diff::ComponentChange::added(&comp, 1));
    }
    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::SideBySide;

    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert_eq!(
        app.side_by_side_state().viewport_rows,
        13,
        "the render must measure the real 80x24 window (17 content rows - 2 context bar - 2 borders), not keep the pre-render default of 20"
    );

    // Walk the cursor well past the fold; the scroll window must follow it.
    for _ in 0..20 {
        handle_key_event(&mut app, key(KeyCode::Char('j')));
    }
    let expected = app.side_by_side_state().aligned_rows[app.side_by_side_state().selected_row]
        .right_name
        .clone()
        .expect("row 20 is a modified/added row and carries a right-side name");
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let st = app.side_by_side_state();
    assert_eq!(
        st.selected_row, 20,
        "20 'j' presses must move the aligned row cursor to row 20"
    );
    assert!(
        (st.left_scroll..st.left_scroll + st.viewport_rows).contains(&st.selected_row),
        "selection {} must stay inside the scroll window starting at {} ({} rows)",
        st.selected_row,
        st.left_scroll,
        st.viewport_rows
    );
    assert!(
        text.contains(&expected),
        "the selected row '{expected}' must be rendered on screen at 80x24:\n{text}"
    );
}

/// Pins: 'y' on the side-by-side tab resolves the SELECTED aligned row's text
/// (through the shared get_yank_text -> get_current_row_info seam) and never
/// reports silently — the status is either an honest "Copied: ..." after a
/// real clipboard write or the explicit "Clipboard unavailable" failure. The
/// pre-fix code claimed "Copied" without ever touching the clipboard.
#[test]
fn sidebyside_yank_resolves_selected_row_and_reports_honestly() {
    let mut app = demo_app(TabKind::SideBySide);
    // Populate the aligned-row cache and the row model via a real frame.
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    handle_key_event(&mut app, key(KeyCode::Char('j')));

    let row_name = {
        let st = app.side_by_side_state();
        assert_eq!(st.selected_row, 1, "'j' must move the aligned row cursor");
        let row = &st.aligned_rows[1];
        row.left_name
            .clone()
            .or_else(|| row.right_name.clone())
            .expect("aligned rows carry a component name")
    };

    let yank = crate::tui::events::get_yank_text(&app)
        .expect("side-by-side in Aligned mode must resolve a copyable row");
    assert!(
        yank.contains(&row_name),
        "yank text {yank:?} must name the selected row's component {row_name:?}"
    );
    assert!(
        yank.starts_with("- ") || yank.starts_with("~ ") || yank.starts_with("+ "),
        "yank text must carry the '-/~/+ name version' row shape, got {yank:?}"
    );

    handle_key_event(&mut app, key(KeyCode::Char('y')));
    let status = app
        .status_message
        .as_deref()
        .expect("'y' must always set a status message");
    assert!(
        status.starts_with("Copied: ") || status == "Clipboard unavailable",
        "'y' must either copy for real or admit failure, got {status:?}"
    );
    if let Some(copied) = status.strip_prefix("Copied: ") {
        assert!(
            copied.contains(&row_name),
            "the copied preview {copied:?} must name the selected row {row_name:?}"
        );
    }
}

/// Pins: 'D' resolves the deep-dive component through the SAME filtered +
/// sorted list the Components table renders (app.diff_component_items via
/// get_selected_component_name's Diff arm), not the raw
/// added->removed->modified concatenation that opened the wrong component
/// under any sort. The existing deep-dive test reads the overlay's own
/// component_name back, which is circular w.r.t. resolution.
#[test]
fn deep_dive_resolves_through_sorted_component_list() {
    let mut app = demo_app(TabKind::Components);
    app.prepare_render();

    // Advance the sort (Name -> Version) so the table order diverges from the
    // raw concatenation (demo versions interleave the added/removed/modified
    // groups).
    handle_key_event(&mut app, key(KeyCode::Char('s')));

    // Find a row where the sorted table disagrees with the raw concatenation.
    let (idx, expected, raw_name) = {
        let result = app.data.diff_result.as_ref().expect("diff data");
        let raw: Vec<&str> = result
            .components
            .added
            .iter()
            .chain(result.components.removed.iter())
            .chain(result.components.modified.iter())
            .map(|c| c.name.as_str())
            .collect();
        let items = app.diff_component_items(app.components_state().filter);
        let idx = (0..items.len().min(raw.len()))
            .find(|&i| items[i].name != raw[i])
            .expect("demo fixture must yield a row where the Version sort differs from the raw concatenation");
        (idx, items[idx].name.clone(), raw[idx].to_string())
    };
    assert_ne!(
        expected, raw_name,
        "probe precondition: index {idx} discriminates the two orders"
    );

    for _ in 0..idx {
        handle_key_event(&mut app, key(KeyCode::Down));
    }
    assert_eq!(
        app.components_state().selected,
        idx,
        "Down must land on the target row"
    );

    handle_key_event(&mut app, key(KeyCode::Char('D')));
    assert!(
        app.overlays.component_deep_dive.visible,
        "'D' must open the deep-dive overlay"
    );
    assert_eq!(
        app.overlays.component_deep_dive.component_name, expected,
        "the deep dive must open the highlighted (sorted) table row, not the raw concatenation's '{raw_name}'"
    );
}

/// Pins the Enter/Space guard on the Timeline Components panel: with a filter
/// yielding zero entries the history modal must NOT open (it would clear its
/// rect, render nothing, and swallow every key except Esc/q) and the guard
/// status must explain why (src/tui/events/timeline.rs Enter arm).
#[test]
fn timeline_enter_guarded_when_filter_matches_nothing() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary; // deterministic tab dispatch (App::base restores from prefs)
    {
        let summary = &mut app
            .data
            .timeline_result
            .as_mut()
            .expect("timeline data")
            .evolution_summary;
        summary.components_added.clear();
        summary.components_removed.clear();
    }
    app.tabs.timeline.total_components = 0;

    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        !app.tabs.timeline.show_component_history,
        "Enter must not open an invisible history modal when the filter yields zero entries"
    );
    assert_eq!(
        app.status_message.as_deref(),
        Some("No components match the current filter"),
        "the Enter guard must explain why nothing opened"
    );

    handle_key_event(&mut app, key(KeyCode::Char(' ')));
    assert!(
        !app.tabs.timeline.show_component_history,
        "Space must be guarded exactly like Enter"
    );
    assert_eq!(
        app.status_message.as_deref(),
        Some("No components match the current filter"),
        "the Space guard must explain why nothing opened"
    );

    // Control: with entries present, Enter still opens the modal, so the
    // guard cannot pass by disabling Enter outright.
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary;
    assert!(app.tabs.timeline.total_components > 0, "fixture control");
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        app.tabs.timeline.show_component_history,
        "Enter must still open the history modal when entries exist"
    );
}

/// Stronger consumption-side pin for the filtered Timeline selection: under a
/// non-All filter BOTH consumers of filtered_evolution_entries — the 'D'
/// deep-dive name lookup (events/helpers.rs Timeline arm) and the Enter
/// history modal (views/timeline.rs render_component_history_modal) — must
/// resolve the SAME entry the Components panel highlights, not the unfiltered
/// head. The existing test only pins the list helper's own semantics, so
/// reverting either consumer to the raw evolution_summary list stayed green.
#[test]
fn timeline_history_modal_and_deep_dive_resolve_filtered_entry() {
    use crate::tui::app::TimelineComponentFilter;
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary; // deterministic tab dispatch

    // Cycle 'f' (All -> Added -> Removed); each press resyncs
    // total_components and clamps the selection (stays at 0).
    for _ in 0..5 {
        handle_key_event(&mut app, key(KeyCode::Char('f')));
        if app.tabs.timeline.component_filter == TimelineComponentFilter::Removed {
            break;
        }
    }
    assert_eq!(
        app.tabs.timeline.component_filter,
        TimelineComponentFilter::Removed
    );
    assert_eq!(app.tabs.timeline.selected_component, 0);

    let (expected, unfiltered_head) = {
        let result = app.data.timeline_result.as_ref().expect("timeline data");
        let removed =
            crate::tui::views::filtered_evolution_entries(result, TimelineComponentFilter::Removed);
        let all =
            crate::tui::views::filtered_evolution_entries(result, TimelineComponentFilter::All);
        assert!(
            !removed.is_empty() && !all.is_empty(),
            "fixture must have entries"
        );
        (removed[0].0.name.clone(), all[0].0.name.clone())
    };
    // Discriminating precondition — already proven for this fixture by
    // timeline_selection_resolves_through_filtered_list.
    assert_ne!(
        expected, unfiltered_head,
        "filtered head must differ from the unfiltered head"
    );

    // Event-side consumer: 'D' must open the deep dive on the filtered entry.
    handle_key_event(&mut app, key(KeyCode::Char('D')));
    assert!(
        app.overlays.component_deep_dive.visible,
        "'D' opens the deep dive"
    );
    assert_eq!(
        app.overlays.component_deep_dive.component_name, expected,
        "the deep dive must resolve through the filtered list, not the unfiltered head '{unfiltered_head}'"
    );
    handle_key_event(&mut app, key(KeyCode::Esc)); // close the deep dive

    // Render-side consumer: the Enter history modal must show the same entry.
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        app.tabs.timeline.show_component_history,
        "Enter opens the history modal"
    );
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains(&format!("Component: {expected}")),
        "the history modal must show the filtered selection '{expected}':\n{text}"
    );
    assert!(
        !text.contains(&format!("Component: {unfiltered_head}")),
        "the history modal must NOT resolve the unfiltered head '{unfiltered_head}':\n{text}"
    );
}

/// Pins the cursor-following windowing of the Timeline Components panel
/// (src/tui/views/timeline.rs skip/take with 4 chrome rows) and the
/// multi-diff variable-components pane (src/tui/views/multi_dashboard.rs):
/// with the selection driven past the 80x24 fold, the selected row must still
/// be rendered. Restoring the old `.take(N)` head-truncation passes every
/// existing test (navigation tests stop at index 1; snapshots render with
/// selection 0) but fails both legs here.
#[test]
fn timeline_and_multidiff_panes_window_around_cursor() {
    use crate::tui::test_support::{demo_multi_diff, demo_timeline};

    /// True when some buffer row both carries the theme selection background
    /// and contains `needle` — i.e. the selected row is actually on screen.
    fn selected_row_visible(app: &mut App, needle: &str) -> bool {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| {
                app.prepare_render();
                render(frame, &mut *app);
            })
            .expect("render");
        let buffer = terminal.backend().buffer();
        let selection = crate::tui::theme::colors().selection;
        (0..24u16).any(|y| {
            let row_text: String = (0..80u16)
                .filter_map(|x| buffer.cell((x, y)).map(|c| c.symbol().to_string()))
                .collect();
            let has_selection_bg = (0..80u16).any(|x| {
                buffer
                    .cell((x, y))
                    .is_some_and(|c| c.style().bg == Some(selection))
            });
            has_selection_bg && row_text.contains(needle)
        })
    }

    pin_theme();

    // --- Timeline Components panel (11 visible rows at 80x24) ---
    let mut app = App::new_timeline(demo_timeline());
    app.active_tab = TabKind::Summary; // deterministic tab dispatch
    handle_key_event(&mut app, key(KeyCode::Tab)); // Versions -> Components
    let total = app.tabs.timeline.total_components;
    assert!(
        total > 12,
        "precondition: the fixture must overflow the 11-row 80x24 pane, got {total}"
    );
    for _ in 0..total {
        handle_key_event(&mut app, key(KeyCode::Char('j')));
    }
    assert_eq!(
        app.tabs.timeline.selected_component,
        total - 1,
        "'j' must walk the cursor to the last filtered entry"
    );
    let needle: String = {
        let result = app.data.timeline_result.as_ref().expect("timeline data");
        crate::tui::views::filtered_evolution_entries(result, app.tabs.timeline.component_filter)
            [total - 1]
            .0
            .name
            .chars()
            .take(12)
            .collect()
    };
    assert!(
        selected_row_visible(&mut app, &needle),
        "the selected component '{needle}' must stay inside the windowed 80x24 Components panel (the old code truncated with .take(N))"
    );

    // --- Multi-diff variable-components pane (4 visible rows at 80x24) ---
    let mut app = App::new_multi_diff(demo_multi_diff());
    app.active_tab = TabKind::Summary;
    {
        let summary = &mut app
            .data
            .multi_diff_result
            .as_mut()
            .expect("multi-diff data")
            .summary;
        let template = summary
            .variable_components
            .first()
            .expect("demo multi-diff must have a variable component")
            .clone();
        summary.variable_components = (0..12)
            .map(|i| {
                let mut vc = template.clone();
                vc.name = format!("varpane-{i:02}");
                vc
            })
            .collect();
    }
    app.tabs.multi_diff.total_variable_components = 12;

    // Below the fold before navigating.
    let before = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        !before.contains("varpane-11"),
        "precondition: the last row must start below the pane fold:\n{before}"
    );

    handle_key_event(&mut app, key(KeyCode::Char('v'))); // drill-down: 'j' moves the pane cursor
    for _ in 0..12 {
        handle_key_event(&mut app, key(KeyCode::Char('j')));
    }
    assert_eq!(app.tabs.multi_diff.selected_variable_component, 11);
    handle_key_event(&mut app, key(KeyCode::Esc)); // close the modal; the selection persists

    assert!(
        selected_row_visible(&mut app, "varpane-11"),
        "the selected variable component must stay inside the windowed 80x24 pane (the old code truncated with .take(N))"
    );
}

// ============================================================================
// Phase 4 regression probes (file-end siblings of `diff_alignment`: that
// module's builders are private to it, so the small helpers are re-declared
// here at module scope).
// ============================================================================

/// Build a Components-tab diff `App` whose single modified `model-a` carries
/// one `ml_metric:*` field change (mirrors `diff_alignment::ml_metric_change`).
fn ml_metric_probe_app(metric: &str, old_v: &str, new_v: &str) -> App {
    use crate::model::{Component, NormalizedSbom};
    pin_theme();
    let old = Component::new("model-a".to_string(), "model-a".to_string())
        .with_version("1.0.0".to_string());
    let new = old.clone();
    let mut change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0);
    change.field_changes = vec![crate::diff::FieldChange {
        field: format!("ml_metric:{metric}"),
        old_value: Some(old_v.to_string()),
        new_value: Some(new_v.to_string()),
    }];
    let mut result = crate::diff::DiffResult::new();
    result.components.modified.push(change);
    result.calculate_summary();
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Components;
    app
}

/// The TUI coloring must consult the same shared `ml_metric_higher_is_better`
/// table as the CLI `--fail-on-ml-regression` gate: a lower-is-better metric
/// moving up is a regression (\u{25bc}), '@slice' suffixes strip to the base
/// metric, and unknown metrics fall back to neutral with no direction cue.
#[test]
fn ml_metric_direction_in_tui_follows_shared_table() {
    // (1) lower-is-better: loss 0.2 -> 0.3 must show the regressed arrow.
    let mut app = ml_metric_probe_app("loss", "0.2", "0.3");
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("ml_metric:loss"),
        "precondition: the metric field change must render in the detail panel:\n{text}"
    );
    assert!(
        text.contains('\u{25bc}'),
        "loss 0.2 -> 0.3 is a regression for a lower-is-better metric and must carry the down arrow:\n{text}"
    );
    assert!(
        !text.contains('\u{25b2}'),
        "a loss increase must never render as improved:\n{text}"
    );

    // (2) '@slice' suffix strips to the higher-is-better base metric.
    let mut app = ml_metric_probe_app("accuracy@validation", "0.9", "0.8");
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains('\u{25bc}') && !text.contains('\u{25b2}'),
        "accuracy@validation must strip to accuracy (higher-is-better), so 0.9 -> 0.8 shows the regressed arrow:\n{text}"
    );

    // (3) unknown metric: no direction knowledge, neutral rendering.
    let mut app = ml_metric_probe_app("custom_metric", "1", "0");
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("ml_metric:custom_metric"),
        "precondition: the unknown metric field change must render:\n{text}"
    );
    assert!(
        !text.contains('\u{25bc}') && !text.contains('\u{25b2}'),
        "unknown metrics must fall back to neutral coloring with no direction arrow:\n{text}"
    );
}

/// Non-finite ml_metric values must fall back to neutral removed/added
/// coloring with NO direction arrow: without the is_finite() guard in
/// render_diff_detail (src/tui/views/components.rs), NaN/inf comparisons
/// fall through to "Improved" and paint a green up arrow.
#[test]
fn nonfinite_ml_metric_renders_without_direction_arrow() {
    // NaN old value: `new < old` and `new == old` are both false for NaN, so
    // an unguarded classifier lands on Improved (\u{25b2}).
    let mut app = ml_metric_probe_app("accuracy", "NaN", "0.8");
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("ml_metric:accuracy"),
        "precondition: the metric field change must render in the detail panel:\n{text}"
    );
    assert!(
        !text.contains('\u{25b2}') && !text.contains('\u{25bc}'),
        "a NaN metric value must render neutrally with no direction arrow:\n{text}"
    );

    // inf new value: unguarded, `inf > 0.9` classifies as Improved.
    let mut app = ml_metric_probe_app("accuracy", "0.9", "inf");
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        !text.contains('\u{25b2}') && !text.contains('\u{25bc}'),
        "an inf metric value must not be classified as improved/regressed:\n{text}"
    );
}

/// The Summary caps ML-regression lines at 3 and renders a muted
/// "... +N more ML regressions" overflow line instead of unbounded lines
/// (src/tui/views/summary.rs take(3) + the count_findings arithmetic).
#[test]
fn summary_caps_ml_regressions_with_overflow_line() {
    use crate::model::NormalizedSbom;
    pin_theme();
    let mut result = crate::diff::DiffResult::default();
    for i in 0..5 {
        result.ml_regressions.push(crate::diff::MlRegression {
            component: format!("model-{i}"),
            metric: "accuracy".to_string(),
            previous_value: 0.9,
            new_value: 0.8,
        });
    }
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Summary;
    // 120x50, not 120x40: at 40 rows the summary layout cascade shrinks the
    // findings header (summary_layout_plan step (a)) and clips the last line
    // by LAYOUT, which would mask the cap under test. At 50 rows the header
    // keeps its planned height and all findings lines (3 chrome + 4 ML + 1
    // vuln status) fit its inner area exactly.
    let text = render_to_text(120, 50, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("ML REGRESSION"),
        "precondition: the ML regression badge must render:\n{text}"
    );
    assert!(
        text.contains("model-2 accuracy: 0.90 \u{2192} 0.80"),
        "the third (last capped) regression must still be listed individually:\n{text}"
    );
    assert!(
        text.contains("+2 more ML regressions"),
        "5 regressions must produce the '+2 more ML regressions' overflow line:\n{text}"
    );
    assert!(
        !text.contains("model-3") && !text.contains("model-4"),
        "regressions beyond the cap of 3 must not be listed individually:\n{text}"
    );
}

/// The Summary's Matching card must name the weakest matched component in
/// muted text after the Min score when min_match_score < 0.995
/// (src/tui/views/summary.rs render_match_metrics_card).
#[test]
fn summary_matching_card_names_weakest_match() {
    use crate::model::{Component, NormalizedSbom};
    pin_theme();
    // 5-char name: the card truncates the name to (card_width - 31) and the
    // Matching card is 36 cols wide at 120x40 (insights 60% of 120 = 72,
    // split across the Quality + Matching cards), leaving a 5-col budget.
    let old =
        Component::new("shaky".to_string(), "shaky".to_string()).with_version("1.0".to_string());
    let new = old.clone();
    let change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0)
        .with_match_info(crate::diff::MatchInfo::simple(0.62, "Fuzzy", "probe"));
    let mut result = crate::diff::DiffResult::new();
    result.components.modified.push(change);
    // App::new_diff and calculate_summary never touch match_metrics, so the
    // manual assignment survives into the render.
    result.match_metrics = Some(crate::diff::MatchMetrics {
        fuzzy_matches: 1,
        avg_match_score: 0.62,
        min_match_score: 0.62,
        ..Default::default()
    });
    result.calculate_summary();
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Summary;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // The closing paren is deliberately omitted from the needle: the line
    // fills the card's inner width exactly, so a 1-cell layout shave must
    // not turn a still-correct render into a false failure.
    assert!(
        text.contains("Min: 0.62 (shaky"),
        "the Matching card must name the weakest matched component after the Min score:\n{text}"
    );
}

/// Render a Components-tab diff whose single modified component carries a
/// 0.75 match of the given tier, and return the fg color painted on the
/// "0.75" digits of the detail panel's "Score:" line. Buffer-level scan:
/// `render_to_text` strips styles, so color banding needs the raw cells.
fn match_score_fg(method: &str) -> ratatui::style::Color {
    use crate::model::{Component, NormalizedSbom};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pin_theme();
    let old = Component::new("fuzzy-lib".to_string(), "fuzzy-lib".to_string())
        .with_version("1.0".to_string());
    let new = old.clone();
    let change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0)
        .with_match_info(crate::diff::MatchInfo::simple(0.75, method, "tier probe"));
    let mut result = crate::diff::DiffResult::new();
    result.components.modified.push(change);
    result.calculate_summary();
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Components;

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| {
            app.prepare_render();
            render(frame, &mut app);
        })
        .expect("render");
    let buffer = terminal.backend().buffer();
    const DIGITS: [&str; 4] = ["0", ".", "7", "5"];
    for y in 0..40u16 {
        let row: String = (0..120u16)
            .filter_map(|x| buffer.cell((x, y)).map(|c| c.symbol().to_string()))
            .collect();
        if !row.contains("Score: 0.75") {
            continue;
        }
        for x in 0..117u16 {
            let is_score = (0..4u16)
                .all(|i| buffer.cell((x + i, y)).map(|c| c.symbol()) == Some(DIGITS[i as usize]));
            if is_score {
                return buffer
                    .cell((x, y))
                    .and_then(|c| c.style().fg)
                    .expect("score digits must carry an explicit fg color");
            }
        }
    }
    panic!("no 'Score: 0.75' line rendered on the Components tab");
}

/// The match-score color must band on the CI LOWER bound, not the raw score:
/// a fuzzy 0.75 (tier margin 0.08 => lower 0.67 < 0.7) paints error, while a
/// near-exact 0.75 (NameIdentity margin 0.03 => lower 0.72) paints warning.
#[test]
fn match_score_color_bands_on_ci_lower_bound() {
    let fuzzy_fg = match_score_fg("Fuzzy");
    let scheme = crate::tui::theme::colors();
    assert_eq!(
        fuzzy_fg, scheme.error,
        "a fuzzy 0.75 (CI lower 0.67) must band on the CI lower bound as error, not on the raw score"
    );

    let name_fg = match_score_fg("NameIdentity");
    assert_eq!(
        name_fg, scheme.warning,
        "a near-exact 0.75 (CI lower 0.72) must band as warning"
    );
    assert_ne!(
        scheme.error, scheme.warning,
        "theme sanity: the two bands must be visually distinguishable"
    );
}

// ============================================================================
// Diff TUI polish residuals (#165/#142, #80, #203, #76, #198, #95)
// ============================================================================

mod polish_residuals {
    use super::{App, TabKind, demo_app, key, render};
    use crate::tui::events::handle_key_event;
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline, render_to_text};
    use crossterm::event::KeyCode;

    const CBOM_OLD: &str = include_str!("../../../tests/fixtures/cyclonedx/cbom-1.6.cdx.json");
    const CBOM_NEW: &str = include_str!("../../../tests/fixtures/cyclonedx/cbom-1.7.cdx.json");

    fn render_app(app: &mut App, w: u16, h: u16) -> String {
        render_to_text(w, h, |frame| {
            app.prepare_render();
            render(frame, app);
        })
    }

    fn cbom_diff_app(tab: TabKind) -> App {
        crate::tui::test_support::pin_theme();
        let old = crate::parsers::parse_sbom_str(CBOM_OLD).expect("old cbom fixture must parse");
        let new = crate::parsers::parse_sbom_str(CBOM_NEW).expect("new cbom fixture must parse");
        let diff = crate::diff::DiffEngine::new()
            .diff(&old, &new)
            .expect("diff must succeed");
        let mut app = App::new_diff(diff, old, new, CBOM_OLD, CBOM_NEW);
        app.active_tab = tab;
        app
    }

    /// #165 + #142: the compliance help bar drops whole key+label pairs with
    /// a trailing '…' when width runs out (no more bare 'E' at 80 cols), and
    /// the grouping hint reads "g group [Flat]" — same verb and capitalized
    /// state vocabulary as the View app.
    #[test]
    fn compliance_help_bar_elides_whole_hints() {
        let mut app = demo_app(TabKind::Compliance);
        let text = render_app(&mut app, 80, 24);
        assert!(
            text.contains("g group [Flat]"),
            "grouping hint must read 'g group [Flat]':\n{text}"
        );
        assert!(
            !text.contains("export report"),
            "at 80 cols the E hint does not fit and must be dropped whole:\n{text}"
        );
        assert!(
            text.contains("[Overview] \u{2026}"),
            "dropped hints must be marked with a trailing ellipsis:\n{text}"
        );

        let mut app = demo_app(TabKind::Compliance);
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("E export report (JSON)"),
            "at 120 cols the E hint fits and must render whole:\n{text}"
        );
    }

    /// #80: CBOM diffs surface the component TYPE (from cryptoProperties
    /// assetType) as a Components-table column and a detail field, and the
    /// Summary chart groups by asset type instead of (absent) ecosystems.
    #[test]
    fn cbom_diff_shows_asset_types() {
        let mut app = cbom_diff_app(TabKind::Components);
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("Type"),
            "Components table must have a Type column for CBOM diffs:\n{text}"
        );
        assert!(
            text.contains("algorithm"),
            "crypto assets must show their assetType in the table:\n{text}"
        );
        assert!(
            text.contains("Type: certificate"),
            "the detail panel must name the selected asset's type:\n{text}"
        );

        let mut app = cbom_diff_app(TabKind::Summary);
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("Changes by Asset Type"),
            "CBOM summary must group changes by asset type:\n{text}"
        );
        assert!(
            !text.contains("Changes by Ecosystem"),
            "the ecosystem grouping (all 'unknown' for crypto assets) must be replaced:\n{text}"
        );

        // Plain SBOM diffs keep the ecosystem grouping (120x50: the demo's
        // taller header drops the charts row at 40 rows).
        let mut app = demo_app(TabKind::Summary);
        let text = render_app(&mut app, 120, 50);
        assert!(
            text.contains("Changes by Ecosystem"),
            "SBOM diffs keep the ecosystem chart:\n{text}"
        );
    }

    /// #203: 'D' resolves the deep-dive target from the ACTIVE tab. Tabs
    /// without a component-shaped selection explain themselves instead of
    /// silently opening the hidden Components-tab selection.
    #[test]
    fn deep_dive_resolves_from_active_tab() {
        // Licenses: no component context -> status message, no overlay.
        let mut app = demo_app(TabKind::Licenses);
        app.prepare_render();
        handle_key_event(&mut app, key(KeyCode::Char('D')));
        assert!(
            !app.overlays.component_deep_dive.visible,
            "'D' on Licenses must not open the hidden Components selection"
        );
        assert_eq!(
            app.status_message.as_deref(),
            Some("Deep dive: select a component on the Components tab"),
        );

        // Vulnerabilities: the selected row's component is the target.
        let mut app = demo_app(TabKind::Vulnerabilities);
        app.prepare_render();
        app.ensure_vulnerability_cache();
        let expected = app.diff_vulnerability_items_from_cache()[0]
            .vuln
            .component_name
            .clone();
        handle_key_event(&mut app, key(KeyCode::Char('D')));
        assert!(
            app.overlays.component_deep_dive.visible,
            "'D' on Vulnerabilities opens the deep dive for the selected row's component \
             (status: {:?})",
            app.status_message
        );
        assert_eq!(app.overlays.component_deep_dive.component_name, expected);
    }

    /// #198: while a multi-mode modal is open (and swallowing every key), the
    /// status bar advertises the MODAL's keys, not the dead mode hints.
    #[test]
    fn modal_status_bars_show_modal_keys() {
        crate::tui::test_support::pin_theme();

        // Matrix pair-diff modal.
        let mut app = App::new_matrix(demo_matrix());
        handle_key_event(&mut app, key(KeyCode::Char('l'))); // col 1: distinct pair
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert!(app.tabs.matrix.show_pair_diff, "Enter opens the pair diff");
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("j/k scroll") && text.contains("Esc close"),
            "matrix status bar must show the modal's keys:\n{text}"
        );
        assert!(
            !text.contains("q quit"),
            "'q quit' is false while the modal is open (q closes it):\n{text}"
        );

        // Multi-diff variable drill-down.
        let mut app = App::new_multi_diff(demo_multi_diff());
        handle_key_event(&mut app, key(KeyCode::Char('v')));
        assert!(app.tabs.multi_diff.show_variable_drill_down);
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("j/k select") && text.contains("Esc close"),
            "multi status bar must show the drill-down's keys:\n{text}"
        );
        assert!(!text.contains("q quit"), "mode hints are dead:\n{text}");

        // Timeline version-diff modal ('d').
        let mut app = App::new_timeline(demo_timeline());
        handle_key_event(&mut app, key(KeyCode::Char('d')));
        assert!(app.tabs.timeline.show_version_diff_modal);
        let text = render_app(&mut app, 120, 40);
        assert!(
            text.contains("\u{2190}/\u{2192} compare version") && text.contains("Esc close"),
            "timeline status bar must show the modal's keys:\n{text}"
        );
        assert!(!text.contains("q quit"), "mode hints are dead:\n{text}");
    }

    /// #95: the matrix pair-diff modal scrolls with j/k, so entries beyond
    /// the visible window are reachable, with row-exact hidden-line markers.
    #[test]
    fn matrix_pair_diff_modal_scrolls() {
        crate::tui::test_support::pin_theme();
        let mut app = App::new_matrix(demo_matrix());
        // beta ↔ gamma: the most changes (9 removed) => overflows at 80x24.
        handle_key_event(&mut app, key(KeyCode::Char('j')));
        handle_key_event(&mut app, key(KeyCode::Char('l')));
        handle_key_event(&mut app, key(KeyCode::Char('l')));
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert!(app.tabs.matrix.show_pair_diff);

        let text = render_app(&mut app, 80, 24);
        assert!(
            text.contains("\u{2014} j/k to scroll"),
            "overflow marker must advertise scrolling:\n{text}"
        );
        assert!(
            !text.contains("above"),
            "unscrolled modal has nothing hidden above:\n{text}"
        );

        // Scroll two lines: the above-marker must count exactly 2.
        handle_key_event(&mut app, key(KeyCode::Char('j')));
        handle_key_event(&mut app, key(KeyCode::Char('j')));
        let text = render_app(&mut app, 80, 24);
        assert!(
            text.contains("\u{2191} 2 more lines above"),
            "after jj the above-marker must count 2:\n{text}"
        );

        // Scroll far past the end: the offset clamps, the bottom marker
        // disappears, and the LAST body line (previously unreachable beyond
        // the per-section cap) is now visible.
        for _ in 0..100 {
            handle_key_event(&mut app, key(KeyCode::Char('j')));
        }
        let text = render_app(&mut app, 80, 24);
        assert!(
            !text.contains("\u{2014} j/k to scroll"),
            "fully scrolled: nothing hidden below:\n{text}"
        );
        assert!(
            text.contains("above"),
            "fully scrolled: hidden lines are above:\n{text}"
        );

        // 'k' scrolls back up (the bottom marker returns).
        handle_key_event(&mut app, key(KeyCode::Char('k')));
        let text = render_app(&mut app, 80, 24);
        assert!(
            text.contains("\u{2014} j/k to scroll"),
            "'k' scrolls back up:\n{text}"
        );

        // Esc still closes and resets the scroll.
        handle_key_event(&mut app, key(KeyCode::Esc));
        assert!(!app.tabs.matrix.show_pair_diff);
        assert_eq!(crate::tui::events::pair_diff_scroll(), 0);
    }
}
