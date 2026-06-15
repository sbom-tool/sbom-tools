//! Shared helpers for TUI snapshot and event tests.
//!
//! Test-only module. Constructs apps from the demo fixtures with a pinned
//! theme so that rendered output is deterministic across runs, and renders a
//! [`TestBackend`] buffer down to plain trimmed text suitable for `insta`
//! string snapshots (colors/styles are intentionally dropped — only the cell
//! glyphs are captured, which is what makes the snapshots stable).

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use crate::diff::{DiffEngine, DiffResult};
use crate::model::{BomProfile, NormalizedSbom};
use crate::parsers::parse_sbom_str;

/// Old demo SBOM (CycloneDX 1.5) used as the diff "before" side.
pub(crate) const DEMO_OLD: &str = include_str!("../../tests/fixtures/demo-old.cdx.json");
/// New demo SBOM (CycloneDX 1.5) used as the diff "after" side.
pub(crate) const DEMO_NEW: &str = include_str!("../../tests/fixtures/demo-new.cdx.json");

/// A complete BSI-aligned AI-BOM fixture (ML model + dataset components).
/// Used by AI-BOM `ViewApp` tab tests; `BomProfile::detect` classifies it as
/// `BomProfile::AiBom`.
pub(crate) const AIBOM_BSI: &str =
    include_str!("../../tests/fixtures/cyclonedx/bsi-aibom-complete.cdx.json");

/// Snapshot terminal sizes: a standard 80x24 and a wide 120x40.
pub(crate) const SIZES: [(u16, u16); 2] = [(80, 24), (120, 40)];

/// Pin the global theme to `dark` so styling is deterministic.
///
/// The text snapshots do not capture color, but pinning the theme also keeps
/// any theme-dependent glyph choices stable and isolates the tests from a
/// developer's saved theme preference.
pub(crate) fn pin_theme() {
    crate::tui::theme::set_theme(crate::tui::theme::Theme::dark());
}

/// Parse the two demo fixtures and compute a diff with the default engine.
pub(crate) fn demo_diff() -> (DiffResult, NormalizedSbom, NormalizedSbom) {
    let old = parse_sbom_str(DEMO_OLD).expect("demo-old fixture must parse");
    let new = parse_sbom_str(DEMO_NEW).expect("demo-new fixture must parse");
    let result = DiffEngine::new()
        .diff(&old, &new)
        .expect("demo diff must succeed");
    (result, old, new)
}

/// Parse the new demo fixture as a single SBOM for `ViewApp` tests.
pub(crate) fn demo_single() -> (NormalizedSbom, BomProfile) {
    let sbom = parse_sbom_str(DEMO_NEW).expect("demo-new fixture must parse");
    let profile = BomProfile::detect(&sbom);
    (sbom, profile)
}

/// Parse the BSI AI-BOM fixture as a single SBOM for AI-BOM `ViewApp` tests.
pub(crate) fn aibom_single() -> (NormalizedSbom, BomProfile) {
    let sbom = parse_sbom_str(AIBOM_BSI).expect("bsi-aibom fixture must parse");
    let profile = BomProfile::detect(&sbom);
    (sbom, profile)
}

/// Render a closure into a [`TestBackend`] of the given size and return the
/// buffer as newline-joined, right-trimmed text.
pub(crate) fn render_to_text<F>(width: u16, height: u16, draw: F) -> String
where
    F: FnOnce(&mut ratatui::Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("TestBackend terminal");
    terminal.draw(draw).expect("draw must succeed");
    buffer_to_text(terminal.backend().buffer())
}

/// Convert a ratatui [`Buffer`](ratatui::buffer::Buffer) into plain text:
/// one line per row, cell glyphs concatenated, trailing spaces trimmed.
fn buffer_to_text(buffer: &ratatui::buffer::Buffer) -> String {
    let width = buffer.area.width as usize;
    let mut out = String::new();
    for row in buffer.content.chunks(width) {
        let mut line = String::new();
        for cell in row {
            line.push_str(cell.symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
