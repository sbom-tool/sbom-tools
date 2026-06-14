//! Golden snapshot coverage for every user-facing report format.
//!
//! The `reports` module has ~9 output formats but historically only
//! count-based assertions (see `golden_fixtures.rs`); there were no stored
//! expected outputs, so a silent change to any renderer's structure or schema
//! could ship undetected. These tests render a FIXED diff pair
//! (`tests/fixtures/demo-old.cdx.json` vs `demo-new.cdx.json`) through each
//! `ReportFormat` and snapshot the result with `insta`.
//!
//! Volatile fields (generation timestamp, tool version, absolute file paths,
//! and time-relative SLA/age strings) are redacted via `insta` filters before
//! snapshotting so the baselines stay stable across machines and releases.
//!
//! The streaming JSON and NDJSON writers are snapshotted SEPARATELY from
//! `JsonReporter`. The streaming JSON schema intentionally differs from the
//! buffered `JsonReporter` schema today (different key layout, no CRA block);
//! pinning both makes that fork visible and locked so neither side drifts
//! silently.

use sbom_tools::model::NormalizedSbom;
use sbom_tools::reports::{
    CsvReporter, HtmlReporter, JsonReporter, MarkdownReporter, NdjsonWriter, ReportConfig,
    ReportGenerator, ReportType, SarifReporter, SideBySideReporter, StreamingJsonWriter,
    SummaryReporter, TableReporter,
};
use sbom_tools::{DiffEngine, DiffResult, parse_sbom_str};

const DEMO_OLD: &str = include_str!("fixtures/demo-old.cdx.json");
const DEMO_NEW: &str = include_str!("fixtures/demo-new.cdx.json");

/// Parse the demo fixtures and compute their diff once per test.
fn demo_diff() -> (DiffResult, NormalizedSbom, NormalizedSbom) {
    let old = parse_sbom_str(DEMO_OLD).expect("demo-old fixture must parse");
    let new = parse_sbom_str(DEMO_NEW).expect("demo-new fixture must parse");
    let diff = DiffEngine::new()
        .diff(&old, &new)
        .expect("demo diff must succeed");
    (diff, old, new)
}

/// A report config with stable file-path metadata so the path-redaction filter
/// has a predictable target and the rendered output is deterministic.
fn stable_config() -> ReportConfig {
    let mut config = ReportConfig::all();
    config.metadata.old_sbom_path = Some("tests/fixtures/demo-old.cdx.json".to_string());
    config.metadata.new_sbom_path = Some("tests/fixtures/demo-new.cdx.json".to_string());
    config
}

/// Build an `insta::Settings` with redaction filters for every volatile field
/// a report renderer can emit. Applied via `bind` so each snapshot is stable.
///
/// Filters run in order; each replaces a volatile substring with a fixed token.
fn redacted_settings() -> insta::Settings {
    let mut settings = insta::Settings::clone_current();
    // RFC 3339 timestamps (JSON / SARIF / streaming `generated_at`).
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        "[TIMESTAMP]",
    );
    // Human-formatted timestamps (`YYYY-MM-DD HH:MM:SS UTC`) in Markdown / HTML.
    settings.add_filter(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", "[TIMESTAMP]");
    // Tool version: `"version": "0.1.21"` (pretty JSON / SARIF) or
    // `"version":"0.1.21"` (compact NDJSON). Match with optional space.
    settings.add_filter(
        r#""version": ?"\d+\.\d+\.\d+""#,
        r#""version": "[VERSION]""#,
    );
    // Tool version embedded in Markdown / HTML prose, e.g. `sbom-tools v0.1.21`.
    settings.add_filter(r"v\d+\.\d+\.\d+", "v[VERSION]");
    // Time-relative SLA / age strings, e.g. `12d old`, `3d overdue`, `5d remaining`.
    settings.add_filter(r"\d+d (old|overdue|remaining)", "[N]d $1");

    // ── CRA Article 14 readiness is date-relative ───────────────────────────
    // The Art. 14 reporting-channel checks flip at the hard-coded 2026-09-11
    // deadline (see src/quality/compliance/cra.rs): pre-deadline the three
    // channel violations are `Info` with "before the deadline" message text;
    // post-deadline they become `Warning` with different text. Normalise the
    // message variants, the channel-status labels, and the affected aggregate
    // counts so the golden baselines stay stable across that boundary.

    // PSIRT (Art. 14): collapse the two message variants to one token.
    settings.add_filter(
        r"\[CRA Art\. 14\] PSIRT URL missing — [^\n\\]*?(?:deadline|reports)",
        "[CRA Art. 14] PSIRT URL missing — [ART14]",
    );
    // Early-warning (Art. 14(1)).
    settings.add_filter(
        r"\[CRA Art\. 14\(1\)\] 24-hour early-warning channel missing — [^\n\\]*?(?:2026-09-11|identified)",
        "[CRA Art. 14(1)] 24-hour early-warning channel missing — [ART14]",
    );
    // Incident-report (Art. 14(2)).
    settings.add_filter(
        r"\[CRA Art\. 14\(2\)\] 72-hour incident-report channel missing — [^\n\\]*?(?:2026-09-11|security)",
        "[CRA Art. 14(2)] 72-hour incident-report channel missing — [ART14]",
    );
    // Markdown / HTML channel-status label: pre-deadline shows
    // "Missing (pre-deadline 2026-09-11)"; post-deadline shows bare "Missing".
    settings.add_filter(r"Missing \(pre-deadline 2026-09-11\)", "Missing");
    // The three channel violations' severity flips Info->Warning at the
    // deadline. They serialise as `"severity": "...",` immediately followed by
    // `"category": "SecurityInfo"` and a `[CRA Art. 14...` message. Normalise
    // any severity in that exact position. (?s) lets `.` span the newline.
    settings.add_filter(
        r#"(?s)"severity": "(?:Info|Warning|Error)",(\s*"category": "SecurityInfo",\s*"message": "\[CRA Art\. 14)"#,
        r#""severity": "[ART14_SEV]",$1"#,
    );
    // CRA aggregate counts shift by the three Art. 14 channels at the deadline
    // (info_count down 3, warning_count up 3). Redact the count fields and the
    // Markdown/HTML "Warnings"/"Info" rows so the totals stay stable.
    settings.add_filter(r#""warning_count": \d+"#, r#""warning_count": "[N]""#);
    settings.add_filter(r#""info_count": \d+"#, r#""info_count": "[N]""#);
    // Markdown CRA table: `| **Warnings** | 16 | 16 |  |`.
    settings.add_filter(
        r"\| \*\*Warnings\*\* \| \d+ \| \d+ \|",
        "| **Warnings** | [N] | [N] |",
    );
    // HTML CRA table: `<tr>...<strong>Warnings</strong>...<td>16</td><td>16</td>...`.
    settings.add_filter(
        r"<strong>Warnings</strong></td><td>\d+</td><td>\d+</td>",
        "<strong>Warnings</strong></td><td>[N]</td><td>[N]</td>",
    );

    settings
}

/// Render a format via a `ReportGenerator` and return its output string.
fn render<R: ReportGenerator>(reporter: &R) -> String {
    let (diff, old, new) = demo_diff();
    let config = stable_config();
    reporter
        .generate_diff_report(&diff, &old, &new, &config)
        .expect("report generation must succeed")
}

// ── Buffered (string) reporters ─────────────────────────────────────────────

#[test]
fn golden_json_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("json", render(&JsonReporter::new()));
    });
}

#[test]
fn golden_sarif_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("sarif", render(&SarifReporter::new()));
    });
}

#[test]
fn golden_markdown_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("markdown", render(&MarkdownReporter::new()));
    });
}

#[test]
fn golden_html_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("html", render(&HtmlReporter::new()));
    });
}

#[test]
fn golden_csv_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("csv", render(&CsvReporter::new()));
    });
}

#[test]
fn golden_summary_report() {
    // `no_color` so the snapshot has no ANSI escape sequences.
    redacted_settings().bind(|| {
        insta::assert_snapshot!("summary", render(&SummaryReporter::new().no_color()));
    });
}

#[test]
fn golden_table_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("table", render(&TableReporter::new().no_color()));
    });
}

#[test]
fn golden_sidebyside_report() {
    redacted_settings().bind(|| {
        insta::assert_snapshot!("sidebyside", render(&SideBySideReporter::new()));
    });
}

// ── Streaming writers (snapshotted separately from JsonReporter) ─────────────

#[test]
fn golden_streaming_json_report() {
    let (diff, old, new) = demo_diff();
    let config = stable_config();
    let mut buf = Vec::new();
    StreamingJsonWriter::new(&mut buf, true)
        .write_diff_report(&diff, &old, &new, &config)
        .expect("streaming JSON must succeed");
    let output = String::from_utf8(buf).expect("streaming JSON must be UTF-8");
    redacted_settings().bind(|| {
        insta::assert_snapshot!("streaming_json", output);
    });
}

#[test]
fn golden_ndjson_report() {
    let (diff, old, new) = demo_diff();
    let config = stable_config();
    let mut buf = Vec::new();
    NdjsonWriter::new(&mut buf)
        .write_diff_report(&diff, &old, &new, &config)
        .expect("NDJSON must succeed");
    let output = String::from_utf8(buf).expect("NDJSON must be UTF-8");
    redacted_settings().bind(|| {
        insta::assert_snapshot!("ndjson", output);
    });
}

// ── Validity regression guards ──────────────────────────────────────────────

/// Both the buffered `JsonReporter` and the `StreamingJsonWriter` MUST emit
/// JSON that round-trips through a strict parser. This pins the streaming
/// trailing-comma fix (an unconditional `,` after the summary section used to
/// produce invalid JSON when no report sections were selected).
#[test]
fn json_outputs_are_valid_json() {
    let (diff, old, new) = demo_diff();
    let config = stable_config();

    let buffered = JsonReporter::new()
        .generate_diff_report(&diff, &old, &new, &config)
        .expect("buffered JSON must succeed");
    serde_json::from_str::<serde_json::Value>(&buffered)
        .expect("JsonReporter output must be valid JSON");

    let mut buf = Vec::new();
    StreamingJsonWriter::new(&mut buf, true)
        .write_diff_report(&diff, &old, &new, &config)
        .expect("streaming JSON must succeed");
    let streamed = String::from_utf8(buf).expect("streaming JSON must be UTF-8");
    serde_json::from_str::<serde_json::Value>(&streamed)
        .expect("StreamingJsonWriter output must be valid JSON");
}

/// Regression guard for the streaming trailing-comma bug: with an EMPTY report
/// selection only `metadata` + `summary` are emitted, so the summary must NOT
/// carry a trailing comma. Before the fix this produced invalid JSON.
#[test]
fn streaming_json_valid_with_no_sections_selected() {
    let (diff, old, new) = demo_diff();
    let config = ReportConfig::with_types(vec![]);

    // Pretty and compact must both round-trip.
    for pretty in [true, false] {
        let mut buf = Vec::new();
        StreamingJsonWriter::new(&mut buf, pretty)
            .write_diff_report(&diff, &old, &new, &config)
            .expect("streaming JSON must succeed");
        let streamed = String::from_utf8(buf).expect("streaming JSON must be UTF-8");
        let value: serde_json::Value = serde_json::from_str(&streamed).unwrap_or_else(|e| {
            panic!(
                "streaming JSON with no sections must be valid (pretty={pretty}): {e}\n{streamed}"
            )
        });
        // Only metadata + summary, no section arrays.
        assert!(value.get("metadata").is_some());
        assert!(value.get("summary").is_some());
        assert!(value.get("components_added").is_none());
    }
}

/// Per-section selections must each yield valid JSON (every section can be the
/// last one written, so each must correctly omit its trailing comma).
#[test]
fn streaming_json_valid_for_each_single_section() {
    let (diff, old, new) = demo_diff();
    for section in [
        ReportType::Components,
        ReportType::Vulnerabilities,
        ReportType::Dependencies,
        ReportType::Licenses,
    ] {
        let config = ReportConfig::with_types(vec![section]);
        let mut buf = Vec::new();
        StreamingJsonWriter::new(&mut buf, true)
            .write_diff_report(&diff, &old, &new, &config)
            .expect("streaming JSON must succeed");
        let streamed = String::from_utf8(buf).expect("streaming JSON must be UTF-8");
        serde_json::from_str::<serde_json::Value>(&streamed).unwrap_or_else(|e| {
            panic!("streaming JSON for {section:?} must be valid: {e}\n{streamed}")
        });
    }
}

// ── SARIF structural invariants ─────────────────────────────────────────────

/// SARIF feeds CI security dashboards, so guard its structure without adding a
/// JSON-schema dependency: assert the document shape, that the driver declares
/// rules, and that every result references a declared `ruleId`.
#[test]
fn sarif_structural_invariants() {
    let sarif = render(&SarifReporter::new());
    let doc: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF must be valid JSON");

    assert_eq!(doc["version"], "2.1.0", "SARIF version must be 2.1.0");
    assert!(doc["$schema"].is_string(), "SARIF must declare $schema");

    let runs = doc["runs"].as_array().expect("runs must be an array");
    assert_eq!(runs.len(), 1, "expected exactly one run");
    let run = &runs[0];

    let driver = &run["tool"]["driver"];
    assert_eq!(driver["name"], "sbom-tools");
    let rules = driver["rules"]
        .as_array()
        .expect("driver.rules must be present and an array");
    assert!(!rules.is_empty(), "driver must declare at least one rule");

    // Collect declared rule ids.
    let declared: std::collections::HashSet<&str> =
        rules.iter().filter_map(|r| r["id"].as_str()).collect();
    assert_eq!(
        declared.len(),
        rules.len(),
        "every declared rule must have a string id"
    );

    // Every result must reference a declared ruleId.
    let results = run["results"].as_array().expect("results must be an array");
    for result in results {
        let rule_id = result["ruleId"]
            .as_str()
            .expect("each result must carry a ruleId");
        assert!(
            declared.contains(rule_id),
            "result references undeclared ruleId: {rule_id}"
        );
    }
}
