//! Compliance snapshot harness.
//!
//! Pins what every compliance level decides for every SBOM fixture, so any
//! change that moves a verdict shows up as a snapshot diff that a reviewer
//! reads (and that becomes the release's Upgrade notes list). Two kinds:
//!
//! - **Verdict snapshots**, one per fixture: for each of the 19 levels, the
//!   verdict, the severity counts and every finding as (severity, rule ID,
//!   subject, counts), then the passed checks as `P` lines (rule ID,
//!   subject) after a `P<n>` count on the header. Messages are left out so
//!   rewording does not churn them. Fixtures with an auto-discovered CRA
//!   sidecar are also run with it, for the levels the shared run
//!   configuration (`ComplianceRunConfig`, which every CLI command and TUI
//!   uses) hands a sidecar to.
//! - **Byte snapshots** of the JSON (the v1 result array and the
//!   `sbom-tools/compliance/v2` envelope), SARIF and OSCAL writers for six
//!   pinned fixtures, plus a check that each writer is byte-identical across
//!   runs.
//! - **Deadline snapshots**, one per CBOM fixture: `cnsa2` and `pqc` under
//!   `--pqc-mode deadline` at three dates and in four configurations, each
//!   finding with its deadline and source. The verdict snapshots are the
//!   readiness mode, the default.
//!
//! Everything runs at a pinned `as_of`, so no snapshot depends on today's
//! date. Accept intended changes with `cargo insta review`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    CnsaCategory, ComplianceLevel, ComplianceResult, ComplianceRunConfig, PqcMode, PqcProfile,
    StandardSelector, ViolationSeverity,
};
use sbom_tools::reports::oscal::generate_assessment_results_at;
use sbom_tools::reports::{
    SarifArtifact, SarifArtifactLocation, SarifOptions, generate_compliance_json,
    generate_multi_compliance_sarif_with,
};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Evaluation instant for every snapshot: the v0.3.0 review date.
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// Fixture directories that hold SBOMs. `abi` holds C-ABI payloads, `csaf`
/// and `vex` hold advisories; none of those are SBOMs.
const SBOM_DIRS: &[&str] = &[
    "aibom",
    "compliance/regressions",
    "cra",
    "cyclonedx",
    "showcase",
    "spdx",
    "spdx3",
];

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc)
}

/// The run a snapshot is judged with: the pinned clock, plus the fixture's
/// auto-discovered CRA sidecar when it has one. The run configuration hands
/// each level the inputs `validate` (and every other entry point) hands it.
fn run(sidecar: Option<&CraSidecarMetadata>) -> ComplianceRunConfig {
    let run = ComplianceRunConfig::new().with_as_of(as_of());
    match sidecar {
        Some(sc) => run.with_sidecar(sc.clone()),
        None => run,
    }
}

/// The levels a run hands a CRA sidecar to, in report order.
fn sidecar_levels() -> Vec<ComplianceLevel> {
    ComplianceLevel::all()
        .iter()
        .copied()
        .filter(|level| ComplianceRunConfig::sidecar_applies(*level))
        .collect()
}

/// Every file under the SBOM directories, sorted, as (relative path, path).
fn fixture_files() -> Vec<(String, PathBuf)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let root = Path::new(FIXTURES_DIR);
    let mut paths = Vec::new();
    for dir in SBOM_DIRS {
        walk(&root.join(dir), &mut paths);
    }
    // The demo pair at the top level is used by the diff snapshots.
    for name in ["demo-old.cdx.json", "demo-new.cdx.json"] {
        paths.push(root.join(name));
    }
    let mut files: Vec<(String, PathBuf)> = paths
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .expect("under fixtures")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, p)
        })
        .collect();
    files.sort();
    files
}

/// Files that are fixtures but not SBOMs (sidecars, docs, scanner configs).
fn is_non_sbom(rel: &str) -> bool {
    rel.ends_with(".cra.json")
        || rel.ends_with(".cra.yaml")
        || rel.ends_with(".md")
        || rel.ends_with(".toml")
        || rel.ends_with("corpus.json")
        || rel.ends_with(".openvex.json")
}

fn severity_letter(s: ViolationSeverity) -> char {
    match s {
        ViolationSeverity::Error => 'E',
        ViolationSeverity::Warning => 'W',
        ViolationSeverity::Info => 'I',
        other => panic!("no verdict letter for severity {other:?}"),
    }
}

/// The subject a verdict line names. An empty canonical ID (review finding
/// V1) prints as "" so the collision stays visible instead of looking like a
/// blank.
fn subject<'a>(component_id: Option<&'a str>, element: Option<&'a str>) -> &'a str {
    match component_id.or(element) {
        None => "-",
        Some("") => "\"\"",
        Some(s) => s,
    }
}

/// Write `lines` sorted, one per distinct line, a repeat marked `×n`.
fn write_sorted(out: &mut String, mut lines: Vec<String>) {
    lines.sort();
    let mut i = 0;
    while i < lines.len() {
        let mut n = 1;
        while i + n < lines.len() && lines[i + n] == lines[i] {
            n += 1;
        }
        if n > 1 {
            let _ = writeln!(out, "  {} ×{n}", lines[i]);
        } else {
            let _ = writeln!(out, "  {}", lines[i]);
        }
        i += n;
    }
}

/// One verdict block: header line, one sorted, de-duplicated line per
/// distinct finding, then one per distinct passed check. A result that
/// passed checks counts them as `P<n>` on the header.
fn render_verdict(out: &mut String, label: &str, result: &ComplianceResult) {
    let verdict = if !result.is_applicable() {
        "not applicable"
    } else if result.is_compliant {
        "compliant"
    } else {
        "NON-COMPLIANT"
    };
    let passed = if result.passed.is_empty() {
        String::new()
    } else {
        format!(" P{}", result.passed.len())
    };
    let _ = writeln!(
        out,
        "[{label}] {verdict} · E{} W{} I{}{passed}",
        result.error_count, result.warning_count, result.info_count
    );
    let findings: Vec<String> = result
        .violations
        .iter()
        .map(|v| {
            let counts = v
                .counts
                .as_ref()
                .map(|c| format!(" ({}/{})", c.affected, c.total))
                .unwrap_or_default();
            format!(
                "{} {}  {}{}",
                severity_letter(v.severity),
                v.rule_id,
                subject(v.component_id.as_deref(), v.element.as_deref()),
                counts
            )
        })
        .collect();
    write_sorted(out, findings);
    let passes: Vec<String> = result
        .passed
        .iter()
        .map(|p| {
            format!(
                "P {}  {}",
                p.rule_id,
                subject(p.component_id.as_deref(), p.element.as_deref())
            )
        })
        .collect();
    write_sorted(out, passes);
}

fn snapshot_name(rel: &str) -> String {
    rel.replace(['/', '.'], "_")
}

#[test]
fn verdict_snapshots_for_every_fixture_and_level() {
    let mut skipped = Vec::new();
    let mut settings = insta::Settings::clone_current();
    settings.set_prepend_module_to_snapshot(true);
    settings.set_omit_expression(true);
    let _guard = settings.bind_to_scope();

    for (rel, path) in fixture_files() {
        if is_non_sbom(&rel) {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        let Ok(sbom) = parse_sbom_str(&raw) else {
            skipped.push(rel);
            continue;
        };
        let sidecar = CraSidecarMetadata::discover_for_sbom(&path)
            .unwrap_or_else(|e| panic!("{rel}: sidecar does not load: {e}"));

        let mut out = format!("fixture: {rel}\nas_of: {AS_OF}\n\n");
        for result in run(None).check_levels(ComplianceLevel::all(), &sbom) {
            render_verdict(&mut out, &format!("{:?}", result.level), &result);
        }
        if let Some(sc) = sidecar.as_ref() {
            out.push_str("\nwith auto-discovered CRA sidecar:\n");
            for result in run(Some(sc)).check_levels(&sidecar_levels(), &sbom) {
                render_verdict(&mut out, &format!("{:?} + sidecar", result.level), &result);
            }
        }
        insta::assert_snapshot!(format!("verdicts__{}", snapshot_name(&rel)), out);
    }

    // Files under the SBOM directories that do not parse are pinned too, so
    // a fixture that stops parsing is noticed instead of silently dropped.
    insta::assert_snapshot!("unparsed_fixtures", skipped.join("\n"));
}

/// The pinned fixtures for byte snapshots, each with the standards that
/// exercise it.
const BYTE_FIXTURES: &[(&str, &[&str])] = &[
    ("cyclonedx/minimal.cdx.json", &["ntia", "cisa-2026"]),
    ("cra/cra-compliant.cdx.json", &["cra", "cra-phase1"]),
    ("cyclonedx/cbom-1.7.cdx.json", &["cnsa2", "pqc"]),
    ("spdx/minimal.spdx.json", &["ntia", "fsct"]),
    ("spdx3/minimal.spdx3.json", &["bsi", "eo14028"]),
    ("cyclonedx/aibom-complete.cdx.json", &["ai-act", "bsi-ai"]),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The fixture text with CRLF line endings folded to LF. Windows checkouts
/// convert line endings (the repo has no `.gitattributes`), which would change
/// the SBOM digest that OSCAL UUIDs derive from.
fn lf_normalized(raw: &str) -> String {
    raw.replace("\r\n", "\n")
}

/// Strip the one value that changes on every release.
fn redact_version(text: &str) -> String {
    text.replace(
        &format!("\"{}\"", env!("CARGO_PKG_VERSION")),
        "\"[VERSION]\"",
    )
}

fn render_outputs(rel: &str, standards: &[&str]) -> [(&'static str, String); 4] {
    let path = Path::new(FIXTURES_DIR).join(rel);
    let raw = std::fs::read_to_string(&path).expect("fixture readable");
    let sbom = parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"));
    let sidecar = CraSidecarMetadata::discover_for_sbom(&path).expect("sidecar loads");
    let levels: Vec<ComplianceLevel> = standards
        .iter()
        .map(|name| {
            name.parse::<StandardSelector>()
                .expect("known standard")
                .level()
        })
        .collect();
    let results = run(sidecar.as_ref()).check_levels(&levels, &sbom);
    // The `--json-schema v1` layout predates passed checks and the checks
    // not evaluated and leaves them out, as `validate` does.
    let v1: Vec<ComplianceResult> = results
        .iter()
        .cloned()
        .map(|mut result| {
            result.passed.clear();
            result.evaluated.clear();
            result
        })
        .collect();
    let json = serde_json::to_string_pretty(&v1).expect("JSON serializes");
    let envelope = generate_compliance_json(&results).expect("envelope serializes");
    // The SBOM as the CLI names it from the repository root.
    let artifact = SarifArtifact::new(
        SarifArtifactLocation::relative(format!("tests/fixtures/{rel}")),
        &sbom,
        &raw,
    );
    let sarif = generate_multi_compliance_sarif_with(
        &results,
        &SarifOptions::new().with_artifact(artifact),
    )
    .expect("SARIF serializes");
    let oscal = generate_assessment_results_at(
        &results,
        &sbom,
        &sha256_hex(lf_normalized(&raw).as_bytes()),
        Some(as_of()),
    )
    .expect("OSCAL serializes");
    [
        ("json", json),
        ("json_v2", envelope),
        ("sarif", sarif),
        ("oscal", oscal),
    ]
}

#[test]
fn writer_byte_snapshots_are_stable_and_deterministic() {
    let mut settings = insta::Settings::clone_current();
    settings.set_prepend_module_to_snapshot(true);
    settings.set_omit_expression(true);
    let _guard = settings.bind_to_scope();

    for (rel, standards) in BYTE_FIXTURES {
        let first = render_outputs(rel, standards);
        // Byte-identical across runs: the review found FSCT reordering its
        // findings and OSCAL stamping the wall clock and random UUIDs.
        for _ in 0..2 {
            let again = render_outputs(rel, standards);
            for ((kind, a), (_, b)) in first.iter().zip(again.iter()) {
                assert_eq!(a, b, "{rel}: {kind} output differs between runs");
            }
        }
        for (kind, text) in &first {
            insta::assert_snapshot!(
                format!("bytes__{}__{kind}", snapshot_name(rel)),
                redact_version(text)
            );
        }
    }
}

/// The CBOM fixtures deadline mode is pinned on: the calendar fixture, which
/// exercises every schedule, and two others with real-world mixes.
const DEADLINE_FIXTURES: &[&str] = &[
    "cyclonedx/cbom-pqc-calendar.cdx.json",
    "cyclonedx/cbom-pqc-transition.cdx.json",
    "cyclonedx/cbom-cnsa2-violations.cdx.json",
];

/// The dates deadline mode is judged at: the review date, a date in NIST IR
/// 8547's 2031–2035 deprecation window, and one after its disallowance.
const DEADLINE_DATES: &[&str] = &[
    "2026-10-12T00:00:00Z",
    "2031-06-01T00:00:00Z",
    "2036-06-01T00:00:00Z",
];

/// The deadline-mode configurations, as the `validate` flags name them.
const DEADLINE_CONFIGS: &[(&str, ComplianceLevel, PqcProfile, Option<CnsaCategory>)] = &[
    ("pqc", ComplianceLevel::NistPqc, PqcProfile::Nist, None),
    (
        "pqc --pqc-profile federal",
        ComplianceLevel::NistPqc,
        PqcProfile::Federal,
        None,
    ),
    ("cnsa2", ComplianceLevel::Cnsa2, PqcProfile::Nist, None),
    (
        "cnsa2 --cnsa-category niche",
        ComplianceLevel::Cnsa2,
        PqcProfile::Nist,
        Some(CnsaCategory::Niche),
    ),
];

/// One deadline-mode block: the verdict line, then each finding as
/// (severity, rule ID, subject, deadline and source), sorted.
fn render_deadline_verdict(out: &mut String, label: &str, result: &ComplianceResult) {
    let verdict = if result.is_compliant {
        "compliant"
    } else {
        "NON-COMPLIANT"
    };
    let _ = writeln!(
        out,
        "[{label}] {verdict} · E{} W{} I{} P{}",
        result.error_count,
        result.warning_count,
        result.info_count,
        result.passed.len()
    );
    let findings: Vec<String> = result
        .violations
        .iter()
        .map(|v| {
            let deadline = v.deadline.as_ref().map_or_else(
                || "undated".to_string(),
                |d| format!("{} {}", d.date, d.source),
            );
            format!(
                "{} {}  {}  {deadline}",
                severity_letter(v.severity),
                v.rule_id,
                subject(v.component_id.as_deref(), v.element.as_deref()),
            )
        })
        .collect();
    write_sorted(out, findings);
}

#[test]
fn deadline_mode_snapshots_for_the_cbom_fixtures() {
    let mut settings = insta::Settings::clone_current();
    settings.set_prepend_module_to_snapshot(true);
    settings.set_omit_expression(true);
    let _guard = settings.bind_to_scope();

    for rel in DEADLINE_FIXTURES {
        let raw =
            std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel)).expect("fixture readable");
        let sbom = parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"));
        let mut out = format!("fixture: {rel}\n--pqc-mode deadline\n\n");
        for (label, level, profile, category) in DEADLINE_CONFIGS {
            for as_of in DEADLINE_DATES {
                let instant = chrono::DateTime::parse_from_rfc3339(as_of)
                    .expect("valid instant")
                    .with_timezone(&chrono::Utc);
                let mut run = ComplianceRunConfig::new()
                    .with_as_of(instant)
                    .with_pqc_mode(PqcMode::Deadline)
                    .with_pqc_profile(*profile);
                if let Some(category) = category {
                    run = run.with_cnsa_category(*category);
                }
                let day = &as_of[..10];
                render_deadline_verdict(
                    &mut out,
                    &format!("{label} @ {day}"),
                    &run.check(*level, &sbom),
                );
            }
        }
        insta::assert_snapshot!(format!("deadline__{}", snapshot_name(rel)), out);
    }
}
