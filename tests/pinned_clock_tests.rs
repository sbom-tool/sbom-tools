//! The pinned test clock: a source lint over every compliance test, and the
//! tests that cross a regulatory date gate on purpose.
//!
//! Compliance checks read the wall clock unless the checker is pinned, so a
//! test that builds `ComplianceChecker::new(level)` and nothing more changes
//! meaning when a date passes: the 2026-09-11 CRA Art. 14 gate broke snapshot
//! tests that way (#369). Tests build checkers with `checker(level)` from
//! `tests/common/clock.rs` (src test modules have a local equivalent) or pin
//! an explicit instant with `.with_as_of(...)` in the same expression. The
//! boundary tests below use explicit instants on both sides of each gate.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sbom_tools::model::{CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const CRA_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cra");

// ============================================================================
// Lint: no test builds a checker on the wall clock
// ============================================================================

const CALL: &str = "ComplianceChecker::new(";
const PIN: &str = ".with_as_of(";

/// `src` with comments and the contents of string and char literals blanked
/// (newlines kept), so text inside them never counts as code.
fn mask(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = c.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for ch in &mut out[from..to.min(c.len())] {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
    };
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        let end = match c[i] {
            '/' if next == Some('/') => (i..c.len()).find(|&j| c[j] == '\n').unwrap_or(c.len()),
            '/' if next == Some('*') => {
                let (mut depth, mut j) = (1, i + 2);
                while j < c.len() && depth > 0 {
                    match (c[j], c.get(j + 1)) {
                        ('/', Some('*')) => (depth, j) = (depth + 1, j + 2),
                        ('*', Some('/')) => (depth, j) = (depth - 1, j + 2),
                        _ => j += 1,
                    }
                }
                j
            }
            '"' => {
                let mut j = i + 1;
                while j < c.len() && c[j] != '"' {
                    j += if c[j] == '\\' { 2 } else { 1 };
                }
                j + 1
            }
            // A char literal; anything else after a quote is a lifetime.
            '\'' if next == Some('\\') => (i + 3..c.len())
                .find(|&j| c[j] == '\'')
                .map_or(c.len(), |j| j + 1),
            '\'' if c.get(i + 2) == Some(&'\'') => i + 3,
            ch if ch.is_alphabetic() || ch == '_' => {
                let start = i;
                while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                // Raw strings: r"…", r#"…"#, br"…".
                let hashes = c[i..].iter().take_while(|&&h| h == '#').count();
                let prefix: String = c[start..i].iter().collect();
                if matches!(prefix.as_str(), "r" | "br") && c.get(i + hashes) == Some(&'"') {
                    let closes =
                        |j: usize| c[j] == '"' && (1..=hashes).all(|h| c.get(j + h) == Some(&'#'));
                    let end = (i + hashes + 1..c.len())
                        .find(|&j| closes(j))
                        .map_or(c.len(), |j| j + 1 + hashes);
                    blank(&mut out, start, end);
                    i = end;
                }
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        };
        blank(&mut out, i, end);
        i = end;
    }
    out.into_iter().collect()
}

/// Index of the `}` closing the block that opens at `open`.
fn block_end(code: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, b) in code.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// End of the expression starting at `start`: the first `;` or `,` outside
/// brackets, or the bracket that closes an enclosing group.
fn expression_end(code: &str, start: usize) -> usize {
    let mut depth = 0usize;
    for (i, b) in code.bytes().enumerate().skip(start) {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return i,
            b')' | b']' | b'}' => depth -= 1,
            b';' | b',' if depth == 0 => return i,
            _ => {}
        }
    }
    code.len()
}

/// The `#[cfg(test)]` modules of a masked src/ file: byte ranges of inline
/// `mod name { … }` blocks, and the names of out-of-line `mod name;` ones.
fn cfg_test_modules(code: &str) -> (Vec<(usize, usize)>, Vec<String>) {
    let (mut inline, mut out_of_line) = (Vec::new(), Vec::new());
    for (at, attr) in code.match_indices("#[cfg(test)]") {
        let mut rest = code[at + attr.len()..].trim_start();
        while let Some(attr) = rest.strip_prefix("#[") {
            rest = attr[attr.find(']').map_or(attr.len(), |i| i + 1)..].trim_start();
        }
        for vis in ["pub(crate)", "pub(super)", "pub"] {
            rest = rest.strip_prefix(vis).unwrap_or(rest).trim_start();
        }
        let Some(decl) = rest.strip_prefix("mod ") else {
            continue;
        };
        let decl = decl.trim_start();
        let name: String = decl
            .chars()
            .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
            .collect();
        let after = decl[name.len()..].trim_start();
        if after.starts_with(';') {
            out_of_line.push(name);
        } else if after.starts_with('{') {
            let open = code.len() - after.len();
            inline.push((open, block_end(code, open)));
        }
    }
    (inline, out_of_line)
}

/// The file an out-of-line `mod name;` declared in `parent` loads.
fn module_file(parent: &Path, name: &str) -> Option<PathBuf> {
    let dir = match parent.file_stem()?.to_str()? {
        "mod" | "lib" | "main" => parent.parent()?.to_path_buf(),
        stem => parent.parent()?.join(stem),
    };
    [
        dir.join(format!("{name}.rs")),
        dir.join(name).join("mod.rs"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// Count the `ComplianceChecker::new(` calls inside `regions` of masked
/// `code`, and return the lines of those whose expression does not also
/// call `.with_as_of(`.
fn unpinned_calls(code: &str, regions: &[(usize, usize)]) -> (usize, Vec<usize>) {
    let (mut calls, mut unpinned) = (0, Vec::new());
    for (at, _) in code.match_indices(CALL) {
        if !regions.iter().any(|&(from, to)| (from..to).contains(&at)) {
            continue;
        }
        calls += 1;
        if !code[at..expression_end(code, at)].contains(PIN) {
            unpinned.push(code[..at].matches('\n').count() + 1);
        }
    }
    (calls, unpinned)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn masked(path: &Path) -> String {
    mask(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
    )
}

/// Every `ComplianceChecker::new(` in test code pins the clock in the same
/// expression. Test code is every file under tests/, and the `#[cfg(test)]`
/// modules under src/ (production code reads the wall clock by design;
/// `--as-of` pins it). Doc examples are comments, so they are not scanned.
#[test]
fn every_test_checker_pins_the_clock() {
    let root = Path::new(ROOT);
    let (mut calls, mut offenders) = (0, Vec::new());
    let mut scan = |path: &Path, code: &str, regions: &[(usize, usize)]| {
        let (n, lines) = unpinned_calls(code, regions);
        calls += n;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        offenders.extend(lines.into_iter().map(|line| format!("  {rel}:{line}")));
    };

    let mut test_files = Vec::new();
    rust_files(&root.join("tests"), &mut test_files);
    for path in &test_files {
        let code = masked(path);
        scan(path, &code, &[(0, code.len())]);
    }

    let mut src_files = Vec::new();
    rust_files(&root.join("src"), &mut src_files);
    let src: Vec<(PathBuf, String)> = src_files
        .into_iter()
        .map(|path| {
            let code = masked(&path);
            (path, code)
        })
        .collect();
    // An out-of-line `#[cfg(test)] mod name;` makes its whole file test code.
    let test_module_files: BTreeSet<PathBuf> = src
        .iter()
        .flat_map(|(path, code)| {
            let (_, out_of_line) = cfg_test_modules(code);
            out_of_line
                .into_iter()
                .filter_map(|name| module_file(path, &name))
        })
        .collect();
    for (path, code) in &src {
        if test_module_files.contains(path) {
            scan(path, code, &[(0, code.len())]);
        } else {
            scan(path, code, &cfg_test_modules(code).0);
        }
    }

    // Guard against a lint that silently scans nothing: the shared helper
    // and the src test-module helpers are calls it must see.
    assert!(
        calls >= 10,
        "the lint saw only {calls} ComplianceChecker::new calls; is it scanning?"
    );
    assert!(
        offenders.is_empty(),
        "ComplianceChecker::new in a test without a pinned clock (the checker \
         reads the wall clock, so the test changes meaning when a date passes). \
         Use `checker(level)` from tests/common/clock.rs (or the test module's \
         local helper), or pin an instant with `.with_as_of(...)` in the same \
         expression:\n{}",
        offenders.join("\n")
    );
}

/// The lint itself: comments, strings and production code are ignored; a
/// call counts as pinned only when `.with_as_of(` is in the same expression.
#[test]
fn the_lint_flags_only_unpinned_test_calls() {
    let sample = r##"
fn production() -> ComplianceChecker {
    ComplianceChecker::new(level)
}

#[cfg(test)]
mod tests {
    // ComplianceChecker::new(level) in a comment is not a call.
    const DOC: &str = "ComplianceChecker::new(level)";
    const RAW: &str = r#"ComplianceChecker::new(level)"#;

    fn pinned() {
        let a = ComplianceChecker::new(level).with_as_of(t);
        let b = ComplianceChecker::new(level)
            .with_sidecar(sc.clone())
            .with_as_of(t)
            .check(&sbom);
    }

    fn unpinned() {
        let c = ComplianceChecker::new(level).check(&sbom);
        let d: Vec<_> = all.iter().map(|l| ComplianceChecker::new(*l).check(&s)).collect();
        let mut e = ComplianceChecker::new(level);
        e = e.with_as_of(t);
    }
}

#[cfg(test)]
mod render_tests;
"##;
    let code = mask(sample);
    let (inline, out_of_line) = cfg_test_modules(&code);
    assert_eq!(out_of_line, ["render_tests"]);
    let (calls, unpinned) = unpinned_calls(&code, &inline);
    assert_eq!(
        calls, 5,
        "a, b, c, d, e; not the production call or the literals"
    );
    assert_eq!(
        unpinned,
        [21, 22, 23],
        "c, d and e are not pinned in their expression"
    );
}

// ============================================================================
// Date-gate boundaries
// ============================================================================

fn ts(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid timestamp")
        .with_timezone(&chrono::Utc)
}

fn cra_fixture(name: &str) -> NormalizedSbom {
    let path = Path::new(CRA_FIXTURES).join(name);
    parse_sbom(&path).unwrap_or_else(|e| panic!("cannot parse {name}: {e}"))
}

fn cra_sidecar(name: &str) -> CraSidecarMetadata {
    CraSidecarMetadata::from_file(&Path::new(CRA_FIXTURES).join(name))
        .unwrap_or_else(|e| panic!("cannot load {name}: {e}"))
}

fn check_at(
    level: ComplianceLevel,
    sbom: &NormalizedSbom,
    sidecar: Option<&CraSidecarMetadata>,
    at: &str,
) -> ComplianceResult {
    let mut checker = ComplianceChecker::new(level).with_as_of(ts(at));
    if let Some(sidecar) = sidecar {
        checker = checker.with_sidecar(sidecar.clone());
    }
    checker.check(sbom)
}

/// The CRA-compliant fixture with its sidecar, minus the three Art. 14
/// reporting channels (PSIRT, 24-hour early warning, 72-hour notification).
/// The sidecar keeps its Important Class I product class.
fn without_reporting_channels() -> (NormalizedSbom, CraSidecarMetadata) {
    let mut sidecar = cra_sidecar("cra-compliant.cra.json");
    sidecar.psirt_url = None;
    sidecar.early_warning_contact = None;
    sidecar.incident_report_contact = None;
    (cra_fixture("cra-compliant.cdx.json"), sidecar)
}

fn art_14_severities(result: &ComplianceResult) -> Vec<ViolationSeverity> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id.starts_with("SBOM-CRA-ART-14-"))
        .map(|v| v.severity)
        .collect()
}

/// CRA Art. 14 reporting obligations apply from 11 September 2026 (Reg.
/// (EU) 2024/2847 Art. 71(2)). A missing reporting channel is Info the day
/// before and a Warning from the gate instant on; the verdict holds, since
/// the Important Class I calibration keeps it below Error.
#[test]
fn art_14_findings_escalate_on_2026_09_11() {
    use ViolationSeverity::{Info, Warning};
    let (sbom, sidecar) = without_reporting_channels();
    for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
        for (at, expected) in [
            ("2026-09-10T00:00:00Z", Info),
            ("2026-09-11T00:00:00Z", Warning),
            ("2026-09-12T00:00:00Z", Warning),
        ] {
            let result = check_at(level, &sbom, Some(&sidecar), at);
            assert_eq!(
                art_14_severities(&result),
                [expected; 3],
                "{level:?} at {at}: one SBOM-CRA-ART-14-* finding per missing channel"
            );
            assert!(
                result.is_compliant,
                "{level:?} at {at}: no Errors either side"
            );
        }
    }
}

/// At Important Class II the same gate flips the verdict: once Art. 14
/// applies, each missing reporting channel is an Error.
#[test]
fn art_14_gate_flips_the_important_class_2_verdict() {
    let (sbom, mut sidecar) = without_reporting_channels();
    sidecar.product_class = Some(CraProductClass::ImportantClass2);
    for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
        let before = check_at(level, &sbom, Some(&sidecar), "2026-09-10T00:00:00Z");
        assert!(
            before.is_compliant && before.error_count == 0,
            "{level:?} the day before: compliant, missing channels are Info"
        );
        assert_eq!(art_14_severities(&before), [ViolationSeverity::Info; 3]);

        let after = check_at(level, &sbom, Some(&sidecar), "2026-09-12T00:00:00Z");
        let errors: Vec<_> = after
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .map(|v| v.rule_id)
            .collect();
        assert!(
            !after.is_compliant,
            "{level:?} the day after: not compliant"
        );
        assert_eq!(
            errors,
            [
                "SBOM-CRA-ART-14-PSIRT",
                "SBOM-CRA-ART-14-EARLY-WARNING",
                "SBOM-CRA-ART-14-NOTIFICATION",
            ],
            "{level:?} the day after: the missing channels are the only Errors"
        );
    }
}

/// Full application of the CRA on 11 December 2027 is not a clock gate in
/// the engine: Phase 2 obligations come from choosing the CRA Phase 2
/// profile, not from the calendar. Every level reaches the same findings
/// and verdict the day before and the day after; if the engine starts
/// gating on this date, this test changes with it.
#[test]
fn cra_full_application_on_2027_12_11_moves_no_verdict() {
    let cases = [
        (
            "cra-compliant.cdx.json",
            Some("cra-compliant.cra.json"),
            true,
        ),
        ("cra-noncompliant-no-manufacturer.cdx.json", None, false),
        ("cra-noncompliant-weak-hashes.cdx.json", None, false),
    ];
    for (fixture, sidecar, cra_compliant) in cases {
        let sbom = cra_fixture(fixture);
        let sidecar = sidecar.map(cra_sidecar);
        let findings = |level: ComplianceLevel, at: &str| {
            let result = check_at(level, &sbom, sidecar.as_ref(), at);
            let mut findings: Vec<String> = result
                .violations
                .iter()
                .map(|v| format!("{} {:?} {}", v.rule_id, v.severity, v.requirement))
                .collect();
            findings.sort();
            (result.is_compliant, findings)
        };
        for level in ComplianceLevel::all() {
            let before = findings(*level, "2027-12-10T00:00:00Z");
            let after = findings(*level, "2027-12-12T00:00:00Z");
            assert_eq!(
                before, after,
                "{fixture} {level:?}: changed across 2027-12-11"
            );
        }
        for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
            assert_eq!(
                findings(level, "2027-12-12T00:00:00Z").0,
                cra_compliant,
                "{fixture} {level:?} verdict"
            );
        }
    }
}
