//! A source lint over the compliance checkers that read the evidence layer
//! (`src/quality/compliance/evidence/`).
//!
//! The evidence of a run is the only thing such a checker reads about the
//! SBOM, so two standards cannot derive one fact two ways. A checker file on
//! the list below may not bind or name the SBOM (`sbom`, `NormalizedSbom`,
//! the context's transitional `sbom` field) and may not read the clock (the
//! evidence's instant is the run's). Where no fact gives what a check needs,
//! it calls `raw_sbom()`, the named escape hatch, with a `// escape hatch:
//! <why>` comment on the line or the line above, and the PR that adds it
//! says why.
//!
//! A port adds its checker file to `READS_EVIDENCE`.

#[path = "common/source_mask.rs"]
mod source_mask;

use std::path::Path;

use source_mask::mask;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The checker files that read the evidence layer, relative to the
/// repository root.
const READS_EVIDENCE: &[&str] = &[
    "src/quality/compliance/bsi.rs",
    "src/quality/compliance/cisa2026.rs",
    "src/quality/compliance/cra.rs",
    "src/quality/compliance/generic.rs",
    "src/quality/compliance/pci_dss.rs",
];

/// Identifiers a checker that reads the evidence may not use: the SBOM, by
/// its usual binding and its type.
const FORBIDDEN_IDENTIFIERS: &[&str] = &["sbom", "NormalizedSbom"];

/// Calls a checker that reads the evidence may not make: the clock (the
/// evidence's instant is the run's).
const FORBIDDEN_CALLS: &[&str] = &[".now()", "Utc::now"];

/// The named escape hatch, allowed with a marker comment.
const ESCAPE_HATCH: &str = "raw_sbom(";
const MARKER: &str = "// escape hatch:";

/// The line numbers (1-based) of the offences in `src`, the source of a
/// checker that reads the evidence, each with what it found. Test modules
/// (from the first `#[cfg(test)]` on) are not checked.
fn offences(src: &str) -> Vec<(usize, String)> {
    let masked = mask(src);
    let code = masked
        .find("#[cfg(test)]")
        .map_or(masked.as_str(), |at| &masked[..at]);
    let lines: Vec<&str> = src.lines().collect();
    let mut found = Vec::new();
    for (n, line) in code.lines().enumerate() {
        for ident in FORBIDDEN_IDENTIFIERS {
            if has_identifier(line, ident) {
                found.push((n + 1, (*ident).to_string()));
            }
        }
        for call in FORBIDDEN_CALLS {
            if line.contains(call) {
                found.push((n + 1, (*call).to_string()));
            }
        }
        if line.contains(ESCAPE_HATCH) {
            let marked = |i: usize| lines.get(i).is_some_and(|l| l.contains(MARKER));
            if !(marked(n) || (n > 0 && marked(n - 1))) {
                found.push((n + 1, format!("{ESCAPE_HATCH}) without `{MARKER}`")));
            }
        }
    }
    found
}

/// Whether `line` uses `ident` as a whole identifier.
fn has_identifier(line: &str, ident: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(ident).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + ident.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

#[test]
fn checkers_that_read_the_evidence_read_nothing_else() {
    let mut report = Vec::new();
    for rel in READS_EVIDENCE {
        let path = Path::new(ROOT).join(rel);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        assert!(
            mask(&src).contains("ComplianceContext"),
            "{rel} is listed as reading the evidence but takes no ComplianceContext"
        );
        for (line, what) in offences(&src) {
            report.push(format!("{rel}:{line}: {what}"));
        }
    }
    assert!(
        report.is_empty(),
        "checkers that read the evidence reach the SBOM or the clock directly:\n{}",
        report.join("\n")
    );
}

#[test]
fn the_lint_flags_only_code_that_reaches_past_the_evidence() {
    let flagged = |src: &str| -> Vec<usize> { offences(src).into_iter().map(|(l, _)| l).collect() };
    // Code that names the SBOM or reads the clock.
    assert_eq!(flagged("let n = sbom.components.len();"), [1]);
    assert_eq!(flagged("fn f(x: &NormalizedSbom) {}"), [1]);
    assert_eq!(flagged("let x = ctx.sbom;"), [1]);
    assert_eq!(flagged("let t = self.now();"), [1]);
    assert_eq!(flagged("let t = chrono::Utc::now();"), [1]);
    // Comments, strings and longer identifiers do not count.
    assert!(flagged("// sbom.components\nlet s = \"sbom-tools\";").is_empty());
    assert!(flagged("let sbom_evidence = 1; let raw_sbom_count = 2;").is_empty());
    assert!(flagged("let n = ctx.ev.component_count();").is_empty());
    // The escape hatch needs its marker, on the line or the line above.
    assert_eq!(flagged("let s = ctx.ev.raw_sbom();"), [1]);
    assert!(flagged("let s = ctx.ev.raw_sbom(); // escape hatch: no fact yet").is_empty());
    assert!(flagged("// escape hatch: no fact yet\nlet s = ctx.ev.raw_sbom();").is_empty());
    // Test modules are not checked.
    assert!(flagged("fn a() {}\n#[cfg(test)]\nmod tests { fn b(sbom: u8) {} }").is_empty());
}
