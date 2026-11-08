//! A source lint over the compliance checkers, which read the evidence
//! layer (`src/quality/compliance/evidence/`).
//!
//! The evidence of a run is the only thing a checker reads about the SBOM,
//! so two standards cannot derive one fact two ways. A checker file on the
//! list below may not bind or name the SBOM (`sbom`, `NormalizedSbom`), may
//! not read the clock (the evidence's instant is the run's), and may not
//! derive a fact the evidence holds from the raw values: it calls none of
//! the predicates behind the facts (`has_known_producer`,
//! `is_package_scoped`, `known_value` and its kin) and parses no spec
//! version. Where no fact gives what a check needs, it calls `raw_sbom()`,
//! the named escape hatch, with a `// escape hatch: <why>` comment on the
//! line or the line above, and the PR that adds it says why.
//!
//! Every checker file is on the list: a test derives the checker files from
//! the standards table and the dispatch (`standards.rs`, `context.rs`), so a
//! new standard's checker cannot read the SBOM without failing the build.

#[path = "common/source_mask.rs"]
mod source_mask;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use source_mask::mask;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The checker files, which read the evidence layer, relative to the
/// repository root.
const READS_EVIDENCE: &[&str] = &[
    "src/quality/compliance/bsi.rs",
    "src/quality/compliance/bsi_sbom_for_ai.rs",
    "src/quality/compliance/cisa2026.rs",
    "src/quality/compliance/cra.rs",
    "src/quality/compliance/crypto.rs",
    "src/quality/compliance/eo14028.rs",
    "src/quality/compliance/eu_ai_act.rs",
    "src/quality/compliance/eucc.rs",
    "src/quality/compliance/fsct.rs",
    "src/quality/compliance/generic.rs",
    "src/quality/compliance/pci_dss.rs",
    "src/quality/compliance/ssdf.rs",
];

/// Identifiers a checker that reads the evidence may not use: the SBOM, by
/// its usual binding and its type.
const FORBIDDEN_IDENTIFIERS: &[&str] = &["sbom", "NormalizedSbom"];

/// Calls a checker that reads the evidence may not make: the clock (the
/// evidence's instant is the run's).
const FORBIDDEN_CALLS: &[&str] = &[".now()", "Utc::now"];

/// The predicates behind the evidence's facts, and the spec-version parse,
/// which a checker may not call: it reads the fact instead (the package
/// scope, a value's state, the producer, the parsed spec version).
const FORBIDDEN_PREDICATES: &[&str] = &[
    "has_known_producer",
    "is_package_scoped",
    "known_value",
    "has_known_value",
    "value_state",
    "spec_version_parsed",
    "SpecVersion::parse",
];

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
        for predicate in FORBIDDEN_PREDICATES {
            if calls(line, predicate) {
                found.push((n + 1, format!("{predicate}()")));
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

/// Whether `line` calls `function` (a name, or a path ending in one): the
/// name is not part of a longer identifier, and an argument list follows.
fn calls(line: &str, function: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(function).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + function.len()..].trim_start();
        !before.is_some_and(is_ident) && after.starts_with('(')
    })
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
    // Deriving a fact the evidence holds.
    assert_eq!(flagged("if has_known_producer(comp) {}"), [1]);
    assert_eq!(
        flagged("let p = c.component_type.is_package_scoped();"),
        [1]
    );
    assert_eq!(flagged("let v = shared::known_value(Some(x));"), [1]);
    assert_eq!(flagged("let v = has_known_value(&c.version);"), [1]);
    assert_eq!(flagged("let s = value_state (raw);"), [1]);
    assert_eq!(flagged("let v = doc.spec_version_parsed();"), [1]);
    assert_eq!(flagged("let v = SpecVersion::parse(raw);"), [1]);
    // Their facts, and names that only contain a predicate's, do not count.
    assert!(flagged("let p = c.package_scoped(); let v = c.version().is_known();").is_empty());
    assert!(flagged("let v = doc.spec_version; let m = SpecVersion::new(1, 4, 0);").is_empty());
    assert!(flagged("let known_value_count = 1; use shared::known_value;").is_empty());
    // The escape hatch needs its marker, on the line or the line above.
    assert_eq!(flagged("let s = ctx.ev.raw_sbom();"), [1]);
    assert!(flagged("let s = ctx.ev.raw_sbom(); // escape hatch: no fact yet").is_empty());
    assert!(flagged("// escape hatch: no fact yet\nlet s = ctx.ev.raw_sbom();").is_empty());
    // Test modules are not checked.
    assert!(flagged("fn a() {}\n#[cfg(test)]\nmod tests { fn b(sbom: u8) {} }").is_empty());
}

/// The source of `path` with comments and literals blanked, up to its test
/// module (the first `#[cfg(test)]`).
fn code_of(path: &Path) -> String {
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let masked = mask(&src);
    let end = masked.find("#[cfg(test)]").unwrap_or(masked.len());
    masked[..end].to_string()
}

/// The Rust files of the compliance engine apart from the evidence layer
/// and the unit tests: where a checker can live.
fn compliance_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
            .map(|e| e.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name != "evidence" && name != "tests" {
                    walk(&path, out);
                }
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&Path::new(ROOT).join("src/quality/compliance"), &mut files);
    files
}

/// Each identifier that follows `prefix` in `code`, with the text after it,
/// in order.
fn names_after<'a>(code: &'a str, prefix: &str) -> Vec<(&'a str, &'a str)> {
    code.match_indices(prefix)
        .map(|(at, _)| {
            let rest = &code[at + prefix.len()..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        })
        .collect()
}

/// The check methods a checker struct of `context.rs` runs: the method its
/// `dedicated_checker!` names, or the `checker.<method>(` calls of its own
/// `impl StandardChecker` block.
fn methods_of(context: &str, checker: &str) -> Vec<String> {
    let squeezed: String = context.chars().filter(|c| !c.is_whitespace()).collect();
    let invocation = format!("dedicated_checker!({checker},");
    if let Some(at) = squeezed.find(&invocation) {
        let args = &squeezed[at + invocation.len()..];
        let args = &args[..args.find(')').expect("the invocation closes")];
        let method = args.rsplit(',').next().expect("a method argument");
        return vec![method.to_string()];
    }
    let header = format!("impl StandardChecker for {checker} {{");
    let at = context
        .find(&header)
        .unwrap_or_else(|| panic!("context.rs defines no checker {checker}"));
    let body = &context[at..];
    let body = &body[..body.find("\n}").expect("the impl block closes")];
    names_after(body, "checker.")
        .into_iter()
        .filter(|(_, after)| after.starts_with('('))
        .map(|(method, _)| method.to_string())
        .collect()
}

/// The checker files: the file that defines each check method a
/// `STANDARDS` entry's checker runs, and every other file that defines a
/// function taking the `ComplianceContext`, but for the dispatch
/// (`context.rs`) and the driver (`checker.rs`), which pass it on.
fn checker_files() -> BTreeSet<String> {
    let compliance = Path::new(ROOT).join("src/quality/compliance");
    let standards = code_of(&compliance.join("standards.rs"));
    let context = code_of(&compliance.join("context.rs"));
    let files: Vec<(String, String)> = compliance_files()
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(ROOT)
                .expect("under the repository")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, code_of(&path))
        })
        .collect();

    let checkers: BTreeSet<&str> = names_after(&standards, "checker: ")
        .into_iter()
        .filter(|(_, after)| after.starts_with("::boxed"))
        .map(|(name, _)| name)
        .collect();
    assert!(
        checkers.len() > 1,
        "no checkers found in the standards table: {checkers:?}"
    );
    let mut found = BTreeSet::new();
    for checker in checkers {
        for method in methods_of(&context, checker) {
            let defines = [format!("fn {method}("), format!("fn {method}<")];
            let homes: Vec<&String> = files
                .iter()
                .filter(|(_, code)| defines.iter().any(|d| code.contains(d)))
                .map(|(rel, _)| rel)
                .collect();
            assert_eq!(
                homes.len(),
                1,
                "{checker} runs {method}, defined in {homes:?}, not in exactly one file"
            );
            found.insert(homes[0].clone());
        }
    }
    for (rel, code) in &files {
        let passes_on = rel.ends_with("/context.rs") || rel.ends_with("/checker.rs");
        let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if !passes_on && squeezed.contains(":&ComplianceContext") {
            found.insert(rel.clone());
        }
    }
    found
}

#[test]
fn every_checker_reads_the_evidence() {
    let listed: BTreeSet<&str> = READS_EVIDENCE.iter().copied().collect();
    let checkers = checker_files();
    for expected in [
        "src/quality/compliance/generic.rs",
        "src/quality/compliance/cra.rs",
        "src/quality/compliance/crypto.rs",
        "src/quality/compliance/eucc.rs",
        "src/quality/compliance/eu_ai_act.rs",
        "src/quality/compliance/bsi_sbom_for_ai.rs",
    ] {
        assert!(
            checkers.contains(expected),
            "the checker files derived from the standards table miss {expected}: {checkers:?}"
        );
    }
    let missing: Vec<_> = checkers
        .iter()
        .filter(|f| !listed.contains(f.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "checker files not in READS_EVIDENCE (a checker reads the evidence, \
         and the lint holds it to that): {missing:?}"
    );
}
