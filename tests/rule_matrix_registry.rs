//! Registry exhaustiveness (audit P3, deferred P0 item): every id in
//! `all_rule_ids()` must resolve via `rule_meta`, and its externally-visible
//! SARIF identity must belong to at least one level's rule list
//! (`rules_for_level`), unless it is a family fallback rule
//! (`generic_rule_id_for_level`), which no check emits and no list names.
//! Every check rule has a standard: the quality profiles, the CRA profiles,
//! BSI, EUCC and the AI profiles have lists of their own, so no rule is
//! exempt.
//!
//! The matrix half (WP 1.2): every compliance level has a rule matrix, and
//! every registered rule key but the fallback rules sits in some
//! `tests/rule_matrix_*.rs` row — tested (by firing cases, or passing cases
//! for a pass-only rule), or skipped with a reason that names the bug or
//! limitation.

use sbom_tools::quality::{
    ComplianceLevel, all_rule_ids, generic_rule_id_for_level, rule_meta, rules_for_level,
};
use std::collections::BTreeSet;
use std::path::Path;

/// The family fallback rules: the rule the SARIF writer files a finding
/// without a registered rule under. No check emits one, so no list and no
/// matrix names them.
fn fallback_rules() -> BTreeSet<&'static str> {
    ComplianceLevel::all()
        .iter()
        .map(|level| generic_rule_id_for_level(*level))
        .collect()
}

/// Every rule some level lists.
fn listed_rules() -> BTreeSet<&'static str> {
    ComplianceLevel::all()
        .iter()
        .flat_map(|level| rules_for_level(*level).iter().copied())
        .collect()
}

#[test]
fn every_registered_rule_resolves_and_belongs_to_a_level_or_is_a_fallback() {
    let listed = listed_rules();
    let fallbacks = fallback_rules();

    for id in all_rule_ids() {
        // Deliverable: every id resolves via rule_meta.
        let meta = rule_meta(id)
            .unwrap_or_else(|| panic!("registered rule id {id:?} does not resolve in rule_meta"));

        let is_listed = listed.contains(meta.sarif_id);
        let is_fallback = fallbacks.contains(id);
        assert!(
            is_listed || is_fallback,
            "rule {id} (SARIF identity {sarif}) is in no level's rule list — add it \
             to the list of every level whose checks emit it (rules_for_level)",
            sarif = meta.sarif_id
        );
        assert!(
            !(is_listed && is_fallback),
            "the fallback rule {id} is in a level's rule list; no check emits it"
        );
    }

    // The fallbacks the SARIF writer files findings under must be real
    // registry ids.
    for id in fallbacks {
        assert!(
            all_rule_ids().contains(&id),
            "fallback rule {id:?} is not a registered rule id"
        );
    }
}

/// Every id a level lists must itself be a registered rule (the registry
/// unit tests pin self-descriptor identity; this integration-level check
/// keeps the exported lists resolvable for external consumers of the crate
/// API).
#[test]
fn every_listed_id_resolves_in_the_registry() {
    for id in listed_rules() {
        assert!(
            rule_meta(id).is_some(),
            "listed rule id {id:?} does not resolve in rule_meta"
        );
    }
}

// ---------------------------------------------------------------------------
// Matrix coverage: every level has a matrix, every rule key has a row
// ---------------------------------------------------------------------------

/// `src` with `//` and `/* */` comments removed; string and char literals
/// are kept verbatim, so a comment can never declare (or hide) a row.
fn strip_comments(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        match c[i] {
            '/' if next == Some('/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 0usize;
                while i < c.len() {
                    match (c[i], c.get(i + 1)) {
                        ('/', Some('*')) => {
                            depth += 1;
                            i += 2;
                        }
                        ('*', Some('/')) => {
                            depth -= 1;
                            i += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => i += 1,
                    }
                }
                out.push(' ');
            }
            '"' => {
                out.push('"');
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        out.push(c[i]);
                        i += 1;
                    }
                    out.push(c[i]);
                    i += 1;
                }
                if i < c.len() {
                    out.push('"');
                    i += 1;
                }
            }
            // A char literal ('x' or an escape); anything else is a lifetime.
            '\'' if next == Some('\\') || c.get(i + 2) == Some(&'\'') => {
                let end = (i + 2..c.len())
                    .find(|&j| c[j] == '\'' && (c[j - 1] != '\\' || j == i + 2))
                    .map_or(c.len(), |j| j + 1);
                out.extend(&c[i..end]);
                i = end;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// Every per-level matrix source (`tests/rule_matrix_*.rs` except this
/// file), comments stripped.
fn matrix_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("tests/ is readable") {
        let path = entry.expect("tests/ entry is readable").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("rule_matrix_")
            && name.ends_with(".rs")
            && name != "rule_matrix_registry.rs"
        {
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            sources.push((name.to_string(), strip_comments(&src)));
        }
    }
    sources.sort();
    assert!(!sources.is_empty(), "no tests/rule_matrix_*.rs files found");
    sources
}

/// The row constructors of tests/common/rule_matrix.rs: firing rows for
/// finding rules, passing rows for pass-only rules, skipped rows for both.
const ROW_CONSTRUCTORS: &[&str] = &["tested", "tested_departing", "passing", "skipped"];

/// One `RuleEntry::<constructor>("<id>", …)` row of a matrix source.
struct MatrixRow {
    file: String,
    id: String,
}

/// The string literal `args` starts with (after leading whitespace), and the
/// text after it.
fn leading_literal(args: &str) -> Option<(&str, &str)> {
    args.trim_start().strip_prefix('"')?.split_once('"')
}

/// The rows a matrix source declares. Row ids must be string literals so
/// this scan can see them; a skipped row's reason, when written inline, must
/// not be empty (`run_matrix` checks reasons passed as constants).
fn matrix_rows(file: &str, code: &str) -> Vec<MatrixRow> {
    let mut rows = Vec::new();
    for (at, marker) in code.match_indices("RuleEntry::") {
        let rest = &code[at + marker.len()..];
        let ctor: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[ctor.len()..].trim_start();
        if !ROW_CONSTRUCTORS.contains(&ctor.as_str()) || !after.starts_with('(') {
            continue;
        }
        let (id, rest) = leading_literal(&after[1..]).unwrap_or_else(|| {
            panic!("{file}: RuleEntry::{ctor} must name its rule id as a string literal")
        });
        if ctor.ends_with("skipped")
            && let Some((reason, _)) = rest
                .trim_start()
                .strip_prefix(',')
                .and_then(leading_literal)
        {
            assert!(
                !reason.trim().is_empty(),
                "{file}: skipped row {id} needs a reason naming the bug or limitation"
            );
        }
        rows.push(MatrixRow {
            file: file.to_string(),
            id: id.to_string(),
        });
    }
    rows
}

/// "All 19 levels have a matrix": every `ComplianceLevel` is named by a
/// matrix source that runs `run_matrix`.
#[test]
fn every_compliance_level_has_a_rule_matrix() {
    let sources = matrix_sources();
    let missing: Vec<String> = ComplianceLevel::all()
        .iter()
        .map(|level| format!("ComplianceLevel::{level:?}"))
        .filter(|needle| {
            !sources
                .iter()
                .any(|(_, code)| code.contains("run_matrix(") && code.contains(needle.as_str()))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "levels without a tests/rule_matrix_*.rs matrix: {missing:?}"
    );
}

/// Every registered rule key sits in some matrix — `tested`, `passing` for a
/// pass-only rule (which `run_matrix` holds to the rule's kind), or
/// `skipped` with a reason, enforced non-empty by `run_matrix`, that names
/// the bug or limitation — so nothing is left out silently. The fallback
/// rules are the exception, and no row may name one: no check emits them.
/// Rows may not name unregistered ids either.
#[test]
fn every_registered_rule_sits_in_a_matrix_or_is_skipped_with_a_reason() {
    let rows: Vec<MatrixRow> = matrix_sources()
        .iter()
        .flat_map(|(file, code)| matrix_rows(file, code))
        .collect();
    assert!(!rows.is_empty(), "no matrix rows found");
    let fallbacks = fallback_rules();

    for row in &rows {
        assert!(
            rule_meta(&row.id).is_some(),
            "{}: row names unregistered rule {}",
            row.file,
            row.id
        );
        assert!(
            !fallbacks.contains(row.id.as_str()),
            "{}: row names the fallback rule {}, which no check emits",
            row.file,
            row.id
        );
    }

    let missing: Vec<&str> = all_rule_ids()
        .iter()
        .copied()
        .filter(|id| !fallbacks.contains(id) && !rows.iter().any(|r| r.id == *id))
        .collect();
    assert!(
        missing.is_empty(),
        "registered rules in no matrix (add a row, or a skipped row naming the \
         bug or limitation):\n  {}",
        missing.join("\n  ")
    );
}
