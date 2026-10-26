//! Registry exhaustiveness (audit P3, deferred P0 item): every id in
//! `all_rule_ids()` must resolve via `rule_meta`, and its externally-visible
//! SARIF identity must belong to at least one per-standard SARIF slice — or
//! the id must be explicitly documented as slice-less with a reason. No
//! silent omissions: stale exemptions (ids that later join a slice) fail too.
//!
//! The matrix half (WP 1.2): every compliance level has a rule matrix, and
//! every registered rule key sits in some `tests/rule_matrix_*.rs` row —
//! tested, or skipped with a reason that names the bug or limitation.

use sbom_tools::quality::{
    CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, COMPLIANCE_SARIF_RULE_IDS, ComplianceLevel,
    EO14028_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS, FSCT_SARIF_RULE_IDS, NTIA_SARIF_RULE_IDS,
    PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, SSDF_SARIF_RULE_IDS, all_rule_ids, rule_meta,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Why the quality profiles' checks are slice-less: they alias
/// SBOM-QUALITY-GENERAL, which no per-standard slice lists.
const QUALITY_CHECK: &str = "quality-profile check aliasing SBOM-QUALITY-GENERAL; the quality \
     profiles have no dedicated SARIF slice — their catalogue is backfilled from fired rules";

/// Internal rule ids whose SARIF identity is deliberately in no per-standard
/// SARIF slice, with the reason. These rules still render in SARIF output via
/// the generator's catalogue-completion backfill when they fire; they are
/// just not part of any upfront-declared rule catalogue.
const SLICELESS: &[(&str, &str)] = &[
    (
        "SBOM-QUALITY-GENERAL",
        "generic bucket for the quality profiles (Minimum/Standard/Comprehensive); \
         those profiles have no dedicated SARIF slice — their catalogue is \
         backfilled from fired rules",
    ),
    ("SBOM-QUALITY-CREATOR", QUALITY_CHECK),
    ("SBOM-QUALITY-SERIAL", QUALITY_CHECK),
    ("SBOM-QUALITY-INVENTORY", QUALITY_CHECK),
    ("SBOM-QUALITY-NAME", QUALITY_CHECK),
    ("SBOM-QUALITY-IDENTIFIER", QUALITY_CHECK),
    ("SBOM-QUALITY-LICENSE", QUALITY_CHECK),
    ("SBOM-QUALITY-HASH", QUALITY_CHECK),
    ("SBOM-QUALITY-SPEC-VERSION", QUALITY_CHECK),
    ("SBOM-QUALITY-SPEC-VERSION-UNKNOWN", QUALITY_CHECK),
    ("SBOM-QUALITY-ELEMENT-ID", QUALITY_CHECK),
    (
        "SBOM-CRA-ART-24-SUPPLIER",
        "CRA OSS-steward supplier rule: the shared COMPLIANCE slice predates the \
         Art. 24 steward profile and does not enumerate it; the SARIF generator \
         backfills the descriptor when the rule fires",
    ),
    (
        "SBOM-CRA-CYCLES",
        "CRA dependency-cycles rule: not enumerated in the shared COMPLIANCE \
         slice; backfilled into the SARIF catalogue when it fires",
    ),
    (
        "SBOM-CRA-ANNEX-VIII",
        "CRA Annex VIII conformity-route rule: not enumerated in the shared \
         COMPLIANCE slice; backfilled into the SARIF catalogue when it fires",
    ),
    (
        "SBOM-EUCC-GENERAL",
        "EUCC generic fallback bucket (SARIF re-bucketing target only); no \
         upfront catalogue lists it",
    ),
    (
        "SBOM-AIACT-GENERAL",
        "EU AI Act generic fallback bucket (SARIF re-bucketing target only); no \
         upfront catalogue lists it",
    ),
    (
        "SBOM-BSIAI-GENERAL",
        "BSI/G7 SBOM-for-AI generic fallback bucket (SARIF re-bucketing target \
         only); no upfront catalogue lists it",
    ),
];

fn slice_union() -> BTreeSet<&'static str> {
    [
        NTIA_SARIF_RULE_IDS,
        FDA_SARIF_RULE_IDS,
        SSDF_SARIF_RULE_IDS,
        EO14028_SARIF_RULE_IDS,
        COMPLIANCE_SARIF_RULE_IDS,
        CNSA2_SARIF_RULE_IDS,
        PQC_SARIF_RULE_IDS,
        CISA2026_SARIF_RULE_IDS,
        PCIDSS_SARIF_RULE_IDS,
        FSCT_SARIF_RULE_IDS,
    ]
    .iter()
    .flat_map(|slice| slice.iter().copied())
    .collect()
}

#[test]
fn every_registered_rule_resolves_and_is_sliced_or_documented_sliceless() {
    let union = slice_union();
    let mut exemptions: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, reason) in SLICELESS {
        assert!(
            exemptions.insert(id, reason).is_none(),
            "duplicate SLICELESS entry for {id}"
        );
        assert!(!reason.trim().is_empty(), "{id}: empty exemption reason");
    }

    for id in all_rule_ids() {
        // Deliverable: every id resolves via rule_meta.
        let meta = rule_meta(id)
            .unwrap_or_else(|| panic!("registered rule id {id:?} does not resolve in rule_meta"));

        let sliced = union.contains(meta.sarif_id);
        let exempt = exemptions.contains_key(id);
        assert!(
            sliced || exempt,
            "rule {id} (SARIF identity {sarif}) belongs to no per-standard SARIF \
             slice and is not documented as slice-less — add it to a slice or to \
             SLICELESS with a reason",
            sarif = meta.sarif_id
        );
        assert!(
            !(sliced && exempt),
            "rule {id} is now covered by a SARIF slice (via {sarif}); remove the \
             stale SLICELESS exemption",
            sarif = meta.sarif_id
        );
    }

    // Exemptions must reference real registry ids (no typo'd dead entries).
    for (id, _) in SLICELESS {
        assert!(
            all_rule_ids().contains(id),
            "SLICELESS entry {id:?} is not a registered rule id"
        );
    }
}

/// Every id enumerated by a per-standard SARIF slice must itself be a
/// registered rule (the registry unit tests pin self-descriptor identity;
/// this integration-level check keeps the exported slices resolvable for
/// external consumers of the crate API).
#[test]
fn every_slice_id_resolves_in_the_registry() {
    for id in slice_union() {
        assert!(
            rule_meta(id).is_some(),
            "SARIF slice id {id:?} does not resolve in rule_meta"
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

/// The row constructors of tests/common/rule_matrix.rs.
const ROW_CONSTRUCTORS: &[&str] = &[
    "tested",
    "tested_departing",
    "skipped",
    "key_tested",
    "key_tested_departing",
    "key_skipped",
];

/// One `RuleEntry::<constructor>("<id>", …)` row of a matrix source.
struct MatrixRow {
    file: String,
    id: String,
    per_key: bool,
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
            per_key: ctor.starts_with("key_"),
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

/// Every registered rule key sits in some matrix: a self-descriptor (its own
/// SARIF rule) needs a SARIF row, an alias key (one that shares another
/// key's SARIF rule) needs a per-key row. Either may be `skipped` — the
/// reason, enforced non-empty by `run_matrix`, names the bug or limitation —
/// but nothing is left out silently. Rows may not name unregistered ids,
/// and a per-key row may not name a self-descriptor.
#[test]
fn every_registered_rule_sits_in_a_matrix_or_is_skipped_with_a_reason() {
    let rows: Vec<MatrixRow> = matrix_sources()
        .iter()
        .flat_map(|(file, code)| matrix_rows(file, code))
        .collect();
    assert!(!rows.is_empty(), "no matrix rows found");

    for row in &rows {
        let meta = rule_meta(&row.id)
            .unwrap_or_else(|| panic!("{}: row names unregistered rule {}", row.file, row.id));
        if row.per_key {
            assert_ne!(
                meta.sarif_id, row.id,
                "{}: per-key row {} is its own SARIF rule; use a SARIF row",
                row.file, row.id
            );
        }
    }

    let mut missing = Vec::new();
    for id in all_rule_ids() {
        let meta = rule_meta(id).expect("listed id resolves");
        let per_key = meta.sarif_id != *id;
        if !rows.iter().any(|r| r.id == *id && r.per_key == per_key) {
            missing.push(if per_key {
                format!("{id} (alias of {}: needs a per-key row)", meta.sarif_id)
            } else {
                format!("{id} (needs a SARIF row)")
            });
        }
    }
    assert!(
        missing.is_empty(),
        "registered rules in no matrix (add a row, or a skipped row naming the \
         bug or limitation):\n  {}",
        missing.join("\n  ")
    );
}
