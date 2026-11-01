//! The rule catalogue (`quality::rule_catalog`, `sbom-tools rules`) and the
//! standard membership it reports (`quality::rules_for_level`).
//!
//! The rule matrices prove each level's list against their fixtures
//! (tests/common/rule_matrix.rs). This file holds the list against every SBOM
//! fixture in the repository too, at every level with and without its
//! sidecar, and checks that the catalogue says what the registry and the
//! lists say, and that its JSON matches `schemas/rules/v1.schema.json` and a
//! strict copy of it, as tests/compliance_json_schema_tests.rs does for the
//! compliance envelope.

#[path = "common/clock.rs"]
mod clock;
#[path = "common/json_schema.rs"]
mod json_schema;

use clock::checker;
use sbom_tools::model::{CraProductClass, CraSidecarMetadata};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, RuleCatalogFilter, RuleKind, StandardSelector, all_rule_ids,
    generic_rule_id_for_level, rule_catalog, rule_catalog_entry, rule_kind, rule_meta,
    rules_for_level, standard_key,
};
use sbom_tools::reports::{RULE_CATALOG_JSON_SCHEMA, generate_rule_catalog_json};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/rules/v1.schema.json");

/// Fixture directories that hold SBOMs (as in tests/compliance_snapshots.rs).
const SBOM_DIRS: &[&str] = &[
    "aibom",
    "compliance/regressions",
    "cra",
    "cyclonedx",
    "showcase",
    "spdx",
    "spdx3",
];

/// Files under the SBOM directories that are not SBOMs.
fn is_non_sbom(path: &Path) -> bool {
    let name = path.to_string_lossy();
    [
        ".cra.json",
        ".cra.yaml",
        ".md",
        ".toml",
        "corpus.json",
        ".openvex.json",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

/// Every SBOM fixture under the SBOM directories, sorted.
fn fixture_paths() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if !is_non_sbom(&path) {
                out.push(path);
            }
        }
    }
    let root = Path::new(FIXTURES_DIR);
    let mut paths = Vec::new();
    for dir in SBOM_DIRS {
        walk(&root.join(dir), &mut paths);
    }
    paths.sort();
    paths
}

/// Every level, run over every SBOM fixture — bare, with the fixture's
/// auto-discovered CRA sidecar, and with a pinned critical product class —
/// reports only rules of its own list. The matrices hold the lists against
/// minimal fixtures; this holds them against the repository's real ones.
#[test]
fn every_level_reports_only_its_listed_rules_on_every_fixture() {
    let mut strays: BTreeMap<String, String> = BTreeMap::new();
    let mut checked = 0usize;
    for path in fixture_paths() {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(sbom) = parse_sbom_str(&raw) else {
            continue;
        };
        let sidecar = CraSidecarMetadata::discover_for_sbom(&path).ok().flatten();
        let rel = path
            .strip_prefix(FIXTURES_DIR)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for level in ComplianceLevel::all() {
            let mut runs = vec![
                ("bare", checker(*level)),
                (
                    "critical class",
                    checker(*level).with_product_class(CraProductClass::Critical),
                ),
            ];
            if let Some(sc) = &sidecar {
                runs.push(("sidecar", checker(*level).with_sidecar(sc.clone())));
            }
            for (how, run) in runs {
                let result = run.check(&sbom);
                checked += 1;
                let listed = rules_for_level(*level);
                let emitted = result
                    .violations
                    .iter()
                    .map(|v| (v.rule_id, v.sarif_rule_id()))
                    .chain(result.passed.iter().map(|p| (p.rule_id, p.sarif_rule_id())));
                for (rule, sarif) in emitted {
                    if !listed.contains(&sarif) {
                        strays
                            .entry(format!("{level:?} {sarif}"))
                            .or_insert_with(|| {
                                format!("[{level:?}] {rel} ({how}) reported {rule} (sarif {sarif})")
                            });
                    }
                }
            }
        }
    }
    assert!(
        checked > 1000,
        "the fixture sweep ran only {checked} checks"
    );
    assert!(
        strays.is_empty(),
        "rules reported outside their level's list (rules_for_level):\n{}",
        strays.into_values().collect::<Vec<_>>().join("\n")
    );
}

/// Each entry's `standards` is exactly the levels whose list names the rule
/// (for a fallback rule, the levels it is the fallback of), and every other
/// field mirrors the registry.
#[test]
fn catalogue_entries_agree_with_the_registry_and_the_level_lists() {
    let entries = rule_catalog(&RuleCatalogFilter::all());
    assert_eq!(entries.len(), all_rule_ids().len());
    for entry in &entries {
        let meta = rule_meta(entry.id).expect("catalogue ids are registered");
        assert_eq!(entry.name, meta.name, "{}", entry.id);
        assert_eq!(entry.description, meta.short_description, "{}", entry.id);
        assert_eq!(
            entry.default_severity, meta.default_severity,
            "{}",
            entry.id
        );
        assert_eq!(Some(entry.kind), rule_kind(entry.id), "{}", entry.id);
        assert_eq!(entry.remediation, meta.remediation, "{}", entry.id);
        assert_eq!(entry.references.len(), meta.refs.len(), "{}", entry.id);
        for (reference, (standard, clause)) in entry.references.iter().zip(meta.refs) {
            assert_eq!(reference.standard, *standard, "{}", entry.id);
            assert_eq!(reference.id, *clause, "{}", entry.id);
            assert!(!reference.label.is_empty(), "{}", entry.id);
        }
        assert_eq!(
            entry.advice.is_some(),
            meta.advice.is_some(),
            "{}",
            entry.id
        );
        assert!(
            entry
                .help_uri
                .as_deref()
                .is_some_and(|uri| uri.starts_with("https://")),
            "{} has no help URI",
            entry.id
        );

        let fallback_of: Vec<&str> = ComplianceLevel::all()
            .iter()
            .filter(|level| generic_rule_id_for_level(**level) == entry.id)
            .map(|level| standard_key(*level))
            .collect();
        let listed_by: Vec<&str> = ComplianceLevel::all()
            .iter()
            .filter(|level| rules_for_level(**level).contains(&entry.id))
            .map(|level| standard_key(*level))
            .collect();
        assert_eq!(entry.fallback, !fallback_of.is_empty(), "{}", entry.id);
        let expected = if entry.fallback {
            fallback_of
        } else {
            listed_by
        };
        assert_eq!(entry.standards, expected, "{}", entry.id);
        assert!(
            !entry.standards.is_empty(),
            "{} belongs to no standard",
            entry.id
        );
    }
    let passes = entries.iter().filter(|e| e.kind == RuleKind::Pass).count();
    assert_eq!(
        passes, 2,
        "SBOM-PQC-009 and SBOM-PQC-010 are the pass-only rules"
    );
}

/// A standard's catalogue is its list, then its fallback rule; selecting it
/// through any `--standard` spelling gives the same rules.
#[test]
fn a_standards_catalogue_is_its_list_then_its_fallback() {
    for level in ComplianceLevel::all() {
        let ids: Vec<&str> = rule_catalog(&RuleCatalogFilter::for_levels([*level]))
            .iter()
            .map(|e| e.id)
            .collect();
        let mut expected = rules_for_level(*level).to_vec();
        expected.push(generic_rule_id_for_level(*level));
        assert_eq!(ids, expected, "{level:?}");
    }
    let by_alias = |name: &str| {
        let selector: StandardSelector = name.parse().expect("known standard");
        rule_catalog(&RuleCatalogFilter::for_standards([selector]))
    };
    assert_eq!(by_alias("cra-art24"), by_alias("oss-steward"));
    assert_eq!(by_alias("cra-phase2"), by_alias("cra"));
    assert_eq!(by_alias("tr-03183"), by_alias("bsi"));
}

/// The rules BSI TR-03183-2 checks are its own: the shared CRA-family
/// catalogue gave BSI 107 rules, most of them CRA, AI Act and EUCC rules.
#[test]
fn single_family_standards_list_only_their_own_rules() {
    for (level, prefix) in [
        (ComplianceLevel::BsiTr03183_2, "SBOM-BSI-TR-03183-2-"),
        (ComplianceLevel::EuccSubstantial, "SBOM-EUCC-"),
        (ComplianceLevel::EuAiAct, "SBOM-AIACT-"),
        (ComplianceLevel::BsiSbomForAi, "SBOM-BSIAI-"),
        (ComplianceLevel::CraOssSteward, "SBOM-CRA-"),
        (ComplianceLevel::Minimum, "SBOM-QUALITY-"),
    ] {
        for id in rules_for_level(level) {
            assert!(id.starts_with(prefix), "{level:?} lists {id}");
        }
    }
    assert_eq!(rules_for_level(ComplianceLevel::BsiTr03183_2).len(), 16);
}

/// SBOM-CRA-ART-24 cites CRA Art. 24, with the EUR-Lex URL of the other CRA
/// references, so its findings carry a reference and a help URI.
#[test]
fn the_steward_gate_cites_article_24() {
    let entry = rule_catalog_entry("SBOM-CRA-ART-24").expect("registered");
    let labels: Vec<&str> = entry.references.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["CRA Art. 24"]);
    let violation = checker(ComplianceLevel::CraOssSteward)
        .check(&sbom_tools::model::NormalizedSbom::default())
        .violations
        .into_iter()
        .find(|v| v.rule_id == "SBOM-CRA-ART-24")
        .expect("an empty SBOM fails the steward gate");
    assert_eq!(violation.standard_refs.len(), 1);
    assert_eq!(
        violation.help_uri(),
        Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
    );
}

fn schema() -> Value {
    let text = std::fs::read_to_string(SCHEMA_PATH).expect("schema readable");
    serde_json::from_str(&text).expect("schema is JSON")
}

fn assert_valid(schema: &Value, document: &Value, label: &str) {
    if let Err(errors) = json_schema::validate(schema, document) {
        panic!(
            "{label}: {} schema violation(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
}

/// The JSON of the whole catalogue, of each standard's and of each single
/// rule matches the published schema and its strict copy, which rejects a
/// field the schema does not declare.
#[test]
fn catalogue_json_matches_the_schema_and_its_strict_copy() {
    let schema = schema();
    let strict = json_schema::strict_copy(&schema);
    let mut documents: Vec<(String, Vec<_>)> =
        vec![("all".to_string(), rule_catalog(&RuleCatalogFilter::all()))];
    for level in ComplianceLevel::all() {
        documents.push((
            format!("{level:?}"),
            rule_catalog(&RuleCatalogFilter::for_levels([*level])),
        ));
    }
    for id in all_rule_ids() {
        documents.push((
            (*id).to_string(),
            vec![rule_catalog_entry(id).expect("registered")],
        ));
    }
    for (label, entries) in &documents {
        let json = generate_rule_catalog_json(entries).expect("serializes");
        let document: Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(document["schema"], RULE_CATALOG_JSON_SCHEMA, "{label}");
        assert_eq!(document["tool"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            document["rules"].as_array().map(Vec::len),
            Some(entries.len()),
            "{label}"
        );
        assert_valid(&schema, &document, label);
        assert_valid(&strict, &document, &format!("{label} (strict)"));
    }
    assert_eq!(RULE_CATALOG_JSON_SCHEMA, "sbom-tools/rules/v1");
}
