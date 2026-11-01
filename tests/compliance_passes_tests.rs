//! Passes are not findings (v0.4.0 review finding O2).
//!
//! A check that affirms what the SBOM gets right is a passed check, kept in
//! `ComplianceResult::passed` apart from the violations; an Info violation
//! reports a gap or gives advice. This file holds that split to the reviewed
//! classification in tests/common/info_classification.rs:
//!
//! - every registered rule with an Info default is a pass-only rule or a
//!   classified Info finding;
//! - across every SBOM fixture at every level (with its CRA sidecar, every
//!   pinned CRA product class, and a clock before the CRA Art. 14 deadline),
//!   every Info violation is a classified finding and every passed check
//!   comes from a pass-only rule;
//! - a standard that does not apply reports no finding at all;
//! - the acceptance case: cbom-quantum-ready reports 0 Info and 8 passed
//!   checks, and no SARIF result describes a pass unless asked to.

#[path = "common/clock.rs"]
mod clock;
#[path = "common/info_classification.rs"]
mod info_classification;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use info_classification::{INFO_FINDINGS, info_finding_reason};
use sbom_tools::model::{CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    CnsaCategory, ComplianceChecker, ComplianceLevel, ComplianceResult, PASS_RULE_IDS, PqcMode,
    PqcProfile, RuleKind, ViolationSeverity, all_rule_ids, rule_kind, rule_meta,
};
use sbom_tools::reports::{
    SarifOptions, generate_compliance_sarif, generate_compliance_sarif_with,
};
use serde_json::Value;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The day before the CRA Art. 14 reporting obligations apply, when a
/// missing reporting channel is an Info.
const BEFORE_ART_14: &str = "2026-09-10T00:00:00Z";

#[test]
fn the_classification_is_well_formed() {
    let mut seen = BTreeSet::new();
    for (rule, reason) in INFO_FINDINGS {
        assert!(seen.insert(*rule), "{rule} is listed twice");
        assert!(!reason.trim().is_empty(), "{rule} has no reason");
        assert_eq!(
            rule_kind(rule),
            Some(RuleKind::Finding),
            "{rule} must be a registered finding rule, not a pass-only one"
        );
    }
    for rule in PASS_RULE_IDS {
        assert!(
            info_finding_reason(rule).is_none(),
            "pass-only {rule} is classified as an Info finding"
        );
    }
}

/// A rule documented at Info either affirms (a pass-only rule) or is a
/// reviewed gap or advice.
#[test]
fn every_info_default_rule_is_a_pass_or_a_classified_finding() {
    let unclassified: Vec<&str> = all_rule_ids()
        .iter()
        .copied()
        .filter(|id| {
            rule_meta(id).is_some_and(|m| m.default_severity == ViolationSeverity::Info)
                && rule_kind(id) != Some(RuleKind::Pass)
                && info_finding_reason(id).is_none()
        })
        .collect();
    assert!(
        unclassified.is_empty(),
        "rules with an Info default that are neither pass-only nor classified in \
         tests/common/info_classification.rs: {unclassified:?}"
    );
}

/// Every parseable SBOM under tests/fixtures, sorted, with its sidecar.
fn sboms() -> Vec<(String, NormalizedSbom, Option<CraSidecarMetadata>)> {
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
    walk(root, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let rel = path.strip_prefix(root).ok()?.to_string_lossy().into_owned();
            if rel.ends_with(".cra.json") || rel.ends_with(".cra.yaml") {
                return None;
            }
            let sbom = parse_sbom_str(&std::fs::read_to_string(&path).ok()?).ok()?;
            let sidecar = CraSidecarMetadata::discover_for_sbom(&path)
                .unwrap_or_else(|e| panic!("{rel}: sidecar does not load: {e}"));
            Some((rel, sbom, sidecar))
        })
        .collect()
}

/// Every checker configuration a fixture runs under, labelled.
fn checkers(sidecar: Option<&CraSidecarMetadata>) -> Vec<(String, ComplianceChecker)> {
    let before_art_14 = chrono::DateTime::parse_from_rfc3339(BEFORE_ART_14)
        .expect("valid instant")
        .with_timezone(&chrono::Utc);
    let mut out = Vec::new();
    for level in ComplianceLevel::all() {
        out.push((format!("{level:?}"), clock::checker(*level)));
        if let Some(sc) = sidecar {
            out.push((
                format!("{level:?} + sidecar"),
                clock::checker(*level).with_sidecar(sc.clone()),
            ));
        }
        if level.is_cra() {
            out.push((
                format!("{level:?} before Art. 14"),
                ComplianceChecker::new(*level).with_as_of(before_art_14),
            ));
            for class in [
                CraProductClass::Default,
                CraProductClass::ImportantClass1,
                CraProductClass::ImportantClass2,
                CraProductClass::Critical,
            ] {
                out.push((
                    format!("{level:?} + {class:?}"),
                    clock::checker(*level).with_product_class(class),
                ));
            }
        }
        // The crypto standards under `--pqc-mode deadline`, which reports
        // an algorithm before its migration deadline at Info.
        if matches!(level, ComplianceLevel::Cnsa2 | ComplianceLevel::NistPqc) {
            for (label, profile, category) in [
                ("nist", PqcProfile::Nist, None),
                ("federal", PqcProfile::Federal, None),
                ("niche", PqcProfile::Nist, Some(CnsaCategory::Niche)),
            ] {
                let mut checker = clock::checker(*level)
                    .with_pqc_mode(PqcMode::Deadline)
                    .with_pqc_profile(profile);
                if let Some(category) = category {
                    checker = checker.with_cnsa_category(category);
                }
                out.push((format!("{level:?} deadline {label}"), checker));
            }
        }
    }
    out
}

/// No affirmation hides among the Info violations of any fixture, and every
/// passed check comes from a pass-only rule.
#[test]
fn every_info_violation_on_every_fixture_is_a_classified_finding() {
    let sboms = sboms();
    assert!(sboms.len() > 50, "fixture walk found {}", sboms.len());
    let mut unclassified: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut info_rules: BTreeSet<&'static str> = BTreeSet::new();
    let mut pass_rules: BTreeSet<&'static str> = BTreeSet::new();
    for (rel, sbom, sidecar) in &sboms {
        for (label, checker) in checkers(sidecar.as_ref()) {
            let result = checker.check(sbom);
            for v in &result.violations {
                if v.severity != ViolationSeverity::Info {
                    continue;
                }
                info_rules.insert(v.rule_id);
                if info_finding_reason(v.rule_id).is_none() {
                    unclassified
                        .entry(v.rule_id)
                        .or_insert_with(|| format!("{rel} [{label}]: {}", v.message));
                }
            }
            for p in &result.passed {
                assert_eq!(
                    rule_kind(p.rule_id),
                    Some(RuleKind::Pass),
                    "{rel} [{label}]: {} passed a check but is no pass-only rule",
                    p.rule_id
                );
                pass_rules.insert(p.rule_id);
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "Info violations of rules tests/common/info_classification.rs does not \
         classify (an affirmation belongs in `passed`; a gap or advice needs a \
         listed reason):\n  {}",
        unclassified
            .iter()
            .map(|(rule, example)| format!("{rule}: {example}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    // The walk does exercise both sides of the split.
    assert!(info_rules.len() > 30, "only {info_rules:?} reported Info");
    assert_eq!(
        pass_rules,
        PASS_RULE_IDS.iter().copied().collect(),
        "every pass-only rule passes a check somewhere in the corpus"
    );
}

/// A standard that does not apply reports neither a violation nor a pass:
/// its verdict is the result's applicability.
#[test]
fn a_standard_that_does_not_apply_reports_no_finding() {
    let mut not_applicable = 0usize;
    for (rel, sbom, sidecar) in sboms() {
        for (label, checker) in checkers(sidecar.as_ref()) {
            let result = checker.check(&sbom);
            if result.is_applicable() {
                continue;
            }
            not_applicable += 1;
            assert!(
                result.violations.is_empty() && result.passed.is_empty(),
                "{rel} [{label}]: an N/A standard reports {:?}",
                result.violations
            );
            assert!(result.is_compliant && result.score().is_none(), "{rel}");
        }
    }
    assert!(not_applicable > 100, "only {not_applicable} N/A results");
}

fn quantum_ready(rel: &str) -> ComplianceResult {
    let raw = std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel)).expect("readable");
    let sbom = parse_sbom_str(&raw).expect("fixture parses");
    clock::checker(ComplianceLevel::NistPqc).check(&sbom)
}

fn sarif_results(sarif: &str) -> Vec<Value> {
    let value: Value = serde_json::from_str(sarif).expect("SARIF is JSON");
    value["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .clone()
}

/// The acceptance case of review finding O2.
#[test]
fn cbom_quantum_ready_reports_no_info_and_eight_passes() {
    for rel in [
        "cyclonedx/cbom-quantum-ready.cdx.json",
        "cyclonedx/cbom-quantum-ready.cdx.xml",
    ] {
        let result = quantum_ready(rel);
        assert!(result.is_compliant, "{rel}");
        assert_eq!(result.info_count, 0, "{rel}: {:?}", result.violations);
        assert!(
            result.violations.is_empty(),
            "{rel}: {:?}",
            result.violations
        );
        assert_eq!(result.passed.len(), 8, "{rel}: {:?}", result.passed);
        assert!(
            result.passed.iter().all(|p| p.rule_id == "SBOM-PQC-009"),
            "{rel}: {:?}",
            result.passed
        );
        assert!(
            result.passed.iter().any(|p| p.message
                == "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"),
            "{rel}: {:?}",
            result.passed
        );

        // No SARIF result describes a pass, unless asked to.
        let plain = generate_compliance_sarif(&result).expect("SARIF");
        assert!(sarif_results(&plain).is_empty(), "{rel}: {plain}");
        let with_passes =
            generate_compliance_sarif_with(&result, &SarifOptions::new().with_passes(true))
                .expect("SARIF");
        let passes = sarif_results(&with_passes);
        assert_eq!(passes.len(), 8, "{rel}");
        assert!(
            passes
                .iter()
                .all(|p| p["kind"] == "pass" && p["level"] == "none"),
            "{rel}: {with_passes}"
        );
    }
}
