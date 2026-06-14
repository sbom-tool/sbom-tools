//! Regression tests for the compliance rule registry (PR-C1).
//!
//! These guard the two invariants the registry refactor is meant to keep:
//!
//! 1. **No orphan rules** — every violation emitted by `ComplianceChecker`
//!    (across every `ComplianceLevel` and a representative fixture set) carries
//!    a `rule_id` that resolves in `rule_meta`.
//! 2. **Stable external SARIF rule IDs** — the rule IDs surfaced in SARIF
//!    output (which GitHub code scanning dedups on) are pinned to an explicit
//!    snapshot, so a reworded message can never silently re-bucket a rule.

use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, rule_meta};
use sbom_tools::reports::generate_compliance_sarif;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Representative fixtures that, between them, trigger violations across the
/// CRA / BSI / CNSA / PQC / SPDX / CycloneDX surfaces.
fn fixtures() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for (dir, files) in [
        (
            "cra",
            &[
                "cra-compliant.cdx.json",
                "cra-noncompliant-no-manufacturer.cdx.json",
                "cra-noncompliant-weak-hashes.cdx.json",
                "router-hardware.cdx.json",
                "bsi-compliant.cdx.json",
            ][..],
        ),
        (
            "cyclonedx",
            &[
                "minimal.cdx.json",
                "with-vulnerabilities.cdx.json",
                "cbom-cnsa2-violations.cdx.json",
                "cbom-weak-crypto.cdx.json",
                "cbom-pqc-transition.cdx.json",
            ][..],
        ),
        ("spdx", &["minimal.spdx.json"][..]),
    ] {
        for f in files {
            let p = fixture_dir(dir).join(f);
            if p.exists() {
                v.push(p);
            }
        }
    }
    v
}

#[test]
fn every_emitted_violation_resolves_in_the_registry() {
    let mut checked = 0usize;
    for fx in fixtures() {
        let Ok(sbom) = parse_sbom(&fx) else {
            panic!("failed to parse fixture {}", fx.display());
        };
        for level in ComplianceLevel::all() {
            let result = ComplianceChecker::new(*level).check(&sbom);
            for v in &result.violations {
                checked += 1;
                let meta = rule_meta(v.rule_id);
                assert!(
                    meta.is_some(),
                    "orphan rule_id {:?} (requirement {:?}) at level {level:?} in {}",
                    v.rule_id,
                    v.requirement,
                    fx.display()
                );
                // The registry's SARIF id must look like a real rule id.
                let sarif_id = meta.unwrap().sarif_id;
                assert!(
                    sarif_id.starts_with("SBOM-"),
                    "rule {:?} maps to a non-SBOM SARIF id {sarif_id:?}",
                    v.rule_id
                );
            }
        }
    }
    assert!(
        checked > 50,
        "expected the fixtures to exercise many violations, only saw {checked}"
    );
}

#[test]
fn empty_sbom_emits_no_orphan_rules_at_any_level() {
    let sbom = sbom_tools::model::NormalizedSbom::default();
    for level in ComplianceLevel::all() {
        let result = ComplianceChecker::new(*level).check(&sbom);
        for v in &result.violations {
            assert!(
                rule_meta(v.rule_id).is_some(),
                "empty SBOM at {level:?} produced orphan rule_id {:?}",
                v.rule_id
            );
        }
    }
}

/// Collect the set of distinct SARIF rule IDs emitted for a fixture/level.
fn sarif_rule_ids(sbom_path: &PathBuf, level: ComplianceLevel) -> BTreeSet<String> {
    let sbom = parse_sbom(sbom_path).expect("parse fixture");
    let sidecar = CraSidecarMetadata::from_file(&sbom_path.with_extension("cra.json")).ok();
    let mut checker = ComplianceChecker::new(level);
    if let Some(s) = sidecar {
        checker = checker.with_sidecar(s);
    }
    let result = checker.check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("SARIF generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
    json["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(String::from))
        .collect()
}

/// Pin the externally-visible SARIF rule IDs for the no-manufacturer CRA
/// fixture under CraPhase2. GitHub code scanning dedups on these IDs, so a
/// change here is a breaking change to downstream alert tracking and must be
/// made deliberately.
#[test]
fn sarif_rule_ids_are_stable_for_cra_noncompliant_fixture() {
    let fx = fixture_dir("cra").join("cra-noncompliant-no-manufacturer.cdx.json");
    let ids = sarif_rule_ids(&fx, ComplianceLevel::CraPhase2);

    // Every emitted ID must be one of the known, stable CRA external rule IDs.
    let allowed: BTreeSet<&str> = [
        "SBOM-CRA-ART-13-3",
        "SBOM-CRA-ART-13-4",
        "SBOM-CRA-ART-13-5",
        "SBOM-CRA-ART-13-6",
        "SBOM-CRA-ART-13-7",
        "SBOM-CRA-ART-13-8",
        "SBOM-CRA-ART-13-9",
        "SBOM-CRA-ART-13-11",
        "SBOM-CRA-ART-13-12",
        "SBOM-CRA-ART-13-15",
        "SBOM-CRA-ANNEX-I",
        "SBOM-CRA-ANNEX-III",
        "SBOM-CRA-ANNEX-VII",
        "SBOM-CRA-PRE-7-RQ-07-RE",
        "SBOM-CRA-GENERAL",
    ]
    .into_iter()
    .collect();

    for id in &ids {
        assert!(
            allowed.contains(id.as_str()),
            "unexpected/new SARIF rule ID {id:?} for CRA noncompliant fixture; \
             changing externally-visible rule IDs breaks GitHub code-scanning dedup"
        );
    }
    // Sanity: the manufacturer/identification gaps must surface their pinned IDs.
    assert!(
        ids.contains("SBOM-CRA-ART-13-15"),
        "expected the manufacturer-identification rule SBOM-CRA-ART-13-15; got {ids:?}"
    );
}

/// The NTIA / FDA / SSDF / EO families keep their stable prefixes. The shared
/// document-metadata checks (creator/serial-number) emit `SBOM-CRA-GENERAL`
/// regardless of level, matching the pre-registry behaviour, so that generic
/// fallback is permitted alongside the profile prefix.
#[test]
fn sarif_rule_ids_keep_profile_prefixes() {
    let fx = fixture_dir("cyclonedx").join("minimal.cdx.json");
    for (level, prefix) in [
        (ComplianceLevel::NtiaMinimum, "SBOM-NTIA-"),
        (ComplianceLevel::NistSsdf, "SBOM-SSDF-"),
        (ComplianceLevel::Eo14028, "SBOM-EO14028-"),
    ] {
        let ids = sarif_rule_ids(&fx, level);
        assert!(
            ids.iter()
                .all(|id| id.starts_with(prefix) || id == "SBOM-CRA-GENERAL"),
            "{level:?} should emit only {prefix}* (or SBOM-CRA-GENERAL) rule IDs, got {ids:?}"
        );
    }
}
