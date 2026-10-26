//! Finding keys are unique within every compliance result.
//!
//! `finding_id` digests the finding key for SARIF `partialFingerprints` and
//! baselines, where two findings with one id would merge distinct alerts.
//! Every rule therefore reports at most one finding per subject, or tells
//! its findings on one subject apart by a `finding_detail` (numbered where
//! the SBOM repeats an entry). This test runs every SBOM under
//! tests/fixtures at every level — without and with its auto-discovered CRA
//! sidecar, and the CRA levels under every pinned product class — and fails
//! on any key or id that repeats within a result. There is no allowlist.

#[path = "common/clock.rs"]
mod clock;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sbom_tools::model::{CraProductClass, CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, finding_id, finding_key,
};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Every file under tests/fixtures that parses as an SBOM (in any format
/// the parsers read), sorted, with its auto-discovered CRA sidecar.
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
    }
    out
}

/// The keys that repeat within `result`, one `<label> <key> ×n` line each.
/// Distinct keys must not share a finding id either.
fn repeated_keys(label: &str, result: &ComplianceResult) -> Vec<String> {
    let mut keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    for violation in &result.violations {
        let key = finding_key(result.level, violation);
        *ids.entry(finding_id(&key)).or_default() += 1;
        *keys.entry(key).or_default() += 1;
    }
    assert_eq!(
        ids.len(),
        keys.len(),
        "{label}: distinct keys share a finding id"
    );
    keys.into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(key, n)| format!("{label} {key} ×{n}"))
        .collect()
}

fn assert_no_repeats(repeats: &[String]) {
    assert!(
        repeats.is_empty(),
        "{} finding keys repeat within a result (split the rule, or give its \
         findings on one subject a finding_detail):\n{}",
        repeats.len(),
        repeats.join("\n")
    );
}

#[test]
fn finding_keys_and_ids_are_unique_within_every_result() {
    let sboms = sboms();
    assert!(sboms.len() > 50, "fixture walk found {}", sboms.len());
    let mut results = 0usize;
    let mut findings = 0usize;
    let mut repeats = Vec::new();
    for (rel, sbom, sidecar) in &sboms {
        for (label, checker) in checkers(sidecar.as_ref()) {
            let result = checker.check(sbom);
            results += 1;
            findings += result.violations.len();
            repeats.extend(repeated_keys(&format!("{rel} [{label}]"), &result));
        }
    }
    assert_no_repeats(&repeats);
    assert!(
        results > 2000 && findings > 10_000,
        "the walk checked only {results} results with {findings} findings"
    );
}

/// A CycloneDX document that trips, on purpose, every way the checks can
/// report two findings of one rule on one subject that no fixture covers:
/// a hardware component missing several [PRE-8-RQ-02] elements, end-of-life
/// data beside a missing support end date, a component missing several
/// quality elements, two invalid manufacturer emails, two un-evidenced
/// sidecar controls, a certificate with two unclassifiable signature
/// candidates, a protocol listing one cipher suite twice, and a
/// vulnerability listed twice for one component.
fn repeat_prone_cdx() -> (NormalizedSbom, CraSidecarMetadata) {
    use sbom_tools::model::{Creator, CreatorType, EolInfo, EolStatus};
    let json = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T00:00:00Z",
            "component": {"type": "application", "bom-ref": "app", "name": "app", "version": "1.0"}
        },
        "components": [
            {"type": "firmware", "bom-ref": "fw-ref", "name": "fw"},
            {"type": "device", "bom-ref": "dev-ref", "name": "dev"},
            {"type": "library", "bom-ref": "lib-x", "name": "lib-x"},
            {"type": "library", "bom-ref": "NOASSERTION", "name": "NOASSERTION"},
            {"type": "library", "bom-ref": "old-lib", "name": "old-lib", "version": "1.0",
             "purl": "pkg:npm/old-lib@1.0"},
            {"type": "library", "bom-ref": "aging-lib", "name": "aging-lib", "version": "2.0",
             "purl": "pkg:npm/aging-lib@2.0"},
            {"type": "cryptographic-asset", "bom-ref": "crypto/certificate/c", "name": "c",
             "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                 "relatedCryptographicAssets": [
                     {"type": "algorithm", "ref": "opaque-a"},
                     {"type": "algorithm", "ref": "opaque-b"}
                 ]}}},
            {"type": "cryptographic-asset", "bom-ref": "crypto/protocol/tls", "name": "tls",
             "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                 "type": "tls", "version": "1.2",
                 "cipherSuites": [
                     {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
                     {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
                 ],
                 "cryptoRefArray": ["RSA-2048"]}}}
        ],
        "vulnerabilities": [
            {"bom-ref": "v1", "id": "CVE-2026-0001", "affects": [{"ref": "lib-x"}]},
            {"bom-ref": "v2", "id": "CVE-2026-0001", "affects": [{"ref": "lib-x"}]}
        ]
    });
    let mut sbom = parse_sbom_str(&json.to_string()).expect("synthetic document parses");
    for email in ["not-an-email", "also not an email"] {
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "Acme".to_string(),
            email: Some(email.to_string()),
        });
    }
    for (name, status) in [
        ("old-lib", EolStatus::EndOfLife),
        ("aging-lib", EolStatus::ApproachingEol),
    ] {
        let comp = sbom
            .components
            .values_mut()
            .find(|c| c.name == name)
            .expect("component present");
        comp.eol = Some(EolInfo {
            status,
            product: name.to_string(),
            cycle: "1".to_string(),
            eol_date: None,
            support_end_date: None,
            is_lts: false,
            latest_in_cycle: None,
            latest_release_date: None,
            days_until_eol: None,
        });
    }
    let sidecar: CraSidecarMetadata = serde_json::from_value(serde_json::json!({
        "annexIPartIControls": {
            "1.a": {"satisfied": true},
            "1.b": {"satisfied": true}
        }
    }))
    .expect("sidecar loads");
    (sbom, sidecar)
}

/// The fixture corpus does not exercise every way a rule can report twice on
/// one subject; this document does, and an SPDX document claiming version
/// 4.0 draws both spec-version findings. Keys stay unique at every level.
#[test]
fn repeat_prone_documents_keep_unique_keys() {
    let (cdx, sidecar) = repeat_prone_cdx();
    let mut spdx4 = parse_sbom_str(
        &std::fs::read_to_string(Path::new(FIXTURES_DIR).join("spdx/minimal.spdx.json"))
            .expect("fixture readable"),
    )
    .expect("fixture parses");
    spdx4.document.spec_version = "4.0".to_string();

    let mut repeats = Vec::new();
    let mut fired: std::collections::BTreeSet<(String, &'static str)> =
        std::collections::BTreeSet::new();
    let mut numbered = 0usize;
    for (name, sbom, sidecar) in [("cdx", &cdx, Some(&sidecar)), ("spdx-4.0", &spdx4, None)] {
        for (label, checker) in checkers(sidecar) {
            let result = checker.check(sbom);
            repeats.extend(repeated_keys(&format!("{name} [{label}]"), &result));
            for v in &result.violations {
                fired.insert((label.clone(), v.rule_id));
                numbered += usize::from(
                    v.finding_detail
                        .as_deref()
                        .is_some_and(|d| d.ends_with("#2")),
                );
            }
        }
    }
    assert_no_repeats(&repeats);

    // The document does trip what it is meant to: several findings of one
    // check family on one subject, and repeats numbered.
    for (label, rule_id) in [
        ("CraPhase2", "SBOM-CRA-PRE-8-RQ-02-PRODUCER"),
        ("CraPhase2", "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER"),
        ("CraPhase2", "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION"),
        ("CraPhase2", "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE"),
        ("CraPhase2", "SBOM-CRA-ART-13-8"),
        ("CraPhase2", "SBOM-CRA-ART-13-8-EOL"),
        ("CraPhase2", "SBOM-CRA-LIFECYCLE"),
        ("CraPhase2", "SBOM-CRA-LIFECYCLE-APPROACHING-EOL"),
        ("CraPhase2", "SBOM-CRA-ART-13-16-EMAIL"),
        ("CraPhase2 + sidecar", "SBOM-CRA-ANNEX-I-CONTROLS"),
        ("Comprehensive", "SBOM-QUALITY-IDENTIFIER"),
        ("Comprehensive", "SBOM-QUALITY-LICENSE"),
        ("Comprehensive", "SBOM-QUALITY-HASH"),
        ("Comprehensive", "SBOM-QUALITY-ELEMENT-ID"),
        ("Comprehensive", "SBOM-QUALITY-SPEC-VERSION-UNKNOWN"),
        ("FdaMedicalDevice", "SBOM-FDA-COMPONENT-NAME"),
        ("FdaMedicalDevice", "SBOM-FDA-ELEMENT-ID"),
        ("Cnsa2", "SBOM-CNSA2-CERT-UNKNOWN"),
        ("Cnsa2", "SBOM-CNSA2-PROTO-002"),
        ("NistPqc", "SBOM-PQC-CERT-UNKNOWN"),
        ("NistPqc", "SBOM-PQC-PROTO-002"),
    ] {
        assert!(
            fired.contains(&(label.to_string(), rule_id)),
            "[{label}] the document must fire {rule_id}"
        );
    }
    assert!(numbered > 0, "no repeated entry was numbered");
}
