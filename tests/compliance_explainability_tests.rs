//! What a compliance result explains: where the field a finding checks
//! lives in the SBOM's own format (`field`), the value the check read
//! (`observed`), and the checks a standard did not evaluate (`evaluated`),
//! in the model and in the JSON envelope and SARIF log. The text report is
//! covered in tests/cli_contract_tests.rs.

#[path = "common/clock.rs"]
mod clock;
#[path = "common/json_schema.rs"]
mod json_schema;

use std::path::{Path, PathBuf};

use clock::checker;
use sbom_tools::model::{CraProductClass, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, EvaluationStatus, PqcMode, PqcProfile, RemediationFormat,
    Violation, rule_meta, rules_for_level,
};
use sbom_tools::reports::{
    generate_compliance_json, generate_compliance_sarif, generate_multi_compliance_sarif,
};
use serde_json::{Value, json};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(rel: &str) -> NormalizedSbom {
    let raw = std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel)).expect("fixture readable");
    parse_sbom_str(&raw).unwrap_or_else(|e| panic!("{rel} must parse: {e}"))
}

fn parse(document: &Value) -> NormalizedSbom {
    parse_sbom_str(&document.to_string()).expect("document parses")
}

/// A CycloneDX 1.6 document for `app`, the primary component, with
/// `components`.
fn cyclonedx(components: Value) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "authors": [{"name": "Example"}],
            "component": {"type": "application", "bom-ref": "app-ref", "name": "app",
                          "version": "1.0.0", "purl": "pkg:generic/app@1.0.0"}
        },
        "components": components,
        "dependencies": [{"ref": "app-ref", "dependsOn": ["lib-ref"]}]
    })
}

/// A library that names no supplier.
fn lib() -> Value {
    json!({"type": "library", "bom-ref": "lib-ref", "name": "lib", "version": "1.0.0",
           "purl": "pkg:npm/lib@1.0.0"})
}

/// The violations of `rule_id` in `result`.
fn findings<'a>(result: &'a ComplianceResult, rule_id: &str) -> Vec<&'a Violation> {
    result
        .violations
        .iter()
        .filter(|v| v.rule_id == rule_id)
        .collect()
}

/// The one violation of `rule_id` about the component `component_id`, or
/// about the document when `None`.
fn finding<'a>(
    result: &'a ComplianceResult,
    rule_id: &str,
    component_id: Option<&str>,
) -> &'a Violation {
    let matching: Vec<_> = findings(result, rule_id)
        .into_iter()
        .filter(|v| v.component_id.as_deref() == component_id)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "one {rule_id} finding about {component_id:?} expected in {:#?}",
        result.violations
    );
    matching[0]
}

/// The rules `result` lists as not evaluated, in order.
fn not_evaluated(result: &ComplianceResult) -> Vec<&'static str> {
    result.evaluated.iter().map(|e| e.rule_id).collect()
}

// ---------------------------------------------------------------------------
// field
// ---------------------------------------------------------------------------

/// A finding names its field in the SBOM's own format; a CycloneDX finding
/// about the primary component names it under `metadata.component`.
#[test]
fn field_names_the_checked_field_in_the_documents_format() {
    let sbom = parse(&cyclonedx(json!([lib()])));
    let result = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert_eq!(
        finding(&result, "SBOM-NTIA-SUPPLIER", Some("pkg:npm/lib@1.0.0"))
            .field
            .as_deref(),
        Some("components[].supplier.name")
    );
    assert_eq!(
        finding(&result, "SBOM-NTIA-SUPPLIER", Some("pkg:generic/app@1.0.0"))
            .field
            .as_deref(),
        Some("metadata.component.supplier.name")
    );

    for (rel, field) in [
        ("spdx/minimal.spdx.json", "packages[].supplier"),
        ("spdx3/minimal.spdx3.json", "suppliedBy"),
    ] {
        let result = checker(ComplianceLevel::NtiaMinimum).check(&fixture(rel));
        let suppliers = findings(&result, "SBOM-NTIA-SUPPLIER");
        assert!(!suppliers.is_empty(), "{rel}: a supplier finding");
        for v in suppliers {
            assert_eq!(v.field.as_deref(), Some(field), "{rel}");
        }
    }

    // A rule whose fix is the same in every format names no field.
    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let freshness = rule_meta("SBOM-CRA-SBOM-FRESHNESS").expect("registered");
    assert!(freshness.advice.is_none());
    for v in findings(&result, "SBOM-CRA-SBOM-FRESHNESS") {
        assert_eq!(v.field, None);
    }
}

/// Files under the SBOM fixture directories that are not SBOMs.
fn is_non_sbom(rel: &str) -> bool {
    [
        ".cra.json",
        ".cra.yaml",
        ".md",
        ".toml",
        "corpus.json",
        ".openvex.json",
    ]
    .iter()
    .any(|suffix| rel.ends_with(suffix))
}

/// Every parseable SBOM fixture, sorted.
fn fixtures() -> Vec<(String, NormalizedSbom)> {
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
    for dir in [
        "aibom",
        "compliance/regressions",
        "cra",
        "cyclonedx",
        "showcase",
        "spdx",
        "spdx3",
    ] {
        walk(&root.join(dir), &mut paths);
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let rel = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            if is_non_sbom(&rel) {
                return None;
            }
            let raw = std::fs::read_to_string(&path).ok()?;
            Some((rel, parse_sbom_str(&raw).ok()?))
        })
        .collect()
}

/// Over every fixture and level: each finding's `field` is its rule's field
/// for the document's format, the CycloneDX primary's under
/// `metadata.component`, and `None` exactly when the rule names none.
#[test]
fn every_finding_names_its_rules_field() {
    let mut fields = 0;
    let mut primary = 0;
    for (rel, sbom) in fixtures() {
        let format = RemediationFormat::of(&sbom.document);
        let primary_id = sbom
            .primary_component_id
            .as_ref()
            .map(|id| id.value().to_string());
        for level in ComplianceLevel::all() {
            let result = checker(*level).check(&sbom);
            for v in &result.violations {
                let registry = rule_meta(v.rule_id).and_then(|m| m.field_for(format));
                let about_primary = primary_id.is_some() && v.component_id == primary_id;
                let expected = registry.map(|field| match field.strip_prefix("components[]") {
                    Some(rest) if about_primary && format == RemediationFormat::CycloneDx => {
                        primary += 1;
                        format!("metadata.component{rest}")
                    }
                    _ => field.to_string(),
                });
                assert_eq!(v.field, expected, "{rel} [{level:?}] {}", v.rule_id);
                fields += usize::from(v.field.is_some());
            }
        }
    }
    assert!(fields > 1000, "{fields} findings named a field");
    assert!(primary > 0, "a finding about a CycloneDX primary component");
}

// ---------------------------------------------------------------------------
// observed
// ---------------------------------------------------------------------------

/// The common checks record the value they read: a placeholder supplier or
/// version, a digest that does not count, an invalid email, a timestamp in
/// the future. A value that is absent records nothing.
#[test]
fn observed_records_the_value_a_check_read() {
    let sbom = parse(&cyclonedx(json!([
        {"type": "library", "bom-ref": "lib-ref", "name": "lib", "version": "TBD",
         "purl": "pkg:npm/lib@1.0.0", "supplier": {"name": "NOASSERTION"},
         "hashes": [{"alg": "SHA-256", "content": "abc"}]}
    ])));
    let lib_id = Some("pkg:npm/lib@1.0.0");
    let ntia = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert_eq!(
        finding(&ntia, "SBOM-NTIA-SUPPLIER", lib_id)
            .observed
            .as_deref(),
        Some("NOASSERTION")
    );
    assert_eq!(
        finding(&ntia, "SBOM-NTIA-VERSION", lib_id)
            .observed
            .as_deref(),
        Some("TBD")
    );
    // The primary names no supplier at all: nothing was read.
    assert_eq!(
        finding(&ntia, "SBOM-NTIA-SUPPLIER", Some("pkg:generic/app@1.0.0")).observed,
        None
    );
    let fda = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
    let hash = finding(&fda, "SBOM-FDA-HASH", lib_id);
    assert_eq!(hash.observed.as_deref(), Some("SHA-256:abc"));
    assert!(
        hash.message.contains("not 64 hex characters"),
        "{}",
        hash.message
    );

    // The SPDX 2.3 fixture's SHA-256 checksum is no hex digest.
    let spdx = checker(ComplianceLevel::FdaMedicalDevice).check(&fixture("spdx/minimal.spdx.json"));
    assert!(
        findings(&spdx, "SBOM-FDA-HASH")
            .iter()
            .any(|v| v.observed.as_deref() == Some("SHA-256:abc123def456...")),
        "{:#?}",
        findings(&spdx, "SBOM-FDA-HASH")
    );

    // A creation timestamp in the future.
    let mut future = cyclonedx(json!([lib()]));
    future["metadata"]["timestamp"] = json!("2027-03-01T00:00:00Z");
    let cra = checker(ComplianceLevel::CraPhase2).check(&parse(&future));
    assert_eq!(
        finding(&cra, "SBOM-CRA-SBOM-FRESHNESS", None)
            .observed
            .as_deref(),
        Some("2027-03-01T00:00:00Z")
    );

    // A manufacturer email that is no address.
    let spdx_doc = json!({
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "app", "documentNamespace": "https://example.com/app-1.0.0",
        "creationInfo": {"created": "2026-01-01T00:00:00Z",
                         "creators": ["Organization: Acme (security@acme)"]},
        "packages": [{"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0",
                      "downloadLocation": "NOASSERTION"}]
    });
    let cra = checker(ComplianceLevel::CraPhase2).check(&parse(&spdx_doc));
    assert_eq!(
        finding(&cra, "SBOM-CRA-ART-13-16-EMAIL", None)
            .observed
            .as_deref(),
        Some("security@acme")
    );
}

/// Crypto checks record the algorithm or protocol version they rejected.
#[test]
fn observed_records_the_rejected_algorithm_and_protocol() {
    let cbom = json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
        "components": [
            {"type": "cryptographic-asset", "bom-ref": "rsa", "name": "RSA-2048",
             "cryptoProperties": {"assetType": "algorithm",
                                  "algorithmProperties": {"primitive": "signature",
                                                          "algorithmFamily": "RSA",
                                                          "parameterSetIdentifier": "2048",
                                                          "nistQuantumSecurityLevel": 0}}},
            {"type": "cryptographic-asset", "bom-ref": "tls", "name": "tls-1.0",
             "cryptoProperties": {"assetType": "protocol",
                                  "protocolProperties": {"type": "tls", "version": "1.0"}}}
        ]
    });
    let sbom = parse(&cbom);
    let pqc = checker(ComplianceLevel::NistPqc).check(&sbom);
    let rsa = findings(&pqc, "SBOM-PQC-001");
    assert_eq!(rsa.len(), 1, "{:#?}", pqc.violations);
    assert_eq!(rsa[0].observed.as_deref(), Some("RSA-2048"));
    let tls = findings(&pqc, "SBOM-PQC-PROTO-001");
    assert_eq!(tls.len(), 1, "{:#?}", pqc.violations);
    assert_eq!(tls[0].observed.as_deref(), Some("tls 1.0"));

    let cnsa = checker(ComplianceLevel::Cnsa2).check(&sbom);
    let tls = findings(&cnsa, "SBOM-CNSA2-PROTO-001");
    assert_eq!(tls.len(), 1, "{:#?}", cnsa.violations);
    assert_eq!(tls[0].observed.as_deref(), Some("tls 1.0"));
}

/// An observed value is SBOM text kept as read, like the message and the
/// element, and bounded to 200 characters, the cut marked. The outputs that
/// show it clean it (tests/cli_contract_tests.rs, the TUI detail tests).
#[test]
fn observed_is_kept_as_read_and_bounded() {
    let hostile = "lib\n::error::forged\u{1b}[31m\u{7}\u{202e}x";
    let colon = "::warning::forged";
    let long = "é".repeat(300);
    // A component whose bom-ref is its name reads as missing a bom-ref;
    // the finding records the bom-ref it read.
    let components: Vec<Value> = [hostile, colon, long.as_str()]
        .iter()
        .map(|name| json!({"type": "library", "bom-ref": name, "name": name, "version": "1.0.0"}))
        .collect();
    let mut document = cyclonedx(Value::Array(components));
    document["dependencies"] = json!([]);
    let result = checker(ComplianceLevel::NtiaMinimum).check(&parse(&document));
    let observed: Vec<&str> = findings(&result, "SBOM-NTIA-ELEMENT-ID")
        .iter()
        .filter_map(|v| v.observed.as_deref())
        .collect();
    assert_eq!(observed.len(), 3, "{:#?}", result.violations);
    assert!(observed.contains(&hostile), "{observed:?}");
    assert!(observed.contains(&colon), "{observed:?}");
    let cut = format!("{}…", "é".repeat(199));
    assert!(observed.contains(&cut.as_str()), "{observed:?}");
    for value in observed {
        assert!(value.chars().count() <= 200, "{value:?}");
    }
}

// ---------------------------------------------------------------------------
// evaluated
// ---------------------------------------------------------------------------

/// CISA 2026 asks for a signature, a lifecycle phase and a completeness
/// declaration, which SPDX 2.x cannot carry: on SPDX 2.x the three checks
/// are listed as not evaluated, with the reason, instead of passing
/// silently.
#[test]
fn cisa_2026_lists_the_checks_spdx_2_cannot_carry() {
    let result = checker(ComplianceLevel::Cisa2026).check(&fixture("spdx/minimal.spdx.json"));
    assert_eq!(
        not_evaluated(&result),
        [
            "SBOM-CISA2026-SIGNATURE",
            "SBOM-CISA2026-GENERATION-CONTEXT",
            "SBOM-CISA2026-COVERAGE",
        ]
    );
    let signature = &result.evaluated[0];
    assert_eq!(signature.status, EvaluationStatus::NotEvaluated);
    assert_eq!(
        signature.reason,
        "SPDX 2.x has no field for an in-document signature"
    );

    // CycloneDX carries all three: they run.
    let result = checker(ComplianceLevel::Cisa2026).check(&fixture("cyclonedx/minimal.cdx.json"));
    assert!(result.evaluated.is_empty(), "{:#?}", result.evaluated);
    assert!(!findings(&result, "SBOM-CISA2026-SIGNATURE").is_empty());
}

/// FSCT's evidence gates: two checks run on CycloneDX only, two on SPDX
/// only, and each format lists the other's as not evaluated.
#[test]
fn fsct_lists_its_evidence_gated_checks() {
    let cyclonedx = checker(ComplianceLevel::Fsct).check(&fixture("cyclonedx/minimal.cdx.json"));
    assert_eq!(
        not_evaluated(&cyclonedx),
        ["SBOM-FSCT-DYNAMIC-DEPS", "SBOM-FSCT-LICENSE-CONCLUDED"]
    );
    let spdx = checker(ComplianceLevel::Fsct).check(&fixture("spdx/minimal.spdx.json"));
    assert_eq!(
        not_evaluated(&spdx),
        ["SBOM-FSCT-SBOM-TYPE", "SBOM-FSCT-SIGNATURE"]
    );
}

/// The CRA checks that depend on the product class run once a class is
/// pinned; the hardware checks run once the SBOM lists hardware.
#[test]
fn cra_lists_class_dependent_and_hardware_checks() {
    const HARDWARE: [&str; 4] = [
        "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
        "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
        "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
        "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    ];
    let software = parse(&cyclonedx(json!([lib()])));
    for level in [ComplianceLevel::CraPhase1, ComplianceLevel::CraPhase2] {
        let result = checker(level).check(&software);
        let mut expected = vec!["SBOM-CRA-ANNEX-IV", "SBOM-CRA-ANNEX-VIII"];
        expected.extend(HARDWARE);
        assert_eq!(not_evaluated(&result), expected, "{level:?}");
        assert!(
            result.evaluated[0].reason.contains("--cra-product-class"),
            "{}",
            result.evaluated[0].reason
        );
        assert_eq!(
            result.evaluated[2].reason,
            "the SBOM lists no device, firmware or device-driver component"
        );

        let pinned = checker(level)
            .with_product_class(CraProductClass::Critical)
            .check(&software);
        assert_eq!(not_evaluated(&pinned), HARDWARE, "{level:?}");
    }

    let firmware = parse(&cyclonedx(json!([
        lib(),
        {"type": "firmware", "bom-ref": "fw", "name": "fw", "version": "2.1",
         "purl": "pkg:generic/fw@2.1", "supplier": {"name": "Acme"}}
    ])));
    let result = checker(ComplianceLevel::CraPhase2).check(&firmware);
    assert_eq!(
        not_evaluated(&result),
        ["SBOM-CRA-ANNEX-IV", "SBOM-CRA-ANNEX-VIII"]
    );

    // The steward profile runs neither: they are not in its rule list.
    let steward = checker(ComplianceLevel::CraOssSteward).check(&software);
    assert!(steward.evaluated.is_empty(), "{:#?}", steward.evaluated);
}

/// The federal TLS 1.3 deadline (SBOM-PQC-PROTO-003) is judged under the
/// federal profile of deadline mode only.
#[test]
fn pqc_lists_the_federal_tls_check_outside_the_federal_profile() {
    let sbom = fixture("cyclonedx/cbom-1.7.cdx.json");
    let federal_tls = ["SBOM-PQC-PROTO-003"];
    let readiness = checker(ComplianceLevel::NistPqc).check(&sbom);
    assert_eq!(not_evaluated(&readiness), federal_tls);
    let nist = checker(ComplianceLevel::NistPqc)
        .with_pqc_mode(PqcMode::Deadline)
        .check(&sbom);
    assert_eq!(not_evaluated(&nist), federal_tls);
    let federal = checker(ComplianceLevel::NistPqc)
        .with_pqc_mode(PqcMode::Deadline)
        .with_pqc_profile(PqcProfile::Federal)
        .check(&sbom);
    assert!(federal.evaluated.is_empty(), "{:#?}", federal.evaluated);
}

/// A spec version that does not parse cannot be placed in a version range:
/// each standard's version check says so instead of passing.
#[test]
fn an_unparseable_spec_version_is_not_evaluated() {
    let mut document = cyclonedx(json!([lib()]));
    document["specVersion"] = json!("1.x");
    let sbom = parse(&document);
    assert!(sbom.document.spec_version_parsed().is_none());
    for (level, rules) in [
        (
            ComplianceLevel::NtiaMinimum,
            &["SBOM-NTIA-SPEC-VERSION"][..],
        ),
        (
            ComplianceLevel::CraPhase2,
            &["SBOM-CRA-MACHINE-READABLE", "SBOM-CRA-SPEC-VERSION"][..],
        ),
        (ComplianceLevel::Cisa2026, &["SBOM-CISA2026-FORMAT"][..]),
        (ComplianceLevel::Eo14028, &["SBOM-EO14028-FORMAT"][..]),
        (
            ComplianceLevel::BsiTr03183_2,
            &["SBOM-BSI-TR-03183-2-4"][..],
        ),
    ] {
        let result = checker(level).check(&sbom);
        for rule in rules {
            let entry = result
                .evaluated
                .iter()
                .find(|e| e.rule_id == *rule)
                .unwrap_or_else(|| {
                    panic!("{level:?}: {rule} not evaluated: {:#?}", result.evaluated)
                });
            assert!(entry.reason.contains("spec version"), "{}", entry.reason);
        }
    }
}

/// Over every fixture and level: a check listed as not evaluated is one of
/// the level's rules, reports no violation and no passed check, appears
/// once, and gives a reason fit for a one-line report.
#[test]
fn checks_not_evaluated_report_nothing() {
    let mut entries = 0;
    for (rel, sbom) in fixtures() {
        for level in ComplianceLevel::all() {
            let result = checker(*level).check(&sbom);
            let mut seen = std::collections::BTreeSet::new();
            for entry in &result.evaluated {
                entries += 1;
                let rule = entry.rule_id;
                assert!(seen.insert(rule), "{rel} [{level:?}] {rule} listed twice");
                assert!(
                    rules_for_level(*level).contains(&rule),
                    "{rel} [{level:?}] {rule} is not a rule of the level"
                );
                assert!(
                    !result.violations.iter().any(|v| v.rule_id == rule)
                        && !result.passed.iter().any(|p| p.rule_id == rule),
                    "{rel} [{level:?}] {rule} is not evaluated but reports a finding"
                );
                assert_eq!(entry.status, EvaluationStatus::NotEvaluated);
                assert!(
                    !entry.reason.is_empty() && !entry.reason.chars().any(char::is_control),
                    "{rel} [{level:?}] {rule}: {:?}",
                    entry.reason
                );
            }
            if !result.is_applicable() {
                assert!(result.evaluated.is_empty(), "{rel} [{level:?}]");
            }
        }
    }
    assert!(entries > 100, "{entries} checks not evaluated");
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/// The `sbom-tools/compliance/v2` envelope carries `field` and `observed` on
/// violations and `evaluated` on results, as the published schema and its
/// strict copy declare.
#[test]
fn the_json_envelope_carries_field_observed_and_evaluated() {
    let sbom = fixture("spdx/minimal.spdx.json");
    let results = [
        checker(ComplianceLevel::Cisa2026).check(&sbom),
        checker(ComplianceLevel::FdaMedicalDevice).check(&sbom),
    ];
    let document: Value =
        serde_json::from_str(&generate_compliance_json(&results).expect("serializes"))
            .expect("envelope is JSON");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/compliance/v2.schema.json"
        ))
        .expect("schema readable"),
    )
    .expect("schema is JSON");
    for schema in [schema.clone(), json_schema::strict_copy(&schema)] {
        if let Err(errors) = json_schema::validate(&schema, &document) {
            panic!("{}", errors.join("\n"));
        }
    }

    let cisa = &document["results"][0];
    assert_eq!(
        cisa["evaluated"][0],
        json!({"rule_id": "SBOM-CISA2026-SIGNATURE", "status": "not_evaluated",
               "reason": "SPDX 2.x has no field for an in-document signature"})
    );
    let fda = &document["results"][1];
    assert!(fda.get("evaluated").is_none(), "{fda}");
    let hash = fda["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .find(|v| v["rule_id"] == "SBOM-FDA-HASH")
        .expect("a hash finding");
    assert_eq!(hash["field"], "packages[].checksums[]");
    assert_eq!(hash["observed"], "SHA-256:abc123def456...");
}

/// SARIF carries `field` and `observed` in the result properties and the
/// checks not evaluated in the run properties, per standard in a
/// multi-standard run.
#[test]
fn sarif_carries_field_observed_and_not_evaluated() {
    let sbom = fixture("spdx/minimal.spdx.json");
    let cisa = checker(ComplianceLevel::Cisa2026).check(&sbom);
    let fda = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);

    let single: Value =
        serde_json::from_str(&generate_compliance_sarif(&cisa).expect("serializes"))
            .expect("SARIF is JSON");
    let run = &single["runs"][0];
    assert_eq!(
        run["properties"]["notEvaluated"][0],
        json!({"ruleId": "SBOM-CISA2026-SIGNATURE",
               "reason": "SPDX 2.x has no field for an in-document signature"})
    );
    // Every rule not evaluated is declared in the run's rules.
    let declared: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    for entry in run["properties"]["notEvaluated"].as_array().expect("list") {
        assert!(
            declared.contains(&entry["ruleId"].as_str().expect("ruleId")),
            "{entry}"
        );
    }

    let multi: Value =
        serde_json::from_str(&generate_multi_compliance_sarif(&[cisa, fda]).expect("serializes"))
            .expect("SARIF is JSON");
    let run = &multi["runs"][0];
    assert!(run["properties"].get("notEvaluated").is_none());
    let standards = run["properties"]["standards"]
        .as_array()
        .expect("standards");
    assert_eq!(
        standards[0]["notEvaluated"].as_array().map(Vec::len),
        Some(3)
    );
    assert!(
        standards[1].get("notEvaluated").is_none(),
        "{}",
        standards[1]
    );
    let hash = run["results"]
        .as_array()
        .expect("results")
        .iter()
        .find(|r| r["ruleId"] == "SBOM-FDA-HASH")
        .expect("a hash result");
    assert_eq!(hash["properties"]["field"], "packages[].checksums[]");
    assert_eq!(hash["properties"]["observed"], "SHA-256:abc123def456...");
}

/// The fields survive a JSON round trip, and payloads without them
/// deserialize.
#[test]
fn explainability_fields_round_trip() {
    let result = checker(ComplianceLevel::Cisa2026).check(&fixture("spdx/minimal.spdx.json"));
    let back: ComplianceResult =
        serde_json::from_value(serde_json::to_value(&result).expect("serializes"))
            .expect("deserializes");
    assert_eq!(back.evaluated, result.evaluated);
    for (a, b) in back.violations.iter().zip(&result.violations) {
        assert_eq!((&a.field, &a.observed), (&b.field, &b.observed));
    }

    let mut old = serde_json::to_value(&result).expect("serializes");
    old.as_object_mut().expect("object").remove("evaluated");
    for v in old["violations"].as_array_mut().expect("violations") {
        let v = v.as_object_mut().expect("object");
        v.remove("field");
        v.remove("observed");
    }
    let back: ComplianceResult = serde_json::from_value(old).expect("old payload deserializes");
    assert!(back.evaluated.is_empty());
    assert!(
        back.violations
            .iter()
            .all(|v| v.field.is_none() && v.observed.is_none())
    );
}
