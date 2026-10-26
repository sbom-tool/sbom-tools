//! Registry-driven per-rule matrix for `ComplianceLevel::Cisa2026`
//! (audit P4: CISA 2026 Minimum Elements, v2.1, July 29, 2026).
//!
//! Every rule id in `CISA2026_SARIF_RULE_IDS` gets a firing fixture and a
//! silent fixture (real CycloneDX JSON through the real parser), or an
//! explicit skip-with-reason; exhaustiveness is enforced against the
//! registry slice.
//!
//! Four rules cannot be exercised through the shared fixture DSL (it has no
//! hooks for `signature`, `metadata.lifecycles`, `compositions`, or an
//! omitted top-level `version`); their firing/silent behaviour is covered by
//! the dedicated raw-JSON tests at the bottom of this file, which drive the
//! same real parser and checker.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::{AS_OF, checker};
use rule_matrix::{
    ComponentFixture, MD5_FILLER, RuleEntry, SbomFixture, check, render_violations, run_matrix,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    CISA2026_SARIF_RULE_IDS, ComplianceLevel, ComplianceResult, ViolationSeverity as Sev,
};

const LEVEL: ComplianceLevel = ComplianceLevel::Cisa2026;

/// Filler SHA-1 digest (40 hex chars) for deprecated-algorithm cases.
const SHA1_FILLER: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

/// A component satisfying every per-component CISA 2026 element: name,
/// version, PURL, supplier (producer evidence), SHA-256 hash, and a license.
fn conforming_component(name: &str) -> ComponentFixture {
    let mut c = ComponentFixture::conforming(name);
    c.licenses = vec!["MIT".to_string()];
    c
}

/// A fixture satisfying every CISA 2026 element the DSL can express: Person
/// author + versioned tool creator, timestamp, current format release,
/// serial number, fully-populated components, and a dependency edge.
///
/// Three Warnings are unavoidable on every DSL fixture — SIGNATURE,
/// GENERATION-CONTEXT, and COVERAGE — because the DSL cannot express a JSF
/// signature, `metadata.lifecycles`, or `compositions`. They are all inside
/// the declared universe, so the matrix's per-rule and sweep assertions are
/// unaffected; the zero-violation conforming case uses the raw-JSON document
/// below instead.
fn base() -> SbomFixture {
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-07-29T12:00:00Z".to_string()),
        serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
        tools: vec![("acme-sbom-tool".to_string(), "1.0.0".to_string())],
        authors: vec![(
            "Dana Author".to_string(),
            Some("dana@acme.example".to_string()),
        )],
        manufacturer: None,
        primary: None,
        components: vec![
            conforming_component("libalpha"),
            conforming_component("libbeta"),
        ],
        dependencies: vec![("ref-libalpha".to_string(), vec!["ref-libbeta".to_string()])],
        vulnerabilities: Vec::new(),
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

#[test]
fn cisa2026_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // No software component at all (no primary, no components): the
        // per-component rules have nothing to judge, which is a finding.
        RuleEntry::tested(
            "SBOM-CISA2026-INVENTORY",
            Sev::Error,
            broken(|s| {
                s.primary = None;
                s.components.clear();
                s.dependencies.clear();
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-AUTHOR",
            Sev::Error,
            // Tool creators remain: the 2026 element is deliberately
            // stricter than SBOM-NTIA-AUTHOR — a tool-only creator list
            // must fail.
            broken(|s| s.authors.clear()),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-CISA2026-SIGNATURE",
            "the fixture DSL cannot express a CycloneDX JSF signature, so every \
             DSL fixture fires this Warning and no DSL silent case exists; \
             firing and silent behaviour are covered by the raw-JSON tests \
             signature_missing_fires_warning / conforming document in this file",
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-FORMAT",
            Sev::Warning,
            // Tool-policy floor (CycloneDX 1.4+): 1.3 must warn.
            broken(|s| s.spec_version = "1.3".to_string()),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-CISA2026-GENERATION-CONTEXT",
            "the fixture DSL has no metadata.lifecycles hook, so every DSL \
             fixture fires this Warning and no DSL silent case exists; covered \
             by the raw-JSON tests generation_context_missing_fires_warning / \
             conforming document in this file",
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-TOOL",
            Sev::Error,
            // Authors stay, so AUTHOR remains silent and the missing tool
            // is isolated. TOOL-VERSION must stay silent too: with no tool
            // identified at all, only the TOOL rule reports the omission.
            broken(|s| s.tools.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-TOOL-VERSION",
            Sev::Warning,
            // A tool is named but carries no version-like token (the parser
            // concatenates name+version, so an empty version leaves a bare
            // name) and no explicit unknown marker.
            broken(|s| s.tools = vec![("acme-sbom-tool".to_string(), String::new())]),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-CISA2026-SBOM-VERSION",
            "the fixture DSL hardcodes the CycloneDX top-level version to 1, so \
             the parsed doc_version is always Some(1) and the rule can never \
             fire through the harness; firing/silent behaviour (omitted \
             bom.version with and without serialNumber) is covered by the \
             raw-JSON tests sbom_version_* in this file",
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-PRODUCER",
            Sev::Error,
            // No supplier and no author: silent absence of any producer
            // evidence (the DSL never emits component authors).
            broken(|s| s.component_mut("libalpha").supplier = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-NAME",
            Sev::Error,
            // "unknown" without a corroborating PURL name segment does not
            // count as a producer-assigned name (the PURL still satisfies
            // the IDENTIFIER element, isolating the NAME rule).
            broken(|s| s.component_mut("libalpha").name = "unknown".to_string()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-VERSION",
            Sev::Error,
            // Silent absence fails; NOASSERTION would pass (see the
            // component_version_noassertion_is_explicit_unknown test).
            broken(|s| s.component_mut("libalpha").version = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-IDENTIFIER",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").purl = None),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-HASH",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").hashes.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-HASH-ALGO",
            Sev::Warning,
            // The MD5 value is valid ASCII-hex, so HASH stays silent and
            // only the algorithm warning fires.
            broken(|s| {
                s.component_mut("libalpha").hashes =
                    vec![("MD5".to_string(), MD5_FILLER.to_string())];
            }),
            base(),
        )
        .with_firing(
            "sha1-deprecated",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").hashes =
                    vec![("SHA-1".to_string(), SHA1_FILLER.to_string())];
            }),
        )
        .with_firing(
            "unrecognized-algorithm",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").hashes =
                    vec![("WHIRLPOOL".to_string(), SHA1_FILLER.to_string())];
            }),
        )
        // Weak digests only, however many: no strong hash to fall back on.
        .with_firing(
            "md5-and-sha1-only",
            Sev::Warning,
            broken(|s| {
                s.component_mut("libalpha").hashes = vec![
                    ("MD5".to_string(), MD5_FILLER.to_string()),
                    ("SHA-1".to_string(), SHA1_FILLER.to_string()),
                ];
            }),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-LICENSE",
            Sev::Error,
            broken(|s| s.component_mut("libalpha").licenses.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-CISA2026-DEPENDENCY",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-CISA2026-COVERAGE",
            "the fixture DSL has no compositions hook, so every DSL fixture \
             fires this Warning (undeclared completeness) and no DSL silent \
             case exists; not-declared / declared-incomplete / declared-complete \
             behaviour is covered by the raw-JSON tests coverage_* in this file",
        ),
        RuleEntry::skipped(
            "SBOM-CISA2026-GENERAL",
            "registry catch-all for the CISA 2026 family: no check site in \
             check_cisa2026 emits it (registry.rs keeps it so the SARIF rule \
             catalogue mirrors the slice); it cannot fire from document content",
        ),
    ];

    run_matrix(LEVEL, CISA2026_SARIF_RULE_IDS, &entries);
}

// ---------------------------------------------------------------------------
// Raw-JSON cases for the elements the fixture DSL cannot express
// (signature, lifecycles, compositions, omitted top-level version), plus the
// escape-hatch and scoping semantics specific to the 2026 elements.
// ---------------------------------------------------------------------------

/// A fully conforming CycloneDX 1.6 document: JSF signature, lifecycle
/// phase, complete compositions declaration, bom.version, serial number,
/// Person author + versioned tool, and fully-populated components with a
/// connected dependency graph.
fn conforming_json() -> serde_json::Value {
    let component = |name: &str| {
        serde_json::json!({
            "type": "library",
            "bom-ref": format!("ref-{name}"),
            "name": name,
            "version": "1.2.3",
            "purl": format!("pkg:npm/{name}@1.2.3"),
            "supplier": { "name": "Acme Components Ltd" },
            "hashes": [{
                "alg": "SHA-256",
                "content": rule_matrix::SHA256_FILLER,
            }],
            "licenses": [{ "license": { "id": "MIT" } }],
        })
    };
    let mut primary = component("acme-app");
    primary["type"] = serde_json::json!("application");
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 2,
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "metadata": {
            "timestamp": "2026-07-29T12:00:00Z",
            "lifecycles": [{ "phase": "build" }],
            "tools": [{ "name": "acme-sbom-tool", "version": "1.0.0" }],
            "authors": [{ "name": "Dana Author", "email": "dana@acme.example" }],
            "component": primary,
        },
        "components": [component("libalpha"), component("libbeta")],
        "dependencies": [
            { "ref": "ref-acme-app", "dependsOn": ["ref-libalpha"] },
            { "ref": "ref-libalpha", "dependsOn": ["ref-libbeta"] },
        ],
        "compositions": [{ "aggregate": "complete" }],
        "signature": { "algorithm": "ES256", "value": "MEUCIQDx7q1FILLERSIGVALUE" },
    })
}

fn check_json(doc: &serde_json::Value) -> ComplianceResult {
    let json = doc.to_string();
    let sbom = parse_sbom_str(&json).unwrap_or_else(|e| panic!("fixture must parse: {e}\n{json}"));
    checker(LEVEL).check(&sbom)
}

/// Assert the rule fired at the given severity.
fn assert_fires(result: &ComplianceResult, id: &str, severity: Sev) {
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.sarif_rule_id() == id && v.severity == severity),
        "{id} must fire at {severity:?}; emitted:\n{}",
        render_violations(result)
    );
}

/// Assert the rule did not fire.
fn assert_silent(result: &ComplianceResult, id: &str) {
    assert!(
        result.violations.iter().all(|v| v.sarif_rule_id() != id),
        "{id} must stay silent; emitted:\n{}",
        render_violations(result)
    );
}

/// The conforming raw-JSON document must pass with a clean verdict — the
/// P4 requirement that a fixture exists for which `is_compliant` holds with
/// zero violations.
#[test]
fn cisa2026_conforming_document_is_compliant_with_zero_violations() {
    let result = check_json(&conforming_json());
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "conforming document must pass with zero violations; got \
         is_compliant={}:\n{}",
        result.is_compliant,
        render_violations(&result)
    );
}

#[test]
fn signature_missing_fires_warning() {
    let mut doc = conforming_json();
    doc.as_object_mut().unwrap().remove("signature");
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-SIGNATURE", Sev::Warning);
}

#[test]
fn signature_without_value_is_not_signature_evidence() {
    let mut doc = conforming_json();
    doc["signature"] = serde_json::json!({ "algorithm": "ES256" });
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-SIGNATURE", Sev::Warning);
}

#[test]
fn generation_context_missing_fires_warning() {
    let mut doc = conforming_json();
    doc["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("lifecycles");
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-GENERATION-CONTEXT", Sev::Warning);
}

#[test]
fn coverage_not_declared_fires_warning() {
    let mut doc = conforming_json();
    doc.as_object_mut().unwrap().remove("compositions");
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-COVERAGE", Sev::Warning);
}

#[test]
fn coverage_declared_incomplete_still_warns() {
    let mut doc = conforming_json();
    doc["compositions"] = serde_json::json!([{ "aggregate": "incomplete" }]);
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-COVERAGE", Sev::Warning);
}

#[test]
fn sbom_version_omitted_with_serial_number_is_silent() {
    let mut doc = conforming_json();
    doc.as_object_mut().unwrap().remove("version");
    let result = check_json(&doc);
    assert_silent(&result, "SBOM-CISA2026-SBOM-VERSION");
}

#[test]
fn sbom_version_omitted_without_serial_number_fires_warning() {
    let mut doc = conforming_json();
    doc.as_object_mut().unwrap().remove("version");
    doc.as_object_mut().unwrap().remove("serialNumber");
    let result = check_json(&doc);
    assert_fires(&result, "SBOM-CISA2026-SBOM-VERSION", Sev::Warning);
}

#[test]
fn sbom_version_present_without_serial_number_is_silent() {
    let mut doc = conforming_json();
    doc.as_object_mut().unwrap().remove("serialNumber");
    let result = check_json(&doc);
    assert_silent(&result, "SBOM-CISA2026-SBOM-VERSION");
}

/// NOASSERTION satisfies the Component Version escape hatch ("the SBOM
/// author should indicate the version is unknown") — deliberately unlike
/// SBOM-NTIA-VERSION, where the sentinel counts as missing.
#[test]
fn component_version_noassertion_is_explicit_unknown() {
    let fixture = broken(|s| {
        s.component_mut("libalpha").version = Some("NOASSERTION".to_string());
    });
    let result = check(LEVEL, &fixture);
    assert!(
        result
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() != "SBOM-CISA2026-VERSION"),
        "an explicit unknown marker must satisfy the version escape hatch; emitted:\n{}",
        render_violations(&result)
    );
}

/// A NOASSERTION supplier is an explicit unknown-provenance marker and
/// satisfies the Component Producer escape hatch.
#[test]
fn producer_noassertion_is_explicit_unknown_provenance() {
    let fixture = broken(|s| {
        s.component_mut("libalpha").supplier = Some("NOASSERTION".to_string());
    });
    let result = check(LEVEL, &fixture);
    assert!(
        result
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() != "SBOM-CISA2026-PRODUCER"),
        "an explicit unknown-provenance marker must satisfy the producer escape hatch; \
         emitted:\n{}",
        render_violations(&result)
    );
}

/// An Organization creator (CycloneDX metadata.manufacturer) satisfies the
/// SBOM Author element just like a Person author does.
#[test]
fn organization_only_creator_satisfies_author() {
    let fixture = broken(|s| {
        s.authors.clear();
        s.manufacturer = Some(("Acme Corp".to_string(), None));
    });
    let result = check(LEVEL, &fixture);
    assert!(
        result
            .violations
            .iter()
            .all(|v| v.sarif_rule_id() != "SBOM-CISA2026-AUTHOR"),
        "an Organization creator must satisfy the SBOM Author element; emitted:\n{}",
        render_violations(&result)
    );
}

/// File-type inventory entries are name+hash records, not packages: the
/// producer / version / identifier / hash / license elements do not apply
/// to them (same carve-out as the NTIA-path checks).
#[test]
fn file_components_are_exempt_from_package_elements() {
    let mut doc = conforming_json();
    doc["components"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "file",
            "bom-ref": "ref-config-file",
            "name": "config.yaml",
        }));
    // Keep the graph connected so DEPENDENCY stays out of the picture.
    doc["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "ref": "ref-libbeta", "dependsOn": ["ref-config-file"] }));
    let result = check_json(&doc);
    for id in [
        "SBOM-CISA2026-PRODUCER",
        "SBOM-CISA2026-VERSION",
        "SBOM-CISA2026-IDENTIFIER",
        "SBOM-CISA2026-HASH",
        "SBOM-CISA2026-LICENSE",
        "SBOM-CISA2026-NAME",
    ] {
        assert_silent(&result, id);
    }
}

// ---------------------------------------------------------------------------
// Review finding V14: weak digests beside a strong one, and SPDX 2.x, which
// has no field for a signature, a lifecycle phase or a completeness
// declaration. These tests pin the evaluation clock.
// ---------------------------------------------------------------------------

/// Filler SHA-512 digest (128 hex chars, the digest of empty input).
const SHA512_FILLER: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// A complete SPDX 2.3 SBOM from the regression corpus.
const SPDX2_COMPLETE: &str = "compliance/regressions/v14-spdx2-cisa2026-complete.spdx.json";

fn fixture_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn check_at_as_of(json: &str) -> ComplianceResult {
    let sbom = parse_sbom_str(json).unwrap_or_else(|e| panic!("fixture must parse: {e}\n{json}"));
    checker(LEVEL).check(&sbom)
}

fn check_fixture(rel: &str) -> ComplianceResult {
    let path = fixture_path(rel);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    check_at_as_of(&raw)
}

/// The cyclonedx-maven-plugin default lists MD5 and SHA-1 next to SHA-256
/// and SHA-512. The strong digests satisfy the element, so the conforming
/// document stays clean with that hash set on every component.
#[test]
fn weak_digests_beside_a_strong_one_do_not_warn() {
    let mut doc = conforming_json();
    let maven_default = serde_json::json!([
        { "alg": "MD5", "content": MD5_FILLER },
        { "alg": "SHA-1", "content": SHA1_FILLER },
        { "alg": "SHA-256", "content": rule_matrix::SHA256_FILLER },
        { "alg": "SHA-512", "content": SHA512_FILLER },
    ]);
    doc["metadata"]["component"]["hashes"] = maven_default.clone();
    for component in doc["components"].as_array_mut().unwrap() {
        component["hashes"] = maven_default.clone();
    }
    let result = check_at_as_of(&doc.to_string());
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "the Maven default hash set must pass cleanly; emitted:\n{}",
        render_violations(&result)
    );
}

/// A strong algorithm counts only with a real digest: next to an SHA-256
/// entry that declares its value unknown, MD5 is the only hash, and warns.
#[test]
fn a_strong_algorithm_without_a_digest_leaves_the_warning() {
    let mut doc = conforming_json();
    doc["components"][0]["hashes"] = serde_json::json!([
        { "alg": "MD5", "content": MD5_FILLER },
        { "alg": "SHA-256", "content": "NOASSERTION" },
    ]);
    let result = check_at_as_of(&doc.to_string());
    assert_fires(&result, "SBOM-CISA2026-HASH-ALGO", Sev::Warning);
    assert_silent(&result, "SBOM-CISA2026-HASH");
}

/// SPDX 2.x cannot express a signature, a lifecycle phase or a completeness
/// declaration, so a complete SPDX 2.3 SBOM passes with no findings at all.
#[test]
fn spdx2_is_not_asked_for_evidence_it_cannot_carry() {
    let result = check_fixture(SPDX2_COMPLETE);
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "a complete SPDX 2.3 SBOM must pass with zero findings; emitted:\n{}",
        render_violations(&result)
    );
}

/// The gate is SPDX 2.x only. SPDX 3 can carry all three, so a document
/// that omits them still warns.
#[test]
fn spdx3_without_the_evidence_still_warns() {
    let result = check_fixture("spdx3/minimal.spdx3.json");
    for id in [
        "SBOM-CISA2026-SIGNATURE",
        "SBOM-CISA2026-GENERATION-CONTEXT",
        "SBOM-CISA2026-COVERAGE",
    ] {
        assert_fires(&result, id, Sev::Warning);
    }
}

/// End to end: `validate --standard cisa-2026 --fail-on-warning` succeeds
/// on a complete SPDX 2.3 SBOM. It used to exit 2 on the three warnings no
/// SPDX 2.x document can clear.
#[test]
fn complete_spdx2_sbom_passes_validate_with_fail_on_warning() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .arg("--no-color")
        .arg("validate")
        .arg(fixture_path(SPDX2_COMPLETE))
        .args([
            "--standard",
            "cisa-2026",
            "--fail-on-warning",
            "--as-of",
            AS_OF,
        ])
        .env("RUST_LOG", "error")
        .output()
        .expect("validate command should run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
