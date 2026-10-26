//! Registry-driven per-rule matrix for `ComplianceLevel::Fsct` — the CISA
//! "Framing Software Component Transparency" (3rd ed., 2024)
//! attribute-maturity profile.
//!
//! Every rule id in `FSCT_SARIF_RULE_IDS` gets a firing fixture and a silent
//! fixture (real CycloneDX JSON through the real parser), or an explicit
//! skip-with-reason; exhaustiveness is enforced against the registry slice.
//! The tier→severity pinning (Minimum Expected → Error, Recommended Practice
//! → Warning, Aspirational Goal → Info) is asserted against the registry
//! defaults — no entry departs from them.
//!
//! The shared fixture DSL cannot express `metadata.lifecycles`, the JSF
//! `signature`, `compositions`, component `copyright`/`cpe`, or SPDX input.
//! Rules whose silent (or firing) state needs those fields are explicitly
//! skipped in the matrix with the dedicated raw-JSON / SPDX tag-value test
//! (below) that covers both states named in the reason.

#[path = "common/rule_matrix.rs"]
mod rule_matrix;

use rule_matrix::clock::checker;
use rule_matrix::{
    ComponentFixture, MD5_FILLER, RuleEntry, SHA256_FILLER, SbomFixture, run_matrix,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, FSCT_SARIF_RULE_IDS, ViolationSeverity as Sev,
};
use std::collections::BTreeMap;

const LEVEL: ComplianceLevel = ComplianceLevel::Fsct;

/// The DSL-expressible conforming core: person author with email, versioned
/// generation tool, timestamp, primary component wired to a depth-2
/// dependency chain, and components carrying version + PURL + supplier +
/// SHA-256 hash + license.
///
/// NOT fully conforming — the DSL cannot express copyright, a second
/// identifier kind, lifecycles, compositions, or a signature, so
/// `SBOM-FSCT-{COPYRIGHT-*,IDENTIFIER-MULTI,SBOM-TYPE,COMPLETENESS,
/// SIGNATURE}` fire on every DSL fixture (all inside the declared universe;
/// the fully conforming document lives in `conforming_doc()` below).
fn base() -> SbomFixture {
    let mut app = ComponentFixture::conforming("acme-app");
    app.licenses = vec!["Apache-2.0".to_string()];
    let mut liba = ComponentFixture::conforming("liba");
    liba.licenses = vec!["MIT".to_string()];
    let mut libb = ComponentFixture::conforming("libb");
    libb.licenses = vec!["MIT".to_string()];
    SbomFixture {
        spec_version: "1.6".to_string(),
        timestamp: Some("2026-01-15T10:00:00Z".to_string()),
        serial_number: Some("urn:uuid:11111111-2222-3333-4444-555555555555".to_string()),
        tools: vec![("acme-sbomgen".to_string(), "3.1.4".to_string())],
        authors: vec![(
            "Dana Producer".to_string(),
            Some("dana@acme.example".to_string()),
        )],
        manufacturer: None,
        primary: Some(app),
        components: vec![liba, libb],
        dependencies: vec![
            ("ref-acme-app".to_string(), vec!["ref-liba".to_string()]),
            ("ref-liba".to_string(), vec!["ref-libb".to_string()]),
        ],
        vulnerabilities: Vec::new(),
        ..SbomFixture::default()
    }
}

fn broken(mutate: impl FnOnce(&mut SbomFixture)) -> SbomFixture {
    let mut fixture = base();
    mutate(&mut fixture);
    fixture
}

/// No primary and no components at all: the per-component aggregates
/// (identifier multiplicity, copyright coverage) have nothing to count, so
/// they stay silent while staying inside the declared universe.
fn empty_inventory() -> SbomFixture {
    broken(|s| {
        s.primary = None;
        s.components.clear();
        s.dependencies.clear();
    })
}

/// Primary removed (components stay wired among themselves): the
/// primary-scoped checks have no subject and stay silent —
/// `SBOM-FSCT-PRIMARY` fires instead.
fn no_primary() -> SbomFixture {
    broken(|s| {
        s.primary = None;
        s.dependencies = vec![("ref-liba".to_string(), vec!["ref-libb".to_string()])];
    })
}

#[test]
fn fsct_rule_matrix_is_exhaustive_with_firing_and_silent_cases() {
    let entries = vec![
        // ── Minimum Expected (Error) + its Recommended companions, in
        //    registry-slice order ─────────────────────────────────────────
        RuleEntry::tested(
            "SBOM-FSCT-AUTHOR",
            Sev::Error,
            broken(|s| s.authors.clear()),
            base(),
        ),
        // §2.2.1.1 Recommended has two sites sharing the id: no tool at
        // all, and tools without a discernible version.
        RuleEntry::tested(
            "SBOM-FSCT-AUTHOR-TOOL",
            Sev::Warning,
            broken(|s| s.tools.clear()),
            base(),
        )
        .with_firing(
            "tool identified without a version",
            Sev::Warning,
            broken(|s| s.tools = vec![("acme-sbomgen".to_string(), String::new())]),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-TIMESTAMP",
            Sev::Error,
            broken(|s| s.timestamp = None),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-FSCT-SBOM-TYPE",
            "the DSL cannot express metadata.lifecycles, so the Info fires on \
             every DSL document and no silent case exists here; \
             fsct_sbom_type_fires_without_lifecycles_and_silences_with covers \
             both states through the real parser",
        ),
        RuleEntry::tested("SBOM-FSCT-PRIMARY", Sev::Error, no_primary(), base()),
        RuleEntry::tested(
            "SBOM-FSCT-DIRECT-DEPS",
            Sev::Error,
            broken(|s| s.dependencies.clear()),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-TRANSITIVE-DEPS",
            Sev::Warning,
            broken(|s| {
                s.dependencies = vec![("ref-acme-app".to_string(), vec!["ref-liba".to_string()])];
            }),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-FSCT-DYNAMIC-DEPS",
            "the positive signal (DYNAMIC_LINK / RUNTIME_DEPENDENCY_OF / \
             PROVIDED_DEPENDENCY_OF edges) is parsed only from SPDX \
             relationships, so the readiness note is evidence-gated to SPDX \
             input and the CycloneDX-only DSL cannot reach the firing state; \
             fsct_dynamic_deps_is_spdx_gated_with_firing_and_silent_states \
             covers both states with SPDX tag-value documents",
        ),
        RuleEntry::tested(
            "SBOM-FSCT-COMPONENT-NAME",
            Sev::Error,
            broken(|s| s.component_mut("liba").name = "NOASSERTION".to_string()),
            base(),
        ),
        // Silent case proves the §2.2.2.2 documented fallback: no version
        // but an author-provided hash passes.
        RuleEntry::tested(
            "SBOM-FSCT-VERSION",
            Sev::Error,
            broken(|s| {
                let liba = s.component_mut("liba");
                liba.version = None;
                liba.hashes.clear();
            }),
            broken(|s| s.component_mut("liba").version = None),
        ),
        // Silent case proves the §2.2.2.3 letter: an explicit 'unknown'
        // declaration satisfies (silent absence does not).
        RuleEntry::tested(
            "SBOM-FSCT-SUPPLIER",
            Sev::Error,
            broken(|s| s.component_mut("liba").supplier = None),
            broken(|s| s.component_mut("liba").supplier = Some("unknown".to_string())),
        ),
        // Silent case proves the hash-as-intrinsic-identifier acceptance.
        RuleEntry::tested(
            "SBOM-FSCT-IDENTIFIER",
            Sev::Error,
            broken(|s| {
                let liba = s.component_mut("liba");
                liba.purl = None;
                liba.hashes.clear();
            }),
            broken(|s| s.component_mut("liba").purl = None),
        ),
        // Every DSL component is PURL-only (< 2 identifier kinds), so the
        // base fixture fires; the silent state needs a second kind (cpe) —
        // covered by the conforming raw-JSON document — or an empty
        // inventory, used here.
        RuleEntry::tested(
            "SBOM-FSCT-IDENTIFIER-MULTI",
            Sev::Warning,
            base(),
            empty_inventory(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-HASH",
            Sev::Error,
            broken(|s| s.component_mut("liba").hashes.clear()),
            base(),
        ),
        // §2.2.2.5 Recommended has two sites sharing the id: hashless
        // primary, and components hashed only below SHA-256/SHA-2.
        RuleEntry::tested(
            "SBOM-FSCT-HASH-PRIMARY-SHA2",
            Sev::Warning,
            broken(|s| {
                s.primary
                    .as_mut()
                    .expect("base fixture has a primary")
                    .hashes
                    .clear();
            }),
            base(),
        )
        .with_firing(
            "weak-only (MD5) hashes",
            Sev::Warning,
            broken(|s| {
                s.component_mut("liba").hashes = vec![("MD5".to_string(), MD5_FILLER.to_string())];
            }),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-RELATIONSHIP",
            Sev::Error,
            broken(|s| {
                s.dependencies = vec![("ref-liba".to_string(), vec!["ref-libb".to_string()])];
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-RELATIONSHIP-ALL",
            Sev::Warning,
            broken(|s| {
                let mut stray = ComponentFixture::conforming("stray");
                stray.licenses = vec!["MIT".to_string()];
                s.components.push(stray);
            }),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-FSCT-COMPLETENESS",
            "the DSL cannot express compositions.aggregate, so the Warning \
             fires on every DSL document and no silent case exists here; \
             fsct_completeness_fires_without_compositions_and_silences_with \
             covers both states through the real parser",
        ),
        RuleEntry::tested(
            "SBOM-FSCT-LICENSE-PRIMARY",
            Sev::Error,
            broken(|s| {
                s.primary
                    .as_mut()
                    .expect("base fixture has a primary")
                    .licenses
                    .clear();
            }),
            base(),
        ),
        // 1/3 licensed (33%) is below the 50% profile-policy floor; the
        // LICENSE-ALL Info firing below stays above it (2/3) so the two
        // tiers separate cleanly.
        RuleEntry::tested(
            "SBOM-FSCT-LICENSE-COVERAGE",
            Sev::Warning,
            broken(|s| {
                s.component_mut("liba").licenses.clear();
                s.component_mut("libb").licenses.clear();
            }),
            base(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-LICENSE-ALL",
            Sev::Info,
            broken(|s| s.component_mut("liba").licenses.clear()),
            base(),
        ),
        // The DSL cannot express component copyright, so the base fixture
        // fires; the silent states need copyright (conforming raw-JSON
        // document), no primary, or an empty inventory.
        RuleEntry::tested(
            "SBOM-FSCT-COPYRIGHT-PRIMARY",
            Sev::Error,
            base(),
            no_primary(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-COPYRIGHT-COVERAGE",
            Sev::Warning,
            base(),
            empty_inventory(),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-COPYRIGHT-ALL",
            Sev::Info,
            base(),
            empty_inventory(),
        ),
        // Ambiguous placeholders fire §2.3.1 while the per-attribute rules
        // stay silent (the attribute counts as populated for their letter).
        RuleEntry::tested(
            "SBOM-FSCT-NOASSERTION",
            Sev::Error,
            broken(|s| s.component_mut("liba").supplier = Some("TBD".to_string())),
            base(),
        )
        .with_firing(
            "ambiguous version placeholder",
            Sev::Error,
            broken(|s| s.component_mut("liba").version = Some("N/A".to_string())),
        ),
        RuleEntry::tested(
            "SBOM-FSCT-UPSTREAM-SBOM",
            Sev::Warning,
            broken(|s| {
                s.dependencies = vec![(
                    "ref-acme-app".to_string(),
                    vec!["ref-liba".to_string(), "ref-libb".to_string()],
                )];
            }),
            base(),
        ),
        RuleEntry::skipped(
            "SBOM-FSCT-SIGNATURE",
            "the DSL cannot express the top-level JSF signature, so the Info \
             fires on every DSL document and no silent case exists here; \
             fsct_signature_fires_without_signature_and_silences_with covers \
             both states through the real parser",
        ),
        RuleEntry::skipped(
            "SBOM-FSCT-GENERAL",
            "registry catch-all for the FSCT family: no check site in \
             check_fsct emits it (registry.rs keeps it so the SARIF rule \
             catalogue mirrors the slice); it cannot fire from document \
             content",
        ),
    ];

    run_matrix(LEVEL, FSCT_SARIF_RULE_IDS, &entries);
}

// ════════════════════════════════════════════════════════════════════════
// Raw-JSON fixtures beyond the DSL: the fully conforming document (all
// three tiers satisfied) and the minimum-only document (Minimum tier
// satisfied, every reachable Recommended/Aspirational rule firing).
// ════════════════════════════════════════════════════════════════════════

/// A CycloneDX 1.6 component that satisfies all three FSCT tiers: name,
/// version, PURL + CPE (two identifier kinds), supplier, SHA-256 hash,
/// license, and copyright.
fn conforming_component(name: &str, license: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "library",
        "bom-ref": format!("ref-{name}"),
        "name": name,
        "version": "1.2.3",
        "purl": format!("pkg:npm/{name}@1.2.3"),
        "cpe": format!("cpe:2.3:a:acme:{name}:1.2.3:*:*:*:*:*:*:*"),
        "supplier": { "name": "Acme Components Ltd" },
        "copyright": "Copyright (c) 2026 Acme Components Ltd",
        "hashes": [{ "alg": "SHA-256", "content": SHA256_FILLER }],
        "licenses": [{ "license": { "id": license } }],
    })
}

/// A CycloneDX 1.6 document that satisfies all three maturity tiers:
/// person author + versioned tool, timestamp, lifecycle (SBOM Type),
/// signature, completeness declaration, a primary wired to a depth-2
/// dependency chain, and fully attributed components (two identifier
/// kinds, SHA-256 hashes, licenses, copyright).
fn conforming_doc() -> serde_json::Value {
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "metadata": {
            "timestamp": "2026-01-15T10:00:00Z",
            "lifecycles": [{ "phase": "build" }],
            "tools": [{ "name": "acme-sbomgen", "version": "3.1.4" }],
            "authors": [{ "name": "Dana Producer", "email": "dana@acme.example" }],
            "component": conforming_component("acme-app", "Apache-2.0"),
        },
        "components": [
            conforming_component("liba", "MIT"),
            conforming_component("libb", "MIT"),
        ],
        "dependencies": [
            { "ref": "ref-acme-app", "dependsOn": ["ref-liba"] },
            { "ref": "ref-liba", "dependsOn": ["ref-libb"] },
            { "ref": "ref-libb", "dependsOn": [] },
        ],
        "compositions": [{ "aggregate": "complete" }],
        "signature": { "algorithm": "ES256", "value": "c2lnbmF0dXJlLXZhbHVl" },
    })
}

fn check_doc(doc: &serde_json::Value) -> ComplianceResult {
    let json = serde_json::to_string_pretty(doc).expect("fixture JSON must serialize");
    let sbom = parse_sbom_str(&json)
        .unwrap_or_else(|e| panic!("fixture must parse as CycloneDX: {e}\n{json}"));
    checker(LEVEL).check(&sbom)
}

fn render(result: &ComplianceResult) -> String {
    result
        .violations
        .iter()
        .map(|v| {
            format!(
                "  [{}] {} : {}",
                v.severity.name(),
                v.sarif_rule_id(),
                v.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The fully conforming CycloneDX document passes all three tiers with zero
/// violations of any severity — a checker that always errored (or an
/// aspirational rule firing on satisfied evidence) would fail here.
#[test]
fn fsct_fully_conforming_fixture_is_compliant_with_zero_violations() {
    let result = check_doc(&conforming_doc());
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "[Fsct] fully conforming fixture must pass with zero violations; got \
         is_compliant={}:\n{}",
        result.is_compliant,
        render(&result)
    );
}

/// A document satisfying ONLY the Minimum Expected tier: person author but
/// no tool, PURL-only identifiers, MD5-only hashes, licenses/copyright on
/// the primary only, a single-level dependency graph with an orphan, no
/// lifecycle/compositions/signature.
fn minimum_only_doc() -> serde_json::Value {
    // Weakened component: PURL only (one identifier kind), MD5 hash only
    // (satisfies the Minimum hash tier), no license, no copyright.
    let weak = |name: &str| {
        serde_json::json!({
            "type": "library",
            "bom-ref": format!("ref-{name}"),
            "name": name,
            "version": "1.2.3",
            "purl": format!("pkg:npm/{name}@1.2.3"),
            "supplier": { "name": "Acme Components Ltd" },
            "hashes": [{ "alg": "MD5", "content": MD5_FILLER }],
        })
    };
    let mut primary = weak("acme-app");
    primary["licenses"] = serde_json::json!([{ "license": { "id": "Apache-2.0" } }]);
    primary["copyright"] = serde_json::json!("Copyright (c) 2026 Acme Components Ltd");
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "metadata": {
            "timestamp": "2026-01-15T10:00:00Z",
            "authors": [{ "name": "Dana Producer", "email": "dana@acme.example" }],
            "component": primary,
        },
        // depa: direct dependency, no nested data; orphanb: in no edge.
        "components": [weak("depa"), weak("orphanb")],
        "dependencies": [
            { "ref": "ref-acme-app", "dependsOn": ["ref-depa"] },
        ],
    })
}

/// The minimum-only document fires EXACTLY the Recommended-tier rules as
/// Warning and the reachable Aspirational-tier rules as Info — no
/// Minimum-tier Error and nothing outside the expected set.
///
/// `SBOM-FSCT-DYNAMIC-DEPS` is the one Aspirational rule absent from the
/// expected set: its positive signal exists only in SPDX input, so the
/// readiness note is evidence-gated off CycloneDX documents (see
/// `fsct_dynamic_deps_is_spdx_gated_with_firing_and_silent_states`).
#[test]
fn fsct_minimum_only_fixture_fires_exactly_recommended_and_aspirational_rules() {
    let result = check_doc(&minimum_only_doc());

    let expected: BTreeMap<&str, Sev> = [
        ("SBOM-FSCT-AUTHOR-TOOL", Sev::Warning),
        ("SBOM-FSCT-TRANSITIVE-DEPS", Sev::Warning),
        ("SBOM-FSCT-IDENTIFIER-MULTI", Sev::Warning),
        ("SBOM-FSCT-HASH-PRIMARY-SHA2", Sev::Warning),
        ("SBOM-FSCT-RELATIONSHIP-ALL", Sev::Warning),
        ("SBOM-FSCT-COMPLETENESS", Sev::Warning),
        ("SBOM-FSCT-LICENSE-COVERAGE", Sev::Warning),
        ("SBOM-FSCT-COPYRIGHT-COVERAGE", Sev::Warning),
        ("SBOM-FSCT-UPSTREAM-SBOM", Sev::Warning),
        ("SBOM-FSCT-SBOM-TYPE", Sev::Info),
        ("SBOM-FSCT-LICENSE-ALL", Sev::Info),
        ("SBOM-FSCT-COPYRIGHT-ALL", Sev::Info),
        ("SBOM-FSCT-SIGNATURE", Sev::Info),
    ]
    .into_iter()
    .collect();

    let mut fired: BTreeMap<&str, Sev> = BTreeMap::new();
    for v in &result.violations {
        let id = v.sarif_rule_id();
        if let Some(prev) = fired.insert(id, v.severity) {
            assert_eq!(
                prev,
                v.severity,
                "[Fsct] {id} fired at two different severities:\n{}",
                render(&result)
            );
        }
    }

    assert_eq!(
        fired,
        expected,
        "[Fsct] minimum-only fixture must fire exactly the Recommended rules \
         as Warning and the reachable Aspirational rules as Info \
         (left = fired, right = expected); emitted:\n{}",
        render(&result)
    );
    // The tier mapping stays honest: the fixture satisfies the Minimum
    // Expected tier, so it must remain compliant (Errors gate compliance).
    assert!(
        result.is_compliant && result.error_count == 0,
        "[Fsct] minimum-only fixture must carry no Error and stay compliant:\n{}",
        render(&result)
    );
}

// ════════════════════════════════════════════════════════════════════════
// Dedicated firing/silent pairs for the rules the fixture DSL cannot
// reach (each named in its matrix skip-with-reason entry above).
// ════════════════════════════════════════════════════════════════════════

fn fired_severities(result: &ComplianceResult, id: &str) -> Vec<Sev> {
    result
        .violations
        .iter()
        .filter(|v| v.sarif_rule_id() == id)
        .map(|v| v.severity)
        .collect()
}

#[test]
fn fsct_sbom_type_fires_without_lifecycles_and_silences_with() {
    let mut firing = conforming_doc();
    firing["metadata"]
        .as_object_mut()
        .expect("metadata is an object")
        .remove("lifecycles");
    let result = check_doc(&firing);
    assert_eq!(
        fired_severities(&result, "SBOM-FSCT-SBOM-TYPE"),
        vec![Sev::Info],
        "[Fsct] removing metadata.lifecycles must fire SBOM-FSCT-SBOM-TYPE as \
         Info:\n{}",
        render(&result)
    );

    let silent = check_doc(&conforming_doc());
    assert!(
        fired_severities(&silent, "SBOM-FSCT-SBOM-TYPE").is_empty(),
        "[Fsct] a declared lifecycle must silence SBOM-FSCT-SBOM-TYPE:\n{}",
        render(&silent)
    );
}

#[test]
fn fsct_signature_fires_without_signature_and_silences_with() {
    let mut firing = conforming_doc();
    firing
        .as_object_mut()
        .expect("document is an object")
        .remove("signature");
    let result = check_doc(&firing);
    assert_eq!(
        fired_severities(&result, "SBOM-FSCT-SIGNATURE"),
        vec![Sev::Info],
        "[Fsct] removing the JSF signature must fire SBOM-FSCT-SIGNATURE as \
         Info:\n{}",
        render(&result)
    );

    let silent = check_doc(&conforming_doc());
    assert!(
        fired_severities(&silent, "SBOM-FSCT-SIGNATURE").is_empty(),
        "[Fsct] a structurally valid signature must silence \
         SBOM-FSCT-SIGNATURE:\n{}",
        render(&silent)
    );
}

#[test]
fn fsct_completeness_fires_without_compositions_and_silences_with() {
    let mut firing = conforming_doc();
    firing
        .as_object_mut()
        .expect("document is an object")
        .remove("compositions");
    let result = check_doc(&firing);
    assert_eq!(
        fired_severities(&result, "SBOM-FSCT-COMPLETENESS"),
        vec![Sev::Warning],
        "[Fsct] removing compositions must fire SBOM-FSCT-COMPLETENESS as \
         Warning:\n{}",
        render(&result)
    );

    let silent = check_doc(&conforming_doc());
    assert!(
        fired_severities(&silent, "SBOM-FSCT-COMPLETENESS").is_empty(),
        "[Fsct] a declared completeness aggregate must silence \
         SBOM-FSCT-COMPLETENESS:\n{}",
        render(&silent)
    );
}

/// SPDX tag-value document (the only format whose parsed model can carry
/// the dynamic-link positive signal).
const SPDX_TAG_VALUE_BASE: &str = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: fsct-dynamic-deps
DocumentNamespace: https://acme.example/spdxdocs/fsct-dynamic-deps
Creator: Person: Dana Producer (dana@acme.example)
Creator: Tool: acme-sbomgen-3.1.4
Created: 2026-01-15T10:00:00Z

PackageName: acme-app
SPDXID: SPDXRef-app
PackageVersion: 1.0.0
PackageSupplier: Organization: Acme Components Ltd
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
PackageCopyrightText: Copyright (c) 2026 Acme Components Ltd

PackageName: liba
SPDXID: SPDXRef-liba
PackageVersion: 2.0.0
PackageSupplier: Organization: Acme Components Ltd
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: Copyright (c) 2026 Acme Components Ltd

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-app
Relationship: SPDXRef-app DEPENDS_ON SPDXRef-liba
";

fn check_str(content: &str) -> ComplianceResult {
    let sbom = parse_sbom_str(content)
        .unwrap_or_else(|e| panic!("fixture must parse as SPDX tag-value: {e}"));
    checker(LEVEL).check(&sbom)
}

#[test]
fn fsct_dynamic_deps_is_spdx_gated_with_firing_and_silent_states() {
    // SPDX without any dynamic/runtime/provided relationship: the
    // aspirational readiness note fires as Info.
    let firing = check_str(SPDX_TAG_VALUE_BASE);
    assert_eq!(
        fired_severities(&firing, "SBOM-FSCT-DYNAMIC-DEPS"),
        vec![Sev::Info],
        "[Fsct] SPDX without dynamic-link relationships must fire \
         SBOM-FSCT-DYNAMIC-DEPS as Info:\n{}",
        render(&firing)
    );

    // A DYNAMIC_LINK relationship is the positive signal.
    let with_dynamic =
        format!("{SPDX_TAG_VALUE_BASE}Relationship: SPDXRef-app DYNAMIC_LINK SPDXRef-liba\n");
    let silent = check_str(&with_dynamic);
    assert!(
        fired_severities(&silent, "SBOM-FSCT-DYNAMIC-DEPS").is_empty(),
        "[Fsct] a DYNAMIC_LINK relationship must silence \
         SBOM-FSCT-DYNAMIC-DEPS:\n{}",
        render(&silent)
    );

    // CycloneDX input never fires the note — the evidence path does not
    // exist in its parsed model (the fully conforming CycloneDX document is
    // already asserted to be violation-free above).
    let cyclonedx = check_doc(&conforming_doc());
    assert!(
        fired_severities(&cyclonedx, "SBOM-FSCT-DYNAMIC-DEPS").is_empty(),
        "[Fsct] CycloneDX input must never fire SBOM-FSCT-DYNAMIC-DEPS:\n{}",
        render(&cyclonedx)
    );
}
