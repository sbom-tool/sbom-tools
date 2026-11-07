//! Tests of the evidence layer: each fact group on a constructed SBOM, the
//! agreement of every fact with the predicates it replaces on every SBOM
//! fixture, and that the facts do not depend on when or on which thread a
//! group is derived.

use std::path::{Path, PathBuf};

use super::super::cisa2026::{hash_algorithm_shortfall, tool_name_carries_version};
use super::super::shared::{
    ValueState, creator_identified, document_signed, has_known_license, has_known_producer,
    has_known_value, is_declared_unknown, is_spdx2, justified_not_affected, known_component_name,
    known_contact, known_value, license_state, manufacturer_identified, manufacturer_reference,
    observed, observed_producer, plausible_digest, unreachable_contact, value_state,
};
use super::{ComponentView, Known, SbomEvidence, Text};
use crate::model::{
    Component, ComponentType, Creator, CreatorType, DependencyEdge, DependencyScope,
    DependencyType, ExternalRefType, ExternalReference, Hash, HashAlgorithm, HashProvenance,
    LicenseExpression, NormalizedSbom, Organization, Property, SbomFormat, SignatureInfo,
    VexJustification, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource,
};

/// The package rules of a context over `sbom`'s evidence, against the
/// checker's own, for both excluded-scope settings: the components they
/// judge, in order, their count, and the inventory-absent finding.
fn assert_context_package_rules_agree(sbom: &NormalizedSbom, at: &str) {
    use super::super::context::ComplianceContext;
    use super::super::{ComplianceChecker, ComplianceLevel};
    let ev = SbomEvidence::new(sbom, as_of());
    for include in [false, true] {
        let checker = ComplianceChecker::new(ComplianceLevel::NtiaMinimum)
            .with_as_of(as_of())
            .with_include_excluded_scope(include);
        let ctx = ComplianceContext::new(&checker, &ev);
        let judged: Vec<_> = ctx
            .package_components()
            .map(|c| c.canonical_id().clone())
            .collect();
        let expected: Vec<_> = checker
            .package_components(sbom)
            .map(|c| c.canonical_id.clone())
            .collect();
        assert_eq!(judged, expected, "{at} (include: {include})");
        assert_eq!(ctx.package_count(), expected.len(), "{at}");
        for c in ev.components() {
            assert_eq!(
                ctx.leaves_out(&c),
                checker.leaves_out(sbom, &sbom.components[c.canonical_id()]),
                "{at}"
            );
        }
        let rule = "SBOM-NTIA-INVENTORY";
        assert_eq!(
            ctx.inventory_absent_violation(rule, "inventory")
                .map(|v| format!("{v:?}")),
            checker
                .inventory_absent_violation(sbom, rule, "inventory")
                .map(|v| format!("{v:?}")),
            "{at} (include: {include})"
        );
    }
}

/// The pinned evaluation instant (tests/common/clock.rs).
fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

fn component(name: &str) -> Component {
    Component::new(name.to_string(), format!("ref-{name}"))
}

fn sbom_of(components: Vec<Component>) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    for c in components {
        sbom.add_component(c);
    }
    sbom
}

fn edge(from: &Component, to: &Component) -> DependencyEdge {
    DependencyEdge::new(
        from.canonical_id.clone(),
        to.canonical_id.clone(),
        DependencyType::DependsOn,
    )
}

fn view<'e, 'a>(ev: &'e SbomEvidence<'a>, name: &str) -> ComponentView<'e, 'a> {
    ev.components()
        .find(|c| c.name() == name)
        .expect("the component is in the inventory")
}

// ----------------------------------------------------------------------------
// Fact groups on constructed SBOMs
// ----------------------------------------------------------------------------

#[test]
fn text_keeps_the_raw_value_and_classifies_it() {
    assert_eq!(
        Text::of(Some(" 1.0 ")),
        Text {
            raw: Some(" 1.0 "),
            value: Known::Value("1.0")
        }
    );
    assert_eq!(Text::of(Some("NOASSERTION")).value, Known::DeclaredUnknown);
    assert_eq!(Text::of(Some("TBD")).value, Known::Missing);
    assert_eq!(Text::of(Some("  ")).value, Known::Missing);
    assert_eq!(Text::of(None).value, Known::Missing);
    assert!(Text::of(Some("1.0")).is_known());
    assert!(!Text::of(Some("unknown")).is_known());
}

#[test]
fn version_column_reads_each_component_once_in_order() {
    let mut a = component("a");
    a.version = Some("1.0".to_string());
    let mut b = component("b");
    b.version = Some("TBD".to_string());
    let c = component("c");
    let sbom = sbom_of(vec![a, b, c]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let versions: Vec<_> = ev.components().map(|c| c.version()).collect();
    assert_eq!(versions[0].value, Known::Value("1.0"));
    assert_eq!(versions[1].raw, Some("TBD"));
    assert_eq!(versions[1].value, Known::Missing);
    assert_eq!(versions[2].raw, None);
}

#[test]
fn producer_is_the_best_of_three_fields_and_quotes_the_first() {
    let org = |name: &str| Some(Organization::new(name.to_string()));
    // A placeholder supplier does not hide a real manufacturer.
    let mut placeholder_then_real = component("p");
    placeholder_then_real.supplier = org("TBD");
    placeholder_then_real.manufacturer = org("Acme");
    // An explicit sentinel is declared unknown, not missing.
    let mut sentinel = component("s");
    sentinel.author = Some("NOASSERTION".to_string());
    let nobody = component("n");
    let sbom = sbom_of(vec![placeholder_then_real, sentinel, nobody]);
    let ev = SbomEvidence::new(&sbom, as_of());

    let p = view(&ev, "p").producer();
    assert!(p.is_known());
    assert_eq!(p.observed, Some("TBD"));
    let s = view(&ev, "s").producer();
    assert_eq!(s.state, ValueState::DeclaredUnknown);
    assert_eq!(s.observed, Some("NOASSERTION"));
    let n = view(&ev, "n").producer();
    assert_eq!(n.state, ValueState::Missing);
    assert_eq!(n.observed, None);
}

#[test]
fn licence_state_is_the_best_of_declared_and_concluded() {
    let mut known = component("k");
    known
        .licenses
        .add_declared(LicenseExpression::new("NOASSERTION".to_string()));
    known.licenses.concluded = Some(LicenseExpression::new("MIT".to_string()));
    let mut sentinel = component("s");
    sentinel
        .licenses
        .add_declared(LicenseExpression::new("NONE".to_string()));
    let none = component("n");
    let sbom = sbom_of(vec![known, sentinel, none]);
    let ev = SbomEvidence::new(&sbom, as_of());
    assert!(view(&ev, "k").licenses().is_known());
    assert_eq!(view(&ev, "s").licenses().state, ValueState::DeclaredUnknown);
    assert_eq!(view(&ev, "n").licenses().state, ValueState::Missing);
}

#[test]
fn only_plausible_digests_count_and_strength_reads_them_only() {
    let with = |name: &str, hashes: Vec<Hash>| {
        let mut c = component(name);
        c.hashes = hashes;
        c
    };
    let sha256 = "a".repeat(64);
    let sbom = sbom_of(vec![
        with("none", vec![]),
        with(
            "empty",
            vec![Hash::new(HashAlgorithm::Sha256, String::new())],
        ),
        with("md5", vec![Hash::new(HashAlgorithm::Md5, "b".repeat(32))]),
        with(
            "bad-strong-good-weak",
            vec![
                Hash::new(HashAlgorithm::Sha256, "zz".to_string()),
                Hash::new(HashAlgorithm::Sha1, "c".repeat(40)),
            ],
        ),
        with("sha256", vec![Hash::new(HashAlgorithm::Sha256, sha256)]),
        with(
            "streebog",
            vec![Hash::new(HashAlgorithm::Streebog512, "d".repeat(128))],
        ),
    ]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let facts = |name| view(&ev, name).hashes().facts;
    assert!(!facts("none").plausible);
    assert!(!facts("empty").plausible);
    assert!(facts("md5").plausible && !facts("md5").plausible_strong);
    assert!(facts("bad-strong-good-weak").plausible);
    assert!(!facts("bad-strong-good-weak").plausible_strong);
    assert!(facts("sha256").plausible_strong);
    assert!(facts("streebog").plausible_strong);
    assert_eq!(view(&ev, "empty").hashes().raw.len(), 1);
}

#[test]
fn package_scope_and_excluded_scope_spare_the_primary() {
    let mut file = component("file");
    file.component_type = ComponentType::File;
    let mut crypto = component("crypto");
    crypto.component_type = ComponentType::Cryptographic;
    let mut test_dep = component("test-dep");
    test_dep.scope = Some(DependencyScope::Excluded);
    let mut product = component("product");
    product.scope = Some(DependencyScope::Excluded);
    let product_id = product.canonical_id.clone();
    let lib = component("lib");
    let mut sbom = sbom_of(vec![file, crypto, test_dep, product, lib]);
    sbom.primary_component_id = Some(product_id);
    let ev = SbomEvidence::new(&sbom, as_of());

    assert!(!view(&ev, "file").package_scoped());
    assert!(!view(&ev, "crypto").package_scoped());
    assert!(view(&ev, "test-dep").excluded_scope());
    assert!(!view(&ev, "product").excluded_scope());
    assert!(!view(&ev, "lib").excluded_scope());
    assert_eq!(ev.package_count(false), 2);
    assert_eq!(ev.package_count(true), 3);
}

#[test]
fn identifier_kinds_are_presence_only() {
    let mut purl = component("purl");
    purl.identifiers.purl = Some("pkg:npm/purl@1.0.0".to_string());
    let mut cpe = component("cpe");
    cpe.identifiers
        .cpe
        .push("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*".to_string());
    let sbom = sbom_of(vec![purl, cpe, component("none")]);
    let ev = SbomEvidence::new(&sbom, as_of());
    assert!(view(&ev, "purl").ids().purl && view(&ev, "purl").ids().any());
    assert!(view(&ev, "cpe").ids().cpe && !view(&ev, "cpe").ids().purl);
    assert!(!view(&ev, "none").ids().any());
}

#[test]
fn graph_facts_follow_the_inventory_and_ignore_unknown_ids() {
    let app = component("app");
    let lib = component("lib");
    let mut leaf = component("leaf");
    leaf.extensions.properties.push(Property {
        name: crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY.to_string(),
        value: "true".to_string(),
    });
    let lone = component("lone");
    let ghost = component("ghost");
    let mut sbom = sbom_of(vec![app.clone(), lib.clone(), leaf.clone(), lone]);
    sbom.add_edge(edge(&app, &lib));
    sbom.add_edge(edge(&lib, &ghost));
    sbom.add_edge(edge(&lib, &lib));
    let ev = SbomEvidence::new(&sbom, as_of());

    assert!(ev.has_edges());
    assert!(view(&ev, "app").touched() && view(&ev, "lib").touched());
    assert!(!view(&ev, "leaf").touched() && !view(&ev, "lone").touched());
    assert!(view(&ev, "leaf").declares_no_dependencies());
    assert!(!view(&ev, "app").declares_no_dependencies());
    // app, leaf and lone have no incoming edge; lib points at itself.
    assert_eq!(ev.graph().root_count, 3);
    assert_eq!(ev.cycle_count(), 1);
}

#[test]
fn lifecycle_properties_match_by_token_and_need_a_value() {
    let with = |name: &str, property: &str, value: &str| {
        let mut c = component(name);
        c.extensions.properties.push(Property {
            name: property.to_string(),
            value: value.to_string(),
        });
        c
    };
    let lifecycle = |c: Component| {
        let sbom = sbom_of(vec![c]);
        SbomEvidence::new(&sbom, as_of()).has_lifecycle_property()
    };
    assert!(lifecycle(with("a", "cdx:eol", "2027-01-01")));
    assert!(lifecycle(with("b", "End-Of-Support", "2027")));
    assert!(!lifecycle(with("c", "geolocation", "berlin")));
    assert!(!lifecycle(with("d", "lifecycle", "TBD")));
}

#[test]
fn vulnerabilities_keep_inventory_order_and_the_vex_justification() {
    let vuln = |id: &str, justified: bool| {
        let mut v = VulnerabilityRef::new(id.to_string(), VulnerabilitySource::Osv);
        if justified {
            let mut vex = VexStatus::new(VexState::NotAffected);
            vex.justification = Some(VexJustification::VulnerableCodeNotPresent);
            v.vex_status = Some(vex);
        }
        v
    };
    let mut a = component("a");
    a.vulnerabilities = vec![vuln("CVE-1", false), vuln("CVE-2", true)];
    let b = component("b");
    let mut c = component("c");
    c.vulnerabilities = vec![vuln("CVE-3", false)];
    let sbom = sbom_of(vec![a, b, c]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let seen: Vec<_> = ev
        .vulnerabilities()
        .iter()
        .map(|f| {
            (
                ev.component(f.component).name(),
                f.vuln.id.as_str(),
                f.justified_not_affected,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("a", "CVE-1", false),
            ("a", "CVE-2", true),
            ("c", "CVE-3", false)
        ]
    );
}

#[test]
fn duplicates_are_listed_in_inventory_order() {
    let mut first = component("dup");
    first.version = Some("1.0".to_string());
    let mut again = first.clone();
    again.identifiers.format_id = "ref-dup-again".to_string();
    let sbom = sbom_of(vec![component("other"), first, again]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let listed: Vec<_> = ev.duplicates().iter().map(|d| d.entries).collect();
    assert_eq!(listed, [2]);
    let clean = sbom_of(vec![component("x")]);
    assert!(SbomEvidence::new(&clean, as_of()).duplicates().is_empty());
}

#[test]
fn document_facts_keep_the_declared_and_the_resolved_primary_apart() {
    let lib = component("lib");
    let mut sbom = sbom_of(vec![lib.clone()]);
    sbom.primary_component_id = Some(component("missing").canonical_id);
    sbom.document.name = Some("NOASSERTION".to_string());
    sbom.document.creators = vec![
        Creator {
            creator_type: CreatorType::Organization,
            name: "Acme".to_string(),
            email: Some("not-an-email".to_string()),
        },
        Creator {
            creator_type: CreatorType::Tool,
            name: "syft 1.0".to_string(),
            email: None,
        },
    ];
    sbom.document.security_contact = Some("security@example.com".to_string());
    sbom.document.vulnerability_disclosure_url = Some("https://acme.test/psirt".to_string());
    let ev = SbomEvidence::new(&sbom, as_of());
    let doc = ev.document();

    assert!(doc.primary_declared.is_some());
    assert!(doc.primary.is_none() && ev.primary().is_none());
    assert_eq!(doc.name.value, Known::DeclaredUnknown);
    assert_eq!(doc.creators.len(), 2);
    assert_eq!(doc.creators[0].email_well_formed, Some(false));
    assert_eq!(doc.creators[1].email_well_formed, None);
    assert!(!doc.security_contact_reaches);
    assert!(doc.vulnerability_disclosure_url_reaches);

    sbom.primary_component_id = Some(lib.canonical_id);
    let ev = SbomEvidence::new(&sbom, as_of());
    assert_eq!(ev.primary().map(|p| p.name()), Some("lib"));
}

#[test]
fn manufacturer_references_count_on_the_described_product_only() {
    let reference = |ref_type| ExternalReference {
        ref_type,
        url: "https://acme.test/security".to_string(),
        comment: None,
        hashes: Vec::new(),
    };
    let product = component("product");
    let mut dependency = component("dependency");
    dependency
        .external_refs
        .push(reference(ExternalRefType::Advisories));
    let mut sbom = sbom_of(vec![product.clone(), dependency]);
    sbom.primary_component_id = Some(product.canonical_id);
    let ev = SbomEvidence::new(&sbom, as_of());
    let advisories = |r: &ExternalReference| r.ref_type == ExternalRefType::Advisories;
    assert!(!ev.manufacturer().reference(advisories));
    assert!(!ev.manufacturer().identified);
}

#[test]
fn a_non_tool_creator_is_judged_by_its_type_only() {
    let creator = |creator_type, name: &str| Creator {
        creator_type,
        name: name.to_string(),
        email: None,
    };
    let mut sbom = sbom_of(vec![]);
    sbom.document.creators = vec![creator(CreatorType::Tool, "syft 1.0")];
    assert!(
        !SbomEvidence::new(&sbom, as_of())
            .document()
            .has_non_tool_creator
    );
    // A placeholder name still counts here: BSI TR-03183-2 judges the
    // creator's contact apart.
    sbom.document
        .creators
        .push(creator(CreatorType::Person, "NOASSERTION"));
    assert!(
        SbomEvidence::new(&sbom, as_of())
            .document()
            .has_non_tool_creator
    );
}

#[test]
fn vulnerability_presence_is_read_per_component() {
    let mut a = component("a");
    a.vulnerabilities = vec![VulnerabilityRef::new(
        "CVE-1".to_string(),
        VulnerabilitySource::Osv,
    )];
    let sbom = sbom_of(vec![a, component("b")]);
    let ev = SbomEvidence::new(&sbom, as_of());
    assert!(view(&ev, "a").has_vulnerabilities());
    assert!(!view(&ev, "b").has_vulnerabilities());
}

#[test]
fn the_first_non_spdx_licence_is_a_real_one_in_licence_order() {
    let with = |name: &str, declared: &[&str], concluded: Option<&str>| {
        let mut c = component(name);
        for expression in declared {
            c.licenses
                .add_declared(LicenseExpression::new((*expression).to_string()));
        }
        c.licenses.concluded = concluded.map(|e| LicenseExpression::new(e.to_string()));
        c
    };
    let sbom = sbom_of(vec![
        with("spdx", &["MIT"], Some("Apache-2.0")),
        with(
            "text",
            &["MIT", "Custom Licence A"],
            Some("Custom Licence B"),
        ),
        with("sentinel", &["NOASSERTION"], None),
        with("placeholder", &["TBD"], Some("Custom Licence C")),
        with("none", &[], None),
    ]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let first = |name| view(&ev, name).first_non_spdx_license();
    assert_eq!(first("spdx"), None);
    assert_eq!(first("text"), Some("Custom Licence A"));
    assert_eq!(first("sentinel"), None);
    assert_eq!(first("placeholder"), Some("Custom Licence C"));
    assert_eq!(first("none"), None);
}

#[test]
fn authored_hash_facts_leave_out_enriched_hashes() {
    let hash = |algorithm, value: String, provenance| {
        let mut h = Hash::new(algorithm, value);
        h.provenance = provenance;
        h
    };
    let with = |name: &str, hashes: Vec<Hash>| {
        let mut c = component(name);
        c.hashes = hashes;
        c
    };
    let (authored, enriched) = (HashProvenance::Authored, HashProvenance::Enriched);
    let sbom = sbom_of(vec![
        with("none", vec![]),
        with(
            "enriched",
            vec![hash(HashAlgorithm::Sha512, "a".repeat(128), enriched)],
        ),
        with(
            "sha256",
            vec![hash(HashAlgorithm::Sha256, "b".repeat(64), authored)],
        ),
        with(
            "bad-sha512",
            vec![hash(HashAlgorithm::Sha512, "zz".to_string(), authored)],
        ),
        with(
            "sha512",
            vec![
                hash(HashAlgorithm::Sha256, "c".repeat(64), enriched),
                hash(HashAlgorithm::Sha512, "d".repeat(128), authored),
            ],
        ),
    ]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let facts = |name| view(&ev, name).authored_hashes().facts;
    assert!(!facts("none").present);
    assert!(!facts("enriched").present && !facts("enriched").plausible_sha512);
    assert!(facts("sha256").present && !facts("sha256").plausible_sha512);
    assert!(facts("bad-sha512").present && !facts("bad-sha512").plausible_sha512);
    assert!(facts("sha512").plausible_sha512);
    let listed: Vec<_> = view(&ev, "sha512")
        .authored_hashes()
        .iter()
        .map(|h| h.algorithm.clone())
        .collect();
    assert_eq!(listed, [HashAlgorithm::Sha512]);
}

#[test]
fn cisa_document_facts_keep_the_serial_as_read_and_classified() {
    let creator = |creator_type, name: &str| Creator {
        creator_type,
        name: name.to_string(),
        email: None,
    };
    let mut sbom = sbom_of(vec![]);
    sbom.document.format = SbomFormat::CycloneDx;
    sbom.document.spec_version = "1.6".to_string();
    sbom.document.creators = vec![
        creator(CreatorType::Tool, "syft 1.0"),
        creator(CreatorType::Person, "NOASSERTION"),
    ];
    sbom.document.serial_number = Some("NOASSERTION".to_string());
    sbom.document.lifecycle_phase = Some("build".to_string());
    let ev = SbomEvidence::new(&sbom, as_of());
    let doc = ev.document();
    assert!(!doc.spdx2);
    assert!(doc.has_tool_creator);
    // A person named by a sentinel is a non-tool creator, but no identified
    // author.
    assert!(doc.has_non_tool_creator && !doc.has_identified_non_tool_creator);
    // The serial is present as read, and declares nothing.
    assert_eq!(doc.serial_number, Some("NOASSERTION"));
    assert_eq!(doc.serial_number_text.raw, Some("NOASSERTION"));
    assert_eq!(doc.serial_number_text.value, Known::DeclaredUnknown);
    assert_eq!(doc.lifecycle_phase.value, Known::Value("build"));
    assert_eq!(doc.doc_version, None);
    assert!(!doc.signed);

    sbom.document.creators[1].email = Some("sbom@acme.test".to_string());
    sbom.document.doc_version = Some(3);
    sbom.document.signature = Some(SignatureInfo {
        algorithm: "ES256".to_string(),
        has_value: true,
    });
    let ev = SbomEvidence::new(&sbom, as_of());
    let doc = ev.document();
    assert!(doc.has_identified_non_tool_creator);
    assert_eq!(doc.doc_version, Some(3));
    assert!(doc.signed);

    sbom.document.format = SbomFormat::Spdx;
    // A version that does not parse counts as 2.x.
    for (spec_version, spdx2) in [("SPDX-2.3", true), ("3.0.1", false), ("draft", true)] {
        sbom.document.spec_version = spec_version.to_string();
        let ev = SbomEvidence::new(&sbom, as_of());
        assert_eq!(ev.document().spdx2, spdx2, "{spec_version}");
    }
}

#[test]
fn the_tool_version_follows_cisa_2026s_heuristic() {
    let discernible = |creator_type, name: &str| {
        let mut sbom = sbom_of(vec![]);
        sbom.document.creators = vec![Creator {
            creator_type,
            name: name.to_string(),
            email: None,
        }];
        SbomEvidence::new(&sbom, as_of())
            .document()
            .tool_version_discernible
    };
    assert!(discernible(CreatorType::Tool, "syft 1.0"));
    assert!(discernible(CreatorType::Tool, "cyclonedx-npm-1.19.3"));
    assert!(!discernible(CreatorType::Tool, "acme"));
    // A digit in an earlier segment is no version (FSCT reads it as one),
    // and an explicit unknown is one (FSCT does not).
    assert!(!discernible(CreatorType::Tool, "syft2 scanner"));
    assert!(discernible(CreatorType::Tool, "acme NOASSERTION"));
    // Only tools are read.
    assert!(!discernible(CreatorType::Person, "acme 1.0"));
}

#[test]
fn authored_hash_facts_read_the_explicit_unknown_and_the_strength() {
    let hash = |algorithm, value: &str, provenance| {
        let mut h = Hash::new(algorithm, value.to_string());
        h.provenance = provenance;
        h
    };
    let with = |name: &str, hashes: Vec<Hash>| {
        let mut c = component(name);
        c.hashes = hashes;
        c
    };
    let (authored, enriched) = (HashProvenance::Authored, HashProvenance::Enriched);
    let md5 = "a".repeat(32);
    let sha256 = "b".repeat(64);
    let sbom = sbom_of(vec![
        with(
            "sentinel",
            vec![hash(HashAlgorithm::Sha256, " NOASSERTION ", authored)],
        ),
        with("weak", vec![hash(HashAlgorithm::Md5, &md5, authored)]),
        with(
            "weak-and-strong",
            vec![
                hash(HashAlgorithm::Md5, &md5, authored),
                hash(HashAlgorithm::Sha256, &sha256, authored),
            ],
        ),
        with(
            "enriched-strong",
            vec![
                hash(HashAlgorithm::Md5, &md5, authored),
                hash(HashAlgorithm::Sha256, &sha256, enriched),
            ],
        ),
        with(
            "bad-strong",
            vec![hash(HashAlgorithm::Sha256, "zz", authored)],
        ),
    ]);
    let ev = SbomEvidence::new(&sbom, as_of());
    let facts = |name| view(&ev, name).authored_hashes().facts;
    let sentinel = facts("sentinel");
    assert!(sentinel.present && !sentinel.plausible && sentinel.declared_unknown);
    assert!(facts("weak").plausible && !facts("weak").plausible_strong);
    assert!(facts("weak-and-strong").plausible_strong);
    assert!(facts("enriched-strong").plausible && !facts("enriched-strong").plausible_strong);
    let bad = facts("bad-strong");
    assert!(bad.present && !bad.plausible && !bad.plausible_strong && !bad.declared_unknown);
}

#[test]
fn the_strong_algorithms_are_those_cisa_2026_finds_no_shortfall_in() {
    let algorithms = [
        (HashAlgorithm::Md5, 32),
        (HashAlgorithm::Sha1, 40),
        (HashAlgorithm::Sha256, 64),
        (HashAlgorithm::Sha384, 96),
        (HashAlgorithm::Sha512, 128),
        (HashAlgorithm::Sha3_256, 64),
        (HashAlgorithm::Sha3_384, 96),
        (HashAlgorithm::Sha3_512, 128),
        (HashAlgorithm::Blake2b256, 64),
        (HashAlgorithm::Blake2b384, 96),
        (HashAlgorithm::Blake2b512, 128),
        (HashAlgorithm::Blake3, 64),
        (HashAlgorithm::Streebog256, 64),
        (HashAlgorithm::Streebog512, 128),
        (HashAlgorithm::Other("SHA224".to_string()), 56),
        (HashAlgorithm::Other("MD6".to_string()), 64),
    ];
    for (algorithm, digits) in algorithms {
        let mut c = component("c");
        c.hashes = vec![Hash::new(algorithm.clone(), "e".repeat(digits))];
        let sbom = sbom_of(vec![c]);
        let ev = SbomEvidence::new(&sbom, as_of());
        let facts = view(&ev, "c").authored_hashes().facts;
        assert!(facts.plausible, "{algorithm}");
        assert_eq!(
            facts.plausible_strong,
            hash_algorithm_shortfall(&algorithm).is_none(),
            "{algorithm}"
        );
    }
}

#[test]
fn a_bom_reference_on_any_component_links_an_external_sbom() {
    let mut dependency = component("dependency");
    dependency.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::Bom,
        url: "https://acme.test/dependency.cdx.json".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    let linked = sbom_of(vec![component("app"), dependency]);
    assert!(SbomEvidence::new(&linked, as_of()).has_bom_reference());
    let alone = sbom_of(vec![component("app")]);
    assert!(!SbomEvidence::new(&alone, as_of()).has_bom_reference());
}

// ----------------------------------------------------------------------------
// The facts do not depend on when or where a group is derived
// ----------------------------------------------------------------------------

/// Every fact of `ev`, derived in the order given, as text.
fn every_fact(ev: &SbomEvidence<'_>, reversed: bool) -> String {
    let mut groups: Vec<Box<dyn Fn() -> String + '_>> = vec![
        Box::new(|| format!("{:?}", ev.document())),
        Box::new(|| format!("{:?}", ev.graph())),
        Box::new(|| format!("{:?}", ev.manufacturer())),
        Box::new(|| format!("{:?}", ev.vulnerabilities())),
        Box::new(|| format!("{:?}", ev.duplicates())),
        Box::new(|| {
            format!(
                "{} {} {} {} {}",
                ev.cycle_count(),
                ev.has_lifecycle_property(),
                ev.package_count(false),
                ev.package_count(true),
                ev.has_bom_reference()
            )
        }),
        Box::new(|| {
            ev.components()
                .map(|c| {
                    format!(
                        "{:?} {:?} {:?} {:?} {:?} {} {} {} {} {} {:?} {:?}\n",
                        c.version(),
                        c.producer(),
                        c.licenses().state,
                        c.hashes().facts,
                        c.ids(),
                        c.name_known(),
                        c.package_scoped(),
                        c.excluded_scope(),
                        c.touched(),
                        c.has_vulnerabilities(),
                        c.first_non_spdx_license(),
                        c.authored_hashes().facts,
                    )
                })
                .collect()
        }),
    ];
    if reversed {
        groups.reverse();
    }
    let mut parts: Vec<String> = groups.iter().map(|group| group()).collect();
    if reversed {
        parts.reverse();
    }
    parts.concat()
}

#[test]
fn derived_twice_the_facts_are_equal() {
    for fixture in fixtures().into_iter().step_by(5) {
        let first = every_fact(&SbomEvidence::new(&fixture.1, as_of()), false);
        let second = every_fact(&SbomEvidence::new(&fixture.1, as_of()), true);
        assert_eq!(first, second, "{}", fixture.0.display());
    }
}

#[test]
fn facts_derived_on_several_threads_equal_those_derived_on_one() {
    for fixture in fixtures().into_iter().step_by(7) {
        let alone = every_fact(&SbomEvidence::new(&fixture.1, as_of()), false);
        let shared = SbomEvidence::new(&fixture.1, as_of());
        let seen: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|n| {
                    let shared = &shared;
                    scope.spawn(move || every_fact(shared, n % 2 == 1))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("no thread panics"))
                .collect()
        });
        for facts in seen {
            assert_eq!(facts, alone, "{}", fixture.0.display());
        }
    }
}

// ----------------------------------------------------------------------------
// Agreement: every fact equals the predicates it replaces, on every fixture
// ----------------------------------------------------------------------------

/// The extensions of the SBOM fixtures (as the equivalence gate reads them).
const SUFFIXES: &[&str] = &[".json", ".xml", ".spdx", ".rdf", ".jsonld", ".tv"];

/// Every fixture under tests/fixtures that parses as an SBOM, by path.
fn fixtures() -> Vec<(PathBuf, NormalizedSbom)> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, found);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| SUFFIXES.iter().any(|s| n.ends_with(s)))
                && std::fs::metadata(&path).is_ok_and(|m| m.len() <= 2_000_000)
            {
                found.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        &mut paths,
    );
    let parsed: Vec<_> = paths
        .into_iter()
        .filter_map(|path| {
            let sbom = crate::parsers::parse_sbom(&path).ok()?;
            Some((path, sbom))
        })
        .collect();
    assert!(
        parsed.len() > 100,
        "the agreement tests read the fixtures; only {} parsed",
        parsed.len()
    );
    parsed
}

#[test]
fn component_facts_agree_with_the_predicates_on_every_fixture() {
    use super::super::{ComplianceChecker, ComplianceLevel};
    let checkers = [false, true].map(|include| {
        ComplianceChecker::new(ComplianceLevel::NtiaMinimum)
            .with_as_of(as_of())
            .with_include_excluded_scope(include)
    });
    for (path, sbom) in fixtures() {
        let at = path.display();
        let ev = SbomEvidence::new(&sbom, as_of());
        assert_eq!(ev.component_count(), sbom.components.len(), "{at}");
        for (view, comp) in ev.components().zip(sbom.components.values()) {
            let at = format!("{at}: {}", comp.canonical_id.value());
            assert!(std::ptr::eq(view.name(), comp.name.as_str()), "{at}");
            assert_eq!(view.name_known(), known_component_name(comp), "{at}");
            assert_eq!(view.version().raw, comp.version.as_deref(), "{at}");
            assert_eq!(
                view.version().is_known(),
                has_known_value(&comp.version),
                "{at}"
            );
            let producer = view.producer();
            assert_eq!(producer.is_known(), has_known_producer(comp), "{at}");
            assert_eq!(
                producer.observed.and_then(observed),
                observed_producer(comp),
                "{at}"
            );
            // CISA 2026's explicit-unknown producer (cisa2026.rs).
            let marked_unknown = comp
                .supplier
                .iter()
                .chain(&comp.manufacturer)
                .any(|o| is_declared_unknown(o.name.trim()))
                || comp
                    .author
                    .as_deref()
                    .is_some_and(|a| is_declared_unknown(a.trim()));
            assert_eq!(
                producer.state != ValueState::Missing,
                has_known_producer(comp) || marked_unknown,
                "{at}"
            );
            assert_eq!(view.licenses().state, license_state(comp), "{at}");
            assert_eq!(view.licenses().is_known(), has_known_license(comp), "{at}");
            assert_eq!(
                view.hashes().facts.plausible,
                comp.hashes
                    .iter()
                    .any(|h| plausible_digest(&h.algorithm, &h.value)),
                "{at}"
            );
            assert_eq!(
                view.ids().any(),
                comp.identifiers.has_cra_identifier(),
                "{at}"
            );
            assert_eq!(
                view.has_vulnerabilities(),
                !comp.vulnerabilities.is_empty(),
                "{at}"
            );
            // BSI TR-03183-2's licence-name and authored-hash reading (bsi.rs).
            let known_licenses: Vec<_> = comp
                .licenses
                .all_licenses()
                .into_iter()
                .filter(|l| known_value(Some(l.expression.as_str())).is_some())
                .collect();
            assert_eq!(
                view.first_non_spdx_license(),
                known_licenses
                    .iter()
                    .find(|l| !l.is_valid_spdx)
                    .map(|l| l.expression.as_str()),
                "{at}"
            );
            let authored: Vec<&Hash> = comp
                .hashes
                .iter()
                .filter(|h| h.provenance == HashProvenance::Authored)
                .collect();
            let authored_facts = view.authored_hashes().facts;
            assert_eq!(authored_facts.present, !authored.is_empty(), "{at}");
            assert_eq!(
                authored_facts.plausible_sha512,
                authored.iter().any(|h| {
                    h.algorithm == HashAlgorithm::Sha512 && plausible_digest(&h.algorithm, &h.value)
                }),
                "{at}"
            );
            assert!(
                view.authored_hashes()
                    .iter()
                    .map(std::ptr::from_ref)
                    .eq(authored.iter().map(|h| std::ptr::from_ref(*h))),
                "{at}"
            );
            // CISA 2026's authored-hash and version reading (cisa2026.rs).
            assert_eq!(
                authored_facts.plausible,
                authored
                    .iter()
                    .any(|h| plausible_digest(&h.algorithm, &h.value)),
                "{at}"
            );
            assert_eq!(
                authored_facts.plausible_strong,
                authored.iter().any(|h| {
                    hash_algorithm_shortfall(&h.algorithm).is_none()
                        && plausible_digest(&h.algorithm, &h.value)
                }),
                "{at}"
            );
            assert_eq!(
                authored_facts.declared_unknown,
                authored.iter().any(|h| is_declared_unknown(h.value.trim())),
                "{at}"
            );
            assert_eq!(
                view.version().value != Known::Missing,
                value_state(comp.version.as_deref()) != ValueState::Missing,
                "{at}"
            );
            for (include, checker) in [false, true].into_iter().zip(&checkers) {
                assert_eq!(
                    !include && view.excluded_scope(),
                    checker.leaves_out(&sbom, comp),
                    "{at}"
                );
                assert_eq!(
                    view.package_scoped() && (include || !view.excluded_scope()),
                    checker.judges_package(&sbom, comp),
                    "{at}"
                );
            }
        }
        for (include, checker) in [false, true].into_iter().zip(&checkers) {
            assert_eq!(
                ev.package_count(include),
                checker.package_components(&sbom).count(),
                "{at}"
            );
        }
    }
}

#[test]
fn document_graph_and_manufacturer_facts_agree_on_every_fixture() {
    use std::collections::HashSet;
    for (path, sbom) in fixtures() {
        let at = path.display();
        let ev = SbomEvidence::new(&sbom, as_of());
        let doc = ev.document();
        let document = &sbom.document;
        assert_eq!(doc.spec_version, document.spec_version_parsed(), "{at}");
        assert_eq!(
            doc.has_known_timestamp,
            document.has_known_timestamp(),
            "{at}"
        );
        assert_eq!(
            doc.created_unparsed,
            document.created_unparsed.as_deref(),
            "{at}"
        );
        assert_eq!(doc.creators.len(), document.creators.len(), "{at}");
        // BSI TR-03183-2's creator of the SBOM (bsi.rs).
        assert_eq!(
            doc.has_non_tool_creator,
            document
                .creators
                .iter()
                .any(|c| c.creator_type != CreatorType::Tool),
            "{at}"
        );
        // CISA 2026's document reading (cisa2026.rs).
        assert_eq!(doc.spdx2, is_spdx2(&sbom), "{at}");
        assert_eq!(
            doc.has_identified_non_tool_creator,
            document
                .creators
                .iter()
                .any(|c| c.creator_type != CreatorType::Tool && creator_identified(c)),
            "{at}"
        );
        assert_eq!(doc.signed, document_signed(&sbom), "{at}");
        assert_eq!(
            doc.lifecycle_phase.is_known(),
            known_value(document.lifecycle_phase.as_deref()).is_some(),
            "{at}"
        );
        let tools: Vec<_> = document
            .creators
            .iter()
            .filter(|c| c.creator_type == CreatorType::Tool)
            .collect();
        assert_eq!(doc.has_tool_creator, !tools.is_empty(), "{at}");
        assert_eq!(
            doc.tool_version_discernible,
            tools.iter().any(|t| tool_name_carries_version(&t.name)),
            "{at}"
        );
        assert_eq!(doc.doc_version, document.doc_version, "{at}");
        assert_eq!(
            doc.serial_number_text.raw,
            document.serial_number.as_deref(),
            "{at}"
        );
        assert_eq!(
            doc.serial_number_text.is_known(),
            known_value(document.serial_number.as_deref()).is_some(),
            "{at}"
        );
        assert_eq!(
            ev.has_bom_reference(),
            sbom.components.values().any(|c| {
                c.external_refs
                    .iter()
                    .any(|r| matches!(r.ref_type, ExternalRefType::Bom))
            }),
            "{at}"
        );
        assert_eq!(doc.name.is_known(), has_known_value(&document.name), "{at}");
        assert_eq!(
            doc.security_contact_reaches,
            known_contact(document.security_contact.as_deref()),
            "{at}"
        );
        assert_eq!(
            doc.vulnerability_disclosure_url_reaches,
            known_contact(document.vulnerability_disclosure_url.as_deref()),
            "{at}"
        );
        assert_eq!(
            ev.primary().map(|p| p.canonical_id()),
            sbom.primary_component().map(|p| &p.canonical_id),
            "{at}"
        );

        // The dependency graph, as the generic dependency checks derived it.
        let mut connected = HashSet::new();
        let mut incoming = HashSet::new();
        for edge in &sbom.edges {
            connected.insert(&edge.from);
            connected.insert(&edge.to);
            incoming.insert(&edge.to);
        }
        for (view, comp) in ev.components().zip(sbom.components.values()) {
            assert_eq!(
                view.touched(),
                connected.contains(&comp.canonical_id),
                "{at}"
            );
            assert_eq!(
                view.declares_no_dependencies(),
                comp.extensions
                    .properties
                    .iter()
                    .any(|p| p.name == crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY),
                "{at}"
            );
        }
        assert_eq!(
            ev.graph().root_count,
            sbom.components
                .keys()
                .filter(|id| !incoming.contains(id))
                .count(),
            "{at}"
        );
        assert_eq!(
            ev.cycle_count(),
            crate::quality::cycles::dependency_cycle_count(&sbom),
            "{at}"
        );

        let vulns: Vec<_> = ev
            .vulnerabilities()
            .iter()
            .map(|f| {
                (
                    ev.component(f.component).canonical_id().clone(),
                    f.vuln.id.clone(),
                    f.justified_not_affected,
                )
            })
            .collect();
        let expected: Vec<_> = sbom
            .all_vulnerabilities()
            .into_iter()
            .map(|(c, v)| {
                (
                    c.canonical_id.clone(),
                    v.id.clone(),
                    justified_not_affected(v),
                )
            })
            .collect();
        assert_eq!(vulns, expected, "{at}");

        let duplicates: Vec<_> = sbom
            .components
            .keys()
            .filter_map(|id| sbom.duplicate_components.get(id))
            .map(|d| d.canonical_id.clone())
            .collect();
        let listed: Vec<_> = ev
            .duplicates()
            .iter()
            .map(|d| d.canonical_id.clone())
            .collect();
        assert_eq!(listed, duplicates, "{at}");

        let manufacturer = ev.manufacturer();
        assert_eq!(
            manufacturer.identified,
            manufacturer_identified(&sbom),
            "{at}"
        );
        assert_eq!(
            manufacturer.unreachable_contact,
            unreachable_contact(&sbom),
            "{at}"
        );
        let predicates: [&dyn Fn(&ExternalReference) -> bool; 4] = [
            &super::super::shared::is_contact_reference,
            &|r| r.ref_type == ExternalRefType::Advisories,
            &|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::Attestation | ExternalRefType::Certification
                )
            },
            &|_| true,
        ];
        for accepts in predicates {
            assert_eq!(
                manufacturer.reference(accepts),
                manufacturer_reference(&sbom, accepts),
                "{at}"
            );
        }
    }
}

#[test]
fn context_package_rules_agree_with_the_checker_on_every_fixture() {
    for (path, sbom) in fixtures() {
        assert_context_package_rules_agree(&sbom, &path.display().to_string());
    }
}

#[test]
fn context_inventory_finding_agrees_in_every_case() {
    let typed = |name: &str, component_type: ComponentType| {
        let mut c = component(name);
        c.component_type = component_type;
        c
    };
    let mut excluded = component("test-dep");
    excluded.scope = Some(DependencyScope::Excluded);
    let cases = [
        ("empty", sbom_of(vec![])),
        (
            "crypto only",
            sbom_of(vec![typed("aes", ComponentType::Cryptographic)]),
        ),
        (
            "files and crypto",
            sbom_of(vec![
                typed("a.c", ComponentType::File),
                typed("aes", ComponentType::Cryptographic),
            ]),
        ),
        ("excluded only", sbom_of(vec![excluded])),
        ("a package", sbom_of(vec![component("lib")])),
    ];
    for (what, sbom) in cases {
        assert_context_package_rules_agree(&sbom, what);
    }
}
