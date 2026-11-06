//! BSI TR-03183-2 checks.

use super::*;

/// BSI TR-03183-2 §5.2.2 makes component name mandatory; the dedicated
/// BSI checker must enforce it (it does not run the generic component
/// check).
#[test]
fn bsi_gates_on_nameless_component() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut c = Component::new(String::new(), "ref-1".to_string()).with_version("1.0".to_string());
    c.identifiers.purl = Some("pkg:cargo/x@1.0".to_string());
    sbom.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-3"),
        "a nameless component must fail BSI §5.2.2"
    );
}

/// Build a component that satisfies every gating BSI v2.1.0 rule:
/// name, version, purl, SPDX licence, supplier, SHA-512 hash.
fn bsi_ok_component(name: &str) -> crate::model::Component {
    use crate::model::{Component, Hash, HashAlgorithm, LicenseExpression, Organization};
    let mut c = Component::new(name.to_string(), name.to_string())
        .with_purl(format!("pkg:cargo/{name}@1.0"))
        .with_version("1.0".to_string());
    c.hashes
        .push(Hash::new(HashAlgorithm::Sha512, "f".repeat(128)));
    c.supplier = Some(Organization::new(format!("{name}-vendor")));
    c.licenses
        .add_declared(LicenseExpression::new("MIT".to_string()));
    c
}

#[test]
fn bsi_tr_03183_2_empty_sbom_emits_errors() {
    let sbom = NormalizedSbom::default();
    let result = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.requirement.contains("BSI TR-03183-2 §5.2.1")
                && v.severity == ViolationSeverity::Error),
        "Empty SBOM should fail BSI §5.2.1 (creator missing)"
    );
}

/// §5.2.2 names SHA-512 in the normative hash clause: MD5-only and
/// SHA-256-only components must fail (expectation flip: SHA-256 used to
/// satisfy the old "SHA-256+" reading), SHA-512 must pass, and a
/// hash-less component is a §3.2.1-aware Warning instead of an Error.
#[test]
fn bsi_tr_03183_2_requires_sha512_hash() {
    use crate::model::{Hash, HashAlgorithm};
    let check = |alg: Option<HashAlgorithm>, hexlen: usize| {
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.hashes.clear();
        if let Some(alg) = alg {
            c.hashes.push(Hash::new(alg, "0".repeat(hexlen)));
        }
        sbom.add_component(c);
        checker(ComplianceLevel::BsiTr03183_2).check(&sbom)
    };

    let md5 = check(Some(HashAlgorithm::Md5), 32);
    assert!(
        md5.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                && v.severity == ViolationSeverity::Error),
        "MD5-only component must fail the §5.2.2 SHA-512 requirement"
    );

    let sha256 = check(Some(HashAlgorithm::Sha256), 64);
    assert!(
        sha256
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                && v.severity == ViolationSeverity::Error),
        "SHA-256-only component must now FAIL the hash rule (§5.2.2 names SHA-512)"
    );

    let sha512 = check(Some(HashAlgorithm::Sha512), 128);
    assert!(
        !sha512
            .violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-4")),
        "SHA-512 component must satisfy the hash rule"
    );

    let none = check(None, 0);
    assert!(
        none.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4-MISSING"
                && v.severity == ViolationSeverity::Warning),
        "hash-less component must warn (§3.2.1 legitimate-omission escape)"
    );
    assert!(
        !none
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"),
        "hash-less component must not also fire the wrong-algorithm Error"
    );
}

/// §4 format gate: CycloneDX < 1.6 and SPDX < 3.0.1 fail; the minimums
/// pass; versions are compared numerically, and a synthetic document
/// with no spec_version skips the gate.
#[test]
fn bsi_tr_03183_2_format_gate() {
    use crate::model::SbomFormat;
    let check = |format: SbomFormat, version: &str| {
        let mut sbom = NormalizedSbom::default();
        sbom.document.format = format;
        sbom.document.spec_version = version.to_string();
        sbom.add_component(bsi_ok_component("lib"));
        let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-4" && v.severity == ViolationSeverity::Error)
    };

    assert!(
        check(SbomFormat::CycloneDx, "1.5"),
        "CycloneDX 1.5 must fail the §4 format gate"
    );
    assert!(
        !check(SbomFormat::CycloneDx, "1.6"),
        "CycloneDX 1.6 must pass the §4 format gate"
    );
    assert!(
        !check(SbomFormat::CycloneDx, "1.7"),
        "CycloneDX 1.7 must pass the §4 format gate"
    );
    assert!(
        check(SbomFormat::Spdx, "2.3"),
        "SPDX 2.3 must fail the §4 format gate"
    );
    assert!(
        check(SbomFormat::Spdx, "3.0"),
        "SPDX 3.0 is below the 3.0.1 minimum and must fail the §4 gate"
    );
    assert!(
        !check(SbomFormat::Spdx, "3.0.1"),
        "SPDX 3.0.1 must pass the §4 format gate"
    );
    assert!(
        !check(SbomFormat::CycloneDx, ""),
        "a document with no spec_version must skip the §4 gate"
    );
}

/// The TR mandates no generation-tool field in any tier: a Person
/// creator with an email must satisfy §5.2.1 with no tool-related
/// Error (expectation flip: tool absence used to be a gating Error).
#[test]
fn bsi_tr_03183_2_does_not_require_tool_creator() {
    use crate::model::{Creator, CreatorType};
    let mut sbom = NormalizedSbom::default();
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Person,
        name: "Jane Doe".to_string(),
        email: Some("jane@acme.example".to_string()),
    });
    sbom.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        !r.violations.iter().any(|v| v.message.contains("tool")),
        "no violation may demand a generation tool (not mandated in any TR tier)"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
        "a Person creator with an email satisfies §5.2.1 entirely"
    );
}

/// §5.2.1 creator granularity: absent entirely → Error; present without
/// email/URL → Warning; present with email → silent.
#[test]
fn bsi_tr_03183_2_creator_contact_granularity() {
    use crate::model::{Creator, CreatorType};
    let base = || {
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(bsi_ok_component("lib"));
        sbom
    };

    let empty = checker(ComplianceLevel::BsiTr03183_2).check(&base());
    assert!(
        empty
            .violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"
                && v.severity == ViolationSeverity::Error),
        "no creator at all must be a §5.2.1 Error"
    );

    let mut contactless = base();
    contactless.document.creators.push(Creator {
        creator_type: CreatorType::Organization,
        name: "Acme".to_string(),
        email: None,
    });
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&contactless);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1-CONTACT"
                && v.severity == ViolationSeverity::Warning),
        "a creator without email/URL must be a §5.2.1 Warning"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"),
        "a contactless creator is present — the absence Error must not fire"
    );

    let mut with_url = base();
    with_url.document.creators.push(Creator {
        creator_type: CreatorType::Organization,
        name: "https://acme.example".to_string(),
        email: None,
    });
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&with_url);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
        "a creator URL satisfies §5.2.1 (URL fallback when no email exists)"
    );
}

/// §5.2.1 maps "Creator of the SBOM" to Person/Organization (CycloneDX
/// metadata.authors/manufacturer), explicitly NOT metadata.tools: a
/// tools-only SBOM (the default output of common generators) must fail
/// the creator gate (expectation flip: Tool creators used to satisfy the
/// presence test).
#[test]
fn bsi_tr_03183_2_tools_only_creators_fail_creator_gate() {
    use crate::model::{Creator, CreatorType};
    let mut sbom = NormalizedSbom::default();
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Tool,
        name: "syft 1.18.0".to_string(),
        email: None,
    });
    sbom.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"
                && v.severity == ViolationSeverity::Error),
        "a tools-only creators list must fail the §5.2.1 creator gate"
    );

    // Silent side: adding an Organization creator with an email (the
    // metadata.manufacturer mapping) alongside the tool satisfies §5.2.1.
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Organization,
        name: "Demo Corp".to_string(),
        email: Some("sbom@demo.example".to_string()),
    });
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-1")),
        "an Organization creator with email satisfies §5.2.1 entirely"
    );
}

/// The §5.2.1 -CONTACT Warning must inspect only non-Tool creators: a
/// tool whose name happens to carry contact-looking characters cannot
/// stand in for the creator's email/URL.
#[test]
fn bsi_tr_03183_2_contact_warning_ignores_tool_contacts() {
    use crate::model::{Creator, CreatorType};
    let mut sbom = NormalizedSbom::default();
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Tool,
        name: "sbom-gen (https://sbom-gen.example)".to_string(),
        email: None,
    });
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Organization,
        name: "Acme".to_string(),
        email: None,
    });
    sbom.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1-CONTACT"
                && v.severity == ViolationSeverity::Warning),
        "a tool's URL must not satisfy the creator contact requirement"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-1"),
        "the Organization creator is present — only the contact Warning may fire"
    );
}

/// §5.2.2 SHA-512: only author-attested hashes count. An
/// enrichment-fetched SHA-512 is not part of the document under
/// assessment and must not mask a missing authored SHA-512
/// (HashProvenance::Authored exclusion).
#[test]
fn bsi_tr_03183_2_sha512_counts_only_authored_hashes() {
    use crate::model::{Hash, HashAlgorithm};
    let check = |hashes: Vec<Hash>| {
        let mut sbom = NormalizedSbom::default();
        let mut c = bsi_ok_component("lib");
        c.hashes = hashes;
        sbom.add_component(c);
        checker(ComplianceLevel::BsiTr03183_2).check(&sbom)
    };

    // Authored SHA-256 + ENRICHED SHA-512: the SHA-512 Error must still
    // fire — the enriched hash is not author-attested.
    let r = check(vec![
        Hash::new(HashAlgorithm::Sha256, "0".repeat(64)),
        Hash::enriched(HashAlgorithm::Sha512, "0".repeat(128)),
    ]);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"
                && v.severity == ViolationSeverity::Error),
        "an enriched SHA-512 must not mask a missing authored SHA-512"
    );

    // Authored SHA-512: silent.
    let r = check(vec![Hash::new(HashAlgorithm::Sha512, "f".repeat(128))]);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-5-4")),
        "an authored SHA-512 satisfies §5.2.2"
    );

    // Enriched hashes only: the component counts as hash-less
    // (§3.2.1-aware Warning), not as carrying the wrong algorithm.
    let r = check(vec![Hash::enriched(HashAlgorithm::Sha512, "0".repeat(128))]);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4-MISSING"
                && v.severity == ViolationSeverity::Warning),
        "enriched-only hashes must count as no authored hash at all"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-4"),
        "enriched-only hashes must not fire the wrong-algorithm Error"
    );
}

/// §5.2.2 component version is a required field: absence gates.
#[test]
fn bsi_tr_03183_2_gates_on_missing_version() {
    let mut sbom = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.version = None;
    sbom.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-VERSION"
                && v.severity == ViolationSeverity::Error),
        "a version-less component must fail BSI §5.2.2"
    );

    let mut ok = NormalizedSbom::default();
    ok.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&ok);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-VERSION"),
        "a versioned component must not fire the version rule"
    );
}

/// §5.2.2 distribution licences are required (Error when absent);
/// §6.1 requires SPDX naming (Warning when the expression is not SPDX).
#[test]
fn bsi_tr_03183_2_licence_rules() {
    use crate::model::LicenseExpression;
    let mut unlicensed = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.licenses.declared.clear();
    c.licenses.concluded = None;
    unlicensed.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&unlicensed);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE"
                && v.severity == ViolationSeverity::Error),
        "a component without distribution licences must fail §5.2.2"
    );

    let mut non_spdx = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.licenses.declared.clear();
    c.licenses.add_declared(LicenseExpression::new(
        "Standard Commercial Terms, see LICENSE.txt".to_string(),
    ));
    non_spdx.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&non_spdx);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE-SPDX"
                && v.severity == ViolationSeverity::Warning),
        "a non-SPDX licence expression must warn under §6.1"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-LICENSE"),
        "a declared (non-SPDX) licence still counts as present"
    );

    let mut spdx_ok = NormalizedSbom::default();
    spdx_ok.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&spdx_ok);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id.starts_with("SBOM-BSI-TR-03183-2-LICENSE")),
        "an SPDX-named licence satisfies both §5.2.2 and §6.1"
    );
}

/// §5.2.2 component creator: presence-level Warning when both supplier
/// and author are absent.
#[test]
fn bsi_tr_03183_2_warns_on_missing_component_creator() {
    let mut sbom = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.supplier = None;
    c.author = None;
    sbom.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-CREATOR"
                && v.severity == ViolationSeverity::Warning),
        "a component without supplier/author must warn under §5.2.2"
    );

    let mut ok = NormalizedSbom::default();
    ok.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&ok);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-CREATOR"),
        "a supplied component must not fire the creator rule"
    );
}

/// §5.2.4 puts purl/CPE in the ADDITIONAL tier ("MUST additionally …
/// if it exists"): absence is a Warning, no longer a gating Error
/// (expectation flip).
#[test]
fn bsi_tr_03183_2_identifier_is_warning_not_error() {
    let mut sbom = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.identifiers.purl = None;
    c.canonical_id = c.identifiers.canonical_id();
    sbom.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    let id_violations: Vec<_> = r
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-2-4")
        .collect();
    assert!(
        !id_violations.is_empty(),
        "a purl-less component must fire the §5.2.4 identifier rule"
    );
    assert!(
        id_violations
            .iter()
            .all(|v| v.severity == ViolationSeverity::Warning),
        "the §5.2.4 identifier rule is additional-tier: Warning, not Error"
    );
}

/// §5.2.2 requires the completeness of the dependency enumeration to be
/// clearly indicated (CycloneDX compositions).
#[test]
fn bsi_tr_03183_2_warns_on_undeclared_completeness() {
    use crate::model::CompletenessDeclaration;
    let mut sbom = NormalizedSbom::default();
    sbom.add_component(bsi_ok_component("lib"));
    // Default is Unknown → warn.
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS"
                && v.severity == ViolationSeverity::Warning),
        "an SBOM without a completeness declaration must warn under §5.2.2"
    );

    sbom.document.completeness_declaration = CompletenessDeclaration::Complete;
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS"),
        "a declared completeness must not warn"
    );
}

/// §3.1: an SBOM MUST NOT contain vulnerability information — a combined
/// document does not conform (Warning; enrichment may attach findings).
#[test]
fn bsi_tr_03183_2_warns_on_embedded_vulnerabilities() {
    use crate::model::{VulnerabilityRef, VulnerabilitySource};
    let mut sbom = NormalizedSbom::default();
    let mut c = bsi_ok_component("lib");
    c.vulnerabilities.push(VulnerabilityRef::new(
        "CVE-2026-0001".to_string(),
        VulnerabilitySource::Cve,
    ));
    sbom.add_component(c);
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-3-1"
                && v.severity == ViolationSeverity::Warning),
        "embedded vulnerability information must warn under §3.1"
    );

    let mut clean = NormalizedSbom::default();
    clean.add_component(bsi_ok_component("lib"));
    let r = checker(ComplianceLevel::BsiTr03183_2).check(&clean);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-BSI-TR-03183-2-3-1"),
        "a vulnerability-free SBOM must not fire §3.1"
    );
}

#[test]
fn bsi_tr_03183_2_passes_for_complete_component() {
    use crate::model::{Creator, CreatorType, DependencyEdge, DependencyType};
    let mut sbom = NormalizedSbom::default();
    sbom.document.creators.push(Creator {
        creator_type: CreatorType::Person,
        name: "Release Engineering".to_string(),
        email: Some("sbom@acme.example".to_string()),
    });
    let a = bsi_ok_component("a");
    let b = bsi_ok_component("b");
    let a_id = a.canonical_id.clone();
    let b_id = b.canonical_id.clone();
    sbom.components.insert(a_id.clone(), a);
    sbom.components.insert(b_id.clone(), b);
    sbom.edges
        .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));

    let result = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Complete BSI-compliant SBOM should produce no Errors; got: {errors:?}"
    );
}
