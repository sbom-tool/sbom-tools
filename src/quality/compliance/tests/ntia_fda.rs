//! NTIA Minimum Elements and FDA checks (the generic path).

use super::*;

/// NTIA lists Timestamp as a required data field; it must gate. A
/// timestamp-less SBOM (epoch sentinel) now fails NtiaMinimum.
#[test]
fn ntia_gates_on_missing_timestamp() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let comp = |sbom: &mut NormalizedSbom| {
        let c = Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        sbom.add_component(c);
    };

    // No real timestamp (epoch sentinel) → NTIA timestamp error.
    let mut no_ts = NormalizedSbom::new(DocumentMetadata::default());
    no_ts.document.created = chrono::DateTime::UNIX_EPOCH;
    comp(&mut no_ts);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&no_ts);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-TIMESTAMP" && v.severity == ViolationSeverity::Error),
        "missing timestamp must fail NTIA"
    );

    // A real timestamp → no timestamp error.
    let mut with_ts = NormalizedSbom::new(DocumentMetadata::default()); // now()
    comp(&mut with_ts);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&with_ts);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-TIMESTAMP")
    );
}

/// "Other Unique Identifiers" is one of the seven NTIA minimum data
/// fields; a component without PURL/CPE/SWHID/SWID must fail NtiaMinimum.
#[test]
fn ntia_gates_on_missing_identifier() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
    let mut without_id = NormalizedSbom::new(DocumentMetadata::default());
    let mut c =
        Component::new("lib".to_string(), "lib@1".to_string()).with_version("1.0".to_string());
    c.supplier = Some(Organization::new("LibCorp".to_string()));
    without_id.add_component(c);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&without_id);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-IDENTIFIER" && v.severity == ViolationSeverity::Error),
        "missing unique identifier must fail NTIA"
    );

    let mut with_id = NormalizedSbom::new(DocumentMetadata::default());
    let mut c = Component::new("lib".to_string(), "lib@1".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    c.supplier = Some(Organization::new("LibCorp".to_string()));
    with_id.add_component(c);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&with_id);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-IDENTIFIER"),
        "PURL satisfies the NTIA identifier element"
    );
}

/// Asserted-as-unknown sentinels (NOASSERTION) must not satisfy the NTIA
/// version and supplier gates — SPDX copies versionInfo verbatim.
#[test]
fn placeholder_values_do_not_satisfy_required_elements() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut c = Component::new("lib".to_string(), "lib@1".to_string())
        .with_version("NOASSERTION".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    c.supplier = Some(Organization::new("NOASSERTION".to_string()));
    sbom.add_component(c);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-VERSION"),
        "NOASSERTION version must not satisfy the NTIA version element"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-SUPPLIER"),
        "NOASSERTION supplier must not satisfy the NTIA supplier element"
    );
}

/// FDA premarket guidance incorporates the NTIA baseline, so a
/// timestamp-less SBOM must fail FdaMedicalDevice like it fails NTIA.
#[test]
fn fda_gates_on_missing_timestamp() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.created = chrono::DateTime::UNIX_EPOCH;
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-FDA-TIMESTAMP" && v.severity == ViolationSeverity::Error),
        "missing timestamp must fail FDA (NTIA baseline)"
    );
}

/// FDA §524B requires level-of-support / end-of-support information;
/// its absence must at least warn, and lifecycle properties satisfy it.
#[test]
fn fda_warns_without_support_lifecycle() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, Property};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.requirement.contains("Level of support")),
        "missing support-lifecycle info must warn under FDA"
    );

    let mut with_eol = NormalizedSbom::new(DocumentMetadata::default());
    let mut c = Component::new("lib".to_string(), "lib@1".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    c.extensions.properties.push(Property {
        name: "end-of-support".to_string(),
        value: "2030-01-01".to_string(),
    });
    with_eol.add_component(c);
    let r = checker(ComplianceLevel::FdaMedicalDevice).check(&with_eol);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.requirement.contains("Level of support")),
        "component end-of-support property satisfies the FDA support check"
    );
}

/// A single token edge among many components must not satisfy the NTIA
/// dependency-relationship element; declared-incomplete SBOMs are exempt.
#[test]
fn dependency_graph_orphans_warn() {
    use crate::model::{
        CompletenessDeclaration, Component, DependencyEdge, DependencyType, DocumentMetadata,
        NormalizedSbom,
    };
    let build = || {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut ids = Vec::new();
        for i in 0..5 {
            let c = Component::new(format!("lib{i}"), format!("lib{i}@1"))
                .with_version("1.0".to_string())
                .with_purl(format!("pkg:cargo/lib{i}@1.0"));
            ids.push(c.canonical_id.clone());
            sbom.add_component(c);
        }
        // One edge between two leaves; the other three stay orphaned.
        sbom.edges.push(DependencyEdge::new(
            ids[0].clone(),
            ids[1].clone(),
            DependencyType::DependsOn,
        ));
        sbom
    };

    let r = checker(ComplianceLevel::NtiaMinimum).check(&build());
    assert!(
        r.violations.iter().any(|v| v
            .message
            .contains("participate in no dependency relationship")),
        "3/5 orphaned components must produce a dependency-coverage warning"
    );

    let mut declared = build();
    declared.document.completeness_declaration = CompletenessDeclaration::Incomplete;
    let r = checker(ComplianceLevel::NtiaMinimum).check(&declared);
    assert!(
        !r.violations.iter().any(|v| v
            .message
            .contains("participate in no dependency relationship")),
        "declared-incomplete SBOMs are exempt from the orphan warning"
    );
}

/// The primary product component must participate in the dependency
/// graph — a root with zero relationships does not describe the product.
#[test]
fn primary_component_must_participate_in_graph() {
    use crate::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom,
    };
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let app = Component::new("app".to_string(), "app".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    let lib_a = Component::new("liba".to_string(), "liba".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/liba@1.0".to_string());
    let lib_b = Component::new("libb".to_string(), "libb".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/libb@1.0".to_string());
    let app_id = app.canonical_id.clone();
    let a_id = lib_a.canonical_id.clone();
    let b_id = lib_b.canonical_id.clone();
    sbom.primary_component_id = Some(app_id.clone());
    sbom.add_component(app);
    sbom.add_component(lib_a);
    sbom.add_component(lib_b);
    // Edge between the two libs only; the primary is disconnected.
    sbom.edges.push(DependencyEdge::new(
        a_id.clone(),
        b_id,
        DependencyType::DependsOn,
    ));
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        r.violations
            .iter()
            .any(|v| v.message.contains("Primary component")
                && v.message.contains("no dependency relationship")),
        "disconnected primary component must warn"
    );

    // Connect the primary → warning disappears.
    sbom.edges
        .push(DependencyEdge::new(app_id, a_id, DependencyType::DependsOn));
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.message.contains("Primary component")
                && v.message.contains("no dependency relationship"))
    );
}

/// Genuine packages named "none"/"unknown" (corroborated by PURL) must
/// not fail the name gate; NOASSERTION always fails it.
#[test]
fn genuine_none_named_package_passes_name_gate() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, Organization};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut c = Component::new("none".to_string(), "none@1".to_string())
        .with_version("1.0.0".to_string())
        .with_purl("pkg:npm/none@1.0.0".to_string());
    c.supplier = Some(Organization::new("Acme".to_string()));
    sbom.add_component(c);
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        !r.violations.iter().any(|v| v.rule_id == "SBOM-NTIA-NAME"),
        "npm package genuinely named 'none' must not fail the name gate"
    );

    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.add_component(
        Component::new("NOASSERTION".to_string(), "x@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:npm/realname@1.0".to_string()),
    );
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        r.violations.iter().any(|v| v.rule_id == "SBOM-NTIA-NAME"),
        "NOASSERTION never satisfies the name gate"
    );
}

/// Lifecycle-evidence property matching is token-based with a real
/// value — "geolocation" must not satisfy the FDA support element.
#[test]
fn fda_support_not_satisfied_by_incidental_eol_substring() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom, Property};
    let build = |name: &str, value: &str| {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut c = Component::new("lib".to_string(), "lib@1".to_string())
            .with_version("1.0".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        c.extensions.properties.push(Property {
            name: name.to_string(),
            value: value.to_string(),
        });
        sbom.add_component(c);
        checker(ComplianceLevel::FdaMedicalDevice).check(&sbom)
    };
    assert!(
        build("geolocation", "enabled")
            .violations
            .iter()
            .any(|v| v.requirement.contains("Level of support")),
        "'geolocation' must not satisfy the support-lifecycle element"
    );
    assert!(
        build("acme:eol", "2030-01-01")
            .violations
            .iter()
            .all(|v| !v.requirement.contains("Level of support")),
        "a real eol property with a value satisfies the element"
    );
    assert!(
        build("end-of-support", "NOASSERTION")
            .violations
            .iter()
            .any(|v| v.requirement.contains("Level of support")),
        "a placeholder value must not satisfy the element"
    );
}

/// A primary component that positively declares "no dependencies"
/// (CycloneDX empty dependsOn, preserved as a synthetic property) is
/// documented — the participation warning must not fire.
#[test]
fn primary_with_declared_empty_deps_does_not_warn() {
    use crate::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom, Property,
    };
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut app = Component::new("app".to_string(), "app".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    app.extensions.properties.push(Property {
        name: crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY.to_string(),
        value: "true".to_string(),
    });
    let lib_a = Component::new("liba".to_string(), "liba".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/liba@1.0".to_string());
    let lib_b = Component::new("libb".to_string(), "libb".to_string())
        .with_version("1.0".to_string())
        .with_purl("pkg:cargo/libb@1.0".to_string());
    let app_id = app.canonical_id.clone();
    let a_id = lib_a.canonical_id.clone();
    let b_id = lib_b.canonical_id.clone();
    sbom.primary_component_id = Some(app_id);
    sbom.add_component(app);
    sbom.add_component(lib_a);
    sbom.add_component(lib_b);
    sbom.edges
        .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));
    let r = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        !r.violations
            .iter()
            .any(|v| v.message.contains("Primary component")),
        "declared-no-dependencies primary must not warn"
    );
}

/// FDA keeps the retired fast-path's any-orphan sensitivity; other
/// standards only warn on a majority of orphans.
#[test]
fn fda_warns_on_minority_orphans() {
    use crate::model::{
        Component, DependencyEdge, DependencyType, DocumentMetadata, NormalizedSbom,
    };
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    let mut ids = Vec::new();
    for i in 0..4 {
        let c = Component::new(format!("lib{i}"), format!("lib{i}@1"))
            .with_version("1.0".to_string())
            .with_purl(format!("pkg:cargo/lib{i}@1.0"));
        ids.push(c.canonical_id.clone());
        sbom.add_component(c);
    }
    // 3 of 4 connected, 1 orphan (minority).
    sbom.edges.push(DependencyEdge::new(
        ids[0].clone(),
        ids[1].clone(),
        DependencyType::DependsOn,
    ));
    sbom.edges.push(DependencyEdge::new(
        ids[1].clone(),
        ids[2].clone(),
        DependencyType::DependsOn,
    ));
    let fda = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
    assert!(
        fda.violations.iter().any(|v| v
            .message
            .contains("participate in no dependency relationship")),
        "FDA warns on any orphaned component"
    );
    let ntia = checker(ComplianceLevel::NtiaMinimum).check(&sbom);
    assert!(
        !ntia.violations.iter().any(|v| v
            .message
            .contains("participate in no dependency relationship")),
        "NTIA only warns when orphans form a majority"
    );
}

/// FDA rule identity: dependency, creator, and serial findings must
/// carry FDA rule ids, not NTIA/CRA ones.
#[test]
fn fda_findings_carry_fda_rule_ids() {
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.creators.clear();
    for i in 0..2 {
        sbom.add_component(
            Component::new(format!("lib{i}"), format!("lib{i}@1"))
                .with_version("1.0".to_string())
                .with_purl(format!("pkg:cargo/lib{i}@1.0")),
        );
    }
    let r = checker(ComplianceLevel::FdaMedicalDevice).check(&sbom);
    assert!(
        r.violations.iter().any(|v| v.rule_id == "SBOM-FDA-CREATOR"),
        "creators-empty must carry SBOM-FDA-CREATOR under FDA"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-FDA-DEPENDENCY"),
        "dependency findings must carry SBOM-FDA-DEPENDENCY under FDA"
    );
    assert!(
        r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-FDA-NAMESPACE"),
        "serial-number finding must carry SBOM-FDA-NAMESPACE under FDA"
    );
    assert!(
        !r.violations
            .iter()
            .any(|v| v.rule_id == "SBOM-NTIA-DEPENDENCY"),
        "FDA runs must not emit NTIA dependency rule identity"
    );
}
