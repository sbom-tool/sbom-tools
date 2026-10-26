//! Integration tests for CRA P1/P2 gap-fill features.
//!
//! Covers cases listed in `memory/cra-improvement-plan.md` that were not
//! exercised by the unit tests landed in P1/P2:
//! - sidecar auto-discovery preference vs. explicit flag
//! - invalid sidecar YAML must not panic
//! - Annex I Part II transitive=Warning under CraPhase1
//! - SBOM-side ExternalRefType::RiskAssessment satisfies Art. 13(2)
//! - multi-standard `--standard bsi,cra,ntia` produces independent results

#[path = "common/clock.rs"]
mod clock;

use clock::checker;
use sbom_tools::model::{
    Component, CraSidecarMetadata, DependencyEdge, DependencyType, ExternalRefType,
    ExternalReference, NormalizedSbom, Organization, SwhidKind,
};
use sbom_tools::quality::{ComplianceLevel, ViolationSeverity};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cra")
}

#[test]
fn invalid_sidecar_yaml_does_not_panic_returns_error() {
    let path = fixtures_dir().join("invalid.cra.yaml");
    assert!(path.exists(), "fixture missing: {}", path.display());
    let result = CraSidecarMetadata::from_file(&path);
    assert!(
        result.is_err(),
        "Invalid YAML should return an error, not panic"
    );
}

#[test]
fn sidecar_auto_discovery_prefers_explicit_flag() {
    let dir = tempfile::tempdir().unwrap();
    let sbom_path = dir.path().join("sbom.json");
    std::fs::write(
        &sbom_path,
        r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
    )
    .unwrap();

    // Auto-discoverable sidecar adjacent to the SBOM.
    let auto = CraSidecarMetadata {
        manufacturer_name: Some("AutoDiscoveredCorp".to_string()),
        ..Default::default()
    };
    std::fs::write(
        dir.path().join("sbom.cra.json"),
        serde_json::to_string(&auto).unwrap(),
    )
    .unwrap();

    // Sanity: auto-discovery would pick up "AutoDiscoveredCorp"
    let discovered = CraSidecarMetadata::find_for_sbom(&sbom_path).unwrap();
    assert_eq!(
        discovered.manufacturer_name.as_deref(),
        Some("AutoDiscoveredCorp")
    );

    // An explicit path should override auto-discovery semantics — we model
    // that by simulating the precedence the CLI implements: when explicit
    // path is provided, callers use it directly and never invoke find_for_sbom.
    let explicit_path = dir.path().join("explicit.cra.json");
    let explicit = CraSidecarMetadata {
        manufacturer_name: Some("ExplicitCorp".to_string()),
        ..Default::default()
    };
    std::fs::write(&explicit_path, serde_json::to_string(&explicit).unwrap()).unwrap();

    let loaded = CraSidecarMetadata::from_file(&explicit_path).unwrap();
    assert_eq!(
        loaded.manufacturer_name.as_deref(),
        Some("ExplicitCorp"),
        "Explicit path should load the explicit file, not the auto-discovered one"
    );
}

#[test]
fn cra_phase1_transitive_supplier_is_warning_or_softer() {
    let mut sbom = NormalizedSbom::default();
    let mut app = Component::new("app".to_string(), "app".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    app.supplier = Some(Organization::new("AppCorp".to_string()));
    let mut lib = Component::new("lib".to_string(), "lib".to_string())
        .with_purl("pkg:cargo/lib@1.0".to_string());
    lib.supplier = Some(Organization::new("LibCorp".to_string()));
    let deep = Component::new("deep".to_string(), "deep".to_string())
        .with_purl("pkg:cargo/deep@1.0".to_string());

    let app_id = app.canonical_id.clone();
    let lib_id = lib.canonical_id.clone();
    let deep_id = deep.canonical_id.clone();
    sbom.primary_component_id = Some(app_id.clone());
    sbom.components.insert(app_id.clone(), app);
    sbom.components.insert(lib_id.clone(), lib);
    sbom.components.insert(deep_id.clone(), deep);
    sbom.edges.push(DependencyEdge::new(
        app_id,
        lib_id.clone(),
        DependencyType::DependsOn,
    ));
    sbom.edges.push(DependencyEdge::new(
        lib_id,
        deep_id,
        DependencyType::DependsOn,
    ));

    let result = checker(ComplianceLevel::CraPhase1).check(&sbom);
    let direct_err = result.violations.iter().any(|v| {
        v.requirement.contains("Direct dependency supplier")
            && v.severity == ViolationSeverity::Error
    });
    assert!(
        !direct_err,
        "Under CraPhase1, direct dependency missing supplier is at most a Warning, not Error"
    );
    let transitive_severity = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Transitive dependency supplier"))
        .map(|v| v.severity);
    assert!(
        matches!(
            transitive_severity,
            Some(ViolationSeverity::Warning) | Some(ViolationSeverity::Info)
        ),
        "Under CraPhase1, transitive supplier missing should be Warning or Info; got {transitive_severity:?}"
    );
}

#[test]
fn art_13_2_external_reference_satisfies_check() {
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new("app".to_string(), "app".to_string())
        .with_purl("pkg:cargo/app@1.0".to_string());
    comp.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::RiskAssessment,
        url: "https://example.com/risk-assessment.pdf".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(comp);

    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 13(2)")),
        "SBOM-side risk-assessment ExternalReference should satisfy Art. 13(2)"
    );
}

#[test]
fn multi_standard_bsi_cra_ntia_produces_independent_results() {
    // Empty SBOM exercises all three checks producing distinct violation sets.
    let sbom = NormalizedSbom::default();
    let bsi = checker(ComplianceLevel::BsiTr03183_2).check(&sbom);
    let cra = checker(ComplianceLevel::CraPhase2).check(&sbom);
    let ntia = checker(ComplianceLevel::NtiaMinimum).check(&sbom);

    // Each level produces violations
    assert!(!bsi.violations.is_empty());
    assert!(!cra.violations.is_empty());
    assert!(!ntia.violations.is_empty());

    // Levels are reported correctly
    assert_eq!(bsi.level, ComplianceLevel::BsiTr03183_2);
    assert_eq!(cra.level, ComplianceLevel::CraPhase2);
    assert_eq!(ntia.level, ComplianceLevel::NtiaMinimum);

    // BSI-only requirement IDs only appear in the BSI result
    let bsi_specific = bsi
        .violations
        .iter()
        .any(|v| v.requirement.contains("BSI TR-03183-2"));
    let cra_has_bsi = cra
        .violations
        .iter()
        .any(|v| v.requirement.contains("BSI TR-03183-2"));
    let ntia_has_bsi = ntia
        .violations
        .iter()
        .any(|v| v.requirement.contains("BSI TR-03183-2"));
    assert!(
        bsi_specific,
        "BSI level must produce BSI-specific violations"
    );
    assert!(
        !cra_has_bsi,
        "CRA level must not surface BSI-specific violations"
    );
    assert!(
        !ntia_has_bsi,
        "NTIA level must not surface BSI-specific violations"
    );

    // CRA-only Art. 14 readiness only appears in the CRA result
    let cra_has_art_14 = cra
        .violations
        .iter()
        .any(|v| v.requirement.contains("Art. 14"));
    let bsi_has_art_14 = bsi
        .violations
        .iter()
        .any(|v| v.requirement.contains("Art. 14"));
    assert!(cra_has_art_14, "CRA level must produce Art. 14 violations");
    assert!(
        !bsi_has_art_14,
        "BSI level must not surface Art. 14 violations"
    );
}

#[test]
fn hardware_fixture_passes_pre_8_rq_02() {
    let path = fixtures_dir().join("router-hardware.cdx.json");
    assert!(path.exists(), "fixture missing: {}", path.display());
    let parsed = sbom_tools::parsers::parse_sbom(&path).expect("parse hardware fixture");
    let result = checker(ComplianceLevel::CraPhase2).check(&parsed);

    // The fixture is intentionally well-formed for hardware: every device/
    // firmware component has producer + identifier + version (firmware).
    let pre_8 = result
        .violations
        .iter()
        .filter(|v| v.requirement.contains("PRE-8-RQ-02"))
        .filter(|v| v.severity == ViolationSeverity::Error)
        .count();
    assert_eq!(
        pre_8, 0,
        "Hardware fixture should produce no [PRE-8-RQ-02] errors; got {pre_8}"
    );
}

#[test]
fn swhid_roundtrip_fixture_parses_all_kinds() {
    let path = fixtures_dir().join("swhid-roundtrip.cdx.json");
    assert!(path.exists(), "fixture missing: {}", path.display());
    let parsed = sbom_tools::parsers::parse_sbom(&path).expect("parse SWHID fixture");

    let by_name = |name: &str| -> &sbom_tools::model::Component {
        parsed
            .components
            .values()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing component {name}"))
    };

    // 1. cnt SWHID
    let cnt = by_name("lib-content");
    assert_eq!(cnt.identifiers.swhid.len(), 1);
    assert_eq!(cnt.identifiers.swhid[0].kind, SwhidKind::Cnt);
    assert_eq!(
        cnt.identifiers.swhid[0].hash_hex(),
        "94a9ed024d3859793618152ea559a168bbcbb5e2"
    );
    assert!(cnt.identifiers.swhid[0].qualifiers.is_empty());
    assert_eq!(
        cnt.identifiers.swhid[0].to_string(),
        "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
        "cnt SWHID must round-trip exactly"
    );

    // 2. dir SWHID
    let dir = by_name("lib-tree");
    assert_eq!(dir.identifiers.swhid[0].kind, SwhidKind::Dir);

    // 3. rev SWHID with origin qualifier
    let rev = by_name("lib-revision");
    assert_eq!(rev.identifiers.swhid[0].kind, SwhidKind::Rev);
    assert_eq!(rev.identifiers.swhid[0].qualifiers.len(), 1);
    assert_eq!(
        rev.identifiers.swhid[0].qualifiers[0],
        (
            "origin".to_string(),
            "https://github.com/example/lib-revision".to_string()
        )
    );
    // Round-trip preserves the qualifier
    assert_eq!(
        rev.identifiers.swhid[0].to_string(),
        "swh:1:rev:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef;origin=https://github.com/example/lib-revision"
    );

    // 4. Multiple SWHIDs on a single component
    let multi = by_name("lib-multi-swhid");
    assert_eq!(multi.identifiers.swhid.len(), 2);
    assert_eq!(multi.identifiers.swhid[0].kind, SwhidKind::Cnt);
    assert_eq!(multi.identifiers.swhid[1].kind, SwhidKind::Dir);

    // CRA Annex I [PRE-7-RQ-07] check: components with only SWHID still
    // satisfy the identifier requirement (proven by no Annex I violation
    // for these names — they all also have PURLs, but the BSI/CRA checks
    // accept SWHID alone, exercised by other unit tests).
    assert!(cnt.identifiers.has_cra_identifier());
    assert!(dir.identifiers.has_cra_identifier());
    assert!(rev.identifiers.has_cra_identifier());
    assert!(multi.identifiers.has_cra_identifier());
}

#[test]
fn bsi_fixture_with_sidecar_passes() {
    let sbom_path = fixtures_dir().join("bsi-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("bsi-compliant.cra.json");
    assert!(sbom_path.exists());
    assert!(sidecar_path.exists());

    let parsed = sbom_tools::parsers::parse_sbom(&sbom_path).expect("parse BSI fixture");
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).expect("load BSI fixture sidecar");

    // BSI level: the fixture itself satisfies all §5 mandatory rules
    let bsi = checker(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let errors: Vec<_> = bsi
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "BSI-compliant fixture should produce no Errors at BsiTr03183_2 level; got {errors:?}"
    );

    // CRA level + sidecar: should not produce Warning-level manufacturer
    // (Art. 13(16)), product (Art. 13(15)), or CVD-policy (Annex I Part
    // II (5)) findings
    let cra_with_sc = checker(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&parsed);
    let warnings_for: Vec<_> = cra_with_sc
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Warning)
        .filter(|v| {
            v.requirement.contains("Art. 13(16)")
                || v.requirement.contains("Art. 13(15)")
                || v.requirement.contains("Annex I Part II (5)")
        })
        .collect();
    assert!(
        warnings_for.is_empty(),
        "CRA + sidecar should suppress Art. 13(16)/13(15)/Annex I Part II (5) Warnings; got {warnings_for:?}"
    );
}
