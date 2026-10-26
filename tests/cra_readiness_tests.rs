//! CRA SBOM readiness tests.

#[path = "common/clock.rs"]
mod clock;

use chrono::{TimeZone, Utc};
use clock::checker;
use sbom_tools::diff::DiffEngine;
use sbom_tools::model::{
    CompletenessDeclaration, Component, Creator, CreatorType, DocumentMetadata, ExternalRefType,
    ExternalReference, NormalizedSbom, Organization, SbomFormat, VulnerabilityRef,
    VulnerabilitySource,
};
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ViolationCategory, ViolationSeverity,
};
use sbom_tools::reports::{
    HtmlReporter, JsonReporter, MarkdownReporter, ReportConfig, ReportGenerator, SarifReporter,
};

fn base_document_metadata() -> DocumentMetadata {
    DocumentMetadata {
        format: SbomFormat::CycloneDx,
        format_version: "1.6".to_string(),
        spec_version: "1.6".to_string(),
        serial_number: Some("urn:uuid:00000000-0000-0000-0000-000000000000".to_string()),
        doc_version: None,
        created: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        creators: vec![Creator {
            creator_type: CreatorType::Organization,
            name: "Acme Corp".to_string(),
            email: Some("security@acme.example".to_string()),
        }],
        name: Some("Acme Product".to_string()),
        security_contact: None,
        vulnerability_disclosure_url: None,
        support_end_date: None,
        lifecycle_phase: None,
        completeness_declaration: CompletenessDeclaration::Unknown,
        signature: None,
        distribution_classification: None,
        citations_count: 0,
    }
}

fn cra_ready_component(name: &str) -> Component {
    let mut comp = Component::new(name.to_string(), format!("{}-ref", name));
    comp = comp.with_version("1.0.0".to_string());
    comp = comp.with_purl(format!("pkg:npm/{}@1.0.0", name));
    comp.supplier = Some(Organization::new("Acme Corp".to_string()));
    comp
}

#[test]
fn cra_missing_identifier_and_version_are_errors() {
    let document = base_document_metadata();
    let mut sbom = NormalizedSbom::new(document);

    // Missing version and identifiers
    let comp = Component::new("lib-a".to_string(), "lib-a-ref".to_string());
    sbom.add_component(comp);

    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);

    assert!(result.violations.iter().any(|v| {
        v.severity == ViolationSeverity::Error
            && v.category == ViolationCategory::ComponentIdentification
            && v.requirement == "CRA Annex I Part II (1): Component version"
    }));

    // Updated requirement string to reflect prEN 40000-1-3 [PRE-7-RQ-07] mapping
    // and SWHID acceptance (CRA P1.2/P1.3).
    assert!(result.violations.iter().any(|v| {
        v.severity == ViolationSeverity::Error
            && v.category == ViolationCategory::ComponentIdentification
            && v.requirement.contains("Annex I")
            && v.requirement.contains("PRE-7-RQ-07")
    }));
}

#[test]
fn cra_security_contact_reference_suppresses_warning() {
    let document = base_document_metadata();
    let mut sbom = NormalizedSbom::new(document);

    let mut comp = cra_ready_component("lib-b");
    comp.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::SecurityContact,
        url: "mailto:security@acme.example".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    sbom.add_component(comp);

    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(!result.violations.iter().any(|v| {
        v.category == ViolationCategory::SecurityInfo
            && v.requirement == "CRA: Vulnerability disclosure contact"
    }));
}

#[test]
fn cra_vulnerability_metadata_warning() {
    let document = base_document_metadata();
    let mut sbom = NormalizedSbom::new(document);

    let mut comp = cra_ready_component("lib-c");
    comp.external_refs.push(ExternalReference {
        ref_type: ExternalRefType::SecurityContact,
        url: "mailto:security@acme.example".to_string(),
        comment: None,
        hashes: Vec::new(),
    });
    comp.vulnerabilities.push(VulnerabilityRef::new(
        "CVE-2026-0001".to_string(),
        VulnerabilitySource::Cve,
    ));
    sbom.add_component(comp);

    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(result.violations.iter().any(|v| {
        v.severity == ViolationSeverity::Warning
            && v.category == ViolationCategory::SecurityInfo
            && v.requirement == "CRA Annex I Part II (4): Vulnerability metadata completeness"
    }));
}

#[test]
fn cra_dependency_and_root_warnings() {
    let document = base_document_metadata();
    let mut sbom = NormalizedSbom::new(document);

    sbom.add_component(cra_ready_component("lib-d"));
    sbom.add_component(cra_ready_component("lib-e"));

    let result = checker(ComplianceLevel::CraPhase2).check(&sbom);
    assert!(result.violations.iter().any(|v| {
        v.severity == ViolationSeverity::Error
            && v.category == ViolationCategory::DependencyInfo
            && v.requirement == "CRA Annex I: Dependency relationships"
    }));
    assert!(result.violations.iter().any(|v| {
        v.severity == ViolationSeverity::Warning
            && v.category == ViolationCategory::DependencyInfo
            && v.requirement == "CRA Annex I: Top-level dependency clarity"
    }));
}

#[test]
fn cyclonedx_security_contact_is_parsed() {
    let content = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "lib-x@1.0.0",
                "name": "lib-x",
                "version": "1.0.0",
                "purl": "pkg:npm/lib-x@1.0.0",
                "externalReferences": [
                    {
                        "type": "security-contact",
                        "url": "mailto:security@acme.example"
                    }
                ]
            }
        ]
    }"#;

    let sbom = parse_sbom_str(content).expect("Failed to parse CycloneDX SBOM");
    let comp = sbom
        .components
        .values()
        .find(|c| c.name == "lib-x")
        .expect("Component missing");

    assert!(
        comp.external_refs
            .iter()
            .any(|r| matches!(r.ref_type, ExternalRefType::SecurityContact))
    );
}

#[test]
fn view_reports_include_cra_compliance() {
    let document = base_document_metadata();
    let mut sbom = NormalizedSbom::new(document);
    sbom.add_component(Component::new("lib-z".to_string(), "lib-z-ref".to_string()));

    let config = ReportConfig::default();

    let json = JsonReporter::new()
        .generate_view_report(&sbom, &config)
        .expect("JSON view report failed");
    let json_value: serde_json::Value =
        serde_json::from_str(&json).expect("Invalid JSON view report");
    assert!(json_value.get("compliance").is_some());
    assert_eq!(json_value["compliance"]["level"], "CraPhase2");

    let sarif = SarifReporter::new()
        .generate_view_report(&sbom, &config)
        .expect("SARIF view report failed");
    let sarif_value: serde_json::Value =
        serde_json::from_str(&sarif).expect("Invalid SARIF view report");
    let results = sarif_value["runs"][0]["results"]
        .as_array()
        .expect("Missing SARIF results");
    assert!(results.iter().any(|r| {
        r["ruleId"]
            .as_str()
            .map(|s| s.starts_with("SBOM-CRA-"))
            .unwrap_or(false)
    }));
}

#[test]
fn diff_reports_include_cra_compliance() {
    let old_doc = base_document_metadata();
    let new_doc = base_document_metadata();

    let mut old_sbom = NormalizedSbom::new(old_doc);
    old_sbom.add_component(cra_ready_component("lib-old"));
    old_sbom.calculate_content_hash();

    let mut new_sbom = NormalizedSbom::new(new_doc);
    let new_comp = Component::new("lib-new".to_string(), "lib-new-ref".to_string());
    new_sbom.add_component(new_comp);
    new_sbom.calculate_content_hash();

    let diff = DiffEngine::new()
        .diff(&old_sbom, &new_sbom)
        .expect("diff should succeed");
    let config = ReportConfig::default();

    let json = JsonReporter::new()
        .generate_diff_report(&diff, &old_sbom, &new_sbom, &config)
        .expect("JSON diff report failed");
    let json_value: serde_json::Value =
        serde_json::from_str(&json).expect("Invalid JSON diff report");
    assert!(json_value.get("cra_compliance").is_some());
    assert!(
        !json_value["cra_compliance"]["new"]["violations"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let sarif = SarifReporter::new()
        .generate_diff_report(&diff, &old_sbom, &new_sbom, &config)
        .expect("SARIF diff report failed");
    let sarif_value: serde_json::Value =
        serde_json::from_str(&sarif).expect("Invalid SARIF diff report");
    let results = sarif_value["runs"][0]["results"]
        .as_array()
        .expect("Missing SARIF results");
    assert!(results.iter().any(|r| {
        r["ruleId"]
            .as_str()
            .map(|s| s.starts_with("SBOM-CRA-"))
            .unwrap_or(false)
    }));
}

#[test]
fn diff_markdown_and_html_reports_compact_cra_details() {
    let old_doc = base_document_metadata();
    let new_doc = base_document_metadata();

    let mut old_sbom = NormalizedSbom::new(old_doc);
    old_sbom.add_component(cra_ready_component("lib-old"));
    old_sbom.calculate_content_hash();

    let mut new_sbom = NormalizedSbom::new(new_doc);
    for index in 0..40 {
        let comp = Component::new(format!("lib-{index}"), format!("lib-{index}-ref"));
        new_sbom.add_component(comp);
    }
    new_sbom.calculate_content_hash();

    let diff = DiffEngine::new()
        .diff(&old_sbom, &new_sbom)
        .expect("diff should succeed");
    let config = ReportConfig::default();

    let markdown = MarkdownReporter::new()
        .generate_diff_report(&diff, &old_sbom, &new_sbom, &config)
        .expect("Markdown diff report failed");
    assert!(markdown.contains("## CRA Compliance"));
    assert!(markdown.contains("### Violation Summary (New SBOM)"));
    assert!(markdown.contains("full CRA violation detail"));
    assert!(!markdown.contains("### Violations (New SBOM)"));
    assert!(
        !markdown.contains(
            "| Severity | Category | Standard refs | Requirement | Message | Remediation |"
        )
    );

    let html = HtmlReporter::new()
        .generate_diff_report(&diff, &old_sbom, &new_sbom, &config)
        .expect("HTML diff report failed");
    assert!(html.contains("<h2>CRA Compliance</h2>"));
    assert!(html.contains("Violation Summary (New SBOM)"));
    assert!(html.contains("full CRA violation detail"));
    assert!(!html.contains("Violations (New SBOM)</h3>"));
    assert!(!html.contains("<th>Severity</th>"));
}

#[test]
fn diff_markdown_and_html_reports_stay_compact_in_both_directions() {
    let old_doc = base_document_metadata();
    let new_doc = base_document_metadata();

    let mut old_sbom = NormalizedSbom::new(old_doc);
    old_sbom.add_component(cra_ready_component("lib-old"));
    old_sbom.calculate_content_hash();

    let mut new_sbom = NormalizedSbom::new(new_doc);
    for index in 0..40 {
        let comp = Component::new(format!("lib-{index}"), format!("lib-{index}-ref"));
        new_sbom.add_component(comp);
    }
    new_sbom.calculate_content_hash();

    let config = ReportConfig::default();

    for (from, to) in [(&old_sbom, &new_sbom), (&new_sbom, &old_sbom)] {
        let diff = DiffEngine::new()
            .diff(from, to)
            .expect("diff should succeed in either direction");

        let markdown = MarkdownReporter::new()
            .generate_diff_report(&diff, from, to, &config)
            .expect("Markdown diff report failed");
        assert!(markdown.contains("### Violation Summary (New SBOM)"));
        assert!(!markdown.contains("### Violations (New SBOM)"));
        assert!(!markdown.contains(
            "| Severity | Category | Standard refs | Requirement | Message | Remediation |"
        ));

        let html = HtmlReporter::new()
            .generate_diff_report(&diff, from, to, &config)
            .expect("HTML diff report failed");
        assert!(html.contains("Violation Summary (New SBOM)"));
        assert!(!html.contains("Violations (New SBOM)</h3>"));
        assert!(!html.contains("<th>Severity</th>"));
    }
}

// ============================================================================
// Diff report sidecar parity (CLI, non-TUI path)
// ============================================================================

/// Minimal CycloneDX SBOM with no security contact anywhere, so the CRA
/// Art. 13(17) single-point-of-contact finding fires as a Warning unless a
/// sidecar supplies `securityContact`.
const SIDECAR_PARITY_SBOM: &str = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "lib-x@1.0.0",
            "name": "lib-x",
            "version": "1.0.0",
            "purl": "pkg:npm/lib-x@1.0.0"
        }
    ]
}"#;

const SIDECAR_PARITY_SIDECAR: &str = r#"{ "securityContact": "security@example.com" }"#;

/// Run `sbom-tools diff <old> <new> -o json` and return the parsed report.
fn run_diff_json(old: &std::path::Path, new: &std::path::Path) -> serde_json::Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .arg("--no-color")
        .env("RUST_LOG", "error")
        .arg("diff")
        .arg(old)
        .arg(new)
        .args(["-o", "json"])
        .output()
        .expect("diff command should run");
    assert!(
        output.status.success(),
        "diff should exit 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("diff -o json should emit valid JSON")
}

/// Severities of all Art. 13(17) (security contact) violations in one side of
/// the report's `cra_compliance` object.
fn art_13_17_severities(cra_detail: &serde_json::Value) -> Vec<String> {
    cra_detail["violations"]
        .as_array()
        .expect("cra_compliance side should carry violations")
        .iter()
        .filter(|v| {
            v["requirement"]
                .as_str()
                .unwrap_or_default()
                .contains("Art. 13(17)")
        })
        .map(|v| v["severity"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// `diff -o json` must resolve each SBOM's adjacent CRA sidecar exactly like
/// the TUI path does (per-SBOM auto-discovery of `<sbom>.cra.json`), so the
/// same invocation can no longer yield different CRA verdicts depending on
/// the output format.
#[test]
fn diff_json_report_honours_adjacent_cra_sidecar_per_sbom() {
    use sbom_tools::model::CraSidecarMetadata;

    // --- Without any sidecar: Art. 13(17) is a Warning on both sides. ---
    let bare_dir = tempfile::tempdir().expect("temp dir");
    let old_path = bare_dir.path().join("base.cdx.json");
    let new_path = bare_dir.path().join("current.cdx.json");
    std::fs::write(&old_path, SIDECAR_PARITY_SBOM).expect("write old SBOM");
    std::fs::write(&new_path, SIDECAR_PARITY_SBOM).expect("write new SBOM");

    let report = run_diff_json(&old_path, &new_path);
    for side in ["old", "new"] {
        assert_eq!(
            art_13_17_severities(&report["cra_compliance"][side]),
            vec!["Warning".to_string()],
            "without a sidecar the {side} SBOM must carry the Art. 13(17) Warning"
        );
    }

    // --- Sidecar next to the NEW SBOM only: new downgraded, old untouched. ---
    let sidecar_dir = tempfile::tempdir().expect("temp dir");
    let old_path = sidecar_dir.path().join("base.cdx.json");
    let new_path = sidecar_dir.path().join("current.cdx.json");
    let sidecar_path = sidecar_dir.path().join("current.cra.json");
    std::fs::write(&old_path, SIDECAR_PARITY_SBOM).expect("write old SBOM");
    std::fs::write(&new_path, SIDECAR_PARITY_SBOM).expect("write new SBOM");
    std::fs::write(&sidecar_path, SIDECAR_PARITY_SIDECAR).expect("write sidecar");

    let report = run_diff_json(&old_path, &new_path);
    assert_eq!(
        art_13_17_severities(&report["cra_compliance"]["new"]),
        vec!["Info".to_string()],
        "the new SBOM's adjacent sidecar supplies the security contact, so \
         Art. 13(17) must be downgraded to Info in the JSON report"
    );
    assert_eq!(
        art_13_17_severities(&report["cra_compliance"]["old"]),
        vec!["Warning".to_string()],
        "sidecar discovery is per-SBOM: the old SBOM has no adjacent sidecar, \
         so its Art. 13(17) Warning must remain"
    );

    // The JSON report must match what the TUI computes for the same SBOM +
    // sidecar (ComplianceChecker with the sidecar attached), not a bare check.
    // `diff` has no --as-of and reads the wall clock, so the expectation does.
    let parsed_new = parse_sbom_str(SIDECAR_PARITY_SBOM).expect("parse new SBOM");
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).expect("load sidecar");
    let expected = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_as_of(Utc::now())
        .with_sidecar(sidecar)
        .check(&parsed_new);
    let new_detail = &report["cra_compliance"]["new"];
    assert_eq!(
        new_detail["is_compliant"].as_bool(),
        Some(expected.is_compliant),
        "is_compliant must match the sidecar-aware (TUI) computation"
    );
    assert_eq!(
        new_detail["warning_count"].as_u64(),
        Some(expected.warning_count as u64),
        "warning_count must match the sidecar-aware (TUI) computation"
    );
    assert_eq!(
        new_detail["info_count"].as_u64(),
        Some(expected.info_count as u64),
        "info_count must match the sidecar-aware (TUI) computation"
    );

    // --- Sidecar next to the OLD SBOM only: the mirror case. ---
    let old_sidecar_dir = tempfile::tempdir().expect("temp dir");
    let old_path = old_sidecar_dir.path().join("base.cdx.json");
    let new_path = old_sidecar_dir.path().join("current.cdx.json");
    std::fs::write(&old_path, SIDECAR_PARITY_SBOM).expect("write old SBOM");
    std::fs::write(&new_path, SIDECAR_PARITY_SBOM).expect("write new SBOM");
    std::fs::write(
        old_sidecar_dir.path().join("base.cra.json"),
        SIDECAR_PARITY_SIDECAR,
    )
    .expect("write sidecar");

    let report = run_diff_json(&old_path, &new_path);
    assert_eq!(
        art_13_17_severities(&report["cra_compliance"]["old"]),
        vec!["Info".to_string()],
        "the old SBOM's adjacent sidecar must be honoured too"
    );
    assert_eq!(
        art_13_17_severities(&report["cra_compliance"]["new"]),
        vec!["Warning".to_string()],
        "the new SBOM has no sidecar, so its Warning must remain"
    );
}
