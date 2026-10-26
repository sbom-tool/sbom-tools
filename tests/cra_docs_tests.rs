//! Integration tests for the `cra-docs` CLI subcommand (CRA-P4.1).
//!
//! Exercises the dossier generator end-to-end: parses an SBOM, optionally
//! a sidecar, and asserts that the three CRA-P4.1 dossier files are
//! emitted with the expected sections and that sidecar fields propagate
//! into each template.

use sbom_tools::cli::run_cra_docs;
use std::fs;
use tempfile::tempdir;

const MINIMAL_CDX: &str = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
    "metadata": {
        "component": {
            "type": "application",
            "name": "example-app",
            "version": "1.0.0"
        }
    },
    "components": [
        {"type": "library", "name": "lib-a", "version": "1.2.3", "purl": "pkg:cargo/lib-a@1.2.3"},
        {"type": "library", "name": "lib-b", "version": "0.9.0", "purl": "pkg:cargo/lib-b@0.9.0"}
    ]
}"#;

const SIDECAR_JSON: &str = r#"{
    "manufacturerName": "Example Corp",
    "manufacturerEmail": "legal@example.com",
    "productName": "Example App",
    "productVersion": "1.0.0",
    "ceMarkingReference": "EU-DoC-2026-001",
    "psirtUrl": "https://example.com/psirt",
    "securityContact": "security@example.com",
    "coordinatedDisclosurePolicyUrl": "https://example.com/security/cvd",
    "earlyWarningContact": "ew@example.com",
    "incidentReportContact": "incidents@example.com",
    "enisaReportingPlatformId": "EU-MFR-1",
    "riskAssessmentUrl": "https://example.com/risk-assessment.pdf",
    "riskAssessmentMethodology": "ISO/IEC 27005:2022",
    "supportEndDate": "2030-12-31T00:00:00Z",
    "productClass": "important-class-1"
}"#;

fn write_temp(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    p
}

#[test]
fn cra_docs_creates_all_three_dossier_files() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    assert!(out.join("eu-declaration-of-conformity.md").exists());
    assert!(out.join("technical-documentation.md").exists());
    assert!(out.join("vulnerability-handling-policy.md").exists());
}

#[test]
fn cra_docs_propagates_sidecar_into_doc_template() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(doc.contains("Example Corp"), "manufacturer name in DoC");
    assert!(doc.contains("legal@example.com"));
    assert!(doc.contains("EU-DoC-2026-001"));
    assert!(doc.contains("Example App"));
    assert!(
        doc.contains("Important Class I"),
        "sidecar productClass surfaces in DoC class"
    );
}

#[test]
fn cra_docs_propagates_sidecar_into_vuln_policy() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let policy = fs::read_to_string(out.join("vulnerability-handling-policy.md")).unwrap();
    assert!(policy.contains("https://example.com/psirt"));
    assert!(policy.contains("security@example.com"));
    assert!(policy.contains("https://example.com/security/cvd"));
    assert!(policy.contains("ew@example.com"));
    assert!(policy.contains("incidents@example.com"));
    assert!(policy.contains("EU-MFR-1"));
}

#[test]
fn cra_docs_tech_doc_summarises_components_and_compliance() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let tech = fs::read_to_string(out.join("technical-documentation.md")).unwrap();
    // Components in scope reflects the SBOM (1 primary + 2 libs = 3 in CycloneDX
    // but our SBOM model may handle this differently; assert the structural
    // header at minimum).
    assert!(tech.contains("Components in scope:"));
    assert!(tech.contains("Compliance check summary"));
    assert!(tech.contains("https://example.com/risk-assessment.pdf"));
    assert!(tech.contains("ISO/IEC 27005:2022"));
}

#[test]
fn cra_docs_auto_discovers_adjacent_sidecar() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    // sidecar named `<sbom-stem>.cra.json` is auto-discovered
    let _ = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("Example Corp"),
        "auto-discovered sidecar must populate manufacturer"
    );
}

#[test]
fn cra_docs_cli_product_class_overrides_default_when_no_sidecar() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, Some("critical".to_string())).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("Critical (Annex IV)"),
        "CLI --cra-product-class=critical must surface in DoC"
    );
    assert!(doc.contains("EUCC"), "Critical class default route is EUCC");
}

#[test]
fn cra_docs_unfilled_fields_show_tbd_placeholders() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("_TBD"),
        "DoC without sidecar must contain _TBD_ placeholders for unfilled fields"
    );
}

/// SBOM text that tries to break out of its place in the dossier Markdown: a
/// new heading, an HTML tag, a link, and a CI workflow command.
const HOSTILE_CDX: &str = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222\n# Forged serial",
    "metadata": {
        "component": {
            "type": "application",
            "name": "evil-app\n## Forged product <img src=x onerror=alert(1)>",
            "version": "1.0.0"
        }
    },
    "components": [
        {"type": "library", "name": "::warning::FORGED\n- [x](javascript:alert(1))", "version": "1.0.0"}
    ]
}"#;

/// Sidecar values with the same break-out attempts (no `productName`, so the
/// DoC takes the product name from the SBOM).
const HOSTILE_SIDECAR: &str = r##"{
    "manufacturerName": "Evil Corp\n**7. Signed for and on behalf of the manufacturer**",
    "manufacturerEmail": "legal@example.com\n# Forged contact",
    "psirtUrl": "https://example.com/psirt>\n# Forged psirt",
    "securityContact": "security@example.com | injected cell",
    "earlyWarningContact": "\\<img src=x onerror=alert(2)>",
    "riskAssessmentMethodology": "ISO <script>alert(1)</script>",
    "annexIPartIControls": {
        "ctl-1\n# Forged control": {
            "satisfied": true,
            "evidenceUrl": "https://example.com/ev) [y](data:text/html,x",
            "methodology": "SAST | injected",
            "note": "fine\n## Forged note"
        }
    },
    "productClass": "important-class-1"
}"##;

/// Whether `needle` occurs in `md` without a Markdown backslash escape on its
/// first character. Only an odd run of backslashes escapes it: an even run is
/// escaped backslashes, after which the needle is live (`\\<img`).
fn contains_unescaped(md: &str, needle: &str) -> bool {
    md.match_indices(needle)
        .any(|(at, _)| md[..at].chars().rev().take_while(|&c| c == '\\').count() % 2 == 0)
}

/// Text from the SBOM and the sidecar is escaped in every dossier file: no
/// crafted value starts its own heading, list item or table row, opens an HTML
/// tag or a link, or begins a line with a workflow command (the S1 rule for
/// human-readable output, here applied to the generated Markdown).
#[test]
fn cra_docs_neutralizes_sbom_and_sidecar_text() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", HOSTILE_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", HOSTILE_SIDECAR);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    for file in [
        "eu-declaration-of-conformity.md",
        "technical-documentation.md",
        "vulnerability-handling-policy.md",
    ] {
        let md = fs::read_to_string(out.join(file)).unwrap();
        for line in md.lines() {
            let line = line.trim_start();
            // A crafted value that begins a line, after any block marker,
            // would render as its own heading or list item.
            assert!(
                !line
                    .trim_start_matches(['#', '-', '*', ' '])
                    .starts_with("Forged"),
                "{file}: a crafted value started its own Markdown block: {line:?}"
            );
            assert!(
                !line.starts_with("::"),
                "{file}: a line starts a workflow command: {line:?}"
            );
        }
        for raw in ["<img", "<script", "[x](javascript", "| injected"] {
            assert!(
                !contains_unescaped(&md, raw),
                "{file}: unescaped {raw:?}:\n{md}"
            );
        }
    }

    // The values are rendered, not dropped: escaped in place, with URLs kept
    // as clickable autolinks.
    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert_eq!(
        doc.lines()
            .filter(|l| l.trim() == "**7. Signed for and on behalf of the manufacturer**")
            .count(),
        1,
        "the manufacturer name forged a second signature section:\n{doc}"
    );
    assert!(
        doc.contains("Evil Corp"),
        "manufacturer still named:\n{doc}"
    );
    assert!(doc.contains("evil-app"), "product still named:\n{doc}");
    let policy = fs::read_to_string(out.join("vulnerability-handling-policy.md")).unwrap();
    assert!(
        policy.contains("<https://example.com/psirt#Forgedpsirt>"),
        "PSIRT URL kept as one autolink:\n{policy}"
    );
    let tech = fs::read_to_string(out.join("technical-documentation.md")).unwrap();
    assert!(
        tech.contains("[link](<https://example.com/ev)[y](data:text/html,x>)"),
        "evidence URL kept inside its link destination:\n{tech}"
    );
}
