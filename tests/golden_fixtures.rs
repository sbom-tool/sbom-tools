use sbom_tools::{DiffEngine, parse_sbom};
use std::path::Path;

#[test]
fn golden_parse_cyclonedx_minimal() {
    let sbom = parse_sbom(Path::new("tests/fixtures/cyclonedx/minimal.cdx.json"))
        .expect("failed to parse minimal CycloneDX fixture");

    // 3 components: metadata.component (test-app) + lodash + express
    assert_eq!(sbom.component_count(), 3);
    assert_eq!(sbom.edges.len(), 1);
    assert_eq!(sbom.vulnerability_counts().total(), 0);
    // Primary component should be set from metadata.component
    assert!(sbom.primary_component_id.is_some());
}

#[test]
fn golden_parse_spdx_minimal() {
    let sbom = parse_sbom(Path::new("tests/fixtures/spdx/minimal.spdx.json"))
        .expect("failed to parse minimal SPDX fixture");

    assert_eq!(sbom.component_count(), 2);
    assert_eq!(sbom.edges.len(), 1);
    assert_eq!(sbom.vulnerability_counts().total(), 0);
}

#[test]
fn golden_parse_cyclonedx_with_vulnerabilities() {
    let sbom = parse_sbom(Path::new(
        "tests/fixtures/cyclonedx/with-vulnerabilities.cdx.json",
    ))
    .expect("failed to parse CycloneDX vulnerabilities fixture");

    let counts = sbom.vulnerability_counts();
    assert_eq!(sbom.component_count(), 2);
    assert_eq!(counts.total(), 2);
    assert_eq!(counts.critical, 1);
    assert_eq!(counts.high, 1);
}

#[test]
fn golden_diff_demo_pair() {
    let old_sbom = parse_sbom(Path::new("tests/fixtures/demo-old.cdx.json"))
        .expect("failed to parse demo-old fixture");
    let new_sbom = parse_sbom(Path::new("tests/fixtures/demo-new.cdx.json"))
        .expect("failed to parse demo-new fixture");

    let diff = DiffEngine::new()
        .diff(&old_sbom, &new_sbom)
        .expect("diff should succeed");

    // Both SBOMs now include metadata.component as primary component
    // Old: acme-webapp@1.0.0 + 8 libs = 9 components
    // New: acme-webapp@2.0.0 + 8 libs = 9 components
    // Added: dayjs, typescript, zod, prisma = 4
    // Removed: moment, request, underscore, jquery = 4
    // Modified: lodash, express, axios, react + acme-webapp = 5
    assert_eq!(diff.summary.components_added, 4);
    assert_eq!(diff.summary.components_removed, 4);
    assert_eq!(diff.summary.components_modified, 5);
    assert_eq!(diff.summary.total_changes, 13);
}
