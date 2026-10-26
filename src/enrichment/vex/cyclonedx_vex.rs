//! CycloneDX VEX document parser.
//!
//! Parses standalone CycloneDX BOMs that serve as VEX documents — they contain
//! a `vulnerabilities` section with `analysis.state` fields but few or no components.
//! See <https://cyclonedx.org/capabilities/vex/> for the specification.

use crate::model::VexStatus;
use crate::parsers::cyclonedx_analysis;
use serde::Deserialize;
use std::collections::HashMap;

use super::openvex::VexParseError;

// ============================================================================
// CycloneDX VEX serde structs (minimal, VEX-focused subset)
// ============================================================================

/// Top-level CycloneDX document (VEX subset).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxVexDocument {
    #[serde(default)]
    bom_format: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<CdxVulnerability>,
}

/// A CycloneDX vulnerability entry with optional VEX analysis.
#[derive(Debug, Deserialize)]
struct CdxVulnerability {
    /// Vulnerability identifier (CVE, GHSA, etc.)
    id: Option<String>,
    /// Affected components (by bom-ref)
    #[serde(default)]
    affects: Vec<CdxAffects>,
    /// VEX analysis section
    analysis: Option<CdxAnalysis>,
}

/// Affected component reference in CycloneDX VEX.
#[derive(Debug, Deserialize)]
struct CdxAffects {
    /// Component bom-ref
    #[serde(rename = "ref")]
    bom_ref: Option<String>,
}

/// VEX analysis section in a CycloneDX vulnerability.
#[derive(Debug, Deserialize)]
struct CdxAnalysis {
    /// VEX state: not_affected, affected, fixed, in_triage
    state: Option<String>,
    /// Justification for not_affected
    justification: Option<String>,
    /// Response actions
    #[serde(default)]
    response: Vec<String>,
    /// Detail/impact description
    detail: Option<String>,
}

// ============================================================================
// Parsing functions
// ============================================================================

/// Check if a JSON string looks like a CycloneDX VEX document.
///
/// A CycloneDX VEX document has `bomFormat: "CycloneDX"` and `vulnerabilities`
/// but lacks a `components` array (or has an empty one). This distinguishes
/// standalone VEX documents from regular CycloneDX SBOMs that also contain
/// vulnerability data.
///
/// Uses minimal JSON parsing of top-level keys to avoid false positives/negatives
/// from substring matching (e.g., `"components"` appearing inside a `detail` string).
pub(crate) fn is_cyclonedx_vex(content: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return false;
    };
    let Some(obj) = value.as_object() else {
        return false;
    };
    // Must be CycloneDX with vulnerabilities
    let is_cdx = obj
        .get("bomFormat")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "CycloneDX");
    let has_vulns = obj
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    // A VEX document should NOT have components, or have an empty array
    let has_components = obj
        .get("components")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());

    is_cdx && has_vulns && !has_components
}

/// Parse a CycloneDX VEX document from a JSON string.
///
/// Returns a map of `(vuln_id, bom_ref)` → `VexStatus` for product-scoped entries
/// and `vuln_id` → `VexStatus` for unscoped entries.
pub(crate) fn parse_cyclonedx_vex(content: &str) -> Result<CdxVexResult, VexParseError> {
    let doc: CdxVexDocument = serde_json::from_str(content)?;

    if doc.bom_format.as_deref() != Some("CycloneDX") {
        return Err(VexParseError::InvalidDocument(
            "not a CycloneDX document (missing bomFormat)".to_string(),
        ));
    }

    if doc.vulnerabilities.is_empty() {
        return Err(VexParseError::InvalidDocument(
            "CycloneDX VEX document has no vulnerabilities".to_string(),
        ));
    }

    let mut scoped = HashMap::new();
    let mut unscoped = HashMap::new();
    let mut statements_parsed = 0;

    for vuln in &doc.vulnerabilities {
        let Some(ref vuln_id) = vuln.id else {
            continue;
        };
        let Some(ref analysis) = vuln.analysis else {
            continue;
        };

        statements_parsed += 1;
        let status = build_vex_status(analysis);

        if vuln.affects.is_empty() {
            // No specific component — applies globally for this vuln
            unscoped.insert(vuln_id.clone(), status);
        } else {
            for affect in &vuln.affects {
                if let Some(ref bom_ref) = affect.bom_ref
                    && !bom_ref.is_empty()
                {
                    scoped.insert((vuln_id.clone(), bom_ref.clone()), status.clone());
                }
            }
        }
    }

    Ok(CdxVexResult {
        scoped,
        unscoped,
        statements_parsed,
    })
}

/// Result of parsing a CycloneDX VEX document.
pub(crate) struct CdxVexResult {
    /// `(vuln_id, bom_ref)` → VexStatus for component-scoped entries
    pub scoped: HashMap<(String, String), VexStatus>,
    /// `vuln_id` → VexStatus for unscoped entries (no specific component)
    pub unscoped: HashMap<String, VexStatus>,
    /// Number of VEX statements parsed
    pub statements_parsed: usize,
}

/// Build a `VexStatus` from a CycloneDX analysis section, the way the
/// CycloneDX SBOM parser reads an embedded one (`parsers::cyclonedx_analysis`),
/// so an external CycloneDX VEX and an embedded analysis mean the same.
fn build_vex_status(analysis: &CdxAnalysis) -> VexStatus {
    cyclonedx_analysis::vex_status(
        analysis.state.as_deref(),
        analysis.justification.as_deref(),
        &analysis.response,
        analysis.detail.as_deref(),
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{VexJustification, VexResponse, VexState};

    const CDX_VEX_SAMPLE: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "vulnerabilities": [
            {
                "id": "CVE-2021-44228",
                "affects": [
                    { "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }
                ],
                "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "detail": "JNDI lookup feature is disabled in our configuration"
                }
            },
            {
                "id": "CVE-2023-1234",
                "affects": [
                    { "ref": "pkg:npm/lodash@4.17.20" }
                ],
                "analysis": {
                    "state": "affected",
                    "response": ["update"],
                    "detail": "Upgrade to lodash@4.17.21"
                }
            },
            {
                "id": "CVE-2024-0001",
                "analysis": {
                    "state": "in_triage"
                }
            }
        ]
    }"#;

    #[test]
    fn test_is_cyclonedx_vex() {
        assert!(is_cyclonedx_vex(CDX_VEX_SAMPLE));
        assert!(!is_cyclonedx_vex(r#"{"statements": []}"#));
    }

    #[test]
    fn test_is_cyclonedx_vex_rejects_sbom_with_components() {
        // Regular CycloneDX SBOM with both components and vulnerabilities
        let sbom = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "foo"}],
            "vulnerabilities": [{"id": "CVE-2024-0001"}]
        }"#;
        assert!(!is_cyclonedx_vex(sbom));
    }

    #[test]
    fn test_is_cyclonedx_vex_accepts_empty_components() {
        // VEX doc with empty components array is valid VEX
        let vex = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
            "vulnerabilities": [{"id": "CVE-2024-0001", "analysis": {"state": "fixed"}}]
        }"#;
        assert!(is_cyclonedx_vex(vex));
    }

    #[test]
    fn test_is_cyclonedx_vex_ignores_components_in_strings() {
        // "components" appearing in a detail string should NOT reject the doc
        let vex = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [{
                "id": "CVE-2024-0001",
                "analysis": {
                    "state": "not_affected",
                    "detail": "Does not affect components in our deployment"
                }
            }]
        }"#;
        assert!(is_cyclonedx_vex(vex));
    }

    #[test]
    fn test_parse_valid_cdx_vex() {
        let result = parse_cyclonedx_vex(CDX_VEX_SAMPLE).expect("should parse");
        assert_eq!(result.statements_parsed, 3);
        assert_eq!(result.scoped.len(), 2);
        assert_eq!(result.unscoped.len(), 1);
    }

    #[test]
    fn test_parse_cdx_vex_states() {
        let result = parse_cyclonedx_vex(CDX_VEX_SAMPLE).expect("should parse");

        let log4j_key = (
            "CVE-2021-44228".to_string(),
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_string(),
        );
        let log4j_status = result.scoped.get(&log4j_key).expect("should have log4j");
        assert_eq!(log4j_status.status, VexState::NotAffected);
        assert_eq!(
            log4j_status.justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );

        let lodash_key = (
            "CVE-2023-1234".to_string(),
            "pkg:npm/lodash@4.17.20".to_string(),
        );
        let lodash_status = result.scoped.get(&lodash_key).expect("should have lodash");
        assert_eq!(lodash_status.status, VexState::Affected);
        assert_eq!(lodash_status.responses, vec![VexResponse::Update]);

        let triage_status = result
            .unscoped
            .get("CVE-2024-0001")
            .expect("should have triage");
        assert_eq!(triage_status.status, VexState::UnderInvestigation);
    }

    #[test]
    fn test_parse_not_cyclonedx() {
        let result = parse_cyclonedx_vex(r#"{"statements": []}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_vulns() {
        let result = parse_cyclonedx_vex(
            r#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": []}"#,
        );
        assert!(result.is_err());
    }

    /// An external CycloneDX VEX statement and the same analysis embedded
    /// in an SBOM read as one VEX status, for every CycloneDX justification
    /// (and an unknown one), with the responses and the detail.
    #[test]
    fn overlay_and_embedded_analysis_read_alike() {
        for justification in [
            "code_not_present",
            "code_not_reachable",
            "requires_configuration",
            "requires_dependency",
            "requires_environment",
            "protected_by_compiler",
            "protected_at_runtime",
            "protected_at_perimeter",
            "protected_by_mitigating_control",
            "totally_made_up",
        ] {
            let vulnerability = format!(
                r#"{{"id": "CVE-2026-0001", "affects": [{{"ref": "pkg:npm/a@1.0.0"}}],
                    "analysis": {{"state": "not_affected", "justification": "{justification}",
                                  "response": ["will_not_fix", "reboot"],
                                  "detail": "the parser is never called"}}}}"#
            );
            let vex_doc = format!(
                r#"{{"bomFormat": "CycloneDX", "specVersion": "1.6",
                    "vulnerabilities": [{vulnerability}]}}"#
            );
            let sbom_doc = format!(
                r#"{{"bomFormat": "CycloneDX", "specVersion": "1.6",
                    "components": [{{"type": "library", "bom-ref": "pkg:npm/a@1.0.0",
                                     "name": "a", "version": "1.0.0",
                                     "purl": "pkg:npm/a@1.0.0"}}],
                    "vulnerabilities": [{vulnerability}]}}"#
            );
            let overlay = parse_cyclonedx_vex(&vex_doc).expect("VEX parses").scoped
                [&("CVE-2026-0001".to_string(), "pkg:npm/a@1.0.0".to_string())]
                .clone();
            let sbom = crate::parsers::parse_sbom_str(&sbom_doc).expect("SBOM parses");
            let embedded = sbom
                .all_vulnerabilities()
                .first()
                .and_then(|(_, v)| v.vex_status.clone())
                .expect("embedded VEX status");
            assert_eq!(overlay.status, embedded.status, "{justification}");
            assert_eq!(
                overlay.justification, embedded.justification,
                "{justification}"
            );
            assert_eq!(
                overlay.justification.is_some(),
                justification != "totally_made_up",
                "{justification}"
            );
            assert_eq!(overlay.responses, embedded.responses, "{justification}");
            assert_eq!(overlay.responses, vec![VexResponse::WillNotFix]);
            assert_eq!(
                overlay.impact_statement, embedded.impact_statement,
                "{justification}"
            );
            assert_eq!(
                overlay.impact_statement.as_deref(),
                Some("the parser is never called")
            );
            assert_eq!(overlay.detail, embedded.detail, "{justification}");
        }
    }

    #[test]
    fn test_multiple_responses_preserved() {
        let vex = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [{
                "id": "CVE-2024-9999",
                "affects": [{ "ref": "pkg:npm/foo@1.0.0" }],
                "analysis": {
                    "state": "affected",
                    "response": ["update", "workaround_available"]
                }
            }]
        }"#;
        let result = parse_cyclonedx_vex(vex).expect("should parse");
        let key = ("CVE-2024-9999".to_string(), "pkg:npm/foo@1.0.0".to_string());
        let status = result.scoped.get(&key).expect("should have entry");
        assert_eq!(
            status.responses,
            vec![VexResponse::Update, VexResponse::Workaround]
        );
    }
}
