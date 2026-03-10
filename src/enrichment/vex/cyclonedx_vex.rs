//! CycloneDX VEX document parser.
//!
//! Parses standalone CycloneDX BOMs that serve as VEX documents — they contain
//! a `vulnerabilities` section with `analysis.state` fields but few or no components.
//! See <https://cyclonedx.org/capabilities/vex/> for the specification.

use crate::model::{VexJustification, VexResponse, VexState, VexStatus};
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
                if let Some(ref bom_ref) = affect.bom_ref {
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

/// Map CycloneDX analysis state to internal `VexState`.
fn parse_cdx_state(s: &str) -> VexState {
    match s {
        "not_affected" | "false_positive" => VexState::NotAffected,
        "affected" => VexState::Affected,
        "fixed" | "resolved" => VexState::Fixed,
        "in_triage" => VexState::UnderInvestigation,
        _ => VexState::UnderInvestigation,
    }
}

/// Map CycloneDX justification string to internal `VexJustification`.
fn parse_cdx_justification(s: &str) -> Option<VexJustification> {
    match s {
        "code_not_present" => Some(VexJustification::ComponentNotPresent),
        "code_not_reachable" => Some(VexJustification::VulnerableCodeNotInExecutePath),
        "requires_configuration" | "requires_dependency" | "requires_environment" => {
            Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
        }
        "protected_by_mitigating_control" => Some(VexJustification::InlineMitigationsAlreadyExist),
        "protected_at_runtime" | "protected_at_perimeter" => {
            Some(VexJustification::InlineMitigationsAlreadyExist)
        }
        _ => None,
    }
}

/// Map CycloneDX response string to internal `VexResponse`.
fn parse_cdx_response(s: &str) -> Option<VexResponse> {
    match s {
        "can_not_fix" => Some(VexResponse::CanNotFix),
        "will_not_fix" => Some(VexResponse::WillNotFix),
        "update" => Some(VexResponse::Update),
        "rollback" => Some(VexResponse::Rollback),
        "workaround_available" => Some(VexResponse::Workaround),
        _ => None,
    }
}

/// Build a `VexStatus` from a CycloneDX analysis section.
fn build_vex_status(analysis: &CdxAnalysis) -> VexStatus {
    let state = analysis
        .state
        .as_deref()
        .map_or(VexState::UnderInvestigation, parse_cdx_state);

    let justification = analysis
        .justification
        .as_deref()
        .and_then(parse_cdx_justification);

    let responses: Vec<VexResponse> = analysis
        .response
        .iter()
        .filter_map(|r| parse_cdx_response(r))
        .collect();

    VexStatus {
        status: state,
        justification,
        action_statement: None,
        impact_statement: None,
        responses,
        detail: analysis.detail.clone(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_parse_cdx_state_mapping() {
        assert_eq!(parse_cdx_state("not_affected"), VexState::NotAffected);
        assert_eq!(parse_cdx_state("affected"), VexState::Affected);
        assert_eq!(parse_cdx_state("fixed"), VexState::Fixed);
        assert_eq!(parse_cdx_state("in_triage"), VexState::UnderInvestigation);
        assert_eq!(parse_cdx_state("false_positive"), VexState::NotAffected);
        assert_eq!(parse_cdx_state("resolved"), VexState::Fixed);
        assert_eq!(parse_cdx_state("unknown"), VexState::UnderInvestigation);
    }

    #[test]
    fn test_parse_cdx_justification_mapping() {
        assert_eq!(
            parse_cdx_justification("code_not_present"),
            Some(VexJustification::ComponentNotPresent)
        );
        assert_eq!(
            parse_cdx_justification("code_not_reachable"),
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
        assert_eq!(
            parse_cdx_justification("protected_by_mitigating_control"),
            Some(VexJustification::InlineMitigationsAlreadyExist)
        );
        assert_eq!(parse_cdx_justification("unknown"), None);
    }

    #[test]
    fn test_parse_cdx_response_mapping() {
        assert_eq!(
            parse_cdx_response("can_not_fix"),
            Some(VexResponse::CanNotFix)
        );
        assert_eq!(parse_cdx_response("update"), Some(VexResponse::Update));
        assert_eq!(
            parse_cdx_response("workaround_available"),
            Some(VexResponse::Workaround)
        );
        assert_eq!(parse_cdx_response("unknown"), None);
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
