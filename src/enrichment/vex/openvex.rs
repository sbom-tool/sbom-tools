//! OpenVEX document parser.
//!
//! Parses standalone OpenVEX JSON documents into internal VEX model types.
//! See <https://github.com/openvex/spec> for the specification.

use crate::model::{VexJustification, VexState, VexStatus};
use serde::Deserialize;
use std::path::Path;

/// Error type for VEX parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum VexParseError {
    #[error("I/O error reading VEX file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid VEX document: {0}")]
    InvalidDocument(String),
}

// ============================================================================
// OpenVEX serde structs
// ============================================================================

/// Top-level OpenVEX document.
#[derive(Debug, Deserialize)]
pub(crate) struct OpenVexDocument {
    #[serde(default)]
    pub statements: Vec<VexStatement>,
}

/// A single VEX statement mapping a vulnerability to products with a status.
#[derive(Debug, Deserialize)]
pub(crate) struct VexStatement {
    pub vulnerability: VexVulnerability,
    pub status: String,
    #[serde(default)]
    pub products: Vec<VexProduct>,
    pub justification: Option<String>,
    pub impact_statement: Option<String>,
    pub action_statement: Option<String>,
}

/// Vulnerability identifier within an OpenVEX statement.
#[derive(Debug, Deserialize)]
pub(crate) struct VexVulnerability {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Product identifier within an OpenVEX statement.
#[derive(Debug, Deserialize)]
pub(crate) struct VexProduct {
    #[serde(rename = "@id")]
    pub id: Option<String>,
    pub identifiers: Option<VexIdentifiers>,
}

/// Product identifiers (PURL, CPE, etc.).
#[derive(Debug, Deserialize)]
pub(crate) struct VexIdentifiers {
    pub purl: Option<String>,
}

// ============================================================================
// Parsing functions
// ============================================================================

/// Parse an OpenVEX document from a JSON string.
pub(crate) fn parse_openvex(content: &str) -> Result<OpenVexDocument, VexParseError> {
    let doc: OpenVexDocument = serde_json::from_str(content)?;
    if doc.statements.is_empty() {
        return Err(VexParseError::InvalidDocument(
            "OpenVEX document has no statements".to_string(),
        ));
    }
    Ok(doc)
}

/// Parse an OpenVEX document from a file path.
pub(crate) fn parse_openvex_file(path: &Path) -> Result<OpenVexDocument, VexParseError> {
    let content = std::fs::read_to_string(path)?;
    parse_openvex(&content)
}

/// Map an OpenVEX status string to internal `VexState`.
pub(crate) fn parse_status(s: &str) -> VexState {
    match s {
        "not_affected" => VexState::NotAffected,
        "affected" => VexState::Affected,
        "fixed" => VexState::Fixed,
        "under_investigation" => VexState::UnderInvestigation,
        _ => VexState::UnderInvestigation,
    }
}

/// Map an OpenVEX justification string to internal `VexJustification`.
pub(crate) fn parse_justification(s: &str) -> Option<VexJustification> {
    match s {
        "component_not_present" => Some(VexJustification::ComponentNotPresent),
        "vulnerable_code_not_present" => Some(VexJustification::VulnerableCodeNotPresent),
        "vulnerable_code_not_in_execute_path" => {
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        }
        "vulnerable_code_cannot_be_controlled_by_adversary" => {
            Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
        }
        "inline_mitigations_already_exist" => Some(VexJustification::InlineMitigationsAlreadyExist),
        _ => None,
    }
}

/// Extract a PURL from a VEX product. Tries `@id` first (if it starts with `pkg:`),
/// then falls back to `identifiers.purl`.
pub(crate) fn extract_product_purl(product: &VexProduct) -> Option<&str> {
    if let Some(ref id) = product.id
        && id.starts_with("pkg:")
    {
        return Some(id.as_str());
    }
    product
        .identifiers
        .as_ref()
        .and_then(|ids| ids.purl.as_deref())
}

/// Build a `VexStatus` from an OpenVEX statement.
pub(crate) fn vex_status_from_statement(stmt: &VexStatement) -> VexStatus {
    let status = parse_status(&stmt.status);
    let justification = stmt.justification.as_deref().and_then(parse_justification);

    VexStatus {
        status,
        justification,
        action_statement: stmt.action_statement.clone(),
        impact_statement: stmt.impact_statement.clone(),
        response: None,
        detail: None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VEX: &str = r#"{
        "statements": [
            {
                "vulnerability": { "name": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"] },
                "status": "not_affected",
                "products": [
                    { "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0" }
                ],
                "justification": "vulnerable_code_not_present",
                "impact_statement": "log4j-core 2.17.0 removed the JNDI lookup feature"
            },
            {
                "vulnerability": { "name": "CVE-2023-1234" },
                "status": "affected",
                "products": [
                    { "identifiers": { "purl": "pkg:npm/lodash@4.17.20" } }
                ],
                "action_statement": "Upgrade to lodash@4.17.21"
            },
            {
                "vulnerability": { "name": "CVE-2024-0001" },
                "status": "under_investigation"
            }
        ]
    }"#;

    #[test]
    fn test_parse_valid_openvex() {
        let doc = parse_openvex(SAMPLE_VEX).expect("should parse");
        assert_eq!(doc.statements.len(), 3);
        assert_eq!(doc.statements[0].vulnerability.name, "CVE-2021-44228");
        assert_eq!(doc.statements[0].status, "not_affected");
        assert_eq!(doc.statements[0].products.len(), 1);
    }

    #[test]
    fn test_parse_empty_statements() {
        let result = parse_openvex(r#"{"statements": []}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no statements"),);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_openvex("not json");
        assert!(matches!(result, Err(VexParseError::JsonError(_))));
    }

    #[test]
    fn test_parse_status_mapping() {
        assert_eq!(parse_status("not_affected"), VexState::NotAffected);
        assert_eq!(parse_status("affected"), VexState::Affected);
        assert_eq!(parse_status("fixed"), VexState::Fixed);
        assert_eq!(
            parse_status("under_investigation"),
            VexState::UnderInvestigation
        );
        assert_eq!(parse_status("unknown"), VexState::UnderInvestigation);
    }

    #[test]
    fn test_parse_justification_mapping() {
        assert_eq!(
            parse_justification("component_not_present"),
            Some(VexJustification::ComponentNotPresent)
        );
        assert_eq!(
            parse_justification("vulnerable_code_not_present"),
            Some(VexJustification::VulnerableCodeNotPresent)
        );
        assert_eq!(
            parse_justification("vulnerable_code_not_in_execute_path"),
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
        assert_eq!(
            parse_justification("vulnerable_code_cannot_be_controlled_by_adversary"),
            Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
        );
        assert_eq!(
            parse_justification("inline_mitigations_already_exist"),
            Some(VexJustification::InlineMitigationsAlreadyExist)
        );
        assert_eq!(parse_justification("unknown_justification"), None);
    }

    #[test]
    fn test_extract_product_purl_from_id() {
        let product = VexProduct {
            id: Some("pkg:maven/org.apache/log4j@2.17.0".to_string()),
            identifiers: None,
        };
        assert_eq!(
            extract_product_purl(&product),
            Some("pkg:maven/org.apache/log4j@2.17.0")
        );
    }

    #[test]
    fn test_extract_product_purl_from_identifiers() {
        let product = VexProduct {
            id: Some("urn:product:foo".to_string()), // not a PURL
            identifiers: Some(VexIdentifiers {
                purl: Some("pkg:npm/lodash@4.17.20".to_string()),
            }),
        };
        assert_eq!(
            extract_product_purl(&product),
            Some("pkg:npm/lodash@4.17.20")
        );
    }

    #[test]
    fn test_extract_product_purl_none() {
        let product = VexProduct {
            id: None,
            identifiers: None,
        };
        assert_eq!(extract_product_purl(&product), None);
    }

    #[test]
    fn test_vex_status_from_statement() {
        let doc = parse_openvex(SAMPLE_VEX).expect("should parse");

        let status0 = vex_status_from_statement(&doc.statements[0]);
        assert_eq!(status0.status, VexState::NotAffected);
        assert_eq!(
            status0.justification,
            Some(VexJustification::VulnerableCodeNotPresent)
        );
        assert!(status0.impact_statement.is_some());

        let status1 = vex_status_from_statement(&doc.statements[1]);
        assert_eq!(status1.status, VexState::Affected);
        assert!(status1.action_statement.is_some());
    }
}
