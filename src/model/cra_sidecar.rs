//! CRA Sidecar Metadata Support
//!
//! Allows loading additional CRA-required metadata from a sidecar file
//! when the SBOM doesn't contain this information.
//!
//! The sidecar file can be JSON or YAML and supplements the SBOM with:
//! - Security contact information
//! - Vulnerability disclosure URLs
//! - Support end dates
//! - Manufacturer details

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// CRA sidecar metadata that supplements SBOM information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CraSidecarMetadata {
    /// Security contact email or URL for vulnerability disclosure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_contact: Option<String>,

    /// URL for vulnerability disclosure policy/portal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_disclosure_url: Option<String>,

    /// End of support/security updates date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_end_date: Option<DateTime<Utc>>,

    /// Manufacturer/vendor name (supplements SBOM creator info)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_name: Option<String>,

    /// Manufacturer contact email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_email: Option<String>,

    /// Product name (supplements SBOM document name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,

    /// Product version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,

    /// CE marking declaration reference (URL or document ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ce_marking_reference: Option<String>,

    /// Security update delivery mechanism description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_mechanism: Option<String>,
}

impl CraSidecarMetadata {
    /// Load sidecar metadata from a JSON file
    pub fn from_json_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_json::from_str(&content)
            .map_err(|e| CraSidecarError::ParseError(e.to_string()))
    }

    /// Load sidecar metadata from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_yaml_ng::from_str(&content)
            .map_err(|e| CraSidecarError::ParseError(e.to_string()))
    }

    /// Load sidecar metadata, auto-detecting format from extension
    pub fn from_file(path: &Path) -> Result<Self, CraSidecarError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "json" => Self::from_json_file(path),
            "yaml" | "yml" => Self::from_yaml_file(path),
            _ => Err(CraSidecarError::UnsupportedFormat(extension)),
        }
    }

    /// Try to find a sidecar file for the given SBOM path
    /// Looks for .cra.json or .cra.yaml files alongside the SBOM
    #[must_use] 
    pub fn find_for_sbom(sbom_path: &Path) -> Option<Self> {
        let parent = sbom_path.parent()?;
        let stem = sbom_path.file_stem()?.to_str()?;

        // Try common sidecar naming patterns
        let patterns = [
            format!("{stem}.cra.json"),
            format!("{stem}.cra.yaml"),
            format!("{stem}.cra.yml"),
            format!("{stem}-cra.json"),
            format!("{stem}-cra.yaml"),
        ];

        for pattern in &patterns {
            let sidecar_path = parent.join(pattern);
            if sidecar_path.exists() {
                if let Ok(metadata) = Self::from_file(&sidecar_path) {
                    return Some(metadata);
                }
            }
        }

        None
    }

    /// Check if any CRA-relevant fields are populated
    #[must_use] 
    pub const fn has_cra_data(&self) -> bool {
        self.security_contact.is_some()
            || self.vulnerability_disclosure_url.is_some()
            || self.support_end_date.is_some()
            || self.manufacturer_name.is_some()
            || self.ce_marking_reference.is_some()
    }

    /// Generate an example sidecar file content
    #[must_use] 
    pub fn example_json() -> String {
        let example = Self {
            security_contact: Some("security@example.com".to_string()),
            vulnerability_disclosure_url: Some("https://example.com/security".to_string()),
            support_end_date: Some(Utc::now() + chrono::Duration::days(365 * 2)),
            manufacturer_name: Some("Example Corp".to_string()),
            manufacturer_email: Some("contact@example.com".to_string()),
            product_name: Some("Example Product".to_string()),
            product_version: Some("1.0.0".to_string()),
            ce_marking_reference: Some("EU-DoC-2024-001".to_string()),
            update_mechanism: Some("Automatic OTA updates via secure channel".to_string()),
        };
        serde_json::to_string_pretty(&example).unwrap_or_default()
    }
}

/// Errors that can occur when loading sidecar metadata
#[derive(Debug)]
pub enum CraSidecarError {
    IoError(String),
    ParseError(String),
    UnsupportedFormat(String),
}

impl std::fmt::Display for CraSidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error reading sidecar file: {e}"),
            Self::ParseError(e) => write!(f, "Parse error in sidecar file: {e}"),
            Self::UnsupportedFormat(ext) => {
                write!(f, "Unsupported sidecar file format: .{ext}")
            }
        }
    }
}

impl std::error::Error for CraSidecarError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_has_no_data() {
        let sidecar = CraSidecarMetadata::default();
        assert!(!sidecar.has_cra_data());
    }

    #[test]
    fn test_has_cra_data_with_contact() {
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@example.com".to_string()),
            ..Default::default()
        };
        assert!(sidecar.has_cra_data());
    }

    #[test]
    fn test_example_json_is_valid() {
        let json = CraSidecarMetadata::example_json();
        let parsed: Result<CraSidecarMetadata, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_json_roundtrip() {
        let original = CraSidecarMetadata {
            security_contact: Some("test@example.com".to_string()),
            support_end_date: Some(Utc::now()),
            ..Default::default()
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(original.security_contact, parsed.security_contact);
    }
}
