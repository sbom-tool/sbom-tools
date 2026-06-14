//! Typed view of the HuggingFace model-info API response.
//!
//! Only the fields that map to high-confidence component data are modeled; the
//! rest of the (large, freeform) response is ignored. In particular the
//! `cardData` block — arbitrary user-authored YAML — is deliberately NOT
//! deserialized: it is unreliable and would invite low-confidence guesses.

use serde::{Deserialize, Serialize};

/// A single repository file as reported by `GET /api/models/{id}?blobs=true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfSibling {
    /// Relative file path within the repo (e.g. `model.safetensors`).
    #[serde(rename = "rfilename")]
    pub filename: Option<String>,
    /// Git-LFS pointer metadata, present for large weight files.
    pub lfs: Option<HfLfs>,
}

/// Git-LFS metadata for a sibling file. The `sha256` here is the **content**
/// hash of the actual weight file (not the LFS pointer), which is exactly the
/// value needed to verify model-weight integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfLfs {
    /// SHA-256 of the file content (hex).
    pub sha256: Option<String>,
    /// Size of the file in bytes (informational).
    pub size: Option<u64>,
}

/// The subset of the HuggingFace model-info response we map to component data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HfModelInfo {
    /// Canonical model id, `{org}/{name}` (or just `{name}` for canonical models).
    pub id: Option<String>,
    /// Pipeline tag, e.g. `text-classification`, `image-classification`.
    /// Mapped to `MlModelInfo.task`.
    #[serde(rename = "pipeline_tag")]
    pub pipeline_tag: Option<String>,
    /// Last modification timestamp (RFC 3339). Used as a staleness signal.
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    /// Declared license id (e.g. `apache-2.0`). Applied ONLY when the component
    /// declares no license — never overwrites a declared license.
    pub license: Option<String>,
    /// Repository files with their LFS metadata (requires `?blobs=true`).
    #[serde(default)]
    pub siblings: Vec<HfSibling>,
}

impl HfModelInfo {
    /// Collect the SHA-256 content hashes of all LFS weight files.
    ///
    /// These are the hashes used both for AI-010 integrity scoring and for
    /// `verify --model-dir`.
    #[must_use]
    pub fn weight_sha256s(&self) -> Vec<String> {
        self.siblings
            .iter()
            .filter_map(|s| s.lfs.as_ref().and_then(|l| l.sha256.clone()))
            .filter(|h| !h.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "id": "google-bert/bert-base-uncased",
        "pipeline_tag": "fill-mask",
        "lastModified": "2024-02-19T11:06:12.000Z",
        "license": "apache-2.0",
        "cardData": { "anything": "should be ignored" },
        "siblings": [
            { "rfilename": "config.json" },
            {
                "rfilename": "model.safetensors",
                "lfs": { "sha256": "aaaa", "size": 440473133 }
            },
            {
                "rfilename": "pytorch_model.bin",
                "lfs": { "sha256": "bbbb", "size": 440473133 }
            }
        ]
    }"#;

    #[test]
    fn parses_high_confidence_fields_and_ignores_card_data() {
        let info: HfModelInfo = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(info.id.as_deref(), Some("google-bert/bert-base-uncased"));
        assert_eq!(info.pipeline_tag.as_deref(), Some("fill-mask"));
        assert_eq!(
            info.last_modified.as_deref(),
            Some("2024-02-19T11:06:12.000Z")
        );
        assert_eq!(info.license.as_deref(), Some("apache-2.0"));
        assert_eq!(info.siblings.len(), 3);
    }

    #[test]
    fn collects_lfs_sha256_hashes_only() {
        let info: HfModelInfo = serde_json::from_str(SAMPLE).unwrap();
        let hashes = info.weight_sha256s();
        assert_eq!(hashes, vec!["aaaa".to_string(), "bbbb".to_string()]);
    }

    #[test]
    fn empty_response_yields_no_hashes() {
        let info: HfModelInfo = serde_json::from_str("{}").unwrap();
        assert!(info.weight_sha256s().is_empty());
        assert!(info.pipeline_tag.is_none());
    }
}
