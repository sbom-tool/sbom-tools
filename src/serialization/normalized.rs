//! The normalized-SBOM JSON payload.
//!
//! One serializer shared by the C ABI (`sbom_tools_parse_sbom_*_json`) and the
//! CLI (`sbom-tools convert --to normalized`), so both surfaces emit exactly the
//! same bytes for the same input. Downstream consumers that pin a crate version
//! can therefore read either surface interchangeably (see "JSON output contract"
//! in the README for what is and is not pinned).
//!
//! The shape is [`NormalizedSbom`] with one change: `components` is an ordered
//! array of `{canonical_id, component}` entries rather than a map, which keeps
//! the payload consumable from languages without ordered maps.

use crate::model::{
    CanonicalId, Component, DependencyEdge, DocumentMetadata, DuplicateComponent, FormatExtensions,
    NormalizedSbom,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// One component entry in the normalized payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedComponentEntry {
    /// Canonical identity of the component (the key in [`NormalizedSbom::components`]).
    pub canonical_id: CanonicalId,
    /// The component itself.
    pub component: Component,
}

/// The normalized-SBOM JSON payload as emitted by the ABI and by
/// `convert --to normalized`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSbomPayload {
    /// Document-level metadata.
    pub document: DocumentMetadata,
    /// Components in SBOM order.
    pub components: Vec<NormalizedComponentEntry>,
    /// Dependency and containment edges.
    pub edges: Vec<DependencyEdge>,
    /// Format-specific extensions carried through normalization.
    pub extensions: FormatExtensions,
    /// Content hash of the normalized document.
    pub content_hash: u64,
    /// Primary component, when the document declares one.
    pub primary_component_id: Option<CanonicalId>,
    /// The other components the document describes, besides the primary
    /// (an SPDX document can describe several). Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub described_root_ids: Vec<CanonicalId>,
    /// The components the document lists more than once, whose entries
    /// were merged (see [`NormalizedSbom::duplicate_components`]). Omitted
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_components: Vec<DuplicateComponent>,
    /// Number of canonical-id collisions resolved during parsing.
    pub collision_count: usize,
}

impl NormalizedSbomPayload {
    /// Build the payload from a normalized SBOM.
    #[must_use]
    pub fn from_sbom(sbom: NormalizedSbom) -> Self {
        Self {
            document: sbom.document,
            components: sbom
                .components
                .into_iter()
                .map(|(canonical_id, component)| NormalizedComponentEntry {
                    canonical_id,
                    component,
                })
                .collect(),
            edges: sbom.edges,
            extensions: sbom.extensions,
            content_hash: sbom.content_hash,
            primary_component_id: sbom.primary_component_id,
            described_root_ids: sbom.described_root_ids,
            duplicate_components: sbom.duplicate_components.into_values().collect(),
            collision_count: sbom.collision_count,
        }
    }

    /// Rebuild the normalized SBOM from the payload.
    #[must_use]
    pub fn into_sbom(self) -> NormalizedSbom {
        let components = self
            .components
            .into_iter()
            .map(|entry| (entry.canonical_id, entry.component))
            .collect::<IndexMap<_, _>>();

        NormalizedSbom {
            document: self.document,
            components,
            edges: self.edges,
            extensions: self.extensions,
            content_hash: self.content_hash,
            primary_component_id: self.primary_component_id,
            described_root_ids: self.described_root_ids,
            duplicate_components: self
                .duplicate_components
                .into_iter()
                .map(|record| (record.canonical_id.clone(), record))
                .collect(),
            collision_count: self.collision_count,
        }
    }

    /// Serialize with the exact settings the ABI uses (pretty-printed, two-space
    /// indent), so the CLI and ABI outputs are byte-identical.
    ///
    /// # Errors
    ///
    /// Returns the underlying `serde_json` error if serialization fails.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

/// Serialize a normalized SBOM to the shared payload JSON.
///
/// # Errors
///
/// Returns the underlying `serde_json` error if serialization fails.
pub fn normalized_sbom_json(sbom: &NormalizedSbom) -> serde_json::Result<String> {
    NormalizedSbomPayload::from_sbom(sbom.clone()).to_json_pretty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_through_json() {
        let mut sbom = NormalizedSbom::default();
        let c = Component::new("left-pad".to_string(), "pkg:npm/left-pad@1.3.0".to_string())
            .with_version("1.3.0".to_string());
        sbom.add_component(c);
        let json = normalized_sbom_json(&sbom).expect("serialize");
        let back: NormalizedSbomPayload = serde_json::from_str(&json).expect("deserialize");
        let rebuilt = back.into_sbom();
        assert_eq!(rebuilt.component_count(), 1);
        assert_eq!(rebuilt.content_hash, sbom.content_hash);
        assert_eq!(
            normalized_sbom_json(&rebuilt).expect("serialize again"),
            json,
            "round trip must be byte-stable"
        );
    }

    /// A component the document lists twice reaches the payload once, with
    /// its duplicate record and the collision count; a payload without one
    /// has no `duplicate_components` key.
    #[test]
    fn payload_carries_the_duplicate_records() {
        let entry = |bom_ref: &str| {
            Component::new("left-pad".to_string(), bom_ref.to_string())
                .with_version("1.3.0".to_string())
                .with_purl("pkg:npm/left-pad@1.3.0".to_string())
        };
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(entry("left-pad-a"));
        sbom.add_component(entry("left-pad-b"));
        let json = normalized_sbom_json(&sbom).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["components"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["collision_count"], 1);
        assert_eq!(value["duplicate_components"][0]["entries"], 2);
        let rebuilt = serde_json::from_str::<NormalizedSbomPayload>(&json)
            .expect("deserialize")
            .into_sbom();
        assert_eq!(rebuilt.duplicate_components, sbom.duplicate_components);

        let json = normalized_sbom_json(&NormalizedSbom::default()).expect("serialize");
        assert!(!json.contains("duplicate_components"));
    }

    #[test]
    fn payload_has_the_contract_top_level_keys() {
        let json = normalized_sbom_json(&NormalizedSbom::default()).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        for key in [
            "document",
            "components",
            "edges",
            "extensions",
            "content_hash",
            "primary_component_id",
            "collision_count",
        ] {
            assert!(value.get(key).is_some(), "missing top-level key {key}");
        }
    }
}
