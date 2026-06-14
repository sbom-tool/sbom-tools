//! Cross-format SBOM emission.
//!
//! Serializes a [`NormalizedSbom`] back out to a concrete SBOM wire format.
//! Unlike [`super::enricher`]/[`super::pruner`], which patch the *original* raw
//! JSON in place, this module *synthesizes* a fresh document from the canonical
//! model — enabling cross-format conversion (e.g. SPDX → CycloneDX).
//!
//! # Lossiness
//!
//! Normalization into [`NormalizedSbom`] is one-way lossy: format-specific
//! fields that don't map onto the canonical model are dropped during parsing.
//! To bound that loss, callers may first run [`preserve_source_json`], which
//! captures each component's verbatim source JSON into
//! [`ComponentExtensions::source_json`](crate::model::ComponentExtensions::source_json).
//! The emitter then splices same-format preserved fields back in and synthesizes
//! the remainder from the typed model. Every synthesis/drop decision is recorded
//! in a [`FidelityReport`] so the loss is reported honestly rather than hidden.

mod cyclonedx;
mod fidelity;
mod preserve;

pub use cyclonedx::emit_cyclonedx;
pub use fidelity::FidelityReport;
pub use preserve::preserve_source_json;

/// Target format for [`emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmitTarget {
    /// CycloneDX 1.7 JSON.
    CycloneDx,
    /// SPDX (2.x / 3.0) — emitter not yet implemented.
    Spdx,
}

impl EmitTarget {
    /// Parse a `--to` target value (case-insensitive).
    ///
    /// Accepts `cyclonedx`/`cdx` and `spdx`. Returns `None` for unknown values.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cyclonedx" | "cdx" | "cyclone-dx" => Some(Self::CycloneDx),
            "spdx" => Some(Self::Spdx),
            _ => None,
        }
    }
}

/// Errors that can occur while emitting an SBOM.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// The requested target format has no emitter yet.
    #[error("emitting to {0} is not yet implemented (only --to cyclonedx is supported)")]
    Unsupported(&'static str),

    /// Serializing the synthesized document to JSON failed.
    #[error("failed to serialize emitted SBOM: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Emit `sbom` to the requested `target`, returning the serialized document and
/// a [`FidelityReport`] describing what was synthesized or dropped.
///
/// # Errors
///
/// Returns [`EmitError::Unsupported`] for targets without an emitter (currently
/// [`EmitTarget::Spdx`]), or [`EmitError::Serialize`] if JSON serialization fails.
pub fn emit(
    sbom: &crate::model::NormalizedSbom,
    target: EmitTarget,
) -> Result<(String, FidelityReport), EmitError> {
    match target {
        EmitTarget::CycloneDx => emit_cyclonedx(sbom),
        EmitTarget::Spdx => Err(EmitError::Unsupported("SPDX")),
    }
}
