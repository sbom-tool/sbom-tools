//! Intermediate representation for normalized SBOMs.
//!
//! This module defines the canonical data structures used for format-agnostic
//! SBOM comparison. Both `CycloneDX` and SPDX formats are normalized to these
//! structures before diff operations.
//!
//! # Index Support
//!
//! For efficient TUI operations on large SBOMs, use [`NormalizedSbomIndex`]
//! to precompute lookups:
//!
//! ```ignore
//! let sbom = parse_sbom(&path)?;
//! let index = NormalizedSbomIndex::build(&sbom);
//!
//! // O(1) dependency lookup instead of O(edges)
//! let deps = index.dependencies_of(&component_id, &sbom.edges);
//! ```

mod cra_sidecar;
mod identifiers;
mod index;
mod license;
mod metadata;
mod sbom;
mod vulnerability;

pub use cra_sidecar::*;
pub use identifiers::*;
pub use index::*;
pub use license::*;
pub use metadata::*;
pub use sbom::*;
pub use vulnerability::*;
