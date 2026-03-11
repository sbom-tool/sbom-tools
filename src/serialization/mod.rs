//! SBOM serialization and transformation.
//!
//! Operates on raw JSON (`serde_json::Value`) to inject enrichment data,
//! filter components, or merge SBOMs — preserving the original format structure.

mod enricher;
mod merger;
mod pruner;

pub use enricher::enrich_sbom_json;
pub use merger::{DeduplicationStrategy, MergeConfig, merge_sbom_json};
pub use pruner::{TailorConfig, tailor_sbom_json};
