//! Dependency staleness enrichment.
//!
//! This module provides functionality to detect stale, deprecated, or archived
//! dependencies by querying package registries.
//!
//! # Supported Ecosystems
//!
//! - npm (npmjs.com)
//! - `PyPI` (pypi.org)
//! - crates.io
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::enrichment::staleness::{StalenessEnricher, StalenessConfig};
//!
//! let config = StalenessConfig::default();
//! let mut enricher = StalenessEnricher::new(config);
//!
//! // Enrich components with staleness information
//! enricher.enrich_components(&mut components)?;
//! ```

mod registry;

pub use registry::{
    PackageMetadata, RegistryClient, RegistryConfig, StalenessEnricher, StalenessEnrichmentStats,
};
