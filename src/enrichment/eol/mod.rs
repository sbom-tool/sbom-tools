//! End-of-life detection via the endoflife.date API.
//!
//! This module enriches SBOM components with lifecycle information by querying
//! the [endoflife.date](https://endoflife.date) API, which tracks release cycle
//! EOL dates for ~590 products.
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::enrichment::eol::{EolEnricher, EolClientConfig};
//!
//! let config = EolClientConfig::default();
//! let mut enricher = EolEnricher::new(config)?;
//! enricher.enrich_components(&mut components)?;
//! ```

mod client;
mod mapping;

pub use client::{EolClientConfig, EolEnricher, EolEnrichmentStats};
pub use mapping::ProductMapper;
