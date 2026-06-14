//! Vulnerability enrichment module.
//!
//! This module provides functionality to enrich SBOM components with vulnerability
//! information from external sources like OSV (Open Source Vulnerabilities).
//!
//! # Example
//!
//! ```no_run
//! use sbom_tools::enrichment::{OsvEnricher, OsvEnricherConfig, VulnerabilityEnricher};
//! use sbom_tools::model::NormalizedSbom;
//!
//! let config = OsvEnricherConfig::default();
//! let enricher = OsvEnricher::new(config).unwrap();
//!
//! // Enrich a mutable SBOM's components
//! // let stats = enricher.enrich(&mut components).unwrap();
//! ```

mod cache;
pub mod eol;
pub mod kev;
pub mod osv;
pub mod source;
pub mod staleness;
mod stats;
mod traits;
pub mod vex;

pub use cache::{CacheKey, FileCache};
pub use eol::{EolClientConfig, EolEnricher, EolEnrichmentStats};
pub use kev::{KevCatalog, KevClient, KevClientConfig, KevEnrichmentStats};
pub use osv::{OsvEnricher, OsvEnricherConfig};
pub use source::{CacheStats, EnrichmentSource, JsonCache};
pub use staleness::{RegistryConfig, StalenessEnricher, StalenessEnrichmentStats};
pub use stats::{EnrichmentError, EnrichmentStats};
pub use traits::{NoOpEnricher, VulnerabilityEnricher};
pub use vex::{VexEnricher, VexEnrichmentStats};

use std::path::PathBuf;
use std::time::Duration;

/// Global enrichment configuration
#[derive(Debug, Clone)]
pub struct EnricherConfig {
    /// Enable OSV enrichment
    pub enable_osv: bool,
    /// Enable KEV (Known Exploited Vulnerabilities) enrichment
    pub enable_kev: bool,
    /// Enable staleness enrichment
    pub enable_staleness: bool,
    /// Enable end-of-life detection
    pub enable_eol: bool,
    /// Cache directory for vulnerability data
    pub cache_dir: PathBuf,
    /// Cache TTL
    pub cache_ttl: Duration,
    /// Bypass cache and fetch fresh data
    pub bypass_cache: bool,
    /// API timeout
    pub timeout: Duration,
    /// Staleness threshold in days (default: 365)
    pub stale_threshold_days: u32,
}

impl Default for EnricherConfig {
    fn default() -> Self {
        Self {
            enable_osv: true,
            enable_kev: true,
            enable_staleness: false, // Off by default (requires registry API calls)
            enable_eol: false,       // Off by default (requires API calls)
            cache_dir: default_cache_dir(),
            cache_ttl: Duration::from_secs(24 * 3600), // 24 hours
            bypass_cache: false,
            timeout: Duration::from_secs(30),
            stale_threshold_days: 365,
        }
    }
}

/// Get the default cache directory.
fn default_cache_dir() -> PathBuf {
    source::namespaced_cache_dir("osv")
}
