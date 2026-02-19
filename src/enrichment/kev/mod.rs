//! CISA Known Exploited Vulnerabilities (KEV) catalog enrichment.
//!
//! This module provides functionality to enrich vulnerability data with
//! information from CISA's KEV catalog, which tracks actively exploited
//! vulnerabilities that require urgent remediation.
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::enrichment::kev::{KevClient, KevClientConfig};
//!
//! let mut client = KevClient::with_defaults();
//! let catalog = client.load_catalog()?;
//!
//! // Check if a CVE is in the KEV catalog
//! if catalog.contains("CVE-2024-1234") {
//!     println!("This CVE is actively exploited!");
//! }
//! ```

mod catalog;
mod client;

pub use catalog::{KevCatalog, KevCatalogResponse, KevEntry, KevVulnerability};
pub use client::{KEV_CATALOG_URL, KevClient, KevClientConfig, KevEnrichmentStats};
