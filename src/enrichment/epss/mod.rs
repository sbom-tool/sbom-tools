//! FIRST EPSS (Exploit Prediction Scoring System) enrichment.
//!
//! This module enriches vulnerability data with EPSS scores from FIRST's daily
//! bulk dataset. Each CVE is assigned a probability (0..1) that it will be
//! exploited in the wild over the next 30 days, plus a percentile rank — a key
//! triage signal alongside the CISA KEV "actively exploited" flag.
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::enrichment::epss::EpssClient;
//!
//! let mut client = EpssClient::with_defaults();
//! client.load_scores()?;
//!
//! if let Some(entry) = client.scores().and_then(|s| s.get("CVE-2024-1234")) {
//!     println!("Exploit probability: {:.2}%", entry.score * 100.0);
//! }
//! ```

mod client;
mod scores;

pub use client::{EPSS_SCORES_URL, EpssClient, EpssClientConfig, EpssEnrichmentStats};
pub use scores::{EpssEntry, EpssScores};
