//! **A powerful library for working with Software Bills of Materials (SBOMs).**
//!
//! `sbom-tools` provides a comprehensive suite of tools for parsing, analyzing, diffing,
//! and enriching software bills of materials. It is designed to be a foundational library for
//! supply chain security, compliance, and dependency management workflows.
//!
//! The library supports common SBOM formats like **CycloneDX** and **SPDX** and normalizes them
//! into a unified, easy-to-use data model. It powers both a command-line interface (CLI)
//! for direct use and a Rust library for programmatic integration into your own applications.
//!
//! ## Key Features
//!
//! - **Multi-Format Parsing**: Ingests CycloneDX (JSON) and SPDX (JSON, Tag-Value) files,
//!   with automatic format detection.
//! - **Intelligent Diffing**: Performs semantic diffs between two SBOMs to identify changes
//!   in components, dependencies, licenses, and vulnerabilities.
//! - **Data Enrichment**: Augments SBOMs with external data, including:
//!   - **Vulnerability Information**: Fetches vulnerability data from the OSV (Open Source Vulnerability) database.
//!   - **End-of-Life (EOL) Status**: Checks components against the `endoflife.date` API to identify unsupported software.
//!   - More enrichers for staleness, KEV, etc.
//! - **Quality & Compliance Scoring**: Checks SBOMs for compliance against established standards
//!   like NTIA Minimum Elements and the EU Cyber Resilience Act (CRA).
//! - **Flexible Reporting**: Generates analysis reports in multiple formats, including JSON,
//!   Markdown, SARIF, and a full-featured interactive Terminal UI (TUI).
//!
//! ## Core Concepts & Modules
//!
//! The library is organized into several key modules:
//!
//! - **[`model`]**: Defines the central data structure, [`NormalizedSbom`]. Regardless of the input
//!   format (CycloneDX or SPDX), the library parses it into this unified model. This allows you to work with
//!   a consistent and predictable API for all your SBOM analysis tasks.
//! - **[`pipeline`]**: Contains the primary functions for processing SBOMs. You can use the functions
//!   in this module to construct a pipeline to parse, enrich, and generate reports in a single,
//!   streamlined operation.
//! - **[`diff`]**: Home of the [`DiffEngine`], which performs a semantic comparison of two `NormalizedSbom` objects.
//! - **[`enrichment`]**: Provides `Enricher` traits and implementations for augmenting SBOMs with external data.
//!   Requires the `enrichment` feature flag.
//! - **[`quality`]**: Contains the [`ComplianceChecker`] for validating SBOMs against standards and the
//!   [`QualityScorer`] for grading overall quality.
//! - **[`reports`]**: Includes generators for creating output reports in various formats.
//!
//! ## Getting Started: Parsing an SBOM
//!
//! The most common entry point is to parse an existing SBOM file using the [`pipeline`] module.
//! The library will automatically detect the format and return a [`NormalizedSbom`].
//!
//! ```no_run
//! use std::path::Path;
//! use sbom_tools::parse_sbom;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let sbom = parse_sbom(Path::new("path/to/your/sbom.json"))?;
//!
//!     println!(
//!         "Successfully parsed SBOM for '{}' with {} components.",
//!         sbom.document.name.unwrap_or_else(|| "Unknown".to_string()),
//!         sbom.components.len()
//!     );
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Examples
//!
//! Below are examples for other common use cases.
//!
//! ### Diffing Two SBOMs
//!
//! The [`DiffEngine`] identifies what has been added, removed, or modified between an "old"
//! and a "new" SBOM.
//!
//! ```no_run
//! use std::path::Path;
//! use sbom_tools::{parse_sbom, DiffEngine};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let old_sbom = parse_sbom(Path::new("path/to/old-sbom.json"))?;
//!     let new_sbom = parse_sbom(Path::new("path/to/new-sbom.json"))?;
//!
//!     let engine = DiffEngine::new();
//!     let diff = engine.diff(&old_sbom, &new_sbom)?;
//!
//!     println!("Components Added: {}", diff.components.added.len());
//!     println!("Components Removed: {}", diff.components.removed.len());
//!
//!     for added in &diff.components.added {
//!         println!("  + {} {}", added.name,
//!             added.new_version.as_deref().unwrap_or(""));
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Enriching with Vulnerability and End-of-Life (EOL) Data
//!
//! You can configure the processing pipeline to run enrichment stages. The following example
//! enables both OSV vulnerability scanning and EOL status checking.
//!
//! *Note: This requires the `enrichment` feature flag to be enabled.*
//!
//! ```ignore
//! use sbom_tools::parse_sbom;
//! use sbom_tools::model::EolStatus;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut sbom = parse_sbom("path/to/your/sbom.json")?;
//!
//!     // Enrich with OSV vulnerability data (requires `enrichment` feature)
//!     #[cfg(feature = "enrichment")]
//!     {
//!         use sbom_tools::{OsvEnricher, OsvEnricherConfig, VulnerabilityEnricher};
//!         let enricher = OsvEnricher::new(OsvEnricherConfig::default());
//!         enricher.enrich(&mut sbom)?;
//!     }
//!
//!     println!("--- Vulnerability and EOL Report ---");
//!     for component in sbom.components.values() {
//!         if !component.vulnerabilities.is_empty() {
//!             println!("\n[!] Component '{}' has {} vulnerabilities:",
//!                 component.name, component.vulnerabilities.len());
//!             for vuln in &component.vulnerabilities {
//!                 println!("    - {}: {}", vuln.id,
//!                     vuln.summary.as_deref().unwrap_or("No summary"));
//!             }
//!         }
//!
//!         if let Some(eol_info) = &component.eol {
//!             if eol_info.status == EolStatus::EndOfLife {
//!                 println!("\n[!] Component '{}' has reached End-of-Life!",
//!                     component.name);
//!                 println!("    - Product: {}", eol_info.product);
//!                 if let Some(eol_date) = eol_info.eol_date {
//!                     println!("    - EOL Date: {}", eol_date);
//!                 }
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Checking for Compliance
//!
//! The [`ComplianceChecker`] validates an SBOM against a specific standard, such as the
//! EU Cyber Resilience Act (CRA).
//!
//! ```no_run
//! use std::path::Path;
//! use sbom_tools::parse_sbom;
//! use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let sbom = parse_sbom(Path::new("path/to/your/sbom.json"))?;
//!
//!     // Check against the EU CRA Phase 2 requirements
//!     let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
//!     let result = checker.check(&sbom);
//!
//!     if result.is_compliant {
//!         println!("SBOM is compliant with {}.", result.level.name());
//!     } else {
//!         println!("SBOM is NOT compliant with {}. Found {} errors and {} warnings.",
//!             result.level.name(),
//!             result.error_count,
//!             result.warning_count
//!         );
//!
//!         for violation in result.violations {
//!             println!("[{:?}] {}: {}",
//!                 violation.severity, violation.category.name(), violation.message);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! `sbom-tools` uses feature flags to manage optional functionality and dependencies.
//! - `enrichment`: Enables all data enrichment modules, such as OSV and EOL lookups.
//!   This adds network dependencies like `reqwest`.
//!
//! ## Command-Line Interface (CLI)
//!
//! This documentation is for the `sbom-tools` library crate. If you are looking for the
//! command-line tool, please refer to the project's README or install it via `cargo install sbom-tools`.

// Lint to discourage unwrap() in production code - prefer explicit error handling
#![warn(clippy::unwrap_used)]
// Pedantic lints: allow categories that are design choices for this codebase
#![allow(
    // Cast safety: usize↔f64/f32/u16/i32 casts are pervasive in TUI layout math
    // and statistical calculations — all values are bounded in practice
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    // Doc completeness: # Errors / # Panics sections are aspirational for 78+15 fns
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    // TUI render functions are inherently long — splitting hurts readability
    clippy::too_many_lines,
    // State structs legitimately use many bools for toggle flags
    clippy::struct_excessive_bools,
    clippy::fn_params_excessive_bools,
    // self is kept for API consistency / future use across trait-like impls
    clippy::unused_self,
    // Variable names like `min`/`mid` or `old`/`new` are clear in context
    clippy::similar_names
)]

pub mod cli;
pub mod config;
pub mod diff;
#[cfg(feature = "enrichment")]
pub mod enrichment;
pub mod error;
pub mod matching;
pub mod model;
pub mod parsers;
pub mod pipeline;
pub mod quality;
pub mod reports;
pub mod tui;
pub mod utils;
pub mod watch;

// Re-export main types for convenience
pub use config::{AppConfig, AppConfigBuilder, ConfigPreset, EnrichmentConfig, TuiConfig};
pub use config::{
    BehaviorConfig, FilterConfig, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig,
    OutputConfig,
};
pub use config::{ConfigError, Validatable};
pub use config::{
    DiffConfig, MatrixConfig, MultiDiffConfig, QueryConfig, TimelineConfig, ViewConfig,
};
pub use diff::{DiffEngine, DiffResult, GraphDiffConfig};
#[cfg(feature = "enrichment")]
pub use enrichment::{
    EnricherConfig, EnrichmentStats, NoOpEnricher, OsvEnricher, OsvEnricherConfig,
    VulnerabilityEnricher,
};
pub use error::{ErrorContext, OptionContext, Result, SbomDiffError};
pub use matching::{
    ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher, MatchResult, MatchTier, MatchingRulesConfig,
    RuleEngine,
};
pub use model::{
    CanonicalId, Component, ComponentSortKey, NormalizedSbom, NormalizedSbomIndex, SbomIndexBuilder,
};
pub use parsers::{SbomParser, parse_sbom, parse_sbom_str};
pub use quality::{QualityGrade, QualityReport, QualityScorer, ScoringProfile};
#[allow(deprecated)]
pub use reports::{ReportFormat, ReportGenerator, StreamingReporter, WriterReporter};

// TUI shared ViewModel exports for building custom TUI components
pub use tui::{
    CycleFilter, FilterState, ListNavigation, ListState, OverlayState, SearchState,
    SearchStateCore, StatusMessage, ViewModelOverlayKind,
};
