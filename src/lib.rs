//! sbom-tools: Semantic SBOM diff and analysis tool
//!
//! A format-agnostic SBOM comparison tool that provides semantic diff operations
//! for CycloneDX and SPDX SBOMs with enterprise-grade reporting.
//!
//! # Quick Start
//!
//! ```no_run
//! use sbom_tools::{parse_sbom, DiffEngine, FuzzyMatchConfig};
//! use std::path::Path;
//!
//! // Parse two SBOMs
//! let old = parse_sbom(Path::new("old.cdx.json")).unwrap();
//! let new = parse_sbom(Path::new("new.cdx.json")).unwrap();
//!
//! // Compute semantic diff
//! let engine = DiffEngine::new()
//!     .with_fuzzy_config(FuzzyMatchConfig::balanced());
//! let result = engine.diff(&old, &new).expect("diff failed");
//!
//! println!("Changes: {}", result.summary.total_changes);
//! ```

// Lint to discourage unwrap() in production code - prefer explicit error handling
#![warn(clippy::unwrap_used)]

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

// Re-export main types for convenience
pub use config::{AppConfig, AppConfigBuilder, ConfigPreset, EnrichmentConfig, TuiConfig};
pub use config::{
    BehaviorConfig, FilterConfig, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig,
    OutputConfig,
};
pub use config::{ConfigError, Validatable};
pub use config::{DiffConfig, MatrixConfig, MultiDiffConfig, TimelineConfig, ViewConfig};
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
pub use parsers::{parse_sbom, parse_sbom_str, SbomParser};
pub use quality::{QualityGrade, QualityReport, QualityScorer, ScoringProfile};
#[allow(deprecated)]
pub use reports::{ReportFormat, ReportGenerator, StreamingReporter, WriterReporter};

// TUI shared ViewModel exports for building custom TUI components
pub use tui::{
    CycleFilter, FilterState, ListNavigation, ListState, OverlayState, SearchState,
    SearchStateCore, StatusMessage, ViewModelOverlayKind,
};
