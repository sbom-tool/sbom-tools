//! Semantic diff engine for SBOMs.
//!
//! This module implements a graph-based semantic diff algorithm inspired by
//! difftastic, adapted for SBOM comparison.
//!
//! # Architecture
//!
//! The diff system is built on traits for extensibility:
//!
//! - [`ChangeComputer`](traits::ChangeComputer): Trait for computing specific types of changes
//! - Individual change computers in the [`changes`] module
//!
//! # Performance Features
//!
//! - **Incremental Diffing**: Cache results and recompute only changed sections
//! - **Batch Candidate Generation**: Use LSH + cross-ecosystem for large SBOMs
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::diff::{DiffEngine, changes::ComponentChangeComputer};
//!
//! let engine = DiffEngine::new();
//! let result = engine.diff(&old_sbom, &new_sbom);
//!
//! // For repeated diffs, use the incremental engine:
//! use sbom_tools::diff::IncrementalDiffEngine;
//! let incremental = IncrementalDiffEngine::new(engine);
//! let result = incremental.diff(&old, &new);
//! if result.was_cached() {
//!     println!("Cache hit!");
//! }
//! ```

pub mod changes;
mod cost;
mod engine;
mod engine_config;
mod engine_matching;
mod engine_rules;
pub mod graph;
pub mod incremental;
pub mod multi;
mod multi_engine;
mod result;
pub mod traits;
mod vertex;

pub use cost::CostModel;
pub use engine::{DiffEngine, LargeSbomConfig};
pub use graph::{diff_dependency_graph, GraphDiffConfig};
pub use incremental::{
    CacheHitType, CacheStats, ChangedSections, DiffCache, DiffCacheConfig, DiffCacheKey,
    IncrementalDiffEngine, IncrementalDiffResult, SectionHashes,
};
pub use multi::{
    ComparisonResult, ComplianceScoreEntry, ComplianceSnapshot, ComponentEvolution,
    DependencySnapshot, DivergenceType, DivergentComponent, EvolutionSummary,
    InconsistentComponent, IncrementalChange, LicenseChange as TimelineLicenseChange,
    LicenseChangeType, MatrixResult, MultiDiffResult, MultiDiffSummary, SbomCluster,
    SbomClustering, SbomInfo, SecurityImpact, TimelineResult, VariableComponent, VersionAtPoint,
    VersionChangeType, VersionSpread, VulnerabilityMatrix, VulnerabilitySnapshot,
};
pub use multi_engine::MultiDiffEngine;
pub use result::{
    ChangeSet, ChangeType, ComponentChange, ComponentLicenseChange, ConfidenceInterval,
    DependencyChange, DependencyChangeType, DependencyGraphChange, DiffResult, DiffSummary,
    FieldChange, GraphChangeImpact, GraphChangeSummary, GraphChangesByImpact, LicenseChange,
    LicenseChanges, LicenseConflict, MatchInfo, MatchScoreComponent, SlaStatus,
    VulnerabilityChanges, VulnerabilityDetail,
};
pub use traits::{
    ChangeComputer, ComponentChangeSet, ComponentMatches, DependencyChangeSet, LicenseChangeSet,
    VulnerabilityChangeSet,
};
pub use vertex::DiffVertex;
