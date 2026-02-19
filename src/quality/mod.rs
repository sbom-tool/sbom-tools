//! SBOM Quality Score module.
//!
//! Provides comprehensive quality assessment for SBOMs based on completeness,
//! compliance, and best practices. Supports different scoring profiles for
//! various use cases.
//!
//! # Features
//!
//! - **Completeness scoring**: Measures how many recommended fields are populated
//! - **Compliance checking**: Validates against format requirements (CycloneDX/SPDX)
//! - **Best practice validation**: Checks for PURLs, licensing, supplier info, etc.
//! - **Actionable recommendations**: Provides specific improvement suggestions
//!
//! # Usage
//!
//! ```no_run
//! use sbom_tools::quality::{QualityScorer, ScoringProfile};
//! use sbom_tools::parsers::parse_sbom;
//! use std::path::Path;
//!
//! let sbom = parse_sbom(Path::new("sbom.json")).unwrap();
//! let scorer = QualityScorer::new(ScoringProfile::Standard);
//! let report = scorer.score(&sbom);
//!
//! println!("Overall score: {}/100", report.overall_score);
//! for rec in report.recommendations {
//!     println!("- {}: {}", rec.category.name(), rec.message);
//! }
//! ```

mod compliance;
mod metrics;
mod scorer;

pub use compliance::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, Violation, ViolationCategory,
    ViolationSeverity,
};
pub use metrics::{
    AuditabilityMetrics, CompletenessMetrics, DependencyMetrics, HashQualityMetrics,
    IdentifierMetrics, LicenseMetrics, LifecycleMetrics, ProvenanceMetrics, VulnerabilityMetrics,
};
pub use scorer::{
    QualityGrade, QualityReport, QualityScorer, Recommendation, RecommendationCategory,
    SCORING_ENGINE_VERSION, ScoringProfile,
};
