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
    Applicability, CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, COMPLIANCE_SARIF_RULE_IDS,
    ClassCheck, ComplianceChecker, ComplianceLevel, ComplianceResult, ConformityAssessmentSummary,
    ConformityEvidence, CraPhase, EO14028_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS, FSCT_SARIF_RULE_IDS,
    FieldAdvice, FormatAdvice, NTIA_SARIF_RULE_IDS, PASS_RULE_IDS, PCIDSS_SARIF_RULE_IDS,
    PQC_SARIF_RULE_IDS, PassedCheck, RemediationFormat, RuleKind, RuleMeta, SSDF_SARIF_RULE_IDS,
    StandardKind, StandardRef, StandardSelector, Violation, ViolationCategory, ViolationCounts,
    ViolationSeverity, all_rule_ids, generic_rule_id_for_level, rule_kind, rule_meta,
};
pub use compliance::{
    DOCUMENT_SUBJECT, FINDING_ID_PREFIX, FindingIdentity, finding_id, finding_key, finding_subject,
    standard_key,
};
pub use metrics::{
    AuditabilityMetrics, CompletenessMetrics, ComplexityFactors, ComplexityLevel,
    CryptographyMetrics, DependencyMetrics, HashQualityMetrics, IdentifierMetrics, LicenseMetrics,
    LifecycleMetrics, ProvenanceMetrics, VulnerabilityMetrics,
};
pub use scorer::{
    AiCheck, AiReadinessMetrics, QualityGrade, QualityReport, QualityScorer, Recommendation,
    RecommendationCategory, SCORING_ENGINE_VERSION, ScoringProfile,
};
