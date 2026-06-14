//! SBOM Quality Scorer.
//!
//! Main scoring engine that combines metrics and compliance checking
//! into an overall quality assessment.

use crate::model::{CompletenessDeclaration, NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::compliance::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use super::metrics::{
    AuditabilityMetrics, CompletenessMetrics, CompletenessWeights, CryptographyMetrics,
    DependencyMetrics, HashQualityMetrics, IdentifierMetrics, LicenseMetrics, LifecycleMetrics,
    ProvenanceMetrics, VulnerabilityMetrics,
};

/// Quality scoring engine version
pub const SCORING_ENGINE_VERSION: &str = "2.1";

/// Returns true if any of the JSON pointers resolves to a non-empty value in `raw`.
/// Used by the AI-readiness profile to inspect model-card fields preserved in
/// `Component.extensions.raw` that are not surfaced into the typed model.
fn has_non_empty_pointer(raw: Option<&Value>, pointers: &[&str]) -> bool {
    pointers
        .iter()
        .filter_map(|pointer| raw.and_then(|value| value.pointer(pointer)))
        .any(|value| match value {
            Value::Null => false,
            Value::Array(items) => !items.is_empty(),
            Value::Object(entries) => !entries.is_empty(),
            Value::String(text) => !text.trim().is_empty(),
            _ => true,
        })
}

/// Scoring profile determines weights and thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ScoringProfile {
    /// Minimal requirements - basic identification
    Minimal,
    /// Standard requirements - recommended for most use cases
    Standard,
    /// Security-focused - emphasizes vulnerability info and supply chain
    Security,
    /// License-focused - emphasizes license compliance
    LicenseCompliance,
    /// EU Cyber Resilience Act - emphasizes supply chain transparency and security disclosure
    Cra,
    /// BSI TR-03183-2 (German national CRA-aligned SBOM technical guideline).
    /// Stricter than CRA on hashes and identifiers; uses CRA-style weights.
    BsiTr03183_2,
    /// Comprehensive - all aspects equally weighted
    Comprehensive,
    /// CBOM - cryptographic BOM focus (algorithm strength, PQC readiness, key/cert lifecycle)
    Cbom,
    /// AI/ML readiness - evaluates model-card completeness for machine-learning components
    AiReadiness,
}

impl ScoringProfile {
    /// Get the compliance level associated with this profile
    #[must_use]
    pub const fn compliance_level(&self) -> ComplianceLevel {
        match self {
            Self::Minimal => ComplianceLevel::Minimum,
            Self::Standard | Self::LicenseCompliance => ComplianceLevel::Standard,
            Self::Security => ComplianceLevel::NtiaMinimum,
            Self::Cra => ComplianceLevel::CraPhase2,
            Self::BsiTr03183_2 => ComplianceLevel::BsiTr03183_2,
            Self::Comprehensive => ComplianceLevel::Comprehensive,
            Self::Cbom => ComplianceLevel::Comprehensive,
            Self::AiReadiness => ComplianceLevel::Comprehensive,
        }
    }

    /// Get weights for this profile
    ///
    /// All weights sum to 1.0. The lifecycle weight is applied only when
    /// enrichment data is available; otherwise it is redistributed.
    const fn weights(self) -> ScoringWeights {
        match self {
            Self::Minimal => ScoringWeights {
                completeness: 0.35,
                identifiers: 0.20,
                licenses: 0.10,
                vulnerabilities: 0.05,
                dependencies: 0.10,
                integrity: 0.05,
                provenance: 0.10,
                lifecycle: 0.05,
            },
            Self::Standard => ScoringWeights {
                completeness: 0.25,
                identifiers: 0.20,
                licenses: 0.12,
                vulnerabilities: 0.08,
                dependencies: 0.10,
                integrity: 0.08,
                provenance: 0.10,
                lifecycle: 0.07,
            },
            Self::Security => ScoringWeights {
                completeness: 0.12,
                identifiers: 0.18,
                licenses: 0.05,
                vulnerabilities: 0.20,
                dependencies: 0.10,
                integrity: 0.15,
                provenance: 0.10,
                lifecycle: 0.10,
            },
            Self::LicenseCompliance => ScoringWeights {
                completeness: 0.15,
                identifiers: 0.12,
                licenses: 0.35,
                vulnerabilities: 0.05,
                dependencies: 0.10,
                integrity: 0.05,
                provenance: 0.10,
                lifecycle: 0.08,
            },
            Self::Cra => ScoringWeights {
                completeness: 0.12,
                identifiers: 0.18,
                licenses: 0.08,
                vulnerabilities: 0.15,
                dependencies: 0.12,
                integrity: 0.12,
                provenance: 0.15,
                lifecycle: 0.08,
            },
            // BSI TR-03183-2 emphasises identifiers and integrity (mandatory hashes)
            // even more than CRA, while still tracking provenance/dependencies.
            Self::BsiTr03183_2 => ScoringWeights {
                completeness: 0.10,
                identifiers: 0.22,
                licenses: 0.08,
                vulnerabilities: 0.10,
                dependencies: 0.12,
                integrity: 0.18,
                provenance: 0.12,
                lifecycle: 0.08,
            },
            Self::Comprehensive => ScoringWeights {
                completeness: 0.15,
                identifiers: 0.13,
                licenses: 0.13,
                vulnerabilities: 0.10,
                dependencies: 0.12,
                integrity: 0.12,
                provenance: 0.13,
                lifecycle: 0.12,
            },
            // CBOM slots are reinterpreted:
            // completeness->CryptoCompl, identifiers->OIDs, licenses->AlgoStrength,
            // vulnerabilities->CryptoRefs, dependencies->CryptoLifecycle,
            // integrity->PQCReadiness, provenance->Provenance(std), lifecycle->Licenses(std)
            Self::Cbom => ScoringWeights {
                completeness: 0.15,
                identifiers: 0.15,
                licenses: 0.22,
                vulnerabilities: 0.10,
                dependencies: 0.13,
                integrity: 0.15,
                provenance: 0.08,
                lifecycle: 0.02,
            },
            // AiReadiness uses a dedicated scoring path; these weights are only a
            // structural fallback and are never reached in normal execution.
            Self::AiReadiness => ScoringWeights {
                completeness: 0.25,
                identifiers: 0.15,
                licenses: 0.15,
                vulnerabilities: 0.10,
                dependencies: 0.10,
                integrity: 0.08,
                provenance: 0.10,
                lifecycle: 0.07,
            },
        }
    }
}

/// Weights for overall score calculation (sum to 1.0)
#[derive(Debug, Clone)]
struct ScoringWeights {
    completeness: f32,
    identifiers: f32,
    licenses: f32,
    vulnerabilities: f32,
    dependencies: f32,
    integrity: f32,
    provenance: f32,
    lifecycle: f32,
}

impl ScoringWeights {
    /// Return weights as an array for iteration
    fn as_array(&self) -> [f32; 8] {
        [
            self.completeness,
            self.identifiers,
            self.licenses,
            self.vulnerabilities,
            self.dependencies,
            self.integrity,
            self.provenance,
            self.lifecycle,
        ]
    }

    /// Renormalize weights, excluding categories marked as N/A.
    ///
    /// When a category has no applicable data (e.g., lifecycle without
    /// enrichment), its weight is proportionally redistributed.
    fn renormalize(&self, available: &[bool; 8]) -> [f32; 8] {
        let raw = self.as_array();
        let total_available: f32 = raw
            .iter()
            .zip(available)
            .filter(|&(_, a)| *a)
            .map(|(w, _)| w)
            .sum();

        if total_available <= 0.0 {
            return [0.0; 8];
        }

        let scale = 1.0 / total_available;
        let mut result = [0.0_f32; 8];
        for (i, (&w, &avail)) in raw.iter().zip(available).enumerate() {
            result[i] = if avail { w * scale } else { 0.0 };
        }
        result
    }
}

/// Quality grade based on score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QualityGrade {
    /// Excellent: 90-100
    A,
    /// Good: 80-89
    B,
    /// Fair: 70-79
    C,
    /// Poor: 60-69
    D,
    /// Failing: <60
    F,
}

impl QualityGrade {
    /// Create grade from score
    #[must_use]
    pub const fn from_score(score: f32) -> Self {
        // Guard against NaN (all comparisons return false) and out-of-range values
        let clamped = if score > 100.0 {
            100
        } else if score >= 0.0 {
            score as u32
        } else {
            0
        };
        match clamped {
            90..=100 => Self::A,
            80..=89 => Self::B,
            70..=79 => Self::C,
            60..=69 => Self::D,
            _ => Self::F,
        }
    }

    /// Get grade letter
    #[must_use]
    pub const fn letter(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }

    /// Get grade description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::A => "Excellent",
            Self::B => "Good",
            Self::C => "Fair",
            Self::D => "Poor",
            Self::F => "Failing",
        }
    }
}

/// Recommendation for improving quality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority (1 = highest, 5 = lowest)
    pub priority: u8,
    /// Category of the recommendation
    pub category: RecommendationCategory,
    /// Human-readable message
    pub message: String,
    /// Estimated impact on score (0-100)
    pub impact: f32,
    /// Affected components (if applicable)
    pub affected_count: usize,
}

/// Single AI-readiness check result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AiCheck {
    /// Machine-readable ID, e.g. "AI-001"
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Whether the check passed for every ML component
    pub passed: bool,
    /// Optional detail message (per-component pass/fail)
    pub detail: Option<String>,
    /// Relative weight of this check (0.0–1.0)
    pub weight: f32,
}

/// AI/ML model-card completeness metrics (populated only for the `AiReadiness` profile)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AiReadinessMetrics {
    /// Number of ML model components found
    pub ml_component_count: usize,
    /// True when no ML components were found — the score is N/A
    pub not_applicable: bool,
    /// Human-readable reason for N/A (when `not_applicable` is true)
    pub na_reason: Option<String>,
    /// Per-check results
    pub checks: Vec<AiCheck>,
    /// Number of ML components that passed every check
    pub components_fully_documented: usize,
}

impl AiReadinessMetrics {
    /// Whether AI readiness is not applicable to this SBOM (no ML components).
    #[must_use]
    pub const fn is_not_applicable(&self) -> bool {
        self.not_applicable
    }
}

/// Category for recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RecommendationCategory {
    Completeness,
    Identifiers,
    Licenses,
    Vulnerabilities,
    Dependencies,
    Compliance,
    Integrity,
    Provenance,
    Lifecycle,
}

impl RecommendationCategory {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Completeness => "Completeness",
            Self::Identifiers => "Identifiers",
            Self::Licenses => "Licenses",
            Self::Vulnerabilities => "Vulnerabilities",
            Self::Dependencies => "Dependencies",
            Self::Compliance => "Compliance",
            Self::Integrity => "Integrity",
            Self::Provenance => "Provenance",
            Self::Lifecycle => "Lifecycle",
        }
    }
}

/// Complete quality report for an SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub struct QualityReport {
    /// Scoring engine version
    pub scoring_engine_version: String,
    /// Overall score (0-100)
    pub overall_score: f32,
    /// Overall grade
    pub grade: QualityGrade,
    /// Scoring profile used
    pub profile: ScoringProfile,

    // Individual category scores (0-100)
    /// Completeness score
    pub completeness_score: f32,
    /// Identifier quality score
    pub identifier_score: f32,
    /// License quality score
    pub license_score: f32,
    /// Vulnerability documentation score (`None` if no vulnerability data)
    pub vulnerability_score: Option<f32>,
    /// Dependency graph quality score
    pub dependency_score: f32,
    /// Hash/integrity quality score
    pub integrity_score: f32,
    /// Provenance quality score (combined provenance + auditability)
    pub provenance_score: f32,
    /// Lifecycle quality score (`None` if no enrichment data)
    pub lifecycle_score: Option<f32>,

    // Detailed metrics
    /// Detailed completeness metrics
    pub completeness_metrics: CompletenessMetrics,
    /// Detailed identifier metrics
    pub identifier_metrics: IdentifierMetrics,
    /// Detailed license metrics
    pub license_metrics: LicenseMetrics,
    /// Detailed vulnerability metrics
    pub vulnerability_metrics: VulnerabilityMetrics,
    /// Detailed dependency metrics
    pub dependency_metrics: DependencyMetrics,
    /// Hash/integrity metrics
    pub hash_quality_metrics: HashQualityMetrics,
    /// Provenance metrics
    pub provenance_metrics: ProvenanceMetrics,
    /// Auditability metrics
    pub auditability_metrics: AuditabilityMetrics,
    /// Lifecycle metrics (enrichment-dependent)
    pub lifecycle_metrics: LifecycleMetrics,
    /// Cryptography quality score (`None` if no crypto components)
    pub cryptography_score: Option<f32>,
    /// Cryptography metrics (CBOM)
    pub cryptography_metrics: CryptographyMetrics,

    /// Compliance check result
    pub compliance: ComplianceResult,
    /// Prioritized recommendations
    pub recommendations: Vec<Recommendation>,
    /// AI/ML readiness metrics (`Some` only when profile is `AiReadiness`)
    pub ai_readiness_metrics: Option<AiReadinessMetrics>,
}

/// Quality scorer for SBOMs
#[derive(Debug, Clone)]
pub struct QualityScorer {
    /// Scoring profile
    profile: ScoringProfile,
    /// Completeness weights
    completeness_weights: CompletenessWeights,
    /// Optional CRA sidecar metadata; when set, the embedded compliance check
    /// (used to drive recommendations under `ScoringProfile::Cra`) consults
    /// the sidecar for fields the SBOM doesn't carry.
    cra_sidecar: Option<crate::model::CraSidecarMetadata>,
    /// Optional CRA Annex III/IV product class. Sidecar `productClass` (when
    /// present on `cra_sidecar`) wins over this value at check time.
    cra_product_class: Option<crate::model::CraProductClass>,
}

impl QualityScorer {
    /// Create a new quality scorer with the given profile
    #[must_use]
    pub fn new(profile: ScoringProfile) -> Self {
        Self {
            profile,
            completeness_weights: CompletenessWeights::default(),
            cra_sidecar: None,
            cra_product_class: None,
        }
    }

    /// Set custom completeness weights
    #[must_use]
    pub const fn with_completeness_weights(mut self, weights: CompletenessWeights) -> Self {
        self.completeness_weights = weights;
        self
    }

    /// Attach CRA sidecar metadata for the embedded compliance check.
    #[must_use]
    pub fn with_cra_sidecar(mut self, sidecar: crate::model::CraSidecarMetadata) -> Self {
        self.cra_sidecar = Some(sidecar);
        self
    }

    /// Set the CRA Annex III/IV product class explicitly (for severity
    /// calibration when the embedded compliance check runs under
    /// `ScoringProfile::Cra`). Sidecar `productClass` overrides this.
    #[must_use]
    pub const fn with_cra_product_class(mut self, class: crate::model::CraProductClass) -> Self {
        self.cra_product_class = Some(class);
        self
    }

    /// Score an SBOM
    pub fn score(&self, sbom: &NormalizedSbom) -> QualityReport {
        // AI readiness uses a dedicated scoring path that is incompatible with the
        // standard 8-category pipeline.
        if self.profile == ScoringProfile::AiReadiness {
            return self.score_ai_readiness(sbom);
        }

        let total_components = sbom.components.len();
        let is_cyclonedx = sbom.document.format == SbomFormat::CycloneDx;

        // Calculate all metrics
        let completeness_metrics = CompletenessMetrics::from_sbom(sbom);
        let identifier_metrics = IdentifierMetrics::from_sbom(sbom);
        let license_metrics = LicenseMetrics::from_sbom(sbom);
        let vulnerability_metrics = VulnerabilityMetrics::from_sbom(sbom);
        let dependency_metrics = DependencyMetrics::from_sbom(sbom);
        let hash_quality_metrics = HashQualityMetrics::from_sbom(sbom);
        let provenance_metrics = ProvenanceMetrics::from_sbom(sbom);
        let auditability_metrics = AuditabilityMetrics::from_sbom(sbom);
        let lifecycle_metrics = LifecycleMetrics::from_sbom(sbom);
        let cryptography_metrics = CryptographyMetrics::from_sbom(sbom);

        // Calculate individual category scores
        let completeness_score = completeness_metrics.overall_score(&self.completeness_weights);
        let identifier_score = identifier_metrics.quality_score(total_components);
        let license_score = license_metrics.quality_score(total_components);
        let vulnerability_score = vulnerability_metrics.documentation_score();
        let dependency_score = dependency_metrics.quality_score(total_components);
        let integrity_score = hash_quality_metrics.quality_score(total_components);
        let provenance_raw = provenance_metrics.quality_score(is_cyclonedx);
        let auditability_raw = auditability_metrics.quality_score(total_components);
        // Combine provenance and auditability (60/40 split)
        let provenance_score = provenance_raw * 0.6 + auditability_raw * 0.4;
        let lifecycle_score = lifecycle_metrics.quality_score();
        let cryptography_score = cryptography_metrics.quality_score();

        // For CBOM profile, substitute crypto-specific scores into the 8 slots
        let is_cbom = self.profile == ScoringProfile::Cbom;
        let (available, scores) = if is_cbom && cryptography_metrics.has_data() {
            let cm = &cryptography_metrics;
            (
                [true; 8], // all categories available for CBOM
                [
                    cm.crypto_completeness_score(), // slot 1: Crpt
                    cm.crypto_identifier_score(),   // slot 2: OIDs
                    cm.algorithm_strength_score(),  // slot 3: Algo
                    cm.crypto_dependency_score(),   // slot 4: Refs
                    cm.crypto_lifecycle_score(),    // slot 5: Life
                    cm.pqc_readiness_score(),       // slot 6: PQC
                    provenance_score,               // slot 7: Prov (standard)
                    license_score,                  // slot 8: Lic  (standard)
                ],
            )
        } else {
            // Standard SBOM scoring
            let vuln_available = vulnerability_score.is_some();
            let lifecycle_available = lifecycle_score.is_some();
            (
                [
                    true,                // completeness
                    true,                // identifiers
                    true,                // licenses
                    vuln_available,      // vulnerabilities
                    true,                // dependencies
                    true,                // integrity
                    true,                // provenance
                    lifecycle_available, // lifecycle
                ],
                [
                    completeness_score,
                    identifier_score,
                    license_score,
                    vulnerability_score.unwrap_or(0.0),
                    dependency_score,
                    integrity_score,
                    provenance_score,
                    lifecycle_score.unwrap_or(0.0),
                ],
            )
        };

        // Calculate weighted overall score with N/A renormalization
        let weights = self.profile.weights();
        let norm = weights.renormalize(&available);

        let mut overall_score: f32 = scores.iter().zip(norm.iter()).map(|(s, w)| s * w).sum();
        overall_score = overall_score.min(100.0);

        // Apply hard penalty caps for critical issues
        overall_score = self.apply_score_caps(
            overall_score,
            &lifecycle_metrics,
            &dependency_metrics,
            &hash_quality_metrics,
            &cryptography_metrics,
            total_components,
        );

        // Run compliance check (with sidecar + product class if configured)
        let mut compliance_checker = ComplianceChecker::new(self.profile.compliance_level());
        if let Some(sc) = self.cra_sidecar.clone() {
            compliance_checker = compliance_checker.with_sidecar(sc);
        }
        if let Some(c) = self.cra_product_class {
            compliance_checker = compliance_checker.with_product_class(c);
        }
        let compliance = compliance_checker.check(sbom);

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &completeness_metrics,
            &identifier_metrics,
            &license_metrics,
            &dependency_metrics,
            &hash_quality_metrics,
            &provenance_metrics,
            &lifecycle_metrics,
            &compliance,
            total_components,
        );

        QualityReport {
            scoring_engine_version: SCORING_ENGINE_VERSION.to_string(),
            overall_score,
            grade: QualityGrade::from_score(overall_score),
            profile: self.profile,
            completeness_score,
            identifier_score,
            license_score,
            vulnerability_score,
            dependency_score,
            integrity_score,
            provenance_score,
            lifecycle_score,
            completeness_metrics,
            identifier_metrics,
            license_metrics,
            vulnerability_metrics,
            dependency_metrics,
            hash_quality_metrics,
            provenance_metrics,
            auditability_metrics,
            lifecycle_metrics,
            cryptography_score,
            cryptography_metrics,
            compliance,
            recommendations,
            ai_readiness_metrics: None,
        }
    }

    /// Score ML model-card completeness for the AI-readiness profile.
    ///
    /// Filters to `MachineLearningModel` components and evaluates nine model-card
    /// checks (AI-001..AI-009). The returned `QualityReport` has all standard
    /// category scores zeroed/`None`; the rich data lives in `ai_readiness_metrics`.
    /// When the SBOM has no ML components the report is marked not-applicable.
    fn score_ai_readiness(&self, sbom: &NormalizedSbom) -> QualityReport {
        use crate::model::ComponentType;

        // Standard metrics are still computed so the report is structurally valid.
        let completeness_metrics = CompletenessMetrics::from_sbom(sbom);
        let identifier_metrics = IdentifierMetrics::from_sbom(sbom);
        let license_metrics = LicenseMetrics::from_sbom(sbom);
        let vulnerability_metrics = VulnerabilityMetrics::from_sbom(sbom);
        let dependency_metrics = DependencyMetrics::from_sbom(sbom);
        let hash_quality_metrics = HashQualityMetrics::from_sbom(sbom);
        let provenance_metrics = ProvenanceMetrics::from_sbom(sbom);
        let auditability_metrics = AuditabilityMetrics::from_sbom(sbom);
        let lifecycle_metrics = LifecycleMetrics::from_sbom(sbom);

        let compliance = ComplianceChecker::new(self.profile.compliance_level()).check(sbom);

        let make_report = |overall_score: f32,
                           grade: QualityGrade,
                           recommendations: Vec<Recommendation>,
                           metrics: AiReadinessMetrics| QualityReport {
            scoring_engine_version: SCORING_ENGINE_VERSION.to_string(),
            overall_score,
            grade,
            profile: self.profile,
            completeness_score: 0.0,
            identifier_score: 0.0,
            license_score: 0.0,
            vulnerability_score: None,
            dependency_score: 0.0,
            integrity_score: 0.0,
            provenance_score: 0.0,
            lifecycle_score: None,
            completeness_metrics: completeness_metrics.clone(),
            identifier_metrics: identifier_metrics.clone(),
            license_metrics: license_metrics.clone(),
            vulnerability_metrics: vulnerability_metrics.clone(),
            dependency_metrics: dependency_metrics.clone(),
            hash_quality_metrics: hash_quality_metrics.clone(),
            provenance_metrics: provenance_metrics.clone(),
            auditability_metrics: auditability_metrics.clone(),
            lifecycle_metrics: lifecycle_metrics.clone(),
            cryptography_score: None,
            cryptography_metrics: CryptographyMetrics::default(),
            compliance: compliance.clone(),
            recommendations,
            ai_readiness_metrics: Some(metrics),
        };

        let ml_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::MachineLearningModel)
            .collect();

        if ml_components.is_empty() {
            let metrics = AiReadinessMetrics {
                ml_component_count: 0,
                not_applicable: true,
                na_reason: Some(
                    "No machine-learning-model components found in this SBOM".to_string(),
                ),
                checks: Vec::new(),
                components_fully_documented: 0,
            };
            return make_report(0.0, QualityGrade::F, Vec::new(), metrics);
        }

        // Per-check (id, name, weight); weights sum to 1.0 across the nine checks.
        const CHECK_DEFS: [(&str, &str, f32); 9] = [
            ("AI-001", "Model card URL present", 0.15),
            ("AI-002", "Architecture family declared", 0.12),
            ("AI-003", "Training datasets referenced", 0.12),
            ("AI-004", "Quantitative analysis present", 0.12),
            ("AI-005", "Fairness assessments included", 0.11),
            ("AI-006", "Energy consumption disclosed", 0.10),
            ("AI-007", "Use-cases documented", 0.10),
            ("AI-008", "Known limitations stated", 0.09),
            ("AI-009", "Ethical considerations present", 0.09),
        ];

        let n = ml_components.len();
        let mut total_weighted_score = 0.0_f32;
        let mut components_fully_documented = 0_usize;
        let mut component_details: Vec<Vec<String>> = vec![Vec::new(); CHECK_DEFS.len()];
        let mut failing_components = vec![0_usize; CHECK_DEFS.len()];

        for component in &ml_components {
            let ml = component.ml_model.as_ref();
            let raw = component.extensions.raw.as_ref();

            let results: [bool; 9] = [
                // AI-001: model card URL
                ml.and_then(|m| m.model_card_url.as_ref()).is_some(),
                // AI-002: architecture family
                ml.and_then(|m| m.architecture_family.as_ref()).is_some(),
                // AI-003: training datasets
                ml.is_some_and(|m| !m.training_datasets.is_empty()),
                // AI-004: quantitative analysis — typed performance metrics, with
                // a raw-pointer fallback for SBOMs parsed before typed extraction.
                ml.is_some_and(|m| !m.performance_metrics.is_empty())
                    || has_non_empty_pointer(
                        raw,
                        &[
                            "/modelCard/quantitativeAnalysis",
                            "/mlModel/modelCard/quantitativeAnalysis",
                        ],
                    ),
                // AI-005: fairness assessments. Fallback pointer corrected to the
                // spec path `fairnessAssessments` (was the non-spec ...Considerations).
                ml.is_some_and(|m| !m.fairness.is_empty())
                    || has_non_empty_pointer(
                        raw,
                        &[
                            "/modelCard/considerations/fairnessAssessments",
                            "/mlModel/modelCard/considerations/fairnessAssessments",
                            "/mlModel/considerations/fairnessAssessments",
                            // Legacy non-spec key, retained for back-compat.
                            "/modelCard/considerations/fairnessConsiderations",
                            "/mlModel/modelCard/considerations/fairnessConsiderations",
                            "/mlModel/considerations/fairnessConsiderations",
                        ],
                    ),
                // AI-006: energy consumption
                ml.and_then(|m| m.energy_kwh_training).is_some(),
                // AI-007: use-cases
                ml.is_some_and(|m| !m.use_cases.is_empty())
                    || has_non_empty_pointer(
                        raw,
                        &[
                            "/modelCard/considerations/useCases",
                            "/mlModel/modelCard/considerations/useCases",
                            "/mlModel/considerations/useCases",
                        ],
                    ),
                // AI-008: limitations
                ml.and_then(|m| m.limitations.as_ref()).is_some(),
                // AI-009: ethical considerations
                ml.is_some_and(|m| !m.ethical_considerations.is_empty())
                    || has_non_empty_pointer(
                        raw,
                        &[
                            "/modelCard/considerations/ethicalConsiderations",
                            "/mlModel/modelCard/considerations/ethicalConsiderations",
                            "/mlModel/considerations/ethicalConsiderations",
                        ],
                    ),
            ];

            if results.iter().all(|&p| p) {
                components_fully_documented += 1;
            }

            total_weighted_score += results
                .iter()
                .zip(CHECK_DEFS.iter())
                .map(|(&passed, (_, _, w))| if passed { *w } else { 0.0 })
                .sum::<f32>();

            for (i, &passed) in results.iter().enumerate() {
                component_details[i].push(format!(
                    "{}: {}",
                    component.name,
                    if passed { "pass" } else { "fail" }
                ));
                if !passed {
                    failing_components[i] += 1;
                }
            }
        }

        let checks: Vec<AiCheck> = CHECK_DEFS
            .iter()
            .enumerate()
            .map(|(i, (id, name, weight))| {
                let failures = failing_components[i];
                let detail = if component_details[i].is_empty() {
                    None
                } else {
                    Some(format!(
                        "{}/{} components passed; {}",
                        n - failures,
                        n,
                        component_details[i].join("; ")
                    ))
                };
                AiCheck {
                    id: (*id).to_string(),
                    name: (*name).to_string(),
                    passed: failures == 0,
                    detail,
                    weight: *weight,
                }
            })
            .collect();

        // Average across all ML components, scaled to 0-100.
        let overall_score = ((total_weighted_score / n as f32) * 100.0).min(100.0);

        let mut recommendations: Vec<Recommendation> = checks
            .iter()
            .zip(failing_components.iter())
            .filter(|(c, _)| !c.passed)
            .enumerate()
            .map(|(i, (chk, &affected_count))| Recommendation {
                priority: (i as u8 / 3) + 1,
                category: RecommendationCategory::Completeness,
                message: format!("[{}] {}", chk.id, chk.name),
                impact: chk.weight * 100.0,
                affected_count,
            })
            .collect();

        recommendations.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                b.impact
                    .partial_cmp(&a.impact)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        let metrics = AiReadinessMetrics {
            ml_component_count: n,
            not_applicable: false,
            na_reason: None,
            checks,
            components_fully_documented,
        };

        make_report(
            overall_score,
            QualityGrade::from_score(overall_score),
            recommendations,
            metrics,
        )
    }

    /// Apply hard score caps for critical issues
    fn apply_score_caps(
        &self,
        mut score: f32,
        lifecycle: &LifecycleMetrics,
        deps: &DependencyMetrics,
        hashes: &HashQualityMetrics,
        crypto: &CryptographyMetrics,
        total_components: usize,
    ) -> f32 {
        let is_security_profile =
            matches!(self.profile, ScoringProfile::Security | ScoringProfile::Cra);

        // EOL components: cap at D grade for security-focused profiles
        if is_security_profile && lifecycle.eol_components > 0 {
            score = score.min(69.0);
        }

        // Dependency cycles: cap at B grade
        if deps.cycle_count > 0
            && matches!(
                self.profile,
                ScoringProfile::Security | ScoringProfile::Cra | ScoringProfile::Comprehensive
            )
        {
            score = score.min(89.0);
        }

        // No hashes at all: cap at C grade for Security profile
        if matches!(self.profile, ScoringProfile::Security)
            && total_components > 0
            && hashes.components_with_any_hash == 0
        {
            score = score.min(79.0);
        }

        // Weak-only hashes: cap at B grade for Security profile
        if matches!(self.profile, ScoringProfile::Security)
            && hashes.components_with_weak_only > 0
            && hashes.components_with_strong_hash == 0
        {
            score = score.min(89.0);
        }

        // CBOM-specific hard caps
        if self.profile == ScoringProfile::Cbom && crypto.has_data() {
            if crypto.weak_algorithm_count > 0 {
                score = score.min(69.0);
            }
            if crypto.compromised_keys > 0 {
                score = score.min(79.0);
            }
            if crypto.quantum_safe_count == 0 && crypto.algorithms_count > 0 {
                score = score.min(79.0);
            }
        }

        score
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_recommendations(
        &self,
        completeness: &CompletenessMetrics,
        identifiers: &IdentifierMetrics,
        licenses: &LicenseMetrics,
        dependencies: &DependencyMetrics,
        hashes: &HashQualityMetrics,
        provenance: &ProvenanceMetrics,
        lifecycle: &LifecycleMetrics,
        compliance: &ComplianceResult,
        total_components: usize,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Priority 1: Compliance errors
        if compliance.error_count > 0 {
            recommendations.push(Recommendation {
                priority: 1,
                category: RecommendationCategory::Compliance,
                message: format!(
                    "Fix {} compliance error(s) to meet {} requirements",
                    compliance.error_count,
                    compliance.level.name()
                ),
                impact: 20.0,
                affected_count: compliance.error_count,
            });
        }

        // Priority 1: EOL components
        if lifecycle.eol_components > 0 {
            recommendations.push(Recommendation {
                priority: 1,
                category: RecommendationCategory::Lifecycle,
                message: format!(
                    "{} component(s) have reached end-of-life — upgrade or replace",
                    lifecycle.eol_components
                ),
                impact: 15.0,
                affected_count: lifecycle.eol_components,
            });
        }

        // Priority 1: Missing versions (critical for identification)
        let missing_versions = total_components
            - ((completeness.components_with_version / 100.0) * total_components as f32) as usize;
        if missing_versions > 0 {
            recommendations.push(Recommendation {
                priority: 1,
                category: RecommendationCategory::Completeness,
                message: "Add version information to all components".to_string(),
                impact: (missing_versions as f32 / total_components.max(1) as f32) * 15.0,
                affected_count: missing_versions,
            });
        }

        // Priority 2: Weak-only hashes
        if hashes.components_with_weak_only > 0 {
            recommendations.push(Recommendation {
                priority: 2,
                category: RecommendationCategory::Integrity,
                message: "Upgrade weak hashes (MD5/SHA-1) to SHA-256 or stronger".to_string(),
                impact: 10.0,
                affected_count: hashes.components_with_weak_only,
            });
        }

        // Priority 2: Missing PURLs (important for identification)
        if identifiers.missing_all_identifiers > 0 {
            recommendations.push(Recommendation {
                priority: 2,
                category: RecommendationCategory::Identifiers,
                message: "Add PURL or CPE identifiers to components".to_string(),
                impact: (identifiers.missing_all_identifiers as f32
                    / total_components.max(1) as f32)
                    * 20.0,
                affected_count: identifiers.missing_all_identifiers,
            });
        }

        // Priority 2: Invalid identifiers
        let invalid_ids = identifiers.invalid_purls + identifiers.invalid_cpes;
        if invalid_ids > 0 {
            recommendations.push(Recommendation {
                priority: 2,
                category: RecommendationCategory::Identifiers,
                message: "Fix malformed PURL/CPE identifiers".to_string(),
                impact: 10.0,
                affected_count: invalid_ids,
            });
        }

        // Priority 2: Missing tool creator info
        if !provenance.has_tool_creator {
            recommendations.push(Recommendation {
                priority: 2,
                category: RecommendationCategory::Provenance,
                message: "Add SBOM creation tool information".to_string(),
                impact: 8.0,
                affected_count: 0,
            });
        }

        // Priority 3: Dependency cycles
        if dependencies.cycle_count > 0 {
            recommendations.push(Recommendation {
                priority: 3,
                category: RecommendationCategory::Dependencies,
                message: format!(
                    "{} dependency cycle(s) detected — review dependency graph",
                    dependencies.cycle_count
                ),
                impact: 10.0,
                affected_count: dependencies.cycle_count,
            });
        }

        // Priority 2-3: Software complexity
        if let Some(level) = &dependencies.complexity_level {
            match level {
                super::metrics::ComplexityLevel::VeryHigh => {
                    recommendations.push(Recommendation {
                        priority: 2,
                        category: RecommendationCategory::Dependencies,
                        message:
                            "Dependency structure is very complex — review for unnecessary transitive dependencies"
                                .to_string(),
                        impact: 8.0,
                        affected_count: dependencies.total_dependencies,
                    });
                }
                super::metrics::ComplexityLevel::High => {
                    recommendations.push(Recommendation {
                        priority: 3,
                        category: RecommendationCategory::Dependencies,
                        message:
                            "Dependency structure is complex — consider reducing hub dependencies or flattening deep chains"
                                .to_string(),
                        impact: 5.0,
                        affected_count: dependencies.total_dependencies,
                    });
                }
                _ => {}
            }
        }

        // Priority 3: Missing licenses
        let missing_licenses = total_components - licenses.with_declared;
        if missing_licenses > 0 && (missing_licenses as f32 / total_components.max(1) as f32) > 0.2
        {
            recommendations.push(Recommendation {
                priority: 3,
                category: RecommendationCategory::Licenses,
                message: "Add license information to components".to_string(),
                impact: (missing_licenses as f32 / total_components.max(1) as f32) * 12.0,
                affected_count: missing_licenses,
            });
        }

        // Priority 3: NOASSERTION licenses
        if licenses.noassertion_count > 0 {
            recommendations.push(Recommendation {
                priority: 3,
                category: RecommendationCategory::Licenses,
                message: "Replace NOASSERTION with actual license information".to_string(),
                impact: 5.0,
                affected_count: licenses.noassertion_count,
            });
        }

        // Priority 3: VCS URL coverage
        if total_components > 0 {
            let missing_vcs = total_components.saturating_sub(
                ((completeness.components_with_hashes / 100.0) * total_components as f32) as usize,
            );
            if missing_vcs > total_components / 2 {
                recommendations.push(Recommendation {
                    priority: 3,
                    category: RecommendationCategory::Provenance,
                    message: "Add VCS (source repository) URLs to components".to_string(),
                    impact: 5.0,
                    affected_count: missing_vcs,
                });
            }
        }

        // Priority 4: Non-standard licenses
        if licenses.non_standard_licenses > 0 {
            recommendations.push(Recommendation {
                priority: 4,
                category: RecommendationCategory::Licenses,
                message: "Use SPDX license identifiers for better interoperability".to_string(),
                impact: 3.0,
                affected_count: licenses.non_standard_licenses,
            });
        }

        // Priority 4: Outdated components
        if lifecycle.outdated_components > 0 {
            recommendations.push(Recommendation {
                priority: 4,
                category: RecommendationCategory::Lifecycle,
                message: format!(
                    "{} component(s) are outdated — newer versions available",
                    lifecycle.outdated_components
                ),
                impact: 5.0,
                affected_count: lifecycle.outdated_components,
            });
        }

        // Priority 4: Missing completeness declaration
        if provenance.completeness_declaration == CompletenessDeclaration::Unknown
            && matches!(
                self.profile,
                ScoringProfile::Cra | ScoringProfile::Comprehensive
            )
        {
            recommendations.push(Recommendation {
                priority: 4,
                category: RecommendationCategory::Provenance,
                message: "Add compositions section with aggregate completeness declaration"
                    .to_string(),
                impact: 5.0,
                affected_count: 0,
            });
        }

        // Priority 4: Missing dependency information
        if total_components > 1 && dependencies.total_dependencies == 0 {
            recommendations.push(Recommendation {
                priority: 4,
                category: RecommendationCategory::Dependencies,
                message: "Add dependency relationships between components".to_string(),
                impact: 10.0,
                affected_count: total_components,
            });
        }

        // Priority 4: Many orphan components
        if dependencies.orphan_components > 1
            && (dependencies.orphan_components as f32 / total_components.max(1) as f32) > 0.3
        {
            recommendations.push(Recommendation {
                priority: 4,
                category: RecommendationCategory::Dependencies,
                message: "Review orphan components that have no dependency relationships"
                    .to_string(),
                impact: 5.0,
                affected_count: dependencies.orphan_components,
            });
        }

        // Priority 5: Missing supplier information
        let missing_suppliers = total_components
            - ((completeness.components_with_supplier / 100.0) * total_components as f32) as usize;
        if missing_suppliers > 0
            && (missing_suppliers as f32 / total_components.max(1) as f32) > 0.5
        {
            recommendations.push(Recommendation {
                priority: 5,
                category: RecommendationCategory::Completeness,
                message: "Add supplier information to components".to_string(),
                impact: (missing_suppliers as f32 / total_components.max(1) as f32) * 8.0,
                affected_count: missing_suppliers,
            });
        }

        // Priority 5: Missing hashes
        let missing_hashes = total_components
            - ((completeness.components_with_hashes / 100.0) * total_components as f32) as usize;
        if missing_hashes > 0
            && matches!(
                self.profile,
                ScoringProfile::Security | ScoringProfile::Comprehensive
            )
        {
            recommendations.push(Recommendation {
                priority: 5,
                category: RecommendationCategory::Integrity,
                message: "Add cryptographic hashes for integrity verification".to_string(),
                impact: (missing_hashes as f32 / total_components.max(1) as f32) * 5.0,
                affected_count: missing_hashes,
            });
        }

        // Priority 5: Consider SBOM signing (only if not already signed)
        if !provenance.has_signature
            && matches!(
                self.profile,
                ScoringProfile::Security | ScoringProfile::Cra | ScoringProfile::Comprehensive
            )
        {
            recommendations.push(Recommendation {
                priority: 5,
                category: RecommendationCategory::Integrity,
                message: "Consider adding a digital signature to the SBOM".to_string(),
                impact: 3.0,
                affected_count: 0,
            });
        }

        // Sort by priority, then by impact
        recommendations.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                b.impact
                    .partial_cmp(&a.impact)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        recommendations
    }
}

impl Default for QualityScorer {
    fn default() -> Self {
        Self::new(ScoringProfile::Standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, ComponentType, DocumentMetadata, MlModelInfo};
    use serde_json::json;

    #[test]
    fn test_grade_from_score() {
        assert_eq!(QualityGrade::from_score(95.0), QualityGrade::A);
        assert_eq!(QualityGrade::from_score(85.0), QualityGrade::B);
        assert_eq!(QualityGrade::from_score(75.0), QualityGrade::C);
        assert_eq!(QualityGrade::from_score(65.0), QualityGrade::D);
        assert_eq!(QualityGrade::from_score(55.0), QualityGrade::F);
    }

    #[test]
    fn test_scoring_profile_compliance_level() {
        assert_eq!(
            ScoringProfile::Minimal.compliance_level(),
            ComplianceLevel::Minimum
        );
        assert_eq!(
            ScoringProfile::Security.compliance_level(),
            ComplianceLevel::NtiaMinimum
        );
        assert_eq!(
            ScoringProfile::Comprehensive.compliance_level(),
            ComplianceLevel::Comprehensive
        );
        assert_eq!(
            ScoringProfile::AiReadiness.compliance_level(),
            ComplianceLevel::Comprehensive
        );
    }

    #[test]
    fn test_scoring_weights_sum_to_one() {
        let profiles = [
            ScoringProfile::Minimal,
            ScoringProfile::Standard,
            ScoringProfile::Security,
            ScoringProfile::LicenseCompliance,
            ScoringProfile::Cra,
            ScoringProfile::Comprehensive,
            ScoringProfile::Cbom,
            ScoringProfile::AiReadiness,
        ];
        for profile in &profiles {
            let w = profile.weights();
            let sum: f32 = w.as_array().iter().sum();
            assert!(
                (sum - 1.0).abs() < 0.01,
                "{profile:?} weights sum to {sum}, expected 1.0"
            );
        }
    }

    #[test]
    fn test_renormalize_all_available() {
        let w = ScoringProfile::Standard.weights();
        let available = [true; 8];
        let norm = w.renormalize(&available);
        let sum: f32 = norm.iter().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_renormalize_lifecycle_unavailable() {
        let w = ScoringProfile::Standard.weights();
        let mut available = [true; 8];
        available[7] = false; // lifecycle
        let norm = w.renormalize(&available);
        let sum: f32 = norm.iter().sum();
        assert!((sum - 1.0).abs() < 0.001);
        assert_eq!(norm[7], 0.0);
    }

    #[test]
    fn test_scoring_engine_version() {
        assert_eq!(SCORING_ENGINE_VERSION, "2.1");
    }

    #[test]
    fn cbom_hard_cap_weak_algorithms() {
        use crate::model::{
            AlgorithmProperties, CanonicalId, Component, ComponentType, CryptoAssetType,
            CryptoPrimitive, CryptoProperties, NormalizedSbom,
        };

        let mut sbom = NormalizedSbom::default();
        // Add a weak crypto component (MD5 algorithm)
        let mut comp = Component::new("MD5".to_string(), "md5-ref".to_string());
        comp.component_type = ComponentType::Cryptographic;
        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Hash)
                    .with_algorithm_family("MD5".to_string())
                    .with_nist_quantum_security_level(0),
            ),
        );
        sbom.components
            .insert(CanonicalId::from_name_version("md5", None), comp);

        let scorer = QualityScorer::new(ScoringProfile::Cbom);
        let report = scorer.score(&sbom);
        // Weak algorithm → D max (69)
        assert!(
            report.overall_score <= 69.0,
            "weak algo should cap at D, got {}",
            report.overall_score
        );
    }

    fn ml_component(bom_ref: &str, name: &str, ml: MlModelInfo, raw: Value) -> Component {
        let mut component =
            Component::new(name.to_string(), bom_ref.to_string()).with_version("1.0.0".to_string());
        component.component_type = ComponentType::MachineLearningModel;
        component.ml_model = Some(ml);
        component.extensions.raw = Some(raw);
        component
    }

    #[test]
    fn test_ai_readiness_not_applicable_without_ml_components() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let metrics = report
            .ai_readiness_metrics
            .expect("AI readiness metrics should be present");
        assert!(metrics.is_not_applicable());
        assert_eq!(metrics.ml_component_count, 0);
        assert!(metrics.checks.is_empty());
    }

    #[test]
    fn test_ai_readiness_reads_nested_model_card_extensions() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let ml = MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            training_datasets: vec![crate::model::DatasetRef {
                reference: None,
                name: Some("wikipedia-2.5B".to_string()),
                purl: None,
            }],
            energy_kwh_training: Some(1500.0),
            model_card_url: Some("https://example.test/model-card".to_string()),
            limitations: Some("Only validated for English text".to_string()),
            ..MlModelInfo::default()
        };
        let raw = json!({
            "mlModel": {
                "modelCard": {
                    "quantitativeAnalysis": {
                        "performanceMetrics": [{ "type": "accuracy", "value": 0.97 }]
                    },
                    "considerations": {
                        "fairnessConsiderations": ["Assessed on demographic parity"],
                        "useCases": ["Document classification"],
                        "ethicalConsiderations": ["Human review required for sensitive domains"]
                    }
                }
            }
        });
        sbom.add_component(ml_component("ml-1", "bert-base", ml, raw));

        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let metrics = report
            .ai_readiness_metrics
            .expect("AI readiness metrics should be present");
        assert!(!metrics.is_not_applicable());
        // All nine checks should pass → fully documented, perfect score.
        for check in &metrics.checks {
            assert!(check.passed, "expected {} to pass", check.id);
        }
        assert_eq!(metrics.components_fully_documented, 1);
        assert!((report.overall_score - 100.0).abs() < 0.01);
        assert_eq!(report.grade, QualityGrade::A);
    }

    #[test]
    fn test_ai_readiness_fails_check_when_any_model_is_missing_it() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let complete_ml = MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            training_datasets: vec![crate::model::DatasetRef {
                reference: None,
                name: Some("dataset".to_string()),
                purl: None,
            }],
            energy_kwh_training: Some(10.0),
            model_card_url: Some("https://example.test/model-card".to_string()),
            limitations: Some("Only validated for English text".to_string()),
            ..MlModelInfo::default()
        };
        let complete_raw = json!({
            "mlModel": { "modelCard": {
                "quantitativeAnalysis": { "performanceMetrics": [{ "type": "accuracy", "value": 0.98 }] },
                "considerations": {
                    "fairnessConsiderations": ["Reviewed"],
                    "useCases": ["Classification"],
                    "ethicalConsiderations": ["Human review required"]
                }
            }}
        });
        sbom.add_component(ml_component(
            "ml-1",
            "complete-model",
            complete_ml.clone(),
            complete_raw,
        ));

        // Second model is missing fairness assessments.
        let incomplete_raw = json!({
            "mlModel": { "modelCard": {
                "quantitativeAnalysis": { "performanceMetrics": [{ "type": "accuracy", "value": 0.94 }] },
                "considerations": {
                    "useCases": ["Classification"],
                    "ethicalConsiderations": ["Human review required"]
                }
            }}
        });
        sbom.add_component(ml_component(
            "ml-2",
            "incomplete-model",
            complete_ml,
            incomplete_raw,
        ));

        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let metrics = report
            .ai_readiness_metrics
            .expect("AI readiness metrics should be present");
        let fairness = metrics
            .checks
            .iter()
            .find(|c| c.id == "AI-005")
            .expect("AI-005 should be present");
        assert!(
            !fairness.passed,
            "AI-005 should fail when any model is missing fairness data"
        );
        assert!(
            fairness
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("1/2 components passed")
        );
        let rec = report
            .recommendations
            .iter()
            .find(|r| r.message.contains("AI-005"))
            .expect("missing fairness recommendation");
        assert_eq!(rec.affected_count, 1);
    }
}
