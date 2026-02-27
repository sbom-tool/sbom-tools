//! SBOM Quality Scorer.
//!
//! Main scoring engine that combines metrics and compliance checking
//! into an overall quality assessment.

use crate::model::{CompletenessDeclaration, NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};

use super::compliance::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use super::metrics::{
    AuditabilityMetrics, CompletenessMetrics, CompletenessWeights, DependencyMetrics,
    HashQualityMetrics, IdentifierMetrics, LicenseMetrics, LifecycleMetrics, ProvenanceMetrics,
    VulnerabilityMetrics,
};

/// Quality scoring engine version
pub const SCORING_ENGINE_VERSION: &str = "2.0";

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
    /// Comprehensive - all aspects equally weighted
    Comprehensive,
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
            Self::Comprehensive => ComplianceLevel::Comprehensive,
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
        match score as u32 {
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

    /// Compliance check result
    pub compliance: ComplianceResult,
    /// Prioritized recommendations
    pub recommendations: Vec<Recommendation>,
}

/// Quality scorer for SBOMs
#[derive(Debug, Clone)]
pub struct QualityScorer {
    /// Scoring profile
    profile: ScoringProfile,
    /// Completeness weights
    completeness_weights: CompletenessWeights,
}

impl QualityScorer {
    /// Create a new quality scorer with the given profile
    #[must_use]
    pub fn new(profile: ScoringProfile) -> Self {
        Self {
            profile,
            completeness_weights: CompletenessWeights::default(),
        }
    }

    /// Set custom completeness weights
    #[must_use]
    pub const fn with_completeness_weights(mut self, weights: CompletenessWeights) -> Self {
        self.completeness_weights = weights;
        self
    }

    /// Score an SBOM
    pub fn score(&self, sbom: &NormalizedSbom) -> QualityReport {
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

        // Determine which categories are available
        let vuln_available = vulnerability_score.is_some();
        let lifecycle_available = lifecycle_score.is_some();
        let available = [
            true,                // completeness
            true,                // identifiers
            true,                // licenses
            vuln_available,      // vulnerabilities
            true,                // dependencies
            true,                // integrity
            true,                // provenance
            lifecycle_available, // lifecycle
        ];

        // Calculate weighted overall score with N/A renormalization
        let weights = self.profile.weights();
        let norm = weights.renormalize(&available);
        let scores = [
            completeness_score,
            identifier_score,
            license_score,
            vulnerability_score.unwrap_or(0.0),
            dependency_score,
            integrity_score,
            provenance_score,
            lifecycle_score.unwrap_or(0.0),
        ];

        let mut overall_score: f32 = scores.iter().zip(norm.iter()).map(|(s, w)| s * w).sum();
        overall_score = overall_score.min(100.0);

        // Apply hard penalty caps for critical issues
        overall_score = self.apply_score_caps(
            overall_score,
            &lifecycle_metrics,
            &dependency_metrics,
            &hash_quality_metrics,
            total_components,
        );

        // Run compliance check
        let compliance_checker = ComplianceChecker::new(self.profile.compliance_level());
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
            compliance,
            recommendations,
        }
    }

    /// Apply hard score caps for critical issues
    fn apply_score_caps(
        &self,
        mut score: f32,
        lifecycle: &LifecycleMetrics,
        deps: &DependencyMetrics,
        hashes: &HashQualityMetrics,
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
        assert_eq!(SCORING_ENGINE_VERSION, "2.0");
    }
}
