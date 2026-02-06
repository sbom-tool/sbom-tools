//! SBOM Quality Scorer.
//!
//! Main scoring engine that combines metrics and compliance checking
//! into an overall quality assessment.

use crate::model::NormalizedSbom;
use serde::{Deserialize, Serialize};

use super::compliance::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use super::metrics::{
    CompletenessMetrics, CompletenessWeights, DependencyMetrics, IdentifierMetrics, LicenseMetrics,
    VulnerabilityMetrics,
};

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
    pub fn compliance_level(&self) -> ComplianceLevel {
        match self {
            Self::Minimal => ComplianceLevel::Minimum,
            Self::Standard | Self::LicenseCompliance => ComplianceLevel::Standard,
            Self::Security => ComplianceLevel::NtiaMinimum,
            Self::Cra => ComplianceLevel::CraPhase2,
            Self::Comprehensive => ComplianceLevel::Comprehensive,
        }
    }

    /// Get weights for this profile
    fn weights(&self) -> ScoringWeights {
        match self {
            Self::Minimal => ScoringWeights {
                completeness: 0.5,
                identifiers: 0.2,
                licenses: 0.1,
                vulnerabilities: 0.1,
                dependencies: 0.1,
            },
            Self::Standard => ScoringWeights {
                completeness: 0.35,
                identifiers: 0.25,
                licenses: 0.15,
                vulnerabilities: 0.1,
                dependencies: 0.15,
            },
            Self::Security => ScoringWeights {
                completeness: 0.2,
                identifiers: 0.25,
                licenses: 0.1,
                vulnerabilities: 0.3,
                dependencies: 0.15,
            },
            Self::LicenseCompliance => ScoringWeights {
                completeness: 0.2,
                identifiers: 0.15,
                licenses: 0.4,
                vulnerabilities: 0.1,
                dependencies: 0.15,
            },
            Self::Cra => ScoringWeights {
                completeness: 0.2,    // Supplier info matters
                identifiers: 0.25,    // Traceability is key
                licenses: 0.1,        // Less emphasized by CRA
                vulnerabilities: 0.25, // Security disclosure critical
                dependencies: 0.2,    // Supply chain transparency
            },
            Self::Comprehensive => ScoringWeights {
                completeness: 0.25,
                identifiers: 0.2,
                licenses: 0.2,
                vulnerabilities: 0.15,
                dependencies: 0.2,
            },
        }
    }
}

/// Weights for overall score calculation
#[derive(Debug, Clone)]
struct ScoringWeights {
    completeness: f32,
    identifiers: f32,
    licenses: f32,
    vulnerabilities: f32,
    dependencies: f32,
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
    pub fn from_score(score: f32) -> Self {
        match score as u32 {
            90..=100 => Self::A,
            80..=89 => Self::B,
            70..=79 => Self::C,
            60..=69 => Self::D,
            _ => Self::F,
        }
    }

    /// Get grade letter
    pub fn letter(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }

    /// Get grade description
    pub fn description(&self) -> &'static str {
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
}

impl RecommendationCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Completeness => "Completeness",
            Self::Identifiers => "Identifiers",
            Self::Licenses => "Licenses",
            Self::Vulnerabilities => "Vulnerabilities",
            Self::Dependencies => "Dependencies",
            Self::Compliance => "Compliance",
        }
    }
}

/// Complete quality report for an SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct QualityReport {
    /// Overall score (0-100)
    pub overall_score: f32,
    /// Overall grade
    pub grade: QualityGrade,
    /// Scoring profile used
    pub profile: ScoringProfile,
    /// Completeness score (0-100)
    pub completeness_score: f32,
    /// Identifier quality score (0-100)
    pub identifier_score: f32,
    /// License quality score (0-100)
    pub license_score: f32,
    /// Vulnerability documentation score (0-100)
    pub vulnerability_score: f32,
    /// Dependency graph quality score (0-100)
    pub dependency_score: f32,
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
    pub fn new(profile: ScoringProfile) -> Self {
        Self {
            profile,
            completeness_weights: CompletenessWeights::default(),
        }
    }

    /// Set custom completeness weights
    pub fn with_completeness_weights(mut self, weights: CompletenessWeights) -> Self {
        self.completeness_weights = weights;
        self
    }

    /// Score an SBOM
    pub fn score(&self, sbom: &NormalizedSbom) -> QualityReport {
        let total_components = sbom.components.len();

        // Calculate metrics
        let completeness_metrics = CompletenessMetrics::from_sbom(sbom);
        let identifier_metrics = IdentifierMetrics::from_sbom(sbom);
        let license_metrics = LicenseMetrics::from_sbom(sbom);
        let vulnerability_metrics = VulnerabilityMetrics::from_sbom(sbom);
        let dependency_metrics = DependencyMetrics::from_sbom(sbom);

        // Calculate individual scores
        let completeness_score = completeness_metrics.overall_score(&self.completeness_weights);
        let identifier_score = identifier_metrics.quality_score(total_components);
        let license_score = license_metrics.quality_score(total_components);
        let vulnerability_score = vulnerability_metrics.documentation_score();
        let dependency_score = dependency_metrics.quality_score(total_components);

        // Calculate weighted overall score
        let weights = self.profile.weights();
        let overall_score = (completeness_score * weights.completeness
            + identifier_score * weights.identifiers
            + license_score * weights.licenses
            + vulnerability_score * weights.vulnerabilities
            + dependency_score * weights.dependencies)
            .min(100.0);

        // Run compliance check
        let compliance_checker = ComplianceChecker::new(self.profile.compliance_level());
        let compliance = compliance_checker.check(sbom);

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &completeness_metrics,
            &identifier_metrics,
            &license_metrics,
            &dependency_metrics,
            &compliance,
            total_components,
        );

        QualityReport {
            overall_score,
            grade: QualityGrade::from_score(overall_score),
            profile: self.profile,
            completeness_score,
            identifier_score,
            license_score,
            vulnerability_score,
            dependency_score,
            completeness_metrics,
            identifier_metrics,
            license_metrics,
            vulnerability_metrics,
            dependency_metrics,
            compliance,
            recommendations,
        }
    }

    fn generate_recommendations(
        &self,
        completeness: &CompletenessMetrics,
        identifiers: &IdentifierMetrics,
        licenses: &LicenseMetrics,
        dependencies: &DependencyMetrics,
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
                category: RecommendationCategory::Completeness,
                message: "Add cryptographic hashes for integrity verification".to_string(),
                impact: (missing_hashes as f32 / total_components.max(1) as f32) * 5.0,
                affected_count: missing_hashes,
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
}
