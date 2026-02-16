//! JSON report generator.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::DiffResult;
use crate::model::NormalizedSbom;
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use chrono::Utc;
use serde::Serialize;

/// JSON report generator
pub struct JsonReporter {
    /// Whether to only include summary
    summary_only: bool,
    /// Pretty print output
    pretty: bool,
}

impl JsonReporter {
    /// Create a new JSON reporter
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            summary_only: false,
            pretty: true,
        }
    }

    /// Create a summary-only reporter
    #[must_use] 
    pub const fn summary_only() -> Self {
        Self {
            summary_only: true,
            pretty: true,
        }
    }

    /// Set pretty printing
    #[must_use]
    pub const fn pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for JsonReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let old_cra = config.old_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(old_sbom)
        });
        let new_cra = config.new_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(new_sbom)
        });
        let cra_compliance = CraCompliance {
            old: CraComplianceDetail::from_result(old_cra),
            new: CraComplianceDetail::from_result(new_cra),
        };

        let report = JsonDiffReport {
            metadata: JsonReportMetadata {
                tool: ToolInfo {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                generated_at: Utc::now().to_rfc3339(),
                old_sbom: SbomInfo {
                    format: old_sbom.document.format.to_string(),
                    file_path: config.metadata.old_sbom_path.clone(),
                    component_count: old_sbom.component_count(),
                },
                new_sbom: SbomInfo {
                    format: new_sbom.document.format.to_string(),
                    file_path: config.metadata.new_sbom_path.clone(),
                    component_count: new_sbom.component_count(),
                },
            },
            summary: JsonSummary {
                total_changes: result.summary.total_changes,
                components: ComponentSummary {
                    added: result.summary.components_added,
                    removed: result.summary.components_removed,
                    modified: result.summary.components_modified,
                },
                vulnerabilities: VulnerabilitySummary {
                    introduced: result.summary.vulnerabilities_introduced,
                    resolved: result.summary.vulnerabilities_resolved,
                    persistent: result.summary.vulnerabilities_persistent,
                },
                semantic_score: result.semantic_score,
            },
            cra_compliance,
            reports: if self.summary_only {
                None
            } else {
                Some(JsonReports {
                    components: if config.includes(ReportType::Components) {
                        Some(ComponentsReport {
                            added: &result.components.added,
                            removed: &result.components.removed,
                            modified: &result.components.modified,
                        })
                    } else {
                        None
                    },
                    dependencies: if config.includes(ReportType::Dependencies) {
                        Some(DependenciesReport {
                            added: &result.dependencies.added,
                            removed: &result.dependencies.removed,
                        })
                    } else {
                        None
                    },
                    licenses: if config.includes(ReportType::Licenses) {
                        Some(LicensesReport {
                            new_licenses: &result.licenses.new_licenses,
                            removed_licenses: &result.licenses.removed_licenses,
                            conflicts: &result.licenses.conflicts,
                        })
                    } else {
                        None
                    },
                    vulnerabilities: if config.includes(ReportType::Vulnerabilities) {
                        Some(VulnerabilitiesReport {
                            introduced: VulnerabilityWithSla::from_slice(&result.vulnerabilities.introduced),
                            resolved: VulnerabilityWithSla::from_slice(&result.vulnerabilities.resolved),
                            persistent: VulnerabilityWithSla::from_slice(&result.vulnerabilities.persistent),
                        })
                    } else {
                        None
                    },
                })
            },
        };

        let json = if self.pretty {
            serde_json::to_string_pretty(&report)
        } else {
            serde_json::to_string(&report)
        }
        .map_err(|e| ReportError::SerializationError(e.to_string()))?;

        Ok(json)
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let cra_result = config.view_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(sbom)
        });
        let compliance = CraComplianceDetail::from_result(cra_result);

        let report = JsonViewReport {
            metadata: JsonViewMetadata {
                tool: ToolInfo {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                generated_at: Utc::now().to_rfc3339(),
                sbom: SbomInfo {
                    format: sbom.document.format.to_string(),
                    file_path: config.metadata.old_sbom_path.clone(),
                    component_count: sbom.component_count(),
                },
            },
            summary: ViewSummary {
                total_components: sbom.component_count(),
                total_dependencies: sbom.edges.len(),
                ecosystems: sbom.ecosystems().iter().map(std::string::ToString::to_string).collect(),
                vulnerability_counts: sbom.vulnerability_counts(),
            },
            compliance,
            components: sbom
                .components
                .values()
                .map(|c| ComponentView {
                    name: c.name.clone(),
                    version: c.version.clone(),
                    ecosystem: c.ecosystem.as_ref().map(std::string::ToString::to_string),
                    licenses: c
                        .licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.clone())
                        .collect(),
                    supplier: c.supplier.as_ref().map(|s| s.name.clone()),
                    vulnerabilities: c.vulnerabilities.len(),
                    eol_status: c.eol.as_ref().map(|e| e.status.label().to_string()),
                    eol_date: c
                        .eol
                        .as_ref()
                        .and_then(|e| e.eol_date.map(|d| d.to_string())),
                    eol_product: c.eol.as_ref().map(|e| e.product.clone()),
                })
                .collect(),
        };

        let json = if self.pretty {
            serde_json::to_string_pretty(&report)
        } else {
            serde_json::to_string(&report)
        }
        .map_err(|e| ReportError::SerializationError(e.to_string()))?;

        Ok(json)
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }
}

// JSON report structures

#[derive(Serialize)]
struct JsonDiffReport<'a> {
    metadata: JsonReportMetadata,
    summary: JsonSummary,
    cra_compliance: CraCompliance,
    #[serde(skip_serializing_if = "Option::is_none")]
    reports: Option<JsonReports<'a>>,
}

#[derive(Serialize)]
struct CraCompliance {
    old: CraComplianceDetail,
    new: CraComplianceDetail,
}

#[derive(Serialize)]
struct CraComplianceDetail {
    #[serde(flatten)]
    result: ComplianceResult,
    /// Summary of violations grouped by CRA article
    article_summary: CraArticleSummary,
}

#[derive(Serialize)]
struct CraArticleSummary {
    /// Article 13(4) - Machine-readable format
    #[serde(rename = "art_13_4_machine_readable_format")]
    art_13_4: usize,
    /// Article 13(6) - Vulnerability disclosure
    #[serde(rename = "art_13_6_vulnerability_disclosure")]
    art_13_6: usize,
    /// Article 13(7) - Coordinated vulnerability disclosure policy
    #[serde(rename = "art_13_7_coordinated_disclosure")]
    art_13_7: usize,
    /// Article 13(8) - Support period
    #[serde(rename = "art_13_8_support_period")]
    art_13_8: usize,
    /// Article 13(11) - Component lifecycle
    #[serde(rename = "art_13_11_component_lifecycle")]
    art_13_11: usize,
    /// Article 13(12) - Product identification
    #[serde(rename = "art_13_12_product_identification")]
    art_13_12: usize,
    /// Article 13(15) - Manufacturer identification
    #[serde(rename = "art_13_15_manufacturer_identification")]
    art_13_15: usize,
    /// Annex I - Technical documentation
    #[serde(rename = "annex_i_technical_documentation")]
    annex_i: usize,
    /// Annex VII - EU Declaration of Conformity
    #[serde(rename = "annex_vii_declaration_of_conformity")]
    annex_vii: usize,
}

impl CraComplianceDetail {
    fn from_result(result: ComplianceResult) -> Self {
        let mut summary = CraArticleSummary {
            art_13_4: 0,
            art_13_6: 0,
            art_13_7: 0,
            art_13_8: 0,
            art_13_11: 0,
            art_13_12: 0,
            art_13_15: 0,
            annex_i: 0,
            annex_vii: 0,
        };

        // Count violations by article reference
        for violation in &result.violations {
            let req = violation.requirement.to_lowercase();
            if req.contains("art. 13(4)") || req.contains("art.13(4)") {
                summary.art_13_4 += 1;
            } else if req.contains("art. 13(6)") || req.contains("art.13(6)") {
                summary.art_13_6 += 1;
            } else if req.contains("art. 13(7)") || req.contains("art.13(7)") {
                summary.art_13_7 += 1;
            } else if req.contains("art. 13(8)") || req.contains("art.13(8)") {
                summary.art_13_8 += 1;
            } else if req.contains("art. 13(11)") || req.contains("art.13(11)") {
                summary.art_13_11 += 1;
            } else if req.contains("art. 13(12)") || req.contains("art.13(12)") {
                summary.art_13_12 += 1;
            } else if req.contains("art. 13(15)") || req.contains("art.13(15)") {
                summary.art_13_15 += 1;
            } else if req.contains("annex vii") {
                summary.annex_vii += 1;
            } else if req.contains("annex i") || req.contains("annex_i") {
                summary.annex_i += 1;
            }
        }

        Self {
            result,
            article_summary: summary,
        }
    }
}

#[derive(Serialize)]
struct JsonReportMetadata {
    tool: ToolInfo,
    generated_at: String,
    old_sbom: SbomInfo,
    new_sbom: SbomInfo,
}

#[derive(Serialize)]
struct ToolInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct SbomInfo {
    format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    component_count: usize,
}

#[derive(Serialize)]
struct JsonSummary {
    total_changes: usize,
    components: ComponentSummary,
    vulnerabilities: VulnerabilitySummary,
    semantic_score: f64,
}

#[derive(Serialize)]
struct ComponentSummary {
    added: usize,
    removed: usize,
    modified: usize,
}

#[derive(Serialize)]
struct VulnerabilitySummary {
    introduced: usize,
    resolved: usize,
    persistent: usize,
}

#[derive(Serialize)]
struct JsonReports<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<ComponentsReport<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<DependenciesReport<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<LicensesReport<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vulnerabilities: Option<VulnerabilitiesReport>,
}

#[derive(Serialize)]
struct ComponentsReport<'a> {
    added: &'a [crate::diff::ComponentChange],
    removed: &'a [crate::diff::ComponentChange],
    modified: &'a [crate::diff::ComponentChange],
}

#[derive(Serialize)]
struct DependenciesReport<'a> {
    added: &'a [crate::diff::DependencyChange],
    removed: &'a [crate::diff::DependencyChange],
}

#[derive(Serialize)]
struct LicensesReport<'a> {
    new_licenses: &'a [crate::diff::LicenseChange],
    removed_licenses: &'a [crate::diff::LicenseChange],
    conflicts: &'a [crate::diff::LicenseConflict],
}

#[derive(Serialize)]
struct VulnerabilitiesReport {
    introduced: Vec<VulnerabilityWithSla>,
    resolved: Vec<VulnerabilityWithSla>,
    persistent: Vec<VulnerabilityWithSla>,
}

/// Wrapper that adds computed SLA status to vulnerability JSON output.
#[derive(Serialize)]
struct VulnerabilityWithSla {
    #[serde(flatten)]
    detail: crate::diff::VulnerabilityDetail,
    sla_status: String,
    sla_category: String,
}

impl VulnerabilityWithSla {
    fn from_detail(v: &crate::diff::VulnerabilityDetail) -> Self {
        let sla = v.sla_status();
        let (status_text, category) = match &sla {
            crate::diff::SlaStatus::Overdue(days) => (format!("{days}d overdue"), "overdue"),
            crate::diff::SlaStatus::DueSoon(days) => (format!("{days}d remaining"), "due_soon"),
            crate::diff::SlaStatus::OnTrack(days) => (format!("{days}d remaining"), "on_track"),
            crate::diff::SlaStatus::NoDueDate => {
                let text = v
                    .days_since_published
                    .map_or_else(|| "unknown".to_string(), |d| format!("{d}d old"));
                (text, "no_due_date")
            }
        };
        Self {
            detail: v.clone(),
            sla_status: status_text,
            sla_category: category.to_string(),
        }
    }

    fn from_slice(vulns: &[crate::diff::VulnerabilityDetail]) -> Vec<Self> {
        vulns.iter().map(Self::from_detail).collect()
    }
}

// View report structures

#[derive(Serialize)]
struct JsonViewReport {
    metadata: JsonViewMetadata,
    summary: ViewSummary,
    compliance: CraComplianceDetail,
    components: Vec<ComponentView>,
}

#[derive(Serialize)]
struct JsonViewMetadata {
    tool: ToolInfo,
    generated_at: String,
    sbom: SbomInfo,
}

#[derive(Serialize)]
struct ViewSummary {
    total_components: usize,
    total_dependencies: usize,
    ecosystems: Vec<String>,
    vulnerability_counts: crate::model::VulnerabilityCounts,
}

#[derive(Serialize)]
struct ComponentView {
    name: String,
    version: Option<String>,
    ecosystem: Option<String>,
    licenses: Vec<String>,
    supplier: Option<String>,
    vulnerabilities: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_product: Option<String>,
}
