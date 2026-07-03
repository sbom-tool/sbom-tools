//! JSON report generator.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::DiffResult;
use crate::model::{Component, NormalizedSbom, VulnerabilityRef};
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use chrono::{DateTime, Utc};
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
        let old_cra = config
            .old_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(old_sbom));
        let new_cra = config
            .new_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(new_sbom));
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
                metadata_changes: result.summary.metadata_changes_count,
                semantic_score: result.semantic_score,
            },
            cra_compliance,
            ml_regressions: if result.ml_regressions.is_empty() {
                None
            } else {
                Some(&result.ml_regressions)
            },
            reports: if self.summary_only {
                None
            } else {
                Some(JsonReports {
                    metadata_changes: if result.metadata_changes.is_empty() {
                        None
                    } else {
                        Some(&result.metadata_changes)
                    },
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
                            introduced: VulnerabilityWithSla::from_slice(
                                &result.vulnerabilities.introduced,
                            ),
                            resolved: VulnerabilityWithSla::from_slice(
                                &result.vulnerabilities.resolved,
                            ),
                            persistent: VulnerabilityWithSla::from_slice(
                                &result.vulnerabilities.persistent,
                            ),
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
        let cra_result = config
            .view_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(sbom));
        let compliance = CraComplianceDetail::from_result(cra_result);

        let direct_ids = sbom.direct_dependency_ids();
        let primary_id = sbom.primary_component_id.as_ref();

        let components: Vec<ComponentView> = sbom
            .components
            .values()
            .map(|c| {
                let kind = classify_dependency(&c.canonical_id, primary_id, &direct_ids);
                ComponentView {
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
                    dependency_kind: kind,
                    vulnerability_count: c.vulnerabilities.len(),
                    vulnerabilities: c
                        .vulnerabilities
                        .iter()
                        .map(VulnerabilityView::from)
                        .collect(),
                    eol_status: c.eol.as_ref().map(|e| e.status.label().to_string()),
                    eol_date: c
                        .eol
                        .as_ref()
                        .and_then(|e| e.eol_date.map(|d| d.to_string())),
                    eol_product: c.eol.as_ref().map(|e| e.product.clone()),
                }
            })
            .collect();

        let mut vulnerabilities: Vec<FlatVulnerabilityView> = Vec::new();
        for comp in sbom.components.values() {
            let kind = classify_dependency(&comp.canonical_id, primary_id, &direct_ids);
            for v in &comp.vulnerabilities {
                vulnerabilities.push(FlatVulnerabilityView::from_pair(comp, v, kind));
            }
        }

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
                ecosystems: sbom
                    .ecosystems()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                vulnerability_counts: sbom.vulnerability_counts(),
            },
            compliance,
            components,
            vulnerabilities,
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
    ml_regressions: Option<&'a [crate::diff::MlRegression]>,
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
    /// Count of document-level metadata changes (author/tool/timestamp/etc.).
    metadata_changes: usize,
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
    /// Document-level metadata changes (omitted when none).
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_changes: Option<&'a [crate::diff::MetadataChange]>,
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
    /// Flattened list of every vulnerability across all components,
    /// annotated with the package it affects and whether that package is
    /// a direct or transitive dependency of the primary component.
    vulnerabilities: Vec<FlatVulnerabilityView>,
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
    /// "primary", "direct", or "transitive" relative to the SBOM's primary component.
    dependency_kind: DependencyKind,
    /// Number of vulnerabilities affecting this component.
    vulnerability_count: usize,
    /// Structured vulnerability details (empty when none).
    vulnerabilities: Vec<VulnerabilityView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eol_product: Option<String>,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum DependencyKind {
    Primary,
    Direct,
    Transitive,
}

fn classify_dependency(
    id: &crate::model::CanonicalId,
    primary: Option<&crate::model::CanonicalId>,
    direct: &std::collections::HashSet<crate::model::CanonicalId>,
) -> DependencyKind {
    if primary == Some(id) {
        DependencyKind::Primary
    } else if direct.contains(id) {
        DependencyKind::Direct
    } else {
        DependencyKind::Transitive
    }
}

/// Per-component vulnerability detail (used both in `components[].vulnerabilities`
/// and as the body of `vulnerabilities[]` at the top level of the view report).
#[derive(Serialize, Clone)]
struct VulnerabilityView {
    /// Vulnerability identifier (CVE, GHSA, OSV, etc.).
    id: String,
    /// Source database (NVD, OSV, GHSA, ...).
    source: String,
    /// Severity label ("Critical", "High", ...) when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    /// Highest CVSS base score across attached CVSS records.
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f32>,
    /// CVSS vector string of the highest-scoring record, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_vector: Option<String>,
    /// First non-empty fixed version reported across the vulnerability's
    /// remediation records, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_version: Option<String>,
    /// CWE identifiers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cwes: Vec<String>,
    /// `true` when listed in CISA's Known Exploited Vulnerabilities catalog.
    kev: bool,
    /// KEV catalog metadata (due date, ransomware flag, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    kev_info: Option<KevInfoView>,
    /// VEX status when an applicable VEX statement is attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    vex_status: Option<String>,
    /// Short description, when supplied by the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Publication date (RFC 3339), when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<String>,
    /// Last-modified date (RFC 3339), when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<String>,
}

#[derive(Serialize, Clone)]
struct KevInfoView {
    date_added: String,
    due_date: String,
    known_ransomware_use: bool,
}

impl From<&VulnerabilityRef> for VulnerabilityView {
    fn from(v: &VulnerabilityRef) -> Self {
        let (cvss_score, cvss_vector) = v
            .cvss
            .iter()
            .max_by(|a, b| {
                a.base_score
                    .partial_cmp(&b.base_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map_or((None, None), |c| (Some(c.base_score), c.vector.clone()));

        Self {
            id: v.id.clone(),
            source: v.source.to_string(),
            severity: v.severity.as_ref().map(ToString::to_string),
            cvss_score,
            cvss_vector,
            fixed_version: v.remediation.as_ref().and_then(|r| r.fixed_version.clone()),
            cwes: v.cwes.clone(),
            kev: v.is_kev,
            kev_info: v.kev_info.as_ref().map(|k| KevInfoView {
                date_added: rfc3339(k.date_added),
                due_date: rfc3339(k.due_date),
                known_ransomware_use: k.known_ransomware_use,
            }),
            vex_status: v.vex_status.as_ref().map(|s| format!("{s:?}")),
            description: v.description.clone(),
            published: v.published.map(rfc3339),
            modified: v.modified.map(rfc3339),
        }
    }
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

/// Top-level flattened vulnerability entry: a `VulnerabilityView` joined with
/// the affected package, so consumers can iterate vulnerabilities without
/// walking the components array.
#[derive(Serialize)]
struct FlatVulnerabilityView {
    /// Vulnerability details.
    #[serde(flatten)]
    vuln: VulnerabilityView,
    /// Affected package name.
    package: String,
    /// Affected package version, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    package_version: Option<String>,
    /// Ecosystem of the affected package, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
    /// Direct/transitive classification of the affected package.
    dependency_kind: DependencyKind,
    /// Convenience boolean — `true` when `dependency_kind` is `direct` or `primary`.
    is_direct: bool,
}

impl FlatVulnerabilityView {
    fn from_pair(comp: &Component, v: &VulnerabilityRef, kind: DependencyKind) -> Self {
        let is_direct = matches!(kind, DependencyKind::Direct | DependencyKind::Primary);
        Self {
            vuln: VulnerabilityView::from(v),
            package: comp.name.clone(),
            package_version: comp.version.clone(),
            ecosystem: comp.ecosystem.as_ref().map(ToString::to_string),
            dependency_kind: kind,
            is_direct,
        }
    }
}
