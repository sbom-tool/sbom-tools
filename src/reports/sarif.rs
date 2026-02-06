//! SARIF 2.1.0 report generator for CI/CD integration.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity};
use serde::Serialize;

/// SARIF report generator
pub struct SarifReporter {
    /// Include informational results
    include_info: bool,
}

impl SarifReporter {
    /// Create a new SARIF reporter
    pub fn new() -> Self {
        Self { include_info: true }
    }

    /// Set whether to include informational results
    pub fn include_info(mut self, include: bool) -> Self {
        self.include_info = include;
        self
    }
}

impl Default for SarifReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator for SarifReporter {
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut results = Vec::new();

        // Add component change results
        if config.includes(ReportType::Components) {
            for comp in &result.components.added {
                if self.include_info {
                    results.push(SarifResult {
                        rule_id: "SBOM-TOOLS-001".to_string(),
                        level: SarifLevel::Note,
                        message: SarifMessage {
                            text: format!(
                                "Component added: {} {}",
                                comp.name,
                                comp.new_version.as_deref().unwrap_or("")
                            ),
                        },
                        locations: vec![],
                    });
                }
            }

            for comp in &result.components.removed {
                results.push(SarifResult {
                    rule_id: "SBOM-TOOLS-002".to_string(),
                    level: SarifLevel::Warning,
                    message: SarifMessage {
                        text: format!(
                            "Component removed: {} {}",
                            comp.name,
                            comp.old_version.as_deref().unwrap_or("")
                        ),
                    },
                    locations: vec![],
                });
            }

            for comp in &result.components.modified {
                if self.include_info {
                    results.push(SarifResult {
                        rule_id: "SBOM-TOOLS-003".to_string(),
                        level: SarifLevel::Note,
                        message: SarifMessage {
                            text: format!(
                                "Component modified: {} {} -> {}",
                                comp.name,
                                comp.old_version.as_deref().unwrap_or("unknown"),
                                comp.new_version.as_deref().unwrap_or("unknown")
                            ),
                        },
                        locations: vec![],
                    });
                }
            }
        }

        // Add vulnerability results
        if config.includes(ReportType::Vulnerabilities) {
            for vuln in &result.vulnerabilities.introduced {
                let depth_label = match vuln.component_depth {
                    Some(1) => " [Direct]",
                    Some(_) => " [Transitive]",
                    None => "",
                };
                let sla_label = format_sla_label(vuln);
                results.push(SarifResult {
                    rule_id: "SBOM-TOOLS-005".to_string(),
                    level: severity_to_level(&vuln.severity),
                    message: SarifMessage {
                        text: format!(
                            "Vulnerability introduced: {} ({}){}{} in {} {}",
                            vuln.id,
                            vuln.severity,
                            depth_label,
                            sla_label,
                            vuln.component_name,
                            vuln.version.as_deref().unwrap_or("")
                        ),
                    },
                    locations: vec![],
                });
            }

            for vuln in &result.vulnerabilities.resolved {
                if self.include_info {
                    let depth_label = match vuln.component_depth {
                        Some(1) => " [Direct]",
                        Some(_) => " [Transitive]",
                        None => "",
                    };
                    let sla_label = format_sla_label(vuln);
                    results.push(SarifResult {
                        rule_id: "SBOM-TOOLS-006".to_string(),
                        level: SarifLevel::Note,
                        message: SarifMessage {
                            text: format!(
                                "Vulnerability resolved: {} ({}){}{} was in {}",
                                vuln.id, vuln.severity, depth_label, sla_label, vuln.component_name
                            ),
                        },
                        locations: vec![],
                    });
                }
            }
        }

        // Add license change results
        if config.includes(ReportType::Licenses) {
            for license in &result.licenses.new_licenses {
                results.push(SarifResult {
                    rule_id: "SBOM-TOOLS-004".to_string(),
                    level: SarifLevel::Warning,
                    message: SarifMessage {
                        text: format!(
                            "New license introduced: {} in components: {}",
                            license.license,
                            license.components.join(", ")
                        ),
                    },
                    locations: vec![],
                });
            }
        }

        // Add CRA compliance results for old and new SBOMs (use pre-computed if available)
        let cra_old = config.old_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(old_sbom)
        });
        let cra_new = config.new_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(new_sbom)
        });
        results.extend(compliance_results_to_sarif(&cra_old, Some("Old SBOM")));
        results.extend(compliance_results_to_sarif(&cra_new, Some("New SBOM")));

        let sarif = SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "sbom-tools".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                        rules: get_sarif_rules(),
                    },
                },
                results,
            }],
        };

        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ReportError::SerializationError(e.to_string()))
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let mut results = Vec::new();

        // Report vulnerabilities in the SBOM
        for (comp, vuln) in sbom.all_vulnerabilities() {
            let severity_str = vuln
                .severity
                .as_ref().map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
            results.push(SarifResult {
                rule_id: "SBOM-VIEW-001".to_string(),
                level: severity_to_level(&severity_str),
                message: SarifMessage {
                    text: format!(
                        "Vulnerability {} ({}) in {} {}",
                        vuln.id,
                        severity_str,
                        comp.name,
                        comp.version.as_deref().unwrap_or("")
                    ),
                },
                locations: vec![],
            });
        }

        // Add CRA compliance results (use pre-computed if available)
        let cra_result = config.view_cra_compliance.clone().unwrap_or_else(|| {
            ComplianceChecker::new(ComplianceLevel::CraPhase2).check(sbom)
        });
        results.extend(compliance_results_to_sarif(&cra_result, None));

        let sarif = SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "sbom-tools".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                        rules: get_sarif_view_rules(),
                    },
                },
                results,
            }],
        };

        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ReportError::SerializationError(e.to_string()))
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }
}

pub fn generate_compliance_sarif(result: &ComplianceResult) -> Result<String, ReportError> {
    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                    rules: get_sarif_compliance_rules(),
                },
            },
            results: compliance_results_to_sarif(result, None),
        }],
    };

    serde_json::to_string_pretty(&sarif)
        .map_err(|e| ReportError::SerializationError(e.to_string()))
}

fn severity_to_level(severity: &str) -> SarifLevel {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => SarifLevel::Error,
        "low" | "info" => SarifLevel::Note,
        _ => SarifLevel::Warning,
    }
}

/// Format SLA status for SARIF message
fn format_sla_label(vuln: &VulnerabilityDetail) -> String {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => format!(" [SLA: {days}d late]"),
        SlaStatus::DueSoon(days) | SlaStatus::OnTrack(days) => format!(" [SLA: {days}d left]"),
        SlaStatus::NoDueDate => vuln
            .days_since_published
            .map(|d| format!(" [Age: {d}d]"))
            .unwrap_or_default(),
    }
}

fn violation_severity_to_level(severity: ViolationSeverity) -> SarifLevel {
    match severity {
        ViolationSeverity::Error => SarifLevel::Error,
        ViolationSeverity::Warning => SarifLevel::Warning,
        ViolationSeverity::Info => SarifLevel::Note,
    }
}

/// Map a violation's requirement string to a specific SARIF rule ID.
fn violation_to_rule_id(requirement: &str) -> &'static str {
    let req = requirement.to_lowercase();
    if req.contains("art. 13(4)") || req.contains("art.13(4)") {
        "SBOM-CRA-ART-13-4"
    } else if req.contains("art. 13(6)") || req.contains("art.13(6)") {
        "SBOM-CRA-ART-13-6"
    } else if req.contains("art. 13(7)") || req.contains("art.13(7)") {
        "SBOM-CRA-ART-13-7"
    } else if req.contains("art. 13(8)") || req.contains("art.13(8)") {
        "SBOM-CRA-ART-13-8"
    } else if req.contains("art. 13(11)") || req.contains("art.13(11)") {
        "SBOM-CRA-ART-13-11"
    } else if req.contains("art. 13(12)") || req.contains("art.13(12)") {
        "SBOM-CRA-ART-13-12"
    } else if req.contains("art. 13(15)") || req.contains("art.13(15)") {
        "SBOM-CRA-ART-13-15"
    } else if req.contains("annex vii") {
        "SBOM-CRA-ANNEX-VII"
    } else if req.contains("annex i") || req.contains("annex_i") {
        "SBOM-CRA-ANNEX-I"
    } else {
        "SBOM-CRA-GENERAL"
    }
}

fn compliance_results_to_sarif(result: &ComplianceResult, label: Option<&str>) -> Vec<SarifResult> {
    let prefix = label.map(|l| format!("{l} - ")).unwrap_or_default();
    result
        .violations
        .iter()
        .map(|v| {
            let element = v.element.as_deref().unwrap_or("unknown");
            SarifResult {
                rule_id: violation_to_rule_id(&v.requirement).to_string(),
                level: violation_severity_to_level(v.severity),
                message: SarifMessage {
                    text: format!(
                        "{}{}: {} (Requirement: {}) [Element: {}]",
                        prefix,
                        result.level.name(),
                        v.message,
                        v.requirement,
                        element
                    ),
                },
                locations: vec![],
            }
        })
        .collect()
}

fn get_sarif_rules() -> Vec<SarifRule> {
    let mut rules = vec![
        SarifRule {
            id: "SBOM-TOOLS-001".to_string(),
            name: "ComponentAdded".to_string(),
            short_description: SarifMessage {
                text: "A new component was added to the SBOM".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-002".to_string(),
            name: "ComponentRemoved".to_string(),
            short_description: SarifMessage {
                text: "A component was removed from the SBOM".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-003".to_string(),
            name: "VersionChanged".to_string(),
            short_description: SarifMessage {
                text: "A component version was changed".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-004".to_string(),
            name: "LicenseChanged".to_string(),
            short_description: SarifMessage {
                text: "A license was added or changed".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-005".to_string(),
            name: "VulnerabilityIntroduced".to_string(),
            short_description: SarifMessage {
                text: "A new vulnerability was introduced".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-006".to_string(),
            name: "VulnerabilityResolved".to_string(),
            short_description: SarifMessage {
                text: "A vulnerability was resolved".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-TOOLS-007".to_string(),
            name: "SupplierChanged".to_string(),
            short_description: SarifMessage {
                text: "A component supplier was changed".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
    ];
    rules.extend(get_sarif_compliance_rules());
    rules
}

fn get_sarif_view_rules() -> Vec<SarifRule> {
    let mut rules = vec![SarifRule {
        id: "SBOM-VIEW-001".to_string(),
        name: "VulnerabilityPresent".to_string(),
        short_description: SarifMessage {
            text: "A vulnerability is present in a component".to_string(),
        },
        default_configuration: SarifConfiguration {
            level: SarifLevel::Warning,
        },
    }];
    rules.extend(get_sarif_compliance_rules());
    rules
}

fn get_sarif_compliance_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-CRA-ART-13-4".to_string(),
            name: "CraMachineReadableFormat".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(4): SBOM must be in a machine-readable format (CycloneDX 1.4+ or SPDX 2.3+)".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-6".to_string(),
            name: "CraVulnerabilityDisclosure".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(6): Vulnerability disclosure contact and metadata completeness".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-7".to_string(),
            name: "CraCoordinatedDisclosure".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(7): Coordinated vulnerability disclosure policy reference".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-8".to_string(),
            name: "CraSupportPeriod".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(8): Support period and security update end date".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-11".to_string(),
            name: "CraComponentLifecycle".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(11): Component lifecycle and end-of-support status".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-12".to_string(),
            name: "CraProductIdentification".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(12): Product name and version identification".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-15".to_string(),
            name: "CraManufacturerIdentification".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(15): Manufacturer identification and contact information".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ANNEX-I".to_string(),
            name: "CraTechnicalDocumentation".to_string(),
            short_description: SarifMessage {
                text: "CRA Annex I: Technical documentation (unique identifiers, dependencies, primary component)".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ANNEX-VII".to_string(),
            name: "CraDeclarationOfConformity".to_string(),
            short_description: SarifMessage {
                text: "CRA Annex VII: EU Declaration of Conformity reference".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-CRA-GENERAL".to_string(),
            name: "CraGeneralRequirement".to_string(),
            short_description: SarifMessage {
                text: "CRA general SBOM readiness requirement".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
    ]
}

// SARIF structures

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifConfiguration {
    level: SarifLevel,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: SarifLevel,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: Option<SarifPhysicalLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum SarifLevel {
    #[allow(dead_code)]
    None,
    Note,
    Warning,
    Error,
}
