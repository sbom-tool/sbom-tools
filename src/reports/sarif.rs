//! SARIF 2.1.0 report generator for CI/CD integration.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use crate::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity, rule_meta,
};
use serde::Serialize;

/// SARIF report generator
pub struct SarifReporter {
    /// Include informational results
    include_info: bool,
}

impl SarifReporter {
    /// Create a new SARIF reporter
    #[must_use]
    pub const fn new() -> Self {
        Self { include_info: true }
    }

    /// Set whether to include informational results
    #[must_use]
    pub const fn include_info(mut self, include: bool) -> Self {
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
                        properties: None,
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
                    properties: None,
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
                        properties: None,
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
                let vex_label = format_vex_label(vuln.vex_state.as_ref());
                results.push(SarifResult {
                    rule_id: "SBOM-TOOLS-005".to_string(),
                    level: severity_to_level(&vuln.severity),
                    message: SarifMessage {
                        text: format!(
                            "Vulnerability introduced: {} ({}){}{}{} in {} {}",
                            vuln.id,
                            vuln.severity,
                            depth_label,
                            sla_label,
                            vex_label,
                            vuln.component_name,
                            vuln.version.as_deref().unwrap_or("")
                        ),
                    },
                    locations: vec![],
                    properties: None,
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
                    let vex_label = format_vex_label(vuln.vex_state.as_ref());
                    results.push(SarifResult {
                        rule_id: "SBOM-TOOLS-006".to_string(),
                        level: SarifLevel::Note,
                        message: SarifMessage {
                            text: format!(
                                "Vulnerability resolved: {} ({}){}{}{} was in {}",
                                vuln.id,
                                vuln.severity,
                                depth_label,
                                sla_label,
                                vex_label,
                                vuln.component_name
                            ),
                        },
                        locations: vec![],
                        properties: None,
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
                    properties: None,
                });
            }
        }

        // Add EOL results (from new SBOM)
        for comp in new_sbom.components.values() {
            if let Some(eol) = &comp.eol {
                match eol.status {
                    crate::model::EolStatus::EndOfLife => {
                        let eol_date_str = eol
                            .eol_date
                            .map_or_else(String::new, |d| format!(" (EOL: {d})"));
                        results.push(SarifResult {
                            rule_id: "SBOM-EOL-001".to_string(),
                            level: SarifLevel::Error,
                            message: SarifMessage {
                                text: format!(
                                    "Component '{}' version '{}' has reached end-of-life{} (product: {})",
                                    comp.name,
                                    comp.version.as_deref().unwrap_or("unknown"),
                                    eol_date_str,
                                    eol.product,
                                ),
                            },
                            locations: vec![],
                            properties: None,
                        });
                    }
                    crate::model::EolStatus::ApproachingEol => {
                        let days_str = eol
                            .days_until_eol
                            .map_or_else(String::new, |d| format!(" ({d} days remaining)"));
                        results.push(SarifResult {
                            rule_id: "SBOM-EOL-002".to_string(),
                            level: SarifLevel::Warning,
                            message: SarifMessage {
                                text: format!(
                                    "Component '{}' version '{}' is approaching end-of-life{} (product: {})",
                                    comp.name,
                                    comp.version.as_deref().unwrap_or("unknown"),
                                    days_str,
                                    eol.product,
                                ),
                            },
                            locations: vec![],
                            properties: None,
                        });
                    }
                    _ => {}
                }
            }
        }

        // Add CRA compliance results for old and new SBOMs (use pre-computed if available)
        let cra_old = config
            .old_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(old_sbom));
        let cra_new = config
            .new_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(new_sbom));
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
                        rules: SarifRuleWithUri::wrap_all(get_sarif_rules()),
                    },
                },
                results,
                properties: None,
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
                .as_ref()
                .map_or_else(|| "Unknown".to_string(), std::string::ToString::to_string);
            let vex_state = vuln
                .vex_status
                .as_ref()
                .map(|v| &v.status)
                .or_else(|| comp.vex_status.as_ref().map(|v| &v.status));
            let vex_label = format_vex_label(vex_state);
            results.push(SarifResult {
                rule_id: "SBOM-VIEW-001".to_string(),
                level: severity_to_level(&severity_str),
                message: SarifMessage {
                    text: format!(
                        "Vulnerability {} ({}){} in {} {}",
                        vuln.id,
                        severity_str,
                        vex_label,
                        comp.name,
                        comp.version.as_deref().unwrap_or("")
                    ),
                },
                locations: vec![],
                properties: None,
            });
        }

        // Add CRA compliance results (use pre-computed if available)
        let cra_result = config
            .view_cra_compliance
            .clone()
            .unwrap_or_else(|| ComplianceChecker::new(ComplianceLevel::CraPhase2).check(sbom));
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
                        rules: SarifRuleWithUri::wrap_all(get_sarif_view_rules()),
                    },
                },
                results,
                properties: None,
            }],
        };

        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ReportError::SerializationError(e.to_string()))
    }

    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }
}

/// Map an AI-readiness check ID (`AI-001`..`AI-010`) to its SARIF rule ID.
/// Unknown IDs fall back to the `SBOM-AIBOM-GENERAL` rule so a future check
/// never silently drops (`AiCheck`/`AiReadinessMetrics` are `#[non_exhaustive]`).
fn ai_check_to_rule_id(check_id: &str) -> &'static str {
    match check_id {
        "AI-001" => "SBOM-AIBOM-001",
        "AI-002" => "SBOM-AIBOM-002",
        "AI-003" => "SBOM-AIBOM-003",
        "AI-004" => "SBOM-AIBOM-004",
        "AI-005" => "SBOM-AIBOM-005",
        "AI-006" => "SBOM-AIBOM-006",
        "AI-007" => "SBOM-AIBOM-007",
        "AI-008" => "SBOM-AIBOM-008",
        "AI-009" => "SBOM-AIBOM-009",
        "AI-010" => "SBOM-AIBOM-010",
        _ => "SBOM-AIBOM-GENERAL",
    }
}

/// Default SARIF severity for each AI-readiness check. AI transparency is a
/// best-practice (not a mandated minimum element), so there are no hard
/// `error`s; documentation gaps are `warning`, softer/contextual gaps `note`.
/// This is the single source of truth shared by the rule table and the results.
fn aibom_level(check_id: &str) -> SarifLevel {
    match check_id {
        // AI-010 is the weight-hash integrity check: a missing weight hash
        // defeats tamper verification, so it is a `warning` like the other
        // load-bearing transparency checks (not a soft `note`).
        "AI-001" | "AI-002" | "AI-003" | "AI-005" | "AI-009" | "AI-010" => SarifLevel::Warning,
        _ => SarifLevel::Note,
    }
}

/// SARIF rule table for the AI BOM model-card completeness checks. The
/// `short_description` text matches the scorer's `CHECK_DEFS` names exactly.
fn get_sarif_aibom_rules() -> Vec<SarifRule> {
    // (rule id, AI check id for level lookup, PascalCase name, description).
    // Descriptions match the scorer's CHECK_DEFS names exactly.
    [
        (
            "SBOM-AIBOM-001",
            "AI-001",
            "AibomModelCardUrl",
            "Model card URL present",
        ),
        (
            "SBOM-AIBOM-002",
            "AI-002",
            "AibomArchitectureFamily",
            "Architecture family declared",
        ),
        (
            "SBOM-AIBOM-003",
            "AI-003",
            "AibomTrainingDatasets",
            "Training datasets referenced",
        ),
        (
            "SBOM-AIBOM-004",
            "AI-004",
            "AibomQuantitativeAnalysis",
            "Quantitative analysis present",
        ),
        (
            "SBOM-AIBOM-005",
            "AI-005",
            "AibomFairnessAssessment",
            "Fairness assessments included",
        ),
        (
            "SBOM-AIBOM-006",
            "AI-006",
            "AibomEnergyConsumption",
            "Energy consumption disclosed",
        ),
        (
            "SBOM-AIBOM-007",
            "AI-007",
            "AibomUseCases",
            "Use-cases documented",
        ),
        (
            "SBOM-AIBOM-008",
            "AI-008",
            "AibomLimitations",
            "Known limitations stated",
        ),
        (
            "SBOM-AIBOM-009",
            "AI-009",
            "AibomEthicalConsiderations",
            "Ethical considerations present",
        ),
        (
            "SBOM-AIBOM-010",
            "AI-010",
            "AibomModelWeightHashes",
            "Model weight hashes present",
        ),
        (
            "SBOM-AIBOM-GENERAL",
            "AI-GENERAL",
            "AibomGeneral",
            "AI BOM model-card completeness",
        ),
    ]
    .into_iter()
    .map(|(rule_id, check_id, name, desc)| SarifRule {
        id: rule_id.to_string(),
        name: name.to_string(),
        short_description: SarifMessage {
            text: desc.to_string(),
        },
        default_configuration: SarifConfiguration {
            level: aibom_level(check_id),
        },
    })
    .collect()
}

/// Generate a SARIF 2.1.0 report for an AI-readiness assessment, emitting one
/// `SBOM-AIBOM-*` result per failing check (findings-only, mirroring the
/// compliance SARIF). The rule table and run-level properties are always
/// emitted, including for the not-applicable (no ML components) case.
pub fn generate_ai_readiness_sarif(
    metrics: &crate::quality::AiReadinessMetrics,
    sbom_name: &str,
    profile: &str,
    overall_score: Option<f32>,
    grade: &str,
) -> Result<String, ReportError> {
    let results: Vec<SarifResult> = metrics
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| {
            let rule_id = ai_check_to_rule_id(&check.id);
            let detail_suffix = check
                .detail
                .as_ref()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default();
            SarifResult {
                rule_id: rule_id.to_string(),
                level: aibom_level(&check.id),
                message: SarifMessage {
                    text: format!(
                        "AIBOM check {} failed: {} ({:.0}% weight){detail_suffix}",
                        check.id,
                        check.name,
                        check.weight * 100.0
                    ),
                },
                locations: vec![],
                properties: Some(SarifResultProperties {
                    standard_ids: vec![format!("AIBOM:{}", check.id)],
                    standard_help_uris: rule_help_uri(rule_id)
                        .map(|u| vec![u.to_string()])
                        .unwrap_or_default(),
                }),
            }
        })
        .collect();

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                    rules: SarifRuleWithUri::wrap_all(get_sarif_aibom_rules()),
                },
            },
            results,
            properties: Some(SarifRunProperties {
                applicable: !metrics.is_not_applicable(),
                overall_score,
                grade: grade.to_string(),
                sbom: sbom_name.to_string(),
                profile: profile.to_string(),
            }),
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

pub fn generate_compliance_sarif(result: &ComplianceResult) -> Result<String, ReportError> {
    let rules = SarifRuleWithUri::wrap_all(get_sarif_rules_for_standard(result.level));
    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                    rules,
                },
            },
            results: compliance_results_to_sarif(result, None),
            properties: None,
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// Generate SARIF output for multiple compliance standards merged into one report.
pub fn generate_multi_compliance_sarif(
    results: &[ComplianceResult],
) -> Result<String, ReportError> {
    // Merge rules from all standards
    let mut all_rules = Vec::new();
    let mut all_results = Vec::new();

    for result in results {
        let rules = get_sarif_rules_for_standard(result.level);
        all_rules.extend(rules);
        all_results.extend(compliance_results_to_sarif(result, None));
    }

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/binarly-io/sbom-tools".to_string(),
                    rules: SarifRuleWithUri::wrap_all(all_rules),
                },
            },
            results: all_results,
            properties: None,
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
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

fn format_vex_label(vex_state: Option<&crate::model::VexState>) -> String {
    match vex_state {
        Some(crate::model::VexState::NotAffected) => " [VEX: Not Affected]".to_string(),
        Some(crate::model::VexState::Fixed) => " [VEX: Fixed]".to_string(),
        Some(crate::model::VexState::Affected) => " [VEX: Affected]".to_string(),
        Some(crate::model::VexState::UnderInvestigation) => {
            " [VEX: Under Investigation]".to_string()
        }
        None => String::new(),
    }
}

const fn violation_severity_to_level(severity: ViolationSeverity) -> SarifLevel {
    match severity {
        ViolationSeverity::Error => SarifLevel::Error,
        ViolationSeverity::Warning => SarifLevel::Warning,
        ViolationSeverity::Info => SarifLevel::Note,
    }
}

fn compliance_results_to_sarif(result: &ComplianceResult, label: Option<&str>) -> Vec<SarifResult> {
    let prefix = label.map(|l| format!("{l} - ")).unwrap_or_default();
    result
        .violations
        .iter()
        .map(|v| {
            let element = v.element.as_deref().unwrap_or("unknown");
            let standard_ids: Vec<String> = v
                .standard_refs
                .iter()
                .map(|sr| format!("{}:{}", sarif_standard_label(sr.standard), sr.id))
                .collect();
            let standard_help_uris: Vec<String> = v
                .standard_refs
                .iter()
                .filter_map(|sr| sr.help_uri.clone())
                .collect();
            let properties = if standard_ids.is_empty() && standard_help_uris.is_empty() {
                None
            } else {
                Some(SarifResultProperties {
                    standard_ids,
                    standard_help_uris,
                })
            };
            // The externally-visible SARIF rule ID comes from the rule
            // registry keyed by the violation's stable `rule_id` — never from
            // re-parsing the human-readable requirement string. Unregistered
            // keys fall back to the generic CRA rule.
            let sarif_rule_id = rule_meta(v.rule_id)
                .map_or("SBOM-CRA-GENERAL", |m| m.sarif_id)
                .to_string();
            SarifResult {
                rule_id: sarif_rule_id,
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
                properties,
            }
        })
        .collect()
}

/// Canonical URL for a SARIF rule, derived from its ID prefix. Returns
/// `None` for rule families that do not map to a single regulation /
/// specification (e.g., `SBOM-TOOLS-*` change-tracking rules).
fn rule_help_uri(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("SBOM-CRA-") {
        Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
    } else if rule_id.starts_with("SBOM-BSI-") {
        Some(
            "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html",
        )
    } else if rule_id.starts_with("SBOM-NIST-SSDF-") || rule_id.starts_with("SBOM-SSDF-") {
        Some("https://doi.org/10.6028/NIST.SP.800-218")
    } else if rule_id.starts_with("SBOM-EO14028-") || rule_id.starts_with("SBOM-EO-14028-") {
        Some("https://www.federalregister.gov/d/2021-10460")
    } else if rule_id.starts_with("SBOM-FDA-") {
        Some(
            "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions",
        )
    } else if rule_id.starts_with("SBOM-NTIA-") {
        Some("https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf")
    } else if rule_id.starts_with("SBOM-PQC-") || rule_id.starts_with("SBOM-NIST-PQC-") {
        Some("https://csrc.nist.gov/projects/post-quantum-cryptography")
    } else if rule_id.starts_with("SBOM-CNSA-") {
        Some(
            "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
        )
    } else if rule_id.starts_with("SBOM-CSAF-") {
        Some("https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html")
    } else if rule_id.starts_with("SBOM-AIBOM-") {
        Some("https://cyclonedx.org/capabilities/mlbom/")
    } else if rule_id.starts_with("SBOM-AIACT-") {
        Some("https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng")
    } else if rule_id.starts_with("SBOM-BSIAI-") {
        Some("https://www.bsi.bund.de")
    } else {
        None
    }
}

/// Compact, hyphen-safe label for a `StandardKind` used in SARIF
/// `properties.standardIds` strings.
fn sarif_standard_label(kind: crate::quality::StandardKind) -> &'static str {
    use crate::quality::StandardKind;
    match kind {
        StandardKind::CraArticle => "CRA",
        StandardKind::CraAnnex => "CRA-Annex",
        StandardKind::Pren40000_1_3 => "prEN-40000-1-3",
        StandardKind::BsiTr03183_2 => "BSI-TR-03183-2",
        StandardKind::NistSsdf => "NIST-SSDF",
        StandardKind::Eo14028 => "EO-14028",
        StandardKind::FdaPremarket => "FDA",
        StandardKind::NtiaMinimum => "NTIA",
        StandardKind::Csaf2 => "CSAF",
        StandardKind::Cnsa2 => "CNSA-2.0",
        StandardKind::NistPqc => "NIST-PQC",
        StandardKind::EuAiAct => "EU-AI-Act",
        StandardKind::BsiSbomForAi => "BSI-G7-SBOM-for-AI",
        StandardKind::Other => "Other",
    }
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
        SarifRule {
            id: "SBOM-EOL-001".to_string(),
            name: "ComponentEndOfLife".to_string(),
            short_description: SarifMessage {
                text: "A component has reached end-of-life".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EOL-002".to_string(),
            name: "ComponentApproachingEol".to_string(),
            short_description: SarifMessage {
                text: "A component is approaching end-of-life".to_string(),
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

/// Get the appropriate compliance rules based on the standard being checked.
fn get_sarif_rules_for_standard(level: ComplianceLevel) -> Vec<SarifRule> {
    match level {
        ComplianceLevel::NtiaMinimum => get_sarif_ntia_rules(),
        ComplianceLevel::FdaMedicalDevice => get_sarif_fda_rules(),
        ComplianceLevel::NistSsdf => get_sarif_ssdf_rules(),
        ComplianceLevel::Eo14028 => get_sarif_eo14028_rules(),
        _ => get_sarif_compliance_rules(),
    }
}

fn get_sarif_ntia_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-NTIA-AUTHOR".to_string(),
            name: "NtiaAuthor".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Author/creator information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-NAME".to_string(),
            name: "NtiaComponentName".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Component name".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-VERSION".to_string(),
            name: "NtiaVersion".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Component version string".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-SUPPLIER".to_string(),
            name: "NtiaSupplier".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Supplier name".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-IDENTIFIER".to_string(),
            name: "NtiaUniqueIdentifier".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Unique identifier (PURL/CPE/SWID)".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-DEPENDENCY".to_string(),
            name: "NtiaDependency".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: Dependency relationship".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-NTIA-GENERAL".to_string(),
            name: "NtiaGeneralRequirement".to_string(),
            short_description: SarifMessage {
                text: "NTIA Minimum Elements: General requirement".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
    ]
}

fn get_sarif_fda_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-FDA-CREATOR".to_string(),
            name: "FdaCreator".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: SBOM creator/manufacturer information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-FDA-NAMESPACE".to_string(),
            name: "FdaNamespace".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: SBOM serial number or document namespace".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-FDA-NAME".to_string(),
            name: "FdaDocumentName".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: SBOM document name/title".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-FDA-SUPPLIER".to_string(),
            name: "FdaSupplier".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Component supplier/manufacturer information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-FDA-HASH".to_string(),
            name: "FdaHash".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Component cryptographic hash".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-FDA-IDENTIFIER".to_string(),
            name: "FdaIdentifier".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Component unique identifier (PURL/CPE/SWID)".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-FDA-VERSION".to_string(),
            name: "FdaVersion".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Component version information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-FDA-DEPENDENCY".to_string(),
            name: "FdaDependency".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Dependency relationships".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-FDA-SUPPORT".to_string(),
            name: "FdaSupport".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Component support/contact information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-FDA-SECURITY".to_string(),
            name: "FdaSecurity".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: Security vulnerability information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-FDA-GENERAL".to_string(),
            name: "FdaGeneralRequirement".to_string(),
            short_description: SarifMessage {
                text: "FDA Medical Device: General SBOM requirement".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
    ]
}

fn get_sarif_ssdf_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-SSDF-PS1".to_string(),
            name: "SsdfProvenance".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PS.1: Provenance and creator identification".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PS2".to_string(),
            name: "SsdfBuildIntegrity".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PS.2: Build integrity — component cryptographic hashes"
                    .to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PS3".to_string(),
            name: "SsdfSupplierIdentification".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PS.3: Supplier identification for components".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PO1".to_string(),
            name: "SsdfSourceProvenance".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PO.1: Source code provenance — VCS references".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PO3".to_string(),
            name: "SsdfBuildMetadata".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PO.3: Build provenance — build system metadata".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PW4".to_string(),
            name: "SsdfDependencyManagement".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PW.4: Dependency management — relationships".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-PW6".to_string(),
            name: "SsdfVulnerabilityInfo".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF PW.6: Vulnerability information and security references"
                    .to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Note,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-RV1".to_string(),
            name: "SsdfComponentIdentification".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF RV.1: Component identification — unique identifiers".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-SSDF-GENERAL".to_string(),
            name: "SsdfGeneralRequirement".to_string(),
            short_description: SarifMessage {
                text: "NIST SSDF: General secure development requirement".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
    ]
}

fn get_sarif_eo14028_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-EO14028-FORMAT".to_string(),
            name: "Eo14028MachineReadable".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Machine-readable SBOM format requirement".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-AUTOGEN".to_string(),
            name: "Eo14028AutoGeneration".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Automated SBOM generation".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-CREATOR".to_string(),
            name: "Eo14028Creator".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): SBOM creator identification".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-IDENTIFIER".to_string(),
            name: "Eo14028Identifier".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Component unique identification".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-DEPENDENCY".to_string(),
            name: "Eo14028Dependency".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Dependency relationship information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-VERSION".to_string(),
            name: "Eo14028Version".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Component version information".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Error,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-INTEGRITY".to_string(),
            name: "Eo14028Integrity".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Component integrity verification (hashes)".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-DISCLOSURE".to_string(),
            name: "Eo14028Disclosure".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(g): Vulnerability disclosure process".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-SUPPLIER".to_string(),
            name: "Eo14028Supplier".to_string(),
            short_description: SarifMessage {
                text: "EO 14028 Sec 4(e): Supplier identification".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
        SarifRule {
            id: "SBOM-EO14028-GENERAL".to_string(),
            name: "Eo14028GeneralRequirement".to_string(),
            short_description: SarifMessage {
                text: "EO 14028: General SBOM requirement".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: SarifLevel::Warning,
            },
        },
    ]
}

fn get_sarif_compliance_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "SBOM-CRA-ART-13-3".to_string(),
            name: "CraUpdateFrequency".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(3): SBOM update frequency — timely regeneration after changes".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-CRA-ART-13-4".to_string(),
            name: "CraMachineReadableFormat".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(4): SBOM must be in a machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+)".to_string(),
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
            id: "SBOM-CRA-ART-13-5".to_string(),
            name: "CraLicensedComponentTracking".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(5): Licensed component tracking — license information for all components".to_string(),
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
            id: "SBOM-CRA-ART-13-9".to_string(),
            name: "CraKnownVulnerabilities".to_string(),
            short_description: SarifMessage {
                text: "CRA Art. 13(9): Known vulnerabilities statement — vulnerability data or assertion".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
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
            id: "SBOM-CRA-ANNEX-III".to_string(),
            name: "CraDocumentIntegrity".to_string(),
            short_description: SarifMessage {
                text: "CRA Annex III: Document signature/integrity — serial number, hash, or digital signature".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
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
        SarifRule {
            id: "SBOM-CRA-PRE-8-RQ-02".to_string(),
            name: "CraHardwareInventory".to_string(),
            short_description: SarifMessage {
                text: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware components must be inventoried with producer, name, identifier, and firmware version"
                    .to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-CRA-PRE-7-RQ-07-RE".to_string(),
            name: "CraVendorHashCarryThrough".to_string(),
            short_description: SarifMessage {
                text: "CRA prEN 40000-1-3 [PRE-7-RQ-07-RE]: Upstream vendor-supplied component hashes must be carried through into the SBOM"
                    .to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-5-1".to_string(),
            name: "BsiTr03183AuthorTool".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §5.1: SBOM author/tool identification".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-5-2".to_string(),
            name: "BsiTr03183Timestamp".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §5.2: ISO-8601 timestamp".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-5-3".to_string(),
            name: "BsiTr03183ComponentIdentifier".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §5.3: Component name and unique identifier".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-5-4".to_string(),
            name: "BsiTr03183ComponentHash".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §5.4: Component cryptographic hash (SHA-256+)".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-5-5".to_string(),
            name: "BsiTr03183Dependencies".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §5.5: Dependency relationships".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-6".to_string(),
            name: "BsiTr03183Recommended".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 §6: Recommended fields (license, supplier, lifecycle)".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-BSI-TR-03183-2-GENERAL".to_string(),
            name: "BsiTr03183General".to_string(),
            short_description: SarifMessage {
                text: "BSI TR-03183-2 general SBOM requirement".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        // EU AI Act Annex IV technical-documentation readiness (AI3).
        SarifRule {
            id: "SBOM-AIACT-NA".to_string(),
            name: "AiActNotApplicable".to_string(),
            short_description: SarifMessage {
                text: "EU AI Act Annex IV readiness not applicable — SBOM has no ML-model or dataset components".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-AIACT-ANNEX-IV-1".to_string(),
            name: "AiActGeneralDescription".to_string(),
            short_description: SarifMessage {
                text: "EU AI Act Annex IV §1: general description of the AI system (architecture, intended purpose)".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-AIACT-ANNEX-IV-2D".to_string(),
            name: "AiActTrainingData".to_string(),
            short_description: SarifMessage {
                text: "EU AI Act Annex IV §2(d): training-data characteristics, provenance, and sensitivity classification".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-AIACT-ANNEX-IV-2G".to_string(),
            name: "AiActValidationMetrics".to_string(),
            short_description: SarifMessage {
                text: "EU AI Act Annex IV §2(g): validation/testing metrics and computational-resources disclosure".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-AIACT-ANNEX-IV-3".to_string(),
            name: "AiActLimitations".to_string(),
            short_description: SarifMessage {
                text: "EU AI Act Annex IV §3: foreseeable limitations and risks".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        // BSI/G7 SBOM-for-AI Minimum Elements readiness (7 clusters).
        SarifRule {
            id: "SBOM-BSIAI-NA".to_string(),
            name: "BsiSbomForAiNotApplicable".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI minimum-elements readiness not applicable — SBOM has no ML-model or dataset components".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-BSIAI-META".to_string(),
            name: "BsiSbomForAiMetadata".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI Metadata cluster: author, data-format name + version, timestamp, generation tool, signature".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSIAI-SYS".to_string(),
            name: "BsiSbomForAiSystemLevel".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI System-Level cluster: primary AI system, producer, data flow & usage".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Warning },
        },
        SarifRule {
            id: "SBOM-BSIAI-MODEL".to_string(),
            name: "BsiSbomForAiModels".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI Models cluster: name, version, identifier, weight hash (NIST-approved algorithm), model card, architecture, datasets, limitations, license".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSIAI-DATASET".to_string(),
            name: "BsiSbomForAiDatasets".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI Datasets cluster: name, identifier, hash, license, sensitivity classification, provenance & intended use".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Error },
        },
        SarifRule {
            id: "SBOM-BSIAI-INFRA".to_string(),
            name: "BsiSbomForAiInfrastructure".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI Infrastructure cluster: runtime / framework dependency links".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
        },
        SarifRule {
            id: "SBOM-BSIAI-SEC".to_string(),
            name: "BsiSbomForAiSecurity".to_string(),
            short_description: SarifMessage {
                text: "BSI/G7 SBOM-for-AI Security cluster: AI-specific security controls, exploitability references".to_string(),
            },
            default_configuration: SarifConfiguration { level: SarifLevel::Note },
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
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifRunProperties>,
}

/// Run-level properties for an AI-readiness SARIF report. Mirrors the run
/// properties the hand-rolled quality SARIF emitted (minus `compliant`, which
/// is not meaningful for an AI-only report). `overall_score` is always emitted
/// (as `null` for the not-applicable case) so machine consumers can distinguish
/// "score 0" from "not applicable".
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRunProperties {
    applicable: bool,
    overall_score: Option<f32>,
    grade: String,
    sbom: String,
    profile: String,
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
    rules: Vec<SarifRuleWithUri>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifConfiguration,
}

/// SarifRule plus a derived `helpUri` (CRA-P5.1). Wraps the existing rule
/// definitions at serialization time so we don't need to thread the URL
/// through every call site that constructs a `SarifRule`. Computed via
/// `rule_help_uri()` based on the rule-ID prefix.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleWithUri {
    #[serde(flatten)]
    inner: SarifRule,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<&'static str>,
}

impl SarifRuleWithUri {
    fn wrap(inner: SarifRule) -> Self {
        let help_uri = rule_help_uri(&inner.id);
        Self { inner, help_uri }
    }

    fn wrap_all(rules: Vec<SarifRule>) -> Vec<Self> {
        rules.into_iter().map(Self::wrap).collect()
    }
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
    /// Standard references (CRA Article, prEN 40000-1-3 ID, BSI section, …)
    /// Surfaced in `properties.standardIds` so downstream GRC/CI tooling can
    /// map a finding to the exact harmonised-standard clause.
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifResultProperties>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    /// Standard reference IDs in the form `<standard>:<id>`
    /// (e.g., `prEN-40000-1-3:PRE-7-RQ-07`, `CRA:Art. 13(4)`).
    /// Plural to match SARIF `properties` extensibility convention.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standard_ids: Vec<String>,
    /// Canonical URLs for each standard the violation references — lifted
    /// from `StandardRef::help_uri`. Order parallels `standard_ids`. Empty
    /// when none of the references have a canonical home.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standard_help_uris: Vec<String>,
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
