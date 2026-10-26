//! SARIF 2.1.0 report generator for CI/CD integration.

use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use crate::quality::{
    ComplianceResult, StandardRef, ViolationSeverity, generic_rule_id_for_level, rule_meta,
};
use serde::Serialize;

mod rules;

use rules::SarifRule;

/// The `$schema` every SARIF log declares: the OASIS SARIF 2.1.0 schema
/// (Errata 01 edition), at the URL the schema itself gives as its `id`.
/// tests/fixtures/schemas/sarif/2.1.0/ keeps a verbatim copy.
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

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
                // Unchanged inventory entries (--include-unchanged) are not
                // findings; emitting them as SBOM-TOOLS-003 pushed false
                // "modified" results into code-scanning consumers.
                if comp.change_type == crate::diff::ChangeType::Unchanged {
                    continue;
                }
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

        // Add document-metadata change results (author/tool/timestamp/spec-version/etc.)
        for change in &result.metadata_changes {
            let old = change.old_value.as_deref().unwrap_or("(none)");
            let new = change.new_value.as_deref().unwrap_or("(none)");
            results.push(SarifResult {
                rule_id: "SBOM-TOOLS-008".to_string(),
                level: SarifLevel::Note,
                message: SarifMessage {
                    text: format!(
                        "Metadata {}: {} ({old} -> {new})",
                        change.kind, change.field
                    ),
                },
                locations: vec![],
                properties: None,
            });
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
        let cra_old = config.old_cra_compliance_or_bare(old_sbom);
        let cra_new = config.new_cra_compliance_or_bare(new_sbom);
        results.extend(compliance_results_to_sarif(&cra_old, Some("Old SBOM")));
        results.extend(compliance_results_to_sarif(&cra_new, Some("New SBOM")));

        // Guarantee every emitted ruleId has a descriptor (the static table
        // predates rules like SBOM-CRA-CYCLES) and descriptor ids are unique.
        let rules = rules::complete_rule_catalogue(rules::diff_rules(), &results);

        let sarif = SarifReport {
            schema: SARIF_SCHEMA_URI.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "sbom-tools".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                        rules,
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
        let cra_result = config.view_cra_compliance_or_bare(sbom);
        results.extend(compliance_results_to_sarif(&cra_result, None));

        // Same descriptor guarantee as the diff path (see above).
        let rules = rules::complete_rule_catalogue(rules::view_rules(), &results);

        let sarif = SarifReport {
            schema: SARIF_SCHEMA_URI.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "sbom-tools".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                        rules,
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
            let rule_id = rules::ai_check_to_rule_id(&check.id);
            let detail_suffix = check
                .detail
                .as_ref()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default();
            SarifResult {
                rule_id: rule_id.to_string(),
                level: rules::aibom_level(&check.id),
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
                    standard_help_uris: rules::rule_help_uri(rule_id)
                        .map(|u| vec![u.to_string()])
                        .unwrap_or_default(),
                    ..SarifResultProperties::default()
                }),
            }
        })
        .collect();

    let sarif = SarifReport {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                    rules: rules::aibom_rules(),
                },
            },
            results,
            properties: Some(SarifRunProperties {
                applicable: !metrics.is_not_applicable(),
                // Same contract as the compliance N/A surfaces: an N/A run
                // carries its human-readable reason (`AiReadinessMetrics`
                // populates `na_reason` exactly when `not_applicable`).
                not_applicable_reason: metrics.na_reason.clone(),
                overall_score,
                grade: Some(grade.to_string()),
                sbom: Some(sbom_name.to_string()),
                profile: Some(profile.to_string()),
                compliant: None,
                standards: Vec::new(),
            }),
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

pub fn generate_compliance_sarif(result: &ComplianceResult) -> Result<String, ReportError> {
    let results = compliance_results_to_sarif(result, None);
    // Surface applicability at run level: a readiness standard that never
    // evaluated the SBOM must be machine-distinguishable from a pass.
    let not_applicable_reason = match &result.applicability {
        crate::quality::Applicability::NotApplicable(reason) => Some(reason.clone()),
        crate::quality::Applicability::Applicable => None,
    };
    let run_properties = Some(SarifRunProperties {
        applicable: result.is_applicable(),
        not_applicable_reason,
        overall_score: result.score().map(f32::from),
        grade: None,
        sbom: None,
        profile: Some(result.level.name().to_string()),
        compliant: None,
        standards: Vec::new(),
    });
    let rules = rules::complete_rule_catalogue(rules::rules_for_standard(result.level), &results);
    let sarif = SarifReport {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                    rules,
                },
            },
            results,
            properties: run_properties,
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// Generate SARIF output for multiple compliance standards merged into one report.
pub fn generate_multi_compliance_sarif(
    results: &[ComplianceResult],
) -> Result<String, ReportError> {
    // Merge rules from all standards; `complete_rule_catalogue` dedups the
    // descriptors (two standards sharing the generic table used to emit
    // every descriptor twice, which SARIF validators reject) and covers any
    // emitted ruleId the static tables miss.
    let mut all_rules = Vec::new();
    let mut all_results = Vec::new();

    for result in results {
        all_rules.extend(rules::rules_for_standard(result.level));
        all_results.extend(compliance_results_to_sarif(result, None));
    }
    let all_rules = rules::complete_rule_catalogue(all_rules, &all_results);

    // Per-standard applicability/score/verdict ride on `properties.standards`
    // — without them a not-applicable standard in a merged run is
    // machine-indistinguishable from a pass (the single-standard run's flat
    // properties don't fit N standards). The flat per-standard fields stay
    // unset; `applicable` reports whether any standard evaluated the SBOM.
    let run_properties = Some(SarifRunProperties {
        applicable: results.iter().any(ComplianceResult::is_applicable),
        not_applicable_reason: None,
        overall_score: None,
        grade: None,
        sbom: None,
        profile: None,
        compliant: None,
        standards: results
            .iter()
            .map(StandardRunSummary::from_result)
            .collect(),
    });

    let sarif = SarifReport {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                    rules: all_rules,
                },
            },
            results: all_results,
            properties: run_properties,
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// Generate SARIF 2.1.0 output for the `quality` command (non-AI-readiness
/// profiles): a single run whose compliance violations flow through the same
/// registry-driven renderer as `validate -o sarif` — the same violation
/// carries the same external ruleId on both surfaces — plus the quality
/// recommendations as advisory results (never `error`; priority 1-2 map to
/// `warning`, lower priorities to `note`) under stable
/// `SBOM-QUALITY-REC-<CATEGORY>` rule ids. Score/grade/verdict ride on the
/// run-level properties.
pub fn generate_quality_sarif(
    report: &crate::quality::QualityReport,
    sbom_name: &str,
    profile: &str,
) -> Result<String, ReportError> {
    let mut results = compliance_results_to_sarif(&report.compliance, None);
    let mut catalogue = rules::rules_for_standard(report.compliance.level);

    // Quality recommendations: one advisory result each, plus a descriptor
    // per emitted recommendation category.
    let mut rec_rule_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for rec in &report.recommendations {
        let rule_id = format!(
            "SBOM-QUALITY-REC-{}",
            rec.category.name().to_uppercase().replace(' ', "-")
        );
        if rec_rule_ids.insert(rule_id.clone()) {
            catalogue.push(rules::quality_recommendation_rule(
                &rule_id,
                rec.category.name(),
            ));
        }
        results.push(SarifResult {
            rule_id,
            level: recommendation_level(rec.priority),
            message: SarifMessage {
                text: format!(
                    "{} ({} affected, +{:.1} impact)",
                    rec.message, rec.affected_count, rec.impact
                ),
            },
            locations: vec![],
            properties: Some(SarifResultProperties {
                priority: Some(rec.priority),
                affected_count: Some(rec.affected_count),
                impact: Some(rec.impact),
                ..SarifResultProperties::default()
            }),
        });
    }

    let catalogue = rules::complete_rule_catalogue(catalogue, &results);
    let not_applicable_reason = match &report.compliance.applicability {
        crate::quality::Applicability::NotApplicable(reason) => Some(reason.clone()),
        crate::quality::Applicability::Applicable => None,
    };
    let sarif = SarifReport {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sbom-tools".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
                    rules: catalogue,
                },
            },
            results,
            properties: Some(SarifRunProperties {
                applicable: report.compliance.is_applicable(),
                not_applicable_reason,
                overall_score: Some(report.overall_score),
                grade: Some(report.grade.letter().to_string()),
                sbom: Some(sbom_name.to_string()),
                profile: Some(profile.to_string()),
                compliant: Some(report.compliance.is_compliant),
                standards: Vec::new(),
            }),
        }],
    };

    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// SARIF level for a quality recommendation. Recommendations are advisory —
/// they must never be `error` (a P1 recommendation is not a compliance
/// failure): priority 1-2 render as `warning`, everything else as `note`.
const fn recommendation_level(priority: u8) -> SarifLevel {
    match priority {
        1 | 2 => SarifLevel::Warning,
        _ => SarifLevel::Note,
    }
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
            // The externally-visible SARIF rule ID comes from the rule
            // registry keyed by the violation's stable `rule_id` — never from
            // re-parsing the human-readable requirement string. Every check
            // is its own rule; a violation built outside the checkers carries
            // the `SBOM-CRA-GENERAL` default or an unregistered key, and is
            // re-bucketed onto the running standard's fallback rule so
            // NTIA/quality/... findings never surface under a CRA identity.
            let is_unmapped = v.rule_id == "SBOM-CRA-GENERAL" || rule_meta(v.rule_id).is_none();
            let sarif_rule_id = if is_unmapped {
                generic_rule_id_for_level(result.level)
            } else {
                v.sarif_rule_id()
            };
            // Fallback violations carry no standard_refs (the generic CRA
            // bucket has none); resolve them from the family-generic rule so
            // fallback results still carry `properties.standardIds` when the
            // running standard is known.
            let fallback_refs: Vec<StandardRef>;
            let refs: &[StandardRef] = if is_unmapped && v.standard_refs.is_empty() {
                fallback_refs = rule_meta(sarif_rule_id)
                    .map(|m| {
                        m.refs
                            .iter()
                            .map(|(kind, id)| StandardRef::new(*kind, *id))
                            .collect()
                    })
                    .unwrap_or_default();
                &fallback_refs
            } else {
                &v.standard_refs
            };
            let standard_ids: Vec<String> = refs
                .iter()
                .map(|sr| format!("{}:{}", sarif_standard_label(sr.standard), sr.id))
                .collect();
            let standard_help_uris: Vec<String> =
                refs.iter().filter_map(|sr| sr.help_uri.clone()).collect();
            let properties = if standard_ids.is_empty()
                && standard_help_uris.is_empty()
                && v.component_id.is_none()
                && v.counts.is_none()
            {
                None
            } else {
                Some(SarifResultProperties {
                    standard_ids,
                    standard_help_uris,
                    component_id: v.component_id.clone(),
                    affected: v.counts.map(|c| c.affected),
                    total: v.counts.map(|c| c.total),
                    ..SarifResultProperties::default()
                })
            };
            SarifResult {
                rule_id: sarif_rule_id.to_string(),
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
        StandardKind::Eucc => "EUCC",
        StandardKind::CisaMinimum2026 => "CISA-2026",
        StandardKind::PciDss4 => "PCI-DSS-v4",
        StandardKind::CisaFsct => "CISA-FSCT-3e",
        StandardKind::Other => "Other",
    }
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

/// Run-level properties shared by every sbom-tools SARIF surface (`validate`
/// single- and multi-standard, `quality`, and AI-readiness runs).
///
/// Every `Option`/`Vec` field is *omitted* when absent (`skip_serializing_if`)
/// — never emitted as `null`/`[]` — so machine consumers must treat a missing
/// key as "no value" and check `applicable` before reading any verdict field.
/// In particular, a run without an `overallScore` key is an unscored
/// (not-applicable) run, not a score of 0.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRunProperties {
    /// Whether the evaluated standard/profile actually applied to the SBOM.
    /// For multi-standard runs: whether at least one standard applied (the
    /// per-standard verdicts live in `standards`).
    applicable: bool,
    /// Human-readable reason when `applicable` is false; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<String>,
    /// Omitted when the run was not scored. Surface-dependent semantics: on
    /// `quality` runs this is the weighted 0-100 quality score, while on
    /// `validate` compliance runs it is the standard's compliance score
    /// (`ComplianceResult::score`) — the two are not comparable.
    #[serde(skip_serializing_if = "Option::is_none")]
    overall_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sbom: Option<String>,
    /// CLI profile name on `quality` runs; standard display name on
    /// `validate` runs. Omitted on multi-standard runs (see `standards`).
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// Compliance verdict for the embedded standard (quality reports only).
    #[serde(skip_serializing_if = "Option::is_none")]
    compliant: Option<bool>,
    /// Per-standard summaries for multi-standard compliance runs — one entry
    /// per checked standard, so a not-applicable standard stays
    /// machine-distinguishable from a pass when several standards share one
    /// run. Omitted on single-standard and quality runs, whose verdict rides
    /// on the flat fields above.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standards: Vec<StandardRunSummary>,
}

/// One `properties.standards` entry of a multi-standard compliance run.
/// Field semantics mirror the flat fields a single-standard run carries.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StandardRunSummary {
    /// Standard display name (the value the single-standard run's `profile`
    /// property carries).
    profile: String,
    /// Whether the standard actually evaluated the SBOM.
    applicable: bool,
    /// Human-readable N/A reason; omitted for applicable standards.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<String>,
    /// Compliance score (0-100); omitted when the standard did not evaluate
    /// the SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    overall_score: Option<f32>,
    /// Raw verdict. Stays `true` for not-applicable standards by the
    /// documented `ComplianceResult` contract — check `applicable` first.
    compliant: bool,
}

impl StandardRunSummary {
    fn from_result(result: &ComplianceResult) -> Self {
        let not_applicable_reason = match &result.applicability {
            crate::quality::Applicability::NotApplicable(reason) => Some(reason.clone()),
            crate::quality::Applicability::Applicable => None,
        };
        Self {
            profile: result.level.name().to_string(),
            applicable: result.is_applicable(),
            not_applicable_reason,
            overall_score: result.score().map(f32::from),
            compliant: result.is_compliant,
        }
    }
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

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    /// Standard reference IDs in the form `<standard>:<id>`
    /// (e.g., `prEN-40000-1-3:PRE-7-RQ-07`, `CRA:Art. 13(8)`).
    /// Plural to match SARIF `properties` extensibility convention.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standard_ids: Vec<String>,
    /// Canonical URLs for each standard the violation references — lifted
    /// from `StandardRef::help_uri`. Order parallels `standard_ids`. Empty
    /// when none of the references have a canonical home.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standard_help_uris: Vec<String>,
    /// Recommendation priority (1 = highest) — quality recommendations only.
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u8>,
    /// Number of affected components — quality recommendations only.
    #[serde(skip_serializing_if = "Option::is_none")]
    affected_count: Option<usize>,
    /// Estimated score impact — quality recommendations only.
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<f32>,
    /// Canonical id of the offending component (compliance results only) —
    /// mirrors `Violation::component_id`, the machine-readable join key back
    /// to the SBOM component. Absent for document-level/aggregate findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    component_id: Option<String>,
    /// Affected-component count for aggregate compliance findings — mirrors
    /// `Violation::counts.affected` (the numerator printed in the message).
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<usize>,
    /// Total-component count for aggregate compliance findings — mirrors
    /// `Violation::counts.total` (the message's denominator).
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

impl SarifMessage {
    fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
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

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SarifLevel {
    #[allow(dead_code)]
    None,
    Note,
    Warning,
    Error,
}
