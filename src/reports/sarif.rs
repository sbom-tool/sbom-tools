//! SARIF 2.1.0 report generator for CI/CD integration.
//!
//! Every result names its rule (`ruleId`, `ruleIndex`), points at the SBOM
//! line of the component it is about (or of the document's metadata) when
//! the writer is given the SBOM file ([`SarifArtifact`]), adds the
//! component's purl as a logical location, and carries a fingerprint of its
//! finding identity (`partialFingerprints`), so a code-scanning alert
//! survives the SBOM's lines moving. `automationDetails.id` gives each kind
//! of run a stable analysis category.
//!
//! A compliance result's properties carry the audit fields of its finding,
//! and a compliance run's properties the verdict of each standard, from the
//! lists `-o json` and `-o oscal-json` share (`reports::audit`).

use super::audit::{self, AssessedSbom};
use super::{ReportConfig, ReportError, ReportFormat, ReportGenerator, ReportType};
use crate::diff::{DiffResult, SlaStatus, VulnerabilityDetail};
use crate::model::NormalizedSbom;
use crate::quality::{
    ComplianceLevel, ComplianceResult, StandardRef, ViolationSeverity, compose_finding_key,
    finding_fingerprint, finding_id, generic_rule_id_for_level, rule_meta, standard_key,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

mod artifact;
mod locator;
mod rules;

pub use artifact::{SARIF_SRCROOT, SarifArtifact, SarifArtifactLocation};
pub use locator::SbomLocator;
use rules::SarifRule;

/// The `$schema` every SARIF log declares: the OASIS SARIF 2.1.0 schema
/// (Errata 01 edition), at the URL the schema itself gives as its `id`.
/// tests/fixtures/schemas/sarif/2.1.0/ keeps a verbatim copy.
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// The most results one SARIF run may carry by default: GitHub code scanning
/// rejects a SARIF file with more than 25,000 results in a run (and shows
/// only the 5,000 most severe). See [`SarifOptions::with_max_results`].
pub const DEFAULT_SARIF_MAX_RESULTS: usize = 25_000;

/// Options of the SARIF writers.
///
/// Without an artifact, results carry no physical location (only the
/// component's logical location), and GitHub code scanning drops them: the
/// CLI always passes the SBOM file.
#[derive(Debug, Clone)]
pub struct SarifOptions {
    artifact: Option<SarifArtifact>,
    subject: Option<SarifSubject>,
    category: Option<String>,
    include_passes: bool,
    max_results: usize,
}

impl Default for SarifOptions {
    fn default() -> Self {
        Self {
            artifact: None,
            subject: None,
            category: None,
            include_passes: false,
            max_results: DEFAULT_SARIF_MAX_RESULTS,
        }
    }
}

/// What a compliance run judged, as SARIF states it: the SHA-256 of the
/// SBOM's bytes, the `sha-256` hash of its artifact in `run.artifacts`, and
/// the run and subject audit fields (`asOf`, `subject`) as run properties.
#[derive(Debug, Clone)]
struct SarifSubject {
    sha256: String,
    properties: Vec<(&'static str, audit::SarifValue)>,
}

impl SarifOptions {
    /// Options with no artifact, no category, no passes and the default cap
    /// of [`DEFAULT_SARIF_MAX_RESULTS`] results.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Point every result at its line in `artifact`, the SBOM file the run
    /// checked.
    #[must_use]
    pub fn with_artifact(mut self, artifact: SarifArtifact) -> Self {
        self.artifact = Some(artifact);
        self
    }

    /// State what a compliance run judged, as `-o json` does: `assessed`,
    /// the SBOM, and `as_of`, the instant every standard was judged at. The
    /// run lists the SBOM in `run.artifacts`, at the artifact's location
    /// when the options have one, with the SHA-256 of its bytes as its
    /// `sha-256` hash, and its properties gain `asOf` and `subject` (the
    /// format, spec version and how the document was read). `validate`
    /// sets it.
    #[must_use]
    pub fn with_subject(mut self, assessed: &AssessedSbom<'_>, as_of: DateTime<Utc>) -> Self {
        let mut fields: Vec<audit::AuditField<'_>> = audit::run_fields(as_of);
        fields.extend(audit::subject_fields(assessed));
        self.subject = Some(SarifSubject {
            sha256: assessed.sha256().to_string(),
            properties: audit::sarif_properties(&fields),
        });
        self
    }

    /// Report the run under the code-scanning category `category` instead of
    /// the default one, which names only the kind of run and its standards
    /// or profile (`sbom-tools/cra+ntia/`, `sbom-tools/quality/security/`).
    ///
    /// The category is the run's `automationDetails.id`, with a `/`
    /// appended when `category` does not end in one, as GitHub's
    /// `upload-sarif` action does with its own `category` input. That input
    /// never replaces an id the SARIF already carries, so a workflow that
    /// uploads results for several SBOMs checked against the same standards
    /// gives each SBOM its category here. A blank `category` keeps the
    /// default.
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Also report every check the SBOM passed
    /// ([`ComplianceResult::passed`]) as a result of `kind: "pass"` at level
    /// `none` (`validate --sarif-include-passes`), with the location,
    /// fingerprints and finding identity a violation's result carries. Off by
    /// default: code scanning lists every result it receives, so a pass
    /// would read as an alert.
    #[must_use]
    pub const fn with_passes(mut self, include_passes: bool) -> Self {
        self.include_passes = include_passes;
        self
    }

    /// Keep at most `max_results` results in the run (`--sarif-max-results`;
    /// `0` keeps every result). A run that would hold more keeps the most
    /// severe ones (error, then warning, then note, then none, each level in
    /// report order), says in `invocations[0].toolExecutionNotifications` how
    /// many it omitted, and logs the same warning. GitHub code scanning
    /// rejects a run of more than [`DEFAULT_SARIF_MAX_RESULTS`] results and
    /// shows only its 5,000 most severe, so the default cap changes nothing
    /// GitHub would display.
    #[must_use]
    pub const fn with_max_results(mut self, max_results: usize) -> Self {
        self.max_results = max_results;
        self
    }

    /// The SBOM file results point into.
    #[must_use]
    pub const fn artifact(&self) -> Option<&SarifArtifact> {
        self.artifact.as_ref()
    }

    /// The category given with [`Self::with_category`].
    #[must_use]
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Whether passed checks are reported (see [`Self::with_passes`]).
    #[must_use]
    pub const fn include_passes(&self) -> bool {
        self.include_passes
    }

    /// The most results a run keeps; `0` means no cap (see
    /// [`Self::with_max_results`]).
    #[must_use]
    pub const fn max_results(&self) -> usize {
        self.max_results
    }

    /// The run properties the subject gives (`asOf`, `subject`); none
    /// without one (see [`Self::with_subject`]).
    fn subject_properties(&self) -> SarifProperties {
        SarifProperties(
            self.subject
                .as_ref()
                .map(|subject| subject.properties.clone())
                .unwrap_or_default(),
        )
    }

    /// `run.artifacts`: the SBOM, at the artifact's location when the
    /// options have one, with the SHA-256 of its bytes; `None` without a
    /// subject (see [`Self::with_subject`]).
    fn run_artifacts(&self) -> Option<Vec<SarifRunArtifact>> {
        let subject = self.subject.as_ref()?;
        let location = self.artifact.as_ref().map(|a| SarifArtifactLocationJson {
            uri: a.location().uri().to_string(),
            uri_base_id: a.location().uri_base_id().map(str::to_string),
        });
        Some(vec![SarifRunArtifact {
            location,
            hashes: BTreeMap::from([("sha-256", subject.sha256.clone())]),
        }])
    }
}

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

/// The finding-key scope of the results of `diff -o sarif` that are not
/// compliance findings.
const DIFF_SCOPE: &str = "diff";
/// The finding-key scope of the vulnerability results of `view -o sarif`.
const VIEW_SCOPE: &str = "view";
/// The finding-key scope of quality recommendations.
const QUALITY_SCOPE: &str = "quality";
/// The finding-key scope of AI-readiness check results.
const AI_READINESS_SCOPE: &str = "ai-readiness";

impl ReportGenerator for SarifReporter {
    /// A diff reports into the new SBOM only: a code-scanning alert belongs
    /// to the file in the repository, and the old SBOM is usually a copy of
    /// an earlier revision outside it. Results about the old side point at
    /// the new SBOM (see [`locate_old_component`]), and the old SBOM's own
    /// CRA findings are not results. The JSON and human-readable diff
    /// reports keep both sides.
    fn generate_diff_report(
        &self,
        result: &DiffResult,
        _old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let new = config.sarif.artifact();
        let mut new_keys = KeyBook::default();
        let mut results = Vec::new();

        // Add component change results
        if config.includes(ReportType::Components) {
            for comp in &result.components.added {
                if self.include_info {
                    results.push(sarif_result(
                        "SBOM-TOOLS-001",
                        SarifLevel::Note,
                        format!(
                            "Component added: {} {}",
                            comp.name,
                            comp.new_version.as_deref().unwrap_or("")
                        ),
                        new_keys.claim(DIFF_SCOPE, "SBOM-TOOLS-001", None, Some(&comp.id)),
                        locate(new, Some(&comp.id)),
                        SarifResultProperties::default(),
                    ));
                }
            }

            for comp in &result.components.removed {
                results.push(sarif_result(
                    "SBOM-TOOLS-002",
                    SarifLevel::Warning,
                    format!(
                        "Component removed: {} {}",
                        comp.name,
                        comp.old_version.as_deref().unwrap_or("")
                    ),
                    new_keys.claim(DIFF_SCOPE, "SBOM-TOOLS-002", None, Some(&comp.id)),
                    locate_old_component(new, &comp.id),
                    SarifResultProperties::default(),
                ));
            }

            for comp in &result.components.modified {
                // Unchanged inventory entries (--include-unchanged) are not
                // findings; emitting them as SBOM-TOOLS-003 pushed false
                // "modified" results into code-scanning consumers.
                if comp.change_type == crate::diff::ChangeType::Unchanged {
                    continue;
                }
                if self.include_info {
                    results.push(sarif_result(
                        "SBOM-TOOLS-003",
                        SarifLevel::Note,
                        format!(
                            "Component modified: {} {} -> {}",
                            comp.name,
                            comp.old_version.as_deref().unwrap_or("unknown"),
                            comp.new_version.as_deref().unwrap_or("unknown")
                        ),
                        new_keys.claim(DIFF_SCOPE, "SBOM-TOOLS-003", None, Some(&comp.id)),
                        locate(new, Some(&comp.id)),
                        SarifResultProperties::default(),
                    ));
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
                results.push(sarif_result(
                    "SBOM-TOOLS-005",
                    severity_to_level(&vuln.severity),
                    format!(
                        "Vulnerability introduced: {} ({}){}{}{} in {} {}",
                        vuln.id,
                        vuln.severity,
                        depth_label,
                        sla_label,
                        vex_label,
                        vuln.component_name,
                        vuln.version.as_deref().unwrap_or("")
                    ),
                    new_keys.claim(
                        DIFF_SCOPE,
                        "SBOM-TOOLS-005",
                        Some(&vuln.id),
                        Some(&vuln.component_id),
                    ),
                    locate(new, Some(&vuln.component_id)),
                    SarifResultProperties::default(),
                ));
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
                    results.push(sarif_result(
                        "SBOM-TOOLS-006",
                        SarifLevel::Note,
                        format!(
                            "Vulnerability resolved: {} ({}){}{}{} was in {}",
                            vuln.id,
                            vuln.severity,
                            depth_label,
                            sla_label,
                            vex_label,
                            vuln.component_name
                        ),
                        new_keys.claim(
                            DIFF_SCOPE,
                            "SBOM-TOOLS-006",
                            Some(&vuln.id),
                            Some(&vuln.component_id),
                        ),
                        locate_old_component(new, &vuln.component_id),
                        SarifResultProperties::default(),
                    ));
                }
            }
        }

        // Add license change results. A new license points at the first
        // component of the new SBOM that declares it.
        if config.includes(ReportType::Licenses) {
            for license in &result.licenses.new_licenses {
                let declaring = new_sbom
                    .components
                    .iter()
                    .find(|(_, c)| {
                        c.licenses
                            .declared
                            .iter()
                            .any(|l| l.expression == license.license)
                    })
                    .map(|(id, _)| id.value());
                results.push(sarif_result(
                    "SBOM-TOOLS-004",
                    SarifLevel::Warning,
                    format!(
                        "New license introduced: {} in components: {}",
                        license.license,
                        license.components.join(", ")
                    ),
                    new_keys.claim(DIFF_SCOPE, "SBOM-TOOLS-004", Some(&license.license), None),
                    locate(new, declaring),
                    SarifResultProperties::default(),
                ));
            }
        }

        // Add document-metadata change results (author/tool/timestamp/spec-version/etc.)
        for change in &result.metadata_changes {
            let old_value = change.old_value.as_deref().unwrap_or("(none)");
            let new_value = change.new_value.as_deref().unwrap_or("(none)");
            results.push(sarif_result(
                "SBOM-TOOLS-008",
                SarifLevel::Note,
                format!(
                    "Metadata {}: {} ({old_value} -> {new_value})",
                    change.kind, change.field
                ),
                new_keys.claim(DIFF_SCOPE, "SBOM-TOOLS-008", Some(&change.field), None),
                locate(new, None),
                SarifResultProperties::default(),
            ));
        }

        // Add EOL results (from new SBOM)
        for comp in new_sbom.components.values() {
            let Some(eol) = &comp.eol else {
                continue;
            };
            let id = comp.canonical_id.value();
            match eol.status {
                crate::model::EolStatus::EndOfLife => {
                    let eol_date_str = eol
                        .eol_date
                        .map_or_else(String::new, |d| format!(" (EOL: {d})"));
                    results.push(sarif_result(
                        "SBOM-EOL-001",
                        SarifLevel::Error,
                        format!(
                            "Component '{}' version '{}' has reached end-of-life{} (product: {})",
                            comp.name,
                            comp.version.as_deref().unwrap_or("unknown"),
                            eol_date_str,
                            eol.product,
                        ),
                        new_keys.claim(DIFF_SCOPE, "SBOM-EOL-001", None, Some(id)),
                        locate(new, Some(id)),
                        SarifResultProperties::default(),
                    ));
                }
                crate::model::EolStatus::ApproachingEol => {
                    let days_str = eol
                        .days_until_eol
                        .map_or_else(String::new, |d| format!(" ({d} days remaining)"));
                    results.push(sarif_result(
                        "SBOM-EOL-002",
                        SarifLevel::Warning,
                        format!(
                            "Component '{}' version '{}' is approaching end-of-life{} (product: {})",
                            comp.name,
                            comp.version.as_deref().unwrap_or("unknown"),
                            days_str,
                            eol.product,
                        ),
                        new_keys.claim(DIFF_SCOPE, "SBOM-EOL-002", None, Some(id)),
                        locate(new, Some(id)),
                        SarifResultProperties::default(),
                    ));
                }
                _ => {}
            }
        }

        // CRA compliance results for the new SBOM (pre-computed if available).
        let cra_new = config.new_cra_compliance_or_bare(new_sbom);
        results.extend(compliance_results_to_sarif(
            &cra_new,
            Some("New SBOM"),
            new,
            &mut new_keys,
        ));

        // Declare the rules of the standard checked, plus a descriptor for
        // any emitted ruleId it lacks (a fallback rule), each id once.
        let rules = rules::complete_rule_catalogue(rules::diff_rules(cra_new.level), &results);
        render_log(
            automation_id(config.sarif.category(), format!("sbom-tools/{DIFF_SCOPE}/")),
            rules,
            results,
            uses_srcroot([new]),
            None,
            None,
            config.sarif.max_results(),
        )
    }

    fn generate_view_report(
        &self,
        sbom: &NormalizedSbom,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let artifact = config.sarif.artifact();
        let mut keys = KeyBook::default();
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
            let id = comp.canonical_id.value();
            results.push(sarif_result(
                "SBOM-VIEW-001",
                severity_to_level(&severity_str),
                format!(
                    "Vulnerability {} ({}){} in {} {}",
                    vuln.id,
                    severity_str,
                    vex_label,
                    comp.name,
                    comp.version.as_deref().unwrap_or("")
                ),
                keys.claim(VIEW_SCOPE, "SBOM-VIEW-001", Some(&vuln.id), Some(id)),
                locate(artifact, Some(id)),
                SarifResultProperties::default(),
            ));
        }

        // Add CRA compliance results (use pre-computed if available)
        let cra_result = config.view_cra_compliance_or_bare(sbom);
        results.extend(compliance_results_to_sarif(
            &cra_result,
            None,
            artifact,
            &mut keys,
        ));

        // Same descriptor guarantee as the diff path (see above).
        let rules = rules::complete_rule_catalogue(rules::view_rules(cra_result.level), &results);
        render_log(
            automation_id(config.sarif.category(), format!("sbom-tools/{VIEW_SCOPE}/")),
            rules,
            results,
            uses_srcroot([artifact]),
            None,
            None,
            config.sarif.max_results(),
        )
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
    generate_ai_readiness_sarif_with(
        metrics,
        sbom_name,
        profile,
        overall_score,
        grade,
        &SarifOptions::default(),
    )
}

/// [`generate_ai_readiness_sarif`] with options: every result points at the
/// document line of `options`' artifact (a check result covers every model).
pub fn generate_ai_readiness_sarif_with(
    metrics: &crate::quality::AiReadinessMetrics,
    sbom_name: &str,
    profile: &str,
    overall_score: Option<f32>,
    grade: &str,
    options: &SarifOptions,
) -> Result<String, ReportError> {
    let artifact = options.artifact();
    let mut keys = KeyBook::default();
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
            // The fallback rule covers checks newer than the catalogue: the
            // check id tells its findings apart.
            let detail = (rule_id == "SBOM-AIBOM-GENERAL").then_some(check.id.as_str());
            sarif_result(
                rule_id,
                rules::aibom_level(&check.id),
                format!(
                    "AIBOM check {} failed: {} ({:.0}% weight){detail_suffix}",
                    check.id,
                    check.name,
                    check.weight * 100.0
                ),
                keys.claim(AI_READINESS_SCOPE, rule_id, detail, None),
                locate(artifact, None),
                SarifResultProperties {
                    standard_ids: vec![format!("AIBOM:{}", check.id)],
                    standard_help_uris: rules::rule_help_uri(rule_id)
                        .map(|u| vec![u.to_string()])
                        .unwrap_or_default(),
                    ..SarifResultProperties::default()
                },
            )
        })
        .collect();

    let properties = SarifRunProperties {
        applicable: Some(!metrics.is_not_applicable()),
        // Same contract as the compliance N/A surfaces: an N/A run
        // carries its human-readable reason (`AiReadinessMetrics`
        // populates `na_reason` exactly when `not_applicable`).
        not_applicable_reason: metrics.na_reason.clone(),
        overall_score,
        grade: Some(grade.to_string()),
        sbom: Some(sbom_name.to_string()),
        profile: Some(profile.to_string()),
        ..SarifRunProperties::default()
    };
    render_log(
        automation_id(options.category(), quality_category(profile)),
        rules::aibom_rules(),
        results,
        uses_srcroot([artifact]),
        None,
        Some(properties),
        options.max_results(),
    )
}

/// SARIF for one compliance standard: its violations, and none of its
/// passed checks (see [`generate_compliance_sarif_with`]).
pub fn generate_compliance_sarif(result: &ComplianceResult) -> Result<String, ReportError> {
    generate_compliance_sarif_with(result, &SarifOptions::default())
}

/// [`generate_compliance_sarif`] with options: results point at their lines
/// in `options`' artifact, and the passed checks follow the violations when
/// [`SarifOptions::include_passes`].
pub fn generate_compliance_sarif_with(
    result: &ComplianceResult,
    options: &SarifOptions,
) -> Result<String, ReportError> {
    let artifact = options.artifact();
    let mut keys = KeyBook::default();
    let mut results = compliance_results_to_sarif(result, None, artifact, &mut keys);
    if options.include_passes() {
        results.extend(passed_checks_to_sarif(result, artifact, &mut keys));
    }
    // The standard's verdict is the run's: its applicability (a readiness
    // standard that never evaluated the SBOM must be machine-distinguishable
    // from a pass), compliance, score and what the run kept out.
    let properties = SarifRunProperties {
        run: options.subject_properties(),
        verdict: SarifProperties::of(&audit::result_fields(result)),
        ..SarifRunProperties::default()
    };
    let rules = rules::complete_rule_catalogue(rules::rules_for_standard(result.level), &results);
    render_log(
        automation_id(
            options.category(),
            standards_category(std::iter::once(result.level)),
        ),
        rules,
        results,
        uses_srcroot([artifact]),
        options.run_artifacts(),
        Some(properties),
        options.max_results(),
    )
}

/// Generate SARIF output for multiple compliance standards merged into one
/// report, without their passed checks (see
/// [`generate_multi_compliance_sarif_with`]).
pub fn generate_multi_compliance_sarif(
    results: &[ComplianceResult],
) -> Result<String, ReportError> {
    generate_multi_compliance_sarif_with(results, &SarifOptions::default())
}

/// [`generate_multi_compliance_sarif`] with options: results point at their
/// lines in `options`' artifact, and each standard's passed checks follow its
/// violations when [`SarifOptions::include_passes`].
pub fn generate_multi_compliance_sarif_with(
    results: &[ComplianceResult],
    options: &SarifOptions,
) -> Result<String, ReportError> {
    let artifact = options.artifact();
    // Merge rules from all standards; `complete_rule_catalogue` dedups the
    // descriptors (two standards sharing the generic table used to emit
    // every descriptor twice, which SARIF validators reject) and covers any
    // emitted ruleId the static tables miss. Finding keys name their
    // standard, so one key book serves every standard.
    let mut keys = KeyBook::default();
    let mut all_rules = Vec::new();
    let mut all_results = Vec::new();

    for result in results {
        all_rules.extend(rules::rules_for_standard(result.level));
        all_results.extend(compliance_results_to_sarif(
            result, None, artifact, &mut keys,
        ));
        if options.include_passes() {
            all_results.extend(passed_checks_to_sarif(result, artifact, &mut keys));
        }
    }
    let all_rules = rules::complete_rule_catalogue(all_rules, &all_results);

    // Per-standard applicability/score/verdict ride on `properties.standards`
    // — without them a not-applicable standard in a merged run is
    // machine-indistinguishable from a pass (the single-standard run's flat
    // properties don't fit N standards). The flat per-standard fields stay
    // unset; `applicable` reports whether any standard evaluated the SBOM.
    let properties = SarifRunProperties {
        run: options.subject_properties(),
        applicable: Some(results.iter().any(ComplianceResult::is_applicable)),
        standards: results
            .iter()
            .map(|result| SarifProperties::of(&audit::result_fields(result)))
            .collect(),
        ..SarifRunProperties::default()
    };
    render_log(
        automation_id(
            options.category(),
            standards_category(results.iter().map(|r| r.level)),
        ),
        all_rules,
        all_results,
        uses_srcroot([artifact]),
        options.run_artifacts(),
        Some(properties),
        options.max_results(),
    )
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
    generate_quality_sarif_with(report, sbom_name, profile, &SarifOptions::default())
}

/// [`generate_quality_sarif`] with options: compliance results point at
/// their lines in `options`' artifact, recommendations (which count across
/// the document) at its document line. The embedded standard's passed checks
/// follow its violations when [`SarifOptions::include_passes`].
pub fn generate_quality_sarif_with(
    report: &crate::quality::QualityReport,
    sbom_name: &str,
    profile: &str,
    options: &SarifOptions,
) -> Result<String, ReportError> {
    let artifact = options.artifact();
    let mut keys = KeyBook::default();
    let mut results = compliance_results_to_sarif(&report.compliance, None, artifact, &mut keys);
    if options.include_passes() {
        results.extend(passed_checks_to_sarif(
            &report.compliance,
            artifact,
            &mut keys,
        ));
    }
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
        // A category holds several recommendations, told apart by their
        // message. Its numbers (counts, the standard's name) are masked so a
        // count that changes keeps the fingerprint.
        let key = keys.claim(
            QUALITY_SCOPE,
            &rule_id,
            Some(&mask_digits(&rec.message)),
            None,
        );
        results.push(sarif_result(
            rule_id,
            recommendation_level(rec.priority),
            format!(
                "{} ({} affected, +{:.1} impact)",
                rec.message, rec.affected_count, rec.impact
            ),
            key,
            locate(artifact, None),
            SarifResultProperties {
                priority: Some(rec.priority),
                affected_count: Some(rec.affected_count),
                impact: Some(rec.impact),
                ..SarifResultProperties::default()
            },
        ));
    }

    let catalogue = rules::complete_rule_catalogue(catalogue, &results);
    // The run names and scores itself (the quality profile and score), and
    // carries the rest of its embedded standard's verdict.
    let properties = SarifRunProperties {
        run: options.subject_properties(),
        overall_score: Some(report.overall_score),
        grade: Some(report.grade.letter().to_string()),
        sbom: Some(sbom_name.to_string()),
        profile: Some(profile.to_string()),
        verdict: SarifProperties::of(&audit::embedded_result_fields(&report.compliance)),
        ..SarifRunProperties::default()
    };
    render_log(
        automation_id(options.category(), quality_category(profile)),
        catalogue,
        results,
        uses_srcroot([artifact]),
        options.run_artifacts(),
        Some(properties),
        options.max_results(),
    )
}

// ---------------------------------------------------------------------------
// Result identity and location
// ---------------------------------------------------------------------------

/// The finding keys one SBOM's results of a run have used. A key that
/// repeats (an SBOM listing one vulnerability twice for a component) gets
/// `#2`, `#3`, … appended to its detail, so no two results of one SBOM share
/// a fingerprint. Compliance finding keys are unique per standard already
/// (see `quality::finding_key`), so they come out unchanged.
#[derive(Default)]
struct KeyBook {
    taken: HashSet<String>,
}

impl KeyBook {
    fn claim(
        &mut self,
        scope: &str,
        rule_id: &str,
        detail: Option<&str>,
        component_id: Option<&str>,
    ) -> String {
        let key = compose_finding_key(scope, rule_id, detail, component_id);
        if self.taken.insert(key.clone()) {
            return key;
        }
        let mut n = 2usize;
        loop {
            let numbered = detail.map_or_else(|| format!("#{n}"), |d| format!("{d}#{n}"));
            let key = compose_finding_key(scope, rule_id, Some(&numbered), component_id);
            if self.taken.insert(key.clone()) {
                return key;
            }
            n += 1;
        }
    }
}

/// `message` with every run of ASCII digits written `#`.
fn mask_digits(message: &str) -> String {
    let mut masked = String::with_capacity(message.len());
    let mut in_digits = false;
    for c in message.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                masked.push('#');
            }
            in_digits = true;
        } else {
            masked.push(c);
            in_digits = false;
        }
    }
    masked
}

/// The analysis category of a compliance run: the canonical `--standard`
/// values of its standards, sorted and joined by `+`, so the same set of
/// standards gives the same category whatever order they were asked in.
/// GitHub code scanning reads everything before the last `/` of
/// `automationDetails.id` as the category; the trailing `/` leaves the run
/// id empty.
fn standards_category(levels: impl Iterator<Item = ComplianceLevel>) -> String {
    let mut keys: Vec<&str> = levels.map(standard_key).collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        "sbom-tools/compliance/".to_string()
    } else {
        format!("sbom-tools/{}/", keys.join("+"))
    }
}

/// The analysis category of a `quality` run: its scoring profile.
fn quality_category(profile: &str) -> String {
    format!("sbom-tools/quality/{}/", profile.replace('/', "-"))
}

/// A run's `automationDetails.id`: the caller's `category`, ending in `/`
/// (see [`SarifOptions::with_category`]), else `default`, the category of
/// its kind of run.
fn automation_id(category: Option<&str>, default: String) -> String {
    match category {
        Some(category) if category.trim().is_empty() => default,
        Some(category) if category.ends_with('/') => category.to_string(),
        Some(category) => format!("{category}/"),
        None => default,
    }
}

/// Whether any of `artifacts` has a URI relative to the source root, so the
/// run must declare the `SRCROOT` base.
fn uses_srcroot<'a>(artifacts: impl IntoIterator<Item = Option<&'a SarifArtifact>>) -> bool {
    artifacts
        .into_iter()
        .flatten()
        .any(|a| a.location().uri_base_id().is_some())
}

/// The location of a result about the component whose canonical id is
/// `component_id`, or about the document when it is `None`:
///
/// - with an artifact, the SBOM file and the line of the component's id
///   (line 1 when the text states none: GitHub drops a result without a
///   physical location) or of the document's metadata;
/// - a component result also names the component as a logical location,
///   by its purl, else its format id (its canonical id without an
///   artifact).
fn locate(artifact: Option<&SarifArtifact>, component_id: Option<&str>) -> Vec<SarifLocation> {
    let logical_locations: Vec<SarifLogicalLocation> = component_id
        .map(|id| SarifLogicalLocation {
            name: artifact
                .and_then(|a| a.logical_name(id))
                .unwrap_or(id)
                .to_string(),
            kind: "component",
        })
        .into_iter()
        .collect();
    let physical_location = artifact.map(|a| {
        let line = component_id.map_or(a.document_line(), |id| a.component_line(id).unwrap_or(1));
        SarifPhysicalLocation {
            artifact_location: SarifArtifactLocationJson {
                uri: a.location().uri().to_string(),
                uri_base_id: a.location().uri_base_id().map(str::to_string),
            },
            region: SarifRegion { start_line: line },
        }
    });
    if physical_location.is_none() && logical_locations.is_empty() {
        return Vec::new();
    }
    vec![SarifLocation {
        physical_location,
        logical_locations,
    }]
}

/// The location of a diff result about a component of the old SBOM (a
/// removal, a resolved vulnerability) in the new SBOM the diff reports into:
/// the component's line when the new SBOM still lists it, else the new
/// SBOM's document line, as a removal is a change to the new file. The
/// component stays the logical location.
fn locate_old_component(new: Option<&SarifArtifact>, component_id: &str) -> Vec<SarifLocation> {
    let mut locations = locate(new, Some(component_id));
    if let (Some(artifact), Some(location)) = (new, locations.first_mut())
        && artifact.component_line(component_id).is_none()
        && let Some(physical) = location.physical_location.as_mut()
    {
        physical.region.start_line = artifact.document_line();
    }
    locations
}

/// One result. Its fingerprint and `properties.findingKey` /
/// `properties.findingId` come from `key`, its finding identity; the
/// `ruleIndex` is set once the run's rule catalogue is known.
fn sarif_result(
    rule_id: impl Into<String>,
    level: SarifLevel,
    message: String,
    key: String,
    locations: Vec<SarifLocation>,
    mut properties: SarifResultProperties,
) -> SarifResult {
    let fingerprint = finding_fingerprint(&key);
    properties.finding_id = finding_id(&key);
    properties.finding_key = key;
    SarifResult {
        rule_id: rule_id.into(),
        rule_index: None,
        kind: None,
        level,
        message: SarifMessage::new(message),
        locations,
        partial_fingerprints: SarifFingerprints::new(fingerprint),
        properties,
    }
}

/// Serialize one run: at most `max_results` results (see
/// [`cap_results`]), each with its `ruleIndex` set from `rules`, the
/// `SRCROOT` base declared when an artifact URI is relative to it, and
/// `artifacts` as `run.artifacts`.
fn render_log(
    automation_id: String,
    rules: Vec<SarifRule>,
    mut results: Vec<SarifResult>,
    relative_to_srcroot: bool,
    artifacts: Option<Vec<SarifRunArtifact>>,
    properties: Option<SarifRunProperties>,
    max_results: usize,
) -> Result<String, ReportError> {
    let total = results.len();
    let omitted = cap_results(&mut results, max_results);
    let invocations = (omitted > 0).then(|| {
        let text = format!(
            "{omitted} of {total} results were omitted to keep the run within {max_results} \
             results (--sarif-max-results; GitHub code scanning rejects a run of more than \
             {DEFAULT_SARIF_MAX_RESULTS}). The most severe were kept. Use -o json for the full \
             list."
        );
        tracing::warn!("{text}");
        vec![SarifInvocation {
            execution_successful: true,
            tool_execution_notifications: vec![SarifNotification {
                level: SarifLevel::Warning,
                message: SarifMessage::new(text),
            }],
        }]
    });
    let index: HashMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| (rule.id.as_str(), i))
        .collect();
    for result in &mut results {
        result.rule_index = index.get(result.rule_id.as_str()).copied();
    }
    let original_uri_base_ids = relative_to_srcroot.then(|| {
        BTreeMap::from([(
            SARIF_SRCROOT,
            SarifBaseDescription {
                description: SarifMessage::new(
                    "The root of the source tree relative artifact URIs resolve against: \
                     the repository the SBOM file is in, or the directory given as \
                     --sarif-base.",
                ),
            },
        )])
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
                    rules,
                },
            },
            invocations,
            automation_details: SarifAutomationDetails { id: automation_id },
            original_uri_base_ids,
            artifacts,
            results,
            properties,
        }],
    };
    serde_json::to_string_pretty(&sarif).map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// Keep at most `max_results` of `results`; `0` keeps them all. The kept
/// results are the most severe — every error, then warnings, notes and
/// `none` (passes) while room is left — and, within the level the cap falls
/// in, the first in report order; they stay in report order. Returns how
/// many were omitted.
fn cap_results(results: &mut Vec<SarifResult>, max_results: usize) -> usize {
    if max_results == 0 || results.len() <= max_results {
        return 0;
    }
    let mut per_level = [0usize; 4];
    for result in results.iter() {
        per_level[severity_rank(result.level)] += 1;
    }
    let mut room = max_results;
    let mut keep = [0usize; 4];
    for (kept, count) in keep.iter_mut().zip(per_level) {
        *kept = count.min(room);
        room -= *kept;
    }
    let omitted = results.len() - max_results;
    let mut kept_so_far = [0usize; 4];
    results.retain(|result| {
        let rank = severity_rank(result.level);
        let keep_it = kept_so_far[rank] < keep[rank];
        kept_so_far[rank] += usize::from(keep_it);
        keep_it
    });
    omitted
}

/// The order in which [`cap_results`] keeps levels: error first.
const fn severity_rank(level: SarifLevel) -> usize {
    match level {
        SarifLevel::Error => 0,
        SarifLevel::Warning => 1,
        SarifLevel::Note => 2,
        SarifLevel::None => 3,
    }
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

/// The SARIF results of one compliance result: one per violation, at the
/// line of the component it is about (or the document's), keyed by its
/// finding identity (`quality::finding_key`), with the violation's audit
/// fields as properties (`reports::audit`).
fn compliance_results_to_sarif(
    result: &ComplianceResult,
    label: Option<&str>,
    artifact: Option<&SarifArtifact>,
    keys: &mut KeyBook,
) -> Vec<SarifResult> {
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
            // The finding key is `finding_key(level, v)`; the key book only
            // numbers a key that would repeat, which no checker's key does.
            let key = keys.claim(
                standard_key(result.level),
                v.rule_id,
                v.finding_detail.as_deref(),
                v.component_id.as_deref(),
            );
            sarif_result(
                sarif_rule_id,
                violation_severity_to_level(v.severity),
                format!(
                    "{}{}: {} (Requirement: {}) [Element: {}]",
                    prefix,
                    result.level.name(),
                    v.message,
                    v.requirement,
                    element
                ),
                key,
                locate(artifact, v.component_id.as_deref()),
                SarifResultProperties {
                    standard_ids,
                    standard_help_uris,
                    audit: SarifProperties::of(&audit::violation_fields(result.level, v)),
                    ..SarifResultProperties::default()
                },
            )
        })
        .collect()
}

/// One result per check `result` passed, emitted only under
/// [`SarifOptions::include_passes`]: `kind: "pass"` at level `none` (SARIF
/// 2.1.0 §3.27.10: a result whose kind is not `fail` has level `none`), under
/// the pass-only rule, with the location and fingerprints a violation's
/// result carries and the pass's own audit fields as properties. Passes and
/// violations share one key space (a rule reports one or the other) and one
/// key book, so no pass shares a violation's fingerprint.
fn passed_checks_to_sarif(
    result: &ComplianceResult,
    artifact: Option<&SarifArtifact>,
    keys: &mut KeyBook,
) -> Vec<SarifResult> {
    result
        .passed
        .iter()
        .map(|pass| {
            let element = pass.element.as_deref().unwrap_or("unknown");
            let standard_ids: Vec<String> = pass
                .standard_refs
                .iter()
                .map(|sr| format!("{}:{}", sarif_standard_label(sr.standard), sr.id))
                .collect();
            let standard_help_uris: Vec<String> = pass
                .standard_refs
                .iter()
                .filter_map(|sr| sr.help_uri.clone())
                .collect();
            let key = keys.claim(
                standard_key(result.level),
                pass.rule_id,
                pass.finding_detail.as_deref(),
                pass.component_id.as_deref(),
            );
            let mut sarif = sarif_result(
                pass.sarif_rule_id(),
                SarifLevel::None,
                format!(
                    "{}: {} (Requirement: {}) [Element: {}]",
                    result.level.name(),
                    pass.message,
                    pass.requirement,
                    element
                ),
                key,
                locate(artifact, pass.component_id.as_deref()),
                SarifResultProperties {
                    standard_ids,
                    standard_help_uris,
                    audit: SarifProperties::of(&audit::pass_fields(result.level, pass)),
                    ..SarifResultProperties::default()
                },
            );
            sarif.kind = Some(SarifKind::Pass);
            sarif
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
        StandardKind::EnisaSbomAdvisory => "ENISA-SBOM-TA",
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
    /// Present only when results were omitted (see [`cap_results`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    invocations: Option<Vec<SarifInvocation>>,
    automation_details: SarifAutomationDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_uri_base_ids: Option<BTreeMap<&'static str, SarifBaseDescription>>,
    /// The SBOM a compliance run judged, with its SHA-256 (see
    /// [`SarifOptions::with_subject`]); absent without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    artifacts: Option<Vec<SarifRunArtifact>>,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifRunProperties>,
}

/// A `run.artifacts[]` entry: the SBOM file, where results point when the
/// run has its location, and the SHA-256 of its bytes under the
/// algorithm's IANA name, `sha-256`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRunArtifact {
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<SarifArtifactLocationJson>,
    hashes: BTreeMap<&'static str, String>,
}

/// `run.invocations[]`: the run succeeded, and its notifications say what
/// it left out.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    tool_execution_notifications: Vec<SarifNotification>,
}

/// One `toolExecutionNotifications` entry.
#[derive(Serialize)]
struct SarifNotification {
    level: SarifLevel,
    message: SarifMessage,
}

/// `run.automationDetails`: `id` is `sbom-tools/<category>/`.
#[derive(Serialize)]
struct SarifAutomationDetails {
    id: String,
}

/// An `originalUriBaseIds` entry. The base's absolute URI is left out: it
/// would put a local path (and user name) into the log, and GitHub resolves
/// relative URIs against the repository root without it.
#[derive(Serialize)]
struct SarifBaseDescription {
    description: SarifMessage,
}

/// Run-level properties shared by every sbom-tools SARIF surface (`validate`
/// single- and multi-standard, `quality`, and AI-readiness runs).
///
/// A compliance standard's verdict is a set of audit fields
/// (`reports::audit::result_fields`): the run's own properties for one
/// standard (`verdict`), one `standards[]` entry each for several, and for a
/// `quality` run the verdict of its embedded standard beside the quality
/// score. Every field is *omitted* when absent — never emitted as
/// `null`/`[]` — so machine consumers must treat a missing key as "no value"
/// and check `applicable` before reading any verdict field. In particular, a
/// run without an `overallScore` key is an unscored (not-applicable) run,
/// not a score of 0.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SarifRunProperties {
    /// What the run judged (see [`SarifOptions::with_subject`]): `asOf`,
    /// the instant, and `subject`, the SBOM's summary. Empty without one.
    #[serde(flatten)]
    run: SarifProperties,
    /// Whether the AI-readiness profile applied to the SBOM; for a
    /// multi-standard run, whether at least one standard applied (each
    /// standard's own verdict is in `standards`). A run with one standard
    /// says it in its verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    applicable: Option<bool>,
    /// Human-readable reason when an AI-readiness run's `applicable` is
    /// false; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<String>,
    /// The weighted 0-100 quality score of a `quality` or AI-readiness run.
    /// A `validate` run with one standard has the standard's compliance
    /// score (`ComplianceResult::score`) under the same name in its verdict;
    /// the two are not comparable.
    #[serde(skip_serializing_if = "Option::is_none")]
    overall_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sbom: Option<String>,
    /// The CLI profile of a `quality` or AI-readiness run. A `validate` run
    /// with one standard has the standard's display name under the same
    /// name in its verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// The verdict of the run's one standard, flattened into the run's
    /// properties: `validate` with one standard, and `quality` (less the
    /// standard's name and score, which the run's own fields replace).
    #[serde(flatten)]
    verdict: SarifProperties,
    /// One verdict per checked standard of a multi-standard compliance
    /// run, so a not-applicable standard stays machine-distinguishable from
    /// a pass when several standards share one run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standards: Vec<SarifProperties>,
}

/// Properties written in the order given: the audit fields of a compliance
/// finding or verdict, by their SARIF names (see `reports::audit`).
#[derive(Default)]
struct SarifProperties(Vec<(&'static str, audit::SarifValue)>);

impl SarifProperties {
    fn of(fields: &[audit::AuditField<'_>]) -> Self {
        Self(audit::sarif_properties(fields))
    }
}

impl Serialize for SarifProperties {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in &self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
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
    /// Index of the rule in the run's `rules`; set by [`render_log`].
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    /// The result's kind; omitted for a failed check (SARIF's default
    /// `fail`). Only a passed check under `--sarif-include-passes` sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<SarifKind>,
    level: SarifLevel,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    partial_fingerprints: SarifFingerprints,
    /// Finding identity, standard references (CRA Article, prEN 40000-1-3
    /// ID, BSI section, …) and the other per-result data.
    properties: SarifResultProperties,
}

/// `result.partialFingerprints`. Both keys derive from the finding identity
/// key, never from the SBOM text, so an alert survives the SBOM's lines
/// moving.
#[derive(Serialize)]
struct SarifFingerprints {
    /// The full SHA-256 hex of the finding identity key.
    #[serde(rename = "sbomToolsFinding/v1")]
    finding: String,
    /// GitHub code scanning matches alerts on this key alone, and its
    /// upload action fills it from the text of the result's line when it is
    /// absent — which re-keys alerts whenever that text or its neighbours
    /// change, and puts every result of a minified SBOM on one line. Setting
    /// it from the identity keeps alerts stable; the value has the action's
    /// shape (16 hex digits, `:1`).
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
}

impl SarifFingerprints {
    fn new(fingerprint: String) -> Self {
        let primary_location_line_hash = format!("{}:1", &fingerprint[..16]);
        Self {
            finding: fingerprint,
            primary_location_line_hash,
        }
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    /// The finding identity key (`quality::finding_key` for compliance
    /// results; the same shape with a surface name — `diff`, `view`,
    /// `quality`, `ai-readiness` — in place of the standard otherwise).
    finding_key: String,
    /// `sbomtools:v1:` + the first 16 hex digits of the key's SHA-256
    /// (`quality::finding_id`).
    finding_id: String,
    /// Standard reference IDs in the form `<standard>:<id>`
    /// (e.g., `prEN-40000-1-3:PRE-7-RQ-07`, `CRA:Art. 13(8)`).
    /// Plural to match SARIF `properties` extensibility convention.
    /// Deprecated in v0.4.0 and removed in v0.5.0: a compliance result
    /// carries its references as `-o json` does, in `standardRefs`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    standard_ids: Vec<String>,
    /// The canonical URLs of the references that have one, in reference
    /// order — lifted from `StandardRef::help_uri`. Empty when none of the
    /// references has a canonical home. Deprecated with `standardIds`.
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
    /// The audit fields of a compliance finding, by their SARIF names, the
    /// same `-o json` and `-o oscal-json` carry (`reports::audit`): its
    /// rule, severity, component, counts, deadline, field and observed value,
    /// references, remediation and help URI. Empty for every other result.
    #[serde(flatten)]
    audit: SarifProperties,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_location: Option<SarifPhysicalLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocationJson,
    region: SarifRegion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocationJson {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
}

/// A top-level logical location: SARIF requires a top-level location's
/// `fullyQualifiedName`, when present, to equal its `name`, so only `name`
/// is written.
#[derive(Serialize)]
struct SarifLogicalLocation {
    name: String,
    kind: &'static str,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SarifLevel {
    /// The level of a result whose kind is not `fail` (SARIF 2.1.0
    /// §3.27.9), such as a passed check.
    None,
    Note,
    Warning,
    Error,
}

/// SARIF `result.kind` values sbom-tools emits besides the default `fail`.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SarifKind {
    /// The rule was evaluated and its conditions were met.
    Pass,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_keys_are_numbered() {
        let mut keys = KeyBook::default();
        assert_eq!(
            keys.claim("view", "SBOM-VIEW-001", Some("CVE-1"), Some("pkg:a")),
            "view|SBOM-VIEW-001:CVE-1|pkg:a"
        );
        assert_eq!(
            keys.claim("view", "SBOM-VIEW-001", Some("CVE-1"), Some("pkg:a")),
            "view|SBOM-VIEW-001:CVE-1#2|pkg:a"
        );
        assert_eq!(
            keys.claim("diff", "SBOM-TOOLS-001", None, Some("pkg:a")),
            "diff|SBOM-TOOLS-001|pkg:a"
        );
        assert_eq!(
            keys.claim("diff", "SBOM-TOOLS-001", None, Some("pkg:a")),
            "diff|SBOM-TOOLS-001:#2|pkg:a"
        );
    }

    #[test]
    fn digits_are_masked_in_recommendation_details() {
        assert_eq!(
            mask_digits("Fix 12 compliance error(s) to meet CRA Phase 2 requirements"),
            "Fix # compliance error(s) to meet CRA Phase # requirements"
        );
        assert_eq!(mask_digits("no digits"), "no digits");
    }

    #[test]
    fn categories_are_stable_whatever_the_order() {
        assert_eq!(
            standards_category(
                [ComplianceLevel::NtiaMinimum, ComplianceLevel::Cisa2026].into_iter()
            ),
            "sbom-tools/cisa-2026+ntia/"
        );
        assert_eq!(
            standards_category(
                [ComplianceLevel::Cisa2026, ComplianceLevel::NtiaMinimum].into_iter()
            ),
            "sbom-tools/cisa-2026+ntia/"
        );
        assert_eq!(
            standards_category(std::iter::empty()),
            "sbom-tools/compliance/"
        );
        assert_eq!(quality_category("cra"), "sbom-tools/quality/cra/");
    }

    fn result_at(level: SarifLevel, n: usize) -> SarifResult {
        sarif_result(
            "SBOM-TOOLS-001",
            level,
            format!("result {n}"),
            format!("test|SBOM-TOOLS-001:{n}|document"),
            Vec::new(),
            SarifResultProperties::default(),
        )
    }

    fn messages(results: &[SarifResult]) -> Vec<&str> {
        results.iter().map(|r| r.message.text.as_str()).collect()
    }

    #[test]
    fn the_cap_keeps_the_most_severe_results_in_report_order() {
        use SarifLevel::{Error, None, Note, Warning};
        let levels = [Note, Error, None, Warning, Error, Note, Warning, Error];
        let run = || -> Vec<SarifResult> {
            levels
                .iter()
                .enumerate()
                .map(|(n, level)| result_at(*level, n))
                .collect()
        };

        // Room for every error and one warning: the first warning in
        // report order, and the kept results stay in report order.
        let mut results = run();
        assert_eq!(cap_results(&mut results, 4), 4);
        assert_eq!(
            messages(&results),
            ["result 1", "result 3", "result 4", "result 7"]
        );

        // Room for errors, warnings and one note; `none` goes first.
        let mut results = run();
        assert_eq!(cap_results(&mut results, 6), 2);
        assert_eq!(
            messages(&results),
            [
                "result 0", "result 1", "result 3", "result 4", "result 6", "result 7"
            ]
        );

        // No cap, or a cap the run fits in, keeps everything.
        for cap in [0, 8, 9] {
            let mut results = run();
            assert_eq!(cap_results(&mut results, cap), 0, "cap {cap}");
            assert_eq!(results.len(), 8, "cap {cap}");
        }
    }

    #[test]
    fn a_capped_run_says_how_many_results_it_omitted() {
        let results: Vec<SarifResult> = (0..5).map(|n| result_at(SarifLevel::Note, n)).collect();
        let sarif = render_log(
            "sbom-tools/test/".to_string(),
            Vec::new(),
            results,
            false,
            None,
            None,
            2,
        )
        .expect("serializes");
        let doc: serde_json::Value = serde_json::from_str(&sarif).expect("JSON");
        let run = &doc["runs"][0];
        assert_eq!(run["results"].as_array().map(Vec::len), Some(2));
        let invocation = &run["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], true);
        let notification = &invocation["toolExecutionNotifications"][0];
        assert_eq!(notification["level"], "warning");
        let text = notification["message"]["text"].as_str().expect("text");
        assert!(text.starts_with("3 of 5 results were omitted"), "{text}");
        assert!(text.contains("-o json"), "{text}");

        // An uncapped run has no invocations.
        let results: Vec<SarifResult> = (0..5).map(|n| result_at(SarifLevel::Note, n)).collect();
        let sarif = render_log(
            "sbom-tools/test/".to_string(),
            Vec::new(),
            results,
            false,
            None,
            None,
            DEFAULT_SARIF_MAX_RESULTS,
        )
        .expect("serializes");
        assert!(!sarif.contains("invocations"), "{sarif}");
    }

    #[test]
    fn a_given_category_replaces_the_default_and_ends_in_a_slash() {
        let default = || "sbom-tools/cra/".to_string();
        assert_eq!(automation_id(None, default()), "sbom-tools/cra/");
        assert_eq!(
            automation_id(Some("services/api/cra"), default()),
            "services/api/cra/"
        );
        assert_eq!(automation_id(Some("sbom-api/"), default()), "sbom-api/");
        assert_eq!(automation_id(Some(" "), default()), "sbom-tools/cra/");
    }

    #[test]
    fn fingerprints_derive_from_the_key() {
        let key = "ntia|SBOM-NTIA-AUTHOR|document";
        let fingerprints = SarifFingerprints::new(finding_fingerprint(key));
        assert_eq!(fingerprints.finding, finding_fingerprint(key));
        assert_eq!(
            fingerprints.primary_location_line_hash,
            "60072ae05d1ef4b8:1"
        );
    }
}

#[cfg(test)]
mod passed_check_tests {
    use super::*;
    use crate::quality::{PassedCheck, StandardKind};
    use serde_json::Value;
    use std::borrow::Cow;

    /// A NIST PQC result with one passed check and no violation.
    fn pqc_with_one_pass() -> ComplianceResult {
        ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new()).with_passed(vec![PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"
                .to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: vec![StandardRef::new(StandardKind::NistPqc, "FIPS 203/204/205")].into(),
        }])
    }

    fn results(sarif: &str) -> Vec<Value> {
        let value: Value = serde_json::from_str(sarif).expect("SARIF is JSON");
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .clone()
    }

    /// Without the option, no SARIF result describes a pass.
    #[test]
    fn passes_are_no_results_by_default() {
        let result = pqc_with_one_pass();
        for sarif in [
            generate_compliance_sarif(&result).expect("serializes"),
            generate_multi_compliance_sarif(std::slice::from_ref(&result)).expect("serializes"),
        ] {
            assert!(results(&sarif).is_empty(), "{sarif}");
            assert!(!sarif.contains("\"kind\""), "{sarif}");
        }
    }

    /// With the option, each pass is a `kind: "pass"` result at level
    /// `none` under the pass-only rule, which the catalogue declares.
    #[test]
    fn include_passes_emits_kind_pass_at_level_none() {
        let result = pqc_with_one_pass();
        let options = SarifOptions::new().with_passes(true);
        for sarif in [
            generate_compliance_sarif_with(&result, &options).expect("serializes"),
            generate_multi_compliance_sarif_with(std::slice::from_ref(&result), &options)
                .expect("serializes"),
        ] {
            let results = results(&sarif);
            assert_eq!(results.len(), 1, "{sarif}");
            let pass = &results[0];
            assert_eq!(pass["ruleId"], "SBOM-PQC-009");
            assert_eq!(pass["kind"], "pass");
            assert_eq!(pass["level"], "none");
            assert_eq!(
                pass["properties"]["componentId"],
                "crypto/algorithm/ml-kem-1024"
            );
            assert_eq!(
                pass["properties"]["standardIds"][0],
                "NIST-PQC:FIPS 203/204/205"
            );
            assert!(
                pass["message"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("uses NIST-approved PQC algorithm")),
                "{pass}"
            );
            let value: Value = serde_json::from_str(&sarif).expect("SARIF is JSON");
            let declared = value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .any(|rule| rule["id"] == "SBOM-PQC-009");
            assert!(declared, "the catalogue declares the pass rule: {sarif}");
        }
    }

    /// A violation's result keeps SARIF's default kind (`fail`): no `kind`.
    #[test]
    fn violations_carry_no_kind() {
        let result = ComplianceResult::new(
            ComplianceLevel::NtiaMinimum,
            vec![crate::quality::Violation {
                severity: ViolationSeverity::Error,
                category: crate::quality::ViolationCategory::DocumentMetadata,
                message: "SBOM must have creator/tool information".to_string(),
                element: None,
                requirement: "NTIA Minimum Elements: Author".to_string(),
                rule_id: "SBOM-NTIA-AUTHOR",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            }],
        );
        let sarif = generate_compliance_sarif_with(&result, &SarifOptions::new().with_passes(true))
            .expect("serializes");
        let results = results(&sarif);
        assert_eq!(results.len(), 1);
        assert!(results[0].get("kind").is_none(), "{sarif}");
        assert_eq!(results[0]["level"], "error");
    }
}
