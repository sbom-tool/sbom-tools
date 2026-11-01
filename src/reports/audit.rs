//! The audit fields of a compliance report: what `-o json`, `-o sarif` and
//! `-o oscal-json` each say about the run, the SBOM, each standard's
//! verdict and each finding, declared once.
//!
//! Each field is an [`AuditName`]: its name in `-o json`, the SARIF property
//! and the OSCAL property (or part) that carry it. [`RUN_FIELDS`],
//! [`SUBJECT_FIELDS`], [`RESULT_FIELDS`] and [`FINDING_FIELDS`] list them in
//! output order, and [`run_fields`], [`subject_fields`], [`result_fields`],
//! [`violation_fields`] and [`pass_fields`] give their values for one run,
//! SBOM, result or finding. The SARIF writer renders them as run and result
//! properties, the OSCAL writer as properties, links and remarks.
//!
//! The JSON envelope writes each result's and each finding's own
//! serialization, and the run and subject fields itself. The tests check
//! that the envelope carries every field listed here under its name and
//! with its value, and no field the lists leave out but the ones they name
//! as the envelope's own. So a field a finding or a result gains reaches
//! `-o json` once its type serializes it, and the tests fail until it is
//! declared here, as a name and a line in the function of each kind of
//! finding or result that has it; SARIF and OSCAL then carry it too.

use std::borrow::Cow;
use std::path::Path;

use crate::model::NormalizedSbom;
use crate::quality::{
    Applicability, ComplianceLevel, ComplianceResult, ConformityAssessmentSummary, PassedCheck,
    RuleEvaluation, StandardRef, SuppressedRule, Violation, ViolationSeverity, finding_id,
    finding_key, standard_key,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// The SBOM
// ---------------------------------------------------------------------------

/// The SBOM a compliance report is about: the parsed document, the SHA-256
/// of the bytes it was parsed from, and the name of the file they came
/// from.
///
/// [`generate_compliance_json_at`](super::generate_compliance_json_at)
/// describes it in the envelope's `subject`,
/// [`generate_assessment_results_at`](super::oscal::generate_assessment_results_at)
/// in the OSCAL document's SBOM resource, and
/// [`SarifOptions::with_subject`](super::SarifOptions::with_subject) in the
/// SARIF run's artifact and properties: the digest, the format and
/// specification version, the file name, and how the document was read
/// (its components, the duplicate entries merged, an unparseable creation
/// timestamp).
#[derive(Debug, Clone)]
pub struct AssessedSbom<'a> {
    sbom: &'a NormalizedSbom,
    sha256: String,
    file_name: Option<String>,
}

impl<'a> AssessedSbom<'a> {
    /// `sbom`, parsed from `input`, the bytes as read.
    #[must_use]
    pub fn new(sbom: &'a NormalizedSbom, input: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let sha256 = Sha256::digest(input)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            sbom,
            sha256,
            file_name: None,
        }
    }

    /// `sbom` with `sha256` as its digest, which need not be one: the OSCAL
    /// tests check what a digest that is no SHA-256 leaves out.
    #[cfg(test)]
    pub(crate) fn with_sha256(sbom: &'a NormalizedSbom, sha256: &str) -> Self {
        Self {
            sbom,
            sha256: sha256.to_string(),
            file_name: None,
        }
    }

    /// The SBOM as read from the file at `path`. The report names the file
    /// without its directory, so it holds no local path.
    #[must_use]
    pub fn with_file_name(mut self, path: impl AsRef<Path>) -> Self {
        self.file_name = path
            .as_ref()
            .file_name()
            .map(|name| name.to_string_lossy())
            // A Windows path read on another system keeps its backslashes.
            .and_then(|name| name.rsplit('\\').next().map(str::to_string))
            .filter(|name| !name.is_empty());
        self
    }

    /// The parsed document.
    #[must_use]
    pub const fn sbom(&self) -> &'a NormalizedSbom {
        self.sbom
    }

    /// Lowercase hex SHA-256 of the bytes the SBOM was parsed from.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The name of the file the SBOM was read from, without its directory;
    /// `None` for an SBOM read from standard input.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    /// The entries of the components the document lists more than once,
    /// before they were merged.
    pub(crate) fn duplicate_entries(&self) -> usize {
        self.sbom
            .duplicate_components
            .values()
            .map(|duplicate| duplicate.entries)
            .sum()
    }

    /// The fields those entries disagree on, each once, sorted.
    pub(crate) fn duplicate_conflicts(&self) -> Vec<String> {
        let fields: std::collections::BTreeSet<&str> = self
            .sbom
            .duplicate_components
            .values()
            .flat_map(|duplicate| duplicate.conflicts.iter().map(String::as_str))
            .collect();
        fields.into_iter().map(str::to_string).collect()
    }
}

/// `at` as the machine outputs write the instant a run judged: RFC 3339 in
/// UTC, with a fraction of a second only when it has one
/// (`2026-10-12T00:00:00Z`). The JSON envelope's `as_of` and the OSCAL
/// timestamps read the same.
pub(crate) fn instant_text(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// Where OSCAL carries a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OscalPart {
    /// The document's own fields: the instant is `metadata.last-modified`,
    /// each result's `start` and each observation's `collected`.
    Metadata,
    /// The SBOM document's back-matter resource.
    Subject,
    /// The standard's `results[]` entry.
    Result,
    /// The finding: what identifies it and how to resolve it.
    Finding,
    /// The finding's observation: the rule, how the check classified the
    /// finding, and what it read.
    Observation,
}

/// The names of one audit field in the machine outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditName {
    /// The field in `-o json`. A dot steps into an object: `counts.affected`
    /// is the `affected` field of `counts`.
    pub(crate) json: &'static str,
    /// The SARIF property, or `None` where SARIF says it in a field of its
    /// own (a result's `findingId`, `ruleId` and message, the SBOM's
    /// artifact). A dot nests it in an object, as in `-o json`:
    /// `subject.duplicates.entries`.
    pub(crate) sarif: Option<&'static str>,
    /// The OSCAL property; for a link, its relation, and for guidance, the
    /// `remarks` that carry it.
    pub(crate) oscal: &'static str,
    /// The part of the OSCAL document that carries it.
    pub(crate) part: OscalPart,
}

const fn name(
    json: &'static str,
    sarif: Option<&'static str>,
    oscal: &'static str,
    part: OscalPart,
) -> AuditName {
    AuditName {
        json,
        sarif,
        oscal,
        part,
    }
}

const AS_OF: AuditName = name("as_of", Some("asOf"), "last-modified", OscalPart::Metadata);

/// The fields of a run, in output order: the instant every standard was
/// judged at. `-o json` writes it beside the subject, SARIF as a run
/// property, OSCAL as the document's and each result's and observation's
/// timestamp.
pub(crate) const RUN_FIELDS: &[AuditName] = &[AS_OF];

/// The SHA-256 is the SBOM artifact's `sha-256` hash in SARIF
/// (`run.artifacts`), and the file is the artifact's location.
const SHA256: AuditName = name("sha256", None, "sha256", OscalPart::Subject);
const FORMAT: AuditName = name(
    "format",
    Some("subject.format"),
    "format",
    OscalPart::Subject,
);
const SPEC_VERSION: AuditName = name(
    "spec_version",
    Some("subject.specVersion"),
    "spec-version",
    OscalPart::Subject,
);
const FILE_NAME: AuditName = name("file_name", None, "file-name", OscalPart::Subject);
const COMPONENTS: AuditName = name(
    "components",
    Some("subject.components"),
    "component-count",
    OscalPart::Subject,
);
const DUPLICATE_COMPONENTS: AuditName = name(
    "duplicates.components",
    Some("subject.duplicates.components"),
    "duplicate-components",
    OscalPart::Subject,
);
const DUPLICATE_ENTRIES: AuditName = name(
    "duplicates.entries",
    Some("subject.duplicates.entries"),
    "duplicate-entries",
    OscalPart::Subject,
);
const DUPLICATE_CONFLICTS: AuditName = name(
    "duplicates.conflicts",
    Some("subject.duplicates.conflicts"),
    "duplicate-conflict",
    OscalPart::Subject,
);
const TIMESTAMP_UNPARSED: AuditName = name(
    "timestamp_unparsed",
    Some("subject.timestampUnparsed"),
    "timestamp-unparsed",
    OscalPart::Subject,
);

/// The fields of the SBOM a report is about, in output order. SARIF writes
/// them in a `subject` run property, but for the SHA-256 and the file
/// name, which are the SBOM's artifact.
pub(crate) const SUBJECT_FIELDS: &[AuditName] = &[
    SHA256,
    FORMAT,
    SPEC_VERSION,
    FILE_NAME,
    COMPONENTS,
    DUPLICATE_COMPONENTS,
    DUPLICATE_ENTRIES,
    DUPLICATE_CONFLICTS,
    TIMESTAMP_UNPARSED,
];

const STANDARD: AuditName = name("standard", Some("standard"), "standard", OscalPart::Result);
const STANDARD_NAME: AuditName = name("name", Some("profile"), "standard-name", OscalPart::Result);
const COMPLIANT: AuditName = name(
    "compliant",
    Some("compliant"),
    "is-compliant",
    OscalPart::Result,
);
const APPLICABLE: AuditName = name(
    "applicable",
    Some("applicable"),
    "applicability",
    OscalPart::Result,
);
const ERROR_COUNT: AuditName = name(
    "counts.error",
    Some("errorCount"),
    "error-count",
    OscalPart::Result,
);
const WARNING_COUNT: AuditName = name(
    "counts.warning",
    Some("warningCount"),
    "warning-count",
    OscalPart::Result,
);
const INFO_COUNT: AuditName = name(
    "counts.info",
    Some("infoCount"),
    "info-count",
    OscalPart::Result,
);
const PASSED_COUNT: AuditName = name(
    "counts.passed",
    Some("passedCount"),
    "passed-count",
    OscalPart::Result,
);
const NOT_APPLICABLE_REASON: AuditName = name(
    "not_applicable_reason",
    Some("notApplicableReason"),
    "not-applicable-reason",
    OscalPart::Result,
);
const SCORE: AuditName = name("score", Some("overallScore"), "score", OscalPart::Result);
const SUPPRESSED_COUNT: AuditName = name(
    "counts.suppressed",
    Some("suppressed"),
    "suppressed-count",
    OscalPart::Result,
);
const EXCLUDED_COMPONENTS: AuditName = name(
    "excluded_components",
    Some("excludedComponents"),
    "excluded-components",
    OscalPart::Result,
);
const EVALUATED: AuditName = name(
    "evaluated",
    Some("notEvaluated"),
    "not-evaluated",
    OscalPart::Result,
);
const SUPPRESSED: AuditName = name(
    "suppressed",
    Some("suppressedRules"),
    "suppressed",
    OscalPart::Result,
);
const CONFORMITY_SUMMARY: AuditName = name(
    "conformity_summary",
    Some("conformitySummary"),
    "conformity",
    OscalPart::Result,
);

/// The fields of one standard's verdict, in output order. SARIF counts the
/// severities too, so a run capped by `--sarif-max-results` still says how
/// many findings there were.
pub(crate) const RESULT_FIELDS: &[AuditName] = &[
    STANDARD,
    STANDARD_NAME,
    COMPLIANT,
    APPLICABLE,
    ERROR_COUNT,
    WARNING_COUNT,
    INFO_COUNT,
    PASSED_COUNT,
    NOT_APPLICABLE_REASON,
    SCORE,
    SUPPRESSED_COUNT,
    EXCLUDED_COMPONENTS,
    EVALUATED,
    SUPPRESSED,
    CONFORMITY_SUMMARY,
];

const FINDING_ID: AuditName = name("finding_id", None, "finding-id", OscalPart::Finding);
const FINDING_KEY: AuditName = name("finding_key", None, "finding-key", OscalPart::Finding);
const SEVERITY: AuditName = name(
    "severity",
    Some("severity"),
    "severity",
    OscalPart::Observation,
);
const DEFAULT_SEVERITY: AuditName = name(
    "default_severity",
    Some("defaultSeverity"),
    "default-severity",
    OscalPart::Observation,
);
const SEVERITY_SOURCE: AuditName = name(
    "severity_source",
    Some("severitySource"),
    "severity-source",
    OscalPart::Observation,
);
const REQUIREMENT: AuditName = name("requirement", None, "requirement", OscalPart::Observation);
const RULE_ID: AuditName = name("rule_id", Some("ruleId"), "rule-id", OscalPart::Observation);
const SARIF_RULE_ID: AuditName = name(
    "sarif_rule_id",
    None,
    "sarif-rule-id",
    OscalPart::Observation,
);
const ELEMENT: AuditName = name("element", None, "sbom-element", OscalPart::Observation);
const COMPONENT_ID: AuditName = name(
    "component_id",
    Some("componentId"),
    "component-id",
    OscalPart::Observation,
);
const AFFECTED: AuditName = name(
    "counts.affected",
    Some("affected"),
    "affected",
    OscalPart::Observation,
);
const TOTAL: AuditName = name(
    "counts.total",
    Some("total"),
    "total",
    OscalPart::Observation,
);
const DEADLINE: AuditName = name(
    "deadline",
    Some("deadline"),
    "deadline",
    OscalPart::Observation,
);
const DEADLINE_SOURCE: AuditName = name(
    "deadline_source",
    Some("deadlineSource"),
    "deadline-source",
    OscalPart::Observation,
);
const FIELD: AuditName = name("field", Some("field"), "field", OscalPart::Observation);
const OBSERVED: AuditName = name(
    "observed",
    Some("observed"),
    "observed",
    OscalPart::Observation,
);
const STANDARD_REFS: AuditName = name(
    "standard_refs",
    Some("standardRefs"),
    "standard-ref",
    OscalPart::Observation,
);
const REMEDIATION: AuditName = name(
    "remediation",
    Some("remediation"),
    "remarks",
    OscalPart::Finding,
);
const HELP_URI: AuditName = name("help_uri", Some("helpUri"), "help", OscalPart::Finding);

/// The fields of one finding, a violation or a passed check, in output
/// order. A passed check has the ones [`pass_fields`] gives: no severity,
/// counts, deadline, field, observed value, remediation or help URI.
pub(crate) const FINDING_FIELDS: &[AuditName] = &[
    FINDING_ID,
    FINDING_KEY,
    SEVERITY,
    DEFAULT_SEVERITY,
    SEVERITY_SOURCE,
    REQUIREMENT,
    RULE_ID,
    SARIF_RULE_ID,
    ELEMENT,
    COMPONENT_ID,
    AFFECTED,
    TOTAL,
    DEADLINE,
    DEADLINE_SOURCE,
    FIELD,
    OBSERVED,
    STANDARD_REFS,
    REMEDIATION,
    HELP_URI,
];

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// The value of one audit field, and how each output writes it.
#[derive(Debug, Clone)]
pub(crate) enum AuditValue<'a> {
    /// Text: a SARIF string and an OSCAL property.
    Text(Cow<'a, str>),
    /// A count: a SARIF integer and an OSCAL property.
    Count(usize),
    /// Yes or no: a SARIF boolean and an OSCAL property, `true` or `false`.
    Flag(bool),
    /// Whether the standard applied: a SARIF boolean and an OSCAL property,
    /// `applicable` or `not-applicable`.
    Applicability(bool),
    /// A score: a SARIF number (`22.0`) and an OSCAL property.
    Score(u8),
    /// A severity: in SARIF as `-o json` writes it (`Error`), in OSCAL in
    /// lowercase (`error`).
    Severity(ViolationSeverity),
    /// Words: a SARIF array of strings and one OSCAL property per word.
    Words(Vec<String>),
    /// A URL: a SARIF string and an OSCAL link.
    Link(&'a str),
    /// Guidance: a SARIF string and the remarks of the OSCAL finding.
    Guidance(Cow<'a, str>),
    /// Standard references: SARIF objects `{standard, id, helpUri}`, and one
    /// OSCAL property per reference (`class` the standard, `value` the
    /// clause) with a link for each reference that has a URL.
    References(&'a [StandardRef]),
    /// The checks not evaluated: SARIF objects `{ruleId, reason}`, and one
    /// OSCAL property per check with the reason in its remarks.
    NotEvaluated(&'a [RuleEvaluation]),
    /// The rules turned off: SARIF objects `{ruleId, findings, source}`, and
    /// three OSCAL properties per rule that share a `group`.
    Suppressed(&'a [SuppressedRule]),
    /// The CRA conformity summary: a SARIF object and OSCAL properties.
    Conformity(&'a ConformityAssessmentSummary),
}

/// One audit field of the SBOM, a result or a finding: its names and its
/// value.
#[derive(Debug, Clone)]
pub(crate) struct AuditField<'a> {
    pub(crate) name: AuditName,
    pub(crate) value: AuditValue<'a>,
}

/// A value as SARIF writes it. An object keeps its fields in the order
/// given, as the SARIF writer's own structs do.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SarifValue {
    /// A string, a number, a boolean or an array of strings.
    Scalar(Value),
    Array(Vec<SarifValue>),
    Object(Vec<(&'static str, SarifValue)>),
}

impl Serialize for SarifValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Self::Scalar(value) => value.serialize(serializer),
            Self::Array(items) => serializer.collect_seq(items),
            Self::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (name, value) in fields {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
        }
    }
}

/// `value` as its serde form: the token the enums of the model serialize to
/// (`CraArticle`, `cli`, `module-h`).
pub(crate) fn token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(token)) => token,
        _ => String::new(),
    }
}

impl AuditValue<'_> {
    /// The value as a SARIF property.
    pub(crate) fn sarif(&self) -> SarifValue {
        use SarifValue::{Array, Object, Scalar};
        match self {
            Self::Text(text) | Self::Guidance(text) => Scalar(Value::from(text.as_ref())),
            Self::Count(count) => Scalar(Value::from(*count)),
            Self::Flag(flag) | Self::Applicability(flag) => Scalar(Value::Bool(*flag)),
            Self::Score(score) => Scalar(Value::from(f64::from(*score))),
            Self::Severity(severity) => Scalar(Value::from(severity.name())),
            Self::Words(words) => Scalar(Value::from(words.clone())),
            Self::Link(uri) => Scalar(Value::from(*uri)),
            Self::References(refs) => Array(
                refs.iter()
                    .map(|r| {
                        let mut entry = vec![
                            ("standard", Scalar(Value::from(token(&r.standard)))),
                            ("id", Scalar(Value::from(r.id.as_str()))),
                        ];
                        if let Some(uri) = &r.help_uri {
                            entry.push(("helpUri", Scalar(Value::from(uri.as_str()))));
                        }
                        Object(entry)
                    })
                    .collect(),
            ),
            Self::NotEvaluated(checks) => Array(
                checks
                    .iter()
                    .map(|check| {
                        Object(vec![
                            ("ruleId", Scalar(Value::from(check.rule_id))),
                            ("reason", Scalar(Value::from(check.reason.as_str()))),
                        ])
                    })
                    .collect(),
            ),
            Self::Suppressed(rules) => Array(
                rules
                    .iter()
                    .map(|rule| {
                        Object(vec![
                            ("ruleId", Scalar(Value::from(rule.rule_id.as_str()))),
                            ("findings", Scalar(Value::from(rule.findings))),
                            ("source", Scalar(Value::from(rule.source.name()))),
                        ])
                    })
                    .collect(),
            ),
            Self::Conformity(summary) => Object(vec![
                (
                    "productClass",
                    Scalar(Value::from(token(&summary.product_class))),
                ),
                ("route", Scalar(Value::from(token(&summary.route)))),
                (
                    "evidence",
                    Array(
                        summary
                            .evidence
                            .iter()
                            .map(|e| {
                                Object(vec![
                                    ("label", Scalar(Value::from(e.label.as_str()))),
                                    ("detail", Scalar(Value::from(e.detail.as_str()))),
                                    ("satisfied", Scalar(Value::Bool(e.satisfied))),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
        }
    }

    /// The value as `-o json` writes it. The envelope writes its own
    /// serializations; the tests compare them with this.
    #[cfg(test)]
    pub(crate) fn json(&self) -> Value {
        let serialized = |value: Result<Value, serde_json::Error>| value.expect("serializes");
        match self {
            Self::Text(text) | Self::Guidance(text) => Value::from(text.as_ref()),
            Self::Count(count) => Value::from(*count),
            Self::Flag(flag) | Self::Applicability(flag) => Value::Bool(*flag),
            Self::Score(score) => Value::from(*score),
            Self::Severity(severity) => serialized(serde_json::to_value(severity)),
            Self::Words(words) => Value::from(words.clone()),
            Self::Link(uri) => Value::from(*uri),
            Self::References(refs) => serialized(serde_json::to_value(refs)),
            Self::NotEvaluated(checks) => serialized(serde_json::to_value(checks)),
            Self::Suppressed(rules) => serialized(serde_json::to_value(rules)),
            Self::Conformity(summary) => serialized(serde_json::to_value(summary)),
        }
    }
}

/// The fields of `rows` that have a value, in row order. The rows name
/// fields of `listed`, in its order, so the list is the output order.
fn present<'a, const N: usize>(
    listed: &[AuditName],
    rows: [(AuditName, Option<AuditValue<'a>>); N],
) -> Vec<AuditField<'a>> {
    debug_assert!(
        rows.iter()
            .map(|(name, _)| listed.iter().position(|listed| listed == name))
            .collect::<Option<Vec<usize>>>()
            .is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1])),
        "audit fields must be listed, and come in their list's order"
    );
    rows.into_iter()
        .filter_map(|(name, value)| {
            Some(AuditField {
                name,
                value: value?,
            })
        })
        .collect()
}

fn text<'a>(value: impl Into<Cow<'a, str>>) -> AuditValue<'a> {
    AuditValue::Text(value.into())
}

fn nonzero(count: usize) -> Option<AuditValue<'static>> {
    (count > 0).then_some(AuditValue::Count(count))
}

fn references(refs: &[StandardRef]) -> Option<AuditValue<'_>> {
    (!refs.is_empty()).then_some(AuditValue::References(refs))
}

// ---------------------------------------------------------------------------
// The fields of an SBOM, a result and a finding
// ---------------------------------------------------------------------------

/// The fields of a run judged at `as_of`, in [`RUN_FIELDS`] order.
pub(crate) fn run_fields(as_of: DateTime<Utc>) -> Vec<AuditField<'static>> {
    present(RUN_FIELDS, [(AS_OF, Some(text(instant_text(as_of))))])
}

/// The fields of `assessed`, in [`SUBJECT_FIELDS`] order.
pub(crate) fn subject_fields<'a>(assessed: &'a AssessedSbom<'_>) -> Vec<AuditField<'a>> {
    let document = &assessed.sbom.document;
    present(
        SUBJECT_FIELDS,
        [
            (SHA256, Some(text(assessed.sha256.as_str()))),
            (FORMAT, Some(text(document.format.to_string()))),
            (SPEC_VERSION, Some(text(document.spec_version.as_str()))),
            (FILE_NAME, assessed.file_name.as_deref().map(text)),
            (
                COMPONENTS,
                Some(AuditValue::Count(assessed.sbom.component_count())),
            ),
            (
                DUPLICATE_COMPONENTS,
                Some(AuditValue::Count(assessed.sbom.duplicate_components.len())),
            ),
            (
                DUPLICATE_ENTRIES,
                Some(AuditValue::Count(assessed.duplicate_entries())),
            ),
            (
                DUPLICATE_CONFLICTS,
                Some(AuditValue::Words(assessed.duplicate_conflicts())),
            ),
            (
                TIMESTAMP_UNPARSED,
                Some(AuditValue::Flag(document.created_unparsed.is_some())),
            ),
        ],
    )
}

/// The fields of `result`, in [`RESULT_FIELDS`] order.
pub(crate) fn result_fields(result: &ComplianceResult) -> Vec<AuditField<'_>> {
    let not_applicable_reason = match &result.applicability {
        Applicability::NotApplicable(reason) => Some(text(reason.as_str())),
        Applicability::Applicable => None,
    };
    present(
        RESULT_FIELDS,
        [
            (STANDARD, Some(text(standard_key(result.level)))),
            (STANDARD_NAME, Some(text(result.level.name()))),
            (COMPLIANT, Some(AuditValue::Flag(result.is_compliant))),
            (
                APPLICABLE,
                Some(AuditValue::Applicability(result.is_applicable())),
            ),
            (ERROR_COUNT, Some(AuditValue::Count(result.error_count))),
            (WARNING_COUNT, Some(AuditValue::Count(result.warning_count))),
            (INFO_COUNT, Some(AuditValue::Count(result.info_count))),
            (PASSED_COUNT, Some(AuditValue::Count(result.passed.len()))),
            (NOT_APPLICABLE_REASON, not_applicable_reason),
            (SCORE, result.score().map(AuditValue::Score)),
            (SUPPRESSED_COUNT, nonzero(result.suppressed_count())),
            (EXCLUDED_COMPONENTS, nonzero(result.excluded_components)),
            (
                EVALUATED,
                (!result.evaluated.is_empty())
                    .then_some(AuditValue::NotEvaluated(&result.evaluated)),
            ),
            (
                SUPPRESSED,
                (!result.suppressed.is_empty())
                    .then_some(AuditValue::Suppressed(&result.suppressed)),
            ),
            (
                CONFORMITY_SUMMARY,
                result
                    .conformity_summary
                    .as_ref()
                    .map(AuditValue::Conformity),
            ),
        ],
    )
}

/// The fields of `result` for an output that names and scores its run
/// itself, as `quality -o sarif` does: all but the standard's name and
/// score.
pub(crate) fn embedded_result_fields(result: &ComplianceResult) -> Vec<AuditField<'_>> {
    result_fields(result)
        .into_iter()
        .filter(|field| field.name != STANDARD_NAME && field.name != SCORE)
        .collect()
}

/// The fields of `violation`, reported under `level`, in
/// [`FINDING_FIELDS`] order.
pub(crate) fn violation_fields(
    level: ComplianceLevel,
    violation: &Violation,
) -> Vec<AuditField<'_>> {
    let key = finding_key(level, violation);
    let severity_override = violation.severity_override;
    present(
        FINDING_FIELDS,
        [
            (FINDING_ID, Some(text(finding_id(&key)))),
            (FINDING_KEY, Some(text(key))),
            (SEVERITY, Some(AuditValue::Severity(violation.severity))),
            (
                DEFAULT_SEVERITY,
                severity_override.map(|o| AuditValue::Severity(o.default)),
            ),
            (
                SEVERITY_SOURCE,
                severity_override.map(|o| text(o.source.name())),
            ),
            (REQUIREMENT, Some(text(violation.requirement.as_str()))),
            (RULE_ID, Some(text(violation.rule_id))),
            (SARIF_RULE_ID, Some(text(violation.sarif_rule_id()))),
            (ELEMENT, violation.element.as_deref().map(text)),
            (COMPONENT_ID, violation.component_id.as_deref().map(text)),
            (
                AFFECTED,
                violation.counts.map(|c| AuditValue::Count(c.affected)),
            ),
            (TOTAL, violation.counts.map(|c| AuditValue::Count(c.total))),
            (
                DEADLINE,
                violation
                    .deadline
                    .as_ref()
                    .map(|d| text(d.date.to_string())),
            ),
            (
                DEADLINE_SOURCE,
                violation.deadline.as_ref().map(|d| text(d.source.as_str())),
            ),
            (FIELD, violation.field.as_deref().map(text)),
            (OBSERVED, violation.observed.as_deref().map(text)),
            (STANDARD_REFS, references(&violation.standard_refs)),
            (
                REMEDIATION,
                Some(AuditValue::Guidance(violation.remediation_guidance())),
            ),
            (HELP_URI, violation.help_uri().map(AuditValue::Link)),
        ],
    )
}

/// The fields of `pass`, a check passed under `level`, in
/// [`FINDING_FIELDS`] order.
pub(crate) fn pass_fields(level: ComplianceLevel, pass: &PassedCheck) -> Vec<AuditField<'_>> {
    let key = finding_key(level, pass);
    present(
        FINDING_FIELDS,
        [
            (FINDING_ID, Some(text(finding_id(&key)))),
            (FINDING_KEY, Some(text(key))),
            (REQUIREMENT, Some(text(pass.requirement.as_str()))),
            (RULE_ID, Some(text(pass.rule_id))),
            (SARIF_RULE_ID, Some(text(pass.sarif_rule_id()))),
            (ELEMENT, pass.element.as_deref().map(text)),
            (COMPONENT_ID, pass.component_id.as_deref().map(text)),
            (STANDARD_REFS, references(&pass.standard_refs)),
        ],
    )
}

/// The SARIF properties `fields` give, in their order: those SARIF has a
/// property for, a dotted name nested in its objects in the order they
/// first appear.
pub(crate) fn sarif_properties(fields: &[AuditField<'_>]) -> Vec<(&'static str, SarifValue)> {
    let mut properties = Vec::new();
    for field in fields {
        if let Some(name) = field.name.sarif {
            insert(&mut properties, name, field.value.sarif());
        }
    }
    properties
}

/// Put `value` at the dotted `path` of `properties`.
fn insert(properties: &mut Vec<(&'static str, SarifValue)>, path: &'static str, value: SarifValue) {
    let Some((head, rest)) = path.split_once('.') else {
        properties.push((path, value));
        return;
    };
    let at = properties
        .iter()
        .position(|(name, value)| *name == head && matches!(value, SarifValue::Object(_)))
        .unwrap_or_else(|| {
            properties.push((head, SarifValue::Object(Vec::new())));
            properties.len() - 1
        });
    if let SarifValue::Object(inner) = &mut properties[at].1 {
        insert(inner, rest, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::{ComplianceRunConfig, RuleSetting, RuleSettings, SettingSource};
    use crate::reports::generate_compliance_json_at;
    use serde_json::json;

    /// The fields of a `-o json` finding that are no audit field: they
    /// describe the finding to a reader (SARIF and OSCAL carry the message
    /// as the result's message and the finding's description), or are part
    /// of its finding key.
    const JSON_ONLY_FINDING_FIELDS: &[&str] = &["category", "message", "finding_detail"];

    /// The fields of a `-o json` result that are no audit field: the
    /// findings themselves, and what the score is computed from.
    const JSON_ONLY_RESULT_FIELDS: &[&str] = &["score_basis", "violations", "passed"];

    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    /// A CycloneDX document that lists one component twice, with two
    /// descriptions, and whose creation timestamp does not parse.
    const DUPLICATES: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {
        "timestamp": "2026-13-45 noon",
        "component": { "type": "application", "name": "app", "version": "1.0", "bom-ref": "app" }
      },
      "components": [
        { "type": "library", "name": "lodash", "version": "4.17.21", "bom-ref": "a",
          "purl": "pkg:npm/lodash@4.17.21", "description": "one" },
        { "type": "library", "name": "lodash", "version": "4.17.21", "bom-ref": "b",
          "purl": "pkg:npm/lodash@4.17.21", "description": "two" }
      ]
    }"#;

    /// SBOMs that between them give every audit field a value: duplicate
    /// components and an unparseable timestamp, a CRA conformity summary,
    /// deadlines and passed checks, the checks not evaluated and components
    /// left out for their scope.
    fn sboms() -> Vec<(String, String)> {
        let mut sboms = vec![("duplicates".to_string(), DUPLICATES.to_string())];
        for rel in [
            "cyclonedx/minimal.cdx.json",
            "cra/cra-compliant.cdx.json",
            "cyclonedx/cbom-pqc-calendar.cdx.json",
            "cyclonedx/scope-excluded.cdx.json",
            "spdx/minimal.spdx.json",
            "spdx3/minimal.spdx3.json",
        ] {
            let path = format!("{}/tests/fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
            let raw = std::fs::read_to_string(&path).expect("fixture readable");
            sboms.push((rel.to_string(), raw));
        }
        sboms
    }

    /// Rule settings that set findings' severities and turn a rule off, so
    /// `default_severity`, `severity_source` and `suppressed` show.
    fn settings() -> RuleSettings {
        let mut settings = RuleSettings::new();
        for (rule, setting) in [
            ("SBOM-NTIA-SUPPLIER", RuleSetting::Warning),
            ("SBOM-CRA-COMPONENT-SUPPLIER", RuleSetting::Info),
            ("SBOM-NTIA-DEPENDENCY", RuleSetting::Off),
        ] {
            settings
                .set(rule, setting, SettingSource::Cli)
                .expect("a registered rule");
        }
        settings
    }

    /// The runs each SBOM is checked with: one with a CRA product class and
    /// PQC deadline mode, one with rule settings.
    fn runs() -> Vec<ComplianceRunConfig> {
        let pinned = ComplianceRunConfig::new().with_as_of(as_of());
        vec![
            pinned
                .clone()
                .with_product_class(crate::model::CraProductClass::Critical)
                .with_pqc_mode(crate::quality::PqcMode::Deadline),
            pinned.with_rule_settings(settings()),
        ]
    }

    /// The value at `path` (a dot steps into an object), or `None` when it
    /// is absent or null.
    fn at<'v>(object: &'v Value, path: &str) -> Option<&'v Value> {
        let value = path
            .split('.')
            .try_fold(object, |value, key| value.get(key))?;
        (!value.is_null()).then_some(value)
    }

    /// `object` carries each of `fields` under its name with its value, and
    /// every field it carries is one of `fields` or one of `json_only`.
    fn assert_carries(
        object: &Value,
        fields: &[AuditField<'_>],
        listed: &[AuditName],
        json_only: &[&str],
        label: &str,
    ) {
        for field in fields {
            assert_eq!(
                at(object, field.name.json),
                Some(&field.value.json()),
                "{label}: `{}` in {object}",
                field.name.json
            );
        }
        let Value::Object(map) = object else {
            panic!("{label}: not an object: {object}");
        };
        for (key, value) in map {
            if value.is_null() || json_only.contains(&key.as_str()) {
                continue;
            }
            let paths: Vec<String> = match value {
                // An object that is no field itself groups fields
                // (`counts.affected`).
                Value::Object(inner) if !listed.iter().any(|name| name.json == key) => {
                    inner.keys().map(|sub| format!("{key}.{sub}")).collect()
                }
                _ => vec![key.clone()],
            };
            for path in paths {
                assert!(
                    listed.iter().any(|name| name.json == path),
                    "{label}: `{path}` is in -o json but not in reports::audit"
                );
                assert!(
                    fields.iter().any(|field| field.name.json == path),
                    "{label}: `{path}` is in -o json, but its audit field has no value"
                );
            }
        }
    }

    /// The audit fields are the envelope's: its subject, every result and
    /// every finding carry each of their audit fields under the same name
    /// and with the same value, and every field they carry is an audit
    /// field or the envelope's own. Each listed field gets a value from one
    /// of the SBOMs, so none goes unchecked.
    #[test]
    fn the_json_envelope_carries_every_audit_field_and_no_other() {
        let mut seen = std::collections::BTreeSet::new();
        for (label, raw) in sboms() {
            let sbom = crate::parse_sbom_str(&raw).expect("SBOM parses");
            let assessed = AssessedSbom::new(&sbom, raw.as_bytes()).with_file_name("sbom.json");
            for run in runs() {
                let results = run.check_levels(ComplianceLevel::all(), &sbom);
                let text =
                    generate_compliance_json_at(&results, &assessed, as_of()).expect("serializes");
                let envelope: Value = serde_json::from_str(&text).expect("JSON");
                let run_level = run_fields(as_of());
                let own = ["schema", "tool", "subject", "results"];
                assert_carries(&envelope, &run_level, RUN_FIELDS, &own, &label);
                seen.extend(run_level.iter().map(|field| field.name.json));
                let subject = subject_fields(&assessed);
                assert_carries(&envelope["subject"], &subject, SUBJECT_FIELDS, &[], &label);
                seen.extend(subject.iter().map(|field| field.name.json));
                let entries = envelope["results"].as_array().expect("results");
                for (result, entry) in results.iter().zip(entries) {
                    let label = format!("{label} {:?}", result.level);
                    let fields = result_fields(result);
                    assert_carries(
                        entry,
                        &fields,
                        RESULT_FIELDS,
                        JSON_ONLY_RESULT_FIELDS,
                        &label,
                    );
                    seen.extend(fields.iter().map(|field| field.name.json));
                    let violations = entry["violations"].as_array().expect("violations");
                    for (violation, json) in result.violations.iter().zip(violations) {
                        let fields = violation_fields(result.level, violation);
                        let only = JSON_ONLY_FINDING_FIELDS;
                        assert_carries(json, &fields, FINDING_FIELDS, only, &label);
                        seen.extend(fields.iter().map(|field| field.name.json));
                    }
                    let passed = entry["passed"].as_array().expect("passed");
                    for (pass, json) in result.passed.iter().zip(passed) {
                        let fields = pass_fields(result.level, pass);
                        let only = JSON_ONLY_FINDING_FIELDS;
                        assert_carries(json, &fields, FINDING_FIELDS, only, &label);
                    }
                }
            }
        }
        for listed in RUN_FIELDS
            .iter()
            .chain(SUBJECT_FIELDS)
            .chain(RESULT_FIELDS)
            .chain(FINDING_FIELDS)
        {
            assert!(
                seen.contains(listed.json),
                "no SBOM gives `{}` a value, so its parity goes unchecked",
                listed.json
            );
        }
    }

    /// The SBOM above reads as one component in two entries, with a
    /// conflict, and its timestamp as unparseable.
    #[test]
    fn the_subject_says_how_the_document_was_read() {
        let sbom = crate::parse_sbom_str(DUPLICATES).expect("SBOM parses");
        let assessed = AssessedSbom::new(&sbom, DUPLICATES.as_bytes());
        let value = |name: AuditName| {
            subject_fields(&assessed)
                .into_iter()
                .find(|field| field.name == name)
                .map(|field| field.value.json())
        };
        assert_eq!(value(COMPONENTS), Some(Value::from(2)));
        assert_eq!(value(DUPLICATE_COMPONENTS), Some(Value::from(1)));
        assert_eq!(value(DUPLICATE_ENTRIES), Some(Value::from(2)));
        assert_eq!(value(DUPLICATE_CONFLICTS), Some(json!(["description"])));
        assert_eq!(value(TIMESTAMP_UNPARSED), Some(Value::Bool(true)));
        assert_eq!(value(FILE_NAME), None, "no file given");
    }

    /// No output names two fields of one kind alike.
    #[test]
    fn names_are_unique_in_each_output() {
        for (label, listed) in [
            ("run and subject", [RUN_FIELDS, SUBJECT_FIELDS].concat()),
            ("result", RESULT_FIELDS.to_vec()),
            ("finding", FINDING_FIELDS.to_vec()),
        ] {
            let mut json = std::collections::HashSet::new();
            let mut sarif = std::collections::HashSet::new();
            let mut oscal = std::collections::HashSet::new();
            for name in listed {
                assert!(json.insert(name.json), "{label}: JSON {}", name.json);
                if let Some(property) = name.sarif {
                    assert!(sarif.insert(property), "{label}: SARIF {property}");
                }
                assert!(
                    oscal.insert((name.part, name.oscal)),
                    "{label}: OSCAL {}",
                    name.oscal
                );
            }
        }
        // A SARIF run of one standard writes its verdict beside the run and
        // subject fields, so their names must not meet either.
        let run_level: std::collections::HashSet<&str> = RUN_FIELDS
            .iter()
            .chain(SUBJECT_FIELDS)
            .filter_map(|name| name.sarif)
            .map(|property| property.split('.').next().unwrap_or(property))
            .collect();
        for name in RESULT_FIELDS {
            if let Some(property) = name.sarif {
                assert!(!run_level.contains(property), "SARIF {property}");
            }
        }
    }

    /// SARIF nests a dotted name: the subject is one `subject` object, its
    /// duplicates one object in it, each in list order.
    #[test]
    fn sarif_nests_dotted_names_in_list_order() {
        let sbom = crate::parse_sbom_str(DUPLICATES).expect("SBOM parses");
        let assessed = AssessedSbom::new(&sbom, DUPLICATES.as_bytes());
        let mut fields: Vec<AuditField<'_>> = run_fields(as_of());
        fields.extend(subject_fields(&assessed));
        let properties = SarifValue::Object(sarif_properties(&fields));
        assert_eq!(
            serde_json::to_string(&properties).expect("JSON"),
            concat!(
                r#"{"asOf":"2026-10-12T00:00:00Z","subject":{"format":"CycloneDX","#,
                r#""specVersion":"1.6","components":2,"duplicates":{"components":1,"#,
                r#""entries":2,"conflicts":["description"]},"timestampUnparsed":true}}"#
            )
        );
    }

    #[test]
    fn the_file_name_keeps_no_directory() {
        let sbom = NormalizedSbom::default();
        for (path, name) in [
            ("/home/alice/sboms/app.cdx.json", Some("app.cdx.json")),
            ("sboms/app.cdx.json", Some("app.cdx.json")),
            ("app.cdx.json", Some("app.cdx.json")),
            ("C:\\Users\\alice\\app.cdx.json", Some("app.cdx.json")),
            ("/", None),
        ] {
            let assessed = AssessedSbom::new(&sbom, b"").with_file_name(path);
            assert_eq!(assessed.file_name(), name, "{path}");
        }
        assert_eq!(AssessedSbom::new(&sbom, b"").file_name(), None);
        assert_eq!(
            AssessedSbom::new(&sbom, b"abc").sha256(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// SARIF writes a score as a number with a fraction, as its
    /// `overallScore` always was, a severity as `-o json` does, and an
    /// object's fields in their own order.
    #[test]
    fn sarif_values_keep_their_established_forms() {
        let text = |value: &AuditValue<'_>| serde_json::to_string(&value.sarif()).expect("JSON");
        assert_eq!(text(&AuditValue::Score(22)), "22.0");
        assert_eq!(
            text(&AuditValue::Severity(ViolationSeverity::Warning)),
            "\"Warning\""
        );
        let checks = [RuleEvaluation::not_evaluated(
            "SBOM-CISA2026-SIGNATURE",
            "SPDX 2.x cannot carry a document signature",
        )];
        assert_eq!(
            text(&AuditValue::NotEvaluated(&checks)),
            r#"[{"ruleId":"SBOM-CISA2026-SIGNATURE","reason":"SPDX 2.x cannot carry a document signature"}]"#
        );
    }
}
