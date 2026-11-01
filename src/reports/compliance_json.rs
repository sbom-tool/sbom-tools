//! The `sbom-tools/compliance/v2` JSON envelope emitted by `validate -o json`.
//!
//! One object whatever the number of standards checked, with one `results[]`
//! entry per standard. The schema is published at
//! `schemas/compliance/v2.schema.json`; docs/compliance-output.md describes
//! every field.
//!
//! Each violation, and each passed check, is its own serialization
//! ([`Violation`], [`PassedCheck`]) plus its finding identity ([`finding_id`],
//! [`finding_key`]), and each result carries every field of the
//! [`ComplianceResult`]'s serialization the envelope does not render itself,
//! with each `<kind>_count` collected under `counts.<kind>`. A field any of
//! these types gains therefore reaches this envelope without a change here;
//! the schema tests fail until the schema declares it, and the audit tests
//! (`reports::audit`) until SARIF and OSCAL carry it too.
//!
//! [`generate_compliance_json_at`] adds what the envelope says about the run:
//! the instant the verdicts were judged at (`as_of`) and the SBOM they judge
//! (`subject`).

use super::ReportError;
use super::audit::{AssessedSbom, instant_text};
use crate::quality::{
    Applicability, ComplianceResult, ConformityAssessmentSummary, FindingIdentity, PassedCheck,
    RuleEvaluation, Violation, finding_id, finding_key, standard_key,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

/// The envelope's `schema` value.
pub const COMPLIANCE_JSON_SCHEMA: &str = "sbom-tools/compliance/v2";

/// Fields of a [`ComplianceResult`]'s serialization that the envelope
/// renders itself (as `standard`/`name`, `compliant`, `applicable`/
/// `not_applicable_reason`, `counts`, `violations`, `passed`, `evaluated`
/// and `conformity_summary`) instead of passing them through.
const RENDERED_FIELDS: &[&str] = &[
    "level",
    "is_compliant",
    "applicability",
    "error_count",
    "warning_count",
    "info_count",
    "violations",
    "passed",
    "evaluated",
    "conformity_summary",
];

#[derive(Serialize)]
struct Envelope<'a> {
    schema: &'static str,
    tool: Tool,
    /// The instant the verdicts were judged at; omitted when the writer is
    /// not told it.
    #[serde(skip_serializing_if = "Option::is_none")]
    as_of: Option<String>,
    /// The SBOM the results judge; omitted when the writer is not given it.
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Subject<'a>>,
    results: Vec<EnvelopeResult<'a>>,
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

/// The envelope's `subject`: the SBOM the results judge, and how its
/// document was read.
#[derive(Serialize)]
struct Subject<'a> {
    /// Lowercase hex SHA-256 of the bytes read.
    sha256: &'a str,
    format: String,
    spec_version: &'a str,
    /// The file's name, without its directory; omitted for standard input.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<&'a str>,
    /// The components, after the duplicate entries were merged.
    components: usize,
    duplicates: Duplicates,
    /// Whether the creation timestamp is there but does not parse.
    timestamp_unparsed: bool,
}

/// The components the document lists more than once, whose entries were
/// merged into one each.
#[derive(Serialize)]
struct Duplicates {
    /// The components listed more than once.
    components: usize,
    /// Their entries.
    entries: usize,
    /// The fields the entries disagree on, each once, sorted.
    conflicts: Vec<String>,
}

impl<'a> Subject<'a> {
    fn of(assessed: &'a AssessedSbom<'_>) -> Self {
        let sbom = assessed.sbom();
        Self {
            sha256: assessed.sha256(),
            format: sbom.document.format.to_string(),
            spec_version: &sbom.document.spec_version,
            file_name: assessed.file_name(),
            components: sbom.component_count(),
            duplicates: Duplicates {
                components: sbom.duplicate_components.len(),
                entries: assessed.duplicate_entries(),
                conflicts: assessed.duplicate_conflicts(),
            },
            timestamp_unparsed: sbom.document.created_unparsed.is_some(),
        }
    }
}

/// One standard's verdict.
#[derive(Serialize)]
struct EnvelopeResult<'a> {
    standard: &'static str,
    name: &'static str,
    applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<&'a str>,
    compliant: bool,
    score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score_basis: Option<ScoreBasis>,
    counts: Counts,
    violations: Vec<Identified<'a, Violation>>,
    passed: Vec<Identified<'a, PassedCheck>>,
    /// The checks the standard did not evaluate, in their own field order;
    /// omitted when it evaluated them all.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    evaluated: &'a [RuleEvaluation],
    #[serde(skip_serializing_if = "Option::is_none")]
    conformity_summary: Option<&'a ConformityAssessmentSummary>,
    /// Every other field of the result's serialization, as a JSON value
    /// (nested keys sorted).
    #[serde(flatten)]
    rest: Map<String, Value>,
}

/// What a result's `score` is computed from (see
/// [`crate::quality::compliance_score`]): with the verdict, enough to
/// recompute it.
#[derive(Serialize)]
struct ScoreBasis {
    /// The elements the standard checked: the document and the components
    /// in its scope.
    checked: usize,
    /// The checks the errors and warnings failed.
    failed: usize,
}

#[derive(Serialize)]
struct Counts {
    error: usize,
    warning: usize,
    info: usize,
    /// Passed checks, which no severity count includes.
    passed: usize,
    /// Findings the rule settings turned off (the sum of `suppressed[]`),
    /// which no other count includes; omitted when none.
    #[serde(skip_serializing_if = "is_zero")]
    suppressed: usize,
    /// Any other `<kind>_count` field of the result, keyed by `<kind>`.
    #[serde(flatten)]
    other: Map<String, Value>,
}

/// Serde helper: skip a count that is zero.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// A violation or a passed check: its own serialization behind its finding
/// identity.
#[derive(Serialize)]
struct Identified<'a, F: Serialize> {
    finding_id: String,
    finding_key: String,
    #[serde(flatten)]
    finding: &'a F,
}

impl<'a, F: Serialize + FindingIdentity> Identified<'a, F> {
    fn new(result: &ComplianceResult, finding: &'a F) -> Self {
        let finding_key = finding_key(result.level, finding);
        Self {
            finding_id: finding_id(&finding_key),
            finding_key,
            finding,
        }
    }
}

/// Render `results` as one `sbom-tools/compliance/v2` envelope, without the
/// `as_of` and `subject` that [`generate_compliance_json_at`] adds.
pub fn generate_compliance_json(results: &[ComplianceResult]) -> Result<String, ReportError> {
    render(results, None, None)
}

/// Render `results` as one `sbom-tools/compliance/v2` envelope about
/// `assessed`, the SBOM they judge, judged at `as_of`. The envelope's
/// `as_of` states that instant, and its `subject` the SBOM's SHA-256,
/// format, specification version and file name, and how its document was
/// read: its components, the duplicate entries merged and whether its
/// creation timestamp parses. `validate -o json` writes this.
pub fn generate_compliance_json_at(
    results: &[ComplianceResult],
    assessed: &AssessedSbom<'_>,
    as_of: DateTime<Utc>,
) -> Result<String, ReportError> {
    render(
        results,
        Some(Subject::of(assessed)),
        Some(instant_text(as_of)),
    )
}

fn render(
    results: &[ComplianceResult],
    subject: Option<Subject<'_>>,
    as_of: Option<String>,
) -> Result<String, ReportError> {
    let envelope = Envelope {
        schema: COMPLIANCE_JSON_SCHEMA,
        tool: Tool {
            name: "sbom-tools",
            version: env!("CARGO_PKG_VERSION"),
        },
        as_of,
        subject,
        results: results
            .iter()
            .map(envelope_result)
            .collect::<Result<_, _>>()?,
    };
    serde_json::to_string_pretty(&envelope)
        .map_err(|e| ReportError::SerializationError(e.to_string()))
}

/// Split the fields of a result's serialization that the envelope does not
/// render itself into extra counts (`<kind>_count`, keyed by `<kind>`) and
/// everything else.
fn passed_through(mut fields: Map<String, Value>) -> (Map<String, Value>, Map<String, Value>) {
    for field in RENDERED_FIELDS {
        fields.remove(*field);
    }
    let (counts, rest) = fields
        .into_iter()
        .partition::<Map<String, Value>, _>(|(key, _)| key.ends_with("_count"));
    let counts = counts
        .into_iter()
        .map(|(key, value)| (key.trim_end_matches("_count").to_string(), value))
        .collect();
    (counts, rest)
}

fn envelope_result(result: &ComplianceResult) -> Result<EnvelopeResult<'_>, ReportError> {
    let Value::Object(fields) =
        serde_json::to_value(result).map_err(|e| ReportError::SerializationError(e.to_string()))?
    else {
        return Err(ReportError::SerializationError(
            "a compliance result must serialize to a JSON object".to_string(),
        ));
    };
    let (other_counts, rest) = passed_through(fields);

    let not_applicable_reason = match &result.applicability {
        Applicability::NotApplicable(reason) => Some(reason.as_str()),
        Applicability::Applicable => None,
    };
    Ok(EnvelopeResult {
        standard: standard_key(result.level),
        name: result.level.name(),
        applicable: result.is_applicable(),
        not_applicable_reason,
        compliant: result.is_compliant,
        score: result.score(),
        score_basis: result.is_applicable().then(|| ScoreBasis {
            checked: result.elements_checked,
            failed: result.failed_checks(),
        }),
        counts: Counts {
            error: result.error_count,
            warning: result.warning_count,
            info: result.info_count,
            passed: result.passed.len(),
            suppressed: result.suppressed_count(),
            other: other_counts,
        },
        violations: result
            .violations
            .iter()
            .map(|violation| Identified::new(result, violation))
            .collect(),
        passed: result
            .passed
            .iter()
            .map(|pass| Identified::new(result, pass))
            .collect(),
        evaluated: &result.evaluated,
        conformity_summary: result.conformity_summary.as_ref(),
        rest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    use crate::quality::{ComplianceChecker, ComplianceLevel};
    use std::borrow::Cow;

    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    /// `level`'s result for a one-component CycloneDX 1.6 SBOM. Its spec
    /// version parses, so NTIA evaluates every check and lists none under
    /// `evaluated`.
    fn check(level: ComplianceLevel) -> ComplianceResult {
        let mut sbom = NormalizedSbom::new(DocumentMetadata {
            spec_version: "1.6".to_string(),
            ..DocumentMetadata::default()
        });
        sbom.add_component(
            Component::new("lodash".to_string(), "lodash-ref".to_string())
                .with_version("4.17.21".to_string())
                .with_purl("pkg:npm/lodash@4.17.21".to_string()),
        );
        ComplianceChecker::new(level)
            .with_as_of(as_of())
            .check(&sbom)
    }

    fn envelope(results: &[ComplianceResult]) -> Value {
        let json = generate_compliance_json(results).expect("envelope serializes");
        serde_json::from_str(&json).expect("envelope is JSON")
    }

    #[test]
    fn one_standard_is_still_an_envelope() {
        let value = envelope(&[check(ComplianceLevel::NtiaMinimum)]);
        assert_eq!(value["schema"], COMPLIANCE_JSON_SCHEMA);
        assert_eq!(value["tool"]["name"], "sbom-tools");
        assert_eq!(value["tool"]["version"], env!("CARGO_PKG_VERSION"));
        let results = value["results"].as_array().expect("results array");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["standard"], "ntia");
        assert_eq!(results[0]["name"], "NTIA Minimum Elements");
    }

    #[test]
    fn result_fields_mirror_the_compliance_result() {
        let result = check(ComplianceLevel::NtiaMinimum);
        let value = envelope(std::slice::from_ref(&result));
        let entry = &value["results"][0];
        assert_eq!(entry["applicable"], true);
        assert!(entry.get("not_applicable_reason").is_none(), "{entry}");
        assert_eq!(entry["compliant"], result.is_compliant);
        assert_eq!(entry["score"], serde_json::json!(result.score()));
        assert_eq!(entry["counts"]["error"], result.error_count);
        assert_eq!(entry["counts"]["warning"], result.warning_count);
        assert_eq!(entry["counts"]["info"], result.info_count);
        assert_eq!(entry["counts"]["passed"], 0);
        assert_eq!(entry["passed"], serde_json::json!([]), "always present");
        for field in ["level", "is_compliant", "applicability", "error_count"] {
            assert!(entry.get(field).is_none(), "{field} leaked: {entry}");
        }
    }

    /// What a later `ComplianceResult` field becomes in the envelope: a
    /// `<kind>_count` joins `counts`, anything else is copied as is.
    #[test]
    fn new_result_fields_pass_through() {
        let Value::Object(mut fields) =
            serde_json::to_value(check(ComplianceLevel::NtiaMinimum)).expect("serializes")
        else {
            panic!("a result serializes to an object");
        };
        fields.insert("skipped_count".to_string(), serde_json::json!(3));
        fields.insert("skipped".to_string(), serde_json::json!([{"rule_id": "X"}]));
        let (counts, rest) = passed_through(fields);
        assert_eq!(
            counts,
            serde_json::json!({"skipped": 3})
                .as_object()
                .cloned()
                .expect("object")
        );
        assert_eq!(
            rest,
            serde_json::json!({"skipped": [{"rule_id": "X"}]})
                .as_object()
                .cloned()
                .expect("object")
        );
    }

    /// A NIST PQC result with one passed check on a component.
    fn with_one_pass() -> ComplianceResult {
        ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new()).with_passed(vec![PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"
                .to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Cow::Borrowed(&[]),
        }])
    }

    #[test]
    fn passed_checks_carry_their_own_fields_plus_finding_identity() {
        let result = with_one_pass();
        let value = envelope(std::slice::from_ref(&result));
        let entry = &value["results"][0];
        assert_eq!(entry["counts"]["passed"], 1);
        assert_eq!(entry["counts"]["info"], 0, "a pass is no Info violation");
        assert_eq!(entry["violations"], serde_json::json!([]));
        let passed = entry["passed"].as_array().expect("passed array");
        assert_eq!(passed.len(), 1);
        let pass = &result.passed[0];
        let key = finding_key(result.level, pass);
        assert_eq!(key, "pqc|SBOM-PQC-009|crypto/algorithm/ml-kem-1024");
        assert_eq!(passed[0]["finding_key"], key.as_str());
        assert_eq!(passed[0]["finding_id"], finding_id(&key).as_str());
        let Value::Object(own) = serde_json::to_value(pass).expect("serializes") else {
            panic!("a passed check serializes to an object");
        };
        for (field, own_value) in &own {
            assert_eq!(&passed[0][field], own_value, "{field}");
        }
        assert_eq!(
            passed[0].as_object().map(Map::len),
            Some(own.len() + 2),
            "exactly the pass's fields plus the identity: {}",
            passed[0]
        );
        assert!(
            entry.get("passed_count").is_none(),
            "no pass-through copy: {entry}"
        );
    }

    #[test]
    fn conformity_summary_keeps_its_own_field_order() {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(Component::new("app".to_string(), "app".to_string()));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_as_of(as_of())
            .with_product_class(crate::model::CraProductClass::Critical)
            .check(&sbom);
        let summary = result.conformity_summary.as_ref().expect("class pinned");
        let json = generate_compliance_json(std::slice::from_ref(&result)).expect("serializes");
        let expected = serde_json::to_string_pretty(summary).expect("serializes");
        let indented = expected.replace('\n', "\n      ");
        assert!(
            json.contains(&format!("\"conformity_summary\": {indented}")),
            "the summary must be the result's own serialization:\n{json}"
        );
    }

    #[test]
    fn violations_carry_their_own_fields_plus_finding_identity() {
        let result = check(ComplianceLevel::NtiaMinimum);
        let value = envelope(std::slice::from_ref(&result));
        let violations = value["results"][0]["violations"]
            .as_array()
            .expect("violations array");
        assert_eq!(violations.len(), result.violations.len());
        for (emitted, violation) in violations.iter().zip(&result.violations) {
            let key = finding_key(result.level, violation);
            assert_eq!(emitted["finding_key"], key.as_str());
            assert_eq!(emitted["finding_id"], finding_id(&key).as_str());
            let Value::Object(own) = serde_json::to_value(violation).expect("serializes") else {
                panic!("a violation serializes to an object");
            };
            for (field, own_value) in &own {
                assert_eq!(&emitted[field], own_value, "{field}");
            }
            assert_eq!(
                emitted.as_object().map(Map::len),
                Some(own.len() + 2),
                "exactly the violation's fields plus the identity: {emitted}"
            );
        }
    }

    #[test]
    fn not_applicable_results_have_a_reason_and_no_score() {
        let value = envelope(&[check(ComplianceLevel::EuAiAct)]);
        let entry = &value["results"][0];
        assert_eq!(entry["standard"], "ai-act");
        assert_eq!(entry["applicable"], false);
        assert!(entry["not_applicable_reason"].is_string(), "{entry}");
        assert!(entry["score"].is_null(), "{entry}");
        assert!(entry.get("score_basis").is_none(), "{entry}");
    }

    /// The score basis recomputes the score: (50 when compliant, else 0) +
    /// floor(50 × checked / (checked + failed)).
    #[test]
    fn score_basis_recomputes_the_score() {
        for level in [
            ComplianceLevel::Minimum,
            ComplianceLevel::NtiaMinimum,
            ComplianceLevel::CraPhase2,
            ComplianceLevel::BsiTr03183_2,
            ComplianceLevel::Fsct,
        ] {
            let result = check(level);
            let value = envelope(std::slice::from_ref(&result));
            let entry = &value["results"][0];
            let basis = &entry["score_basis"];
            assert_eq!(basis["checked"], result.elements_checked, "{entry}");
            assert_eq!(basis["checked"], 2, "the document and lodash: {entry}");
            assert_eq!(basis["failed"], result.failed_checks(), "{entry}");
            let checked = basis["checked"].as_u64().expect("checked");
            let failed = basis["failed"].as_u64().expect("failed");
            let band = if entry["compliant"] == true { 50 } else { 0 };
            let within = if failed == 0 {
                50
            } else {
                50 * checked / (checked + failed)
            };
            assert_eq!(entry["score"], band + within, "{level:?}: {entry}");
        }
    }

    #[test]
    fn several_standards_share_one_envelope_in_order() {
        let value = envelope(&[
            check(ComplianceLevel::NtiaMinimum),
            check(ComplianceLevel::CraPhase2),
        ]);
        let standards: Vec<&str> = value["results"]
            .as_array()
            .expect("results array")
            .iter()
            .filter_map(|r| r["standard"].as_str())
            .collect();
        assert_eq!(standards, ["ntia", "cra"]);
    }
}
