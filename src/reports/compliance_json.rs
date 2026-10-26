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
//! the schema tests fail until the schema declares it.

use super::ReportError;
use crate::quality::{
    Applicability, ComplianceResult, ConformityAssessmentSummary, FindingIdentity, PassedCheck,
    Violation, finding_id, finding_key, standard_key,
};
use serde::Serialize;
use serde_json::{Map, Value};

/// The envelope's `schema` value.
pub const COMPLIANCE_JSON_SCHEMA: &str = "sbom-tools/compliance/v2";

/// Fields of a [`ComplianceResult`]'s serialization that the envelope
/// renders itself (as `standard`/`name`, `compliant`, `applicable`/
/// `not_applicable_reason`, `counts`, `violations`, `passed` and
/// `conformity_summary`) instead of passing them through.
const RENDERED_FIELDS: &[&str] = &[
    "level",
    "is_compliant",
    "applicability",
    "error_count",
    "warning_count",
    "info_count",
    "violations",
    "passed",
    "conformity_summary",
];

#[derive(Serialize)]
struct Envelope<'a> {
    schema: &'static str,
    tool: Tool,
    results: Vec<EnvelopeResult<'a>>,
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
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
    counts: Counts,
    violations: Vec<Identified<'a, Violation>>,
    passed: Vec<Identified<'a, PassedCheck>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conformity_summary: Option<&'a ConformityAssessmentSummary>,
    /// Every other field of the result's serialization, as a JSON value
    /// (nested keys sorted).
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Serialize)]
struct Counts {
    error: usize,
    warning: usize,
    info: usize,
    /// Passed checks, which no severity count includes.
    passed: usize,
    /// Any other `<kind>_count` field of the result, keyed by `<kind>`.
    #[serde(flatten)]
    other: Map<String, Value>,
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

/// Render `results` as one `sbom-tools/compliance/v2` envelope.
pub fn generate_compliance_json(results: &[ComplianceResult]) -> Result<String, ReportError> {
    let envelope = Envelope {
        schema: COMPLIANCE_JSON_SCHEMA,
        tool: Tool {
            name: "sbom-tools",
            version: env!("CARGO_PKG_VERSION"),
        },
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
        counts: Counts {
            error: result.error_count,
            warning: result.warning_count,
            info: result.info_count,
            passed: result.passed.len(),
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
        conformity_summary: result.conformity_summary.as_ref(),
        rest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    use crate::quality::{ComplianceChecker, ComplianceLevel};

    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    fn check(level: ComplianceLevel) -> ComplianceResult {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
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
            standard_refs: Vec::new(),
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
