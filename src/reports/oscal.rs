//! OSCAL assessment-results export for compliance validation findings.

use crate::quality::{ComplianceResult, Violation, ViolationSeverity};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

const OSCAL_VERSION: &str = "1.1.2";
const ASSESSMENT_PLAN_URN: &str = "urn:sbom-tools:assessment-plan:validation";

/// Generate an OSCAL 1.1.2 assessment-results JSON document.
pub fn generate_assessment_results(results: &[ComplianceResult]) -> Result<String> {
    build_assessment_results(results, Utc::now(), &mut Uuid::new_v4)
}

fn build_assessment_results(
    results: &[ComplianceResult],
    timestamp: DateTime<Utc>,
    uuid: &mut impl FnMut() -> Uuid,
) -> Result<String> {
    let collected = timestamp.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut observations = Vec::new();
    let mut findings = Vec::new();
    for result in results {
        for violation in &result.violations {
            let observation_uuid = uuid();
            observations.push(observation(violation, observation_uuid, &collected));
            findings.push(finding(violation, observation_uuid, uuid()));
        }
    }

    let mut assessment = json!({
        "uuid": uuid(),
        "title": "sbom-tools validation assessment",
        "description": "Validation results derived only from the supplied SBOM.",
        "start": collected,
        "reviewed-controls": {
            "control-selections": [{
                "description": "Controls represented by the selected sbom-tools validation standards.",
                "include-all": {}
            }]
        }
    });
    if !observations.is_empty() {
        assessment["observations"] = Value::Array(observations);
        assessment["findings"] = Value::Array(findings);
    }

    Ok(serde_json::to_string_pretty(&json!({
        "assessment-results": {
            "uuid": uuid(),
            "metadata": {
                "title": "sbom-tools validation assessment results",
                "last-modified": collected,
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION
            },
            "import-ap": { "href": ASSESSMENT_PLAN_URN },
            "results": [assessment]
        }
    }))?)
}

fn observation(violation: &Violation, uuid: Uuid, collected: &str) -> Value {
    let mut props = vec![
        json!({
            "name": "severity",
            "ns": "https://sbom.tools/ns/oscal",
            "value": severity(violation.severity)
        }),
        json!({
            "name": "standard-reference",
            "ns": "https://sbom.tools/ns/oscal",
            "value": violation.requirement
        }),
    ];
    if let Some(element) = &violation.element {
        props.push(json!({
            "name": "sbom-element",
            "ns": "https://sbom.tools/ns/oscal",
            "value": element
        }));
    }
    json!({
        "uuid": uuid,
        "title": violation.rule_id,
        "description": violation.message,
        "methods": ["EXAMINE"],
        "types": ["finding"],
        "collected": collected,
        "props": props
    })
}

fn finding(violation: &Violation, observation_uuid: Uuid, uuid: Uuid) -> Value {
    json!({
        "uuid": uuid,
        "title": violation.rule_id,
        "description": violation.message,
        "target": {
            "type": "objective-id",
            "target-id": violation.rule_id.to_ascii_lowercase(),
            "status": {
                // OSCAL 1.1.2 finding-target status `state` is a closed enum
                // (satisfied | not-satisfied, no allow-other). Any violation —
                // regardless of severity — is a non-satisfied objective; the
                // severity detail is carried separately in the observation's
                // custom `severity` property.
                "state": "not-satisfied"
            }
        },
        "related-observations": [{ "observation-uuid": observation_uuid }]
    })
}

const fn severity(value: ViolationSeverity) -> &'static str {
    match value {
        ViolationSeverity::Error => "error",
        ViolationSeverity::Warning => "warning",
        ViolationSeverity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::build_assessment_results;
    use crate::quality::{
        ComplianceLevel, ComplianceResult, Violation, ViolationCategory, ViolationSeverity,
    };
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn violation(message: &str) -> Violation {
        Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-METADATA",
            standard_refs: Vec::new(),
        }
    }

    fn result(violations: Vec<Violation>) -> ComplianceResult {
        ComplianceResult {
            is_compliant: violations.is_empty(),
            level: ComplianceLevel::NtiaMinimum,
            error_count: violations.len(),
            warning_count: 0,
            info_count: 0,
            violations,
            conformity_summary: None,
        }
    }

    fn build(results: &[ComplianceResult]) -> serde_json::Value {
        let timestamp = Utc
            .with_ymd_and_hms(2026, 7, 1, 12, 0, 0)
            .single()
            .expect("valid timestamp");
        let mut next = 0u128;
        let json = build_assessment_results(results, timestamp, &mut || {
            next += 1;
            Uuid::from_u128(next)
        })
        .expect("OSCAL serialization");
        serde_json::from_str(&json).expect("valid JSON")
    }

    #[test]
    fn empty_result_omits_observations_and_findings() {
        let document = build(&[result(Vec::new())]);
        let assessment = &document["assessment-results"]["results"][0];
        assert!(assessment.get("observations").is_none());
        assert!(assessment.get("findings").is_none());
    }

    #[test]
    fn single_finding_links_to_its_observation() {
        let document = build(&[result(vec![violation("missing metadata")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(1));
        assert_eq!(assessment["findings"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            assessment["findings"][0]["related-observations"][0]["observation-uuid"],
            assessment["observations"][0]["uuid"]
        );
    }

    #[test]
    fn multiple_findings_are_emitted_in_input_order() {
        let document = build(&[result(vec![violation("first"), violation("second")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(2));
        assert_eq!(assessment["findings"][0]["description"], "first");
        assert_eq!(assessment["findings"][1]["description"], "second");
        assert_eq!(
            document["assessment-results"]["metadata"]["last-modified"],
            "2026-07-01T12:00:00Z"
        );
    }

    #[test]
    fn finding_status_state_is_valid_oscal_token_for_every_severity() {
        // OSCAL 1.1.2 finding-target status `state` is a CLOSED enum:
        // only "satisfied" / "not-satisfied" (no allow-other). Every violation
        // is a non-satisfied objective regardless of severity. This guards the
        // Info/Warning branches that the other tests (Error-only) never reach.
        let with_severity = |message: &str, severity: ViolationSeverity| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-METADATA",
            standard_refs: Vec::new(),
        };
        let document = build(&[result(vec![
            with_severity("info finding", ViolationSeverity::Info),
            with_severity("warning finding", ViolationSeverity::Warning),
            with_severity("error finding", ViolationSeverity::Error),
        ])]);
        let findings = document["assessment-results"]["results"][0]["findings"]
            .as_array()
            .expect("findings array");
        assert_eq!(findings.len(), 3);
        for finding in findings {
            assert_eq!(finding["target"]["status"]["state"], "not-satisfied");
        }
    }
}
