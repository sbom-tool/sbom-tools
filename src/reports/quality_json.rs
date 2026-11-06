//! The JSON document `sbom-tools quality -o json` prints, which the C ABI's
//! `sbom_tools_score_sbom_with_options_json` returns too.
//!
//! One object: the tool and its version, the SBOM's file name, the profile
//! (as `--profile` names it), whether the profile applied, and the
//! [`QualityReport`]'s own serialization under `report`.

use super::ReportError;
use crate::quality::{AiReadinessMetrics, QualityReport};
use serde_json::{Value, json};
use std::path::Path;

/// Render `report` as the document `sbom-tools quality -o json` prints for
/// the SBOM read from `sbom_path` (`-` for standard input), which it names
/// by its file name.
///
/// An AI-readiness report on an SBOM without ML components did not apply:
/// its `applicable` is `false`, and its `overall_score` is `null` and its
/// `grade` `N/A`, so a consumer does not read the 0.0 and F the scorer
/// leaves as a failing score (the 8-category pipeline did not run).
pub fn generate_quality_json(
    report: &QualityReport,
    sbom_path: &Path,
) -> Result<String, ReportError> {
    let not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(AiReadinessMetrics::is_not_applicable);

    let mut report_value =
        serde_json::to_value(report).map_err(|e| ReportError::SerializationError(e.to_string()))?;
    if not_applicable && let Some(obj) = report_value.as_object_mut() {
        obj.insert("overall_score".to_string(), Value::Null);
        obj.insert("grade".to_string(), Value::String("N/A".to_string()));
    }

    let output = json!({
        "tool": "sbom-tools",
        "version": env!("CARGO_PKG_VERSION"),
        "sbom": sbom_path.file_name().unwrap_or_default().to_string_lossy(),
        "profile": report.profile.to_string(),
        "applicable": !not_applicable,
        "report": report_value,
    });
    serde_json::to_string_pretty(&output)
        .map_err(|e| ReportError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DocumentMetadata, NormalizedSbom};
    use crate::quality::{QualityScorer, ScoringProfile};

    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    fn render(profile: ScoringProfile, path: &str) -> Value {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(profile).with_as_of(as_of()).score(&sbom);
        let json = generate_quality_json(&report, Path::new(path)).expect("renders");
        serde_json::from_str(&json).expect("JSON")
    }

    #[test]
    fn names_the_tool_the_sbom_and_the_profile() {
        let value = render(ScoringProfile::LicenseCompliance, "dir/app.cdx.json");
        assert_eq!(value["tool"], "sbom-tools");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["sbom"], "app.cdx.json");
        assert_eq!(value["profile"], "license-compliance");
        assert_eq!(value["applicable"], true);
        assert!(value["report"]["overall_score"].is_number());
        assert_eq!(render(ScoringProfile::Standard, "-")["sbom"], "-");
    }

    /// An AI-readiness run without ML components is N/A, not a failing 0.
    #[test]
    fn a_not_applicable_ai_readiness_run_has_no_score() {
        let value = render(ScoringProfile::AiReadiness, "model.cdx.json");
        assert_eq!(value["applicable"], false);
        assert!(value["report"]["overall_score"].is_null());
        assert_eq!(value["report"]["grade"], "N/A");
    }
}
