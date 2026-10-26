//! Report type definitions.

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Output format for reports
///
/// Serde names are kebab-case, matching the CLI spellings (`-o oscal-json`)
/// so a hand-written config file can use the same values the CLI documents.
/// The historical PascalCase variant names are kept as aliases so existing
/// config files (`format: Json`) keep loading.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReportFormat {
    /// Auto-detect: TUI if TTY, summary otherwise
    #[default]
    #[serde(alias = "Auto")]
    Auto,
    /// Interactive TUI display
    #[serde(alias = "Tui")]
    Tui,
    /// Side-by-side terminal diff (like difftastic)
    #[value(alias = "side-by-side")]
    #[serde(alias = "SideBySide")]
    SideBySide,
    /// Structured JSON output
    #[serde(alias = "Json")]
    Json,
    /// SARIF 2.1.0 for CI/CD
    #[serde(alias = "Sarif")]
    Sarif,
    /// OSCAL 1.2.3 assessment-results JSON
    #[serde(alias = "OscalJson")]
    OscalJson,
    /// Human-readable Markdown
    #[serde(alias = "Markdown")]
    Markdown,
    /// Interactive HTML report
    #[serde(alias = "Html")]
    Html,
    /// Brief summary output
    #[serde(alias = "Summary")]
    Summary,
    /// Compact table for terminal (colored)
    #[serde(alias = "Table")]
    Table,
    /// CSV for spreadsheet import
    #[serde(alias = "Csv")]
    Csv,
    /// Newline-delimited JSON (one record per line, streaming-friendly)
    #[serde(alias = "Ndjson")]
    Ndjson,
    /// interlynk-io/sbomqs `score --json`-shaped quality scores (0-10),
    /// recomputed per-feature for side-by-side comparison with sbomqs
    /// output (`quality` command only)
    #[serde(alias = "SbomqsJson")]
    SbomqsJson,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Tui => write!(f, "tui"),
            Self::SideBySide => write!(f, "side-by-side"),
            Self::Json => write!(f, "json"),
            Self::Sarif => write!(f, "sarif"),
            Self::OscalJson => write!(f, "oscal-json"),
            Self::Markdown => write!(f, "markdown"),
            Self::Html => write!(f, "html"),
            Self::Summary => write!(f, "summary"),
            Self::Table => write!(f, "table"),
            Self::Csv => write!(f, "csv"),
            Self::Ndjson => write!(f, "ndjson"),
            Self::SbomqsJson => write!(f, "sbomqs-json"),
        }
    }
}

/// Types of reports that can be generated
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize, JsonSchema,
)]
pub enum ReportType {
    /// All report types
    #[default]
    All,
    /// Component changes summary
    Components,
    /// Dependency changes
    Dependencies,
    /// License changes
    Licenses,
    /// Vulnerability changes
    Vulnerabilities,
}

/// Minimum severity level for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MinSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl MinSeverity {
    /// Parse severity from string. Returns None for unrecognized values.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Check if a severity string meets this minimum threshold
    #[must_use]
    pub fn meets_threshold(&self, severity: &str) -> bool {
        let sev = match severity.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => return true, // Unknown severities are included
        };
        sev >= *self
    }
}

/// Configuration for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Which report types to include
    pub report_types: Vec<ReportType>,
    /// Maximum items per section
    pub max_items: Option<usize>,
    /// Include detailed field changes
    pub include_field_changes: bool,
    /// Title for the report
    pub title: Option<String>,
    /// Additional metadata to include
    pub metadata: ReportMetadata,
    /// Only show items with changes (filter out unchanged)
    pub only_changes: bool,
    /// Minimum severity level for vulnerability filtering
    pub min_severity: Option<MinSeverity>,
    /// Pre-computed CRA compliance for old SBOM (avoids redundant recomputation)
    #[serde(skip)]
    pub old_cra_compliance: Option<crate::quality::ComplianceResult>,
    /// Pre-computed CRA compliance for new SBOM (avoids redundant recomputation)
    #[serde(skip)]
    pub new_cra_compliance: Option<crate::quality::ComplianceResult>,
    /// Pre-computed CRA compliance for single SBOM in view mode
    #[serde(skip)]
    pub view_cra_compliance: Option<crate::quality::ComplianceResult>,
    /// The old SBOM file of a diff, which `-o sarif` results about the old
    /// SBOM point into. Without it they carry no physical location.
    #[serde(skip)]
    pub old_sarif_artifact: Option<crate::reports::SarifArtifact>,
    /// The new SBOM file of a diff, which `-o sarif` results about the new
    /// SBOM point into.
    #[serde(skip)]
    pub new_sarif_artifact: Option<crate::reports::SarifArtifact>,
    /// The SBOM file of a view, which `-o sarif` results point into.
    #[serde(skip)]
    pub view_sarif_artifact: Option<crate::reports::SarifArtifact>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            report_types: vec![ReportType::All],
            max_items: None,
            include_field_changes: true,
            title: None,
            metadata: ReportMetadata::default(),
            only_changes: false,
            min_severity: None,
            old_cra_compliance: None,
            new_cra_compliance: None,
            view_cra_compliance: None,
            old_sarif_artifact: None,
            new_sarif_artifact: None,
            view_sarif_artifact: None,
        }
    }
}

impl ReportConfig {
    /// Create a config for all report types
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// CRA Phase 2 compliance for the old SBOM of a diff report.
    ///
    /// Returns the pre-computed [`Self::old_cra_compliance`] when populated —
    /// every first-party pipeline (the diff report stage and the TUI export)
    /// populates it with a sidecar-aware result so all output formats agree
    /// with the TUI. The bare (sidecar-less) computation only exists as a
    /// last resort for direct library callers that hand a reporter a default
    /// `ReportConfig`; it lives here, in one place, so the individual
    /// reporters cannot re-grow divergent fallback checkers.
    #[must_use]
    pub fn old_cra_compliance_or_bare(
        &self,
        old_sbom: &crate::model::NormalizedSbom,
    ) -> crate::quality::ComplianceResult {
        self.old_cra_compliance
            .clone()
            .unwrap_or_else(|| bare_cra_phase2_check(old_sbom))
    }

    /// CRA Phase 2 compliance for the new SBOM of a diff report.
    ///
    /// See [`Self::old_cra_compliance_or_bare`] for the fallback contract.
    #[must_use]
    pub fn new_cra_compliance_or_bare(
        &self,
        new_sbom: &crate::model::NormalizedSbom,
    ) -> crate::quality::ComplianceResult {
        self.new_cra_compliance
            .clone()
            .unwrap_or_else(|| bare_cra_phase2_check(new_sbom))
    }

    /// CRA Phase 2 compliance for the SBOM of a view report.
    ///
    /// See [`Self::old_cra_compliance_or_bare`] for the fallback contract.
    #[must_use]
    pub fn view_cra_compliance_or_bare(
        &self,
        sbom: &crate::model::NormalizedSbom,
    ) -> crate::quality::ComplianceResult {
        self.view_cra_compliance
            .clone()
            .unwrap_or_else(|| bare_cra_phase2_check(sbom))
    }

    /// Create a config for specific report types
    #[must_use]
    pub fn with_types(types: Vec<ReportType>) -> Self {
        Self {
            report_types: types,
            ..Default::default()
        }
    }

    /// Check if a report type should be included
    #[must_use]
    pub fn includes(&self, report_type: ReportType) -> bool {
        self.report_types.contains(&ReportType::All) || self.report_types.contains(&report_type)
    }
}

/// Last-resort CRA Phase 2 check with no sidecar or product class attached.
///
/// Only reachable through the `*_or_bare` accessors on [`ReportConfig`] when a
/// caller did not pre-compute compliance. First-party pipelines never hit this:
/// they resolve the CRA sidecar (explicit flag or `<sbom>.cra.{json,yaml}`
/// auto-discovery) and populate the config fields so every output format
/// renders the same verdicts as the TUI.
fn bare_cra_phase2_check(sbom: &crate::model::NormalizedSbom) -> crate::quality::ComplianceResult {
    crate::quality::ComplianceChecker::new(crate::quality::ComplianceLevel::CraPhase2).check(sbom)
}

/// Metadata included in reports
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Old SBOM file path
    pub old_sbom_path: Option<String>,
    /// New SBOM file path
    pub new_sbom_path: Option<String>,
    /// Tool version
    pub tool_version: String,
    /// Generation timestamp
    pub generated_at: Option<String>,
    /// Custom properties
    pub custom: std::collections::HashMap<String, String>,
}

impl ReportMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_format_deserializes_kebab_case_and_legacy_pascal_case() {
        // kebab-case is the canonical (CLI-matching) spelling; the historical
        // PascalCase names must keep loading so existing configs don't break.
        for (raw, expected) in [
            ("auto", ReportFormat::Auto),
            ("tui", ReportFormat::Tui),
            ("side-by-side", ReportFormat::SideBySide),
            ("oscal-json", ReportFormat::OscalJson),
            ("Auto", ReportFormat::Auto),
            ("Json", ReportFormat::Json),
            ("SideBySide", ReportFormat::SideBySide),
            ("OscalJson", ReportFormat::OscalJson),
            ("Ndjson", ReportFormat::Ndjson),
            ("sbomqs-json", ReportFormat::SbomqsJson),
            ("SbomqsJson", ReportFormat::SbomqsJson),
        ] {
            let parsed: ReportFormat = serde_json::from_str(&format!("\"{raw}\""))
                .unwrap_or_else(|e| panic!("'{raw}' must deserialize: {e}"));
            assert_eq!(parsed, expected, "'{raw}' mapped to the wrong variant");
        }
    }

    #[test]
    fn report_format_serializes_to_the_cli_spelling() {
        // Serialization, Display (CLI), and deserialization agree, so a
        // `config show`/`config check` round-trip is loss-free.
        for format in [
            ReportFormat::Auto,
            ReportFormat::Tui,
            ReportFormat::SideBySide,
            ReportFormat::Json,
            ReportFormat::Sarif,
            ReportFormat::OscalJson,
            ReportFormat::Markdown,
            ReportFormat::Html,
            ReportFormat::Summary,
            ReportFormat::Table,
            ReportFormat::Csv,
            ReportFormat::Ndjson,
            ReportFormat::SbomqsJson,
        ] {
            let serialized = serde_json::to_string(&format).unwrap();
            assert_eq!(serialized, format!("\"{format}\""));
            let round: ReportFormat = serde_json::from_str(&serialized).unwrap();
            assert_eq!(round, format);
        }
    }
}
