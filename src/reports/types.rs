//! Report type definitions.

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Output format for reports
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize, JsonSchema)]
pub enum ReportFormat {
    /// Auto-detect: TUI if TTY, summary otherwise
    #[default]
    Auto,
    /// Interactive TUI display
    Tui,
    /// Side-by-side terminal diff (like difftastic)
    #[value(alias = "side-by-side")]
    SideBySide,
    /// Structured JSON output
    Json,
    /// SARIF 2.1.0 for CI/CD
    Sarif,
    /// Human-readable Markdown
    Markdown,
    /// Interactive HTML report
    Html,
    /// Brief summary output
    Summary,
    /// Compact table for terminal (colored)
    Table,
    /// CSV for spreadsheet import
    Csv,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Auto => write!(f, "auto"),
            ReportFormat::Tui => write!(f, "tui"),
            ReportFormat::SideBySide => write!(f, "side-by-side"),
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::Sarif => write!(f, "sarif"),
            ReportFormat::Markdown => write!(f, "markdown"),
            ReportFormat::Html => write!(f, "html"),
            ReportFormat::Summary => write!(f, "summary"),
            ReportFormat::Table => write!(f, "table"),
            ReportFormat::Csv => write!(f, "csv"),
        }
    }
}

/// Types of reports that can be generated
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize, JsonSchema)]
pub enum ReportType {
    /// All report types
    #[default]
    All,
    /// Component changes summary
    Components,
    /// Dependency changes
    Dependencies,
    /// OSS dependency changes
    OssDependencies,
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
    pub fn meets_threshold(&self, severity: &str) -> bool {
        let sev = match severity.to_lowercase().as_str() {
            "critical" => MinSeverity::Critical,
            "high" => MinSeverity::High,
            "medium" => MinSeverity::Medium,
            "low" => MinSeverity::Low,
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
    /// Include unchanged items in the report
    pub include_unchanged: bool,
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
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            report_types: vec![ReportType::All],
            include_unchanged: false,
            max_items: None,
            include_field_changes: true,
            title: None,
            metadata: ReportMetadata::default(),
            only_changes: false,
            min_severity: None,
            old_cra_compliance: None,
            new_cra_compliance: None,
            view_cra_compliance: None,
        }
    }
}

impl ReportConfig {
    /// Create a config for all report types
    pub fn all() -> Self {
        Self::default()
    }

    /// Create a config for specific report types
    pub fn with_types(types: Vec<ReportType>) -> Self {
        Self {
            report_types: types,
            ..Default::default()
        }
    }

    /// Check if a report type should be included
    pub fn includes(&self, report_type: ReportType) -> bool {
        self.report_types.contains(&ReportType::All) || self.report_types.contains(&report_type)
    }
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
    pub fn new() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        }
    }
}
