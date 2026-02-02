//! Analyst report data structures for security analysis exports.
//!
//! This module provides structures for generating comprehensive security
//! analysis reports that can be exported to Markdown or JSON format.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete analyst report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystReport {
    /// Report metadata
    pub metadata: AnalystReportMetadata,
    /// Executive summary with risk score
    pub executive_summary: ExecutiveSummary,
    /// Vulnerability findings
    pub vulnerability_findings: VulnerabilityFindings,
    /// Component-related findings
    pub component_findings: ComponentFindings,
    /// Compliance status summary
    pub compliance_status: ComplianceStatus,
    /// Analyst notes and annotations
    pub analyst_notes: Vec<AnalystNote>,
    /// Recommended actions
    pub recommendations: Vec<Recommendation>,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
}

impl AnalystReport {
    /// Create a new empty analyst report
    pub fn new() -> Self {
        Self {
            metadata: AnalystReportMetadata::default(),
            executive_summary: ExecutiveSummary::default(),
            vulnerability_findings: VulnerabilityFindings::default(),
            component_findings: ComponentFindings::default(),
            compliance_status: ComplianceStatus::default(),
            analyst_notes: Vec::new(),
            recommendations: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    /// Export report to JSON format
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export report to Markdown format
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Title
        md.push_str("# Security Analysis Report\n\n");

        // Metadata
        if let Some(title) = &self.metadata.title {
            md.push_str(&format!("**Analysis:** {}\n", title));
        }
        if let Some(analyst) = &self.metadata.analyst {
            md.push_str(&format!("**Analyst:** {}\n", analyst));
        }
        md.push_str(&format!(
            "**Generated:** {}\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if !self.metadata.sbom_paths.is_empty() {
            md.push_str(&format!(
                "**SBOMs Analyzed:** {}\n",
                self.metadata.sbom_paths.join(", ")
            ));
        }
        md.push_str("\n---\n\n");

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!(
            "**Risk Score:** {} ({:?})\n\n",
            self.executive_summary.risk_score, self.executive_summary.risk_level
        ));

        md.push_str("| Metric | Count |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!(
            "| Critical Issues | {} |\n",
            self.executive_summary.critical_issues
        ));
        md.push_str(&format!(
            "| High Issues | {} |\n",
            self.executive_summary.high_issues
        ));
        md.push_str(&format!(
            "| KEV Vulnerabilities | {} |\n",
            self.executive_summary.kev_count
        ));
        md.push_str(&format!(
            "| Stale Dependencies | {} |\n",
            self.executive_summary.stale_dependencies
        ));
        md.push_str(&format!(
            "| License Conflicts | {} |\n",
            self.executive_summary.license_conflicts
        ));
        if let Some(cra) = self.executive_summary.cra_compliance_score {
            md.push_str(&format!("| CRA Compliance | {}% |\n", cra));
        }
        md.push('\n');

        if !self.executive_summary.summary_text.is_empty() {
            md.push_str(&self.executive_summary.summary_text);
            md.push_str("\n\n");
        }

        // Vulnerability Findings
        md.push_str("## Vulnerability Findings\n\n");
        md.push_str(&format!(
            "- **Total Vulnerabilities:** {}\n",
            self.vulnerability_findings.total_count
        ));
        md.push_str(&format!(
            "- **Critical:** {}\n",
            self.vulnerability_findings.critical_vulnerabilities.len()
        ));
        md.push_str(&format!(
            "- **High:** {}\n",
            self.vulnerability_findings.high_vulnerabilities.len()
        ));
        md.push_str(&format!(
            "- **Medium:** {}\n",
            self.vulnerability_findings.medium_vulnerabilities.len()
        ));
        md.push_str(&format!(
            "- **Low:** {}\n",
            self.vulnerability_findings.low_vulnerabilities.len()
        ));

        if !self.vulnerability_findings.kev_vulnerabilities.is_empty() {
            md.push_str("\n### Known Exploited Vulnerabilities (KEV)\n\n");
            md.push_str(
                "These vulnerabilities are actively being exploited in the wild and require immediate attention.\n\n",
            );
            for vuln in &self.vulnerability_findings.kev_vulnerabilities {
                md.push_str(&format!(
                    "- **{}** ({}) - {}\n",
                    vuln.id, vuln.severity, vuln.component_name
                ));
            }
        }
        md.push('\n');

        // Component Findings
        md.push_str("## Component Findings\n\n");
        md.push_str(&format!(
            "- **Total Components:** {}\n",
            self.component_findings.total_components
        ));
        md.push_str(&format!(
            "- **Added:** {}\n",
            self.component_findings.added_count
        ));
        md.push_str(&format!(
            "- **Removed:** {}\n",
            self.component_findings.removed_count
        ));
        md.push_str(&format!(
            "- **Stale:** {}\n",
            self.component_findings.stale_components.len()
        ));
        md.push_str(&format!(
            "- **Deprecated:** {}\n",
            self.component_findings.deprecated_components.len()
        ));
        md.push('\n');

        // License Issues
        if !self.component_findings.license_issues.is_empty() {
            md.push_str("### License Issues\n\n");
            for issue in &self.component_findings.license_issues {
                let components = issue.affected_components.join(", ");
                md.push_str(&format!(
                    "- **{}** ({}): {} - {}\n",
                    issue.issue_type, issue.severity, issue.description, components
                ));
            }
            md.push('\n');
        }

        // Compliance Status
        if self.compliance_status.score > 0 {
            md.push_str("## Compliance Status\n\n");
            md.push_str(&format!(
                "**CRA Compliance:** {}%\n\n",
                self.compliance_status.score
            ));

            if !self.compliance_status.violations_by_article.is_empty() {
                md.push_str("### CRA Violations\n\n");
                for violation in &self.compliance_status.violations_by_article {
                    md.push_str(&format!(
                        "- **{}** ({} occurrences): {}\n",
                        violation.article, violation.count, violation.description
                    ));
                }
                md.push('\n');
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            md.push_str("## Recommendations\n\n");

            let mut sorted_recs = self.recommendations.clone();
            sorted_recs.sort_by(|a, b| a.priority.cmp(&b.priority));

            for rec in &sorted_recs {
                md.push_str(&format!(
                    "### [{:?}] {} - {}\n\n",
                    rec.priority, rec.category, rec.title
                ));
                md.push_str(&rec.description);
                md.push_str("\n\n");
                if !rec.affected_components.is_empty() {
                    md.push_str(&format!(
                        "**Affected:** {}\n\n",
                        rec.affected_components.join(", ")
                    ));
                }
                if let Some(effort) = &rec.effort {
                    md.push_str(&format!("**Estimated Effort:** {}\n\n", effort));
                }
            }
        }

        // Analyst Notes
        if !self.analyst_notes.is_empty() {
            md.push_str("## Analyst Notes\n\n");
            for note in &self.analyst_notes {
                let target = note
                    .target_id
                    .as_ref()
                    .map(|id| format!(" ({})", id))
                    .unwrap_or_default();
                let fp_marker = if note.false_positive {
                    " [FALSE POSITIVE]"
                } else {
                    ""
                };
                md.push_str(&format!(
                    "- **{}{}{}**: {}\n",
                    note.target_type, target, fp_marker, note.note
                ));
            }
            md.push('\n');
        }

        // Footer
        md.push_str("---\n\n");
        md.push_str("*Generated by sbom-tools*\n");

        md
    }
}

impl Default for AnalystReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Report metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalystReportMetadata {
    /// Tool name and version
    pub tool_version: String,
    /// Title of the analysis
    pub title: Option<String>,
    /// Analyst name or identifier
    pub analyst: Option<String>,
    /// SBOM file paths
    pub sbom_paths: Vec<String>,
    /// Analysis date
    pub analysis_date: Option<DateTime<Utc>>,
}

/// Executive summary with overall risk assessment
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// Overall risk score (0-100, higher = more risk)
    pub risk_score: u8,
    /// Risk level label (Low, Medium, High, Critical)
    pub risk_level: RiskLevel,
    /// Number of critical security issues
    pub critical_issues: usize,
    /// Number of high severity issues
    pub high_issues: usize,
    /// Count of KEV (Known Exploited Vulnerabilities)
    pub kev_count: usize,
    /// Count of stale/unmaintained dependencies
    pub stale_dependencies: usize,
    /// Count of license conflicts
    pub license_conflicts: usize,
    /// CRA compliance percentage (0-100)
    pub cra_compliance_score: Option<u8>,
    /// Brief summary text
    pub summary_text: String,
}

/// Risk level classification
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Calculate from risk score
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Vulnerability findings section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityFindings {
    /// Total vulnerability count
    pub total_count: usize,
    /// KEV vulnerabilities (highest priority)
    pub kev_vulnerabilities: Vec<VulnFinding>,
    /// Critical severity vulnerabilities
    pub critical_vulnerabilities: Vec<VulnFinding>,
    /// High severity vulnerabilities
    pub high_vulnerabilities: Vec<VulnFinding>,
    /// Medium severity vulnerabilities
    pub medium_vulnerabilities: Vec<VulnFinding>,
    /// Low severity vulnerabilities
    pub low_vulnerabilities: Vec<VulnFinding>,
}

impl VulnerabilityFindings {
    /// Get all findings in priority order
    pub fn all_findings(&self) -> Vec<&VulnFinding> {
        let mut all = Vec::new();
        all.extend(self.kev_vulnerabilities.iter());
        all.extend(self.critical_vulnerabilities.iter());
        all.extend(self.high_vulnerabilities.iter());
        all.extend(self.medium_vulnerabilities.iter());
        all.extend(self.low_vulnerabilities.iter());
        all
    }
}

/// Individual vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    /// Vulnerability ID (CVE, GHSA, etc.)
    pub id: String,
    /// Severity level
    pub severity: String,
    /// CVSS score
    pub cvss_score: Option<f32>,
    /// Whether in KEV catalog
    pub is_kev: bool,
    /// Whether used in ransomware
    pub is_ransomware_related: bool,
    /// KEV due date if applicable
    pub kev_due_date: Option<DateTime<Utc>>,
    /// Affected component name
    pub component_name: String,
    /// Component version
    pub component_version: Option<String>,
    /// Vulnerability description
    pub description: Option<String>,
    /// Remediation suggestion
    pub remediation: Option<String>,
    /// Attack paths to this vulnerability
    pub attack_paths: Vec<String>,
    /// Status in diff (Introduced, Resolved, Persistent)
    pub change_status: Option<String>,
    /// Analyst note if present
    pub analyst_note: Option<String>,
    /// Marked as false positive
    pub is_false_positive: bool,
}

impl VulnFinding {
    /// Create a new vulnerability finding
    pub fn new(id: String, component_name: String) -> Self {
        Self {
            id,
            severity: "Unknown".to_string(),
            cvss_score: None,
            is_kev: false,
            is_ransomware_related: false,
            kev_due_date: None,
            component_name,
            component_version: None,
            description: None,
            remediation: None,
            attack_paths: Vec::new(),
            change_status: None,
            analyst_note: None,
            is_false_positive: false,
        }
    }
}

/// Component-related findings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentFindings {
    /// Total component count
    pub total_components: usize,
    /// Components added (in diff mode)
    pub added_count: usize,
    /// Components removed (in diff mode)
    pub removed_count: usize,
    /// Stale components (>1 year without update)
    pub stale_components: Vec<StaleComponentFinding>,
    /// Deprecated components
    pub deprecated_components: Vec<DeprecatedComponentFinding>,
    /// License issues
    pub license_issues: Vec<LicenseIssueFinding>,
}

/// Stale component finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleComponentFinding {
    /// Component name
    pub name: String,
    /// Current version
    pub version: Option<String>,
    /// Days since last update
    pub days_since_update: u32,
    /// Last publish date
    pub last_published: Option<DateTime<Utc>>,
    /// Latest available version
    pub latest_version: Option<String>,
    /// Staleness level
    pub staleness_level: String,
    /// Analyst note if present
    pub analyst_note: Option<String>,
}

/// Deprecated component finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedComponentFinding {
    /// Component name
    pub name: String,
    /// Current version
    pub version: Option<String>,
    /// Deprecation message
    pub deprecation_message: Option<String>,
    /// Suggested replacement
    pub replacement: Option<String>,
    /// Analyst note if present
    pub analyst_note: Option<String>,
}

/// License issue finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssueFinding {
    /// Issue type
    pub issue_type: LicenseIssueType,
    /// Severity
    pub severity: IssueSeverity,
    /// First license involved
    pub license_a: String,
    /// Second license involved (for conflicts)
    pub license_b: Option<String>,
    /// Affected components
    pub affected_components: Vec<String>,
    /// Description of the issue
    pub description: String,
    /// Analyst note if present
    pub analyst_note: Option<String>,
}

/// Type of license issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseIssueType {
    /// Incompatible licenses in same binary
    BinaryIncompatible,
    /// Incompatible licenses in project
    ProjectIncompatible,
    /// Network copyleft (AGPL) implications
    NetworkCopyleft,
    /// Patent clause conflict
    PatentConflict,
    /// Unknown or unrecognized license
    UnknownLicense,
}

impl std::fmt::Display for LicenseIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseIssueType::BinaryIncompatible => write!(f, "Binary Incompatible"),
            LicenseIssueType::ProjectIncompatible => write!(f, "Project Incompatible"),
            LicenseIssueType::NetworkCopyleft => write!(f, "Network Copyleft"),
            LicenseIssueType::PatentConflict => write!(f, "Patent Conflict"),
            LicenseIssueType::UnknownLicense => write!(f, "Unknown License"),
        }
    }
}

/// Issue severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueSeverity::Error => write!(f, "Error"),
            IssueSeverity::Warning => write!(f, "Warning"),
            IssueSeverity::Info => write!(f, "Info"),
        }
    }
}

/// Compliance status summary
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceStatus {
    /// Overall compliance level
    pub level: String,
    /// Compliance score (0-100)
    pub score: u8,
    /// Total violations count
    pub total_violations: usize,
    /// Violations by CRA article (for CRA compliance)
    pub violations_by_article: Vec<ArticleViolations>,
    /// Key compliance issues
    pub key_issues: Vec<String>,
}

/// Violations grouped by CRA article
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleViolations {
    /// Article reference (e.g., "Art. 13(6)")
    pub article: String,
    /// Article description
    pub description: String,
    /// Violation count
    pub count: usize,
}

/// Analyst note/annotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystNote {
    /// Target type (what is being annotated)
    pub target_type: NoteTargetType,
    /// Target identifier (CVE ID, component name, etc.)
    pub target_id: Option<String>,
    /// Note content
    pub note: String,
    /// Whether this marks a false positive
    pub false_positive: bool,
    /// Severity override if applicable
    pub severity_override: Option<String>,
    /// Note creation timestamp
    pub created_at: DateTime<Utc>,
    /// Analyst identifier
    pub analyst: Option<String>,
}

impl AnalystNote {
    /// Create a new analyst note
    pub fn new(target_type: NoteTargetType, note: String) -> Self {
        Self {
            target_type,
            target_id: None,
            note,
            false_positive: false,
            severity_override: None,
            created_at: Utc::now(),
            analyst: None,
        }
    }

    /// Create a note for a vulnerability
    pub fn for_vulnerability(vuln_id: String, note: String) -> Self {
        Self {
            target_type: NoteTargetType::Vulnerability,
            target_id: Some(vuln_id),
            note,
            false_positive: false,
            severity_override: None,
            created_at: Utc::now(),
            analyst: None,
        }
    }

    /// Create a note for a component
    pub fn for_component(component_name: String, note: String) -> Self {
        Self {
            target_type: NoteTargetType::Component,
            target_id: Some(component_name),
            note,
            false_positive: false,
            severity_override: None,
            created_at: Utc::now(),
            analyst: None,
        }
    }

    /// Mark as false positive
    pub fn mark_false_positive(mut self) -> Self {
        self.false_positive = true;
        self
    }
}

/// Type of target for analyst notes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteTargetType {
    /// Note about a vulnerability
    Vulnerability,
    /// Note about a component
    Component,
    /// Note about a license
    License,
    /// General note
    General,
}

impl std::fmt::Display for NoteTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoteTargetType::Vulnerability => write!(f, "Vulnerability"),
            NoteTargetType::Component => write!(f, "Component"),
            NoteTargetType::License => write!(f, "License"),
            NoteTargetType::General => write!(f, "General"),
        }
    }
}

/// Recommended action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level
    pub priority: RecommendationPriority,
    /// Category of recommendation
    pub category: RecommendationCategory,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Affected components
    pub affected_components: Vec<String>,
    /// Estimated effort (optional)
    pub effort: Option<String>,
}

impl Recommendation {
    /// Create a new recommendation
    pub fn new(
        priority: RecommendationPriority,
        category: RecommendationCategory,
        title: String,
        description: String,
    ) -> Self {
        Self {
            priority,
            category,
            title,
            description,
            affected_components: Vec::new(),
            effort: None,
        }
    }
}

/// Recommendation priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendationPriority::Critical => write!(f, "Critical"),
            RecommendationPriority::High => write!(f, "High"),
            RecommendationPriority::Medium => write!(f, "Medium"),
            RecommendationPriority::Low => write!(f, "Low"),
        }
    }
}

/// Recommendation category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationCategory {
    /// Upgrade a dependency
    Upgrade,
    /// Replace a dependency
    Replace,
    /// Investigate further
    Investigate,
    /// Monitor for updates
    Monitor,
    /// Add missing information
    AddInfo,
    /// Fix configuration
    Config,
}

impl std::fmt::Display for RecommendationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendationCategory::Upgrade => write!(f, "Upgrade"),
            RecommendationCategory::Replace => write!(f, "Replace"),
            RecommendationCategory::Investigate => write!(f, "Investigate"),
            RecommendationCategory::Monitor => write!(f, "Monitor"),
            RecommendationCategory::AddInfo => write!(f, "Add Information"),
            RecommendationCategory::Config => write!(f, "Configuration"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(26), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(51), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(76), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    #[test]
    fn test_analyst_note_creation() {
        let note = AnalystNote::for_vulnerability(
            "CVE-2024-1234".to_string(),
            "Mitigated by WAF".to_string(),
        );
        assert_eq!(note.target_type, NoteTargetType::Vulnerability);
        assert_eq!(note.target_id, Some("CVE-2024-1234".to_string()));
        assert!(!note.false_positive);

        let fp_note = note.mark_false_positive();
        assert!(fp_note.false_positive);
    }

    #[test]
    fn test_recommendation_ordering() {
        assert!(RecommendationPriority::Critical < RecommendationPriority::High);
        assert!(RecommendationPriority::High < RecommendationPriority::Medium);
        assert!(RecommendationPriority::Medium < RecommendationPriority::Low);
    }
}
