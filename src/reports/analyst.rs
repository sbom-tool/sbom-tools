//! Analyst report data structures for security analysis exports.
//!
//! This module provides structures for generating comprehensive security
//! analysis reports that can be exported to Markdown or JSON format.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Write;

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
    /// Cryptographic asset findings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_findings: Option<CryptoFindings>,
    /// Analyst notes and annotations
    pub analyst_notes: Vec<AnalystNote>,
    /// Recommended actions
    pub recommendations: Vec<Recommendation>,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
}

impl AnalystReport {
    /// Create a new empty analyst report
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: AnalystReportMetadata::default(),
            executive_summary: ExecutiveSummary::default(),
            vulnerability_findings: VulnerabilityFindings::default(),
            component_findings: ComponentFindings::default(),
            compliance_status: ComplianceStatus::default(),
            crypto_findings: None,
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
    #[must_use]
    pub fn to_markdown(&self) -> String {
        // Estimate capacity: ~200 bytes per section, plus variable content
        let crypto_size = self.crypto_findings.as_ref().map_or(0, |cf| {
            500 + cf.weak_algorithms.len() * 100 + cf.deprecation_warnings.len() * 80
        });
        let estimated_size = 2000
            + self.vulnerability_findings.kev_vulnerabilities.len() * 100
            + self.component_findings.license_issues.len() * 150
            + self.recommendations.len() * 300
            + self.analyst_notes.len() * 100
            + crypto_size;
        let mut md = String::with_capacity(estimated_size);

        // Title
        md.push_str("# Security Analysis Report\n\n");

        // Metadata
        if let Some(title) = &self.metadata.title {
            let _ = writeln!(md, "**Analysis:** {title}");
        }
        if let Some(analyst) = &self.metadata.analyst {
            let _ = writeln!(md, "**Analyst:** {analyst}");
        }
        let _ = writeln!(
            md,
            "**Generated:** {}",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if !self.metadata.sbom_paths.is_empty() {
            let _ = writeln!(
                md,
                "**SBOMs Analyzed:** {}",
                self.metadata.sbom_paths.join(", ")
            );
        }
        md.push_str("\n---\n\n");

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        let _ = writeln!(
            md,
            "**Risk Score:** {} ({:?})\n",
            self.executive_summary.risk_score, self.executive_summary.risk_level
        );

        md.push_str("| Metric | Count |\n");
        md.push_str("|--------|-------|\n");
        let _ = writeln!(
            md,
            "| Critical Issues | {} |",
            self.executive_summary.critical_issues
        );
        let _ = writeln!(
            md,
            "| High Issues | {} |",
            self.executive_summary.high_issues
        );
        let _ = writeln!(
            md,
            "| KEV Vulnerabilities | {} |",
            self.executive_summary.kev_count
        );
        let _ = writeln!(
            md,
            "| Stale Dependencies | {} |",
            self.executive_summary.stale_dependencies
        );
        let _ = writeln!(
            md,
            "| License Conflicts | {} |",
            self.executive_summary.license_conflicts
        );
        if let Some(cra) = self.executive_summary.cra_compliance_score {
            let _ = writeln!(md, "| CRA Compliance | {cra}% |");
        }
        md.push('\n');

        if !self.executive_summary.summary_text.is_empty() {
            md.push_str(&self.executive_summary.summary_text);
            md.push_str("\n\n");
        }

        // Vulnerability Findings
        md.push_str("## Vulnerability Findings\n\n");
        let _ = writeln!(
            md,
            "- **Total Vulnerabilities:** {}",
            self.vulnerability_findings.total_count
        );
        let _ = writeln!(
            md,
            "- **Critical:** {}",
            self.vulnerability_findings.critical_vulnerabilities.len()
        );
        let _ = writeln!(
            md,
            "- **High:** {}",
            self.vulnerability_findings.high_vulnerabilities.len()
        );
        let _ = writeln!(
            md,
            "- **Medium:** {}",
            self.vulnerability_findings.medium_vulnerabilities.len()
        );
        let _ = writeln!(
            md,
            "- **Low:** {}",
            self.vulnerability_findings.low_vulnerabilities.len()
        );

        if !self.vulnerability_findings.kev_vulnerabilities.is_empty() {
            md.push_str("\n### Known Exploited Vulnerabilities (KEV)\n\n");
            md.push_str(
                "These vulnerabilities are actively being exploited in the wild and require immediate attention.\n\n",
            );
            for vuln in &self.vulnerability_findings.kev_vulnerabilities {
                let _ = writeln!(
                    md,
                    "- **{}** ({}) - {}",
                    vuln.id, vuln.severity, vuln.component_name
                );
            }
        }
        md.push('\n');

        // Component Findings
        md.push_str("## Component Findings\n\n");
        let _ = writeln!(
            md,
            "- **Total Components:** {}",
            self.component_findings.total_components
        );
        let _ = writeln!(md, "- **Added:** {}", self.component_findings.added_count);
        let _ = writeln!(
            md,
            "- **Removed:** {}",
            self.component_findings.removed_count
        );
        let _ = writeln!(
            md,
            "- **Stale:** {}",
            self.component_findings.stale_components.len()
        );
        let _ = writeln!(
            md,
            "- **Deprecated:** {}",
            self.component_findings.deprecated_components.len()
        );
        md.push('\n');

        // License Issues
        if !self.component_findings.license_issues.is_empty() {
            md.push_str("### License Issues\n\n");
            for issue in &self.component_findings.license_issues {
                let components = issue.affected_components.join(", ");
                let _ = writeln!(
                    md,
                    "- **{}** ({}): {} - {}",
                    issue.issue_type, issue.severity, issue.description, components
                );
            }
            md.push('\n');
        }

        // Cryptographic Findings
        if let Some(cf) = &self.crypto_findings {
            md.push_str("## Cryptographic Asset Findings\n\n");
            md.push_str("| Metric | Value |\n");
            md.push_str("|--------|-------|\n");
            let _ = writeln!(md, "| Total Crypto Assets | {} |", cf.total_crypto_assets);
            let _ = writeln!(md, "| Algorithms | {} |", cf.algorithms_count);
            let _ = writeln!(md, "| Certificates | {} |", cf.certificates_count);
            let _ = writeln!(md, "| Key Material | {} |", cf.keys_count);
            let _ = writeln!(md, "| Protocols | {} |", cf.protocols_count);
            // A 0/0 readiness is vacuous, not perfect: without algorithms
            // there is nothing to be quantum-ready about.
            if cf.algorithms_count > 0 {
                let _ = writeln!(
                    md,
                    "| Quantum Readiness | {:.0}% ({}/{}) |",
                    cf.quantum_readiness_pct, cf.quantum_safe_count, cf.algorithms_count
                );
            } else {
                md.push_str("| Quantum Readiness | n/a (no algorithms declared) |\n");
            }
            if cf.hybrid_pqc_count > 0 {
                let _ = writeln!(md, "| Hybrid PQC Combiners | {} |", cf.hybrid_pqc_count);
            }
            md.push('\n');

            if !cf.weak_algorithms.is_empty() {
                md.push_str("### Weak/Broken Algorithms\n\n");
                md.push_str("| Algorithm | Family | Quantum Level | Reason |\n");
                md.push_str("|-----------|--------|---------------|--------|\n");
                for algo in &cf.weak_algorithms {
                    let family = algo.family.as_deref().unwrap_or("-");
                    let ql = algo
                        .quantum_level
                        .map_or("-".to_string(), |l| l.to_string());
                    let _ = writeln!(md, "| {} | {family} | {ql} | {} |", algo.name, algo.reason);
                }
                md.push('\n');
            }

            if !cf.expired_certificates.is_empty() {
                md.push_str("### Expired Certificates\n\n");
                for cert in &cf.expired_certificates {
                    let expires = cert.expires.as_deref().unwrap_or("unknown");
                    let _ = writeln!(md, "- **{}** — expired {expires}", cert.name);
                }
                md.push('\n');
            }

            if !cf.compromised_keys.is_empty() {
                md.push_str("### Compromised Key Material\n\n");
                for key in &cf.compromised_keys {
                    let _ = writeln!(
                        md,
                        "- **{}** ({}) — state: {}",
                        key.name, key.material_type, key.state
                    );
                }
                md.push('\n');
            }

            if !cf.deprecation_warnings.is_empty() {
                md.push_str("### Quantum Deprecation Warnings\n\n");
                for warning in &cf.deprecation_warnings {
                    let _ = writeln!(md, "- {warning}");
                }
                md.push('\n');
            }
        }

        // Compliance Status
        if self.compliance_status.score > 0 {
            md.push_str("## Compliance Status\n\n");
            let _ = writeln!(
                md,
                "**CRA Compliance:** {}%\n",
                self.compliance_status.score
            );

            if !self.compliance_status.violations_by_article.is_empty() {
                md.push_str("### CRA Violations\n\n");
                for violation in &self.compliance_status.violations_by_article {
                    let _ = writeln!(
                        md,
                        "- **{}** ({} occurrences): {}",
                        violation.article, violation.count, violation.description
                    );
                }
                md.push('\n');
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            md.push_str("## Recommendations\n\n");

            let mut sorted_recs = self.recommendations.clone();
            sorted_recs.sort_by_key(|a| a.priority);

            for rec in &sorted_recs {
                let _ = writeln!(
                    md,
                    "### [{:?}] {} - {}\n",
                    rec.priority, rec.category, rec.title
                );
                md.push_str(&rec.description);
                md.push_str("\n\n");
                if !rec.affected_components.is_empty() {
                    let _ = writeln!(md, "**Affected:** {}\n", rec.affected_components.join(", "));
                }
                if let Some(effort) = &rec.effort {
                    let _ = writeln!(md, "**Estimated Effort:** {effort}\n");
                }
            }
        }

        // Analyst Notes
        if !self.analyst_notes.is_empty() {
            md.push_str("## Analyst Notes\n\n");
            for note in &self.analyst_notes {
                let fp_marker = if note.false_positive {
                    " [FALSE POSITIVE]"
                } else {
                    ""
                };
                if let Some(id) = &note.target_id {
                    let _ = writeln!(
                        md,
                        "- **{} ({}){}**: {}",
                        note.target_type, id, fp_marker, note.note
                    );
                } else {
                    let _ = writeln!(md, "- **{}{}**: {}", note.target_type, fp_marker, note.note);
                }
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
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=25 => Self::Low,
            26..=50 => Self::Medium,
            51..=75 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Get display label
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
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
    #[must_use]
    pub fn all_findings(&self) -> Vec<&VulnFinding> {
        let capacity = self.kev_vulnerabilities.len()
            + self.critical_vulnerabilities.len()
            + self.high_vulnerabilities.len()
            + self.medium_vulnerabilities.len()
            + self.low_vulnerabilities.len();
        let mut all = Vec::with_capacity(capacity);
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
    #[must_use]
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
            Self::BinaryIncompatible => write!(f, "Binary Incompatible"),
            Self::ProjectIncompatible => write!(f, "Project Incompatible"),
            Self::NetworkCopyleft => write!(f, "Network Copyleft"),
            Self::PatentConflict => write!(f, "Patent Conflict"),
            Self::UnknownLicense => write!(f, "Unknown License"),
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
            Self::Error => write!(f, "Error"),
            Self::Warning => write!(f, "Warning"),
            Self::Info => write!(f, "Info"),
        }
    }
}

/// Cryptographic asset findings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoFindings {
    /// Total cryptographic components
    pub total_crypto_assets: usize,
    /// Algorithm count
    pub algorithms_count: usize,
    /// Certificate count
    pub certificates_count: usize,
    /// Key material count
    pub keys_count: usize,
    /// Protocol count
    pub protocols_count: usize,
    /// Quantum readiness percentage (0-100)
    pub quantum_readiness_pct: f32,
    /// Quantum-safe algorithm count
    pub quantum_safe_count: usize,
    /// Quantum-vulnerable algorithm count
    pub quantum_vulnerable_count: usize,
    /// Hybrid PQC combiner count
    pub hybrid_pqc_count: usize,
    /// Weak/broken algorithms found
    pub weak_algorithms: Vec<CryptoAlgorithmFinding>,
    /// Expired certificates
    pub expired_certificates: Vec<CryptoCertFinding>,
    /// Compromised key material
    pub compromised_keys: Vec<CryptoKeyFinding>,
    /// Deprecation warnings (quantum-vulnerable classical algorithms)
    pub deprecation_warnings: Vec<String>,
}

/// Individual algorithm finding for analyst reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAlgorithmFinding {
    /// Algorithm name
    pub name: String,
    /// Algorithm family (e.g., "SHA-1", "DES")
    pub family: Option<String>,
    /// NIST quantum security level (0 = vulnerable)
    pub quantum_level: Option<u8>,
    /// Why this is flagged
    pub reason: String,
}

/// Certificate finding for analyst reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoCertFinding {
    /// Certificate subject or component name
    pub name: String,
    /// Expiry date
    pub expires: Option<String>,
    /// Days overdue (positive = expired)
    pub days_overdue: Option<i64>,
}

/// Key material finding for analyst reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKeyFinding {
    /// Key component name
    pub name: String,
    /// Material type
    pub material_type: String,
    /// Current state
    pub state: String,
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
    /// Article reference (e.g., "Art. 13(17)")
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub const fn mark_false_positive(mut self) -> Self {
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
    /// Note about a cryptographic asset
    Cryptography,
    /// General note
    General,
}

impl std::fmt::Display for NoteTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vulnerability => write!(f, "Vulnerability"),
            Self::Component => write!(f, "Component"),
            Self::License => write!(f, "License"),
            Self::Cryptography => write!(f, "Cryptography"),
            Self::General => write!(f, "General"),
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
    #[must_use]
    pub const fn new(
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
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
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
    /// Cryptographic migration or remediation
    Cryptography,
}

impl std::fmt::Display for RecommendationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upgrade => write!(f, "Upgrade"),
            Self::Replace => write!(f, "Replace"),
            Self::Investigate => write!(f, "Investigate"),
            Self::Monitor => write!(f, "Monitor"),
            Self::AddInfo => write!(f, "Add Information"),
            Self::Config => write!(f, "Configuration"),
            Self::Cryptography => write!(f, "Cryptography"),
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

    /// Zero algorithms must render as "n/a", never a vacuous 100% readiness.
    #[test]
    fn test_crypto_findings_zero_algorithms_render_na() {
        let mut report = AnalystReport::new();
        report.crypto_findings = Some(CryptoFindings {
            total_crypto_assets: 2,
            certificates_count: 2,
            ..Default::default()
        });
        let md = report.to_markdown();
        assert!(md.contains("| Quantum Readiness | n/a (no algorithms declared) |"));
        assert!(!md.contains("Quantum Readiness | 100%"));
    }
}
