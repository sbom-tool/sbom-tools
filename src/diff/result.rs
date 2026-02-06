//! Diff result structures.

use crate::model::{CanonicalId, Component, ComponentRef, DependencyEdge, VulnerabilityRef};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Map a severity string to a numeric rank for comparison.
///
/// Higher values indicate more severe vulnerabilities.
/// Returns 0 for unrecognized severity strings.
fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Complete result of an SBOM diff operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct DiffResult {
    /// Summary statistics
    pub summary: DiffSummary,
    /// Component changes
    pub components: ChangeSet<ComponentChange>,
    /// Dependency changes
    pub dependencies: ChangeSet<DependencyChange>,
    /// License changes
    pub licenses: LicenseChanges,
    /// Vulnerability changes
    pub vulnerabilities: VulnerabilityChanges,
    /// Total semantic score
    pub semantic_score: f64,
    /// Graph structural changes (only populated if graph diffing is enabled)
    #[serde(default)]
    pub graph_changes: Vec<DependencyGraphChange>,
    /// Summary of graph changes
    #[serde(default)]
    pub graph_summary: Option<GraphChangeSummary>,
    /// Number of custom matching rules applied
    #[serde(default)]
    pub rules_applied: usize,
}

impl DiffResult {
    /// Create a new empty diff result
    pub fn new() -> Self {
        Self {
            summary: DiffSummary::default(),
            components: ChangeSet::new(),
            dependencies: ChangeSet::new(),
            licenses: LicenseChanges::default(),
            vulnerabilities: VulnerabilityChanges::default(),
            semantic_score: 0.0,
            graph_changes: Vec::new(),
            graph_summary: None,
            rules_applied: 0,
        }
    }

    /// Calculate and update summary statistics
    pub fn calculate_summary(&mut self) {
        self.summary.components_added = self.components.added.len();
        self.summary.components_removed = self.components.removed.len();
        self.summary.components_modified = self.components.modified.len();
        self.summary.total_changes = self.summary.components_added
            + self.summary.components_removed
            + self.summary.components_modified;

        self.summary.dependencies_added = self.dependencies.added.len();
        self.summary.dependencies_removed = self.dependencies.removed.len();

        self.summary.vulnerabilities_introduced = self.vulnerabilities.introduced.len();
        self.summary.vulnerabilities_resolved = self.vulnerabilities.resolved.len();
        self.summary.vulnerabilities_persistent = self.vulnerabilities.persistent.len();

        self.summary.licenses_added = self.licenses.new_licenses.len();
        self.summary.licenses_removed = self.licenses.removed_licenses.len();
    }

    /// Check if there are any changes
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.summary.total_changes > 0
            || !self.dependencies.is_empty()
            || !self.vulnerabilities.introduced.is_empty()
            || !self.vulnerabilities.resolved.is_empty()
            || !self.graph_changes.is_empty()
    }

    /// Set graph changes and compute summary
    pub fn set_graph_changes(&mut self, changes: Vec<DependencyGraphChange>) {
        self.graph_summary = Some(GraphChangeSummary::from_changes(&changes));
        self.graph_changes = changes;
    }

    /// Find a component change by canonical ID
    pub fn find_component_by_id(&self, id: &CanonicalId) -> Option<&ComponentChange> {
        let id_str = id.value();
        self.components
            .added
            .iter()
            .chain(self.components.removed.iter())
            .chain(self.components.modified.iter())
            .find(|c| c.id == id_str)
    }

    /// Find a component change by ID string
    pub fn find_component_by_id_str(&self, id_str: &str) -> Option<&ComponentChange> {
        self.components
            .added
            .iter()
            .chain(self.components.removed.iter())
            .chain(self.components.modified.iter())
            .find(|c| c.id == id_str)
    }

    /// Get all component changes as a flat list with their indices for navigation
    pub fn all_component_changes(&self) -> Vec<&ComponentChange> {
        self.components
            .added
            .iter()
            .chain(self.components.removed.iter())
            .chain(self.components.modified.iter())
            .collect()
    }

    /// Find vulnerabilities affecting a specific component by ID
    pub fn find_vulns_for_component(&self, component_id: &CanonicalId) -> Vec<&VulnerabilityDetail> {
        let id_str = component_id.value();
        self.vulnerabilities
            .introduced
            .iter()
            .chain(self.vulnerabilities.resolved.iter())
            .chain(self.vulnerabilities.persistent.iter())
            .filter(|v| v.component_id == id_str)
            .collect()
    }

    /// Build an index of component IDs to their changes for fast lookup
    #[must_use]
    pub fn build_component_id_index(&self) -> HashMap<String, &ComponentChange> {
        self.components
            .added
            .iter()
            .chain(&self.components.removed)
            .chain(&self.components.modified)
            .map(|c| (c.id.clone(), c))
            .collect()
    }

    /// Filter vulnerabilities by minimum severity level
    pub fn filter_by_severity(&mut self, min_severity: &str) {
        let min_sev = severity_rank(min_severity);

        self.vulnerabilities
            .introduced
            .retain(|v| severity_rank(&v.severity) >= min_sev);
        self.vulnerabilities
            .resolved
            .retain(|v| severity_rank(&v.severity) >= min_sev);
        self.vulnerabilities
            .persistent
            .retain(|v| severity_rank(&v.severity) >= min_sev);

        // Recalculate summary
        self.calculate_summary();
    }

    /// Filter out vulnerabilities where VEX status is `NotAffected` or `Fixed`.
    ///
    /// Keeps vulnerabilities that are `Affected`, `UnderInvestigation`, or have no VEX status.
    pub fn filter_by_vex(&mut self) {
        self.vulnerabilities
            .introduced
            .retain(VulnerabilityDetail::is_vex_actionable);
        self.vulnerabilities
            .resolved
            .retain(VulnerabilityDetail::is_vex_actionable);
        self.vulnerabilities
            .persistent
            .retain(VulnerabilityDetail::is_vex_actionable);

        self.calculate_summary();
    }
}

impl Default for DiffResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics for the diff
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_changes: usize,
    pub components_added: usize,
    pub components_removed: usize,
    pub components_modified: usize,
    pub dependencies_added: usize,
    pub dependencies_removed: usize,
    pub vulnerabilities_introduced: usize,
    pub vulnerabilities_resolved: usize,
    pub vulnerabilities_persistent: usize,
    pub licenses_added: usize,
    pub licenses_removed: usize,
}

/// Generic change set for added/removed/modified items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet<T> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub modified: Vec<T>,
}

impl<T> ChangeSet<T> {
    pub fn new() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

impl<T> Default for ChangeSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about how a component was matched.
///
/// Included in JSON output to explain why components were correlated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInfo {
    /// Match confidence score (0.0 - 1.0)
    pub score: f64,
    /// Matching method used (ExactIdentifier, Alias, Fuzzy, etc.)
    pub method: String,
    /// Human-readable explanation
    pub reason: String,
    /// Detailed score breakdown (optional)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub score_breakdown: Vec<MatchScoreComponent>,
    /// Normalizations applied during matching
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub normalizations: Vec<String>,
    /// Confidence interval for the match score
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_interval: Option<ConfidenceInterval>,
}

/// Confidence interval for match score.
///
/// Provides uncertainty bounds around the match score, useful for
/// understanding match reliability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound of confidence (0.0 - 1.0)
    pub lower: f64,
    /// Upper bound of confidence (0.0 - 1.0)
    pub upper: f64,
    /// Confidence level (e.g., 0.95 for 95% CI)
    pub level: f64,
}

impl ConfidenceInterval {
    /// Create a new confidence interval.
    pub fn new(lower: f64, upper: f64, level: f64) -> Self {
        Self {
            lower: lower.clamp(0.0, 1.0),
            upper: upper.clamp(0.0, 1.0),
            level,
        }
    }

    /// Create a 95% confidence interval from a score and standard error.
    ///
    /// Uses ±1.96 × SE for 95% CI.
    pub fn from_score_and_error(score: f64, std_error: f64) -> Self {
        let margin = 1.96 * std_error;
        Self::new(score - margin, score + margin, 0.95)
    }

    /// Create a simple confidence interval based on the matching tier.
    ///
    /// Exact matches have tight intervals, fuzzy matches have wider intervals.
    pub fn from_tier(score: f64, tier: &str) -> Self {
        let margin = match tier {
            "ExactIdentifier" => 0.0,
            "Alias" => 0.02,
            "EcosystemRule" => 0.03,
            "CustomRule" => 0.05,
            "Fuzzy" => 0.08,
            _ => 0.10,
        };
        Self::new(score - margin, score + margin, 0.95)
    }

    /// Get the width of the interval.
    pub fn width(&self) -> f64 {
        self.upper - self.lower
    }
}

/// A component of the match score for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchScoreComponent {
    /// Name of this score component
    pub name: String,
    /// Weight applied
    pub weight: f64,
    /// Raw score
    pub raw_score: f64,
    /// Weighted contribution
    pub weighted_score: f64,
    /// Description
    pub description: String,
}

/// Component change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentChange {
    /// Component canonical ID (string for serialization)
    pub id: String,
    /// Typed canonical ID for navigation (skipped in JSON output for backward compat)
    #[serde(skip)]
    pub canonical_id: Option<CanonicalId>,
    /// Component reference with ID and name together
    #[serde(skip)]
    pub component_ref: Option<ComponentRef>,
    /// Old component ID (for modified components)
    #[serde(skip)]
    pub old_canonical_id: Option<CanonicalId>,
    /// Component name
    pub name: String,
    /// Old version (if existed)
    pub old_version: Option<String>,
    /// New version (if exists)
    pub new_version: Option<String>,
    /// Ecosystem
    pub ecosystem: Option<String>,
    /// Change type
    pub change_type: ChangeType,
    /// Detailed field changes
    pub field_changes: Vec<FieldChange>,
    /// Associated cost
    pub cost: u32,
    /// Match information (for modified components, explains how old/new were correlated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_info: Option<MatchInfo>,
}

impl ComponentChange {
    /// Create a new component addition
    pub fn added(component: &Component, cost: u32) -> Self {
        Self {
            id: component.canonical_id.to_string(),
            canonical_id: Some(component.canonical_id.clone()),
            component_ref: Some(ComponentRef::from_component(component)),
            old_canonical_id: None,
            name: component.name.clone(),
            old_version: None,
            new_version: component.version.clone(),
            ecosystem: component.ecosystem.as_ref().map(std::string::ToString::to_string),
            change_type: ChangeType::Added,
            field_changes: Vec::new(),
            cost,
            match_info: None,
        }
    }

    /// Create a new component removal
    pub fn removed(component: &Component, cost: u32) -> Self {
        Self {
            id: component.canonical_id.to_string(),
            canonical_id: Some(component.canonical_id.clone()),
            component_ref: Some(ComponentRef::from_component(component)),
            old_canonical_id: Some(component.canonical_id.clone()),
            name: component.name.clone(),
            old_version: component.version.clone(),
            new_version: None,
            ecosystem: component.ecosystem.as_ref().map(std::string::ToString::to_string),
            change_type: ChangeType::Removed,
            field_changes: Vec::new(),
            cost,
            match_info: None,
        }
    }

    /// Create a component modification
    pub fn modified(
        old: &Component,
        new: &Component,
        field_changes: Vec<FieldChange>,
        cost: u32,
    ) -> Self {
        Self {
            id: new.canonical_id.to_string(),
            canonical_id: Some(new.canonical_id.clone()),
            component_ref: Some(ComponentRef::from_component(new)),
            old_canonical_id: Some(old.canonical_id.clone()),
            name: new.name.clone(),
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            ecosystem: new.ecosystem.as_ref().map(std::string::ToString::to_string),
            change_type: ChangeType::Modified,
            field_changes,
            cost,
            match_info: None,
        }
    }

    /// Create a component modification with match explanation
    pub fn modified_with_match(
        old: &Component,
        new: &Component,
        field_changes: Vec<FieldChange>,
        cost: u32,
        match_info: MatchInfo,
    ) -> Self {
        Self {
            id: new.canonical_id.to_string(),
            canonical_id: Some(new.canonical_id.clone()),
            component_ref: Some(ComponentRef::from_component(new)),
            old_canonical_id: Some(old.canonical_id.clone()),
            name: new.name.clone(),
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            ecosystem: new.ecosystem.as_ref().map(std::string::ToString::to_string),
            change_type: ChangeType::Modified,
            field_changes,
            cost,
            match_info: Some(match_info),
        }
    }

    /// Add match information to an existing change
    pub fn with_match_info(mut self, match_info: MatchInfo) -> Self {
        self.match_info = Some(match_info);
        self
    }

    /// Get the typed canonical ID, falling back to parsing from string if needed
    pub fn get_canonical_id(&self) -> CanonicalId {
        self.canonical_id
            .clone()
            .unwrap_or_else(|| CanonicalId::from_name_version(&self.name, self.new_version.as_deref().or(self.old_version.as_deref())))
    }

    /// Get a ComponentRef for this change
    pub fn get_component_ref(&self) -> ComponentRef {
        self.component_ref.clone().unwrap_or_else(|| {
            ComponentRef::with_version(
                self.get_canonical_id(),
                &self.name,
                self.new_version.clone().or_else(|| self.old_version.clone()),
            )
        })
    }
}

impl MatchInfo {
    /// Create from a MatchExplanation
    pub fn from_explanation(explanation: &crate::matching::MatchExplanation) -> Self {
        let method = format!("{:?}", explanation.tier);
        let ci = ConfidenceInterval::from_tier(explanation.score, &method);
        Self {
            score: explanation.score,
            method,
            reason: explanation.reason.clone(),
            score_breakdown: explanation
                .score_breakdown
                .iter()
                .map(|c| MatchScoreComponent {
                    name: c.name.clone(),
                    weight: c.weight,
                    raw_score: c.raw_score,
                    weighted_score: c.weighted_score,
                    description: c.description.clone(),
                })
                .collect(),
            normalizations: explanation.normalizations_applied.clone(),
            confidence_interval: Some(ci),
        }
    }

    /// Create a simple match info without detailed breakdown
    pub fn simple(score: f64, method: &str, reason: &str) -> Self {
        let ci = ConfidenceInterval::from_tier(score, method);
        Self {
            score,
            method: method.to_string(),
            reason: reason.to_string(),
            score_breakdown: Vec::new(),
            normalizations: Vec::new(),
            confidence_interval: Some(ci),
        }
    }

    /// Create a match info with a custom confidence interval
    pub fn with_confidence_interval(mut self, ci: ConfidenceInterval) -> Self {
        self.confidence_interval = Some(ci);
        self
    }
}

/// Type of change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    Unchanged,
}

/// Individual field change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Dependency change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyChange {
    /// Source component
    pub from: String,
    /// Target component
    pub to: String,
    /// Relationship type
    pub relationship: String,
    /// Change type
    pub change_type: ChangeType,
}

impl DependencyChange {
    pub fn added(edge: &DependencyEdge) -> Self {
        Self {
            from: edge.from.to_string(),
            to: edge.to.to_string(),
            relationship: edge.relationship.to_string(),
            change_type: ChangeType::Added,
        }
    }

    pub fn removed(edge: &DependencyEdge) -> Self {
        Self {
            from: edge.from.to_string(),
            to: edge.to.to_string(),
            relationship: edge.relationship.to_string(),
            change_type: ChangeType::Removed,
        }
    }
}

/// License change information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseChanges {
    /// Newly introduced licenses
    pub new_licenses: Vec<LicenseChange>,
    /// Removed licenses
    pub removed_licenses: Vec<LicenseChange>,
    /// License conflicts
    pub conflicts: Vec<LicenseConflict>,
    /// Components with license changes
    pub component_changes: Vec<ComponentLicenseChange>,
}

/// Individual license change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseChange {
    /// License expression
    pub license: String,
    /// Components using this license
    pub components: Vec<String>,
    /// License family
    pub family: String,
}

/// License conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConflict {
    pub license_a: String,
    pub license_b: String,
    pub component: String,
    pub description: String,
}

/// Component-level license change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentLicenseChange {
    pub component_id: String,
    pub component_name: String,
    pub old_licenses: Vec<String>,
    pub new_licenses: Vec<String>,
}

/// Vulnerability change information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityChanges {
    /// Newly introduced vulnerabilities
    pub introduced: Vec<VulnerabilityDetail>,
    /// Resolved vulnerabilities
    pub resolved: Vec<VulnerabilityDetail>,
    /// Persistent vulnerabilities (present in both)
    pub persistent: Vec<VulnerabilityDetail>,
}

impl VulnerabilityChanges {
    /// Count vulnerabilities by severity
    pub fn introduced_by_severity(&self) -> HashMap<String, usize> {
        // Pre-allocate for typical severity levels (critical, high, medium, low, unknown)
        let mut counts = HashMap::with_capacity(5);
        for vuln in &self.introduced {
            *counts.entry(vuln.severity.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Get critical and high severity introduced vulnerabilities
    pub fn critical_and_high_introduced(&self) -> Vec<&VulnerabilityDetail> {
        self.introduced
            .iter()
            .filter(|v| v.severity == "Critical" || v.severity == "High")
            .collect()
    }
}

/// SLA status for vulnerability remediation tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlaStatus {
    /// Past SLA deadline by N days
    Overdue(i64),
    /// Due within 3 days (N days remaining)
    DueSoon(i64),
    /// Within SLA window (N days remaining)
    OnTrack(i64),
    /// No SLA deadline applicable
    NoDueDate,
}

impl SlaStatus {
    /// Format for display (e.g., "3d late", "2d left", "45d old")
    pub fn display(&self, days_since_published: Option<i64>) -> String {
        match self {
            Self::Overdue(days) => format!("{days}d late"),
            Self::DueSoon(days) => format!("{days}d left"),
            Self::OnTrack(days) => format!("{days}d left"),
            Self::NoDueDate => {
                if let Some(age) = days_since_published {
                    format!("{age}d old")
                } else {
                    "-".to_string()
                }
            }
        }
    }

    /// Check if this is an overdue status
    pub fn is_overdue(&self) -> bool {
        matches!(self, Self::Overdue(_))
    }

    /// Check if this is due soon (approaching deadline)
    pub fn is_due_soon(&self) -> bool {
        matches!(self, Self::DueSoon(_))
    }
}

/// Detailed vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDetail {
    /// Vulnerability ID
    pub id: String,
    /// Source database
    pub source: String,
    /// Severity level
    pub severity: String,
    /// CVSS score
    pub cvss_score: Option<f32>,
    /// Affected component ID (string for serialization)
    pub component_id: String,
    /// Typed canonical ID for the component (skipped in JSON for backward compat)
    #[serde(skip)]
    pub component_canonical_id: Option<CanonicalId>,
    /// Component reference with ID and name together
    #[serde(skip)]
    pub component_ref: Option<ComponentRef>,
    /// Affected component name
    pub component_name: String,
    /// Affected version
    pub version: Option<String>,
    /// CWE identifiers
    pub cwes: Vec<String>,
    /// Description
    pub description: Option<String>,
    /// Remediation info
    pub remediation: Option<String>,
    /// Whether this vulnerability is in CISA's Known Exploited Vulnerabilities catalog
    #[serde(default)]
    pub is_kev: bool,
    /// Dependency depth (1 = direct, 2+ = transitive, None = unknown)
    #[serde(default)]
    pub component_depth: Option<u32>,
    /// Date vulnerability was published (ISO 8601)
    #[serde(default)]
    pub published_date: Option<String>,
    /// KEV due date (CISA mandated remediation deadline)
    #[serde(default)]
    pub kev_due_date: Option<String>,
    /// Days since published (positive = past)
    #[serde(default)]
    pub days_since_published: Option<i64>,
    /// Days until KEV due date (negative = overdue)
    #[serde(default)]
    pub days_until_due: Option<i64>,
    /// VEX state for this vulnerability's component (if available)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vex_state: Option<crate::model::VexState>,
}

impl VulnerabilityDetail {
    /// Whether this vulnerability is VEX-actionable (not resolved by vendor analysis).
    ///
    /// Returns `true` if the VEX state is `Affected`, `UnderInvestigation`, or absent.
    /// Returns `false` if the VEX state is `NotAffected` or `Fixed`.
    pub fn is_vex_actionable(&self) -> bool {
        !matches!(
            self.vex_state,
            Some(crate::model::VexState::NotAffected) | Some(crate::model::VexState::Fixed)
        )
    }

    /// Create from a vulnerability reference and component
    pub fn from_ref(vuln: &VulnerabilityRef, component: &Component) -> Self {
        // Calculate days since published (published is DateTime<Utc>)
        let days_since_published = vuln.published.map(|dt| {
            let today = chrono::Utc::now().date_naive();
            (today - dt.date_naive()).num_days()
        });

        // Format published date as string for serialization
        let published_date = vuln.published.map(|dt| dt.format("%Y-%m-%d").to_string());

        // Get KEV info if present
        let (kev_due_date, days_until_due) = if let Some(kev) = &vuln.kev_info {
            (
                Some(kev.due_date.format("%Y-%m-%d").to_string()),
                Some(kev.days_until_due()),
            )
        } else {
            (None, None)
        };

        Self {
            id: vuln.id.clone(),
            source: vuln.source.to_string(),
            severity: vuln
                .severity
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| "Unknown".to_string()),
            cvss_score: vuln.max_cvss_score(),
            component_id: component.canonical_id.to_string(),
            component_canonical_id: Some(component.canonical_id.clone()),
            component_ref: Some(ComponentRef::from_component(component)),
            component_name: component.name.clone(),
            version: component.version.clone(),
            cwes: vuln.cwes.clone(),
            description: vuln.description.clone(),
            remediation: vuln.remediation.as_ref().map(|r| {
                format!(
                    "{}: {}",
                    r.remediation_type,
                    r.description.as_deref().unwrap_or("")
                )
            }),
            is_kev: vuln.is_kev,
            component_depth: None,
            published_date,
            kev_due_date,
            days_since_published,
            days_until_due,
            vex_state: component.vex_status.as_ref().map(|v| v.status.clone()),
        }
    }

    /// Create from a vulnerability reference and component with known depth
    pub fn from_ref_with_depth(
        vuln: &VulnerabilityRef,
        component: &Component,
        depth: Option<u32>,
    ) -> Self {
        let mut detail = Self::from_ref(vuln, component);
        detail.component_depth = depth;
        detail
    }

    /// Calculate SLA status based on KEV due date or severity-based policy
    ///
    /// Priority order:
    /// 1. KEV due date (CISA mandated deadline)
    /// 2. Severity-based SLA (Critical=1d, High=7d, Medium=30d, Low=90d)
    pub fn sla_status(&self) -> SlaStatus {
        // KEV due date takes priority
        if let Some(days) = self.days_until_due {
            if days < 0 {
                return SlaStatus::Overdue(-days);
            } else if days <= 3 {
                return SlaStatus::DueSoon(days);
            } else {
                return SlaStatus::OnTrack(days);
            }
        }

        // Fall back to severity-based SLA
        if let Some(age_days) = self.days_since_published {
            let sla_days = match self.severity.to_lowercase().as_str() {
                "critical" => 1,
                "high" => 7,
                "medium" => 30,
                "low" => 90,
                _ => return SlaStatus::NoDueDate,
            };
            let remaining = sla_days - age_days;
            if remaining < 0 {
                return SlaStatus::Overdue(-remaining);
            } else if remaining <= 3 {
                return SlaStatus::DueSoon(remaining);
            } else {
                return SlaStatus::OnTrack(remaining);
            }
        }

        SlaStatus::NoDueDate
    }

    /// Get the typed component canonical ID
    pub fn get_component_id(&self) -> CanonicalId {
        self.component_canonical_id
            .clone()
            .unwrap_or_else(|| CanonicalId::from_name_version(&self.component_name, self.version.as_deref()))
    }

    /// Get a ComponentRef for the affected component
    pub fn get_component_ref(&self) -> ComponentRef {
        self.component_ref.clone().unwrap_or_else(|| {
            ComponentRef::with_version(
                self.get_component_id(),
                &self.component_name,
                self.version.clone(),
            )
        })
    }
}

// ============================================================================
// Graph-Aware Diffing Types
// ============================================================================

/// Represents a structural change in the dependency graph
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyGraphChange {
    /// The component involved in the change
    pub component_id: CanonicalId,
    /// Human-readable component name
    pub component_name: String,
    /// The type of structural change
    pub change: DependencyChangeType,
    /// Assessed impact of this change
    pub impact: GraphChangeImpact,
}

/// Types of dependency graph structural changes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DependencyChangeType {
    /// A new dependency link was added
    DependencyAdded {
        dependency_id: CanonicalId,
        dependency_name: String,
    },

    /// A dependency link was removed
    DependencyRemoved {
        dependency_id: CanonicalId,
        dependency_name: String,
    },

    /// A dependency was reparented (had exactly one parent in both, but different)
    Reparented {
        dependency_id: CanonicalId,
        dependency_name: String,
        old_parent_id: CanonicalId,
        old_parent_name: String,
        new_parent_id: CanonicalId,
        new_parent_name: String,
    },

    /// Dependency depth changed (e.g., transitive became direct)
    DepthChanged {
        old_depth: u32, // 1 = direct, 2+ = transitive
        new_depth: u32,
    },
}

impl DependencyChangeType {
    /// Get a short description of the change type
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DependencyAdded { .. } => "added",
            Self::DependencyRemoved { .. } => "removed",
            Self::Reparented { .. } => "reparented",
            Self::DepthChanged { .. } => "depth_changed",
        }
    }
}

/// Impact level of a graph change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphChangeImpact {
    /// Internal reorganization, no functional change
    Low,
    /// Depth or type change, may affect build/runtime
    Medium,
    /// Security-relevant component relationship changed
    High,
    /// Vulnerable component promoted to direct dependency
    Critical,
}

impl GraphChangeImpact {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parse from a string label. Returns Low for unrecognized values.
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }
}

impl std::fmt::Display for GraphChangeImpact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Summary statistics for graph changes
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphChangeSummary {
    pub total_changes: usize,
    pub dependencies_added: usize,
    pub dependencies_removed: usize,
    pub reparented: usize,
    pub depth_changed: usize,
    pub by_impact: GraphChangesByImpact,
}

impl GraphChangeSummary {
    /// Build summary from a list of changes
    pub fn from_changes(changes: &[DependencyGraphChange]) -> Self {
        let mut summary = Self {
            total_changes: changes.len(),
            ..Default::default()
        };

        for change in changes {
            match &change.change {
                DependencyChangeType::DependencyAdded { .. } => summary.dependencies_added += 1,
                DependencyChangeType::DependencyRemoved { .. } => summary.dependencies_removed += 1,
                DependencyChangeType::Reparented { .. } => summary.reparented += 1,
                DependencyChangeType::DepthChanged { .. } => summary.depth_changed += 1,
            }

            match change.impact {
                GraphChangeImpact::Low => summary.by_impact.low += 1,
                GraphChangeImpact::Medium => summary.by_impact.medium += 1,
                GraphChangeImpact::High => summary.by_impact.high += 1,
                GraphChangeImpact::Critical => summary.by_impact.critical += 1,
            }
        }

        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphChangesByImpact {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}
