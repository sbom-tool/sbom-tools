//! Vulnerability grouping by root cause component.
//!
//! This module provides functionality to group vulnerabilities by the component
//! that introduces them, reducing noise and showing the true scope of security issues.

use crate::diff::result::VulnerabilityDetail;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a vulnerability group
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnGroupStatus {
    /// Newly introduced vulnerabilities
    Introduced,
    /// Resolved vulnerabilities
    Resolved,
    /// Persistent vulnerabilities (present in both old and new)
    Persistent,
}

impl std::fmt::Display for VulnGroupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Introduced => write!(f, "Introduced"),
            Self::Resolved => write!(f, "Resolved"),
            Self::Persistent => write!(f, "Persistent"),
        }
    }
}

/// A group of vulnerabilities sharing the same root cause component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityGroup {
    /// Root cause component ID
    pub component_id: String,
    /// Component name
    pub component_name: String,
    /// Component version (if available)
    pub component_version: Option<String>,
    /// Vulnerabilities in this group
    pub vulnerabilities: Vec<VulnerabilityDetail>,
    /// Maximum severity in the group
    pub max_severity: String,
    /// Maximum CVSS score in the group
    pub max_cvss: Option<f32>,
    /// Count by severity level
    pub severity_counts: HashMap<String, usize>,
    /// Group status (Introduced, Resolved, Persistent)
    pub status: VulnGroupStatus,
    /// Whether any vulnerability is in KEV catalog
    pub has_kev: bool,
    /// Whether any vulnerability is ransomware-related
    pub has_ransomware_kev: bool,
}

impl VulnerabilityGroup {
    /// Create a new empty group for a component
    #[must_use] 
    pub fn new(
        component_id: String,
        component_name: String,
        status: VulnGroupStatus,
    ) -> Self {
        Self {
            component_id,
            component_name,
            component_version: None,
            vulnerabilities: Vec::new(),
            max_severity: "Unknown".to_string(),
            max_cvss: None,
            severity_counts: HashMap::new(),
            status,
            has_kev: false,
            has_ransomware_kev: false,
        }
    }

    /// Add a vulnerability to the group
    pub fn add_vulnerability(&mut self, vuln: VulnerabilityDetail) {
        // Update severity counts
        *self.severity_counts.entry(vuln.severity.clone()).or_insert(0) += 1;

        // Update max severity (priority: Critical > High > Medium > Low > Unknown)
        let vuln_priority = severity_priority(&vuln.severity);
        let current_priority = severity_priority(&self.max_severity);
        if vuln_priority < current_priority {
            self.max_severity.clone_from(&vuln.severity);
        }

        // Update max CVSS
        if let Some(score) = vuln.cvss_score {
            self.max_cvss = Some(self.max_cvss.map_or(score, |c| c.max(score)));
        }

        // Update version from first vulnerability with version
        if self.component_version.is_none() {
            self.component_version.clone_from(&vuln.version);
        }

        self.vulnerabilities.push(vuln);
    }

    /// Get total vulnerability count
    #[must_use] 
    pub fn vuln_count(&self) -> usize {
        self.vulnerabilities.len()
    }

    /// Check if group has any critical vulnerabilities
    #[must_use] 
    pub fn has_critical(&self) -> bool {
        self.severity_counts.get("Critical").copied().unwrap_or(0) > 0
    }

    /// Check if group has any high severity vulnerabilities
    #[must_use] 
    pub fn has_high(&self) -> bool {
        self.severity_counts.get("High").copied().unwrap_or(0) > 0
    }

    /// Get summary line for display
    #[must_use] 
    pub fn summary_line(&self) -> String {
        let version_str = self
            .component_version
            .as_ref()
            .map(|v| format!("@{v}"))
            .unwrap_or_default();

        let severity_badges: Vec<String> = ["Critical", "High", "Medium", "Low"]
            .iter()
            .filter_map(|sev| {
                self.severity_counts.get(*sev).and_then(|&count| {
                    if count > 0 {
                        Some(format!("{}:{}", &sev[..1], count))
                    } else {
                        None
                    }
                })
            })
            .collect();

        format!(
            "{}{}: {} CVEs [{}]",
            self.component_name,
            version_str,
            self.vuln_count(),
            severity_badges.join(" ")
        )
    }
}

/// Get priority value for severity (lower = more severe)
fn severity_priority(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        "none" => 5,
        _ => 6,
    }
}

/// Group vulnerabilities by component
#[must_use] 
pub fn group_vulnerabilities(
    vulns: &[VulnerabilityDetail],
    status: VulnGroupStatus,
) -> Vec<VulnerabilityGroup> {
    let mut groups: HashMap<String, VulnerabilityGroup> = HashMap::new();

    for vuln in vulns {
        let group = groups
            .entry(vuln.component_id.clone())
            .or_insert_with(|| {
                VulnerabilityGroup::new(
                    vuln.component_id.clone(),
                    vuln.component_name.clone(),
                    status,
                )
            });

        group.add_vulnerability(vuln.clone());
    }

    // Sort groups by severity (most severe first), then by count
    let mut result: Vec<_> = groups.into_values().collect();
    result.sort_by(|a, b| {
        let sev_cmp = severity_priority(&a.max_severity).cmp(&severity_priority(&b.max_severity));
        if sev_cmp == std::cmp::Ordering::Equal {
            b.vuln_count().cmp(&a.vuln_count())
        } else {
            sev_cmp
        }
    });

    result
}

/// Grouped view of vulnerability changes
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityGroupedView {
    /// Groups of introduced vulnerabilities
    pub introduced_groups: Vec<VulnerabilityGroup>,
    /// Groups of resolved vulnerabilities
    pub resolved_groups: Vec<VulnerabilityGroup>,
    /// Groups of persistent vulnerabilities
    pub persistent_groups: Vec<VulnerabilityGroup>,
}

impl VulnerabilityGroupedView {
    /// Create grouped view from vulnerability lists
    #[must_use] 
    pub fn from_changes(
        introduced: &[VulnerabilityDetail],
        resolved: &[VulnerabilityDetail],
        persistent: &[VulnerabilityDetail],
    ) -> Self {
        Self {
            introduced_groups: group_vulnerabilities(introduced, VulnGroupStatus::Introduced),
            resolved_groups: group_vulnerabilities(resolved, VulnGroupStatus::Resolved),
            persistent_groups: group_vulnerabilities(persistent, VulnGroupStatus::Persistent),
        }
    }

    /// Get total group count
    #[must_use] 
    pub fn total_groups(&self) -> usize {
        self.introduced_groups.len() + self.resolved_groups.len() + self.persistent_groups.len()
    }

    /// Get total vulnerability count across all groups
    pub fn total_vulns(&self) -> usize {
        self.introduced_groups.iter().map(VulnerabilityGroup::vuln_count).sum::<usize>()
            + self.resolved_groups.iter().map(VulnerabilityGroup::vuln_count).sum::<usize>()
            + self.persistent_groups.iter().map(VulnerabilityGroup::vuln_count).sum::<usize>()
    }

    /// Check if any group has KEV vulnerabilities
    #[must_use] 
    pub fn has_any_kev(&self) -> bool {
        self.introduced_groups.iter().any(|g| g.has_kev)
            || self.resolved_groups.iter().any(|g| g.has_kev)
            || self.persistent_groups.iter().any(|g| g.has_kev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vuln(id: &str, component_id: &str, severity: &str) -> VulnerabilityDetail {
        VulnerabilityDetail {
            id: id.to_string(),
            source: "OSV".to_string(),
            severity: severity.to_string(),
            cvss_score: None,
            component_id: component_id.to_string(),
            component_canonical_id: None,
            component_ref: None,
            component_name: format!("{}-pkg", component_id),
            version: Some("1.0.0".to_string()),
            description: None,
            remediation: None,
            is_kev: false,
            cwes: Vec::new(),
            component_depth: None,
            published_date: None,
            kev_due_date: None,
            days_since_published: None,
            days_until_due: None,
            vex_state: None,
            vex_justification: None,
            vex_impact_statement: None,
        }
    }

    #[test]
    fn test_group_vulnerabilities() {
        let vulns = vec![
            make_vuln("CVE-2024-0001", "lodash", "Critical"),
            make_vuln("CVE-2024-0002", "lodash", "High"),
            make_vuln("CVE-2024-0003", "lodash", "High"),
            make_vuln("CVE-2024-0004", "express", "Medium"),
        ];

        let groups = group_vulnerabilities(&vulns, VulnGroupStatus::Introduced);

        assert_eq!(groups.len(), 2);

        // lodash should be first (Critical severity)
        assert_eq!(groups[0].component_id, "lodash");
        assert_eq!(groups[0].vuln_count(), 3);
        assert_eq!(groups[0].max_severity, "Critical");
        assert_eq!(groups[0].severity_counts.get("Critical"), Some(&1));
        assert_eq!(groups[0].severity_counts.get("High"), Some(&2));

        // express should be second
        assert_eq!(groups[1].component_id, "express");
        assert_eq!(groups[1].vuln_count(), 1);
    }

    #[test]
    fn test_grouped_view() {
        let introduced = vec![
            make_vuln("CVE-2024-0001", "lodash", "High"),
            make_vuln("CVE-2024-0002", "lodash", "Medium"),
        ];
        let resolved = vec![make_vuln("CVE-2024-0003", "old-dep", "Critical")];
        let persistent = vec![];

        let view = VulnerabilityGroupedView::from_changes(&introduced, &resolved, &persistent);

        assert_eq!(view.total_groups(), 2);
        assert_eq!(view.total_vulns(), 3);
        assert_eq!(view.introduced_groups.len(), 1);
        assert_eq!(view.resolved_groups.len(), 1);
    }

    #[test]
    fn test_summary_line() {
        let mut group = VulnerabilityGroup::new(
            "lodash".to_string(),
            "lodash".to_string(),
            VulnGroupStatus::Introduced,
        );
        group.add_vulnerability(make_vuln("CVE-1", "lodash", "Critical"));
        group.add_vulnerability(make_vuln("CVE-2", "lodash", "High"));
        group.add_vulnerability(make_vuln("CVE-3", "lodash", "High"));

        let summary = group.summary_line();
        assert!(summary.contains("lodash"));
        assert!(summary.contains("3 CVEs"));
        assert!(summary.contains("C:1"));
        assert!(summary.contains("H:2"));
    }
}
