//! Security-focused filter criteria for components.
//!
//! This module provides filter criteria and quick filters for security-focused
//! component analysis in the TUI.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    /// Get short label (single letter)
    pub fn short_label(&self) -> &'static str {
        match self {
            Self::Low => "L",
            Self::Medium => "M",
            Self::High => "H",
            Self::Critical => "C",
        }
    }

    /// Get numeric value (higher = more risk)
    pub fn value(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// License category for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LicenseCategory {
    Permissive,
    Copyleft,
    WeakCopyleft,
    Proprietary,
    Unknown,
}

impl LicenseCategory {
    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            Self::Permissive => "Permissive",
            Self::Copyleft => "Copyleft",
            Self::WeakCopyleft => "Weak Copyleft",
            Self::Proprietary => "Proprietary",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for LicenseCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Security-focused filter criteria for components
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityFilterCriteria {
    /// Minimum risk level to show
    pub min_risk: Option<RiskLevel>,
    /// Must have vulnerabilities
    pub has_vulns: Option<bool>,
    /// Minimum vulnerability count
    pub min_vuln_count: Option<usize>,
    /// Specific vulnerability severity
    pub vuln_severity: Option<String>,
    /// License category filter
    pub license_type: Option<LicenseCategory>,
    /// Maximum age in months (for staleness)
    pub max_age_months: Option<u32>,
    /// Must be flagged/marked for review
    pub is_flagged: Option<bool>,
    /// Must have KEV vulnerabilities
    pub has_kev: Option<bool>,
    /// Text search query (name/purl)
    pub text_query: Option<String>,
    /// Direct dependencies only
    pub direct_deps_only: Option<bool>,
}

impl SecurityFilterCriteria {
    /// Create new empty criteria
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if no filters are active
    pub fn is_empty(&self) -> bool {
        self.min_risk.is_none()
            && self.has_vulns.is_none()
            && self.min_vuln_count.is_none()
            && self.vuln_severity.is_none()
            && self.license_type.is_none()
            && self.max_age_months.is_none()
            && self.is_flagged.is_none()
            && self.has_kev.is_none()
            && self.text_query.is_none()
            && self.direct_deps_only.is_none()
    }

    /// Count active filters
    pub fn active_filter_count(&self) -> usize {
        let mut count = 0;
        if self.min_risk.is_some() {
            count += 1;
        }
        if self.has_vulns.is_some() {
            count += 1;
        }
        if self.min_vuln_count.is_some() {
            count += 1;
        }
        if self.vuln_severity.is_some() {
            count += 1;
        }
        if self.license_type.is_some() {
            count += 1;
        }
        if self.max_age_months.is_some() {
            count += 1;
        }
        if self.is_flagged.is_some() {
            count += 1;
        }
        if self.has_kev.is_some() {
            count += 1;
        }
        if self.text_query.is_some() {
            count += 1;
        }
        if self.direct_deps_only.is_some() {
            count += 1;
        }
        count
    }

    /// Get summary of active filters
    pub fn summary(&self) -> String {
        let count = self.active_filter_count();
        if count == 0 {
            "No filters active".to_string()
        } else {
            let mut parts = Vec::new();
            if let Some(risk) = &self.min_risk {
                parts.push(format!("{}+ risk", risk.short_label()));
            }
            if self.has_vulns == Some(true) {
                parts.push("Has vulns".to_string());
            }
            if let Some(sev) = &self.vuln_severity {
                parts.push(format!("{sev} vulns"));
            }
            if self.has_kev == Some(true) {
                parts.push("KEV".to_string());
            }
            if let Some(lic) = &self.license_type {
                parts.push(format!("{lic}"));
            }
            if self.max_age_months.is_some() {
                parts.push("Stale".to_string());
            }
            if self.is_flagged == Some(true) {
                parts.push("Flagged".to_string());
            }
            format!("{} filters: {}", count, parts.join(", "))
        }
    }

    /// Clear all filters
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Set minimum risk level
    #[must_use]
    pub fn with_min_risk(mut self, level: RiskLevel) -> Self {
        self.min_risk = Some(level);
        self
    }

    /// Filter to components with vulnerabilities
    #[must_use]
    pub fn with_vulns(mut self) -> Self {
        self.has_vulns = Some(true);
        self
    }

    /// Filter to KEV components
    #[must_use]
    pub fn with_kev(mut self) -> Self {
        self.has_kev = Some(true);
        self
    }

    /// Filter by license category
    #[must_use]
    pub fn with_license(mut self, category: LicenseCategory) -> Self {
        self.license_type = Some(category);
        self
    }
}

/// Quick filter presets for the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuickFilter {
    /// High risk components
    HighRisk,
    /// Components with any vulnerabilities
    HasVulns,
    /// Components with critical vulnerabilities
    CriticalVulns,
    /// Components with KEV vulnerabilities
    HasKev,
    /// Components with copyleft licenses
    Copyleft,
    /// Flagged components
    Flagged,
    /// Stale components (>6 months)
    Stale,
    /// Direct dependencies only
    DirectDeps,
}

impl QuickFilter {
    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            Self::HighRisk => "High Risk",
            Self::HasVulns => "Has Vulns",
            Self::CriticalVulns => "Critical",
            Self::HasKev => "KEV",
            Self::Copyleft => "Copyleft",
            Self::Flagged => "Flagged",
            Self::Stale => "Stale",
            Self::DirectDeps => "Direct",
        }
    }

    /// Get keyboard shortcut (1-8)
    pub fn shortcut(&self) -> &'static str {
        match self {
            Self::HighRisk => "1",
            Self::HasVulns => "2",
            Self::CriticalVulns => "3",
            Self::HasKev => "4",
            Self::Copyleft => "5",
            Self::Flagged => "6",
            Self::Stale => "7",
            Self::DirectDeps => "8",
        }
    }

    /// Apply this quick filter to criteria
    pub fn apply(&self, criteria: &mut SecurityFilterCriteria) {
        match self {
            Self::HighRisk => {
                criteria.min_risk = Some(RiskLevel::High);
            }
            Self::HasVulns => {
                criteria.has_vulns = Some(true);
            }
            Self::CriticalVulns => {
                criteria.vuln_severity = Some("Critical".to_string());
            }
            Self::HasKev => {
                criteria.has_kev = Some(true);
            }
            Self::Copyleft => {
                criteria.license_type = Some(LicenseCategory::Copyleft);
            }
            Self::Flagged => {
                criteria.is_flagged = Some(true);
            }
            Self::Stale => {
                criteria.max_age_months = Some(6);
            }
            Self::DirectDeps => {
                criteria.direct_deps_only = Some(true);
            }
        }
    }

    /// Remove this quick filter from criteria
    pub fn unapply(&self, criteria: &mut SecurityFilterCriteria) {
        match self {
            Self::HighRisk => {
                criteria.min_risk = None;
            }
            Self::HasVulns => {
                criteria.has_vulns = None;
            }
            Self::CriticalVulns => {
                criteria.vuln_severity = None;
            }
            Self::HasKev => {
                criteria.has_kev = None;
            }
            Self::Copyleft => {
                criteria.license_type = None;
            }
            Self::Flagged => {
                criteria.is_flagged = None;
            }
            Self::Stale => {
                criteria.max_age_months = None;
            }
            Self::DirectDeps => {
                criteria.direct_deps_only = None;
            }
        }
    }

    /// Check if this quick filter is currently active
    pub fn is_active(&self, criteria: &SecurityFilterCriteria) -> bool {
        match self {
            Self::HighRisk => criteria.min_risk.is_some(),
            Self::HasVulns => criteria.has_vulns == Some(true),
            Self::CriticalVulns => criteria.vuln_severity.is_some(),
            Self::HasKev => criteria.has_kev == Some(true),
            Self::Copyleft => {
                criteria.license_type == Some(LicenseCategory::Copyleft)
            }
            Self::Flagged => criteria.is_flagged == Some(true),
            Self::Stale => criteria.max_age_months.is_some(),
            Self::DirectDeps => criteria.direct_deps_only == Some(true),
        }
    }

    /// Get all available quick filters
    pub fn all() -> &'static [Self] {
        &[
            Self::HighRisk,
            Self::HasVulns,
            Self::CriticalVulns,
            Self::HasKev,
            Self::Copyleft,
            Self::Flagged,
            Self::Stale,
            Self::DirectDeps,
        ]
    }
}

impl std::fmt::Display for QuickFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Security filter state for TUI
#[derive(Debug, Clone, Default)]
pub struct SecurityFilterState {
    /// Current filter criteria
    pub criteria: SecurityFilterCriteria,
    /// Active quick filters
    pub active_quick_filters: HashSet<QuickFilter>,
    /// Whether filter bar is visible
    pub show_filter_bar: bool,
    /// Selected quick filter index (for keyboard navigation)
    pub focused_quick_filter: usize,
}

impl SecurityFilterState {
    /// Create new filter state
    pub fn new() -> Self {
        Self {
            criteria: SecurityFilterCriteria::new(),
            active_quick_filters: HashSet::new(),
            show_filter_bar: true,
            focused_quick_filter: 0,
        }
    }

    /// Toggle a quick filter
    pub fn toggle_quick_filter(&mut self, filter: QuickFilter) {
        if self.active_quick_filters.contains(&filter) {
            self.active_quick_filters.remove(&filter);
            filter.unapply(&mut self.criteria);
        } else {
            self.active_quick_filters.insert(filter);
            filter.apply(&mut self.criteria);
        }
    }

    /// Toggle quick filter by index (1-8)
    pub fn toggle_by_index(&mut self, index: usize) {
        let filters = QuickFilter::all();
        if index < filters.len() {
            self.toggle_quick_filter(filters[index]);
        }
    }

    /// Clear all filters
    pub fn clear_all(&mut self) {
        self.criteria.clear();
        self.active_quick_filters.clear();
    }

    /// Check if any filters are active
    pub fn has_active_filters(&self) -> bool {
        !self.criteria.is_empty()
    }

    /// Get summary text
    pub fn summary(&self) -> String {
        self.criteria.summary()
    }

    /// Navigate to next quick filter
    pub fn focus_next(&mut self) {
        let total = QuickFilter::all().len();
        self.focused_quick_filter = (self.focused_quick_filter + 1) % total;
    }

    /// Navigate to previous quick filter
    pub fn focus_prev(&mut self) {
        let total = QuickFilter::all().len();
        if self.focused_quick_filter == 0 {
            self.focused_quick_filter = total - 1;
        } else {
            self.focused_quick_filter -= 1;
        }
    }

    /// Toggle the currently focused quick filter
    pub fn toggle_focused(&mut self) {
        let filters = QuickFilter::all();
        if self.focused_quick_filter < filters.len() {
            self.toggle_quick_filter(filters[self.focused_quick_filter]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criteria_empty() {
        let criteria = SecurityFilterCriteria::new();
        assert!(criteria.is_empty());
        assert_eq!(criteria.active_filter_count(), 0);
    }

    #[test]
    fn test_criteria_with_filters() {
        let criteria = SecurityFilterCriteria::new()
            .with_min_risk(RiskLevel::High)
            .with_vulns()
            .with_kev();

        assert!(!criteria.is_empty());
        assert_eq!(criteria.active_filter_count(), 3);
    }

    #[test]
    fn test_quick_filter_toggle() {
        let mut state = SecurityFilterState::new();

        assert!(!state.has_active_filters());

        state.toggle_quick_filter(QuickFilter::HighRisk);
        assert!(state.has_active_filters());
        assert!(state.active_quick_filters.contains(&QuickFilter::HighRisk));

        state.toggle_quick_filter(QuickFilter::HighRisk);
        assert!(!state.has_active_filters());
    }

    #[test]
    fn test_quick_filter_by_index() {
        let mut state = SecurityFilterState::new();

        state.toggle_by_index(0); // HighRisk
        assert!(state.active_quick_filters.contains(&QuickFilter::HighRisk));

        state.toggle_by_index(1); // HasVulns
        assert!(state.active_quick_filters.contains(&QuickFilter::HasVulns));

        // Out of bounds should do nothing
        state.toggle_by_index(100);
        assert_eq!(state.active_quick_filters.len(), 2);
    }

    #[test]
    fn test_clear_all() {
        let mut state = SecurityFilterState::new();

        state.toggle_quick_filter(QuickFilter::HighRisk);
        state.toggle_quick_filter(QuickFilter::HasVulns);
        assert!(state.has_active_filters());

        state.clear_all();
        assert!(!state.has_active_filters());
        assert!(state.active_quick_filters.is_empty());
    }

    #[test]
    fn test_focus_navigation() {
        let mut state = SecurityFilterState::new();
        assert_eq!(state.focused_quick_filter, 0);

        state.focus_next();
        assert_eq!(state.focused_quick_filter, 1);

        state.focus_prev();
        assert_eq!(state.focused_quick_filter, 0);

        // Wrap around
        state.focus_prev();
        assert_eq!(state.focused_quick_filter, QuickFilter::all().len() - 1);
    }
}
