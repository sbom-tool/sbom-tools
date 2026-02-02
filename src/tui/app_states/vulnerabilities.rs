//! Vulnerabilities state types.

use crate::tui::state::ListNavigation;

pub struct VulnerabilitiesState {
    pub selected: usize,
    pub total: usize,
    pub filter: VulnFilter,
    pub sort_by: VulnSort,
    /// Whether to group vulnerabilities by component
    pub group_by_component: bool,
    /// Set of expanded group component IDs
    pub expanded_groups: std::collections::HashSet<String>,
    /// Cached filter+sort key for invalidation
    pub cached_key: Option<(VulnFilter, VulnSort)>,
    /// Cached indices: (status, index_into_status_vec)
    pub cached_indices: Vec<(DiffVulnStatus, usize)>,
}

impl VulnerabilitiesState {
    pub fn new(total: usize) -> Self {
        Self {
            selected: 0,
            total,
            filter: VulnFilter::All,
            sort_by: VulnSort::Severity,
            group_by_component: false,
            expanded_groups: std::collections::HashSet::new(),
            cached_key: None,
            cached_indices: Vec::new(),
        }
    }

    /// Invalidate the cached vulnerability indices.
    pub fn invalidate_cache(&mut self) {
        self.cached_key = None;
        self.cached_indices.clear();
    }

    /// Toggle grouped display mode
    pub fn toggle_grouped_mode(&mut self) {
        self.group_by_component = !self.group_by_component;
        self.selected = 0;
    }

    /// Toggle expansion of a group
    pub fn toggle_group(&mut self, component_id: &str) {
        if self.expanded_groups.contains(component_id) {
            self.expanded_groups.remove(component_id);
        } else {
            self.expanded_groups.insert(component_id.to_string());
        }
    }

    /// Expand all groups
    pub fn expand_all_groups(&mut self, group_ids: &[String]) {
        for id in group_ids {
            self.expanded_groups.insert(id.clone());
        }
    }

    /// Collapse all groups
    pub fn collapse_all_groups(&mut self) {
        self.expanded_groups.clear();
    }

    /// Check if a group is expanded
    pub fn is_group_expanded(&self, component_id: &str) -> bool {
        self.expanded_groups.contains(component_id)
    }

    pub fn select_next(&mut self) {
        if self.total > 0 && self.selected < self.total - 1 {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn clamp_selection(&mut self) {
        if self.total == 0 {
            self.selected = 0;
        } else if self.selected >= self.total {
            self.selected = self.total.saturating_sub(1);
        }
    }

    pub fn toggle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
        self.invalidate_cache();
    }

    pub fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
        self.selected = 0;
        self.invalidate_cache();
    }
}

impl ListNavigation for VulnerabilitiesState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnFilter {
    All,
    Introduced,
    Resolved,
    Critical,
    High,
    /// Filter to KEV (Known Exploited Vulnerabilities) only
    Kev,
    /// Filter to direct dependencies only (depth == 1)
    Direct,
    /// Filter to transitive dependencies only (depth > 1)
    Transitive,
    /// Filter to VEX-actionable vulnerabilities (Affected, UnderInvestigation, or no VEX status)
    VexActionable,
}

impl VulnFilter {
    pub fn label(&self) -> &'static str {
        match self {
            VulnFilter::All => "All",
            VulnFilter::Introduced => "Introduced",
            VulnFilter::Resolved => "Resolved",
            VulnFilter::Critical => "Critical",
            VulnFilter::High => "High",
            VulnFilter::Kev => "KEV",
            VulnFilter::Direct => "Direct",
            VulnFilter::Transitive => "Transitive",
            VulnFilter::VexActionable => "VEX Actionable",
        }
    }

    /// Cycle to next filter option
    pub fn next(self) -> Self {
        match self {
            VulnFilter::All => VulnFilter::Introduced,
            VulnFilter::Introduced => VulnFilter::Resolved,
            VulnFilter::Resolved => VulnFilter::Critical,
            VulnFilter::Critical => VulnFilter::High,
            VulnFilter::High => VulnFilter::Kev,
            VulnFilter::Kev => VulnFilter::Direct,
            VulnFilter::Direct => VulnFilter::Transitive,
            VulnFilter::Transitive => VulnFilter::VexActionable,
            VulnFilter::VexActionable => VulnFilter::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VulnSort {
    #[default]
    Severity,
    Id,
    Component,
    /// Sort by fix urgency (severity × blast radius)
    FixUrgency,
    /// Sort by CVSS score (highest first)
    CvssScore,
    /// Sort by SLA urgency (most overdue first)
    SlaUrgency,
}

impl VulnSort {
    pub fn next(&self) -> Self {
        match self {
            Self::Severity => Self::FixUrgency,
            Self::FixUrgency => Self::CvssScore,
            Self::CvssScore => Self::SlaUrgency,
            Self::SlaUrgency => Self::Component,
            Self::Component => Self::Id,
            Self::Id => Self::Severity,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Severity => "Severity",
            Self::FixUrgency => "Fix Urgency",
            Self::CvssScore => "CVSS Score",
            Self::SlaUrgency => "SLA Urgency",
            Self::Component => "Component",
            Self::Id => "ID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffVulnStatus {
    Introduced,
    Resolved,
    Persistent,
}

impl DiffVulnStatus {
    pub fn label(&self) -> &'static str {
        match self {
            DiffVulnStatus::Introduced => "Introduced",
            DiffVulnStatus::Resolved => "Resolved",
            DiffVulnStatus::Persistent => "Persistent",
        }
    }
}

pub struct DiffVulnItem<'a> {
    pub status: DiffVulnStatus,
    pub vuln: &'a crate::diff::VulnerabilityDetail,
}

