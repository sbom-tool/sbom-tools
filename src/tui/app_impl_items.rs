//! Item list building methods for App.

use super::app::App;
use super::app_states::{
    sort_component_changes, sort_components, ChangeType, ComponentFilter, DiffVulnItem,
    DiffVulnStatus, VulnFilter,
};
use crate::diff::SlaStatus;

/// Check whether a vulnerability matches the active filter.
fn matches_vuln_filter(vuln: &crate::diff::VulnerabilityDetail, filter: &VulnFilter) -> bool {
    match filter {
        VulnFilter::Critical => vuln.severity == "Critical",
        VulnFilter::High => vuln.severity == "High" || vuln.severity == "Critical",
        VulnFilter::Kev => vuln.is_kev,
        VulnFilter::Direct => vuln.component_depth == Some(1),
        VulnFilter::Transitive => vuln.component_depth.is_some_and(|d| d > 1),
        VulnFilter::VexActionable => vuln.is_vex_actionable(),
        _ => true,
    }
}

/// Determine which vulnerability categories (introduced, resolved, persistent)
/// should be included for a given filter.
fn vuln_category_includes(filter: &VulnFilter) -> (bool, bool, bool) {
    let introduced = matches!(
        filter,
        VulnFilter::All
            | VulnFilter::Introduced
            | VulnFilter::Critical
            | VulnFilter::High
            | VulnFilter::Kev
            | VulnFilter::Direct
            | VulnFilter::Transitive
            | VulnFilter::VexActionable
    );
    let resolved = matches!(
        filter,
        VulnFilter::All
            | VulnFilter::Resolved
            | VulnFilter::Critical
            | VulnFilter::High
            | VulnFilter::Kev
            | VulnFilter::Direct
            | VulnFilter::Transitive
            | VulnFilter::VexActionable
    );
    let persistent = matches!(
        filter,
        VulnFilter::All
            | VulnFilter::Critical
            | VulnFilter::High
            | VulnFilter::Kev
            | VulnFilter::Direct
            | VulnFilter::Transitive
            | VulnFilter::VexActionable
    );
    (introduced, resolved, persistent)
}

impl App {
    /// Find component index in diff mode using the same ordering as the components view
    pub(super) fn find_component_index_all(
        &self,
        name: &str,
        change_type: Option<ChangeType>,
        version: Option<&str>,
    ) -> Option<usize> {
        let name_lower = name.to_lowercase();
        let version_lower = version.map(str::to_lowercase);

        self.diff_component_items(ComponentFilter::All)
            .iter()
            .position(|comp| {
                let matches_type = change_type.is_none_or(|t| match t {
                    ChangeType::Added => comp.change_type == crate::diff::ChangeType::Added,
                    ChangeType::Removed => comp.change_type == crate::diff::ChangeType::Removed,
                    ChangeType::Modified => comp.change_type == crate::diff::ChangeType::Modified,
                });
                let matches_name = comp.name.to_lowercase() == name_lower;
                let matches_version = version_lower.as_ref().is_none_or(|v| {
                    comp.new_version.as_deref().map(str::to_lowercase) == Some(v.clone())
                        || comp.old_version.as_deref().map(str::to_lowercase)
                            == Some(v.clone())
                });

                matches_type && matches_name && matches_version
            })
    }

    /// Build diff-mode components list in the same order as the table.
    pub fn diff_component_items(
        &self,
        filter: ComponentFilter,
    ) -> Vec<&crate::diff::ComponentChange> {
        let Some(diff) = self.data.diff_result.as_ref() else {
            return Vec::new();
        };

        let mut items = Vec::new();
        if filter == ComponentFilter::All || filter == ComponentFilter::Added {
            items.extend(diff.components.added.iter());
        }
        if filter == ComponentFilter::All || filter == ComponentFilter::Removed {
            items.extend(diff.components.removed.iter());
        }
        if filter == ComponentFilter::All || filter == ComponentFilter::Modified {
            items.extend(diff.components.modified.iter());
        }

        sort_component_changes(&mut items, self.tabs.components.sort_by);
        items
    }

    /// Count diff-mode components matching the filter (without building full list).
    /// More efficient than diff_component_items().len() for just getting a count.
    pub fn diff_component_count(&self, filter: ComponentFilter) -> usize {
        let Some(diff) = self.data.diff_result.as_ref() else {
            return 0;
        };

        match filter {
            ComponentFilter::All => {
                diff.components.added.len()
                    + diff.components.removed.len()
                    + diff.components.modified.len()
            }
            ComponentFilter::Added => diff.components.added.len(),
            ComponentFilter::Removed => diff.components.removed.len(),
            ComponentFilter::Modified => diff.components.modified.len(),
        }
    }

    /// Count view-mode components (without building full list).
    pub fn view_component_count(&self) -> usize {
        self.data.sbom.as_ref().map_or(0, crate::model::NormalizedSbom::component_count)
    }

    /// Build view-mode components list in the same order as the table.
    pub fn view_component_items(&self) -> Vec<&crate::model::Component> {
        let Some(sbom) = self.data.sbom.as_ref() else {
            return Vec::new();
        };
        let mut items: Vec<_> = sbom.components.values().collect();
        sort_components(&mut items, self.tabs.components.sort_by);
        items
    }

    /// Build diff-mode vulnerabilities list in the same order as the table.
    pub fn diff_vulnerability_items(&self) -> Vec<DiffVulnItem<'_>> {
        let Some(diff) = self.data.diff_result.as_ref() else {
            return Vec::new();
        };
        let filter = &self.tabs.vulnerabilities.filter;
        let sort = &self.tabs.vulnerabilities.sort_by;
        let mut all_vulns: Vec<DiffVulnItem<'_>> = Vec::new();

        let (include_introduced, include_resolved, include_persistent) =
            vuln_category_includes(filter);

        if include_introduced {
            for vuln in &diff.vulnerabilities.introduced {
                if !matches_vuln_filter(vuln, filter) {
                    continue;
                }
                all_vulns.push(DiffVulnItem {
                    status: DiffVulnStatus::Introduced,
                    vuln,
                });
            }
        }

        if include_resolved {
            for vuln in &diff.vulnerabilities.resolved {
                if !matches_vuln_filter(vuln, filter) {
                    continue;
                }
                all_vulns.push(DiffVulnItem {
                    status: DiffVulnStatus::Resolved,
                    vuln,
                });
            }
        }

        if include_persistent {
            for vuln in &diff.vulnerabilities.persistent {
                if !matches_vuln_filter(vuln, filter) {
                    continue;
                }
                all_vulns.push(DiffVulnItem {
                    status: DiffVulnStatus::Persistent,
                    vuln,
                });
            }
        }

        // Get blast radius data for FixUrgency sorting
        let reverse_graph = &self.tabs.dependencies.cached_reverse_graph;

        match sort {
            super::app_states::VulnSort::Severity => {
                all_vulns.sort_by(|a, b| {
                    let sev_order = |s: &str| match s {
                        "Critical" => 0,
                        "High" => 1,
                        "Medium" => 2,
                        "Low" => 3,
                        _ => 4,
                    };
                    sev_order(&a.vuln.severity).cmp(&sev_order(&b.vuln.severity))
                });
            }
            super::app_states::VulnSort::Id => {
                all_vulns.sort_by(|a, b| a.vuln.id.cmp(&b.vuln.id));
            }
            super::app_states::VulnSort::Component => {
                all_vulns.sort_by(|a, b| a.vuln.component_name.cmp(&b.vuln.component_name));
            }
            super::app_states::VulnSort::FixUrgency => {
                // Sort by fix urgency (severity × blast radius)
                all_vulns.sort_by(|a, b| {
                    let urgency_a = calculate_vuln_urgency(a.vuln, reverse_graph);
                    let urgency_b = calculate_vuln_urgency(b.vuln, reverse_graph);
                    urgency_b.cmp(&urgency_a) // Higher urgency first
                });
            }
            super::app_states::VulnSort::CvssScore => {
                // Sort by CVSS score (highest first)
                all_vulns.sort_by(|a, b| {
                    let score_a = a.vuln.cvss_score.unwrap_or(0.0);
                    let score_b = b.vuln.cvss_score.unwrap_or(0.0);
                    score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            super::app_states::VulnSort::SlaUrgency => {
                // Sort by SLA urgency (most overdue first)
                all_vulns.sort_by(|a, b| {
                    let sla_a = sla_sort_key(a.vuln);
                    let sla_b = sla_sort_key(b.vuln);
                    sla_a.cmp(&sla_b)
                });
            }
        }

        all_vulns
    }

    /// Ensure the vulnerability cache is populated for the current filter+sort.
    ///
    /// Call this before `diff_vulnerability_items_from_cache()` to guarantee
    /// the cache is warm.
    pub fn ensure_vulnerability_cache(&mut self) {
        let current_key = (self.tabs.vulnerabilities.filter, self.tabs.vulnerabilities.sort_by);

        if self.tabs.vulnerabilities.cached_key == Some(current_key)
            && !self.tabs.vulnerabilities.cached_indices.is_empty()
        {
            return; // Cache is warm
        }

        // Cache miss: compute full list, extract stable indices, then drop items
        let items = self.diff_vulnerability_items();
        let indices: Vec<(DiffVulnStatus, usize)> = if let Some(diff) =
            self.data.diff_result.as_ref()
        {
            items
                .iter()
                .filter_map(|item| {
                    let list = match item.status {
                        DiffVulnStatus::Introduced => &diff.vulnerabilities.introduced,
                        DiffVulnStatus::Resolved => &diff.vulnerabilities.resolved,
                        DiffVulnStatus::Persistent => &diff.vulnerabilities.persistent,
                    };
                    // Find the index by pointer identity
                    let ptr = item.vuln as *const crate::diff::VulnerabilityDetail;
                    list.iter()
                        .position(|v| std::ptr::eq(v, ptr))
                        .map(|idx| (item.status, idx))
                })
                .collect()
        } else {
            Vec::new()
        };
        drop(items);

        self.tabs.vulnerabilities.cached_key = Some(current_key);
        self.tabs.vulnerabilities.cached_indices = indices;
    }

    /// Reconstruct vulnerability items from the cache (cheap pointer lookups).
    ///
    /// Panics if the cache has not been populated. Call `ensure_vulnerability_cache()`
    /// first.
    pub fn diff_vulnerability_items_from_cache(&self) -> Vec<DiffVulnItem<'_>> {
        let Some(diff) = self.data.diff_result.as_ref() else {
            return Vec::new();
        };
        self.tabs
            .vulnerabilities
            .cached_indices
            .iter()
            .filter_map(|(status, idx)| {
                let vuln = match status {
                    DiffVulnStatus::Introduced => diff.vulnerabilities.introduced.get(*idx),
                    DiffVulnStatus::Resolved => diff.vulnerabilities.resolved.get(*idx),
                    DiffVulnStatus::Persistent => diff.vulnerabilities.persistent.get(*idx),
                }?;
                Some(DiffVulnItem {
                    status: *status,
                    vuln,
                })
            })
            .collect()
    }

    /// Count diff-mode vulnerabilities matching the current filter (without building full list).
    /// More efficient than diff_vulnerability_items().len() for just getting a count.
    pub fn diff_vulnerability_count(&self) -> usize {
        let Some(diff) = self.data.diff_result.as_ref() else {
            return 0;
        };
        let filter = &self.tabs.vulnerabilities.filter;

        let (include_introduced, include_resolved, include_persistent) =
            vuln_category_includes(filter);

        let mut count = 0;
        if include_introduced {
            count += diff
                .vulnerabilities
                .introduced
                .iter()
                .filter(|v| matches_vuln_filter(v, filter))
                .count();
        }
        if include_resolved {
            count += diff
                .vulnerabilities
                .resolved
                .iter()
                .filter(|v| matches_vuln_filter(v, filter))
                .count();
        }
        if include_persistent {
            count += diff
                .vulnerabilities
                .persistent
                .iter()
                .filter(|v| matches_vuln_filter(v, filter))
                .count();
        }
        count
    }

    /// Find a vulnerability index based on the current filter/sort settings
    pub(super) fn find_vulnerability_index(&self, id: &str) -> Option<usize> {
        self.diff_vulnerability_items()
            .iter()
            .position(|item| item.vuln.id == id)
    }

    // ========================================================================
    // Index access methods for O(1) lookups
    // ========================================================================

    /// Get the sort key for a component in the new SBOM (diff mode).
    ///
    /// Returns pre-computed lowercase strings to avoid repeated allocations during sorting.
    pub fn get_new_sbom_sort_key(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Option<&crate::model::ComponentSortKey> {
        self.data.new_sbom_index.as_ref().and_then(|idx| idx.sort_key(id))
    }

    /// Get the sort key for a component in the old SBOM (diff mode).
    pub fn get_old_sbom_sort_key(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Option<&crate::model::ComponentSortKey> {
        self.data.old_sbom_index.as_ref().and_then(|idx| idx.sort_key(id))
    }

    /// Get the sort key for a component in the single SBOM (view mode).
    pub fn get_sbom_sort_key(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Option<&crate::model::ComponentSortKey> {
        self.data.sbom_index.as_ref().and_then(|idx| idx.sort_key(id))
    }

    /// Get dependencies of a component using the cached index (O(k) instead of O(edges)).
    pub fn get_dependencies_indexed(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Vec<&crate::model::DependencyEdge> {
        if let (Some(sbom), Some(idx)) = (&self.data.new_sbom, &self.data.new_sbom_index) {
            idx.dependencies_of(id, &sbom.edges)
        } else if let (Some(sbom), Some(idx)) = (&self.data.sbom, &self.data.sbom_index) {
            idx.dependencies_of(id, &sbom.edges)
        } else {
            Vec::new()
        }
    }

    /// Get dependents of a component using the cached index (O(k) instead of O(edges)).
    pub fn get_dependents_indexed(
        &self,
        id: &crate::model::CanonicalId,
    ) -> Vec<&crate::model::DependencyEdge> {
        if let (Some(sbom), Some(idx)) = (&self.data.new_sbom, &self.data.new_sbom_index) {
            idx.dependents_of(id, &sbom.edges)
        } else if let (Some(sbom), Some(idx)) = (&self.data.sbom, &self.data.sbom_index) {
            idx.dependents_of(id, &sbom.edges)
        } else {
            Vec::new()
        }
    }
}

/// Calculate fix urgency for a vulnerability based on severity and blast radius
fn calculate_vuln_urgency(
    vuln: &crate::diff::VulnerabilityDetail,
    reverse_graph: &std::collections::HashMap<String, Vec<String>>,
) -> u8 {
    use crate::tui::security::{calculate_fix_urgency, severity_to_rank};

    let severity_rank = severity_to_rank(&vuln.severity);
    let cvss_score = vuln.cvss_score.unwrap_or(0.0);

    // Calculate blast radius for affected component
    let mut blast_radius = 0usize;
    if let Some(direct_deps) = reverse_graph.get(&vuln.component_name) {
        blast_radius = direct_deps.len();
        // Add transitive count (simplified - just use direct for performance)
        for dep in direct_deps {
            if let Some(transitive) = reverse_graph.get(dep) {
                blast_radius += transitive.len();
            }
        }
    }

    calculate_fix_urgency(severity_rank, blast_radius, cvss_score)
}

/// Calculate SLA sort key for a vulnerability (lower = more urgent)
fn sla_sort_key(vuln: &crate::diff::VulnerabilityDetail) -> i64 {
    match vuln.sla_status() {
        SlaStatus::Overdue(days) => -(days + crate::tui::constants::SLA_OVERDUE_SORT_OFFSET), // Most urgent (very negative)
        SlaStatus::DueSoon(days) | SlaStatus::OnTrack(days) => days,
        SlaStatus::NoDueDate => i64::MAX,
    }
}
