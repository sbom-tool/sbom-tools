//! Navigation state types.

use crate::tui::app::TabKind;

// Navigation Context for Cross-View Navigation
// ============================================================================

/// Breadcrumb entry for navigation history
#[derive(Debug, Clone)]
pub struct Breadcrumb {
    /// Tab we came from
    pub tab: TabKind,
    /// Description of what was selected (e.g., "CVE-2024-1234", "lodash")
    pub label: String,
    /// Selection index to restore when going back
    pub selection_index: usize,
}

/// Navigation context for cross-view navigation and breadcrumbs
#[derive(Debug, Clone, Default)]
pub struct NavigationContext {
    /// Breadcrumb trail for back navigation
    pub breadcrumbs: Vec<Breadcrumb>,
    /// Target component name to navigate to (for vuln → component navigation)
    pub target_component: Option<String>,
    /// Target vulnerability ID to navigate to (for component → vuln navigation)
    pub target_vulnerability: Option<String>,
}

impl NavigationContext {
    pub const fn new() -> Self {
        Self {
            breadcrumbs: Vec::new(),
            target_component: None,
            target_vulnerability: None,
        }
    }

    /// Push a new breadcrumb onto the trail
    pub fn push_breadcrumb(&mut self, tab: TabKind, label: String, selection_index: usize) {
        self.breadcrumbs.push(Breadcrumb {
            tab,
            label,
            selection_index,
        });
    }

    /// Pop the last breadcrumb and return it (for back navigation)
    pub fn pop_breadcrumb(&mut self) -> Option<Breadcrumb> {
        self.breadcrumbs.pop()
    }

    /// Clear all breadcrumbs (on explicit tab switch)
    pub fn clear_breadcrumbs(&mut self) {
        self.breadcrumbs.clear();
    }

    /// Check if we have navigation history
    pub fn has_history(&self) -> bool {
        !self.breadcrumbs.is_empty()
    }

    /// Get the current breadcrumb trail as a string
    pub fn breadcrumb_trail(&self) -> String {
        self.breadcrumbs
            .iter()
            .map(|b| format!("{}: {}", b.tab.title(), b.label))
            .collect::<Vec<_>>()
            .join(" > ")
    }

    /// Clear navigation targets
    pub fn clear_targets(&mut self) {
        self.target_component = None;
        self.target_vulnerability = None;
    }
}

