//! Compliance state types.

/// Available policy presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyPreset {
    #[default]
    Enterprise,
    Strict,
    Permissive,
    /// EU Cyber Resilience Act compliance (delegates to quality::ComplianceChecker)
    Cra,
    /// NTIA Minimum Elements compliance (delegates to quality::ComplianceChecker)
    Ntia,
    /// FDA Medical Device compliance (delegates to quality::ComplianceChecker)
    Fda,
}

impl PolicyPreset {
    pub fn next(&self) -> Self {
        match self {
            Self::Enterprise => Self::Strict,
            Self::Strict => Self::Permissive,
            Self::Permissive => Self::Cra,
            Self::Cra => Self::Ntia,
            Self::Ntia => Self::Fda,
            Self::Fda => Self::Enterprise,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Enterprise => "Enterprise",
            Self::Strict => "Strict",
            Self::Permissive => "Permissive",
            Self::Cra => "EU CRA",
            Self::Ntia => "NTIA",
            Self::Fda => "FDA",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Enterprise => "Standard enterprise security policy",
            Self::Strict => "Maximum security, minimal risk tolerance",
            Self::Permissive => "Minimal checks, only critical issues",
            Self::Cra => "EU Cyber Resilience Act (2024/2847) SBOM requirements",
            Self::Ntia => "NTIA minimum elements for software transparency",
            Self::Fda => "FDA premarket submission SBOM requirements",
        }
    }

    /// Whether this preset delegates to the standards-based compliance checker.
    pub fn is_standards_based(&self) -> bool {
        matches!(self, Self::Cra | Self::Ntia | Self::Fda)
    }

    /// Get the corresponding ComplianceLevel for standards-based presets.
    pub fn compliance_level(&self) -> Option<crate::quality::ComplianceLevel> {
        match self {
            Self::Cra => Some(crate::quality::ComplianceLevel::CraPhase2),
            Self::Ntia => Some(crate::quality::ComplianceLevel::NtiaMinimum),
            Self::Fda => Some(crate::quality::ComplianceLevel::FdaMedicalDevice),
            _ => None,
        }
    }
}

/// State for compliance/policy view (diff mode security policy)
#[derive(Debug, Clone, Default)]
pub struct PolicyComplianceState {
    /// Currently selected policy preset
    pub policy_preset: PolicyPreset,
    /// Cached compliance result
    pub result: Option<crate::tui::security::ComplianceResult>,
    /// Selected violation index
    pub selected_violation: usize,
    /// Whether compliance check has been run
    pub checked: bool,
    /// Show detailed view of selected violation
    pub show_details: bool,
}

impl PolicyComplianceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn toggle_policy(&mut self) {
        self.policy_preset = self.policy_preset.next();
        self.result = None; // Clear cached result when policy changes
        self.checked = false;
    }

    pub fn select_next(&mut self) {
        if let Some(ref result) = self.result {
            if !result.violations.is_empty()
                && self.selected_violation < result.violations.len() - 1
            {
                self.selected_violation += 1;
            }
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_violation > 0 {
            self.selected_violation -= 1;
        }
    }

    pub fn toggle_details(&mut self) {
        self.show_details = !self.show_details;
    }

    pub fn violation_count(&self) -> usize {
        self.result
            .as_ref()
            .map_or(0, |r| r.violations.len())
    }

    pub fn passes(&self) -> bool {
        self.result.as_ref().is_none_or(|r| r.passes)
    }

    pub fn score(&self) -> u8 {
        self.result.as_ref().map_or(100, |r| r.score)
    }
}

/// State for compliance tab in diff mode (side-by-side multi-standard comparison)
#[derive(Debug, Clone)]
pub struct DiffComplianceState {
    /// Currently selected compliance standard index
    pub selected_standard: usize,
    /// Currently selected violation in the list
    pub selected_violation: usize,
    /// Scroll offset for violations viewport
    pub scroll_offset: usize,
    /// Show old SBOM violations (left panel), new SBOM violations (right panel), or diff
    pub view_mode: DiffComplianceViewMode,
    /// Whether the detail overlay is shown for the selected violation
    pub show_detail: bool,
}

/// What to show in the diff compliance tab
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffComplianceViewMode {
    /// Side-by-side violation counts per standard
    Overview,
    /// Show violations that are new in the new SBOM
    NewViolations,
    /// Show violations resolved between old and new
    ResolvedViolations,
    /// Show all violations for old SBOM
    OldViolations,
    /// Show all violations for new SBOM
    NewSbomViolations,
}

impl Default for DiffComplianceState {
    fn default() -> Self {
        Self {
            selected_standard: 3,
            selected_violation: 0,
            scroll_offset: 0,
            show_detail: false,
            view_mode: DiffComplianceViewMode::Overview,
        }
    }
}

impl DiffComplianceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_standard(&mut self) {
        let count = crate::quality::ComplianceLevel::all().len();
        self.selected_standard = (self.selected_standard + 1) % count;
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub fn prev_standard(&mut self) {
        let count = crate::quality::ComplianceLevel::all().len();
        self.selected_standard = if self.selected_standard == 0 {
            count - 1
        } else {
            self.selected_standard - 1
        };
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub fn next_view_mode(&mut self) {
        self.view_mode = match self.view_mode {
            DiffComplianceViewMode::Overview => DiffComplianceViewMode::NewViolations,
            DiffComplianceViewMode::NewViolations => DiffComplianceViewMode::ResolvedViolations,
            DiffComplianceViewMode::ResolvedViolations => DiffComplianceViewMode::OldViolations,
            DiffComplianceViewMode::OldViolations => DiffComplianceViewMode::NewSbomViolations,
            DiffComplianceViewMode::NewSbomViolations => DiffComplianceViewMode::Overview,
        };
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub fn select_next(&mut self, max: usize) {
        if max > 0 && self.selected_violation + 1 < max {
            self.selected_violation += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_violation > 0 {
            self.selected_violation -= 1;
        }
    }

    /// Adjust scroll_offset to keep the selected violation visible within the viewport.
    pub fn adjust_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 {
            return;
        }
        // Keep 1 row of padding when possible
        if self.selected_violation < self.scroll_offset {
            self.scroll_offset = self.selected_violation;
        } else if self.selected_violation >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_violation + 1 - viewport_height;
        }
    }
}

