//! Compliance state types.

/// Available policy presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyPreset {
    #[default]
    Enterprise,
    Strict,
    Permissive,
    /// EU Cyber Resilience Act compliance (delegates to `quality::ComplianceChecker`)
    Cra,
    /// NTIA Minimum Elements compliance (delegates to `quality::ComplianceChecker`)
    Ntia,
    /// FDA Medical Device compliance (delegates to `quality::ComplianceChecker`)
    Fda,
    /// NIST SP 800-218 Secure Software Development Framework
    NistSsdf,
    /// Executive Order 14028 Section 4
    Eo14028,
    /// NSA CNSA 2.0 — Post-Quantum Cryptography (strictest)
    Cnsa2,
    /// NIST PQC Readiness — IR 8547 + FIPS 203/204/205
    NistPqc,
    /// BSI TR-03183-2 — German national CRA-aligned SBOM guideline
    BsiTr03183_2,
    /// CRA Article 24 — Open-source software steward (lighter manufacturer profile)
    CraOssSteward,
    /// EUCC Substantial — Reg. (EU) 2024/482 reference profile (Annex IV)
    EuccSubstantial,
    /// EU AI Act — Reg. (EU) 2024/1689 Annex IV technical-documentation readiness
    EuAiAct,
    /// BSI/G7 SBOM-for-AI — Feb 2026 minimum-elements readiness
    BsiSbomForAi,
}

impl PolicyPreset {
    pub const fn next(self) -> Self {
        match self {
            Self::Enterprise => Self::Strict,
            Self::Strict => Self::Permissive,
            Self::Permissive => Self::Cra,
            Self::Cra => Self::Ntia,
            Self::Ntia => Self::Fda,
            Self::Fda => Self::NistSsdf,
            Self::NistSsdf => Self::Eo14028,
            Self::Eo14028 => Self::Cnsa2,
            Self::Cnsa2 => Self::NistPqc,
            Self::NistPqc => Self::BsiTr03183_2,
            Self::BsiTr03183_2 => Self::CraOssSteward,
            Self::CraOssSteward => Self::EuccSubstantial,
            Self::EuccSubstantial => Self::EuAiAct,
            Self::EuAiAct => Self::BsiSbomForAi,
            Self::BsiSbomForAi => Self::Enterprise,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Enterprise => "Enterprise",
            Self::Strict => "Strict",
            Self::Permissive => "Permissive",
            Self::Cra => "EU CRA",
            Self::Ntia => "NTIA",
            Self::Fda => "FDA",
            Self::NistSsdf => "NIST SSDF",
            Self::Eo14028 => "EO 14028",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::CraOssSteward => "CRA OSS Steward",
            Self::EuccSubstantial => "EUCC",
            Self::EuAiAct => "EU AI Act",
            Self::BsiSbomForAi => "BSI/G7 SBOM-for-AI",
        }
    }

    /// Whether this preset delegates to the standards-based compliance checker.
    pub const fn is_standards_based(self) -> bool {
        matches!(
            self,
            Self::Cra
                | Self::Ntia
                | Self::Fda
                | Self::NistSsdf
                | Self::Eo14028
                | Self::Cnsa2
                | Self::NistPqc
                | Self::BsiTr03183_2
                | Self::CraOssSteward
                | Self::EuccSubstantial
                | Self::EuAiAct
                | Self::BsiSbomForAi
        )
    }

    /// Get the corresponding `ComplianceLevel` for standards-based presets.
    pub const fn compliance_level(self) -> Option<crate::quality::ComplianceLevel> {
        match self {
            Self::Cra => Some(crate::quality::ComplianceLevel::CraPhase2),
            Self::Ntia => Some(crate::quality::ComplianceLevel::NtiaMinimum),
            Self::Fda => Some(crate::quality::ComplianceLevel::FdaMedicalDevice),
            Self::NistSsdf => Some(crate::quality::ComplianceLevel::NistSsdf),
            Self::Eo14028 => Some(crate::quality::ComplianceLevel::Eo14028),
            Self::Cnsa2 => Some(crate::quality::ComplianceLevel::Cnsa2),
            Self::NistPqc => Some(crate::quality::ComplianceLevel::NistPqc),
            Self::BsiTr03183_2 => Some(crate::quality::ComplianceLevel::BsiTr03183_2),
            Self::CraOssSteward => Some(crate::quality::ComplianceLevel::CraOssSteward),
            Self::EuccSubstantial => Some(crate::quality::ComplianceLevel::EuccSubstantial),
            Self::EuAiAct => Some(crate::quality::ComplianceLevel::EuAiAct),
            Self::BsiSbomForAi => Some(crate::quality::ComplianceLevel::BsiSbomForAi),
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

    pub const fn toggle_details(&mut self) {
        self.show_details = !self.show_details;
    }

    pub fn passes(&self) -> bool {
        self.result.as_ref().is_none_or(|r| r.passes)
    }
}

/// Severity filter for compliance violation display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplianceSeverityFilter {
    /// Show all violations
    #[default]
    All,
    /// Show only errors
    ErrorsOnly,
    /// Show warnings and above
    WarningsAndAbove,
}

impl ComplianceSeverityFilter {
    /// Cycle to the next filter option.
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::ErrorsOnly,
            Self::ErrorsOnly => Self::WarningsAndAbove,
            Self::WarningsAndAbove => Self::All,
        }
    }

    /// Human-readable label for display in the filter bar.
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::ErrorsOnly => "Errors",
            Self::WarningsAndAbove => "Warn+",
        }
    }

    /// Whether a violation severity passes this filter.
    pub fn matches(self, severity: crate::quality::ViolationSeverity) -> bool {
        match self {
            Self::All => true,
            Self::ErrorsOnly => {
                matches!(severity, crate::quality::ViolationSeverity::Error)
            }
            Self::WarningsAndAbove => {
                matches!(
                    severity,
                    crate::quality::ViolationSeverity::Error
                        | crate::quality::ViolationSeverity::Warning
                )
            }
        }
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
    /// Severity filter for violation display
    pub severity_filter: ComplianceSeverityFilter,
    /// Whether violations are grouped by component/element
    pub group_by_element: bool,
    /// Which element groups are currently expanded (by element name)
    pub expanded_groups: std::collections::HashSet<String>,
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
            severity_filter: ComplianceSeverityFilter::default(),
            group_by_element: false,
            expanded_groups: std::collections::HashSet::new(),
        }
    }
}

impl DiffComplianceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn next_standard(&mut self) {
        let count = crate::quality::ComplianceLevel::all().len();
        self.selected_standard = (self.selected_standard + 1) % count;
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub const fn prev_standard(&mut self) {
        let count = crate::quality::ComplianceLevel::all().len();
        self.selected_standard = if self.selected_standard == 0 {
            count - 1
        } else {
            self.selected_standard - 1
        };
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    pub const fn next_view_mode(&mut self) {
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

    pub const fn select_next(&mut self, max: usize) {
        if max > 0 && self.selected_violation + 1 < max {
            self.selected_violation += 1;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected_violation > 0 {
            self.selected_violation -= 1;
        }
    }

    /// Cycle the severity filter and reset selection.
    pub const fn toggle_severity_filter(&mut self) {
        self.severity_filter = self.severity_filter.next();
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }

    /// Toggle grouping violations by component/element.
    pub fn toggle_group_by_element(&mut self) {
        self.group_by_element = !self.group_by_element;
        self.selected_violation = 0;
        self.scroll_offset = 0;
    }
}
