//! Overlays state types.

/// View switcher state for quick navigation between multi-comparison views
#[derive(Debug, Clone, Default)]
pub struct ViewSwitcherState {
    /// Whether the view switcher overlay is visible
    pub visible: bool,
    /// Currently highlighted view option (0=Multi-Diff, 1=Timeline, 2=Matrix)
    pub selected: usize,
    /// Views available for switching
    pub available_views: Vec<MultiViewType>,
}

/// Types of multi-comparison views
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiViewType {
    MultiDiff,
    Timeline,
    Matrix,
}

impl MultiViewType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MultiDiff => "Multi-Diff Dashboard",
            Self::Timeline => "Timeline View",
            Self::Matrix => "Matrix Comparison",
        }
    }

    pub fn shortcut(&self) -> &'static str {
        match self {
            Self::MultiDiff => "1",
            Self::Timeline => "2",
            Self::Matrix => "3",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::MultiDiff => "◆",
            Self::Timeline => "◇",
            Self::Matrix => "▦",
        }
    }
}

impl ViewSwitcherState {
    pub fn new() -> Self {
        Self {
            visible: false,
            selected: 0,
            available_views: vec![
                MultiViewType::MultiDiff,
                MultiViewType::Timeline,
                MultiViewType::Matrix,
            ],
        }
    }

    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    pub fn show(&mut self) {
        self.visible = true;
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    pub fn next(&mut self) {
        if !self.available_views.is_empty() {
            self.selected = (self.selected + 1) % self.available_views.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.available_views.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.available_views.len() - 1);
        }
    }

    pub fn current_view(&self) -> Option<MultiViewType> {
        self.available_views.get(self.selected).copied()
    }
}

/// Component deep dive state for cross-view component tracking
#[derive(Debug, Clone, Default)]
pub struct ComponentDeepDiveState {
    /// Whether the deep dive modal is visible
    pub visible: bool,
    /// The component being analyzed
    pub component_name: String,
    /// Component canonical ID (if known)
    pub component_id: Option<String>,
    /// Active section in the deep dive (0=Overview, 1=Versions, 2=Dependencies, 3=Vulnerabilities)
    pub active_section: usize,
    /// Data collected from different views
    pub collected_data: ComponentDeepDiveData,
}

/// Collected data for component deep dive across views
#[derive(Debug, Clone, Default)]
pub struct ComponentDeepDiveData {
    /// Version history (from timeline view)
    pub version_history: Vec<ComponentVersionEntry>,
    /// Targets where this component appears (from multi-diff)
    pub target_presence: Vec<ComponentTargetPresence>,
    /// Similarity with other components (from matrix)
    pub similarity_info: Vec<ComponentSimilarityInfo>,
    /// Associated vulnerabilities
    pub vulnerabilities: Vec<ComponentVulnInfo>,
    /// Dependencies (what this component depends on)
    pub dependencies: Vec<String>,
    /// Dependents (what depends on this component)
    pub dependents: Vec<String>,
}

/// Version entry in component history
#[derive(Debug, Clone)]
pub struct ComponentVersionEntry {
    pub version: String,
    pub sbom_label: String,
    pub date: Option<String>,
    pub change_type: String, // "added", "modified", "removed", "unchanged"
}

/// Component presence in a target SBOM
#[derive(Debug, Clone)]
pub struct ComponentTargetPresence {
    pub target_name: String,
    pub version: Option<String>,
    pub is_present: bool,
    pub deviation_from_baseline: Option<String>,
}

/// Similarity info for a component
#[derive(Debug, Clone)]
pub struct ComponentSimilarityInfo {
    pub other_sbom: String,
    pub similarity_score: f64,
    pub version_in_other: Option<String>,
}

/// Vulnerability info for a component
#[derive(Debug, Clone)]
pub struct ComponentVulnInfo {
    pub vuln_id: String,
    pub severity: String,
    pub status: String, // "introduced", "resolved", "persistent"
    pub description: Option<String>,
}

impl ComponentDeepDiveState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open deep dive for a specific component
    pub fn open(&mut self, name: String, id: Option<String>) {
        self.visible = true;
        self.component_name = name;
        self.component_id = id;
        self.active_section = 0;
        self.collected_data = ComponentDeepDiveData::default();
    }

    pub fn close(&mut self) {
        self.visible = false;
    }

    pub fn next_section(&mut self) {
        self.active_section = (self.active_section + 1) % 4;
    }

    pub fn prev_section(&mut self) {
        self.active_section = self.active_section.checked_sub(1).unwrap_or(3);
    }

    pub fn section_labels() -> [&'static str; 4] {
        ["Overview", "Versions", "Dependencies", "Vulnerabilities"]
    }
}

/// Keyboard shortcuts overlay state
#[derive(Debug, Clone, Default)]
pub struct ShortcutsOverlayState {
    /// Whether the overlay is visible
    pub visible: bool,
    /// Current view context for showing relevant shortcuts
    pub context: ShortcutsContext,
}

/// Context for showing relevant shortcuts
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShortcutsContext {
    #[default]
    Global,
    MultiDiff,
    Timeline,
    Matrix,
    Diff,
}

impl ShortcutsOverlayState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn show(&mut self, context: ShortcutsContext) {
        self.visible = true;
        self.context = context;
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }
}

