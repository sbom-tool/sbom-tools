//! Search state types.

/// Search state for diff mode.
#[derive(Debug, Clone)]
pub struct DiffSearchState {
    pub active: bool,
    pub query: String,
    pub results: Vec<DiffSearchResult>,
    pub selected: usize,
}

impl DiffSearchState {
    pub fn new() -> Self {
        Self {
            active: false,
            query: String::new(),
            results: Vec::new(),
            selected: 0,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
    }

    pub fn select_next(&mut self) {
        if !self.results.is_empty() && self.selected < self.results.len() - 1 {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn clear(&mut self) {
        self.query.clear();
        self.results.clear();
        self.selected = 0;
    }
}

impl Default for DiffSearchState {
    fn default() -> Self {
        Self::new()
    }
}

/// Search result for diff mode.
#[derive(Debug, Clone)]
pub enum DiffSearchResult {
    Component {
        name: String,
        version: Option<String>,
        change_type: ChangeType,
        match_field: String,
    },
    Vulnerability {
        id: String,
        component_name: String,
        severity: Option<String>,
        change_type: VulnChangeType,
    },
    License {
        license: String,
        component_name: String,
        change_type: ChangeType,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

impl ChangeType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnChangeType {
    Introduced,
    Resolved,
    Persistent,
}

impl VulnChangeType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Introduced => "introduced",
            Self::Resolved => "resolved",
            Self::Persistent => "persistent",
        }
    }
}

