//! Generic search state for TUI views.
//!
//! Provides a reusable search state that can work with any result type,
//! eliminating duplication between `DiffSearchState` and `SearchState`.

use crate::tui::state::ListNavigation;

/// Generic search state that works with any result type.
///
/// This replaces the duplicate `DiffSearchState` and `SearchState` structs
/// with a single, type-parameterized implementation.
///
/// # Type Parameter
///
/// - `R`: The result type for search matches (e.g., `DiffSearchResult`, `SearchResult`)
///
/// # Example
///
/// ```ignore
/// use crate::tui::viewmodel::SearchState;
///
/// // For diff mode
/// let mut search: SearchState<DiffSearchResult> = SearchState::new();
///
/// // For view mode
/// let mut search: SearchState<ViewSearchResult> = SearchState::new();
/// ```
#[derive(Debug, Clone)]
pub struct SearchState<R> {
    /// Whether search mode is active
    pub active: bool,
    /// Current search query
    pub query: String,
    /// Search results
    pub results: Vec<R>,
    /// Selected result index
    pub selected: usize,
}

impl<R> Default for SearchState<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> SearchState<R> {
    /// Create a new empty search state.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            active: false,
            query: String::new(),
            results: Vec::new(),
            selected: 0,
        }
    }

    /// Start search mode.
    pub fn start(&mut self) {
        self.active = true;
        self.query.clear();
        self.results.clear();
        self.selected = 0;
    }

    /// Stop search mode.
    pub const fn stop(&mut self) {
        self.active = false;
    }

    /// Clear query and results.
    pub fn clear(&mut self) {
        self.query.clear();
        self.results.clear();
        self.selected = 0;
    }

    /// Add a character to the query.
    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
    }

    /// Remove the last character from the query.
    pub fn pop_char(&mut self) {
        self.query.pop();
    }

    /// Check if the query is long enough to search.
    #[must_use] 
    pub fn has_valid_query(&self) -> bool {
        self.query.len() >= 2
    }

    /// Get the lowercased query for case-insensitive matching.
    #[must_use] 
    pub fn query_lower(&self) -> String {
        self.query.to_lowercase()
    }

    /// Set results and reset selection.
    pub fn set_results(&mut self, results: Vec<R>) {
        self.results = results;
        self.selected = 0;
    }

    /// Get the currently selected result.
    #[must_use] 
    pub fn selected_result(&self) -> Option<&R> {
        self.results.get(self.selected)
    }

    /// Select the next result.
    pub fn select_next(&mut self) {
        if !self.results.is_empty() && self.selected < self.results.len() - 1 {
            self.selected += 1;
        }
    }

    /// Select the previous result.
    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Check if there are any results.
    #[must_use] 
    pub fn has_results(&self) -> bool {
        !self.results.is_empty()
    }

    /// Get the result count.
    #[must_use] 
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

impl<R> ListNavigation for SearchState<R> {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.results.len()
    }

    fn set_total(&mut self, _total: usize) {
        // Results are managed via set_results, not directly
    }
}

/// Non-generic core of search state for when result type isn't needed.
///
/// Useful for extracting just the active/query state without results.
#[derive(Debug, Clone, Default)]
pub struct SearchStateCore {
    /// Whether search mode is active
    pub active: bool,
    /// Current search query
    pub query: String,
}

impl SearchStateCore {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.active = true;
        self.query.clear();
    }

    pub const fn stop(&mut self) {
        self.active = false;
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
    }

    #[must_use] 
    pub fn has_valid_query(&self) -> bool {
        self.query.len() >= 2
    }

    #[must_use] 
    pub fn query_lower(&self) -> String {
        self.query.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_state_lifecycle() {
        let mut state: SearchState<String> = SearchState::new();

        assert!(!state.active);
        assert!(state.query.is_empty());

        state.start();
        assert!(state.active);
        assert!(state.query.is_empty());

        state.push_char('t');
        state.push_char('e');
        state.push_char('s');
        state.push_char('t');
        assert_eq!(state.query, "test");
        assert!(state.has_valid_query());

        state.pop_char();
        assert_eq!(state.query, "tes");

        state.stop();
        assert!(!state.active);
    }

    #[test]
    fn test_search_state_results() {
        let mut state: SearchState<String> = SearchState::new();

        state.set_results(vec![
            "result1".to_string(),
            "result2".to_string(),
            "result3".to_string(),
        ]);

        assert!(state.has_results());
        assert_eq!(state.result_count(), 3);
        assert_eq!(state.selected, 0);
        assert_eq!(state.selected_result(), Some(&"result1".to_string()));

        state.select_next();
        assert_eq!(state.selected, 1);
        assert_eq!(state.selected_result(), Some(&"result2".to_string()));

        state.select_next();
        assert_eq!(state.selected, 2);

        // Can't go past end
        state.select_next();
        assert_eq!(state.selected, 2);

        state.select_prev();
        assert_eq!(state.selected, 1);

        state.select_prev();
        assert_eq!(state.selected, 0);

        // Can't go below 0
        state.select_prev();
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn test_search_state_clear() {
        let mut state: SearchState<String> = SearchState::new();
        state.query = "test".to_string();
        state.set_results(vec!["a".to_string(), "b".to_string()]);
        state.selected = 1;

        state.clear();

        assert!(state.query.is_empty());
        assert!(state.results.is_empty());
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn test_search_state_list_navigation() {
        let mut state: SearchState<i32> = SearchState::new();
        state.set_results(vec![1, 2, 3, 4, 5]);

        // Test ListNavigation trait
        assert_eq!(state.selected(), 0);
        assert_eq!(state.total(), 5);

        state.set_selected(2);
        assert_eq!(state.selected(), 2);

        // Page navigation
        state.page_down();
        assert_eq!(state.selected(), 4); // Clamped to max

        state.go_first();
        assert_eq!(state.selected(), 0);

        state.go_last();
        assert_eq!(state.selected(), 4);
    }

    #[test]
    fn test_search_state_core() {
        let mut core = SearchStateCore::new();

        assert!(!core.active);
        assert!(core.query.is_empty());

        core.start();
        assert!(core.active);

        core.push_char('A');
        core.push_char('B');
        assert_eq!(core.query, "AB");
        assert!(core.has_valid_query());
        assert_eq!(core.query_lower(), "ab");

        core.stop();
        assert!(!core.active);
    }
}
