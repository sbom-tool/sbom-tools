//! TUI trait abstractions for view state management.
//!
//! This module provides the `ViewState` trait for decomposing the monolithic App
//! into focused, testable view state machines.
//!
//! # Architecture
//!
//! The TUI follows a state machine pattern where each view (Summary, Components,
//! Dependencies, etc.) implements `ViewState` to handle its own:
//! - Event processing
//! - State management
//! - Rendering
//! - Keyboard shortcuts
//!
//! The main `App` struct acts as an orchestrator that:
//! - Manages global state (overlays, search, navigation)
//! - Dispatches events to the active view
//! - Coordinates cross-view navigation
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::tui::traits::{ViewState, EventResult, Shortcut};
//!
//! struct MyView {
//!     selected: usize,
//!     items: Vec<String>,
//! }
//!
//! impl ViewState for MyView {
//!     fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
//!         match key.code {
//!             KeyCode::Up => {
//!                 self.select_prev();
//!                 EventResult::Consumed
//!             }
//!             KeyCode::Down => {
//!                 self.select_next();
//!                 EventResult::Consumed
//!             }
//!             _ => EventResult::Ignored,
//!         }
//!     }
//!
//!     fn title(&self) -> &str { "My View" }
//!     fn shortcuts(&self) -> Vec<Shortcut> { vec![] }
//! }
//! ```

use crossterm::event::{KeyEvent, MouseEvent};
use std::fmt;

/// Result of handling an event in a view.
///
/// Views return this to indicate whether they consumed the event
/// or if it should be handled by the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventResult {
    /// Event was handled by this view
    Consumed,
    /// Event was not handled, let parent process it
    Ignored,
    /// Navigate to a different tab
    NavigateTo(TabTarget),
    /// Request to exit the application
    Exit,
    /// Request to show an overlay
    ShowOverlay(OverlayKind),
    /// Set a status message
    StatusMessage(String),
}

impl EventResult {
    /// Create a status message result
    pub fn status(msg: impl Into<String>) -> Self {
        EventResult::StatusMessage(msg.into())
    }

    /// Create a navigation result
    pub fn navigate(target: TabTarget) -> Self {
        EventResult::NavigateTo(target)
    }
}

/// Target for tab navigation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TabTarget {
    Summary,
    Components,
    Dependencies,
    Licenses,
    Vulnerabilities,
    Quality,
    Compliance,
    SideBySide,
    GraphChanges,
    Source,
    /// Navigate to a specific component by name
    ComponentByName(String),
    /// Navigate to a specific vulnerability by ID
    VulnerabilityById(String),
}

impl TabTarget {
    /// Convert to TabKind if this is a simple tab navigation
    pub fn to_tab_kind(&self) -> Option<super::app::TabKind> {
        match self {
            TabTarget::Summary => Some(super::app::TabKind::Summary),
            TabTarget::Components => Some(super::app::TabKind::Components),
            TabTarget::Dependencies => Some(super::app::TabKind::Dependencies),
            TabTarget::Licenses => Some(super::app::TabKind::Licenses),
            TabTarget::Vulnerabilities => Some(super::app::TabKind::Vulnerabilities),
            TabTarget::Quality => Some(super::app::TabKind::Quality),
            TabTarget::Compliance => Some(super::app::TabKind::Compliance),
            TabTarget::SideBySide => Some(super::app::TabKind::SideBySide),
            TabTarget::GraphChanges => Some(super::app::TabKind::GraphChanges),
            TabTarget::Source => Some(super::app::TabKind::Source),
            TabTarget::ComponentByName(_) => Some(super::app::TabKind::Components),
            TabTarget::VulnerabilityById(_) => Some(super::app::TabKind::Vulnerabilities),
        }
    }

    /// Convert from TabKind
    pub fn from_tab_kind(kind: super::app::TabKind) -> Self {
        match kind {
            super::app::TabKind::Summary => TabTarget::Summary,
            super::app::TabKind::Components => TabTarget::Components,
            super::app::TabKind::Dependencies => TabTarget::Dependencies,
            super::app::TabKind::Licenses => TabTarget::Licenses,
            super::app::TabKind::Vulnerabilities => TabTarget::Vulnerabilities,
            super::app::TabKind::Quality => TabTarget::Quality,
            super::app::TabKind::Compliance => TabTarget::Compliance,
            super::app::TabKind::SideBySide => TabTarget::SideBySide,
            super::app::TabKind::GraphChanges => TabTarget::GraphChanges,
            super::app::TabKind::Source => TabTarget::Source,
        }
    }
}

/// Overlay types that can be shown
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayKind {
    Help,
    Export,
    Legend,
    Search,
    Shortcuts,
}

/// A keyboard shortcut for display in help/footer
#[derive(Debug, Clone)]
pub struct Shortcut {
    /// Key sequence (e.g., "j/k", "Tab", "Enter")
    pub key: String,
    /// Brief description (e.g., "Navigate", "Switch tab")
    pub description: String,
    /// Whether this is a primary shortcut (shown in footer)
    pub primary: bool,
}

impl Shortcut {
    /// Create a new shortcut
    pub fn new(key: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            description: description.into(),
            primary: false,
        }
    }

    /// Create a primary shortcut (shown in footer)
    pub fn primary(key: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            description: description.into(),
            primary: true,
        }
    }
}

/// Context provided to views for accessing shared state
pub struct ViewContext<'a> {
    /// Current application mode
    pub mode: ViewMode,
    /// Whether the view is currently focused
    pub focused: bool,
    /// Terminal width
    pub width: u16,
    /// Terminal height
    pub height: u16,
    /// Current tick count for animations
    pub tick: u64,
    /// Mutable status message slot
    pub status_message: &'a mut Option<String>,
}

impl<'a> ViewContext<'a> {
    /// Set a status message
    pub fn set_status(&mut self, msg: impl Into<String>) {
        *self.status_message = Some(msg.into());
    }

    /// Clear the status message
    pub fn clear_status(&mut self) {
        *self.status_message = None;
    }
}

/// Application mode for context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    /// Comparing two SBOMs
    Diff,
    /// Viewing a single SBOM
    View,
    /// Multi-diff comparison
    MultiDiff,
    /// Timeline analysis
    Timeline,
    /// Matrix comparison
    Matrix,
}

impl ViewMode {
    /// Convert from the legacy AppMode enum
    pub fn from_app_mode(mode: super::app::AppMode) -> Self {
        match mode {
            super::app::AppMode::Diff => ViewMode::Diff,
            super::app::AppMode::View => ViewMode::View,
            super::app::AppMode::MultiDiff => ViewMode::MultiDiff,
            super::app::AppMode::Timeline => ViewMode::Timeline,
            super::app::AppMode::Matrix => ViewMode::Matrix,
        }
    }
}

/// Trait for view state machines.
///
/// Each tab/view in the TUI should implement this trait to handle
/// its own events and state management independently.
///
/// # Event Flow
///
/// 1. App receives event from terminal
/// 2. App checks for global handlers (quit, overlays, search)
/// 3. App dispatches to active view's `handle_key` or `handle_mouse`
/// 4. View processes event and returns `EventResult`
/// 5. App acts on result (navigation, status, etc.)
///
/// # State Management
///
/// Views own their state and should be self-contained. The only
/// shared state comes through `ViewContext`, which provides:
/// - Current mode (Diff, View, MultiDiff, etc.)
/// - Terminal dimensions
/// - Animation tick
///
/// # Rendering
///
/// Rendering is handled separately by the UI module, which reads
/// from view state. Views should expose their state through getters.
pub trait ViewState: Send {
    /// Handle a key event.
    ///
    /// Returns `EventResult` indicating how the event was processed.
    /// Views should return `EventResult::Ignored` for unhandled keys
    /// to allow parent handling.
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut ViewContext) -> EventResult;

    /// Handle a mouse event.
    ///
    /// Default implementation ignores all mouse events.
    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    /// Get the title for this view (used in tabs).
    fn title(&self) -> &str;

    /// Get keyboard shortcuts for this view.
    ///
    /// These are displayed in the help overlay and footer hints.
    fn shortcuts(&self) -> Vec<Shortcut>;

    /// Called when this view becomes active.
    ///
    /// Use this to refresh data or reset transient state.
    fn on_enter(&mut self, _ctx: &mut ViewContext) {}

    /// Called when this view is deactivated.
    ///
    /// Use this to clean up or save state.
    fn on_leave(&mut self, _ctx: &mut ViewContext) {}

    /// Called on every tick for animations.
    ///
    /// Default implementation does nothing.
    fn on_tick(&mut self, _ctx: &mut ViewContext) {}

    /// Check if the view has any modal/overlay active.
    ///
    /// Used by App to determine if global shortcuts should be suppressed.
    fn has_modal(&self) -> bool {
        false
    }
}

/// Extension trait for list-based views.
///
/// Provides common navigation behavior for views that display
/// a selectable list of items.
pub trait ListViewState: ViewState {
    /// Get the current selection index.
    fn selected(&self) -> usize;

    /// Set the selection index.
    fn set_selected(&mut self, idx: usize);

    /// Get the total number of items.
    fn total(&self) -> usize;

    /// Move selection to the next item.
    fn select_next(&mut self) {
        let total = self.total();
        let selected = self.selected();
        if total > 0 && selected < total.saturating_sub(1) {
            self.set_selected(selected + 1);
        }
    }

    /// Move selection to the previous item.
    fn select_prev(&mut self) {
        let selected = self.selected();
        if selected > 0 {
            self.set_selected(selected - 1);
        }
    }

    /// Move selection down by a page.
    fn page_down(&mut self) {
        let total = self.total();
        let selected = self.selected();
        if total > 0 {
            self.set_selected((selected + 10).min(total.saturating_sub(1)));
        }
    }

    /// Move selection up by a page.
    fn page_up(&mut self) {
        let selected = self.selected();
        self.set_selected(selected.saturating_sub(10));
    }

    /// Move to the first item.
    fn go_first(&mut self) {
        self.set_selected(0);
    }

    /// Move to the last item.
    fn go_last(&mut self) {
        let total = self.total();
        if total > 0 {
            self.set_selected(total.saturating_sub(1));
        }
    }

    /// Handle common navigation keys for list views.
    ///
    /// Call this from `handle_key` to get standard navigation behavior:
    /// - j/Down: select next
    /// - k/Up: select prev
    /// - g/Home: go to first
    /// - G/End: go to last
    /// - PageUp/PageDown: page navigation
    fn handle_list_nav_key(&mut self, key: KeyEvent) -> EventResult {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.select_next();
                EventResult::Consumed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.select_prev();
                EventResult::Consumed
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.go_first();
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.go_last();
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                self.page_down();
                EventResult::Consumed
            }
            KeyCode::PageUp => {
                self.page_up();
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }
}

/// Display formatting for EventResult (for debugging)
impl fmt::Display for EventResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventResult::Consumed => write!(f, "Consumed"),
            EventResult::Ignored => write!(f, "Ignored"),
            EventResult::NavigateTo(target) => write!(f, "NavigateTo({:?})", target),
            EventResult::Exit => write!(f, "Exit"),
            EventResult::ShowOverlay(kind) => write!(f, "ShowOverlay({:?})", kind),
            EventResult::StatusMessage(msg) => write!(f, "StatusMessage({})", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};

    /// Test implementation for verification
    struct TestListView {
        selected: usize,
        total: usize,
    }

    impl TestListView {
        fn new(total: usize) -> Self {
            Self { selected: 0, total }
        }
    }

    impl ViewState for TestListView {
        fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
            self.handle_list_nav_key(key)
        }

        fn title(&self) -> &str {
            "Test View"
        }

        fn shortcuts(&self) -> Vec<Shortcut> {
            vec![
                Shortcut::primary("j/k", "Navigate"),
                Shortcut::new("g/G", "First/Last"),
            ]
        }
    }

    impl ListViewState for TestListView {
        fn selected(&self) -> usize {
            self.selected
        }

        fn set_selected(&mut self, idx: usize) {
            self.selected = idx;
        }

        fn total(&self) -> usize {
            self.total
        }
    }

    fn make_key_event(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn make_context() -> ViewContext<'static> {
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        ViewContext {
            mode: ViewMode::Diff,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_list_view_navigation() {
        let mut view = TestListView::new(10);
        let mut ctx = make_context();

        // Initially at 0
        assert_eq!(view.selected(), 0);

        // Move down
        let result = view.handle_key(make_key_event(KeyCode::Down), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected(), 1);

        // Move up
        let result = view.handle_key(make_key_event(KeyCode::Up), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected(), 0);

        // Can't go below 0
        let result = view.handle_key(make_key_event(KeyCode::Up), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected(), 0);
    }

    #[test]
    fn test_list_view_go_to_end() {
        let mut view = TestListView::new(10);
        let mut ctx = make_context();

        // Go to last
        let result = view.handle_key(make_key_event(KeyCode::Char('G')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected(), 9);

        // Can't go past end
        let result = view.handle_key(make_key_event(KeyCode::Down), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        assert_eq!(view.selected(), 9);
    }

    #[test]
    fn test_event_result_display() {
        assert_eq!(format!("{}", EventResult::Consumed), "Consumed");
        assert_eq!(format!("{}", EventResult::Ignored), "Ignored");
        assert_eq!(format!("{}", EventResult::Exit), "Exit");
    }

    #[test]
    fn test_shortcut_creation() {
        let shortcut = Shortcut::new("Enter", "Select item");
        assert_eq!(shortcut.key, "Enter");
        assert_eq!(shortcut.description, "Select item");
        assert!(!shortcut.primary);

        let primary = Shortcut::primary("q", "Quit");
        assert!(primary.primary);
    }

    #[test]
    fn test_event_result_helpers() {
        let result = EventResult::status("Test message");
        assert_eq!(
            result,
            EventResult::StatusMessage("Test message".to_string())
        );

        let nav = EventResult::navigate(TabTarget::Components);
        assert_eq!(nav, EventResult::NavigateTo(TabTarget::Components));
    }
}
