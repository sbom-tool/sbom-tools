//! Overlay state management for TUI views.
//!
//! Provides a unified way to manage overlay visibility (help, export, legend)
//! across both diff and view TUI modes.

/// Available overlay types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayKind {
    /// Help/shortcuts overlay
    Help,
    /// Export dialog
    Export,
    /// Color legend
    Legend,
}

/// Manages overlay visibility with mutual exclusion.
///
/// Only one overlay can be visible at a time - showing a new overlay
/// automatically closes others.
///
/// # Example
///
/// ```ignore
/// use crate::tui::viewmodel::OverlayState;
///
/// let mut overlay = OverlayState::new();
///
/// overlay.toggle(OverlayKind::Help);
/// assert!(overlay.is_showing(OverlayKind::Help));
///
/// overlay.toggle(OverlayKind::Export);
/// assert!(overlay.is_showing(OverlayKind::Export));
/// assert!(!overlay.is_showing(OverlayKind::Help)); // Auto-closed
/// ```
#[derive(Debug, Clone, Default)]
pub struct OverlayState {
    /// Currently visible overlay (if any)
    current: Option<OverlayKind>,
}

impl OverlayState {
    /// Create a new overlay state with no overlay visible.
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Check if any overlay is currently visible.
    pub fn has_overlay(&self) -> bool {
        self.current.is_some()
    }

    /// Check if a specific overlay is visible.
    pub fn is_showing(&self, kind: OverlayKind) -> bool {
        self.current == Some(kind)
    }

    /// Get the currently visible overlay.
    pub fn current(&self) -> Option<OverlayKind> {
        self.current
    }

    /// Show a specific overlay, closing any other.
    pub fn show(&mut self, kind: OverlayKind) {
        self.current = Some(kind);
    }

    /// Close the current overlay.
    pub fn close(&mut self) {
        self.current = None;
    }

    /// Close all overlays.
    pub fn close_all(&mut self) {
        self.current = None;
    }

    /// Toggle a specific overlay.
    ///
    /// If the overlay is showing, close it. Otherwise, show it.
    pub fn toggle(&mut self, kind: OverlayKind) {
        if self.current == Some(kind) {
            self.current = None;
        } else {
            self.current = Some(kind);
        }
    }

    /// Toggle help overlay.
    pub fn toggle_help(&mut self) {
        self.toggle(OverlayKind::Help);
    }

    /// Toggle export overlay.
    pub fn toggle_export(&mut self) {
        self.toggle(OverlayKind::Export);
    }

    /// Toggle legend overlay.
    pub fn toggle_legend(&mut self) {
        self.toggle(OverlayKind::Legend);
    }

    // Convenience accessors for backwards compatibility

    /// Check if help overlay is visible.
    pub fn show_help(&self) -> bool {
        self.is_showing(OverlayKind::Help)
    }

    /// Check if export overlay is visible.
    pub fn show_export(&self) -> bool {
        self.is_showing(OverlayKind::Export)
    }

    /// Check if legend overlay is visible.
    pub fn show_legend(&self) -> bool {
        self.is_showing(OverlayKind::Legend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_state_new() {
        let state = OverlayState::new();
        assert!(!state.has_overlay());
        assert!(state.current().is_none());
    }

    #[test]
    fn test_overlay_state_show() {
        let mut state = OverlayState::new();

        state.show(OverlayKind::Help);
        assert!(state.has_overlay());
        assert!(state.is_showing(OverlayKind::Help));
        assert!(state.show_help());
        assert!(!state.show_export());
        assert!(!state.show_legend());
    }

    #[test]
    fn test_overlay_state_mutual_exclusion() {
        let mut state = OverlayState::new();

        state.show(OverlayKind::Help);
        assert!(state.is_showing(OverlayKind::Help));

        state.show(OverlayKind::Export);
        assert!(state.is_showing(OverlayKind::Export));
        assert!(!state.is_showing(OverlayKind::Help));

        state.show(OverlayKind::Legend);
        assert!(state.is_showing(OverlayKind::Legend));
        assert!(!state.is_showing(OverlayKind::Export));
    }

    #[test]
    fn test_overlay_state_toggle() {
        let mut state = OverlayState::new();

        // Toggle on
        state.toggle(OverlayKind::Help);
        assert!(state.is_showing(OverlayKind::Help));

        // Toggle off
        state.toggle(OverlayKind::Help);
        assert!(!state.has_overlay());

        // Toggle different overlay
        state.toggle(OverlayKind::Help);
        state.toggle(OverlayKind::Export);
        assert!(state.is_showing(OverlayKind::Export));
        assert!(!state.is_showing(OverlayKind::Help));
    }

    #[test]
    fn test_overlay_state_close() {
        let mut state = OverlayState::new();

        state.show(OverlayKind::Help);
        assert!(state.has_overlay());

        state.close();
        assert!(!state.has_overlay());
    }

    #[test]
    fn test_overlay_state_close_all() {
        let mut state = OverlayState::new();

        state.show(OverlayKind::Legend);
        state.close_all();
        assert!(!state.has_overlay());
    }

    #[test]
    fn test_overlay_state_convenience_toggles() {
        let mut state = OverlayState::new();

        state.toggle_help();
        assert!(state.show_help());

        state.toggle_export();
        assert!(state.show_export());
        assert!(!state.show_help());

        state.toggle_legend();
        assert!(state.show_legend());
        assert!(!state.show_export());
    }
}
