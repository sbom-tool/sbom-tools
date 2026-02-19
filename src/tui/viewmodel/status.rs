//! Status message management for TUI views.
//!
//! Provides a unified way to display temporary status messages
//! across both diff and view TUI modes.

use std::time::{Duration, Instant};

/// Manages temporary status messages with optional auto-clear.
///
/// Status messages are displayed briefly to notify users of actions
/// (e.g., "Exported to file.json", "Copied to clipboard").
///
/// # Example
///
/// ```ignore
/// use crate::tui::viewmodel::StatusMessage;
///
/// let mut status = StatusMessage::new();
///
/// status.set("File exported successfully");
/// assert!(status.message().is_some());
///
/// status.clear();
/// assert!(status.message().is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct StatusMessage {
    /// The current message (if any)
    message: Option<String>,
    /// When the message was set (for auto-clear)
    set_at: Option<Instant>,
    /// Auto-clear duration (None = no auto-clear)
    auto_clear_after: Option<Duration>,
}

impl StatusMessage {
    /// Create a new status message manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a status message manager with auto-clear after duration.
    #[must_use]
    pub const fn with_auto_clear(duration: Duration) -> Self {
        Self {
            message: None,
            set_at: None,
            auto_clear_after: Some(duration),
        }
    }

    /// Set a status message.
    pub fn set(&mut self, msg: impl Into<String>) {
        self.message = Some(msg.into());
        self.set_at = Some(Instant::now());
    }

    /// Clear the status message.
    pub fn clear(&mut self) {
        self.message = None;
        self.set_at = None;
    }

    /// Get the current message (checking auto-clear if configured).
    pub fn message(&mut self) -> Option<&str> {
        // Check auto-clear
        if let (Some(set_at), Some(duration)) = (self.set_at, self.auto_clear_after)
            && set_at.elapsed() >= duration
        {
            self.message = None;
            self.set_at = None;
        }
        self.message.as_deref()
    }

    /// Get the current message without checking auto-clear.
    ///
    /// Use this when you don't want to mutate state.
    #[must_use]
    pub fn peek(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Check if there's an active message.
    #[must_use]
    pub const fn has_message(&self) -> bool {
        self.message.is_some()
    }

    /// Get the message directly (for backwards compatibility).
    ///
    /// Returns a reference to the Option<String> without auto-clear logic.
    #[must_use]
    pub const fn as_option(&self) -> &Option<String> {
        &self.message
    }

    /// Take the message, clearing it.
    pub const fn take(&mut self) -> Option<String> {
        self.set_at = None;
        self.message.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_status_message_set_clear() {
        let mut status = StatusMessage::new();

        assert!(!status.has_message());
        assert!(status.peek().is_none());

        status.set("Test message");
        assert!(status.has_message());
        assert_eq!(status.peek(), Some("Test message"));

        status.clear();
        assert!(!status.has_message());
        assert!(status.peek().is_none());
    }

    #[test]
    fn test_status_message_take() {
        let mut status = StatusMessage::new();

        status.set("Take me");
        let taken = status.take();

        assert_eq!(taken, Some("Take me".to_string()));
        assert!(!status.has_message());
    }

    #[test]
    fn test_status_message_auto_clear() {
        let mut status = StatusMessage::with_auto_clear(Duration::from_millis(50));

        status.set("Auto clear message");
        assert!(status.message().is_some());

        // Wait for auto-clear
        thread::sleep(Duration::from_millis(60));
        assert!(status.message().is_none());
    }

    #[test]
    fn test_status_message_no_auto_clear_default() {
        let mut status = StatusMessage::new();

        status.set("No auto clear");
        thread::sleep(Duration::from_millis(10));
        assert!(status.message().is_some()); // Still there
    }
}
