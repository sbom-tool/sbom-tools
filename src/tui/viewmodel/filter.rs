//! Filter state management for TUI views.
//!
//! Provides generic filter cycling that can work with any enum-based filter,
//! eliminating the need to duplicate filter toggle logic across views.

/// Trait for filter types that can cycle through options.
///
/// Implement this for your filter enums to enable cycling behavior.
///
/// # Example
///
/// ```ignore
/// use crate::tui::viewmodel::CycleFilter;
///
/// #[derive(Clone, Copy, Default)]
/// enum MyFilter {
///     #[default]
///     All,
///     Active,
///     Completed,
/// }
///
/// impl CycleFilter for MyFilter {
///     fn next(&self) -> Self {
///         match self {
///             Self::All => Self::Active,
///             Self::Active => Self::Completed,
///             Self::Completed => Self::All,
///         }
///     }
///
///     fn prev(&self) -> Self {
///         match self {
///             Self::All => Self::Completed,
///             Self::Active => Self::All,
///             Self::Completed => Self::Active,
///         }
///     }
///
///     fn display_name(&self) -> &str {
///         match self {
///             Self::All => "All",
///             Self::Active => "Active",
///             Self::Completed => "Completed",
///         }
///     }
/// }
/// ```
pub trait CycleFilter: Clone + Copy + Default {
    /// Get the next filter in the cycle.
    #[must_use]
    fn next(&self) -> Self;

    /// Get the previous filter in the cycle.
    #[must_use]
    fn prev(&self) -> Self;

    /// Get a display name for the filter.
    fn display_name(&self) -> &str;
}

/// Generic filter state that works with any CycleFilter enum.
///
/// Provides common state management for filter selection including
/// cycling and display name access.
#[derive(Debug, Clone)]
pub struct FilterState<F: CycleFilter> {
    /// Current filter value
    pub current: F,
}

impl<F: CycleFilter> Default for FilterState<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: CycleFilter> FilterState<F> {
    /// Create a new filter state with the default filter.
    pub fn new() -> Self {
        Self {
            current: F::default(),
        }
    }

    /// Create a filter state with a specific initial value.
    pub fn with_filter(filter: F) -> Self {
        Self { current: filter }
    }

    /// Cycle to the next filter.
    pub fn next(&mut self) {
        self.current = self.current.next();
    }

    /// Cycle to the previous filter.
    pub fn prev(&mut self) {
        self.current = self.current.prev();
    }

    /// Set a specific filter.
    pub fn set(&mut self, filter: F) {
        self.current = filter;
    }

    /// Reset to the default filter.
    pub fn reset(&mut self) {
        self.current = F::default();
    }

    /// Get the current filter's display name.
    pub fn display_name(&self) -> &str {
        self.current.display_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test filter implementation
    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    enum TestFilter {
        #[default]
        All,
        FilterA,
        FilterB,
    }

    impl CycleFilter for TestFilter {
        fn next(&self) -> Self {
            match self {
                Self::All => Self::FilterA,
                Self::FilterA => Self::FilterB,
                Self::FilterB => Self::All,
            }
        }

        fn prev(&self) -> Self {
            match self {
                Self::All => Self::FilterB,
                Self::FilterA => Self::All,
                Self::FilterB => Self::FilterA,
            }
        }

        fn display_name(&self) -> &str {
            match self {
                Self::All => "All Items",
                Self::FilterA => "Filter A",
                Self::FilterB => "Filter B",
            }
        }
    }

    #[test]
    fn test_filter_state_cycling() {
        let mut state = FilterState::<TestFilter>::new();

        assert_eq!(state.current, TestFilter::All);
        assert_eq!(state.display_name(), "All Items");

        state.next();
        assert_eq!(state.current, TestFilter::FilterA);
        assert_eq!(state.display_name(), "Filter A");

        state.next();
        assert_eq!(state.current, TestFilter::FilterB);

        state.next();
        assert_eq!(state.current, TestFilter::All);

        state.prev();
        assert_eq!(state.current, TestFilter::FilterB);
    }

    #[test]
    fn test_filter_state_set_reset() {
        let mut state = FilterState::<TestFilter>::new();

        state.set(TestFilter::FilterB);
        assert_eq!(state.current, TestFilter::FilterB);

        state.reset();
        assert_eq!(state.current, TestFilter::All);
    }

    #[test]
    fn test_filter_state_with_initial() {
        let state = FilterState::with_filter(TestFilter::FilterA);
        assert_eq!(state.current, TestFilter::FilterA);
    }
}
