//! Named constants for TUI layout and navigation.

/// Number of items to scroll per page-up/page-down action.
pub const PAGE_SIZE: usize = 10;

/// Default maximum tree depth for dependency view (range: 1-10).
pub const DEFAULT_TREE_MAX_DEPTH: usize = 5;

/// Maximum allowed tree depth (upper bound for user adjustment).
pub const MAX_TREE_DEPTH: usize = 10;

/// Default maximum root nodes in dependency tree (range: 10-100).
pub const DEFAULT_TREE_MAX_ROOTS: usize = 50;

/// Minimum allowed root nodes.
pub const MIN_TREE_ROOTS: usize = 10;

/// Maximum allowed root nodes.
pub const MAX_TREE_ROOTS: usize = 100;

/// Increment step for root node count adjustment.
pub const TREE_ROOTS_STEP: usize = 10;

/// Sort key offset to prioritize overdue SLA items (ensures they sort first).
pub const SLA_OVERDUE_SORT_OFFSET: i64 = 10_000;
