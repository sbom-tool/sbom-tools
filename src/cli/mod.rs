//! CLI command handlers.
//!
//! This module provides testable command handlers that are invoked by main.rs.
//! Each handler implements the business logic for a specific CLI subcommand.

mod diff;
mod multi;
mod quality;
mod validate;
mod view;

pub use diff::run_diff;
pub use multi::{run_diff_multi, run_matrix, run_timeline};
pub use quality::run_quality;
pub use validate::run_validate;
pub use view::run_view;

// Re-export config types used by handlers
pub use crate::config::{DiffConfig, ViewConfig};
