//! CLI command handlers.
//!
//! This module provides testable command handlers that are invoked by main.rs.
//! Each handler implements the business logic for a specific CLI subcommand.

mod diff;
mod multi;
mod quality;
mod query;
mod validate;
mod view;
mod watch;

pub use diff::run_diff;
pub use multi::{run_diff_multi, run_matrix, run_timeline};
pub use quality::run_quality;
pub use query::{QueryFilter, run_query};
pub use validate::run_validate;
pub use view::run_view;
pub use watch::run_watch;

// Re-export config types used by handlers
pub use crate::config::{DiffConfig, ViewConfig};
