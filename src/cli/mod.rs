//! CLI command handlers.
//!
//! This module provides testable command handlers that are invoked by main.rs.
//! Each handler implements the business logic for a specific CLI subcommand.

mod diff;
#[cfg(feature = "enrichment")]
mod enrich;
mod license_check;
mod merge;
mod multi;
mod quality;
mod query;
mod tailor;
mod validate;
mod verify;
mod vex;
mod view;
mod watch;

pub use diff::run_diff;
#[cfg(feature = "enrichment")]
pub use enrich::run_enrich;
pub use license_check::run_license_check;
pub use merge::run_merge;
pub use multi::{run_diff_multi, run_matrix, run_timeline};
pub use quality::run_quality;
pub use query::{QueryFilter, run_query};
pub use tailor::run_tailor;
pub use validate::run_validate;
pub use verify::{VerifyAction, run_verify};
pub use vex::{VexAction, run_vex};
pub use view::run_view;
pub use watch::run_watch;

// Re-export config types used by handlers
pub use crate::config::{DiffConfig, ViewConfig};
