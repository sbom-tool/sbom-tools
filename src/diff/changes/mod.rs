//! Change computer implementations.
//!
//! This module provides concrete implementations of the `ChangeComputer` trait
//! for each type of change: components, dependencies, licenses, and vulnerabilities.

mod components;
mod dependencies;
mod licenses;
mod metadata;
pub mod vuln_grouping;
mod vulnerabilities;

pub use components::ComponentChangeComputer;
pub use dependencies::DependencyChangeComputer;
pub use licenses::LicenseChangeComputer;
pub use metadata::compute_metadata_changes;
pub use vuln_grouping::{
    VulnGroupStatus, VulnerabilityGroup, VulnerabilityGroupedView, group_vulnerabilities,
};
pub use vulnerabilities::VulnerabilityChangeComputer;
