//! Change computer implementations.
//!
//! This module provides concrete implementations of the `ChangeComputer` trait
//! for each type of change: components, dependencies, licenses, and vulnerabilities.

mod components;
mod dependencies;
mod licenses;
mod vulnerabilities;
pub mod vuln_grouping;

pub use components::ComponentChangeComputer;
pub use dependencies::DependencyChangeComputer;
pub use licenses::LicenseChangeComputer;
pub use vulnerabilities::VulnerabilityChangeComputer;
pub use vuln_grouping::{
    group_vulnerabilities, VulnGroupStatus, VulnerabilityGroup, VulnerabilityGroupedView,
};
