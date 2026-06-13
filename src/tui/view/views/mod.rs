//! View-specific rendering for the `ViewApp`.

mod algorithms;
mod certificates;
mod compliance;
mod crypto;
mod dependencies;
mod keys;
mod licenses;
mod overview;
mod pqc_compliance;
mod protocols;
mod quality;
mod source;
mod tree;
mod vulnerabilities;

pub use algorithms::render_algorithms;
pub use certificates::render_certificates;
pub(crate) use compliance::build_groups;
pub use compliance::{StandardComplianceState, compute_compliance_results, render_compliance};
pub use crypto::render_crypto;
pub(crate) use dependencies::DependencyGraph;
pub use dependencies::{FlatDepNode, render_dependencies};
pub use keys::render_keys;
pub use licenses::render_licenses;
pub(crate) use licenses::{build_license_data_from_app, get_first_component_id_for_license};
pub use overview::render_overview;
pub use pqc_compliance::render_pqc_compliance;
pub use protocols::render_protocols;
pub use quality::render_quality;
pub use source::render_source;
pub(crate) use source::{SourceLink, resolve_source_reference};
pub use tree::render_tree;
pub(crate) use vulnerabilities::build_vuln_cache;
pub use vulnerabilities::{
    VulnCache, VulnCacheRef, VulnDisplayItem, VulnRow, build_display_items, render_vulnerabilities,
};
