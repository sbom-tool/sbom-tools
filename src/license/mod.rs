//! License policy engine.
//!
//! Evaluates component licenses against organizational policies,
//! detects compatibility issues in the dependency tree, and produces
//! detailed compliance reports.

mod policy;
mod propagation;

pub use policy::{
    LicensePolicyConfig, LicensePolicyResult, LicensePolicyViolation, PolicyDecision,
    evaluate_license_policy,
};
pub use propagation::{LicenseConflict, check_license_propagation};
