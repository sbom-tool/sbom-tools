//! SBOM integrity verification.
//!
//! Provides file hash verification, component hash auditing,
//! and SBOM signature/provenance checking.

mod audit;
mod hash;
mod model_dir;

pub use audit::{HashAuditReport, HashAuditResult, audit_component_hashes};
pub use hash::{HashError, HashVerifyResult, read_hash_file, verify_file_hash};
pub use model_dir::{
    ComponentModelVerification, ModelVerifyReport, ModelVerifyResult, verify_model_dir,
};
