//! SBOM integrity verification.
//!
//! Provides file hash verification, component hash auditing,
//! and SBOM signature/provenance checking.

mod audit;
mod hash;

pub use audit::{HashAuditReport, HashAuditResult, audit_component_hashes};
pub use hash::{HashVerifyResult, read_hash_file, verify_file_hash};
