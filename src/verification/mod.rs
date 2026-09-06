//! SBOM integrity verification.
//!
//! Provides file hash verification, component hash auditing,
//! and SBOM signature/provenance checking.

mod audit;
mod hash;
mod model_dir;
pub mod pipeline_receipt;
mod pipeline_receipt_fingerprint;
mod pipeline_receipt_generator;
mod pipeline_receipt_io;
mod pipeline_receipt_paths;
mod pipeline_receipt_policy;

pub use audit::{HashAuditReport, HashAuditResult, audit_component_hashes};
pub use hash::{
    HashError, HashVerifyResult, compute_file_sha256, read_hash_file, verify_file_hash,
};
pub use model_dir::{
    ComponentModelVerification, ModelVerifyReport, ModelVerifyResult, verify_model_dir,
};
pub use pipeline_receipt::{
    AggregatePolicy, AggregateVerification, CheckOutcome, ExpectedContext, HostedReceiptMetadata,
    PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA, PIPELINE_SHARD_RECEIPT_SCHEMA, PipelineShardReceipt,
    ReceiptArtifact, ReceiptArtifactInput, ReceiptError, ReceiptGenerationInput, ReceiptInput,
    Sha256Digest, TargetIdentity, TrustContext, TrustedArtifact, VerificationCheck,
    aggregate_receipts, validate_receipt,
};
pub use pipeline_receipt_fingerprint::{lock_fingerprint, source_fingerprint};
pub use pipeline_receipt_generator::{
    derive_trust_context, generate_receipt, generate_receipt_from_descriptor,
};
pub use pipeline_receipt_io::{check_receipt, read_receipt, write_receipt};
