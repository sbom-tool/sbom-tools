//! Unsigned, target-scoped verification receipts.
use super::{
    pipeline_receipt_paths::validate_relative_path,
    pipeline_receipt_policy::{compare_artifacts, validate_policy},
};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use thiserror::Error;
pub const PIPELINE_SHARD_RECEIPT_SCHEMA: &str = "pipeline-shard-receipt/v1";
pub const PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA: &str = "pipeline-shard-receipt-input/v1";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);
impl Sha256Digest {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ReceiptError> {
        let value = value.as_ref();
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| ReceiptError::InvalidDigest(value.into()))?;
        if hex.len() != 64
            || !hex.bytes().all(|b| b.is_ascii_hexdigit())
            || hex != hex.to_ascii_lowercase()
        {
            return Err(ReceiptError::InvalidDigest(value.into()));
        }
        Ok(Self(value.into()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Self(format!("sha256:{hex}"))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("invalid sha256 digest: {0}")]
    InvalidDigest(String),
    #[error("receipt I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("receipt JSON failed for {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("receipt contract violation: {0}")]
    Contract(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustContext {
    PullRequest,
    ProtectedMain,
    Release,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentity {
    pub verification_scope: String,
    pub os: String,
    pub architecture: String,
    pub toolchain: String,
    pub profile: String,
    pub features: Vec<String>,
    pub binding_runtime: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    Passed,
    Failed,
    Cancelled,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCheck {
    pub name: String,
    pub outcome: CheckOutcome,
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifact {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineShardReceipt {
    pub schema: String,
    pub repository: String,
    pub workflow: String,
    pub run_id: Option<String>,
    pub commit_sha: String,
    pub source_fingerprint: Sha256Digest,
    pub trust_context: TrustContext,
    pub promotable: bool,
    pub target: TargetIdentity,
    pub lock_digest: Sha256Digest,
    pub versions: BTreeMap<String, String>,
    pub checks: Vec<VerificationCheck>,
    pub artifacts: Vec<ReceiptArtifact>,
    pub dagger_trace: Option<String>,
    pub started_at: String,
    pub completed_at: String,
    pub failure_classification: Option<String>,
}

pub struct ReceiptInput {
    pub repository: String,
    pub workflow: String,
    pub run_id: Option<String>,
    pub commit_sha: String,
    pub trust_context: TrustContext,
    pub promotable: bool,
    pub target: TargetIdentity,
    pub source_root: PathBuf,
    pub lock_paths: Vec<PathBuf>,
    pub versions: BTreeMap<String, String>,
    pub checks: Vec<VerificationCheck>,
    pub artifacts: Vec<ReceiptArtifact>,
    pub dagger_trace: Option<String>,
    pub started_at: String,
    pub completed_at: String,
    pub failure_classification: Option<String>,
}

/// Strict, digest-free descriptor consumed by the CI receipt generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGenerationInput {
    pub schema: String,
    pub repository: String,
    pub workflow: String,
    pub commit_sha: String,
    pub source_root: PathBuf,
    pub lock_paths: Vec<PathBuf>,
    pub artifact_root: PathBuf,
    pub artifacts: Vec<ReceiptArtifactInput>,
    pub target: TargetIdentity,
    pub versions: BTreeMap<String, String>,
    pub checks: Vec<VerificationCheck>,
    pub started_at: String,
    pub completed_at: String,
    pub run_id: Option<String>,
    pub dagger_trace: Option<String>,
    pub failure_classification: Option<String>,
    pub hosted: Option<HostedReceiptMetadata>,
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifactInput {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedReceiptMetadata {
    pub event_name: String,
    pub ref_name: String,
    pub repository: String,
    pub default_branch: String,
    pub sha: String,
    pub head_repository: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContext {
    pub repository: String,
    pub workflow: String,
    pub commit_sha: String,
    pub trust_context: TrustContext,
    pub promotable: bool,
    pub source_fingerprint: Sha256Digest,
    pub lock_digest: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePolicy {
    pub expected_targets: Vec<TargetIdentity>,
    pub context: ExpectedContext,
    pub required_checks: Vec<String>,
    pub artifacts: Vec<TrustedArtifact>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedArtifact {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateVerification {
    pub receipt_count: usize,
    pub artifact_count: usize,
}

pub fn validate_receipt(r: &PipelineShardReceipt) -> Result<(), ReceiptError> {
    if r.schema != PIPELINE_SHARD_RECEIPT_SCHEMA {
        return Err(ReceiptError::Contract("unsupported schema".into()));
    }
    validate_receipt_identity(r)?;
    validate_receipt_checks(r)?;
    Ok(())
}
fn validate_receipt_identity(r: &PipelineShardReceipt) -> Result<(), ReceiptError> {
    if r.repository.is_empty() || r.workflow.is_empty() {
        return Err(ReceiptError::Contract(
            "required identity field is empty".into(),
        ));
    }
    validate_target(&r.target)?;
    for artifact in &r.artifacts {
        if artifact.name.is_empty() {
            return Err(ReceiptError::Contract(
                "artifact names must be nonempty".into(),
            ));
        }
        validate_relative_path(&artifact.path, "artifact path")?;
    }
    validate_commit(&r.commit_sha)?;
    validate_times(&r.started_at, &r.completed_at)?;
    if r.promotable {
        return Err(ReceiptError::Contract(
            "unsigned receipts cannot be promotable; signed promotion authority is deferred".into(),
        ));
    }
    Ok(())
}
fn validate_receipt_checks(r: &PipelineShardReceipt) -> Result<(), ReceiptError> {
    let mut names = BTreeSet::new();
    for check in &r.checks {
        if check.name.is_empty() || !names.insert(&check.name) {
            return Err(ReceiptError::Contract(
                "check names must be unique and nonempty".into(),
            ));
        }
        validate_check(check)?;
    }
    if r.checks.is_empty() {
        return Err(ReceiptError::Contract(
            "at least one check is required".into(),
        ));
    }
    let failed = r
        .checks
        .iter()
        .any(|c| matches!(c.outcome, CheckOutcome::Failed | CheckOutcome::Cancelled));
    if failed != r.failure_classification.is_some() {
        return Err(ReceiptError::Contract(
            "failure classification disagrees with check outcomes".into(),
        ));
    }
    Ok(())
}
fn validate_target(target: &TargetIdentity) -> Result<(), ReceiptError> {
    if !is_portable_scope(&target.verification_scope)
        || target.os.is_empty()
        || target.architecture.is_empty()
        || target.toolchain.is_empty()
        || target.profile.is_empty()
    {
        return Err(ReceiptError::Contract(
            "target identity fields must be nonempty and verification_scope must be portable"
                .into(),
        ));
    }
    Ok(())
}

fn is_portable_scope(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.contains(char::is_whitespace)
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}
fn validate_commit(value: &str) -> Result<(), ReceiptError> {
    if !(40..=64).contains(&value.len())
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || value != value.to_ascii_lowercase()
    {
        return Err(ReceiptError::Contract(
            "commit_sha must be lowercase hexadecimal SHA".into(),
        ));
    }
    Ok(())
}
fn validate_times(start: &str, end: &str) -> Result<(), ReceiptError> {
    let a = DateTime::<FixedOffset>::parse_from_rfc3339(start)
        .map_err(|_| ReceiptError::Contract("started_at must be RFC3339".into()))?;
    let b = DateTime::<FixedOffset>::parse_from_rfc3339(end)
        .map_err(|_| ReceiptError::Contract("completed_at must be RFC3339".into()))?;
    if b < a {
        return Err(ReceiptError::Contract(
            "completed_at precedes started_at".into(),
        ));
    }
    Ok(())
}
fn validate_check(c: &VerificationCheck) -> Result<(), ReceiptError> {
    if c.passed
        .checked_add(c.failed)
        .and_then(|n| n.checked_add(c.ignored))
        == Some(0)
    {
        return Err(ReceiptError::Contract(format!(
            "check {} has no recorded cases",
            c.name
        )));
    }
    if matches!(c.outcome, CheckOutcome::Passed) && c.failed > 0 {
        return Err(ReceiptError::Contract(format!(
            "passed check {} reports failures",
            c.name
        )));
    }
    match c.outcome {
        CheckOutcome::Failed | CheckOutcome::Cancelled if c.failed == 0 => {
            return Err(ReceiptError::Contract(format!(
                "failed check {} reports no failures",
                c.name
            )));
        }
        CheckOutcome::Skipped if c.failed != 0 || c.passed != 0 => {
            return Err(ReceiptError::Contract(format!(
                "skipped check {} reports passed or failed cases",
                c.name
            )));
        }
        _ => {}
    }
    Ok(())
}

pub fn aggregate_receipts(
    receipts: &[PipelineShardReceipt],
    policy: &AggregatePolicy,
) -> Result<AggregateVerification, ReceiptError> {
    validate_policy(policy)?;
    if receipts.len() != policy.expected_targets.len() {
        return Err(ReceiptError::Contract(
            "receipt count does not match expected targets".into(),
        ));
    }
    validate_expected_targets(policy)?;
    validate_trusted_artifacts(policy)?;
    let (artifact_ids, trusted_ids) = verify_receipt_set(receipts, policy)?;
    if trusted_ids.len() != policy.artifacts.len() {
        return Err(ReceiptError::Contract("required artifact missing".into()));
    }
    Ok(AggregateVerification {
        receipt_count: receipts.len(),
        artifact_count: artifact_ids.len(),
    })
}

fn validate_expected_targets(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let mut expected_ids = BTreeSet::new();
    for target in &policy.expected_targets {
        validate_target(target)?;
        let id =
            serde_json::to_string(target).map_err(|e| ReceiptError::Contract(e.to_string()))?;
        if !expected_ids.insert(id) {
            return Err(ReceiptError::Contract("duplicate expected target".into()));
        }
    }
    Ok(())
}

fn validate_trusted_artifacts(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let mut trusted_ids = BTreeSet::new();
    for artifact in &policy.artifacts {
        validate_relative_path(&artifact.path, "trusted artifact path")?;
        let id = format!("{}:{}", artifact.name, artifact.path);
        if !trusted_ids.insert(id) {
            return Err(ReceiptError::Contract(
                "duplicate trusted artifact identity".into(),
            ));
        }
    }
    Ok(())
}

fn verify_receipt_set(
    receipts: &[PipelineShardReceipt],
    policy: &AggregatePolicy,
) -> Result<(BTreeSet<String>, BTreeSet<String>), ReceiptError> {
    let context = &policy.context;
    let mut seen = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    let mut trusted_ids = BTreeSet::new();
    for r in receipts {
        validate_receipt(r)?;
        compare_context(r, context)?;
        let id =
            serde_json::to_string(&r.target).map_err(|e| ReceiptError::Contract(e.to_string()))?;
        if !seen.insert(id) || !policy.expected_targets.contains(&r.target) {
            return Err(ReceiptError::Contract(
                "duplicate or unexpected target".into(),
            ));
        }
        if r.checks.iter().any(|check| {
            matches!(
                check.outcome,
                CheckOutcome::Failed | CheckOutcome::Cancelled
            )
        }) {
            return Err(ReceiptError::Contract(
                "receipt contains a failed or cancelled check".into(),
            ));
        }
        verify_checks(r, &policy.required_checks)?;
        compare_artifacts(r, &policy.artifacts, &mut artifact_ids, &mut trusted_ids)?;
    }
    Ok((artifact_ids, trusted_ids))
}
fn compare_context(r: &PipelineShardReceipt, e: &ExpectedContext) -> Result<(), ReceiptError> {
    if r.repository != e.repository
        || r.workflow != e.workflow
        || r.commit_sha != e.commit_sha
        || r.trust_context != e.trust_context
        || r.promotable != e.promotable
        || r.source_fingerprint != e.source_fingerprint
        || r.lock_digest != e.lock_digest
    {
        return Err(ReceiptError::Contract("receipt context mismatch".into()));
    }
    Ok(())
}

fn verify_checks(r: &PipelineShardReceipt, required: &[String]) -> Result<(), ReceiptError> {
    for name in required {
        let matches: Vec<_> = r.checks.iter().filter(|c| &c.name == name).collect();
        if matches.len() != 1 || !matches!(matches[0].outcome, CheckOutcome::Passed) {
            return Err(ReceiptError::Contract(format!(
                "required check {name} did not pass"
            )));
        }
    }
    Ok(())
}
