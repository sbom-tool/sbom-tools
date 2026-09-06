//! Deterministic construction of unsigned aggregate receipt policies.
use super::{
    pipeline_receipt::{
        AggregatePolicy, ExpectedContext, HostedReceiptMetadata, ReceiptArtifactInput,
        ReceiptError, TargetIdentity, TrustedArtifact,
    },
    pipeline_receipt_fingerprint::{lock_fingerprint, source_fingerprint},
    pipeline_receipt_generator::{canonical_target, derive_trust_context, hash_artifacts},
    pipeline_receipt_paths::validate_relative_path,
};
use std::{collections::BTreeSet, fs, path::Path};

pub const AGGREGATE_POLICY_MANIFEST_SCHEMA: &str = "aggregate-policy-manifest/v1";
pub const AGGREGATE_POLICY_CONTEXT_SCHEMA: &str = "aggregate-policy-context/v1";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePolicyManifest {
    pub schema: String,
    pub workflow: String,
    pub source_root: std::path::PathBuf,
    pub lock_paths: Vec<std::path::PathBuf>,
    pub artifact_root: std::path::PathBuf,
    pub expected_targets: Vec<TargetIdentity>,
    pub required_checks: Vec<String>,
    pub artifacts: Vec<ReceiptArtifactInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePolicyContextInput {
    pub schema: String,
    pub repository: String,
    pub commit_sha: String,
    #[serde(deserialize_with = "super::pipeline_receipt::require_nullable")]
    pub hosted: Option<HostedReceiptMetadata>,
    pub local: bool,
}

pub fn generate_policy(
    mut manifest: AggregatePolicyManifest,
    context: AggregatePolicyContextInput,
) -> Result<AggregatePolicy, ReceiptError> {
    expand_runtime_paths(
        &mut manifest.source_root,
        &mut manifest.artifact_root,
        &mut manifest.lock_paths,
    )?;
    for target in &mut manifest.expected_targets {
        *target = canonical_target(target.clone())?;
    }
    validate_manifest(&manifest)?;
    validate_context(&context)?;
    if let Some(hosted) = &context.hosted {
        if hosted.repository != context.repository || hosted.sha != context.commit_sha {
            return Err(ReceiptError::Contract(
                "runtime context does not match hosted metadata".into(),
            ));
        }
    }
    let (trust_context, _) = derive_trust_context(context.hosted.as_ref(), context.local)?;
    let source_fingerprint = source_fingerprint(&manifest.source_root)?;
    let lock_digest = lock_fingerprint(&manifest.source_root, &manifest.lock_paths)?;
    let artifacts: Vec<TrustedArtifact> =
        hash_artifacts(&manifest.artifact_root, &manifest.artifacts)?
            .into_iter()
            .map(|a| TrustedArtifact {
                name: a.name,
                path: a.path,
                size: a.size,
                sha256: a.sha256,
            })
            .collect();
    let mut targets = manifest.expected_targets;
    targets.sort_by_key(|target| serde_json::to_string(target).unwrap_or_default());
    let mut checks = manifest.required_checks;
    checks.sort();
    let mut artifacts = artifacts;
    artifacts.sort_by(|a, b| a.name.cmp(&b.name).then(a.path.cmp(&b.path)));
    Ok(AggregatePolicy {
        schema: super::pipeline_receipt::AGGREGATE_POLICY_SCHEMA.into(),
        expected_targets: targets,
        context: ExpectedContext {
            repository: context.repository,
            workflow: manifest.workflow,
            commit_sha: context.commit_sha,
            trust_context,
            promotable: false,
            source_fingerprint,
            lock_digest,
        },
        required_checks: checks,
        artifacts,
    })
}

fn expand_runtime_paths(
    source_root: &mut std::path::PathBuf,
    artifact_root: &mut std::path::PathBuf,
    lock_paths: &mut [std::path::PathBuf],
) -> Result<(), ReceiptError> {
    let replace = |path: &mut std::path::PathBuf| {
        if path.as_os_str() == "$RUNNER_TEMP/sbom-receipt-source" {
            let temp = std::env::var("RUNNER_TEMP")
                .map_err(|_| ReceiptError::Contract("RUNNER_TEMP is required".into()))?;
            *path = std::path::PathBuf::from(&temp).join("sbom-receipt-source");
        }
        Ok::<(), ReceiptError>(())
    };
    replace(source_root)?;
    replace(artifact_root)?;
    let _ = lock_paths;
    Ok(())
}

fn validate_manifest(manifest: &AggregatePolicyManifest) -> Result<(), ReceiptError> {
    if manifest.schema != AGGREGATE_POLICY_MANIFEST_SCHEMA
        || manifest.workflow.is_empty()
        || manifest.source_root.as_os_str().is_empty()
        || manifest.artifact_root.as_os_str().is_empty()
        || manifest.lock_paths.is_empty()
        || manifest.expected_targets.is_empty()
        || manifest.required_checks.is_empty()
    {
        return Err(ReceiptError::Contract(
            "invalid or incomplete policy manifest".into(),
        ));
    }
    let mut locks = BTreeSet::new();
    for path in &manifest.lock_paths {
        let value = path
            .to_str()
            .ok_or_else(|| ReceiptError::Contract("lock path must be UTF-8".into()))?;
        validate_relative_path(value, "lock path")?;
        if !locks.insert(value) {
            return Err(ReceiptError::Contract("duplicate lock path".into()));
        }
    }
    let mut targets = BTreeSet::new();
    for target in &manifest.expected_targets {
        super::pipeline_receipt::validate_target(target)?;
        let key =
            serde_json::to_string(target).map_err(|e| ReceiptError::Contract(e.to_string()))?;
        if !targets.insert(key) {
            return Err(ReceiptError::Contract("duplicate expected target".into()));
        }
    }
    let mut checks = BTreeSet::new();
    for check in &manifest.required_checks {
        if check.is_empty() || !checks.insert(check) {
            return Err(ReceiptError::Contract(
                "required check names must be unique and nonempty".into(),
            ));
        }
    }
    let mut artifacts = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path, "trusted artifact path")?;
        if artifact.name.is_empty() || !artifacts.insert((&artifact.name, &artifact.path)) {
            return Err(ReceiptError::Contract(
                "trusted artifact identities must be unique and nonempty".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_context(context: &AggregatePolicyContextInput) -> Result<(), ReceiptError> {
    if context.schema != AGGREGATE_POLICY_CONTEXT_SCHEMA || context.repository.is_empty() {
        return Err(ReceiptError::Contract(
            "invalid runtime policy context".into(),
        ));
    }
    if !(40..=64).contains(&context.commit_sha.len())
        || !context.commit_sha.bytes().all(|b| b.is_ascii_hexdigit())
        || context.commit_sha != context.commit_sha.to_ascii_lowercase()
    {
        return Err(ReceiptError::Contract(
            "runtime commit_sha is invalid".into(),
        ));
    }
    Ok(())
}

pub fn write_policy(path: &Path, policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let bytes = serde_json::to_vec_pretty(policy).map_err(|source| ReceiptError::Json {
        path: path.into(),
        source,
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| ReceiptError::Io {
            path: path.into(),
            source,
        })?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })
}

pub fn write_context(
    path: &Path,
    context: &AggregatePolicyContextInput,
) -> Result<(), ReceiptError> {
    validate_context(context)?;
    super::pipeline_receipt_generator::derive_trust_context(
        context.hosted.as_ref(),
        context.local,
    )?;
    let bytes = serde_json::to_vec_pretty(context).map_err(|source| ReceiptError::Json {
        path: path.into(),
        source,
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| ReceiptError::Io {
            path: path.into(),
            source,
        })?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })
}
