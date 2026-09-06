//! Descriptor-driven receipt generation and hosted trust derivation.
use super::{
    pipeline_receipt::{
        HostedReceiptMetadata, PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA, PIPELINE_SHARD_RECEIPT_SCHEMA,
        PipelineShardReceipt, ReceiptArtifact, ReceiptArtifactInput, ReceiptError,
        ReceiptGenerationInput, ReceiptInput, Sha256Digest, TrustContext, validate_receipt,
    },
    pipeline_receipt_fingerprint::{lock_fingerprint, source_fingerprint},
    pipeline_receipt_paths::validate_relative_path,
};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub fn generate_receipt(input: ReceiptInput) -> Result<PipelineShardReceipt, ReceiptError> {
    let receipt = PipelineShardReceipt {
        schema: PIPELINE_SHARD_RECEIPT_SCHEMA.into(),
        repository: input.repository,
        workflow: input.workflow,
        run_id: input.run_id,
        commit_sha: input.commit_sha,
        source_fingerprint: source_fingerprint(&input.source_root)?,
        trust_context: input.trust_context,
        promotable: input.promotable,
        target: input.target,
        lock_digest: lock_fingerprint(&input.source_root, &input.lock_paths)?,
        versions: input.versions,
        checks: input.checks,
        artifacts: input.artifacts,
        dagger_trace: input.dagger_trace,
        started_at: input.started_at,
        completed_at: input.completed_at,
        failure_classification: input.failure_classification,
    };
    validate_receipt(&receipt)?;
    Ok(receipt)
}

pub fn derive_trust_context(
    hosted: Option<&HostedReceiptMetadata>,
    local: bool,
) -> Result<(TrustContext, bool), ReceiptError> {
    if local {
        if hosted.is_some() {
            return Err(ReceiptError::Contract(
                "local mode must not include hosted metadata".into(),
            ));
        }
        return Ok((TrustContext::Local, false));
    }
    let metadata = hosted.ok_or_else(|| {
        ReceiptError::Contract("hosted metadata is required unless local mode is explicit".into())
    })?;
    validate_hosted_metadata(metadata)?;
    classify_hosted_event(metadata)
}

fn validate_hosted_metadata(metadata: &HostedReceiptMetadata) -> Result<(), ReceiptError> {
    if metadata.repository.is_empty()
        || metadata.default_branch.is_empty()
        || metadata.ref_name.is_empty()
    {
        return Err(ReceiptError::Contract(
            "hosted metadata is incomplete".into(),
        ));
    }
    Ok(())
}

fn classify_hosted_event(
    metadata: &HostedReceiptMetadata,
) -> Result<(TrustContext, bool), ReceiptError> {
    match metadata.event_name.as_str() {
        "pull_request" | "pull_request_target"
            if metadata.ref_name.starts_with("refs/pull/")
                && metadata
                    .head_repository
                    .as_deref()
                    .is_some_and(|r| !r.is_empty()) =>
        {
            Ok((TrustContext::PullRequest, false))
        }
        "push" if metadata.ref_name == format!("refs/heads/{}", metadata.default_branch) => {
            Ok((TrustContext::ProtectedMain, false))
        }
        "push"
            if metadata.ref_name.starts_with("refs/tags/")
                && metadata.ref_name.len() > "refs/tags/".len() =>
        {
            Ok((TrustContext::Release, false))
        }
        "pull_request" | "pull_request_target" => Err(ReceiptError::Contract(
            "ambiguous pull request metadata".into(),
        )),
        _ => Err(ReceiptError::Contract(
            "unsupported or ambiguous hosted event".into(),
        )),
    }
}

pub fn generate_receipt_from_descriptor(
    descriptor: ReceiptGenerationInput,
) -> Result<PipelineShardReceipt, ReceiptError> {
    validate_descriptor(&descriptor)?;
    let (trust_context, promotable) =
        derive_trust_context(descriptor.hosted.as_ref(), descriptor.local)?;
    let target = canonical_target(descriptor.target)?;
    let artifacts = hash_artifacts(&descriptor.artifact_root, &descriptor.artifacts)?;
    generate_receipt(ReceiptInput {
        repository: descriptor.repository,
        workflow: descriptor.workflow,
        run_id: descriptor.run_id,
        commit_sha: descriptor.commit_sha,
        trust_context,
        promotable,
        target,
        source_root: descriptor.source_root,
        lock_paths: descriptor.lock_paths,
        versions: descriptor.versions,
        checks: descriptor.checks,
        artifacts,
        dagger_trace: descriptor.dagger_trace,
        started_at: descriptor.started_at,
        completed_at: descriptor.completed_at,
        failure_classification: descriptor.failure_classification,
    })
}

fn validate_descriptor(descriptor: &ReceiptGenerationInput) -> Result<(), ReceiptError> {
    if descriptor.schema != PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA
        || descriptor.repository.is_empty()
        || descriptor.workflow.is_empty()
    {
        return Err(ReceiptError::Contract(
            "invalid generator input identity or schema".into(),
        ));
    }
    if let Some(hosted) = &descriptor.hosted {
        if hosted.sha != descriptor.commit_sha {
            return Err(ReceiptError::Contract(
                "hosted SHA does not match commit_sha".into(),
            ));
        }
        if hosted.repository != descriptor.repository {
            return Err(ReceiptError::Contract(
                "hosted repository does not match receipt repository".into(),
            ));
        }
    }
    Ok(())
}

fn canonical_target(
    mut target: super::pipeline_receipt::TargetIdentity,
) -> Result<super::pipeline_receipt::TargetIdentity, ReceiptError> {
    target.features.sort();
    if target.features.iter().any(String::is_empty)
        || target.features.windows(2).any(|p| p[0] == p[1])
    {
        return Err(ReceiptError::Contract(
            "target features must be unique and nonempty".into(),
        ));
    }
    Ok(target)
}

fn hash_artifacts(
    root: &Path,
    inputs: &[ReceiptArtifactInput],
) -> Result<Vec<ReceiptArtifact>, ReceiptError> {
    let meta = fs::symlink_metadata(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ReceiptError::Contract(
            "artifact root must be a regular directory".into(),
        ));
    }
    let canonical_root = fs::canonicalize(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    let mut names = BTreeSet::new();
    let mut artifacts = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.name.is_empty() || !names.insert(&input.name) {
            return Err(ReceiptError::Contract(
                "artifact names must be unique and nonempty".into(),
            ));
        }
        validate_relative_path(&input.path, "artifact path")?;
        let path = root.join(&input.path);
        reject_symlink_components(root, &input.path)?;
        artifacts.push(hash_one_artifact(&path, &canonical_root, input)?);
    }
    Ok(artifacts)
}

fn hash_one_artifact(
    path: &Path,
    root: &Path,
    input: &ReceiptArtifactInput,
) -> Result<ReceiptArtifact, ReceiptError> {
    let resolved = fs::canonicalize(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    if !resolved.starts_with(root) {
        return Err(ReceiptError::Contract(
            "artifact path escapes artifact root".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReceiptError::Contract(
            "artifact must be a regular file".into(),
        ));
    }
    let bytes = fs::read(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    Ok(ReceiptArtifact {
        name: input.name.clone(),
        path: input.path.clone(),
        size: bytes.len() as u64,
        sha256: Sha256Digest::from_bytes(&bytes),
    })
}

fn reject_symlink_components(root: &Path, relative: &str) -> Result<(), ReceiptError> {
    let mut current = PathBuf::from(root);
    for component in Path::new(relative).components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|source| ReceiptError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ReceiptError::Contract(
                "artifact path contains a symlink".into(),
            ));
        }
    }
    Ok(())
}
