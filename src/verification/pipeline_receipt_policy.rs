use super::pipeline_receipt::{
    AggregatePolicy, PipelineShardReceipt, ReceiptError, TrustedArtifact,
};
use std::collections::BTreeSet;

pub(crate) fn validate_policy(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    if policy.expected_targets.is_empty() || policy.required_checks.is_empty() {
        return Err(ReceiptError::Contract(
            "aggregate policy targets and required checks must be nonempty".into(),
        ));
    }
    validate_policy_context(policy)?;
    validate_policy_lists(policy)
}
fn validate_policy_context(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let context = &policy.context;
    if context.promotable || context.repository.is_empty() || context.workflow.is_empty() {
        return Err(ReceiptError::Contract(
            "expected unsigned policy context is invalid".into(),
        ));
    }
    if !(40..=64).contains(&context.commit_sha.len())
        || !context.commit_sha.bytes().all(|b| b.is_ascii_hexdigit())
        || context.commit_sha != context.commit_sha.to_ascii_lowercase()
    {
        return Err(ReceiptError::Contract(
            "expected commit_sha is invalid".into(),
        ));
    }
    Ok(())
}
fn validate_policy_lists(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let mut checks = BTreeSet::new();
    if policy
        .required_checks
        .iter()
        .any(|name| name.is_empty() || !checks.insert(name))
    {
        return Err(ReceiptError::Contract(
            "required check names must be unique and nonempty".into(),
        ));
    }
    for target in &policy.expected_targets {
        let mut features = BTreeSet::new();
        if target
            .features
            .iter()
            .any(|feature| feature.is_empty() || !features.insert(feature))
        {
            return Err(ReceiptError::Contract(
                "target feature names must be unique and nonempty".into(),
            ));
        }
    }
    if policy
        .artifacts
        .iter()
        .any(|artifact| artifact.name.is_empty())
    {
        return Err(ReceiptError::Contract(
            "trusted artifact name must be nonempty".into(),
        ));
    }
    Ok(())
}

pub(crate) fn compare_artifacts(
    receipt: &PipelineShardReceipt,
    trusted: &[TrustedArtifact],
    ids: &mut BTreeSet<String>,
    trusted_ids: &mut BTreeSet<String>,
) -> Result<(), ReceiptError> {
    for claim in &receipt.artifacts {
        let id = format!("{}:{}", claim.name, claim.path);
        if !ids.insert(id.clone()) {
            return Err(ReceiptError::Contract("duplicate artifact identity".into()));
        }
        let expected = trusted
            .iter()
            .find(|a| a.name == claim.name && a.path == claim.path)
            .ok_or_else(|| ReceiptError::Contract("unexpected artifact".into()))?;
        trusted_ids.insert(id);
        if expected.size != claim.size || expected.sha256 != claim.sha256 {
            return Err(ReceiptError::Contract("artifact manifest mismatch".into()));
        }
    }
    Ok(())
}
