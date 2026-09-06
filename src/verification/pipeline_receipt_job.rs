//! Strict workflow-job adapter for target-scoped receipt generation.
use super::{
    pipeline_receipt::{CheckOutcome, ReceiptError, ReceiptGenerationInput, VerificationCheck},
    pipeline_receipt_generator::generate_receipt_from_descriptor,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptJobManifest {
    pub schema: String,
    pub workflow: String,
    pub source_root: std::path::PathBuf,
    pub lock_paths: Vec<std::path::PathBuf>,
    pub artifact_root: std::path::PathBuf,
    pub artifacts: Vec<super::pipeline_receipt::ReceiptArtifactInput>,
    pub target: super::pipeline_receipt::TargetIdentity,
    pub checks: Vec<String>,
}

pub fn generate_job_receipt(
    mut manifest: ReceiptJobManifest,
    context: super::pipeline_receipt_policy_generator::AggregatePolicyContextInput,
    outcomes: &[(String, String)],
    runner_os: Option<&str>,
    runner_arch: Option<&str>,
) -> Result<super::pipeline_receipt::PipelineShardReceipt, ReceiptError> {
    if manifest.schema != super::pipeline_receipt::PIPELINE_SHARD_JOB_MANIFEST_SCHEMA {
        return Err(ReceiptError::Contract("invalid job manifest schema".into()));
    }
    resolve_source_token(&mut manifest)?;
    if manifest.checks.is_empty() {
        return Err(ReceiptError::Contract("job manifest has no checks".into()));
    }
    validate_runner_target(&manifest.target, runner_os, runner_arch)?;
    let checks = build_checks(&manifest.checks, outcomes)?;
    let now = chrono::Utc::now().to_rfc3339();
    let failure_classification = checks.iter().find_map(|check| match check.outcome {
        CheckOutcome::Failed => Some("failed".into()),
        CheckOutcome::Cancelled => Some("cancelled".into()),
        CheckOutcome::Passed | CheckOutcome::Skipped => None,
    });
    generate_receipt_from_descriptor(ReceiptGenerationInput {
        schema: super::pipeline_receipt::PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA.into(),
        repository: context.repository,
        workflow: manifest.workflow,
        commit_sha: context.commit_sha,
        source_root: manifest.source_root,
        lock_paths: manifest.lock_paths,
        artifact_root: manifest.artifact_root,
        artifacts: manifest.artifacts,
        target: manifest.target,
        versions: BTreeMap::new(),
        checks,
        started_at: now.clone(),
        completed_at: now,
        run_id: None,
        dagger_trace: None,
        failure_classification,
        hosted: context.hosted,
        local: context.local,
    })
}

fn resolve_source_token(manifest: &mut ReceiptJobManifest) -> Result<(), ReceiptError> {
    if manifest.source_root.as_os_str() != "$RUNNER_TEMP/sbom-receipt-source" {
        return Ok(());
    }
    let temp = std::env::var("RUNNER_TEMP")
        .map_err(|_| ReceiptError::Contract("RUNNER_TEMP is required".into()))?;
    manifest.source_root = std::path::PathBuf::from(temp).join("sbom-receipt-source");
    manifest.artifact_root = manifest.source_root.clone();
    Ok(())
}

fn validate_runner_target(
    target: &super::pipeline_receipt::TargetIdentity,
    runner_os: Option<&str>,
    runner_arch: Option<&str>,
) -> Result<(), ReceiptError> {
    if let Some(os) = runner_os {
        let actual = match os {
            "Linux" => "linux",
            "macOS" => "macos",
            "Windows" => "windows",
            _ => return Err(ReceiptError::Contract("unsupported runner OS".into())),
        };
        if actual != target.os {
            return Err(ReceiptError::Contract(
                "runner OS does not match target".into(),
            ));
        }
    }
    if let Some(arch) = runner_arch {
        let actual = match arch {
            "X64" => "x86_64",
            "ARM64" => "arm64",
            _ => {
                return Err(ReceiptError::Contract(
                    "unsupported runner architecture".into(),
                ));
            }
        };
        if actual != target.architecture {
            return Err(ReceiptError::Contract(
                "runner architecture does not match target".into(),
            ));
        }
    }
    Ok(())
}

fn build_checks(
    declared: &[String],
    outcomes: &[(String, String)],
) -> Result<Vec<VerificationCheck>, ReceiptError> {
    let mut supplied = BTreeMap::new();
    for (name, outcome) in outcomes {
        if supplied.insert(name, parse_outcome(outcome)?).is_some() {
            return Err(ReceiptError::Contract("duplicate check outcome".into()));
        }
    }
    let checks = declared
        .iter()
        .map(|name| check_from_outcome(name, supplied.get(name).copied()))
        .collect::<Result<Vec<_>, _>>()?;
    let expected: BTreeSet<&String> = declared.iter().collect();
    if supplied.keys().any(|name| !expected.contains(name)) {
        return Err(ReceiptError::Contract("unexpected check outcome".into()));
    }
    Ok(checks)
}

fn check_from_outcome(
    name: &str,
    outcome: Option<CheckOutcome>,
) -> Result<VerificationCheck, ReceiptError> {
    let outcome =
        outcome.ok_or_else(|| ReceiptError::Contract(format!("missing outcome for {name}")))?;
    Ok(VerificationCheck {
        name: name.into(),
        outcome,
        passed: u64::from(outcome == CheckOutcome::Passed),
        failed: u64::from(matches!(
            outcome,
            CheckOutcome::Failed | CheckOutcome::Cancelled
        )),
        ignored: u64::from(outcome == CheckOutcome::Skipped),
    })
}

fn parse_outcome(value: &str) -> Result<CheckOutcome, ReceiptError> {
    match value {
        "success" | "passed" => Ok(CheckOutcome::Passed),
        "failure" | "failed" => Ok(CheckOutcome::Failed),
        "cancelled" | "canceled" => Ok(CheckOutcome::Cancelled),
        "skipped" => Ok(CheckOutcome::Skipped),
        _ => Err(ReceiptError::Contract(format!(
            "invalid check outcome: {value}"
        ))),
    }
}
